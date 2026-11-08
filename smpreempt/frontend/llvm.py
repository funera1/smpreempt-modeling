"""LLVM IR -> structural instruction transition graph, without access policy.

No path enumeration, loop unrolling, JIT, or solver is used here. Expressions
retain LLVM types/flags; they are not a new, independently executable LLVM ISA.
Opaque effects are barriers that require a call summary or additional semantics.
"""
import ctypes as C
import hashlib

from smpreempt.frontend.llvm_c import LLVM

OPCODES = {
    1: 'ret', 2: 'br', 3: 'switch', 4: 'indirectbr', 5: 'invoke', 7: 'unreachable',
    8: 'add', 9: 'fadd', 10: 'sub', 11: 'fsub', 12: 'mul', 13: 'fmul',
    14: 'udiv', 15: 'sdiv', 16: 'fdiv', 17: 'urem', 18: 'srem', 19: 'frem',
    20: 'shl', 21: 'lshr', 22: 'ashr', 23: 'and', 24: 'or', 25: 'xor',
    26: 'alloca', 27: 'load', 28: 'store', 29: 'getelementptr',
    30: 'trunc', 31: 'zext', 32: 'sext', 33: 'fptoui', 34: 'fptosi',
    35: 'uitofp', 36: 'sitofp', 37: 'fptrunc', 38: 'fpext',
    39: 'ptrtoint', 40: 'inttoptr', 41: 'bitcast', 42: 'icmp', 43: 'fcmp',
    44: 'phi', 45: 'call', 46: 'select', 49: 'va_arg', 50: 'extractelement',
    51: 'insertelement', 52: 'shufflevector', 53: 'extractvalue', 54: 'insertvalue',
    55: 'fence', 56: 'cmpxchg', 57: 'atomicrmw', 58: 'resume', 59: 'landingpad',
    60: 'addrspacecast', 61: 'cleanupret', 62: 'catchret', 63: 'catchpad',
    64: 'cleanuppad', 65: 'catchswitch', 66: 'fneg', 67: 'callbr', 68: 'freeze',
}
PREDICATES = dict(enumerate(('eq', 'ne', 'ugt', 'uge', 'ult', 'ule', 'sgt', 'sge', 'slt', 'sle'), 32))
INTEGER_BINARY = {'add', 'sub', 'mul', 'udiv', 'sdiv', 'urem', 'srem', 'shl', 'lshr', 'ashr', 'and', 'or', 'xor'}
CASTS = {'trunc', 'zext', 'sext', 'ptrtoint', 'inttoptr', 'bitcast', 'addrspacecast'}
ABI_ATTRIBUTES = ('byval', 'sret', 'inalloca', 'preallocated', 'byref', 'nest', 'swifterror', 'swiftself')


def cycles(adjacency):
    """Iterative SCCs: report cyclic regions, not claimed natural-loop headers."""
    visited, order = set(), []
    for root in adjacency:
        stack = [(root, False)]
        while stack:
            node, done = stack.pop()
            if done:
                order.append(node)
            elif node not in visited:
                visited.add(node)
                stack.append((node, True))
                stack.extend((target, False) for target in adjacency[node] if target not in visited)
    reverse = {n: [] for n in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].append(source)
    visited, result = set(), []
    for root in reversed(order):
        if root in visited:
            continue
        component, stack = [], [root]
        visited.add(root)
        while stack:
            node = stack.pop()
            component.append(node)
            for target in reverse[node]:
                if target not in visited:
                    visited.add(target)
                    stack.append(target)
        if len(component) > 1 or root in adjacency[root]:
            result.append(sorted(component))
    return result


class Extractor:
    def __init__(self, api, module):
        self.api, self.module = api, module
        self.layout = api.LLVMGetDataLayoutStr(module.value).decode()
        self.target_data = api.LLVMCreateTargetData(self.layout.encode()) if self.layout else None
        self.ids, self.names, self.functions, self.blocks, self.instructions = {}, {}, [], {}, {}
        self.type_cache = {}
        self.diagnostics = []
        self._index()

    def close(self):
        if self.target_data:
            self.api.LLVMDisposeTargetData(self.target_data)
            self.target_data = None

    def _index(self):
        a = self.api
        for f in a.chain(a.LLVMGetFirstFunction, a.LLVMGetNextFunction, self.module.value):
            fid = f'f{len(self.functions)}'
            self.functions.append(f)
            self.ids[f], self.names[f] = fid, a.name(f)
            for index, arg in enumerate(a.chain(a.LLVMGetFirstParam, a.LLVMGetNextParam, f)):
                self.ids[arg], self.names[arg] = f'{fid}:arg{index}', a.name(arg)
            blocks = list(a.chain(a.LLVMGetFirstBasicBlock, a.LLVMGetNextBasicBlock, f))
            self.blocks[f] = blocks
            for index, block in enumerate(blocks):
                bid = f'{fid}:b{index}'
                self.ids[block] = bid
                value = a.LLVMBasicBlockAsValue(block)
                self.ids[value], self.names[block] = bid, a.name(value)
                instructions = list(a.chain(a.LLVMGetFirstInstruction, a.LLVMGetNextInstruction, block))
                self.instructions[block] = instructions
                for index, inst in enumerate(instructions):
                    self.ids[inst], self.names[inst] = f'{bid}:i{index}', a.name(inst)
        for index, g in enumerate(a.chain(a.LLVMGetFirstGlobal, a.LLVMGetNextGlobal, self.module.value)):
            self.ids[g], self.names[g] = f'g{index}', a.name(g)

    def typ(self, ty):
        if ty not in self.type_cache:
            text = self.api.text(self.api.LLVMPrintTypeToString, ty)
            kind = self.api.LLVMGetTypeKind(ty)
            desc = {'llvm': text}
            if kind == 8:
                desc['integer_bits'] = self.api.LLVMGetIntTypeWidth(ty)
            elif kind == 12:
                desc['address_space'] = self.api.LLVMGetPointerAddressSpace(ty)
            self.type_cache[ty] = desc
        return dict(self.type_cache[ty])

    def size(self, ty, allocation=False):
        # Scalable vectors, including nested ones, cannot be lowered to a fixed byte count.
        if not self.target_data or not self.api.LLVMTypeIsSized(ty):
            return None
        if 'vscale' in self.typ(ty)['llvm']:
            return None
        function = self.api.LLVMABISizeOfType if allocation else self.api.LLVMStoreSizeOfType
        return function(self.target_data, ty)

    def aggregate_layout(self, ty):
        a = self.api
        kind = a.LLVMGetTypeKind(ty)
        result = dict(type=self.typ(ty), allocation_bytes=self.size(ty, allocation=True))
        if kind == 11:
            element = a.LLVMGetElementType(ty)
            result.update(count=a.LLVMGetArrayLength(ty), element=self.aggregate_layout(element))
        elif kind == 10 and a.LLVMTypeIsSized(ty):
            result['fields'] = [dict(index=i, type=self.typ(a.LLVMStructGetTypeAtIndex(ty, i)),
                offset=self.api.LLVMOffsetOfElement(self.target_data, ty, i) if self.target_data else None)
                for i in range(a.LLVMCountStructElementTypes(ty))]
        return result

    def ref(self, value):
        a = self.api
        result = {'type': self.typ(a.LLVMTypeOf(value))}
        if value in self.ids:
            return dict(result, kind='reference', id=self.ids[value], name=self.names.get(value, ''))
        text = a.text(a.LLVMPrintValueToString, value)
        kind = 'poison' if a.LLVMIsPoison(value) else 'undef' if a.LLVMIsUndef(value) else 'constant_expression' if a.LLVMIsAConstantExpr(value) else 'literal'
        result.update(kind=kind, llvm=text)
        if a.LLVMGetTypeKind(a.LLVMTypeOf(value)) in (10, 11) and kind == 'literal':
            count = a.LLVMGetNumOperands(value)
            if count:
                result['elements'] = [self.ref(a.LLVMGetOperand(value, i)) for i in range(count)]
        if kind == 'constant_expression':
            result['requires_semantics'] = True
        if a.LLVMIsAConstantInt(value):
            width = a.LLVMGetIntTypeWidth(a.LLVMTypeOf(value))
            # LLVM's canonical printer emits scalar APInts as decimal, true or false.
            literal = text.split(None, 1)[1]
            number = {'true': 1, 'false': 0}.get(literal)
            if number is None:
                number = int(literal)
            result['bits_unsigned'] = str(number % (1 << width))
        return result

    def location(self, inst):
        a = self.api
        line = a.LLVMGetDebugLocLine(inst)
        if not line:
            return None
        return dict(file=a.string(a.LLVMGetDebugLocFilename, inst, C.c_uint),
                    directory=a.string(a.LLVMGetDebugLocDirectory, inst, C.c_uint),
                    line=line, column=a.LLVMGetDebugLocColumn(inst))

    def abi_attributes(self, value, count, callsite=False):
        a = self.api
        get = a.LLVMGetCallSiteEnumAttribute if callsite else a.LLVMGetEnumAttributeAtIndex
        attributes = []
        for index in range(count+1):
            for name in ABI_ATTRIBUTES:
                kind = a.LLVMGetEnumAttributeKindForName(name.encode(), len(name))
                if kind and get(value, index, kind):
                    attributes.append(dict(index=index, name=name))
        return attributes

    def gep(self, inst):
        a = self.api
        source = a.LLVMGetGEPSourceElementType(inst)
        indices = [a.LLVMGetOperand(inst, i) for i in range(1, a.LLVMGetNumOperands(inst))]
        terms, current = [], source
        for index, value in enumerate(indices):
            kind = a.LLVMGetTypeKind(current)
            if index == 0:
                terms.append(dict(index=self.ref(value), scale_bytes=self.size(current, allocation=True)))
            elif kind == 10:  # struct field indices are verifier-checked integer constants
                field = a.LLVMConstIntGetZExtValue(value)
                offset = a.LLVMOffsetOfElement(self.target_data, current, field) if self.target_data and a.LLVMTypeIsSized(current) and 'vscale' not in self.typ(current)['llvm'] else None
                terms.append(dict(field=field, offset_bytes=offset))
                current = a.LLVMStructGetTypeAtIndex(current, field)
            elif kind in (11, 13):
                current = a.LLVMGetElementType(current)
                terms.append(dict(index=self.ref(value), scale_bytes=self.size(current, allocation=True)))
            else:
                terms.append(dict(index=self.ref(value), requires_semantics=True))
        return dict(operator='getelementptr', base=self.ref(a.LLVMGetOperand(inst, 0)),
                    source_type=self.typ(source), indices=[self.ref(i) for i in indices],
                    inbounds=bool(a.LLVMIsInBounds(inst)), offset_terms=terms,
                    nowrap_flags=a.LLVMGEPGetNoWrapFlags(inst) if hasattr(a, 'LLVMGEPGetNoWrapFlags') else int(bool(a.LLVMIsInBounds(inst))),
                    arithmetic='LLVM GEP index arithmetic under module datalayout')

    def opaque(self, inst, op, reason, **details):
        self.diagnostics.append(dict(node=self.ids[inst], opcode=op, reason=reason))
        return dict(kind='opaque_effect', requires_semantics=True, reason=reason,
                    continuation='requires expansion or a validated summary',
                    memory_effect='unknown; never assumed unchanged', **details)

    def effect(self, inst, op):
        a = self.api
        operands = [a.LLVMGetOperand(inst, i) for i in range(a.LLVMGetNumOperands(inst))]
        refs = [self.ref(v) for v in operands]
        result_type = self.typ(a.LLVMTypeOf(inst))
        if op in INTEGER_BINARY:
            if a.LLVMGetTypeKind(a.LLVMTypeOf(inst)) != 8:
                return self.opaque(inst, op, 'vector arithmetic is not lowered', operands=refs)
            flags = {}
            if op in ('add', 'sub', 'mul', 'shl'):
                flags.update(nuw=bool(a.LLVMGetNUW(inst)), nsw=bool(a.LLVMGetNSW(inst)))
            if op in ('udiv', 'sdiv', 'lshr', 'ashr'):
                flags['exact'] = bool(a.LLVMGetExact(inst))
            if op == 'or':
                flags['disjoint'] = bool(a.LLVMGetIsDisjoint(inst))
            return dict(kind='assign', target=self.ids[inst],
                        expression=dict(operator=op, operands=refs, type=result_type, flags=flags))
        if op == 'icmp':
            return dict(kind='assign', target=self.ids[inst], expression=dict(operator='icmp',
                        predicate=PREDICATES[a.LLVMGetICmpPredicate(inst)], operands=refs, type=result_type))
        if op in CASTS | {'select', 'freeze'}:
            flags = {'nneg': bool(a.LLVMGetNNeg(inst))} if op == 'zext' else {}
            if op == 'trunc' and int(a.version.split('.')[0]) >= 20:
                flags = dict(nuw=bool(a.LLVMGetNUW(inst)), nsw=bool(a.LLVMGetNSW(inst)))
            return dict(kind='assign', target=self.ids[inst], expression=dict(operator=op, operands=refs, type=result_type, flags=flags))
        if op == 'getelementptr':
            return dict(kind='assign', target=self.ids[inst], expression=self.gep(inst))
        if op == 'alloca':
            ty = a.LLVMGetAllocatedType(inst)
            return dict(kind='allocate', target=self.ids[inst], count=refs[0],
                        element_type=self.typ(ty), element_allocation_bytes=self.size(ty, allocation=True),
                        alignment=a.LLVMGetAlignment(inst), pointer_type=result_type,
                        lifetime='current function invocation; allocation failure/stack limits not evaluated')
        if op in ('load', 'store'):
            ordering = a.LLVMGetOrdering(inst)
            volatile = bool(a.LLVMGetVolatile(inst))
            ty = a.LLVMTypeOf(inst) if op == 'load' else a.LLVMTypeOf(operands[0])
            details = dict(address=refs[0 if op == 'load' else 1], value_type=self.typ(ty),
                           size_bytes=self.size(ty), alignment=a.LLVMGetAlignment(inst),
                           volatile=volatile, atomic_ordering=ordering)
            if op == 'store':
                details['value'] = refs[0]
            if ordering or volatile:
                return self.opaque(inst, op, 'atomic/volatile memory access needs additional semantics', operation=op, **details)
            return dict(kind=op, **details, **({'target': self.ids[inst]} if op == 'load' else {}))
        if op in ('call', 'invoke', 'callbr'):
            callee = a.LLVMGetCalledValue(inst)
            arguments = [self.ref(a.LLVMGetArgOperand(inst, i)) for i in range(a.LLVMGetNumArgOperands(inst))]
            details = dict(arguments=arguments, result=None if result_type['llvm'] == 'void' else self.ids[inst])
            details.update(abi_attributes=self.abi_attributes(inst, len(arguments), callsite=True),
                           calling_convention=a.LLVMGetInstructionCallConv(inst))
            if a.LLVMIsAInlineAsm(callee):
                details.update(callee_kind='inline_asm', assembly=a.string(a.LLVMGetInlineAsmAsmString, callee),
                               constraints=a.string(a.LLVMGetInlineAsmConstraintString, callee),
                               side_effects=bool(a.LLVMGetInlineAsmHasSideEffects(callee)))
            elif a.LLVMIsAFunction(callee):
                details.update(callee_kind='direct', callee=self.ref(callee),
                               definition_available=bool(self.blocks[callee]))
            else:
                details.update(callee_kind='indirect', callee=self.ref(callee))
            # Even memset/memcpy or a defined function is not silently atomic.
            return self.opaque(inst, op, 'call/assembly requires an explicit expansion or summary', **details)
        if op == 'ret':
            return dict(kind='return', value=refs[0] if refs else None)
        if op == 'unreachable':
            return dict(kind='unreachable', defined_execution=False)
        if op in ('br', 'switch'):
            return dict(kind='control')
        return self.opaque(inst, op, 'instruction semantics are not lowered', operands=refs)

    def phi(self, inst):
        a = self.api
        return dict(id=self.ids[inst], name=self.names[inst], llvm=a.text(a.LLVMPrintValueToString, inst),
                    source=self.location(inst), target=self.ids[inst],
                    incoming=[dict(predecessor=self.ids[a.LLVMGetIncomingBlock(inst, i)],
                                   value=self.ref(a.LLVMGetIncomingValue(inst, i)))
                              for i in range(a.LLVMCountIncoming(inst))])

    def function(self, f):
        a = self.api
        fid = self.ids[f]
        result = dict(id=fid, name=self.names[f], type=self.typ(a.LLVMGlobalGetValueType(f)),
                      return_type=self.typ(a.LLVMGetReturnType(a.LLVMGlobalGetValueType(f))),
                      variadic=bool(a.LLVMIsFunctionVarArg(a.LLVMGlobalGetValueType(f))),
                      parameters=[self.ref(v) for v in a.chain(a.LLVMGetFirstParam, a.LLVMGetNextParam, f)],
                      declaration=not bool(self.blocks[f]), blocks=[], nodes=[], transitions=[])
        result['abi_attributes'] = self.abi_attributes(f, len(result['parameters']))
        result['calling_convention'] = a.LLVMGetFunctionCallConv(f)
        adjacency = {}
        for block in self.blocks[f]:
            bid = self.ids[block]
            insts = self.instructions[block]
            phis = [i for i in insts if a.LLVMGetInstructionOpcode(i) == 44]
            body = [i for i in insts if a.LLVMGetInstructionOpcode(i) != 44]
            entry = bid+':entry'
            result['blocks'].append(dict(id=bid, name=self.names[block], entry=entry,
                                         phis=[self.phi(i) for i in phis], instructions=[self.ids[i] for i in body]))
            result['nodes'].append(dict(id=entry, kind='block_entry', block=bid))
            result['transitions'].append(dict(source=entry, target=self.ids[body[0]], guard=True,
                effect=dict(kind='parallel_phi', selector='predecessor_block',
                            assignments=[self.phi(i) for i in phis]), frame='memory and other SSA bindings unchanged'))
            term = a.LLVMGetBasicBlockTerminator(block)
            successors = [a.LLVMGetSuccessor(term, i) for i in range(a.LLVMGetNumSuccessors(term))]
            adjacency[bid] = [self.ids[b] for b in successors]
            for index, inst in enumerate(body):
                op = OPCODES.get(a.LLVMGetInstructionOpcode(inst), f'opcode_{a.LLVMGetInstructionOpcode(inst)}')
                iid = self.ids[inst]
                node = dict(id=iid, block=bid, opcode=op, name=self.names[inst],
                            llvm=a.text(a.LLVMPrintValueToString, inst), source=self.location(inst),
                            result_type=self.typ(a.LLVMTypeOf(inst)))
                result['nodes'].append(node)
                effect = self.effect(inst, op)
                # Constant expressions/undef/poison remain explicit, not evaluated as ordinary integers.
                if inst != term:
                    result['transitions'].append(dict(source=iid, target=self.ids[body[index+1]],
                        guard=True, effect=effect, frame='other SSA bindings and memory unchanged except explicit effect'))
                    continue
                def edge(target, guard):
                    return dict(source=iid, target=self.ids[target]+':entry', guard=guard,
                                effect=effect, predecessor_block=bid)
                if op == 'br':
                    if a.LLVMIsConditional(inst):
                        condition = self.ref(a.LLVMGetCondition(inst))
                        result['transitions'].extend([edge(successors[0], condition),
                            edge(successors[1], dict(operator='not', operand=condition))])
                    else:
                        result['transitions'].append(edge(successors[0], True))
                elif op == 'switch':
                    value = self.ref(a.LLVMGetOperand(inst, 0))
                    cases = [self.ref(a.LLVMGetOperand(inst, 2+2*i)) for i in range(len(successors)-1)]
                    result['transitions'].append(edge(successors[0], dict(operator='not_in', value=value, cases=cases)))
                    for successor, case in zip(successors[1:], cases):
                        result['transitions'].append(edge(successor, dict(operator='eq', operands=[value, case])))
                elif op in ('ret', 'unreachable'):
                    result['transitions'].append(dict(source=iid, target=None, guard=True, effect=effect))
                else:
                    # Destinations are known structurally; feasibility is intentionally opaque.
                    for index, target in enumerate(successors):
                        result['transitions'].append(edge(target, dict(kind='opaque_successor_condition', index=index)))
                    if not successors:
                        result['transitions'].append(dict(source=iid, target=None, guard=True, effect=effect))
        result['entry'] = self.ids[self.blocks[f][0]]+':entry' if self.blocks[f] else None
        result['cyclic_regions'] = cycles(adjacency)
        return result

    def report(self, functions=None):
        a = self.api
        requested = None if functions is None else set(functions)
        if requested is not None:
            missing = requested - {self.names[f] for f in self.functions}
            if missing:
                raise ValueError('unknown functions: ' + ', '.join(sorted(missing)))
        graphs = [self.function(f) for f in self.functions if requested is None or self.names[f] in requested]
        globals_ = []
        for g in a.chain(a.LLVMGetFirstGlobal, a.LLVMGetNextGlobal, self.module.value):
            initializer = a.LLVMGetInitializer(g)
            globals_.append(dict(id=self.ids[g], name=self.names[g],
                type=self.typ(a.LLVMGlobalGetValueType(g)), constant=bool(a.LLVMIsGlobalConstant(g)),
                layout=self.aggregate_layout(a.LLVMGlobalGetValueType(g)),
                initializer=None if not initializer else self.ref(initializer)))
        return dict(schema='smpreempt.llvm-transitions.v1',
            status='extracted_with_opaque_effects' if self.diagnostics else 'extracted',
            input=dict(path=self.module.path, sha256=hashlib.sha256(self.module.data).hexdigest()),
            llvm=dict(library=a.library, version=a.version),
            target=a.LLVMGetTarget(self.module.value).decode(), datalayout=self.layout,
            state=dict(pc='instruction node ID', values='typed SSA bindings within one invocation',
                       memory='abstract memory; typed load/store effects; no access permissions',
                       predecessor_block='source block for simultaneous PHI assignment'),
            semantics=dict(level='structural LLVM transition relations; not an executable verifier',
                expressions='LLVM semantics, including poison/undef, flags, attributes and datalayout',
                source_of_truth='canonical module IR and instruction text retained; attributes and metadata are not erased',
                loops='cyclic graph; no unrolling or reachability analysis',
                calls='opaque barriers; continuation requires expansion or a validated summary',
                memory_intrinsics='opaque calls, not assumed atomic',
                access_control='not evaluated',
                safety='not evaluated'),
            function_index=[dict(id=self.ids[f], name=self.names[f], definition_available=bool(self.blocks[f]))
                            for f in self.functions],
            canonical_ir=a.text(a.LLVMPrintModuleToString, self.module.value),
            globals=globals_, functions=graphs, diagnostics=self.diagnostics)


def extract_llvm(path, *, functions=None, library=None):
    api = LLVM(library)
    with api.module(path) as module:
        extractor = Extractor(api, module)
        try:
            return extractor.report(functions)
        finally:
            extractor.close()
