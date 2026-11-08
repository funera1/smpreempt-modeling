"""Bounded symbolic execution of a deliberately small LLVM CFG subset.

This applies one extracted CFG edge to an explicit symbolic state. It is not a
full LLVM interpreter: unsupported effects stop a path, and the step bound is
explicit. Pointer arguments and globals are symbolic addresses in one flat
byte array; object validity, aliasing and permissions are not inferred.
"""
from dataclasses import dataclass, field, replace

import z3

from smpreempt.model.llvm_scalars import Scalar, ScalarSemantics, UnsupportedLLVM, scalar
from smpreempt.model.symbolic_pmp import SymbolicPMP


@dataclass(frozen=True)
class LLVMState:
    pc: str
    values: dict
    memory: object
    path: object = field(default_factory=lambda: z3.BoolVal(True))
    predecessor: str = None
    steps: int = 0
    status: str = 'running'
    result: object = None
    stopped_reason: str = None
    trace: tuple = ()
    memory_events: tuple = ()
    function_id: str = None
    frames: tuple = ()
    pmp: object = None
    csrs: dict = field(default_factory=dict)
    gprs: dict = field(default_factory=dict)
    sfence_epoch: int = 0
    machine_events: tuple = ()


@dataclass(frozen=True)
class CallFrame:
    function_id: str
    values: dict
    continuation: str
    predecessor: str
    result_id: str
    callsite: str


def _fresh_pmp(prefix):
    return SymbolicPMP.fresh(prefix+'_pmp')


def _pmpcfg_value(pmp, index):
    # RV64 pmpcfg0 contains pmp0cfg..pmp7cfg; pmpcfg1 is reserved.
    if index != 0:
        raise UnsupportedLLVM('PMP CSR is outside the selected eight-entry profile')
    return z3.Concat(*reversed(pmp.cfg))


def _csr_read(state, csr, prefix):
    if csr.startswith('pmpcfg'):
        index = int(csr[6:])
        if state.pmp is None:
            raise UnsupportedLLVM('PMP state is not initialized')
        return _pmpcfg_value(state.pmp, index)
    if csr.startswith('pmpaddr'):
        index = int(csr[7:])
        if state.pmp is None or not 0 <= index < len(state.pmp.addr):
            raise UnsupportedLLVM('PMP address CSR is outside the selected profile')
        return state.pmp.addr[index]
    return state.csrs.get(csr, z3.BitVec(prefix+'_'+csr, 64))


def _csr_write(state, csr, value, node=None):
    if csr.startswith(('pmpcfg', 'pmpaddr')):
        if state.pmp is None:
            raise UnsupportedLLVM('PMP state is not initialized')
        # On RV64, pmpcfg0 is a 64-bit CSR containing eight independent bytes.
        if csr.startswith('pmpcfg') and value.size() != 64:
            raise UnsupportedLLVM('RV64 pmpcfg writes must be 64 bits')
        if csr.startswith('pmpaddr') and value.size() < 64:
            value = z3.ZeroExt(64-value.size(), value)
        elif value.size() > 64:
            value = z3.Extract(63, 0, value)
        pmp, valid = state.pmp.write(csr, value)
        return replace(state, pmp=pmp,
            path=z3.And(state.path, valid),
            machine_events=state.machine_events+(dict(kind='pmp_csr_write', csr=csr,
                value=value.sexpr(), warl_valid=valid.sexpr(), node=node),))
    if value.size() < 64:
        value = z3.ZeroExt(64-value.size(), value)
    elif value.size() > 64:
        value = z3.Extract(63, 0, value)
    csrs = dict(state.csrs)
    csrs[csr] = value
    return replace(state, csrs=csrs,
        machine_events=state.machine_events+(dict(kind='csr_write', csr=csr, value=value.sexpr(), node=node),))


def _asm_value(value, bindings, state, prefix):
    kind = value['kind']
    if kind == 'immediate':
        return z3.BitVecVal(value['value'], 64)
    if kind == 'register':
        index = value['index']
        return z3.BitVecVal(0, 64) if index == 0 else state.gprs.get(index, z3.BitVec(prefix+f'_x{index}', 64))
    if kind == 'llvm_operand':
        binding = bindings[value['index']]
        if binding['kind'] != 'input':
            raise UnsupportedLLVM('inline-asm output used as an input without tied-operand semantics')
        scalar_value = _operand(binding['value'], state.values)
        if not isinstance(scalar_value, Scalar):
            raise UnsupportedLLVM('inline-asm operand is not an integer scalar')
        bits = scalar_value.bits
        if bits.size() < 64:
            return z3.ZeroExt(64-bits.size(), bits)
        return z3.Extract(63, 0, bits) if bits.size() > 64 else bits
    raise UnsupportedLLVM('inline-asm operand kind is unsupported: '+kind)


def _set_asm_destination(destination, value, bindings, state):
    if destination['kind'] == 'register':
        index = destination['index']
        if index == 0:
            return state
        gprs = dict(state.gprs)
        gprs[index] = value
        return replace(state, gprs=gprs)
    if destination['kind'] == 'llvm_operand':
        binding = bindings[destination['index']]
        if binding['kind'] != 'output':
            raise UnsupportedLLVM('inline-asm destination maps to an input operand')
        values = dict(state.values)
        values[binding['target']] = Scalar(value)
        return replace(state, values=values)
    raise UnsupportedLLVM('inline-asm destination kind is unsupported')


def _execute_inline_asm(effect, state, node_id):
    from smpreempt.extraction.riscv_asm_effects import extract_asm
    asm = extract_asm(effect)
    if not asm['complete']:
        raise UnsupportedLLVM(asm.get('reason', 'inline assembly contains an unknown instruction'))
    current = state
    label_values = {}
    for index, step in enumerate(asm['steps']):
        kind = step['kind']
        prefix = f'{node_id}_asm{index}'
        if kind in ('label', 'alignment'):
            current = replace(current, machine_events=current.machine_events+(
                dict(kind='asm_'+kind, node=node_id, text=step.get('text')) ,))
            continue
        if kind == 'label_address':
            label = step['value']['label']
            address = label_values.setdefault(label, z3.BitVec(prefix+'_label_pc', 64))
            current = _set_asm_destination(step['destination'], address, asm['bindings'], current)
            current = replace(current, machine_events=current.machine_events+(
                dict(kind='asm_label_address', node=node_id, label=label,
                     value=address.sexpr(), pc_exact=False),))
            continue
        if kind == 'csr':
            old = _csr_read(current, step['csr'], prefix)
            destination = step['destination']
            if step.get('csr_read'):
                current = _set_asm_destination(destination, old, asm['bindings'], current)
            if step.get('csr_write'):
                source = _asm_value(step['value'], asm['bindings'], current, prefix)
                if step['update'] == 'replace':
                    new = source
                elif step['update'] == 'set':
                    new = old | source
                elif step['update'] == 'clear':
                    new = old & ~source
                else:
                    raise UnsupportedLLVM('unknown CSR update operation')
                current = _csr_write(current, step['csr'], new, node=node_id)
            continue
        if kind == 'fence':
            instruction = step.get('catalogue_id')
            if instruction == 'translation.sfence.vma':
                epoch = current.sfence_epoch+1
                current = replace(current, sfence_epoch=epoch,
                    machine_events=current.machine_events+(dict(kind='translation_sync',
                        instruction=instruction, epoch=epoch, node=node_id,
                        pmp_snapshot='current CSR state recorded; no hardware cache semantics applied'),))
            else:
                current = replace(current, machine_events=current.machine_events+(
                    dict(kind='memory_ordering', instruction=instruction, node=node_id,
                         note='ordering effect is recorded, not applied to an operational memory model'),))
            continue
        raise UnsupportedLLVM('unsupported inline-asm operation: '+kind)
    return current


def _width(expression):
    ty = expression.get('type', {})
    width = ty.get('integer_bits') or (64 if ty.get('llvm') == 'ptr' else None)
    if width is None:
        raise UnsupportedLLVM('only integer result values are implemented')
    return width


def _operand(expression, values):
    kind = expression.get('kind')
    if kind == 'reference':
        try:
            return values[expression['id']]
        except KeyError as exc:
            raise UnsupportedLLVM('unbound LLVM value: '+expression['id']) from exc
    if expression.get('type', {}).get('llvm') == 'ptr':
        if kind == 'literal' and expression.get('llvm') == 'ptr null':
            return Scalar(z3.BitVecVal(0, 64))
        raise UnsupportedLLVM('only pointer references and null are supported')
    return ScalarSemantics(values).evaluate(expression)


def _eval(expression, state):
    op = expression.get('operator')
    if op == 'getelementptr':
        base = _operand(expression['base'], state.values)
        offset = base.bits
        poison, ub = base.poison, base.ub
        inbounds_checks = [z3.BoolVal(True)]
        for term in expression['offset_terms']:
            if 'field' in term:
                amount = term.get('offset_bytes')
                if amount is None:
                    raise UnsupportedLLVM('GEP struct offset is unavailable')
                delta = z3.BitVecVal(amount, offset.size())
            else:
                index = _operand(term['index'], state.values)
                stride = term.get('scale_bytes')
                if stride is None:
                    raise UnsupportedLLVM('GEP element stride is unavailable')
                if index.bits.size() < offset.size():
                    extended = z3.SignExt(offset.size()-index.bits.size(), index.bits)
                elif index.bits.size() > offset.size():
                    extended = z3.Extract(offset.size()-1, 0, index.bits)
                else:
                    extended = index.bits
                delta = extended * stride
                poison, ub = z3.Or(poison, index.poison), z3.Or(ub, index.ub)
                inbounds_checks.append(z3.SignExt(offset.size(), extended) * stride == z3.SignExt(offset.size(), delta))
            new_offset = offset + delta
            inbounds_checks.append(z3.SignExt(offset.size(), offset) + z3.SignExt(offset.size(), delta) == z3.SignExt(offset.size(), new_offset))
            offset = new_offset
        if expression.get('inbounds'):
            # Without object provenance only the no-wrap part can be checked;
            # staying within the source object is left as an explicit condition.
            poison = z3.Or(poison, z3.Not(z3.And(*inbounds_checks)))
        return Scalar(offset, poison, ub)
    return ScalarSemantics(state.values, prefix=f'step_{state.steps}_{state.pc}').evaluate(expression)


def _read_memory(memory, address, width):
    if width < 8 or width % 8:
        raise UnsupportedLLVM('memory access width must be a positive multiple of 8')
    parts = [z3.Select(memory, address+i) for i in range(width//8)]
    return parts[0] if len(parts) == 1 else z3.Concat(*reversed(parts))


def _write_memory(memory, address, value):
    if value.bits.size() < 8 or value.bits.size() % 8:
        raise UnsupportedLLVM('memory store width must be a positive multiple of 8')
    for index in range(value.bits.size()//8):
        memory = z3.Store(memory, address+index, z3.Extract(index*8+7, index*8, value.bits))
    return memory


def _as_bv64(value):
    if value.bits.size() < 64:
        return z3.ZeroExt(64-value.bits.size(), value.bits)
    return z3.Extract(63, 0, value.bits) if value.bits.size() > 64 else value.bits


def _execute_memset(effect, state, node_id):
    args = effect['arguments']
    if len(args) != 4:
        raise UnsupportedLLVM('unexpected llvm.memset signature')
    destination, fill, length, is_volatile = [_operand(arg, state.values) for arg in args]
    destination, length = _as_bv64(destination), _as_bv64(length)
    if fill.bits.size() != 8:
        raise UnsupportedLLVM('llvm.memset fill must be i8')
    no_wrap = z3.ULE(z3.ZeroExt(1, destination)+z3.ZeroExt(1, length),
                     z3.BitVecVal(1 << 64, 65))
    valid = z3.And(is_volatile.defined, is_volatile.bits == 0,
                   no_wrap, fill.defined, length.defined)
    index = z3.BitVec(f'{node_id}_memset_index', 64)
    relative = index-destination
    updated = z3.Lambda(index, z3.If(z3.ULT(relative, length), fill.bits,
                                     z3.Select(state.memory, index)))
    event = dict(kind='memset', node=node_id, address=destination.sexpr(),
                 length=length.sexpr(), byte=fill.bits.sexpr(),
                 no_wrap=no_wrap.sexpr())
    return replace(state, memory=updated, path=z3.And(state.path, valid),
        memory_events=state.memory_events+(event,))


def _execute_direct_call(effect, edge, state, functions, max_call_depth):
    callee_ref = effect.get('callee') or {}
    callee = functions.get(callee_ref.get('id'))
    if callee is None:
        return None
    if callee.get('variadic') or len(callee['parameters']) != len(effect['arguments']):
        raise UnsupportedLLVM('variadic calls require explicit ABI semantics')
    if callee.get('abi_attributes') or effect.get('abi_attributes'):
        raise UnsupportedLLVM('ABI-affecting call attributes require semantics')
    if callee.get('calling_convention', 0) != effect.get('calling_convention', 0):
        raise UnsupportedLLVM('nonmatching calling convention')
    if len(callee['parameters']) != len(effect['arguments']):
        raise UnsupportedLLVM('call arity differs from callee signature')
    if len(state.frames) >= max_call_depth:
        raise UnsupportedLLVM('runtime call depth bound reached')
    bound = {}
    globals_ = {key:value for key,value in state.values.items() if key.startswith('g')}
    bound.update(globals_)
    for parameter, argument in zip(callee['parameters'], effect['arguments']):
        value = _operand(argument, state.values)
        parameter_type = parameter['type']
        expected_width = parameter_type.get('integer_bits') or (64 if parameter_type.get('llvm') == 'ptr' else None)
        if expected_width is None or not isinstance(value, Scalar) or value.bits.size() != expected_width:
            raise UnsupportedLLVM('call argument type does not match supported callee parameter type')
        bound[parameter['id']] = value
    frame = CallFrame(state.function_id, dict(state.values), edge['target'],
        state.predecessor, effect.get('result'), edge['source'])
    return replace(state, pc=callee['entry'], values=bound,
        function_id=callee['id'], frames=state.frames+(frame,),
        steps=state.steps+1,
        trace=state.trace+(dict(source=edge['source'], target=callee['entry'],
            effect='call_enter', callee=callee['name']),))


def apply_edge(edge, state, *, functions=None, max_call_depth=32):
    """Return a successor state, or mark the path stopped on unsupported LLVM."""
    effect = edge['effect']
    values, memory = dict(state.values), state.memory
    target, result, predecessor = edge.get('target'), state.result, state.predecessor
    events = state.memory_events
    try:
        if effect['kind'] == 'assign':
            expression = effect['expression']
            if expression.get('operator') == 'getelementptr':
                value = _eval(expression, state)
            else:
                value = ScalarSemantics(values, prefix=f'step_{state.steps}_{state.pc}').evaluate(expression)
            values[effect['target']] = value
            # LLVM immediate UB (for example division by zero) makes this
            # instruction's successor execution undefined.
            state = replace(state, values=values, memory=memory,
                            path=z3.And(state.path, z3.Not(value.ub)))
        elif effect['kind'] == 'load':
            if effect.get('volatile') or effect.get('atomic_ordering'):
                raise UnsupportedLLVM('volatile/atomic load needs an explicit ordering model')
            address = _operand(effect['address'], values)
            ty = effect['value_type']
            width = ty.get('integer_bits') or (64 if ty.get('llvm') == 'ptr' else None)
            if width is None:
                raise UnsupportedLLVM('aggregate load is unsupported')
            state = replace(state, values=values, memory=memory,
                            path=z3.And(state.path, address.defined))
            values[effect['target']] = Scalar(_read_memory(memory, address.bits, width),
                address.poison, address.ub)
            events += (dict(kind='load', node=edge['source'], address=address.bits.sexpr(),
                            width_bits=width, value=values[effect['target']].bits.sexpr()),)
        elif effect['kind'] == 'store':
            if effect.get('volatile') or effect.get('atomic_ordering'):
                raise UnsupportedLLVM('volatile/atomic store needs an explicit ordering model')
            address = _operand(effect['address'], values)
            value = _operand(effect['value'], values)
            if not isinstance(address, Scalar) or not isinstance(value, Scalar):
                raise UnsupportedLLVM('store requires scalar address and value')
            state = replace(state, values=values, memory=memory,
                            path=z3.And(state.path, address.defined, value.defined))
            memory = _write_memory(memory, address.bits, value)
            events += (dict(kind='store', node=edge['source'], address=address.bits.sexpr(),
                            width_bits=value.bits.size(), value=value.bits.sexpr()),)
        elif effect['kind'] == 'parallel_phi':
            if effect.get('selector') != 'predecessor_block':
                raise UnsupportedLLVM('unknown PHI selector')
            updates = {}
            for assignment in effect['assignments']:
                incoming = [i for i in assignment['incoming'] if i['predecessor'] == state.predecessor]
                if len(incoming) != 1:
                    raise UnsupportedLLVM('PHI needs exactly one incoming value for the predecessor')
                updates[assignment['target']] = _operand(incoming[0]['value'], values)
            values.update(updates)
        elif effect['kind'] == 'return':
            result = None if effect['value'] is None else _operand(effect['value'], values)
            if state.frames:
                frame = state.frames[-1]
                caller_values = dict(frame.values)
                if frame.result_id:
                    if result is None:
                        raise UnsupportedLLVM('void return cannot bind a call result')
                    caller_values[frame.result_id] = result
                return replace(state, pc=frame.continuation, values=caller_values,
                    function_id=frame.function_id, predecessor=frame.predecessor,
                    frames=state.frames[:-1], result=None, steps=state.steps+1,
                    trace=state.trace+(dict(source=edge['source'], target=frame.continuation,
                        effect='call_return', callsite=frame.callsite),))
        elif effect['kind'] == 'allocate':
            address = z3.BitVec(f"alloc_{edge['source']}_{state.steps}", 64)
            values[effect['target']] = Scalar(address)
        elif effect['kind'] == 'opaque_effect':
            if effect.get('callee_kind') == 'inline_asm':
                state = _execute_inline_asm(effect, replace(state, values=values, memory=memory), edge['source'])
                values = dict(state.values)
                memory = state.memory
            elif effect.get('callee_kind') == 'direct':
                name = effect.get('callee', {}).get('name', '')
                if name.startswith('llvm.lifetime.start.') or name.startswith('llvm.lifetime.end.'):
                    state = replace(state, machine_events=state.machine_events+(
                        dict(kind='lifetime_intrinsic', name=name,
                             effect='allocation lifetime not enforced by this executor'),))
                elif name.startswith('llvm.memset.'):
                    state = _execute_memset(effect, replace(state, values=values, memory=memory), edge['source'])
                    values, memory, events = dict(state.values), state.memory, state.memory_events
                elif name == 'sbi_printf':
                    # This known platform logging routine is outside the ordinary
                    # memory/PMP state model. Its arguments are still evaluated by
                    # LLVM, but its device/console effects are represented only as
                    # an explicit summary event.
                    state = replace(state, machine_events=state.machine_events+(
                        dict(kind='external_call_summary', callee=name,
                             assumption='logging/device effects omitted; no PMP or modeled RAM effect'),))
                    if effect.get('result'):
                        values[effect['result']] = Scalar(z3.BitVec(
                            f"{edge['source']}_sbi_printf_result", 32))
                else:
                    if functions is None:
                        raise UnsupportedLLVM('direct call needs a module function graph')
                    entered = _execute_direct_call(effect, edge, replace(state, values=values, memory=memory),
                                                   functions, max_call_depth)
                    if entered is None:
                        raise UnsupportedLLVM('callee definition is unavailable')
                    return entered
            else:
                raise UnsupportedLLVM(effect.get('reason', 'opaque effect'))
        elif effect['kind'] in ('control', 'unreachable'):
            if effect['kind'] == 'unreachable':
                return replace(state, pc=target, values=values, memory=memory,
                    path=state.path, predecessor=predecessor, steps=state.steps+1,
                    status='stopped', result=result, stopped_reason='LLVM unreachable reached',
                    trace=state.trace, memory_events=events)
        else:
            raise UnsupportedLLVM('unsupported transition effect: '+effect['kind'])
        if target and target.endswith(':entry'):
            predecessor = edge.get('predecessor_block')
        path = state.path
        guard = edge.get('guard', True)
        if guard is not True:
            condition = _eval(guard, replace(state, values=values, memory=memory,
                                             path=path, predecessor=predecessor))
            if condition.bits.size() != 1:
                raise UnsupportedLLVM('CFG guard is not i1')
            path = z3.And(path, condition.defined, condition.bits == 1)
        checker = z3.Solver()
        checker.add(path)
        if checker.check() == z3.unsat:
            return None
        status = 'returned' if effect['kind'] == 'return' else 'running'
        taken = dict(source=edge['source'], target=target, effect=effect['kind'])
        if guard is not True:
            taken['guard'] = guard
        return replace(state, pc=target, values=values, memory=memory, path=path,
            predecessor=predecessor, steps=state.steps+1, status=status,
            result=result, stopped_reason=None,
            trace=state.trace+(taken,), memory_events=events)
    except (UnsupportedLLVM, KeyError, ValueError) as exc:
        barrier = dict(source=edge['source'], target=target,
                       effect=effect['kind'], status='unsupported')
        return replace(state, values=values, memory=memory, predecessor=predecessor,
            steps=state.steps+1, status='stopped', result=result,
            stopped_reason=str(exc), trace=state.trace+(barrier,), memory_events=events)


def initial_state(function, arguments=None, *, prefix='llvm_exec', module_report=None):
    """Create a state with symbolic integer/pointer parameters and byte memory."""
    arguments = {} if arguments is None else dict(arguments)
    values = {}
    for parameter in function['parameters']:
        if parameter['id'] in arguments:
            supplied = arguments[parameter['id']]
            values[parameter['id']] = supplied if isinstance(supplied, Scalar) else Scalar(supplied)
            continue
        ty = parameter['type']
        width = ty.get('integer_bits') or (64 if ty.get('llvm') == 'ptr' else None)
        if width is None:
            raise UnsupportedLLVM('unsupported parameter type: '+ty.get('llvm', '?'))
        values[parameter['id']] = Scalar(z3.BitVec(f'{prefix}_{parameter["id"].replace(":", "_")}', width))
    memory = z3.Array(f'{prefix}_memory', z3.BitVecSort(64), z3.BitVecSort(8))
    if module_report is not None:
        for global_ in module_report['globals']:
            values[global_['id']] = Scalar(z3.BitVec(f'{prefix}_{global_["id"]}_address', 64))
        for global_ in module_report['globals']:
            initializer = global_.get('initializer') or {}
            layout = global_.get('layout') or {}
            size = layout.get('allocation_bytes')
            if not size:
                continue
            address = values[global_['id']].bits
            if 'zeroinitializer' in initializer.get('llvm', ''):
                index = z3.BitVec(prefix+'_'+global_['id']+'_zero_index', 64)
                memory = z3.Lambda(index, z3.If(z3.ULT(index-address, size),
                    z3.BitVecVal(0, 8), z3.Select(memory, index)))
            elif initializer.get('kind') == 'literal' and 'bits_unsigned' in initializer:
                width = size*8
                if width <= 4096:
                    raw = int(initializer['bits_unsigned'])
                    value = z3.BitVecVal(raw, width)
                    for index in range(size):
                        memory = z3.Store(memory, address+index,
                            z3.Extract(index*8+7, index*8, value))
    return LLVMState(function['entry'], values, memory, path=z3.BoolVal(True),
        function_id=function['id'], pmp=_fresh_pmp(prefix),
        csrs={'mtvec': z3.BitVec(prefix+'_mtvec', 64)},
        gprs={0: z3.BitVecVal(0, 64)})


def run_bounded(function, *, arguments=None, max_steps=100, max_states=1000,
                prefix='llvm_exec', module_report=None, max_call_depth=32):
    """Enumerate symbolic CFG prefixes up to explicit edge/state bounds."""
    if max_steps < 0 or max_states < 1:
        raise ValueError('invalid execution bounds')
    if max_call_depth < 0:
        raise ValueError('call depth must be nonnegative')
    functions = ({f['id']:f for f in module_report['functions'] if not f['declaration']}
                 if module_report is not None else {function['id']:function})
    outgoing = {}
    for current in functions.values():
        for edge in current['transitions']:
            outgoing.setdefault((current['id'],edge['source']), []).append(edge)
    queue = [initial_state(function, arguments, prefix=prefix, module_report=module_report)]
    terminal = []
    while queue:
        state = queue.pop(0)
        if state.status != 'running' or state.steps >= max_steps:
            if state.status == 'running':
                state = replace(state, status='bound_reached')
            terminal.append(state)
            continue
        edges = outgoing.get((state.function_id,state.pc), [])
        if not edges:
            terminal.append(replace(state, status='stopped', stopped_reason='no outgoing CFG edge'))
            continue
        for edge in edges:
            successor = apply_edge(edge, state, functions=functions,
                                   max_call_depth=max_call_depth)
            if successor is not None:
                queue.append(successor)
                if len(queue)+len(terminal) > max_states:
                    terminal.append(replace(state, status='state_bound_reached',
                        stopped_reason='maximum queued states exceeded'))
                    queue.clear()
                    break
    return terminal
