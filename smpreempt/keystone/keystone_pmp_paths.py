"""Execute extracted PMP-helper paths for explicit, valid region metadata.

This instantiates actual LLVM control/data flow and inline CSR operations. It is
not a whole-Keystone reachability proof. Unknown effects stop the path.
"""
from copy import deepcopy
from dataclasses import dataclass
import z3

from smpreempt.model.llvm_scalars import ByteMemory, Scalar, scalar, UnsupportedLLVM
from smpreempt.model.llvm_memory import MemoryObject, Pointer, RelationEvaluator
from smpreempt.extraction.riscv_asm_effects import extract_asm
from smpreempt.model.riscv_model import P, napot_encode
from smpreempt.model.symbolic_pmp import SymbolicPMP


@dataclass(frozen=True)
class RegionMetadata:
    base: int = 0x81000000
    size: int = 0x1000
    region_id: int = 2
    register_index: int = 1
    mode: int = 0x18

    @property
    def encoded_address(self):
        if self.mode == 0x18:
            return napot_encode(self.base, self.size)
        if self.mode == 8:
            return (self.base+self.size) >> 2
        raise ValueError('only NAPOT/TOR region metadata is supported')


def initial_pmp(region, enclave_running=False):
    if not 0 < region.register_index < 7 or not 0 < region.region_id < 16:
        raise ValueError('region must not use the SM or OS PMP slot')
    if region.mode == 8 and region.register_index < 2:
        raise ValueError('TOR pair must not overlap SM entry0')
    pmp = P()
    pmp.cfg[0], pmp.addr[0] = 0x18, napot_encode(0x80000000, 0x200000)
    # During enclave execution slot7 represents the shared UTM mapping; on
    # Host return the OS region is installed there. Keep Host entry outside UTM.
    pmp.cfg[7] = 0x1f
    pmp.addr[7] = napot_encode(0x82000000, 0x1000) if enclave_running else (1 << 54)-1
    pmp.cfg[region.register_index] = region.mode | (7 if enclave_running else 0)
    pmp.addr[region.register_index] = region.encoded_address
    if region.mode == 8:
        pmp.addr[region.register_index-1] = region.base >> 2
    return pmp


def metadata_environment(report, region):
    values, objects = {}, {}
    globals_ = {g['name']: g for g in report['globals']}
    for name in ('regions', 'region_def_bitmap', 'reg_bitmap'):
        if name not in globals_:
            raise UnsupportedLLVM('required Keystone global is absent: '+name)
        g = globals_[name]
        size = g['layout']['allocation_bytes']
        memory = ByteMemory.fresh('metadata_'+name)
        # These are explicit helper-entry contracts, not boot-time initializers.
        if name == 'regions':
            layout = g['layout']['element']
            fields = {f['index']: f for f in layout['fields']}
            if set(fields) != set(range(5)) or g['layout']['count'] <= region.region_id:
                raise UnsupportedLLVM('unrecognized pmp_region layout')
            record = {0: region.size, 1: region.mode, 2: region.base, 3: 0, 4: region.register_index}
            for index, number in record.items():
                f = fields[index]
                width = f['type'].get('integer_bits')
                if width is None or f['offset'] is None:
                    raise UnsupportedLLVM('metadata layout is not concrete')
                address = layout['allocation_bytes']*region.region_id+f['offset']
                memory = memory.store(z3.BitVecVal(address, 64), scalar(number, width))
        else:
            number = (1 << region.region_id) | 0b1011 if name == 'region_def_bitmap' else (1 << region.register_index) | 0x81
            memory = memory.store(z3.BitVecVal(0, 64), scalar(number, g['type']['integer_bits']))
        values[g['id']] = Pointer(name)
        objects[name] = MemoryObject(memory, size, 8)
    return values, objects


def is_true(expression):
    return z3.is_true(z3.simplify(expression))


def pmp_snapshot(pmp):
    return dict(cfg=[z3.simplify(c).sexpr() for c in pmp.cfg], addr=[z3.simplify(a).sexpr() for a in pmp.addr])


def execute_helper(report, name, region, initial, permission=0, max_steps=2000):
    functions = [f for f in report['functions'] if f['name'] == name]
    if len(functions) != 1:
        raise ValueError('expected one helper definition: '+name)
    function = functions[0]
    values, objects = metadata_environment(report, region)
    for index, param in enumerate(function['parameters']):
        width = param['type'].get('integer_bits')
        if width is None:
            raise UnsupportedLLVM('unsupported helper argument type')
        values[param['id']] = scalar(region.region_id if index == 0 else permission, width)
    evaluator = RelationEvaluator.from_graph(report, values, objects, prefix=name)
    nodes = {n['id']: n for n in function['nodes']}
    edges = {}
    for edge in function['transitions']:
        edges.setdefault(edge['source'], []).append(edge)
    pmp = SymbolicPMP.concrete(initial)
    auxiliary = {'mtvec': scalar(0x80000000, 64)}
    temps = {0: scalar(0, 64)}
    operations, llvm_trace, cuts = [], [], []
    last_fence = -1
    def cut(where):
        cuts.append(dict(position=where, pmp=pmp, cache_invalidated=last_fence >= 0,
                         operation_count=len(operations), source=nodes[where].get('source') if where in nodes else operations[-1].get('source')))
    cut(function['entry'])
    pc, predecessor = function['entry'], None
    for _ in range(max_steps):
        node = nodes[pc]
        llvm_trace.append(dict(node=pc, llvm=node.get('llvm'), source=node.get('source')))
        candidates = edges[pc]
        if len(candidates) != 1:
            selected = []
            for edge in candidates:
                guard = edge['guard']
                value = evaluator.evaluate(guard) if guard is not True else scalar(1, 1)
                if not is_true(value.defined):
                    raise UnsupportedLLVM('branch definedness is not established')
                condition = z3.simplify(value.bits == 1)
                if z3.is_true(condition):
                    selected.append(edge)
                elif not z3.is_false(condition):
                    raise UnsupportedLLVM('helper metadata does not select one concrete control path')
            if len(selected) != 1:
                raise UnsupportedLLVM('no unique helper branch')
            edge = selected[0]
        else:
            edge = candidates[0]
        effect, kind = edge['effect'], edge['effect']['kind']
        if kind == 'parallel_phi':
            updates = {}
            for phi in effect['assignments']:
                incoming = [i for i in phi['incoming'] if i['predecessor'] == predecessor]
                if len(incoming) != 1:
                    raise UnsupportedLLVM('unresolved helper PHI')
                updates[phi['target']] = evaluator.evaluate(incoming[0]['value'])
            evaluator.values.update(updates)
        elif kind == 'assign':
            value = evaluator.evaluate(effect['expression'])
            if isinstance(value, Scalar) and not is_true(value.defined):
                raise UnsupportedLLVM('helper arithmetic is not defined under the metadata contract')
            evaluator.values[effect['target']] = value
        elif kind == 'load':
            expr = dict(operator='load', memory=dict(kind='entry_memory'), **{k:v for k,v in effect.items() if k not in ('kind','target')})
            value = evaluator.evaluate(expr)
            if not is_true(value.defined):
                raise UnsupportedLLVM('helper metadata load not established as defined')
            evaluator.values[effect['target']] = value
        elif kind == 'opaque_effect':
            if effect.get('callee_kind') != 'inline_asm':
                raise UnsupportedLLVM('reachable external call: '+str(effect.get('callee')))
            asm = extract_asm(effect, dict(function=name, node=pc, location=node.get('source')))
            if not asm['complete']:
                raise UnsupportedLLVM('unknown reachable asm effect')
            inputs = []
            for binding in asm['bindings']:
                inputs.append(binding if binding['kind'] == 'output' else evaluator.evaluate(binding['value']))
            def read(operand):
                if operand['kind'] == 'llvm_operand':
                    value = inputs[operand['index']]
                    if not isinstance(value, Scalar):
                        raise UnsupportedLLVM('asm reads an output before defining it')
                    if not is_true(value.defined):
                        raise UnsupportedLLVM('asm input may be poison/undefined')
                    # Clang supplies an XLEN-wide physical register for r constraints.
                    if value.bits.size() < 64:
                        if not z3.is_bv_value(z3.simplify(value.bits)) or z3.simplify(value.bits).as_long() != 0:
                            raise UnsupportedLLVM('nonzero narrow asm input extension is not established')
                        value = scalar(0, 64)
                    return value
                if operand['kind'] == 'register':
                    return temps[operand['index']]
                if operand['kind'] == 'local_label_address':
                    return Scalar(z3.BitVec(f'{pc}_asm_label', 64))
                raise UnsupportedLLVM('unsupported asm operand')
            def write(operand, value):
                if operand['kind'] == 'llvm_operand':
                    output = inputs[operand['index']]
                    if not isinstance(output, dict) or output.get('kind') != 'output':
                        raise UnsupportedLLVM('asm attempts to overwrite an input-only operand')
                    evaluator.values[output['target']] = value
                elif operand['kind'] == 'register' and operand['index'] != 0:
                    temps[operand['index']] = value
            for index, step in enumerate(asm['steps']):
                if step['kind'] in ('label', 'alignment'):
                    continue
                event = deepcopy(step)
                if step['kind'] == 'label_address':
                    write(step['destination'], read(step['value']))
                elif step['kind'] == 'csr':
                    csr = step['csr']
                    old = Scalar(z3.Concat(*reversed(pmp.cfg))) if csr == 'pmpcfg0' else Scalar(pmp.addr[int(csr[7:])]) if csr.startswith('pmpaddr') and int(csr[7:]) < 8 else auxiliary.get(csr)
                    if old is None:
                        raise UnsupportedLLVM('CSR outside the configured eight-entry profile: '+csr)
                    if step['csr_write']:
                        requested = read(step['value'])
                        event['requested'] = z3.simplify(requested.bits).sexpr()
                        event['_requested_expr'] = requested.bits
                        if csr == 'mtvec':
                            auxiliary[csr] = requested
                        else:
                            pmp, supported = pmp.write(csr, requested.bits)
                            if not is_true(supported) or not is_true(z3.And(*[c & 0x60 == 0 for c in pmp.cfg])):
                                raise UnsupportedLLVM('unmodeled PMP WARL write')
                    if step['csr_read']:
                        write(step['destination'], old)
                elif step['kind'] == 'fence':
                    if not step['full_scope']:
                        raise UnsupportedLLVM('selective fence needs additional semantics')
                    last_fence = len(operations)
                else:
                    raise UnsupportedLLVM('unsupported asm effect')
                event['pmp_after'] = pmp_snapshot(pmp)
                event['llvm_node'] = pc
                event['asm_index'] = index
                operations.append(event)
                cut(pc+f':asm:{index}')
        elif kind == 'return':
            result = None if effect['value'] is None else evaluator.evaluate(effect['value'])
            if result is not None and (not is_true(result.defined) or not is_true(result.bits == 0)):
                raise UnsupportedLLVM('helper did not return success')
            return dict(function=name, region=region, initial_pmp=initial, operations=operations,
                        cuts=cuts, llvm_trace=llvm_trace, return_value=0,
                        metadata_contract='one valid private-region record; not boot-to-helper reachability',
                        auxiliary_state_restored=is_true(auxiliary['mtvec'].bits == 0x80000000))
        elif kind != 'control':
            raise UnsupportedLLVM('unsupported reachable helper effect: '+kind)
        if edge['target'] is None:
            raise UnsupportedLLVM('helper terminated without a modeled return')
        if 'predecessor_block' in edge:
            predecessor = edge['predecessor_block']
        pc = edge['target']
    raise UnsupportedLLVM('helper execution limit reached')
