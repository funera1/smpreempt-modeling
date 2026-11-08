"""Annotate LLVM CFG edges with declarative RISC-V operation effects.

No reachability, access policy, or attack predicate is evaluated. Unknown effects
are retained as barriers. Inline assembly is an ordered nested operation list,
not a claim that LLVM instruction boundaries equal final machine boundaries.
"""
from copy import deepcopy

from smpreempt.extraction.llvm_transforms import expand_calls
from smpreempt.extraction.riscv_asm_effects import extract_asm
from smpreempt.model.riscv_memory_operations import BY_ID, STATE


def operation(identifier, evidence, **details):
    template = BY_ID.get(identifier)
    return dict(catalogue_id=identifier, evidence=evidence,
                may_change=deepcopy(template['may_change']) if template else (['csr', 'registers'] if identifier == 'auxiliary.csr.mtvec' else ['unknown']),
                semantics='declarative; hardware profile and exception semantics unresolved',
                **details)


def classify(node, effect):
    opcode = node.get('opcode')
    kind = effect['kind']
    operations = []
    assumptions = []
    unresolved = []
    if effect.get('callee_kind') == 'inline_asm':
        try:
            asm = extract_asm(effect)
        except ValueError as exc:
            asm = dict(steps=[], complete=False, reason=str(exc))
        for index, step in enumerate(asm['steps']):
            identifier = step.get('catalogue_id')
            if step.get('unknown_csr'):
                unresolved.append('CSR has no declared state-effect mapping: '+step['csr'])
            if identifier:
                operations.append(operation(identifier, 'inline-assembly syntax', ordinal=index, instruction=step))
            elif step['kind'] in ('label_address', 'alignment'):
                unresolved.append('Assembler pseudo/alignment machine boundaries unresolved.')
            elif step['kind'] == 'unknown':
                unresolved.append(step.get('reason', 'unknown assembly'))
        if not asm['complete']:
            unresolved.append(asm.get('reason', 'inline assembly contains unsupported operations'))
        assumptions.append('Assembly operands are LLVM constraint bindings; register allocation and pseudo expansion require final machine code.')
        if '~{memory}' in effect.get('constraints', ''):
            assumptions.append('The memory clobber is a compiler constraint, not a hardware fence or an additional memory store.')
        return operations, assumptions, unresolved, asm
    memory_op = effect.get('operation', kind)
    if memory_op in ('load', 'store'):
        operations.append(operation('memory.'+memory_op, 'LLVM memory instruction',
                                    llvm_effect=deepcopy(effect)))
        assumptions.append('LLVM addresses remain IR pointers; physical address translation and PTE identity are not inferred.')
    elif opcode in ('atomicrmw', 'cmpxchg'):
        operations.append(dict(catalogue_id=None, evidence='LLVM atomic instruction',
                               may_change=['memory', 'values', 'ordering'],
                               semantics='atomic LLVM operation; RISC-V lowering unresolved'))
        unresolved.append('Atomic lowering may use AMO or LR/SC; no machine instruction sequence inferred.')
    elif opcode == 'fence':
        operations.append(dict(catalogue_id=None, evidence='LLVM fence instruction',
                               may_change=['ordering'], semantics='LLVM ordering; hardware fence lowering unresolved'))
        unresolved.append('LLVM fence is not assigned an exact RISC-V encoding.')
    elif effect.get('callee_kind') == 'direct':
        name = effect.get('callee', {}).get('name', '')
        if name.startswith(('llvm.memset.', 'llvm.memcpy.', 'llvm.memmove.')):
            operations.append(dict(catalogue_id=None, evidence='LLVM memory intrinsic',
                                   may_change=['memory'], intrinsic=name,
                                   semantics='bulk IR memory effect; not an atomic machine operation'))
            unresolved.append('Memory intrinsic lowering and intermediate machine states unresolved.')
    if effect.get('definedness_contracts_pending'):
        unresolved.append('Expanded call retains unevaluated LLVM definedness contracts.')
    if kind == 'opaque_effect':
        unresolved.append(effect.get('reason', 'effect semantics unavailable'))
    return operations, assumptions, unresolved, None


def extract_abstract_transitions(report, roots=None, max_depth=4, max_nodes=20000, *, expand=True):
    """Keep every graph edge and attach mappings; direct calls use bounded cloning.

    Recursion, unavailable definitions and call contracts remain explicit. The
    depth bound limits structural expansion, not loop traversal or path search.
    """
    source = deepcopy(report)
    for function in source['functions']:
        for node in function['nodes']:
            node['implementation'] = dict(function=function['name'], node=node['id'],
                instruction=node.get('llvm'), source_location=deepcopy(node.get('source')),
                source_location_available=node.get('source') is not None)
    # Preserve origin IDs across clone identifier rewriting by restoring from
    # the original instruction table after expansion.
    origins = {n['id']: deepcopy(n['implementation']) for f in source['functions'] for n in f['nodes']}
    if expand:
        graph = expand_calls(source, roots=roots, max_depth=max_depth, max_nodes=max_nodes)
    else:
        if roots is not None:
            raise ValueError('shared annotation expects a preselected graph, without roots')
        graph = source
    barriers = 0
    for function in graph['functions']:
        nodes = {n['id']: n for n in function['nodes']}
        for node in nodes.values():
            original = node['id'].rsplit(':call:', 1)[-1]
            node['implementation'] = deepcopy(origins[original])
        for index, edge in enumerate(function['transitions']):
            node = nodes[edge['source']]
            ops, assumptions, unresolved, asm = classify(node, edge['effect'])
            if isinstance(edge['guard'], dict) and edge['guard'].get('kind') == 'opaque_successor_condition':
                unresolved.append('Successor condition not modeled.')
            changes = {'pc'}
            if 'predecessor_block' in edge:
                changes.add('predecessor_block')
            if edge['effect']['kind'] in ('allocate', 'call_enter', 'call_return'):
                changes.add('llvm_objects')
            if edge['effect']['kind'] in ('assign', 'parallel_phi', 'load', 'allocate', 'call_enter', 'call_return'):
                changes.add('values')
            if edge['effect']['kind'] == 'opaque_effect':
                changes.add('unknown')
            for op in ops:
                changes.update(op['may_change'])
            edge['abstract'] = dict(id=f"{function['id']}:t{index}", operations=ops,
                may_change=sorted(changes), facts=dict(implementation=deepcopy(node['implementation']),
                    graph_source=edge['source'], graph_target=edge['target'],
                    guard=deepcopy(edge['guard']), llvm_effect=deepcopy(edge['effect'])),
                assumptions=assumptions, unresolved=unresolved,
                barrier=bool(unresolved), assembly=asm)
            barriers += bool(unresolved)
    return dict(schema='smpreempt.abstract-transitions.v1', input=deepcopy(report['input']),
        target=report['target'], datalayout=report['datalayout'],
        state={**STATE, 'values': 'LLVM SSA bindings; not physical GPR allocation',
               'predecessor_block': 'LLVM block selected for PHI assignments',
               'llvm_objects': 'IR allocation identity and invocation lifetime'},
        graph=graph, barrier_edges=barriers,
        assumptions=['Structural normal CFG only; exception/trap paths need a hardware and runtime profile.',
                     'No secrecy, ownership, PTE role, effective access permissions, or reachability inferred.',
                     'Catalogue may_change lists are conservative declarative possibilities, not observed hardware writes.',
                     'Call expansion retains unresolved contracts; recursive and external calls remain barriers.'],
        analysis_scope='model extraction only; no vulnerability or exploitability analysis')
