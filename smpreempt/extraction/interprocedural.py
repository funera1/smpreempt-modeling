"""Shared function CFGs, matched call/return links, conditional callback edges.

No call-depth bound or path enumeration. Field evidence yields candidates, never
an exhaustive points-to result. Residual unknown targets are always retained.
"""
from collections import defaultdict, deque
from copy import deepcopy

from smpreempt.extraction.abstract_transitions import extract_abstract_transitions


def signature_matches(function, node, effect):
    return (function['return_type'] == node['result_type']
            and (len(function['parameters']) <= len(effect['arguments']) if function.get('variadic')
                 else len(function['parameters']) == len(effect['arguments']))
            and all(p['type'] == a['type'] for p, a in zip(function['parameters'], effect['arguments']))
            and function.get('calling_convention', 0) == effect.get('calling_convention', 0))


def constant_offset(expression):
    offset = 0
    for term in expression['offset_terms']:
        if 'offset_bytes' in term:
            if term['offset_bytes'] is None:
                return None
            offset += term['offset_bytes']
        else:
            index = term['index']
            if 'bits_unsigned' not in index or term['scale_bytes'] is None:
                return None
            width = index['type']['integer_bits']
            value = int(index['bits_unsigned'])
            if value >= 1 << (width-1):
                value -= 1 << width
            offset += value*term['scale_bytes']
    return offset


def field_address(value, effects, seen=None):
    """Recover syntactic base + constant byte offset, without alias claims."""
    if value.get('kind') != 'reference':
        return None
    identifier = value['id']
    seen = set() if seen is None else seen
    if identifier in seen:
        return None
    seen = seen | {identifier}
    effect = effects.get(identifier, {})
    expr = effect.get('expression', {})
    if expr.get('operator') == 'getelementptr':
        offset = constant_offset(expr)
        base = field_address(expr['base'], effects, seen)
        return None if offset is None or base is None else (base[0], base[1]+offset)
    if expr.get('operator') in ('bitcast', 'addrspacecast'):
        return field_address(expr['operands'][0], effects, seen)
    return identifier, 0


def collect_field_evidence(report):
    functions = {f['id']: f for f in report['functions'] if not f['declaration']}
    evidence = []
    for global_ in report['globals']:
        elements = (global_.get('initializer') or {}).get('elements', [])
        for field in global_.get('layout', {}).get('fields', []):
            if field['index'] >= len(elements):
                continue
            value = elements[field['index']]
            if value.get('id') in functions:
                evidence.append(dict(target=value['id'], offset=field['offset'],
                    kind='global_initializer_field', global_id=global_['id'],
                    global_name=global_['name'], field_index=field['index'],
                    initializer=deepcopy(global_['initializer'])))
    for function in report['functions']:
        effects = {e['source']: e['effect'] for e in function['transitions']}
        nodes = {n['id']: n for n in function['nodes']}
        for node, effect in effects.items():
            if effect['kind'] != 'store' or effect['value'].get('id') not in functions:
                continue
            address = field_address(effect['address'], effects)
            if address is not None:
                evidence.append(dict(target=effect['value']['id'], offset=address[1],
                    kind='function_pointer_store', base=address[0], function=function['name'],
                    node=node, instruction=nodes[node].get('llvm'), source_location=nodes[node].get('source')))
    return evidence


def shared_interprocedural(report, roots=None):
    functions = {f['id']: f for f in report['functions'] if not f['declaration']}
    names = {f['name']: f['id'] for f in functions.values()}
    selected_roots = list(names) if roots is None else roots
    for root in selected_roots:
        if root not in names:
            raise ValueError('root has no definition: '+root)
    evidence = collect_field_evidence(report)
    field_targets = defaultdict(list)
    for item in evidence:
        if item['offset'] is not None:
            field_targets[item['offset']].append(item)
    calls = []
    for function in functions.values():
        effects = {e['source']: e['effect'] for e in function['transitions']}
        nodes = {n['id']: n for n in function['nodes']}
        for edge in function['transitions']:
            effect = edge['effect']
            if effect.get('callee_kind') not in ('direct', 'indirect'):
                continue
            node = nodes[edge['source']]
            record = dict(caller=function['id'], callsite=node['id'], continuation=edge['target'],
                llvm_guard=deepcopy(edge['guard']), arguments=deepcopy(effect['arguments']),
                result=effect['result'], candidates=[], residual_unknown=effect['callee_kind']=='indirect',
                instruction=node.get('llvm'), source_location=node.get('source'))
            if node.get('opcode') != 'call':
                record['unresolved'] = 'invoke/callbr requires exceptional control semantics'
                calls.append(record)
                continue
            if effect['callee_kind'] == 'direct':
                target = effect['callee'].get('id')
                if target in functions and signature_matches(functions[target], node, effect):
                    record['candidates'].append(dict(target=target, kind='direct', evidence=[]))
                else:
                    record['unresolved'] = 'definition unavailable or signature requires separate call semantics'
                    record['callee'] = effect['callee'].get('name')
            else:
                load = effects.get(effect['callee'].get('id'), {})
                address = field_address(load['address'], effects) if load.get('kind') == 'load' else None
                record['callee_value'] = deepcopy(effect['callee'])
                record['loaded_field'] = None if address is None else dict(base=address[0], offset=address[1])
                grouped = defaultdict(list)
                for item in field_targets.get(address[1], []) if address else []:
                    if signature_matches(functions[item['target']], node, effect):
                        grouped[item['target']].append(deepcopy(item))
                for target, facts in grouped.items():
                    record['candidates'].append(dict(target=target, kind='conditional_field_candidate', evidence=facts,
                        condition=dict(operator='pointer_equals_function', value=deepcopy(effect['callee']), function=target),
                        assumptions=['Same byte offset and signature suggest a candidate; object aliasing and packet transport are not established.',
                                     'Other targets remain possible; this is not a complete points-to analysis.']))
            calls.append(record)
    by_caller = defaultdict(list)
    for call in calls:
        by_caller[call['caller']].append(call)
    selected, pending = set(), deque(names[name] for name in selected_roots)
    while pending:
        identifier = pending.popleft()
        if identifier in selected:
            continue
        selected.add(identifier)
        for call in by_caller[identifier]:
            pending.extend(c['target'] for c in call['candidates'])
    subset = dict(report, functions=[f for f in report['functions'] if f['id'] in selected])
    result = extract_abstract_transitions(subset, expand=False)
    selected_calls = [c for c in calls if c['caller'] in selected]
    links = []
    for call in selected_calls:
        for candidate in call['candidates']:
            target = functions[candidate['target']]
            token = call['callsite']+'->'+target['id']
            links.append(dict(kind='call_enter', source=call['callsite'], target=target['entry'],
                callsite=call['callsite'], candidate_kind=candidate['kind'], token=token,
                guard=dict(llvm=call['llvm_guard'], target_condition=candidate.get('condition', True)),
                effect=dict(push_frame=dict(token=token, continuation=call['continuation'], result=call['result'],
                        variadic_arguments=call['arguments'][len(target['parameters']):]),
                    bind=[dict(parameter=p['id'], value=a) for p,a in zip(target['parameters'],call['arguments'])],
                    simultaneous=True, fresh_invocation=True),
                contracts='LLVM ABI, attributes, lifetime and definedness require separate semantics'))
            for edge in target['transitions']:
                if edge['effect']['kind'] == 'return':
                    links.append(dict(kind='call_return', source=edge['source'], target=call['continuation'],
                        callsite=call['callsite'], token=token,
                        guard=dict(stack_top_token=token),
                        effect=dict(pop_frame=True, bind_result=call['result'], value=edge['effect']['value'])))
    result.update(schema='smpreempt.shared-interprocedural.v1', roots=selected_roots,
        calls=selected_calls, interprocedural_links=links,
        representation='one CFG per function; matched stack tokens; no call-depth bound',
        traversal_rules=['Original call continuation edges remain as IR facts, not executable bypasses of modeled callees.',
            'At modeled calls take call_enter, then only returns with matching stack_top_token.',
            'Each dynamic invocation has fresh SSA/object bindings, even if the same static CFG is reused.',
            'External, residual indirect and opaque effects remain barriers; continuation needs an explicit contract.'],
        callback_evidence=evidence)
    result['state'].update(call_stack='unbounded matched call frames; no state-space exploration performed',
        values='SSA bindings qualified by dynamic invocation frame',
        llvm_objects='allocation identity qualified by dynamic invocation')
    result['assumptions'].append('Callback edges are conditional candidates based on field evidence, not proved dispatch targets or reachable executions.')
    return result
