"""Finite structural call expansion and straight-line memory relations.

These transformations preserve LLVM expressions, not a machine executable.
No access-control policy is introduced. Opaque effects remain barriers.
"""
from copy import deepcopy


def rewrite(value, ids):
    if isinstance(value, list):
        return [rewrite(v, ids) for v in value]
    if isinstance(value, dict):
        return {k: rewrite(v, ids) for k, v in value.items()}
    if isinstance(value, str):
        return ids.get(value, value)
    return value


def expand_calls(report, roots=None, max_depth=4, max_nodes=20000):
    if max_depth < 0 or max_nodes < 1:
        raise ValueError('invalid call expansion limits')
    functions = {f['id']: f for f in report['functions']}
    by_name = {f['name']: f for f in report['functions']}
    selected = [f for f in report['functions'] if not f['declaration']] if roots is None else []
    for name in roots or []:
        if name not in by_name:
            raise ValueError('unknown root function: '+name)
        if by_name[name]['declaration']:
            raise ValueError('root has no definition: '+name)
        selected.append(by_name[name])
    output = []
    remaining = []
    for root in selected:
        result = dict(id=root['id'], name=root['name'], entry=root['entry'],
                      parameters=deepcopy(root['parameters']), declaration=False,
                      nodes=[], transitions=[], blocks=[], expansions=[])
        node_count = 0

        def clone(function, prefix, depth, ancestry):
            nonlocal node_count
            ids = {}
            for block in function['blocks']:
                ids[block['id']] = prefix+block['id']
                for phi in block['phis']:
                    ids[phi['id']] = prefix+phi['id']
            for node in function['nodes']:
                ids[node['id']] = prefix+node['id']
            for param in function['parameters']:
                ids[param['id']] = prefix+param['id']
            nodes = rewrite(deepcopy(function['nodes']), ids)
            edges = rewrite(deepcopy(function['transitions']), ids)
            node_count += len(nodes)
            if node_count > max_nodes:
                raise ValueError('call expansion node limit exceeded; reduce roots/depth')
            result['nodes'].extend(nodes)
            result['blocks'].extend(rewrite(deepcopy(function['blocks']), ids))
            indexed = {n['id']: n for n in nodes}
            for edge in edges:
                effect = edge['effect']
                node = indexed[edge['source']]
                if effect['kind'] != 'opaque_effect' or node.get('opcode') != 'call' or effect.get('callee_kind') != 'direct':
                    result['transitions'].append(edge)
                    continue
                callee = functions.get(effect['callee']['id'])
                reason = None
                if callee is None or callee['declaration']:
                    reason = 'definition unavailable'
                elif depth >= max_depth:
                    reason = 'call expansion depth limit'
                elif callee['id'] in ancestry:
                    reason = 'recursive call requires a summary'
                elif callee.get('abi_attributes') or effect.get('abi_attributes'):
                    reason = 'ABI-affecting attributes require call-frame semantics'
                elif callee.get('calling_convention', 0) or effect.get('calling_convention', 0):
                    reason = 'nondefault calling convention requires semantics'
                elif callee.get('variadic') or len(effect['arguments']) != len(callee['parameters']):
                    reason = 'variadic/mismatched arguments require semantics'
                elif (callee.get('return_type') != node['result_type'] or
                      any(p['type'] != arg['type'] for p, arg in zip(callee['parameters'], effect['arguments']))):
                    reason = 'call signature does not match the available definition'
                elif any(word in node['llvm'] for word in ('musttail ', ' tail ', 'deopt', 'funclet')):
                    reason = 'special call contract requires semantics'
                if reason:
                    edge['effect']['expansion_blocked'] = reason
                    remaining.append(dict(root=root['name'], node=node['id'], reason=reason))
                    result['transitions'].append(edge)
                    continue
                call_prefix = node['id']+':call:'
                entry, return_edges, callee_params = clone(callee, call_prefix, depth+1, ancestry+(callee['id'],))
                bindings = [{'target': p['id'], 'value': arg} for p, arg in zip(callee_params, effect['arguments'])]
                result['transitions'].append(dict(source=edge['source'], target=entry, guard=edge['guard'],
                    effect=dict(kind='call_enter', assignments=bindings, simultaneous=True,
                        callsite=node['id'], contract_llvm=node['llvm'],
                        definedness_contracts_pending=True,
                        memory='shared', allocation_lifetime='fresh dynamic invocation')))
                for ret in return_edges:
                    returned = ret['effect']['value']
                    if bool(effect['result']) != (returned is not None):
                        raise ValueError('inconsistent call/return types in extracted graph')
                    ret['target'] = edge['target']
                    ret['effect'] = dict(kind='call_return', assignments=[] if returned is None else
                        [dict(target=effect['result'], value=returned)],
                        callsite=node['id'], invalidate_allocations_from=call_prefix,
                        contract_llvm=node['llvm'])
                result['expansions'].append(dict(callsite=node['id'], callee=callee['name'], entry=entry, depth=depth+1))
            returns = [e for e in result['transitions'] if e['source'] in indexed and e['effect']['kind'] == 'return']
            return ids[function['entry']], returns, rewrite(deepcopy(function['parameters']), ids)

        clone(root, '', 0, (root['id'],))
        # Cycles of cloned CFGs remain in transitions; no path/loop expansion.
        result['unexpanded_effects'] = [e['source'] for e in result['transitions'] if e['effect']['kind'] == 'opaque_effect']
        output.append(result)
    return dict(schema='smpreempt.llvm-expanded.v1', input=report['input'],
                target=report['target'], datalayout=report['datalayout'],
                canonical_ir=report['canonical_ir'], globals=deepcopy(report['globals']),
                functions=output, remaining_calls=remaining,
                limits=dict(max_depth=max_depth, max_nodes_per_root=max_nodes),
                semantics='structural call expansion; call contracts retained, not evaluated; no access policy')


def substitute(value, environment):
    if isinstance(value, dict):
        if value.get('kind') == 'reference' and value['id'] in environment:
            # Expressions in the environment already refer to entry values.
            return deepcopy(environment[value['id']])
        return {k: substitute(v, environment) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, environment) for v in value]
    return value


def summarize_segments(graph, max_expression_nodes=100000):
    """Compose finite linear regions; stop before opaque/call/lifetime effects.

    Memory is a persistent expression: every load names the memory version it
    observes. Intermediate prefixes are retained for later interruption queries.
    """
    results = []
    for f in graph['functions']:
        if f['declaration']:
            continue
        nodes = {n['id']: n for n in f['nodes']}
        incoming = {n: [] for n in nodes}
        outgoing = {n: [] for n in nodes}
        for e in f['transitions']:
            outgoing[e['source']].append(e)
            if e['target'] in incoming:
                incoming[e['target']].append(e)
        visited, segments = set(), []
        starts = [n for n in nodes if n == f['entry'] or len(incoming[n]) != 1 or
                  len(outgoing[incoming[n][0]['source']]) != 1 or
                  nodes[incoming[n][0]['source']]['block'] != nodes[n]['block']]
        for start in starts+list(nodes):
            if start in visited:
                continue
            environment, memory, effects, prefixes = {}, {'kind': 'entry_memory'}, [], []
            current, path = start, []
            while current not in visited:
                visited.add(current)
                path.append(current)
                edges = outgoing[current]
                if len(edges) != 1:
                    break
                e, effect = edges[0], edges[0]['effect']
                kind = effect['kind']
                if kind == 'assign':
                    environment[effect['target']] = substitute(effect['expression'], environment)
                    if effect['expression'].get('operator') == 'freeze':
                        environment[effect['target']]['ssa_binding'] = effect['target']
                elif kind == 'parallel_phi':
                    updates = {}
                    for phi in effect['assignments']:
                        updates[phi['target']] = dict(operator='phi_select', selector='entry_predecessor_block',
                            incoming=substitute(phi['incoming'], environment))
                    environment.update(updates)
                elif kind == 'load':
                    environment[effect['target']] = dict(operator='load', memory=memory,
                        **{k: substitute(v, environment) for k, v in effect.items() if k not in ('target', 'kind')})
                elif kind == 'store':
                    memory = dict(operator='store', memory=memory,
                                  **{k: substitute(v, environment) for k, v in effect.items() if k != 'kind'})
                elif kind in ('control', 'return', 'unreachable'):
                    effects.append(substitute(effect, environment))
                else:
                    effects.append(dict(kind='barrier', node=current, effect=deepcopy(effect)))
                    break
                snapshot = dict(after=current, values=deepcopy(environment), memory=deepcopy(memory))
                prefixes.append(snapshot)
                # Protect against expression blowup while retaining an explicit incomplete result.
                def count(v):
                    if isinstance(v, dict):
                        return 1+sum(count(x) for x in v.values())
                    if isinstance(v, list):
                        return 1+sum(count(x) for x in v)
                    return 1
                if count(snapshot) > max_expression_nodes:
                    effects.append(dict(kind='barrier', node=current, reason='expression size limit'))
                    break
                target = e['target']
                if target is None or target in visited or len(incoming[target]) != 1 or nodes[target]['block'] != nodes[current]['block']:
                    break
                current = target
            exits = []
            for e in outgoing[current]:
                exits.append(dict(target=e['target'], guard=substitute(e['guard'], environment),
                                  predecessor_block=e.get('predecessor_block')))
            segments.append(dict(entry=start, nodes=path, values=environment, memory=memory,
                                 effects=effects, prefixes=prefixes, exits=exits,
                                 complete=not any(e['kind'] == 'barrier' for e in effects)))
        results.append(dict(function=f['name'], id=f['id'], segments=segments))
    return dict(schema='smpreempt.llvm-segments.v1', input=graph['input'], functions=results,
                semantics='LLVM expression composition; intermediate memory versions retained; no reachability claim')
