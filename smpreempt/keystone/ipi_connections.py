"""Evidence and explicitly conditional transport links for Keystone PMP IPIs."""
from collections import defaultdict, deque
from copy import deepcopy


def describe_ipi_connections(shared):
    functions = {f['id']: f for f in shared['graph']['functions']}
    by_name = {f['name']: f for f in functions.values()}
    calls = shared['calls']
    indirect = []
    packets = []
    for call in calls:
        for candidate in call['candidates']:
            target = functions[candidate['target']]['name']
            if candidate['kind'] != 'conditional_field_candidate':
                continue
            if target in ('tlb_update', 'tlb_sync', 'tlb_process'):
                facts = [e for e in candidate['evidence'] if e.get('global_name')=='tlb_ops']
            elif target == 'sbi_pmp_ipi_local_update':
                facts = [e for e in candidate['evidence'] if e.get('function')=='send_and_sync_pmp_ipi']
                packets.extend(facts)
            else:
                continue
            if facts:
                indirect.append(dict(caller=functions[call['caller']]['name'], callsite=call['callsite'],
                    target=target, loaded_field=call.get('loaded_field'), condition=candidate['condition'],
                    evidence=deepcopy(facts), residual_unknown=call['residual_unknown']))
    registrations = []
    for f in shared['graph']['functions']:
        effects = {e['source']:e['effect'] for e in f['transitions']}
        for node, effect in effects.items():
            if effect.get('callee', {}).get('name') != 'sbi_ipi_event_create':
                continue
            if not effect['arguments'] or effect['arguments'][0].get('name') != 'tlb_ops':
                continue
            stores = [dict(node=n, effect=deepcopy(e)) for n,e in effects.items()
                      if e['kind']=='store' and e['value'].get('id')==effect['result']
                      and e['address'].get('name')=='tlb_event']
            registrations.append(dict(function=f['name'], node=node, call=deepcopy(effect), result_stores=stores))
    queue_calls = defaultdict(list)
    for f in shared['graph']['functions']:
        for edge in f['transitions']:
            effect = edge['effect']
            name = effect.get('callee', {}).get('name')
            if name in ('sbi_fifo_enqueue', 'sbi_fifo_dequeue'):
                queue_calls[(f['name'], name)].append(dict(function=f['name'], node=edge['source'],
                    queue=deepcopy(effect['arguments'][0]), packet=deepcopy(effect['arguments'][1]),
                    result=effect['result']))
    transfers = []
    for send in queue_calls[('tlb_update','sbi_fifo_enqueue')]:
        for receive in queue_calls[('tlb_process','sbi_fifo_dequeue')]+queue_calls[('tlb_process_count','sbi_fifo_dequeue')]:
            transfers.append(dict(kind='conditional_queue_transport', enqueue=send, dequeue=receive,
                conditions=['Both calls succeed.', 'Both queue pointers denote the same live FIFO.',
                            'The dequeued element is this enqueued packet, accounting for FIFO order and other requests.',
                            'Entry size covers the callback and PMP request fields; no intervening invalid mutation.'],
                assumed_relation='dequeued packet bytes equal enqueued packet bytes at enqueue time',
                assumptions=['Queue transport contract; not a proved alias, scheduling, memory-order or FIFO invariant.'],
                modeled_as='cross-hart data/event relation, not a synchronous call or return edge'))
    # Retain the copy-call sites in the actual queue implementation as evidence;
    # their presence does not by itself prove the transport contract.
    copy_sites = []
    for name in ('sbi_fifo_enqueue','sbi_fifo_dequeue'):
        if name in by_name:
            for e in by_name[name]['transitions']:
                if e['effect'].get('callee', {}).get('name')=='sbi_memcpy':
                    copy_sites.append(dict(function=name,node=e['source'],effect=deepcopy(e['effect'])))
    adjacency = defaultdict(list)
    for call in calls:
        for candidate in call['candidates']:
            adjacency[call['caller']].append((candidate['target'],call['callsite'],candidate['kind']))
    paths = []
    for start in ('destroy_enclave','sbi_ipi_process'):
        if start not in by_name or 'pmp_unset' not in by_name:
            continue
        pending = deque([(by_name[start]['id'],[])])
        seen = set()
        while pending:
            node, path = pending.popleft()
            if node in seen:
                continue
            seen.add(node)
            if functions[node]['name']=='pmp_unset':
                paths.append(dict(start=start, target='pmp_unset', calls=path,
                    interpretation='structural function chain; conditional callbacks and CFG branch feasibility are not discharged'))
                break
            for target,site,kind in adjacency[node]:
                pending.append((target,path+[dict(caller=functions[node]['name'],target=functions[target]['name'],
                                                 callsite=site,kind=kind)]))
    unique_packets = {p['node']:p for p in packets}
    return dict(schema='smpreempt.keystone-ipi-connections.v1', input=shared['input'],
        registrations=registrations, packet_callback_stores=list(unique_packets.values()),
        dispatch_candidates=indirect, queue_transfers=transfers, queue_copy_evidence=copy_sites,
        structural_paths=paths,
        status='conditional_connections_extracted',
        unresolved=['Runtime event registration and event-ID routing invariant.',
                    'Pointer aliasing, queue identity and packet preservation across hart transport.',
                    'Callback target completeness, delivery, progress and timing.',
                    'PMP write acceptance, exceptions and effective access permissions.'])
