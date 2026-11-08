"""Host-read counterexamples at actual extracted PMP-helper boundaries.

Conditions are explicit: one private-region metadata record, a candidate PM,
a representative cached permission, and (for erase) a recognized loop summary.
No A/R-history policy or boot-to-entry reachability assumption is hidden here.
"""
from dataclasses import asdict
from copy import deepcopy
import z3

from smpreempt.model.riscv_model import State, E, P, Machine, Insn, PM, step, check_access
from smpreempt.model.symbolic_pmp import SymbolicPMP
from smpreempt.model.symbolic_cache import SymbolicCachedAccess
from smpreempt.keystone.keystone_pmp_paths import RegionMetadata, initial_pmp

HOST_ENTRY = 0x80200000
POLICIES = ('preserve', 'enable_host_no_sync', 'enable_host_sync', 'protect_target_sync', 'os_only_sync')


def candidate_pm(pmp, region, name):
    if name not in POLICIES:
        raise ValueError('unknown PM candidate')
    cfg, addr = list(pmp.cfg), list(pmp.addr)
    if name != 'preserve':
        cfg[7], addr[7] = z3.BitVecVal(0x1f, 8), z3.BitVecVal((1 << 54)-1, 64)
    if name == 'protect_target_sync':
        cfg[region.register_index] = z3.BitVecVal(region.mode, 8)
        addr[region.register_index] = z3.BitVecVal(region.encoded_address, 64)
        if region.mode == 8:
            cfg[region.register_index-1] = z3.BitVecVal(0, 8)
            addr[region.register_index-1] = z3.BitVecVal(region.base >> 2, 64)
    if name == 'os_only_sync':
        for i in range(1, 7):
            cfg[i] = z3.BitVecVal(0, 8)
    return SymbolicPMP(tuple(cfg), tuple(addr)), name.endswith('_sync') and name != 'enable_host_no_sync'


def model_pmp(model, pmp):
    return P(cfg=[model.eval(c, model_completion=True).as_long() for c in pmp.cfg],
             addr=[model.eval(a, model_completion=True).as_long() for a in pmp.addr])


def replay_read(path, cut, region, processed, address, host_pmp, sync, cached, model):
    """Replay PMP/cache and the selected read in two memory worlds."""
    observations, traces = [], []
    for secret in (0xA5, 0x5A):
        state = State()
        state.E.pc, state.E.priv = 0x80001000, 'M'
        state.E.csr['mtvec'] = 0x80000000
        state.P = deepcopy(path['initial_pmp'])
        state.V.cache_pmp_permissions = True
        state.M.store(address, 1, secret)
        trace = []
        if path.get('cache_seeded'):
            state.E.priv = 'S'
            state.E.pc = region.base+0x100
            check_access(state, state.E.pc, 4, 'X')
            state.E.put(10, region.base)
            state = step(state, Insn('LBU', rd=12, rs1=10))
            trace.append(dict(actor='C', operation='LBU', address=region.base,
                              purpose='legal cached permission provenance'))
            state.E.priv = 'M'
            state.E.pc = 0x80001000
        for i in range(processed):
            state.M.store(region.base+i, 1, 0)
        for event in path['operations'][:cut['operation_count']]:
            if event['kind'] == 'csr' and event['csr_write']:
                value = model.eval(event['_requested_expr'], model_completion=True).as_long()
                state.E.put(31, value)
                state = step(state, Insn('CSRW', rs1=31, csr=event['csr']))
                trace.append(dict(actor='SM', operation='CSRW', csr=event['csr'], value=value))
            elif event['kind'] == 'fence':
                state = step(state, Insn('SFENCE.VMA'))
                trace.append(dict(actor='SM', operation='SFENCE.VMA'))
        expected = model_pmp(model, cut['pmp'])
        if state.P != expected:
            raise AssertionError('extracted PMP updates differ from concrete replay')
        host = Machine(state).preempt(PM(host_pmp, sync_pmp=sync), check_policy=False)
        host.S.E.pc = HOST_ENTRY  # explicit entry in this candidate PM profile
        check_access(host.S, HOST_ENTRY, 4, 'X')
        host.S.E.put(10, address)
        host = host.instruction(Insn('LBU', rd=12, rs1=10), use_cached=cached)
        observed = host.S.E.get(12)
        observations.append(observed)
        trace.append(dict(actor='PM', operation='atomic candidate switchout', sync=sync))
        trace.append(dict(actor='H', operation='LBU', address=address, observed=observed,
                          permission_source='cached' if cached else 'current'))
        traces.append(trace)
    if observations[0] == observations[1]:
        raise AssertionError('Host observations did not differ')
    return dict(observations=observations, projection_replayed=True, traces=traces,
                scope='PMP/cache and byte-read projection; not final ELF/trap-vector replay')


def analyze_cuts(path, region, *, context, processed=None, timeout_ms=10000):
    if timeout_ms < 1:
        raise ValueError('timeout must be positive')
    prefix = context.replace('-', '_')
    k = z3.BitVec(prefix+'_processed', 64) if processed is None else z3.BitVecVal(processed, 64)
    if processed is not None and not 0 <= processed <= region.size:
        raise ValueError('invalid processed prefix')
    address = z3.BitVec(prefix+'_host_byte', 64)
    initial = SymbolicPMP.concrete(path['initial_pmp'])
    cache = SymbolicCachedAccess.seed(initial, z3.BitVecVal(region.base, 64), 1, 'S') if path.get('cache_seeded') else SymbolicCachedAccess.from_concrete(None)
    domain = z3.And(z3.ULE(k, region.size), z3.UGE(address, region.base), z3.ULT(address, region.base+region.size))
    unready = z3.UGE(address, region.base+k)
    result = {}
    for policy in POLICIES:
        rows = []
        for index, cut in enumerate(path['cuts']):
            host, sync = candidate_pm(cut['pmp'], region, policy)
            host_cache = cache.invalidate() if cut['cache_invalidated'] or sync else cache
            feasible = z3.And(cut['pmp'].installable(host), host.installable(cut['pmp']))
            entry = host.allow(z3.BitVecVal(HOST_ENTRY, 64), 4, 'X')
            current_read = host.allow(address, 1, 'R')
            cached_read = host_cache.allow(host, address, 1, 'R', 'S', True)
            effective_read = z3.Or(current_read, cached_read)
            effective_write = z3.Or(host.allow(address, 1, 'W'), host_cache.allow(host, address, 1, 'W', 'S', True))
            def query(condition):
                solver = z3.Solver()
                solver.set(timeout=timeout_ms)
                solver.add(domain, condition)
                status = solver.check()
                return solver, status
            row = dict(cut=index, position=cut['position'], operation_count=cut['operation_count'], source=cut.get('source'))
            for name, condition in (
                ('pm_feasible', feasible), ('host_start', z3.And(feasible, entry)),
                ('unready_fresh_read', z3.And(feasible, entry, unready, current_read)),
                ('unready_effective_read', z3.And(feasible, entry, unready, effective_read)),
                ('host_write_access', z3.And(feasible, entry, effective_write))):
                solver, status = query(condition)
                row[name] = str(status)
                if status == z3.unknown:
                    row[name+'_reason'] = solver.reason_unknown()
                if name == 'unready_effective_read' and status == z3.sat:
                    model = solver.model()
                    a = model.eval(address, model_completion=True).as_long()
                    kk = model.eval(k, model_completion=True).as_long()
                    via_cache = not z3.is_true(model.eval(current_read, model_completion=True))
                    row['witness'] = dict(address=hex(a), processed=kk, size=region.size,
                        current_pmp_readable=not via_cache, permission_source='cached' if via_cache else 'current',
                        host_pmp=asdict(model_pmp(model, host)),
                        replay=replay_read(path, cut, region, kk, a, model_pmp(model, host), sync, via_cache, model))
            if row['pm_feasible'] == 'unsat':
                row['classification'] = 'pm_infeasible'
            elif row['host_start'] == 'unsat':
                row['classification'] = 'host_cannot_start'
            elif row['unready_effective_read'] == 'sat':
                row['classification'] = 'read_counterexample_under_contract'
            elif any(row.get(key) == 'unknown' for key in ('pm_feasible','host_start','unready_effective_read')):
                row['classification'] = 'unknown'
            else:
                row['classification'] = 'no_read_counterexample_in_this_scenario'
            rows.append(row)
        result[policy] = dict(cuts=rows, counterexample_cuts=[r['cut'] for r in rows if 'witness' in r],
            integrity='not checked; host_write_access is exposure, not proof of invalid trusted use')
    return dict(context=context, region=asdict(region), processed='symbolic 0..size' if processed is None else processed,
                cache_provenance='legal prior enclave S-mode access under initial PMP' if path.get('cache_seeded') else 'none at entry',
                policies=result, assumptions=['single hart; M-mode helper with MPRV off; Bare identity access',
                    'private content is an entry contract, not inferred from bits or access history',
                    'PM CPU/save-area isolation is trusted and PM executes atomically',
                    'eight-entry base PMP profile matching generic configuration; no Smepmp',
                    'one representative permitted permission cache; not a specific chip TLB'],
                reachability='actual helper path under metadata contract; no boot-to-entry proof')


def release_callsite_order(report):
    """Check same-block, same-rid scrub-before-unset facts in actual LLVM."""
    findings = []
    for f in report['functions']:
        if f['name'] != 'destroy_enclave':
            continue
        effects = {e['source']: e['effect'] for e in f['transitions']}
        def callee(effect):
            return effect.get('callee', {}).get('name') if effect else None
        for block in f['blocks']:
            ids = block['instructions']
            for index, node in enumerate(ids):
                effect = effects[node]
                if callee(effect) != 'sbi_memset':
                    continue
                args = effect['arguments']
                if args[1].get('bits_unsigned') != '0':
                    continue
                pointer = effects.get(args[0].get('id'), {}).get('expression', {})
                if pointer.get('operator') != 'inttoptr':
                    continue
                base = effects.get(pointer['operands'][0].get('id'))
                size = effects.get(args[2].get('id'))
                if callee(base) != 'pmp_region_get_addr' or callee(size) != 'pmp_region_get_size':
                    continue
                rid = base['arguments'][0]
                if size['arguments'][0] != rid:
                    continue
                for later in ids[index+1:]:
                    release = effects[later]
                    if callee(release) == 'pmp_unset_global' and release['arguments'][0] == rid:
                        findings.append(dict(function=f['name'], block=block['id'], clear=node, release=later,
                            rid=rid, base_lookup=pointer['operands'][0], size_lookup=args[2],
                            fact='same-rid zero-fill returns before unset in this basic block',
                            limitation='external interference, faults and global reachability not proved'))
                        break
    return findings


def revocation_callsite_order(report):
    """Normal-CFG facts: revoke calls precede OS grant before normal return."""
    findings = []
    callers = []
    for f in report['functions']:
        if f['name'] not in ('exit_enclave', 'stop_enclave'):
            continue
        for edge in f['transitions']:
            if edge['effect'].get('callee', {}).get('name') == 'context_switch_to_host':
                callers.append(dict(function=f['name'], node=edge['source']))
    for f in report['functions']:
        if f['name'] != 'context_switch_to_host' or not callers:
            continue
        nodes = {n['id']: n for n in f['nodes']}
        outgoing = {}
        for e in f['transitions']:
            outgoing.setdefault(e['source'], []).append(e)
        def call(e, name, index, value):
            effect = e['effect']
            return (effect.get('callee', {}).get('name') == name and
                    effect['arguments'][index].get('bits_unsigned') == str(value))
        grants = {e['source'] for e in f['transitions'] if call(e, 'osm_pmp_set', 0, 7)}
        returns = {e['source'] for e in f['transitions'] if e['effect']['kind'] == 'return'}
        for e in f['transitions']:
            if not call(e, 'pmp_set_keystone', 1, 0):
                continue
            # Removing grant nodes must disconnect this continuation from all
            # ordinary returns. External calls/traps are not proved by this.
            pending, seen, bypass = [e['target']], set(), False
            while pending:
                at = pending.pop()
                if at is None or at in grants or at in seen:
                    continue
                seen.add(at)
                if at in returns:
                    bypass = True
                pending.extend(edge['target'] for edge in outgoing.get(at, []))
            if grants and not bypass:
                findings.append(dict(function=f['name'], revoke=e['source'], source=nodes[e['source']].get('source'),
                    rid=e['effect']['arguments'][0], os_grants=sorted(grants), callers=callers,
                    fact='every normal-CFG return after this revoke crosses an OS RWX grant',
                    limitation='normal CFG ordering only; external effects/traps/global reachability not proved'))
    return findings
