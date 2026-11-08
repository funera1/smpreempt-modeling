"""Host-only direct-data attacks after an arbitrary interruption; no G/T4.

Fixed Bare/PMP/R within one Host epoch. Byte reads/writes summarize arbitrary
ordinary Host data accesses, without claiming full ISA or noninterference.
"""
from dataclasses import dataclass, replace

import z3

from smpreempt.analysis.preemption import interruption_domain, protected_at, switchout_state, validate_host_template
from smpreempt.model.riscv_model import E, Insn, Machine, P, State, V, _pmp_installable, step
from smpreempt.analysis.symbolic_system import SystemState
from smpreempt.model.symbolic_cache import SymbolicCachedAccess
from smpreempt.model.symbolic_pmp import SymbolicPMP


@dataclass(frozen=True)
class HostMemory:
    """H-only relation: fixed PMP; observe readable bytes, mutate writable bytes."""
    pmp: object
    cache: object = None

    def allow(self, address, kind, use_cached=False):
        if self.cache is None:
            return self.pmp.allow(address, 1, kind)
        return self.cache.allow(self.pmp, address, 1, kind, "S", use_cached)

    def read(self, memory, address, *, use_cached=False):
        return self.allow(address, "R", use_cached), z3.Select(memory, address)

    def write(self, memory, address, value, *, use_cached=False):
        return self.allow(address, "W", use_cached), z3.Store(memory, address, value)

    def closure(self, before, after):
        """Frame for arbitrarily many writes; unmodifiable bytes stay identical."""
        byte = z3.BitVec("host_frame_byte", 64)
        writable = z3.Or(self.pmp.allow(byte, 1, "W"), self.allow(byte, "W", True))
        return z3.ForAll([byte], z3.Implies(z3.Not(writable),
                                         z3.Select(after, byte) == z3.Select(before, byte)))


def _install_pmp(state, target):
    """Decoded M-mode CSR writes, addresses first and lock bits last."""
    state = state.clone()
    state.E.priv = "M"
    for index, address in enumerate(target.addr):
        state.E.put(5, address)
        state = step(state, Insn("CSRW", rs1=5, csr=f"pmpaddr{index}"))
    state.E.put(5, sum(c << (8 * i) for i, c in enumerate(target.cfg)))
    state = step(state, Insn("CSRW", rs1=5, csr="pmpcfg0"))
    if state.P != target:
        raise AssertionError("PMP CSR replay differs from the symbolic target")
    return state


def _project_and_replay(model, before, host, address, value, operation, pm, use_cached, origin):
    """Replay the witness byte/PMP projection, not the whole arbitrary array."""
    integer = lambda expr: model.eval(expr, model_completion=True).as_long()
    pa = integer(address)
    old = integer(z3.Select(before.q.memory, address))
    data = integer(value)
    source_pmp = P([integer(c) for c in before.pmp.cfg], [integer(a) for a in before.pmp.addr])
    host_pmp = P([integer(c) for c in host.pmp.cfg], [integer(a) for a in host.pmp.addr])
    if not _pmp_installable(source_pmp, host_pmp):
        raise AssertionError("witness PMP cannot be installed")
    prior_trace = []
    if origin is None:
        state = State(E=E(pc=0x1000, priv="S"), P=host_pmp)
        state.M.store(pa, 1, old)
    else:
        cached_address = integer(before.cache.va)
        state = State(E=E(pc=0x1000, priv="S"), P=origin,
                      V=V(cache_pmp_permissions=True))
        state.E.put(10, cached_address)
        state = step(state, Insn("LBU", rd=12, rs1=10))  # public byte was zero
        prior_trace.append({"actor": "H", "operation": "LBU", "address": cached_address, "observed": 0})
        state.E.priv = "M"  # trusted historical entry, not an attacker privilege change
        state.E.put(10, pa)
        state.E.put(11, old)
        state = step(state, Insn("SB", rs1=10, rs2=11), fill_cache=False)
        prior_trace.append({"actor": "SM", "operation": "SB", "address": pa, "value": old})
        state = _install_pmp(state, source_pmp)
        prior_trace.append({"actor": "SM", "operation": "PMP_UPDATE"})
        state = _install_pmp(state, host_pmp)
        prior_trace.append({"actor": "PM", "operation": "PMP_UPDATE"})
        state = step(state, Insn("CSRW", rs1=0, csr="satp"))
        if pm.sync_pmp:
            state = step(state, Insn("SFENCE.VMA"))
            prior_trace.append({"actor": "PM", "operation": "SFENCE.VMA"})
        state.E = E(pc=0x1000, priv="S")
        expected_cache = SymbolicCachedAccess.from_concrete(state.V.cached)
        if not z3.is_true(z3.simplify(model.eval(host.cache.same_as(expected_cache), model_completion=True))):
            raise AssertionError("cache provenance/fence replay mismatch")
    state.E.put(10, pa)
    state.E.put(11, data)
    cached_choice = z3.is_true(model.eval(use_cached, model_completion=True))
    hit = cached_choice and state.V.cached is not None and state.V.cached.matches(pa, 1, "S")
    result = Machine(state, "H").instruction(Insn(operation, rd=12, rs1=10, rs2=11), use_cached=cached_choice)
    event = {"operation": operation, "address": pa}
    event["permission_source"] = "cached" if hit else "current"
    if operation == "LBU":
        if result.S.E.get(12) != old:
            raise AssertionError("concrete read differs from symbolic observation")
        event["observed"] = old
    else:
        if result.S.M.load(pa, 1) != data or data == old:
            raise AssertionError("concrete write did not alter the protected byte")
        event.update({"before": old, "after": data})
    return {"byte": pa,
            "in_history": z3.is_true(model.eval(z3.Select(before.q.history, address), model_completion=True)),
            "source_pmp": {"cfg": source_pmp.cfg, "addr": source_pmp.addr},
            "host_pmp": {"cfg": host_pmp.cfg, "addr": host_pmp.addr},
            "host_trace": [event], "projection_replayed": True,
            "prior_trace": prior_trace, "cache_provenance_replayed": origin is not None}


def analyze_host_attacks(pm, *, constrain=None, timeout_ms=10000, cache_origin_pmp=None, stale_only=False):
    """Existentially find direct protected reads and actual byte corruption.

    No admission condition, no resume, no invoke. K0 source state and R are
    arbitrary. Host start requires Out installability and entry X permission.
    Reverse installability is reported but does not exclude a Host-only attack.
    """
    if timeout_ms < 1:
        raise ValueError("timeout must be positive")
    validate_host_template(pm)
    if cache_origin_pmp is not None and any(c & 0x80 for c in cache_origin_pmp.cfg):
        raise ValueError("cache provenance replay currently requires an unlocked prior PMP")
    if cache_origin_pmp is not None:
        from smpreempt.model.riscv_model import PM
        validate_host_template(PM(cache_origin_pmp))
    before = SystemState.fresh("attack_initial", translation_model=cache_origin_pmp is not None)
    cached_address = z3.BitVec("prior_access_address", 64)
    if cache_origin_pmp is not None:
        prior = SymbolicPMP.concrete(cache_origin_pmp)
        before = replace(before, cache=SymbolicCachedAccess.seed(prior, cached_address, 1, "S"),
                         satp=z3.BitVecVal(0, 64))
    host = switchout_state(before, pm)
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(interruption_domain(before))
    if cache_origin_pmp is not None:
        solver.add(prior.allow(cached_address, 1, "R"), prior.installable(before.pmp))
    if constrain is not None:
        solver.add(constrain(before))
    installed = before.pmp.installable(host.pmp)
    entry = host.pmp.allow(z3.BitVecVal(0x1000, 64), 4, "X")
    started = z3.And(installed, entry)
    address = z3.BitVec("attack_address", 64)
    value = z3.BitVec("attack_value", 8)
    protected = protected_at(before.q.history, address, pm)
    use_cached = z3.Bool("use_cached_permissions")
    effect = HostMemory(host.pmp, host.cache)
    readable, observed = effect.read(host.q.memory, address, use_cached=use_cached)
    writable, changed = effect.write(host.q.memory, address, value, use_cached=use_cached)

    def query(condition, operation=None):
        solver.push()
        solver.add(condition)
        result = solver.check()
        if result == z3.sat:
            answer = {"status": "sat"}
            if operation:
                answer["witness"] = _project_and_replay(solver.model(), before, host,
                                                       address, value, operation, pm, use_cached, cache_origin_pmp)
                pa = answer["witness"]["byte"]
                regions = () if pm.policy is None else pm.policy.regions
                answer["witness"]["fixed_regions"] = [r.name for r in regions if r.start <= pa < r.end]
        elif result == z3.unsat:
            answer = {"status": "unsat"}
        else:
            answer = {"status": "unknown", "reason": solver.reason_unknown()}
        solver.pop()
        return answer

    domain = query(z3.BoolVal(True))
    startup = {"host_start": query(started),
               "install_blocked": query(z3.Not(installed)),
               "entry_not_executable": query(z3.And(installed, z3.Not(entry))),
               "restore_blocked_after_start": query(z3.And(started, z3.Not(host.pmp.installable(before.pmp))))}
    attacks = {
        "protected_read": query(z3.And(started, protected, readable,
            z3.Not(host.pmp.allow(address, 1, "R")) if stale_only else True), "LBU"),
        "protected_write": query(z3.And(started, protected, writable,
            z3.Not(host.pmp.allow(address, 1, "W")) if stale_only else True,
            z3.Select(changed, address) != observed), "SB"),
    }
    if any(a["status"] == "sat" for a in attacks.values()):
        status = "attack_found"
    elif domain["status"] == "unsat":
        status = "empty_domain"
    elif startup["host_start"]["status"] == "unsat":
        status = "host_unavailable"
    elif any(a["status"] == "unknown" for a in [domain, startup["host_start"], *attacks.values()]):
        status = "unknown"
    else:
        status = "no_direct_data_attack_in_model"
    return {"status": status, "state_set": "K0" if constrain is None else "constrained_K0",
            "domain": domain, "startup": startup, "attacks": attacks,
            "sync_pmp": pm.sync_pmp, "stale_permissions_only": stale_only,
            "scope": "Bare, one provenanced cache entry when enabled, fixed PMP/R; no resume/invoke/G"}
