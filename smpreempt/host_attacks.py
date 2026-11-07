"""Host-only direct-data attacks after an arbitrary interruption; no G/T4.

Fixed Bare/PMP/R within one Host epoch. Byte reads/writes summarize arbitrary
ordinary Host data accesses, without claiming full ISA or noninterference.
"""
from dataclasses import dataclass

import z3

from smpreempt.preemption import interruption_domain, protected_at, switchout_state, validate_host_template
from smpreempt.riscv_model import E, Insn, Machine, P, State, _pmp_installable
from smpreempt.symbolic_system import SystemState


@dataclass(frozen=True)
class HostMemory:
    """H-only relation: fixed PMP; observe readable bytes, mutate writable bytes."""
    pmp: object

    def read(self, memory, address):
        return self.pmp.allow(address, 1, "R"), z3.Select(memory, address)

    def write(self, memory, address, value):
        return self.pmp.allow(address, 1, "W"), z3.Store(memory, address, value)

    def closure(self, before, after):
        """Frame for arbitrarily many writes; unmodifiable bytes stay identical."""
        byte = z3.BitVec("host_frame_byte", 64)
        return z3.ForAll([byte], z3.Implies(z3.Not(self.pmp.allow(byte, 1, "W")),
                                         z3.Select(after, byte) == z3.Select(before, byte)))


def _project_and_replay(model, before, host, address, value, operation):
    """Replay the witness byte/PMP projection, not the whole arbitrary array."""
    integer = lambda expr: model.eval(expr, model_completion=True).as_long()
    pa = integer(address)
    old = integer(z3.Select(before.q.memory, address))
    data = integer(value)
    source_pmp = P([integer(c) for c in before.pmp.cfg], [integer(a) for a in before.pmp.addr])
    host_pmp = P([integer(c) for c in host.pmp.cfg], [integer(a) for a in host.pmp.addr])
    if not _pmp_installable(source_pmp, host_pmp):
        raise AssertionError("witness PMP cannot be installed")
    state = State(E=E(pc=0x1000, priv="S"), P=host_pmp)
    state.M.store(pa, 1, old)
    state.E.put(10, pa)
    state.E.put(11, data)
    result = Machine(state, "H").instruction(Insn(operation, rd=12, rs1=10, rs2=11))
    event = {"operation": operation, "address": pa}
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
            "host_trace": [event], "projection_replayed": True}


def analyze_host_attacks(pm, *, constrain=None, timeout_ms=10000):
    """Existentially find direct protected reads and actual byte corruption.

    No admission condition, no resume, no invoke. K0 source state and R are
    arbitrary. Host start requires Out installability and entry X permission.
    Reverse installability is reported but does not exclude a Host-only attack.
    """
    if timeout_ms < 1:
        raise ValueError("timeout must be positive")
    validate_host_template(pm)
    before = SystemState.fresh("attack_initial")
    host = switchout_state(before, pm)
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(interruption_domain(before))
    if constrain is not None:
        solver.add(constrain(before))
    installed = before.pmp.installable(host.pmp)
    entry = host.pmp.allow(z3.BitVecVal(0x1000, 64), 4, "X")
    started = z3.And(installed, entry)
    address = z3.BitVec("attack_address", 64)
    value = z3.BitVec("attack_value", 8)
    protected = protected_at(before.q.history, address, pm)
    effect = HostMemory(host.pmp)
    readable, observed = effect.read(host.q.memory, address)
    writable, changed = effect.write(host.q.memory, address, value)

    def query(condition, operation=None):
        solver.push()
        solver.add(condition)
        result = solver.check()
        if result == z3.sat:
            answer = {"status": "sat"}
            if operation:
                answer["witness"] = _project_and_replay(solver.model(), before, host,
                                                       address, value, operation)
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
        "protected_read": query(z3.And(started, protected, readable), "LBU"),
        "protected_write": query(z3.And(started, protected, writable,
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
            "scope": "Bare, fixed PMP/R, Host-only ordinary byte data accesses; no resume/invoke/G"}
