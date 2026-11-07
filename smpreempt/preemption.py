"""Switch operations W, admission policy G, and arbitrary-state obligations.

Concrete control needs no Z3. Symbolic helpers import Z3 lazily.
"""
from dataclasses import dataclass, replace

from smpreempt.riscv_model import ModelFault, ProtectionPolicy, _pmp_installable, pmp_allow


def protected_at(history, address, pm):
    import z3
    a = z3.ZeroExt(1, address)
    regions = () if pm.policy is None else pm.policy.regions
    return z3.Or(z3.Select(history, address),
                 *[z3.And(z3.UGE(a, r.start), z3.ULT(a, r.end)) for r in regions])


def switchout_state(before, pm):
    """Wout: trusted slot, zero Host GPRs, template/passthrough PMP; M/A persist."""
    import z3
    from smpreempt.symbolic_pmp import SymbolicPMP
    pmp = before.pmp if pm.safe_host_pmp is None else SymbolicPMP.concrete(pm.safe_host_pmp)
    q = replace(before.q, pc=z3.BitVecVal(0x1000, 64),
                registers=(z3.BitVecVal(0, 64),) * 32)
    return replace(before, q=q, pmp=pmp, host=z3.BoolVal(True), pending=z3.BoolVal(False),
                   saved_pc=before.q.pc, saved_registers=before.q.registers, saved_pmp=before.pmp)


def switchin_state(host):
    """Win: restore trusted PC/GPR/PMP, retain current M/A."""
    import z3
    return replace(host, q=replace(host.q, pc=host.saved_pc, registers=host.saved_registers),
                   pmp=host.saved_pmp, host=z3.BoolVal(False), pending=z3.BoolVal(False))


def switch_feasible(before, host):
    import z3
    return z3.And(before.pmp.installable(host.pmp), host.pmp.installable(before.pmp))


def interruption_domain(before):
    """K0 format constraints, without program reachability or correct isolation."""
    import z3
    from smpreempt.symbolic_system import RUN
    return z3.And(z3.Not(before.host), before.status == RUN, z3.Not(before.pending),
        *[z3.And(z3.ULT(address, 1 << 54), cfg & 0x60 == 0,
                 z3.Or(cfg & 2 == 0, cfg & 1 != 0))
          for cfg, address in zip(before.pmp.cfg, before.pmp.addr)])


def validate_host_template(pm):
    if pm.safe_host_pmp is not None and any(
            cfg & 0x60 or (cfg & 2 and not cfg & 1) for cfg in pm.safe_host_pmp.cfg):
        raise ValueError("Host template uses a reserved base-PMP encoding")


@dataclass(frozen=True)
class PreemptionControl:
    """G observes PMP, A, trusted region metadata, and the Host entry address.

    always is the hypothesis that W alone suffices. isolation checks the full
    protected set and entry X permission, as well as install/restore locks.
    """
    mode: str = "isolation"

    def __post_init__(self):
        if self.mode not in ("always", "isolation"):
            raise ValueError("control mode must be always or isolation")

    def symbolic_allowed(self, before, host, pm):
        import z3
        if self.mode == "always":
            return z3.BoolVal(True)
        byte = z3.BitVec("control_byte", 64)
        isolated = z3.ForAll([byte], z3.Implies(protected_at(before.q.history, byte, pm),
            z3.Not(z3.Or(host.pmp.allow(byte, 1, "R"), host.pmp.allow(byte, 1, "W")))))
        return z3.And(switch_feasible(before, host), isolated,
                      host.pmp.allow(z3.BitVecVal(0x1000, 64), 4, "X"))

    def allows(self, machine, pm):
        if self.mode == "always":
            return True
        target = machine.S.P if pm.safe_host_pmp is None else pm.safe_host_pmp
        regions = machine.history_policy().regions
        if pm.policy is not None:
            regions += pm.policy.regions
        return (_pmp_installable(machine.S.P, target) and _pmp_installable(target, machine.S.P)
                and not ProtectionPolicy(regions).violations(target)
                and pmp_allow(target, "S", 0x1000, 4, "X"))

    def request(self, machine, pm):
        """Attempt/service a request. A denied request remains pending in C/SM."""
        if machine.c not in ("C", "SM") or machine.suspended is not None:
            raise ModelFault("preemption request requires unsuspended C/SM")
        if self.allows(machine, pm):
            try:
                # Policy belongs to G here; retain legacy PM checks elsewhere.
                return machine.preempt(pm, check_policy=False)
            except ModelFault:
                pass  # W cannot install/restore PMP: defer without changing S.
        return replace(machine, pending=True)


def check_switch(pm, control=None, *, constrain=None, timeout_ms=10000):
    """Check W/G for arbitrary representable Bare-subset state K0.

    No SM program or bound. constrain(before) optionally defines a narrower
    state set, with no automatic claim of reachability. Checks are separate;
    UNSAT means that obligation holds in K0, not full TEE security.
    """
    import z3
    from smpreempt.symbolic_system import SystemState, RUN
    if timeout_ms < 1:
        raise ValueError("timeout must be positive")
    validate_host_template(pm)
    control = PreemptionControl() if control is None else control
    before = SystemState.fresh("arbitrary")
    host = switchout_state(before, pm)
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    # K0 has no correct-PMP, no program-PC, and no history reachability premise.
    solver.add(interruption_domain(before))
    if constrain is not None:
        solver.add(constrain(before))
    admitted = control.symbolic_allowed(before, host, pm)
    feasible = switch_feasible(before, host)
    byte = z3.BitVec("obligation_byte", 64)
    protected = protected_at(before.q.history, byte, pm)

    def query(condition, *, witness=False):
        solver.push()
        solver.add(condition)
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            answer = {"status": "sat"}
            if witness:
                pa = model.eval(byte, model_completion=True).as_long()
                answer["witness"] = {
                    "pc": model.eval(before.q.pc, model_completion=True).as_long(),
                    "pmpcfg": [model.eval(c, model_completion=True).as_long() for c in before.pmp.cfg],
                    "pmpaddr": [model.eval(a, model_completion=True).as_long() for a in before.pmp.addr],
                    "byte": pa,
                    "in_history": z3.is_true(model.eval(z3.Select(before.q.history, byte), model_completion=True)),
                }
        elif result == z3.unsat:
            answer = {"status": "unsat"}
        else:
            answer = {"status": "unknown", "reason": solver.reason_unknown()}
        solver.pop()
        return answer

    domain = query(z3.BoolVal(True))
    admission = query(admitted)
    denial = query(z3.Not(admitted))
    # An arbitrary Host may alter any writable byte, and its own CPU state.
    # For any chosen byte, this projection is exact for the bytewise write
    # relation. Other bytes are irrelevant to this pointwise integrity check.
    host_value = z3.BitVec("host_byte_value", 8)
    value_after_host = z3.If(host.pmp.allow(byte, 1, "W"), host_value,
                           z3.Select(host.q.memory, byte))
    host_registers = (z3.BitVecVal(0, 64),) + tuple(z3.BitVec(f"host_x{i}", 64) for i in range(1, 32))
    after_host = replace(host, q=replace(host.q, pc=z3.BitVec("host_pc", 64), registers=host_registers,
        memory=z3.Array("host_memory", z3.BitVecSort(64), z3.BitVecSort(8))))
    resumed = switchin_state(after_host)
    restored_cpu = z3.And(resumed.q.pc == before.q.pc,
        *[a == b for a, b in zip(resumed.q.registers, before.q.registers)],
        resumed.pmp.same_as(before.pmp))
    checks = {
        "install_and_restore": query(z3.And(admitted, z3.Not(feasible)), witness=True),
        "host_entry_executable": query(z3.And(admitted, feasible,
            z3.Not(host.pmp.allow(z3.BitVecVal(0x1000, 64), 4, "X"))), witness=True),
        "direct_isolation": query(z3.And(admitted, feasible, protected,
            z3.Or(host.pmp.allow(byte, 1, "R"), host.pmp.allow(byte, 1, "W"))), witness=True),
        "protected_byte_integrity": query(z3.And(admitted, feasible, protected,
            value_after_host != z3.Select(before.q.memory, byte)), witness=True),
        "host_gpr_scrub": query(z3.And(admitted, feasible,
            z3.Or(*[r != 0 for r in host.q.registers])), witness=True),
        "cpu_pmp_restore": query(z3.And(admitted, feasible, z3.Not(restored_cpu)), witness=True),
        "host_memory_retained": query(z3.And(admitted, feasible,
            resumed.q.memory != after_host.q.memory), witness=True),
    }
    if any(c["status"] == "sat" for c in checks.values()):
        status = "counterexample"
    elif domain["status"] == "unsat":
        status = "empty_domain"
    elif admission["status"] == "unsat":
        status = "no_admitted_state"
    elif any(c["status"] == "unknown" for c in [domain, admission, *checks.values()]):
        status = "unknown"
    else:
        status = "valid_for_K0_obligations"
    return {"status": status, "control": control.mode,
            "state_set": "K0" if constrain is None else "constrained_K0", "domain": domain,
            "admission": admission, "denial": denial, "checks": checks}
