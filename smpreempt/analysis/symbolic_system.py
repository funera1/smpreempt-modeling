"""Composed bounded transition system for the documented Bare/PMP subset."""
from dataclasses import asdict, dataclass, replace

import z3

from smpreempt.model.riscv_model import (
    AccessFault, HostAction, IllegalInstruction, Insn, Machine, PM, ModelFault, Unsupported,
    _effective_privilege,
)
from smpreempt.model.symbolic_instructions import InstructionState, instruction_transition
from smpreempt.model.symbolic_pmp import SymbolicPMP
from smpreempt.model.symbolic_cache import SymbolicCachedAccess
from smpreempt.analysis.preemption import (
    protected_at as protected_byte, switchout_state, switchin_state, switch_feasible, effective_may_allow,
)

RUN, ACCESS_FAULT, MISALIGNED, PM_REJECTED, EXIT, MODEL_GAP, UNSUPPORTED, ILLEGAL = range(8)
STEP, HOST_LD, HOST_SD, PREEMPT, RESUME = range(5)
STATUS_NAMES = ("run", "access_fault", "misaligned", "pm_rejected", "exit",
                "model_gap", "unsupported", "illegal_instruction")
BASE_OPS = {"ADD", "ADDI", "XOR", "AND", "LD", "SD", "BEQ", "JAL", "JALR"}


@dataclass(frozen=True)
class SystemState:
    q: InstructionState
    pmp: SymbolicPMP
    host: z3.BoolRef
    status: z3.ArithRef
    saved_pc: z3.BitVecRef
    saved_registers: tuple
    saved_pmp: SymbolicPMP
    pending: z3.BoolRef
    cache: object = None
    satp: object = None
    saved_satp: object = None

    @classmethod
    def fresh(cls, name, *, translation_model=False):
        return cls(InstructionState.fresh(name), SymbolicPMP.fresh(name),
                   z3.Bool(f"{name}_host"), z3.Int(f"{name}_status"),
                   z3.BitVec(f"{name}_saved_pc", 64),
                   (z3.BitVecVal(0, 64),) + tuple(z3.BitVec(f"{name}_saved_x{i}", 64) for i in range(1, 32)),
                   SymbolicPMP.fresh(f"{name}_saved"), z3.Bool(f"{name}_pending"),
                   SymbolicCachedAccess.fresh(f"{name}_cache") if translation_model else None,
                   z3.BitVec(f"{name}_satp", 64) if translation_model else None,
                   z3.BitVec(f"{name}_saved_satp", 64) if translation_model else None)

    @classmethod
    def initial(cls, machine, *, translation_model=False):
        translation_model = translation_model or machine.S.V.cache_pmp_permissions
        pmp = SymbolicPMP.concrete(machine.S.P)
        return cls(InstructionState.from_machine(machine), pmp, z3.BoolVal(False),
                   z3.IntVal(RUN), z3.BitVecVal(0, 64),
                   (z3.BitVecVal(0, 64),) * 32, pmp, z3.BoolVal(machine.pending),
                   SymbolicCachedAccess.from_concrete(machine.S.V.cached) if translation_model else None,
                   z3.BitVecVal(machine.S.V.satp, 64) if translation_model else None,
                   z3.BitVecVal(0, 64) if translation_model else None)

    def same_as(self, other):
        if (self.cache is None) != (other.cache is None):
            return z3.BoolVal(False)
        translation = z3.BoolVal(True) if self.cache is None else z3.And(
            self.cache.same_as(other.cache), self.satp == other.satp, self.saved_satp == other.saved_satp)
        return z3.And(translation, self.q.same_as(other.q), self.pmp.same_as(other.pmp),
                      self.host == other.host, self.status == other.status, self.pending == other.pending,
                      self.saved_pc == other.saved_pc,
                      *[a == b for a, b in zip(self.saved_registers, other.saved_registers)],
                      self.saved_pmp.same_as(other.saved_pmp))


@dataclass(frozen=True)
class Choice:
    action: z3.ArithRef
    address: z3.BitVecRef
    value: z3.BitVecRef
    use_cached: z3.BoolRef
    fill_cache: z3.BoolRef

    @classmethod
    def fresh(cls, name):
        return cls(z3.Int(f"{name}_action"), z3.BitVec(f"{name}_address", 64),
                   z3.BitVec(f"{name}_value", 64), z3.Bool(f"{name}_cached"), z3.Bool(f"{name}_fill"))


def protected_at(state, address, pm):
    return protected_byte(state.q.history, address, pm)


def exposed(state, address, pm):
    return z3.And(protected_at(state, address, pm),
                  z3.Or(effective_may_allow(state, address, 1, "R"), effective_may_allow(state, address, 1, "W")))


class BoundedSystem:
    """Incrementally unroll a fixed PC map with symbolic state and choices.

    CSR/V/trusted privilege/context do not change in this subset. PM resets
    Host E/V and restores those fixed trusted fields; only PC/GPR/PMP need slots.
    """
    def __init__(self, initial: Machine, program, pm: PM, exits=frozenset(), timeout_ms=10000,
                 *, control=None, namespace=""):
        if initial.c not in ("SM", "C") or initial.suspended is not None:
            raise ValueError("start in an unsuspended C/SM context")
        if initial.S.V.satp != 0 or initial.S.V.tlb:
            raise Unsupported("composed BMC requires Bare mode and empty placeholder TLB")
        if timeout_ms < 1:
            raise ValueError("timeout must be positive")
        if set(program) & set(exits):
            raise ValueError("program and exits overlap")
        if any(not 0 <= pc < 1 << 64 for pc in exits):
            raise ValueError("exit PC outside RV64")
        for pc, instruction in program.items():
            if not 0 <= pc < 1 << 64:
                raise ValueError("PC outside RV64")
            if any(not 0 <= i < 32 for i in (instruction.rd, instruction.rs1, instruction.rs2)):
                raise ValueError("register index outside 0..31")
            if instruction.op.upper() not in BASE_OPS | {"SFENCE.VMA"} and not (
                    instruction.op.upper() == "CSRW" and instruction.csr in
                    {"satp", "pmpcfg0", *(f"pmpaddr{i}" for i in range(8))}):
                raise Unsupported(f"composed BMC instruction: {instruction}")
            if instruction.op.upper() == "SFENCE.VMA" and (instruction.rs1 or instruction.rs2):
                raise Unsupported("only sfence.vma x0,x0 is modeled")
        self.initial, self.program, self.pm, self.exits = initial, dict(program), pm, frozenset(exits)
        self.control = control
        self.namespace = namespace
        self.solver = z3.Solver()
        self.solver.set(timeout=timeout_ms)
        translation_model = initial.S.V.cache_pmp_permissions or any(
            i.op.upper() == "CSRW" and i.csr == "satp" for i in program.values())
        self.states = [SystemState.initial(initial, translation_model=translation_model)]
        self.choices = []

    def switch_conditions(self, before):
        host = switchout_state(before, self.pm)
        feasible = switch_feasible(before, host)
        if self.control is not None:
            return host, z3.And(feasible, self.control.symbolic_allowed(before, host, self.pm))
        # Compatibility with the original PM-enforced policy mode.
        byte = z3.BitVec(f"{self.namespace}legacy_pm_byte", 64)
        protected = z3.Select(before.q.history, byte) if self.pm.enforce_history else z3.BoolVal(False)
        if self.pm.policy is not None:
            a = z3.ZeroExt(1, byte)
            protected = z3.Or(protected, *[z3.And(z3.UGE(a, r.start), z3.ULT(a, r.end))
                                           for r in self.pm.policy.regions])
        isolated = z3.ForAll([byte], z3.Implies(protected, z3.Not(z3.Or(
            effective_may_allow(host, byte, 1, "R"), effective_may_allow(host, byte, 1, "W")))))
        return host, z3.And(feasible, isolated)

    def transition(self, before, after, choice):
        edges = []
        running = before.status == RUN
        trusted = z3.And(running, z3.Not(before.host))
        at_exit = z3.Or(*[before.q.pc == pc for pc in self.exits])
        host_candidate, ready = self.switch_conditions(before)
        can_step = (z3.Or(at_exit, z3.Not(z3.And(before.pending, ready)))
                    if self.control is not None else z3.BoolVal(True))

        def edge(guard, candidate):
            edges.append(z3.And(guard, after.same_as(candidate)))

        def terminal(guard, status):
            edge(guard, replace(before, status=z3.IntVal(status)))

        # Terminal nodes stutter: bounded prefixes always have extensions.
        edge(z3.Not(running), before)
        known = []
        privilege = _effective_privilege(self.initial.S.E, "R")
        for pc, insn in self.program.items():
            at = before.q.pc == pc
            known.append(at)
            execute = z3.And(trusted, can_step, choice.action == STEP, at)
            if insn.op.upper() == "CSRW":
                if insn.csr == "satp":
                    if self.initial.S.E.priv == "U":
                        terminal(execute, ILLEGAL)
                    else:
                        edge(execute, replace(before, q=replace(before.q, pc=before.q.pc + 4),
                                              satp=before.q.registers[insn.rs1]))
                    continue
                if self.initial.S.E.priv != "M":
                    terminal(execute, ILLEGAL)
                    continue
                pmp, supported = before.pmp.write(insn.csr, before.q.registers[insn.rs1])
                q = replace(before.q, pc=before.q.pc + 4)
                edge(z3.And(execute, supported), replace(before, q=q, pmp=pmp))
                terminal(z3.And(execute, z3.Not(supported)), UNSUPPORTED)
            elif insn.op.upper() == "SFENCE.VMA":
                if self.initial.S.E.priv == "U":
                    terminal(execute, ILLEGAL)
                else:
                    edge(execute, replace(before, q=replace(before.q, pc=before.q.pc + 4),
                         cache=None if before.cache is None else before.cache.invalidate()))
            else:
                def permission(a, k):
                    if before.cache is not None and self.initial.S.V.cache_pmp_permissions:
                        return before.cache.allow(before.pmp, a, 8, k, privilege, choice.use_cached)
                    return before.pmp.allow(a, 8, k, privilege)
                t = instruction_transition(before.q, insn, self.initial,
                    access_check=permission)
                candidate = replace(before, q=t.next_state)
                if insn.op.upper() in ("LD", "SD"):
                    vm_supported = z3.BoolVal(True) if before.satp is None or privilege == "M" else before.satp == 0
                    if before.cache is not None and self.initial.S.V.cache_pmp_permissions:
                        address = before.q.registers[insn.rs1] + insn.imm
                        candidate = replace(candidate, cache=before.cache.after_access(
                            before.pmp, address, 8, privilege, choice.use_cached, choice.fill_cache))
                    terminal(z3.And(execute, z3.Not(vm_supported)), UNSUPPORTED)
                    execute = z3.And(execute, vm_supported)
                edge(z3.And(execute, t.success), candidate)
                terminal(z3.And(execute, t.access_fault), ACCESS_FAULT)
                terminal(z3.And(execute, t.misaligned), MISALIGNED)
        terminal(z3.And(trusted, choice.action == STEP, at_exit), EXIT)
        terminal(z3.And(trusted, can_step, choice.action == STEP,
                        z3.Not(z3.Or(*known, at_exit))), MODEL_GAP)
        switch = z3.And(trusted, z3.Not(at_exit), choice.action == PREEMPT)
        edge(z3.And(switch, ready), host_candidate)
        if self.control is None:
            terminal(z3.And(switch, z3.Not(ready)), PM_REJECTED)
        else:
            edge(z3.And(switch, z3.Not(before.pending), z3.Not(ready)),
                 replace(before, pending=z3.BoolVal(True)))

        for action, operation in ((HOST_LD, "LD"), (HOST_SD, "SD")):
            registers = list(before.q.registers)
            registers[10], registers[11] = choice.address, choice.value
            q = replace(before.q, registers=tuple(registers))
            # Host macros have the same register setup as concrete HostAction.
            host_env = Machine(self.initial.S.clone(), "H")
            host_env.S.E.priv = "S"
            def host_permission(a, k):
                if before.cache is not None and self.initial.S.V.cache_pmp_permissions:
                    return before.cache.allow(before.pmp, a, 8, k, "S", choice.use_cached)
                return before.pmp.allow(a, 8, k)
            t = instruction_transition(q, Insn(
                operation, rd=12, rs1=10, rs2=11), host_env,
                access_check=host_permission)
            execute = z3.And(running, before.host, choice.action == action)
            vm_supported = z3.BoolVal(True) if before.satp is None else before.satp == 0
            terminal(z3.And(execute, z3.Not(vm_supported)), UNSUPPORTED)
            execute = z3.And(execute, vm_supported)
            candidate = replace(before, q=t.next_state)
            if before.cache is not None and self.initial.S.V.cache_pmp_permissions:
                candidate = replace(candidate, cache=before.cache.after_access(
                    before.pmp, choice.address, 8, "S", choice.use_cached, choice.fill_cache))
            edge(z3.And(execute, t.success), candidate)
            terminal(z3.And(execute, t.access_fault), ACCESS_FAULT)
            terminal(z3.And(execute, t.misaligned), MISALIGNED)
        resume = z3.And(running, before.host, choice.action == RESUME)
        restore_ok = before.pmp.installable(before.saved_pmp)
        edge(z3.And(resume, restore_ok), switchin_state(before, self.pm))
        terminal(z3.And(resume, z3.Not(restore_ok)), PM_REJECTED)
        return z3.Or(*edges)

    def extend(self):
        index = len(self.choices)
        choice = Choice.fresh(f"{self.namespace}t{index}")
        after = SystemState.fresh(f"{self.namespace}s{index + 1}", translation_model=self.states[-1].cache is not None)
        self.solver.add(z3.simplify(self.transition(self.states[-1], after, choice)))
        self.choices.append(choice)
        self.states.append(after)

    def replay(self, model, depth):
        """Replay SAT transitions and compare every normal successor's full state."""
        machine, trace = self.initial, []
        for i in range(depth):
            choice = self.choices[i]
            action = model.eval(choice.action, model_completion=True).as_long()
            before, after = self.states[i], self.states[i + 1]
            status = model.eval(after.status).as_long()
            use_cached = z3.is_true(model.eval(choice.use_cached, model_completion=True))
            fill_cache = z3.is_true(model.eval(choice.fill_cache, model_completion=True))
            if model.eval(before.status).as_long() != RUN:
                continue
            if action == STEP:
                pc = machine.S.E.pc
                if status == EXIT:
                    trace.append({"action": "exit", "pc": pc})
                    continue
                insn = self.program.get(pc)
                trace.append({"action": "instruction", "pc": pc,
                              "instruction": asdict(insn) if insn else None})
                operation = lambda: machine.instruction(insn, use_cached=use_cached, fill_cache=fill_cache)
            elif action == PREEMPT:
                trace.append({"action": "preempt"})
                operation = (lambda: machine.preempt(self.pm)) if self.control is None else (
                    lambda: self.control.request(machine, self.pm))
            elif action == RESUME:
                trace.append({"action": "resume"})
                operation = lambda: machine.resume(self.pm)
            else:
                address = model.eval(choice.address, model_completion=True).as_long()
                value = model.eval(choice.value, model_completion=True).as_long()
                op = "LD" if action == HOST_LD else "SD"
                trace.append({"action": "host", "operation": op, "address": address, "value": value})
                operation = lambda: HostAction(op, address, value).execute(
                    machine, use_cached=use_cached, fill_cache=fill_cache)
            if status != RUN:
                if status == MODEL_GAP:
                    trace[-1]["outcome"] = STATUS_NAMES[status]
                    continue
                try:
                    operation()
                except ModelFault as exc:
                    expected = {ACCESS_FAULT: AccessFault, MISALIGNED: Unsupported,
                                UNSUPPORTED: Unsupported, ILLEGAL: IllegalInstruction,
                                PM_REJECTED: ModelFault}[status]
                    if not isinstance(exc, expected):
                        raise AssertionError("symbolic/concrete failure type mismatch") from exc
                    trace[-1]["outcome"] = STATUS_NAMES[status]
                    continue
                raise AssertionError("symbolic terminal outcome did not occur concretely")
            machine = operation()
            if action == PREEMPT and machine.pending:
                trace[-1]["outcome"] = "deferred"
            equality = z3.And(after.q.same_as(InstructionState.from_machine(machine)),
                              after.pmp.same_as(SymbolicPMP.concrete(machine.S.P)),
                              after.host == (machine.c == "H"), after.pending == machine.pending)
            if after.cache is not None:
                equality = z3.And(equality, after.satp == machine.S.V.satp,
                                  after.cache.same_as(SymbolicCachedAccess.from_concrete(machine.S.V.cached)))
            if machine.suspended is not None:
                equality = z3.And(equality, after.saved_pc == machine.suspended.E.pc,
                    *[a == machine.suspended.E.get(j) for j, a in enumerate(after.saved_registers)],
                    after.saved_pmp.same_as(SymbolicPMP.concrete(machine.suspended.P)))
                if after.saved_satp is not None:
                    equality = z3.And(equality, after.saved_satp == machine.suspended.V.satp)
            if not z3.is_true(z3.simplify(model.eval(equality, model_completion=True))):
                raise AssertionError(f"symbolic/concrete state mismatch at transition {i}")
        return machine, trace


def find_counterexample(initial, program, pm, bound=6, exits=frozenset(), timeout_ms=10000, *, control=None):
    if bound < 0:
        raise ValueError("bound must be nonnegative")
    encoding = BoundedSystem(initial, program, pm, exits, timeout_ms, control=control)
    solver = encoding.solver
    for depth in range(bound + 1):
        state = encoding.states[-1]
        witness = z3.BitVec(f"bad_byte_{depth}", 64)
        solver.push()
        solver.add(state.host, exposed(state, witness, pm))
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            machine, trace = encoding.replay(model, depth)
            address = model.eval(witness, model_completion=True).as_long()
            concrete_violations = machine.history_policy().violations(machine.S.P)
            if pm.policy is not None:
                concrete_violations += pm.policy.violations(machine.S.P)
            if not concrete_violations:
                raise AssertionError("SMT violation not reproduced")
            return {"status": "counterexample", "depth": depth, "address": address,
                    "trace": trace, "replayed": True}
        reason = solver.reason_unknown() if result == z3.unknown else None
        solver.pop()
        if result == z3.unknown:
            return {"status": "unknown", "depth": depth, "reason": reason}
        if depth < bound:
            encoding.extend()
    solver.push()
    solver.add(z3.Or(*[z3.Or(s.status == MODEL_GAP, s.status == UNSUPPORTED) for s in encoding.states]))
    result = solver.check()
    if result == z3.sat:
        _, trace = encoding.replay(solver.model(), bound)
        return {"status": "incomplete", "bound": bound, "reason": "reachable model gap or unsupported WARL",
                "trace": trace}
    if result == z3.unknown:
        return {"status": "unknown", "reason": solver.reason_unknown()}
    solver.pop()
    solver.push()
    solver.add(z3.Or(*[s.status == PM_REJECTED for s in encoding.states]))
    refusal = solver.check()
    solver.pop()
    if control is not None:
        solver.add(z3.Or(*[s.pending for s in encoding.states]))
        deferred = solver.check()
        return {"status": "bounded_unsat", "bound": bound,
                "deferral_reachable": True if deferred == z3.sat else False if deferred == z3.unsat else "unknown"}
    return {"status": "bounded_unsat", "bound": bound,
            "pm_rejection_reachable": True if refusal == z3.sat else False if refusal == z3.unsat else "unknown"}
