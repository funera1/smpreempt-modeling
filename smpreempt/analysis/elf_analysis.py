"""Bounded two-execution Host-byte-read analysis for a linked RV64 ELF.

Uses the existing transition system, not the legacy A/R exposure predicate.
The two executions have shared public inputs and independent secret registers.
Only SM prefix execution and one PM-mediated Host read are modeled here.
"""
from dataclasses import replace
from copy import deepcopy
import z3

from smpreempt.frontend.elf import ELF
from smpreempt.model.riscv_model import Machine, State, PM, AccessFault, check_access
from smpreempt.analysis.preemption import switchout_state, switch_feasible, effective_may_allow
from smpreempt.analysis.symbolic_system import BoundedSystem, RUN, STEP, EXIT, STATUS_NAMES


def analyze_reads(image: ELF, *, entry=None, secret_registers=(11,), registers=None,
                  bound=8, pm=None, initial_pmp=None, exits=(), cuts=(), timeout_ms=10000):
    if bound < 0 or timeout_ms < 1:
        raise ValueError('bound must be nonnegative and timeout positive')
    secret_registers = tuple(secret_registers)
    registers = {} if registers is None else dict(registers)
    if not secret_registers or any(r not in range(1, 32) for r in secret_registers):
        raise ValueError('specify at least one secret register x1..x31')
    if any(r not in range(1, 32) or not 0 <= v < 1 << 64 for r, v in registers.items()):
        raise ValueError('invalid public register assignment')
    if set(secret_registers) & registers.keys():
        raise ValueError('a register cannot be both public constant and secret')
    if any(s.address != s.physical for s in image.segments):
        raise ValueError('Bare adapter requires identity virtual/physical PT_LOAD addresses')
    if sum(len(s.data) for s in image.segments) > 1 << 20:
        raise ValueError('prototype supports at most 1 MiB of file-backed PT_LOAD data')
    pc = image.entry if entry is None else entry
    exits = frozenset(exits)
    if pc not in image.instructions:
        raise ValueError('entry is not an extracted instruction boundary')
    cuts = frozenset(cuts)
    if any(not 0 <= a < 1 << 64 for a in (pc, *exits, *cuts)):
        raise ValueError('entry, exits and cuts must be RV64 addresses')
    initial = Machine(State())
    initial.S.E.pc = pc
    if initial_pmp is not None:
        initial.S.P = initial_pmp
    pm = PM(None) if pm is None else pm
    if pm.policy is not None or pm.enforce_history:
        raise ValueError('semantic analysis does not accept A/R admission policies')
    program = {a: i.decoded for a, i in image.instructions.items()
               if i.decoded is not None and a not in exits}
    memory = z3.Array('elf_public_memory', z3.BitVecSort(64), z3.BitVecSort(8))
    # Loader zero-fill and file contents are public and shared between executions.
    for s in image.segments:
        if s.memory_size > len(s.data):
            a = z3.BitVec('elf_bss_address', 64)
            start = s.address + len(s.data)
            memory = z3.Lambda(a, z3.If(z3.And(z3.UGE(a, start), z3.ULE(a, s.address+s.memory_size-1)),
                                       z3.BitVecVal(0, 8), z3.Select(memory, a)))
        for offset, byte in enumerate(s.data):
            memory = z3.Store(memory, z3.BitVecVal(s.address+offset, 64), z3.BitVecVal(byte, 8))
    public = [z3.BitVecVal(0, 64)] + [z3.BitVec(f'elf_public_x{i}', 64) for i in range(1, 32)]
    for r, value in registers.items():
        public[r] = z3.BitVecVal(value, 64)
    encodings = []
    for side in ('left', 'right'):
        e = BoundedSystem(initial, program, pm, exits, timeout_ms, namespace=f'elf_{side}_')
        rs = list(public)
        for r in secret_registers:
            rs[r] = z3.BitVec(f'elf_{side}_secret_x{r}', 64)
        e.states[0] = replace(e.states[0], q=replace(e.states[0].q, registers=tuple(rs), memory=memory))
        encodings.append(e)
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    address = z3.BitVec('elf_host_probe_address', 64)
    covered_cuts, diagnostics = [], []

    def ask(condition):
        solver.push()
        solver.add(condition)
        status = solver.check()
        model = solver.model() if status == z3.sat else None
        reason = solver.reason_unknown() if status == z3.unknown else None
        solver.pop()
        return status, model, reason

    def number(model, expr):
        return model.eval(expr, model_completion=True).as_long()

    def trace(e, model):
        result = []
        for before, after in zip(e.states, e.states[1:]):
            at = number(model, before.q.pc)
            insn = image.instructions.get(at)
            result.append(dict(pc=hex(at), bytes=None if insn is None else insn.raw.hex(),
                next_pc=hex(number(model, after.q.pc)),
                status=STATUS_NAMES[number(model, after.status)]))
        return result

    def replay_read(e, model, probe):
        """Project relevant input bytes and replay every instruction concretely.

        No equality of an arbitrary SMT array to a sparse concrete array is
        claimed: check GPR/PC/PMP and every touched byte instead.
        """
        machine = Machine(deepcopy(initial.S))
        q0 = e.states[0].q
        for r in range(1, 32):
            machine.S.E.put(r, number(model, q0.registers[r]))
        touched = {probe}
        for state in e.states[:-1]:
            insn = program[number(model, state.q.pc)]
            if insn.op in ('LD', 'SD'):
                a = (number(model, state.q.registers[insn.rs1])+insn.imm) % (1 << 64)
                touched.update((a+i) % (1 << 64) for i in range(8))
        for a in touched:
            machine.S.M.data[a] = number(model, z3.Select(q0.memory, a))
        for before, after in zip(e.states, e.states[1:]):
            machine = machine.instruction(program[number(model, before.q.pc)])
            expected = [number(model, r) for r in after.q.registers]
            if machine.S.E.pc != number(model, after.q.pc) or [machine.S.E.get(r) for r in range(32)] != expected:
                raise AssertionError('ELF symbolic/concrete CPU replay mismatch')
            if (machine.S.P.cfg != [number(model, c) for c in after.pmp.cfg]
                    or machine.S.P.addr != [number(model, a) for a in after.pmp.addr]):
                raise AssertionError('ELF symbolic/concrete PMP replay mismatch')
            if any(machine.S.M.load(a, 1) != number(model, z3.Select(after.q.memory, a)) for a in touched):
                raise AssertionError('ELF symbolic/concrete memory replay mismatch')
        host = machine.preempt(pm, check_policy=False)
        try:
            check_access(host.S, probe, 1, 'R')
            return dict(readable=True, value=host.S.M.load(probe, 1))
        except AccessFault:
            return dict(readable=False, value=None)

    common = dict(elf_sha256=image.sha256, entry=hex(pc), bound=bound,
                  property='bounded two-run Host byte-read observation',
                  assumptions=['single hart, trusted M-mode Bare prefix',
                               'fixed decoded code; self-modifying writes reported as incomplete',
                               'no timing observation, intentional release, Host write, or resumed suffix',
                               'PM CPU save/scrub is abstract; no permission cache in this adapter'],
                  secret_registers=list(secret_registers),
                  cuts=[hex(a) for a in sorted(cuts)], exits=[hex(a) for a in sorted(exits)],
                  initial_pmp=dict(cfg=initial.S.P.cfg, addr=initial.S.P.addr),
                  host_pmp=None if pm.safe_host_pmp is None else dict(cfg=pm.safe_host_pmp.cfg, addr=pm.safe_host_pmp.addr))
    for depth in range(bound+1):
        left, right = (e.states[-1] for e in encodings)
        running = z3.And(left.status == RUN, right.status == RUN)
        selected = z3.BoolVal(True) if not cuts else z3.And(
            z3.Or(*[left.q.pc == a for a in cuts]), z3.Or(*[right.q.pc == a for a in cuts]))
        running = z3.And(running, selected)
        lh, rh = switchout_state(left, pm), switchout_state(right, pm)
        la, ra = effective_may_allow(lh, address, 1, 'R'), effective_may_allow(rh, address, 1, 'R')
        feasible = z3.And(switch_feasible(left, lh), switch_feasible(right, rh),
                         lh.pmp.allow(z3.BitVecVal(0x1000, 64), 4, 'X'),
                         rh.pmp.allow(z3.BitVecVal(0x1000, 64), 4, 'X'))
        observation_diff = z3.Or(la != ra, z3.And(la, ra,
                                     z3.Select(left.q.memory, address) != z3.Select(right.q.memory, address)))
        status, model, reason = ask(z3.And(running, feasible, observation_diff))
        if status == z3.sat:
            probe = number(model, address)
            replayed = [replay_read(e, model, probe) for e in encodings]
            if replayed[0] == replayed[1]:
                raise AssertionError('ELF Host observations did not differ in concrete replay')
            witness = dict(address=hex(number(model, address)), depth=depth,
                left_pc=hex(number(model, left.q.pc)), right_pc=hex(number(model, right.q.pc)),
                left_readable=z3.is_true(model.eval(la, model_completion=True)),
                right_readable=z3.is_true(model.eval(ra, model_completion=True)),
                left_byte=number(model, z3.Select(left.q.memory, address)),
                right_byte=number(model, z3.Select(right.q.memory, address)),
                initial_registers={side: {f'x{i}': number(model, e.states[0].q.registers[i])
                                         for i in range(1, 32)} for side, e in zip(('left', 'right'), encodings)},
                traces={side: trace(e, model) for side, e in zip(('left', 'right'), encodings)})
            return dict(common, status='counterexample', witness=witness,
                        diagnostics=diagnostics, concrete_replayed=True, concrete_observations=replayed)
        if status == z3.unknown:
            return dict(common, status='unknown', depth=depth, reason=reason, diagnostics=diagnostics)
        reachable, _, reason = ask(z3.And(running, feasible))
        if reachable == z3.unknown:
            return dict(common, status='unknown', depth=depth, reason=reason, diagnostics=diagnostics)
        if reachable == z3.sat:
            covered_cuts.append(depth)
        # Report a reachable model gap/fault even if another path gives no leak.
        for side, e in zip(('left', 'right'), encodings):
            state = e.states[-1]
            known_pc = z3.Or(*[state.q.pc == a for a in set(program) | exits])
            bad = z3.Or(z3.And(state.status != RUN, state.status != EXIT),
                        z3.And(state.status == RUN, z3.Not(known_pc)))
            gap, gm, reason = ask(bad)
            if gap == z3.unknown:
                return dict(common, status='unknown', depth=depth, reason=reason, diagnostics=diagnostics)
            if gap == z3.sat:
                at = number(gm, state.q.pc)
                raw = image.instructions.get(at)
                diagnostic = dict(side=side, depth=depth, pc=hex(at),
                    outcome='model_gap' if number(gm, state.status) == RUN else STATUS_NAMES[number(gm, state.status)],
                    instruction=None if raw is None else raw.report())
                if diagnostic not in diagnostics:
                    diagnostics.append(diagnostic)
            # Stores into executable segments violate the fixed-code premise.
            writes = []
            for at, insn in program.items():
                if insn.op != 'SD':
                    continue
                target = state.q.registers[insn.rs1] + insn.imm
                overlaps = [z3.Or(*[z3.And(z3.UGE(target+i, s.address),
                                           z3.ULE(target+i, s.address+s.memory_size-1)) for i in range(8)])
                            for s in image.segments if s.flags & 1 and s.memory_size]
                writes.append(z3.And(state.status == RUN, state.q.pc == at, z3.Or(*overlaps)))
            hit, _, reason = ask(z3.Or(*writes))
            if hit == z3.unknown:
                return dict(common, status='unknown', depth=depth, reason=reason, diagnostics=diagnostics)
            if hit == z3.sat:
                return dict(common, status='incomplete', reason='reachable store may modify executable memory',
                            depth=depth, diagnostics=diagnostics)
        if depth < bound:
            for e in encodings:
                e.extend()
                solver.add(e.solver.assertions()[-1], e.choices[-1].action == STEP,
                           z3.Not(e.choices[-1].use_cached), z3.Not(e.choices[-1].fill_cache))
    return dict(common, status='incomplete' if diagnostics or not covered_cuts else 'no_counterexample_within_bound',
                reason='reachable model gaps/faults' if diagnostics else 'no feasible Host cut' if not covered_cuts else 'finite prefix bound only',
                checked_cut_depths=covered_cuts, diagnostics=diagnostics)
