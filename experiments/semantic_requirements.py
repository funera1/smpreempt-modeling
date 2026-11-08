"""Path-local semantic probes using existing instruction semantics, without R/A.

Run from the repository root: python -m experiments.semantic_requirements
This is an experiment for the proposed specification, not a full CFG analyzer.
"""
import json
from dataclasses import replace
import z3
from smpreempt.model.riscv_model import Machine, State, Insn
from smpreempt.model.symbolic_instructions import InstructionState, instruction_transition
from smpreempt.model.symbolic_pmp import SymbolicPMP
from smpreempt.scenarios import demo_machine

# Path-local research probe. No A/R-based safety predicate, no runtime policy change.
a0 = 0x8000
base = InstructionState.fresh('public')
registers = [z3.BitVecVal(0, 64)] * 32
registers[10] = z3.BitVecVal(a0, 64)
base = replace(base, pc=z3.BitVecVal(0x4000, 64), registers=tuple(registers),
               history=z3.K(z3.BitVecSort(64), z3.BoolVal(False)))
env = Machine(State())  # trusted M-mode, no PMP locks, Bare

def execute(q, *insns):
    for i in insns:
        transition = instruction_transition(q, i, env)
        if not z3.is_true(z3.simplify(transition.success)):
            raise AssertionError('probe requires total successful decoded operations')
        q = transition.next_state
    return q

def query(*conditions, witness=None):
    solver = z3.Solver()
    solver.set(timeout=10000)
    solver.add(*conditions)
    result = solver.check()
    report = {'status': str(result)}
    if result == z3.sat and witness is not None:
        report['address'] = hex(solver.model().eval(witness, model_completion=True).as_long())
    if result == z3.unknown:
        report['reason'] = solver.reason_unknown()
    return report

# Confidentiality: same public initial memory, independent secret inputs in GPRs.
worlds = []
for side in ('L', 'R'):
    regs = list(base.registers)
    regs[11], regs[12] = z3.BitVecs('secret_' + side + '_0 secret_' + side + '_1', 64)
    q = replace(base, registers=tuple(regs))
    deposited = execute(q, Insn('SD', rs1=10, rs2=11), Insn('SD', rs1=10, rs2=12, imm=8))
    half = execute(deposited, Insn('SD', rs1=10, rs2=0))
    erased = execute(half, Insn('SD', rs1=10, rs2=0, imm=8))
    worlds.append((deposited, half, erased))
probe = z3.BitVec('probe_address', 64)
_, protected_pmp, _, _ = demo_machine()
_, public_pmp, _, _ = demo_machine()
public_pmp.cfg[0] = 0
conf = {}
for index, name in enumerate(('secret_deposited', 'half_erased', 'fully_erased')):
    left, right = worlds[0][index], worlds[1][index]
    leak = z3.Select(left.memory, probe) != z3.Select(right.memory, probe)
    conf[name] = {
        'semantic_read_restriction_needed': query(leak, witness=probe),
        'host_read_with_open_pmp': query(leak, SymbolicPMP.concrete(public_pmp).allow(probe, 1, 'R'), witness=probe),
        'host_read_with_isolating_pmp': query(leak, SymbolicPMP.concrete(protected_pmp).allow(probe, 1, 'R'), witness=probe),
    }

# Integrity: arbitrary Host-provided initial memory; expected trusted value is zero.
w, value = z3.BitVec('write_address', 64), z3.BitVec('write_value', 8)
def disturb(q):
    return replace(q, memory=z3.Store(q.memory, w, value))
zeroed = execute(base, Insn('SD', rs1=10, rs2=0))
before_init = execute(disturb(base), Insn('SD', rs1=10, rs2=0), Insn('LD', rd=7, rs1=10))
after_init = execute(disturb(zeroed), Insn('LD', rd=7, rs1=10))
unchecked = execute(base, Insn('LD', rd=7, rs1=10))
initialization = {
    'host_write_before_initialization': query(before_init.registers[7] != 0, witness=w),
    'host_write_after_initialization': query(after_init.registers[7] != 0, witness=w),
    'after_initialization_with_isolating_pmp': query(after_init.registers[7] != 0,
        SymbolicPMP.concrete(protected_pmp).allow(w, 1, 'W'), witness=w),
    'baseline_without_initialization': query(unchecked.registers[7] != 0),
}

# Successful validation branch is actual BEQ; the other branch would reject input.
checked = execute(base, Insn('LD', rd=7, rs1=10))
branched = execute(checked, Insn('BEQ', rs1=7, rs2=0, imm=8))
accepted = branched.pc == checked.pc + 8
reference = execute(branched, Insn('LD', rd=8, rs1=10))
reread = execute(disturb(branched), Insn('LD', rd=8, rs1=10))
toctou = {
    'baseline_validation_then_reread': query(accepted, reference.registers[8] != checked.registers[7]),
    'host_write_then_reread': query(accepted, reread.registers[8] != checked.registers[7], witness=w),
    'host_write_then_use_saved_checked_register': query(accepted, disturb(branched).registers[7] != 0),
}
expected = {
    'host_write_before_initialization': 'unsat',
    'host_write_after_initialization': 'sat',
    'after_initialization_with_isolating_pmp': 'unsat',
    'baseline_without_initialization': 'sat',
    'baseline_validation_then_reread': 'unsat',
    'host_write_then_reread': 'sat',
    'host_write_then_use_saved_checked_register': 'unsat',
}
matched = all(report['status'] == expected[name] for name, report in {**initialization, **toctou}.items())
for name, reports in conf.items():
    wanted = 'unsat' if name == 'fully_erased' else 'sat'
    matched = matched and reports['semantic_read_restriction_needed']['status'] == wanted
    matched = matched and reports['host_read_with_open_pmp']['status'] == wanted
    matched = matched and reports['host_read_with_isolating_pmp']['status'] == 'unsat'
print(json.dumps({'scope': 'path-local proposal probe, not integrated analyzer or full CFG proof',
                  'expected_results_match': matched,
                  'confidentiality': conf, 'initialization': initialization, 'toctou': toctou}, indent=2))
if not matched:
    raise SystemExit('an experiment was inconclusive or differed from the stated hypothesis')
