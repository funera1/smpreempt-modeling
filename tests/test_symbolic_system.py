import importlib.util
import unittest

HAS_Z3 = importlib.util.find_spec("z3") is not None
if HAS_Z3:
    import z3
    from smpreempt.model.riscv_model import (
        Insn, Machine, PM, Unsupported, pmp_allow,
        step, _pmp_installable, PMP_ADDR_BITS,
    )
    from smpreempt.scenarios import demo_machine
    from smpreempt.model.symbolic_pmp import SymbolicPMP
    from smpreempt.analysis.symbolic_system import (
        BoundedSystem, find_counterexample, STEP, PREEMPT, HOST_SD, RESUME,
        ACCESS_FAULT, MISALIGNED, PM_REJECTED, EXIT,
    )


@unittest.skipUnless(HAS_Z3, "install requirements-smt.txt to run SMT tests")
class SymbolicPMPTests(unittest.TestCase):
    def test_byte_and_word_permissions_against_concrete(self):
        s, _, _, _ = demo_machine()
        for mode in range(4):
            for permissions in (0, 1, 3, 5, 7):
                s.P.cfg[0] = mode << 3 | permissions
                symbolic = SymbolicPMP.concrete(s.P)
                for address in (0x7ffc, 0x8000, 0x80ff, 0x8100):
                    for size in (1, 8):
                        for kind in ("R", "W"):
                            allowed = z3.simplify(symbolic.allow(z3.BitVecVal(address, 64), size, kind))
                            self.assertEqual(z3.is_true(allowed), pmp_allow(s.P, "S", address, size, kind))

    def test_empty_and_reversed_tor_entries_do_not_match(self):
        s, _, _, _ = demo_machine()
        for previous, current in ((0x2000, 0x2000), (0x2001, 0x2000)):
            s.P.cfg[0], s.P.cfg[1], s.P.cfg[2] = 0, 1 << 3, (3 << 3) | 7
            s.P.addr[0], s.P.addr[1], s.P.addr[2] = previous, current, 0x1fff
            symbolic = SymbolicPMP.concrete(s.P)
            address = 0x7ffc
            self.assertEqual(z3.is_true(z3.simplify(symbolic.allow(z3.BitVecVal(address, 64), 8, "R"))),
                             pmp_allow(s.P, "S", address, 8, "R"))

    def test_ranges_and_priority_against_concrete(self):
        s, _, _, _ = demo_machine()
        for mode in range(4):
            for lock in (0, 0x80):
                s.P.cfg[0] = lock | mode << 3 | 1
                for encoded in (0, 0x2000, 0x201f, (1 << PMP_ADDR_BITS) - 1):
                    s.P.addr[0] = encoded
                    symbolic = SymbolicPMP.concrete(s.P)
                    for address in (0, 0x7ffc, 0x8000, 0x80fc, 0x8100, (1 << 64) - 8):
                        for priv in ("M", "S", "U"):
                            for kind in ("R", "W", "X"):
                                allowed = z3.simplify(symbolic.allow(z3.BitVecVal(address, 64), 8, kind, priv))
                                self.assertEqual(z3.is_true(allowed), pmp_allow(s.P, priv, address, 8, kind))

    def test_csr_writes_and_installability_against_concrete(self):
        for locked_tor in (False, True):
            s, target, _, _ = demo_machine()
            if locked_tor:
                s.P.cfg[1] = 0x80 | (1 << 3) | 1
            symbolic = SymbolicPMP.concrete(s.P)
            for csr, value in (("pmpaddr0", (1 << 64) - 1), ("pmpaddr1", 0x1234),
                               ("pmpcfg0", 0x1818), ("pmpcfg0", 0)):
                s.E.put(5, value)
                expected = step(s, Insn("CSRW", rs1=5, csr=csr))
                written, supported = symbolic.write(csr, z3.BitVecVal(value, 64))
                self.assertTrue(z3.is_true(z3.simplify(supported)))
                self.assertTrue(z3.is_true(z3.simplify(written.same_as(SymbolicPMP.concrete(expected.P)))))
            self.assertEqual(z3.is_true(z3.simplify(symbolic.installable(SymbolicPMP.concrete(target)))),
                             _pmp_installable(s.P, target))
        written, supported = symbolic.write("pmpcfg0", z3.BitVecVal(2, 64))
        self.assertTrue(z3.is_false(z3.simplify(supported)))


@unittest.skipUnless(HAS_Z3, "install requirements-smt.txt to run SMT tests")
class SymbolicSystemTests(unittest.TestCase):
    def test_zero_bound_and_invalid_bound(self):
        s, _, _, _ = demo_machine()
        program = {s.E.pc: Insn("JAL", imm=0)}
        self.assertEqual(find_counterexample(Machine(s), program, PM(None), bound=0)["status"], "bounded_unsat")
        with self.assertRaises(ValueError):
            find_counterexample(Machine(s), program, PM(None), bound=-1)

    def test_shared_history_counterexample_is_replayed(self):
        s, template, _, _ = demo_machine()
        s.E.put(10, 0x2000)
        program = {0x4000: Insn("LD", rs1=10), 0x4004: Insn("JAL", imm=0)}
        result = find_counterexample(Machine(s), program, PM(template), bound=2)
        self.assertEqual(result["status"], "counterexample")
        self.assertEqual(result["depth"], 2)
        self.assertTrue(result["replayed"])
        self.assertTrue(0x2000 <= result["address"] < 0x2008)

    def demo_program(self):
        s, template, snippet, _ = demo_machine()
        instructions = [Insn("LD", rd=7, rs1=10)] + snippet
        program = {s.E.pc + 4 * i: insn for i, insn in enumerate(instructions)}
        return s, template, program

    def test_composed_counterexample_and_bound(self):
        s, template, program = self.demo_program()
        self.assertEqual(find_counterexample(Machine(s), program, PM(None), bound=2,
                                             timeout_ms=30000)["status"], "bounded_unsat")
        result = find_counterexample(Machine(s), program, PM(None), bound=3, timeout_ms=30000)
        self.assertEqual(result["status"], "counterexample")
        self.assertEqual(result["depth"], 3)
        self.assertTrue(result["replayed"])
        self.assertEqual([event["action"] for event in result["trace"]],
                         ["instruction", "instruction", "preempt"])
        safe = find_counterexample(Machine(s), program, PM(template, enforce_history=True),
                                   bound=3, timeout_ms=30000)
        self.assertEqual(safe["status"], "bounded_unsat")

    def test_repeated_switches_symbolic_host_write_and_saved_state(self):
        s, template, program = self.demo_program()
        system = BoundedSystem(Machine(s), program, PM(template, enforce_history=True), timeout_ms=20000)
        schedule = (STEP, PREEMPT, HOST_SD, RESUME, STEP, STEP, PREEMPT, RESUME)
        for action in schedule:
            system.extend()
            choice = system.choices[-1]
            system.solver.add(choice.action == action)
            if action == HOST_SD:
                system.solver.add(choice.address == 0x2000, choice.value == 0xFEED)
        self.assertEqual(system.solver.check(), z3.sat)
        machine, trace = system.replay(system.solver.model(), len(schedule))
        self.assertEqual(machine.S.M.load(0x2000, 8), 0xFEED)
        self.assertEqual(machine.S.M.load(0x8000, 8), 0)
        self.assertEqual(machine.S.E.get(7), 0x1122334455667788)
        self.assertEqual(machine.accessed, frozenset(range(0x8000, 0x8008)))
        self.assertEqual(sum(e["action"] == "preempt" for e in trace), 2)

    def test_branch_selects_pc_and_host_input_survives_resume(self):
        s, template, _, _ = demo_machine()
        s.E.put(10, 0x2000)
        program = {0x4000: Insn("LD", rd=7, rs1=10),
                   0x4004: Insn("BEQ", rs1=7, rs2=0, imm=8),
                   0x4008: Insn("CSRW", rs1=5, csr="pmpcfg0"),
                   0x400c: Insn("JAL", imm=0)}
        # Force a symbolic Host write before SM's first read. It controls branch.
        system = BoundedSystem(Machine(s), program, PM(template))
        for action in (PREEMPT, HOST_SD, RESUME, STEP, STEP):
            system.extend()
            choice = system.choices[-1]
            system.solver.add(choice.action == action)
            if action == HOST_SD:
                system.solver.add(choice.address == 0x2000, choice.value != 0)
        system.solver.add(system.states[-1].q.pc == 0x4008)
        self.assertEqual(system.solver.check(), z3.sat)
        machine, _ = system.replay(system.solver.model(), 5)
        self.assertNotEqual(machine.S.E.get(7), 0)
        self.assertEqual(machine.S.E.pc, 0x4008)

    def test_refusal_fault_and_exit_are_explicit_terminals(self):
        s, template, _, _ = demo_machine()
        s.E.put(10, 0x2000)
        s = Machine(s).instruction(Insn("LD", rs1=10))
        program = {s.S.E.pc: Insn("JAL", imm=0)}
        system = BoundedSystem(s, program, PM(template, enforce_history=True))
        system.extend()
        system.solver.add(system.choices[0].action == PREEMPT,
                          system.states[1].status == PM_REJECTED)
        self.assertEqual(system.solver.check(), z3.sat)
        system.replay(system.solver.model(), 1)
        result = find_counterexample(s, program, PM(template, enforce_history=True), bound=1)
        self.assertEqual(result["status"], "bounded_unsat")
        self.assertTrue(result["pm_rejection_reachable"])
        initial, _, _, _ = demo_machine()
        for address, status in ((0x8000, ACCESS_FAULT), (0x8001, MISALIGNED)):
            initial.E.priv = "S"
            initial.E.put(10, address)
            system = BoundedSystem(Machine(initial, "C"), {0x4000: Insn("LD", rs1=10)}, PM(None))
            system.extend()
            system.solver.add(system.choices[0].action == STEP, system.states[1].status == status)
            self.assertEqual(system.solver.check(), z3.sat)
            system.replay(system.solver.model(), 1)
        system = BoundedSystem(Machine(initial, "C"), {}, PM(None), exits={0x4000})
        system.extend()
        system.solver.add(system.states[1].status == EXIT)
        self.assertEqual(system.solver.check(), z3.sat)
        system.replay(system.solver.model(), 1)

    def test_gaps_and_unsupported_are_not_safe_results(self):
        s, _, _, _ = demo_machine()
        result = find_counterexample(Machine(s), {}, PM(None), bound=1)
        self.assertEqual(result["status"], "incomplete")
        s.E.put(5, 2)  # reserved R=0,W=1 encoding
        result = find_counterexample(Machine(s), {0x4000: Insn("CSRW", rs1=5, csr="pmpcfg0")}, PM(None), bound=1)
        self.assertEqual(result["status"], "incomplete")
        with self.assertRaises(Unsupported):
            BoundedSystem(Machine(s), {0x4000: Insn("ECALL")}, PM(None))


if __name__ == "__main__":
    unittest.main()
