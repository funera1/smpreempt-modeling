import importlib.util
import unittest

from smpreempt.model.riscv_model import AccessFault, Insn, Machine, PM, ProtectionPolicy, Region, State
from smpreempt.scenarios import demo_machine

HAS_Z3 = importlib.util.find_spec("z3") is not None
if HAS_Z3:
    import z3
    from smpreempt.analysis.host_attacks import HostMemory, analyze_host_attacks
    from smpreempt.model.symbolic_pmp import SymbolicPMP


class ByteAccessTests(unittest.TestCase):
    def test_byte_replay_zero_extension_truncation_and_history(self):
        s = State()
        s.E.put(10, 0x3001)
        s.E.put(11, 0x1234)
        s.M.store(0x3000, 3, 0xAAFE55)
        m = Machine(s).instruction(Insn("LBU", rd=12, rs1=10))
        self.assertEqual(m.S.E.get(12), 0xFE)
        m = m.instruction(Insn("SB", rs1=10, rs2=11))
        self.assertEqual(m.S.M.load(0x3000, 3), 0xAA3455)
        self.assertEqual(m.accessed, frozenset({0x3001}))
        m.S.E.priv = "S"
        with self.assertRaises(AccessFault):
            m.instruction(Insn("LBU", rs1=10))


@unittest.skipUnless(HAS_Z3, "install requirements-smt.txt to run symbolic tests")
class HostOnlyAttackTests(unittest.TestCase):
    def history(self, address):
        return z3.Store(z3.K(z3.BitVecSort(64), z3.BoolVal(False)),
                        z3.BitVecVal(address, 64), z3.BoolVal(True))

    def test_arbitrary_states_yield_host_only_read_and_write_witnesses(self):
        _, template, _, _ = demo_machine()
        for pm in (PM(None), PM(template)):
            with self.subTest(template=pm.safe_host_pmp is not None):
                result = analyze_host_attacks(pm)
                self.assertEqual(result["status"], "attack_found")
                for attack, operation in (("protected_read", "LBU"), ("protected_write", "SB")):
                    witness = result["attacks"][attack]["witness"]
                    self.assertTrue(witness["projection_replayed"])
                    self.assertTrue(witness["in_history"])
                    self.assertEqual([e["operation"] for e in witness["host_trace"]], [operation])
                write = result["attacks"]["protected_write"]["witness"]["host_trace"][0]
                self.assertNotEqual(write["before"], write["after"])
                self.assertNotIn("control", result)

    def test_history_inside_denied_region_has_no_direct_attack(self):
        _, template, _, _ = demo_machine()
        result = analyze_host_attacks(PM(template), constrain=lambda s: s.q.history == self.history(0x8000))
        self.assertEqual(result["status"], "no_direct_data_attack_in_model")
        self.assertEqual(result["state_set"], "constrained_K0")
        self.assertEqual(result["startup"]["host_start"]["status"], "sat")
        self.assertTrue(all(a["status"] == "unsat" for a in result["attacks"].values()))

    def test_read_and_write_attacks_are_separate(self):
        _, template, _, _ = demo_machine()
        template.cfg[1] &= ~2
        result = analyze_host_attacks(PM(template))
        self.assertEqual(result["attacks"]["protected_read"]["status"], "sat")
        self.assertEqual(result["attacks"]["protected_write"]["status"], "unsat")

    def test_fixed_protected_region_is_independent_of_history(self):
        _, template, _, _ = demo_machine()
        pm = PM(template, ProtectionPolicy((Region("private", 0x2000, 0x2001),)))
        result = analyze_host_attacks(pm, constrain=lambda s: s.q.history == z3.K(
            z3.BitVecSort(64), z3.BoolVal(False)))
        for attack in result["attacks"].values():
            self.assertEqual(attack["status"], "sat")
            self.assertFalse(attack["witness"]["in_history"])
            self.assertEqual(attack["witness"]["fixed_regions"], ["private"])

    def test_no_host_execution_is_not_a_security_success(self):
        state = State()
        result = analyze_host_attacks(PM(state.P))
        self.assertEqual(result["status"], "host_unavailable")
        self.assertEqual(result["startup"]["entry_not_executable"]["status"], "sat")
        s, template, _, _ = demo_machine()
        s.P.cfg[0] |= 0x80
        result = analyze_host_attacks(PM(template),
            constrain=lambda initial: initial.pmp.same_as(SymbolicPMP.concrete(s.P)))
        self.assertEqual(result["status"], "host_unavailable")
        self.assertEqual(result["startup"]["install_blocked"]["status"], "sat")

    def test_restore_failure_does_not_hide_host_only_attacks(self):
        state, template, _, _ = demo_machine()
        template.cfg[0] |= 0x80
        result = analyze_host_attacks(PM(template), constrain=lambda s: z3.And(
            s.pmp.same_as(SymbolicPMP.concrete(state.P)), s.q.history == self.history(0x2000)))
        self.assertEqual(result["status"], "attack_found")
        self.assertEqual(result["startup"]["restore_blocked_after_start"]["status"], "sat")
        self.assertEqual(result["attacks"]["protected_read"]["status"], "sat")

    def test_host_write_summary_preserves_every_unwritable_byte(self):
        _, template, _, _ = demo_machine()
        effect = HostMemory(SymbolicPMP.concrete(template))
        before, after = (z3.Array(name, z3.BitVecSort(64), z3.BitVecSort(8))
                         for name in ("frame_before", "frame_after"))
        address = z3.BitVec("frame_address", 64)
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(effect.closure(before, after), z3.Not(effect.pmp.allow(address, 1, "W")),
                   z3.Select(before, address) != z3.Select(after, address))
        self.assertEqual(solver.check(), z3.unsat)

    def test_empty_domain_and_invalid_limits(self):
        _, template, _, _ = demo_machine()
        self.assertEqual(analyze_host_attacks(PM(template), constrain=lambda s: z3.BoolVal(False))["status"],
                         "empty_domain")
        with self.assertRaises(ValueError):
            analyze_host_attacks(PM(template), timeout_ms=0)


if __name__ == "__main__":
    unittest.main()
