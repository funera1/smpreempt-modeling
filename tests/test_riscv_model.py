import unittest
from copy import deepcopy
from smpreempt.model.riscv_model import (
    State, Insn, step, pmp_allow,
    PM, Machine, HostAction, ProtectionPolicy, AccessFault, IllegalInstruction,
)
from smpreempt.scenarios import demo_machine


class ModelTests(unittest.TestCase):
    def test_switch_protection_at_each_scrub_boundary(self):
        s, template, program, regions = demo_machine()
        policy = ProtectionPolicy(tuple(regions))
        machine = Machine(s)
        for cut in range(len(program) + 1):
            exposed = cut in (1, 2, 3)
            host = machine.preempt(PM(None))
            self.assertEqual(bool(policy.violations(host.S.P)), exposed)
            if exposed:
                read = HostAction("LD", 0x8008).execute(host)
                expected = 0 if cut == 3 else 0x8877665544332211
                self.assertEqual(read.S.E.get(12), expected)
                written = HostAction("SD", 0x8008, 7).execute(host)
                self.assertEqual(written.S.M.load(0x8008, 8), 7)
            safe = machine.preempt(PM(template, policy))
            for operation in ("LD", "SD"):
                with self.assertRaises(AccessFault):
                    HostAction(operation, 0x8008, 7).execute(safe)
            if cut < len(program):
                machine = machine.instruction(program[cut])

    def test_arithmetic_and_zero(self):
        s = State()
        s.E.put(1, 5)
        s.E.put(2, 7)
        n = step(s, Insn("ADD", rd=3, rs1=1, rs2=2))
        self.assertEqual(n.E.get(3), 12)
        self.assertEqual(s.E.get(3), 0)
        n = step(n, Insn("ADD", rd=0, rs1=1, rs2=2))
        self.assertEqual(n.E.get(0), 0)

    def test_pmp_priority_and_partial_overlap(self):
        s, _, _, _ = demo_machine()
        self.assertFalse(pmp_allow(s.P, "S", 0x8000, 8, "R"))
        self.assertTrue(pmp_allow(s.P, "M", 0x8000, 8, "R"))
        self.assertFalse(pmp_allow(s.P, "S", 0x7ffc, 8, "R"))
        self.assertTrue(pmp_allow(s.P, "S", 0x7000, 8, "R"))

    def test_locked_entry(self):
        s, _, _, _ = demo_machine()
        s.P.cfg[0] |= 0x80
        before = deepcopy(s.P)
        s.E.put(5, 0)
        s = step(s, Insn("CSRW", rs1=5, csr="pmpcfg0"))
        self.assertEqual(s.P.cfg[0], before.cfg[0])
        self.assertFalse(pmp_allow(s.P, "M", 0x8000, 8, "R"))
        s.E.put(5, 0x4000)
        s = step(s, Insn("CSRW", rs1=5, csr="pmpaddr0"))
        self.assertEqual(s.P.addr[0], before.addr[0])

    def test_lower_priv_cannot_write_pmp(self):
        s, _, _, _ = demo_machine()
        s.E.priv = "S"
        with self.assertRaises(IllegalInstruction):
            step(s, Insn("CSRW", rs1=5, csr="pmpcfg0"))


    def test_context_transitions(self):
        s, template, program, _ = demo_machine()
        m = Machine(s, "SM")
        m = m.instruction(program[0])
        self.assertEqual(m.c, "SM")
        m = m.preempt(PM(template))
        self.assertEqual(m.c, "H")
        self.assertIsNotNone(m.suspended)
        m.S.E.put(10, 0x8000)
        with self.assertRaises(AccessFault):
            m.instruction(Insn("LD", rd=5, rs1=10))  # Host cannot read EPM
        m = m.resume(PM(template))
        self.assertEqual(m.c, "SM")
        self.assertEqual(m.S.E.pc, 0x4004)

    def test_pmp_csrs_change_protection(self):
        s, _, _, _ = demo_machine()
        s.E.put(7, 0x100)
        s2 = step(s, Insn("CSRW", rs1=7, csr="pmpaddr0"))
        self.assertNotEqual(s.P.addr[0], s2.P.addr[0])
        self.assertEqual(s2.E.pc, 0x4004)

    def test_load_store_and_bare_translation(self):
        s, _, _, _ = demo_machine()
        s.E.put(10, 0x2000)
        s.E.put(11, 1234)
        s = step(s, Insn("SD", rs1=10, rs2=11))
        s = step(s, Insn("LD", rd=12, rs1=10))
        self.assertEqual(s.E.get(12), 1234)

    def test_host_mutates_unprotected_memory_pm_does_not_undo(self):
        s, template, _, _ = demo_machine()
        host, saved = PM(template).switchout(s)
        host.M.store(0x2000, 8, 123)
        resumed = PM(template).switchin(host, saved)
        self.assertEqual(resumed.M.load(0x2000, 8), 123)


if __name__ == "__main__":
    unittest.main()
