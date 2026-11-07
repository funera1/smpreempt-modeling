import unittest

from smpreempt.riscv_model import AccessFault, HostAction, Insn, IsolationRejected, Machine, PM
from smpreempt.scenarios import demo_machine


class HistoryTests(unittest.TestCase):
    def test_successful_reads_and_writes_accumulate_physical_bytes(self):
        s, _, _, _ = demo_machine()
        s.E.put(10, 0x2000)
        original = Machine(s)
        read = original.instruction(Insn("LD", rd=10, rs1=10))
        # Uses pre-instruction rs1 even when LD overwrites the address register.
        self.assertEqual(read.accessed, frozenset(range(0x2000, 0x2008)))
        self.assertFalse(original.accessed)
        read.S.E.put(10, 0x2008)
        written = read.instruction(Insn("SD", rs1=10))
        self.assertEqual(written.accessed, frozenset(range(0x2000, 0x2010)))
        self.assertEqual(len(written.history_policy().regions), 1)

    def test_fault_does_not_update_history(self):
        s, _, _, _ = demo_machine()
        s.E.priv = "S"
        s.E.put(10, 0x8000)
        m = Machine(s, "C")
        with self.assertRaises(AccessFault):
            m.instruction(Insn("LD", rs1=10))
        self.assertFalse(m.accessed)

    def test_history_survives_repeated_switches_host_does_not_extend_it(self):
        s, template, _, _ = demo_machine()
        m = Machine(s).instruction(Insn("LD", rs1=10))
        pm = PM(template, enforce_history=True)
        for _ in range(2):
            host = HostAction("SD", 0x2000, 123).execute(m.preempt(pm))
            self.assertEqual(host.accessed, m.accessed)
            resumed = host.resume(pm)
            self.assertEqual(resumed.S.E, m.S.E)
            self.assertEqual(resumed.S.M.load(0x2000, 8), 123)
            self.assertEqual(resumed.accessed, m.accessed)
            m = resumed

    def test_shared_read_makes_template_insufficient(self):
        s, template, _, _ = demo_machine()
        s.E.put(10, 0x2000)
        m = Machine(s).instruction(Insn("LD", rs1=10))
        with self.assertRaises(IsolationRejected):
            m.preempt(PM(template, enforce_history=True))


if __name__ == "__main__":
    unittest.main()
