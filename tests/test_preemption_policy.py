import unittest
from copy import deepcopy

from smpreempt.riscv_model import (
    Insn, Machine, ModelFault, PM, ProtectionPolicy, Region, Unsupported,
    napot_encode, pmp_allow, step,
)
from smpreempt.scenarios import demo_machine


class PolicyTests(unittest.TestCase):
    def test_policy_independent_of_template(self):
        s, template, _, regions = demo_machine()
        template.cfg[0] = 0
        with self.assertRaisesRegex(ModelFault, "isolation violation"):
            PM(template, ProtectionPolicy(tuple(regions))).switchout(s)

    def test_interval_check_matches_byte_oracle(self):
        s, _, _, _ = demo_machine()
        region = Region("boundary", 0x7ff0, 0x8110)
        # TOR, NA4, NAPOT, OFF; permissions and overlapping priority.
        for mode in range(4):
            for permissions in (0, 1, 3, 5, 7):
                p = deepcopy(s.P)
                p.cfg[0] = mode << 3 | permissions
                p.addr[0] = napot_encode(0x8000, 0x100)
                oracle = any(pmp_allow(p, "S", a, 1, op)
                             for a in range(region.start, region.end)
                             for op in ("R", "W"))
                self.assertEqual(bool(ProtectionPolicy((region,)).violations(p)), oracle)

    def test_template_cannot_lock_out_resume(self):
        s, template, _, _ = demo_machine()
        template.cfg[0] |= 0x80
        with self.assertRaisesRegex(ModelFault, "prevent resume"):
            PM(template).switchout(s)

    def test_ecall_does_not_grant_host_machine_execution(self):
        s, template, _, _ = demo_machine()
        host = Machine(s).preempt(PM(template))
        with self.assertRaises(Unsupported):
            host.instruction(Insn("ECALL"))
        raw = step(host.S, Insn("ECALL"))
        self.assertEqual(raw.E.priv, "M")
        self.assertEqual(host.S.E.priv, "S")
        with self.assertRaises(ModelFault):
            Machine(raw, "H").instruction(Insn("ADDI"))

    def test_locked_tor_predecessor(self):
        s, _, _, _ = demo_machine()
        s.P.cfg[1] = 0x80 | (1 << 3)
        old_address = s.P.addr[0]
        s.E.put(5, 0x100)
        result = step(s, Insn("CSRW", csr="pmpaddr0", rs1=5))
        self.assertEqual(result.P.addr[0], old_address)


if __name__ == "__main__":
    unittest.main()
