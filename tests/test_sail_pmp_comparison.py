"""Ensure independent Sail logs are compared with concrete CSR effects."""
import unittest

from smpreempt.exploration.compare_sail_pmp import compare


class SailPMPComparisonTests(unittest.TestCase):
    def test_match_and_mismatch(self):
        report = {'paths':[{'status':'returned', 'trace':[
            {'pc':'0x80000004', 'csr':'pmpaddr0', 'csr_read':False, 'csr_write':True,
             'csr_after':'#x0000000000002000'}]}]}
        trace = '[0] [M]: 0x0000000080000004 (0x3B071073) csrrw x0, pmpaddr0, x14\nCSR pmpaddr0 (0x3B0) <- 0x0000000000002000\n'
        self.assertEqual(compare(report, trace)['status'], 'match')
        self.assertEqual(compare(report, trace.replace('2000', '1000'))['status'], 'mismatch')

    def test_symbolic_result_cannot_be_claimed_as_concrete_comparison(self):
        report = {'paths':[{'status':'returned', 'trace':[
            {'pc':'0x4', 'csr':'pmpaddr0', 'csr_read':False, 'csr_write':True,
             'csr_after':'initial_addr0'}]}]}
        with self.assertRaisesRegex(ValueError, 'symbolic'):
            compare(report, '[0] [M]: 0x4 (0x3B071073) csrrw\nCSR pmpaddr0 (0x3B0) <- 0x0\n')
