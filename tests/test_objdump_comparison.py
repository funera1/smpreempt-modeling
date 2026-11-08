import unittest

from smpreempt.exploration.compare_objdump import compare


class ObjdumpComparisonTests(unittest.TestCase):
    def test_matches_mixed_width_and_detects_missing_boundary(self):
        report = {'function':{'name':'f', 'address':'0x1000', 'end':'0x1006'},
                  'instructions':[{'pc':'0x1000', 'bytes':'4111'},
                                  {'pc':'0x1002', 'bytes':'7390053a'}]}
        lines = '  1000:\t1141\tc.addi sp,-16\n  1002:\t3a059073\tcsrw pmpcfg0,a1\n'
        self.assertEqual(compare(report, lines)['status'], 'match')
        self.assertEqual(compare(report, lines.splitlines()[0])['status'], 'mismatch')

    def test_no_in_range_instructions_is_an_error(self):
        report = {'function':{'name':'f', 'address':'0x1000', 'end':'0x1002'},
                  'instructions':[{'pc':'0x1000', 'bytes':'4111'}]}
        with self.assertRaisesRegex(ValueError, 'no instructions'):
            compare(report, '  2000:\t1141\tc.addi sp,-16\n')
