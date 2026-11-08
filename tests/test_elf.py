"""Implementation-to-model adapter: decoding, coverage and semantic witnesses."""
from pathlib import Path
import struct
import tempfile
import unittest
import importlib.util

from examples.elf.build_fixture import build_elf
from smpreempt.frontend.elf import ELF, decode32
from smpreempt.model.riscv_model import Insn, P, PM

HAS_Z3 = importlib.util.find_spec('z3') is not None
if HAS_Z3:
    from smpreempt.analysis.elf_analysis import analyze_reads


class ELFTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'test.elf'

    def image(self, words=None):
        self.path.write_bytes(build_elf() if words is None else build_elf(words))
        return ELF(self.path)

    def test_load_symbols_and_instructions(self):
        image = self.image()
        self.assertEqual(image.symbol('secret_then_scrub').address, 0x1000)
        self.assertEqual(image.symbol('scrubbed').address, 0x1008)
        self.assertEqual(image.instructions[0x1000].decoded, Insn('SD', rs1=10, rs2=11))
        self.assertEqual(image.instructions[0x1004].decoded, Insn('SD', rs1=10))
        self.assertEqual(image.instructions[0x1008].decoded, Insn('JAL'))
        self.assertEqual(image.report()['unsupported_instructions'], 0)

    def test_decoder_signed_immediates_and_csr(self):
        self.assertEqual(decode32(0xfff50513, 0), Insn('ADDI', rd=10, rs1=10, imm=-1))
        self.assertEqual(decode32(0xfe053c23, 0), Insn('SD', rs1=10, imm=-8))
        self.assertEqual(decode32(0xfe000ee3, 0), Insn('BEQ', imm=-4))
        self.assertEqual(decode32(0xffdff06f, 0), Insn('JAL', imm=-4))
        self.assertEqual(decode32(0x80000537, 0), Insn('ADDI', rd=10, imm=-0x80000000))
        self.assertEqual(decode32(0x00001517, 0x1000), Insn('ADDI', rd=10, imm=0x2000))
        self.assertEqual(decode32(0x3a051073, 0), Insn('CSRW', rs1=10, csr='pmpcfg0'))
        self.assertEqual(decode32(0x12000073, 0), Insn('SFENCE.VMA'))
        self.assertIsNone(decode32(0x12050073, 0))  # selective fence unsupported
        self.assertIsNone(decode32(0x3a051573, 0))  # CSRRW with a readback is not CSRW

    def test_unsupported_and_compressed_stay_in_listing(self):
        image = self.image((0x00000001,))
        self.assertIsNone(image.instructions[0x1000].decoded)
        self.assertEqual(len(image.instructions[0x1000].raw), 2)
        self.assertIn(0x1002, image.instructions)
        self.assertGreater(image.report()['unsupported_instructions'], 0)

    def test_reject_wrong_machine_and_truncated_tables(self):
        data = bytearray(build_elf())
        struct.pack_into('<H', data, 18, 62)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'RISC-V'):
            ELF(self.path)
        self.path.write_bytes(build_elf()[:-10])
        with self.assertRaisesRegex(ValueError, 'outside file'):
            ELF(self.path)

    @unittest.skipUnless(HAS_Z3, 'requires z3')
    def test_semantic_leak_and_concrete_replay(self):
        report = analyze_reads(self.image(), registers={10: 0x8000}, bound=2,
                               pm=PM(P(cfg=[31]+[0]*7, addr=[(1<<54)-1]+[0]*7)))
        self.assertEqual(report['status'], 'counterexample')
        self.assertEqual(report['witness']['depth'], 1)
        self.assertTrue(report['concrete_replayed'])
        self.assertTrue(0x8000 <= int(report['witness']['address'], 16) < 0x8008)
        self.assertNotEqual(*[o['value'] for o in report['concrete_observations']])

    @unittest.skipUnless(HAS_Z3, 'requires z3')
    def test_scrubbed_cut_does_not_leak(self):
        report = analyze_reads(self.image(), registers={10: 0x8000}, bound=3, cuts=(0x1008,),
                               pm=PM(P(cfg=[31]+[0]*7, addr=[(1<<54)-1]+[0]*7)))
        self.assertEqual(report['status'], 'no_counterexample_within_bound')
        self.assertEqual(report['checked_cut_depths'], [2, 3])

    @unittest.skipUnless(HAS_Z3, 'requires z3')
    def test_pm_isolation_and_nonvacuity(self):
        pmp = P(cfg=[24, 31]+[0]*6, addr=[0x2000, (1<<54)-1]+[0]*6)
        report = analyze_reads(self.image(), registers={10: 0x8000}, bound=2, pm=PM(pmp))
        self.assertEqual(report['status'], 'no_counterexample_within_bound')
        self.assertIn(1, report['checked_cut_depths'])
        rejected = analyze_reads(self.image(), registers={10: 0x8000}, bound=1, pm=PM(P()))
        self.assertEqual(rejected['status'], 'incomplete')
        self.assertEqual(rejected['reason'], 'no feasible Host cut')

    @unittest.skipUnless(HAS_Z3, 'requires z3')
    def test_reachable_unknown_is_incomplete_even_at_bound_zero(self):
        report = analyze_reads(self.image((0x00000001,)), bound=0,
                               pm=PM(P(cfg=[31]+[0]*7, addr=[(1<<54)-1]+[0]*7)))
        self.assertEqual(report['status'], 'incomplete')
        self.assertEqual(report['diagnostics'][0]['outcome'], 'model_gap')

    @unittest.skipUnless(HAS_Z3, 'requires z3')
    def test_self_modifying_store_is_incomplete(self):
        report = analyze_reads(self.image(), registers={10: 0x1000}, bound=2,
                               pm=PM(P(cfg=[31]+[0]*7, addr=[(1<<54)-1]+[0]*7)))
        self.assertEqual(report['status'], 'incomplete')
        self.assertIn('executable', report['reason'])

    @unittest.skipUnless(HAS_Z3, 'requires z3')
    def test_nonidentity_load_is_rejected(self):
        data = bytearray(build_elf())
        struct.pack_into('<Q', data, 64+24, 0x2000)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'identity'):
            analyze_reads(ELF(self.path))

    @unittest.skipUnless(HAS_Z3, 'requires z3')
    def test_secret_branch_can_leak_through_different_paths(self):
        # beq a1,zero,+8; sd a1,0(a0); jal zero,0
        image = self.image((0x00058463, 0x00b53023, 0x0000006f))
        report = analyze_reads(image, registers={10: 0x8000}, bound=2,
                               pm=PM(P(cfg=[31]+[0]*7, addr=[(1<<54)-1]+[0]*7)))
        self.assertEqual(report['status'], 'counterexample')
        self.assertTrue(report['concrete_replayed'])


if __name__ == '__main__':
    unittest.main()
