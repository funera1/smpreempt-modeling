"""Per-PC access checks preserve witnesses and incomplete outcomes."""
from pathlib import Path
import json
import struct
import subprocess
import sys
import tempfile
import unittest

import z3

from examples.elf.build_fixture import build_elf
from smpreempt.analysis.elf_preemption import check_boundaries
from smpreempt.frontend.elf import ELF
from smpreempt.model.symbolic_pmp import SymbolicPMP


def pmp(cfg0=0x1f, addr0=0x2000):
    return SymbolicPMP(tuple(z3.BitVecVal(v, 8) for v in [cfg0]+[0]*15),
                       tuple(z3.BitVecVal(v, 64) for v in [addr0]+[0]*15))


class ELFPreemptionTests(unittest.TestCase):
    def check(self, words, **options):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'example.elf'
            path.write_bytes(build_elf(words))
            image = ELF(path)
            return check_boundaries(image, image.symbol('secret_then_scrub'),
                                    region_base=0x8000, region_size=8, **options)

    def test_current_pmp_changes_access_at_next_boundary(self):
        # csrw pmpaddr0,x0; nop; ret
        report = self.check((0x3b001073, 0x00000013, 0x00008067),
                            pmp=pmp(), assume_fresh_pmp=True)
        by_pc = {b['pc']:b for b in report['boundaries']}
        self.assertEqual(by_pc['0x1000']['status'], 'abstract_counterexample')
        self.assertEqual(set(by_pc['0x1000']['witnesses']), {'R', 'W'})
        address = int(by_pc['0x1000']['witnesses']['R']['address'], 16)
        self.assertTrue(0x8000 <= address < 0x8008)
        self.assertEqual(by_pc['0x1004']['status'], 'no_counterexample_within_bound')
        self.assertFalse(report['exploration']['incomplete'])

    def test_synchronization_must_be_explicit(self):
        report = self.check((0x3b001073, 0x00008067), pmp=pmp())
        self.assertTrue(all(b['status'] == 'unknown' for b in report['boundaries']))
        self.assertIn('unspecified', report['boundaries'][0]['reason'])

    def test_step_bound_cannot_produce_safe_result(self):
        report = self.check((0x3b001073, 0x00000013, 0x00008067),
                            pmp=pmp(), assume_fresh_pmp=True, max_steps=1)
        by_pc = {b['pc']:b for b in report['boundaries']}
        self.assertEqual(by_pc['0x1000']['status'], 'abstract_counterexample')
        self.assertEqual(by_pc['0x1004']['status'], 'unknown')
        self.assertTrue(report['exploration']['incomplete'])

    def test_locked_entry_remains_accessible_after_write(self):
        report = self.check((0x3b001073, 0x00008067),
                            pmp=pmp(cfg0=0x9f), assume_fresh_pmp=True)
        self.assertEqual(report['boundaries'][1]['status'], 'abstract_counterexample')

    def test_same_pc_merges_states_conservatively(self):
        # beq a0,zero,+8; csrw pmpaddr0,x0; nop; ret
        report = self.check((0x00050463, 0x3b001073, 0x00000013, 0x00008067),
                            pmp=pmp(), assume_fresh_pmp=True)
        point = next(b for b in report['boundaries'] if b['pc'] == '0x1008')
        self.assertEqual(point['observed_states'], 2)
        self.assertEqual(point['status'], 'abstract_counterexample')

    def test_invalid_region_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'physical-address'):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'example.elf'
                path.write_bytes(build_elf())
                image = ELF(path)
                check_boundaries(image, image.symbol('secret_then_scrub'),
                                 region_base=1 << 56, region_size=1)

    def test_cli_reports_before_and_after_pmp_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'example.elf'
            pmp_path = Path(directory)/'pmp.json'
            path.write_bytes(build_elf((0x3b001073, 0x00008067)))
            pmp_path.write_text(json.dumps({'cfg':[31]+[0]*15, 'addr':[8192]+[0]*15}))
            output = subprocess.check_output([sys.executable, '-m', 'smpreempt.exploration.check_elf_preemption',
                str(path), '--function', 'secret_then_scrub', '--region-base', '0x8000',
                '--region-size', '8', '--pmp-json', str(pmp_path), '--assume-fresh-pmp'])
        report = json.loads(output)
        self.assertEqual([b['status'] for b in report['boundaries']],
                         ['abstract_counterexample', 'no_counterexample_within_bound'])
        self.assertEqual(report['policy']['host_translation'], 'Bare')
        self.assertEqual(report['initial_pmp']['kind'], 'concrete')

    def test_nonidentity_elf_is_rejected(self):
        data = bytearray(build_elf())
        struct.pack_into('<Q', data, 64+24, 0x2000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'example.elf'
            path.write_bytes(data)
            image = ELF(path)
            with self.assertRaisesRegex(ValueError, 'identity'):
                check_boundaries(image, image.symbol('secret_then_scrub'),
                                 region_base=0x8000, region_size=8)
