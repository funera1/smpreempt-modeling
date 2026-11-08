"""Behavioral checks for bounded ELF PMP instruction transitions."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

import z3

from examples.elf.build_fixture import build_elf
from smpreempt.analysis.elf_pmp_steps import execute_function
from smpreempt.frontend.elf import ELF
from smpreempt.model.symbolic_pmp import SymbolicPMP


def concrete_pmp(cfg=None, addr=None):
    cfg = [0]*16 if cfg is None else cfg
    addr = [0]*16 if addr is None else addr
    return SymbolicPMP(tuple(z3.BitVecVal(x, 8) for x in cfg),
                       tuple(z3.BitVecVal(x, 64) for x in addr))


def csr(number, f3, rd, rs1):
    return number << 20 | rs1 << 15 | f3 << 12 | rd << 7 | 0x73


class ELFPMPExecutionTests(unittest.TestCase):
    def run_words(self, words, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sample.elf'
            path.write_bytes(build_elf(words))
            image = ELF(path)
            return execute_function(image, image.symbol('secret_then_scrub'), **kwargs)

    def test_pmp_operations_follow_real_instruction_order(self):
        report = self.run_words((csr(0x3a0, 2, 10, 0), csr(0x3b0, 1, 0, 11),
                                 csr(0x3a0, 1, 0, 10), 0x12000073, 0x00008067),
                                pmp=concrete_pmp(), registers={11:0x123})
        self.assertEqual(len(report['paths']), 1)
        path = report['paths'][0]
        self.assertEqual(path['status'], 'returned')
        self.assertEqual([event['opcode'] for event in path['trace']],
                         ['CSRRS', 'CSRRW', 'CSRRW', 'SFENCE.VMA', 'JALR'])
        self.assertEqual(path['trace'][1]['csr_before'], '#x0000000000000000')
        self.assertEqual(path['trace'][1]['csr_after'], '#x0000000000000123')

    def test_locked_tor_entry_preserves_preceding_address(self):
        cfg, addr = [0]*16, [0]*16
        cfg[1], addr[0] = 0x89, 0x20
        report = self.run_words((csr(0x3b0, 1, 0, 11), 0x00008067),
                                pmp=concrete_pmp(cfg, addr), registers={11:0x44})
        event = report['paths'][0]['trace'][0]
        self.assertEqual(event['csr_before'], '#x0000000000000020')
        self.assertEqual(event['csr_after'], '#x0000000000000020')

    def test_unsupported_warl_configuration_is_unknown(self):
        report = self.run_words((csr(0x3a0, 1, 0, 10),), pmp=concrete_pmp(), registers={10:2})
        self.assertEqual([p['status'] for p in report['paths']], ['unknown'])
        self.assertIn('WARL', report['paths'][0]['reason'])

    def test_second_rv64_pmpcfg_register_updates_entry_eight(self):
        report = self.run_words((csr(0x3a2, 1, 0, 10), 0x00008067),
                                pmp=concrete_pmp(), registers={10:0x1f})
        self.assertEqual(report['paths'][0]['trace'][0]['csr_after'], '#x000000000000001f')
        self.assertEqual(report['paths'][0]['status'], 'returned')

    def test_csr_immediate_forms_return_old_value_and_modify_address(self):
        report = self.run_words((csr(0x3b0, 5, 10, 31), csr(0x3b0, 7, 11, 3), 0x00008067),
                                pmp=concrete_pmp())
        first, second = report['paths'][0]['trace'][:2]
        self.assertEqual(first['register_result'], '#x0000000000000000')
        self.assertEqual(first['csr_after'], '#x000000000000001f')
        self.assertEqual(second['register_result'], '#x000000000000001f')
        self.assertEqual(second['csr_after'], '#x000000000000001c')

    def test_symbolic_invalid_warl_alternative_is_not_discarded(self):
        report = self.run_words((csr(0x3a0, 1, 0, 10), 0x00008067), pmp=concrete_pmp())
        self.assertEqual({p['status'] for p in report['paths']}, {'returned', 'unknown'})

    def test_step_bound_does_not_count_as_return(self):
        report = self.run_words((0x00000013, 0x00008067), pmp=concrete_pmp(), max_steps=1)
        self.assertEqual(report['paths'][0]['status'], 'bound_reached')

    def test_symbolic_branch_explores_both_successors(self):
        # beq a0,zero,+8; addi a1,zero,1; ret
        report = self.run_words((0x00050463, 0x00100593, 0x00008067), pmp=concrete_pmp())
        self.assertEqual([p['status'] for p in report['paths']], ['returned', 'returned'])
        self.assertEqual({p['trace'][0]['taken'] for p in report['paths']}, {True, False})

    def test_unsupported_instruction_is_unknown(self):
        report = self.run_words((0x02b50533,), pmp=concrete_pmp())  # mul a0,a0,a1
        self.assertEqual(report['paths'][0]['status'], 'unknown')
        self.assertIn('not implemented', report['paths'][0]['reason'])

    def test_store_load_propagates_memory_value_to_pmp_write(self):
        # sd a1,0(a0); ld a2,0(a0); csrw pmpaddr0,a2; ret
        report = self.run_words((0x00b53023, 0x00053603, csr(0x3b0, 1, 0, 12), 0x00008067),
                                pmp=concrete_pmp(), registers={10:0x8000, 11:0x123})
        path = report['paths'][0]
        self.assertEqual(path['status'], 'returned')
        self.assertEqual([e['opcode'] for e in path['trace']], ['SD', 'LD', 'CSRRW', 'JALR'])
        self.assertEqual(path['trace'][2]['csr_after'], '#x0000000000000123')

    def test_locked_pmp_denial_is_not_normal_memory_execution(self):
        cfg, addr = [0]*16, [0]*16
        cfg[0], addr[0] = 0x98, 0x2000  # locked NAPOT 8-byte region at 0x8000, no R/W
        report = self.run_words((0x00053503,), pmp=concrete_pmp(cfg, addr), registers={10:0x8000})
        self.assertEqual([p['status'] for p in report['paths']], ['unknown'])
        self.assertIn('fail PMP', report['paths'][0]['reason'])

    def test_store_to_executable_bytes_is_unknown(self):
        report = self.run_words((0x00b53023, 0x00008067), pmp=concrete_pmp(),
                                registers={10:0x1000, 11:0})
        self.assertEqual([p['status'] for p in report['paths']], ['unknown'])
        self.assertIn('executable code', report['paths'][0]['reason'])

    def test_byte_load_sign_extends_stored_data(self):
        report = self.run_words((0x00b50023, 0x00050603, 0x00008067),
                                pmp=concrete_pmp(), registers={10:0x8000, 11:0x80})
        self.assertEqual(report['paths'][0]['trace'][1]['value'], '#xffffffffffffff80')

    def test_shift_immediate_and_addiw_sign_extension(self):
        srli = (63 << 20) | (11 << 15) | (5 << 12) | (12 << 7) | 0x13
        addiw = (1 << 20) | (11 << 15) | (13 << 7) | 0x1b
        report = self.run_words((srli, addiw, 0x00008067), pmp=concrete_pmp(),
                                registers={11:0x7fffffff})
        self.assertEqual(report['paths'][0]['trace'][0]['result'], '#x0000000000000000')
        self.assertEqual(report['paths'][0]['trace'][1]['result'], '#xffffffff80000000')

    def test_compressed_keystone_style_prologue(self):
        # c.addi sp,-16; c.sdsp ra,8(sp); c.sdsp s0,0(sp); c.addi4spn s0,sp,16; ret
        report = self.run_words((0xe4061141, 0x0800e022, 0x00008067), pmp=concrete_pmp(),
                                registers={2:0x90000000, 1:0xdeadbeef, 8:0x1234})
        path = report['paths'][0]
        self.assertEqual(path['status'], 'returned')
        self.assertEqual([e['opcode'] for e in path['trace']],
                         ['C.ADDI', 'SD', 'SD', 'C.ADDI4SPN', 'JALR'])
        self.assertEqual(path['trace'][1]['address'], '#x000000008ffffff8')
        self.assertEqual(path['trace'][2]['address'], '#x000000008ffffff0')
        self.assertEqual(path['trace'][3]['result'], '#x0000000090000000')

    def test_compressed_load_and_andi(self):
        # c.lw a2,4(a1); c.andi a2,1; ret
        report = self.run_words((0x8a0541d0, 0x00008067), pmp=concrete_pmp(),
                                registers={11:0x8000}, memory_bytes={0x8004:0xff, 0x8005:0,
                                                                   0x8006:0, 0x8007:0})
        self.assertEqual(report['paths'][0]['trace'][0]['address'], '#x0000000000008004')
        self.assertEqual(report['paths'][0]['trace'][1]['result'], '#x0000000000000001')

    def test_compressed_jump_decodes_target(self):
        report = self.run_words((0x0001a4e1,), pmp=concrete_pmp())
        self.assertEqual(report['paths'][0]['trace'][0]['target'], '0x12c8')
        self.assertEqual(report['paths'][0]['status'], 'unknown')

    def test_mtvec_requires_opt_in_and_preserves_old_value(self):
        words = (csr(0x305, 1, 5, 5), csr(0x305, 1, 0, 5), 0x00008067)
        without = self.run_words(words, pmp=concrete_pmp(), registers={5:0x80000000})
        self.assertEqual(without['paths'][0]['status'], 'unknown')
        with_profile = self.run_words(words, pmp=concrete_pmp(), registers={5:0x80000000},
                                      assume_mtvec_writable=True)
        path = with_profile['paths'][0]
        self.assertEqual(path['status'], 'returned')
        self.assertEqual(path['trace'][0]['csr_after'], '#x0000000080000000')
        self.assertEqual(path['trace'][1]['csr_after'], 'initial_mtvec')

    def test_concrete_compressed_jump_table_target_is_followed(self):
        # c.jr a4; c.nop; ret, with the jump-table result supplied in a4
        report = self.run_words((0x00018702, 0x00008067), pmp=concrete_pmp(),
                                registers={14:0x1004})
        self.assertEqual(report['paths'][0]['status'], 'returned')
        self.assertEqual(report['paths'][0]['trace'][0]['target'], '0x1004')

    def test_concrete_jalr_outside_function_stays_unknown(self):
        # jalr ra,8(ra) attempts to call an external function.
        report = self.run_words((0x008080e7,), pmp=concrete_pmp(), registers={1:0x2000})
        self.assertEqual(report['paths'][0]['status'], 'unknown')
        self.assertEqual(report['paths'][0]['trace'][0]['target'], '0x2008')
        self.assertIn('left selected function', report['paths'][0]['reason'])

    def test_cli_initial_memory_is_little_endian_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sample.elf'
            pmp_path = Path(directory)/'pmp.json'
            # lw a2,4(a1); csrw pmpaddr0,a2; ret
            path.write_bytes(build_elf((0x0045a603, csr(0x3b0, 1, 0, 12), 0x00008067)))
            pmp_path.write_text(json.dumps({'cfg':[0]*16, 'addr':[0]*16}))
            output = subprocess.check_output([sys.executable, '-m', 'smpreempt.exploration.step_elf_pmp',
                str(path), '--function', 'secret_then_scrub', '--pmp-json', str(pmp_path),
                '--reg', 'x11=0x8000', '--mem32', '0x8004=0x123'])
        report = json.loads(output)
        self.assertEqual(report['paths'][0]['trace'][1]['csr_after'], '#x0000000000000123')
        self.assertEqual(report['initial_memory_bytes']['0x8004'], '0x23')
        self.assertEqual(report['initial_memory_bytes']['0x8005'], '0x1')
