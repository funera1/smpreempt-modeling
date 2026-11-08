"""Architectural operation classification without enclave policy assumptions."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

from smpreempt.model.riscv_memory_operations import catalogue, normalize_instruction, normalize_sequence, csr_name

ROOT = Path(__file__).resolve().parents[1]


class MemoryOperationTests(unittest.TestCase):
    def test_catalogue_covers_requested_families_without_claiming_full_isa(self):
        report = catalogue()
        operations = {o['id']: o for o in report['operations']}
        self.assertEqual(len(operations), len(report['operations']))
        self.assertTrue({'pmp.address.write', 'pmp.config.write', 'pmp.security.write',
                         'translation.satp.write', 'translation.pte.write', 'translation.sfence.vma',
                         'privilege.mstatus.write', 'privilege.sstatus.write', 'attributes.platform.change'} <= operations.keys())
        self.assertIn('attack success', report['not_inferred'])
        self.assertTrue(all(o['normal_relation'] and o['sources'] for o in operations.values()))
        report['operations'][0]['notes'].append('mutation')
        self.assertNotIn('mutation', catalogue()['operations'][0]['notes'])

    def test_csrrw_is_one_atomic_instruction_with_prestate_source(self):
        operation = normalize_instruction(dict(opcode='CSRRW', csr='pmpcfg0', rd=5, rs1=5))
        self.assertEqual(operation['operation'], 'pmp.config.write')
        self.assertTrue(operation['csr_read'])
        self.assertTrue(operation['csr_write'])
        self.assertEqual(operation['requested_value'], {'operator': 'read_gpr_before', 'index': 5})
        self.assertEqual(operation['result_expression'], {'operator': 'csr_before', 'csr': 'pmpcfg0'})
        self.assertEqual(len(normalize_sequence([operation['decoded']])['transitions']), 1)

    def test_csrrw_x0_suppresses_read_but_still_writes_zero(self):
        operation = normalize_instruction(dict(opcode='CSRRW', csr='pmpaddr0', rd=0, rs1=0))
        self.assertFalse(operation['csr_read'])
        self.assertTrue(operation['csr_write'])
        self.assertEqual(operation['requested_value']['value'], 0)

    def test_csrrs_write_suppression_is_by_register_identity(self):
        read = normalize_instruction(dict(opcode='CSRRS', csr='pmpcfg0', rd=0, rs1=0))
        self.assertTrue(read['csr_read'])
        self.assertFalse(read['csr_write'])
        self.assertEqual(read['operation'], 'csr.read')
        # A nonzero register index requests a write even if its runtime value is zero.
        write = normalize_instruction(dict(opcode='CSRRS', csr='pmpcfg0', rd=0, rs1=5))
        self.assertTrue(write['csr_write'])
        self.assertEqual(write['requested_value']['operator'], 'or')

    def test_csr_immediates_aliases_and_clear(self):
        immediate = normalize_instruction(dict(opcode='CSRRCI', csr='mstatus', rd=8, zimm=0))
        self.assertFalse(immediate['csr_write'])
        replace = normalize_instruction(dict(opcode='CSRWI', csr='mstatus', zimm=0))
        self.assertTrue(replace['csr_write'])
        self.assertFalse(replace['csr_read'])
        clear = normalize_instruction(dict(opcode='CSRC', csr='mstatus', rs1=6))
        self.assertEqual(clear['requested_value']['operator'], 'and_not')
        alias = normalize_instruction(dict(opcode='CSRR', csr='mstatus', rd=9))
        self.assertFalse(alias['csr_write'])
        with self.assertRaises(ValueError):
            normalize_instruction(dict(opcode='CSRRWI', csr='mstatus', rd=0, zimm=32))

    def test_csr_addresses_and_unknown_csr_are_not_nops(self):
        self.assertEqual(csr_name(0x3a2), 'pmpcfg2')
        self.assertEqual(csr_name('0x3b3'), 'pmpaddr3')
        known = normalize_instruction(dict(opcode='CSRW', csr=0x747, rs1=4))
        self.assertEqual(known['operation'], 'pmp.security.write')
        unknown = normalize_instruction(dict(opcode='CSRW', csr='custom_secret_control', rs1=4))
        self.assertTrue(unknown['unknown_effect'])
        self.assertTrue(unknown['csr_write'])

    def test_sfence_scope_depends_on_register_identity_not_value(self):
        full = normalize_instruction(dict(opcode='SFENCE.VMA', rs1=0, rs2=0))
        selected = normalize_instruction(dict(opcode='SFENCE.VMA', rs1=5, rs2=6))
        self.assertTrue(full['address_selector']['all'])
        self.assertTrue(full['identifier_selector']['all'])
        self.assertFalse(selected['address_selector']['all'])
        self.assertFalse(selected['identifier_selector']['all'])
        self.assertFalse(full['ordinary_memory_change'])
        self.assertEqual(full['hart_scope'], 'current hart')

    def test_pte_is_a_contextual_store_not_two_stores(self):
        store = dict(opcode='SD', rs1=10, rs2=11, imm=0)
        ordinary = normalize_instruction(store)
        self.assertEqual(ordinary['operation'], 'memory.store')
        store.update(memory_role='pte', role_evidence='page-table object from caller', facets=['PBMT'])
        pte = normalize_instruction(store)
        self.assertEqual(pte['operation'], 'translation.pte.write')
        self.assertEqual(pte['underlying_operation'], 'memory.store')
        self.assertEqual(pte['memory_effect_count'], 1)
        del store['role_evidence']
        with self.assertRaisesRegex(ValueError, 'role_evidence'):
            normalize_instruction(store)

    def test_atomic_conditional_store_and_extensions(self):
        amo = normalize_instruction(dict(opcode='AMOADD.W', rd=5, rs1=6, rs2=7, aq=True))
        self.assertEqual(amo['operation'], 'memory.amo')
        sc = normalize_instruction(dict(opcode='SC.D', rd=5, rs1=6, rs2=7))
        self.assertEqual(sc['operation'], 'memory.lrsc')
        zero = normalize_instruction(dict(opcode='CBO.ZERO', rs1=6))
        self.assertEqual(zero['operation'], 'cache.zero')
        guest = normalize_instruction(dict(opcode='HFENCE.GVMA', rs1=0, rs2=0))
        self.assertEqual(guest['operation'], 'translation.hfence')

    def test_sequence_retains_unknowns_and_instruction_boundaries(self):
        sequence = normalize_sequence([dict(opcode='CSRW', csr='pmpcfg0', rs1=5),
                                       dict(opcode='UNMODELED'), dict(opcode='SFENCE.VMA')])
        self.assertEqual(sequence['interruption_boundaries'], ['s0', 's1', 's2', 's3'])
        self.assertEqual(sequence['unknown_steps'], [1])
        with self.assertRaises(ValueError):
            normalize_instruction(dict(opcode='SD', rs1=3))

    def test_cli_catalogue_and_example(self):
        command = [sys.executable, '-m', 'smpreempt.exploration.riscv_memory_operations']
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
        self.assertEqual(len(json.loads(result.stdout)['operations']), 22)
        example = subprocess.run(command+['--input', 'examples/riscv-memory-ops/pmp-update.json'],
                                 cwd=ROOT, text=True, capture_output=True, check=True)
        report = json.loads(example.stdout)
        self.assertEqual([s['operation'] for s in report['steps']],
                         ['pmp.address.write', 'csr.read', 'pmp.config.write', 'translation.sfence.vma'])


if __name__ == '__main__':
    unittest.main()
