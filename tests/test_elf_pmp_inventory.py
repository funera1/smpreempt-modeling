"""Check encoded CSR semantics, real disassembly and conservative CFG boundaries."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

from examples.elf.build_fixture import build_elf
from smpreempt.extraction.elf_pmp_inventory import _compressed_flow, inspect_function
from smpreempt.frontend.elf import ELF
from smpreempt.frontend.llvm_mc import LLVMDisassembler, LLVMDisassemblerUnavailable


def csr(csr_number, f3, rd, rs1):
    return (csr_number << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | 0x73


class PMPInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.decoder = LLVMDisassembler()
        except LLVMDisassemblerUnavailable as exc:
            raise unittest.SkipTest(str(exc)) from exc

    @classmethod
    def tearDownClass(cls):
        cls.decoder.close()

    def test_csr_read_write_suppression_and_sync(self):
        words = (csr(0x3a0, 2, 10, 0),    # CSRRS a0,pmpcfg0,x0: read only
                 csr(0x3b8, 1, 0, 11),   # CSRRW x0,pmpaddr8,a1: write only
                 csr(0x3a2, 7, 0, 0),    # CSRRCI x0,pmpcfg2,0: read only
                 0x12050073,              # sfence.vma a0,x0
                 0x00008067)              # ret
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sample.elf'
            path.write_bytes(build_elf(words))
            image = ELF(path)
            report = inspect_function(image, image.symbol('secret_then_scrub'), self.decoder)
        instructions = report['instructions']
        self.assertEqual([i['pc'] for i in instructions], ['0x1000','0x1004','0x1008','0x100c','0x1010'])
        first, second, third, fence, ret = [i['classification'] for i in instructions]
        self.assertEqual((first['category'], first['csr_read'], first['csr_write']), ('pmp.config', True, False))
        self.assertEqual((second['operands']['csr'], second['csr_read'], second['csr_write']), ('pmpaddr8', False, True))
        self.assertEqual(instructions[1]['execution_model_status'], 'unsupported_by_existing_execution_model')
        self.assertEqual((third['operands']['csr'], third['operands']['zimm'], third['csr_write']), ('pmpcfg2', 0, False))
        self.assertEqual((fence['opcode'], fence['operands']), ('SFENCE.VMA', {'rs1': 10, 'rs2': 0}))
        self.assertEqual(instructions[-1]['control_flow']['kind'], 'indirect_jump_or_return')
        self.assertTrue(all(i['disassembly'] for i in instructions))

    def test_compressed_instruction_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sample.elf'
            path.write_bytes(build_elf((0x00010001, 0x00008067)))
            image = ELF(path)
            report = inspect_function(image, image.symbol('secret_then_scrub'), self.decoder)
        self.assertEqual([(i['pc'], i['size']) for i in report['instructions']],
                         [('0x1000', 2), ('0x1002', 2), ('0x1004', 4)])
        self.assertEqual(report['instructions'][0]['control_flow']['successors'], ['0x1002'])
        self.assertEqual(report['instructions'][0]['execution_model_status'], 'unsupported_by_existing_execution_model')

    def test_indirect_compressed_jump_is_not_assumed_fallthrough(self):
        self.assertEqual(_compressed_flow(0x8082, 0x1000)['kind'], 'indirect_jump_or_return')
        self.assertEqual(_compressed_flow(0x9002, 0x1000)['kind'], 'trap_or_system')

    def test_cli_preserves_provenance_and_function_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sample.elf'
            metadata = Path(directory)/'build.json'
            path.write_bytes(build_elf())
            metadata.write_text('{"commit":"example","platform":"generic"}')
            output = subprocess.check_output([sys.executable, '-m', 'smpreempt.exploration.inspect_elf_pmp',
                str(path), '--function', 'scrubbed', '--build-metadata', str(metadata)])
            report = json.loads(output)
        self.assertEqual(report['function']['name'], 'scrubbed')
        self.assertEqual([i['pc'] for i in report['instructions']], ['0x1008'])
        self.assertEqual(report['build_metadata']['content']['commit'], 'example')
        self.assertEqual(len(report['input']['sha256']), 64)
