"""Preserve compilation inputs, link real IR, and keep capture limitations visible."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from smpreempt.keystone.keystone_ir import ir_arguments, prepare_capture, capture
from smpreempt.extraction.llvm_link import link_ir
from smpreempt.frontend.llvm import extract_llvm
from smpreempt.extraction.llvm_transforms import expand_calls
from tests.test_llvm import API, ROOT


class CapturePlanTests(unittest.TestCase):
    def test_preserve_defines_abi_and_paths_remove_object_outputs(self):
        args = ['riscv64-unknown-elf-gcc', '-O2', '-mabi=lp64', '-march=rv64gc',
                '-Ipath with spaces', '-DNAME="x y"', '-MMD', '-MF', 'old.d',
                '-c', 'enclave.c', '-o', 'old.o']
        command, removed = ir_arguments(args, 'enclave.c', '/tmp/new.ll', '/tmp/clang', 'riscv64-unknown-elf')
        self.assertIn('-Ipath with spaces', command)
        self.assertIn('-DNAME="x y"', command)
        self.assertIn('-mabi=lp64', command)
        self.assertNotIn('old.o', command)
        self.assertNotIn('-MMD', command)
        self.assertEqual(command[-4:], ['-S', '-emit-llvm', '-o', '/tmp/new.ll'])
        self.assertIn('old.d', removed)
        self.assertIn('--target=riscv64-unknown-elf', command)

    def test_do_not_silently_retarget_gcc_or_execute_a_shell(self):
        with self.assertRaisesRegex(ValueError, '--target'):
            ir_arguments(['riscv64-unknown-elf-gcc', '-c', 'enclave.c'], 'enclave.c', '/tmp/new.ll', 'clang')
        with self.assertRaisesRegex(ValueError, 'response-file'):
            ir_arguments(['clang', '@args'], 'enclave.c', '/tmp/new.ll', 'clang')
        with self.assertRaisesRegex(ValueError, 'shell'):
            ir_arguments(['clang', '-c', 'enclave.c', ';', 'other'], 'enclave.c', '/tmp/new.ll', 'clang')

    def test_missing_build_inputs_are_reported_not_mocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)/'repo'
            (repo/'sm/src').mkdir(parents=True)
            source = repo/'sm/src/enclave.c'
            source.write_text('int f(void) { return 0; }')
            report = prepare_capture(repo, Path(tmp)/'out', clang='/missing/clang')
            self.assertEqual(report['readiness'], 'missing_dependencies')
            self.assertIsNone(report['command'])
            self.assertEqual(capture(report)['status'], 'not_run')
            self.assertEqual(source.read_text(), 'int f(void) { return 0; }')
            self.assertEqual(len(report['blockers']), 2)

    def test_database_selects_exact_translation_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)/'repo'
            (repo/'sm/src').mkdir(parents=True)
            source = repo/'sm/src/enclave.c'
            source.write_text('int f(void) { return 0; }')
            db = Path(tmp)/'compile_commands.json'
            db.write_text(json.dumps([dict(directory=str(repo), file='sm/src/enclave.c',
                arguments=['clang', '--target=riscv64-unknown-elf', '-DPLATFORM=1', '-c', 'sm/src/enclave.c', '-o', 'a.o'])]))
            report = prepare_capture(repo, Path(tmp)/'out', compilation_database=db, clang='/missing/clang')
            self.assertEqual(report['command'][-1], str(Path(tmp)/'out/enclave.ll'))
            self.assertIn('-DPLATFORM=1', report['command'])
            self.assertEqual(len(report['blockers']), 1)
            self.assertIn('compiler', report)


@unittest.skipIf(API is None, 'requires LLVM')
class LinkTests(unittest.TestCase):
    def test_linked_definition_can_be_expanded(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b, out = [Path(tmp)/n for n in ('a.ll', 'b.ll', 'linked.bc')]
            a.write_text('declare i64 @helper(i64)\ndefine i64 @caller(i64 %x) { %r = call i64 @helper(i64 %x)\n ret i64 %r }')
            b.write_text('define i64 @helper(i64 %x) { %r = add i64 %x, 1\n ret i64 %r }')
            provenance = link_ir([a, b], out, API.library)
            self.assertEqual(len(provenance['inputs']), 2)
            report = extract_llvm(out, library=API.library)
            expanded = expand_calls(report, roots=['caller'])['functions'][0]
            self.assertEqual(len(expanded['expansions']), 1)
            self.assertEqual(expanded['unexpanded_effects'], [])
            with self.assertRaisesRegex(ValueError, 'differ'):
                link_ir([a, b], a, API.library)

    def test_mismatched_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b, out = [Path(tmp)/n for n in ('a.ll', 'b.ll', 'out.ll')]
            a.write_text('target triple = "riscv64-unknown-elf"\ndefine void @f() { ret void }')
            b.write_text('target triple = "x86_64-unknown-linux-gnu"\ndefine void @g() { ret void }')
            with self.assertRaisesRegex(ValueError, 'different targets'):
                link_ir([a, b], out, API.library)

    def test_compiled_c_if_clang_is_available(self):
        clang = os.environ.get('SMPREEMPT_TEST_CLANG') or shutil.which('clang-20') or shutil.which('clang-18') or shutil.which('clang')
        if not clang:
            self.skipTest('Clang executable not present')
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'memory.ll'
            subprocess.run([clang, '--target=riscv64-unknown-elf', '-O1', '-g', '-S', '-emit-llvm',
                            str(ROOT/'examples/llvm/memory.c'), '-o', str(out)], check=True, capture_output=True)
            report = extract_llvm(out, library=API.library)
            names = {f['name'] for f in report['functions']}
            self.assertTrue({'erase', 'validate_and_use', 'set_permissions'} <= names)
            self.assertTrue(any(d['opcode'] == 'call' for d in report['diagnostics']))

class BatchCaptureTests(unittest.TestCase):
    def test_make_log_parser_does_not_run_shell_prefix(self):
        from smpreempt.keystone.keystone_ir import compilation_records
        records = compilation_records('mkdir /never; echo CC; /tool/clang -DUNIT=2 -c "src/a b.c" -o a.o\n'
                                      'echo unrelated\n', '/tool/clang', '/build')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['file'], '/build/src/a b.c')
        self.assertIn('-DUNIT=2', records[0]['arguments'])
        with self.assertRaisesRegex(ValueError, 'multiple compile commands'):
            compilation_records('x; /tool/clang -c a.c\nx; /tool/clang -c a.c', '/tool/clang', '/build')

    def test_missing_sources_are_reported_and_assembly_inventoried(self):
        from smpreempt.keystone.keystone_ir import capture_database
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root/'compile_commands.json'
            db.write_text(json.dumps([
                dict(directory=str(root), file='missing.c', arguments=['clang', '-c', 'missing.c']),
                dict(directory=str(root), file='entry.S', arguments=['clang', '-c', 'entry.S'])]))
            with patch('smpreempt.keystone.keystone_ir.shutil.which', return_value='/tool/clang'):
                result = capture_database(db, root/'out', 'clang')
            self.assertEqual(result['status'], 'incomplete')
            self.assertEqual(result['units'][0]['status'], 'not_run')
            self.assertEqual(len(result['skipped']), 1)
            self.assertFalse((root/'out/linked.ll').exists())

    def test_batch_preserves_per_file_flags_and_resolves_definitions(self):
        from smpreempt.keystone.keystone_ir import capture_database
        clang = os.environ.get('SMPREEMPT_TEST_CLANG') or shutil.which('clang')
        if not clang or API is None:
            self.skipTest('requires Clang and LLVM')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory, body in [('a', 'extern int helper(void); int caller(void) { return helper()+VALUE; }'),
                                    ('b', 'int helper(void) { return VALUE; }')]:
                (root/directory).mkdir()
                (root/directory/'unit.c').write_text(body)
            records = [dict(directory=str(root), file=f'{directory}/unit.c', arguments=[clang,
                '--target=riscv64-unknown-elf', f'-DVALUE={value}', '-c', f'{directory}/unit.c', '-o', 'old.o'])
                for directory,value in [('a', 3), ('b', 7)]]
            db = root/'compile_commands.json';db.write_text(json.dumps(records))
            result = capture_database(db, root/'out', clang)
            self.assertEqual(result['status'], 'captured')
            self.assertEqual(len({u['output'] for u in result['units']}), 2)
            self.assertIn('-DVALUE=3', result['units'][0]['command'])
            self.assertIn('-DVALUE=7', result['units'][1]['command'])
            linked = root/'out/linked.ll'
            link_ir([u['output'] for u in result['units']], linked, API.library)
            graph = extract_llvm(linked, library=API.library)
            self.assertFalse(next(f for f in graph['functions'] if f['name']=='helper')['declaration'])


if __name__ == '__main__':
    unittest.main()
