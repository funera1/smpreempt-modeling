"""LLVM parser-backed extraction: structural and memory relations, not BMC."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from smpreempt.frontend.llvm import extract_llvm, cycles
from smpreempt.frontend.llvm_c import LLVM, LLVMUnavailable

try:
    API = LLVM()
except LLVMUnavailable:
    API = None

ROOT = Path(__file__).resolve().parents[1]
HEADER = 'target datalayout = "e-p:64:64-i64:64-n32:64-S128"\n'


@unittest.skipIf(API is None, 'requires libLLVM 18 or 20')
class LLVMTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'test.ll'

    def extract(self, text, **kwargs):
        self.path.write_text(text)
        return extract_llvm(self.path, library=API.library, **kwargs)

    def effects(self, graph):
        return [t['effect'] for f in graph['functions'] for t in f['transitions']]

    def test_erase_loop_remains_a_cycle_and_store(self):
        report = extract_llvm(ROOT/'examples/llvm/erase.ll', library=API.library)
        f = report['functions'][0]
        self.assertEqual(report['status'], 'extracted')
        self.assertEqual(f['cyclic_regions'], [[f['blocks'][1]['id']]])
        store = next(e for e in self.effects(report) if e['kind'] == 'store')
        self.assertEqual(store['size_bytes'], 1)
        self.assertEqual(store['value']['bits_unsigned'], '0')
        branch = next(n for n in f['nodes'] if n.get('opcode') == 'br')
        edges = [t for t in f['transitions'] if t['source'] == branch['id']]
        self.assertEqual(len(edges), 2)
        self.assertEqual(edges[1]['guard'], {'operator': 'not', 'operand': edges[0]['guard']})
        # Repeating extraction does not unroll the loop or depend on LLVM object addresses.
        again = extract_llvm(ROOT/'examples/llvm/erase.ll', library=API.library)
        self.assertEqual(f, again['functions'][0])

    def test_phi_updates_are_parallel_and_predecessor_specific(self):
        report = self.extract('''define i64 @swap_loop(i64 %a, i64 %b, i1 %again) {
entry:
  br label %loop
loop:
  %x = phi i64 [ %a, %entry ], [ %y, %loop ]
  %y = phi i64 [ %b, %entry ], [ %x, %loop ]
  br i1 %again, label %loop, label %exit
exit:
  ret i64 %x
}''')
        phi = next(e for e in self.effects(report) if e['kind'] == 'parallel_phi' and e['assignments'])
        self.assertEqual(len(phi['assignments']), 2)
        x, y = phi['assignments']
        self.assertEqual(x['incoming'][1]['value']['id'], y['target'])
        self.assertEqual(y['incoming'][1]['value']['id'], x['target'])
        self.assertEqual(phi['selector'], 'predecessor_block')

    def test_switch_multiline_preserves_case_and_default_guards(self):
        report = self.extract('''define i32 @choose(i32 %n) {
entry:
  switch i32 %n, label %other [
    i32 -1, label %negative
    i32 3, label %three
  ]
negative:
  ret i32 10
three:
  ret i32 20
other:
  ret i32 30
}''')
        f = report['functions'][0]
        switch = next(n for n in f['nodes'] if n.get('opcode') == 'switch')
        edges = [t for t in f['transitions'] if t['source'] == switch['id']]
        self.assertEqual(len(edges), 3)
        self.assertEqual(edges[0]['guard']['operator'], 'not_in')
        self.assertEqual([e['guard']['operands'][1]['bits_unsigned'] for e in edges[1:]], ['4294967295', '3'])
        self.assertEqual(edges[0]['target'], f['blocks'][3]['entry'])
        self.assertEqual(edges[1]['target'], f['blocks'][1]['entry'])

    def test_gep_struct_padding_array_stride_and_alloca(self):
        report = self.extract(HEADER+'''%Pair = type { i8, i64, [4 x i16] }
define i16 @field(ptr %p, i64 %i) {
entry:
  %local = alloca %Pair, i64 3, align 8
  %q = getelementptr inbounds %Pair, ptr %p, i64 0, i32 2, i64 %i
  %v = load i16, ptr %q, align 2
  ret i16 %v
}''')
        effects = self.effects(report)
        allocation = next(e for e in effects if e['kind'] == 'allocate')
        self.assertEqual(allocation['element_allocation_bytes'], 24)
        gep = next(e['expression'] for e in effects if e.get('expression', {}).get('operator') == 'getelementptr')
        self.assertTrue(gep['inbounds'])
        self.assertEqual(gep['offset_terms'][0]['scale_bytes'], 24)
        self.assertEqual(gep['offset_terms'][1]['offset_bytes'], 16)
        self.assertEqual(gep['offset_terms'][2]['scale_bytes'], 2)
        self.assertEqual(next(e for e in effects if e['kind'] == 'load')['size_bytes'], 2)

    def test_no_datalayout_does_not_guess_byte_sizes(self):
        report = self.extract('define i64 @read(ptr %p) { %v = load i64, ptr %p\n ret i64 %v }')
        load = next(e for e in self.effects(report) if e['kind'] == 'load')
        self.assertIsNone(load['size_bytes'])

    def test_integer_flags_and_types_are_not_dropped(self):
        report = self.extract('''define i32 @arithmetic(i32 %a, i32 %b) {
  %x = add nuw nsw i32 %a, %b
  %y = sdiv exact i32 %x, 2
  %z = icmp slt i32 %y, 0
  %r = select i1 %z, i32 %a, i32 %y
  ret i32 %r
}''')
        exprs = [e['expression'] for e in self.effects(report) if e['kind'] == 'assign']
        self.assertEqual(exprs[0]['flags'], {'nuw': True, 'nsw': True})
        self.assertEqual(exprs[0]['type']['integer_bits'], 32)
        self.assertTrue(exprs[1]['flags']['exact'])
        self.assertEqual(exprs[2]['predicate'], 'slt')
        self.assertEqual(exprs[3]['operator'], 'select')

    def test_calls_asm_and_memset_are_opaque_not_atomic(self):
        report = extract_llvm(ROOT/'examples/llvm/effects.ll', library=API.library)
        effects = self.effects(report)
        opaque = [e for e in effects if e['kind'] == 'opaque_effect']
        self.assertEqual(len(opaque), 4)
        self.assertEqual(report['status'], 'extracted_with_opaque_effects')
        self.assertEqual(opaque[0]['callee']['name'], 'llvm.memset.p0.i64')
        self.assertEqual(opaque[1]['callee_kind'], 'inline_asm')
        self.assertIn('sfence.vma', opaque[1]['assembly'])
        self.assertEqual(opaque[1]['constraints'], 'r,~{memory}')
        self.assertTrue(opaque[2]['volatile'])
        self.assertTrue(all(e['requires_semantics'] for e in opaque))

    def test_atomic_unknown_and_indirect_calls_preserved(self):
        report = self.extract('''define i64 @atomic_ops(ptr %p, ptr %fn) {
  %a = load atomic i64, ptr %p acquire, align 8
  %b = atomicrmw add ptr %p, i64 1 seq_cst
  fence seq_cst
  %r = call i64 %fn(ptr %p)
  ret i64 %r
}''')
        effects = [e for e in self.effects(report) if e['kind'] == 'opaque_effect']
        self.assertEqual(len(effects), 4)
        self.assertGreater(effects[0]['atomic_ordering'], 0)
        self.assertEqual(effects[-1]['callee_kind'], 'indirect')
        text = '\n'.join(n.get('llvm', '') for f in report['functions'] for n in f['nodes'])
        self.assertIn('atomicrmw', text)
        self.assertIn('fence seq_cst', text)

    def test_global_initializer_and_quoted_names(self):
        report = self.extract('''@counter = global i64 7
@buf = constant [2 x i8] c"A\\00"
define i64 @"function with space"(i64) {
  %2 = add i64 %0, 1
  ret i64 %2
}''')
        self.assertEqual(report['globals'][0]['initializer']['bits_unsigned'], '7')
        self.assertTrue(report['globals'][1]['constant'])
        self.assertEqual(report['functions'][0]['name'], 'function with space')
        self.assertEqual(report['functions'][0]['parameters'][0]['id'], 'f0:arg0')

    def test_invalid_syntax_and_invalid_ssa_rejected(self):
        with self.assertRaises(ValueError):
            self.extract('not LLVM IR')
        with self.assertRaisesRegex(ValueError, 'dominate'):
            self.extract('''define i64 @bad(i1 %c) {
entry:
  br i1 %c, label %one, label %two
one:
  %x = add i64 1, 2
  br label %two
two:
  ret i64 %x
}''')

    def test_filter_and_defined_call_do_not_silently_inline(self):
        text = '''define i64 @callee(i64 %x) { ret i64 %x }
define i64 @caller(i64 %x) { %r = call i64 @callee(i64 %x)\n ret i64 %r }'''
        report = self.extract(text, functions=['caller'])
        self.assertEqual([f['name'] for f in report['functions']], ['caller'])
        call = next(e for e in self.effects(report) if e['kind'] == 'opaque_effect')
        self.assertTrue(call['definition_available'])
        self.assertEqual(len(report['function_index']), 2)
        with self.assertRaisesRegex(ValueError, 'unknown functions'):
            self.extract(text, functions=['missing'])

    def test_bitcode_and_text_produce_same_graph(self):
        self.path.write_text(HEADER+'define i64 @f(i64 %x) { ret i64 %x }')
        bc = Path(self.temp.name)/'test.bc'
        with API.module(self.path) as module:
            self.assertEqual(API.LLVMWriteBitcodeToFile(module.value, bytes(bc)), 0)
        ll_graph = extract_llvm(self.path, library=API.library)
        bc_graph = extract_llvm(bc, library=API.library)
        self.assertEqual(ll_graph['functions'], bc_graph['functions'])
        self.assertNotEqual(ll_graph['input']['sha256'], bc_graph['input']['sha256'])

    def test_cli_returns_json_and_reports_input_error(self):
        command = [sys.executable, '-m', 'smpreempt.exploration.extract_llvm',
                   str(ROOT/'examples/llvm/erase.ll'), '--llvm-library', API.library]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout)['schema'], 'smpreempt.llvm-transitions.v1')
        bad = subprocess.run(command+['--function', 'missing'], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(bad.returncode, 2)
        self.assertIn('unknown functions', bad.stderr)

    def test_llvm18_reader_if_available(self):
        try:
            other = LLVM('libLLVM.so.18.1')
        except LLVMUnavailable:
            self.skipTest('LLVM 18 is not available')
        result = extract_llvm(ROOT/'examples/llvm/erase.ll', library=other.library)
        self.assertTrue(result['llvm']['version'].startswith('18.'))
        self.assertTrue(result['functions'][0]['cyclic_regions'])


class GraphTests(unittest.TestCase):
    def test_cycle_regions_do_not_confuse_diamonds_with_loops(self):
        self.assertEqual(cycles({'a': ['b', 'c'], 'b': ['d'], 'c': ['d'], 'd': []}), [])
        result = cycles({'a': ['b'], 'b': ['c'], 'c': ['b', 'd'], 'd': ['d']})
        self.assertEqual({tuple(c) for c in result}, {('b', 'c'), ('d',)})


if __name__ == '__main__':
    unittest.main()
