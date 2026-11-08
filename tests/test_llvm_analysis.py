"""Composition, template induction and the executable scalar/memory subset."""
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_llvm import API, HEADER, ROOT
from smpreempt.frontend.llvm import extract_llvm
from smpreempt.extraction.llvm_transforms import expand_calls, summarize_segments
from smpreempt.extraction.llvm_loop_summaries import summarize_loops

try:
    import z3
    from smpreempt.model.llvm_scalars import ScalarSemantics, ByteMemory, Scalar, UnsupportedLLVM, scalar
    from smpreempt.model.llvm_memory import RelationEvaluator, MemoryObject, Pointer
except ImportError:
    z3 = None


def literal(n, width=8):
    return dict(kind='literal', type=dict(integer_bits=width), bits_unsigned=str(n % (1 << width)))


def ref(name, width=8):
    return dict(kind='reference', id=name, type=dict(integer_bits=width))


def expression(op, *operands, width=8, flags=None):
    return dict(operator=op, operands=list(operands), type=dict(integer_bits=width), flags=flags or {})


@unittest.skipIf(API is None, 'requires LLVM')
class TransformTests(unittest.TestCase):
    def extract(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'input.ll'
            p.write_text(text)
            return extract_llvm(p, library=API.library)

    def test_two_calls_have_distinct_contexts_and_returns(self):
        report = extract_llvm(ROOT/'examples/llvm/calls.ll', library=API.library)
        graph = expand_calls(report, roots=['caller'])['functions'][0]
        ids = [n['id'] for n in graph['nodes']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(graph['expansions']), 2)
        self.assertEqual(graph['unexpanded_effects'], [])
        returns = [e['effect'] for e in graph['transitions'] if e['effect']['kind'] == 'call_return']
        self.assertEqual(len(returns), 2)
        self.assertNotEqual(returns[0]['assignments'][0]['value']['id'], returns[1]['assignments'][0]['value']['id'])
        self.assertNotEqual(returns[0]['assignments'][0]['target'], returns[1]['assignments'][0]['target'])
        entries = [e['effect'] for e in graph['transitions'] if e['effect']['kind'] == 'call_enter']
        self.assertEqual(entries[0]['assignments'][0]['value']['id'], graph['parameters'][0]['id'])

    def test_recursion_and_limits_remain_explicit(self):
        report = self.extract('define i64 @recursive(i64 %x) { %r = call i64 @recursive(i64 %x)\n ret i64 %r }')
        graph = expand_calls(report, roots=['recursive'])
        self.assertIn('recursive', graph['remaining_calls'][0]['reason'])
        calls = extract_llvm(ROOT/'examples/llvm/calls.ll', library=API.library)
        limited = expand_calls(calls, roots=['caller'], max_depth=0)
        self.assertEqual(len(limited['functions'][0]['unexpanded_effects']), 2)
        with self.assertRaisesRegex(ValueError, 'node limit'):
            expand_calls(calls, roots=['caller'], max_nodes=1)

    def test_byval_call_is_not_expanded_as_a_shared_pointer_alias(self):
        report = self.extract('''%S = type { i64 }
define i64 @copied(ptr byval(%S) %p) { %x = load i64, ptr %p\n ret i64 %x }
define i64 @caller(ptr %p) { %x = call i64 @copied(ptr byval(%S) %p)\n ret i64 %x }''')
        expanded = expand_calls(report, roots=['caller'])
        self.assertEqual(expanded['functions'][0]['expansions'], [])
        self.assertIn('ABI-affecting', expanded['remaining_calls'][0]['reason'])

    def test_opaque_effect_stops_segment_composition(self):
        report = extract_llvm(ROOT/'examples/llvm/effects.ll', library=API.library)
        segments = summarize_segments(report)['functions'][0]['segments']
        self.assertTrue(any(not s['complete'] for s in segments))
        self.assertTrue(any(e['kind'] == 'barrier' for s in segments for e in s['effects']))

    def test_memory_versions_preserve_store_load_order(self):
        report = self.extract(HEADER+'''define i8 @alias(ptr %p, ptr %q) {
  store i8 7, ptr %p, align 1
  %a = load i8, ptr %p, align 1
  store i8 8, ptr %q, align 1
  %b = load i8, ptr %p, align 1
  ret i8 %b
}''')
        segment = summarize_segments(report)['functions'][0]['segments'][0]
        loads = [v for v in segment['values'].values() if v.get('operator') == 'load']
        self.assertEqual(len(loads), 2)
        self.assertEqual(loads[0]['memory']['operator'], 'store')
        self.assertEqual(loads[1]['memory']['memory']['operator'], 'store')
        self.assertGreater(len(segment['prefixes']), 3)
        if z3 is not None:
            f = report['functions'][0]
            values = {p['id']: Pointer('shared') for p in f['parameters']}
            evaluator = RelationEvaluator(values, {'shared': MemoryObject(ByteMemory.fresh('alias'), 1)})
            loaded = evaluator.evaluate(loads[1])
            self.assertEqual(z3.simplify(loaded.bits).as_long(), 8)
            self.assertTrue(z3.is_false(z3.simplify(loaded.ub)))

    @unittest.skipIf(z3 is None, 'requires Z3')
    def test_clear_template_induction_and_nonmatching_loops(self):
        report = extract_llvm(ROOT/'examples/llvm/erase.ll', library=API.library)
        result = summarize_loops(report, prove=True)
        self.assertEqual(len(result['summaries']), 1)
        self.assertEqual(result['summaries'][0]['proof']['status'], 'proved_for_template')
        self.assertEqual(result['unresolved'], [])
        text = (ROOT/'examples/llvm/erase.ll').read_text().replace('store i8 0', 'store i8 1')
        rejected = summarize_loops(self.extract(text))
        self.assertEqual(rejected['summaries'], [])
        self.assertEqual(len(rejected['unresolved']), 1)
        text = (ROOT/'examples/llvm/erase.ll').read_text().replace('br i1 %empty, label %exit, label %loop', 'br label %loop')
        rejected = summarize_loops(self.extract(text))
        self.assertEqual(rejected['summaries'], [])

    @unittest.skipIf(z3 is None, 'requires Z3')
    def test_pointer_count_fill_template_and_stride_rejection(self):
        report = extract_llvm(ROOT/'examples/llvm/fill-pointer.ll', library=API.library)
        result = summarize_loops(report, prove=True)
        self.assertEqual(result['summaries'][0]['kind'], 'byte_fill_prefix')
        self.assertEqual(result['summaries'][0]['proof']['status'], 'proved_for_template')
        self.assertEqual(result['summaries'][0]['proof']['fill'], 'arbitrary fixed byte')
        text = (ROOT/'examples/llvm/erase.ll').read_text().replace('getelementptr i8', 'getelementptr i16')
        result = summarize_loops(self.extract(text))
        self.assertEqual(result['summaries'], [])
        self.assertEqual(len(result['unresolved']), 1)

    @unittest.skipIf(z3 is None, 'requires Z3')
    def test_real_increment_relation_executes_with_memory(self):
        report = extract_llvm(ROOT/'examples/llvm/calls.ll', functions=['increment'], library=API.library)
        segment = summarize_segments(report)['functions'][0]['segments'][0]
        initial = ByteMemory.fresh('increment').store(z3.BitVecVal(0, 64), scalar(41, 64))
        evaluator = RelationEvaluator({'f0:arg0': Pointer('data')}, {'data': MemoryObject(initial, 8, 8)})
        after = evaluator.memory(segment['memory'])
        self.assertFalse(z3.is_true(z3.simplify(after.ub)))
        self.assertEqual(z3.simplify(after.objects['data'].memory.load(z3.BitVecVal(0, 64), 64).bits).as_long(), 42)


@unittest.skipIf(z3 is None, 'requires Z3')
class ScalarTests(unittest.TestCase):
    def assert_bool(self, value, expected):
        self.assertEqual(z3.is_true(z3.simplify(value)), expected)
        self.assertTrue(z3.is_true(z3.simplify(value)) or z3.is_false(z3.simplify(value)))

    def test_wrapping_overflow_poison_and_immediate_ub_are_distinct(self):
        semantics = ScalarSemantics()
        wrapped = semantics.evaluate(expression('add', literal(255), literal(1)))
        self.assertEqual(z3.simplify(wrapped.bits).as_long(), 0)
        self.assert_bool(wrapped.poison, False)
        unsigned = semantics.evaluate(expression('add', literal(255), literal(1), flags={'nuw': True}))
        signed = semantics.evaluate(expression('add', literal(127), literal(1), flags={'nsw': True}))
        self.assert_bool(unsigned.poison, True)
        self.assert_bool(signed.poison, True)
        self.assert_bool(unsigned.ub, False)
        zero = semantics.evaluate(expression('udiv', literal(1), literal(0)))
        self.assert_bool(zero.ub, True)
        exact = semantics.evaluate(expression('udiv', literal(5), literal(2), flags={'exact': True}))
        self.assert_bool(exact.poison, True)
        self.assert_bool(exact.ub, False)
        overflow = semantics.evaluate(expression('srem', literal(128), literal(255)))
        self.assert_bool(overflow.ub, True)

    def test_select_does_not_propagate_unselected_poison_and_freeze(self):
        semantics = ScalarSemantics()
        poison = dict(kind='poison', type=dict(integer_bits=8))
        selected = semantics.evaluate(expression('select', literal(1, 1), literal(7), poison))
        self.assert_bool(selected.poison, False)
        self.assertEqual(z3.simplify(selected.bits).as_long(), 7)
        frozen = semantics.evaluate(expression('freeze', poison))
        self.assert_bool(frozen.poison, False)
        with self.assertRaises(UnsupportedLLVM):
            semantics.evaluate(dict(kind='constant_expression', llvm='...'))

    def test_cast_and_disjoint_flags(self):
        s = ScalarSemantics()
        self.assert_bool(s.evaluate(expression('zext', literal(255), width=16, flags={'nneg': True})).poison, True)
        self.assert_bool(s.evaluate(expression('trunc', literal(256, 16), flags={'nuw': True})).poison, True)
        self.assert_bool(s.evaluate(expression('or', literal(3), literal(1), flags={'disjoint': True})).poison, True)
        self.assert_bool(s.evaluate(expression('shl', literal(1), literal(8))).poison, True)

    def test_poison_memory_and_defined_branch(self):
        memory = ByteMemory.fresh('poison_memory').store(z3.BitVecVal(0, 64), Scalar(z3.BitVecVal(0, 8), z3.BoolVal(True)))
        self.assert_bool(memory.load(z3.BitVecVal(0, 64), 8).poison, True)
        guard = ScalarSemantics({'condition': Scalar(z3.BitVecVal(1, 1), z3.BoolVal(True))}).branch_guard(ref('condition', 1))
        self.assert_bool(guard, False)

    def test_gep_one_past_and_memory_bounds(self):
        evaluator = RelationEvaluator({'p': Pointer('data')}, {'data': MemoryObject(ByteMemory.fresh('bounds'), 8)})
        def gep(index):
            return dict(operator='getelementptr', base=ref('p'), inbounds=True,
                        offset_terms=[dict(index=literal(index, 64), scale_bytes=1)])
        one_past = evaluator.evaluate(gep(8))
        self.assert_bool(one_past.offset.poison, False)
        self.assert_bool(evaluator.evaluate(gep(9)).offset.poison, True)
        load = dict(operator='load', memory=dict(kind='entry_memory'), address=gep(8),
                    value_type=dict(integer_bits=8), size_bytes=1, alignment=1)
        self.assert_bool(evaluator.evaluate(load).ub, True)
        with self.assertRaises(UnsupportedLLVM):
            evaluator.evaluate(expression('ptrtoint', ref('p'), width=64))

    def test_zero_gep_on_null_does_not_invent_poison(self):
        e = RelationEvaluator({}, {})
        gep = dict(operator='getelementptr', base=dict(kind='literal', type=dict(llvm='ptr'), llvm='ptr null'),
                   inbounds=True, offset_terms=[dict(index=literal(0, 64), scale_bytes=1)])
        self.assert_bool(e.evaluate(gep).offset.poison, False)
        gep['offset_terms'][0]['index'] = literal(1, 64)
        self.assert_bool(e.evaluate(gep).offset.poison, True)

    def test_freeze_is_shared_when_composition_duplicates_its_expression(self):
        s = ScalarSemantics()
        frozen = expression('freeze', dict(kind='poison', type=dict(integer_bits=8)))
        frozen['ssa_binding'] = 'one_dynamic_freeze'
        compared = dict(operator='icmp', predicate='eq', operands=[frozen, frozen])
        self.assertEqual(z3.simplify(s.evaluate(compared).bits).as_long(), 1)

    def test_pointer_layout_profile_is_checked(self):
        with self.assertRaises(UnsupportedLLVM):
            RelationEvaluator.from_graph({'datalayout': 'e-p:32:32'}, {}, {})
        with self.assertRaises(UnsupportedLLVM):
            RelationEvaluator.from_graph({'datalayout': 'e-p:64:64:64:32'}, {}, {})
        with self.assertRaises(UnsupportedLLVM):
            RelationEvaluator.from_graph({'datalayout': 'E-p:64:64'}, {}, {})


if __name__ == '__main__':
    unittest.main()
