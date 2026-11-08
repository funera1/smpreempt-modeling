"""Shared CFG and evidence-based conditional callback extraction."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from smpreempt.frontend.llvm import extract_llvm
from smpreempt.extraction.interprocedural import shared_interprocedural
from tests.test_llvm import API, ROOT, HEADER


@unittest.skipIf(API is None, 'requires libLLVM')
class SharedCFGTests(unittest.TestCase):
    def read(self, text):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name)/'fixture.ll'
        path.write_text(HEADER+text)
        return extract_llvm(path, library=API.library)

    def test_repeated_calls_share_body_but_match_returns(self):
        raw = extract_llvm(ROOT/'examples/llvm/calls.ll', library=API.library)
        original = deepcopy(raw)
        result = shared_interprocedural(raw, roots=['caller'])
        self.assertEqual(raw, original)
        self.assertEqual(len(result['graph']['functions']), 2)
        enters = [e for e in result['interprocedural_links'] if e['kind']=='call_enter']
        self.assertEqual(len(enters), 2)
        self.assertEqual(enters[0]['target'], enters[1]['target'])
        self.assertNotEqual(enters[0]['token'], enters[1]['token'])
        for enter in enters:
            returns = [e for e in result['interprocedural_links'] if e['kind']=='call_return' and e['token']==enter['token']]
            self.assertTrue(returns)
            self.assertTrue(all(e['guard']['stack_top_token']==enter['token'] for e in returns))
            self.assertTrue(all(e['target']==enter['effect']['push_frame']['continuation'] for e in returns))
        source = {f['id']:f for f in raw['functions']}
        for f in result['graph']['functions']:
            self.assertEqual([{k:v for k,v in e.items() if k!='abstract'} for e in f['transitions']], source[f['id']]['transitions'])

    def test_deep_chain_and_recursion_have_no_depth_limit_or_cloning(self):
        text = '\n'.join(f'define void @f{i}() {{ call void @f{i+1}()\n ret void }}' for i in range(12))
        text += '\ndefine void @f12() { call void @f12()\n ret void }'
        result = shared_interprocedural(self.read(text), roots=['f0'])
        self.assertEqual(len(result['graph']['functions']), 13)
        enters = [e for e in result['interprocedural_links'] if e['kind']=='call_enter']
        self.assertEqual(len(enters), 13)
        self.assertFalse(any(c.get('unresolved') for c in result['calls']))

    def test_initializer_fields_and_store_candidates_are_conditional(self):
        raw = self.read('''
%Ops = type { i64, ptr }
@ops = global %Ops { i64 0, ptr @callback }
define void @callback(ptr %p) { ret void }
define void @other(ptr %p) { ret void }
define i64 @wrong(ptr %p) { ret i64 0 }
define void @register(ptr %p) {
 %field = getelementptr %Ops, ptr %p, i64 0, i32 1
 store ptr @other, ptr %field
 store ptr @wrong, ptr %field
 ret void
}
define void @dispatch(ptr %p) {
 %field = getelementptr i8, ptr %p, i64 8
 %cb = load ptr, ptr %field
 call void %cb(ptr %p)
 ret void
}
''')
        initializer = next(g for g in raw['globals'] if g['name']=='ops')['initializer']
        self.assertEqual(initializer['elements'][1]['name'], 'callback')
        result = shared_interprocedural(raw, roots=['dispatch'])
        call = result['calls'][0]
        names = {f['id']:f['name'] for f in raw['functions']}
        self.assertEqual({names[c['target']] for c in call['candidates']}, {'callback','other'})
        self.assertTrue(call['residual_unknown'])
        self.assertTrue(all(c['kind']=='conditional_field_candidate' for c in call['candidates']))
        self.assertTrue(all(c['condition']['operator']=='pointer_equals_function' for c in call['candidates']))
        self.assertEqual(call['loaded_field']['offset'],8)
        self.assertTrue(all(c['evidence'] and c['assumptions'] for c in call['candidates']))

    def test_different_offsets_and_missing_definitions_remain_unresolved(self):
        raw = self.read('''
declare void @external()
define void @callback(ptr %p) { ret void }
define void @registration(ptr %p) {
 %field = getelementptr i8, ptr %p, i64 16
 store ptr @callback, ptr %field
 ret void
}
define void @dispatch(ptr %p) {
 %field = getelementptr i8, ptr %p, i64 8
 %cb = load ptr, ptr %field
 call void %cb(ptr %p)
 call void @external()
 ret void
}
''')
        result = shared_interprocedural(raw, roots=['dispatch'])
        self.assertEqual(len(result['graph']['functions']),1)
        self.assertTrue(result['calls'][0]['residual_unknown'])
        self.assertFalse(result['calls'][0]['candidates'])
        self.assertTrue(result['calls'][1]['unresolved'])

    def test_invalid_root_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'no definition'):
            shared_interprocedural(self.read('define void @f() { ret void }'), roots=['missing'])

    def test_variadic_definition_kept_without_claiming_abi_execution(self):
        raw = self.read('''
define i32 @var(i32 %x, ...) { ret i32 %x }
define i32 @caller() {
 %r = call i32 (i32, ...) @var(i32 3, i64 7)
 ret i32 %r
}
''')
        result = shared_interprocedural(raw, roots=['caller'])
        self.assertEqual(len(result['graph']['functions']),2)
        enter = next(e for e in result['interprocedural_links'] if e['kind']=='call_enter')
        self.assertEqual(enter['effect']['push_frame']['variadic_arguments'][0]['bits_unsigned'],'7')
        self.assertIn('ABI',enter['contracts'])

    def test_ipi_report_records_transport_as_conditional_not_control_edge(self):
        from smpreempt.keystone.ipi_connections import describe_ipi_connections
        raw = self.read('''
%Ops = type { [32 x i8], ptr, ptr, ptr }
@tlb_ops = global %Ops { [32 x i8] zeroinitializer, ptr @tlb_update, ptr @tlb_sync, ptr @tlb_process }
@tlb_event = global i32 64
declare i32 @sbi_ipi_event_create(ptr)
declare i32 @sbi_fifo_enqueue(ptr, ptr)
declare i32 @sbi_fifo_dequeue(ptr, ptr)
define void @init() {
 %r = call i32 @sbi_ipi_event_create(ptr @tlb_ops)
 store i32 %r, ptr @tlb_event
 ret void
}
define void @pmp_unset(ptr %p) { ret void }
define void @sbi_pmp_ipi_local_update(ptr %p) { call void @pmp_unset(ptr %p)
 ret void }
define void @send_and_sync_pmp_ipi(ptr %p) {
 %f = getelementptr i8, ptr %p, i64 32
 store ptr @sbi_pmp_ipi_local_update, ptr %f
 ret void
}
define void @tlb_update(ptr %q, ptr %p) {
 %r = call i32 @sbi_fifo_enqueue(ptr %q, ptr %p)
 ret void
}
define void @tlb_sync() { ret void }
define void @tlb_process(ptr %p) {
 %r = call i32 @sbi_fifo_dequeue(ptr %p, ptr %p)
 %field = getelementptr i8, ptr %p, i64 32
 %cb = load ptr, ptr %field
 call void %cb(ptr %p)
 ret void
}
define void @sbi_ipi_process(ptr %p) {
 %field = getelementptr i8, ptr %p, i64 48
 %cb = load ptr, ptr %field
 call void %cb(ptr %p)
 ret void
}
''')
        shared = shared_interprocedural(raw)
        snapshot = deepcopy(shared)
        result = describe_ipi_connections(shared)
        self.assertEqual(shared,snapshot)
        self.assertEqual(len(result['registrations']),1)
        self.assertEqual(len(result['registrations'][0]['result_stores']),1)
        self.assertEqual(len(result['packet_callback_stores']),1)
        self.assertEqual(len(result['queue_transfers']),1)
        relation = result['queue_transfers'][0]
        self.assertEqual(relation['kind'],'conditional_queue_transport')
        self.assertTrue(relation['conditions'])
        self.assertTrue(relation['assumptions'])
        self.assertIn('not a synchronous',relation['modeled_as'])
        self.assertEqual(result['structural_paths'][0]['start'],'sbi_ipi_process')
        self.assertTrue(result['unresolved'])

    def test_unrelated_input_does_not_invent_ipi_evidence(self):
        from smpreempt.keystone.ipi_connections import describe_ipi_connections
        result = describe_ipi_connections(shared_interprocedural(self.read('define void @f() { ret void }')))
        for field in ['registrations','packet_callback_stores','dispatch_candidates','queue_transfers','structural_paths']:
            self.assertEqual(result[field],[])

    def test_invoke_does_not_connect_normal_return_to_unwind_destination(self):
        raw = self.read('''
declare i32 @personality(...)
define void @callee() { ret void }
define void @caller() personality ptr @personality {
entry:
 invoke void @callee() to label %normal unwind label %exception
normal:
 ret void
exception:
 %lp = landingpad { ptr, i32 } cleanup
 resume { ptr, i32 } %lp
}
''')
        result = shared_interprocedural(raw, roots=['caller'])
        self.assertFalse(result['interprocedural_links'])
        self.assertTrue(all('exceptional' in c['unresolved'] for c in result['calls']))
