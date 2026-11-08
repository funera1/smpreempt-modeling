"""Extraction correctness checks; no security predicates or attack execution."""
from copy import deepcopy
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

from smpreempt.extraction.abstract_transitions import extract_abstract_transitions
from smpreempt.extraction.llvm_transforms import expand_calls
from smpreempt.frontend.llvm import extract_llvm
from tests.test_llvm import API, ROOT, HEADER


@unittest.skipIf(API is None, 'requires libLLVM')
class AbstractTransitionsTests(unittest.TestCase):
    def read(self, filename):
        return extract_llvm(ROOT/'examples/llvm'/filename, library=API.library)

    def edges(self, result):
        return [e for f in result['graph']['functions'] for e in f['transitions']]

    def test_cfg_guards_effects_and_loop_backedges_unchanged(self):
        for fixture, root in [('erase.ll', 'erase'), ('calls.ll', 'caller'), ('effects.ll', 'effects')]:
            with self.subTest(fixture=fixture):
                report = self.read(fixture)
                expected = expand_calls(report, roots=[root])
                untouched = deepcopy(report)
                result = extract_abstract_transitions(report, roots=[root])
                self.assertEqual(report, untouched)
                for before, after in zip(expected['functions'], result['graph']['functions']):
                    stripped = [{k: v for k, v in e.items() if k != 'abstract'} for e in after['transitions']]
                    self.assertEqual(before['transitions'], stripped)
                    self.assertEqual(before['blocks'], after['blocks'])
                    self.assertEqual(before['entry'], after['entry'])
                    self.assertEqual([n['id'] for n in before['nodes']], [n['id'] for n in after['nodes']])

    def test_assembly_order_binding_and_state_mapping(self):
        result = extract_abstract_transitions(self.read('effects.ll'), roots=['effects'])
        edge = next(e for e in self.edges(result) if e['abstract']['assembly'])
        annotation = edge['abstract']
        self.assertEqual([o['catalogue_id'] for o in annotation['operations']],
                         ['pmp.config.write', 'translation.sfence.vma'])
        self.assertEqual(annotation['assembly']['bindings'][0]['value']['name'], 'cfg')
        self.assertIn('csr', annotation['may_change'])
        self.assertIn('pmp_views', annotation['may_change'])
        self.assertIn('translation_views', annotation['may_change'])
        self.assertIn('asm sideeffect', annotation['facts']['implementation']['instruction'])
        self.assertFalse(annotation['facts']['implementation']['source_location_available'])
        self.assertTrue(annotation['assumptions'])

    def test_memory_and_external_effects_are_not_silent_noops(self):
        result = extract_abstract_transitions(self.read('effects.ll'), roots=['effects'])
        annotations = [e['abstract'] for e in self.edges(result)]
        volatile = next(a for a in annotations if a['facts']['llvm_effect'].get('volatile'))
        self.assertEqual(volatile['operations'][0]['catalogue_id'], 'memory.load')
        self.assertTrue(volatile['barrier'])
        external = next(a for a in annotations if a['facts']['llvm_effect'].get('callee', {}).get('name') == 'external')
        self.assertTrue(external['barrier'])
        self.assertIn('unknown', external['may_change'])
        intrinsic = next(a for a in annotations if a['operations'] and a['operations'][0].get('intrinsic'))
        self.assertTrue(intrinsic['barrier'])
        self.assertIsNone(intrinsic['operations'][0]['catalogue_id'])

    def test_cloned_calls_keep_implementation_and_distinct_contexts(self):
        result = extract_abstract_transitions(self.read('calls.ll'), roots=['caller'])
        loads = [e for e in self.edges(result) if e['effect']['kind'] == 'load']
        self.assertEqual(len(loads), 2)
        self.assertNotEqual(loads[0]['source'], loads[1]['source'])
        self.assertEqual(loads[0]['abstract']['facts']['implementation'], loads[1]['abstract']['facts']['implementation'])
        self.assertEqual(loads[0]['abstract']['facts']['implementation']['function'], 'increment')
        returns = [e for e in self.edges(result) if e['effect']['kind'] == 'call_return']
        self.assertEqual(len(returns), 2)
        self.assertEqual(len({e['effect']['callsite'] for e in returns}), 2)

    def test_unknown_asm_and_recursion_remain_barriers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'unknown.ll'
            path.write_text(HEADER+'''define void @recursive() {
entry:
 call void asm sideeffect "wfi", ""()
 call void @recursive()
 ret void
}
''')
            report = extract_llvm(path, library=API.library)
            result = extract_abstract_transitions(report, roots=['recursive'])
            barriers = [e for e in self.edges(result) if e['abstract']['barrier']]
            self.assertEqual(len(barriers), 2)
            self.assertTrue(result['graph']['remaining_calls'])
            self.assertFalse(next(e['abstract']['assembly'] for e in barriers if e['abstract']['assembly'])['complete'])

    def test_cli_emits_extraction_schema(self):
        proc = subprocess.run([sys.executable, '-m', 'smpreempt.exploration.extract_llvm',
            str(ROOT/'examples/llvm/calls.ll'), '--abstract-model', '--function', 'caller'],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['schema'], 'smpreempt.abstract-transitions.v1')

    def test_csr_forms_and_hardware_fences(self):
        from smpreempt.extraction.riscv_asm_effects import extract_asm
        asm = extract_asm(dict(callee_kind='inline_asm', constraints='r', result=None,
            arguments=[dict(kind='reference', id='cfg')], assembly='''csrs mstatus, $0
csrc sstatus, zero
csrrwi zero, satp, 0
csrci mseccfg, 1
fence rw, rw
fence.i
sfence.vma zero, zero'''))
        self.assertTrue(asm['complete'])
        self.assertEqual([s['catalogue_id'] for s in asm['steps']], [
            'privilege.mstatus.write', 'csr.read', 'translation.satp.write',
            'pmp.security.write', 'ordering.fence', 'ordering.fence.i', 'translation.sfence.vma'])
        self.assertFalse(asm['steps'][1]['csr_write'])
        self.assertTrue(asm['steps'][2]['csr_write'])
        self.assertFalse(asm['steps'][2]['csr_read'])

    def test_debug_location_is_retained_as_fact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'debug.ll'
            path.write_text(HEADER+'''define void @clear(ptr %p) !dbg !4 {
entry:
 store i8 0, ptr %p, !dbg !7
 ret void, !dbg !8
}
!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3}
!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "fixture", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "clear.c", directory: "/research")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "clear", scope: !1, file: !1, line: 3, type: !5, scopeLine: 3, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!5 = !DISubroutineType(types: !2)
!7 = !DILocation(line: 4, column: 2, scope: !4)
!8 = !DILocation(line: 5, column: 1, scope: !4)
''')
            report = extract_llvm(path, library=API.library)
            result = extract_abstract_transitions(report, roots=['clear'])
            store = next(e for e in self.edges(result) if e['effect']['kind'] == 'store')
            origin = store['abstract']['facts']['implementation']
            self.assertTrue(origin['source_location_available'])
            self.assertEqual(origin['source_location']['line'], 4)
            self.assertEqual(origin['source_location']['column'], 2)
            self.assertEqual(origin['function'], 'clear')

    def test_depth_limit_does_not_drop_calls_or_claim_semantics(self):
        result = extract_abstract_transitions(self.read('calls.ll'), roots=['caller'], max_depth=0)
        calls = [e for e in self.edges(result) if e['effect'].get('callee_kind') == 'direct']
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(e['abstract']['barrier'] for e in calls))
        self.assertEqual(len(result['graph']['remaining_calls']), 2)
        self.assertTrue(all(c['reason'] == 'call expansion depth limit' for c in result['graph']['remaining_calls']))
