"""Capture actual PMP code, lower its asm, and check explicit interruption cases."""
import json
from pathlib import Path
from dataclasses import asdict

from smpreempt.frontend.llvm import extract_llvm
from smpreempt.keystone.keystone_ir import ir_arguments, capture, digest
from smpreempt.extraction.riscv_asm_effects import extract_report_asm
from smpreempt.keystone.keystone_pmp_paths import RegionMetadata, initial_pmp, execute_helper, pmp_snapshot
from smpreempt.analysis.keystone_preemption_analysis import analyze_cuts, release_callsite_order, revocation_callsite_order
from smpreempt.extraction.llvm_loop_summaries import summarize_loops
from smpreempt.model.symbolic_pmp import SymbolicPMP


def serialize_path(path):
    return dict(function=path['function'], region=asdict(path['region']),
        metadata_contract=path['metadata_contract'], llvm_trace=path['llvm_trace'],
        auxiliary_state_restored=path['auxiliary_state_restored'],
        operations=[{k:v for k,v in op.items() if not k.startswith('_')} for op in path['operations']],
        cuts=[{**{k:v for k,v in cut.items() if k != 'pmp'}, 'pmp':pmp_snapshot(cut['pmp'])} for cut in path['cuts']])


def run_pipeline(capture_manifest, output_dir, timeout_ms=10000):
    base = json.loads(Path(capture_manifest).read_text())
    if base.get('status') != 'captured':
        raise ValueError('requires a successful actual Keystone capture manifest')
    repo = Path(base['repository'])
    if digest(base['source']) != base['source_sha256']:
        raise ValueError('captured enclave.c differs from the current source')
    if digest(base['output']) != base['ir_sha256']:
        raise ValueError('captured enclave IR differs from its manifest')
    for header, expected in base.get('reference_profile', {}).get('header_sha256', {}).items():
        if digest(header) != expected:
            raise ValueError('header differs from captured configuration: '+header)
    platform = repo/'sm/src/platform/generic/platform.h'
    if '#define PMP_N_REG               8' not in platform.read_text():
        raise ValueError('analysis backend requires the captured generic eight-entry profile')
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    args = list(base['original_arguments'])
    source = repo/'sm/src/pmp.c'
    args[args.index('-c')+1] = str(source)
    args = [a.replace('-D__OBJNAME__=enclave', '-D__OBJNAME__=pmp') for a in args]
    command, removed = ir_arguments(args, source, out/'pmp.ll', base['compiler'])
    manifest = dict(readiness='ready', source=str(source), source_sha256=digest(source), output=str(out/'pmp.ll'),
        compiler=base['compiler'], command=command, directory=base['directory'],
        original_arguments=args, removed_output_options=removed, keystone_commit=base['commit'])
    manifest = capture(manifest)
    (out/'pmp-capture.json').write_text(json.dumps(manifest, indent=2)+'\n')
    if manifest['status'] != 'captured':
        raise ValueError('actual pmp.c compilation failed; see '+str(out/'pmp-capture.json'))
    graph = extract_llvm(out/'pmp.ll', functions=['pmp_set_keystone', 'pmp_unset'])
    asm = extract_report_asm(graph)
    (out/'pmp-llvm-graph.json').write_text(json.dumps(graph, indent=2)+'\n')
    (out/'pmp-asm-operations.json').write_text(json.dumps(asm, indent=2)+'\n')
    enclave = extract_llvm(base['output'], functions=['destroy_enclave','exit_enclave','stop_enclave','context_switch_to_host'])
    order = release_callsite_order(enclave)
    revocations = revocation_callsite_order(enclave)
    if not order:
        raise ValueError('could not establish actual same-rid clear-before-release facts')
    if not revocations:
        raise ValueError('could not establish revocation/Host-grant ordering in actual exit/stop code')
    dependencies = base.get('additional_translation_units', [])
    strings = [d for d in dependencies if Path(d['source']).name == 'sbi_string.c' and d['status'] == 'captured']
    if len(strings) != 1 or digest(strings[0]['output']) != strings[0]['ir_sha256']:
        raise ValueError('actual sbi_string.c capture is required for scrub-loop semantics')
    loop = summarize_loops(extract_llvm(strings[0]['output'], functions=['sbi_memset']), prove=True, timeout_ms=timeout_ms)
    if len(loop['summaries']) != 1 or loop['summaries'][0]['proof']['status'] != 'proved_for_template':
        raise ValueError('actual memset loop is not covered by the proved template')
    (out/'release-order.json').write_text(json.dumps(order, indent=2)+'\n')
    (out/'revocation-order.json').write_text(json.dumps(revocations, indent=2)+'\n')
    (out/'actual-scrub-summary.json').write_text(json.dumps(loop, indent=2)+'\n')
    results, summaries = [], []
    for mode_name, region in [('napot', RegionMetadata()), ('tor', RegionMetadata(size=0x3000, register_index=2, mode=8))]:
        revoke = execute_helper(graph, 'pmp_set_keystone', region, initial_pmp(region, enclave_running=True), permission=0)
        revoke['cache_seeded'] = True
        release = execute_helper(graph, 'pmp_unset', region, initial_pmp(region))
        for label, path in [('revoke', revoke), ('release', release)]:
            (out/f'{mode_name}-{label}-path.json').write_text(json.dumps(serialize_path(path), indent=2)+'\n')
        for context, path, processed in [(mode_name+'-enclave-exit-revocation', revoke, 0),
                                         (mode_name+'-destroy-release-after-scrub', release, region.size)]:
            result = analyze_cuts(path, region, context=context, processed=processed, timeout_ms=timeout_ms)
            results.append(result)
    region = RegionMetadata()
    pmp = initial_pmp(region)
    erase = dict(initial_pmp=pmp, operations=[], cache_seeded=False,
                 cuts=[dict(position='actual_sbi_memset:arbitrary_processed_prefix', pmp=SymbolicPMP.concrete(pmp),
                            cache_invalidated=False, operation_count=0, source=order[0])])
    results.append(analyze_cuts(erase, region, context='destroy-scrub-in-progress', processed=None, timeout_ms=timeout_ms))
    for result in results:
        summaries.append(dict(context=result['context'], processed=result['processed'],
            policies={name:dict(counterexample_cuts=policy['counterexample_cuts'],
                classifications=sorted({cut['classification'] for cut in policy['cuts']}))
                for name, policy in result['policies'].items()}))
    report = dict(schema='smpreempt.keystone-preemption-cases.v1', keystone_commit=base['commit'],
        configuration=base.get('reference_profile', {}).get('profile', 'capture manifest profile'),
        pmp_source_sha256=manifest['source_sha256'], pmp_ir_sha256=manifest['ir_sha256'],
        extracted_asm_count=len(asm['assemblies']), unsupported_asm_count=sum(not a['complete'] for a in asm['assemblies']),
        release_order_facts=len(order), revocation_order_facts=len(revocations), summaries=summaries, results=results,
        integrity='not proved; only host write permission exposure is reported',
        conclusion_scope='counterexamples for introduced arbitrary SM preemption and explicit candidate PMs/entry contracts; not a vanilla Keystone vulnerability claim',
        not_checked=['boot-to-helper reachability', 'all region values and all PMP configurations',
                     'actual deployed-board TLB behavior', 'multiple harts/IPI interleavings',
                     'trap-vector/PM implementation correctness', 'reentry/resume trusted-use attacks'])
    (out/'analysis.json').write_text(json.dumps(report, indent=2)+'\n')
    return report
