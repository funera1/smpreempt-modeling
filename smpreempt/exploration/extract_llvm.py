"""Extract a static LLVM IR transition graph, with no access-control analysis."""
import argparse
import json

from smpreempt.frontend.llvm import extract_llvm
from smpreempt.frontend.llvm_c import LLVMUnavailable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='textual LLVM IR (.ll) or LLVM bitcode (.bc)')
    parser.add_argument('--function', action='append', help='extract only these function bodies (repeatable)')
    parser.add_argument('--llvm-library', help='path/name of libLLVM 18 or 20; or set SMPREEMPT_LIBLLVM')
    parser.add_argument('--keystone-ipi-report', help='write evidence and conditional queue connections; requires --shared-calls')
    parser.add_argument('--shared-calls', action='store_true', help='one CFG per function, no call-depth limit, conditional field callback candidates')
    parser.add_argument('--abstract-model', action='store_true', help='annotate CFG with abstract state effects and provenance; expands defined calls')
    parser.add_argument('--expand-calls', action='store_true', help='expand ordinary defined calls; keep recursion/unknown effects opaque')
    parser.add_argument('--call-depth', type=int, default=4)
    parser.add_argument('--summary', choices=('graph', 'segments', 'loops'), default='graph')
    parser.add_argument('--prove', action='store_true', help='check induction obligations for recognized loop templates (requires Z3)')
    parser.add_argument('--execute-bounded', type=int, metavar='STEPS', help='run the supported single-function LLVM subset for at most STEPS CFG edges')
    parser.add_argument('--max-states', type=int, default=1000, help='maximum queued symbolic states for --execute-bounded')
    parser.add_argument('--runtime-call-depth', type=int, default=32, help='maximum nested defined calls for --execute-bounded')
    parser.add_argument('--show-values', action='store_true', help='include final SSA bindings in --execute-bounded output')
    parser.add_argument('--timeout-ms', type=int, default=10000)
    args = parser.parse_args()
    try:
        if args.keystone_ipi_report and not args.shared_calls:
            raise ValueError('--keystone-ipi-report requires --shared-calls')
        if args.shared_calls and (not args.abstract_model or args.expand_calls):
            raise ValueError('--shared-calls requires --abstract-model and excludes --expand-calls')
        if args.abstract_model and args.summary != 'graph':
            raise ValueError('--abstract-model requires --summary graph')
        if args.prove and args.summary != 'loops':
            raise ValueError('--prove applies only to --summary loops')
        if args.expand_calls and args.summary == 'loops':
            raise ValueError('loop template recognition currently takes an isolated original function, without --expand-calls')
        if args.call_depth < 0 or args.timeout_ms < 1:
            raise ValueError('call depth must be nonnegative and timeout positive')
        if args.execute_bounded is not None and (args.execute_bounded < 0 or args.max_states < 1 or args.runtime_call_depth < 0):
            raise ValueError('execution bounds must be nonnegative steps and positive states')
        if args.execute_bounded is not None and (args.abstract_model or args.expand_calls or args.shared_calls or args.summary != 'graph'):
            raise ValueError('--execute-bounded currently executes one original function without summaries or call expansion')
        if args.execute_bounded is not None and len(args.function or []) != 1:
            raise ValueError('--execute-bounded requires exactly one --function')
        report = extract_llvm(args.input, functions=None if args.expand_calls or args.abstract_model or args.execute_bounded is not None else args.function, library=args.llvm_library)
        if args.execute_bounded is not None:
            from smpreempt.model.llvm_stepper import run_bounded
            roots = [f for f in report['functions'] if f['name'] == args.function[0]]
            if len(roots) != 1:
                raise ValueError(f"expected exactly one root function named {args.function[0]!r}, found {len(roots)}")
            function = roots[0]
            states = run_bounded(function, max_steps=args.execute_bounded, max_states=args.max_states,
                max_call_depth=args.runtime_call_depth, module_report=report)
            def encode(value):
                if value is None:
                    return None
                if hasattr(value, 'bits'):
                    return dict(bits=value.bits.sexpr(), poison=value.poison.sexpr(), ub=value.ub.sexpr())
                return str(value)
            source_locations = {node['id']: dict(function=f['name'], location=node.get('source'))
                for f in report['functions'] for node in f['nodes']}
            def encode_path(s):
                relevant = {item.get('source') for item in s.trace}
                relevant.update(item.get('node') for item in s.memory_events+s.machine_events)
                relevant.discard(None)
                return dict(status=s.status, function=s.function_id, call_depth=len(s.frames), steps=s.steps, pc=s.pc,
                    predecessor=s.predecessor, path_condition=s.path.sexpr(), result=encode(s.result),
                    stopped_reason=s.stopped_reason, trace=s.trace, memory_events=s.memory_events,
                    pmp=None if s.pmp is None else dict(cfg=[x.sexpr() for x in s.pmp.cfg],
                        addr=[x.sexpr() for x in s.pmp.addr], sfence_epoch=s.sfence_epoch),
                    machine_events=s.machine_events,
                    source_locations={node:source_locations[node] for node in relevant if node in source_locations},
                    values={key:encode(value) for key,value in s.values.items()} if args.show_values else None)
            report = dict(schema='smpreempt.llvm-bounded-execution.v1', input=report['input'],
                function=function['name'], target=report['target'], step_bound=args.execute_bounded,
                state_bound=args.max_states, runtime_call_depth=args.runtime_call_depth,
                paths=[encode_path(s) for s in states],
                limits=['Single root function; defined direct calls use nested frames, unknown calls stop execution.',
                        'Loops are followed only up to the explicit CFG-edge bound.',
                        'Pointer values use a flat symbolic address space; object bounds and aliasing are not checked.',
                        'Supported PMP CSR writes use the existing eight-entry symbolic base-PMP model; SFENCE.VMA records a synchronization boundary but does not model a hardware TLB/PMP cache.',
                        'Inline-asm pseudo-instruction PCs are symbolic; alignment padding is a recorded no-op.',
                        'No PMP permissions, host behavior, or attack conditions are modeled.'])
        elif args.shared_calls:
            from smpreempt.extraction.interprocedural import shared_interprocedural
            report = shared_interprocedural(report, roots=args.function)
            if args.keystone_ipi_report:
                from pathlib import Path
                from smpreempt.keystone.ipi_connections import describe_ipi_connections
                destination = Path(args.keystone_ipi_report)
                if destination.resolve() == Path(args.input).resolve():
                    raise ValueError('IPI report must not overwrite input IR')
                destination.write_text(json.dumps(describe_ipi_connections(report), ensure_ascii=False, indent=2)+'\n')
        elif args.abstract_model:
            from smpreempt.extraction.abstract_transitions import extract_abstract_transitions
            report = extract_abstract_transitions(report, roots=args.function, max_depth=args.call_depth)
        elif args.expand_calls:
            from smpreempt.extraction.llvm_transforms import expand_calls
            report = expand_calls(report, roots=args.function, max_depth=args.call_depth)
        if args.summary == 'segments':
            from smpreempt.extraction.llvm_transforms import summarize_segments
            report = summarize_segments(report)
        elif args.summary == 'loops':
            from smpreempt.extraction.llvm_loop_summaries import summarize_loops
            report = summarize_loops(report, prove=args.prove, timeout_ms=args.timeout_ms)
    except (OSError, ValueError, LLVMUnavailable) as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
