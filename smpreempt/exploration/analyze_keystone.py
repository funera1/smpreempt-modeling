"""Extract actual Keystone PMP transitions and check candidate preemption cases."""
import argparse
import json
from pathlib import Path

from smpreempt.analysis.keystone_attack_pipeline import run_pipeline
from smpreempt.frontend.llvm_c import LLVMUnavailable


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture', default='results/keystone-generic-ir/capture.json')
    p.add_argument('--output-dir', default='results/keystone-generic-ir/preemption')
    p.add_argument('--timeout-ms', type=int, default=10000)
    args = p.parse_args()
    try:
        report = run_pipeline(args.capture, args.output_dir, args.timeout_ms)
        print(json.dumps(dict(output=str(Path(args.output_dir).resolve()/'analysis.json'),
            scope=report['conclusion_scope'], extracted_asm_count=report['extracted_asm_count'],
            unsupported_asm_count=report['unsupported_asm_count'], release_order_facts=report['release_order_facts'],
            revocation_order_facts=report['revocation_order_facts'],
            summaries=report['summaries']), indent=2))
    except (OSError, ValueError, LLVMUnavailable) as exc:
        p.error(str(exc))


if __name__ == '__main__':
    main()
