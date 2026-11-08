"""Inspect or run an IR capture using Keystone's actual compile command."""
import argparse
import json
from pathlib import Path

from smpreempt.keystone.keystone_ir import prepare_capture, capture, generic_compile_database, capture_opensbi_string


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('repository')
    p.add_argument('--output-dir', default='results/keystone-ir')
    p.add_argument('--source', default='sm/src/enclave.c')
    p.add_argument('--compile-commands')
    p.add_argument('--clang')
    p.add_argument('--target')
    p.add_argument('--generic-opensbi', help='derive a reference generic compile command from an OpenSBI v1.1 checkout')
    p.add_argument('--include-opensbi-string', action='store_true', help='also capture the actual sbi_memset/memcpy definitions')
    p.add_argument('--run', action='store_true', help='compile if all required inputs are available')
    args = p.parse_args()
    try:
        profile = None
        if args.include_opensbi_string and not args.generic_opensbi:
            raise ValueError('--include-opensbi-string requires --generic-opensbi')
        if args.generic_opensbi:
            if not args.clang or args.compile_commands or args.source != 'sm/src/enclave.c':
                raise ValueError('--generic-opensbi requires --clang and the default enclave.c source, without --compile-commands')
            db, profile = generic_compile_database(args.repository, args.generic_opensbi, args.clang, args.output_dir)
            args.compile_commands = str(db)
        report = prepare_capture(args.repository, args.output_dir, source=args.source,
            compilation_database=args.compile_commands, clang=args.clang, target=args.target)
        if args.run:
            report = capture(report)
            if args.include_opensbi_string and report['status'] == 'captured':
                dependency = capture_opensbi_string(report, profile)
                report['additional_translation_units'] = [dependency]
                if dependency['status'] != 'captured':
                    report['status'] = 'dependency_compile_failed'
        if profile:
            report['reference_profile'] = profile
        output = Path(args.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        (output/'capture.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if args.run and report.get('status') != 'captured':
            raise SystemExit(1)
    except (OSError, ValueError, KeyError) as exc:
        p.error(str(exc))


if __name__ == '__main__':
    main()
