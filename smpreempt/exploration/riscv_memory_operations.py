"""List generic RISC-V memory operation relations or normalize decoded input."""
import argparse
import json
from pathlib import Path

from smpreempt.model.riscv_memory_operations import catalogue, BY_ID, normalize_sequence


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group()
    group.add_argument('--operation', choices=tuple(BY_ID), help='show one operation-family transition template')
    group.add_argument('--input', help='JSON list of decoded instructions; preserve operation boundaries')
    args = p.parse_args()
    try:
        if args.operation:
            report = BY_ID[args.operation]
        elif args.input:
            values = json.loads(Path(args.input).read_text())
            if not isinstance(values, list):
                raise ValueError('input must be a list of decoded instructions')
            report = normalize_sequence(values)
        else:
            report = catalogue()
        print(json.dumps(report, indent=2, ensure_ascii=False))
    except (OSError, ValueError, KeyError) as exc:
        p.error(str(exc))


if __name__ == '__main__':
    main()
