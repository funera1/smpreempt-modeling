"""Link captured .ll/.bc files; preserve the inputs and report provenance."""
import argparse
import json

from smpreempt.extraction.llvm_link import link_ir
from smpreempt.frontend.llvm_c import LLVMUnavailable


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('inputs', nargs='+')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--llvm-library')
    args = p.parse_args()
    try:
        print(json.dumps(link_ir(args.inputs, args.output, args.llvm_library), indent=2))
    except (OSError, ValueError, LLVMUnavailable) as exc:
        p.error(str(exc))


if __name__ == '__main__':
    main()
