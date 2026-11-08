"""List a RISC-V ELF function's machine instructions and PMP-related encodings."""
import argparse
import hashlib
import json
from pathlib import Path

from smpreempt.extraction.elf_pmp_inventory import inspect_function
from smpreempt.frontend.elf import ELF
from smpreempt.frontend.llvm_mc import LLVMDisassembler, LLVMDisassemblerUnavailable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', help='linked RV64 ELF input')
    parser.add_argument('--function', required=True, help='defined function symbol with a nonzero size')
    parser.add_argument('--llvm-library', help='LLVM shared library name or path')
    parser.add_argument('--build-metadata', help='optional JSON with externally supplied build provenance')
    parser.add_argument('--features', default='+m,+a,+f,+d,+c,+zicsr,+zifencei',
                        help='LLVM RISC-V target features; match the actual build')
    args = parser.parse_args()
    try:
        image = ELF(args.elf)
        symbol = image.symbol(args.function)
        with LLVMDisassembler(args.llvm_library, args.features) as decoder:
            report = inspect_function(image, symbol, decoder)
        report['build_metadata'] = None
        if args.build_metadata:
            raw = Path(args.build_metadata).read_bytes()
            report['build_metadata'] = dict(path=args.build_metadata,
                sha256=hashlib.sha256(raw).hexdigest(), content=json.loads(raw))
    except (OSError, ValueError, LLVMDisassemblerUnavailable) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
