"""Check direct Host byte permissions at bounded ELF instruction boundaries."""
import argparse
import json

from smpreempt.analysis.elf_preemption import check_boundaries
from smpreempt.exploration.elf_inputs import add_execution_arguments, parse_execution_inputs
from smpreempt.frontend.elf import ELF
from smpreempt.frontend.llvm_mc import LLVMDisassembler, LLVMDisassemblerUnavailable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_execution_arguments(parser)
    parser.add_argument('--region-base', required=True, type=lambda x: int(x, 0))
    parser.add_argument('--region-size', required=True, type=lambda x: int(x, 0))
    parser.add_argument('--host-mode', choices=('S', 'U'), default='S')
    parser.add_argument('--assume-fresh-pmp', action='store_true',
                        help='assume Host access checks see the current PMP values')
    args = parser.parse_args()
    try:
        registers, memory, pmp, provenance = parse_execution_inputs(args)
        image = ELF(args.elf)
        with LLVMDisassembler(args.llvm_library, args.features) as decoder:
            report = check_boundaries(image, image.symbol(args.function),
                region_base=args.region_base, region_size=args.region_size, host_mode=args.host_mode,
                assume_fresh_pmp=args.assume_fresh_pmp, timeout_ms=args.timeout_ms,
                max_steps=args.steps, max_states=args.max_states, registers=registers,
                memory_bytes=memory, pmp=pmp, disassembler=decoder,
                assume_mtvec_writable=args.assume_mtvec_writable)
        report['initial_pmp'] = provenance
    except (OSError, ValueError, LLVMDisassemblerUnavailable) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
