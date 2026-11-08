"""Bounded symbolic execution of PMP instructions in a linked RV64 ELF function."""
import argparse
import json

from smpreempt.analysis.elf_pmp_steps import execute_function
from smpreempt.exploration.elf_inputs import add_execution_arguments, parse_execution_inputs
from smpreempt.frontend.elf import ELF
from smpreempt.frontend.llvm_mc import LLVMDisassembler, LLVMDisassemblerUnavailable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_execution_arguments(parser)
    args = parser.parse_args()
    try:
        registers, memory_bytes, pmp, provenance = parse_execution_inputs(args)
        image = ELF(args.elf)
        with LLVMDisassembler(args.llvm_library, args.features) as decoder:
            report = execute_function(image, image.symbol(args.function), max_steps=args.steps,
                max_states=args.max_states, timeout_ms=args.timeout_ms, registers=registers,
                memory_bytes=memory_bytes, pmp=pmp, disassembler=decoder,
                assume_mtvec_writable=args.assume_mtvec_writable)
        report['initial_pmp'] = provenance
    except (OSError, ValueError, LLVMDisassemblerUnavailable) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
