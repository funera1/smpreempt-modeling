"""Build a tiny synthetic RV64 ELF for the PMP instruction inventory."""
from pathlib import Path
import sys

from examples.elf.build_fixture import build_elf


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: python3 -m examples.elf.build_pmp_fixture OUTPUT.elf')
    words = (0x3a002573,  # csrrs a0,pmpcfg0,zero
             0x3b059073,  # csrrw zero,pmpaddr0,a1
             0x3a051073,  # csrrw zero,pmpcfg0,a0
             0x12000073,  # sfence.vma zero,zero
             0x00008067)  # jalr zero,ra,0
    Path(sys.argv[1]).write_bytes(build_elf(words, function_name='pmp_demo'))


if __name__ == '__main__':
    main()
