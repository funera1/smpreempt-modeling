"""Extract a linked Keystone/RV64 ELF, or check bounded semantic read leaks."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path

from smpreempt.frontend.elf import ELF
from smpreempt.model.riscv_model import P, PM


def integer(text):
    return int(text, 0)


def pmp_config(path):
    data = json.loads(Path(path).read_text())
    if set(data) != {'cfg', 'addr'} or len(data['cfg']) != 8 or len(data['addr']) != 8:
        raise ValueError('PMP JSON requires cfg[8] and addr[8]')
    cfg = [integer(v) if isinstance(v, str) else v for v in data['cfg']]
    addr = [integer(v) if isinstance(v, str) else v for v in data['addr']]
    if any(type(v) is not int or not 0 <= v < 256 or v & 0x60 or (v & 3) == 2 for v in cfg):
        raise ValueError('invalid PMP configuration byte')
    if any(type(v) is not int or not 0 <= v < 1 << 54 for v in addr):
        raise ValueError('invalid 54-bit PMP address')
    return P(cfg=cfg, addr=addr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf')
    parser.add_argument('--analysis', choices=('extract', 'reads'), default='extract')
    parser.add_argument('--entry', help='symbol name or numeric PC; defaults to ELF entry')
    parser.add_argument('--exit', action='append', default=[], help='explicit harness exit PC or symbol')
    parser.add_argument('--cut', action='append', default=[], help='restrict observations to these PCs/symbols')
    parser.add_argument('--secret-reg', action='append', type=int, default=None)
    parser.add_argument('--reg', action='append', default=[], help='public register assignment, e.g. 10=0x8000')
    parser.add_argument('--initial-pmp', help='initial trusted PMP JSON (default all OFF)')
    parser.add_argument('--host-pmp', help='candidate Host PMP JSON (default preserve current PMP)')
    parser.add_argument('--bound', type=int, default=8)
    parser.add_argument('--timeout-ms', type=int, default=10000)
    args = parser.parse_args()
    try:
        image = ELF(args.elf)
        def location(value):
            try:
                return integer(value)
            except ValueError:
                return image.symbol(value).address
        entry = image.entry if args.entry is None else location(args.entry)
        if entry not in image.instructions:
            raise ValueError('entry is not an extracted instruction boundary')
        if args.analysis == 'extract':
            report = image.report()
            report['selected_entry'] = hex(entry)
            report['transitions'] = []
            for at, record in sorted(image.instructions.items()):
                insn = record.decoded
                if insn is None:
                    edge = dict(pc=hex(at), kind='unsupported', successors=[])
                elif insn.op == 'JALR':
                    edge = dict(pc=hex(at), kind='indirect', successors=[],
                                target='(x[rs1] + imm) & ~1', instruction=asdict(insn))
                else:
                    successors = [at+insn.imm] if insn.op == 'JAL' else [at+4, at+insn.imm] if insn.op == 'BEQ' else [at+4]
                    edge = dict(pc=hex(at), kind='conditional' if insn.op == 'BEQ' else 'direct',
                                successors=[hex(a % (1 << 64)) for a in dict.fromkeys(successors)], instruction=asdict(insn))
                report['transitions'].append(edge)
        else:
            from smpreempt.analysis.elf_analysis import analyze_reads
            registers = {}
            for assignment in args.reg:
                r, value = assignment.split('=', 1)
                r = int(r.removeprefix('x'))
                if r in registers:
                    raise ValueError('duplicate register assignment')
                registers[r] = integer(value)
            report = analyze_reads(image, entry=entry, bound=args.bound,
                exits=[location(v) for v in args.exit],
                cuts=[location(v) for v in args.cut],
                secret_registers=(11,) if args.secret_reg is None else args.secret_reg,
                registers=registers, timeout_ms=args.timeout_ms,
                initial_pmp=None if args.initial_pmp is None else pmp_config(args.initial_pmp),
                pm=PM(None if args.host_pmp is None else pmp_config(args.host_pmp)))
            report['elf_path'] = str(Path(args.elf))
        print(json.dumps(report, indent=2))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
