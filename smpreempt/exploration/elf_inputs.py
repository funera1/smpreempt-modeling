"""Shared command-line inputs for bounded ELF execution and access checks."""
import hashlib
import json
from pathlib import Path

import z3

from smpreempt.model.riscv_model import PMP_ADDR_BITS
from smpreempt.model.symbolic_pmp import SymbolicPMP


def add_execution_arguments(parser):
    parser.add_argument('elf', help='linked RV64 ELF input')
    parser.add_argument('--function', required=True, help='defined function with nonzero symbol size')
    parser.add_argument('--steps', type=int, default=100, help='maximum instructions per path')
    parser.add_argument('--max-states', type=int, default=1000, help='maximum instruction states explored')
    parser.add_argument('--timeout-ms', type=int, default=5000, help='solver timeout in milliseconds')
    parser.add_argument('--reg', action='append', default=[], help='initial GPR assignment e.g. x10=0x80')
    for width in (8, 32, 64):
        parser.add_argument(f'--mem{width}', action='append', default=[],
                            help=f'initial little-endian {width}-bit memory value, ADDRESS=VALUE')
    parser.add_argument('--pmp-json', help='concrete initial cfg[16], addr[16] JSON; otherwise symbolic')
    parser.add_argument('--assume-mtvec-writable', action='store_true',
                        help='assume mtvec direct/vectored values write and read back exactly')
    parser.add_argument('--llvm-library', help='LLVM shared library name or path')
    parser.add_argument('--features', default='+m,+a,+f,+d,+c,+zicsr,+zifencei')


def load_pmp_input(path):
    raw = Path(path).read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {'cfg', 'addr'}:
        raise ValueError('PMP input requires cfg and addr arrays')
    cfg, addr = data['cfg'], data['addr']
    if not isinstance(cfg, list) or not isinstance(addr, list) or len(cfg) != 16 or len(addr) != 16:
        raise ValueError('PMP input requires cfg[16] and addr[16]')
    cfg = [int(v, 0) if isinstance(v, str) else v for v in cfg]
    addr = [int(v, 0) if isinstance(v, str) else v for v in addr]
    if any(type(v) is not int or not 0 <= v <= 255 or v & 0x60 or (v & 3) == 2 for v in cfg):
        raise ValueError('PMP input has unsupported configuration byte')
    if any(type(v) is not int or not 0 <= v < 1 << PMP_ADDR_BITS for v in addr):
        raise ValueError('PMP input address is outside the profile')
    return SymbolicPMP(tuple(z3.BitVecVal(v, 8) for v in cfg),
                       tuple(z3.BitVecVal(v, 64) for v in addr)), hashlib.sha256(raw).hexdigest()


def parse_execution_inputs(args):
    registers, memory_bytes = {}, {}
    for item in args.reg:
        key, value = item.split('=', 1)
        index = int(key.removeprefix('x'))
        if index in registers:
            raise ValueError('duplicate register assignment')
        registers[index] = int(value, 0)
    for width in (8, 32, 64):
        for item in getattr(args, f'mem{width}'):
            address, value = (int(x, 0) for x in item.split('=', 1))
            if not 0 <= address < 1 << 64 or address+width//8 > 1 << 64 or not 0 <= value < 1 << width:
                raise ValueError(f'invalid --mem{width} address/value')
            for offset in range(width//8):
                if address+offset in memory_bytes:
                    raise ValueError('overlapping initial memory assignments')
                memory_bytes[address+offset] = (value >> (offset*8)) & 255
    pmp, pmp_hash = (None, None) if args.pmp_json is None else load_pmp_input(args.pmp_json)
    pmp_provenance = dict(kind='symbolic') if pmp is None else dict(
        kind='concrete', path=args.pmp_json, sha256=pmp_hash)
    return registers, memory_bytes, pmp, pmp_provenance
