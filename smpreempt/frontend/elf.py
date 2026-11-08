"""Strict linked ELF64/RISC-V reader and partial RV64 decoder (no dependencies).

Unknown instructions stay in the listing; they are never treated as NOPs.
Addresses are virtual ELF addresses. The execution adapter requires identity
PT_LOAD addresses, matching the current Bare physical-memory model.
"""
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import struct

from smpreempt.model.riscv_model import Insn


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def decode32(word, pc):
    """Return a modeled instruction, or None. LUI/AUIPC normalize exactly."""
    op, rd, f3 = word & 127, (word >> 7) & 31, (word >> 12) & 7
    r1, r2, f7 = (word >> 15) & 31, (word >> 20) & 31, word >> 25
    imm = signed(word >> 20, 12)
    if op == 0x13 and f3 == 0:
        return Insn('ADDI', rd=rd, rs1=r1, imm=imm)
    if op == 0x33 and f7 == 0 and f3 in (0, 4, 7):
        return Insn({0: 'ADD', 4: 'XOR', 7: 'AND'}[f3], rd=rd, rs1=r1, rs2=r2)
    if op == 3 and f3 == 3:
        return Insn('LD', rd=rd, rs1=r1, imm=imm)
    if op == 0x23 and f3 == 3:
        return Insn('SD', rs1=r1, rs2=r2, imm=signed(((word >> 25) << 5) | ((word >> 7) & 31), 12))
    if op == 0x63 and f3 == 0:
        v = ((word >> 31) << 12) | (((word >> 7) & 1) << 11) | (((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1)
        return Insn('BEQ', rs1=r1, rs2=r2, imm=signed(v, 13))
    if op == 0x6f:
        v = ((word >> 31) << 20) | (((word >> 12) & 255) << 12) | (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1)
        return Insn('JAL', rd=rd, imm=signed(v, 21))
    if op == 0x67 and f3 == 0:
        return Insn('JALR', rd=rd, rs1=r1, imm=imm)
    if op in (0x37, 0x17):
        v = signed(word & 0xfffff000, 32) + (pc if op == 0x17 else 0)
        return Insn('ADDI', rd=rd, imm=v)
    if op == 0x73 and f3 == 1 and rd == 0:
        csr = word >> 20
        name = {0x180: 'satp', 0x3a0: 'pmpcfg0', **{0x3b0+i: f'pmpaddr{i}' for i in range(8)}}.get(csr)
        if name:
            return Insn('CSRW', rs1=r1, csr=name)
    if op == 0x73 and f3 == 0 and rd == 0 and f7 == 9:
        if not r1 and not r2:
            return Insn('SFENCE.VMA')
    return None


@dataclass(frozen=True)
class Segment:
    address: int
    physical: int
    data: bytes
    memory_size: int
    flags: int


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int
    function: bool


@dataclass(frozen=True)
class Instruction:
    address: int
    raw: bytes
    decoded: object
    reason: str = ''

    def report(self):
        return dict(address=hex(self.address), bytes=self.raw.hex(), size=len(self.raw),
                    instruction=None if self.decoded is None else asdict(self.decoded),
                    unsupported=self.reason or None)


class ELF:
    def __init__(self, path):
        self.path = str(path)
        data = Path(path).read_bytes()
        self.sha256 = hashlib.sha256(data).hexdigest()
        def block(offset, size):
            if offset < 0 or size < 0 or offset + size > len(data):
                raise ValueError('ELF range outside file')
            return data[offset:offset+size]
        if block(0, 7) != b'\x7fELF\x02\x01\x01':
            raise ValueError('requires little-endian ELF64 version 1')
        h = struct.unpack('<16sHHIQQQIHHHHHH', block(0, 64))
        _, kind, machine, version, self.entry, phoff, shoff, self.flags, ehsize, phsize, phnum, shsize, shnum, shstr = h
        if kind != 2 or machine != 243 or version != 1 or ehsize != 64:
            raise ValueError('requires a linked RISC-V ET_EXEC ELF64')
        if not shnum or phnum == 0xffff or shstr == 0xffff:
            raise ValueError('sectionless/extended-numbering ELF is not supported')
        if shsize != 64 or (phnum and phsize != 56):
            raise ValueError('unexpected ELF table entry size')
        sections = [struct.unpack('<IIQQQQIIQQ', block(shoff+i*shsize, 64)) for i in range(shnum)]
        self.segments = []
        for i in range(phnum):
            typ, flags, offset, va, pa, filesz, memsz, align = struct.unpack('<IIQQQQQQ', block(phoff+i*phsize, 56))
            if typ in (2, 3):
                raise ValueError('dynamic linking/interpreters are not supported')
            if typ != 1:
                continue
            if filesz > memsz or va + memsz > 1 << 64:
                raise ValueError('invalid PT_LOAD size')
            self.segments.append(Segment(va, pa, block(offset, filesz), memsz, flags))
        if not self.segments:
            raise ValueError('ELF has no PT_LOAD segments')
        ordered = sorted(self.segments, key=lambda s: s.address)
        if any(a.address+a.memory_size > b.address for a, b in zip(ordered, ordered[1:])):
            raise ValueError('overlapping PT_LOAD segments are not supported')
        self.symbols = []
        self.instructions = {}
        def string(table, offset):
            if offset >= len(table):
                raise ValueError('invalid ELF string offset')
            end = table.find(b'\x00', offset)
            if end < 0:
                raise ValueError('unterminated ELF string')
            return table[offset:end].decode('utf8', errors='replace')
        for sec in sections:
            name, typ, flags, addr, offset, size, link, info, align, entsize = sec
            if typ in (2, 11):
                if entsize != 24 or size % 24 or link >= len(sections):
                    raise ValueError('invalid symbol table')
                strings = sections[link]
                table = block(strings[4], strings[5])
                for j in range(size//24):
                    n, inf, other, ndx, value, nbytes = struct.unpack('<IBBHQQ', block(offset+j*24, 24))
                    if ndx and n:
                        self.symbols.append(Symbol(string(table, n), value, nbytes, (inf & 15) == 2))
            if not flags & 4 or not flags & 2 or typ != 1:
                continue
            code = block(offset, size)
            if not any(s.flags & 1 and s.address <= addr and addr+size <= s.address+len(s.data)
                       and s.data[addr-s.address:addr-s.address+size] == code for s in self.segments):
                raise ValueError('executable section does not match an executable PT_LOAD')
            pos = 0
            while pos < len(code):
                remaining = code[pos:]
                low = int.from_bytes(remaining[:2], 'little')
                width = 2 if low & 3 != 3 else 4 if low & 31 != 31 else 6 if low & 63 == 31 else 8 if low & 127 == 63 else len(remaining)
                raw = remaining[:width]
                decoded = decode32(int.from_bytes(raw, 'little'), addr+pos) if width == 4 and len(raw) == 4 else None
                reason = '' if decoded is not None else ('unmodeled RV64 instruction' if width == 4 else 'compressed, long, or truncated instruction')
                if addr+pos in self.instructions:
                    raise ValueError('overlapping executable sections')
                self.instructions[addr+pos] = Instruction(addr+pos, raw, decoded, reason)
                pos += len(raw)

    def symbol(self, name):
        matches = {s for s in self.symbols if s.name == name}
        if len(matches) != 1:
            raise ValueError(f'expected one defined symbol: {name}')
        return matches.pop()

    def report(self):
        return dict(path=self.path, sha256=self.sha256, entry=hex(self.entry), flags=self.flags,
                    segments=[dict(address=hex(s.address), physical=hex(s.physical),
                                   file_size=len(s.data), memory_size=s.memory_size, flags=s.flags)
                              for s in self.segments],
                    symbols=[asdict(s) for s in self.symbols],
                    instructions=[i.report() for _, i in sorted(self.instructions.items())],
                    supported_instructions=sum(i.decoded is not None for i in self.instructions.values()),
                    unsupported_instructions=sum(i.decoded is None for i in self.instructions.values()))
