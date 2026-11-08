"""Symbolic base-PMP subset with RV64 eight- or sixteen-entry profiles."""
from dataclasses import dataclass

import z3

from smpreempt.model.riscv_model import PMP_ADDR_BITS


@dataclass(frozen=True)
class SymbolicPMP:
    cfg: tuple
    addr: tuple

    @classmethod
    def fresh(cls, name, count=8):
        if count not in (8, 16):
            raise ValueError('supported PMP profiles have eight or sixteen entries')
        return cls(tuple(z3.BitVec(f"{name}_cfg{i}", 8) for i in range(count)),
                   tuple(z3.BitVec(f"{name}_addr{i}", 64) for i in range(count)))

    @classmethod
    def concrete(cls, pmp):
        if len(pmp.cfg) != 8 or len(pmp.addr) != 8:
            raise ValueError("symbolic PMP requires eight entries")
        if any(not 0 <= c <= 255 for c in pmp.cfg) or any(
                not 0 <= a < 1 << PMP_ADDR_BITS for a in pmp.addr):
            raise ValueError("PMP registers outside modeled widths")
        return cls(tuple(z3.BitVecVal(c, 8) for c in pmp.cfg),
                   tuple(z3.BitVecVal(a, 64) for a in pmp.addr))

    def same_as(self, other):
        if len(self.cfg) != len(other.cfg) or len(self.addr) != len(other.addr):
            raise ValueError('PMP profiles differ')
        return z3.And(*[a == b for a, b in zip(self.cfg + self.addr, other.cfg + other.addr)])

    def range(self, index):
        cfg, address = self.cfg[index], z3.ZeroExt(2, self.addr[index])
        mode = z3.Extract(4, 3, cfg)
        previous = z3.ZeroExt(2, self.addr[index - 1]) if index else z3.BitVecVal(0, 66)
        # n trailing ones => mask has n+1 low ones, including n=54.
        mask = address ^ (address + 1)
        napot_lo = (address & ~mask) << 2
        napot_hi = napot_lo + ((mask + 1) << 2)
        lo = z3.If(mode == 1, previous << 2, z3.If(mode == 2, address << 2, napot_lo))
        hi = z3.If(mode == 1, address << 2, z3.If(mode == 2, (address << 2) + 4, napot_hi))
        active = z3.And(mode != 0, z3.Or(mode != 1, z3.ULT(lo, hi)))
        return active, lo, hi

    def allow(self, address, size, kind, privilege="S"):
        if size < 1 or kind not in ("R", "W", "X") or privilege not in ("M", "S", "U"):
            raise ValueError("invalid PMP access")
        a = z3.ZeroExt(2, address)
        result = z3.BoolVal(privilege == "M")
        bit = {"R": 1, "W": 2, "X": 4}[kind]
        for i in reversed(range(len(self.cfg))):
            active, lo, hi = self.range(i)
            overlap = z3.And(active, z3.ULT(a, hi), z3.UGT(a + size, lo))
            covered = z3.And(z3.ULE(lo, a), z3.ULE(a + size, hi))
            permission = self.cfg[i] & bit != 0
            if privilege == "M":
                permission = z3.Or(self.cfg[i] & 0x80 == 0, permission)
            result = z3.If(overlap, z3.And(covered, permission), result)
        return result

    def address_locked(self, index):
        own = self.cfg[index] & 0x80 != 0
        if index == len(self.cfg)-1:
            return own
        following = self.cfg[index + 1]
        return z3.Or(own, z3.And(following & 0x80 != 0, z3.Extract(4, 3, following) == 1))

    def installable(self, target):
        if len(self.cfg) != len(target.cfg) or len(self.addr) != len(target.addr):
            raise ValueError('PMP profiles differ')
        return z3.And(*[
            z3.And(z3.Implies(self.cfg[i] & 0x80 != 0, self.cfg[i] == target.cfg[i]),
                   z3.Implies(self.address_locked(i), self.addr[i] == target.addr[i]))
            for i in range(len(self.cfg))])

    def write(self, csr, value):
        """Returns (updated PMP, supported-WARL predicate)."""
        cfg, addr = list(self.cfg), list(self.addr)
        valid = z3.BoolVal(True)
        if csr in ("pmpcfg0", "pmpcfg2"):
            start = 0 if csr == "pmpcfg0" else 8
            if start + 8 > len(cfg):
                raise ValueError(f"unsupported PMP CSR: {csr}")
            conditions = []
            for i in range(start, start+8):
                offset = i-start
                byte = z3.Extract(8 * offset + 7, 8 * offset, value)
                unlocked = self.cfg[i] & 0x80 == 0
                conditions.append(z3.Implies(unlocked, z3.Or(byte & 2 == 0, byte & 1 != 0)))
                cfg[i] = z3.If(unlocked, byte, self.cfg[i])
            valid = z3.And(*conditions)
        elif csr in {f"pmpaddr{i}" for i in range(len(addr))}:
            i = int(csr[7:])
            addr[i] = z3.If(self.address_locked(i), self.addr[i], value & ((1 << PMP_ADDR_BITS) - 1))
        else:
            raise ValueError(f"unsupported PMP CSR: {csr}")
        return SymbolicPMP(tuple(cfg), tuple(addr)), valid
