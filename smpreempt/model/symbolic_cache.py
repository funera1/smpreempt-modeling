"""One optional cached permission result for Bare identity mappings.

Entries are created from an allowed access/known prior PMP, never free rights.
This is a representative implementation-permitted behavior, not a full TLB.
"""
from dataclasses import dataclass, fields, replace

import z3


@dataclass(frozen=True)
class SymbolicCachedAccess:
    valid: object
    va: object
    pa: object
    size: object
    privilege: object
    readable: object
    writable: object
    executable: object

    @classmethod
    def fresh(cls, name):
        return cls(z3.Bool(f"{name}_valid"), z3.BitVec(f"{name}_va", 64),
                   z3.BitVec(f"{name}_pa", 64), z3.BitVec(f"{name}_size", 64),
                   z3.BitVec(f"{name}_priv", 2), z3.Bool(f"{name}_R"),
                   z3.Bool(f"{name}_W"), z3.Bool(f"{name}_X"))

    @classmethod
    def from_concrete(cls, entry):
        if entry is None:
            return cls(z3.BoolVal(False), *(z3.BitVecVal(0, 64) for _ in range(3)),
                       z3.BitVecVal(0, 2), *(z3.BoolVal(False) for _ in range(3)))
        return cls(z3.BoolVal(True), z3.BitVecVal(entry.va, 64), z3.BitVecVal(entry.pa, 64),
                   z3.BitVecVal(entry.size, 64), z3.BitVecVal({"U": 0, "S": 1, "M": 3}[entry.privilege], 2),
                   *(z3.BoolVal(entry.allows(k)) for k in ("R", "W", "X")))

    @classmethod
    def seed(cls, pmp, address, size, privilege):
        return cls(z3.BoolVal(True), address, address, z3.BitVecVal(size, 64),
                   z3.BitVecVal({"U": 0, "S": 1, "M": 3}[privilege], 2),
                   *(pmp.allow(address, size, k, privilege) for k in ("R", "W", "X")))

    def matches(self, address, size, privilege):
        a, start = z3.ZeroExt(1, address), z3.ZeroExt(1, self.va)
        return z3.And(self.valid, self.va == self.pa,
                      self.privilege == {"U": 0, "S": 1, "M": 3}[privilege],
                      z3.ULE(start, a), z3.ULE(a + size, start + z3.ZeroExt(1, self.size)))

    def allow(self, pmp, address, size, kind, privilege, use_cached):
        permission = {"R": self.readable, "W": self.writable, "X": self.executable}[kind]
        return z3.If(z3.And(use_cached, self.matches(address, size, privilege)), permission,
                     pmp.allow(address, size, kind, privilege))

    def after_access(self, pmp, address, size, privilege, use_cached, fill_cache=True):
        fresh = self.seed(pmp, address, size, privilege)
        hit = z3.Or(z3.Not(fill_cache), z3.And(use_cached, self.matches(address, size, privilege)))
        return type(self)(*[z3.If(hit, getattr(self, f.name), getattr(fresh, f.name)) for f in fields(self)])

    def invalidate(self):
        return replace(self, valid=z3.BoolVal(False))

    def same_as(self, other):
        return z3.And(self.valid == other.valid, z3.Implies(self.valid,
            z3.And(*[getattr(self, f.name) == getattr(other, f.name)
                     for f in fields(self) if f.name != "valid"])))
