"""Small-step RV64/PMP model for exploratory security-monitor preemption.

Scope: one hart, RV64, fixed 32-bit instructions supplied as decoded objects,
Bare addressing only, sparse little-endian physical memory, naturally aligned
64-bit LD/SD, byte LBU/SB, and a subset of M-mode CSRs. This is NOT a full ISA emulator.

Hardware state S=(E,V,P,M). The controlling execution context (H,C,SM,PM) is
separate. The preemption manager uses an abstract trusted save area: this is a
modeling assumption, not a verified memory implementation.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Optional

MASK64 = (1 << 64) - 1
PMP_ADDR_BITS = 54  # illustrative physical address encoding width
PMP_R, PMP_W, PMP_X = 1, 2, 4
PMP_OFF, PMP_TOR, PMP_NA4, PMP_NAPOT = 0, 1, 2, 3
MSTATUS_MIE = 1 << 3
MSTATUS_MPIE = 1 << 7
MSTATUS_MPP_SHIFT = 11
MSTATUS_MPP_MASK = 3 << MSTATUS_MPP_SHIFT
MSTATUS_MPRV = 1 << 17


class ModelFault(Exception):
    pass


class AccessFault(ModelFault):
    pass


class IllegalInstruction(ModelFault):
    pass


class Unsupported(ModelFault):
    pass


class IsolationRejected(ModelFault):
    """PM refuses to expose accessed memory to Host."""
    pass


@dataclass
class E:
    pc: int = 0
    r: list[int] = field(default_factory=lambda: [0] * 32)
    priv: str = "M"
    csr: dict[str, int] = field(default_factory=lambda: {
        "mstatus": 0, "mepc": 0, "mcause": 0, "mtvec": 0,
    })

    def get(self, index: int) -> int:
        return 0 if index == 0 else self.r[index]

    def put(self, index: int, value: int) -> None:
        if index != 0:
            self.r[index] = value & MASK64


@dataclass
class V:
    satp: int = 0              # Bare=0 only for actual memory accesses
    tlb: dict = field(default_factory=dict)


@dataclass
class P:
    cfg: list[int] = field(default_factory=lambda: [0] * 8)
    addr: list[int] = field(default_factory=lambda: [0] * 8)


@dataclass
class M:
    data: dict[int, int] = field(default_factory=dict)  # byte-addressed

    def load(self, pa: int, size: int) -> int:
        return sum(self.data.get(pa + i, 0) << (8 * i) for i in range(size))

    def store(self, pa: int, size: int, value: int) -> None:
        for i in range(size):
            self.data[pa + i] = (value >> (8 * i)) & 0xFF


@dataclass
class State:
    E: E = field(default_factory=E)
    V: V = field(default_factory=V)
    P: P = field(default_factory=P)
    M: M = field(default_factory=M)

    def clone(self) -> State:
        return deepcopy(self)


@dataclass(frozen=True)
class Insn:
    op: str
    rd: int = 0
    rs1: int = 0
    rs2: int = 0
    imm: int = 0
    csr: str = ""


@dataclass(frozen=True)
class Region:
    name: str
    start: int
    end: int  # exclusive

    def __post_init__(self):
        if not 0 <= self.start < self.end <= 1 << 64:
            raise ValueError("region must be a nonempty RV64 physical interval")


@dataclass(frozen=True)
class IsolationViolation:
    region: str
    address: int
    operation: str


@dataclass(frozen=True)
class ProtectionPolicy:
    """Trusted R_t metadata, supplied independently of current PMP registers.

    Regions remain protected through destruction/scrubbing. No automatic
    release inference from PMP or memory contents is permitted here.
    """
    regions: tuple[Region, ...]

    def violations(self, p: P) -> tuple[IsolationViolation, ...]:
        # PMP permissions are constant between entry endpoints. Checking one
        # byte per segment is equivalent to checking every protected byte.
        endpoints = set()
        for i in range(len(p.cfg)):
            area = pmp_range(p, i)
            if area is not None:
                endpoints.update(area)
        found = []
        for r in self.regions:
            points = sorted({r.start} | {a for a in endpoints if r.start < a < r.end})
            for a in points:
                for op in ("R", "W"):
                    if pmp_allow(p, "S", a, 1, op):
                        found.append(IsolationViolation(r.name, a, op))
        return tuple(found)

    def require_isolation(self, p: P) -> None:
        violations = self.violations(p)
        if violations:
            v = violations[0]
            raise ModelFault(f"Host isolation violation: {v.region} {v.operation} at {v.address:#x}")


def napot_encode(base: int, size: int) -> int:
    """Standard PMP NAPOT encoding for a naturally aligned power-of-two range."""
    if size < 8 or size & (size - 1) or base % size:
        raise ValueError("NAPOT needs size >=8, power of two, aligned base")
    n = size.bit_length() - 4  # size 8 => n=0; 16=>1, 256=>5
    return (base >> 2) | ((1 << n) - 1)


def _trailing_ones(x: int, width: int = PMP_ADDR_BITS) -> int:
    n = 0
    while n < width and (x >> n) & 1:
        n += 1
    return n


def pmp_range(p: P, i: int) -> Optional[tuple[int, int]]:
    mode = (p.cfg[i] >> 3) & 3
    if mode == PMP_OFF:
        return None
    if mode == PMP_TOR:
        lo = (p.addr[i - 1] << 2) if i else 0
        hi = p.addr[i] << 2
        return (lo, hi) if lo < hi else None
    if mode == PMP_NA4:
        lo = p.addr[i] << 2
        return lo, lo + 4
    n = _trailing_ones(p.addr[i])
    size = 1 << (n + 3)
    base = (p.addr[i] & ~((1 << (n + 1)) - 1)) << 2
    return base, base + size


def pmp_allow(p: P, privilege: str, pa: int, size: int, op: str) -> bool:
    """First overlapping PMP entry wins; partial coverage fails.

    Assumes at least one PMP entry is implemented (8 in this model).
    Ignores Smepmp, PMA, memory ordering and decomposed accesses.
    """
    bit = {"R": PMP_R, "W": PMP_W, "X": PMP_X}[op]
    for i, cfg in enumerate(p.cfg):
        area = pmp_range(p, i)
        if area is None:
            continue
        lo, hi = area
        if pa < hi and pa + size > lo:  # intersects any byte
            if not (lo <= pa and pa + size <= hi):
                return False
            if privilege == "M" and not (cfg & 0x80):  # unlocked
                return True
            return bool(cfg & bit)
    return privilege == "M"  # S/U fail when implemented PMP has no match


def _write_pmpcfg0(p: P, value: int) -> None:
    for i in range(8):
        if p.cfg[i] & 0x80:  # locked
            continue
        byte = (value >> (8 * i)) & 0xFF
        # The R=0, W=1 PMP permission encoding is reserved in base PMP.
        if (byte & PMP_W) and not (byte & PMP_R):
            raise Unsupported(f"WARL handling for reserved PMP permissions in entry {i} not modeled")
        p.cfg[i] = byte


def _write_pmpaddr(p: P, i: int, value: int) -> None:
    if p.cfg[i] & 0x80:
        return
    # Locked TOR entry i+1 also locks the preceding address register.
    if i + 1 < len(p.cfg) and p.cfg[i + 1] & 0x80:
        if ((p.cfg[i + 1] >> 3) & 3) == PMP_TOR:
            return
    p.addr[i] = value & ((1 << PMP_ADDR_BITS) - 1)


def _effective_privilege(e: E, kind: str) -> str:
    if kind != "X" and e.priv == "M" and (e.csr["mstatus"] & MSTATUS_MPRV):
        mpp = (e.csr["mstatus"] & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT
        return {0: "U", 1: "S", 3: "M"}.get(mpp, "M")
    return e.priv


def _translate(s: State, va: int, kind: str) -> int:
    priv = _effective_privilege(s.E, kind)
    if priv != "M" and s.V.satp != 0:
        raise Unsupported("Sv39 page walks not implemented; Bare mode only")
    # M-mode instruction/data accesses normally use physical addresses.
    return va & MASK64


def check_access(s: State, va: int, size: int, kind: str) -> int:
    pa = _translate(s, va, kind)
    if not pmp_allow(s.P, _effective_privilege(s.E, kind), pa, size, kind):
        raise AccessFault(f"{kind} denied in {s.E.priv}-mode at {pa:#x}")
    return pa


def step(old: State, i: Insn) -> State:
    """Execute one explicitly decoded 32-bit instruction (no fetch/decode)."""
    s = old.clone()
    e = s.E
    v1, v2 = e.get(i.rs1), e.get(i.rs2)
    next_pc = (e.pc + 4) & MASK64
    op = i.op.upper()

    if op == "ADD":
        e.put(i.rd, v1 + v2)
    elif op == "ADDI":
        e.put(i.rd, v1 + i.imm)
    elif op == "XOR":
        e.put(i.rd, v1 ^ v2)
    elif op == "AND":
        e.put(i.rd, v1 & v2)
    elif op in ("LD", "LBU"):
        va = (v1 + i.imm) & MASK64
        size = 8 if op == "LD" else 1
        if va % size:
            raise Unsupported("unaligned LD omitted")
        pa = check_access(s, va, size, "R")
        e.put(i.rd, s.M.load(pa, size))
    elif op in ("SD", "SB"):
        va = (v1 + i.imm) & MASK64
        size = 8 if op == "SD" else 1
        if va % size:
            raise Unsupported("unaligned SD omitted")
        pa = check_access(s, va, size, "W")
        s.M.store(pa, size, v2)
    elif op == "BEQ":
        if v1 == v2:
            next_pc = (e.pc + i.imm) & MASK64
    elif op == "JAL":
        e.put(i.rd, next_pc)
        next_pc = (e.pc + i.imm) & MASK64
    elif op == "JALR":
        e.put(i.rd, next_pc)
        next_pc = (v1 + i.imm) & ~1 & MASK64
    elif op == "CSRW":
        if i.csr.startswith("pmp"):
            if e.priv != "M":
                raise IllegalInstruction("PMP CSRs require M-mode")
            if i.csr == "pmpcfg0":
                _write_pmpcfg0(s.P, v1)
            elif i.csr.startswith("pmpaddr"):
                n = int(i.csr[len("pmpaddr"):])
                if not 0 <= n < len(s.P.addr):
                    raise IllegalInstruction("PMP index unsupported")
                _write_pmpaddr(s.P, n, v1)
            else:
                raise IllegalInstruction(f"CSR not implemented: {i.csr}")
        elif i.csr == "satp":
            if e.priv not in ("S", "M"):
                raise IllegalInstruction("satp requires S/M-mode")
            s.V.satp = v1
        elif i.csr in e.csr:
            if e.priv != "M":
                raise IllegalInstruction("M-mode CSR access from lower privilege")
            e.csr[i.csr] = v1
        else:
            raise IllegalInstruction(f"CSR not implemented: {i.csr}")
    elif op == "SFENCE.VMA":
        if e.priv not in ("S", "M"):
            raise IllegalInstruction("sfence.vma requires S/M-mode")
        s.V.tlb.clear()  # full fence abstraction only
    elif op == "ECALL":
        # Simplified: no medeleg; all ECALLs target M-mode.
        privilege_code = {"U": 0, "S": 1, "M": 3}[e.priv]
        ms = e.csr["mstatus"]
        ms = (ms & ~MSTATUS_MPP_MASK) | (privilege_code << MSTATUS_MPP_SHIFT)
        if ms & MSTATUS_MIE:
            ms |= MSTATUS_MPIE
        else:
            ms &= ~MSTATUS_MPIE
        ms &= ~MSTATUS_MIE
        e.csr["mstatus"] = ms
        e.csr["mepc"] = e.pc
        e.csr["mcause"] = {"U": 8, "S": 9, "M": 11}[e.priv]
        e.priv = "M"
        next_pc = e.csr["mtvec"] & ~3
    elif op == "MRET":
        if e.priv != "M":
            raise IllegalInstruction("mret requires M-mode")
        ms = e.csr["mstatus"]
        mpp = (ms & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT
        newpriv = {0: "U", 1: "S", 3: "M"}.get(mpp)
        if newpriv is None:
            raise IllegalInstruction("invalid MPP")
        if ms & MSTATUS_MPIE:
            ms |= MSTATUS_MIE
        else:
            ms &= ~MSTATUS_MIE
        ms |= MSTATUS_MPIE
        ms &= ~MSTATUS_MPP_MASK
        if newpriv != "M":
            ms &= ~MSTATUS_MPRV
        e.csr["mstatus"] = ms
        e.priv = newpriv
        next_pc = e.csr["mepc"]
    else:
        raise Unsupported(f"instruction not modeled: {i.op}")

    e.pc = next_pc
    e.r[0] = 0
    return s


def _pmp_installable(old: P, new: P) -> bool:
    # Check whether M-mode can replace raw PMP regs without violating locks.
    for i in range(len(old.cfg)):
        if (old.cfg[i] & 0x80) and (old.cfg[i] != new.cfg[i]):
            return False
        addr_locked = bool(old.cfg[i] & 0x80)
        if i + 1 < len(old.cfg):
            addr_locked |= bool(old.cfg[i + 1] & 0x80) and (
                ((old.cfg[i + 1] >> 3) & 3) == PMP_TOR)
        if addr_locked and old.addr[i] != new.addr[i]:
            return False
    return True


@dataclass
class Suspended:
    E: E
    V: V
    P: P
    context: str


class PM:
    """Abstract trusted PM. Private save slots are assumed inaccessible to H.

    safe_host_pmp=None models a broken PM that passes through the SM's PMP.
    A supplied template models an independent, trusted protection policy.
    Actual CSR write ordering and PM trap entry are intentionally abstract.
    """
    def __init__(self, safe_host_pmp: Optional[P], policy: Optional[ProtectionPolicy] = None,
                 enforce_history: bool = False):
        self.safe_host_pmp = deepcopy(safe_host_pmp)
        self.policy = policy
        self.enforce_history = enforce_history

    def switchout(self, sm: State, context: str = "SM", *, check_policy: bool = True) -> tuple[State, Suspended]:
        if context not in ("SM", "C"):
            raise ValueError("only trusted contexts may be interrupted")
        slot = Suspended(deepcopy(sm.E), deepcopy(sm.V), deepcopy(sm.P), context)
        host = sm.clone()
        if self.safe_host_pmp is not None:
            if not _pmp_installable(host.P, self.safe_host_pmp):
                raise ModelFault("cannot install safe PMP: locked entries")
            host.P = deepcopy(self.safe_host_pmp)
        if check_policy and self.policy is not None:
            self.policy.require_isolation(host.P)
        # A temporary template must also permit restoring the suspended PMP.
        if not _pmp_installable(host.P, slot.P):
            raise ModelFault("Host PMP template would prevent resume: locked entries")
        host.E = E(pc=0x1000, priv="S")  # all Host GPRs initialized afresh
        host.V = V(satp=0)                # Bare Host address space
        return host, slot

    def switchin(self, host: State, slot: Suspended) -> State:
        if not _pmp_installable(host.P, slot.P):
            raise ModelFault("cannot restore original PMP: locked entries")
        s = host.clone()                  # Host changes to shared M persist!
        s.E = deepcopy(slot.E)
        s.V = deepcopy(slot.V)
        s.P = deepcopy(slot.P)
        return s



@dataclass
class Machine:
    """Context-labelled transition system Σ=(S,c), with PM steps atomic.

    T1/T3: instruction(); T2: preempt(); T4(resume): resume().
    T4(invoke) needs a trusted entrypoint/reentrancy policy, not modeled yet.
    """
    S: State
    c: str = "SM"
    suspended: Optional[Suspended] = None
    accessed: frozenset[int] = frozenset()
    pending: bool = False

    def history_policy(self) -> ProtectionPolicy:
        """Coalesce the trusted, monotonically growing byte history into ranges."""
        regions = []
        for a in sorted(self.accessed):
            if regions and regions[-1].end == a:
                r = regions[-1]
                regions[-1] = Region(r.name, r.start, a + 1)
            else:
                regions.append(Region("access-history", a, a + 1))
        return ProtectionPolicy(tuple(regions))

    def instruction(self, instr: Insn) -> Machine:
        if self.c not in ("H", "C", "SM"):
            raise ModelFault("cannot execute normal instructions in PM")
        if self.c == "H" and self.S.E.priv not in ("S", "U"):
            raise ModelFault("Host must execute at lower privilege")
        result = step(self.S, instr)
        if result.E.priv != self.S.E.priv:
            raise Unsupported("privilege transition requires PM dispatch in Machine; use step for raw ISA semantics")
        if self.c == "H" and instr.op.upper() == "ECALL":
            raise Unsupported("Host ECALL requires PM dispatch")
        accessed = self.accessed
        if self.c in ("C", "SM") and instr.op.upper() in ("LD", "SD", "LBU", "SB"):
            va = (self.S.E.get(instr.rs1) + instr.imm) & MASK64
            size = 8 if instr.op.upper() in ("LD", "SD") else 1
            kind = "R" if instr.op.upper() in ("LD", "LBU") else "W"
            pa = check_access(self.S, va, size, kind)
            accessed = accessed | frozenset(range(pa, pa + size))
        return Machine(result, self.c, self.suspended, accessed, self.pending)

    def preempt(self, pm: PM, *, check_policy: bool = True) -> Machine:
        if self.c not in ("C", "SM") or self.suspended is not None:
            raise ModelFault("cannot preempt this context")
        host, slot = pm.switchout(self.S, self.c, check_policy=check_policy)
        if check_policy and pm.enforce_history and self.history_policy().violations(host.P):
            raise IsolationRejected("Host PMP exposes C/SM access history")
        return Machine(host, "H", slot, self.accessed)

    def resume(self, pm: PM) -> Machine:
        if self.c != "H" or self.suspended is None:
            raise ModelFault("no pending context to resume")
        return Machine(pm.switchin(self.S, self.suspended),
                       self.suspended.context, None, self.accessed)


@dataclass(frozen=True)
class HostAction:
    operation: str
    address: int
    value: int = 0

    def execute(self, machine: Machine) -> Machine:
        if self.operation not in ("LD", "SD"):
            raise ValueError("Host action must be LD or SD")
        # Shorthand for attacker-controlled GPR setup followed by one access.
        state = machine.S.clone()
        state.E.put(10, self.address)
        state.E.put(11, self.value)
        return Machine(state, machine.c, machine.suspended, machine.accessed, machine.pending).instruction(
            Insn(self.operation, rd=12, rs1=10, rs2=11))
