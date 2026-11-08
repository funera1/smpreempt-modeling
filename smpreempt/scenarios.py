"""Shared hypothetical scenario for the BMC example and regression tests."""
from copy import deepcopy

from smpreempt.model.riscv_model import (
    State, P, Insn, Region, PMP_NAPOT, PMP_R, PMP_W, PMP_X, napot_encode,
)


def demo_machine() -> tuple[State, P, list[Insn], list[Region]]:
    """A toy SM that temporarily disables EPM protection before zeroing it."""
    protected = [Region("EPM", 0x8000, 0x8100)]
    s = State()
    s.E.pc = 0x4000
    s.E.priv = "M"
    s.M.store(0x8000, 8, 0x1122334455667788)
    s.M.store(0x8008, 8, 0x8877665544332211)
    deny = (PMP_NAPOT << 3)                         # entry 0: deny RWX
    allow = (PMP_NAPOT << 3) | PMP_R | PMP_W | PMP_X  # entry 1: permit RWX
    s.P.cfg[0] = deny
    s.P.addr[0] = napot_encode(0x8000, 0x100)
    s.P.cfg[1] = allow
    s.P.addr[1] = napot_encode(0x0000, 0x10000)
    safe_pmp = deepcopy(s.P)
    s.E.put(5, allow << 8)          # t0: disable entry0; entry1 remains allow
    s.E.put(6, deny | allow << 8)   # t1: restore entry0 deny
    s.E.put(10, 0x8000)            # a0: EPM base
    program = [
        Insn("CSRW", rs1=5, csr="pmpcfg0"),
        Insn("SD", rs1=10, rs2=0, imm=0),
        Insn("SD", rs1=10, rs2=0, imm=8),
        Insn("CSRW", rs1=6, csr="pmpcfg0"),
    ]
    return s, safe_pmp, program, protected
