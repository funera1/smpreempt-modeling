"""Guarded decoded-instruction transitions; concrete privilege/PMP environment.

Only pc, GPRs, memory and history are symbolic. CSR/V/P/c/slot are unchanged
parameters in this subset. No architectural trap or instruction fetch semantics.
"""
from dataclasses import dataclass, replace

import z3

from smpreempt.symbolic_pmp import SymbolicPMP
from smpreempt.riscv_model import Insn, Machine, Unsupported, _effective_privilege


def load64(memory, address):
    return z3.Concat(*[z3.Select(memory, address + i) for i in reversed(range(8))])


def store64(memory, address, value):
    for i in range(8):
        memory = z3.Store(memory, address + i, z3.Extract(i * 8 + 7, i * 8, value))
    return memory


@dataclass(frozen=True)
class InstructionState:
    pc: z3.BitVecRef
    registers: tuple
    memory: z3.ArrayRef
    history: z3.ArrayRef

    @classmethod
    def fresh(cls, name):
        return cls(z3.BitVec(f"{name}_pc", 64),
                   (z3.BitVecVal(0, 64),) + tuple(z3.BitVec(f"{name}_x{i}", 64) for i in range(1, 32)),
                   z3.Array(f"{name}_M", z3.BitVecSort(64), z3.BitVecSort(8)),
                   z3.Array(f"{name}_A", z3.BitVecSort(64), z3.BoolSort()))

    @classmethod
    def from_machine(cls, machine):
        memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
        history = z3.K(z3.BitVecSort(64), z3.BoolVal(False))
        for address, value in machine.S.M.data.items():
            memory = z3.Store(memory, z3.BitVecVal(address, 64), z3.BitVecVal(value, 8))
        for address in machine.accessed:
            history = z3.Store(history, z3.BitVecVal(address, 64), z3.BoolVal(True))
        return cls(z3.BitVecVal(machine.S.E.pc, 64),
                   tuple(z3.BitVecVal(machine.S.E.get(i), 64) for i in range(32)), memory, history)

    def same_as(self, other):
        return z3.And(self.pc == other.pc, self.memory == other.memory,
                      self.history == other.history,
                      *[a == b for a, b in zip(self.registers, other.registers)])


@dataclass(frozen=True)
class InstructionTransition:
    success: z3.BoolRef
    access_fault: z3.BoolRef
    misaligned: z3.BoolRef
    next_state: InstructionState

    def relation(self, after):
        # next_state is meaningful only on success. Faults do not produce a
        # fabricated normal successor or architectural trap state.
        return z3.And(self.success, after.same_as(self.next_state))


def instruction_transition(before: InstructionState, insn: Insn,
                           environment: Machine, *, access_check=None) -> InstructionTransition:
    """Define one instruction with arbitrary symbolic operands/memory/history.

    environment supplies only fixed c, privilege, CSRs, V and P; its GPRs, pc,
    M and accessed are ignored. Unsupported instructions fail explicitly.
    """
    if environment.c not in ("H", "C", "SM"):
        raise ValueError("normal instruction requires H/C/SM")
    if environment.c == "H" and environment.S.E.priv not in ("U", "S"):
        raise ValueError("Host cannot execute in M-mode")
    if any(not 0 <= index < 32 for index in (insn.rd, insn.rs1, insn.rs2)):
        raise ValueError("register index must be 0..31")
    op = insn.op.upper()
    registers = list(before.registers)
    registers[0] = z3.BitVecVal(0, 64)
    v1, v2 = registers[insn.rs1], registers[insn.rs2]
    pc = before.pc + 4
    memory, history = before.memory, before.history
    success, fault, misaligned = z3.BoolVal(True), z3.BoolVal(False), z3.BoolVal(False)

    def put(value):
        if insn.rd:
            registers[insn.rd] = value

    if op == "ADD":
        put(v1 + v2)
    elif op == "ADDI":
        put(v1 + insn.imm)
    elif op == "XOR":
        put(v1 ^ v2)
    elif op == "AND":
        put(v1 & v2)
    elif op in ("LD", "SD"):
        kind = "R" if op == "LD" else "W"
        address = v1 + insn.imm
        aligned = address & 7 == 0
        if access_check is None:
            priv = _effective_privilege(environment.S.E, kind)
            if priv != "M" and environment.S.V.satp != 0:
                raise Unsupported("symbolic instruction transitions support Bare only")
            allowed = SymbolicPMP.concrete(environment.S.P).allow(address, 8, kind, priv)
        else:
            # Full-machine BMC supplies the CURRENT symbolic PMP here.
            allowed = access_check(address, kind)
        success = z3.And(aligned, allowed)
        fault = z3.And(aligned, z3.Not(allowed))
        misaligned = z3.Not(aligned)
        if op == "LD":
            put(load64(memory, address))
        else:
            memory = store64(memory, address, v2)
        if environment.c in ("C", "SM"):
            for offset in range(8):
                history = z3.Store(history, address + offset, z3.BoolVal(True))
    elif op == "BEQ":
        pc = z3.If(v1 == v2, before.pc + insn.imm, pc)
    elif op == "JAL":
        put(pc)
        pc = before.pc + insn.imm
    elif op == "JALR":
        put(pc)
        pc = (v1 + insn.imm) & z3.BitVecVal((1 << 64) - 2, 64)
    else:
        raise Unsupported(f"symbolic instruction not implemented: {op}")
    after = replace(before, pc=pc, registers=tuple(registers), memory=memory, history=history)
    return InstructionTransition(success, fault, misaligned, after)
