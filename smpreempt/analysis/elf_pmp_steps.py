"""Bounded symbolic execution of a small RV64 PMP-related instruction subset.

This is a single-hart M-mode research profile, not a complete ISA or WARL model.
Unknown instructions, paths, and configuration writes are kept as unknown.
"""
from collections import deque
from dataclasses import dataclass, field, replace

import z3

from smpreempt.frontend.elf import signed
from smpreempt.extraction.elf_pmp_inventory import _csr_effect
from smpreempt.model.riscv_model import PMP_ADDR_BITS
from smpreempt.model.symbolic_pmp import SymbolicPMP


@dataclass(frozen=True)
class State:
    pc: int
    gpr: tuple
    pmp: SymbolicPMP
    memory: object
    code_ranges: tuple
    path: object
    auxiliary_csrs: dict = field(default_factory=dict)
    trace: tuple = ()
    steps: int = 0
    status: str = 'running'
    reason: str = None


def _expr(x):
    return z3.simplify(x).sexpr()


def _check(condition, timeout_ms):
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(condition)
    return solver.check()


def _csr_read(pmp, name):
    if name in ('pmpcfg0', 'pmpcfg2'):
        start = 0 if name == 'pmpcfg0' else 8
        if start+8 <= len(pmp.cfg):
            return z3.Concat(*reversed(pmp.cfg[start:start+8]))
    if name.startswith('pmpaddr'):
        index = int(name[7:])
        if 0 <= index < len(pmp.addr):
            return pmp.addr[index]
    return None


def _initial_constraints(pmp):
    checks = []
    for cfg, addr in zip(pmp.cfg, pmp.addr):
        checks.extend((cfg & 0x60 == 0, z3.Or(cfg & 2 == 0, cfg & 1 != 0),
                       z3.LShR(addr, PMP_ADDR_BITS) == 0))
    return z3.And(*checks)


def _event(state, record, opcode, **details):
    return dict(pc=hex(state.pc), bytes=record.raw.hex(), opcode=opcode, **details)


def _next(state, pc, event, *, registers=None, pmp=None, memory=None, auxiliary_csrs=None,
          path=None, status='running', reason=None):
    return replace(state, pc=pc % (1 << 64), gpr=state.gpr if registers is None else tuple(registers),
        pmp=state.pmp if pmp is None else pmp, memory=state.memory if memory is None else memory,
        auxiliary_csrs=state.auxiliary_csrs if auxiliary_csrs is None else auxiliary_csrs,
        path=state.path if path is None else path,
        trace=state.trace+(event,), steps=state.steps+1, status=status, reason=reason)


def _stop(state, record, reason):
    return _next(state, state.pc, _event(state, record, 'unknown', reason=reason),
                 status='unknown', reason=reason)


def _csr_step(state, record, word):
    effect = _csr_effect(word)
    if effect is None:
        return [_stop(state, record, 'unsupported CSR instruction')]
    operand = effect['operands']
    name, rd = operand['csr'], operand['rd']
    auxiliary = name in state.auxiliary_csrs
    old = state.auxiliary_csrs[name] if auxiliary else _csr_read(state.pmp, name)
    if old is None:
        return [_stop(state, record, 'CSR is outside the supported base-PMP profile: '+name)]
    source = z3.BitVecVal(operand['zimm'], 64) if 'zimm' in operand else state.gpr[operand['rs1']]
    op = effect['opcode']
    wanted = source if op in ('CSRRW', 'CSRRWI') else old | source if op in ('CSRRS', 'CSRRSI') else old & ~source
    regs = list(state.gpr)
    if rd:
        regs[rd] = old
    next_pmp, next_aux, valid = state.pmp, dict(state.auxiliary_csrs), z3.BoolVal(True)
    if effect['csr_write']:
        if auxiliary:
            # Explicit opt-in profile: mtvec direct/vectored values are writable
            # and read back exactly. Other WARL cases remain unknown.
            valid = z3.Or(wanted & 3 == 0, wanted & 3 == 1)
            next_aux[name] = wanted
        else:
            next_pmp, valid = state.pmp.write(name, wanted)
        if name.startswith('pmpcfg'):
            start = 0 if name == 'pmpcfg0' else 8
            reserved = []
            for i in range(8):
                byte = z3.Extract(i*8+7, i*8, wanted)
                reserved.append(z3.Implies(state.pmp.cfg[start+i] & 0x80 == 0, byte & 0x60 == 0))
            valid = z3.And(valid, *reserved)
    after = next_aux[name] if auxiliary else _csr_read(next_pmp, name)
    event = _event(state, record, op, csr=name, operands=operand,
        csr_read=effect['csr_read'], csr_write=effect['csr_write'],
        csr_before=_expr(old), requested_value=_expr(wanted) if effect['csr_write'] else None,
        csr_after=_expr(after), register_result=_expr(old) if rd else None,
        supported_warl_condition=_expr(valid))
    candidates = [_next(state, state.pc+4, event, registers=regs, pmp=next_pmp, auxiliary_csrs=next_aux,
                        path=z3.And(state.path, valid))]
    if effect['csr_write'] and (name.startswith('pmpcfg') or auxiliary):
        reason = name+' write outside the supported WARL subset'
        candidates.append(_next(state, state.pc, _event(state, record, op, csr=name,
            reason=reason),
            path=z3.And(state.path, z3.Not(valid)), status='unknown',
            reason=reason))
    return candidates


def _memory_step(state, record, word):
    opcode, f3 = word & 127, (word >> 12) & 7
    rd, rs1, rs2 = (word >> 7) & 31, (word >> 15) & 31, (word >> 20) & 31
    loads = {0:('LB', 1, True), 1:('LH', 2, True), 2:('LW', 4, True),
             3:('LD', 8, True), 4:('LBU', 1, False), 5:('LHU', 2, False),
             6:('LWU', 4, False)}
    stores = {0:('SB', 1), 1:('SH', 2), 2:('SW', 4), 3:('SD', 8)}
    if opcode == 0x03 and f3 in loads:
        name, width, sign_extend = loads[f3]
        immediate, kind = signed(word >> 20, 12), 'R'
    elif opcode == 0x23 and f3 in stores:
        name, width = stores[f3]
        immediate = signed(((word >> 25) << 5) | ((word >> 7) & 31), 12)
        kind = 'W'
    else:
        return [_stop(state, record, 'memory instruction is not implemented')]
    address = state.gpr[rs1] + immediate
    aligned = (address & (width-1)) == 0
    no_wrap = z3.ULE(z3.ZeroExt(1, address) + width, z3.BitVecVal(1 << 64, 65))
    permitted = state.pmp.allow(address, width, kind, privilege='M')
    code_safe = z3.BoolVal(True)
    if kind == 'W':
        a = z3.ZeroExt(1, address)
        code_safe = z3.And(*[z3.Or(z3.ULE(a+width, lo), z3.UGE(a, hi))
                             for lo, hi in state.code_ranges])
    valid = z3.simplify(z3.And(aligned, no_wrap, permitted, code_safe))
    regs, memory = list(state.gpr), state.memory
    if kind == 'R':
        parts = [z3.Select(memory, address+i) for i in reversed(range(width))]
        value = parts[0] if width == 1 else z3.Concat(*parts)
        if width < 8:
            value = z3.SignExt(64-width*8, value) if sign_extend else z3.ZeroExt(64-width*8, value)
        if rd:
            regs[rd] = value
        result = _expr(value) if rd else None
    else:
        value = state.gpr[rs2]
        for index in range(width):
            memory = z3.Store(memory, address+index, z3.Extract(index*8+7, index*8, value))
        result = _expr(value)
    event = _event(state, record, name, address=_expr(address), width=width,
                   value=result, access_condition=_expr(valid))
    return [
        _next(state, state.pc+len(record.raw), event, registers=regs, memory=memory,
              path=z3.And(state.path, valid)),
        _next(state, state.pc, _event(state, record, name,
              reason='memory access may be misaligned, wrap, fail PMP, or modify executable code'),
              path=z3.And(state.path, z3.Not(valid)), status='unknown',
              reason='memory access may be misaligned, wrap, fail PMP, or modify executable code')]


def _compressed_memory_word(half):
    quadrant, f3 = half & 3, (half >> 13) & 7
    compact_base = 8 + ((half >> 7) & 7)
    compact_reg = 8 + ((half >> 2) & 7)
    if quadrant == 0 and f3 in (2, 3, 6, 7):
        is_store = f3 in (6, 7)
        is_double = f3 in (3, 7)
        imm = (((half >> 10) & 7) << 3 |
               (((half >> 5) & 3) << 6 if is_double else
                (((half >> 6) & 1) << 2 | ((half >> 5) & 1) << 6)))
        base, reg = compact_base, compact_reg
    elif quadrant == 2 and f3 in (2, 3, 6, 7):
        is_store, is_double = f3 in (6, 7), f3 in (3, 7)
        base = 2
        if is_store:
            reg = (half >> 2) & 31
            imm = (((half >> 10) & 7) << 3 | ((half >> 7) & 7) << 6) if is_double else (
                ((half >> 9) & 15) << 2 | ((half >> 7) & 3) << 6)
        else:
            reg = (half >> 7) & 31
            if not reg:
                return None
            imm = (((half >> 12) & 1) << 5 | ((half >> 5) & 3) << 3 |
                   ((half >> 2) & 7) << 6) if is_double else (
                   ((half >> 12) & 1) << 5 | ((half >> 4) & 7) << 2 | ((half >> 2) & 3) << 6)
    else:
        return None
    f3_normal = 3 if is_double else 2
    if is_store:
        return ((imm >> 5) << 25 | reg << 20 | base << 15 | f3_normal << 12 |
                (imm & 31) << 7 | 0x23)
    return imm << 20 | base << 15 | f3_normal << 12 | reg << 7 | 0x03


def _compressed_step(state, record, half):
    quadrant, f3 = half & 3, (half >> 13) & 7
    word = _compressed_memory_word(half)
    if word is not None:
        return _memory_step(state, record, word)
    if half == 1:
        return [_next(state, state.pc+2, _event(state, record, 'C.NOP'))]
    if half == 0x8082:
        return [_next(state, state.pc, _event(state, record, 'C.JR', target=_expr(state.gpr[1])),
                      status='returned', reason='return target is outside the function harness')]
    if quadrant == 2 and f3 == 4 and (half >> 2) & 31 == 0:
        rs1, link = (half >> 7) & 31, (half >> 12) & 1
        if rs1:
            target = z3.simplify(state.gpr[rs1] & z3.BitVecVal((1 << 64)-2, 64))
            if not z3.is_bv_value(target):
                return [_stop(state, record, 'symbolic compressed indirect jump target')]
            regs = list(state.gpr)
            if link:
                regs[1] = z3.BitVecVal((state.pc+2) % (1 << 64), 64)
            return [_next(state, target.as_long(), _event(state, record, 'C.JALR' if link else 'C.JR',
                          target=hex(target.as_long())), registers=regs)]
    regs = list(state.gpr)
    rd, rs2 = (half >> 7) & 31, (half >> 2) & 31
    imm = signed(((half >> 12) & 1) << 5 | ((half >> 2) & 31), 6)
    op, value = None, None
    if quadrant == 0 and f3 == 0:
        amount = (((half >> 11) & 3) << 4 | ((half >> 7) & 15) << 6 |
                  ((half >> 6) & 1) << 2 | ((half >> 5) & 1) << 3)
        if amount:
            rd = 8+((half >> 2) & 7)
            op, value = 'C.ADDI4SPN', regs[2]+amount
    elif quadrant == 1 and f3 == 0 and rd:
        op, value = 'C.ADDI', regs[rd]+imm
    elif quadrant == 1 and f3 == 1 and rd:
        op, value = 'C.ADDIW', z3.SignExt(32, z3.Extract(31, 0, regs[rd]+imm))
    elif quadrant == 1 and f3 == 2 and rd:
        op, value = 'C.LI', z3.BitVecVal(imm % (1 << 64), 64)
    elif quadrant == 1 and f3 == 3 and rd == 2:
        amount = (((half >> 12) & 1) << 9 | ((half >> 6) & 1) << 4 |
                  ((half >> 5) & 1) << 6 | ((half >> 3) & 3) << 7 |
                  ((half >> 2) & 1) << 5)
        if amount:
            op, value = 'C.ADDI16SP', regs[2]+signed(amount, 10)
    elif quadrant == 1 and f3 == 3 and rd not in (0, 2) and imm:
        op, value = 'C.LUI', z3.BitVecVal((imm << 12) % (1 << 64), 64)
    elif quadrant == 1 and f3 == 4 and ((half >> 10) & 3) == 2:
        rd = 8+((half >> 7) & 7)
        op, value = 'C.ANDI', regs[rd] & imm
    elif quadrant == 2 and f3 == 0 and rd:
        shift = ((half >> 12) & 1) << 5 | ((half >> 2) & 31)
        op, value = 'C.SLLI', regs[rd] << shift
    elif quadrant == 2 and f3 == 4 and rd and rs2:
        op = 'C.ADD' if (half >> 12) & 1 else 'C.MV'
        value = regs[rd]+regs[rs2] if op == 'C.ADD' else regs[rs2]
    elif quadrant == 1 and f3 == 5:
        offset = (((half >> 12) & 1) << 11 | ((half >> 11) & 1) << 4 |
                  ((half >> 9) & 3) << 8 | ((half >> 8) & 1) << 10 |
                  ((half >> 7) & 1) << 6 | ((half >> 6) & 1) << 7 |
                  ((half >> 3) & 7) << 1 | ((half >> 2) & 1) << 5)
        target = (state.pc+signed(offset, 12)) % (1 << 64)
        return [_next(state, target, _event(state, record, 'C.J', target=hex(target)))]
    elif quadrant == 1 and f3 in (6, 7):
        offset = (((half >> 12) & 1) << 8 | ((half >> 10) & 3) << 3 |
                  ((half >> 5) & 3) << 6 | ((half >> 3) & 3) << 1 |
                  ((half >> 2) & 1) << 5)
        offset = signed(offset, 9)
        reg = 8+((half >> 7) & 7)
        condition = regs[reg] == 0 if f3 == 6 else regs[reg] != 0
        name = 'C.BEQZ' if f3 == 6 else 'C.BNEZ'
        return [_next(state, target, _event(state, record, name, taken=taken,
                     target=hex(target % (1 << 64))), path=z3.And(state.path, guard))
                for target, guard, taken in ((state.pc+offset, condition, True),
                                             (state.pc+2, z3.Not(condition), False))]
    if value is None:
        return [_stop(state, record, 'compressed instruction is not implemented')]
    regs[rd] = value
    return [_next(state, state.pc+2, _event(state, record, op, rd=rd, result=_expr(value)), registers=regs)]


def _step(state, record):
    raw = record.raw
    if len(raw) == 2:
        return _compressed_step(state, record, int.from_bytes(raw, 'little'))
    if len(raw) != 4:
        return [_stop(state, record, 'instruction length is not implemented')]
    word = int.from_bytes(raw, 'little')
    opcode, rd, f3 = word & 127, (word >> 7) & 31, (word >> 12) & 7
    rs1, rs2, f7 = (word >> 15) & 31, (word >> 20) & 31, word >> 25
    regs = list(state.gpr)
    if opcode == 0x73 and f3 in (1, 2, 3, 5, 6, 7):
        return _csr_step(state, record, word)
    if opcode in (0x03, 0x23):
        return _memory_step(state, record, word)
    if (word & 0xfe007fff) == 0x12000073:
        event = _event(state, record, 'SFENCE.VMA', rs1=rs1, rs2=rs2,
                       synchronization='recorded only; cached permission semantics not modeled')
        return [_next(state, state.pc+4, event)]
    if opcode == 0x67 and f3 == 0 and rd == 0 and rs1 == 1 and word >> 20 == 0:
        return [_next(state, state.pc, _event(state, record, 'JALR', target=_expr(regs[1])),
                      status='returned', reason='return target is outside the function harness')]
    if opcode == 0x67 and f3 == 0:
        target = z3.simplify((regs[rs1]+signed(word >> 20, 12)) & z3.BitVecVal((1 << 64)-2, 64))
        if not z3.is_bv_value(target):
            return [_stop(state, record, 'symbolic indirect jump target')]
        if rd:
            regs[rd] = z3.BitVecVal((state.pc+4) % (1 << 64), 64)
        return [_next(state, target.as_long(), _event(state, record, 'JALR', rd=rd,
                      target=hex(target.as_long())), registers=regs)]
    if opcode == 0x63 and f3 in (0, 1, 4, 5, 6, 7):
        imm = (((word >> 31) & 1) << 12 | ((word >> 7) & 1) << 11 |
               ((word >> 25) & 63) << 5 | ((word >> 8) & 15) << 1)
        imm = signed(imm, 13)
        a, b = regs[rs1], regs[rs2]
        cond = {0: a == b, 1: a != b, 4: a < b, 5: a >= b,
                6: z3.ULT(a, b), 7: z3.UGE(a, b)}[f3]
        names = {0:'BEQ', 1:'BNE', 4:'BLT', 5:'BGE', 6:'BLTU', 7:'BGEU'}
        return [_next(state, target, _event(state, record, names[f3], taken=taken,
                                           target=hex(target % (1 << 64))),
                      path=z3.And(state.path, guard))
                for target, guard, taken in ((state.pc+imm, cond, True), (state.pc+4, z3.Not(cond), False))]
    if opcode == 0x6f:
        imm = (((word >> 31) & 1) << 20 | ((word >> 12) & 255) << 12 |
               ((word >> 20) & 1) << 11 | ((word >> 21) & 1023) << 1)
        if rd:
            regs[rd] = z3.BitVecVal((state.pc+4) % (1 << 64), 64)
        target = (state.pc + signed(imm, 21)) % (1 << 64)
        return [_next(state, target, _event(state, record, 'JAL', rd=rd, target=hex(target)), registers=regs)]
    value = None
    op = None
    imm = signed(word >> 20, 12)
    if opcode == 0x13 and f3 in (0, 4, 6, 7):
        op = {0:'ADDI', 4:'XORI', 6:'ORI', 7:'ANDI'}[f3]
        value = {0:lambda: regs[rs1]+imm, 4:lambda: regs[rs1]^imm,
                 6:lambda: regs[rs1]|imm, 7:lambda: regs[rs1]&imm}[f3]()
    elif opcode == 0x13 and f3 in (2, 3):
        op = 'SLTI' if f3 == 2 else 'SLTIU'
        rhs = z3.BitVecVal(imm % (1 << 64), 64)
        condition = regs[rs1] < rhs if f3 == 2 else z3.ULT(regs[rs1], rhs)
        value = z3.If(condition, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    elif opcode == 0x13 and f3 in (1, 5):
        funct6, shift = word >> 26, (word >> 20) & 63
        if f3 == 1 and funct6 == 0:
            op, value = 'SLLI', regs[rs1] << shift
        elif f3 == 5 and funct6 == 0:
            op, value = 'SRLI', z3.LShR(regs[rs1], shift)
        elif f3 == 5 and funct6 == 0x10:
            op, value = 'SRAI', regs[rs1] >> shift
    elif opcode == 0x33 and f7 in (0, 0x20):
        ops = {(0, 0):('ADD', lambda: regs[rs1]+regs[rs2]),
               (0, 0x20):('SUB', lambda: regs[rs1]-regs[rs2]),
               (1, 0):('SLL', lambda: regs[rs1] << (regs[rs2] & 63)),
               (2, 0):('SLT', lambda: z3.If(regs[rs1] < regs[rs2], z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))),
               (3, 0):('SLTU', lambda: z3.If(z3.ULT(regs[rs1], regs[rs2]), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))),
               (4, 0):('XOR', lambda: regs[rs1]^regs[rs2]),
               (5, 0):('SRL', lambda: z3.LShR(regs[rs1], regs[rs2] & 63)),
               (5, 0x20):('SRA', lambda: regs[rs1] >> (regs[rs2] & 63)),
               (6, 0):('OR', lambda: regs[rs1]|regs[rs2]),
               (7, 0):('AND', lambda: regs[rs1]&regs[rs2])}
        if (f3, f7) in ops:
            op, calculate = ops[(f3, f7)]
            value = calculate()
    elif opcode == 0x1b and f3 == 0:
        op = 'ADDIW'
        value = z3.SignExt(32, z3.Extract(31, 0, regs[rs1]+imm))
    elif opcode == 0x3b and f3 in (1, 5) and f7 in (0, 0x20):
        shift = z3.Extract(4, 0, regs[rs2])
        operand = z3.Extract(31, 0, regs[rs1])
        shift32 = z3.ZeroExt(27, shift)
        if f3 == 1 and f7 == 0:
            op, value = 'SLLW', z3.SignExt(32, operand << shift32)
        elif f3 == 5 and f7 == 0:
            op, value = 'SRLW', z3.SignExt(32, z3.LShR(operand, shift32))
        elif f3 == 5 and f7 == 0x20:
            op, value = 'SRAW', z3.SignExt(32, operand >> shift32)
    elif opcode in (0x37, 0x17):
        op = 'LUI' if opcode == 0x37 else 'AUIPC'
        upper = signed(word & 0xfffff000, 32)
        value = z3.BitVecVal((upper + (state.pc if opcode == 0x17 else 0)) % (1 << 64), 64)
    if value is None:
        return [_stop(state, record, 'instruction semantics not implemented')]
    if rd:
        regs[rd] = value
    return [_next(state, state.pc+4, _event(state, record, op, rd=rd,
                  result=_expr(value) if rd else None), registers=regs)]


def execute_function(image, symbol, *, max_steps=100, max_states=1000,
                     timeout_ms=5000, registers=None, memory_bytes=None, pmp=None, disassembler=None,
                     assume_mtvec_writable=False, boundary_observer=None):
    if not symbol.function or symbol.size <= 0:
        raise ValueError('selected symbol must be a function with a nonzero size')
    if max_steps < 0 or max_states < 1 or timeout_ms < 1:
        raise ValueError('invalid execution bounds')
    registers = {} if registers is None else registers
    if any(type(i) is not int or not 1 <= i < 32 or type(v) is not int or not 0 <= v < 1 << 64
           for i, v in registers.items()):
        raise ValueError('register assignments require x1..x31 and unsigned 64-bit values')
    gpr = (z3.BitVecVal(0, 64),) + tuple(z3.BitVecVal(registers[i], 64) if i in registers
             else z3.BitVec(f'initial_x{i}', 64) for i in range(1, 32))
    pmp = SymbolicPMP.fresh('initial', count=16) if pmp is None else pmp
    if len(pmp.cfg) != 16 or len(pmp.addr) != 16:
        raise ValueError('execution requires a 16-entry PMP profile')
    initial_path = _initial_constraints(pmp)
    auxiliary_csrs = {}
    if assume_mtvec_writable:
        auxiliary_csrs['mtvec'] = z3.BitVec('initial_mtvec', 64)
        mode = auxiliary_csrs['mtvec'] & 3
        initial_path = z3.And(initial_path, z3.Or(mode == 0, mode == 1))
    if _check(initial_path, timeout_ms) == z3.unsat:
        raise ValueError('initial PMP state violates the selected profile')
    memory = z3.Array('initial_memory', z3.BitVecSort(64), z3.BitVecSort(8))
    memory_bytes = {} if memory_bytes is None else memory_bytes
    if any(type(a) is not int or not 0 <= a < 1 << 64 or type(v) is not int or not 0 <= v < 256
           for a, v in memory_bytes.items()):
        raise ValueError('initial memory assignments require 64-bit addresses and byte values')
    for address, value in sorted(memory_bytes.items()):
        memory = z3.Store(memory, z3.BitVecVal(address, 64), z3.BitVecVal(value, 8))
    code_ranges = tuple((s.address, s.address+s.memory_size) for s in image.segments if s.flags & 1)
    start = State(symbol.address, gpr, pmp, memory, code_ranges, initial_path,
                  auxiliary_csrs=auxiliary_csrs)
    queue, terminal, explored = deque([start]), [], 0
    end = symbol.address + symbol.size
    while queue and explored < max_states:
        state = queue.popleft()
        feasible = _check(state.path, timeout_ms)
        if feasible == z3.unsat:
            continue
        if feasible == z3.unknown:
            terminal.append(replace(state, status='unknown', reason='solver could not decide path feasibility'))
            continue
        if state.status != 'running':
            terminal.append(state)
            continue
        if not symbol.address <= state.pc < end:
            terminal.append(replace(state, status='unknown', reason='control flow left selected function'))
            continue
        record = image.instructions.get(state.pc)
        if record is None or state.pc+len(record.raw) > end:
            terminal.append(replace(state, status='unknown', reason='no complete instruction at PC'))
            continue
        if boundary_observer is not None:
            boundary_observer(state, record)
        if state.steps >= max_steps:
            terminal.append(replace(state, status='bound_reached', reason='instruction step limit'))
            continue
        explored += 1
        if disassembler is not None:
            length, _ = disassembler.decode(record.raw, state.pc)
            if length != len(record.raw):
                terminal.append(_stop(state, record, 'LLVM could not decode this instruction'))
                continue
        queue.extend(_step(state, record))
    terminal.extend(replace(s, status='unknown', reason='global state expansion limit') for s in queue)
    return dict(schema='smpreempt.elf-pmp-steps.v1',
        input=dict(path=image.path, sha256=image.sha256),
        function=dict(name=symbol.name, address=hex(symbol.address), size=symbol.size),
        bounds=dict(max_steps=max_steps, max_states=max_states, solver_timeout_ms=timeout_ms),
        decoder=None if disassembler is None else dict(backend='LLVM MC disassembler C API',
            library=disassembler.library, features=disassembler.features),
        initial_register_assignments={f'x{i}':hex(v) for i,v in registers.items()},
        initial_memory_bytes={hex(a):hex(v) for a,v in sorted(memory_bytes.items())},
        auxiliary_csr_profile=dict(mtvec_writable_direct_or_vectored=assume_mtvec_writable),
        explored_instruction_states=explored,
        paths=[dict(status=s.status, reason=s.reason, pc=hex(s.pc), steps=s.steps,
                    path_condition=_expr(s.path), trace=s.trace) for s in terminal],
        assumptions=['RV64, one hart, M-mode; base PMP only, no Smepmp.',
            f'16 PMP entries, illustrative {PMP_ADDR_BITS}-bit pmpaddr and four-byte grain.',
            'Initial PMP values have zero reserved bits, legal R/W encodings and bounded addresses.',
            'PMP CSR write results outside the implemented WARL subset are reported as unknown.',
            'Memory starts as an arbitrary byte array; ordinary RAM, identity mapping, little endian and MPRV=0 are assumed.',
            'Naturally aligned byte/half/word/doubleword accesses check PMP; faults and unaligned access are unknown.',
            'Stores that may change an executable segment are unknown; instruction fetch uses fixed ELF bytes.',
            'Symbolic indirect targets, interprocedural calls, trap handling, interrupts, MMIO, PMA and cache semantics are not modeled.',
            'SFENCE.VMA is recorded but has no modeled cache effect.',
            'No Host transition, PMP access check, attack predicate, unbounded proof or Sail equivalence is computed.'])
