"""Function-scoped machine instruction inventory; no symbolic execution."""
from dataclasses import asdict

from smpreempt.frontend.elf import signed
from smpreempt.model.riscv_memory_operations import csr_name


def _add(pc, offset):
    return hex((pc + offset) % (1 << 64))


def _csr_effect(word):
    f3, rd, source = (word >> 12) & 7, (word >> 7) & 31, (word >> 15) & 31
    names = {1:'CSRRW', 2:'CSRRS', 3:'CSRRC', 5:'CSRRWI', 6:'CSRRSI', 7:'CSRRCI'}
    if f3 not in names:
        return None
    csr = csr_name(word >> 20)
    op = names[f3]
    read = rd != 0 if f3 in (1, 5) else True
    write = f3 in (1, 5) or source != 0
    if csr.startswith('pmpaddr'):
        category = 'pmp.address'
    elif csr.startswith('pmpcfg'):
        category = 'pmp.config'
    elif csr in ('mseccfg', 'mseccfgh'):
        category = 'pmp.security'
    else:
        category = 'csr.other'
    return dict(opcode=op, category=category, operands=dict(rd=rd, csr=csr,
        **({'zimm':source} if f3 >= 5 else {'rs1':source})),
        csr_read=read, csr_write=write,
        semantics='encoded CSR access; availability, privilege, WARL and lock behavior are not checked')


def _compressed_flow(half, pc):
    quadrant, f3 = half & 3, (half >> 13) & 7
    if quadrant == 1 and f3 == 5:
        imm = (((half >> 12) & 1) << 11 | ((half >> 11) & 1) << 4 |
               ((half >> 9) & 3) << 8 | ((half >> 8) & 1) << 10 |
               ((half >> 7) & 1) << 6 | ((half >> 6) & 1) << 7 |
               ((half >> 3) & 7) << 1 | ((half >> 2) & 1) << 5)
        return dict(kind='direct_jump', successors=[_add(pc, signed(imm, 12))])
    if quadrant == 1 and f3 in (6, 7):
        imm = (((half >> 12) & 1) << 8 | ((half >> 10) & 3) << 3 |
               ((half >> 5) & 3) << 6 | ((half >> 3) & 3) << 1 |
               ((half >> 2) & 1) << 5)
        return dict(kind='conditional_branch', successors=[_add(pc, 2), _add(pc, signed(imm, 9))])
    if quadrant == 2 and f3 == 4:
        rs1, rs2, high = (half >> 7) & 31, (half >> 2) & 31, (half >> 12) & 1
        if rs2 == 0 and rs1:
            return dict(kind='indirect_jump_with_link' if high else 'indirect_jump_or_return',
                        successors=[], target_register=rs1,
                        link_value=_add(pc, 2) if high else None)
        if high and not rs1 and not rs2:
            return dict(kind='trap_or_system', successors=[])
    return dict(kind='fallthrough', successors=[_add(pc, 2)])


def _flow(raw, pc):
    if len(raw) == 2:
        return _compressed_flow(int.from_bytes(raw, 'little'), pc)
    if len(raw) != 4:
        return dict(kind='unknown', successors=[])
    word = int.from_bytes(raw, 'little')
    op, rd, f3 = word & 127, (word >> 7) & 31, (word >> 12) & 7
    if op == 0x63:
        imm = (((word >> 31) & 1) << 12 | ((word >> 7) & 1) << 11 |
               ((word >> 25) & 63) << 5 | ((word >> 8) & 15) << 1)
        return dict(kind='conditional_branch', successors=[_add(pc, 4), _add(pc, signed(imm, 13))])
    if op == 0x6f:
        imm = (((word >> 31) & 1) << 20 | ((word >> 12) & 255) << 12 |
               ((word >> 20) & 1) << 11 | ((word >> 21) & 1023) << 1)
        return dict(kind='direct_jump_with_link' if rd else 'direct_jump', successors=[_add(pc, signed(imm, 21))],
                    link_register=rd, link_value=_add(pc, 4) if rd else None)
    if op == 0x67 and f3 == 0:
        return dict(kind='indirect_jump_with_link' if rd else 'indirect_jump_or_return', successors=[],
                    target_register=(word >> 15) & 31, offset=signed(word >> 20, 12),
                    link_register=rd, link_value=_add(pc, 4) if rd else None)
    if op == 0x73 and f3 == 0 and (word & 0xfe007fff) != 0x12000073:
        return dict(kind='trap_or_system', successors=[])
    if op not in (0x03, 0x07, 0x0f, 0x13, 0x17, 0x1b, 0x23, 0x27, 0x2f,
                  0x33, 0x37, 0x3b, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57, 0x73):
        return dict(kind='unknown', successors=[])
    return dict(kind='fallthrough', successors=[_add(pc, 4)])


def inspect_function(image, symbol, disassembler):
    if not symbol.function or symbol.size <= 0:
        raise ValueError('selected symbol must be a function with a nonzero size')
    end = symbol.address + symbol.size
    if end > 1 << 64:
        raise ValueError('function extends beyond address space')
    pc = symbol.address
    instructions = []
    while pc < end:
        record = image.instructions.get(pc)
        if record is None:
            raise ValueError(f'function has no executable instruction bytes at {hex(pc)}')
        raw = record.raw[:end-pc]
        size, text = disassembler.decode(raw, pc)
        valid = bool(size and size == len(raw))
        effect = None
        if valid and len(raw) == 4:
            word = int.from_bytes(raw, 'little')
            if word & 127 == 0x73:
                effect = _csr_effect(word)
                if (word & 0xfe007fff) == 0x12000073:
                    effect = dict(opcode='SFENCE.VMA', category='translation.sync',
                                  operands=dict(rs1=(word >> 15) & 31, rs2=(word >> 20) & 31))
        flow = _flow(raw, pc) if valid else dict(kind='unknown', successors=[])
        instructions.append(dict(pc=hex(pc), size=len(raw), bytes=raw.hex(),
            disassembly=text if valid else None,
            classification=effect or dict(category='other' if valid else 'unknown',
                                           opcode=None, operands=None),
            control_flow=flow,
            existing_model_instruction=asdict(record.decoded) if record.decoded else None,
            execution_model_status='partial_model_instruction_available' if record.decoded else 'unsupported_by_existing_execution_model',
            unsupported=None if valid else 'LLVM could not decode exactly this instruction boundary'))
        pc += len(raw)
    return dict(schema='smpreempt.elf-pmp-inventory.v1',
        input=dict(path=image.path, sha256=image.sha256, elf_entry=hex(image.entry), flags=image.flags),
        function=dict(name=symbol.name, address=hex(symbol.address), size=symbol.size, end=hex(end)),
        decoder=dict(backend='LLVM MC disassembler C API', library=disassembler.library,
            target='riscv64-unknown-elf', features=disassembler.features,
            structured_operands='PMP/CSR and selected control flow fields decoded from instruction bits; LLVM C API returns display text'),
        instructions=instructions,
        limits=['Function symbol range is a static byte range, not a reachability proof.',
                'Normal control-flow candidates omit traps and asynchronous interrupts; indirect targets are unresolved.',
                'LLVM display text is not parsed; structured opcode/operands are provided only for supported CSR and SFENCE encodings.',
                'Instruction decode, PMP profile legality, and symbolic state transitions are distinct; no safety or attack result is computed.'])
