"""Implementation-independent RISC-V memory-operation transition vocabulary.

This module exports declarative relations and normalizes already decoded
instructions. It does not execute a complete ISA, infer secrets, or decide
attacks. Profile-dependent functions are explicitly unresolved obligations.
"""
from copy import deepcopy
import re

SPEC = 'https://docs.riscv.org/reference/isa/v20260120/'
SOURCES = {
    'machine': SPEC+'priv/machine.html',
    'supervisor': 'https://docs.riscv.org/reference/isa/priv/supervisor.html',
    'zicsr': SPEC+'unpriv/zicsr.html',
    'smepmp': SPEC+'priv/smepmp.html',
    'svpbmt': 'https://docs.riscv.org/reference/isa/v20240411/priv/svpbmt.html',
    'hypervisor': 'https://docs.riscv.org/reference/isa/priv/hypervisor',
    'cmo': 'https://docs.riscv.org/reference/isa/unpriv/cmo.html',
    'rvwmo': 'https://docs.riscv.org/reference/isa/unpriv/rvwmo.html',
}
STATE = {
    'pc': 'instruction position; source provenance is attached separately',
    'registers': 'GPR/FP/vector values as required by the selected profile',
    'memory': 'physical bytes, plus visibility/atomicity events when required',
    'csr': 'architectural CSR values, including aliases',
    'privilege': 'current privilege and virtualization state',
    'translation_views': 'per-hart cached/implicit address-translation state',
    'pmp_views': 'per-hart permitted cached PMP observations, with provenance',
    'ordering': 'explicit/implicit memory and instruction-fetch ordering',
    'reservation': 'LR/SC reservation state',
    'platform': 'PMA/MMIO/cache/device configuration supplied by a platform model',
}


def operation(id, category, encoding, requires, parameters, relation, changes, preserves, notes, sources):
    return dict(id=id, category=category, encodings=encoding, requires=requires,
                parameters=parameters, normal_relation=relation,
                may_change=changes, preserves=preserves, notes=notes,
                nonnormal_outcomes=['illegal/virtual instruction if unavailable or disallowed',
                                    'operation-specific access/page/misalignment faults where applicable'],
                semantics_status='declarative_template; profile-specific functions need an execution backend',
                sources=[SOURCES[s] for s in sources])


CATALOG = [
    operation('memory.load', 'contents', ['integer/FP/vector/guest load families'], ['selected ISA memory instructions'],
        ['address', 'width', 'destination', 'execution context'],
        ['(pa, permissions, attributes) := TranslateAndCheck(S, address, read)',
         'destination := LoadValue(S.memory, pa, width)', 'apply allowed translation/PTE-A-D side effects'],
        ['registers', 'translation_views', 'pmp_views', 'memory', 'ordering'], ['PMP configuration'],
        ['Load does not assign a confidentiality label.', 'Implicit page-table A/D updates are separate hardware effects, not user stores.'], ['machine', 'supervisor']),
    operation('memory.store', 'contents', ['SB/SH/SW/SD', 'FP/vector/guest store families'], ['selected ISA memory instructions'],
        ['address', 'width', 'value', 'execution context'],
        ['(pa, permissions, attributes) := TranslateAndCheck(S, address, write)',
         'memory := StoreEffect(S.memory, pa, width, value, profile)', 'update visibility/reservations as required'],
        ['memory', 'translation_views', 'pmp_views', 'reservation', 'ordering'], ['PMP configuration'],
        ['memset/scrub/initialization are sequences of these operations, not special ownership instructions.',
         'The profile must account for partial visible effects on faulting/decomposed operations.'], ['machine', 'supervisor']),
    operation('memory.amo', 'contents', ['AMO*.W/D and optional widths/CAS'], ['A or selected atomic extension'],
        ['address', 'width', 'operator', 'source', 'destination', 'aq', 'rl'],
        ['old := AtomicReadModifyWrite(memory, address, operator, source, profile)', 'destination := ArchitecturalExtend(old)',
         'ordering := ApplyAcquireRelease(ordering, aq, rl)'],
        ['memory', 'registers', 'ordering', 'reservation', 'translation_views', 'pmp_views'], ['PMP configuration'],
        ['AMO checks and atomicity depend on width, alignment, PMA and extension support.'], ['machine', 'rvwmo']),
    operation('memory.lrsc', 'contents', ['LR.*', 'SC.*'], ['A or selected LR/SC extension'],
        ['address', 'width', 'source/destination', 'reservation', 'aq', 'rl'],
        ['LR: load value and establish a profile-defined reservation',
         'SC: choose permitted success/failure; write only on success; return result and update reservation'],
        ['memory', 'registers', 'reservation', 'ordering', 'translation_views', 'pmp_views'], ['PMP configuration'],
        ['A store-conditional is not an unconditional store.'], ['rvwmo', 'machine']),
    operation('csr.read', 'control', ['CSR read forms after Zicsr normalization'], ['Zicsr', 'implemented/accessible CSR'],
        ['csr', 'destination', 'read_requested'], ['destination := ReadCSR(S, csr); apply any specified read effects'],
        ['registers', 'profile-defined read side effects'], ['ordinary memory absent specified side effects'],
        ['Use this operation when CSRRS/CSRRC suppress writes by using x0/zimm=0.'], ['zicsr']),
    operation('pmp.address.write', 'protection', ['CSR writes to pmpaddrN'], ['Zicsr', 'PMP', 'M-mode'],
        ['entry', 'requested_value', 'XLEN', 'PMP grain/PA width', 'lock/Smepmp state'],
        ['pmpaddrN\' := PMPAddressWritePolicy(S, N, requested_value, profile)',
         'pmp_views\' := AllowedViewEvolutionAfterPMPWrite(S.pmp_views, S, profile)'],
        ['csr', 'pmp_views'], ['memory'],
        ['Base PMP: own L or a locked next TOR entry can suppress the write.',
         'An address register can also be the lower bound of the following TOR entry.',
         'Do not assume the new requested value is always accepted or that cached permissions are synchronized.'], ['machine', 'smepmp']),
    operation('pmp.config.write', 'protection', ['CSR writes to pmpcfgN'], ['Zicsr', 'PMP', 'M-mode'],
        ['packed configuration value', 'XLEN', 'implemented entries', 'WARL/lock/Smepmp state'],
        ['csr\' := PMPConfigWritePolicy(S, packed_value, profile)',
         'pmp_views\' := AllowedViewEvolutionAfterPMPWrite(S.pmp_views, S, profile)'],
        ['csr', 'pmp_views'], ['memory'],
        ['R/W/X, A and L are fields of the same packed CSR write, not four independent instructions.',
         'Apply per-entry lock rules, matching priority, legal encodings and XLEN-specific CSR layout.',
         'L can also change M-mode enforcement; it is not merely a software configuration lock.'], ['machine', 'smepmp']),
    operation('pmp.security.write', 'protection', ['CSR writes to mseccfg[/mseccfgh]'], ['Zicsr', 'Smepmp', 'M-mode'],
        ['requested_value', 'MML', 'MMWP', 'RLB', 'existing rules'],
        ['csr\' := SmepmpWritePolicy(S, requested_value, profile)', 'permission interpretation := SmepmpRules(csr\', profile)'],
        ['csr', 'pmp_views'], ['memory'],
        ['Sticky fields and lock bypass have extension-specific conditions.', 'Do not reuse base PMP rules unchanged when Smepmp is active.',
         'Other mseccfg fields outside Smepmp remain profile-dependent.'], ['smepmp']),
    operation('translation.satp.write', 'translation', ['CSR writes to satp'], ['Zicsr', 'S-mode architecture'],
        ['MODE', 'ASID', 'PPN', 'privilege/TVM/virtualization state'],
        ['satp\' := SatpWARLWritePolicy(S, requested_value, profile)',
         'translation_views\' := AllowedViewEvolutionWithoutImplicitFence(S, profile)'],
        ['csr', 'translation_views'], ['memory', 'PMP configuration'],
        ['Writing satp does not by itself supply SFENCE.VMA ordering or invalidate all translation caches.',
         'An unsupported MODE can cause the complete write to be ignored.', 'V=1 selects the relevant virtualized CSR behavior.'], ['supervisor']),
    operation('translation.pte.write', 'translation', ['Store/AMO/SC to known page-table memory'], ['selected paging/atomic profile'],
        ['physical PTE location', 'value/operator', 'stage/level', 'width', 'PTE role evidence'],
        ['apply the underlying memory operation exactly once',
         'translation_views\' := AllowedViewsBeforeRequiredSynchronization(S, profile)'],
        ['memory', 'translation_views', 'reservation', 'ordering'], ['PMP configuration'],
        ['A PTE write is a contextual classification of a memory write, not a distinct opcode.',
         'Track PPN/V/R/W/X/U/G/A/D and applicable extension bits together.',
         'Svpbmt PBMT is a PTE field; hardware A/D updates also change page-table memory.'], ['supervisor', 'svpbmt']),
    operation('translation.sfence.vma', 'synchronization', ['SFENCE.VMA rs1,rs2'], ['S-mode architecture', 'privilege/TVM permits'],
        ['rs1 register identity and value', 'rs2 register identity and value', 'hart'],
        ['translation_views\' := SFencePermittedViews(S, rs1, rs2, current_hart, profile)',
         'ordering\' := OrderRequiredImplicitReferences(S, scope, profile)',
         'full-scope fence also provides specified PMP/VM synchronization'],
        ['translation_views', 'pmp_views', 'ordering'], ['ordinary memory contents', 'PMP CSR values'],
        ['Only the local hart is affected; global entries and ASID/address scope matter.',
         'The x0 register means all-address/all-ASID scope; a non-x0 register containing zero is not the same selector.',
         'This operation does not zero memory and is not a general data-cache flush.'], ['machine', 'supervisor']),
    operation('privilege.mstatus.write', 'execution_context', ['CSR writes to mstatus[/mstatush]'], ['Zicsr', 'M-mode'],
        ['MPRV', 'MPP', 'SUM', 'MXR', 'TVM/TSR', 'requested_value', 'profile'],
        ['csr\' := MstatusWARLAndAliasPolicy(S, requested_value, profile)',
         'effective access context := DeriveContext(privilege, csr\', access_kind, profile)'],
        ['csr'], ['memory', 'PMP configuration'],
        ['MPRV affects explicit data accesses, not instruction fetch in the same way.',
         'Other fields remain represented by the whole CSR operation.'], ['machine', 'supervisor']),
    operation('privilege.sstatus.write', 'execution_context', ['CSR writes to sstatus'], ['Zicsr', 'S-mode architecture'],
        ['SUM', 'MXR', 'SPP', 'requested_value', 'profile'],
        ['csr\' := WriteSupervisorVisibleMstatusAlias(S, requested_value, profile)'],
        ['csr'], ['memory', 'PMP configuration'],
        ['sstatus is an architectural view/alias, not an independent contradictory copy of mstatus.',
         'SUM/MXR changes are immediately effective; do not impose a universal SFENCE requirement on every control change.',
         'SUM/MXR do not override PMP restrictions.'], ['supervisor', 'machine']),
    operation('privilege.return', 'execution_context', ['MRET', 'SRET'], ['selected privilege architecture'],
        ['saved privilege', 'return PC', 'status stack fields', 'virtualization state'],
        ['(pc\', privilege\', csr\') := PrivilegeReturnRules(S, instruction, profile)'],
        ['pc', 'privilege', 'csr', 'reservation (as permitted)'], ['memory', 'PMP configuration'],
        ['A privilege change can change access checks without a PMP write.', 'This is a privilege transition, not a PM context-save implementation.'], ['machine', 'supervisor']),
    operation('ordering.fence', 'synchronization', ['FENCE', 'FENCE.TSO if applicable'], ['selected memory-ordering profile'],
        ['predecessor/successor sets', 'fm', 'hart'], ['ordering\' := FenceOrderingRelation(S, pred, succ, fm, profile)'],
        ['ordering'], ['memory contents', 'PMP CSR values', 'translation configuration'],
        ['A memory-ordering fence does not stand in for SFENCE.VMA or erase data.'], ['rvwmo']),
    operation('ordering.fence.i', 'synchronization', ['FENCE.I'], ['Zifencei'],
        ['hart'], ['instruction-fetch view/order\' := LocalInstructionSynchronization(S, profile)'],
        ['ordering', 'instruction-fetch view'], ['ordinary memory contents', 'PMP CSR values'],
        ['Local instruction-fetch synchronization is distinct from permission revocation and memory zeroing.'], ['rvwmo']),
    operation('attributes.environment.write', 'attributes', ['CSR writes to menvcfg/senvcfg/henvcfg and high halves'], ['relevant extensions and privilege'],
        ['CSR/fields', 'PBMTE where applicable', 'cache-operation controls', 'profile'],
        ['csr\' := EnvironmentConfigurationPolicy(S, requested_value, profile)',
         'derived attribute/operation interpretation := DecodeEnvironment(csr\', profile)'],
        ['csr', 'translation_views', 'platform-derived interpretation'], ['memory contents'],
        ['Fields are extension-specific; do not invent a generic PMA CSR.',
         'Changing PTE interpretation may require the extension-specified synchronization.'], ['machine', 'supervisor', 'svpbmt', 'hypervisor']),
    operation('attributes.platform.change', 'platform', ['platform-specific MMIO/CSR/firmware operation'], ['explicit platform specification'],
        ['platform register', 'value', 'PMA/interconnect/device rules'],
        ['platform\' := PlatformSpecifiedTransition(S, operation)'],
        ['platform', 'possibly visibility/ordering'], ['no universal frame beyond the platform specification'],
        ['PMA is not universally software-writable.', 'No standard universal PMA-setting instruction is assumed.'], ['machine']),
    operation('cache.zero', 'contents_extension', ['CBO.ZERO'], ['Zicboz', 'environment permits'],
        ['address', 'cache-block size', 'translation/context'],
        ['memory\' := ZeroCacheBlockWithSpecifiedGranularity(S, address, profile)'],
        ['memory', 'ordering', 'reservation', 'translation_views', 'pmp_views'], ['PMP configuration'],
        ['Block size is a profile parameter.', 'The entire block is not guaranteed to be one atomic store.'], ['cmo']),
    operation('cache.management', 'visibility_extension', ['CBO.CLEAN', 'CBO.FLUSH', 'CBO.INVAL'], ['Zicbom', 'environment permits'],
        ['address', 'cache block', 'operation', 'coherence domain'],
        ['cache/visibility state\' := CacheManagementRules(S, operation, profile)'],
        ['platform cache/visibility', 'ordering'], ['PMP CSR values'],
        ['Do not interpret cache invalidation or flushing as guaranteed memory erasure.'], ['cmo']),
    operation('translation.guest.root.write', 'virtualization_extension', ['CSR writes to vsatp/hgatp'], ['H extension'],
        ['VS/G stage', 'MODE', 'ASID/VMID', 'PPN', 'privilege/virtualization state'],
        ['csr\' := GuestTranslationRootWritePolicy(S, requested_value, profile)',
         'translation_views\' := PermittedViewsWithoutImplicitFence(S, profile)'],
        ['csr', 'translation_views'], ['memory', 'PMP configuration'],
        ['VS-stage and G-stage need distinct state and synchronization scopes.'], ['hypervisor']),
    operation('translation.hfence', 'virtualization_extension', ['HFENCE.VVMA', 'HFENCE.GVMA'], ['H extension', 'permitted privilege'],
        ['stage', 'address selector', 'ASID/VMID selector', 'hart'],
        ['translation_views/order\' := HypervisorFenceRules(S, instruction, selectors, hart, profile)'],
        ['translation_views', 'ordering'], ['memory contents', 'PMP CSR values'],
        ['HFENCE.VVMA and HFENCE.GVMA affect different translation stages; neither is a global all-hart erase.'], ['hypervisor']),
]
BY_ID = {op['id']: op for op in CATALOG}


def catalogue():
    return dict(schema='smpreempt.riscv-memory-operations.v1', state=STATE, operations=deepcopy(CATALOG),
                scope='operation families for memory contents/protection/translation/synchronization; not all RISC-V extensions',
                not_inferred=['confidentiality/ownership', 'public-ready', 'trusted use', 'attack success'],
                out_of_scope=['full ISA execution', 'all extension mechanisms', 'DMA/IOMMU/debug protection',
                              'microarchitectural side channels', 'trap-handler code effects'],
                profile_requirements=['XLEN and physical-address width', 'implemented privilege/extension set',
                                     'PMP count/grain/WARL behavior', 'VM implementation and translation modes',
                                     'cache/PMA/platform details', 'hart topology and event model'],
                status='declarative relations; no attack search or complete ISA backend')


CSR_NUMBERS = {0x100: 'sstatus', 0x180: 'satp', 0x280: 'vsatp', 0x300: 'mstatus', 0x305: 'mtvec', 0x310: 'mstatush',
               0x747: 'mseccfg', 0x757: 'mseccfgh', 0x680: 'hgatp', 0x30a: 'menvcfg', 0x31a: 'menvcfgh',
               0x10a: 'senvcfg', 0x60a: 'henvcfg', 0x61a: 'henvcfgh'}


def csr_name(csr):
    if isinstance(csr, str):
        value = csr.lower()
        if not value.startswith('0x'):
            return value
        csr = int(value, 16)
    if type(csr) is not int or not 0 <= csr < 4096:
        raise ValueError('CSR must be a name or a 12-bit numeric address')
    if 0x3a0 <= csr <= 0x3af:
        return 'pmpcfg'+str(csr-0x3a0)
    if 0x3b0 <= csr <= 0x3ef:
        return 'pmpaddr'+str(csr-0x3b0)
    return CSR_NUMBERS.get(csr, hex(csr))


def csr_family(name):
    if re.fullmatch(r'pmpaddr(?:[0-9]|[1-5][0-9]|6[0-3])', name):
        return 'pmp.address.write'
    if re.fullmatch(r'pmpcfg(?:[0-9]|1[0-5])', name):
        return 'pmp.config.write'
    return {'mseccfg': 'pmp.security.write', 'mseccfgh': 'pmp.security.write',
            'satp': 'translation.satp.write', 'mstatus': 'privilege.mstatus.write', 'mstatush': 'privilege.mstatus.write',
            'sstatus': 'privilege.sstatus.write', 'vsatp': 'translation.guest.root.write', 'hgatp': 'translation.guest.root.write',
            'menvcfg': 'attributes.environment.write', 'menvcfgh': 'attributes.environment.write',
            'senvcfg': 'attributes.environment.write', 'henvcfg': 'attributes.environment.write',
            'henvcfgh': 'attributes.environment.write'}.get(name)


def register(index):
    if type(index) is not int or not 0 <= index < 32:
        raise ValueError('register index must be 0..31')
    return dict(operator='constant', value=0) if index == 0 else dict(operator='read_gpr_before', index=index)


def normalize_instruction(instruction):
    """Normalize decoded fields, not assembly strings. No missing opcode is a NOP."""
    if not isinstance(instruction, dict):
        raise ValueError('instruction must be a decoded-fields object')
    insn = deepcopy(instruction)
    op = str(insn.get('opcode', '')).upper()
    if not op:
        raise ValueError('instruction requires opcode')
    aliases = {'CSRW': ('CSRRW', 0), 'CSRWI': ('CSRRWI', 0), 'CSRS': ('CSRRS', 0),
               'CSRC': ('CSRRC', 0), 'CSRSI': ('CSRRSI', 0), 'CSRCI': ('CSRRCI', 0)}
    if op in aliases:
        op, insn['rd'] = aliases[op]
    if op == 'CSRR':
        op, insn['rs1'] = 'CSRRS', 0
    common = dict(source=instruction.get('source'), decoded=deepcopy(instruction),
                  semantics_status='normalized operation; requires the selected profile relation',
                  architectural_step=True)
    csr_ops = {'CSRRW': 'replace', 'CSRRS': 'set', 'CSRRC': 'clear',
               'CSRRWI': 'replace', 'CSRRSI': 'set', 'CSRRCI': 'clear'}
    if op in csr_ops:
        name = csr_name(insn['csr'])
        rd = insn['rd']
        register(rd)
        immediate = op.endswith('I')
        update = csr_ops[op]
        if immediate:
            source = insn['zimm']
            if type(source) is not int or not 0 <= source < 32:
                raise ValueError('CSR immediate must be 0..31')
            value = dict(operator='constant', value=source)
        else:
            source = insn['rs1']
            value = register(source)
        write = update == 'replace' or source != 0
        read = update != 'replace' or rd != 0
        old = dict(operator='csr_before', csr=name)
        requested = value if update == 'replace' else dict(operator='or' if update == 'set' else 'and_not', operands=[old, value])
        family = csr_family(name)
        return dict(common, operation=family if write else 'csr.read', csr_family=family,
                    csr=name, csr_read=read, csr_write=write,
                    result_register=None if rd == 0 else rd,
                    result_expression=old if rd != 0 else None,
                    requested_value=requested if write else None,
                    effects_order='source operands and old CSR are from the pre-state; CSR update and rd result belong to one instruction',
                    legality='check implemented CSR, XLEN layout, privilege and extension/trap controls before applying the family policy',
                    unknown_effect=family is None)
    if op in ('SFENCE.VMA', 'HFENCE.VVMA', 'HFENCE.GVMA'):
        r1, r2 = insn.get('rs1', 0), insn.get('rs2', 0)
        address, identifier = register(r1), register(r2)
        return dict(common, operation='translation.sfence.vma' if op == 'SFENCE.VMA' else 'translation.hfence',
                    instruction=op, address_selector=dict(all=r1 == 0, expression=address),
                    identifier_selector=dict(all=r2 == 0, expression=identifier),
                    hart_scope='current hart', ordinary_memory_change=False,
                    pmp_sync_guarantee='full-scope specification rule' if op == 'SFENCE.VMA' and r1 == r2 == 0 else 'requires scoped profile analysis')
    if op in ('MRET', 'SRET'):
        return dict(common, operation='privilege.return', instruction=op)
    if op in ('FENCE', 'FENCE.TSO', 'FENCE.I'):
        return dict(common, operation='ordering.fence.i' if op == 'FENCE.I' else 'ordering.fence', instruction=op,
                    selectors={k: insn[k] for k in ('pred', 'succ', 'fm') if k in insn}, ordinary_memory_change=False)
    if op.startswith('CBO.'):
        if op == 'CBO.ZERO':
            return dict(common, operation='cache.zero', address=register(insn['rs1']))
        if op in ('CBO.CLEAN', 'CBO.FLUSH', 'CBO.INVAL'):
            return dict(common, operation='cache.management', instruction=op, address=register(insn['rs1']))
    is_amo = re.fullmatch(r'AMO(?:ADD|SWAP|XOR|AND|OR|MIN|MAX|MINU|MAXU|CAS)\.(?:B|H|W|D|Q)', op)
    if op in ('LR.W', 'LR.D', 'SC.W', 'SC.D'):
        family = 'memory.lrsc'
    elif is_amo:
        family = 'memory.amo'
    elif op in ('SB', 'SH', 'SW', 'SD'):
        family = 'memory.store'
    elif op in ('LB', 'LBU', 'LH', 'LHU', 'LW', 'LWU', 'LD'):
        family = 'memory.load'
    else:
        return dict(common, operation=None, unknown_effect=True, reason='opcode outside the enumerated decoder subset')
    operands = {k: insn[k] for k in ('rd', 'rs1', 'rs2', 'imm', 'aq', 'rl') if k in insn}
    required = ('rd', 'rs1') if family == 'memory.load' or op.startswith('LR.') else ('rs1', 'rs2') if family == 'memory.store' else ('rd', 'rs1', 'rs2')
    if any(field not in operands for field in required):
        raise ValueError('missing decoded operand for '+op)
    for field in ('rd', 'rs1', 'rs2'):
        if field in operands:
            register(operands[field])
    role = insn.get('memory_role')
    if role is not None and role != 'pte':
        raise ValueError('unknown memory_role; omit it or use pte with explicit evidence')
    if role == 'pte':
        if family not in ('memory.store', 'memory.amo') and not op.startswith('SC.'):
            raise ValueError('PTE update requires a memory-writing operation')
        if not insn.get('role_evidence'):
            raise ValueError('PTE classification requires role_evidence from an implementation/model')
        return dict(common, operation='translation.pte.write', underlying_operation=family,
                    operands=operands, instruction=op, role_evidence=insn['role_evidence'],
                    facets=insn.get('facets', []), memory_effect_count=1)
    return dict(common, operation=family, instruction=op, operands=operands,
                memory_role='not inferred from opcode')


def normalize_sequence(instructions):
    normalized = [normalize_instruction(i) for i in instructions]
    return dict(schema='smpreempt.riscv-memory-sequence.v1', steps=normalized,
                transitions=[dict(source=f's{i}', target=f's{i+1}', operation=step) for i, step in enumerate(normalized)],
                interruption_boundaries=[f's{i}' for i in range(len(normalized)+1)],
                unknown_steps=[i for i, step in enumerate(normalized) if step.get('unknown_effect')],
                semantics='ordered operation relations; no concrete-state enumeration or attack verdict',
                note='one CSR instruction is one boundary step, including its read-modify-write and GPR result')
