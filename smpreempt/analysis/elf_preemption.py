"""Bounded per-instruction checks of direct Host byte accesses after a switch.

The modeled switch preserves PMP and assumes saved CPU registers are isolated.
This is a conditional access check, not a complete confidentiality proof.
"""
from collections import Counter

import z3

from smpreempt.analysis.elf_pmp_steps import execute_function
from smpreempt.model.riscv_model import PMP_ADDR_BITS


def check_boundaries(image, symbol, *, region_base, region_size, host_mode='S',
                     assume_fresh_pmp=False, timeout_ms=5000, **execution_options):
    if type(region_base) is not int or type(region_size) is not int or region_base < 0 or region_size <= 0:
        raise ValueError('region base must be nonnegative and size must be positive')
    if region_base+region_size > (1 << (PMP_ADDR_BITS+2)):
        raise ValueError('region lies outside the selected physical-address profile')
    if host_mode not in ('S', 'U'):
        raise ValueError('host mode must be S or U')
    if any(s.address != s.physical for s in image.segments):
        raise ValueError('boundary checker requires identity-mapped ELF load segments')
    points = {}

    def observe(state, record):
        point = points.setdefault(state.pc, dict(visits=0, query_unknown=False, witnesses={}))
        point['visits'] += 1
        if not assume_fresh_pmp:
            return
        byte = z3.BitVec('host_access_address', 64)
        constraints = [state.path, z3.UGE(byte, region_base), z3.ULT(byte, region_base+region_size)]
        for access in ('R', 'W'):
            if access in point['witnesses']:
                continue
            solver = z3.Solver()
            solver.set(timeout=timeout_ms)
            solver.add(*constraints, state.pmp.allow(byte, 1, access, privilege=host_mode))
            result = solver.check()
            if result == z3.unknown:
                point['query_unknown'] = True
            elif result == z3.sat:
                model = solver.model()
                point['witnesses'][access] = dict(
                    address=hex(model.eval(byte, model_completion=True).as_long()),
                    at_step=state.steps,
                    pmp_cfg=[hex(model.eval(v, model_completion=True).as_long()) for v in state.pmp.cfg],
                    pmp_addr=[hex(model.eval(v, model_completion=True).as_long()) for v in state.pmp.addr],
                    trace=list(state.trace),
                    note='Abstract model witness; not replayed against an implementation or hardware.')

    execution = execute_function(image, symbol, timeout_ms=timeout_ms,
                                 boundary_observer=observe, **execution_options)
    reasons = Counter((p['status'], p['reason']) for p in execution['paths'] if p['status'] != 'returned')
    incomplete = bool(reasons)
    boundaries = []
    for pc, instruction in sorted(image.instructions.items()):
        if not symbol.address <= pc < symbol.address+symbol.size:
            continue
        point = points.get(pc)
        witnesses = {} if point is None else point['witnesses']
        if not assume_fresh_pmp:
            status = 'unknown'
            reason = 'PMP synchronization/effective view is unspecified'
        elif witnesses:
            status = 'abstract_counterexample'
            reason = 'Host byte access is permitted in at least one modeled reachable state'
        elif point is not None and (incomplete or point['query_unknown']):
            status = 'unknown'
            reason = 'execution or access query is incomplete'
        elif point is not None:
            status = 'no_counterexample_within_bound'
            reason = 'no permitted byte access found in observed modeled states'
        elif incomplete:
            status = 'unknown'
            reason = 'point was not observed and execution is incomplete'
        else:
            status = 'not_reached_within_bound'
            reason = 'point was not observed within the explored function executions'
        boundaries.append(dict(pc=hex(pc), bytes=instruction.raw.hex(), status=status, reason=reason,
                               observed_states=0 if point is None else point['visits'],
                               witnesses=witnesses))
    return dict(schema='smpreempt.elf-preemption-boundaries.v1',
        input=execution['input'], function=execution['function'], bounds=execution['bounds'],
        decoder=execution['decoder'], initial_register_assignments=execution['initial_register_assignments'],
        initial_memory_bytes=execution['initial_memory_bytes'], auxiliary_csr_profile=execution['auxiliary_csr_profile'],
        policy=dict(region_base=hex(region_base), region_size=region_size, host_mode=host_mode,
                    operations=['R', 'W'], access_width_bytes=1, host_translation='Bare',
                    pm='preserve PMP; saved CPU registers assumed isolated',
                    assume_fresh_pmp=assume_fresh_pmp),
        exploration=dict(explored_instruction_states=execution['explored_instruction_states'],
            incomplete=incomplete,
            terminal_statuses=dict(Counter(p['status'] for p in execution['paths'])),
            incomplete_reasons=[dict(status=status, reason=reason, count=count)
                                for (status, reason), count in reasons.items()]),
        boundaries=boundaries,
        limitations=[item for item in execution['assumptions'] if not item.startswith('No Host transition,')]+[
            'Host instruction fetch/entry, actual PM implementation, trap behavior, restart and host requests are not checked.',
            'Region is an explicit input and is assumed to require both read and write isolation.',
            'Single-byte PMP checks are conditional on a fresh PMP view; cached permissions are not modeled.',
            'Counterexamples are abstract model witnesses, not replayed attacks.',
            'No unbounded proof, instruction-sequence-independent reachability or forbidden-region synthesis is performed.'])
