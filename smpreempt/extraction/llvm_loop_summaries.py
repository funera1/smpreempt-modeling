"""Recognize one strict byte-clear loop template and check its induction.

This is not general invariant inference. Nonmatching loops remain unresolved.
The summary retains every possible cleared prefix k, rather than atomic memset.
"""
import hashlib
import json


def ref_id(value):
    return value.get('id') if isinstance(value, dict) and value.get('kind') == 'reference' else None


def integer(value):
    return int(value['bits_unsigned']) if isinstance(value, dict) and 'bits_unsigned' in value else None


def recognize_clear_loop(function, region):
    if len(region) != 1:
        return None, 'only a single-block byte-clear loop is recognized'
    blocks = {b['id']: b for b in function['blocks']}
    block = blocks[region[0]]
    if len(block['phis']) != 1:
        return None, 'requires exactly one induction PHI'
    phi = block['phis'][0]
    nodes = {n['id']: n for n in function['nodes']}
    body = [nodes[n] for n in block['instructions']]
    if [n.get('opcode') for n in body] != ['getelementptr', 'store', 'add', 'icmp', 'br']:
        return None, 'body is not exactly GEP/store/increment/compare/branch'
    edges = {}
    for e in function['transitions']:
        edges.setdefault(e['source'], []).append(e)
    def effect(index):
        return edges[body[index]['id']][0]['effect']
    gep, store, inc, cmp = effect(0), effect(1), effect(2), effect(3)
    if any(e['kind'] == 'opaque_effect' for e in (gep, store, inc, cmp)):
        return None, 'loop contains an opaque memory effect'
    g, inc, cmp = gep.get('expression', {}), inc.get('expression', {}), cmp.get('expression', {})
    induction, next_id = phi['target'], body[2]['id']
    params = {p['id']: p for p in function['parameters']}
    base = ref_id(g.get('base'))
    if (g.get('operator') != 'getelementptr' or g.get('source_type', {}).get('llvm') != 'i8'
            or len(g.get('indices', [])) != 1 or ref_id(g['indices'][0]) != induction
            or len(g.get('offset_terms', [])) != 1 or g['offset_terms'][0].get('scale_bytes') != 1
            or base not in params or params[base]['type'].get('address_space') != 0):
        return None, 'GEP must index an address-space-0 pointer argument by the PHI'
    if (store.get('kind') != 'store' or ref_id(store.get('address')) != body[0]['id']
            or integer(store.get('value')) != 0 or store['value_type'].get('integer_bits') != 8
            or store.get('alignment') != 1 or store.get('volatile') or store.get('atomic_ordering')):
        return None, 'requires a nonvolatile, align-1 store of byte zero'
    if (inc.get('operator') != 'add' or ref_id(inc['operands'][0]) != induction
            or integer(inc['operands'][1]) != 1 or inc.get('flags', {}).get('nsw')):
        return None, 'requires increment by one without additional signed-overflow restriction'
    width = inc.get('type', {}).get('integer_bits')
    if not width or width < 2 or g['indices'][0]['type'].get('integer_bits') != width:
        return None, 'induction/index widths are not compatible'
    if cmp.get('operator') != 'icmp' or cmp.get('predicate') != 'eq':
        return None, 'requires equality exit comparison'
    operands = cmp['operands']
    if ref_id(operands[0]) == next_id:
        bound = ref_id(operands[1])
    elif ref_id(operands[1]) == next_id:
        bound = ref_id(operands[0])
    else:
        return None, 'exit comparison does not use incremented induction'
    if bound not in params or params[bound]['type'].get('integer_bits') != width:
        return None, 'loop bound must be a same-width integer argument'
    incoming = phi['incoming']
    loop_in = [i for i in incoming if i['predecessor'] == block['id']]
    initial = [i for i in incoming if i['predecessor'] != block['id']]
    if len(loop_in) != 1 or ref_id(loop_in[0]['value']) != next_id or len(initial) != 1 or integer(initial[0]['value']) != 0:
        return None, 'requires PHI initialized to zero and loop-carried increment'
    exits = edges[body[4]['id']]
    if (len(exits) != 2 or ref_id(exits[0]['guard']) != body[3]['id']
            or exits[1]['target'] != block['entry']
            or exits[1]['guard'] != dict(operator='not', operand=exits[0]['guard'])):
        return None, 'exit/backedge guards do not match the equality comparison'
    pre = blocks.get(initial[0]['predecessor'])
    if pre is None or pre['entry'] != function['entry'] or pre['phis'] or len(pre['instructions']) != 2:
        return None, 'requires a zero-length check in the function entry block'
    pcmp, pbr = (nodes[i] for i in pre['instructions'])
    if pcmp.get('opcode') != 'icmp' or pbr.get('opcode') != 'br':
        return None, 'preheader is not a zero-length check'
    compare = edges[pcmp['id']][0]['effect'].get('expression', {})
    check = compare.get('operands', [])
    valid_zero_test = len(check) == 2 and ((ref_id(check[0]) == bound and integer(check[1]) == 0) or
                                         (ref_id(check[1]) == bound and integer(check[0]) == 0))
    entry_edges = edges[pbr['id']]
    if (compare.get('operator') != 'icmp' or compare.get('predicate') != 'eq' or not valid_zero_test
            or len(entry_edges) != 2 or ref_id(entry_edges[0]['guard']) != pcmp['id']
            or entry_edges[0]['target'] != exits[0]['target'] or entry_edges[1]['target'] != block['entry']
            or entry_edges[1]['guard'] != dict(operator='not', operand=entry_edges[0]['guard'])):
        return None, 'zero-length branch does not bypass the same loop exit'
    # A byte index with the high bit set is negative under GEP sign-extension.
    # Restrict the contract explicitly rather than claiming all unsigned sizes.
    return dict(kind='byte_clear_prefix', function=function['name'], loop_block=block['id'],
        entry=block['entry'], exit=exits[0]['target'], base_argument=base, length_argument=bound,
        induction=induction, integer_bits=width,
        preconditions=['base and n are defined non-poison inputs', f'0 <= n < 2^{width-1}', 'base denotes a live writable object containing at least n bytes',
                       'pointer index arithmetic can represent offsets 0..n without wrapping'],
        relation='0 <= k <= n; M_k[a] = (0 if 0 <= a < k else M_initial[a])',
        progress='one loop store changes k to k+1; scalar steps leave memory unchanged',
        intermediate_states='every prefix k is retained; not an atomic whole-region erase',
        complete_when='k = n', source_nodes=[n['id'] for n in body],
        equivalence_basis='strict syntactic template; SMT obligations check this template, not arbitrary LLVM programs'), None


def prove_clear_template(width=64, timeout_ms=10000, symbolic_fill=False):
    import z3
    if width < 2 or timeout_ms < 1:
        raise ValueError('invalid proof width/timeout')
    n, k, a = z3.Ints('clear_n clear_k clear_address')
    memory = z3.Array('clear_initial', z3.IntSort(), z3.BitVecSort(8))
    initial_poison = z3.Array('clear_initial_poison', z3.IntSort(), z3.BoolSort())
    zero = z3.BitVec('fill_byte', 8) if symbolic_fill else z3.BitVecVal(0, 8)
    def value(prefix, at):
        return z3.If(z3.And(at >= 0, at < prefix), zero, z3.Select(memory, at))
    def poison(prefix, at):
        return z3.If(z3.And(at >= 0, at < prefix), z3.BoolVal(False), z3.Select(initial_poison, at))
    domain = z3.And(n >= 0, n < 1 << (width-1))
    bits, limit = z3.BitVecs('clear_k_bits clear_n_bits', width)
    obligations = {
        'initial': (domain, value(0, a) != z3.Select(memory, a)),
        'store_step': (z3.And(domain, k >= 0, k < n),
                       z3.If(a == k, zero, value(k, a)) != value(k+1, a)),
        'frame': (z3.And(domain, k >= 0, k <= n, z3.Not(z3.And(a >= 0, a < k))),
                  value(k, a) != z3.Select(memory, a)),
        'completion': (z3.And(domain, a >= 0, a < n), value(n, a) != zero),
        'poison_store_step': (z3.And(domain, k >= 0, k < n),
                             z3.If(a == k, z3.BoolVal(False), poison(k, a)) != poison(k+1, a)),
        'poison_completion': (z3.And(domain, a >= 0, a < n), poison(n, a)),
        'remaining_count_step': (z3.And(domain, k >= 0, k < n), (n-k)-1 != n-(k+1)),
        'exit_condition': (z3.And(domain, k >= 0, k < n), ((n-k)-1 == 0) != (k+1 == n)),
        'increment_no_unsigned_wrap': (z3.And(z3.ULT(bits, limit), z3.ULT(limit, 1 << (width-1))),
                                       z3.ULE(bits+1, bits)),
    }
    reports = {}
    for name, (guard, violation) in obligations.items():
        solver = z3.Solver()
        solver.set(timeout=timeout_ms)
        solver.add(guard, violation)
        result = solver.check()
        reports[name] = dict(status=str(result))
        if result == z3.unknown:
            reports[name]['reason'] = solver.reason_unknown()
    return dict(status='proved_for_template' if all(r['status'] == 'unsat' for r in reports.values()) else 'unproved',
                obligations=reports, fill='arbitrary fixed byte' if symbolic_fill else 'zero',
                scope='unbounded prefix-count induction for the matched template under stated preconditions')


def summarize_loops(report, prove=False, timeout_ms=10000):
    summaries, unresolved = [], []
    for f in report['functions']:
        for region in f['cyclic_regions']:
            summary, reason = recognize_clear_loop(f, region)
            if summary is None:
                summary, alternative = recognize_pointer_fill_loop(f, region)
                if alternative:
                    reason += '; ' + alternative
            if summary is None:
                unresolved.append(dict(function=f['name'], region=region, reason=reason))
            else:
                if prove:
                    summary['proof'] = prove_clear_template(summary['integer_bits'], timeout_ms,
                                                          symbolic_fill=summary['kind'] == 'byte_fill_prefix')
                summaries.append(summary)
    digest = hashlib.sha256(json.dumps(report['functions'], sort_keys=True).encode()).hexdigest()
    return dict(schema='smpreempt.llvm-loop-summaries.v1', input=report['input'], graph_sha256=digest,
                summaries=summaries, unresolved=unresolved,
                scope='memory projection of matched loops; no access policy or whole-program safety claim')


def recognize_pointer_fill_loop(function, region):
    """Clang's decrementing count / incrementing pointer sbi_memset template."""
    if len(region) != 1:
        return None, 'not a single-block pointer/count loop'
    blocks = {b['id']: b for b in function['blocks']}
    nodes = {n['id']: n for n in function['nodes']}
    block = blocks[region[0]]
    phis = block['phis']
    body = [nodes[n] for n in block['instructions']]
    if len(phis) != 2 or [n.get('opcode') for n in body] != ['add', 'getelementptr', 'store', 'icmp', 'br']:
        return None, 'not the pointer/count fill template'
    edges = {}
    for edge in function['transitions']:
        edges.setdefault(edge['source'], []).append(edge)
    effects = [edges[n['id']][0]['effect'] for n in body[:4]]
    if any(e['kind'] == 'opaque_effect' for e in effects):
        return None, 'opaque effect in fill loop'
    dec, gep, store, cmp = effects
    dec, gep, cmp = dec.get('expression', {}), gep.get('expression', {}), cmp.get('expression', {})
    pointer_phi = next((p for p in phis if ref_id(gep.get('base')) == p['target']), None)
    count_phi = next((p for p in phis if p != pointer_phi), None)
    if pointer_phi is None or count_phi is None:
        return None, 'missing pointer/count induction'
    width = dec.get('type', {}).get('integer_bits')
    if (not width or width < 2 or dec.get('operator') != 'add' or len(dec.get('operands', [])) != 2
            or ref_id(dec['operands'][0]) != count_phi['target'] or integer(dec['operands'][1]) != (1 << width)-1
            or any(dec.get('flags', {}).values())):
        return None, 'count must decrement by one without additional flags'
    if (gep.get('source_type', {}).get('llvm') != 'i8' or len(gep.get('indices', [])) != 1
            or len(gep.get('offset_terms', [])) != 1 or gep['offset_terms'][0].get('scale_bytes') != 1
            or integer(gep['indices'][0]) != 1 or ref_id(store.get('address')) != pointer_phi['target']
            or store.get('kind') != 'store' or store['value_type'].get('integer_bits') != 8
            or store.get('alignment') != 1):
        return None, 'requires pointer increment by one and a byte store to the old pointer'
    params = {p['id']: p for p in function['parameters']}
    initial_values = []
    for phi, carried in ((pointer_phi, body[1]['id']), (count_phi, body[0]['id'])):
        back = [i for i in phi['incoming'] if i['predecessor'] == block['id']]
        initial = [i for i in phi['incoming'] if i['predecessor'] != block['id']]
        if len(back) != 1 or ref_id(back[0]['value']) != carried or len(initial) != 1:
            return None, 'PHI inputs do not match pointer/count recurrence'
        initial_values.append(initial[0])
    pointer_initial, count_initial = initial_values
    base, bound = ref_id(pointer_initial['value']), ref_id(count_initial['value'])
    if (base not in params or params[base]['type'].get('address_space') != 0
            or bound not in params or params[bound]['type'].get('integer_bits') != width
            or pointer_initial['predecessor'] != count_initial['predecessor']):
        return None, 'initial pointer/count must be compatible arguments from the same preheader'
    preheader = blocks[pointer_initial['predecessor']]
    prep = [nodes[n] for n in preheader['instructions']]
    if preheader['phis'] or [n.get('opcode') for n in prep] != ['trunc', 'br']:
        return None, 'fill byte must be prepared by one truncation before the loop'
    fill = edges[prep[0]['id']][0]['effect'].get('expression', {})
    if (fill.get('operator') != 'trunc' or fill.get('type', {}).get('integer_bits') != 8
            or any(fill.get('flags', {}).values()) or ref_id(fill['operands'][0]) not in params
            or ref_id(store.get('value')) != prep[0]['id']):
        return None, 'store value is not a fixed truncated argument'
    pre_edges = edges[prep[1]['id']]
    if len(pre_edges) != 1 or pre_edges[0]['target'] != block['entry'] or pre_edges[0]['guard'] is not True:
        return None, 'preheader does not enter the loop unconditionally'
    pair = cmp.get('operands', [])
    if (cmp.get('predicate') != 'eq' or len(pair) != 2
            or not ((ref_id(pair[0]) == body[0]['id'] and integer(pair[1]) == 0) or
                    (ref_id(pair[1]) == body[0]['id'] and integer(pair[0]) == 0))):
        return None, 'exit must test the decremented count against zero'
    branch = edges[body[4]['id']]
    if (len(branch) != 2 or ref_id(branch[0]['guard']) != body[3]['id']
            or branch[1]['target'] != block['entry']
            or branch[1]['guard'] != dict(operator='not', operand=branch[0]['guard'])):
        return None, 'loop exit/backedge guards are not matched'
    entry = next((b for b in function['blocks'] if b['entry'] == function['entry']), None)
    if entry is None or entry['phis'] or len(entry['instructions']) != 2:
        return None, 'missing zero-length entry check'
    check, jump = [nodes[n] for n in entry['instructions']]
    if check.get('opcode') != 'icmp' or jump.get('opcode') != 'br':
        return None, 'entry is not compare/branch'
    expr = edges[check['id']][0]['effect'].get('expression', {})
    args = expr.get('operands', [])
    entry_branch = edges[jump['id']]
    if (expr.get('predicate') != 'eq' or len(args) != 2
            or not ((ref_id(args[0]) == bound and integer(args[1]) == 0) or
                    (ref_id(args[1]) == bound and integer(args[0]) == 0))
            or len(entry_branch) != 2 or ref_id(entry_branch[0]['guard']) != check['id']
            or entry_branch[0]['target'] != branch[0]['target'] or entry_branch[1]['target'] != preheader['entry']
            or entry_branch[1]['guard'] != dict(operator='not', operand=entry_branch[0]['guard'])):
        return None, 'zero-length path does not bypass the fill loop'
    return dict(kind='byte_fill_prefix', function=function['name'], loop_block=block['id'],
        entry=block['entry'], exit=branch[0]['target'], base_argument=base, length_argument=bound,
        fill_expression=fill, integer_bits=width,
        preconditions=['base, n and fill are defined non-poison inputs', f'0 <= n < 2^{width-1}', 'base denotes a live writable object containing at least n bytes',
                       'pointer and index arithmetic for offsets 0..n do not wrap'],
        relation='0 <= k <= n; M_k[a] = (fill_byte if 0 <= a < k else M_initial[a])',
        progress='one store fills the next byte; scalar/pointer steps leave memory unchanged',
        complete_when='k = n', intermediate_states='every written prefix k; not atomic memset',
        source_nodes=[n['id'] for n in body],
        equivalence_basis='strict pointer/count syntactic template; memory-projection induction'), None
