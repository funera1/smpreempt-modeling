"""Strict read-only extraction of the inline-asm subset used by PMP macros.

Operand placeholders stay bound to LLVM values, not invented physical register
numbers. A pseudo LA or assembler alignment remains explicit. Unknown asm is a
barrier. Hardware CSR boundaries are retained; pseudo expansion needs ELF later.
"""
import re

from smpreempt.model.riscv_memory_operations import csr_family


REGISTERS = {'zero': 0, 'ra': 1, 'sp': 2, 'gp': 3, 'tp': 4, 't0': 5, 't1': 6,
             't2': 7, 's0': 8, 'fp': 8, 's1': 9, **{f'a{i}': 10+i for i in range(8)},
             **{f's{i}': 16+i for i in range(2, 12)}, **{f't{i}': 25+i for i in range(3, 7)}}


def operand(text):
    text = text.strip()
    if re.fullmatch(r'\$[0-9]+', text):
        return dict(kind='llvm_operand', index=int(text[1:]))
    if text in REGISTERS:
        return dict(kind='register', index=REGISTERS[text])
    if re.fullmatch(r'x(?:[0-9]|[12][0-9]|3[01])', text):
        return dict(kind='register', index=int(text[1:]))
    if re.fullmatch(r'[0-9]+[fb]', text):
        return dict(kind='local_label_address', label=text)
    raise ValueError('unsupported asm operand: '+text)


def extract_asm(effect, source=None):
    if effect.get('callee_kind') != 'inline_asm':
        raise ValueError('expected an inline-asm effect')
    constraints = [c.strip() for c in effect['constraints'].split(',') if c.strip()]
    outputs = [c for c in constraints if c.startswith('=')]
    if any(c.startswith('+') or c.isdigit() for c in constraints) or len(outputs) > 1:
        raise ValueError('tied/read-write/multiple asm outputs require additional semantics')
    bindings = ([dict(kind='output', target=effect['result'])] if outputs else [])
    bindings += [dict(kind='input', value=a) for a in effect['arguments']]
    allowed = {'r', '=r', '~{memory}', '~{x5}', '~{t0}'}
    if any(c not in allowed for c in constraints):
        raise ValueError('unsupported asm constraint: '+effect['constraints'])
    steps = []
    # LLVM returns the actual assembler string with actual line breaks.
    for line in effect['assembly'].splitlines():
        for statement in line.split(';'):
            text = statement.split('#', 1)[0].strip()
            if not text:
                continue
            label = re.match(r'^([0-9]+):\s*(.*)$', text)
            if label:
                steps.append(dict(kind='label', name=label[1], text=label[1]+':'))
                text = label[2]
                if not text:
                    continue
            if text.startswith('.align '):
                steps.append(dict(kind='alignment', text=text, expansion='may emit padding; no PMP change'))
                continue
            words = text.split(None, 1)
            opcode = words[0].lower()
            args = [] if len(words) == 1 else [a.strip() for a in words[1].split(',')]
            if opcode == 'la' and len(args) == 2:
                step = dict(kind='label_address', destination=operand(args[0]), value=operand(args[1]),
                            expansion='pseudo instruction; requires final code for exact PC boundaries')
            elif opcode == 'csrr' and len(args) == 2:
                step = dict(kind='csr', opcode='CSRRS', csr=args[1], destination=operand(args[0]),
                            value=dict(kind='register', index=0), update='set', csr_read=True, csr_write=False,
                            catalogue_id='csr.read', csr_family=csr_family(args[1]))
            elif opcode in ('csrw', 'csrrw') and len(args) == (2 if opcode == 'csrw' else 3):
                rd, csr, value = (dict(kind='register', index=0), args[0], operand(args[1])) if opcode == 'csrw' else (operand(args[0]), args[1], operand(args[2]))
                step = dict(kind='csr', opcode='CSRRW', csr=csr, destination=rd, value=value,
                            update='replace', csr_read=rd != dict(kind='register', index=0), csr_write=True,
                            catalogue_id=csr_family(csr), unknown_csr=csr_family(csr) is None)
                if csr == 'mtvec':
                    step.update(catalogue_id='auxiliary.csr.mtvec', unknown_csr=False,
                                note='trap-vector state retained; trap behavior not analyzed')
            elif opcode in ('csrrs', 'csrrc', 'csrrwi', 'csrrsi', 'csrrci',
                            'csrs', 'csrc', 'csrwi', 'csrsi', 'csrci'):
                aliases = {'csrs': 'csrrs', 'csrc': 'csrrc', 'csrwi': 'csrrwi',
                           'csrsi': 'csrrsi', 'csrci': 'csrrci'}
                base = aliases.get(opcode, opcode)
                if opcode in aliases and len(args) == 2:
                    rd, csr, raw = dict(kind='register', index=0), args[0], args[1]
                elif opcode not in aliases and len(args) == 3:
                    rd, csr, raw = operand(args[0]), args[1], args[2]
                else:
                    raise ValueError('invalid CSR operands: '+text)
                if base.endswith('i'):
                    immediate = int(raw, 0)
                    if not 0 <= immediate < 32:
                        raise ValueError('CSR immediate must be 0..31')
                    value = dict(kind='immediate', value=immediate)
                    zero = immediate == 0
                else:
                    value = operand(raw)
                    zero = value == dict(kind='register', index=0)
                replace = base in ('csrrw', 'csrrwi')
                writes = replace or not zero
                family = csr_family(csr)
                step = dict(kind='csr', opcode=base.upper(), csr=csr,
                            destination=rd, value=value,
                            update='replace' if replace else ('set' if base in ('csrrs', 'csrrsi') else 'clear'),
                            csr_read=not replace or rd != dict(kind='register', index=0),
                            csr_write=writes, catalogue_id=family if writes else 'csr.read',
                            unknown_csr=writes and family is None)
            elif opcode in ('fence', 'fence.i'):
                if (opcode == 'fence.i' and args) or (opcode == 'fence' and len(args) not in (0, 2)):
                    raise ValueError('unsupported fence operands: '+text)
                step = dict(kind='fence', catalogue_id='ordering.'+opcode,
                            operands=args, hart_scope='local')
            elif opcode == 'sfence.vma' and len(args) in (0, 2):
                r1, r2 = [operand(a) for a in args] if args else [dict(kind='register', index=0)]*2
                step = dict(kind='fence', catalogue_id='translation.sfence.vma', rs1=r1, rs2=r2,
                            full_scope=r1 == r2 == dict(kind='register', index=0), hart_scope='local')
            else:
                step = dict(kind='unknown', text=text, reason='unsupported inline-asm instruction')
            step.update(text=text, source=source, ordinal=len(steps))
            for item in (step.get('value'), step.get('destination')):
                if item and item['kind'] == 'llvm_operand' and item['index'] >= len(bindings):
                    raise ValueError('asm placeholder outside operand bindings')
            steps.append(step)
    return dict(steps=steps, bindings=bindings, source=source,
                complete=all(s['kind'] != 'unknown' for s in steps),
                instruction_boundaries='exact at extracted CSR/fence operations; LA/alignment expansion unresolved')


def extract_report_asm(report):
    results = []
    for function in report['functions']:
        nodes = {n['id']: n for n in function['nodes']}
        for edge in function['transitions']:
            effect = edge['effect']
            if effect.get('callee_kind') != 'inline_asm':
                continue
            source = dict(function=function['name'], node=edge['source'], location=nodes[edge['source']].get('source'))
            try:
                result = extract_asm(effect, source)
            except ValueError as exc:
                result = dict(steps=[], source=source, complete=False, reason=str(exc))
            results.append(result)
    return dict(schema='smpreempt.riscv-inline-asm.v1', input=report['input'], assemblies=results)
