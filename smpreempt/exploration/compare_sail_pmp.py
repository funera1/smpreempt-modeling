"""Compare concrete PMP CSR events from our ELF trace and Sail's trace log."""
import argparse
import hashlib
import json
from pathlib import Path
import re


STEP = re.compile(r'^\[\d+\]\s+\[[A-Z]+\]:\s+(0x[0-9a-f]+)', re.I)
CSR = re.compile(r'^CSR\s+(pmp(?:cfg|addr)\d+)\s+\(0x[0-9a-f]+\)\s+(->|<-)\s+(0x[0-9a-f]+)', re.I)


def _number(text):
    if text.startswith('#x'):
        return int(text[2:], 16)
    if text.startswith('#b'):
        return int(text[2:], 2)
    raise ValueError('model CSR value is symbolic or unsupported: '+text[:80])


def compare(report, sail_text):
    paths = report.get('paths', [])
    if len(paths) != 1 or paths[0].get('status') != 'returned':
        raise ValueError('model report must contain exactly one returned concrete path')
    model = []
    for e in paths[0]['trace']:
        csr = e.get('csr', '')
        if not csr.startswith(('pmpcfg', 'pmpaddr')):
            continue
        if e.get('csr_read'):
            model.append((int(e['pc'], 16), csr, 'read', _number(e['csr_before'])))
        if e.get('csr_write'):
            model.append((int(e['pc'], 16), csr, 'write', _number(e['csr_after'])))
    sail = []
    pc = None
    for line in sail_text.splitlines():
        step = STEP.match(line)
        if step:
            pc = int(step[1], 16)
        event = CSR.match(line)
        if event:
            if pc is None:
                raise ValueError('Sail PMP CSR event occurs before an instruction')
            sail.append((pc, event[1].lower(), 'read' if event[2] == '->' else 'write', int(event[3], 16)))
    if not model or not sail:
        raise ValueError('both traces must contain PMP CSR events')
    def output(events):
        return [dict(pc=hex(pc), csr=csr, operation=op, value=hex(value))
                for pc, csr, op, value in events]
    return dict(schema='smpreempt.sail-pmp-comparison.v1',
        status='match' if model == sail else 'mismatch',
        model_events=output(model), sail_events=output(sail),
        scope=('Concrete PMP CSR read/write events only; user must ensure both executions use the same ELF and initial profile. '
               'No general ISA equivalence or safety proof.'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('model_json')
    parser.add_argument('sail_trace')
    parser.add_argument('--sail-version', help='reported Sail release/build identifier')
    args = parser.parse_args()
    try:
        model_bytes = Path(args.model_json).read_bytes()
        sail_bytes = Path(args.sail_trace).read_bytes()
        result = compare(json.loads(model_bytes), sail_bytes.decode('utf-8'))
        result['inputs'] = dict(model_sha256=hashlib.sha256(model_bytes).hexdigest(),
                                sail_trace_sha256=hashlib.sha256(sail_bytes).hexdigest(),
                                sail_version=args.sail_version)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    if result['status'] != 'match':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
