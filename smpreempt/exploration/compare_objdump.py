"""Cross-check an ELF inventory's PC/byte boundaries against GNU objdump."""
import argparse
import hashlib
import json
from pathlib import Path
import re


LINE = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f]{4,16})\s', re.I)


def compare(inventory, objdump_text):
    function = inventory['function']
    start, end = int(function['address'], 16), int(function['end'], 16)
    expected = {int(i['pc'], 16):i['bytes'] for i in inventory['instructions']}
    if len(expected) != len(inventory['instructions']) or not expected:
        raise ValueError('inventory has no instructions or contains duplicate PCs')
    actual = {}
    for line in objdump_text.splitlines():
        match = LINE.match(line)
        if not match:
            continue
        pc = int(match[1], 16)
        if start <= pc < end:
            if pc in actual:
                raise ValueError('objdump output contains duplicate PC')
            actual[pc] = bytes.fromhex(match[2])[::-1].hex()
    if not actual:
        raise ValueError('objdump output has no instructions in the selected function')
    mismatch = [dict(pc=hex(pc), inventory=expected.get(pc), objdump=actual.get(pc))
                for pc in sorted(expected.keys() | actual.keys()) if expected.get(pc) != actual.get(pc)]
    return dict(schema='smpreempt.objdump-boundary-comparison.v1',
        status='match' if not mismatch else 'mismatch',
        function=function, inventory_count=len(expected), objdump_count=len(actual),
        mismatches=mismatch,
        scope='PCs and raw instruction bytes only; opcode/operand semantics and reachability are not checked.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory_json')
    parser.add_argument('objdump_text')
    args = parser.parse_args()
    try:
        left, right = Path(args.inventory_json).read_bytes(), Path(args.objdump_text).read_bytes()
        result = compare(json.loads(left), right.decode('utf-8'))
        result['inputs'] = dict(inventory_sha256=hashlib.sha256(left).hexdigest(),
                                objdump_sha256=hashlib.sha256(right).hexdigest())
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    if result['status'] != 'match':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
