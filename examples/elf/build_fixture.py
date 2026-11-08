"""Emit a tiny hand-encoded RV64 ELF, not a Keystone binary or compiler output.

    python3 examples/elf/build_fixture.py /tmp/erase.elf

.text: sd a1,0(a0); sd zero,0(a0); jal zero,0
Public ABI: a0 points to data; a1 is the specified secret input.
"""
from pathlib import Path
import struct
import sys


def build_elf(words=(0x00b53023, 0x00053023, 0x0000006f), function_name='secret_then_scrub'):
    code = b''.join(struct.pack('<I', w) for w in words)
    function_name_bytes = function_name.encode('ascii')
    if not function_name_bytes or b'\0' in function_name_bytes:
        raise ValueError('function name must be a nonempty ASCII string without NUL')
    strings = b'\0'+function_name_bytes+b'\0scrubbed\0'
    names = b'\0.text\0.symtab\0.strtab\0.shstrtab\0'
    symbols = bytes(24) + struct.pack('<IBBHQQ', 1, 0x12, 0, 1, 0x1000, len(code))
    symbols += struct.pack('<IBBHQQ', len(function_name_bytes)+2, 0x12, 0, 1, 0x1008, 4)
    textoff = 0x100
    symoff = (textoff+len(code)+7) & ~7
    stroff = symoff+len(symbols)
    nameoff = stroff+len(strings)
    shoff = (nameoff+len(names)+7) & ~7
    output = bytearray(shoff+5*64)
    ident = b'\x7fELF\x02\x01\x01'+bytes(9)
    output[:64] = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 243, 1, 0x1000,
                              64, shoff, 0, 64, 56, 1, 64, 5, 4)
    output[64:120] = struct.pack('<IIQQQQQQ', 1, 5, textoff, 0x1000, 0x1000,
                                len(code), len(code), 0x100)
    output[textoff:textoff+len(code)] = code
    output[symoff:symoff+len(symbols)] = symbols
    output[stroff:stroff+len(strings)] = strings
    output[nameoff:nameoff+len(names)] = names
    sections = [(0,)*10,
        (1, 1, 6, 0x1000, textoff, len(code), 0, 0, 4, 0),
        (7, 2, 0, 0, symoff, len(symbols), 3, 1, 8, 24),
        (15, 3, 0, 0, stroff, len(strings), 0, 0, 1, 0),
        (23, 3, 0, 0, nameoff, len(names), 0, 0, 1, 0)]
    for i, section in enumerate(sections):
        output[shoff+i*64:shoff+(i+1)*64] = struct.pack('<IIQQQQIIQQ', *section)
    return bytes(output)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: build_fixture.py OUTPUT.elf')
    Path(sys.argv[1]).write_bytes(build_elf())
