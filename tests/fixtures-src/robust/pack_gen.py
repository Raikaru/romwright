#!/usr/bin/env python3
"""Minimal hand-rolled packer fixture generator.

Takes an assembled payload object, XOR-encodes its .text bytes, and emits
a decoder stub source whose data blob holds the scrambled bytes. The real
code exists in the image only as high-entropy data; the decoder's own
`jmp *%rdi` into the decoded buffer has a Top target and must refuse.

Usage: pack_gen.py payload.o out.s
Prints: blob_len <len> entry_offset <off> on stdout for the gate.
"""
import subprocess
import sys

KEY = 0xAA


def main() -> int:
    payload, out = sys.argv[1], sys.argv[2]
    text = subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text', payload, '/dev/stdout'],
                          check=True, capture_output=True).stdout
    assert len(text) > 64, len(text)
    blob = bytes(b ^ KEY for b in text)
    body = '\n'.join(f'    .byte {", ".join(str(b) for b in blob[i:i + 12])}'
                     for i in range(0, len(blob), 12))
    src = f'''    # Generated packed fixture: decoder stub + XOR blob.
    # Never executed (the buffer is not executable); import only.
    .data
    .globl blob, blob_len
blob:
{body}
blob_len:
    .quad {len(blob)}
    .bss
    .globl codebuf
    .comm codebuf,{len(blob)},16
    .text
    .globl _start
    .type _start, @function
_start:
    leaq blob(%rip), %rsi
    movq blob_len(%rip), %rcx
    leaq codebuf(%rip), %rdi
.Ldec:
    movb (%rsi), %al
    xorb ${KEY}, %al
    movb %al, (%rdi)
    incq %rsi
    incq %rdi
    decq %rcx
    jne .Ldec
    leaq codebuf(%rip), %rdi
br_dec:
    jmp *%rdi
'''
    with open(out, 'w') as handle:
        handle.write(src)
    print(f'blob_len {len(blob)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
