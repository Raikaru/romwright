#!/usr/bin/env python3
"""Executable packed fixture generator.

Like pack_gen.py, but the decoder maps RWX memory with mmap, decodes
the XOR blob there, CALLS the payload entry, and exits with its return
code. The payload is relocation-free (RIP-relative only), so executing
from a fresh mapping is faithful. This is a working packed binary:
the gate runs it and checks the exit code, proving end-to-end
execution, then requires the static import to claim no wrong edges.

Usage: pack_exec.py payload.o out.s
Prints: blob_len <len> on stdout for the gate.
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
    src = f'''    # Generated executable packed fixture: mmap RWX, decode, call.
    # Payload entry is at offset 0; exit code is its return value.
    .data
    .globl blob, blob_len
blob:
{body}
blob_len:
    .quad {len(blob)}
    .text
    .globl _start
    .type _start, @function
_start:
    xorq %rdi, %rdi
    movq ${len(blob)}, %rsi
    movl $7, %edx
    movl $0x22, %r10d
    movq $-1, %r8
    xorl %r9d, %r9d
    movl $9, %eax
    syscall
    testq %rax, %rax
    js .Lfail
    movq %rax, %r15
    leaq blob(%rip), %rsi
    movq blob_len(%rip), %rcx
    movq %rax, %rdi
.Ldec:
    movb (%rsi), %al
    xorb ${KEY}, %al
    movb %al, (%rdi)
    incq %rsi
    incq %rdi
    decq %rcx
    jne .Ldec
    movl $2, %edi
br_exec:
    call *%r15
    movzbq %al, %rdi
    movl $60, %eax
    syscall
.Lfail:
    movl $99, %edi
    movl $60, %eax
    syscall
'''
    with open(out, 'w') as handle:
        handle.write(src.replace('br_exec:', '.globl br_exec\nbr_exec:'))
    print(f'blob_len {len(blob)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
