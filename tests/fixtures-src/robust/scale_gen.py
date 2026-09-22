#!/usr/bin/env python3
"""Scale fixture generator: a valid ELF with a large mapped size.

Emits assembly with a few real marker dispatch functions (nm ground
truth, like asm_table.s) plus `.fill` padding to reach the target total
mapped size. The padding stresses the loader/mapper/store path without
relocating like code: it must import, stay bounded, and still recover
the markers exactly.

Usage: scale_gen.py <megabytes> <out.s>
"""
import sys

MARKERS = 3
CASES = 4


def marker(index: int) -> str:
    cases = '\n'.join(
        f'mk{index}_c{case}:\n    movl ${300 + index * 10 + case}, %eax\n    ret'
        for case in range(CASES))
    table = ', '.join(f'mk{index}_c{case}-.Lmktable{index}' for case in range(CASES))
    exported = ', '.join([f'mk{index}_dispatch', f'mk{index}_br']
                         + [f'mk{index}_c{case}' for case in range(CASES)])
    return f'''    .globl {exported}
    .type mk{index}_dispatch, @function
mk{index}_dispatch:
    cmpl ${CASES}, %edi
    jae .Lmkdef{index}
    leaq .Lmktable{index}(%rip), %rax
    movslq (%rax,%rdi,4), %rcx
    addq %rax, %rcx
mk{index}_br:
    jmp *%rcx
{cases}
.Lmkdef{index}:
    movl $-1, %eax
    ret
    .data
    .align 4
.Lmktable{index}:
    .long {table}
    .text
'''


def main() -> int:
    megabytes, out = int(sys.argv[1]), sys.argv[2]
    target = megabytes * 1024 * 1024
    parts = ['    .text']
    for index in range(MARKERS):
        parts.append(marker(index))
    # Data padding first (cheap for the assembler: one fill directive
    # per megabyte, no per-byte parsing).
    code_estimate = 4096
    data_mb = max(target - code_estimate, 1024 * 1024) // (1024 * 1024)
    parts.append('    .data')
    for _ in range(data_mb):
        parts.append('    .fill 1048576, 1, 0xAB')
    # Text padding after the markers: architecturally nops so a linear
    # sweep stays aligned, but no symbols and no branches.
    parts.append('    .text')
    parts.append('    .fill 1048576, 1, 0x90')
    parts.append('    .globl _start')
    parts.append('    .type _start, @function')
    parts.append('_start:')
    parts.append('    movl $60, %eax')
    parts.append('    xorl %edi, %edi')
    parts.append('    syscall')
    with open(out, 'w') as handle:
        handle.write('\n'.join(parts) + '\n')
    print(f'scale_mb {megabytes}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
