    # Overlapping-decode dispatch: case1's entry points into the middle
    # of another instruction's encoding, so only table-driven decoding
    # reaches it. Ground truth via nm: br_over -> case0, real1.
    # The bytes [66 90] decode linearly as a 2-byte nop, but the table
    # lands on the second byte (a 1-byte nop). Executing dispatch(1)
    # deterministically exits 121.
    .text
    .globl dispatch, br_over, case0, real1
    .type dispatch, @function
dispatch:
    cmpl $2, %edi
    jae .Ldefault
    leaq .Ltable(%rip), %rax
    movslq (%rax,%rdi,4), %rcx
    addq %rax, %rcx
br_over:
    jmp *%rcx
case0:
    movl $120, %eax
    ret
    .byte 0x66            # operand-size prefix; linear sweep reads [66 90]
real1:                    # as a 2-byte nop, but the table lands here, on the
    .byte 0x90            # 1-byte nop inside the prefix: mid-instruction entry
    movl $121, %eax
    ret
.Ldefault:
    movl $-1, %eax
    ret
    .globl _start
    .type _start, @function
_start:
    movl $1, %edi
    call dispatch
    movzbq %al, %rdi
    movl $60, %eax
    syscall
    .data
    .align 4
.Ltable:
    .long case0-.Ltable, real1-.Ltable
