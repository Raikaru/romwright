    # Opaque predicate: imul leaves the low 32 bits of a square, which is
    # never negative, so `js .Ldead` is never taken. Ground truth via nm:
    # br_opq -> c0..c3. The dead edge must not invent targets.
    .text
    .globl opq, br_opq, c0, c1, c2, c3
    .type opq, @function
opq:
    movl %edi, %eax
    imull %edi, %eax
    js .Ldead
    cmpl $4, %edi
    jae .Ldef
    leaq .Ltable(%rip), %rax
    movslq (%rax,%rdi,4), %rcx
    addq %rax, %rcx
br_opq:
    jmp *%rcx
c0:
    movl $200, %eax
    ret
c1:
    movl $201, %eax
    ret
c2:
    movl $202, %eax
    ret
c3:
    movl $203, %eax
    ret
.Ldef:
    movl $-1, %eax
    ret
.Ldead:
    movl $-2, %eax
    ret
    .globl _start
    .type _start, @function
_start:
    movl $1, %edi
    call opq
    movzbq %al, %rdi
    movl $60, %eax
    syscall
    .data
    .align 4
.Ltable:
    .long c0-.Ltable, c1-.Ltable, c2-.Ltable, c3-.Ltable
