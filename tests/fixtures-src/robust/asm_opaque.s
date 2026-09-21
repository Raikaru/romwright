    # Opaque predicate with defined flags: x*(x+1) is always even (one
    # of x, x+1 is even), so `test $1` always sets ZF and `jnz .Ldead`
    # is never taken. Ground truth via nm: br_opq -> c0..c3. The dead
    # edge must not invent targets. _start checks boundary inputs and
    # exits 0 only if every result matches (exit code = failing index+1).
    .text
    .globl opq, br_opq, c0, c1, c2, c3
    .type opq, @function
opq:
    movl %edi, %eax
    leal 1(%rdi), %ecx
    imull %ecx, %eax
    testl $1, %eax
    jnz .Ldead
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
    leaq inputs(%rip), %rbx
    leaq expect(%rip), %r12
    xorl %ebp, %ebp
.Lchk:
    cmpl $9, %ebp
    jae .Lok
    movl (%rbx,%rbp,4), %edi
    call opq
    cmpb (%r12,%rbp,1), %al
    jne .Lfail
    incq %rbp
    jmp .Lchk
.Lok:
    xorl %edi, %edi
    movl $60, %eax
    syscall
.Lfail:
    movl %ebp, %edi
    incq %rdi
    movl $60, %eax
    syscall
    .data
    .align 4
inputs:
    .long 0, 1, 2, 3, 4, 5, 46341, -1, 0x7fffffff
expect:
    .byte 200, 201, 202, 203, 255, 255, 255, 255, 255
    .align 4
.Ltable:
    .long c0-.Ltable, c1-.Ltable, c2-.Ltable, c3-.Ltable
