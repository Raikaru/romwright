    # Flattened state-machine dispatcher: loop-carried state indexes a
    # two-entry PIC table. Ground truth via nm: br_flat -> state0, state1.
    # Recovery may legitimately refuse (loop widening); it must never
    # claim anything else.
    .text
    .globl flat, br_flat, state0, state1
    .type flat, @function
flat:
    xorl %eax, %eax
.Lnext:
    cmpl $2, %eax
    ja .Ldone
    leaq .Lstates(%rip), %rdx
    movslq (%rdx,%rax,4), %rcx
    addq %rdx, %rcx
br_flat:
    jmp *%rcx
state0:
    addl $1, %eax
    jmp .Lnext
state1:
    addl $2, %eax
    jmp .Lnext
.Ldone:
    ret
    .globl _start
    .type _start, @function
_start:
    call flat
    xorl %edi, %edi
    movl $60, %eax
    syscall
    .data
    .align 4
.Lstates:
    .long state0-.Lstates, state1-.Lstates
