    # Runtime-patched dispatch: sm_target holds sm_case0 at rest but is
    # unconditionally overwritten with sm_case1 before the indirect
    # jump (exit code 11 proves the runtime target). Ground truth via
    # nm: br_sm -> sm_case1. Recovering only the at-rest sm_case0 is a
    # stale-pointer wrong edge; refusal is also accepted.
    .section .selfmod,"awx",@progbits
    .globl selfmod, br_sm, sm_case0, sm_case1, sm_target
selfmod:
    leaq sm_case1(%rip), %rax
    movq %rax, sm_target(%rip)
br_sm:
    jmp *sm_target(%rip)
    hlt
sm_case0:
    movl $10, %eax
    ret
sm_case1:
    movl $11, %eax
    ret
sm_target:
    .quad sm_case0
    .text
    .globl _start
    .type _start, @function
_start:
    call selfmod
    movzbq %al, %rdi
    movl $60, %eax
    syscall
