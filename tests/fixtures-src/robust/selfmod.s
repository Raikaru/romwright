    # Runtime-patched dispatch: sm_target holds sm_case0 at rest and is
    # overwritten with sm_case1 before the indirect jump. Ground truth
    # via nm: br_sm statically reads sm_case0 only. sm_case1 must never
    # be claimed (it is reachable only after the runtime patch).
    .section .selfmod,"awx",@progbits
    .globl selfmod, br_sm, sm_case0, sm_case1, sm_target
    .type selfmod, @function
selfmod:
    leaq sm_case1(%rip), %rax
    movq %rax, sm_target(%rip)
    jmp *sm_target(%rip)
br_sm:
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
