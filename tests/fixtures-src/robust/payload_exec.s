    # Self-contained PIC payload for the executable packed fixture: code
    # AND table live in .text (objcopy --only-section=.text carries both),
    # RIP-relative only, no relocations. Entry at offset 0 is dispatch;
    # dispatch(2) returns 102.
    .text
    .globl dispatch, case0, case1, case2, case3, case4
    .type dispatch, @function
dispatch:
    cmpl $5, %edi
    jae .Ldefault
    leaq .Ltable(%rip), %rax
    movslq (%rax,%rdi,4), %rcx
    addq %rax, %rcx
    jmp *%rcx
case0:
    movl $100, %eax
    ret
case1:
    movl $101, %eax
    ret
case2:
    movl $102, %eax
    ret
case3:
    movl $103, %eax
    ret
case4:
    movl $104, %eax
    ret
.Ldefault:
    movl $-1, %eax
    ret
    .align 4
.Ltable:
    .long case0-.Ltable, case1-.Ltable, case2-.Ltable, case3-.Ltable, case4-.Ltable
