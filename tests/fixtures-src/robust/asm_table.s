    # Hand-built x86-64 jump table with PIC dword offsets.
    # Ground truth via nm: br_dispatch -> case0..case4 (default NOT included).
    .text
    .globl dispatch, br_dispatch, case0, case1, case2, case3, case4
    .type dispatch, @function
dispatch:
    cmpl $5, %edi
    jae .Ldefault
    leaq .Ltable(%rip), %rax
    movslq (%rax,%rdi,4), %rcx
    addq %rax, %rcx
br_dispatch:
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
    .globl _start
    .type _start, @function
_start:
    movl $2, %edi
    call dispatch
    movzbq %al, %rdi
    movl $60, %eax
    syscall
    .data
    .align 4
.Ltable:
    .long case0-.Ltable, case1-.Ltable, case2-.Ltable, case3-.Ltable, case4-.Ltable
