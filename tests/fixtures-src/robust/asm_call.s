    # Odd-address indirect call: oddtarget sits at an odd address and
    # is called through a register. Ground truth via nm: br_call ->
    # oddtarget exactly. Clearing bit 0 (ARM mode handling) would
    # mistarget mid-instruction; the kind must stay call, not jump.
    # _start exits 7, proving runtime behavior.
    .text
    .byte 0x90
    .globl callit, br_call, oddtarget
    .type callit, @function
callit:
    leaq oddtarget(%rip), %rax
br_call:
    call *%rax
    ret
oddtarget:
    movl $7, %eax
    ret
    .globl _start
    .type _start, @function
_start:
    call callit
    movzbq %al, %rdi
    movl $60, %eax
    syscall
