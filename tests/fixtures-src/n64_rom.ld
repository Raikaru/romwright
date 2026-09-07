/* m5-004 fixture layout: IPL3 copies the game code to RDRAM and jumps to the
   boot address in the ROM header (n64brew "ROM header": 0x08). 0x80000400 is
   the conventional entry, just above the interrupt vectors. */
ENTRY(n64_main)

SECTIONS {
    . = 0x80000400;
    .text : { *(.text .text.*) }
    .rodata : ALIGN(8) { *(.rodata .rodata.*) }
    .bss (NOLOAD) : ALIGN(8) { *(.bss .bss.*) }
    /DISCARD/ : { *(.MIPS.abiflags) *(.reginfo) *(.comment) *(.pdr) *(.gnu.attributes) }
}
