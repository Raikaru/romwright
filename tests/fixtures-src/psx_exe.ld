/* m5-003 fixture layout: PlayStation executables load into main RAM above
   the BIOS work area (psx-spx "Memory Map": 2 MB at 0x80000000, KSEG0). */
ENTRY(psx_main)

SECTIONS {
    . = 0x80010000;
    .text : { *(.text .text.*) }
    .rodata : ALIGN(4) { *(.rodata .rodata.*) }
    .bss (NOLOAD) : ALIGN(4) { *(.bss .bss.*) }
    /DISCARD/ : { *(.MIPS.abiflags) *(.reginfo) *(.comment) *(.pdr) *(.gnu.attributes) }
}
