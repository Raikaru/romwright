/* m5-002 fixture layout: the ARM7 image runs from its own WRAM (gbatek "DS
   Memory Map": 0x037f8000, 64K shared/private split). */
ENTRY(arm7_main)

SECTIONS {
    . = 0x037f8000;
    .text : { *(.text .text.*) }
    .rodata : ALIGN(4) { *(.rodata .rodata.*) }
    .bss (NOLOAD) : ALIGN(4) { *(.bss .bss.*) }
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
