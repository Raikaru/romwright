/* m5-002 fixture layout: the ARM9 image runs from main RAM (gbatek "DS
   Memory Map": 0x02000000, 4M on a retail DS). */
ENTRY(arm9_main)

SECTIONS {
    . = 0x02000000;
    .text : { *(.text .text.*) }
    .rodata : ALIGN(4) { *(.rodata .rodata.*) }
    .bss (NOLOAD) : ALIGN(4) { *(.bss .bss.*) }
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
