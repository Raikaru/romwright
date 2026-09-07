/* m5-001 gate fixture layout: cartridge ROM at 0x08000000 (gbatek "Memory
   Map"), with the documented 192-byte header ahead of the code. The header
   holds the entry branch at offset 0 and the fixed 0x96 at offset 0xB2 that
   identifies a cartridge image. */
ENTRY(_rom_entry)

MEMORY {
    rom (rx) : ORIGIN = 0x08000000, LENGTH = 32M
    iwram (rwx) : ORIGIN = 0x03000000, LENGTH = 32K
}

SECTIONS {
    .header 0x08000000 : {
        KEEP(*(.gba_header))
    } > rom

    .text : ALIGN(4) {
        *(.text .text.*)
    } > rom

    .rodata : ALIGN(4) {
        *(.rodata .rodata.*)
    } > rom

    .bss (NOLOAD) : ALIGN(4) {
        *(.bss .bss.*)
    } > iwram

    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
