@ m5-001 gate fixture: the documented Game Boy Advance cartridge header
@ (gbatek "Cartridge Header"). Only the fields a loader must read are real:
@ the entry branch at 0x00, the first eight logo bytes, and the fixed 0x96 at
@ 0xB2. The logo *is* a loader check, not only the BIOS's: Ghidra's GBA loader
@ reads bytes 4..12 and refuses a cartridge that does not carry them
@ (`GBALoader.findSupportedLoadSpecs`), so with them blank the oracle cannot
@ load this fixture at all and the language it selects -- ARM:LE:32:v4t --
@ stays unmeasurable. Eight bytes of format magic are reproduced for that
@ reason; the remaining 148 bytes of the logo bitmap are not.
    .section .gba_header, "ax"
    .arm
    .global _rom_entry
_rom_entry:
    b       game_main               @ 0x00: ROM entry point
    .byte   0x24, 0xff, 0xae, 0x51  @ 0x04: logo magic a loader identifies by
    .byte   0x69, 0x9a, 0xa2, 0x21
    .space  0x94, 0                 @ 0x0c: rest of the logo area, blank
    .ascii  "ROMWRIGHTGATE"           @ 0xa0: game title (12 bytes)
    .byte   0
    .ascii  "VGAT"                  @ 0xac: game code
    .ascii  "VT"                    @ 0xb0: maker code
    .byte   0x96                    @ 0xb2: fixed value
    .byte   0x00                    @ 0xb3: main unit code
    .byte   0x00                    @ 0xb4: device type
    .space  7, 0                    @ 0xb5: reserved
    .byte   0x00                    @ 0xbc: software version
    .byte   0x00                    @ 0xbd: complement check
    .space  2, 0                    @ 0xbe: reserved
