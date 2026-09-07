@ m5-001 gate fixture: the documented Game Boy Advance cartridge header
@ (gbatek "Cartridge Header"). Only the fields a loader must read are real:
@ the entry branch at 0x00 and the fixed 0x96 at 0xB2. The Nintendo logo
@ bytes are not reproduced -- they are the BIOS's check, not the loader's,
@ and copying them here would put someone else's data in this repository.
    .section .gba_header, "ax"
    .arm
    .global _rom_entry
_rom_entry:
    b       game_main               @ 0x00: ROM entry point
    .space  0x9c, 0                 @ 0x04: logo area, deliberately blank
    .ascii  "VENTRISGATE"           @ 0xa0: game title (12 bytes)
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
