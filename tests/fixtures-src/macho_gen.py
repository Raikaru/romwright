#!/usr/bin/env python3
"""Minimal thin-64 Mach-O fixture generator.

Emits a valid `0xFEEDFACF` little-endian image: one `__TEXT` segment
with a two-instruction function, one `__DATA` segment, a two-symbol
`LC_SYMTAB`, and `LC_MAIN`. Ground truth for the m1-010 gate is this
file's construction, not a stock oracle.

Usage: macho_gen.py <out>
"""

import struct
import sys


def main() -> int:
    out = sys.argv[1]
    text_vaddr = 0x100000000
    data_vaddr = 0x100001000
    code = bytes([0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3])  # mov eax,7; ret
    data = bytes([0x01, 0x02, 0x03, 0x04])
    strtab = b'\x00_main\x00_helper\x00'
    ncmds = 4
    header_len = 32
    cmds_len = 72 + 72 + 24 + 24
    text_off = header_len + cmds_len
    data_off = text_off + len(code)
    sym_off = data_off + len(data)
    str_off = sym_off + 2 * 16
    # Patch file offsets into the segment commands.
    text_cmd = (struct.pack('<2I16s2Q', 0x19, 72, b'__TEXT', text_vaddr, 0x1000)
                + struct.pack('<2Q', text_off, len(code))
                + struct.pack('<4I', 5, 5, 0, 0))
    data_cmd = (struct.pack('<2I16s2Q', 0x19, 72, b'__DATA', data_vaddr, 0x1000)
                + struct.pack('<2Q', data_off, len(data))
                + struct.pack('<4I', 3, 3, 0, 0))
    sym_cmd = struct.pack('<6I', 0x2, 24, sym_off, 2, str_off, len(strtab))
    main_cmd = struct.pack('<2I2Q', 0x80000028, 24, text_off, 0)
    header = struct.pack('<8I', 0xFEEDFACF, 0x01000007, 3, 2, ncmds,
                         cmds_len, 0, 0)
    sym0 = struct.pack('<IBBHQ', 1, 0x0F, 1, 0, text_vaddr)
    sym1 = struct.pack('<IBBHQ', 7, 0x0F, 1, 0, text_vaddr)
    blob = (header + text_cmd + data_cmd + sym_cmd + main_cmd
            + code + data + sym0 + sym1 + strtab)
    with open(out, 'wb') as handle:
        handle.write(blob)
    print(f'macho {len(blob)} bytes, text @{text_vaddr:#x}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
