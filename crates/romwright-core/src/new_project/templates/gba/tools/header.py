#!/usr/bin/env python3
"""Write asm/header.s, the cartridge header unit: header.py [--check]

The header is the first 0xC0 bytes of the ROM: the entry branch, the Nintendo logo
(read from your retail image with `.incbin`: it is not stored here), the title,
game and maker codes, the fixed 0x96 byte, unit/device codes, the version and the
header's complement check. The complement check is *computed* from the fields in
config/header.json (the BIOS's rule, -(sum(0xA0..0xBC) + 0x19) & 0xFF), so a
project that edits a field keeps a valid header; if the retail byte is not what
the rule gives (a patched ROM), the retail byte is kept and a note says so.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def complement(fields):
    total = sum(fields) + 0x19
    return (-total) & 0xFF


def main():
    config = json.loads((ROOT / "config" / "header.json").read_text())
    project = json.loads((ROOT / "config" / "project.json").read_text())
    orig = project["image"]["orig"]
    covered = bytes.fromhex(config["title"]) + bytes.fromhex(config["game_code"]) + bytes.fromhex(config["maker_code"])
    covered += bytes([config["fixed"], config["main_unit"], config["device_type"]]) + bytes.fromhex(config["reserved_b5"])
    covered += bytes([config["version"]])
    computed = complement(covered)
    stored = config["complement"]
    if computed != stored:
        print(f"note: the retail header complement {stored:#04x} is not the BIOS rule's {computed:#04x}; the retail byte is kept", file=sys.stderr)
    value = computed if computed == stored else stored

    def bytes_line(label, data):
        return f"\t.byte {', '.join(f'{b:#04x}' for b in data)}\t@ {label}\n"

    text = ".section .text, \"ax\"\n.arm\n\t.global header_entry\nheader_entry:\n"
    text += f"\t.4byte {int.from_bytes(bytes.fromhex(config['entry']), 'little'):#010x}\t@ entry branch\n"
    text += f"\t.incbin \"{orig}\", 4, 156\t@ Nintendo logo (retail bytes)\n"
    text += bytes_line("title", bytes.fromhex(config["title"]))
    text += bytes_line("game code", bytes.fromhex(config["game_code"]))
    text += bytes_line("maker code", bytes.fromhex(config["maker_code"]))
    text += bytes_line("fixed 0x96, main unit, device type", bytes([config["fixed"], config["main_unit"], config["device_type"]]))
    text += bytes_line("reserved", bytes.fromhex(config["reserved_b5"]))
    text += bytes_line("software version", bytes([config["version"]]))
    text += bytes_line("complement check (computed)", bytes([value]))
    text += bytes_line("reserved", bytes.fromhex(config["reserved_be"]))
    out = ROOT / "asm" / "header.s"
    out.parent.mkdir(parents=True, exist_ok=True)
    if not out.exists() or out.read_text() != text:
        out.write_text(text)
    print(f"asm/header.s: complement check {value:#04x}")


if __name__ == "__main__":
    main()
