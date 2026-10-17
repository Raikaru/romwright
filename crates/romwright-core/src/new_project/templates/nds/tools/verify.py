#!/usr/bin/env python3
"""Check the built ROM against the retail checksum: verify.py BUILT CHECKSUM_FILE STAMP

On a mismatch, say where: the first differing offset and the ROM region it falls in
(read from the built ROM's own header), so a failing swap points at its cause.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def region(rom, offset):
    arm9_off, _entry, _ram, arm9_size = struct.unpack_from("<IIII", rom, 0x20)
    arm7_off, _entry7, _ram7, arm7_size = struct.unpack_from("<IIII", rom, 0x30)
    fnt_off, fnt_size, fat_off, fat_size = struct.unpack_from("<IIII", rom, 0x40)
    y9_off, y9_size, y7_off, y7_size = struct.unpack_from("<IIII", rom, 0x50)
    spans = [
        ("header", 0, 0x4000), ("ARM9 program", arm9_off, arm9_size), ("ARM9 overlay table", y9_off, y9_size),
        ("ARM7 program", arm7_off, arm7_size), ("file name table", fnt_off, fnt_size), ("file allocation table", fat_off, fat_size),
    ]
    for name, start, size in spans:
        if start <= offset < start + size:
            return f"{name} ({start:#x}..{start + size:#x})"
    return "overlay or file data"


def main():
    built, checksum, stamp = (Path(arg) for arg in sys.argv[1:4])
    expected = checksum.read_text().split()[0]
    data = built.read_bytes()
    got = hashlib.sha1(data).hexdigest()
    if got == expected:
        stamp.write_text(got + "\n")
        print(f"OK  {built}  sha1 {got}")
        return
    project = json.loads((ROOT / "config" / "project.json").read_text())
    original = ROOT / project["image"]["orig"]
    message = [f"MISMATCH  {built}\n  expected sha1 {expected}\n  built    sha1 {got}  ({len(data)} bytes)"]
    if original.exists():
        retail = original.read_bytes()
        if len(retail) != len(data):
            message.append(f"  size differs: retail {len(retail)} bytes, built {len(data)}")
        diffs = [i for i in range(min(len(retail), len(data))) if retail[i] != data[i]]
        if diffs:
            message.append(f"  {len(diffs)} byte(s) differ; first at offset {diffs[0]:#x} in the {region(data, diffs[0])}")
    sys.exit("\n".join(message))


main()
