#!/usr/bin/env python3
"""Check the built image against the retail checksum: verify.py BUILT CHECKSUM_FILE STAMP

On a mismatch, say where: the first differing offset, the address it maps to
and the function that contains it, so a failing swap points at its cause.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def functions():
    rows = []
    for line in (ROOT / "config" / "symbol_addrs.txt").read_text().splitlines():
        match = re.match(r"(\S+) = (0x[0-9a-fA-F]+); // type:func(?: size:(0x[0-9a-fA-F]+))?", line)
        if match:
            rows.append((int(match.group(2), 16), int(match.group(3) or "0", 16), match.group(1)))
    return sorted(rows)


def locate(offset, layout):
    for seg in layout:
        if seg["offset"] <= offset < seg["offset"] + seg["size"]:
            vaddr = seg["vaddr"] + offset - seg["offset"]
            owner = ""
            for start, size, name in functions():
                if start <= vaddr and (vaddr < start + size or (size == 0 and vaddr < start + 4)):
                    owner = f" in {name}"
            return f"offset {offset:#x} = vaddr {vaddr:#x}{owner}"
    return f"offset {offset:#x} (outside the loaded image: header or trailer)"


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
        diff = next((i for i in range(min(len(retail), len(data))) if retail[i] != data[i]), None)
        if diff is not None:
            message.append("  first difference: " + locate(diff, project["layout"]))
    sys.exit("\n".join(message))


main()
