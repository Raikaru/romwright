#!/usr/bin/env python3
"""Check the built ROM against the retail checksum: verify.py BUILT CHECKSUM_FILE STAMP

On a mismatch, say where: the first differing offset, the address it maps to and
the unit that contains it, so a failing swap points at its cause.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def locate(offset, project):
    base = project["image"]["base"]
    address = base + offset
    for unit in json.loads((ROOT / "config" / "units.json").read_text()):
        if unit["start"] <= address < unit["end"]:
            return f"offset {offset:#x} = address {address:#010x} in {unit['kind']} unit {unit['name']} ({unit['start']:#x}..{unit['end']:#x})"
    return f"offset {offset:#x} = address {address:#010x}"


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
            message.append("  first difference: " + locate(diff, project))
    sys.exit("\n".join(message))


main()
