#!/usr/bin/env python3
"""m8-005: a PE's imports, named the way an ELF's are.

An ELF import lands in the store as an external symbol at the slot the loader
fills, and the stub that jumps through that slot takes the imported name --
`002038f0 printf external=1` with `00201720 printf` jumping to it
(`m5-009`). A PE had **none of that**: `tiny_pe32.exe` imported into a store
with zero symbols, because nothing read
`IMAGE_DIRECTORY_ENTRY_IMPORT`.

The rules are Ghidra's, from `ImportDataDirectory.parse`,
`ImportDescriptor` and `ThunkData`:

  * descriptors are 20 bytes and end when `OriginalFirstThunk` and
    `FirstThunk` are both zero;
  * the name table is `OriginalFirstThunk` when it maps, otherwise
    `FirstThunk`; it is walked in lockstep with the IAT and ends at the first
    zero entry;
  * a thunk with the ordinal flag set (`0x80000000`, or `1 << 63` for PE32+)
    imports by ordinal and is named `Ordinal_<n>`; otherwise its value is an
    RVA to `IMAGE_IMPORT_BY_NAME`, whose name follows a two-byte hint;
  * the address an import occupies is its **IAT slot**, `FirstThunk + offset`;
  * `TimeDateStamp != 0` means the image is bound and its IAT already holds
    resolved addresses -- values that are not in-image code.

Per fixture the gate requires the store to hold exactly the imports the image
declares: one external symbol per IAT slot, named as imported, and every stub
that jumps through such a slot named after the import rather than `FUN_...`.

Usage:
    python3 tests/m8-005_pe_imports.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sqlite3
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from gen_corpus import parse_pe_info  # noqa: E402

FIXTURES = ["tiny_pe.exe", "dispatch.exe", "tiny_pe32.exe", "exports32.dll"]
DESCRIPTOR = 20
MAX_SANE = 0x2000


def load_m8_001():
    spec = importlib.util.spec_from_file_location(
        "m8_001", ROOT / "tests/m8-001_pe_unwind.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["m8_001"] = module
    spec.loader.exec_module(module)
    return module


def reader(data: bytes):
    sections = parse_pe_info(data)["sections"]

    def at(rva: int, size: int) -> bytes:
        for section in sections:
            if section["vaddr"] <= rva < section["vaddr"] + section["vsize"]:
                offset = section["raw_off"] + (rva - section["vaddr"])
                return data[offset:offset + size]
        return b""
    return at


def imports(data: bytes, base: int, at, width: int) -> tuple[list[dict], int]:
    """Every import as (slot address, name, library), and the bound count."""
    m8_001 = sys.modules["m8_001"]
    rva, size = m8_001.data_directory(data, 1)
    if not rva or size < DESCRIPTOR:
        return [], 0
    rows, bound = [], 0
    field = "<Q" if width == 8 else "<I"
    ordinal_flag = 1 << (width * 8 - 1)
    for index in range(size // DESCRIPTOR):
        descriptor = at(rva + index * DESCRIPTOR, DESCRIPTOR)
        if len(descriptor) < DESCRIPTOR:
            break
        original, stamp, _, name_rva, first = struct.unpack("<5I", descriptor)
        if original == 0 and first == 0:
            break
        library = at(name_rva, 128).split(b"\0")[0].decode(errors="replace")
        if stamp != 0:
            bound += 1
        names_rva = original or first
        for slot in range(MAX_SANE):
            entry = at(names_rva + slot * width, width)
            if len(entry) < width:
                break
            value = struct.unpack_from(field, entry)[0]
            if value == 0:
                break
            if value & ordinal_flag:
                label = f"Ordinal_{value & 0xFFFF}"
            else:
                label = at(int(value) + 2, 128).split(b"\0")[0].decode(errors="replace")
            rows.append({"slot": base + first + slot * width,
                         "name": label, "library": library})
    return rows, bound


def store(image: Path, work: Path) -> tuple[dict[int, tuple[str, int, str]],
                                            dict[int, str], list[tuple[int, int, str]]]:
    project = work / f"{image.stem}-imports"
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(image),
         "--name", "imports", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"native import failed: {result.stderr.strip()}"
    database = sqlite3.connect(project / "project.sqlite")
    symbols = {int(address, 16): (name, external, source) for address, name, external, source
               in database.execute("SELECT address, name, external, source FROM symbols")}
    functions = {int(entry, 16): name
                 for entry, name in database.execute("SELECT entry, name FROM functions")}
    thunks = [(int(function, 16), int(thunked, 16), kind) for function, thunked, kind
              in database.execute("SELECT function, thunked, kind FROM thunks")]
    return symbols, functions, thunks


def score(fixture: Path, work: Path) -> dict:
    m8_001 = sys.modules["m8_001"]
    data = fixture.read_bytes()
    base = m8_001.image_base(data)
    width = 8 if struct.unpack_from(
        "<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 24)[0] == 0x20B else 4
    declared, bound = imports(data, base, reader(data), width)
    symbols, functions, thunks = store(fixture, work)

    missing, misnamed, not_external = [], [], []
    for row in declared:
        held = symbols.get(row["slot"])
        if held is None:
            missing.append(f"{row['slot']:08x} {row['name']} ({row['library']})")
            continue
        name, external, _ = held
        if name != row["name"]:
            misnamed.append(f"{row['slot']:08x} is {name!r}, imported as {row['name']!r}")
        if not external:
            not_external.append(f"{row['slot']:08x} {row['name']}")

    # A stub that jumps through an import slot must carry the import's name.
    slots = {row["slot"]: row["name"] for row in declared}
    unnamed_stubs = []
    for function, thunked, kind in thunks:
        if thunked in slots and functions.get(function, "").startswith("FUN_"):
            unnamed_stubs.append(f"{function:08x} -> {thunked:08x} "
                                 f"({slots[thunked]}, {kind})")
    # An IAT slot holds a pointer the loader writes: it is data, and a
    # function there would be invented code -- the mistake a bound image
    # invites, since its slots already hold resolved addresses.
    invented = [f"{slot:08x} {name}" for slot, name in slots.items()
                if slot in functions]
    return {
        "id": fixture.name,
        "metrics": {
            "pe.imports.declared": len(declared),
            "pe.imports.libraries": len({row["library"] for row in declared}),
            "pe.imports.bound_descriptors": bound,
            "pe.imports.missing": len(missing),
            "pe.imports.misnamed": len(misnamed),
            "pe.imports.not_external": len(not_external),
            "pe.imports.unnamed_stubs": len(unnamed_stubs),
        },
        "libraries": sorted({row["library"] for row in declared}),
        "sample": [f"{row['slot']:08x} {row['library']}!{row['name']}"
                   for row in declared[:6]],
        "failures": {"missing": missing, "misnamed": misnamed,
                     "not_external": not_external,
                     "unnamed_stubs": unnamed_stubs, "invented": invented},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    load_m8_001()
    rows = []
    with tempfile.TemporaryDirectory(prefix="m8-005-") as directory:
        work = Path(directory)
        for name in FIXTURES:
            fixture = ROOT / "tests/fixtures-src" / name
            assert fixture.is_file(), f"missing committed fixture {name}"
            rows.append(score(fixture, work))

    for row in rows:
        for label, failures in row["failures"].items():
            assert not failures, f"{row['id']}: {label}: {failures[:6]}"
    assert sum(row["metrics"]["pe.imports.declared"] for row in rows) > 0, (
        "no fixture declares an import")

    totals = {name: sum(row["metrics"][name] for row in rows)
              for name in rows[0]["metrics"]}
    summary = (f"{len(rows)} PE fixtures: {totals['pe.imports.declared']} imports "
               f"from {totals['pe.imports.libraries']} library references, each "
               f"an external symbol at its IAT slot named as imported, every "
               f"stub through a slot named after its import")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m8-005",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "totals": totals,
            "fixtures": rows,
        }, indent=1) + "\n")
    print(f"m8-005: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
