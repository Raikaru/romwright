#!/usr/bin/env python3
"""m8-004: the roots a PE declares itself -- TLS callbacks and exports.

`m8-001` reads the exception directory. Two more directories name code that
no call reaches, and neither was read:

  * `IMAGE_DIRECTORY_ENTRY_TLS` holds `AddressOfCallBacks`, a null-terminated
    array of callback addresses. Ghidra's `TLSDataDirectory` walks at most 20
    slots, stops at the first null, and makes each callback an external entry
    point; the addresses in that array are **virtual addresses**, not RVAs.
  * `IMAGE_DIRECTORY_ENTRY_EXPORT` holds `AddressOfFunctions`. Ghidra's
    `ExportDataDirectory` skips gap slots (RVA 0) and treats an RVA *inside*
    the export directory as a forwarder -- a string naming another library,
    not code -- while `PeLoader.processExports` makes every other export an
    external entry point carrying its exported name.

Measured before implementing: on `tiny_pe32.exe` the two TLS callbacks were
already recovered, but only because a base relocation happened to point at
them -- nothing recorded that the image *declares* them. In
`exports32.dll` the three exported functions were not recovered at all, from
the stripped or the unstripped image, because the importer reads no COFF
symbol table and nothing inside the image calls them.

Per fixture the gate requires:

  * every TLS callback to be a function carrying a `native-import:pe-tls`
    reference from the slot that named it;
  * every non-forwarded export to be a function carrying a
    `native-import:pe-export` reference from its `AddressOfFunctions` slot,
    **named as the image exports it**;
  * no function at a forwarder address.

Usage:
    python3 tests/m8-004_pe_roots.py [--report OUT.json]
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
MAX_CALLBACKS = 20  # Ghidra's cap, and the reason a corrupt array cannot run away


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


def tls_callbacks(data: bytes, base: int, at, width: int) -> list[tuple[int, int]]:
    """(slot address, callback address) pairs, as the loader would walk them."""
    m8_001 = sys.modules["m8_001"]
    rva, size = m8_001.data_directory(data, 9)
    if not rva or size < 4 * width:
        return []
    directory = at(rva, 6 * width)
    if len(directory) < 4 * width:
        return []
    field = "<Q" if width == 8 else "<I"
    callbacks_va = struct.unpack_from(field, directory, 3 * width)[0]
    if not callbacks_va:
        return []
    slots = []
    for index in range(MAX_CALLBACKS):
        slot_rva = callbacks_va - base + index * width
        raw = at(slot_rva, width)
        if len(raw) < width:
            break
        value = struct.unpack_from(field, raw)[0]
        if value == 0:
            break
        slots.append((base + slot_rva, value))
    return slots


def exports(data: bytes, base: int, at) -> list[dict]:
    m8_001 = sys.modules["m8_001"]
    rva, size = m8_001.data_directory(data, 0)
    if not rva or size < 40:
        return []
    header = at(rva, 40)
    (_, _, _, _, _, ordinal_base, count, name_count,
     functions_rva, names_rva, ordinals_rva) = struct.unpack_from("<IIHHIIIIIII", header)
    functions = struct.unpack_from(f"<{count}I", at(functions_rva, 4 * count))
    names = struct.unpack_from(f"<{name_count}I", at(names_rva, 4 * name_count))
    ordinals = struct.unpack_from(f"<{name_count}H", at(ordinals_rva, 2 * name_count))
    rows = []
    for index, function_rva in enumerate(functions):
        if function_rva == 0:  # a gap in the ordinal space, not an export
            continue
        label = None
        for position, ordinal in enumerate(ordinals):
            if ordinal == index:
                label = at(names[position], 128).split(b"\0")[0].decode()
                break
        rows.append({
            "ordinal": index + ordinal_base,
            "name": label,
            "address": base + function_rva,
            "slot": base + functions_rva + index * 4,
            "forwarded": rva <= function_rva < rva + size,
        })
    return rows


def store(image: Path, work: Path) -> tuple[dict[int, str], dict[int, set[tuple[int, str]]]]:
    project = work / f"{image.stem}-roots"
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(image),
         "--name", "roots", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"native import failed: {result.stderr.strip()}"
    database = sqlite3.connect(project / "project.sqlite")
    functions = {int(entry, 16): name
                 for entry, name in database.execute("SELECT entry, name FROM functions")}
    references: dict[int, set[tuple[int, str]]] = {}
    for source, destination, provenance in database.execute(
            "SELECT src, dst, provenance FROM xrefs"):
        references.setdefault(int(destination, 16), set()).add(
            (int(source, 16), provenance))
    return functions, references


def score(fixture: Path, work: Path) -> dict:
    m8_001 = sys.modules["m8_001"]
    data = fixture.read_bytes()
    base = m8_001.image_base(data)
    width = 8 if struct.unpack_from(
        "<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 24)[0] == 0x20B else 4
    at = reader(data)
    callbacks = tls_callbacks(data, base, at, width)
    exported = exports(data, base, at)
    functions, references = store(fixture, work)

    missing_callbacks, unproven_callbacks = [], []
    for slot, callback in callbacks:
        if callback not in functions:
            missing_callbacks.append(f"{callback:08x}")
        elif (slot, "native-import:pe-tls") not in references.get(callback, set()):
            unproven_callbacks.append(f"{callback:08x}")

    missing_exports, unproven_exports, misnamed = [], [], []
    for row in exported:
        if row["forwarded"]:
            continue
        if row["address"] not in functions:
            missing_exports.append(f"{row['address']:08x} {row['name']}")
            continue
        if (row["slot"], "native-import:pe-export") not in references.get(
                row["address"], set()):
            unproven_exports.append(f"{row['address']:08x} {row['name']}")
        if row["name"] and functions[row["address"]] != row["name"]:
            misnamed.append(f"{row['address']:08x} is "
                            f"{functions[row['address']]!r}, exported as {row['name']!r}")

    forwarder_functions = [f"{row['address']:08x}" for row in exported
                           if row["forwarded"] and row["address"] in functions]
    return {
        "id": fixture.name,
        "functions": len(functions),
        "metrics": {
            "pe.tls.callbacks": len(callbacks),
            "pe.tls.missing": len(missing_callbacks),
            "pe.tls.unproven": len(unproven_callbacks),
            "pe.exports": sum(1 for row in exported if not row["forwarded"]),
            "pe.exports.forwarded": sum(1 for row in exported if row["forwarded"]),
            "pe.exports.missing": len(missing_exports),
            "pe.exports.unproven": len(unproven_exports),
            "pe.exports.misnamed": len(misnamed),
            "pe.exports.forwarder_functions": len(forwarder_functions),
        },
        "provenance_proven": sorted(
            {provenance for targets in references.values()
             for _, provenance in targets
             if provenance.startswith("native-import:pe-")}),
        "callbacks": [f"{callback:08x}" for _, callback in callbacks],
        "exported": [f"{row['address']:08x} {row['name']}" for row in exported
                     if not row["forwarded"]],
        "failures": {"tls_missing": missing_callbacks,
                     "tls_unproven": unproven_callbacks,
                     "exports_missing": missing_exports,
                     "exports_unproven": unproven_exports,
                     "misnamed": misnamed,
                     "forwarder_functions": forwarder_functions},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    load_m8_001()
    rows = []
    with tempfile.TemporaryDirectory(prefix="m8-004-") as directory:
        work = Path(directory)
        for name in FIXTURES:
            fixture = ROOT / "tests/fixtures-src" / name
            assert fixture.is_file(), f"missing committed fixture {name}"
            rows.append(score(fixture, work))

    for row in rows:
        for label, failures in row["failures"].items():
            assert not failures, f"{row['id']}: {label}: {failures[:6]}"
    assert sum(row["metrics"]["pe.tls.callbacks"] for row in rows) > 0, (
        "no fixture exercises a TLS callback array")
    assert sum(row["metrics"]["pe.exports"] for row in rows) > 0, (
        "no fixture exercises an export directory")

    totals = {name: sum(row["metrics"][name] for row in rows)
              for name in rows[0]["metrics"]}
    summary = (f"{len(rows)} PE fixtures: {totals['pe.tls.callbacks']} TLS "
               f"callbacks and {totals['pe.exports']} exports recovered, each "
               f"with the reference that named it, exported names applied, "
               f"{totals['pe.exports.forwarded']} forwarders left alone")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m8-004",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "totals": totals,
            "fixtures": rows,
        }, indent=1) + "\n")
    print(f"m8-004: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
