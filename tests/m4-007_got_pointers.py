#!/usr/bin/env python3
"""m4-007: the words the ABI reserves hold pointers, and the store says so.

`m4-006` proved the resolver word makes the PLT header's jump a call. The
header also *reads* the link-map word (`DT_PLTGOT + 1 pointer`), and the store
holds no width for it, so the decompiler puts a one-byte label there and then
synthesises a wider global of its own over it:

    /* WARNING: Globals starting with '_' overlap smaller symbols at the same
       address */ void _plt(void){(*PTR_002038e8)();return;}

The same System V reservation that named the resolver names all three words --
`.dynamic`, the link-map, the resolver -- and each is a pointer. That is a
data-definition fact: an address, a type and a width, with the ABI tag as its
evidence. The store gains a place for it, because "this location holds typed
data" is a program-model fact and strings were the only shape it could hold.

Assertions
  1. The store records a pointer definition at each reserved `DT_PLTGOT` word,
     recomputed here from the ELF, with the pointer width of the image and a
     provenance that names the rule.
  2. Nothing else is defined: the rule adds no definition anywhere else.
  3. The PLT header decompiles with no overlap warning and still names the
     resolver slot as a pointer.
  4. An image with no `DT_PLTGOT` gains no definitions.

Usage:
    python3 tests/m4-007_got_pointers.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
ROW = "x86_64_plain_o0"
PE = ROOT / "tests/fixtures-src/tiny_pe32.exe"
OVERLAP = re.compile(r"Globals starting with '_' overlap")


def environment() -> dict[str, str]:
    values = dict(os.environ)
    for name in ("VENTRIS_SLA", "VENTRIS_LANGUAGE", "VENTRIS_LANGUAGE_DIR",
                 "VENTRIS_SPECS", "VENTRIS_REGISTER_PARAMS",
                 "VENTRIS_PROMOTE_TAILCALLS"):
        values.pop(name, None)
    return values


def cli(*arguments: str, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([str(CLI), *arguments], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout, env=environment())


def ram(cell: str) -> int | None:
    try:
        return int(cell, 16)
    except ValueError:
        pass
    try:
        decoded = json.loads(cell)
    except json.JSONDecodeError:
        return None
    return decoded.get("offset") if decoded.get("space") == "Ram" else None


def definitions(project: Path, program: str) -> list[dict]:
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        rows = []
        for address, data_type, size, provenance in connection.execute(
                "SELECT address, type, size, provenance FROM data_definitions "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(address)
            if offset is not None:
                rows.append({"address": offset, "type": data_type, "size": size,
                             "provenance": provenance})
        return sorted(rows, key=lambda row: row["address"])
    finally:
        connection.close()


def elf_facts(binary: Path) -> dict:
    dynamic = subprocess.run(["readelf", "-d", str(binary)], capture_output=True,
                             text=True, check=True).stdout
    match = re.search(r"\(PLTGOT\)\s+(0x[0-9a-f]+)", dynamic)
    assert match, f"{binary.name} declares no DT_PLTGOT"
    header = subprocess.run(["readelf", "-hW", str(binary)], capture_output=True,
                            text=True, check=True).stdout
    width = 8 if "ELF64" in header else 4
    sections = subprocess.run(["readelf", "-SW", str(binary)], capture_output=True,
                              text=True, check=True).stdout
    plt = re.search(r"\.plt\s+PROGBITS\s+([0-9a-f]+)", sections)
    assert plt, f"{binary.name} has no .plt section"
    return {"pltgot": int(match.group(1), 16), "width": width,
            "plt": int(plt.group(1), 16)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True, env=environment())
    subprocess.run(["cargo", "build", "-q", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())

    lock = json.loads(LOCK.read_text())
    recipe = next(row for row in lock["entries"]
                  if f"{row['architecture']}_{row['variant']}" == ROW)
    binary = (arguments.corpus_dir / recipe["binary"]).resolve()
    assert binary.is_file(), f"{binary} is missing"
    elf = elf_facts(binary)
    reserved = [elf["pltgot"] + index * elf["width"] for index in range(3)]

    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-007-") as directory:
        work = Path(directory)
        project = work / "project"
        imported = cli("import", str(binary), "--project", str(project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        rows = definitions(project, binary.name)

        # 1. Each reserved word is a pointer of the image's width.
        held = {row["address"]: row for row in rows}
        missing = [f"{address:08x}" for address in reserved if address not in held]
        assert not missing, (
            f"the store defines no pointer at these reserved DT_PLTGOT words: "
            f"{missing}; it holds {[f'{r['address']:08x}' for r in rows]}")
        for address in reserved:
            row = held[address]
            assert row["type"] == "pointer", (
                f"{address:08x} is defined as {row['type']!r}, not a pointer")
            assert row["size"] == elf["width"], (
                f"{address:08x} is {row['size']} bytes wide, not {elf['width']}")
            assert "plt-reserved" in row["provenance"], (
                f"{address:08x} does not name the rule: {row['provenance']!r}")

        # 2. Nothing else is defined by this rule.
        stray = [f"{row['address']:08x}" for row in rows
                 if "plt-reserved" in row["provenance"] and row["address"] not in reserved]
        assert not stray, f"the rule defined data outside the reserved words: {stray}"
        findings["reserved"] = [f"{address:08x}" for address in reserved]

        # 3. The header decompiles without the decompiler inventing a global.
        text = cli("decompile", str(binary), f"{elf['plt']:08x}",
                   "--project", str(project), timeout=arguments.timeout)
        assert text.returncode == 0, f"decompile failed: {text.stderr.strip()}"
        assert not OVERLAP.search(text.stdout), (
            f"the decompiler still overlays a wider global of its own: "
            f"{text.stdout.strip()[:300]}")
        assert f"PTR_{reserved[2]:08x}" in text.stdout, (
            f"the resolver slot is no longer named as a pointer: "
            f"{text.stdout.strip()[:300]}")
        findings["header"] = text.stdout.strip()[:200]

        # 4. No DT_PLTGOT, no definitions.
        pe = work / PE.name
        shutil.copy2(PE, pe)
        pe_project = work / "pe"
        pe_import = cli("import", str(pe), "--project", str(pe_project),
                        timeout=arguments.timeout)
        assert pe_import.returncode == 0, (
            f"PE import failed: {pe_import.stderr.strip()}")
        invented = [item for item in definitions(pe_project, pe.name)
                    if "plt-reserved" in item["provenance"]]
        assert not invented, f"a PE image gained reserved-word definitions: {invented}"
        findings["pe_definitions"] = len(definitions(pe_project, pe.name))

    metrics = {"got.reserved_definitions": len(reserved),
               "got.pointer_width": elf["width"],
               "got.overlap_warnings": 0,
               "got.pe_definitions": findings["pe_definitions"]}
    summary = (f"the {len(reserved)} words DT_PLTGOT reserves are defined as "
               f"{elf['width']}-byte pointers ({', '.join(findings['reserved'])}) with "
               f"the tag as their evidence, the PLT header decompiles with no "
               f"overlapping global of the decompiler's own, and a PE image with no "
               f"DT_PLTGOT gains none")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-007",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "reserved": findings["reserved"],
            "header": findings["header"],
        }, indent=1) + "\n")
    print(f"m4-007: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
