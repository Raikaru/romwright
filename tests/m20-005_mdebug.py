#!/usr/bin/env python3
"""m20-005: MIPS .debug (mdebug) ingestion agrees with the symtab.

SLUS_209.50's `.debug` section is Metrowerks CodeWarrior DWARF 1, not
ECOFF: a flat DIE stream whose length field includes itself and whose
attribute codes pack (attribute << 4) | form. The importer's mdebug
reader recovers every subroutine DIE's name, low_pc, and high_pc; on
this image all 5221 of them coincide with FUNC symtab entries, so the
gate is agreement plus no regression rather than a count delta. The
`mdebug` phase in --timings output proves the reader ran and produced
rows.

Usage:
    python3 tests/m20-005_mdebug.py [--images-dir DIR] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = Path.home() / "romwright-corpus/extracted/ps2-capcom-fighting-evolution"
IMAGE = "SLUS_209.50"

# DWARF 1 tags and attributes the reader consumes.
TAG_SUBROUTINE = {0x06, 0x14, 0x1F}
AT_NAME = 0x003
AT_LOW_PC = 0x011
AT_HIGH_PC = 0x012
FORM_SIZE = {1: 4, 2: 4, 5: 2, 6: 4, 7: 8}

TIMINGS = re.compile(r"^TIMINGS (\{.*\})$", re.M)


def dwarf1_subroutines(debug: bytes) -> dict[int, tuple[str, int]]:
    """Named subroutine DIEs: low_pc -> (name, high_pc - low_pc)."""
    subs: dict[int, tuple[str, int]] = {}
    off = 0
    while off + 6 <= len(debug):
        (length,) = struct.unpack_from("<I", debug, off)
        if length < 6:
            off += max(length, 4)
            continue
        end = off + length
        if end > len(debug):
            break
        (tag,) = struct.unpack_from("<H", debug, off + 4)
        p = off + 6
        name = None
        low = high = None
        while p + 2 <= end:
            (code,) = struct.unpack_from("<H", debug, p)
            p += 2
            attr, form = code >> 4, code & 0xF
            if form in FORM_SIZE:
                size = FORM_SIZE[form]
                if attr in (AT_LOW_PC, AT_HIGH_PC):
                    (value,) = struct.unpack_from("<I", debug, p)
                    if attr == AT_LOW_PC:
                        low = value
                    else:
                        high = value
                p += size
            elif form == 3:
                (n,) = struct.unpack_from("<H", debug, p)
                p += 2 + n
            elif form == 4:
                (n,) = struct.unpack_from("<I", debug, p)
                p += 4 + n
            elif form == 8:
                nul = debug.index(b"\0", p)
                if attr == AT_NAME:
                    name = debug[p:nul].decode("latin1")
                p = nul + 1
            else:
                break
        if tag in TAG_SUBROUTINE and low and name:
            subs[low] = (name, (high - low) if high else 0)
        off = end
    return subs


def symtab_functions(image: Path) -> dict[int, tuple[str, int]]:
    """Defined FUNC symbols: address -> (name, size)."""
    output = subprocess.run(["readelf", "-sW", str(image)], capture_output=True,
                            text=True, check=True).stdout
    functions: dict[int, tuple[str, int]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[3] != "FUNC":
            continue
        address = int(parts[1], 16)
        if address:
            functions[address] = (parts[7], int(parts[2]))
    return functions


def debug_section(image: Path) -> bytes:
    """The SHT_MIPS_DEBUG `.debug` section's bytes."""
    data = image.read_bytes()
    sections = subprocess.run(["readelf", "-SW", str(image)],
                              capture_output=True, text=True, check=True).stdout
    for line in sections.splitlines():
        match = re.search(r"\.debug\s+MIPS_DEBUG\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)",
                          line)
        if match:
            off, size = int(match.group(1), 16), int(match.group(2), 16)
            return data[off:off + size]
    raise AssertionError("no MIPS_DEBUG .debug section")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-005",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "status": "skipped"}
    image = arguments.images_dir / IMAGE
    if not image.is_file():
        report["reason"] = "images absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"
    with tempfile.TemporaryDirectory(prefix="m20-005-") as temporary:
        project = Path(temporary) / "project"
        # The import cache would serve a stored DB with no phase timings;
        # the gate needs the reader to actually run.
        env = dict(os.environ, ROMWRIGHT_NO_IMPORT_CACHE="1")
        imported = subprocess.run(
            [str(cli), "import", str(image), "--no-analysis",
             "--name", "ps2", "--project", str(project), "--timings"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800, env=env)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        # The mdebug phase only exists when the reader found and parsed a
        # debug stream into at least one function.
        timings = TIMINGS.search(imported.stdout)
        assert timings, f"no TIMINGS line: {imported.stdout.strip()}"
        phases = json.loads(timings.group(1))["phases"]
        assert "mdebug" in phases, f"no mdebug phase: {phases}"

        store = sqlite3.connect(project / "project.sqlite")
        functions = {int(entry, 16): (name, size) for entry, name, size in
                     store.execute("SELECT entry, name, size FROM functions")}

        truth = symtab_functions(image)
        subs = dwarf1_subroutines(debug_section(image))
        assert len(subs) > 5000, f"gate's own DWARF1 parse found {len(subs)}"

        # 1. No regression: every symtab FUNC kept its name.
        missing = [a for a in truth if a not in functions]
        renamed = [a for a, (n, _) in truth.items()
                   if a in functions and functions[a][0] != n]
        assert not missing, f"{len(missing)} symtab functions lost"
        assert not renamed, (
            f"{len(renamed)} symtab names overwritten, e.g. "
            f"{renamed[0]:#x}: {truth[renamed[0]][0]} -> {functions[renamed[0]][0]}")

        # 2. The debug stream adds coverage, never subtracts it.
        assert len(functions) >= len(truth), (
            f"{len(functions)} functions < {len(truth)} symtab FUNCs")

        # 3. DWARF/symtab agreement: every named subroutine DIE lands on a
        # function carrying the same name and the same byte size.
        disagree = [(a, n) for a, (n, sz) in subs.items()
                    if a not in functions
                    or functions[a][0] != n
                    or (sz and functions[a][1] != sz)]
        assert not disagree, (
            f"{len(disagree)} DWARF subroutines disagree, e.g. "
            f"{disagree[0][0]:#x} {disagree[0][1]}")

        summary = (f"{len(functions)} functions ({len(truth)} symtab FUNC), "
                   f"{len(subs)} DWARF1 subroutines all agreeing, "
                   f"mdebug phase {phases['mdebug']:.3f}s")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"functions": len(functions),
                               "symtab_func": len(truth),
                               "dwarf1_subroutines": len(subs)})
        print(f"m20-005: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
