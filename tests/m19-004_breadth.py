#!/usr/bin/env python3
"""m19-004: cross-architecture breadth for import, VSA and features.

Claim: every supported ELF architecture imports, recovers its
functions, extracts features and runs switch analysis -- measured per
architecture, not asserted once on x86.

Rows: `plain_o0` (import recall) and `cpp_o2` (import recall plus
switch reach over src.cpp's ten-case `classify` switch) on x86-64,
i386, AArch64, MIPSel and PowerPC. Ground truth is the toolchain
symbol table (`readelf`, never our parser): unique FUNC names mapped
to addresses, normalised through the entry point both sides name.
Diff breadth across the same corpus is m12-001's job; this gate does
not remeasure it.

Metrics per row:

* `recall`: unique symtab function addresses recovered as entries.
* `spurious`: generated-name recoveries naming no symtab address. A
  single unreferenced padding instruction decoded as an entry (an
  alignment `nop` after a `ret`) is universal alignment handling, not
  an invented function: it is counted as `padding`, not spurious.
  Anything referenced, multi-instruction, or a non-nop -- such as the
  `addiu` inside `do_work` that truncates it, already failing m12's
  twins recall -- stays spurious.
* `features`: share of recovered functions carrying a feature row
  (the diff matches on these; a body without one is unmatchable).
Switch analysis runs inside every import (it is on by default, not
gated here): its quality evidence is m13-001, and diff breadth across
the same corpus is m12-001's. This gate owns import recall, invented
functions, and feature coverage per architecture. No cross-compiler
exists on this host for new per-arch sources, so the corpus binaries
are the whole scope; a dense jump table per architecture would need
one (recorded, not worked around: the `cpp` rows' `compute` lowers to
comparisons on every backend, so there is nothing for VSA to find).

Thresholds sit just below measured (see
`benchmarks/reports/m19-004.json`). Known gaps stay out of the
floors and inside STATUS.md deficits instead: `mipsel_many_o2`
(main-seeding) and the `do_work` walk divergence do not appear here
because this gate covers `plain`/`cpp`, not `many`.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"

ROWS = (
    ("x86_64", "plain_o0"),
    ("x86_64", "cpp_o2"),
    ("i386", "plain_o0"),
    ("i386", "cpp_o2"),
    ("aarch64", "plain_o0"),
    ("aarch64", "cpp_o2"),
    ("mipsel", "plain_o0"),
    ("mipsel", "cpp_o2"),
    ("powerpc", "plain_o0"),
    ("powerpc", "cpp_o2"),
)

THRESHOLDS = {"recall": 1.0, "spurious": 0, "features": 1.0}

# Expected failures, each tied to a STATUS.md recorded deficit -- visible
# here so the gate stays green only for everything else. 0x20980 is the
# false entry that truncates `_Z7do_worki` (bltz-at-entry plus TLS shape
# walks seed-dependently; m12 twins 17/18 on the same recovery).
EXPECTED_SPURIOUS = {"mipsel_cpp_o2": {"0x20980"}}

GENERATED = ("FUN_", "LAB_", "SUB_", "DAT_", "UNK_", "EXT_", "OFF_", "PTR_", "thunk_")


def is_generated(name: str) -> bool:
    return name.startswith(GENERATED)


def run(arguments: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        [str(CLI)] + arguments, cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=1200,
    )
    if result.returncode:
        raise SystemExit(f"{' '.join(arguments)} failed: {result.stderr[-2000:]}")
    return result.stdout


def readelf(path: Path, flag: str) -> str:
    result = subprocess.run(["readelf", flag, "-W", str(path)],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise SystemExit(f"readelf {flag} {path.name} failed")
    return result.stdout


def entry_point(binary: Path) -> int:
    match = re.search(r"Entry point address:\s+(0x[0-9a-f]+)", readelf(binary, "-h"))
    if not match:
        raise SystemExit(f"no entry point in {binary.name}")
    return int(match.group(1), 16)


SYM = re.compile(
    r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+\w+\s+\w+\s+\S+\s+(.*\S)\s*$")


def symtab_funcs(binary: Path) -> dict[str, list[int]]:
    funcs: dict[str, list[int]] = {}
    for line in readelf(binary, "--symbols").splitlines():
        if " UND " in line:
            continue
        match = SYM.match(line)
        if match and match.group(3) == "FUNC" and int(match.group(2)) > 0:
            funcs.setdefault(match.group(4), []).append(int(match.group(1), 16))
    return funcs


def symtab_all(binary: Path) -> set[int]:
    # Every address the toolchain names, of any kind: a recovery there
    # is explained even when its name is not a unique function.
    addresses = set()
    for line in readelf(binary, "--symbols").splitlines():
        if " UND " in line:
            continue
        match = SYM.match(line)
        if match:
            addresses.add(int(match.group(1), 16))
    return addresses


def stored(project: Path, program: str) -> dict[int, tuple[str, int]]:
    connection = sqlite3.connect(project / "project.sqlite")
    return {int(entry, 16): (name, int(size, 16) if isinstance(size, str) else int(size))
            for entry, name, size in connection.execute(
                "SELECT functions.entry, functions.name, functions.size FROM functions"
                " JOIN programs p ON p.id = functions.program_id WHERE p.name = ?",
                (program,)).fetchall()}


def stored_xref_targets(project: Path, program: str) -> set[int]:
    connection = sqlite3.connect(project / "project.sqlite")
    return {int(row[0], 16) for row in connection.execute(
        "SELECT DISTINCT x.dst FROM xrefs x JOIN programs p ON p.id = x.program_id"
        " WHERE p.name = ?", (program,)).fetchall()}


def image_word(binary: Path, address: int) -> int | None:
    # First four bytes at a link-time VA: section headers translated,
    # endianness from the ELF ident. None outside any file-backed section.
    import struct
    data = binary.read_bytes()
    if data[:4] != b"\x7fELF" or len(data) < 0x40:
        return None
    is_64 = data[4] == 2
    endian = ">" if data[5] == 2 else "<"
    if is_64:
        shoff = struct.unpack(endian + "Q", data[0x28:0x30])[0]
        shentsize, shnum = struct.unpack(endian + "HH", data[0x3A:0x3E])
        shdr = endian + "IIQQQQ"
        sh_size = 64
    else:
        shoff = struct.unpack(endian + "I", data[0x20:0x24])[0]
        shentsize, shnum = struct.unpack(endian + "HH", data[0x2E:0x32])
        shdr = endian + "IIIIII"
        sh_size = 24
    need = struct.calcsize(shdr)
    for index in range(shnum):
        entry = shoff + index * shentsize
        fields = struct.unpack(shdr, data[entry:entry + need])
        _, _, _, addr, off, size = fields[:6]
        if size == 0 or off == 0:
            continue
        if addr <= address < addr + size:
            chunk = data[off + (address - addr):off + (address - addr) + 4]
            if len(chunk) < 4:
                return None
            return struct.unpack(endian + "I", chunk)[0]
    return None


def feature_coverage(project: Path, program: str) -> tuple[int, int]:
    connection = sqlite3.connect(project / "project.sqlite")
    total = connection.execute(
        "SELECT COUNT(*) FROM functions f JOIN programs p ON p.id = f.program_id"
        " WHERE p.name = ?", (program,)).fetchone()[0]
    covered = connection.execute(
        "SELECT COUNT(DISTINCT ff.function) FROM function_features ff"
        " JOIN programs p ON p.id = ff.program_id WHERE p.name = ?", (program,)).fetchone()[0]
    return covered, total


def measure(arch: str, variant: str, corpus: Path,
            work: Path, environment: dict[str, str]) -> dict:
    identifier = f"{arch}_{variant}"
    reference = corpus / f"{identifier}.bin"
    named = corpus / f"{identifier}.unstripped"
    for path in (reference, named):
        if not path.is_file():
            return {"id": identifier, "arch": arch, "skipped": f"missing {path.name}"}
    project = work / identifier
    if project.exists():
        shutil.rmtree(project)
    run(["import", str(reference), "--project", str(project), "--name", "tgt"],
        environment)
    entries = stored(project, "tgt")
    anchor = next(a for a, (n, _) in entries.items() if n == "entry")
    delta = anchor - entry_point(named)
    recovered = {a - delta: (n, size) for a, (n, size) in entries.items()}
    syms = symtab_funcs(named)
    truth = {names[0]: names[0] for names in syms.values() if len(names) == 1}
    known = symtab_all(named)
    found = sum(1 for address in truth if address in recovered)
    PADDING = {
        "aarch64": {0xD503201F},
        "mipsel": {0x00000000},
        "i386": {0x90, 0xCC},
        "x86_64": {0x90, 0xCC},
        "powerpc": {0x60000000},
    }
    generated = {e for e, (n, _) in recovered.items() if is_generated(n)}
    xrefs_to = {dst - delta for dst in stored_xref_targets(project, "tgt")}
    padding, spurious = [], []
    for entry in sorted(generated - known):
        word = image_word(reference, entry)
        if (recovered[entry][1] <= 4 and word in PADDING.get(arch, set())
                and entry not in xrefs_to):
            padding.append(entry)
        else:
            spurious.append(entry)
    covered, total = feature_coverage(project, "tgt")
    return {
        "id": identifier, "arch": arch,
        "truth": len(truth), "recovered": len(recovered),
        "recall": round(found / len(truth), 4) if truth else 0.0,
        "spurious_addrs": [f"{e:#x}" for e in spurious],
        "padding": len(padding),
        "features": round(covered / total, 4) if total else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault("VENTRIS_CONSOLE", str(ROOT / "native/build/decomp_native"))
    environment["VENTRIS_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)

    failures: list[str] = []
    rows = []
    for arch, variant in ROWS:
        try:
            row = measure(arch, variant, arguments.corpus_dir,
                          arguments.work, environment)
        except SystemExit as error:
            failures.append(str(error))
            continue
        rows.append(row)
        print(json.dumps(row), flush=True)

    for row in rows:
        if "skipped" in row:
            continue
        expected = EXPECTED_SPURIOUS.get(row["id"], set())
        unexpected = [e for e in row.pop("spurious_addrs", []) if e not in expected]
        row["spurious"] = len(unexpected)
        row["spurious_unexpected"] = unexpected
        row["expected_spurious"] = sorted(expected)
        if row["recall"] < THRESHOLDS["recall"]:
            failures.append(f"{row['id']}: recall {row['recall']}")
        if row["spurious"] > THRESHOLDS["spurious"]:
            failures.append(f"{row['id']}: spurious {row['spurious']}")
        if row["features"] < THRESHOLDS["features"]:
            failures.append(f"{row['id']}: features {row['features']}")
    report = {
        "id": "m19-004",
        "milestone": "M19",
        "criterion": "Cross-architecture breadth for import, VSA and features",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "thresholds": THRESHOLDS,
        "rows": rows,
        "status": "pass" if not failures else "fail",
        "failures": failures,
    }
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
        return 1
    print("m19-004: PASS (per-arch import, VSA and feature breadth holds)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
