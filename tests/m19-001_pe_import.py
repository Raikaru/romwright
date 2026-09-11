#!/usr/bin/env python3
"""m19-001: PE import measured against external truth.

Claim: importing a Windows PE recovers the functions its own toolchain
declares -- no more, no fewer than the floors allow.

One pair: `tests/corpus-src/many.c` built with mingw-w64 as PE32+
DLLs, `-O0` and `-O2 -fno-inline`, stripped for the measured import
with unstripped twins for truth. Ground truth is the toolchain symbol
table (`mingw-nm`, never our parser): unique text-symbol names mapped
to addresses with no base adjustment (our loader keeps link VAs).
Runs in seconds.

Deliberately not gated here: retail PE images. Large retail imports
cost tens of minutes per run for no additional signal over this pair
-- same metrics, same code paths -- so they stay out of the test
loop entirely, and out of the corpus by user direction.

Metrics (per pair):

* `recall`: unique truth addresses recovered as function entries.
* `spurious`: recovered entries with generated names (`FUN_...`)
  naming no toolchain address at all -- invented functions. Named
  recoveries (import stubs take the imported name) are outside this
  denominator by construction.

Thresholds, set from what was measured (see
`benchmarks/reports/m19-001.json`): floors sit just below measured to
catch collapse and nothing else.
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
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Floors sit just below measured.
THRESHOLDS = {"recall": 0.97, "spurious": 0}

GENERATED = ("FUN_", "LAB_", "SUB_", "DAT_", "UNK_", "EXT_", "OFF_", "PTR_", "thunk_")


def is_generated(name: str) -> bool:
    return name.startswith(GENERATED)


def run(arguments: list[str], environment: dict[str, str], timeout: int = 3600) -> str:
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli")] + arguments, cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode:
        raise SystemExit(f"{' '.join(arguments)} failed: {result.stderr[-2000:]}")
    return result.stdout


def stored_functions(project: Path, program: str) -> dict[int, str]:
    connection = sqlite3.connect(project / "project.sqlite")
    return {int(entry, 16): name for entry, name in connection.execute(
        "SELECT functions.entry, functions.name FROM functions"
        " JOIN programs p ON p.id = functions.program_id WHERE p.name = ?",
        (program,)).fetchall()}


def nm_text_symbols(binary: Path) -> dict[str, list[int]]:
    tool = shutil.which("x86_64-w64-mingw32-nm") or shutil.which("nm")
    if tool is None:
        raise SystemExit("no nm for PE symbol truth (x86_64-w64-mingw32-nm or nm)")
    result = subprocess.run([tool, str(binary)],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise SystemExit(f"nm {binary.name} failed: {result.stderr[-500:]}")
    out = result.stdout
    symbols: dict[str, list[int]] = {}
    for line in out.splitlines():
        match = re.match(r"^([0-9a-f]+) ([a-zA-Z]) (\S+)$", line.strip())
        if match and match.group(2) in "tT":
            symbols.setdefault(match.group(3), []).append(int(match.group(1), 16))
    return symbols


def build_many(work: Path) -> tuple[Path, Path, Path, Path]:
    """Compiles the many.c PE pair plus unstripped twins for truth."""
    cc = os.environ.get("MINGW_CC", "x86_64-w64-mingw32-gcc")
    if not shutil.which(cc):
        raise SystemExit(f"mingw compiler not found: {cc}")
    source = ROOT / "tests/corpus-src/many.c"
    flags = ["-shared", "-fPIC", "-Wno-error=implicit-function-declaration"]
    outputs = [work / name for name in
               ("many_o0.dll", "many_o2.dll",
                "many_o0.unstripped.dll", "many_o2.unstripped.dll")]
    reference, target, reference_named, target_named = outputs
    if not (reference.is_file() and target.is_file()):
        subprocess.run(
            [cc] + flags + ["-O0", "-o", str(reference), str(source)],
            check=True, capture_output=True, text=True, timeout=600)
        subprocess.run(
            [cc] + flags + ["-O2", "-fno-inline", "-o", str(target), str(source)],
            check=True, capture_output=True, text=True, timeout=600)
    shutil.copy(reference, reference_named)
    shutil.copy(target, target_named)
    for path in (reference, target):
        subprocess.run(["x86_64-w64-mingw32-strip", "-s", str(path)],
                       check=True, timeout=120)
    return reference, target, reference_named, target_named


def score_truth(truth: dict[int, int], recovered: dict[int, str],
                known: set[int] | None = None) -> dict:
    found = sum(1 for address in truth if address in recovered)
    generated = {e for e, n in recovered.items() if is_generated(n)}
    known = set(truth) if known is None else known
    spurious = sorted(e for e in generated if e not in known)
    return {
        "truth": len(truth),
        "recovered": len(recovered),
        "recall": round(found / len(truth), 4) if truth else 0.0,
        "spurious": len(spurious),
    }


def many_rows(work: Path, environment: dict[str, str]) -> list[dict]:
    reference, target, reference_named, target_named = build_many(work)
    rows = []
    for level, binary, program in (("O0", reference, "many_o0"), ("O2", target, "many_o2")):
        project = work / f"many-{level}"
        if project.exists():
            shutil.rmtree(project)
        started = time.monotonic()
        print(run(["import", str(binary), "--project", str(project),
                   "--name", program], environment).strip(), flush=True)
        wall_s = round(time.monotonic() - started, 1)
        symbols = nm_text_symbols(
            reference_named if level == "O0" else target_named)
        truth = {names[0]: names[0] for names in symbols.values() if len(names) == 1}
        known = {address for names in symbols.values() for address in names}
        row = score_truth(truth, stored_functions(project, program), known)
        row.update({"id": f"many-{level}", "import_wall_s": wall_s})
        rows.append(row)
        print(json.dumps(row), flush=True)
    return rows




def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault("VENTRIS_CONSOLE", str(ROOT / "native/build/decomp_native"))
    tmp = arguments.work / "tmp"
    tmp.mkdir(exist_ok=True)
    environment["TMPDIR"] = str(tmp)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)

    failures: list[str] = []
    rows = many_rows(arguments.work, environment)
    for row in rows:
        if row["recall"] < THRESHOLDS["recall"]:
            failures.append(f"{row['id']}: recall {row['recall']} < {THRESHOLDS['recall']}")
        if row["spurious"] > THRESHOLDS["spurious"]:
            failures.append(f"{row['id']}: spurious {row['spurious']}")
    report = {
        "id": "m19-001",
        "milestone": "M19",
        "criterion": "PE import measured against external truth",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "inputs": {"many_src": "tests/corpus-src/many.c",
                   "many_cc_flags": {"O0": "-O0", "O2": "-O2 -fno-inline"}},
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
    print(f"m19-001: PASS ({len(rows)} PE rows at floors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
