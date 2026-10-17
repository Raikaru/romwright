#!/usr/bin/env python3
"""m19-001: PE import measured against external truth.

Claim: importing a Windows PE recovers the functions its own toolchain
declares -- no more, no fewer than the floors allow.

The locked pe64 corpus rows (plain_o0, plain_o2, plain_pie DLL,
many_o2 EXE): stripped primaries are imported, unstripped twins supply
truth. Ground truth is the toolchain symbol table (`mingw-nm`, never
our parser): unique text-symbol names mapped to addresses with no base
adjustment (our loader keeps link VAs). No gate-time build: earlier
revisions compiled their own pair here, an unlocked second build path
for the same artifacts. Runs in seconds; pe32 lives in m3-001 under
its tied exemptions.

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
        [str(ROOT / "target/release/romwright-cli")] + arguments, cwd=ROOT, env=environment,
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
            name = match.group(3)
            # Assembler locals (`.l_start`, loop labels) and section
            # symbols (`.text`) are addresses, not toolchain-declared
            # functions; no real function name starts with a dot.
            if name.startswith("."):
                continue
            symbols.setdefault(name, []).append(int(match.group(1), 16))
    return symbols


def sha256_file(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def locked_rows(corpus: Path, work: Path, environment: dict[str, str]) -> list[dict]:
    """Score the locked pe64 rows: pinned bytes in, toolchain truth out."""
    manifest = json.loads((corpus / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"]
               if entry["architecture"] == "pe64" and entry.get("status") == "ok"]
    if not entries:
        raise SystemExit(f"no locked pe64 rows in {corpus / 'manifest.json'}")
    rows = []
    for entry in entries:
        identifier = f"{entry['architecture']}_{entry['variant']}"
        binary = corpus / entry["binary"]
        twin = corpus / entry["unstripped_twin"]
        digest = sha256_file(binary)
        if digest != entry["binary_sha256"]:
            raise SystemExit(f"{binary.name}: digest mismatch, corpus is not the lock")
        if sha256_file(twin) != entry["unstripped_twin_sha256"]:
            raise SystemExit(f"{twin.name}: twin digest mismatch, corpus is not the lock")
        project = work / identifier
        if project.exists():
            shutil.rmtree(project)
        started = time.monotonic()
        print(run(["import", str(binary), "--project", str(project),
                   "--name", identifier], environment).strip(), flush=True)
        wall_s = round(time.monotonic() - started, 1)
        symbols = nm_text_symbols(twin)
        truth = {names[0]: names[0] for names in symbols.values() if len(names) == 1}
        known = {address for names in symbols.values() for address in names}
        row = score_truth(truth, stored_functions(project, identifier), known)
        row.update({"id": identifier, "binary_sha256": digest,
                    "import_wall_s": wall_s})
        rows.append(row)
        print(json.dumps(row), flush=True)
    return rows




def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    tmp = arguments.work / "tmp"
    tmp.mkdir(exist_ok=True)
    environment["TMPDIR"] = str(tmp)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], cwd=ROOT, check=True)

    failures: list[str] = []
    rows = locked_rows(arguments.corpus_dir, arguments.work, environment)
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
        "inputs": {"corpus": "locked pe64 rows from tests/corpus.lock.json"},
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
