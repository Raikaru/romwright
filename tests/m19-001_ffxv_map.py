#!/usr/bin/env python3
"""m19-001: PE import measured against external truth.

Claim: importing a Windows PE recovers the functions its own toolchain
declares -- no more, no fewer than the floors allow.

Two pairs, same metrics, different speeds:

* `many` (the gate): `tests/corpus-src/many.c` built with mingw-w64 as
  PE32+ DLLs, `-O0` and `-O2 -fno-inline`, stripped for the measured
  import with unstripped twins for truth. Ground truth is the toolchain
  symbol table (`mingw-nm`, never our parser): unique text-symbol names
  mapped to addresses with no base adjustment (our loader keeps link
  VAs). Runs in seconds; this is what blocks.
* `ffxv` (periodic, `--ffxv`, tens of minutes): the retail FFXV PE
  against its MSVC
  linker MAP (`scripts/msvc_map.py`: segment N is the Nth PE section
  in VA order, every row cross-checked against `Rva+Base`). A 91MB
  import takes tens of minutes; it records evidence, it does not
  block. Inputs are hash-pinned retail files outside the repository
  (STATUS.md reserves new corpus binaries to user approval; these
  were approved in conversation).

Metrics (per pair):

* `recall`: unique truth addresses recovered as function entries.
* `spurious`: recovered entries with generated names (`FUN_...`)
  naming no toolchain address at all -- invented functions. Named
  recoveries (import stubs take the imported name) are outside this
  denominator by construction.

Thresholds, set from what was measured (see
`benchmarks/reports/m19-001.json`): floors sit just below measured to
catch collapse and nothing else. The FFXV row carries its own, since
two thirds of its oracle are 12-16 byte exception-handling funclets
(`?dtor$N@...`, reached only through .xdata): the claim is
non-funclet recall, with funclet recall recorded, not floored. Its
four measured spurious are characterised, not waived: one unlisted
real function and three mid-stub splits of delay-load import stubs
-- the ceiling ratchets down when either is fixed.
"""

from __future__ import annotations

import argparse
import hashlib
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
sys.path.insert(0, str(ROOT / "scripts"))
from msvc_map import parse_map  # noqa: E402

CORPUS = Path.home() / "ventris-corpus/extracted/win-ffxv"
EXE_SHA256 = "4f09d014565860dfced7ecb3fe30bcea82166019731a4e9825a62673d031e9c8"
MAP_SHA256 = "821b32442d1100795bd6863fb8fa9cb50ab42d7b534cc7f1cf2b410dc4f0c604"

# Floors sit just below measured. The FFXV row carries its own: most of
# the MAP's `f` rows are 12-16 byte exception-handling funclets reached
# only through .xdata, so the headline denominator is split -- the claim
# is non-funclet recall, with funclet recall recorded, not floored.
THRESHOLDS = {"recall": 0.97, "spurious": 0}
FFXV_THRESHOLDS = {"recall": 0.29, "recall_nonfunclet": 0.83, "spurious": 4}

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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def ffxv_row(work: Path, environment: dict[str, str],
             project: Path | None = None) -> dict:
    exe, map_path = CORPUS / "ffxv_s.exe", CORPUS / "ffxv_s.map"
    for path, pinned in ((exe, EXE_SHA256), (map_path, MAP_SHA256)):
        if not path.is_file():
            raise SystemExit(f"missing input {path}")
        if sha256(path) != pinned:
            raise SystemExit(f"{path.name} hash mismatch: not the pinned retail file")
    oracle = parse_map(map_path, exe)
    print(f"oracle: {len(oracle.functions)} functions, "
          f"{oracle.data_rows} data rows, {oracle.disagreed} disagreed", flush=True)
    if project is None:
        project = work / "ffxv"
        if project.exists():
            shutil.rmtree(project)
        started = time.monotonic()
        # A 91MB retail import takes the better part of two hours; the gate
        # timeout prices the work, not the patience.
        print(run(["import", str(exe), "--project", str(project), "--name", "ffxv"],
                  environment, timeout=10800).strip(), flush=True)
        wall_s = round(time.monotonic() - started, 1)
    else:
        # Scoring an existing store: re-importing is a separate supervised
        # step, run once. The binary that built it must be current -- the
        # import cache this project was restored from is keyed on the
        # analyser, but a hand-rolled directory is not, so record it.
        wall_s = None
        print(f"scoring existing project {project}", flush=True)
    recovered = stored_functions(project, "ffxv")
    function_vas = set(oracle.functions)
    funclet = re.compile(r"\?(dtor|catch|fin|filt|unwind)\$[0-9]")
    core = {a for a in function_vas if not funclet.search(oracle.functions[a])}
    truth = {address: address for address in function_vas}
    row = score_truth(truth, recovered)
    core_found = sum(1 for a in core if a in recovered)
    row.update({
        "id": "ffxv",
        "import_wall_s": wall_s,
        "oracle_data": len(oracle.data),
        "funclets": len(function_vas) - len(core),
        "recall_nonfunclet": round(core_found / len(core), 4) if core else 0.0,
        "funclet_recall": round(
            sum(1 for a in function_vas - core if a in recovered)
            / max(1, len(function_vas) - len(core)), 4),
        "data_hits": sum(1 for e in recovered if e in oracle.data
                         and e not in function_vas),
    })
    print(json.dumps({k: (v if not isinstance(v, set) else sorted(v))
                      for k, v in row.items()}), flush=True)
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ffxv", action="store_true",
                        help="also run the retail FFXV pair (tens of minutes)")
    parser.add_argument("--project", type=Path, default=None,
                        help="with --ffxv, score this existing project instead of"
                        " re-importing (a supervised import run once)")
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    if arguments.ffxv and arguments.project is None:
        # A 91MB import writes a ~1GB console image plus a hundreds-of-MB
        # WAL; tmpfs quotas turn that into a silent seed-only analysis or
        # a mid-commit I/O error. Fail fast on small filesystems. Scoring
        # an existing project needs kilobytes, so it is exempt.
        free = os.statvfs(arguments.work).f_bavail * os.statvfs(arguments.work).f_frsize
        if free < 4 << 30:
            raise SystemExit(
                f"--ffxv needs a disk-backed --work with 4GB free: {arguments.work}"
                f" has {free >> 20}MB")
    environment = dict(os.environ)
    environment.setdefault("VENTRIS_CONSOLE", str(ROOT / "native/build/decomp_native"))
    tmp = arguments.work / "tmp"
    tmp.mkdir(exist_ok=True)
    environment["TMPDIR"] = str(tmp)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)

    failures: list[str] = []
    rows = many_rows(arguments.work, environment)
    if arguments.ffxv:
        rows.append(ffxv_row(arguments.work, environment, arguments.project))
    for row in rows:
        floors = FFXV_THRESHOLDS if row["id"] == "ffxv" else THRESHOLDS
        if row["recall"] < floors["recall"]:
            failures.append(f"{row['id']}: recall {row['recall']} < {floors['recall']}")
        if row["id"] == "ffxv" and row["recall_nonfunclet"] < floors["recall_nonfunclet"]:
            failures.append(f"ffxv: non-funclet recall {row['recall_nonfunclet']}"
                            f" < {floors['recall_nonfunclet']}")
        if row["spurious"] > floors["spurious"]:
            failures.append(f"{row['id']}: spurious {row['spurious']}")
    report = {
        "id": "m19-001",
        "milestone": "M19",
        "criterion": "PE import measured against external truth",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "inputs": {"many_src": "tests/corpus-src/many.c",
                   "many_cc_flags": {"O0": "-O0", "O2": "-O2 -fno-inline"},
                   "ffxv": {"exe_sha256": EXE_SHA256, "map_sha256": MAP_SHA256}
                   if arguments.ffxv else "not run (pass --ffxv)"},
        "thresholds": {"many": THRESHOLDS, "ffxv": FFXV_THRESHOLDS},
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
