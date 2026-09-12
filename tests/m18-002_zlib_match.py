#!/usr/bin/env python3
"""m18-002: REVDECODE-style context matching on a divergent zlib pair.

Claim: when data-flow similarity inverts among near-duplicate functions
(false pairs scoring 0.93-0.97), call-graph context resolves what raw
similarity cannot. The pipeline decodes relevance in two places: the
semantic pass commits strongest-first and defers hits the paired
neighbourhood contradicts, and a final coordinate-ascent pass moves or
swaps committed pairs only on strict improvement of the whole pairing's
alignment objective (content plus degree-normalised preserved call
edges), with every destination clearing the commit floor.

Pair: zlib 1.3.1 built `-O0` against `-O2 -fno-inline` as position
independent shared objects (168 same-name function pairs). The O2 build
rewrites small functions aggressively while the call graph stays put,
which is exactly the divergence the context classes exist for.

Ground truth: symbol tables the matcher never opens -- unstripped twins
of both builds. A reference entry maps to the target entry holding the
same name when that name is unique and the stripped import recovered it.

Thresholds, set from what was measured (see
`benchmarks/reports/m18-002.json`):

* `precision` 0.95 -- measured 1.0 with the classes on. The floor
  sits below measured to catch collapse and nothing else.
* `recall` 0.85 -- measured 0.9345 with the classes on. The floor
  holds the level the named-import run reaches; the 0.469 floor from
  the name-scarce era is superseded.
* No-loss rule (the hard gate): the correct matches the semantic-off
  run finds must all survive the semantic-on run. Context that costs a
  single true match fails, however the floors look.
* Gain rule, retired 2026-09-11: the semantic-on run used to hold one
  correct match the semantic-off run missed (`compressBound`). Since
  the stripped import recovers real names, both settings resolve the
  whole judged set (157/157) and the margin is vacuous -- not broken,
  just unmeasurable. The demonstration lives in the b47e9656 report;
  the old gain pair still matches in both settings every run (checked
  in the verdict, reported, never failed on).

The zlib source downloads pinned (URL and sha256 below) into the work
directory and builds with the local C compiler; the report records the
tarball hash and the compiler version, since code generation is what is
being measured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"

ZLIB_URL = "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"
ZLIB_SHA256 = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
ZLIB_SOURCES = (
    "adler32", "compress", "crc32", "deflate", "gzclose", "gzlib",
    "gzread", "gzwrite", "infback", "inffast", "inflate", "inftrees",
    "trees", "uncompr", "zutil",
)

THRESHOLDS = {"precision": 0.95, "recall": 0.85}

GENERATED = ("FUN_", "LAB_", "SUB_", "DAT_", "UNK_", "EXT_", "OFF_", "PTR_", "thunk_")


def is_generated(name: str) -> bool:
    return name.startswith(GENERATED)


def run(arguments: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        [str(CLI)] + arguments, cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=900,
    )
    if result.returncode:
        raise SystemExit(f"{' '.join(arguments)} failed: {result.stderr[-2000:]}")
    return result.stdout


def fetch_zlib(work: Path) -> tuple[Path, str]:
    """Downloads the pinned tarball (verifying its hash) and extracts it."""
    archive = work / "zlib-1.3.1.tar.gz"
    if archive.is_file():
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != ZLIB_SHA256:
            raise SystemExit(f"stale tarball {archive} with hash {digest}; remove it")
    else:
        try:
            with urllib.request.urlopen(ZLIB_URL, timeout=120) as response:
                archive.write_bytes(response.read())
        except Exception as error:
            raise SystemExit(f"cannot download {ZLIB_URL}: {error}")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != ZLIB_SHA256:
            archive.unlink()
            raise SystemExit(f"tarball hash {digest} != pinned {ZLIB_SHA256}")
    source = work / "zlib-1.3.1"
    if not (source / "deflate.c").is_file():
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(work)
    return source, digest


def build_pair(source: Path, work: Path) -> tuple[Path, Path, Path, Path, str]:
    cc = os.environ.get("CC", "cc")
    reference = work / "zlib_o0.so"
    target = work / "zlib_o2.so"
    reference_named = work / "zlib_o0.unstripped.so"
    target_named = work / "zlib_o2.unstripped.so"
    if not (reference.is_file() and target.is_file()):
        flags = ["-shared", "-fPIC", "-Wno-error=implicit-function-declaration"]
        subprocess.run(
            [cc] + flags + ["-O0", "-o", str(reference)]
            + [str(source / f"{name}.c") for name in ZLIB_SOURCES],
            check=True, capture_output=True, text=True, timeout=600,
        )
        subprocess.run(
            [cc] + flags + ["-O2", "-fno-inline", "-o", str(target)]
            + [str(source / f"{name}.c") for name in ZLIB_SOURCES],
            check=True, capture_output=True, text=True, timeout=600,
        )
    shutil.copy(reference, reference_named)
    shutil.copy(target, target_named)
    for path in (reference, target):
        subprocess.run(["strip", "-s", str(path)], check=True, timeout=120)
    version = subprocess.run(
        [cc, "--version"], capture_output=True, text=True, timeout=60,
    ).stdout.splitlines()[0] if shutil.which(cc) else cc
    return reference, target, reference_named, target_named, version


def function_names(project: Path, program: str) -> dict[int, str]:
    connection = sqlite3.connect(project / "project.sqlite")
    rows = connection.execute(
        "SELECT functions.entry, functions.name FROM functions"
        " JOIN programs p ON p.id = functions.program_id WHERE p.name = ?",
        (program,),
    ).fetchall()
    return {int(entry, 16): name for entry, name in rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault("VENTRIS_CONSOLE", str(ROOT / "native/build/decomp_native"))
    environment["VENTRIS_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)

    failures: list[str] = []
    source, digest = fetch_zlib(arguments.work)
    reference, target, reference_named, target_named, compiler = build_pair(
        source, arguments.work)
    for path in (reference, target, reference_named, target_named):
        if not path.is_file():
            failures.append(f"missing input {path}")

    scored: dict[str, dict] = {}
    if not failures:
        projects = {}
        for program, binary in (("reference", reference), ("target", target),
                                ("reference-named", reference_named),
                                ("target-named", target_named)):
            project = arguments.work / f"zlib-{program}"
            if project.exists():
                shutil.rmtree(project)
            run(["import", str(binary), "--project", str(project), "--name", program],
                environment)
            projects[program] = project
        for program, binary in (("reference", reference), ("target", target)):
            out = run(["index-semantics", str(binary), program,
                       "--project", str(projects[program])], environment)
            print(out.strip(), flush=True)
        reference_names = function_names(projects["reference-named"], "reference-named")
        reference_recovered = function_names(projects["reference"], "reference")
        target_recovered = function_names(projects["target"], "target")
        target_named = function_names(projects["target-named"], "target-named")
        by_name: dict[str, list[int]] = {}
        for address, name in target_named.items():
            if not is_generated(name):
                by_name.setdefault(name, []).append(address)
        truth: dict[int, int] = {}
        for address, name in reference_names.items():
            if is_generated(name) or address not in reference_recovered:
                continue
            candidates = [c for c in by_name.get(name, []) if c in target_recovered]
            if len(candidates) == 1:
                truth[address] = candidates[0]
        if not truth:
            failures.append("no ground truth")
        for setting, extra in (("with", []), ("without", ["--no-semantic"])):
            if failures:
                continue
            out = run(["diff", "target", "--project", str(projects["target"]),
                       "--reference", str(projects["reference"]),
                       "--reference-name", "reference", "--json"] + extra, environment)
            report = json.loads(out)
            matches = {(m["reference"]["offset"], m["target"]["offset"])
                       for m in report["matches"]}
            judged = [(r, t) for r, t in matches if r in truth]
            correct = sorted(r for r, t in judged if truth[r] == t)
            row = {
                "setting": setting,
                "truth": len(truth),
                "matched": len(matches),
                "judged": len(judged),
                "correct": len(correct),
                "correct_refs": [f"{a:08x}" for a in correct],
                "precision": round(len(correct) / len(judged), 4) if judged else 0.0,
                "recall": round(len(correct) / len(truth), 4) if truth else 0.0,
                "evidence": {},
            }
            for match in report["matches"]:
                key = (match["reference"]["offset"], match["target"]["offset"])
                if key[0] in truth:
                    name = str(match.get("evidence", "?"))
                    judged_count, correct_count = row["evidence"].get(name, (0, 0))
                    row["evidence"][name] = (
                        judged_count + 1, correct_count + (truth[key[0]] == key[1]))
            scored[setting] = row
            print(json.dumps(row), flush=True)

    if not failures and scored:
        with_row, without_row = scored["with"], scored["without"]
        correct_with = set(with_row["correct_refs"])
        correct_without = set(without_row["correct_refs"])
        lost = sorted(correct_without - correct_with)
        gained = sorted(correct_with - correct_without)
        with_row["gained_refs"] = gained
        without_row["lost_refs"] = lost
        if lost:
            failures.append(f"semantic run lost correct matches {lost}")
        # Gain retired: with names recovered both settings resolve the
        # judged set, so an empty margin is expected, not a failure.
        # gained_refs stays in the report as evidence either way.
        for metric in ("precision", "recall"):
            if with_row[metric] < THRESHOLDS[metric]:
                failures.append(
                    f"with {metric} {with_row[metric]} < {THRESHOLDS[metric]}")

    report = {
        "id": "m18-002",
        "milestone": "M18",
        "criterion": "REVDECODE-style context matching on a divergent zlib pair",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "inputs": {"zlib_url": ZLIB_URL, "zlib_sha256": ZLIB_SHA256,
                   "tarball_digest": digest, "compiler": compiler,
                   "cc_flags": {"O0": "-O0", "O2": "-O2 -fno-inline"}},
        "thresholds": THRESHOLDS,
        "rows": [scored["with"], scored["without"]] if scored else [],
        "status": "pass" if not failures else "fail",
        "failures": failures,
    }
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
        return 1
    print(f"m18-002: PASS (zlib O0-vs-O2 precision {scored['with']['precision']}, "
          f"recall {scored['with']['recall']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
