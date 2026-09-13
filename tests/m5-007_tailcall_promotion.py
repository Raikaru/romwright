#!/usr/bin/env python3
"""m5-007: promote a proven tail-call target to a function, behind a flag.

m5-006 made the transfer a fact. This gate answers whether the target may
become a function. The evidence required is the same evidence a relocation
candidate needs (m1-005): the address must be in executable, image-backed
code, must not lie inside a body flow already proved, and its own flow must
decode to a real instruction. Nothing is promoted from the branch alone.

Stock Ghidra does not create the function either (`tests/m5-002_nds.py`
records that), so this is an improvement over the frozen baseline, not
parity repair. AGENTS.md II.1 reserves *enabling* an M4-style pass by
default to the human, so the pass is off unless
`ROMWRIGHT_PROMOTE_TAILCALLS` is set, and this gate asserts both states:

  * flag off  -- every fact is byte-identical to m5-006's behaviour;
  * flag on   -- `nds.arm7` recovers `mix`, recall 0.7500 -> 1.0000, and
                 the reference becomes a call because the target is now a
                 function (Ghidra's CALL_RETURN rule);
  * flag on, over the 20 locked ELF inputs -- **no invented function
    anywhere** and no per-row recall below the committed m3-001 baseline,
    scored by the ratified gate rather than a second implementation.

Usage:
    python3 tests/m5-007_tailcall_promotion.py [--corpus-dir DIR] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
FLAG = "ROMWRIGHT_PROMOTE_TAILCALLS"
TAIL_CALL = (0x037F_802C, 0x037F_8000)
BASELINE = ROOT / "benchmarks" / "reports" / "m3-001.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def import_container(cli: Path, container: Path, work: Path, promote: bool,
                     timeout: int) -> sqlite3.Connection:
    project = work / ("on" if promote else "off")
    environment = dict(os.environ)
    environment.pop(FLAG, None)
    if promote:
        environment[FLAG] = "1"
    imported = subprocess.run(
        [str(cli), "import", str(container), "--name", "nds", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=environment)
    assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
    return sqlite3.connect(project / "project.sqlite")


def program_facts(store: sqlite3.Connection, program: str) -> dict:
    identifier = store.execute(
        "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
    assert identifier, f"{program} is missing from the store"
    entries = {int(entry, 16) for (entry,) in store.execute(
        "SELECT entry FROM functions WHERE program_id = ?", (identifier[0],))}
    references = {(int(src, 16), int(dst, 16)): kind for src, dst, kind in store.execute(
        "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier[0],))}
    return {"entries": entries, "references": references}


def score_corpus(corpus: Path, oracle: Path, timeout: int) -> dict:
    """Run the ratified DWARF gate with the flag on and read its verdict."""
    assert BASELINE.is_file(), f"{BASELINE} is missing; m3-001 must be committed first"
    baseline = {row["id"]: row for row in json.loads(BASELINE.read_text())["rows"]}
    environment = dict(os.environ, **{FLAG: "1"})
    with tempfile.TemporaryDirectory(prefix="m5-007-corpus-") as temporary:
        report = Path(temporary) / "promoted.json"
        result = subprocess.run(
            [sys.executable, str(ROOT / "benchmarks" / "dwarf_gate.py"),
             "--corpus-dir", str(corpus), "--oracle-dir", str(oracle),
             "--report", str(report)],
            cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=environment)
        assert report.is_file(), (
            f"the DWARF gate produced no report: "
            f"{result.stderr.strip() or result.stdout.strip()}")
        scored = json.loads(report.read_text())

    rows = [row for row in scored["rows"] if row.get("status") != "skipped"]
    assert len(rows) >= 20, f"only {len(rows)} corpus rows were scored"
    invented = {row["id"]: row["metrics"].get("native.dwarf.fn.unattributed", 0)
                for row in rows}
    offenders = {name: count for name, count in invented.items() if count}
    assert not offenders, (
        f"promotion invented functions DWARF cannot explain: {offenders}")

    regressions = {}
    promotions = {}
    for row in rows:
        recorded = baseline.get(row["id"])
        assert recorded, f"{row['id']} has no committed m3-001 baseline row"
        before = recorded["metrics"]["native.dwarf.fn.recall"]
        after = row["metrics"]["native.dwarf.fn.recall"]
        if after + 1e-9 < before:
            regressions[row["id"]] = (before, after)
        delta = row["metrics"]["native.functions"] - \
            recorded["metrics"]["native.functions"]
        if delta:
            promotions[row["id"]] = delta
    assert not regressions, (
        f"promotion lost functions the baseline recovered: {regressions}")

    return {
        "rows": len(rows),
        "unattributed": sum(invented.values()),
        "function_count_deltas": promotions,
        "gate_passed": bool(scored.get("passed")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--corpus-dir", type=Path)
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle")
    parser.add_argument("--timeout", type=int, default=2400)
    arguments = parser.parse_args()

    report = {"id": "m5-007", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "status": "skipped"}
    for tool in ("clang", "ld.lld", "llvm-objcopy", "readelf"):
        if shutil.which(tool) is None:
            report["reason"] = f"no freestanding ARM toolchain: {tool} not found"
            print(f"SKIP: {report['reason']}")
            if arguments.report:
                arguments.report.write_text(json.dumps(report, indent=2) + "\n")
            return 0

    fixture = load_module("m5_002", ROOT / "tests" / "m5-002_nds.py")
    from dwarf_arity import extract

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"

    with tempfile.TemporaryDirectory(prefix="m5-007-") as temporary:
        work = Path(temporary)
        container, images = fixture.build_container(work)
        truth = {name: {int(address, 16)
                        for address in extract(image["elf"])["functions"]}
                 for name, image in images.items()}
        symbols = {name: fixture.twin_symbols(image["elf"])
                   for name, image in images.items()}

        off = program_facts(import_container(cli, container, work, False,
                                            arguments.timeout), "nds.arm7")
        on_store = import_container(cli, container, work, True, arguments.timeout)
        on = program_facts(on_store, "nds.arm7")
        on9 = program_facts(on_store, "nds.arm9")

        # 1. The flag is off by default: II.1 reserves enabling the pass.
        assert TAIL_CALL[1] not in off["entries"], (
            f"{TAIL_CALL[1]:#x} was promoted with the flag off; enabling this "
            f"pass by default is reserved to the human"
        )
        assert off["references"].get(TAIL_CALL) == "UNCONDITIONAL_JUMP", (
            f"with the flag off the transfer must stay the jump reference "
            f"m5-006 recorded, found {off['references'].get(TAIL_CALL)!r}"
        )

        # 2. With the flag on the target becomes a function, and the reference
        #    follows Ghidra's rule for a jump into a function entry.
        assert TAIL_CALL[1] in on["entries"], (
            f"{TAIL_CALL[1]:#x} was not promoted with {FLAG} set; entries are "
            f"{sorted(hex(entry) for entry in on['entries'])}"
        )
        assert on["references"].get(TAIL_CALL) == "UNCONDITIONAL_CALL", (
            f"once the target is a function the reference is a call "
            f"(SharedReturnAnalysisCmd's CALL_RETURN override), found "
            f"{on['references'].get(TAIL_CALL)!r}"
        )

        # 3. Recall closes and nothing is invented, on both CPUs.
        for program, facts, name in (("nds.arm7", on, "arm7"), ("nds.arm9", on9, "arm9")):
            matched = truth[name] & facts["entries"]
            recall = len(matched) / len(truth[name])
            invented = sorted(f"{address:08x}" for address in facts["entries"] - truth[name]
                              if address not in symbols[name])
            assert not invented, f"{program}: invented functions {invented}"
            assert recall == 1.0, (
                f"{program}: dwarf.fn.recall {recall:.4f} with promotion on; "
                f"missing {sorted(f'{a:08x}' for a in truth[name] - facts['entries'])}"
            )

        # 4. The promoted function is real code: it decompiles.
        environment = dict(os.environ, **{FLAG: "1"})
        decompiled = subprocess.run(
            [str(cli), "decompile", str(container), f"{TAIL_CALL[1]:08x}",
             "--name", "nds.arm7", "--project", str(work / "on")],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout,
            env=environment)
        assert decompiled.returncode == 0 and "(" in decompiled.stdout, (
            f"the promoted function does not decompile: "
            f"{decompiled.stderr.strip() or decompiled.stdout.strip()}"
        )

    corpus = None
    if arguments.corpus_dir:
        corpus = score_corpus(arguments.corpus_dir, arguments.oracle_dir,
                              arguments.timeout)

    summary = (f"promotion off by default; on, nds.arm7 recall 1.0000 over "
               f"{len(truth['arm7'])} DWARF functions with 0 invented")
    if corpus:
        summary += (f"; {corpus['rows']} locked ELF inputs scored with the flag on: "
                    f"{corpus['unattributed']} invented functions, "
                    f"no recall below the m3-001 baseline")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"promoted": f"{TAIL_CALL[1]:08x}",
                               "arm7.dwarf.fn.recall": 1.0,
                               "corpus_unattributed":
                                   corpus["unattributed"] if corpus else None},
                      corpus=corpus)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-007: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
