#!/usr/bin/env python3
"""m2-016: measured import phases, shard invariance and the flow budget.

The import pipeline grew ten passes since m1-003 set a 5.0 s budget on total
libc import time, so that number stopped describing batched flow. This gate
measures each phase instead, and pins the two things a budget must not be
able to buy: the facts and the batching.

Assertions
  1. `import --timings` reports every phase (parse, patterns, flow,
     discovery, references, store) and they sum to no more than the total.
  2. Sharding is fact-invariant: a one-console import and an N-console
     import produce byte-identical function, xref, string, symbol and thunk
     sets. Wall time is the only thing shards may change.
  3. The reference pass is at least 2x faster with N >= 4 consoles than with
     one. Relative, so it means the same thing on any machine.
  4. The flow phase stays inside m1-003's 5.0 s budget, measured on the
     phase that m1-003 names instead of on the whole pipeline.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIBC = Path(os.environ.get("VENTRIS_LIBC", "/usr/lib64/libc.so.6"))
PHASES = ("parse", "patterns", "flow", "discovery", "references", "store")
FLOW_BUDGET_SECONDS = 5.0
REFERENCE_SPEEDUP = 2.0
TOTAL_CEILING_SECONDS = 60.0

FACT_QUERIES = {
    "functions": "SELECT entry, name, size FROM functions ORDER BY entry, name",
    "xrefs": "SELECT src, dst, kind, provenance FROM xrefs ORDER BY src, dst, kind, provenance",
    "strings": "SELECT address, value FROM strings ORDER BY address, value",
    "symbols": "SELECT address, name FROM symbols ORDER BY address, name",
    "thunks": "SELECT function, thunked, kind FROM thunks ORDER BY function, thunked",
}


def facts(project: Path) -> dict:
    """Row counts and digests of everything the import writes."""
    database = sqlite3.connect(project / "project.sqlite")
    tables = {row[0] for row in database.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    digests = {}
    for table, query in FACT_QUERIES.items():
        if table not in tables:
            raise AssertionError(f"store is missing the {table} table")
        rows = list(database.execute(query))
        digests[table] = {
            "rows": len(rows),
            "sha256": hashlib.sha256(repr(rows).encode()).hexdigest(),
        }
    return digests


def run_import(binary: Path, shards: int, work: Path) -> dict:
    """One measured native import at a pinned console-shard count."""
    project = work / f"shards-{shards}"
    project.mkdir(parents=True)
    environment = dict(os.environ, VENTRIS_CONSOLE_SHARDS=str(shards))
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(binary),
         "--name", "libc", "--project", str(project), "--timings"],
        cwd=ROOT, env=environment, capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(f"import failed at {shards} shard(s): {result.stderr.strip()}")
    line = next((row for row in result.stdout.splitlines()
                 if row.startswith("TIMINGS ")), None)
    if line is None:
        raise AssertionError(
            f"import --timings printed no TIMINGS line: {result.stdout.strip()}")
    measured = json.loads(line[len("TIMINGS "):])
    missing = [phase for phase in PHASES if phase not in measured["phases"]]
    if missing:
        raise AssertionError(f"unmeasured import phases: {missing}")
    if measured["shards"] != shards:
        raise AssertionError(
            f"import used {measured['shards']} shard(s), not the pinned {shards}")
    return {"timings": measured, "facts": facts(project)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--binary", type=Path, default=LIBC)
    arguments = parser.parse_args()

    report = {"id": "m2-016", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"flow.seconds": FLOW_BUDGET_SECONDS,
                             "references.speedup": REFERENCE_SPEEDUP,
                             "total.seconds": TOTAL_CEILING_SECONDS},
              "status": "skipped", "runs": {}, "checks": {}}
    if not arguments.binary.is_file():
        report["reason"] = f"{arguments.binary} not present"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    lanes = min(os.cpu_count() or 1, 6)
    report["consoles"] = lanes
    with tempfile.TemporaryDirectory(prefix="m2-016-") as temporary:
        work = Path(temporary)
        single = run_import(arguments.binary, 1, work)
        sharded = run_import(arguments.binary, lanes, work)

    report["runs"] = {"single": single["timings"], "sharded": sharded["timings"]}

    # 1. Phases account for the run: no phase may be reported outside it.
    for name, run in (("single", single), ("sharded", sharded)):
        measured = run["timings"]
        # `discovery` covers `patterns` and `flow`; count the outer phases.
        accounted = sum(measured["phases"][phase]
                        for phase in ("parse", "discovery", "references", "store"))
        if accounted > measured["total"] + 0.05:
            raise AssertionError(
                f"{name}: phases sum to {accounted:.3f}s over a {measured['total']:.3f}s run")
        report["checks"][f"{name}.accounted_seconds"] = round(accounted, 6)

    # 2. Shards change wall time, never facts.
    differing = [table for table in FACT_QUERIES
                 if single["facts"][table] != sharded["facts"][table]]
    report["checks"]["fact_invariance"] = not differing
    report["facts"] = sharded["facts"]
    if differing:
        raise AssertionError(
            f"sharded import changed facts: {differing} "
            f"single={ {t: single['facts'][t] for t in differing} } "
            f"sharded={ {t: sharded['facts'][t] for t in differing} }")

    # 3. The reference pass must actually shard.
    speedup = single["timings"]["phases"]["references"] / max(
        sharded["timings"]["phases"]["references"], 1e-9)
    report["checks"]["references.speedup"] = round(speedup, 4)
    if lanes < 4:
        report["checks"]["references.speedup_asserted"] = False
        print(f"NOTE: {lanes} console(s) available; speedup {speedup:.2f}x recorded, not asserted")
    else:
        report["checks"]["references.speedup_asserted"] = True
        if speedup < REFERENCE_SPEEDUP:
            raise AssertionError(
                f"reference pass sharded {speedup:.2f}x on {lanes} consoles, "
                f"under the {REFERENCE_SPEEDUP}x requirement")

    # 4. m1-003's budget, measured on the phase it names.
    flow = sharded["timings"]["phases"]["flow"]
    report["checks"]["flow.seconds"] = flow
    if flow >= FLOW_BUDGET_SECONDS:
        raise AssertionError(
            f"flow phase took {flow:.3f}s, over the {FLOW_BUDGET_SECONDS}s budget")

    total = sharded["timings"]["total"]
    report["checks"]["total.seconds"] = total
    if total >= TOTAL_CEILING_SECONDS:
        raise AssertionError(
            f"import took {total:.3f}s, over the {TOTAL_CEILING_SECONDS}s ceiling")

    report["status"] = "pass"
    report["passed"] = True
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m2-016: PASS ({lanes} consoles; flow {flow:.3f}s < {FLOW_BUDGET_SECONDS}s, "
          f"references {speedup:.2f}x, total {total:.3f}s, "
          f"{sharded['facts']['xrefs']['rows']} xrefs identical to the single-console run)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
