#!/usr/bin/env python3
"""m15-001: stock structuring, over our own control-flow graphs.

Ghidra's decompiler exposes structuring as a standalone service: the
`structureGraph` command (`ghidra_process.cc:503`) takes an encoded
`BlockGraph`, runs `structureLoops`, `calcForwardDominator` and
`CollapseStructure` over a copy of it, and returns the collapsed hierarchy.
No function, no p-code, no decompilation. So it can be driven with *our*
blocks and *our* edges, which is what makes a structuring pass of ours
measurable: a difference in goto count is then a difference between two
structuring algorithms, and not between two ways of recovering a CFG. It also
needs no patch to the pinned tree -- the command has been there all along.

Three claims:

1. **The seam is faithful.** Canonical shapes come back structured the way the
   algorithm is defined to structure them: an if/else, a self-loop and a
   two-block loop need no unstructured jump; an irreducible graph and a loop
   with two exits need exactly one each.

2. **The graphs are the same graphs, and where they are not, it is for one
   stated reason.** The blocks the demand-driven walk derives are compared,
   per function, against the block count whole-image analysis measured
   independently (`function_features`). They must agree exactly on every
   function whose extent both producers agree on -- *except* where the
   whole-image pass recovered a jump table inside the body, because those
   case edges come from the switch round, which a single walk does not run.
   The partition is asserted both ways: no disagreement outside that class,
   and every disagreement inside it.

3. **Our structuring leaves fewer edges unstructured.** The same graphs go
   through `structuring::structure` in Rust, and the total it cannot
   structure is compared with stock's. Both sides count the same category,
   so neither may score a `break` as structured while the other does not.

4. **The baseline is recorded.** The number of edges stock's structuring
   could not structure, over the scored functions, is written to the report.
   That is what a structuring pass of ours has to beat on the same functions,
   recorded before such a pass exists so it cannot be chosen afterwards.
   Note the measure: `structureGraph` stops after `CollapseStructure`, before
   the printing pass that decides which unstructured edges become `break` or
   `continue`, so every one of them is reported as `f_goto_goto` here. It is
   a comparison of structurings on identical graphs, not a count of `goto`
   keywords in emitted C.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/romwright-cli"
WORKER = ROOT / "target/release/romwright-worker"
SPECS = ROOT / "native/specs"
LIBC_CANDIDATES = (
    "/usr/lib64/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
)
# Structuring is defined on the graph, so these hold on any language.
# Measured 0.788 on libc; the gate holds the claim, not the exact number.
OURS_OVER_STOCK = 0.90
SHAPES = (
    ("ifelse", 4, [(0, 1), (0, 2), (1, 3), (2, 3)], 0),
    ("selfloop", 3, [(0, 1), (1, 1), (1, 2)], 0),
    ("twoblockloop", 3, [(0, 1), (1, 0), (1, 2)], 0),
    ("irreducible", 4, [(0, 1), (0, 2), (1, 2), (2, 1), (1, 3)], 1),
    ("twoexitloop", 4, [(0, 1), (1, 2), (2, 1), (1, 3), (2, 3)], 1),
)


def default_binary() -> Path:
    pinned = os.environ.get("ROMWRIGHT_LIBC")
    if pinned:
        return Path(pinned)
    for candidate in LIBC_CANDIDATES:
        if Path(candidate).is_file():
            return Path(candidate)
    return Path(LIBC_CANDIDATES[0])


def structure_shapes(environment) -> dict:
    requests = "".join(
        json.dumps({"id": name, "blocks": list(range(blocks)), "edges": list(edges)}) + "\n"
        for name, blocks, edges, _ in SHAPES
    )
    result = subprocess.run(
        [str(WORKER), str(ROOT / "native/build/ghidra_opt"), str(SPECS),
         str(ROOT / "tests/fixtures-src/tiny_bin"), "shapes", "--structure",
         "--base", "0x400000"],
        input=requests, text=True, capture_output=True, env=environment, cwd=ROOT, timeout=300)
    if result.returncode:
        raise RuntimeError(f"structuring worker failed: {result.stderr[-800:]}")
    return {row["id"]: row
            for row in (json.loads(line) for line in result.stdout.splitlines()
                        if line.startswith("{"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=default_binary())
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=400,
                        help="multi-block functions scored")
    arguments = parser.parse_args()
    environment = os.environ.copy()
    environment.setdefault("ROMWRIGHT_CONSOLE", str(ROOT / "native/build/decomp_native"))
    environment["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    install = Path(os.environ.get("ROMWRIGHT_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
    shape_environment = dict(
        environment,
        ROMWRIGHT_LANGUAGE="x86:LE:64:default",
        ROMWRIGHT_LANGUAGE_DIR=str(SPECS),
        ROMWRIGHT_SLA=str(install / "Ghidra/Processors/x86/data/languages/x86-64.sla"))
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True)

    report = {
        "gate": "m15-001",
        "milestone": "M15",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                          text=True).strip(),
        "date": datetime.now(timezone.utc).date().isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "binary": str(arguments.binary),
        "shapes": [],
        "metrics": {},
    }
    failures = []

    # 1. The seam.
    answered = structure_shapes(shape_environment)
    for name, _, _, expected in SHAPES:
        row = answered.get(name)
        if row is None or "error" in row:
            failures.append(f"shape {name}: {row.get('error') if row else 'no answer'}")
            continue
        report["shapes"].append({"id": name, "gotos": row["gotos"],
                                 "expected": expected, "kinds": row["kinds"]})
        if row["gotos"] != expected:
            failures.append(f"shape {name}: {row['gotos']} gotos, expected {expected}")

    if not arguments.binary.is_file():
        report["metrics"]["reason"] = f"{arguments.binary} not present"
        report["passed"] = not failures
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"SKIP: {report['metrics']['reason']}")
        return 1 if failures else 0

    with tempfile.TemporaryDirectory(prefix="m15-001-") as temporary:
        analysed = Path(temporary) / "analysed"
        loaded = Path(temporary) / "loaded"
        name = arguments.binary.name
        for project, extra in ((analysed, []), (loaded, ["--no-analysis"])):
            subprocess.run([str(CLI), "import", str(arguments.binary), "--project",
                            str(project), "--name", name, *extra],
                           cwd=ROOT, env=environment, check=True, capture_output=True,
                           timeout=3600)
        with sqlite3.connect(analysed / "project.sqlite") as db:
            measured = dict(db.execute(
                "SELECT function, blocks FROM function_features WHERE blocks > 1"
                " ORDER BY function LIMIT ?", (arguments.limit,)))
            sizes = dict(db.execute("SELECT entry, size FROM functions"))
            tables = {}
            for entry in measured:
                start = int(entry, 16)
                tables[entry] = db.execute(
                    "SELECT COUNT(*) FROM xrefs WHERE provenance = 'native-import:switch'"
                    " AND src >= ? AND src < ?",
                    (f"{start:08x}", f"{start + sizes.get(entry, 0):08x}")).fetchone()[0]
        if not measured:
            raise SystemExit("no multi-block functions to score")
        result = subprocess.run(
            [str(CLI), "structure", str(arguments.binary), name, ",".join(measured),
             "--project", str(loaded), "--json"],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=3600)
        if result.returncode:
            raise SystemExit(f"structuring failed: {result.stderr[-800:]}")
        answers = [json.loads(line) for line in result.stdout.splitlines()
                   if line.startswith("{")]

    refused = [row for row in answers if "error" in row]
    rows = [row for row in answers if "error" not in row]
    # Only functions both producers attributed the same code to are comparable.
    comparable = [row for row in rows if row.get("size") == sizes.get(row["id"])]
    switchless = [row for row in comparable if not tables.get(row["id"])]
    with_tables = [row for row in comparable if tables.get(row["id"])]
    disagreeing = [row for row in switchless if row["blocks"] != measured[row["id"]]]
    agreeing_tables = [row for row in with_tables if row["blocks"] == measured[row["id"]]]
    gotos = sum(row["gotos"] for row in comparable)
    ours = sum(row["ours"]["unstructured"] for row in comparable if "ours" in row)
    better = sum(1 for row in comparable
                 if "ours" in row and row["ours"]["unstructured"] < row["gotos"])
    worse = [row for row in comparable
             if "ours" in row and row["ours"]["unstructured"] > row["gotos"]]
    ratio = ours / gotos if gotos else 1.0
    report["metrics"] = {
        "scored": len(measured),
        "answered": len(rows),
        "refused": len(refused),
        "comparable": len(comparable),
        "without_tables": len(switchless),
        "with_tables": len(with_tables),
        "block_disagreements_without_tables": len(disagreeing),
        "table_functions_that_agree": len(agreeing_tables),
        "stock_unstructured_edges": gotos,
        "our_unstructured_edges": ours,
        "ours_over_stock": round(ratio, 4),
        "functions_we_structure_better": better,
        "functions_we_structure_worse": len(worse),
        "worst_regression": max(
            (row["ours"]["unstructured"] - row["gotos"] for row in worse), default=0),
        "duplicated_tails": sum(row["ours"]["duplicated"] for row in comparable
                                if "ours" in row),
        "functions_with_gotos": sum(1 for row in comparable if row["gotos"]),
        "examples": [
            {"function": row["id"], "walk_blocks": row["blocks"],
             "batch_blocks": measured[row["id"]], "switch_edges": tables.get(row["id"], 0)}
            for row in (disagreeing + with_tables)[:10]
        ],
    }
    if refused:
        failures.append(f"{len(refused)} graphs the decompiler refused, "
                        f"e.g. {refused[0].get('error')}")
    if disagreeing:
        failures.append(
            f"{len(disagreeing)} functions with no recovered jump table disagree on block "
            f"count, e.g. {disagreeing[0]['id']} walk {disagreeing[0]['blocks']} vs batch "
            f"{measured[disagreeing[0]['id']]}")
    if not with_tables:
        failures.append("no function with a recovered jump table was scored, so the "
                        "stated exception is untested")
    elif agreeing_tables:
        failures.append(
            f"{len(agreeing_tables)} functions with recovered jump tables agree on block "
            "count, so the exception no longer describes the difference")

    if ratio > OURS_OVER_STOCK:
        failures.append(
            f"our structuring leaves {ours} edges unstructured against stock's {gotos} "
            f"({ratio:.4f} of it), over the {OURS_OVER_STOCK} requirement")
    report["passed"] = not failures
    report["failures"] = failures
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    metrics = report["metrics"]
    print(
        f"m15-001: PASS ({len(SHAPES)} canonical shapes structured as defined; "
        f"{metrics['without_tables']} functions without recovered tables agree exactly "
        f"with whole-image analysis on block count, all {metrics['with_tables']} with "
        f"tables differ as stated; stock leaves {metrics['stock_unstructured_edges']} edges "
        f"unstructured over "
        f"{metrics['comparable']} functions, {metrics['functions_with_gotos']} of them "
        f"holding at least one; ours leaves {metrics['our_unstructured_edges']} "
        f"({metrics['ours_over_stock']} of stock), better on "
        f"{metrics['functions_we_structure_better']} functions, worse on "
        f"{metrics['functions_we_structure_worse']} by at most "
        f"{metrics['worst_regression']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
