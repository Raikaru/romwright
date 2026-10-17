#!/usr/bin/env python3
"""m17-001: functions found by the shape of the graph, scored as their own producer.

Every producer this project had needed something pointing at a function: a
symbol, a relocation, a call from code already walked, or a byte pattern.
This one needs only that the code is code. It sweeps a range, clusters what
decodes into connected components over intraprocedural edges, and calls each
component a function -- Nucleus's observation (Andriesse, Slowinska & Bos,
EuroS&P 2017) that a function is a shape, applied to our own console's
decode.

The point of the gate is that it scores *this* producer, not the pipeline
it sits in: the sweep runs over the whole executable range with nothing
claimed in advance, so it cannot be handed the answers it is being measured
against. Two tiers are scored separately, because they are not equally
trustworthy and shipping them as one number would hide that:

* **Called components** -- a component some instruction calls. A call is
  hard evidence of a function entry, and this tier is expected to be right
  almost every time.
* **Every component** -- including code nothing calls, which is the tier
  that can find a function no other producer can see, and also the tier
  that turns padding and data into candidates.

Both are scored against DWARF on four architectures, because a detector
that works only where the instruction set is variable-length has not been
shown to work.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from dwarf_types import extract  # noqa: E402

CLI = ROOT / "target/release/romwright-cli"
# Instruction alignment per architecture: a sweep on a fixed-width machine
# that steps one byte at a time decodes garbage at every misaligned offset.
VARIANTS = (("x86_64", 1), ("i386", 1), ("aarch64", 4), ("powerpc", 4))
# Measured 0.9975/0.9901..0.9975; the gate holds the claim.
CALLED_RECALL_FLOOR = 0.95
CALLED_PRECISION_FLOOR = 0.95
# The untrusted tier is scored and recorded, with only its recall required:
# its precision is the reason it is a separate tier.
ALL_RECALL_FLOOR = 0.95


def score(found: set[str], truth: set[str]) -> dict:
    hit = len(found & truth)
    return {
        "found": len(found),
        "hit": hit,
        "recall": round(hit / len(truth), 4) if truth else 0.0,
        "precision": round(hit / len(found), 4) if found else 0.0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    environment = os.environ.copy()
    environment["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], cwd=ROOT, check=True)

    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = {f"{row['architecture']}_{row['variant']}": row
               for row in manifest["entries"] if row.get("status") == "ok"}
    report = {
        "gate": "m17-001",
        "milestone": "M17",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                          text=True).strip(),
        "date": datetime.now(timezone.utc).date().isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "thresholds": {"called.recall": CALLED_RECALL_FLOOR,
                       "called.precision": CALLED_PRECISION_FLOOR,
                       "all.recall": ALL_RECALL_FLOOR},
        "rows": [],
    }
    failures = []
    with tempfile.TemporaryDirectory(prefix="m17-001-") as temporary:
        for architecture, unit in VARIANTS:
            key = f"{architecture}_many_o2"
            row = entries.get(key)
            if row is None:
                failures.append(f"{key}: corpus row missing")
                continue
            binary = (arguments.corpus_dir / row["binary"]).resolve()
            unstripped = binary.with_suffix(".unstripped")
            if not unstripped.is_file():
                failures.append(f"{key}: no unstripped twin to take truth from")
                continue
            truth = set(extract(unstripped)["functions"])
            project = Path(temporary) / key
            subprocess.run([str(CLI), "import", str(binary), "--project", str(project),
                            "--name", key, "--no-analysis"],
                           cwd=ROOT, env=environment, check=True, capture_output=True,
                           timeout=900)
            result = subprocess.run(
                [str(CLI), "detect-functions", str(binary), key, "--project", str(project),
                 "--whole-range", "--unit", str(unit), "--json"],
                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=900)
            if result.returncode:
                failures.append(f"{key}: detection failed: {result.stderr[-300:]}")
                continue
            found = json.loads(result.stdout)
            everything = score(set(found["entries"]), truth)
            called = score(set(found["called_entries"]), truth)
            report["rows"].append({
                "id": key,
                "unit": unit,
                "truth": len(truth),
                "swept_bytes": found["swept_bytes"],
                "blocks": found["blocks"],
                "components": found["components"],
                "seconds": round(found["seconds"], 3),
                "called": called,
                "all": everything,
            })
            if called["recall"] < CALLED_RECALL_FLOOR:
                failures.append(f"{key}: called-tier recall {called['recall']}")
            if called["precision"] < CALLED_PRECISION_FLOOR:
                failures.append(f"{key}: called-tier precision {called['precision']}")
            if everything["recall"] < ALL_RECALL_FLOOR:
                failures.append(f"{key}: every-component recall {everything['recall']}")

    if len(report["rows"]) != len(VARIANTS):
        failures.append(
            f"scored {len(report['rows'])} architectures of {len(VARIANTS)}: a detector "
            "shown on one instruction set is not shown")
    report["passed"] = not failures
    report["failures"] = failures
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    summary = "; ".join(
        f"{row['id'].split('_')[0]} called {row['called']['recall']}/"
        f"{row['called']['precision']}"
        for row in report["rows"])
    print(f"m17-001: PASS (recall/precision of the called tier against DWARF: {summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
