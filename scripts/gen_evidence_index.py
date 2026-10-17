#!/usr/bin/env python3
"""Generate or check the README evidence index from the committed reports.

Every gate writes a JSON report under `benchmarks/reports/`. This turns those
files into one table: which gate, which milestone, what it measured, and the
file that produces it. Nothing here is written by hand, so the index cannot
claim a number no report carries.

A report at the top of `benchmarks/reports/` is current evidence: it must
record a pass, or a skip with a reason. Intermediate diagnostic runs live in
`benchmarks/reports/diagnostics/` and are not indexed -- keeping a failing run
next to current evidence is what made the directory unreadable.

Usage:
    python scripts/gen_evidence_index.py          # rewrite the README index
    python scripts/gen_evidence_index.py --check  # fail if it is stale
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPORTS = ROOT / "benchmarks" / "reports"
BEGIN = "<!-- evidence-index:begin -->"
END = "<!-- evidence-index:end -->"
TASK = re.compile(r"^m(\d+)-(\d+)([a-z]?)")
# Reports that record machine state rather than a gate verdict.
UNGATED = {"corpus.json", "baseline-stock.json"}


def identity(report: dict) -> str | None:
    for key in ("id", "task", "gate"):
        value = report.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def milestone(report: dict, name: str) -> str:
    recorded = report.get("milestone")
    if isinstance(recorded, str) and recorded:
        return recorded
    match = TASK.match(name)
    return f"M{match.group(1)}" if match else "-"


def measured(report: dict) -> str:
    """The numbers the report itself carries, in its own words.

    Metrics come first and in full: a row that showed only the thresholded
    subset would not move when a measured number changed, which is exactly the
    property this index has to have.
    """
    def render(key: str, value: object) -> str:
        if isinstance(value, float):
            return f"`{key}` {value:.4f}"
        return f"`{key}` {value}"

    metrics = report.get("metrics")
    if isinstance(metrics, dict) and metrics:
        return "; ".join(render(key, value) for key, value in sorted(metrics.items())
                         if isinstance(value, (int, float, str)))
    thresholds = report.get("thresholds")
    if isinstance(thresholds, dict) and thresholds:
        pieces = []
        for key in sorted(thresholds):
            for source in ("checks", "totals"):
                values = report.get(source)
                if isinstance(values, dict) and key in values:
                    pieces.append(render(key, values[key]))
                    break
        if pieces:
            return "; ".join(pieces)
    summary = report.get("summary")
    if isinstance(summary, dict):
        counts = {key: summary[key] for key in ("pass", "fail", "skipped")
                  if key in summary}
        if counts:
            return ", ".join(f"{value} {key}" for key, value in counts.items())
    totals = report.get("totals")
    if isinstance(totals, dict) and totals:
        rendered = [render(key, value) for key, value in sorted(totals.items())
                    if isinstance(value, (int, float)) and not isinstance(value, bool)]
        if rendered:
            return "; ".join(rendered)
    # A report that gates on top-level scalars, such as the stage-4 workflow
    # gate's peak RSS and wall time.
    scalars = [render(key, value) for key, value in sorted(report.items())
               if isinstance(value, (int, float)) and not isinstance(value, bool)]
    if scalars:
        return "; ".join(scalars[:4])
    if isinstance(summary, str) and summary:
        return summary
    return "recorded"


def producer(name: str, key: str) -> str:
    """The committed file that writes this report, when one is discoverable."""
    stem = TASK.match(key)
    candidates = []
    for directory in ("tests", "benchmarks", "scripts"):
        for path in sorted((ROOT / directory).glob("*")):
            if not path.is_file():
                continue
            if path.name.startswith(key) or (stem and path.name.startswith(stem.group(0))):
                candidates.append(f"{directory}/{path.name}")
    return f"`{candidates[0]}`" if candidates else "-"


def rows() -> list[tuple[str, str, str, str, str, str]]:
    collected = []
    problems = []
    for path in sorted(REPORTS.glob("*.json")):
        if path.name in UNGATED:
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as failure:
            problems.append(f"{path.name}: unreadable ({failure})")
            continue
        if isinstance(report, list):
            # A table of rows (a before/after record, `n64_layout_discovery.json`)
            # has no verdict to index; m5-012 reads it the same way.
            continue
        if not isinstance(report, dict):
            problems.append(f"{path.name}: not a report object")
            continue
        status = report.get("status")
        if status == "skipped":
            if not report.get("reason"):
                problems.append(f"{path.name}: skipped with no reason")
                continue
        elif report.get("passed") is False:
            problems.append(
                f"{path.name}: records a failure; move it to "
                f"benchmarks/reports/diagnostics/ if it is a diagnostic run")
            continue
        elif "passed" not in report:
            # A recorded measurement rather than a verdict: a frozen baseline,
            # a corpus manifest, a per-architecture measurement. Indexed as
            # what it is, so it cannot read as a gate that passed.
            status = "recorded"
        key = identity(report) or path.stem
        collected.append((path.name, key, milestone(report, key), status or "pass",
                          measured(report), producer(path.name, key)))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        raise SystemExit(1)
    collected.sort(key=lambda row: (row[2], row[1], row[0]))
    return collected


def table() -> str:
    lines = ["| Report | Gate | Milestone | Status | Measured | Produced by |",
             "|---|---|---|---|---|---|"]
    for name, key, stage, status, numbers, produced in rows():
        lines.append(f"| `{name}` | `{key}` | {stage} | {status} | {numbers} "
                     f"| {produced} |")
    return "\n".join(lines)


def update(check: bool) -> bool:
    content = README.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(BEGIN) + r"\n.*?\n" + re.escape(END), re.DOTALL)
    match = pattern.search(content)
    if not match:
        raise ValueError(
            f"README.md has no evidence-index markers ({BEGIN} ... {END})")
    expected = f"{BEGIN}\n{table()}\n{END}"
    if match.group(0) != expected:
        if check:
            print("Evidence index in README.md is stale!", file=sys.stderr)
            print("Run 'python scripts/gen_evidence_index.py' to regenerate it.",
                  file=sys.stderr)
            return False
        README.write_text(content.replace(match.group(0), expected, 1),
                          encoding="utf-8")
        print("Updated README.md evidence index successfully.")
        return True
    if check:
        print("Evidence index in README.md is up to date.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the README index is stale")
    arguments = parser.parse_args()
    return 0 if update(check=arguments.check) else 1


if __name__ == "__main__":
    raise SystemExit(main())
