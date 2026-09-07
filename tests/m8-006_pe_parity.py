#!/usr/bin/env python3
"""m8-006: PE parity as one milestone, enumerated from the importer.

Five PE gates exist and each writes its own report, but nothing states the
milestone-level claim, and nothing notices when the importer grows an
evidence class no gate measures. `m5-012` closed linkage parity the same way:
the claim has to be derived, not written down.

The PE evidence classes are read from the importer's own vocabulary -- the
`native-import:pe-*` provenance strings it can emit -- and then checked three
ways:

  * **exercised**: every declared class appears in a store built from a
    committed fixture. A class the code can emit but no fixture triggers is
    either dead or missing a fixture;
  * **measured**: every declared class is named by a committed report other
    than this one, so some gate says it proved that class;
  * **externals**: PE imports reach the store as external symbols, which is
    the class with no provenance string of its own, and `m8-005` must measure
    it.

The milestone summary is then assembled from the five reports, each of which
must exist, be passing, and carry the metric it claims.

Usage:
    python3 tests/m8-006_pe_parity.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "benchmarks" / "reports"
FIXTURES = ["tiny_pe.exe", "dispatch.exe", "tiny_pe32.exe", "exports32.dll"]
PROVENANCE = re.compile(r'"(native-import:pe-[a-z-]+)"')
# The milestone claim: which report carries which headline metric.
CLAIMS = {
    "m8-001": ["pe.dwarf.fn.recall", "pe.dwarf.fn.unattributed"],
    "m8-002": ["pe32.dwarf.fn.recall", "pe32.dwarf.fn.unattributed",
               "ghidra.dwarf.fn.recall"],
    "m8-003": ["body.crossing", "body.exact"],
    "m8-004": ["pe.tls.callbacks", "pe.exports"],
    "m8-005": ["pe.imports.declared", "pe.imports.unnamed_stubs"],
}


def declared_classes() -> set[str]:
    """The provenance strings the native importer can emit for a PE."""
    found: set[str] = set()
    for source in (ROOT / "crates/lre-core/src").rglob("*.rs"):
        if "test" in source.name:
            continue
        found.update(PROVENANCE.findall(source.read_text(encoding="utf-8")))
    return found


def observed(work: Path) -> tuple[dict[str, int], int]:
    """Provenance counts and external-symbol count over the PE fixtures."""
    counts: dict[str, int] = {}
    externals = 0
    for name in FIXTURES:
        fixture = ROOT / "tests/fixtures-src" / name
        assert fixture.is_file(), f"missing committed fixture {name}"
        project = work / f"{fixture.stem}-parity"
        result = subprocess.run(
            [str(ROOT / "target/release/lre-cli"), "import", str(fixture),
             "--name", "parity", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True)
        assert result.returncode == 0, f"{name}: import failed: {result.stderr.strip()}"
        database = sqlite3.connect(project / "project.sqlite")
        for provenance, count in database.execute(
                "SELECT provenance, COUNT(*) FROM xrefs GROUP BY provenance"):
            if provenance.startswith("native-import:pe-"):
                counts[provenance] = counts.get(provenance, 0) + count
        externals += next(database.execute(
            "SELECT COUNT(*) FROM symbols WHERE external = 1"))[0]
    return counts, externals


def measured_by(name: str) -> list[str]:
    """Committed reports that name this class, excluding this gate's own."""
    holders = []
    for report in sorted(REPORTS.glob("*.json")):
        if report.stem == "m8-006":
            continue
        if name in report.read_text(encoding="utf-8"):
            holders.append(report.name)
    return holders


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    declared = declared_classes()
    assert declared, "the importer declares no PE provenance classes"
    with tempfile.TemporaryDirectory(prefix="m8-006-") as directory:
        counts, externals = observed(Path(directory))

    unexercised = sorted(declared - set(counts))
    assert not unexercised, (
        f"these PE evidence classes are declared but no committed fixture "
        f"produces them: {unexercised}")
    undeclared = sorted(set(counts) - declared)
    assert not undeclared, (
        f"the store holds PE provenance the importer does not declare: {undeclared}")

    coverage = {name: measured_by(name) for name in sorted(declared)}
    unmeasured = sorted(name for name, holders in coverage.items() if not holders)
    assert not unmeasured, (
        f"these PE evidence classes have no committed report behind them: "
        f"{unmeasured}")
    assert externals > 0, "no PE fixture produced an external symbol"
    assert measured_by("pe.imports.declared"), (
        "PE imports reach the store as external symbols, and no committed "
        "report measures them")

    milestone = {}
    missing_claims = []
    for identifier, metrics in CLAIMS.items():
        path = REPORTS / f"{identifier}.json"
        if not path.is_file():
            missing_claims.append(f"{identifier}: no committed report")
            continue
        report = json.loads(path.read_text())
        if not report.get("passed"):
            missing_claims.append(f"{identifier}: report does not pass")
            continue
        held = {}
        for metric in metrics:
            value = report.get("totals", {}).get(metric)
            if value is None:
                value = report.get("metrics", {}).get(metric)
            if value is None:
                for row in report.get("gated", []) + report.get("fixtures", []):
                    if metric in row.get("metrics", {}):
                        value = row["metrics"][metric]
                        break
            if value is None:
                missing_claims.append(f"{identifier}: {metric} is not measured")
            else:
                held[metric] = value
        milestone[identifier] = held
    assert not missing_claims, f"the milestone claim is unsupported: {missing_claims}"

    summary = (f"{len(declared)} PE evidence classes, all exercised by committed "
               f"fixtures and all measured by a committed report; "
               f"{sum(counts.values())} references and {externals} external "
               f"symbols across {len(FIXTURES)} fixtures; five gates carry the "
               f"milestone claim")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m8-006",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {
                "pe.classes.declared": len(declared),
                "pe.classes.unexercised": 0,
                "pe.classes.unmeasured": 0,
                "pe.references": sum(counts.values()),
                "pe.externals": externals,
            },
            "classes": {name: {"references": counts[name], "measured_by": coverage[name]}
                        for name in sorted(declared)},
            "milestone": milestone,
        }, indent=1) + "\n")
    print(f"m8-006: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
