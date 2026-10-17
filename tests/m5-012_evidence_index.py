#!/usr/bin/env python3
"""m5-012: the committed evidence is indexed, and the index is generated.

Sixty-five report files sit in `benchmarks/reports/` with no index. Nothing
tells a reader which gates are green, on which artifact, with which numbers,
and twelve of the files carry `passed: false` because they are intermediate
diagnostic runs that were committed next to current evidence. STATUS.md's own
"next task" claimed `gate.sh` reads the thunk report; it does not read any of
them.

This gate makes the evidence surface auditable:

  * every report at the top of `benchmarks/reports/` is current evidence --
    `passed: true`, or a skip with a recorded reason. Diagnostic runs live in
    `benchmarks/reports/diagnostics/`, where they are not claims;
  * every acceptance test that writes a `--report` has a committed report
    carrying its id, so a measured result cannot exist only in a transcript
    (the few that need inputs a checkout lacks are listed with the reason, and
    an exemption that is no longer needed fails);
  * the README index is generated from those reports and is in sync, with the
    rows derived: change a measured number and the row moves, delete a report
    and the row disappears, commit a failing report and the generator refuses.

Usage:
    python3 tests/m5-012_evidence_index.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "gen_evidence_index.py"
REPORTS = ROOT / "benchmarks" / "reports"
DIAGNOSTICS = REPORTS / "diagnostics"
README = ROOT / "README.md"
BEGIN = "<!-- evidence-index:begin -->"
END = "<!-- evidence-index:end -->"
TASK = re.compile(r"^(m\d+-\d+[a-z]?)")
# Acceptance tests that write a `--report` but cannot publish one from a
# checkout: each needs inputs this repository does not hold (retail images,
# private decompilation projects, cross toolchains and hours of wall time).
# The reason is the contract. An exemption that stops being needed fails, so
# the table shrinks when a test gains a committed report.
NEEDS_INPUTS_THE_CHECKOUT_LACKS = {
    "m20-": "the tests without a committed report read retail images or decompilation projects of private games that a checkout lacks (they print `SKIP: ... absent`)",
    "m22-": "C-output lanes: cross compilers, private decompilation repositories and hours of wall time (docs/c-output-lanes.md)",
    "m23-001": "downloads the pinned PS2 toolchains and rebuilds the retail ELFs of private games (docs/new-project.md)",
}


def top_level_reports() -> dict[str, dict]:
    found = {}
    for path in sorted(REPORTS.glob("*.json")):
        try:
            report = json.loads(path.read_text())
        except json.JSONDecodeError as failure:
            raise AssertionError(f"{path.name} is not readable JSON: {failure}")
        found[path.name] = report if isinstance(report, dict) else {"list": report}
    assert found, "no reports are committed"
    return found


def identity(report: dict) -> str | None:
    for key in ("id", "task", "gate"):
        value = report.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def check_reports_are_current(reports: dict[str, dict]) -> list[str]:
    """A committed report at the top level is a claim, so it must hold."""
    failing = []
    for name, report in reports.items():
        if report.get("status") == "skipped":
            assert report.get("reason"), f"{name}: skipped with no recorded reason"
            continue
        if report.get("passed") is False:
            failing.append(name)
    assert not failing, (
        f"reports committed as current evidence that did not pass: {failing}; "
        f"move intermediate runs to benchmarks/reports/diagnostics/"
    )
    return sorted(reports)


def check_every_measured_test_published(reports: dict[str, dict],
                                        publishing: str | None = None) -> list[str]:
    published = {identity(report) for report in reports.values()} - {None}
    # The invocation that writes a report publishes it: this gate's own
    # evidence is created by the run that checks the rule.
    if publishing:
        published.add(publishing)
    missing = []
    for path in sorted(Path(ROOT / "tests").glob("m*")):
        if path.suffix not in (".py", ".sh") or "--report" not in path.read_text(
                errors="replace"):
            continue
        match = TASK.match(path.name)
        if not match:
            continue
        if match.group(1) not in published:
            missing.append(path.name)
    exempt = {name for name in missing for prefix in NEEDS_INPUTS_THE_CHECKOUT_LACKS if name.startswith(prefix)}
    unused = [prefix for prefix in NEEDS_INPUTS_THE_CHECKOUT_LACKS
              if not any(name.startswith(prefix) for name in missing)]
    assert not unused, (
        f"these exemptions cover no test that lacks a report any more; remove them: {unused}")
    missing = [name for name in missing if name not in exempt]
    assert not missing, (
        f"these acceptance tests write a report that is not committed: {missing}")
    return sorted(published)


def fixture(root: Path) -> None:
    (root / "scripts").mkdir()
    shutil.copyfile(SCRIPT, root / "scripts" / SCRIPT.name)
    (root / "benchmarks" / "reports").mkdir(parents=True)
    for path in REPORTS.glob("*.json"):
        shutil.copyfile(path, root / "benchmarks" / "reports" / path.name)
    (root / "tests").mkdir()
    for path in Path(ROOT / "tests").glob("m*"):
        if path.is_file():
            shutil.copyfile(path, root / "tests" / path.name)
    (root / "README.md").write_text(f"## Evidence\n\n{BEGIN}\n| stale |\n{END}\n")


def generated_rows(root: Path) -> dict[str, str]:
    result = subprocess.run([sys.executable, str(root / "scripts" / SCRIPT.name)],
                            cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"generator failed in the fixture tree: "
        f"{result.stderr.strip() or result.stdout.strip()}")
    rows = {}
    for line in (root / "README.md").read_text().splitlines():
        if line.startswith("|") and "---" not in line and line.count("|") >= 3:
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            rows[cells[0]] = " | ".join(cells[1:])
    return rows


def check_rows_follow_the_reports() -> dict[str, object]:
    observed: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m5-012-") as temporary:
        root = Path(temporary)
        fixture(root)
        baseline = generated_rows(root)
        row = "`m5-011.json`"
        assert row in baseline, (
            f"no row for m5-011.json; rows are {sorted(baseline)[:8]}")
        assert "11" in baseline[row], (
            f"the row does not carry the measured number: {baseline[row]!r}")
        observed["rows"] = len(baseline)

        # 1. A measured number moves the row.
        path = root / "benchmarks" / "reports" / "m5-011.json"
        doctored = json.loads(path.read_text())
        doctored["metrics"]["pattern.label.applied"] = 4242
        path.write_text(json.dumps(doctored))
        moved = generated_rows(root)
        assert "4242" in moved[row], (
            f"row ignored the report's metrics: {moved[row]!r}")

        # 2. A failing report is refused outright, not printed as evidence.
        doctored["passed"] = False
        doctored["status"] = "fail"
        path.write_text(json.dumps(doctored))
        refused = subprocess.run(
            [sys.executable, str(root / "scripts" / SCRIPT.name)],
            cwd=root, capture_output=True, text=True)
        assert refused.returncode != 0, (
            "the generator indexed a report that records a failure")
        assert "m5-011" in (refused.stderr + refused.stdout), (
            "the generator did not name the failing report")

        # 3. No report, no row.
        path.unlink()
        without = generated_rows(root)
        assert row not in without, (
            "the row survived deletion of its report, so it is not derived")
    return observed


def check_readme_in_sync() -> None:
    body = README.read_text()
    assert BEGIN in body and END in body, (
        "README has no evidence-index markers, so the index cannot be regenerated")
    result = subprocess.run([sys.executable, str(SCRIPT), "--check"],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"the README evidence index is stale: "
        f"{result.stderr.strip() or result.stdout.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    assert SCRIPT.is_file(), f"{SCRIPT.relative_to(ROOT)} does not exist"
    reports = top_level_reports()
    current = check_reports_are_current(reports)
    published = check_every_measured_test_published(
        reports, "m5-012" if arguments.report else None)
    assert DIAGNOSTICS.is_dir(), (
        f"{DIAGNOSTICS.relative_to(ROOT)} does not exist; intermediate runs have "
        f"nowhere to live that is not a claim")
    diagnostics = sorted(path.name for path in DIAGNOSTICS.glob("*.json"))
    assert diagnostics, "no diagnostic runs were separated from current evidence"
    observed = check_rows_follow_the_reports()
    check_readme_in_sync()

    summary = (f"{len(current)} current reports indexed, {len(published)} published "
               f"ids, {len(diagnostics)} diagnostic runs separated, "
               f"{observed['rows']} generated rows")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m5-012",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {"current_reports": len(current),
                        "published_ids": len(published),
                        "diagnostic_runs": len(diagnostics),
                        "generated_rows": observed["rows"]},
        }, indent=1) + "\n")
    print(f"m5-012: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
