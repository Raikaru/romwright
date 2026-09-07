#!/usr/bin/env python3
"""m5-005: the console platform matrix is measured, not written by hand.

Every console row in the README support matrix must be derived from the
platform's own committed gate report, and every platform that is *not*
supported must be named together with the blocker that stops it. A support
claim nobody measured is the failure mode this gate exists to prevent, so
the checks below are all differential: mutate a report and the row must
move with it; delete a report and the row must disappear.

Usage:
    python3 tests/m5-005_platform_matrix.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "gen_support_matrix.py"
CATALOG = ROOT / "docs" / "platform-tiers.json"
REPORTS = ROOT / "benchmarks" / "reports"
README = ROOT / "README.md"

# The blockers named in STATUS.md's console sequencing decision. Each one is
# a hardware or container fact, not a scheduling preference.
REQUIRED_BLOCKER_TERMS = ("VFPU", "R5900", "SPU", "VMX128", "encrypt")

BEGIN = "<!-- support-matrix:begin -->"
END = "<!-- support-matrix:end -->"


def console_reports() -> dict[str, dict]:
    """The committed console gate reports, keyed by report id.

    A platform report is one carrying a `platform` block. This gate's own
    report does not describe a platform, so it is not one of them.
    """
    found = {}
    for path in sorted(REPORTS.glob("m5-*.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(report.get("platform"), dict):
            found[path.stem] = report
    assert len(found) >= 4, (
        f"expected every gated console platform to commit a report with a "
        f"platform block; found {sorted(found)}"
    )
    return found


def check_reports_carry_platform_identity(reports: dict[str, dict]) -> list[str]:
    """A generator cannot read a summary sentence; it needs fields."""
    inputs = []
    for name, report in reports.items():
        platform = report.get("platform")
        assert isinstance(platform, dict), (
            f"{name}.json has no 'platform' block, so the matrix row for it "
            f"could only be written by hand"
        )
        label = platform.get("input")
        assert isinstance(label, str) and label, f"{name}: platform.input missing"
        assert platform.get("family") == "console", (
            f"{name}: platform.family must be 'console', got {platform.get('family')!r}"
        )
        test = platform.get("test")
        assert isinstance(test, str) and (ROOT / test).is_file(), (
            f"{name}: platform.test must name a committed test, got {test!r}"
        )
        programs = platform.get("programs")
        assert isinstance(programs, list) and programs, (
            f"{name}: platform.programs must list the imported programs"
        )
        for program in programs:
            for key in ("name", "language", "dwarf.fn.recall", "dwarf.functions"):
                assert key in program, f"{name}: program entry missing {key!r}"
            assert isinstance(program["dwarf.fn.recall"], (int, float)), (
                f"{name}: recall must be a number"
            )
        inputs.append(label)
    assert len(set(inputs)) == len(inputs), f"duplicate platform.input values: {inputs}"
    return inputs


def check_catalog() -> list[dict]:
    """The unsupported platforms and their blockers are committed data."""
    assert CATALOG.is_file(), f"{CATALOG.relative_to(ROOT)} does not exist"
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    platforms = catalog.get("platforms")
    assert isinstance(platforms, list) and platforms, "catalog lists no platforms"

    blocked = [p for p in platforms if p.get("tier") == 2]
    assert blocked, "catalog names no tier-2 platform"
    for platform in blocked:
        assert platform.get("input"), f"catalog entry without input: {platform}"
        blocker = platform.get("blocker")
        assert isinstance(blocker, str) and len(blocker) > 20, (
            f"{platform.get('input')}: blocker must state the fact that stops it"
        )
        evidence = platform.get("evidence")
        assert isinstance(evidence, str) and evidence, (
            f"{platform.get('input')}: blocker needs evidence naming where it was checked"
        )

    text = json.dumps(blocked)
    for term in REQUIRED_BLOCKER_TERMS:
        assert term.lower() in text.lower(), (
            f"the {term} blocker is not recorded in the catalog"
        )
    return platforms


def generated_rows(root: Path) -> dict[str, str]:
    """Run the generator in `root` and return its supported-matrix rows."""
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / SCRIPT.name)],
        cwd=root, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"generator failed in fixture tree: {result.stderr.strip() or result.stdout.strip()}"
    )
    rows = {}
    body = (root / "README.md").read_text(encoding="utf-8")
    for line in body.splitlines():
        if line.startswith("| Platform |"):
            break  # the blocked table starts here; those are not claims
        if line.startswith("|") and line.count("|") >= 3 and "---" not in line:
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            rows[cells[0]] = " | ".join(cells[1:])
    return rows


def fixture_tree(root: Path) -> None:
    (root / "scripts").mkdir()
    shutil.copyfile(SCRIPT, root / "scripts" / SCRIPT.name)
    (root / "docs").mkdir()
    shutil.copyfile(CATALOG, root / "docs" / CATALOG.name)
    (root / "benchmarks" / "reports").mkdir(parents=True)
    for path in REPORTS.glob("m5-*.json"):
        shutil.copyfile(path, root / "benchmarks" / "reports" / path.name)
    for name in ("stage4-gate.json", "ui-gate.json", "discovery-gate.json",
                 "parity-gate.json"):
        source = REPORTS / name
        if source.is_file():
            shutil.copyfile(source, root / "benchmarks" / "reports" / name)
    (root / "tests").mkdir()
    for path in sorted(ROOT.glob("tests/m5-*.py")):
        shutil.copyfile(path, root / "tests" / path.name)
    (root / "README.md").write_text(
        f"## Support matrix\n\n{BEGIN}\n| stale |\n{END}\n", encoding="utf-8"
    )


def check_rows_follow_the_reports(reports: dict[str, dict]) -> dict[str, object]:
    """Differential checks: the row must move when the measurement moves."""
    observed: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m5-005-") as temporary:
        root = Path(temporary)
        fixture_tree(root)
        baseline = generated_rows(root)

        for name, report in reports.items():
            label = report["platform"]["input"]
            assert label in baseline, (
                f"{name}: no generated row for {label!r}; rows are "
                f"{sorted(baseline)}"
            )
            recall = max(p["dwarf.fn.recall"] for p in report["platform"]["programs"])
            assert f"{recall:.4f}" in baseline[label], (
                f"{label}: generated row does not carry the measured recall "
                f"{recall:.4f}: {baseline[label]!r}"
            )
        observed["rows"] = baseline

        # 1. A different measured number produces a different row.
        target = "m5-001"
        path = root / "benchmarks" / "reports" / f"{target}.json"
        doctored = json.loads(path.read_text())
        for program in doctored["platform"]["programs"]:
            program["dwarf.fn.recall"] = 0.9123
        path.write_text(json.dumps(doctored))
        moved = generated_rows(root)
        label = reports[target]["platform"]["input"]
        assert "0.9123" in moved[label], (
            f"{label}: row ignored the report's recall; it is hard-coded: "
            f"{moved[label]!r}"
        )

        # 2. A failed gate cannot render as a gated claim.
        doctored["status"] = "fail"
        doctored["passed"] = False
        path.write_text(json.dumps(doctored))
        failed = generated_rows(root)
        assert "gated" not in failed[label].lower(), (
            f"{label}: a failed gate still claims to be gated: {failed[label]!r}"
        )

        # 3. No report, no claim.
        path.unlink()
        without = generated_rows(root)
        assert label not in without, (
            f"{label}: row survived the deletion of its gate report, so the "
            f"claim is not measured"
        )

        # 4. Tier-2 platforms are named with their blockers, and never as
        #    supported inputs.
        catalog = json.loads((root / "docs" / CATALOG.name).read_text())
        body = (root / "README.md").read_text(encoding="utf-8")
        blocked_rows = 0
        for platform in catalog["platforms"]:
            if platform.get("tier") != 2:
                continue
            blocked_rows += 1
            assert platform["input"] in body, (
                f"{platform['input']} is not named in the generated section"
            )
            assert platform["blocker"] in body, (
                f"{platform['input']}: its blocker is not printed"
            )
            assert platform["input"] not in without, (
                f"{platform['input']} appears as a supported input"
            )
        observed["blocked"] = blocked_rows

        # 5. An unproven tier-1 claim is a generation failure, not a row.
        catalog["platforms"].append({
            "input": "Invented platform",
            "tier": 1,
            "gate": "m5-999",
        })
        (root / "docs" / CATALOG.name).write_text(json.dumps(catalog))
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / SCRIPT.name)],
            cwd=root, capture_output=True, text=True,
        )
        assert result.returncode != 0, (
            "the generator printed a tier-1 support claim with no gate report"
        )
        assert "m5-999" in (result.stderr + result.stdout), (
            "the generator did not name the missing gate report"
        )
    return observed


def check_readme_in_sync() -> None:
    body = README.read_text(encoding="utf-8")
    assert BEGIN in body and END in body, (
        "README support matrix is not delimited by generator markers, so it "
        "cannot be regenerated without hand editing"
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"README support matrix is stale: "
        f"{result.stderr.strip() or result.stdout.strip()}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    reports = console_reports()
    inputs = check_reports_carry_platform_identity(reports)
    catalog = check_catalog()
    observed = check_rows_follow_the_reports(reports)
    check_readme_in_sync()

    summary = (
        f"{len(inputs)} console platforms generated from gate reports, "
        f"{observed['blocked']} blocked platforms named with their blockers"
    )
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({
            "id": "m5-005",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {
                "generated_rows": len(inputs),
                "blocked_platforms": observed["blocked"],
                "catalog_platforms": len(catalog),
            },
            "inputs": inputs,
        }, indent=1) + "\n", encoding="utf-8")
    print(f"m5-005: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
