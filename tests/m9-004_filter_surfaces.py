#!/usr/bin/env python3
"""m9-004: the evidence filter, where a user can reach it.

`m9-003` put `evidence` on the paged reads and proved it exact over the API.
No consumer passed it: `lre-cli xrefs` had no flag and the xrefs dock fetched
every reference, so the audit the filter exists for could not be run from a
terminal or a window.

This gate drives both surfaces against the service that answers them:

  * `lre-cli xrefs --evidence KIND` must print **exactly** what the API
    returns for that kind -- including an address where the filter actually
    narrows the set, so a flag that is accepted and ignored fails -- and must
    refuse a kind that does not exist rather than printing everything;
  * the desktop's kind selector must reach the same answer: the app is run in
    gate mode over a fixture and its `ui.xrefs.declared_rows` is compared with
    the API's declared count for the same address, both directions summed;
  * the committed `benchmarks/reports/ui-gate.json` must carry that metric, so
    the window is measured in CI and not only here.

Usage:
    python3 tests/m9-004_filter_surfaces.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
import ui_gate  # noqa: E402

FIXTURE = ROOT / "tests/fixtures-src/tiny_bin"
REPORTS = ROOT / "benchmarks" / "reports"
KINDS = ("declared", "decoded", "inferred")
ROW = re.compile(r"^([0-9a-f]+) --(\S+)--> ([0-9a-f]+) \[.*source=(\S+);")


class Api:
    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(ROOT / "target/release/lre-api"), "--project", str(project)],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.identity = 0

    def result(self, method: str, **params):
        self.identity += 1
        self.process.stdin.write(json.dumps(
            {"api": 2, "id": self.identity, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"the service closed on {method}"
        answer = json.loads(line)
        assert "result" in answer, f"{method} failed: {answer}"
        return answer["result"]

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=30)


def cli(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(ROOT / "target/release/lre-cli"), *arguments],
                          cwd=ROOT, capture_output=True, text=True)


def printed(output: str) -> list[tuple[str, str, str, str]]:
    rows = []
    for line in output.splitlines():
        match = ROW.match(line.strip())
        if match:
            rows.append(match.groups())
    return rows


def api_rows(api: Api, address: str, incoming: bool, kind: str | None):
    params = {"program": "tiny", "address": address, "incoming": incoming,
              "offset": 0, "limit": 4096}
    if kind:
        params["evidence"] = kind
    page = api.result("xrefs_page", **params)
    return [(f"{row['from']['offset']:08x}", row["kind"],
             f"{row['to']['offset']:08x}", row["provenance"]["source"])
            for row in page["rows"]], page["total"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "-p", "lre-api"], cwd=ROOT, check=True)
    assert FIXTURE.is_file(), f"missing committed fixture {FIXTURE.name}"

    checked, narrowing = 0, 0
    with tempfile.TemporaryDirectory(prefix="m9-004-") as directory:
        work = Path(directory)
        project = work / "project"
        built = cli("import", str(FIXTURE), "--name", "tiny", "--project", str(project))
        assert built.returncode == 0, f"import failed: {built.stderr.strip()}"
        api = Api(project)
        try:
            functions = api.result("functions", program="tiny")
            addresses = [f"{row['entry']['offset']:08x}" for row in functions]
            for address in addresses:
                whole, _ = api_rows(api, address, True, None)
                if not whole:
                    continue
                for kind in KINDS:
                    expected, total = api_rows(api, address, True, kind)
                    result = cli("xrefs", "tiny", "--to", address, "--evidence", kind,
                                 "--project", str(project))
                    assert result.returncode == 0, (
                        f"{address} {kind}: cli failed: {result.stderr.strip()}")
                    assert printed(result.stdout) == expected, (
                        f"{address} {kind}: the terminal shows "
                        f"{len(printed(result.stdout))} rows, the API returns {total}")
                    checked += len(expected)
                    if 0 < len(expected) < len(whole):
                        narrowing += 1
            refused = cli("xrefs", "tiny", "--to", addresses[0], "--evidence",
                          "probably", "--project", str(project))
            assert refused.returncode != 0 and "bad evidence kind" in refused.stderr, (
                f"an unknown kind was not refused: {refused.stdout!r} "
                f"{refused.stderr!r}")
            whole_program = cli("xrefs", "tiny", "--evidence", "declared",
                                "--project", str(project))
            assert whole_program.returncode != 0, (
                "filtering without an address was answered rather than refused")

            desktop = {}
            try:
                app = ui_gate.default_app(ROOT).resolve()
            except ui_gate.GateError as failure:
                desktop = {"skipped": str(failure)}
                app = None
            if app is not None:
                # The window navigates to the first function it lists, so the
                # comparison uses the address it reports rather than one picked
                # here -- an address the app never opened would prove nothing.
                metrics = ui_gate.run_app(app, project, FIXTURE, "tiny",
                                          addresses[0], timeout=240.0)
                address = f"{int(metrics['ui.xrefs.address']):08x}"
                declared = sum(api_rows(api, address, incoming, "declared")[1]
                               for incoming in (True, False))
                assert metrics["ui.xrefs.declared_rows"] == declared, (
                    f"the window showed {metrics['ui.xrefs.declared_rows']} declared "
                    f"rows where the service returns {declared}")
                assert metrics["ui.xrefs.declared_rows"] <= metrics["ui.xrefs.rows"], (
                    "a filtered window cannot hold more rows than an unfiltered one")
                unfiltered = sum(api_rows(api, address, incoming, None)[1]
                                 for incoming in (True, False))
                assert metrics["ui.xrefs.rows"] == unfiltered, (
                    f"the window showed {metrics['ui.xrefs.rows']} rows at "
                    f"{address} where the service returns {unfiltered}")
                desktop = {"address": address,
                           "rows": metrics["ui.xrefs.rows"],
                           "declared_rows": metrics["ui.xrefs.declared_rows"],
                           "service_declared": declared}
        finally:
            api.close()

    assert narrowing > 0, (
        "no address had a kind that narrowed the set, so an ignored flag would "
        "have passed")

    committed = json.loads((REPORTS / "ui-gate.json").read_text())
    rows = [row.get("metrics", {}) for row in committed.get("corpus", [])]
    assert rows, "the committed UI gate report has no corpus entry"
    assert all("ui.xrefs.declared_rows" in row for row in rows), (
        "the committed UI gate does not measure ui.xrefs.declared_rows")
    for row in rows:
        assert 0 < row["ui.xrefs.declared_rows"] <= row["ui.xrefs.rows"], (
            f"the committed UI gate records {row['ui.xrefs.declared_rows']} declared "
            f"of {row['ui.xrefs.rows']} rows")

    metrics = {
        "surface.cli_rows_checked": checked,
        "surface.narrowing_addresses": narrowing,
        "surface.ui_declared_rows": desktop.get("declared_rows", -1),
        "surface.ui_rows": desktop.get("rows", -1),
        "surface.committed_ui_declared_rows": min(
            row["ui.xrefs.declared_rows"] for row in rows),
    }
    summary = (f"{checked} rows matched between the terminal and the service across "
               f"{len(KINDS)} kinds, {narrowing} addresses where a kind narrowed the "
               f"set, an unknown kind refused")
    if "skipped" in desktop:
        summary += f"; desktop run skipped ({desktop['skipped']})"
    else:
        summary += (f"; the window showed {desktop['declared_rows']} declared of "
                    f"{desktop['rows']} rows, matching the service")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m9-004",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "desktop": desktop,
        }, indent=1) + "\n")
    print(f"m9-004: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
