#!/usr/bin/env python3
"""m9-003: ask for facts by the standard that proved them.

`m9-002` classified every provenance class as `declared`, `decoded` or
`inferred`. Nothing let a consumer *ask* by that standard: a script auditing a
binary had to fetch every reference and filter client-side, paying for rows it
throws away and losing the page total, and the desktop could not show
"declared only".

`xrefs_page` and `symbols_page` now take `evidence`. The filter is derived
from the shared table -- the sources of that kind -- so it cannot drift from
what the API reports on each fact.

Per image the gate proves, over the API rather than the store:

  * **exactness**: for each kind, the filtered rows are exactly the unfiltered
    rows whose class carries that kind -- no row missing, none extra;
  * **an honest page**: the filtered `total` counts the filtered facts, not all
    of them, and `revision` is the same store revision the unfiltered page
    reports;
  * **paging**: two half-pages under a filter reassemble the whole filtered
    set in order;
  * **refusal**: an evidence kind that does not exist is `invalid_params`, not
    an empty page that looks like an answer.

Usage:
    python3 tests/m9-003_evidence_filter.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KINDS = ("declared", "decoded", "inferred")
PE_FIXTURES = {"tiny_pe32.exe": "llvm-strip", "exports32.dll": "i686-w64-mingw32-strip"}


class Api:
    """One long-lived `romwright-api` process, spoken to over its stdio protocol."""

    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(ROOT / "target/release/romwright-api"), "--project", str(project)],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.identity = 0

    def call(self, method: str, **params):
        self.identity += 1
        self.process.stdin.write(json.dumps(
            {"api": 2, "id": self.identity, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"the service closed on {method}"
        return json.loads(line)

    def result(self, method: str, **params):
        answer = self.call(method, **params)
        assert "result" in answer, f"{method} failed: {answer}"
        return answer["result"]

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=30)


def table() -> dict[str, str]:
    """Class -> evidence kind, as the CLI publishes the shared table."""
    result = subprocess.run(
        [str(ROOT / "target/release/romwright-cli"), "provenance", "--json"],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"`romwright-cli provenance` failed: {result.stderr.strip()}"
    return {row["source"]: row["evidence"] for row in json.loads(result.stdout)}


def busiest(api: Api, program: str) -> list[str]:
    """Addresses with the most references, so a page has something to filter."""
    counts: dict[str, int] = {}
    page = api.result("xrefs_page", program=program, address="0", incoming=True,
                      offset=0, limit=1)
    del page  # the address is required; this only proves the method answers
    rows = api.result("functions", program=program)
    for row in rows:
        address = f"{row['entry']['offset']:08x}"
        answer = api.result("xrefs_page", program=program, address=address,
                            incoming=True, offset=0, limit=256)
        if answer["rows"]:
            counts[address] = len(answer["rows"])
    return [address for address, _ in
            sorted(counts.items(), key=lambda item: -item[1])[:4]]


def check_xrefs(api: Api, program: str, address: str, kinds: dict[str, str]) -> dict:
    whole = api.result("xrefs_page", program=program, address=address,
                       incoming=True, offset=0, limit=1024)
    unfiltered = whole["rows"]
    checked = 0
    for kind in KINDS:
        expected = [row for row in unfiltered
                    if kinds.get(row["provenance"]["source"]) == kind]
        page = api.result("xrefs_page", program=program, address=address,
                          incoming=True, offset=0, limit=1024, evidence=kind)
        got = page["rows"]
        assert got == expected, (
            f"{program} {address} {kind}: filtered rows differ from the "
            f"unfiltered rows of that kind ({len(got)} vs {len(expected)})")
        assert page["total"] == len(expected), (
            f"{program} {address} {kind}: total is {page['total']} for "
            f"{len(expected)} filtered facts")
        assert page["revision"] == whole["revision"], (
            f"{program} {address} {kind}: revision changed under a filter")
        if len(expected) >= 2:
            half = len(expected) // 2
            first = api.result("xrefs_page", program=program, address=address,
                               incoming=True, offset=0, limit=half, evidence=kind)
            second = api.result("xrefs_page", program=program, address=address,
                                incoming=True, offset=half, limit=1024, evidence=kind)
            assert first["rows"] + second["rows"] == expected, (
                f"{program} {address} {kind}: paging under the filter lost or "
                f"reordered rows")
            assert first["total"] == len(expected), (
                f"{program} {address} {kind}: a partial page reported total "
                f"{first['total']}")
        checked += len(expected)
    assert checked == len([row for row in unfiltered
                           if row["provenance"]["source"] in kinds]), (
        f"{program} {address}: the three kinds do not partition the facts")
    return {"address": address, "references": len(unfiltered), "matched": checked}


def check_symbols(api: Api, program: str, kinds: dict[str, str]) -> dict:
    whole = api.result("symbols_page", program=program, offset=0, limit=4096)
    unfiltered = whole["rows"]
    total_matched = 0
    for kind in KINDS:
        expected = [row for row in unfiltered if kinds.get(row["source"]) == kind]
        page = api.result("symbols_page", program=program, offset=0, limit=4096,
                          evidence=kind)
        assert page["rows"] == expected, (
            f"{program} symbols {kind}: filtered rows differ ({len(page['rows'])} "
            f"vs {len(expected)})")
        assert page["total"] == len(expected), (
            f"{program} symbols {kind}: total is {page['total']} for "
            f"{len(expected)} filtered symbols")
        assert page["revision"] == whole["revision"], (
            f"{program} symbols {kind}: revision changed under a filter")
        total_matched += len(expected)
    return {"symbols": len(unfiltered), "matched": total_matched}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                    "-p", "romwright-api"], cwd=ROOT, check=True)
    kinds = table()
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"] if entry.get("status") == "ok"]
    assert entries, "the corpus has no usable entry"

    rows = []
    with tempfile.TemporaryDirectory(prefix="m9-003-") as directory:
        work = Path(directory)
        images = [arguments.corpus_dir / entry["binary"] for entry in entries[:3]]
        for name, tool in PE_FIXTURES.items():
            stripped = work / name
            shutil.copy2(ROOT / "tests/fixtures-src" / name, stripped)
            subprocess.run([tool, "--strip-all", str(stripped)], check=True)
            images.append(stripped)

        for image in images:
            project = work / f"{image.stem}-filter"
            built = subprocess.run(
                [str(ROOT / "target/release/romwright-cli"), "import", str(image),
                 "--name", "filtered", "--project", str(project)],
                cwd=ROOT, capture_output=True, text=True)
            assert built.returncode == 0, (
                f"{image.name}: import failed: {built.stderr.strip()}")
            api = Api(project)
            try:
                addresses = busiest(api, "filtered")
                assert addresses, f"{image.name}: no address carries a reference"
                checks = [check_xrefs(api, "filtered", address, kinds)
                          for address in addresses]
                symbols = check_symbols(api, "filtered", kinds)
                refused = api.call("xrefs_page", program="filtered",
                                   address=addresses[0], incoming=True,
                                   offset=0, limit=8, evidence="probably")
                assert refused.get("error", {}).get("code") == "invalid_params", (
                    f"{image.name}: an unknown evidence kind was answered rather "
                    f"than refused: {refused}")
            finally:
                api.close()
            rows.append({"id": image.name, "addresses": checks, **symbols})

    facts = sum(check["matched"] for row in rows for check in row["addresses"])
    metrics = {
        "filter.images": len(rows),
        "filter.addresses": sum(len(row["addresses"]) for row in rows),
        "filter.facts_matched": facts,
        "filter.symbols_matched": sum(row["matched"] for row in rows),
        "filter.kinds": len(KINDS),
    }
    summary = (f"{metrics['filter.images']} images: {metrics['filter.addresses']} "
               f"addresses filtered by each of {len(KINDS)} evidence kinds, "
               f"{facts} references and {metrics['filter.symbols_matched']} symbols "
               f"returned exactly by kind with honest totals, paging preserved, "
               f"and an unknown kind refused")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m9-003",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "images": rows,
        }, indent=1) + "\n")
    print(f"m9-003: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
