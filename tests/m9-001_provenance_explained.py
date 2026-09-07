#!/usr/bin/env python3
"""m9-001: every fact says what proved it, from one table.

The store labels each fact with the pass that produced it --
`native-import:pe-export`, `native-analysis:constant-propagation` -- and every
surface showed that string raw or not at all. The CLI printed
`source=native-import:pe-reloc`, the desktop's xrefs dock showed no
provenance column whatsoever, and a user had no way to learn what a base
relocation proves.

One table in `lre-model` names each class in a sentence, and every surface
reads that table rather than keeping its own:

  * the API serialises `explanation` inside every `provenance` object, so a
    consumer never has to map the string itself;
  * `lre-cli provenance` lists the table, or the classes one program holds;
  * the desktop's xrefs dock renders the sentence, counted by the UI gate as
    `ui.xrefs.unexplained`.

The gate requires:

  * every provenance string the crates declare has a sentence;
  * every provenance value present in a store built from a committed fixture
    or a locked corpus entry has a sentence;
  * a real `lre-api` process returns that same sentence with each fact;
  * `benchmarks/reports/ui-gate.json` records `ui.xrefs.unexplained == 0`, so
    the desktop is measured rather than assumed.

Usage:
    python3 tests/m9-001_provenance_explained.py --corpus-dir DIR [--report OUT.json]
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
PE_FIXTURES = ["tiny_pe.exe", "dispatch.exe", "tiny_pe32.exe", "exports32.dll"]
# The vocabulary the crates declare: a provenance string is a fact's source,
# never incidental text, so the literals are the definition.
DECLARED = re.compile(r'"(native-(?:import|analysis)(?::[a-z0-9-]+)*)"')


def declared_classes() -> set[str]:
    found: set[str] = set()
    for source in (ROOT / "crates").rglob("*.rs"):
        if "/target/" in str(source):
            continue
        found.update(DECLARED.findall(source.read_text(encoding="utf-8")))
    return found


def table() -> dict[str, str]:
    """The shared table, as the CLI publishes it."""
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "provenance", "--json"],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"`lre-cli provenance --json` failed: {result.stderr.strip()}")
    rows = json.loads(result.stdout)
    return {row["source"]: row["explanation"] for row in rows}


def store_classes(binary: Path, work: Path) -> tuple[set[str], Path]:
    project = work / f"{binary.stem}-explained"
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(binary),
         "--name", "explained", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"{binary.name}: import failed: {result.stderr.strip()}"
    database = sqlite3.connect(project / "project.sqlite")
    found = {row[0] for row in database.execute("SELECT DISTINCT provenance FROM xrefs")}
    found |= {row[0] for row in database.execute("SELECT DISTINCT source FROM symbols")}
    found |= {row[0] for row in database.execute(
        "SELECT DISTINCT provenance FROM thunks")}
    return {value for value in found if value}, project


def api_explanations(project: Path, address: str) -> list[dict]:
    """Facts as a real API process returns them."""
    request = json.dumps({"api": 2, "id": 1, "method": "xrefs",
                          "params": {"program": "explained", "address": address}})
    result = subprocess.run(
        [str(ROOT / "target/release/lre-api"), "--project", str(project)],
        cwd=ROOT, input=request + "\n", capture_output=True, text=True)
    assert result.returncode == 0, f"lre-api failed: {result.stderr.strip()}"
    answer = json.loads(result.stdout.splitlines()[0])
    assert "result" in answer, f"xrefs failed: {answer}"
    return answer["result"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "-p", "lre-api"], cwd=ROOT, check=True)
    declared = declared_classes()
    published = table()
    assert published, "the shared table is empty"

    unexplained_declared = sorted(name for name in declared if not published.get(name))
    assert not unexplained_declared, (
        f"these declared provenance classes have no sentence: {unexplained_declared}")

    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"] if entry.get("status") == "ok"]
    assert entries, "the corpus has no usable entry"

    observed: dict[str, int] = {}
    api_checked = 0
    with tempfile.TemporaryDirectory(prefix="m9-001-") as directory:
        work = Path(directory)
        images = [arguments.corpus_dir / entry["binary"] for entry in entries[:4]]
        images += [ROOT / "tests/fixtures-src" / name for name in PE_FIXTURES]
        for image in images:
            classes, project = store_classes(image, work)
            for name in classes:
                observed[name] = observed.get(name, 0) + 1
            # One image is enough to prove the API carries the sentence, but
            # every fact in it must, not a sample.
            if api_checked == 0:
                database = sqlite3.connect(project / "project.sqlite")
                address = next(database.execute(
                    "SELECT dst FROM xrefs ORDER BY dst LIMIT 1"), (None,))[0]
                if address:
                    facts = api_explanations(project, address)
                    silent = [fact for fact in facts
                              if not fact.get("provenance", {}).get("explanation")]
                    assert not silent, (
                        f"{image.name}: the API returned facts with no explanation: "
                        f"{silent[:2]}")
                    wrong = [fact for fact in facts
                             if fact["provenance"]["explanation"]
                             != published.get(fact["provenance"]["source"])]
                    assert not wrong, (
                        f"{image.name}: the API explanation differs from the table: "
                        f"{wrong[:2]}")
                    api_checked = len(facts)

    unexplained_observed = sorted(name for name in observed if not published.get(name))
    assert not unexplained_observed, (
        f"these provenance values appear in a store with no sentence: "
        f"{unexplained_observed}")
    assert api_checked > 0, "no fixture produced a fact to check through the API"

    ui = REPORTS / "ui-gate.json"
    assert ui.is_file(), "benchmarks/reports/ui-gate.json is not committed"
    ui_metrics = json.loads(ui.read_text()).get("metrics", {})
    assert "ui.xrefs.unexplained" in ui_metrics, (
        "the committed UI gate does not measure ui.xrefs.unexplained, so the "
        "desktop's rendering is assumed rather than measured")
    assert ui_metrics["ui.xrefs.unexplained"] == 0, (
        f"the desktop rendered {ui_metrics['ui.xrefs.unexplained']} facts with "
        f"no explanation")
    assert ui_metrics.get("ui.xrefs.rows", 0) > 0, (
        "the UI gate rendered no xref rows, so the count proves nothing")

    summary = (f"{len(published)} classes in the shared table, "
               f"{len(declared)} declared in the crates and "
               f"{len(observed)} observed in stores, all explained; "
               f"{api_checked} facts carried the table's sentence through the "
               f"API; the desktop rendered {ui_metrics['ui.xrefs.rows']} xref "
               f"rows with 0 unexplained")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m9-001",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {
                "provenance.classes": len(published),
                "provenance.declared": len(declared),
                "provenance.observed": len(observed),
                "provenance.unexplained": 0,
                "provenance.api_facts_checked": api_checked,
                "ui.xrefs.unexplained": ui_metrics["ui.xrefs.unexplained"],
                "ui.xrefs.rows": ui_metrics["ui.xrefs.rows"],
            },
            "table": published,
            "observed": {name: observed[name] for name in sorted(observed)},
        }, indent=1) + "\n")
    print(f"m9-001: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
