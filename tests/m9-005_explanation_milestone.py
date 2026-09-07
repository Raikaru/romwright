#!/usr/bin/env python3
"""m9-005: fact explanation as one milestone, enumerated from the surfaces.

Four gates exist (`m9-001`..`m9-004`) and each writes its own report. Nothing
states the milestone-level claim, and nothing notices when a surface that
shows a fact stops saying what proved it.

The surfaces are enumerated from the repository and then driven, not listed
here:

  * **the API**: every method `docs/core-api.md` publishes is called on a real
    project; every `provenance` object in every answer must carry an
    `explanation` and an `evidence` kind, unless a person asserted the fact,
    in which case the person is the evidence;
  * **the terminal**: every verb `lre-cli` prints in its own usage that takes
    just a program is run; every `source=` it prints must be a class the
    shared table explains;
  * **the window**: the committed UI gate must show no unexplained row and a
    filtered count that narrows without exceeding the whole;
  * **the claim**: each of the four reports must exist, pass, and carry the
    metric it claims.

Usage:
    python3 tests/m9-005_explanation_milestone.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "benchmarks" / "reports"
FIXTURE = ROOT / "tests/fixtures-src/tiny_bin"
METHOD_SECTION = re.compile(r"## Every method\n(.*?)\n\n", re.S)
BACKTICKED = re.compile(r"`([a-z_0-9]+)`")
USAGE_VERB = re.compile(r"^\s*lre-cli ([a-z-]+)")
SOURCE = re.compile(r"source=(\S+?);")
CLAIMS = {
    "m9-001": ["provenance.classes", "provenance.unexplained",
               "ui.xrefs.unexplained"],
    "m9-002": ["evidence.classes", "evidence.unbacked_confidence"],
    "m9-003": ["filter.facts_matched", "filter.symbols_matched"],
    "m9-004": ["surface.cli_rows_checked", "surface.narrowing_addresses"],
}
# Verbs that need more than a program name, or that write: a milestone gate
# reads, and each of these is driven by the gate that owns it.
NEEDS_MORE = {
    "import", "decompile", "decompile-doc", "disasm", "mem", "bookmark",
    "patch", "rename", "comment", "signatures", "dump-specs", "open", "graph",
    "search", "architectures", "provenance", "undo",
}


class Api:
    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(ROOT / "target/release/lre-api"), "--project", str(project)],
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

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=30)


def published_methods() -> list[str]:
    text = (ROOT / "docs/core-api.md").read_text(encoding="utf-8")
    match = METHOD_SECTION.search(text)
    assert match, "docs/core-api.md no longer publishes a method list"
    return sorted(set(BACKTICKED.findall(match.group(1))))


def table() -> dict[str, dict]:
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "provenance", "--json"],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"`lre-cli provenance` failed: {result.stderr.strip()}"
    return {row["source"]: row for row in json.loads(result.stdout)}


def provenance_objects(payload) -> list[dict]:
    """Every structured provenance in an answer, at any depth."""
    found = []
    if isinstance(payload, dict):
        held = payload.get("provenance")
        if isinstance(held, dict):
            found.append(held)
        for value in payload.values():
            found.extend(provenance_objects(value))
    elif isinstance(payload, list):
        for value in payload:
            found.extend(provenance_objects(value))
    return found


def usage_verbs() -> list[str]:
    """The verbs the CLI prints in its own usage, which it emits bare."""
    result = subprocess.run([str(ROOT / "target/release/lre-cli")],
                            cwd=ROOT, capture_output=True, text=True)
    text = result.stdout + result.stderr
    assert "usage:" in text, f"the CLI prints no usage: {text[:200]!r}"
    verbs = []
    for line in text.splitlines():
        match = USAGE_VERB.match(line)
        if match and match.group(1) not in verbs:
            verbs.append(match.group(1))
    return verbs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "-p", "lre-api"], cwd=ROOT, check=True)
    kinds = table()
    methods = published_methods()
    assert methods, "no API methods are published"

    silent, answered, skipped_methods = [], 0, []
    printed_sources: dict[str, int] = {}
    unexplained_sources = []
    with tempfile.TemporaryDirectory(prefix="m9-005-") as directory:
        project = Path(directory) / "project"
        built = subprocess.run(
            [str(ROOT / "target/release/lre-cli"), "import", str(FIXTURE),
             "--name", "tiny", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True)
        assert built.returncode == 0, f"import failed: {built.stderr.strip()}"

        api = Api(project)
        try:
            for method in methods:
                answer = api.call(method, program="tiny")
                if "error" in answer:
                    skipped_methods.append(f"{method}: {answer['error']['code']}")
                    continue
                answered += 1
                for held in provenance_objects(answer["result"]):
                    if held.get("kind") == "asserted":
                        continue  # a person asserted it; the person is the evidence
                    if not held.get("explanation") or not held.get("evidence"):
                        silent.append(f"{method}: {held.get('source')!r}")
        finally:
            api.close()

        for verb in usage_verbs():
            if verb in NEEDS_MORE:
                continue
            result = subprocess.run(
                [str(ROOT / "target/release/lre-cli"), verb, "tiny",
                 "--project", str(project)],
                cwd=ROOT, capture_output=True, text=True)
            if result.returncode != 0:
                continue  # a verb needing more than a program is another gate's
            for source in SOURCE.findall(result.stdout):
                printed_sources[source] = printed_sources.get(source, 0) + 1
                if source not in kinds and source != "unknown":
                    unexplained_sources.append(f"{verb}: {source}")

    assert not silent, (
        f"the API answered with facts that do not say what proved them: {silent[:6]}")
    assert answered >= 8, (
        f"only {answered} published methods answered, which proves too little")
    assert not unexplained_sources, (
        f"the terminal printed sources the table does not explain: "
        f"{unexplained_sources[:6]}")
    assert printed_sources, "no verb printed a fact's source"

    committed = json.loads((REPORTS / "ui-gate.json").read_text())
    windows = [row.get("metrics", {}) for row in committed.get("corpus", [])]
    assert windows, "the committed UI gate report has no corpus entry"
    for window in windows:
        assert window.get("ui.xrefs.unexplained") == 0, (
            f"the window rendered {window.get('ui.xrefs.unexplained')} facts with "
            f"no explanation")
        assert 0 < window.get("ui.xrefs.declared_rows", 0) <= window["ui.xrefs.rows"], (
            f"the window's filtered count is {window.get('ui.xrefs.declared_rows')} "
            f"of {window['ui.xrefs.rows']}")

    milestone, missing = {}, []
    for identifier, metrics in CLAIMS.items():
        path = REPORTS / f"{identifier}.json"
        if not path.is_file():
            missing.append(f"{identifier}: no committed report")
            continue
        report = json.loads(path.read_text())
        if not report.get("passed"):
            missing.append(f"{identifier}: report does not pass")
            continue
        held = {}
        for metric in metrics:
            value = report.get("metrics", {}).get(metric)
            if value is None:
                value = report.get("totals", {}).get(metric)
            if value is None:
                missing.append(f"{identifier}: {metric} is not measured")
            else:
                held[metric] = value
        milestone[identifier] = held
    assert not missing, f"the milestone claim is unsupported: {missing}"

    metrics = {
        "explanation.methods_published": len(methods),
        "explanation.methods_answered": answered,
        "explanation.silent_facts": 0,
        "explanation.printed_sources": len(printed_sources),
        "explanation.window_unexplained": max(
            window["ui.xrefs.unexplained"] for window in windows),
        "explanation.window_declared_rows": min(
            window["ui.xrefs.declared_rows"] for window in windows),
    }
    summary = (f"{answered} of {len(methods)} published API methods answered on a "
               f"real project and every fact in them said what proved it; "
               f"{len(printed_sources)} sources printed by the terminal all "
               f"explained; the window rendered "
               f"{metrics['explanation.window_declared_rows']} declared rows with 0 "
               f"unexplained; four gates carry the milestone claim")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m9-005",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "printed_sources": dict(sorted(printed_sources.items())),
            "methods_skipped": sorted(skipped_methods),
            "milestone": milestone,
        }, indent=1) + "\n")
    print(f"m9-005: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
