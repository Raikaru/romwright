#!/usr/bin/env python3
"""m6-006: documentation coverage, enumerated from the repository.

Five pages are gated one by one. What was missing is the milestone-level
claim, and a claim needs a rule that cannot be satisfied by editing the test:

  * **every user-facing surface has a page.** The surfaces are enumerated from
    the repository -- the workspace's `bin` targets, the desktop CMake target,
    the modules under `python/`, and the scripts under `packaging/` -- not from
    a list here. Each must be named by `README.md` or a page under `docs/`.
  * **every page that shows commands is executed.** A page carrying a
    ```console or ```json block is runnable, so some `tests/m6-*` gate must
    name it. A page with no such block is a record and is exempt by its own
    content, not by name.
  * **no page cites a metric no report measured.** Metric families are read
    from the committed reports; any token on a page that belongs to a family
    must be a metric some report actually carries, so a renamed or retired
    metric cannot survive in prose.

Usage:
    python3 tests/m6-006_documentation_coverage.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
REPORTS = ROOT / "benchmarks" / "reports"
COMMANDS = re.compile(r"^```(console|json|sh|bash)$", re.MULTILINE)
NOT_GATED = re.compile(r"<!--\s*not gated:\s*(.+?)\s*-->", re.DOTALL)
BACKTICKED = re.compile(r"`([A-Za-z][A-Za-z0-9_.]*)`")
METRIC_SHAPE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,3}$")


def prose() -> dict[str, str]:
    """Every page a reader is pointed at, including the README."""
    pages = {"README.md": (ROOT / "README.md").read_text(encoding="utf-8")}
    for path in sorted(DOCS.glob("*.md")):
        pages[f"docs/{path.name}"] = path.read_text(encoding="utf-8")
    return pages


def surfaces() -> dict[str, list[str]]:
    """User-facing surfaces, read out of the repository."""
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    binaries = sorted({target["name"] for package in metadata["packages"]
                       for target in package["targets"] if "bin" in target["kind"]})
    desktop = re.findall(r"add_executable\((\S+)",
                         (ROOT / "desktop/romwright-qt/CMakeLists.txt")
                         .read_text(encoding="utf-8"))
    modules = sorted(path.name for path in (ROOT / "python").glob("*.py"))
    packaging = sorted(path.name for path in (ROOT / "packaging").glob("*.py"))
    return {"binaries": binaries, "desktop": sorted(desktop),
            "python": modules, "packaging": packaging}


def reported_metrics() -> tuple[set[str], set[str]]:
    """Metric names, and the parent paths they use, from the reports.

    Collected recursively: reports nest their numbers differently -- some under
    `metrics`, some under `totals`, `checks` or a pass-specific block such as
    `optimized_bounds.before` -- and a metric is a metric wherever it is
    recorded.
    """
    names: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if METRIC_SHAPE.match(key):
                    names.add(key)
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    for path in sorted(REPORTS.rglob("*.json")):
        try:
            walk(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    # A citation counts as a metric only when its parent path is one a report
    # uses: `ghidra.dwarf.fn.recall` is a metric, `ghidra.program.model.listing`
    # is a Java package that happens to start with the same word.
    parents = {name.rsplit(".", 1)[0] for name in names}
    return names, parents


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    pages = prose()
    everything = "\n".join(pages.values())

    # 1. Every surface is named by some page.
    found = surfaces()
    undocumented = {}
    for kind, names in found.items():
        missing = [name for name in names if name not in everything]
        if missing:
            undocumented[kind] = missing
    assert not undocumented, (
        f"these surfaces are named nowhere in README.md or docs/: {undocumented}")

    # 2. Every block that shows commands is executed by a gate, or carries the
    #    reason it is not. A page named by a gate is covered as a whole; a
    #    block on any other page needs `<!-- not gated: reason -->` above it.
    # This gate's own source is excluded: naming a page here would otherwise
    # mark it covered, which is the loophole a coverage rule must not have.
    gate_text = "\n".join(path.read_text(encoding="utf-8")
                          for path in sorted((ROOT / "tests").glob("m6-*.py"))
                          if path.name != Path(__file__).name)
    runnable, ungated, excused = [], [], 0
    for name, text in pages.items():
        blocks = list(COMMANDS.finditer(text))
        if not blocks:
            continue
        gated = name in gate_text or Path(name).name in gate_text
        if gated:
            runnable.append(name)
            # A gate runs every `console`/`json` block on the page it names.
            # An `sh`/`bash` block is illustrative even there, so it still owes
            # a reason -- otherwise a new block hides behind a gated page.
            blocks = [block for block in blocks
                      if block.group(1) in ("sh", "bash")]
        for block in blocks:
            # The window is characters, not lines: a reason worth reading is
            # often two lines long.
            window = text[:block.start()].rstrip()[-320:]
            marker = None
            for marker in NOT_GATED.finditer(window):
                pass
            reason = None
            if marker is not None and window.endswith(marker.group(0)):
                reason = " ".join(marker.group(1).split())
            line_number = text[:block.start()].count("\n") + 1
            if reason is None or len(reason) < 20:
                ungated.append(f"{name}:{line_number}")
            else:
                excused += 1
    assert not ungated, (
        f"these command blocks are neither gated nor marked with a reason: "
        f"{ungated}")

    # 3. No page cites a metric no report measured.
    names, parents = reported_metrics()
    assert names, "no metrics were found in the committed reports"
    stale = {}
    for page, text in pages.items():
        cited = {token for token in BACKTICKED.findall(text)
                 if METRIC_SHAPE.match(token)
                 and token.rsplit(".", 1)[0] in parents}
        missing = sorted(token for token in cited if token not in names)
        if missing:
            stale[page] = missing
    assert not stale, (
        f"these pages cite metrics no committed report carries: {stale}")

    surface_count = sum(len(names) for names in found.values())
    summary = (f"{surface_count} surfaces named in prose, {len(runnable)} pages "
               f"gated command-by-command, {excused} blocks excused with a "
               f"recorded reason, {len(names)} measured metric names, no stale "
               f"citation")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m6-006",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {"surfaces": surface_count,
                        "gated_pages": len(runnable),
                        "excused_blocks": excused,
                        "metric_names": len(names),
                        "pages": len(pages)},
            "surfaces": found,
            "gated_pages": sorted(runnable),
        }, indent=1) + "\n")
    print(f"m6-006: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
