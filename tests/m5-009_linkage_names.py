#!/usr/bin/env python3
"""m5-009: a stub whose import name is proven carries that name.

m5-008 recorded the linkage thunk for every stub whose slot the store
resolves. Five of those stubs are still called `FUN_000206a8` in the function
table while the store holds `__cxa_finalize` as a symbol at that exact
address and stock Ghidra names the function that. Function names are
user-visible and feed m3-001 attribution, so the name has to follow the same
evidence the thunk followed.

The gate compares our function name with the stock name at every thunk entry
stock Ghidra records inside the image, and classifies every difference:

  * `import` -- the stock name is a symbol at that address in our own store
    and our function name is still generated. That is the gap this task
    closes, and it must be zero.
  * `presentation` -- stock's name is a synthetic init/fini-array label
    (`_INIT_0`), which is Ghidra's presentation of a fact we hold as a data
    reference. Accepted only when our store really holds that reference from
    an initializer pointer or a relocation, so the fact cannot be missing
    while the label excuses it.
  * anything else fails.

Names are also audited for support: a function name must be generated
(`FUN_`), or a symbol at the same address, or one of the loader's own
section-derived names. Inventing a name is a failure even when it agrees with
Ghidra.

Usage:
    python3 tests/m5-009_linkage_names.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))

THRESHOLDS = {
    "linkage.name.missing_import": 0,
    "linkage.name.unexplained": 0,
    "linkage.name.unsupported": 0,
}

# Ghidra's labels for entries of `.init_array` / `.fini_array`. Ventris derives
# the same names from the dynamic arrays as of m5-010, so the presentation
# class below is normally empty; it stays because a platform without a dynamic
# table would fall back to it, and it demands the reference either way.
SYNTHETIC = re.compile(r"^_(INIT|FINI)_\d+$")
DERIVED = re.compile(r"^_(INIT|PREINIT|FINI)_\d+$")
# Names `collect_elf_section_starts` gives from the section table itself.
SECTION_NAMES = {"_init", "_fini", "_plt", "_entry"}
# Provenance of a reference that proves an address is an initializer target.
INITIALIZER_SOURCES = ("native-import:elf-pointer", "native-import:elf-reloc",
                       "native-import:elf-unwind")


def native_facts(cli: Path, binary: Path, work: Path, timeout: int) -> dict:
    project = work / "project"
    imported = subprocess.run(
        [str(cli), "import", str(binary), "--name", "scored", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    assert imported.returncode == 0, (
        f"{binary.name}: native import failed: {imported.stderr.strip()}")
    store = sqlite3.connect(project / "project.sqlite")
    functions = {entry.lower(): name for entry, name in store.execute(
        "SELECT entry, name FROM functions")}
    symbols: dict[str, set[str]] = {}
    for address, name in store.execute("SELECT address, name FROM symbols"):
        symbols.setdefault(address.lower(), set()).add(name)
    referenced: dict[str, set[str]] = {}
    for destination, provenance in store.execute(
            "SELECT dst, provenance FROM xrefs WHERE kind = 'DATA'"):
        referenced.setdefault(destination.lower(), set()).add(provenance)
    return {"functions": functions, "symbols": symbols, "referenced": referenced}


def classify(identifier: str, stock: dict, native: dict) -> dict:
    equal, presentation = 0, []
    missing_import, unexplained = [], []
    for entry, fact in sorted(stock.items()):
        ours = native["functions"].get(entry)
        if ours is None:
            continue  # entry not a function of ours; m5-008 owns that class
        theirs = fact["name"]
        if ours == theirs:
            equal += 1
            continue
        if theirs in native["symbols"].get(entry, set()):
            missing_import.append({"entry": entry, "ours": ours, "stock": theirs})
            continue
        if SYNTHETIC.match(theirs):
            sources = native["referenced"].get(entry, set())
            if any(source.startswith(known) for source in sources
                   for known in INITIALIZER_SOURCES):
                presentation.append({"entry": entry, "ours": ours, "stock": theirs,
                                     "evidence": sorted(sources)})
                continue
        unexplained.append({"entry": entry, "ours": ours, "stock": theirs})

    # Every name must be supported by evidence at its own address: a symbol,
    # the section table, or - since m5-010 - an initializer array that
    # references the address and gives the index in the name.
    unsupported = []
    for entry, name in sorted(native["functions"].items()):
        if name.startswith("FUN_") or name in SECTION_NAMES:
            continue
        if name in native["symbols"].get(entry, set()):
            continue
        if DERIVED.match(name):
            sources = native["referenced"].get(entry, set())
            if any(source.startswith(known) for source in sources
                   for known in INITIALIZER_SOURCES):
                continue
        unsupported.append({"entry": entry, "name": name})

    comparable = (equal + len(presentation) + len(missing_import)
                  + len(unexplained))
    return {"id": identifier, "rows": len(stock), "comparable": comparable,
            "equal": equal,
            "presentation": presentation, "missing_import": missing_import,
            "unexplained": unexplained, "unsupported": unsupported}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    report = {"id": "m5-009", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": THRESHOLDS, "status": "skipped"}
    if not (arguments.ghidra / "support/analyzeHeadless").is_file():
        report["reason"] = f"no pinned Ghidra install at {arguments.ghidra}"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    from thunk_gate import stock_thunks

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())

    rows, totals = [], {"rows": 0, "comparable": 0, "equal": 0, "presentation": 0,
                        "missing_import": 0, "unexplained": 0, "unsupported": 0}
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        identifier = f"{entry['architecture']}_{entry['variant']}"
        binary = arguments.corpus_dir / entry["binary"]
        with tempfile.TemporaryDirectory(prefix="m5-009-") as temporary:
            work = Path(temporary)
            exported = stock_thunks(arguments.ghidra, binary, work, arguments.timeout)
            stock = {key.lower(): {"name": value["name"]}
                     for key, value in exported["thunks"].items()}
            native = native_facts(cli, binary, work, arguments.timeout)
        row = classify(identifier, stock, native)
        rows.append(row)
        totals["rows"] += row["rows"]
        totals["comparable"] += row["comparable"]
        totals["equal"] += row["equal"]
        for key in ("presentation", "missing_import", "unexplained", "unsupported"):
            totals[key] += len(row[key])

        assert not row["missing_import"], (
            f"{identifier}: the import name is a symbol at these addresses but the "
            f"function still carries a generated name: {row['missing_import']}")
        assert not row["unexplained"], (
            f"{identifier}: names differ from stock with no explanation: "
            f"{row['unexplained']}")
        assert not row["unsupported"], (
            f"{identifier}: function names with no symbol at their own address: "
            f"{row['unsupported']}")

    assert len(rows) >= 20, f"only {len(rows)} corpus entries were scored"
    assert totals["equal"], "no name agreed with stock, so nothing was compared"
    metrics = {
        # Stock thunks that are not functions of ours belong to m5-008's
        # entry classes; naming is scored only where both have a function.
        "linkage.name.agreement": totals["equal"] / max(totals["comparable"], 1),
        "linkage.name.missing_import": totals["missing_import"],
        "linkage.name.unexplained": totals["unexplained"],
        "linkage.name.unsupported": totals["unsupported"],
        "linkage.name.presentation": totals["presentation"],
    }
    for name, threshold in THRESHOLDS.items():
        assert metrics[name] <= threshold, f"{name} is {metrics[name]}"

    summary = (f"{len(rows)} corpus entries: {totals['equal']}/{totals['comparable']} stock "
               f"thunk names matched, {totals['presentation']} synthetic init-array "
               f"labels not copied but proven by reference, 0 missing import names, "
               f"0 unsupported names")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary, metrics=metrics,
                      totals=totals, corpus=rows)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-009: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
