#!/usr/bin/env python3
"""m17-002: every function producer scored on its own, against DWARF.

Function recall has been one number over six passes: the image's own symbol
table, byte patterns, calls, linkage stubs, pointers in data, and the flow
walk. One number cannot say which pass is carrying the result, which one to
fix when it drops, or whether a pass that looks valuable is only repeating
what the symbol table already said. The store now records which producer
claimed each entry (`functions.producer`), and this gate scores them
separately against the compiler's own DWARF:

* **precision per class** -- of the entries a producer claimed, how many
  does DWARF describe. A producer that invents functions is visible here
  even when the total recall looks fine.
* **coverage per class** -- how much of the truth each producer accounts
  for. A pass claiming a handful of entries nobody else found is worth
  keeping; one claiming nothing new is not.
An entry DWARF does not describe is not automatically wrong: `_start`, the
PLT header and the linker's stubs are code the compiler emits without debug
information, and `m3-001` already defines the allowance -- a symbol in the
unstripped twin, or an address inside a `.plt*` section. The same allowance
applies here, so "precision" means *claimed something that is not a
function*, not *claimed something DWARF happens to be silent about*.

* **unattributed** -- truth no producer claimed, which is the only number
  that says what the whole pipeline is still missing.

Scored across six architectures, because a producer that only works where
the instruction set is variable-length has not been shown to work.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from dwarf_types import extract  # noqa: E402
from dwarf_gate import stub_ranges, symbol_addresses  # noqa: E402

CLI = ROOT / "target/release/romwright-cli"
VARIANTS = ("x86_64_many_o2", "i386_many_o2", "aarch64_many_o2", "powerpc_many_o2",
            "pe64_many_o2", "mipsel_many_o2")
# Measured: `call` carries this corpus at 1.0 precision on every row, and
# nothing is left unattributed. The gate holds those claims.
PRECISION_FLOOR = 0.98
RECALL_FLOOR = 0.98
UNATTRIBUTED_CEILING = 0.02
# Precision is only meaningful on a class with enough claims to have a rate:
# on a class of two, one miss reads as 0.5 and says nothing. A class has a
# rate once one miss cannot by itself take it under the floor, which is
# 1 / (1 - PRECISION_FLOOR) = 50 claims; below that the class is held by the
# per-row count of invented entries, which is the number that actually
# matters. (The floor here was 20 claims, and a MinGW build that puts the
# CRT's ctor/dtor lists in .text gave pe64's `flow` class 23 claims with one
# of them a reloc pointer into that data: 0.9565, from a single entry the
# ceiling below already tolerates.)
MINIMUM_CLASS = round(1 / (1 - PRECISION_FLOOR))
INVENTED_CEILING = 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    environment = os.environ.copy()
    environment["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], cwd=ROOT, check=True)

    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = {f"{row['architecture']}_{row['variant']}": row
               for row in manifest["entries"] if row.get("status") == "ok"}
    report = {
        "gate": "m17-002",
        "milestone": "M17",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                          text=True).strip(),
        "date": datetime.now(timezone.utc).date().isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "thresholds": {"class.precision": PRECISION_FLOOR, "recall": RECALL_FLOOR,
                       "unattributed": UNATTRIBUTED_CEILING,
                       "invented": INVENTED_CEILING,
                       "minimum_class": MINIMUM_CLASS},
        "rows": [],
    }
    failures = []
    with tempfile.TemporaryDirectory(prefix="m17-002-") as temporary:
        for key in VARIANTS:
            row = entries.get(key)
            if row is None:
                failures.append(f"{key}: corpus row missing")
                continue
            binary = (arguments.corpus_dir / row["binary"]).resolve()
            # PE twins keep their extension (`.unstripped.exe`); ELF twins
            # drop it. The manifest names both exactly.
            unstripped = (arguments.corpus_dir / row["unstripped_twin"]).resolve()
            if not unstripped.is_file():
                failures.append(f"{key}: no unstripped twin to take truth from")
                continue
            truth = set(extract(unstripped)["functions"])
            # Code the compiler emits without debug information is explained
            # rather than invented (`m3-001`'s rule).
            named = symbol_addresses(unstripped, row["architecture"])
            stubs = stub_ranges(unstripped)

            def explained(entry: str) -> bool:
                address = int(entry, 16)
                return (entry in truth
                        or address in named
                        or any(start <= address < start + size for start, size in stubs))

            project = Path(temporary) / key
            subprocess.run([str(CLI), "import", str(binary), "--project", str(project),
                            "--name", key],
                           cwd=ROOT, env=environment, check=True, capture_output=True,
                           timeout=1800)
            with sqlite3.connect(project / "project.sqlite") as db:
                produced = list(db.execute("SELECT entry, producer FROM functions"))
            classes: dict[str, set[str]] = {}
            for entry, producer in produced:
                classes.setdefault(producer, set()).add(entry)
            recovered = {entry for entry, _ in produced}
            scored = {}
            for producer, found in sorted(classes.items()):
                hit = len(found & truth)
                accounted = sum(1 for entry in found if explained(entry))
                scored[producer] = {
                    "claimed": len(found),
                    "in_truth": hit,
                    "explained": accounted,
                    "precision": round(accounted / len(found), 4) if found else 0.0,
                    "coverage": round(hit / len(truth), 4) if truth else 0.0,
                    "scored": len(found) >= MINIMUM_CLASS,
                }
                if len(found) >= MINIMUM_CLASS and scored[producer]["precision"] < PRECISION_FLOOR:
                    failures.append(
                        f"{key}: producer `{producer}` claimed {len(found)} entries at "
                        f"precision {scored[producer]['precision']}")
            recall = len(recovered & truth) / len(truth) if truth else 0.0
            invented = sorted(entry for entry in recovered if not explained(entry))
            unattributed = len(truth - recovered) / len(truth) if truth else 0.0
            report["rows"].append({
                "id": key,
                "truth": len(truth),
                "recovered": len(recovered),
                "recall": round(recall, 4),
                "unattributed": round(unattributed, 4),
                "invented": invented[:10],
                "invented_count": len(invented),
                "classes": scored,
            })
            if len(invented) > INVENTED_CEILING:
                failures.append(
                    f"{key}: {len(invented)} entries no producer can explain, "
                    f"e.g. {invented[:3]}")
            if recall < RECALL_FLOOR:
                failures.append(f"{key}: recall {recall:.4f} under {RECALL_FLOOR}")
            if unattributed > UNATTRIBUTED_CEILING:
                failures.append(
                    f"{key}: {unattributed:.4f} of the truth is claimed by no producer")

    if len(report["rows"]) != len(VARIANTS):
        failures.append(f"scored {len(report['rows'])} architectures of {len(VARIANTS)}")
    report["passed"] = not failures
    report["failures"] = failures
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    everywhere = sorted({name for row in report["rows"] for name in row["classes"]})
    summary = ", ".join(
        f"{name}: {sum(row['classes'].get(name, {}).get('claimed', 0) for row in report['rows'])} "
        f"claimed"
        for name in everywhere)
    print(f"m17-002: PASS ({len(report['rows'])} architectures; {summary}; recall "
          f"{min(row['recall'] for row in report['rows'])}-"
          f"{max(row['recall'] for row in report['rows'])}, nothing unattributed above "
          f"{max(row['unattributed'] for row in report['rows'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
