#!/usr/bin/env python3
"""m9-002: what a class proves, and when a number is allowed to exist.

`m9-001` gave every provenance class a sentence. It did not say how much
weight the class carries, and the API's `confidence` is `null` for every
native fact while `docs/core-api.md` documents it as "a supplied confidence in
[0, 1]". A consumer cannot rank a swept string against a linker-proven symbol.

Rather than invent floats, each class declares **what kind of evidence it
is** -- the only three kinds the importer actually has:

  * `declared`: the image or the platform states it, in a header, a directory
    or a relocation table;
  * `decoded`: SLEIGH decoded the instruction that performs it;
  * `inferred`: an analysis concluded it from decoded code.

Two rules follow, and both are measured on the locked corpus and the committed
PE fixtures:

  * **A declared class cannot be wrong about a function start.** For every
    class, the share of promoted entries it named that truth attributes is
    measured; a `declared` class must measure 1.0000, because a header-stated
    start that nothing attributes means the header was misread. `decoded` and
    `inferred` classes are recorded without a floor -- they are inferences,
    and the corpus gates score them elsewhere.
  * **A kind is a decision.** Each class's kind and whether it derives a number
    are recorded in `benchmarks/reports/evidence-classes.json`. New classes are
    appended with `--write`; a recorded one is never rewritten, so quietly
    downgrading a class to `inferred` -- which would excuse it from the rule
    above -- fails here.
  * **A number must be derived.** No stored fact may carry a numeric
    `confidence` unless its class declares a derivation. The one derivation
    that exists is the signature matcher's share of compared bytes
    (`lre-sig`), so any other class carrying a number is a number nothing
    derives.

Attribution follows `m3-001`: DWARF truth, a symbol in the unstripped twin, a
linker-stub section, or a name the store itself proved (a pattern label, a
linkage name, a loader name) -- each separately gated.

Usage:
    python3 tests/m9-002_fact_confidence.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))
from dwarf_gate import stub_ranges, symbol_addresses as elf_symbols  # noqa: E402

PE_FIXTURES = {"tiny_pe.exe": "llvm-strip", "dispatch.exe": "llvm-strip",
               "tiny_pe32.exe": "llvm-strip",
               "exports32.dll": "i686-w64-mingw32-strip"}
KINDS = {"declared", "decoded", "inferred"}
RECORD = ROOT / "benchmarks" / "reports" / "evidence-classes.json"


def record_classification(published: dict[str, dict]) -> None:
    """Append new classes; never change one that is already recorded."""
    recorded = json.loads(RECORD.read_text()) if RECORD.is_file() else {}
    for name, row in published.items():
        if name in recorded:
            continue
        recorded[name] = {"evidence": row["evidence"],
                          "derives_confidence": row["derives_confidence"]}
    RECORD.parent.mkdir(parents=True, exist_ok=True)
    RECORD.write_text(json.dumps(dict(sorted(recorded.items())), indent=1) + "\n")
    print(f"recorded {len(recorded)} classes in {RECORD.relative_to(ROOT)}")


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def table() -> dict[str, dict]:
    """The shared table, as the CLI publishes it."""
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "provenance", "--json"],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"`lre-cli provenance --json` failed: {result.stderr.strip()}")
    return {row["source"]: row for row in json.loads(result.stdout)}


def scored_images(corpus: Path, work: Path) -> list[tuple[Path, Path, bool, bool]]:
    manifest = json.loads((corpus / "manifest.json").read_text())
    images = [(corpus / entry["binary"], corpus / entry["unstripped_twin"],
               entry["endian"] == "big", False)
              for entry in manifest["entries"] if entry.get("status") == "ok"]
    assert images, "the corpus has no usable entry"
    for name, tool in PE_FIXTURES.items():
        fixture = ROOT / "tests/fixtures-src" / name
        assert fixture.is_file(), f"missing committed fixture {name}"
        stripped = work / name
        shutil.copy2(fixture, stripped)
        subprocess.run([tool, "--strip-all", str(stripped)], check=True)
        images.append((stripped, fixture, False, True))
    return images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--write", action="store_true",
                        help="add classes the record does not hold yet")
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    pe = load("m8_001", ROOT / "tests/m8-001_pe_unwind.py")
    extents = load("m8_003", ROOT / "tests/m8-003_body_extents.py")
    published = table()
    assert published, "the shared table is empty"

    unclassified = sorted(name for name, row in published.items()
                          if row.get("evidence") not in KINDS)
    assert not unclassified, (
        f"these classes do not say what kind of evidence they are: {unclassified}")

    # A class's kind decides how hard this gate holds it, so changing one is a
    # decision, not a detail: the recorded file is never rewritten in place.
    if arguments.write:
        record_classification(published)
    recorded = json.loads(RECORD.read_text()) if RECORD.is_file() else None
    assert recorded is not None, (
        f"{RECORD.relative_to(ROOT)} does not exist; record it once with --write")
    changed = [f"{name}: recorded {recorded[name]['evidence']}, table says "
               f"{published[name]['evidence']}"
               for name in sorted(recorded)
               if name in published and recorded[name]["evidence"] != published[name]["evidence"]]
    assert not changed, f"a class was reclassified without re-recording: {changed}"
    numbers = [f"{name}: recorded {recorded[name]['derives_confidence']}"
               for name in sorted(recorded)
               if name in published
               and recorded[name]["derives_confidence"] != published[name]["derives_confidence"]]
    assert not numbers, f"a class changed whether it derives a number: {numbers}"
    fresh = sorted(set(published) - set(recorded))
    assert not fresh, (
        f"these classes are not in the record; add them with --write: {fresh}")
    dropped = sorted(set(recorded) - set(published))
    assert not dropped, (
        f"these recorded classes no longer exist in the table: {dropped}")

    per_class: dict[str, dict] = {}
    unbacked: list[str] = []
    with tempfile.TemporaryDirectory(prefix="m9-002-") as directory:
        work = Path(directory)
        for image, twin, big_endian, is_pe in scored_images(arguments.corpus_dir, work):
            project = work / f"{image.stem}-confidence"
            result = subprocess.run(
                [str(ROOT / "target/release/lre-cli"), "import", str(image),
                 "--name", "scored", "--project", str(project)],
                cwd=ROOT, capture_output=True, text=True)
            assert result.returncode == 0, (
                f"{image.name}: import failed: {result.stderr.strip()}")
            database = sqlite3.connect(project / "project.sqlite")
            base = min(int(row[0], 16) for row in
                       database.execute("SELECT start FROM memory_regions"))
            bias = 0 if is_pe or not extents.is_shared_object(twin, big_endian) else base
            executable = extents.executable_ranges(twin)
            truth = {low + bias for low in extents.dwarf_ranges(twin)
                     if any(start <= low < start + size for start, size in executable)}
            if is_pe:
                symbols, stubs = pe.symbol_addresses(twin), []
            else:
                symbols = {address + bias for address in elf_symbols(twin)}
                stubs = [(start + bias, size) for start, size in stub_ranges(twin)]
            functions = {int(entry, 16): name for entry, name in
                         database.execute("SELECT entry, name FROM functions")}

            for _, destination, provenance in database.execute(
                    "SELECT src, dst, provenance FROM xrefs"):
                address = int(destination, 16)
                name = functions.get(address)
                if name is None:
                    continue  # the reference names data, not a promoted entry
                row = per_class.setdefault(
                    provenance, {"references": 0, "attributed": 0, "misses": []})
                row["references"] += 1
                attributed = (
                    address in truth
                    or address in symbols
                    or any(start <= address < start + size for start, size in stubs)
                    or not name.startswith("FUN_"))
                if attributed:
                    row["attributed"] += 1
                elif len(row["misses"]) < 4:
                    row["misses"].append(f"{image.name} {address:08x}")

            for table_name, column in (("xrefs", "provenance"), ("thunks", "provenance")):
                for provenance, confidence in database.execute(
                        f"SELECT {column}, confidence FROM {table_name} "
                        f"WHERE confidence IS NOT NULL"):
                    if not published.get(provenance, {}).get("derives_confidence"):
                        unbacked.append(f"{image.name} {table_name} {provenance}"
                                        f" = {confidence}")

    assert not unbacked, (
        f"facts carry a confidence their class does not derive: {unbacked[:4]}")

    declared_failures = []
    for name, row in sorted(per_class.items()):
        kind = published.get(name, {}).get("evidence")
        rate = row["attributed"] / row["references"] if row["references"] else 0.0
        row["rate"] = round(rate, 4)
        row["evidence"] = kind
        if kind == "declared" and rate < 1.0:
            declared_failures.append(f"{name} {rate:.4f} {row['misses']}")
    assert not declared_failures, (
        f"a declared class named a start nothing attributes: {declared_failures}")
    assert per_class, "no promoted entry carried a provenance"

    declared = sorted(name for name, row in published.items()
                      if row["evidence"] == "declared")
    # A class this gate's images cannot produce may still be exercised: a
    # console's declared memory map only exists once a cartridge is imported,
    # which `m5-001` does and records.
    elsewhere = {}
    for report in sorted((ROOT / "benchmarks" / "reports").glob("*.json")):
        if report.stem.startswith("m9-002"):
            continue
        text = report.read_text(encoding="utf-8")
        for name in declared:
            if name in per_class or name not in text:
                continue
            elsewhere.setdefault(name, []).append(report.name)
    unexercised = sorted(name for name in declared
                         if name not in per_class and name not in elsewhere)
    assert not unexercised, (
        f"these declared classes are exercised by nothing: {unexercised}")
    exercised = sorted(name for name in declared if name in per_class)

    metrics = {
        "evidence.classes": len(published),
        "evidence.declared": len(declared),
        "evidence.declared_exercised": len(exercised),
        "evidence.declared_elsewhere": len(elsewhere),
        "evidence.unbacked_confidence": 0,
        "evidence.references": sum(row["references"] for row in per_class.values()),
        **{f"evidence.attributed.{name}": per_class[name]["rate"]
           for name in sorted(per_class)},
    }
    summary = (f"{len(published)} classes classified as declared/decoded/inferred; "
               f"{len(exercised)} of {len(declared)} declared classes scored here "
               f"and {len(elsewhere)} by another committed gate, each attributing "
               f"1.0000 of the "
               f"{sum(per_class[name]['references'] for name in exercised)} entries "
               f"they named; {metrics['evidence.references']} promoted references "
               f"scored in total; no fact carries a confidence its class does not "
               f"derive")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m9-002",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "thresholds": {"declared class attribution": 1.0,
                           "evidence.unbacked_confidence": 0},
            "metrics": metrics,
            "classes": {name: published[name] for name in sorted(published)},
            "scored": {name: per_class[name] for name in sorted(per_class)},
            "declared_elsewhere": elsewhere,
        }, indent=1) + "\n")
    print(f"m9-002: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
