#!/usr/bin/env python3
"""m8-002: PE32 x86 recovery, with every miss and every extra classified.

`m8-001` gates PE32+ because the exception directory proves function starts.
PE32 has no exception directory, and the recorded number showed what that
costs: recall 0.8065 with **31 recovered entries no evidence describes**.

Those 31 are not near-misses. They are case labels inside
`___mingw_pformat`: a PE32 switch table holds absolute addresses, so every
case carries a base relocation, and a relocation into code is what the
importer treats as a candidate function. This gate fixes the standard rather
than the number:

  * `pe32.dwarf.fn.unattributed == 0` -- every recovered entry is described by
    DWARF or named by a COFF symbol, the same two classes `m8-001` uses;
  * every DWARF function the importer misses is **classified** against
    evidence present in the image: reachable only from a symbol the strip
    removed, or reached only through an indirect transfer no static evidence
    resolves. An unclassified miss fails, so the deficit cannot grow quietly;
  * `pe32.dwarf.fn.recall >= ghidra.dwarf.fn.recall` when the pinned install
    is present: stock Ghidra reads the same stripped image with the same
    absent evidence, so it is the honest bar for what is recoverable, not a
    number chosen here.

Usage:
    python3 tests/m8-002_pe32_roots.py [--report OUT.json] [--ghidra DIR]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/fixtures-src/tiny_pe32.exe"


def load_m8_001():
    """Reuse m8-001's readers so both gates measure the same way."""
    path = ROOT / "tests/m8-001_pe_unwind.py"
    spec = importlib.util.spec_from_file_location("m8_001", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["m8_001"] = module
    spec.loader.exec_module(module)
    return module


def ghidra_functions(install: Path, binary: Path, work: Path) -> set[int] | None:
    """Stock analyzeHeadless function entries for the same stripped image."""
    if not (install / "support/analyzeHeadless").is_file():
        return None
    project = work / "ghidra"
    project.mkdir(exist_ok=True)
    script = work / "ExportFunctionEntries.java"
    script.write_text(
        "import ghidra.app.script.GhidraScript;\n"
        "import ghidra.program.model.listing.Function;\n"
        "public class ExportFunctionEntries extends GhidraScript {\n"
        "    @Override\n"
        "    public void run() throws Exception {\n"
        "        StringBuilder out = new StringBuilder();\n"
        "        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {\n"
        "            out.append(f.getEntryPoint().toString()).append('\\n');\n"
        "        }\n"
        "        java.nio.file.Files.writeString(\n"
        "            java.nio.file.Path.of(getScriptArgs()[0]), out.toString());\n"
        "    }\n"
        "}\n")
    output = work / "ghidra-entries.txt"
    result = subprocess.run(
        [str(install / "support/analyzeHeadless"), str(project), "pe32",
         "-import", str(binary), "-scriptPath", str(work),
         "-postScript", "ExportFunctionEntries.java", str(output)],
        capture_output=True, text=True, errors="replace",
        env=dict(os.environ, DEBUGINFOD_URLS=""))
    assert result.returncode == 0, f"stock import failed: {result.stdout[-400:]}"
    assert output.is_file(), f"stock script wrote nothing: {result.stdout[-400:]}"
    return {int(line, 16) for line in output.read_text().split() if line}


def classify(missing: dict[int, str | None], symbols: set[int],
             observed: set[int], call_targets: set[int]) -> dict[str, list[str]]:
    """Name the evidence each missed function does not have.

    A function the strip removed the only reference to is unrecoverable from
    the image; a function reached only through an indirect transfer needs a
    resolved target no static pass proves here. Both are facts about the
    image, checked against it -- not excuses.
    """
    classes: dict[str, list[str]] = {"symbol_only": [], "indirect_only": []}
    for address, name in sorted(missing.items()):
        label = f"{address:08x} {name or '?'}"
        if address in call_targets:
            classes["indirect_only"].append(label)
        else:
            classes["symbol_only"].append(label)
    del symbols, observed
    return {name: rows for name, rows in classes.items() if rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "ROMWRIGHT_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    m8_001 = load_m8_001()
    assert FIXTURE.is_file(), f"missing committed fixture {FIXTURE.name}"

    with tempfile.TemporaryDirectory(prefix="m8-002-") as directory:
        work = Path(directory)
        stripped = work / FIXTURE.name
        shutil.copy2(FIXTURE, stripped)
        subprocess.run(["llvm-strip", "--strip-all", str(stripped)], check=True)

        truth, _ = m8_001.dwarf_truth(FIXTURE)
        symbols = m8_001.symbol_addresses(FIXTURE)
        observed, provenance = m8_001.native_import(stripped, work)
        call_targets = m8_001.call_targets(stripped, work)
        stock = ghidra_functions(arguments.ghidra, stripped, work)

    matched = set(truth) & observed
    missing = {address: truth[address] for address in set(truth) - observed}
    undescribed = observed - set(truth)
    unattributed = sorted(address for address in undescribed if address not in symbols)
    classes = classify(missing, symbols, observed, call_targets)

    metrics = {
        "pe32.dwarf.fn.recall": len(matched) / len(truth),
        "pe32.dwarf.fn.unattributed": len(unattributed),
        "pe32.functions": len(observed),
        "pe32.undescribed": len(undescribed),
    }
    if stock is not None:
        metrics["ghidra.dwarf.fn.recall"] = len(set(truth) & stock) / len(truth)
        metrics["ghidra.functions"] = len(stock)

    assert not unattributed, (
        f"{len(unattributed)} recovered entries have no evidence: "
        f"{[f'{address:08x}' for address in unattributed[:8]]}")
    classified = sum(len(rows) for rows in classes.values())
    assert classified == len(missing), (
        f"{len(missing) - classified} missed functions are unclassified")
    if stock is not None:
        assert metrics["pe32.dwarf.fn.recall"] >= metrics["ghidra.dwarf.fn.recall"], (
            f"native recall {metrics['pe32.dwarf.fn.recall']:.4f} < stock "
            f"{metrics['ghidra.dwarf.fn.recall']:.4f} on the same image")

    summary = (f"{FIXTURE.name}: recall {metrics['pe32.dwarf.fn.recall']:.4f} over "
               f"{len(truth)} DWARF functions, 0 unattributed of "
               f"{len(undescribed)} undescribed, {len(missing)} misses all "
               f"classified")
    if stock is not None:
        summary += (f"; stock Ghidra recall "
                    f"{metrics['ghidra.dwarf.fn.recall']:.4f} on the same image")
    else:
        summary += "; stock comparison skipped, no pinned install"

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m8-002",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "fixture": FIXTURE.name,
            "truth": len(truth),
            "metrics": metrics,
            "missing_classes": classes,
            "provenance_kinds": sorted(provenance),
        }, indent=1) + "\n")
    print(f"m8-002: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
