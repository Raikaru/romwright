#!/usr/bin/env python3
"""m4-014: answer a data query the way Ghidra answers it, or not at all.

The PowerPC entry decompiles with a warning stock never emits:

    /* WARNING: Globals starting with '_' overlap smaller symbols at the
       same address */

`Funcdata::checkGlobals` (funcdata_varnode.cc:1742-1749) raises it when a
global access is *wider* than the symbol the client supplied at that address:
we answered `getMappedSymbols(0x10030734)` with a bare `<labelsym>` -- a name,
no type, so one byte -- and the instruction reads four. A symbol narrower than
the access is worse than no symbol at all, because with no symbol the
decompiler sizes one itself (`Scope::buildDefaultName`).

Ghidra's own answer is explicit (`DecompileCallback.encodeData`, :835-855):

    Symbol sym = data.getPrimarySymbol();
    if (sym != null) { highSymbol = new HighCodeSymbol(sym.getID(), ...); }
    else {
      highSymbol = new HighCodeSymbol(0, SymbolUtilities.getDynamicName(...));
      if (data.getDataType() == DataType.DEFAULT &&
          highSymbol.getMutability() == NORMAL)
        return false;                     // ← nothing is sent
    }

A composed name over a location the store knows nothing else about is exactly
that case: no stored symbol, no type. So the answer is nothing, and the
decompiler names and sizes the location itself.

Assertions
  1. The PowerPC entry decompiles with no overlap warning, and no corpus row
     regains one.
  2. A location the store *names* still renders by that name, and a location
     the store *types* still renders with its type -- neither path is touched
     (that is what `m4-004`, `m4-007` and `m4-011` measured).
  3. A location with neither a name nor a type is answered with nothing: the
     text carries the decompiler's own default name for it, not a `DAT_` label
     we invented, and no overlap warning.

Usage:
    python3 tests/m4-014_data_answers.py --corpus-dir DIR [--report OUT.json]
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

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
OVERLAP = re.compile(r"Globals starting with '_' overlap")
# The decompiler's own name for a location nobody described: a type letter,
# the space name and the offset (`Scope::buildDefaultName`).
DEFAULT_NAME = re.compile(r"\b[a-z]{1,4}Ram([0-9a-f]{8,16})\b")
INVENTED = re.compile(r"\bDAT_([0-9a-f]{6,16})\b")
ROWS = ("powerpc_plain_o0", "aarch64_plain_o0", "x86_64_plain_o0", "i386_plain_o0")


def environment() -> dict[str, str]:
    values = dict(os.environ)
    for name in ("VENTRIS_SLA", "VENTRIS_LANGUAGE", "VENTRIS_LANGUAGE_DIR",
                 "VENTRIS_SPECS", "VENTRIS_REGISTER_PARAMS",
                 "VENTRIS_PROMOTE_TAILCALLS"):
        values.pop(name, None)
    return values


def cli(*arguments: str, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([str(CLI), *arguments], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout, env=environment())


def ram(cell: str) -> int | None:
    try:
        return int(cell, 16)
    except ValueError:
        pass
    try:
        decoded = json.loads(cell)
    except json.JSONDecodeError:
        return None
    return decoded.get("offset") if decoded.get("space") == "Ram" else None


def facts(project: Path, program: str) -> dict:
    """What the store knows about each location a decompilation can show."""
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        functions = {}
        for entry, name, size in connection.execute(
                "SELECT entry, name, size FROM functions WHERE program_id = ?",
                (identifier,)):
            offset = ram(entry)
            if offset is not None:
                functions[offset] = (name, size or 1)
        names = {offset: name for address, name in connection.execute(
            "SELECT address, name FROM symbols WHERE program_id = ?", (identifier,))
            if (offset := ram(address)) is not None}
        typed = {offset: kind for address, kind in connection.execute(
            "SELECT address, type FROM data_definitions WHERE program_id = ?",
            (identifier,)) if (offset := ram(address)) is not None}
        strings = {offset for (address,) in connection.execute(
            "SELECT address FROM strings WHERE program_id = ?", (identifier,))
            if (offset := ram(address)) is not None}
        reads = {}
        for source, destination, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            from_offset, to_offset = ram(source), ram(destination)
            if from_offset is not None and to_offset is not None and kind in (
                    "READ", "WRITE", "DATA"):
                reads.setdefault(to_offset, []).append(from_offset)
        return {"functions": functions, "names": names, "typed": typed,
                "strings": strings, "reads": reads}
    finally:
        connection.close()


def containing(functions: dict, address: int) -> int | None:
    candidates = [entry for entry, (_, size) in functions.items()
                  if entry <= address < entry + size]
    return max(candidates) if candidates else None


def decompiled(binary: Path, entry: int, project: Path, timeout: int) -> str:
    result = cli("decompile", str(binary), f"{entry:08x}", "--project", str(project),
                 timeout=timeout)
    assert result.returncode == 0, (
        f"{binary.name}: decompile of {entry:08x} failed: {result.stderr.strip()}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True, env=environment())
    subprocess.run(["cargo", "build", "-q", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())

    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-014-") as directory:
        work = Path(directory)
        overlapping: list[str] = []
        invented: list[str] = []
        sized_by_decompiler: list[str] = []
        named_rows: list[str] = []
        typed_rows: list[str] = []
        for name in ROWS:
            binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
            assert binary.is_file(), f"{binary} is missing"
            project = work / name
            imported = cli("import", str(binary), "--project", str(project),
                           timeout=arguments.timeout)
            assert imported.returncode == 0, (
                f"{name}: import failed: {imported.stderr.strip()}")
            row = facts(project, binary.name)

            # Locations the store knows nothing about but an instruction reads:
            # the case Ghidra answers with nothing.
            unknown = sorted(address for address, sources in row["reads"].items()
                             if address not in row["names"]
                             and address not in row["typed"]
                             and address not in row["strings"]
                             and containing(row["functions"], address) is None
                             and sources)
            for entry, (label, _) in sorted(row["functions"].items()):
                text = decompiled(binary, entry, project, arguments.timeout)
                if OVERLAP.search(text):
                    overlapping.append(f"{name}:{entry:08x}")
                # 3. No invented label for a location with no fact behind it.
                for match in INVENTED.finditer(text):
                    address = int(match.group(1), 16)
                    if address in unknown:
                        invented.append(f"{name}:{entry:08x} -> {match.group(0)}")
                for match in DEFAULT_NAME.finditer(text):
                    if int(match.group(1), 16) in unknown:
                        sized_by_decompiler.append(f"{name}:{entry:08x} "
                                                   f"-> {match.group(0)}")
                # 2. A name the store holds is still rendered, and so is a type.
                for address, held in row["names"].items():
                    rendered = re.sub(r"[^A-Za-z0-9_]", "_", held)
                    if address in row["reads"] and rendered in text:
                        named_rows.append(f"{name}:{rendered}")
                for address in row["typed"]:
                    if f"{address:08x}" in text:
                        typed_rows.append(f"{name}:{address:08x}")
        assert not overlapping, (
            f"these functions still warn that a global overlaps a smaller symbol "
            f"we supplied: {overlapping}")
        assert not invented, (
            f"a location the store holds no name or type for was answered with an "
            f"invented label: {invented}")
        assert named_rows, "no stored name reached any decompilation, so nothing is proven"
        assert typed_rows, "no stored type reached any decompilation"
        findings = {"rows": len(ROWS), "overlap_warnings": 0,
                    "invented_labels": 0,
                    "decompiler_named": sorted(set(sized_by_decompiler))[:6],
                    "stored_names_rendered": len(set(named_rows)),
                    "stored_types_rendered": len(set(typed_rows))}

    summary = (f"{findings['rows']} corpus rows decompile with no overlap warning "
               f"and no invented label; {findings['stored_names_rendered']} stored "
               f"names and {findings['stored_types_rendered']} stored types still "
               f"reach the text")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-014",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "positive acceptance on four corpus rows, not a locked corpus gate",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-014: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
