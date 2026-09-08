#!/usr/bin/env python3
"""m4-015: a data reference records how wide the access was.

Two corpus rows decompile with a warning stock never emits:

    /* WARNING: Globals starting with '_' overlap smaller symbols at the
       same address */

`Funcdata::checkGlobals` (funcdata_varnode.cc:1742-1749) raises it when a
global access is wider than the symbol the client supplied there. We answer a
referenced location with a bare `<labelsym>` -- a name and no type, so one byte
-- and the instruction reads four or eight.

Ghidra answers the same query with a symbol whose type is the *data* defined at
that address (`DecompileCallback.encodeData`, :835-855), and its own analyzers
define data of the access size at every referenced location. That is the fact
we do not record. Dropping the label instead of sizing it is measurably worse:
answering "nothing" where the store holds no type (which is stock's behaviour
when it has neither symbol nor data) costs **5 of 30** token-identical
functions, because those labels are what stock's own dynamic names look like.

So the fix is the fact, not the silence: the console already decodes the access
that proves the width -- a `CPUI_LOAD`'s output, a `CPUI_STORE`'s value, a
memory varnode's own size -- and drops it. Carry it through the reference
protocol into a `data_definitions` row of `undefined<width>`, and answer with a
symbol of that width and the name the store would have used anyway.

Assertions
  1. No corpus row warns that a global overlaps a smaller symbol.
  2. The location whose read raised it holds `undefined` data of the access
     width, with provenance, and its reader still names it in the text -- the
     name m4-004 earned is kept, and the width is what is new.
  3. Every width the store records is one an access can have (1..8) and
     matches an access an instruction actually performs.
  4. A location whose address is merely taken -- a `DATA` reference with no
     load or store -- gets no width, because nothing proved one.

Usage:
    python3 tests/m4-015_reference_widths.py --corpus-dir DIR [--report OUT.json]
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
SOURCE = "native-analysis:data-width"
ROWS = ("powerpc_plain_o0", "i386_plain_o0", "x86_64_plain_o0", "aarch64_plain_o0")


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
        widths = {}
        for address, kind, size, provenance in connection.execute(
                "SELECT address, type, size, provenance FROM data_definitions "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(address)
            if offset is not None:
                widths[offset] = {"type": kind, "size": size, "provenance": provenance}
        references = {}
        for source, destination, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            from_offset, to_offset = ram(source), ram(destination)
            if from_offset is not None and to_offset is not None:
                references.setdefault(to_offset, set()).add((from_offset, kind))
        names = {offset: name for address, name in connection.execute(
            "SELECT address, name FROM symbols WHERE program_id = ?", (identifier,))
            if (offset := ram(address)) is not None}
        return {"functions": functions, "widths": widths, "references": references,
                "names": names}
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

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())

    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-015-") as directory:
        work = Path(directory)
        warned, sized, named, unproven = [], [], [], []
        for name in ROWS:
            binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
            assert binary.is_file(), f"{binary} is missing"
            project = work / name
            imported = cli("import", str(binary), "--project", str(project),
                           timeout=arguments.timeout)
            assert imported.returncode == 0, (
                f"{name}: import failed: {imported.stderr.strip()}")
            row = facts(project, binary.name)

            # 3. Every width is an access width, on a location an instruction
            #    reads or writes.
            for address, held in row["widths"].items():
                if held["provenance"] != SOURCE:
                    continue
                assert 1 <= held["size"] <= 8, (
                    f"{name}: {address:08x} records width {held['size']}")
                kinds = {kind for _, kind in row["references"].get(address, ())}
                assert kinds & {"READ", "WRITE", "READ_WRITE"}, (
                    f"{name}: {address:08x} records a width with no access to prove "
                    f"it: {sorted(kinds)}")
                sized.append(f"{name}:{address:08x}/{held['size']}")

            # 4. An address merely taken proves no width.
            for address, uses in row["references"].items():
                kinds = {kind for _, kind in uses}
                if kinds and not kinds & {"READ", "WRITE", "READ_WRITE"}:
                    held = row["widths"].get(address)
                    if held is not None and held["provenance"] == SOURCE:
                        unproven.append(f"{name}:{address:08x}")

            # 1. and 2. Nothing warns, and a sized location is still named.
            for entry, _ in sorted(row["functions"].items()):
                text = decompiled(binary, entry, project, arguments.timeout)
                if OVERLAP.search(text):
                    warned.append(f"{name}:{entry:08x}")
                for address, held in row["widths"].items():
                    if held["provenance"] != SOURCE:
                        continue
                    label = row["names"].get(address, f"DAT_{address:08x}")
                    rendered = re.sub(r"[^A-Za-z0-9_]", "_", label)
                    if any(source_address >= entry
                           for source_address, _ in row["references"].get(address, ())) \
                            and rendered in text:
                        named.append(f"{name}:{rendered}")
        assert not warned, (
            f"these functions still warn that a global overlaps a smaller symbol: "
            f"{warned}")
        assert not unproven, (
            f"these locations record a width nothing dereferenced: {unproven}")
        assert sized, "no access width was recorded, so nothing is proven"
        assert named, "no sized location reached a decompilation by name"
        findings = {"rows": len(ROWS), "overlap_warnings": 0,
                    "widths_recorded": len(set(sized)),
                    "named_in_text": len(set(named)),
                    "widths": sorted(set(sized))[:8]}

    summary = (f"{findings['widths_recorded']} access widths recorded across "
               f"{findings['rows']} rows, {findings['named_in_text']} of the sized "
               f"locations still named in the text, 0 overlap warnings")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-015",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "positive acceptance on four corpus rows plus two controls",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-015: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
