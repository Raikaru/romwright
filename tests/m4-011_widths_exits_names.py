#!/usr/bin/env python3
"""m4-011: render the image's own widths, exits and names.

Three divergences `m4-003` still measures are defects on our side, one per
kind of fact, and each shows up as text a person can read:

  * **width.** PowerPC BE32 renders a typed pointer slot as
    `PTR___gmon_start___10020730._0_4_` -- the decompiler extracting four
    bytes out of something it was told is eight -- because the worker's
    pointer width was a constant instead of the language's. The tspec says
    `<space name="ram" size="4">`.
  * **exit.** The AArch64 entry function runs *past* `abort()` and swallows
    the next function's body, because nothing told the decompiler that
    `abort` does not return. The name is on Ghidra's own pinned list
    (`Base/data/ElfFunctionsThatDoNotReturn`), which the tree already reads
    for its thunk rule, and no import records the fact.
  * **name.** A stub the image calls `__i686.get_pc_thunk.bx` is printed
    verbatim into C, where `.` is a member access, not part of an identifier.
    Ghidra replaces characters a symbol cannot carry
    (`SymbolUtilities.replaceInvalidChars`, :417-419, with `USE_UNDERSCORES`).

Assertions
  1. A typed pointer slot decompiles without a field extraction on a 32-bit
     image, and the store's own definition width equals the language's.
  2. A function whose name is on the pinned no-return list carries the fact
     with provenance, and its caller's decompilation stops at the call.
  3. A name a C identifier cannot carry is rendered with the characters
     replaced, and the store keeps what the image declared.

Usage:
    python3 tests/m4-011_widths_exits_names.py --corpus-dir DIR [--report OUT.json]
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
SPECS = ROOT / "native/specs"
EXTRACTION = re.compile(r"\._[0-9]+_[0-9]+_")
# What a C identifier can carry; the worker replaces the rest, as Ghidra's
# own applied names do.
INVALID = re.compile(r"[^A-Za-z0-9_]")


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
                functions[offset] = {"name": name, "size": size or 0}
        definitions = {}
        for address, kind, size in connection.execute(
                "SELECT address, type, size FROM data_definitions WHERE program_id = ?",
                (identifier,)):
            offset = ram(address)
            if offset is not None:
                definitions[offset] = {"type": kind, "size": size}
        behaviours = {}
        for function, no_return, provenance in connection.execute(
                "SELECT function, no_return, provenance FROM return_behaviors "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(function)
            if offset is not None:
                behaviours[offset] = {"no_return": bool(no_return),
                                      "provenance": provenance}
        language = connection.execute(
            "SELECT language FROM programs WHERE id = ?", (identifier,)).fetchone()[0]
        return {"functions": functions, "definitions": definitions,
                "behaviours": behaviours, "language": language}
    finally:
        connection.close()


def language_pointer_width(language: str) -> int:
    """The RAM space width the language's own tspec declares."""
    bundle = SPECS / language.replace(":", "-")
    assert bundle.is_dir(), f"spec bundle missing: {bundle}"
    tspec = bundle / "tspec.xml"
    match = re.search(r'<space name="ram"[^>]*size="(\d+)"', tspec.read_text())
    assert match, f"{tspec} declares no ram space width"
    return int(match.group(1))


def decompile(binary: Path, entry: int, project: Path, timeout: int) -> str:
    result = cli("decompile", str(binary), f"{entry:08x}", "--project", str(project),
                 timeout=timeout)
    assert result.returncode == 0, (
        f"decompile of {entry:08x} failed: {result.stderr.strip()}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True, env=environment())
    # The release CLI drives the worker beside it, so the gate builds the pair
    # it measures (m4-014).
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())

    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-011-") as directory:
        work = Path(directory)
        stores = {}
        for name in ("powerpc_plain_o0", "i386_plain_o0", "aarch64_plain_o0"):
            binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
            assert binary.is_file(), f"{binary} is missing"
            project = work / name
            imported = cli("import", str(binary), "--project", str(project),
                           timeout=arguments.timeout)
            assert imported.returncode == 0, (
                f"{name}: import failed: {imported.stderr.strip()}")
            stores[name] = (binary, project, facts(project, binary.name))

        # 1. Widths: a typed pointer is the language's pointer, and the
        #    decompiler never has to carve a field out of it.
        widths = {}
        for name in ("powerpc_plain_o0", "i386_plain_o0"):
            binary, project, row = stores[name]
            width = language_pointer_width(row["language"])
            widths[name] = width
            pointers = sorted(address for address, held in row["definitions"].items()
                              if held["type"] == "pointer")
            assert pointers, f"{name}: the store types no pointer"
            wrong = [f"{address:08x}={row['definitions'][address]['size']}"
                     for address in pointers
                     if row["definitions"][address]["size"] != width]
            assert not wrong, (
                f"{name}: {row['language']} points with {width} bytes and the store "
                f"holds {wrong}")
            carved = []
            for entry in sorted(row["functions"]):
                text = decompile(binary, entry, project, arguments.timeout)
                if EXTRACTION.search(text):
                    carved.append(f"{entry:08x}: {EXTRACTION.search(text).group(0)}")
            assert not carved, (
                f"{name}: the decompiler carved fields out of typed data, so it was "
                f"told the wrong width: {carved}")
        findings["widths"] = widths

        # 2. Exits: a pinned no-return name is a fact, and its caller stops.
        binary, project, row = stores["aarch64_plain_o0"]
        exits = sorted(address for address, held in row["functions"].items()
                       if held["name"].lstrip("_") in ("abort", "exit"))
        assert exits, "the AArch64 row holds no pinned no-return import"
        untyped = [f"{address:08x}" for address in exits
                   if not row["behaviours"].get(address, {}).get("no_return")]
        assert not untyped, (
            f"these pinned no-return imports carry no fact: {untyped}; the store "
            f"holds {row['behaviours']}")
        for address in exits:
            provenance = row["behaviours"][address]["provenance"]
            assert provenance, f"{address:08x} carries a fact with no provenance"
        callers = [entry for entry, held in row["functions"].items()
                   if held["name"].lstrip("_") == "entry"]
        assert callers, "the AArch64 row holds no entry function"
        text = decompile(binary, callers[0], project, arguments.timeout)
        after = [f"{address:08x}" for address in row["functions"]
                 if address > callers[0]
                 and row["functions"][address]["name"] in text
                 and row["functions"][address]["name"].lstrip("_") not in
                 ("abort", "exit", "libc_start_main")]
        assert not after, (
            f"the entry function's decompilation runs past its no-return call and "
            f"reaches {after}: {text.strip()[:300]}")
        findings["exits"] = {f"{address:08x}": row["behaviours"][address]["provenance"]
                             for address in exits}

        # 3. Names: what C cannot spell is replaced, and the store keeps the
        #    name the image declared.
        binary, project, row = stores["i386_plain_o0"]
        awkward = sorted(address for address, held in row["functions"].items()
                         if INVALID.search(held["name"]))
        assert awkward, "the i386 row holds no name a C identifier cannot carry"
        for address in awkward:
            declared = row["functions"][address]["name"]
            expected = INVALID.sub("_", declared)
            text = decompile(binary, address, project, arguments.timeout)
            assert expected in text, (
                f"{address:08x}: the store declares {declared!r} and the "
                f"decompilation shows neither it sanitised ({expected!r}) nor "
                f"anything like it: {text.strip()[:200]}")
            assert declared not in text, (
                f"{address:08x}: {declared!r} is printed into C verbatim, where "
                f"'.' is a member access: {text.strip()[:200]}")
        findings["names"] = {f"{address:08x}": row["functions"][address]["name"]
                             for address in awkward}

    metrics = {"render.pointer_widths": len(findings["widths"]),
               "render.field_extractions": 0,
               "render.no_return_facts": len(findings["exits"]),
               "render.sanitised_names": len(findings["names"])}
    summary = (f"typed pointers are the language's width on "
               f"{len(findings['widths'])} 32-bit rows with no field extraction "
               f"anywhere, {len(findings['exits'])} pinned no-return imports carry "
               f"the fact so the entry function stops at its call, and "
               f"{len(findings['names'])} names a C identifier cannot carry are "
               f"rendered with the characters replaced while the store keeps what "
               f"the image declared")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-011",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "widths": findings["widths"],
            "exits": findings["exits"],
            "names": findings["names"],
        }, indent=1) + "\n")
    print(f"m4-011: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
