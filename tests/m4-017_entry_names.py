#!/usr/bin/env python3
"""m4-017: name the loader's own entry points the way the loader names them.

Splitting `function-facts` by field (m4-016 left it at 10) shows two causes of
five rows each, and the larger one is a name we invented:

    oracle='entry'     ours='_entry'      x86-64, x86-32, PowerPC
    oracle='_DT_INIT'  ours='_init'       AArch64, x86-64, x86-32
    oracle='_DT_FINI'  ours='_fini'       AArch64, x86-64, PowerPC
    oracle='FUN_...'   ours='_plt'        (ours says more; stock has no name)

The first three are not conventions we chose -- stock's names come from
documented loader rules and ours from a section name or an invented
underscore:

  * `ElfLoader.ELF_ENTRY_FUNCTION_NAME = "entry"`, applied to `e_entry`
    (`ElfProgramBuilder.processEntryPoints`, :657);
  * `createDynamicEntryPoints(DT_INIT, null, ...)` and the same for `DT_FINI`
    name their target `"_" + dynamicEntryType.name`, i.e. `_DT_INIT` and
    `_DT_FINI` (:678-679, :704) -- the array forms of which this tree already
    matches (`_INIT_0`, m5-010).

And the precedence is Ghidra's: the target must be in an executable block, and
**a function that already exists there keeps its name** -- only the external
entry-point flag is added (`createEntryFunction`, :783-798). So a symbol from
the image's own table wins over the loader's name, and the loader's name wins
over a section-derived guess.

Assertions
  1. On every stripped ELF row, the function at `e_entry` is named `entry`,
     and the targets of `DT_INIT` and `DT_FINI` are `_DT_INIT` and `_DT_FINI`.
  2. A section-derived name with no dynamic tag behind it is untouched: the
     `.plt` start is still `_plt`.
  3. The unstripped twin of the same image keeps the name its symbol table
     gives the entry (`_start`), because a symbol-derived function keeps it.
  4. A PE image is untouched: this is the ELF loader's rule.

Usage:
    python3 tests/m4-017_entry_names.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/romwright-cli"
LOCK = ROOT / "tests/corpus.lock.json"
PE = ROOT / "tests/fixtures-src/tiny_pe32.exe"
ROWS = ("x86_64_plain_o0", "i386_plain_o0", "aarch64_plain_o0", "powerpc_plain_o0")


def environment() -> dict[str, str]:
    values = dict(os.environ)
    for name in ("ROMWRIGHT_SLA", "ROMWRIGHT_LANGUAGE", "ROMWRIGHT_LANGUAGE_DIR",
                 "ROMWRIGHT_SPECS", "ROMWRIGHT_REGISTER_PARAMS",
                 "ROMWRIGHT_PROMOTE_TAILCALLS"):
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


def names(project: Path, program: str) -> dict[int, str]:
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        return {offset: name for entry, name in connection.execute(
            "SELECT entry, name FROM functions WHERE program_id = ?", (identifier,))
            if (offset := ram(entry)) is not None}
    finally:
        connection.close()


def header(binary: Path) -> dict:
    """`e_entry`, the section table, and the dynamic tags, read directly."""
    data = binary.read_bytes()
    assert data[:4] == b"\x7fELF", binary
    wide = data[4] == 2
    order = "big" if data[5] == 2 else "little"

    def field(at: int, size: int) -> int:
        return int.from_bytes(data[at:at + size], order)

    width = 8 if wide else 4
    entry = field(24, width)
    phoff = field(32, 8) if wide else field(28, 4)
    phentsize = field(54, 2) if wide else field(42, 2)
    phnum = field(56, 2) if wide else field(44, 2)
    tags: dict[int, int] = {}
    for index in range(phnum):
        at = phoff + index * phentsize
        if field(at, 4) != 2:  # PT_DYNAMIC
            continue
        offset = field(at + 8, 8) if wide else field(at + 4, 4)
        while True:
            tag = field(offset, width)
            value = field(offset + width, width)
            if tag == 0:
                break
            tags.setdefault(tag, value)
            offset += 2 * width
    return {"entry": entry, "tags": tags}


def section_start(binary: Path, wanted: str) -> int | None:
    listed = subprocess.run(["readelf", "-SW", str(binary)], capture_output=True,
                            text=True, check=True)
    for line in listed.stdout.splitlines():
        fields = line.replace("]", "] ").split()
        if wanted in fields:
            index = fields.index(wanted)
            return int(fields[index + 2], 16)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True, env=environment())

    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-017-") as directory:
        work = Path(directory)
        named, kept = [], []
        for row in ROWS:
            binary = (arguments.corpus_dir / recipes[row]["binary"]).resolve()
            assert binary.is_file(), f"{binary} is missing"
            project = work / row
            imported = cli("import", str(binary), "--project", str(project),
                           timeout=arguments.timeout)
            assert imported.returncode == 0, (
                f"{row}: import failed: {imported.stderr.strip()}")
            held = names(project, binary.name)
            elf = header(binary)

            # 1. The loader's own names.
            assert held.get(elf["entry"]) == "entry", (
                f"{row}: the entry at {elf['entry']:08x} is named "
                f"{held.get(elf['entry'])!r}, and stock names it 'entry'")
            named.append(f"{row}:entry")
            for tag, expected in ((0xc, "_DT_INIT"), (0xd, "_DT_FINI")):
                target = elf["tags"].get(tag)
                if target is None:
                    continue
                assert held.get(target) == expected, (
                    f"{row}: DT tag {tag:#x} names {target:08x}, which the store "
                    f"calls {held.get(target)!r} instead of {expected!r}")
                named.append(f"{row}:{expected}")

            # 2. A section-derived name with no tag behind it stands.
            plt = section_start(binary, ".plt")
            if plt is not None and plt in held:
                assert held[plt] == "_plt", (
                    f"{row}: the .plt start at {plt:08x} lost its section name: "
                    f"{held[plt]!r}")
                kept.append(f"{row}:_plt")

        # 3. A symbol from the image's own table wins.
        unstripped = (arguments.corpus_dir /
                      recipes["x86_64_plain_o0"]["binary"]).with_suffix(".unstripped")
        assert unstripped.is_file(), f"{unstripped} is missing"
        project = work / "unstripped"
        imported = cli("import", str(unstripped), "--project", str(project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, imported.stderr.strip()
        held = names(project, unstripped.name)
        elf = header(unstripped)
        assert held.get(elf["entry"]) == "_start", (
            f"the unstripped twin's entry is named {held.get(elf['entry'])!r}; its "
            f"own symbol table calls it '_start' and a symbol-derived function "
            f"keeps its name")
        findings["symbol_wins"] = held.get(elf["entry"])

        # 4. A PE image is untouched by an ELF rule.
        assert PE.is_file(), f"{PE} is missing"
        project = work / "pe"
        imported = cli("import", str(PE), "--project", str(project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, imported.stderr.strip()
        pe_names = set(names(project, PE.name).values())
        assert not {"_DT_INIT", "_DT_FINI"} & pe_names, (
            f"a PE image gained ELF dynamic-entry names: {sorted(pe_names)}")
        findings["pe_untouched"] = sorted(pe_names)[:6]
        findings["named"] = sorted(set(named))
        findings["kept"] = sorted(set(kept))

    summary = (f"{len(findings['named'])} loader entry points named as stock names "
               f"them, {len(findings['kept'])} section-derived names kept, a symbol "
               f"table still wins, and a PE image is untouched")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-017",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "naming acceptance with three controls, not a corpus gate",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-017: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
