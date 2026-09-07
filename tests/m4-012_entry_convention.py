#!/usr/bin/env python3
"""m4-012: the ELF entry point carries the platform's process-entry model.

The last divergence class `m4-003` cannot explain is one token: the oracle
renders the x86 entry function as `void processEntry entry(...)` and we render
`void _entry(...)`, with different parameters underneath, because the operating
system does not enter a process through the C calling convention.

Ghidra's rule, verbatim (`ElfProgramBuilder.processEntryPoints`, :655-675):

    long entry = elf.e_entry();
    if (entry != 0 && (elf.isExecutable() || elf.isSharedObject())) {
      ... if (entryFunc != null && (elf.e_ident_osabi() == ELFOSABI_LINUX ||
                                    elf.e_ident_osabi() == ELFOSABI_NONE)) {
        try { entryFunc.setCallingConvention("processEntry"); }
        catch (InvalidInputException e) { /* not defined in the cspec: skip */ }

Three conditions, one silent skip. The image proves the address (`e_entry`,
`e_type`, `e_ident[EI_OSABI]`); the language decides whether the model exists
at all -- `x86-64-gcc.cspec` and `x86gcc.cspec` declare `processEntry`,
`AARCH64.cspec` does not, and where it is undefined Ghidra records nothing.
Sending an undeclared model would be worse than sending none: the decompiler
answers `createUnknownModel` (fspec.cc:4695-4698), a placeholder with no
storage locations at all.

The fact belongs in the store with provenance, like every other durable fact,
and reaches the decompiler as `<prototype model=... modellock="true">` on the
function element (`FuncProto::decode`, fspec.cc:4690-4740; Ghidra's own Java
locks the model whenever the name is known, `FunctionPrototype.grabFromFunction`
:135-136).

Assertions
  1. An ELF executable whose language declares the model records exactly one
     convention fact, at `e_entry`, with provenance -- and the API reports it
     on that function and no other.
  2. The entry's decompilation names the model and takes the model's
     parameters, not the default convention's.
  3. Each of Ghidra's three conditions is load-bearing: a non-Linux OS/ABI
     byte, a relocatable `e_type`, and a non-ELF container each record
     nothing, and the rendering falls back to the default convention.
  4. A language whose compiler spec does not declare the model records
     nothing and renders nothing -- the same silent skip.

Usage:
    python3 tests/m4-012_entry_convention.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
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
PE = ROOT / "tests/fixtures-src/tiny_pe32.exe"
MODEL = "processEntry"
SOURCE = "native-import:entry-convention"
# `void processEntry entry(undefined8 param_1,undefined8 param_2)`: everything
# before the body is the signature the decompiler printed.
SIGNATURE = re.compile(r"^(.*?)\{", re.S)


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


def conventions(project: Path, program: str) -> dict[int, dict]:
    """Every calling-convention fact the store holds, by function address."""
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        row = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        assert row, f"{program} is not in {project}"
        found = {}
        for function, convention, provenance, kind in connection.execute(
                "SELECT function, convention, provenance, provenance_kind "
                "FROM calling_conventions WHERE program_id = ?", (row[0],)):
            offset = ram(function)
            assert offset is not None, function
            found[offset] = {"convention": convention, "provenance": provenance,
                             "kind": kind}
        return found
    finally:
        connection.close()


def elf_entry(binary: Path) -> int:
    """`e_entry`, read out of the header the loader reads."""
    data = binary.read_bytes()
    assert data[:4] == b"\x7fELF", binary
    width, order = (8, "little") if data[4] == 2 else (4, "little")
    if data[5] == 2:
        order = "big"
    offset = 24 if width == 8 else 24
    return int.from_bytes(data[offset:offset + width], order)


def imported(binary: Path, project: Path, timeout: int) -> None:
    result = cli("import", str(binary), "--project", str(project), timeout=timeout)
    assert result.returncode == 0, f"{binary.name}: import failed: {result.stderr.strip()}"


def signature(binary: Path, entry: int, project: Path, timeout: int) -> str:
    result = cli("decompile", str(binary), f"{entry:08x}", "--project", str(project),
                 timeout=timeout)
    assert result.returncode == 0, (
        f"{binary.name}: decompile of {entry:08x} failed: {result.stderr.strip()}")
    match = SIGNATURE.search(result.stdout)
    assert match, f"{binary.name}: no signature in {result.stdout[:200]!r}"
    return " ".join(match.group(1).split())


def parameters(rendered: str) -> list[str]:
    inner = rendered[rendered.index("(") + 1:rendered.rindex(")")].strip()
    return [] if inner in ("", "void") else [item.strip() for item in inner.split(",")]


def declares_model(language: str) -> bool:
    """Whether the language's own compiler spec defines the model."""
    bundle = SPECS / language.replace(":", "-")
    cspec = bundle / "cspec.xml" if bundle.is_dir() else SPECS / "cspec.xml"
    return f'prototype name="{MODEL}"' in cspec.read_text()


def language_of(project: Path, program: str) -> str:
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        return connection.execute(
            "SELECT language FROM programs WHERE name = ?", (program,)).fetchone()[0]
    finally:
        connection.close()


def patched(source: Path, work: Path, name: str, offset: int, value: bytes) -> Path:
    """A copy of the image with one header field changed, nothing else."""
    target = work / name
    shutil.copy(source, target)
    data = bytearray(target.read_bytes())
    data[offset:offset + len(value)] = value
    target.write_bytes(bytes(data))
    return target


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
    with tempfile.TemporaryDirectory(prefix="m4-012-") as directory:
        work = Path(directory)

        # 1. The fact, once, where the ABI puts it.
        binary = (arguments.corpus_dir / recipes["x86_64_plain_o0"]["binary"]).resolve()
        assert binary.is_file(), f"{binary} is missing"
        project = work / "x86_64"
        imported(binary, project, arguments.timeout)
        entry = elf_entry(binary)
        language = language_of(project, binary.name)
        assert declares_model(language), (
            f"{language} no longer declares {MODEL}, so this row proves nothing")
        recorded = conventions(project, binary.name)
        assert list(recorded) == [entry], (
            f"the store holds {MODEL} facts at {[f'{a:08x}' for a in recorded]}, "
            f"and the ABI enters the process at {entry:08x}")
        fact = recorded[entry]
        assert fact["convention"] == MODEL, fact
        assert (fact["provenance"], fact["kind"]) == (SOURCE, "inferred"), fact
        findings["entry"] = f"{entry:08x}"
        findings["fact"] = fact

        # The API reports it on that function, and on no other.
        listed = cli("functions", binary.name, "--project", str(project),
                     "--json", timeout=arguments.timeout)
        assert listed.returncode == 0, listed.stderr.strip()
        rows = json.loads(listed.stdout)
        carried = {int(row["entry"]["offset"]): row.get("calling_convention")
                   for row in rows if row.get("calling_convention")}
        assert carried == {entry: MODEL}, (
            f"the API reports the convention on {[f'{a:08x}' for a in carried]}, "
            f"expected only {entry:08x}")

        # 2. The model's parameters, named in the rendered signature.
        rendered = signature(binary, entry, project, arguments.timeout)
        assert MODEL in rendered, f"the entry renders without the model: {rendered}"
        taken = parameters(rendered)
        assert len(taken) == 2, (
            f"the model passes two parameters (RDX, then the stack); the entry "
            f"renders {len(taken)}: {rendered}")
        assert "unaff_retaddr" not in rendered, (
            f"the default convention's artefact survives: {rendered}")
        findings["rendered"] = rendered

        # 3. Each condition of the rule, one control apiece.
        controls: dict[str, object] = {}
        for name, offset, value in (
                # e_ident[EI_OSABI]: FreeBSD, an ABI Ghidra's rule excludes.
                ("osabi", 7, bytes([9])),
                # e_type: ET_REL, neither executable nor shared object.
                ("type", 16, (1).to_bytes(2, "little"))):
            image = patched(binary, work, f"{name}.bin", offset, value)
            control = work / name
            imported(image, control, arguments.timeout)
            held = conventions(control, image.name)
            assert not held, (
                f"the {name} control records a convention anyway: "
                f"{ {f'{a:08x}': v for a, v in held.items()} }")
            fallback = signature(image, entry, control, arguments.timeout)
            assert MODEL not in fallback, (
                f"the {name} control renders the model anyway: {fallback}")
            controls[name] = fallback

        assert PE.is_file(), f"{PE} is missing"
        pe_project = work / "pe"
        imported(PE, pe_project, arguments.timeout)
        pe_held = conventions(pe_project, PE.name)
        assert not pe_held, f"a PE image records an ELF entry convention: {pe_held}"
        controls["pe"] = "no convention rows"

        # 4. A language with no such model: nothing recorded, nothing rendered.
        aarch64 = (arguments.corpus_dir / recipes["aarch64_plain_o0"]["binary"]).resolve()
        arm_project = work / "aarch64"
        imported(aarch64, arm_project, arguments.timeout)
        arm_language = language_of(arm_project, aarch64.name)
        assert not declares_model(arm_language), (
            f"{arm_language} now declares {MODEL}, so this control proves nothing")
        arm_held = conventions(arm_project, aarch64.name)
        assert not arm_held, (
            f"{arm_language} declares no {MODEL} model, and the store recorded "
            f"{ {f'{a:08x}': v for a, v in arm_held.items()} }")
        arm_rendered = signature(aarch64, elf_entry(aarch64), arm_project,
                                 arguments.timeout)
        assert MODEL not in arm_rendered, arm_rendered
        controls["undeclared_model"] = f"{arm_language}: {arm_rendered[:80]}"
        findings["controls"] = controls

    summary = (f"the ELF entry at {findings['entry']} carries {MODEL} with "
               f"provenance and renders {len(parameters(findings['rendered']))} "
               f"model parameters; 4 controls record none")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-012",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "positive acceptance plus four controls, not a locked corpus gate",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-012: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
