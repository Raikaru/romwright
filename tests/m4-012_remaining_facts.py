#!/usr/bin/env python3
"""m4-012: account for every differing token, and record what it names.

`m4-003` used to accept a function as explained as soon as *one* named class
differed, without checking that the class accounted for the whole difference.
A convention nothing recorded -- `processEntry` on the x86 entry rows -- hid
behind a name that did differ. The gate now subtracts what each class licenses
and fails on what is left, and the residue named three facts we did not hold:

  * **the process-entry model.** Ghidra's rule, verbatim
    (`ElfProgramBuilder.processEntryPoints`, :655-675): for `e_entry` of an
    executable or shared object whose `e_ident[EI_OSABI]` is `ELFOSABI_LINUX`
    or `ELFOSABI_NONE`, `setCallingConvention("processEntry")`, and skip
    silently when the compiler spec declares no such model. Sending an
    undeclared name would be worse than sending none: the decompiler answers
    `createUnknownModel` (fspec.cc:4695-4698), a model with no storage at all.
  * **the compiler spec's call fixups.** `__i686.get_pc_thunk.bx` is a stub
    the x86 cspec replaces with p-code; Ghidra's installer maps every
    `<callfixup>`'s `<target>` to its fixup and sets it on any function of
    that name, trying one and two leading underscores as well
    (`CallFixupAnalyzer`, :436-459 and :200-222). The fixup body travels with
    the spec, so only the name has to reach the decompiler
    (`FuncProto::decode`, fspec.cc:4814-4819).
  * **the dynamic table's own labels.** `_DYNAMIC` at the table, and
    `__DT_<TAG>` at every nonzero ADDRESS-valued tag's target, applied only
    where nothing else names the address
    (`markupDynamicTable`, :2691-2723, `addDynamicMemoryReference`,
    :2753-2773).

Assertions
  1. An ELF executable whose language declares the model records exactly one
     convention fact, at `e_entry`, with provenance -- and the listing reports
     it on that function and no other; its decompilation names the model and
     takes the model's parameters, not the default convention's.
  2. Each of Ghidra's three conditions is load-bearing: a non-Linux OS/ABI
     byte, a relocatable `e_type`, and a non-ELF container each record
     nothing; and a language whose spec declares no such model records
     nothing -- the same silent skip.
  3. A stub the spec fixes up is replaced in its callers' text although the
     store still records the call, and removing the `<callfixup>` from the
     spec brings the call back. A language whose only fixup targets a name no
     image carries fixes up nothing.
  4. The dynamic table is labelled at its address, the tags it names are
     labelled where nothing else names them, and a slot an import already
     names keeps that name.
  5. The accounting itself fails on an unexplained token and passes when
     every differing token is licensed.

Usage:
    python3 tests/m4-012_remaining_facts.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
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


def decompiled(binary: Path, entry: int, project: Path, timeout: int,
               specs: Path | None = None) -> str:
    """One function's C text. `specs` points the runtime at another bundle."""
    environment_override = environment()
    if specs is not None:
        environment_override["VENTRIS_SPECS"] = str(specs)
    result = subprocess.run(
        [str(CLI), "decompile", str(binary), f"{entry:08x}", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout,
        env=environment_override)
    assert result.returncode == 0, (
        f"{binary.name}: decompile of {entry:08x} failed: {result.stderr.strip()}")
    return result.stdout


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
    # The root specs are the x86-64 bundle; every other language needs its
    # own directory, and a missing one is a provisioning failure, not a
    # semantic fact.
    if not bundle.is_dir():
        assert language == "x86:LE:64:default", f"spec bundle missing: {bundle}"
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


def call_edges(project: Path, program: str) -> set[tuple[int, int]]:
    """Call xrefs the store holds, as (from, to)."""
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        edges = set()
        for source, target, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            if "CALL" not in kind:
                continue
            source, target = ram(source), ram(target)
            if source is not None and target is not None:
                edges.add((source, target))
        return edges
    finally:
        connection.close()


def named_symbols(project: Path, program: str) -> dict[int, tuple[str, str]]:
    """Every stored symbol as address -> (name, source)."""
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        found = {}
        for address, name, source in connection.execute(
                "SELECT address, name, source FROM symbols WHERE program_id = ?",
                (identifier,)):
            offset = ram(address)
            if offset is not None:
                found[offset] = (name, source)
        return found
    finally:
        connection.close()


def functions_named(project: Path, program: str) -> dict[str, int]:
    """Stored function names -> entry."""
    return {name: entry for entry, (name, _) in stored_functions(project, program).items()}


def stored_functions(project: Path, program: str) -> dict[int, tuple[str, int]]:
    """Stored functions as entry -> (name, size)."""
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        found = {}
        for entry, name, size in connection.execute(
                "SELECT entry, name, size FROM functions WHERE program_id = ?",
                (identifier,)):
            offset = ram(entry)
            if offset is not None:
                found[offset] = (name, size or 1)
        return found
    finally:
        connection.close()


def containing(functions: dict[int, tuple[str, int]], address: int) -> int | None:
    """The function whose body holds `address`."""
    for entry, (_, size) in functions.items():
        if entry <= address < entry + size:
            return entry
    return None


def as_identifier(name: str) -> str:
    """The name as the decompiler can print it: `.` is a member access in C."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def code_only(text: str) -> str:
    """The C without comments. The decompiler names a replaced function in its
    own warning (`/* WARNING: Function: X replaced with injection: Y */`), so
    the question "is it still called" is about the code, not the commentary."""
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def dynamic_segment(binary: Path) -> tuple[int, int]:
    """(p_vaddr, p_offset) of PT_DYNAMIC -- two different numbers."""
    data = binary.read_bytes()
    wide = data[4] == 2
    order = "big" if data[5] == 2 else "little"

    def field(at: int, size: int) -> int:
        return int.from_bytes(data[at:at + size], order)

    phoff = field(32, 8) if wide else field(28, 4)
    entry_size = field(54, 2) if wide else field(42, 2)
    count = field(56, 2) if wide else field(44, 2)
    for index in range(count):
        header = phoff + index * entry_size
        if field(header, 4) != 2:  # PT_DYNAMIC
            continue
        if wide:
            return field(header + 16, 8), field(header + 8, 8)
        return field(header + 8, 4), field(header + 4, 4)
    raise AssertionError(f"{binary.name} has no PT_DYNAMIC segment")


def dynamic_tag(binary: Path, wanted: int) -> int | None:
    """The value of one dynamic tag, read the way the loader reads it."""
    data = binary.read_bytes()
    wide = data[4] == 2
    order = "big" if data[5] == 2 else "little"
    width = 8 if wide else 4
    _, offset = dynamic_segment(binary)
    while True:
        tag = int.from_bytes(data[offset:offset + width], order)
        value = int.from_bytes(data[offset + width:offset + 2 * width], order)
        if tag == 0:
            return None
        if tag == wanted:
            return value
        offset += 2 * width


def spec_bundle_without_fixups(language: str, work: Path) -> Path:
    """A copy of `native/specs` whose language bundle declares no fixups."""
    root = work / "specs-no-fixups"
    shutil.copytree(SPECS, root)
    bundle = root / language.replace(":", "-")
    cspec = bundle / "cspec.xml" if bundle.is_dir() else root / "cspec.xml"
    text = cspec.read_text()
    stripped = re.sub(r"<callfixup\b.*?</callfixup>", "", text, flags=re.S)
    assert stripped != text, f"{cspec} declares no call fixup to remove"
    cspec.write_text(stripped)
    return root


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

        # The listing reports it on that function, and on no other: a fact
        # about a function belongs where functions are listed.
        listed = cli("functions", binary.name, "--project", str(project),
                     timeout=arguments.timeout)
        assert listed.returncode == 0, listed.stderr.strip()
        carried = {}
        for line in listed.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[-1].startswith("["):
                carried[int(fields[0], 16)] = fields[-1].strip("[]")
        assert carried == {entry: MODEL}, (
            f"the listing reports conventions on "
            f"{ {f'{a:08x}': v for a, v in carried.items()} }, expected only "
            f"{entry:08x} -> {MODEL}")

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

        # 3. A stub the compiler spec fixes up: replaced in its callers, while
        #    the store still records the call it replaced.
        i386 = (arguments.corpus_dir / recipes["i386_plain_o0"]["binary"]).resolve()
        i386_project = work / "i386"
        imported(i386, i386_project, arguments.timeout)
        i386_functions = stored_functions(i386_project, i386.name)
        stubs = {name: entry for entry, (name, _) in i386_functions.items()
                 if "get_pc_thunk" in name}
        assert stubs, "the i386 row records no get_pc_thunk stub to fix up"
        stub_name, stub_entry = sorted(stubs.items())[0]
        printed = as_identifier(stub_name)
        # The call sites the store records, resolved to the functions that
        # hold them: a fixup is visible in the caller's text.
        callers = sorted({function for source, target in
                          call_edges(i386_project, i386.name) if target == stub_entry
                          if (function := containing(i386_functions, source)) is not None})
        assert callers, f"nothing calls {stub_name} at {stub_entry:08x}"
        replaced = []
        for caller in callers:
            text = code_only(decompiled(i386, caller, i386_project, arguments.timeout))
            assert printed not in text, (
                f"{caller:08x} still calls {printed}, so the spec's fixup was "
                f"not applied: {text[:200]}")
            replaced.append(f"{caller:08x}")
        findings["fixup"] = {"stub": stub_name, "printed": printed,
                             "entry": f"{stub_entry:08x}", "callers_replaced": replaced}

        # Remove the fixup from the spec and the call comes back.
        without = spec_bundle_without_fixups(language_of(i386_project, i386.name), work)
        restored = code_only(decompiled(i386, callers[0], i386_project,
                                         arguments.timeout, specs=without))
        assert printed in restored, (
            f"with no <callfixup> in the spec the call to {printed} should be "
            f"back, and {callers[0]:08x} renders: {restored[:200]}")
        controls["no_callfixup_in_spec"] = restored[:120]

        # A language whose only fixup targets a name no image carries.
        arm_fixups = [text for text in
                      (decompiled(aarch64, entry, arm_project, arguments.timeout)
                       for entry in sorted(functions_named(arm_project,
                                                           aarch64.name).values()))
                      if "injection" in text]
        assert not arm_fixups, (
            f"{arm_language} declares only a placeholder fixup target, and "
            f"{len(arm_fixups)} function(s) were fixed up: {arm_fixups[:1]}")
        controls["placeholder_target_only"] = f"{arm_language}: no injection"

        # 4. The dynamic table's own labels.
        powerpc = (arguments.corpus_dir / recipes["powerpc_plain_o0"]["binary"]).resolve()
        ppc_project = work / "powerpc"
        imported(powerpc, ppc_project, arguments.timeout)
        symbols = named_symbols(ppc_project, powerpc.name)
        table_vaddr, table_offset = dynamic_segment(powerpc)
        assert table_vaddr != table_offset, (
            f"{powerpc.name} loads its dynamic table at its file offset, so this "
            f"row cannot tell an address from an offset")
        assert symbols.get(table_vaddr, (None, None))[0] == "_DYNAMIC", (
            f"the dynamic table at {table_vaddr:08x} is not labelled `_DYNAMIC`: "
            f"{symbols.get(table_vaddr)}")
        assert table_offset not in symbols, (
            f"a label landed on the table's file offset {table_offset:08x}: "
            f"{symbols.get(table_offset)}")
        labelled = {name: f"{address:08x}" for address, (name, source) in symbols.items()
                    if source == "native-import:dynamic-tag"}
        # DT_JMPREL (0x17) names the PLT relocation table, which nothing else
        # names, so the label is applied there.
        jmprel = dynamic_tag(powerpc, 0x17)
        assert jmprel is not None, f"{powerpc.name} has no DT_JMPREL"
        assert symbols.get(jmprel, (None, None))[0] == "__DT_JMPREL", (
            f"DT_JMPREL names {jmprel:08x}, labelled {symbols.get(jmprel)}")
        # DT_PLTGOT's slot is named by the import it holds: Ghidra's own guard
        # keeps the existing name, and so does ours.
        pltgot = dynamic_tag(powerpc, 0x3)
        assert pltgot is not None, f"{powerpc.name} has no DT_PLTGOT"
        held = symbols.get(pltgot)
        assert held and held[0] != "__DT_PLTGOT", (
            f"the DT_PLTGOT slot at {pltgot:08x} lost the name its import "
            f"proved: {held}")
        findings["dynamic_labels"] = {"table": f"{table_vaddr:08x}",
                                      "labelled": dict(sorted(labelled.items())),
                                      "kept": {f"{pltgot:08x}": held[0]}}

        # 5. The accounting fails on an unexplained token and passes when every
        #    differing token is licensed.
        parity = importlib.util.spec_from_file_location(
            "m4_003", ROOT / "tests/m4-003_language_parity.py")
        module = importlib.util.module_from_spec(parity)
        parity.loader.exec_module(module)
        context = {"symbols": set(), "prototypes": set(), "externals": {},
                   "strings": {}, "definitions": set(), "names": {}}
        rows = ({"name": "ours"}, {"name": "theirs"})
        licensed_only = module.residue(
            "void ours(void){return;}", "void theirs(void){return;}",
            rows[0], rows[1], {"function-facts": {"name": ["theirs", "ours"]}}, context)
        assert licensed_only == [], (
            f"a difference the name accounts for was left unexplained: {licensed_only}")
        hidden = module.residue(
            "void ours(void){return;}", "void theirs(void){processEntry();return;}",
            rows[0], rows[1], {"function-facts": {"name": ["theirs", "ours"]}}, context)
        assert "processEntry" in hidden, (
            f"a token no class licenses was accepted anyway: {hidden}")
        findings["accounting"] = {"licensed": licensed_only, "unexplained": hidden}

    summary = (
        f"the ELF entry at {findings['entry']} carries {MODEL} with provenance and "
        f"renders {len(parameters(findings['rendered']))} model parameters, "
        f"{findings['fixup']['stub']} is replaced in "
        f"{len(findings['fixup']['callers_replaced'])} caller(s), "
        f"{len(findings['dynamic_labels']['labelled'])} dynamic-tag labels are "
        f"recorded and the import's own name is kept; "
        f"{len(findings['controls'])} controls hold and the accounting reports "
        f"an unexplained token")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-012",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "positive acceptance plus controls, not a locked corpus gate",
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
