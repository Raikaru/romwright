#!/usr/bin/env python3
"""m19-002: disassembly failure classes as support-matrix rows.

Claim: our recovered code contains no failure of the classes Pang et
al. name in "SoK: All You Ever Wanted to Know About x86/x64 Binary
Disassembly" (S&P 2021, doi 10.1109/SP40001.2021.00012, arXiv:2007.14266)
-- measured as observables against ground truth, one row per class,
with the paper section each row derives from. The paper's corpus is
x86/x64 only and it publishes no closed failure table (§III-D names
three indirect-jump subclasses; data-in-code, overlapping
instructions, padding and gaps appear as constructs and error modes in
§III-A and the introduction), so every row states its section; claiming
"Pang's taxonomy" as a closed list would be an invented citation.

Observables, all from the project store plus an external symbol table
the importer never opens (`readelf`, not our parser):

* `data-in-code` (§III-A): a recovered function range intersecting a
  symtab data object's range (`STT_OBJECT`/`STT_COMMON` with nonzero
  size). Bytes we call code that the toolchain's own symbols call data.
* `overlap` (§III-A): two recovered function ranges overlapping where
  the symtab's function ranges do not (aliases the toolchain itself
  carries are agreement, not failure), plus any control-flow xref
  destination landing strictly inside a recovered body that is not its
  entry -- the mid-instruction-target shape of overlapping decode. DATA
  references are out of scope: landing pads and literal pools legitimately
  name code addresses.
* `jump-table` (§III-D): bounded target sets at indirect branches.
  Already scored by m13-001 (VSA switch recovery vs stock Ghidra);
  this gate cites that report instead of remeasuring.

Corpus: same-source twins with symbol tables (x86-64 O0/O2, a
duplicate-heavy many-functions build, i386 and AArch64 O0). Address
spaces are normalised by the ELF entry point, which both sides name.

Thresholds sit at zero observed failures: any instance is a defect to
record, not noise to absorb. A binary contributing no occurrences still
contributes its function count, so the rows state their denominator.
"""

from __future__ import annotations

import argparse
import os
import json
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "romwright-cli"

PAIRS = (
    ("x86_64_plain_o0", "x86-64"),
    ("x86_64_plain_o2", "x86-64"),
    ("x86_64_many_o2", "x86-64"),
    ("i386_plain_o0", "i386"),
    ("aarch64_plain_o0", "aarch64"),
)

SYM = re.compile(
    r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+\w+\s+\w+\s+\S+\s+(.*\S)\s*$")


def run(arguments: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        [str(CLI)] + arguments, cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=900,
    )
    if result.returncode:
        raise SystemExit(f"{' '.join(arguments)} failed: {result.stderr[-2000:]}")
    return result.stdout


def readelf(path: Path, flag: str) -> str:
    result = subprocess.run(
        ["readelf", flag, "-W", str(path)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode:
        raise SystemExit(f"readelf {flag} {path.name} failed")
    return result.stdout


def entry_point(binary: Path) -> int:
    for line in readelf(binary, "-h").splitlines():
        match = re.search(r"Entry point address:\s+(0x[0-9a-f]+)", line)
        if match:
            return int(match.group(1), 16)
    raise SystemExit(f"no entry point in {binary.name}")


def symtab(binary: Path) -> tuple[list[tuple[int, int, str, str]], list[tuple[int, int, str]]]:
    """(funcs, data) as (address, size, section, name), link-time VAs."""
    funcs, data = [], []
    for line in readelf(binary, "--symbols").splitlines():
        if " UND " in line:
            continue
        match = SYM.match(line)
        if not match:
            continue
        address, size, kind, name = (
            int(match.group(1), 16), int(match.group(2)), match.group(3), match.group(4))
        if kind == "FUNC" and size > 0 and name != "UND":
            section = line.split()[6] if len(line.split()) > 6 else ""
            funcs.append((address, size, section, name))
        elif kind in ("OBJECT", "COMMON") and size > 0:
            data.append((address, size, name))
    return funcs, data


def stored_functions(project: Path, program: str) -> list[tuple[int, str, int]]:
    connection = sqlite3.connect(project / "project.sqlite")
    rows = connection.execute(
        "SELECT functions.entry, functions.name, functions.size FROM functions"
        " JOIN programs p ON p.id = functions.program_id WHERE p.name = ?",
        (program,),
    ).fetchall()
    out = []
    for entry, name, size in rows:
        out.append((int(entry, 16), name,
                    int(size, 16) if isinstance(size, str) else int(size)))
    return out


def stored_code_dsts(project: Path, program: str) -> list[int]:
    # Control-flow references only: a DATA reference to a code address is
    # a legitimate construct (landing pads, literal pools), while a call
    # or branch landing inside a body that is not its entry is the
    # overlapping-decode shape (Pang §III-A).
    connection = sqlite3.connect(project / "project.sqlite")
    return [int(row[0], 16) for row in connection.execute(
        "SELECT DISTINCT x.dst FROM xrefs x JOIN programs p ON p.id = x.program_id"
        " WHERE p.name = ? AND x.kind != 'DATA'", (program,)).fetchall()]


def measure(identifier: str, arch: str, corpus: Path, work: Path,
            environment: dict[str, str]) -> dict:
    reference = corpus / f"{identifier}.bin"
    named = corpus / f"{identifier}.unstripped"
    for path in (reference, named):
        if not path.is_file():
            return {"id": identifier, "arch": arch, "skipped": f"missing {path.name}"}
    project = work / identifier
    if project.exists():
        shutil.rmtree(project)
    run(["import", str(reference), "--project", str(project), "--name", "tgt"],
        environment)
    entries = stored_functions(project, "tgt")
    anchor = next(address for address, name, _ in entries if name == "entry")
    delta = anchor - entry_point(named)
    # Normalise the store into link-time VAs through the entry point both
    # sides name.
    recovered = [(address - delta, name, size) for address, name, size in entries]
    dsts = [dst - delta for dst in stored_code_dsts(project, "tgt")]
    funcs, data = symtab(named)
    data_in_code = []
    for start, name, size in recovered:
        if size <= 0:
            continue
        for dstart, dsize, dname in data:
            if start < dstart + dsize and dstart < start + size:
                data_in_code.append({"at": f"{start:#x}", "function": name,
                                     "data": dname})
                break
    overlap = []
    order = sorted(recovered)
    for i in range(len(order) - 1):
        start, name, size = order[i]
        end = start + size
        for j in range(i + 1, len(order)):
            other, oname, osize = order[j]
            if other >= end:
                break
            if (start, end) == (other, other + osize):
                continue
            agreed = any(t0 < end and start < t1 and t0 < other + osize and other < t1
                         for t0, t1 in [(s, s + z) for s, z, _, _ in funcs])
            overlap.append({"a": f"{start:#x}", "b": f"{other:#x}",
                            "symtab_agrees": agreed})
    bodies = [(start, start + size) for start, _, size in recovered if size > 1]
    entries = {start for start, _, _ in recovered}
    mid_target = 0
    for dst in dsts:
        for start, end in bodies:
            if start < dst < end and dst not in entries:
                mid_target += 1
                break
    return {
        "id": identifier, "arch": arch,
        "functions": len(recovered),
        "data_in_code": data_in_code,
        "overlap": overlap,
        "mid_body_targets": mid_target,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault("ROMWRIGHT_CONSOLE", str(ROOT / "native/build/decomp_native"))
    environment["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], cwd=ROOT, check=True)

    failures: list[str] = []
    rows = []
    with tempfile.TemporaryDirectory(prefix="m19-002-", dir=arguments.work) as temporary:
        work = Path(temporary)
        for identifier, arch in PAIRS:
            try:
                row = measure(identifier, arch, arguments.corpus_dir, work, environment)
            except SystemExit as error:
                failures.append(str(error))
                continue
            rows.append(row)
            print(json.dumps({k: (v if not isinstance(v, list) else len(v))
                              for k, v in row.items() if k != "skipped"}), flush=True)

    measured = [row for row in rows if "skipped" not in row]
    for row in measured:
        if row["data_in_code"]:
            failures.append(f"{row['id']}: data-in-code {row['data_in_code'][:2]}")
        bad_overlap = [o for o in row["overlap"] if not o["symtab_agrees"]]
        if bad_overlap:
            failures.append(f"{row['id']}: overlapping recoveries {bad_overlap[:2]}")
        if row["mid_body_targets"]:
            failures.append(f"{row['id']}: {row['mid_body_targets']} mid-body targets")
    report = {
        "id": "m19-002",
        "milestone": "M19",
        "criterion": "Disassembly failure classes as support-matrix rows",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "citations": {
            "data-in-code": "Pang et al., SoK x86/x64 disassembly, S&P 2021, §III-A",
            "overlap": "Pang et al., SoK x86/x64 disassembly, S&P 2021, §III-A",
            "jump-table": "Pang et al., SoK x86/x64 disassembly, S&P 2021, §III-D; measured by m13-001",
        },
        "thresholds": {"data_in_code": 0, "overlap": 0, "mid_body_targets": 0},
        "rows": rows,
        "status": "pass" if not failures else "fail",
        "failures": failures,
    }
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
        return 1
    total = sum(row["functions"] for row in measured)
    print(f"m19-002: PASS (0 failure-class instances over {total} functions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
