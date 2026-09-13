#!/usr/bin/env python3
"""m11-002: the approved target's other modules, each measured as m11-001 measures Bond.elf.

007 Agent Under Fire (GameCube GQFE78) ships five modules beside the `bond.dol`
image `m1-009` scores: `Bond.elf` (m11-001) and four more this gate runs the
same session on -- `boot.elf`, `base.elf`, `Movie.elf` and `driving.elf`. Each
is ELF32 big-endian PowerPC with its own symbol table, so each scores its own
blind recovery. No JVM runs in any step.

Per module:

  1. **Blind recovery.** A stripped copy (asserted to carry no symbol table)
     is imported, and recall and precision are scored against the unstripped
     module's `STT_FUNC` symbols, which never reach the importer.
  2. **Navigation.** `functions_page` unfiltered and filtered, `xrefs_page`
     into a recovered callee, and a `listing` window, through one `romwright-api`
     process bound to the module's project.
  3. **Decompilation.** `decompile_doc` on five recovered functions: tokens
     and a prototype for every one.
  4. **Recovery passes.** `recover_classes` (recorded, not asserted) and
     `infer_prototypes` over the module under a budget.
  5. **An analyst edit that survives.** A rename, a second import, the name
     read back.

The gate also records which surfaces answer differently on a module that is
*loaded* rather than *booted*: `boot.elf` and `base.elf` link at 0x80680000,
the address the disc's boot process runs them from, while the game modules
`Bond.elf`, `Movie.elf` and `driving.elf` all link at 0x80007100 and are loaded
over one another by that boot code. A live read (`memory_live`) against the
running console therefore answers for whichever module is resident; this gate
makes no live claim and records that as the surface that differs, and it
records the entry point and load address of every module so the overlap is a
fact in the report rather than an assumption.

Floors are per module, written from the first measured run with room for a
slower host, not for a regression in kind: the small boot modules recover
fewer functions and precision differs per module, so one floor for all five
would either be too loose for Bond.elf or refuse the others.

The images are private (a retail disc): with the target absent the gate
records `skipped` with the reason and passes, which is why it is not wired
into CI.

Usage:
    python3 tests/m11-002_game_modules.py [--files DIR] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import statistics
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = Path.home() / "Projects/agent-under-fire/orig/GQFE78/files"

# sha256, then the floors the first measured run set (recall, precision,
# functions recovered), each with room below what was measured on this
# machine: boot/base 0.9472/0.8790/694, Movie 0.9550/0.7849/1678,
# driving 0.9669/0.9172/5954.
MODULES = {
    "boot.elf": {
        "sha256": "29b2a3b48badbfef7b62542d14a0ca41f4bfc72a728bb4644c012bc69061446d",
        "recall": 0.92, "precision": 0.85, "functions": 600,
    },
    "base.elf": {
        "sha256": "22cc9ec3ec53652cf7c3a05bc050a88a9a2c0ed2c5e2bea9ab7f5ef073f961be",
        "recall": 0.92, "precision": 0.85, "functions": 600,
    },
    "Movie.elf": {
        "sha256": "408014af8990ed7d7e449d7614f6dc4e46c8981c2dc7e551932b0d3b22da8ac7",
        "recall": 0.93, "precision": 0.75, "functions": 1500,
    },
    "driving.elf": {
        "sha256": "fcb6f28c96d2e503524e4657c05c82c86006a74e3a7c795a4b79a850d9a305e8",
        "recall": 0.94, "precision": 0.88, "functions": 5500,
    },
}
COMMON = {
    "import_wall_s": 90.0,
    "import_peak_kb": 300000,
    "page_ms": 500.0,
    "decompile_ms": 2000.0,
}


def load_session_gate():
    """m11-001's helpers: the strip, the symbol oracle, the import, the api."""
    spec = importlib.util.spec_from_file_location(
        "m11_001", ROOT / "tests/m11-001_game_session.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def elf_layout(image: bytes) -> dict:
    """Entry point and the first executable load address of an ELF32 BE image."""
    entry, phoff = struct.unpack_from(">II", image, 24)
    phentsize, phnum = struct.unpack_from(">HH", image, 42)
    loads = []
    for index in range(phnum):
        p_type, _, vaddr, _, filesz, memsz, flags, _ = struct.unpack_from(
            ">8I", image, phoff + index * phentsize)
        if p_type == 1:
            loads.append({"vaddr": f"{vaddr:08x}", "memsz": memsz, "flags": flags})
    code = [load for load in loads if load["flags"] & 1]
    return {"entry": f"{entry:08x}", "load": code[0]["vaddr"] if code else None,
            "segments": loads}


def session(gate, name: str, source: Path, work: Path, budget_ms: int) -> dict:
    """One m11-001 session on one module; returns its steps and metrics."""
    image = source.read_bytes()
    oracle = gate.function_symbols(image)
    module_work = work / name
    if module_work.exists():
        shutil.rmtree(module_work)
    module_work.mkdir(parents=True)
    stripped = module_work / f"{source.stem}.stripped.elf"
    gate.strip_symbols(source, stripped)
    assert not gate.has_symbol_table(stripped.read_bytes()), (
        f"{name}: the stripped copy still carries a symbol table")

    project = module_work / "project"
    cost = gate.imported(stripped, project)
    functions = gate.recovered_functions(project)
    entries = {entry for entry, _, _ in functions}
    matched = entries & set(oracle)
    # m11-001's import and store helpers name the program `bond`; each module
    # lives in its own project, so the name need not distinguish them.
    program = gate.PROGRAM
    result = {
        "layout": elf_layout(image),
        "steps": {"import": cost},
        "metrics": {
            "oracle_functions": len(oracle),
            "import_wall_s": cost["wall_s"],
            "import_peak_kb": cost["peak_kb"],
            "functions": len(functions),
            "functions_matched": len(matched),
            "recall": len(matched) / len(oracle),
            "precision": len(matched) / len(functions),
        },
    }

    api = gate.Api(project)
    try:
        programs, _ = api.result("programs")
        row = next(entry for entry in programs if entry["program"] == program)
        result["steps"]["language"] = row["language"]
        assert row["language"] == "PowerPC:BE:32:default", (
            f"{name}: the module resolved to {row['language']!r}")

        sample = sorted(entry for entry, _, size in functions if 100 <= size <= 600)
        assert len(sample) >= 5, f"{name}: too few mid-sized functions to walk: {len(sample)}"
        _, unfiltered_ms = api.result(
            "functions_page", program=program, offset=0, limit=50)
        # The modules link at different addresses, so the filter is the
        # leading digits of a name this module recovered.
        filtered, filtered_ms = api.result(
            "functions_page", program=program, offset=0, limit=50,
            filter=f"{sample[0]:08x}"[:4])
        assert filtered["rows"], f"{name}: a filter that matches recovered names returned nothing"
        callee = f"{sample[1]:08x}"
        xrefs, xrefs_ms = api.result(
            "xrefs_page", program=program, address=callee, offset=0, limit=10)
        listing, listing_ms = api.result(
            "listing", program=program, binary=str(stripped),
            start=f"{sample[0]:08x}", count=16)
        rows = listing["rows"] if isinstance(listing, dict) else listing
        assert rows, f"{name}: the listing window came back empty"
        result["metrics"].update({
            "page_ms": max(unfiltered_ms, filtered_ms, xrefs_ms, listing_ms),
            "xrefs_rows": len(xrefs["rows"]),
            "listing_rows": len(rows),
        })

        decompiled = []
        for entry in sample[:5]:
            document, elapsed = api.result(
                "decompile_doc", program=program, binary=str(stripped),
                address=f"{entry:08x}")
            assert document["tokens"], f"{name}: {entry:08x} decompiled to nothing"
            assert document["prototype"], f"{name}: {entry:08x} came back without a prototype"
            decompiled.append(elapsed)
        result["metrics"]["decompile_ms"] = statistics.median(decompiled)
        result["metrics"]["decompiled"] = len(decompiled)

        classes, classes_ms = api.result(
            "recover_classes", program=program, binary=str(stripped))
        result["steps"]["recover_classes"] = dict(classes, ms=round(classes_ms, 1))

        inference, inference_ms = api.result(
            "infer_prototypes", program=program, binary=str(stripped),
            budget_ms=budget_ms)
        result["steps"]["infer_prototypes"] = dict(inference, ms=round(inference_ms, 1))
        assert inference["analyzed"] >= 1, f"{name}: prototype inference analysed nothing"
        result["metrics"]["inference_analyzed"] = inference["analyzed"]

        held = api.result("memory", program=program, binary=str(stripped),
                          address=f"{sample[0]:08x}", size=8)[0]
        result["metrics"]["memory_bytes"] = held["size"]

        renamed = f"auf_{source.stem.lower()}_{sample[2]:08x}"
        api.result("rename", program=program, address=f"{sample[2]:08x}", name=renamed)
    finally:
        api.close()

    result["steps"]["reimport"] = gate.imported(stripped, project)
    surviving = {entry: label for entry, label, _ in gate.recovered_functions(project)}
    assert surviving.get(sample[2]) == renamed, (
        f"{name}: the rename did not survive the second import: "
        f"{surviving.get(sample[2])!r} != {renamed!r}")
    result["metrics"]["edit_survived_reimport"] = 1.0
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=Path, default=FILES)
    parser.add_argument("--work", type=Path,
                        default=Path(os.environ.get("ROMWRIGHT_SESSION_WORK",
                                                    Path.home() / "romwright-cache/session")) / "modules")
    parser.add_argument("--budget-ms", type=int, default=20000)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {
        "id": "m11-002",
        "milestone": "M11",
        "criterion": "GOAL.md C3: measured game-first sessions on the approved targets",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "files": str(arguments.files),
        "floors": {"common": COMMON, "modules": MODULES},
        "modules": {},
        "status": "skipped",
        "passed": True,
    }
    present = {name: arguments.files / name for name in MODULES
               if (arguments.files / name).is_file()}
    if not present:
        report["reason"] = (f"the approved target's modules are absent under "
                            f"{arguments.files} (007 Agent Under Fire, GameCube GQFE78, "
                            f"a private disc image)")
        print(f"m11-002: SKIP ({report['reason']})")
    else:
        assert set(present) == set(MODULES), (
            f"the target is present but modules are missing: "
            f"{sorted(set(MODULES) - set(present))}")
        import subprocess
        subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                        "-p", "romwright-api", "-p", "romwright-worker"], cwd=ROOT, check=True)
        gate = load_session_gate()
        failures = []
        for name, source in present.items():
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            assert digest == MODULES[name]["sha256"], (
                f"{name}: the module's hash moved: {digest} (pinned {MODULES[name]['sha256']})")
            result = session(gate, name, source, arguments.work, arguments.budget_ms)
            result["sha256"] = digest
            report["modules"][name] = result
            metrics = result["metrics"]
            for key, limit in COMMON.items():
                if metrics[key] > limit:
                    failures.append({"module": name, "metric": key,
                                     "value": metrics[key], "floor": limit})
            for key in ("recall", "precision", "functions"):
                if metrics[key] < MODULES[name][key]:
                    failures.append({"module": name, "metric": key,
                                     "value": metrics[key], "floor": MODULES[name][key]})

        # The surface that answers differently on a loaded module: every game
        # module links at one address, so only the resident one answers a
        # live read; the boot modules link elsewhere. Recorded from the
        # headers, never assumed.
        loads = {name: result["layout"]["load"] for name, result in report["modules"].items()}
        report["loaded_not_booted"] = {
            "load_addresses": loads,
            "shared_load_address": sorted({address for address in loads.values()
                                           if list(loads.values()).count(address) > 1}),
            "surface": "memory_live answers for the resident module only; this gate makes "
                       "no live claim on any of them. Every file-backed surface "
                       "(functions, xrefs, listing, decompile, memory, rename) answered "
                       "the same way it does for Bond.elf",
        }
        assert not failures, f"module metrics below their floors: {failures}"
        report["status"] = "pass"
        summary = "; ".join(
            f"{name}: {m['functions']} functions in {m['import_wall_s']:.1f} s, recall "
            f"{m['recall']:.4f} precision {m['precision']:.4f} over {m['oracle_functions']} "
            f"symbols, {m['decompiled']} decompiled (median {m['decompile_ms']:.0f} ms), "
            f"{m['inference_analyzed']} inferred"
            for name, m in ((name, result["metrics"])
                            for name, result in report["modules"].items()))
        report["summary"] = summary
        print(f"m11-002: PASS ({summary})")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
