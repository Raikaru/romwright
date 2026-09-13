#!/usr/bin/env python3
"""m4-001: recover parameters passed in registers by no shipped model.

The M3 regression gate records one deficit: `i386_many_o2:proto.arity`, where
stock Ghidra and native both score 0.0000 against DWARF. The cause is
specific. clang compiles `static int fn_n(int x)` for i386 into
`lea 0x3(%ecx),%eax; ret` -- the argument arrives in ECX under the compiler's
internal convention -- and `__cdecl` has no register parameter slot, so
`DecompilerParameterIdCmd` commits none. Ghidra's own dataflow *does* see the
input: it names the varnode `in_ECX` (`Scope::buildDefaultName`,
database.cc:2470-2478 of the pinned tree, "Irregular input").

This pass turns that evidence into parameters when a prototype model in the
program's own compiler spec passes exactly those registers, in that order,
as its leading parameters. It is off by default: II.1 reserves enabling an M4
pass.

Assertions
  1. Default behaviour is unchanged: with the pass off, native arity on the
     i386 row still equals the frozen baseline.
  2. With `ROMWRIGHT_REGISTER_PARAMS=1`, native arity on that row is at least
     0.98 against DWARF truth.
  3. No other corpus row loses arity when the pass is enabled.
  4. The recovered facts say where they came from: the persisted prototype
     names a model from the program's compiler spec and its provenance
     records this pass, not the decompiler's default recovery.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))
from prototype_gate import run_api

BASELINE = ROOT / "benchmarks/reports/baseline-ghidra-truth.json"
DEFICIT_ROW = "i386_many_o2"
ARITY_THRESHOLD = 0.98
PROVENANCE = "native-prototype:register-input"


def arity_scores(corpus: Path, enabled: bool, timeout: int) -> dict:
    """Per-row native arity from the prototype gate, pass off or on."""
    environment = dict(os.environ)
    environment.pop("ROMWRIGHT_REGISTER_PARAMS", None)
    if enabled:
        environment["ROMWRIGHT_REGISTER_PARAMS"] = "1"
    with tempfile.TemporaryDirectory(prefix="m4-001-") as temporary:
        report = Path(temporary) / "arity.json"
        result = subprocess.run(
            [sys.executable, str(ROOT / "benchmarks/prototype_gate.py"),
             "--corpus-dir", str(corpus), "--report", str(report)],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=timeout)
        if not report.is_file():
            raise AssertionError(
                f"prototype gate produced no report: {result.stderr.strip() or result.stdout.strip()}")
        document = json.loads(report.read_text())
    return {row["id"]: row["metrics"]["proto.arity"]
            for row in document["corpus"] if row["status"] != "skipped"}


def recovered_prototype(corpus: Path, timeout: int) -> dict:
    """Import the i386 row with the pass on and read back one prototype."""
    manifest = json.loads((corpus / "manifest.json").read_text())
    entry = next(row for row in manifest["entries"]
                 if f"{row['architecture']}_{row['variant']}" == DEFICIT_ROW)
    binary = corpus / entry["binary"]
    twin = corpus / entry["unstripped_twin"]
    symbols = subprocess.run(["readelf", "-sW", str(twin)], text=True,
                             capture_output=True, check=True).stdout
    target = None
    for line in symbols.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "FUNC" and parts[7].startswith("fn_"):
            target = f"{int(parts[1], 16):08x}"
            break
    if target is None:
        raise AssertionError("no fn_* symbol in the unstripped twin")

    environment = dict(os.environ, ROMWRIGHT_REGISTER_PARAMS="1")
    for name in ("ROMWRIGHT_SLA", "ROMWRIGHT_LANGUAGE", "ROMWRIGHT_LANGUAGE_DIR", "ROMWRIGHT_SPECS"):
        environment.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="m4-001-store-") as temporary:
        project = Path(temporary)
        run_api(ROOT, project, [
            ("import_native", dict(binary=str(binary), name=DEFICIT_ROW))], timeout, environment)
        run_api(ROOT, project, [
            ("infer_prototypes", dict(binary=str(binary), program=DEFICIT_ROW,
                                      budget_ms=60000))], timeout, environment)
        (prototypes,) = run_api(ROOT, project, [
            ("prototypes", dict(program=DEFICIT_ROW))], timeout, environment)
    match = next((row for row in prototypes
                  if row["function"]["offset"] == int(target, 16)), None)
    if match is None:
        raise AssertionError(f"no persisted prototype at {target}")
    return match


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    arguments = parser.parse_args()

    baseline = {row["id"]: row["metrics"]["ghidra.dwarf.proto.arity"]
                for row in json.loads(BASELINE.read_text())["rows"]
                if row["status"] == "recorded"}

    disabled = arity_scores(arguments.corpus_dir, False, arguments.timeout)
    if abs(disabled[DEFICIT_ROW] - baseline[DEFICIT_ROW]) > 1e-9:
        raise AssertionError(
            f"default behaviour changed: {DEFICIT_ROW} scores {disabled[DEFICIT_ROW]} "
            f"with the pass off, baseline records {baseline[DEFICIT_ROW]}")

    enabled = arity_scores(arguments.corpus_dir, True, arguments.timeout)
    if enabled[DEFICIT_ROW] < ARITY_THRESHOLD:
        raise AssertionError(
            f"{DEFICIT_ROW} arity {enabled[DEFICIT_ROW]:.4f} < {ARITY_THRESHOLD} "
            f"with the register-parameter pass enabled")

    lost = {row: (enabled[row], disabled[row]) for row in disabled
            if enabled.get(row, 0.0) + 1e-9 < disabled[row]}
    if lost:
        raise AssertionError(f"rows lost arity when the pass was enabled: {lost}")

    prototype = recovered_prototype(arguments.corpus_dir, arguments.timeout)
    provenance = prototype.get("provenance", {})
    source = provenance.get("source", "")
    if not source.startswith(f"{PROVENANCE}("):
        raise AssertionError(
            f"recovered prototype does not record the pass and its registers: {provenance}")
    if "ECX" not in source:
        raise AssertionError(f"provenance names no register evidence: {source}")
    # x86-32 gcc ships no model that passes ECX first: `__regparm*` start at
    # EAX and its `__thiscall` passes `this` on the stack. Claiming one would
    # be a false convention, so the row must record none.
    if prototype.get("calling_convention") is not None:
        raise AssertionError(
            f"pass claimed a convention no spec model supports: "
            f"{prototype['calling_convention']}")
    if "param_1" not in prototype.get("signature", ""):
        raise AssertionError(
            f"recovered signature has no parameter: {prototype.get('signature')!r}")

    report = {"id": "m4-001", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"proto.arity": ARITY_THRESHOLD},
              "rows": {row: {"off": disabled[row], "on": enabled[row],
                             "baseline": baseline[row]} for row in sorted(disabled)},
              "recovered": {"function": prototype["function"],
                            "calling_convention": prototype["calling_convention"],
                            "signature": prototype["signature"],
                            "provenance": provenance},
              "status": "pass", "passed": True}
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    improved = sum(1 for row in disabled if enabled[row] > disabled[row] + 1e-9)
    print(f"m4-001: PASS ({DEFICIT_ROW} arity {disabled[DEFICIT_ROW]:.4f} -> "
          f"{enabled[DEFICIT_ROW]:.4f}, {improved} row(s) improved, none lost; "
          f"{source} at {prototype['function']['offset']:#x})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
