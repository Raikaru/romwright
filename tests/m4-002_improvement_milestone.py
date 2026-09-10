#!/usr/bin/env python3
"""m4-002: measured improvement over stock, as one milestone claim.

M4 is the C2 criterion: improvements over the frozen stock-Ghidra baseline,
measured against ground truth, each behind a flag that II.1 reserves enabling.
Two passes exist (`m4-001` register parameters, `m5-007` tail-call promotion)
and each writes its own report. Nothing states the milestone claim, nothing
proves both passes are off unless asked, and nothing explains the arity that
neither producer recovers -- so a reader cannot tell a ceiling from a defect.

The passes are enumerated from `crates/lre-core/src/session.rs`, not listed
here, and then:

  * **every opt-in pass is gated**: a boolean pass read from the environment
    with no report behind it fails the gate;
  * **every opt-in pass is off unless asked**: with a clean environment the
    store holds no fact the pass produces, and with the flag set it does, so
    the default is proved by behaviour rather than by reading the source;
  * **native is never worse than stock**: every row of the committed M3
    regression gate, on every II.3 metric;
  * **the residual is a ceiling, not a defect**: for each row where both
    producers miss one arity, the missed parameter's register never appears in
    the function's own disassembly, so no evidence for it exists in the image;
  * **the claim**: both pass gates exist, pass, and carry the numbers the
    milestone asserts, and the corpus-total improvement is derived from them.

Usage:
    python3 tests/m4-002_improvement_milestone.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))
from prototype_gate import run_api  # noqa: E402  (repo-local helper)

REPORTS = ROOT / "benchmarks" / "reports"
SESSION = ROOT / "crates/lre-core/src/session.rs"
FLAG = re.compile(r'(\w+):\s*std::env::var_os\("(VENTRIS_[A-Z_]+)"\)\.is_some\(\)')
# The NDS cartridge is assembled from committed sources by `m5-002`, the gate
# that owns the loader; the promotion pass is measured on that same image.
NDS_BUILDER = ROOT / "tests/m5-002_nds.py"

# Every opt-in pass, the gate that measured it, and the claim that gate must
# still carry. Paths are tuples because metric names contain dots.
PASSES = {
    "VENTRIS_REGISTER_PARAMS": {
        "field": "register_params",
        "report": "m4-001",
        "claim": [(("rows", "i386_many_o2", "on"), "ge", 0.98),
                  (("rows", "i386_many_o2", "off"), "le", 0.02)],
    },
    "VENTRIS_PROMOTE_TAILCALLS": {
        "field": "promote_tailcalls",
        "report": "m5-007",
        "claim": [(("metrics", "arm7.dwarf.fn.recall"), "ge", 1.0),
                  (("metrics", "corpus_unattributed"), "eq", 0)],
    },
}
# The behavioural proof that each pass is off by default: the fact it produces,
# and how to ask the store for it.
DEFAULT_OFF = {
    "VENTRIS_REGISTER_PARAMS": {"row": "i386_many_o2",
                                "provenance": "native-prototype:register-input"},
    "VENTRIS_PROMOTE_TAILCALLS": {"entry": 0x037F8000},
}
# One arity both producers miss, per row, and the register that would carry it.
# `dead` spellings are every name the SLEIGH disassembler can print for the
# ABI's second integer argument; `live` is the first, so a scan that sees
# nothing is caught rather than believed.
RESIDUAL = {
    "x86_64_many_o2": {"entry": 0x2041D0, "arity": 2,
                       "dead": r"\b(RSI|ESI|SI|SIL)\b", "live": r"\b(RDI|EDI|DI|DIL)\b"},
    "aarch64_many_o2": {"entry": 0x213304, "arity": 2,
                        "dead": r"\b[wx]1\b", "live": r"\b[wx]0\b"},
    "powerpc_many_o2": {"entry": 0x10013034, "arity": 2,
                        "dead": r"\br4\b", "live": r"\br3\b"},
}
COMPARE = {"ge": lambda a, b: a >= b - 1e-9,
           "le": lambda a, b: a <= b + 1e-9,
           "eq": lambda a, b: a == b}


def enumerated_passes() -> dict[str, str]:
    """Boolean opt-in passes, read from the runtime config itself."""
    text = SESSION.read_text(encoding="utf-8")
    found = {flag: field for field, flag in FLAG.findall(text)}
    assert found, "no boolean environment pass found in RuntimeConfig::from_env"
    return found


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def clean_environment(**extra: str) -> dict[str, str]:
    """The environment a plain install has: no pass flags, no spec overrides."""
    environment = dict(os.environ)
    for name in ("VENTRIS_SLA", "VENTRIS_LANGUAGE", "VENTRIS_LANGUAGE_DIR",
                 "VENTRIS_SPECS", *PASSES):
        environment.pop(name, None)
    environment.update(extra)
    return environment


def resolve(document: dict, path: tuple[str, ...]):
    node = document
    for key in path:
        assert isinstance(node, dict) and key in node, (
            f"{path} is missing from the report")
        node = node[key]
    return node


def register_pass_facts(corpus: Path, binary: Path, row: str, provenance: str,
                        enabled: bool, timeout: int) -> int:
    """Prototypes carrying the register pass's provenance, flag off or on."""
    environment = clean_environment()
    if enabled:
        environment["VENTRIS_REGISTER_PARAMS"] = "1"
    with tempfile.TemporaryDirectory(prefix="m4-002-proto-") as temporary:
        project = Path(temporary)
        run_api(ROOT, project, [
            ("import_native", dict(binary=str(binary), name=row))], timeout, environment)
        run_api(ROOT, project, [
            ("infer_prototypes", dict(binary=str(binary), program=row,
                                      budget_ms=60000))], timeout, environment)
        (prototypes,) = run_api(ROOT, project, [
            ("prototypes", dict(program=row))], timeout, environment)
    return sum(1 for row in prototypes
               if str(row.get("provenance", {}).get("source", "")).startswith(provenance))


def promotion_pass_facts(binary: Path, entry: int, enabled: bool, timeout: int) -> bool:
    """Whether the tail-called leaf exists as a function, flag off or on."""
    environment = clean_environment()
    if enabled:
        environment["VENTRIS_PROMOTE_TAILCALLS"] = "1"
    with tempfile.TemporaryDirectory(prefix="m4-002-promote-") as temporary:
        project = Path(temporary)
        imported, = run_api(ROOT, project, [
            ("import_native", dict(binary=str(binary), name="nds"))], timeout, environment)
        programs = [entry["program"] for entry in imported["programs"]]
        found = False
        for program in programs:
            (functions,) = run_api(ROOT, project, [
                ("functions", dict(program=program))], timeout, environment)
            found = found or any(row["entry"]["offset"] == entry for row in functions)
    return found


LINE = re.compile(r"^0x([0-9a-f]+):")


def body(binary: Path, entry: int, timeout: int) -> tuple[list[str], int]:
    """SLEIGH lines inside the function's own recovered extent, from the image.

    The extent comes from the store, not from DWARF: the claim is about what
    evidence the image carries, so the bound must be recovered too.
    """
    environment = clean_environment()
    with tempfile.TemporaryDirectory(prefix="m4-002-disasm-") as temporary:
        project = Path(temporary)
        run_api(ROOT, project, [
            ("import_native", dict(binary=str(binary), name="row"))], timeout, environment)
        (functions,) = run_api(ROOT, project, [
            ("functions", dict(program="row"))], timeout, environment)
        row = next((item for item in functions if item["entry"]["offset"] == entry), None)
        assert row is not None, f"no recovered function at {entry:#x} in {binary.name}"
        size = row["size"]
        assert size and size > 0, f"the function at {entry:#x} has no recovered size"
        (text,) = run_api(ROOT, project, [
            ("disasm_native", dict(binary=str(binary), count=size,
                                   address={"space": "Ram", "offset": entry}))],
            timeout, environment)
    lines = []
    for line in text.splitlines():
        match = LINE.match(line)
        if match and int(match.group(1), 16) < entry + size:
            lines.append(line)
    return lines, size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    # Build what is being measured: the behavioural checks below run the
    # debug API binary, and a stale one hides exactly the defect they look for.
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-api", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=clean_environment())

    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row
               for row in lock["entries"] if row["format"] == "elf"}

    # 1. Every opt-in pass is enumerated from the runtime config and gated.
    passes = enumerated_passes()
    ungated = sorted(set(passes) - set(PASSES))
    assert not ungated, (
        f"these passes are opt-in and no gate here carries them: {ungated}")
    gone = sorted(set(PASSES) - set(passes))
    assert not gone, f"these passes no longer exist in the runtime config: {gone}"
    for flag, spec in PASSES.items():
        assert passes[flag] == spec["field"], (
            f"{flag} now sets {passes[flag]}, not {spec['field']}")

    # 2. Each pass is off unless asked, proved by the facts it leaves.
    defaults = {}
    row = DEFAULT_OFF["VENTRIS_REGISTER_PARAMS"]["row"]
    binary = (arguments.corpus_dir / recipes[row]["binary"]).resolve()
    provenance = DEFAULT_OFF["VENTRIS_REGISTER_PARAMS"]["provenance"]
    off = register_pass_facts(arguments.corpus_dir, binary, row, provenance,
                              False, arguments.timeout)
    on = register_pass_facts(arguments.corpus_dir, binary, row, provenance,
                             True, arguments.timeout)
    assert off == 0, f"the register pass produced {off} facts with a clean environment"
    assert on > 0, "the register pass produced nothing when asked, so the flag is dead"
    defaults["VENTRIS_REGISTER_PARAMS"] = {"off": off, "on": on}

    promote = DEFAULT_OFF["VENTRIS_PROMOTE_TAILCALLS"]
    with tempfile.TemporaryDirectory(prefix="m4-002-nds-") as temporary:
        container, _ = load_module("m5_002", NDS_BUILDER).build_container(Path(temporary))
        off_found = promotion_pass_facts(container, promote["entry"], False,
                                         arguments.timeout)
        on_found = promotion_pass_facts(container, promote["entry"], True,
                                        arguments.timeout)
    assert not off_found, (
        f"{promote['entry']:#x} became a function with a clean environment")
    assert on_found, (
        f"{promote['entry']:#x} stayed absent when promotion was asked for, "
        f"so the flag is dead")
    defaults["VENTRIS_PROMOTE_TAILCALLS"] = {"off": 0, "on": 1}

    # 3. Native is never worse than stock, on the committed regression gate.
    regression = json.loads((REPORTS / "m3-003.json").read_text())
    assert regression.get("passed"), "the M3 regression gate does not pass"
    worse = []
    for entry in regression["rows"]:
        for metric, value in entry["native"].items():
            if value + 1e-9 < entry["baseline"][metric]:
                worse.append(f"{entry['id']}:{metric}")
    assert not worse, f"native scores below stock on {worse}"

    # 4. The residual arity is a ceiling: the register carries no evidence.
    residual = {}
    for name, spec in RESIDUAL.items():
        entry = json.loads((REPORTS / "m3-003.json").read_text())
        row_entry = next(item for item in entry["rows"] if item["id"] == name)
        counts = row_entry["counts"]
        missed = counts["arity_matched"] - counts["native_arity_correct"]
        assert missed == 1, f"{name} misses {missed} arities, not the one recorded"
        assert counts["native_arity_correct"] == counts["baseline_arity_correct"], (
            f"{name} and stock no longer miss the same count")
        binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
        rows, size = body(binary, spec["entry"], arguments.timeout)
        assert len(rows) > 100, f"{name}: only {len(rows)} instructions decoded"
        text = "\n".join(rows)
        live = len(re.findall(spec["live"], text))
        dead = len(re.findall(spec["dead"], text))
        assert live > 0, (
            f"{name}: the scan saw no first-argument register, so seeing no "
            f"second one proves nothing")
        assert dead == 0, (
            f"{name}: the second-argument register appears {dead} times in the "
            f"function, so the missed parameter has evidence after all")
        residual[name] = {"entry": f"{spec['entry']:08x}", "body_bytes": size,
                          "instructions": len(rows),
                          "first_argument_reads": live, "second_argument_reads": dead,
                          "truth_arity": spec["arity"]}

    # 5. The claim: both gates pass and carry their numbers.
    milestone, missing = {}, []
    for flag, spec in PASSES.items():
        path = REPORTS / f"{spec['report']}.json"
        if not path.is_file():
            missing.append(f"{spec['report']}: no report")
            continue
        document = json.loads(path.read_text())
        if not document.get("passed"):
            missing.append(f"{spec['report']}: report does not pass")
        held = {}
        for keys, operator, wanted in spec["claim"]:
            value = resolve(document, keys)
            if not COMPARE[operator](value, wanted):
                missing.append(f"{spec['report']}: {'.'.join(keys)} is {value}, "
                               f"not {operator} {wanted}")
            held[".".join(keys)] = value
        milestone[spec["report"]] = held
    assert not missing, f"the milestone claim is unsupported: {missing}"

    # The corpus total the milestone asserts, derived from the gates that
    # measured it: the register pass is the only one that moves arity.
    arity = json.loads((REPORTS / "m4-001.json").read_text())["rows"]
    matched = {item["id"]: item["counts"]["arity_matched"] for item in regression["rows"]}
    stock = sum(item["counts"]["baseline_arity_correct"] for item in regression["rows"])
    total = sum(matched.values())
    native_off = sum(item["counts"]["native_arity_correct"] for item in regression["rows"])
    native_on = sum(round(arity[name]["on"] * matched[name]) for name in matched)
    assert native_off == stock, (
        f"default native arity {native_off} differs from stock {stock}")
    assert native_on > stock, (
        f"with every pass enabled native arity {native_on} does not beat stock {stock}")

    metrics = {
        "improvement.passes_gated": len(passes),
        "improvement.passes_default_off": len(defaults),
        "improvement.arity_correct_stock": stock,
        "improvement.arity_correct_native_default": native_off,
        "improvement.arity_correct_native_enabled": native_on,
        "improvement.arity_truth_functions": total,
        "improvement.residual_dead_parameters": len(residual),
    }
    summary = (
        f"{len(passes)} opt-in passes, each gated and proved off with a clean "
        f"environment; native matches stock on all {len(regression['rows'])} locked "
        f"rows by default ({native_off}/{total} arities) and beats it with the passes "
        f"enabled ({native_on}/{total} against stock's {stock}); the {len(residual)} "
        f"arities neither producer recovers are dead parameters whose register never "
        f"appears in the function")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-002",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "passes": {flag: {"field": passes[flag], **defaults[flag]} for flag in passes},
            "residual": residual,
            "milestone": milestone,
        }, indent=1) + "\n")
    print(f"m4-002: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
