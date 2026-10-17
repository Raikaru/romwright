#!/usr/bin/env python3
"""How much of the decompiled output is owned by Rust, and how much by the
vendored Ghidra C++ (STATUS.md, "Reserved decisions": the entry criterion
for replacing the vendored decompiler is that we own more of the decompiled
output than the vendored tree does).

The metric, its stages and what each number means are defined in
docs/ownership.md. This script computes every number from the code and from
a run; nothing is entered by hand. Three sources:

  inventory   lines of first-party Rust, of our C++ (native/ghidra-opt-
              sleigh.patch and native/romwright_*.hh) and of the vendored
              C++ tree, counted from the files, tests excluded.

  run         per image, the 8 research images' sampled functions
              (benchmarks/console_research.py's sample rule, seed and
              size): a fresh default import, then `export-c --address` per
              sampled function with ROMWRIGHT_OWNERSHIP_LOG set. The worker
              (crates/romwright-worker/src/worker.rs `log_ownership`,
              printc/ownership.rs) writes one JSON line per function: the
              printed tokens split into the ones replayed from PrintC's own
              fragments and the ones the Rust block layer emitted, the block
              tree's constructs against Ghidra's, the Rust semantic edits and
              cuts, the stored prototypes the decompiler was given and the
              jump tables it recovered. The import's own tables (functions by
              producer, facts by provenance, phase times) and a second
              import with the decompiler's switch path off say who recovered
              each dispatch. Two ablation passes (Rust structuring off, Rust
              IR passes off) give the counterfactual: how many functions
              print differently without the Rust components.

  coverage    the binaries of the run are instrumented (clang source-based
              coverage for ghidra_opt, rustc
              -C instrument-coverage for the CLI and worker, both in
              continuous mode so a process killed by the worker still leaves
              its counts). The lines each implementation actually executed,
              by file, are attributed to a stage and to an owner: first-party
              Rust, third-party Rust (kuna-sleigh), our C++ (patch-added lines
              and native/romwright_*.hh), vendored C++.

Usage (on the build host, see docs/ownership.md "Reproduce"):

  benchmarks/ownership.py --target-dir ~/runs/OwnershipMetric/target-cov \\
      --cov-build ~/runs/OwnershipMetric/cov-build \\
      --cache ~/runs/OwnershipMetric/cache --jobs 3

  benchmarks/ownership.py --inventory-only   # static counts, no images needed

Writes benchmarks/reports/ownership.json and ownership.md (both only by this
script).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))

SCHEMA = "ownership/1"
OWNERS = ("rust_first_party", "rust_third_party", "cpp_ours", "cpp_vendored")


# ---------------------------------------------------------------------------
# Stage tables. Each rule is (glob, stage); the first match wins. These are
# the only hand-written inputs; docs/ownership.md explains each stage and
# `unassigned` in the report lists any executed file no rule claims.
# ---------------------------------------------------------------------------

STAGES = [
    ("load", "container parsing, segments, symbols, relocations, platform maps; the bytes and "
             "names the decompiler is given"),
    ("discovery", "function entries and data/code references (walk, seeds, pattern and "
                  "constant-propagation references, thunks, no-return)"),
    ("flow", "instruction flow classification during the walk"),
    ("pcode_lift", "SLEIGH decode and p-code build"),
    ("switch_recovery", "jump-table recovery (stored import tables and the decompiler's own)"),
    ("simplification", "p-code dataflow and the action/rule pipeline up to high variables"),
    ("variables", "high-variable merge, explicit/implied marking, variable names and the for-loop op moves (stage 3)"),
    ("type_inference", "type propagation, casts, and the p-code type solver"),
    ("prototype", "calling convention, parameter and return recovery; persisted prototypes"),
    ("structuring", "control-flow structuring of the function's block graph"),
    ("printing", "C expression/declaration emission, block layer and pretty printing"),
    ("postprocess", "export-c text canonicalisation (temporary names, honesty markers)"),
    ("host", "process, wire protocol, facade, database and CLI plumbing"),
]

RUST_RULES = [
    ("crates/romwright-worker/src/printc/structure*", "structuring"),
    ("crates/romwright-worker/src/printc/collapse*", "structuring"),
    ("crates/romwright-worker/src/printc/query.rs", "structuring"),
    ("crates/romwright-worker/src/printc/merge/*", "variables"),
    ("crates/romwright-worker/src/printc/ownership.rs", "host"),
    ("crates/romwright-worker/src/printc/*", "printing"),
    ("crates/romwright-worker/src/structure.rs", "structuring"),
    ("crates/romwright-worker/src/provider.rs", "load"),
    ("crates/romwright-worker/src/specs.rs", "load"),
    ("crates/romwright-worker/src/prototype.rs", "prototype"),
    ("crates/romwright-worker/src/semantic.rs", "simplification"),
    ("crates/romwright-worker/src/*", "host"),
    ("crates/romwright-worker-client/*", "host"),
    ("crates/romwright-core/src/native_runtime/lift.rs", "pcode_lift"),
    ("crates/romwright-core/src/native_runtime/flow.rs", "flow"),
    ("crates/romwright-core/src/native_runtime/propagation*", "discovery"),
    ("crates/romwright-core/src/native_runtime/reference_pass.rs", "discovery"),
    ("crates/romwright-core/src/native_runtime/patterns.rs", "discovery"),
    ("crates/romwright-core/src/native_runtime/linkage.rs", "discovery"),
    ("crates/romwright-core/src/native_runtime/disasm.rs", "pcode_lift"),
    ("crates/romwright-core/src/native_runtime/*", "host"),
    ("crates/romwright-core/src/native_runtime.rs", "host"),
    ("crates/romwright-core/src/native/discovery*", "discovery"),
    ("crates/romwright-core/src/native/vsa.rs", "switch_recovery"),
    ("crates/romwright-core/src/native/sja.rs", "switch_recovery"),
    ("crates/romwright-core/src/native/switch*", "switch_recovery"),
    ("crates/romwright-core/src/native/references.rs", "discovery"),
    ("crates/romwright-core/src/native/elf_pointers.rs", "discovery"),
    ("crates/romwright-core/src/native/*unwind*", "discovery"),
    ("crates/romwright-core/src/native/*exception*", "discovery"),
    ("crates/romwright-core/src/native/pe_roots.rs", "discovery"),
    ("crates/romwright-core/src/native/store.rs", "host"),
    ("crates/romwright-core/src/native/programs.rs", "host"),
    ("crates/romwright-core/src/native/n64_discovery.rs", "discovery"),
    ("crates/romwright-core/src/native/nonreturn.rs", "discovery"),
    ("crates/romwright-core/src/native/tally.rs", "host"),
    ("crates/romwright-core/src/native/features.rs", "discovery"),
    ("crates/romwright-core/src/native/strings.rs", "discovery"),
    ("crates/romwright-core/src/native/mdebug*", "type_inference"),
    ("crates/romwright-core/src/native/*", "load"),
    ("crates/romwright-core/src/native.rs", "discovery"),
    ("crates/romwright-core/src/nonreturn.rs", "discovery"),
    ("crates/romwright-core/src/cfg_functions.rs", "discovery"),
    ("crates/romwright-core/src/types_infer/prototypes.rs", "prototype"),
    ("crates/romwright-core/src/types_infer*", "type_inference"),
    ("crates/romwright-core/src/subtype.rs", "type_inference"),
    ("crates/romwright-model/src/type_evidence.rs", "type_inference"),
    ("crates/romwright-core/src/library_types.rs", "prototype"),
    ("crates/romwright-core/src/sdk_types*", "prototype"),
    ("crates/romwright-core/src/prototypes.rs", "prototype"),
    ("crates/romwright-core/src/qualified_prototypes.rs", "prototype"),
    ("crates/romwright-core/src/register_params.rs", "prototype"),
    ("crates/romwright-core/src/structuring.rs", "structuring"),
    ("crates/romwright-core/src/func_ir/types.rs", "type_inference"),
    ("crates/romwright-core/src/func_ir*", "simplification"),
    ("crates/romwright-model/src/function_ir.rs", "simplification"),
    ("crates/romwright-core/src/emit_m2c*", "postprocess"),
    ("crates/romwright-core/src/ir.rs", "simplification"),
    ("crates/romwright-core/src/disasm.rs", "pcode_lift"),
    ("crates/romwright-core/src/listing.rs", "pcode_lift"),
    ("*", "host"),
]

# Vendored C++ (and our headers/patch) by file stem. First match wins.
CPP_RULES = [
    ("loadimage*", "load"), ("bfd_arch*", "load"), ("memstate*", "load"),
    ("sleigh*", "pcode_lift"), ("slgh*", "pcode_lift"), ("pcodeparse*", "pcode_lift"),
    ("translate*", "pcode_lift"), ("context*", "pcode_lift"), ("globalcontext*", "pcode_lift"),
    ("pcodeinject*", "pcode_lift"), ("inject_*", "pcode_lift"), ("ghidra_translate*", "pcode_lift"),
    ("ghidra_context*", "pcode_lift"), ("semantics*", "pcode_lift"), ("pcoderaw*", "pcode_lift"),
    ("opcodes*", "pcode_lift"), ("emulate*", "pcode_lift"), ("opbehavior*", "pcode_lift"),
    ("flow.*", "flow"), ("romwright_ppc_return*", "pcode_lift"),
    ("jumptable*", "switch_recovery"), ("romwright_budget*", "switch_recovery"),
    ("romwright_nonreturn*", "discovery"),
    ("romwright_printir*", "printing"), ("romwright_ir*", "simplification"),
    ("romwright_structure*", "structuring"), ("romwright_merge*", "variables"), ("romwright_bytes*", "printing"),
    ("type.*", "type_inference"), ("typeop*", "type_inference"), ("cast*", "type_inference"),
    ("fspec*", "prototype"), ("modelrules*", "prototype"), ("callgraph*", "prototype"),
    ("block.*", "structuring"), ("blockaction*", "structuring"), ("graph.*", "structuring"),
    ("printc*", "printing"), ("printlanguage*", "printing"), ("prettyprint*", "printing"),
    ("printjava*", "printing"), ("grammar*", "printing"), ("comment*", "printing"),
    ("action.*", "simplification"), ("coreaction*", "simplification"), ("ruleaction*", "simplification"),
    ("subflow*", "simplification"), ("double*", "simplification"), ("condexe*", "simplification"),
    ("constseq*", "simplification"), ("heritage*", "simplification"), ("merge*", "variables"),
    ("cover*", "variables"), ("rangeutil*", "simplification"), ("varmap*", "simplification"),
    ("funcdata*", "simplification"), ("varnode*", "simplification"), ("op.*", "simplification"),
    ("transform*", "simplification"), ("expression*", "simplification"), ("unify*", "simplification"),
    ("float*", "simplification"), ("dynamic*", "simplification"), ("multiprecision*", "simplification"),
    ("unionresolve*", "simplification"), ("variable*", "variables"), ("blockaction*", "structuring"),
    ("database*", "load"), ("cpool*", "load"), ("space.*", "load"), ("address.*", "load"),
    ("ghidra_process*", "host"), ("ghidra_arch*", "host"), ("marshal*", "host"), ("xml*", "host"),
    ("architecture*", "host"), ("consolemain*", "host"), ("ifacedecomp*", "host"),
    ("interface*", "host"), ("ifaceterm*", "host"), ("libdecomp*", "host"), ("capability*", "host"),
    ("*", "host"),
]

# export-c phases of `import --timings`, by the implementation that does the
# work inside the phase (crates/romwright-core/src/native.rs `discover`,
# native/discovery.rs). The reference pass runs in process over kuna-sleigh
# (native_runtime/propagation); `switch` is the decompiler path.
PHASE_OWNER = {
    "references-only": ("rust", "native/references.rs reference pass over native_runtime/propagation (in process)"),
    "patterns": ("rust", "native_runtime/patterns.rs function-start pattern search (Ghidra BytePatterns, in process)"),
    "switch": ("cpp", "decompiler switch path (ghidra_opt via the worker)"),
    "discovery": ("rust", "native/discovery.rs walk"),
    "flow": ("rust", "in-process SLEIGH flow (kuna-sleigh)"),
    "parse": ("rust", "container parse"),
    "settle": ("rust", "native.rs settle"),
    "store": ("rust", "database write"),
    "switch-vsa": ("rust", "native/vsa.rs value-set analysis"),
}
# `references` repeats `references-only`, so it is not summed.
PHASE_SKIP = {"references"}

# Provenance of stored facts, by the implementation whose result is stored.
# Every provenance is decided by Rust code (native/*.rs, native_runtime/) from
# SLEIGH flow facts or the image since the constant propagation moved in
# process; the set stays so a C++-computed fact would show here.
CPP_PROVENANCE: set[str] = set()
# Crates on the import/decompile/export-c path; the rest (desktop, debugger,
# API server, differ, signatures) are product surface the pipeline never runs.
PIPELINE_CRATES = {"romwright-core", "romwright-db", "romwright-model", "romwright-worker",
                   "romwright-worker-client", "romwright-cli", "romwright-facts"}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def stage_of(path: str, rules) -> str:
    for pattern, stage in rules:
        if fnmatch.fnmatch(path, pattern):
            return stage
    return "host"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Inventory: lines of code from the files
# ---------------------------------------------------------------------------

C_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def code_lines_cpp(text: str) -> int:
    text = C_COMMENT.sub("", text)
    return sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("//"))


def rust_split(text: str) -> tuple[int, int]:
    """(code lines, test lines): non-blank, non-comment lines; a
    `#[cfg(test)]` item (a `mod tests { .. }` block) counts as test."""
    code = test = 0
    depth = 0
    in_test = False
    pending_test = False
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if in_block:
            if "*/" in line:
                in_block = False
            continue
        if line.startswith("/*"):
            if "*/" not in line:
                in_block = True
            continue
        if not line or line.startswith("//"):
            continue
        if not in_test and line.startswith("#[cfg(test)]"):
            pending_test = True
            test += 1
            continue
        if pending_test and not in_test:
            test += 1
            depth = line.count("{") - line.count("}")
            if depth > 0:
                in_test = True
            else:
                pending_test = False
            continue
        if in_test:
            test += 1
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_test = False
                pending_test = False
            continue
        code += 1
    return code, test


def parse_patch(patch: Path) -> dict[str, dict]:
    """Per patched file: new-file flag, the set of added line numbers in the
    patched file, and the count of added code lines (non-blank, non-comment)."""
    files: dict[str, dict] = {}
    current = None
    new_line = 0
    new_file = False
    for raw in patch.read_text(errors="replace").splitlines():
        if raw.startswith("diff --git "):
            new_file = False
            current = None
        elif raw.startswith("new file mode"):
            new_file = True
        elif raw.startswith("+++ "):
            name = raw[4:].strip()
            if name == "/dev/null":
                current = None
                continue
            name = name[2:] if name.startswith("b/") else name
            current = files.setdefault(name, {"new_file": new_file, "added": set(), "code": 0})
            current["new_file"] = new_file
        elif raw.startswith("--- "):
            continue
        elif raw.startswith("@@") and current is not None:
            match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            new_line = int(match.group(1)) if match else 0
        elif current is not None and raw.startswith("+"):
            current["added"].add(new_line)
            body = raw[1:].strip()
            if body and not body.startswith(("//", "/*", "*")):
                current["code"] += 1
            new_line += 1
        elif current is not None and raw.startswith(" "):
            new_line += 1
    return files


def inventory() -> dict:
    crates = {}
    totals = Counter()
    for crate in sorted((ROOT / "crates").iterdir()):
        src = crate / "src"
        if not src.is_dir():
            continue
        code = test = 0
        for path in src.rglob("*.rs"):
            relative = path.relative_to(crate / "src").as_posix()
            text = path.read_text(errors="replace")
            c, t = rust_split(text)
            if path.name == "tests.rs" or "/tests/" in "/" + relative or path.name.endswith("_tests.rs"):
                test += c + t
            else:
                code += c
                test += t
        crates[crate.name] = {"code": code, "test": test}
        totals["code"] += code
        totals["test"] += test
    kuna = ROOT / "third_party" / "kuna-sleigh"
    kuna_code = 0
    if kuna.is_dir():
        for path in kuna.rglob("*.rs"):
            kuna_code += rust_split(path.read_text(errors="replace"))[0]
    vendored = ROOT / "third_party" / "ghidra" / "decompiler"
    vendored_code = vendored_files = 0
    for path in vendored.iterdir():
        if path.suffix in {".cc", ".hh", ".h", ".y", ".l"}:
            vendored_code += code_lines_cpp(path.read_text(errors="replace"))
            vendored_files += 1
    patch = parse_patch(ROOT / "native" / "ghidra-opt-sleigh.patch")
    patch_code = sum(item["code"] for item in patch.values())
    headers = {}
    for path in sorted((ROOT / "native").glob("romwright_*.hh")):
        headers[path.name] = code_lines_cpp(path.read_text(errors="replace"))
    return {
        "unit": "code lines: non-blank, non-comment; Rust test code excluded",
        "rust_first_party": {
            "code": totals["code"], "test": totals["test"], "crates": crates,
            "pipeline_code": sum(crates[name]["code"] for name in PIPELINE_CRATES if name in crates),
            "pipeline_crates": sorted(PIPELINE_CRATES),
        },
        "rust_third_party_vendored": {
            "kuna-sleigh (third_party/kuna-sleigh, patched copy; kuna-base and kuna-num are git dependencies, not counted)": kuna_code},
        "cpp_ours": {
            "patch_added_code": patch_code,
            "patch_files": len(patch),
            "patch_new_files": sorted(name for name, item in patch.items() if item["new_file"]),
            "headers": headers,
            "headers_code": sum(headers.values()),
            "code": patch_code + sum(headers.values()),
        },
        "cpp_vendored": {"code": vendored_code, "files": vendored_files,
                         "note": "counts every file of the pinned tree, including the SLEIGH compiler, the "
                                 "interactive console and the BFD loader, which `ghidra_opt` does not link; "
                                 "the coverage map's executable lines (`cpp_vendored`) are what the binary holds"},
    }


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, check=True, **kwargs).stdout


def parse_lcov(text: str):
    """{file: {line: count}} from `llvm-cov export -format=lcov`."""
    files: dict[str, dict[int, int]] = {}
    current = None
    for raw in text.splitlines():
        if raw.startswith("SF:"):
            current = files.setdefault(raw[3:], {})
        elif raw.startswith("DA:") and current is not None:
            line, count = raw[3:].split(",")[:2]
            line = int(line)
            current[line] = max(current.get(line, 0), int(count))
    return files


def classify_rust(path: str, workspace: str) -> str:
    """first-party: this repository's crates; third-party: the kuna-sleigh
    port of Ghidra's translator (path or git checkout); dependency: every
    other crate and the standard library."""
    if path.startswith(workspace + "/crates/"):
        return "rust_first_party"
    if "/third_party/kuna-sleigh/" in path or re.search(r"/git/checkouts/kuna-[^/]+/", path):
        return "rust_third_party"
    return "rust_dependency"


def coverage(args, patch: dict[str, dict]) -> dict:
    """Executed lines per owner and stage from the merged profiles."""
    profraw = sorted(args.profraw.glob("*.profraw"))
    if not profraw:
        return {"status": "no profiles", "dir": str(args.profraw)}
    merged = args.profraw / "merged.profdata"
    run(["llvm-profdata", "merge", "-sparse", *map(str, profraw), "-o", str(merged)])
    target = args.target_dir / "release"
    rust_bins = [target / "romwright-cli", target / "romwright-worker"]
    cpp_bins = [args.cov_build / "ghidra_opt"]
    workspace = str(ROOT)
    if args.source_root:
        workspace = str(args.source_root)
    src_root = args.cov_build / "src" / "decompiler"
    out = {"profiles": len(profraw), "binaries": {}}
    # The C++ build tree must be this tree's patch and headers, or the line
    # attribution (patch-added lines) is wrong.
    built = args.cov_build / "src"
    cpp_inputs = {"native/ghidra-opt-sleigh.patch": built / "apply.patch"}
    cpp_inputs.update({f"native/{p.name}": built / "decompiler" / p.name
                       for p in (ROOT / "native").glob("romwright_*.hh")})
    out["cpp_build_matches_tree"] = all(
        theirs.is_file() and (ROOT / name).read_bytes() == theirs.read_bytes()
        for name, theirs in cpp_inputs.items())
    # Per (owner, stage): executable and executed lines; per file kept for the
    # unassigned list and the report's file table.
    cells: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    per_binary = {}
    cpp_union: dict[str, dict[int, int]] = {}
    rust_union: dict[str, dict[int, int]] = {}
    for binary in rust_bins + cpp_bins:
        if not binary.is_file():
            out["binaries"][binary.name] = "missing"
            continue
        text = subprocess.run(
            ["llvm-cov", "export", "-format=lcov", f"-instr-profile={merged}", str(binary)],
            capture_output=True, text=True).stdout
        files = parse_lcov(text)
        per_binary[binary.name] = {"files": len(files)}
        union = rust_union if binary in rust_bins else cpp_union
        for name, lines in files.items():
            target_lines = union.setdefault(name, {})
            for line, count in lines.items():
                target_lines[line] = max(target_lines.get(line, 0), count)
    out["binaries"].update(per_binary)
    unassigned = Counter()
    dependency_lines = [0, 0]
    rust_files = {}
    for name, lines in rust_union.items():
        owner = classify_rust(name, workspace)
        relative = name[len(workspace) + 1:] if name.startswith(workspace + "/") else name
        if owner == "rust_dependency":
            dependency_lines[0] += len(lines)
            dependency_lines[1] += sum(1 for count in lines.values() if count > 0)
            continue
        stage = stage_of(relative, RUST_RULES) if owner == "rust_first_party" else "pcode_lift"
        executable = len(lines)
        executed = sum(1 for count in lines.values() if count > 0)
        cells[(owner, stage)][0] += executable
        cells[(owner, stage)][1] += executed
        if owner == "rust_first_party" and stage == "host" and executed:
            unassigned[relative] = executed
        rust_files[relative] = [executable, executed, stage, owner]
    cpp_files = {}
    for name, lines in cpp_union.items():
        path = Path(name)
        try:
            relative = path.resolve().relative_to(src_root.resolve()).as_posix()
        except ValueError:
            continue
        stem = relative
        stage = stage_of(stem, CPP_RULES)
        ours_lines = patch.get("decompiler/" + relative, {}).get("added", set())
        always_ours = relative.startswith("romwright_")
        for line, count in lines.items():
            owner = "cpp_ours" if always_ours or line in ours_lines else "cpp_vendored"
            cells[(owner, stage)][0] += 1
            cells[(owner, stage)][1] += 1 if count > 0 else 0
        executable = len(lines)
        executed = sum(1 for count in lines.values() if count > 0)
        ours_executed = sum(1 for line, count in lines.items()
                            if count > 0 and (always_ours or line in ours_lines))
        cpp_files[relative] = [executable, executed, stage, ours_executed]
    by_stage = {stage: {owner: {"executable": cells[(owner, stage)][0], "executed": cells[(owner, stage)][1]}
                        for owner in OWNERS} for stage, _ in STAGES}
    totals = {owner: {"executable": sum(cells[(owner, s)][0] for s, _ in STAGES),
                      "executed": sum(cells[(owner, s)][1] for s, _ in STAGES)} for owner in OWNERS}
    out.update(by_stage=by_stage, totals=totals,
               rust_dependencies={"executable": dependency_lines[0], "executed": dependency_lines[1],
                                  "note": "other crates and std linked into the Rust binaries; not an owner"},
               unassigned_rust_files=dict(unassigned.most_common(15)),
               top_executed_vendored=sorted(
                   ((relative, row[1] - row[3], row[2]) for relative, row in cpp_files.items()),
                   key=lambda item: -item[1])[:25],
               top_executed_first_party=sorted(
                   ((relative, row[1], row[2]) for relative, row in rust_files.items()
                    if row[3] == "rust_first_party"), key=lambda item: -item[1])[:25])
    return out


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

IDENT = re.compile(r"[A-Za-z_]\w*")
RENAMED = re.compile(r"\b(?:temp_[vf]\d+|sp[0-9A-F]+)\b")


def export_one(tools, project: Path, binary: Path, program: str, address: int, env: dict,
               transforms: str | None, ownership_log: Path | None, profraw: Path | None) -> dict:
    """One `export-c --address`; the row the ownership report keeps."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="own-c-") as temporary:
        outdir = Path(temporary) / "out"
        argv = [str(tools.cli), "export-c", str(binary), program, str(outdir), "--address", f"{address:x}",
                "--project", str(project)]
        if transforms is not None:
            argv += ["--transforms", transforms]
        extra = dict(env)
        if ownership_log is not None:
            ownership_log.unlink(missing_ok=True)
            extra["ROMWRIGHT_OWNERSHIP_LOG"] = str(ownership_log)
        process_env = tools.env(extra)
        if profraw is not None:
            process_env["LLVM_PROFILE_FILE"] = str(profraw / "own-%m%c.profraw")
        started = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=600, env=process_env)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = -9, "", "timeout after 600s"
        seconds = round(time.monotonic() - started, 3)
        files = sorted(outdir.glob("*.c")) if outdir.exists() else []
        row = {"address": f"{address:08x}", "exit": code, "seconds": seconds}
        if code != 0 or not files:
            row.update(success=False, error=(stderr or stdout)[-300:])
            return row
        text = "\n".join(path.read_text(errors="replace") for path in files)
    try:
        report = json.loads(stdout)
    except ValueError:
        report = {}
    identifiers = [word for word in IDENT.findall(text)]
    row.update(
        success=True,
        sha256=hashlib.sha256(text.encode()).hexdigest()[:16],
        lines=sum(1 for line in text.splitlines() if line.strip()),
        gotos=len(re.findall(r"\bgoto\b", text)),
        semantic_rewrites=report.get("semantic_rewrites"),
        identifiers=len(identifiers),
        renamed_identifiers=len(RENAMED.findall(text)),
    )
    if ownership_log is not None and ownership_log.is_file():
        records = []
        for line in ownership_log.read_text().splitlines():
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
        wanted = f"{address:x}"
        match = [record for record in records if record.get("address") == wanted]
        row["own"] = (match or records or [None])[-1]
        row["own_records"] = len(records)
        ownership_log.unlink(missing_ok=True)
    return row


def run_pass(tools, spec, project, binary, program, sample, env, transforms, jobs, work: Path,
             with_log: bool, profraw: Path | None, label: str) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()

    def one(address):
        log_path = work / f"{label}-{address:08x}.jsonl" if with_log else None
        return export_one(tools, project, binary, program, address, env, transforms, log_path, profraw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        rows = list(pool.map(one, sample))
    return {"label": label, "env": env, "transforms": transforms,
            "wall_seconds": round(time.monotonic() - started, 1), "functions": rows}


def db_facts(project: Path, program: str, sample: list[int]) -> dict:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    facts = {}
    facts["functions"] = db.execute("SELECT COUNT(*) FROM functions WHERE program_id=?", (pid,)).fetchone()[0]
    facts["functions_by_producer"] = dict(db.execute(
        "SELECT producer, COUNT(*) FROM functions WHERE program_id=? GROUP BY 1 ORDER BY 2 DESC", (pid,)))
    facts["xrefs_by_provenance"] = {
        f"{provenance}|{kind}": count for provenance, kind, count in db.execute(
            "SELECT provenance, kind, COUNT(*) FROM xrefs WHERE program_id=? GROUP BY 1,2 ORDER BY 3 DESC", (pid,))}
    facts["data_definitions_by_provenance"] = dict(db.execute(
        "SELECT provenance, COUNT(*) FROM data_definitions WHERE program_id=? GROUP BY 1", (pid,)))
    facts["flow_overrides_by_provenance"] = dict(db.execute(
        "SELECT provenance, COUNT(*) FROM flow_overrides WHERE program_id=? GROUP BY 1", (pid,)))
    facts["prototypes_by_provenance"] = dict(db.execute(
        "SELECT provenance, COUNT(*) FROM prototypes WHERE program_id=? GROUP BY 1", (pid,)))
    facts["memory_bytes"] = db.execute(
        "SELECT COALESCE(SUM(size),0) FROM memory_regions WHERE program_id=?", (pid,)).fetchone()[0]
    facts["symbols_by_source"] = dict(db.execute(
        "SELECT source, COUNT(*) FROM symbols WHERE program_id=? GROUP BY 1", (pid,)))
    sizes = {}
    producers = Counter()
    instructions = 0
    for entry, size, producer in db.execute(
            "SELECT entry, size, producer FROM functions WHERE program_id=?", (pid,)):
        try:
            address = int(entry, 16)
        except ValueError:
            continue
        sizes[address] = (size, producer)
    wanted = set(sample)
    for address in wanted:
        if address in sizes:
            producers[sizes[address][1]] += 1
    for entry, count in db.execute(
            "SELECT function, instructions FROM function_features WHERE program_id=?", (pid,)):
        try:
            if int(entry, 16) in wanted:
                instructions += count
        except ValueError:
            continue
    facts["sample_functions_by_producer"] = dict(producers)
    facts["sample_instructions"] = instructions
    facts["sample_bytes"] = sum(sizes[a][0] for a in wanted if a in sizes)
    switches = defaultdict(set)
    for src, dst in db.execute(
            "SELECT src, dst FROM xrefs WHERE program_id=? AND provenance='native-import:switch'", (pid,)):
        switches[int(src, 16)].add(int(dst, 16))
    facts["_switches"] = switches
    facts["_sizes"] = sizes
    db.close()
    return facts


def switch_attribution(default_facts: dict, vsa_only_facts: dict, sample: list[int]) -> dict:
    """Who recovered each stored dispatch: a branch the VSA-only import
    (decompiler switch path off) also has was recovered by Rust value-set
    analysis, any other by the decompiler's path."""
    vsa = vsa_only_facts["_switches"]
    stored = default_facts["_switches"]
    by_rust = {b: t for b, t in stored.items() if b in vsa}
    by_decompiler = {b: t for b, t in stored.items() if b not in vsa}
    sizes = default_facts["_sizes"]
    inside = defaultdict(list)
    entries = sorted(sizes)
    import bisect
    for branch in stored:
        index = bisect.bisect_right(entries, branch) - 1
        if index >= 0:
            entry = entries[index]
            if branch < entry + max(sizes[entry][0], 1):
                inside[entry].append(branch)
    sample_set = set(sample)
    in_sample = {b for entry, branches in inside.items() if entry in sample_set for b in branches}
    return {
        "stored_dispatches": len(stored),
        "stored_cases": sum(len(t) for t in stored.values()),
        "rust_vsa_dispatches": len(by_rust),
        "rust_vsa_cases": sum(len(t) for t in by_rust.values()),
        "decompiler_dispatches": len(by_decompiler),
        "decompiler_cases": sum(len(t) for t in by_decompiler.values()),
        "vsa_only_import_dispatches": len(vsa),
        "sample_dispatches": len(in_sample),
        "sample_rust_vsa": len(in_sample & set(by_rust)),
        "sample_decompiler": len(in_sample & set(by_decompiler)),
        "_in_sample": in_sample,
    }


def aggregate_rows(rows: list[dict]) -> dict:
    """Sums of the ownership log over the functions that printed."""
    total = Counter()
    kinds = Counter()
    regions = Counter()
    created = Counter()
    removed = Counter()
    applied = Counter()
    passes = Counter()
    sources = Counter()
    kinds_rust = Counter()
    expr_kinds = defaultdict(lambda: [0, 0])
    expr_reasons = Counter()
    n = 0
    for row in rows:
        own = row.get("own")
        if not row.get("success") or not own or not own.get("print"):
            continue
        n += 1
        print_stats = own["print"]
        tokens = print_stats["tokens"]
        total["tokens"] += tokens["total"]
        total["fragment_tokens"] += tokens["fragments"]
        total["block_layer_tokens"] += tokens["block_layer"]
        total["rust_expression_tokens"] += tokens.get("rust_expressions", 0)
        kinds_rust.update(tokens.get("rust_expressions_by_kind") or {})
        expressions = print_stats.get("expressions") or {}
        for key, (rust, kept) in (expressions.get("by_kind") or {}).items():
            expr_kinds[key][0] += rust
            expr_kinds[key][1] += kept
        expr_reasons.update(expressions.get("reasons") or {})
        total["spacing_tokens"] += tokens["spacing"]
        kinds.update(tokens["fragments_by_kind"])
        regions.update(tokens["fragments_by_region"])
        constructs = print_stats["constructs"]
        total["ghidra_constructs"] += constructs["ghidra"]
        total["printed_constructs"] += constructs["printed"]
        total["kept_constructs"] += constructs["kept"]
        created.update(constructs["created_by_kind"])
        removed.update(constructs["removed_by_kind"])
        total["gotos_ghidra"] += print_stats["gotos"][0]
        total["gotos_printed"] += print_stats["gotos"][1]
        total["labels_ghidra"] += print_stats["labels"][0]
        total["labels_printed"] += print_stats["labels"][1]
        for model, count in print_stats["applied"].items():
            applied[model] += count
        total["restructured_functions"] += int(print_stats["restructured"])
        total["operations"] += own["operations"]
        total["calls"] += own["calls"]
        total["calls_with_stored_prototype"] += own["calls_with_stored_prototype"]
        total["edits"] += own["edits"]["total"]
        total["edits_additive_inverse"] += own["edits"]["additive_inverse"]
        total["edits_canonical_helpers"] += own["edits"]["canonical_helpers"]
        total["functions_with_edits"] += int(own["edits"]["total"] > 0)
        total["cuts_proposed"] += own["cuts"]["proposed"]
        total["cuts_kept"] += own["cuts"]["kept"]
        total["functions_with_stored_prototype"] += int(own["stored_prototype"] is not None)
        stored = own.get("stored_prototype")
        if stored:
            source = stored["source"]
            sources[re.sub(r"\(.*?\)", "()", source)] += 1
            if "inferred-types(" in source:
                total["inferred_slot_upgrades"] += source.count("->")
        total["jump_tables_printed"] += len(own.get("jump_tables") or [])
        total["jump_table_cases_printed"] += sum(t["targets"] for t in own.get("jump_tables") or [])
        # Where each printed table's addresses came from (JumpTable::recoverStored):
        # the import's stored table agreed with jumptable.cc ("confirmed"), replaced it
        # ("applied"), or there was none ("none").
        for item in own.get("switch_sources") or []:
            total[f"printed_switch_{item['state']}"] += 1
        proto = own.get("printed_prototype") or {}
        total["printed_parameters"] += proto.get("parameters") or 0
        total["parameters_from_pass"] += (proto.get("parameters") or 0) if proto.get("parameter_source") else 0
        total["identifiers"] += row.get("identifiers", 0)
        total["renamed_identifiers"] += row.get("renamed_identifiers", 0)
        for report in own["passes"]:
            passes[f"{report['name']}:{report['role']}"] += report["items"]
    return {"functions": n, **total, "fragment_tokens_by_kind": dict(kinds),
            "rust_expression_tokens_by_kind": dict(kinds_rust),
            "expressions_rust_by_kind": {k: v[0] for k, v in sorted(expr_kinds.items())},
            "expressions_fragment_by_kind": {k: v[1] for k, v in sorted(expr_kinds.items())},
            "expression_fallback_reasons": dict(expr_reasons),
            "fragment_tokens_by_region": dict(regions), "constructs_created_by_kind": dict(created),
            "constructs_removed_by_kind": dict(removed), "structuring_applied": dict(applied),
            "pass_items": dict(passes), "prototype_sources": dict(sources)}


def counterfactual_union(default_rows, ablated_rows: list[list[dict]]) -> dict:
    """Functions that print differently in at least one ablation pass: the
    functions that depend on the Rust structuring models or the Rust IR
    passes (a function changed by neither prints the same without both)."""
    others = [{row["address"]: row for row in rows if row.get("success")} for rows in ablated_rows]
    both = different = 0
    for row in default_rows:
        if not row.get("success") or any(row["address"] not in other for other in others):
            continue
        both += 1
        different += int(any(row["sha256"] != other[row["address"]]["sha256"] for other in others))
    return {"compared": both, "identical": both - different, "different": different}


def counterfactual(default_rows, other_rows) -> dict:
    """Functions printed by both passes, and how many differ in text."""
    other = {row["address"]: row for row in other_rows if row.get("success")}
    both = same = 0
    for row in default_rows:
        if not row.get("success") or row["address"] not in other:
            continue
        both += 1
        same += int(row["sha256"] == other[row["address"]]["sha256"])
    return {"compared": both, "identical": same, "different": both - same}


def source_digest() -> dict:
    digest = hashlib.sha256()
    count = 0
    for base in ("crates", "native", "third_party/kuna-sleigh"):
        for path in sorted((ROOT / base).rglob("*")):
            if path.is_file() and path.suffix in {".rs", ".hh", ".cc", ".patch", ".toml", ".sh"} \
                    and "target" not in path.parts and "build" not in path.relative_to(ROOT).parts[:2]:
                digest.update(path.relative_to(ROOT).as_posix().encode())
                digest.update(hashlib.sha256(path.read_bytes()).digest())
                count += 1
    info = {"files": count, "sha256": digest.hexdigest()[:16]}
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True)
    if head.returncode == 0:
        info["git_head"] = head.stdout.strip()
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                               capture_output=True, text=True).stdout.splitlines()
        info["uncommitted_paths"] = len(dirty)
    else:
        info["vcs"] = "none: a working-tree snapshot, not a checkout"
    return info


PROTOTYPE_CACHES = [
    ("research-final", Path.home() / ".cache" / "romwright" / "research-final"),
    ("research-proto", Path.home() / ".cache" / "romwright" / "research-proto"),
]
TYPES_VAR = "ROMWRIGHT_INFERRED_TYPES"
REGISTER_VAR = "ROMWRIGHT_REGISTER_PARAMS"


def persisted_prototype_input(args, CR, spec):
    """The persisted-prototype profile's input: a research cache's
    `infer_prototypes` project with the inferred-types merge on (the
    current default), and the sample that cache decompiled. The `infer_prototypes`
    job costs 10 s (psx) to 87 min (Vita), so the profile reads the projects
    those runs left, copied and never mutated. The newest project whose job
    finished its rounds wins: research-final's x360 and Vita jobs stopped on
    the job budget, research-proto's finished."""
    best, best_time = None, -1.0
    for name, root in args.prototype_caches:
        # Project names are `<id>-<image sha12>-<env key12>-<tools>-proto-<key>`.
        # Match the id exactly: `psp-puzzle-bobble-pocket-*` would also take
        # the project of `psp-puzzle-bobble-pocket-symtab`.
        own = re.compile(rf"{re.escape(spec['id'])}-[0-9a-f]{{12}}-[0-9a-f]{{12}}-[0-9a-f]+-proto-[0-9a-f]+")
        for project in sorted(root.joinpath("projects").iterdir()):
            if not own.fullmatch(project.name):
                continue
            done = CR.read_json(project / "done.json")
            if not done or not done.get("prototypes"):
                continue
            env = done["prototypes"].get("env") or {}
            if env.get(REGISTER_VAR):
                continue
            # In research-final the merge was opt-in (env value 1); later it
            # became the default and `0` is the ablation.
            on = env.get(TYPES_VAR) == "1" if name == "research-final" else env.get(TYPES_VAR) != "0"
            if not on:
                continue
            sample = CR.read_json(root / "samples" / f"{spec['id']}-{done['tools']}-{args.n}-{args.seed}.json")
            if sample is None or done["prototypes"]["report"].get("stop_reason") == "budget":
                continue
            stamp = (project / "done.json").stat().st_mtime
            if stamp > best_time:
                best, best_time = (project, done, [int(a) for a in sample]), stamp
    return best


def run_image(args, CR, tools, spec, cache: Path) -> dict:
    corpus = args.corpus
    source = corpus / spec["image"]
    if not source.is_file() or (spec.get("truth") and not (corpus / spec["truth"][1]).is_file()):
        return {"status": "skipped", "reason": "image or truth absent"}
    binary = CR.prepared_binary(spec, corpus, cache)
    image_sha = CR.sha256_file(source)
    truth = CR.function_truth(spec, corpus)
    dwarf = None
    if spec["id"] in CR.DWARF:
        dwarf_path = cache / "dwarf" / f"{spec['id']}-{image_sha[:12]}.json"
        dwarf_report = CR.read_json(dwarf_path)
        if dwarf_report is None:
            log(f"{spec['id']}: reading DWARF truth")
            extracted = CR.dwarf_truth(corpus / CR.DWARF[spec["id"]])
            dwarf_report = dict(extracted, functions={f"{k:08x}": v for k, v in extracted["functions"].items()})
            CR.write_json(dwarf_path, dwarf_report)
        dwarf = {int(k, 16): v for k, v in dwarf_report["functions"].items()}
    # The default import is profiled; the decompiler-switch-off import that
    # attributes dispatches is an ablation and is not merged into coverage.
    os.environ["LLVM_PROFILE_FILE"] = str(args.profraw / "own-%m%c.profraw")
    project, marker = CR.import_env_project(tools, spec, binary, image_sha, {}, truth, cache)
    program = marker["program"]
    os.environ["LLVM_PROFILE_FILE"] = str(args.profraw_ablation / "abl-%m%c.profraw")
    vsa_project, vsa_marker = CR.import_env_project(
        tools, spec, binary, image_sha, {CR.NO_SWITCH_DECOMPILER: "1"}, truth, cache)
    sample = CR.choose_sample(spec, project, program, truth, dwarf, args.n, args.seed)
    work = cache / "work" / spec["id"]
    result_path = cache / "results" / tools.fingerprint / f"{spec['id']}-{args.n}-{args.seed}.json"
    cached = CR.read_json(result_path)
    key = {"tools": tools.fingerprint, "sample": sha256_text(json.dumps(sample)), "project": project.name}
    if cached and cached.get("key") == key:
        log(f"{spec['id']}: reusing {result_path}")
        return cached["image"]
    log(f"{spec['id']}: {len(sample)} sampled functions")
    # Default pass (profiled), then ablations (not merged into coverage).
    default = run_pass(tools, spec, project, binary, program, sample, {}, None, args.jobs, work,
                       True, args.profraw, "default")
    ablations = {}
    for name, env, transforms in (
            ("rust-structuring-none", {CR.STRUCTURING: "none"}, None),
            ("ir-none", {CR.IR: ""}, ""),
            # Not part of "either": the expression printer is meant to print what PrintC's
            # fragments print, so this pass measures that (identical = no output difference).
            ("rust-expressions-off", {"ROMWRIGHT_RUST_EXPRESSIONS": "off"}, None)):
        ablations[name] = run_pass(tools, spec, project, binary, program, sample, env, transforms,
                                   args.jobs, work, False, args.profraw_ablation, name)
    default_facts = db_facts(project, program, sample)
    vsa_facts = db_facts(vsa_project, vsa_marker["program"], sample)
    attribution = switch_attribution(default_facts, vsa_facts, sample)
    in_sample = attribution.pop("_in_sample")
    printed_set = set()
    for row in default["functions"]:
        for table in (row.get("own") or {}).get("jump_tables") or []:
            printed_set.add(int(table["branch"], 16))
    rust_branches = {b for b in default_facts["_switches"] if b in vsa_facts["_switches"]}
    attribution["sample_printed_as_switch"] = len(in_sample & printed_set)
    attribution["sample_printed_as_switch_rust_vsa"] = len(in_sample & printed_set & rust_branches)
    attribution["sample_printed_tables_not_stored"] = len(printed_set - set(default_facts["_switches"]))
    # Printed tables whose addresses the stored table supplied, and of those the ones Rust VSA
    # recovered at import (the rest were recovered by the import's own decompiler pass).
    supplied = {int(item["branch"]) for row in default["functions"]
                for item in (row.get("own") or {}).get("switch_sources") or []
                if item["state"] in ("confirmed", "applied")}
    attribution["sample_printed_stored"] = len(supplied)
    attribution["sample_printed_stored_rust_vsa"] = len(supplied & rust_branches)
    for facts in (default_facts, vsa_facts):
        facts.pop("_switches")
        facts.pop("_sizes")
    successes = [row for row in default["functions"] if row.get("success")]
    image = {
        "status": "ran",
        "program": program,
        "sample": [f"{a:08x}" for a in sample],
        "import": {"seconds": marker.get("seconds"), "phases": marker.get("phases"),
                   "switch_stats": marker.get("switch_stats"), "diagnostics": marker.get("diagnostics")},
        "facts": default_facts,
        "switch": attribution,
        "default_pass": {"wall_seconds": default["wall_seconds"], "sampled": len(sample),
                         "decompiled": len(successes),
                         "failed": [row["address"] for row in default["functions"] if not row.get("success")]},
        "aggregate": aggregate_rows(default["functions"]),
        "counterfactual": {
            **{name: counterfactual(default["functions"], result["functions"])
               for name, result in ablations.items()},
            "either": counterfactual_union(
                default["functions"],
                [r["functions"] for name, r in ablations.items() if name != "rust-expressions-off"]),
        },
    }
    # Persisted-prototype profile: the same worker over a project that
    # carries `infer_prototypes` results.
    prototypes = persisted_prototype_input(args, CR, spec)
    if prototypes:
        origin, done, p_sample = prototypes
        destination = cache / "projects-persisted" / spec["id"]
        if not (destination / "done.json").is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            CR.reflink_copy(origin, destination)
        os.environ["LLVM_PROFILE_FILE"] = str(args.profraw / "own-%m%c.profraw")
        persisted = run_pass(tools, spec, destination, binary, done["program"], p_sample, {}, None,
                             args.jobs, work, True, args.profraw, "persisted")
        p_facts = db_facts(destination, done["program"], p_sample)
        p_facts.pop("_switches")
        p_facts.pop("_sizes")
        image["persisted_prototypes"] = {
            "origin": str(origin), "origin_tools": done["tools"],
            "job": {"env": done["prototypes"]["env"], "seconds": done["prototypes"]["seconds"],
                    "analyzed": done["prototypes"]["report"].get("analyzed"),
                    "changed": done["prototypes"]["report"].get("changed"),
                    "rounds": done["prototypes"]["report"].get("rounds")},
            "sampled": len(p_sample),
            "decompiled": sum(1 for row in persisted["functions"] if row.get("success")),
            "prototypes_by_provenance": p_facts["prototypes_by_provenance"],
            "aggregate": aggregate_rows(persisted["functions"]),
        }
    else:
        image["persisted_prototypes"] = None
    CR.write_json(result_path, {"key": key, "image": image})
    return image


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def pct(part, whole) -> str:
    return "n/a" if not whole else f"{100.0 * part / whole:.1f}%"


def share(part, whole):
    return None if not whole else round(part / whole, 4)


def total_of(images: dict, node) -> Counter:
    """Sum of the numeric values of `node(image)` over the images that ran;
    nested dicts of counts (fragment kinds, prototype sources) are summed
    key by key."""
    total = Counter()
    for image in images.values():
        if image.get("status") != "ran":
            continue
        values = node(image) or {}
        for key, value in values.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                total[key] += value
            elif isinstance(value, dict) and all(
                    isinstance(item, (int, float)) and not isinstance(item, bool) for item in value.values()):
                nested = total[key] if isinstance(total[key], dict) else {}
                for name, item in value.items():
                    nested[name] = nested.get(name, 0) + item
                total[key] = nested
    return total


def merged(images: dict, node, key) -> Counter:
    total = Counter()
    for image in images.values():
        if image.get("status") == "ran":
            total.update((node(image) or {}).get(key) or {})
    return total


def stage_table(report: dict) -> list[dict]:
    """One row per stage: owner shares of the stage's unit, from this run."""
    images = {k: v for k, v in report["images"].items() if v.get("status") == "ran"}
    agg = total_of(images, lambda i: i["aggregate"])
    persisted_images = {k: v for k, v in images.items() if v.get("persisted_prototypes")}
    pagg = total_of(persisted_images, lambda i: i["persisted_prototypes"]["aggregate"])
    switch = total_of(images, lambda i: i["switch"])
    facts = Counter()
    for image in images.values():
        for table in ("xrefs_by_provenance", "data_definitions_by_provenance", "flow_overrides_by_provenance"):
            for key, count in image["facts"][table].items():
                facts[key.split("|")[0]] += count
    cpp_facts = sum(count for provenance, count in facts.items() if provenance in CPP_PROVENANCE)
    all_facts = sum(facts.values())
    phases = Counter()
    for image in images.values():
        for name, seconds in (image["import"].get("phases") or {}).items():
            if name not in PHASE_SKIP and name in PHASE_OWNER:
                phases[PHASE_OWNER[name][0]] += seconds
    producers = merged(images, lambda i: i["facts"], "sample_functions_by_producer")
    instructions = total_of(images, lambda i: i["facts"]).get("sample_instructions", 0)
    coverage_cells = (report.get("coverage") or {}).get("by_stage") or {}

    def executed(stage, owner):
        return (coverage_cells.get(stage) or {}).get(owner, {}).get("executed")

    rows = []

    def row(stage, unit, basis, owners, detail):
        rows.append({"stage": stage, "unit": unit, "basis": basis,
                     "owners": {owner: owners.get(owner) for owner in OWNERS}, "detail": detail})

    row("load", "bytes, symbols and types handed to the decompiler", "code",
        {"rust_first_party": 1.0},
        "provider.rs answers every query the C++ makes for bytes, symbols, types and flow facts; "
        f"C++ loader lines executed: {executed('load', 'cpp_vendored')} vendored (storage of what it is given)")
    row("discovery", "stored analysis facts (xrefs, data definitions, flow overrides) by provenance", "run",
        {"rust_first_party": share(all_facts - cpp_facts, all_facts), "cpp_ours": share(cpp_facts, all_facts)},
        f"sampled functions by producer: {dict(producers)} (all Rust passes); constant-propagation facts are "
        f"computed in process (native_runtime/propagation); facts owned by C++: {cpp_facts} of "
        f"{all_facts}. Import time in C++-owned phases: "
        f"{pct(phases['cpp'], phases['cpp'] + phases['rust'])}")
    row("flow (import walk)", "flow queries during the discovery walk", "code",
        {"rust_third_party": 1.0},
        "discovery.rs walks with the in-process kuna-sleigh decoder (`SleighFlow`), and the constant "
        "propagation follows flow over the same decoder (native_runtime/propagation/graph.rs, FlowInfo); no C++ "
        "answers flow during import")
    row("flow (decompile)", "instructions followed into the function body and its blocks", "code + coverage",
        {"cpp_vendored": 1.0},
        "the decompiler's own FlowInfo (flow.cc) builds the function's p-code and block graph on every decompile; "
        f"vendored flow lines executed {executed('flow', 'cpp_vendored')}")
    row("pcode_lift", "instructions lifted on the printed path", "run + code",
        {"cpp_vendored": 1.0},
        f"{instructions} instructions in the sampled functions are lifted by the decompiler's own SLEIGH "
        "(ghidra_opt, ROMWRIGHT_SLA). Rust-lifted p-code (kuna-sleigh) feeds value-set analysis, SJA, the type "
        "solver and the prototype job, never the printed text")
    row("switch_recovery", "dispatches in the stored import tables", "run",
        {"rust_first_party": share(switch["rust_vsa_dispatches"], switch["stored_dispatches"]),
         "cpp_vendored": share(switch["decompiler_dispatches"], switch["stored_dispatches"])},
        f"{int(switch['rust_vsa_dispatches'])} of {int(switch['stored_dispatches'])} dispatches "
        f"({pct(switch['rust_vsa_cases'], switch['stored_cases'])} of case edges) by Rust VSA; the rest by "
        "the decompiler path (a branch the decompiler-off import also stores is Rust's)")
    printed = int(agg["jump_tables_printed"])
    supplied = int(agg.get("printed_switch_confirmed", 0) + agg.get("printed_switch_applied", 0))
    row("switch_recovery (printed)", "switch tables the decompiler used when printing", "run",
        {"rust_first_party": share(switch["sample_printed_stored_rust_vsa"], printed),
         "cpp_vendored": share(printed - switch["sample_printed_stored_rust_vsa"], printed)},
        f"{printed} printed tables in {int(agg['functions'])} functions; the import's stored table was the "
        f"authority for {supplied} ({pct(supplied, printed)}): {int(agg.get('printed_switch_confirmed', 0))} "
        f"agreed with what jumptable.cc recovers again at decompile time, {int(agg.get('printed_switch_applied', 0))} "
        f"replaced it; {int(agg.get('printed_switch_none', 0))} had no stored table. Of the supplied tables "
        f"{int(switch['sample_printed_stored_rust_vsa'])} are Rust VSA's (the rest are the import's own decompiler "
        "pass, jumptable.cc at import time); jumptable.cc still derives the normalization, guards and case "
        f"values. Of the sample's {int(switch['sample_rust_vsa'])} Rust-recovered dispatches "
        f"{int(switch['sample_printed_as_switch_rust_vsa'])} also printed as a switch")
    row("simplification", "final p-code operations", "run",
        {"rust_first_party": share(agg["edits"], agg["operations"]),
         "cpp_vendored": share(agg["operations"] - agg["edits"], agg["operations"])},
        f"{int(agg['edits'])} Rust edits ({int(agg['edits_additive_inverse'])} additive_inverse, "
        f"{int(agg['edits_canonical_helpers'])} canonical_helpers) over {int(agg['operations'])} operations; "
        f"{int(agg['functions_with_edits'])} of {int(agg['functions'])} functions have an edit")
    type_tokens = (agg.get("fragment_tokens_by_kind") or {}).get("type", 0)
    row("type_inference (default)", "printed type tokens", "run",
        {"rust_first_party": 0.0 if not agg.get("parameters_from_pass") else None,
         "cpp_vendored": 1.0 if not agg.get("parameters_from_pass") else None},
        f"{int(agg['fragment_tokens_by_kind'].get('type', 0))} type tokens; the default import stores no "
        "persisted prototype, so every printed type is Ghidra's. The Rust type solver still runs per "
        "function as an evidence pass whose classes only steer export-c's temporary and global names")
    if pagg.get("functions"):
        upgrades = pagg.get("inferred_slot_upgrades", 0)
        ptype_tokens = (pagg.get("fragment_tokens_by_kind") or {}).get("type", 0)
        row("type_inference (persisted prototypes)", "printed type tokens", "run",
            {"rust_first_party": share(upgrades, ptype_tokens),
             "cpp_vendored": share(ptype_tokens - upgrades, ptype_tokens)},
            f"{int(upgrades)} parameter types upgraded by the Rust merge (provenance `->` records) against "
            f"{int(ptype_tokens)} printed type tokens in {int(pagg['functions'])} functions on "
            f"{len(persisted_images)} images; upper bound, one printed token per upgraded slot")
    row("prototype (default)", "printed function prototypes; call sites", "run",
        {"rust_first_party": share(agg["functions_with_stored_prototype"], agg["functions"]),
         "cpp_vendored": share(agg["functions"] - agg["functions_with_stored_prototype"], agg["functions"])},
        f"{int(agg['functions_with_stored_prototype'])} of {int(agg['functions'])} printed functions had a "
        f"stored prototype; {int(agg['calls_with_stored_prototype'])} of {int(agg['calls'])} call sites name a "
        "callee with one (type-archive and SDK tables, Rust)")
    if pagg.get("functions"):
        recovered_by_rust = sum(count for source, count in (pagg.get("prototype_sources") or {}).items()
                                if "inferred-types" in source)
        stored = int(pagg["functions_with_stored_prototype"])
        row("prototype (persisted prototypes)", "printed function prototypes", "run",
            {"rust_first_party": share(recovered_by_rust, pagg["functions"]),
             "cpp_vendored": share(pagg["functions"] - recovered_by_rust, pagg["functions"])},
            f"{stored} of {int(pagg['functions'])} printed functions had a stored prototype and "
            f"{int(pagg['calls_with_stored_prototype'])} of {int(pagg['calls'])} call sites name a callee with one, "
            "all persisted by Rust. Share here is who decided the signature: a stored row whose provenance is "
            "`native-decompiler prototype recovery` alone is Ghidra's recovery stored by Rust; Rust decided "
            "the rows that also carry `inferred-types` (at least one slot changed). Source mix: "
            f"{dict(pagg.get('prototype_sources') or {})}")
    row("structuring", "control-flow constructs in the printed tree", "run",
        {"rust_first_party": share(agg["printed_constructs"] - agg["kept_constructs"], agg["printed_constructs"]),
         "cpp_vendored": share(agg["kept_constructs"], agg["printed_constructs"])},
        f"gotos {int(agg['gotos_ghidra'])} -> {int(agg['gotos_printed'])} and labels "
        f"{int(agg['labels_ghidra'])} -> {int(agg['labels_printed'])} after the Rust models; "
        f"{int(agg['restructured_functions'])} of {int(agg['functions'])} functions printed a Rust tree; "
        f"created {dict(agg.get('constructs_created_by_kind') or {})}; "
        f"IR `structure` cuts kept {int(agg['cuts_kept'])} of {int(agg['cuts_proposed'])}")
    rust_tokens = agg["block_layer_tokens"] + agg.get("rust_expression_tokens", 0)
    rust_statements = sum((agg.get("expressions_rust_by_kind") or {}).values())
    kept_statements = sum((agg.get("expressions_fragment_by_kind") or {}).values())
    row("printing", "visible text tokens", "run",
        {"rust_first_party": share(rust_tokens, agg["tokens"]),
         "cpp_vendored": share(agg["fragment_tokens"], agg["tokens"])},
        f"{int(agg['tokens'])} tokens: {int(agg['fragment_tokens'])} replayed from PrintC fragments "
        f"(by kind {dict(agg.get('fragment_tokens_by_kind') or {})}), {int(agg['block_layer_tokens'])} emitted by the "
        f"Rust block layer and {int(agg.get('rust_expression_tokens', 0))} by the Rust expression printer "
        f"(printc/render.rs, from the exported print trees; by kind {dict(agg.get('rust_expression_tokens_by_kind') or {})}); "
        f"{int(rust_statements)} expressions printed by Rust, {int(kept_statements)} kept PrintC's fragment "
        f"(by context.kind rust {dict(agg.get('expressions_rust_by_kind') or {})}, fragment "
        f"{dict(agg.get('expressions_fragment_by_kind') or {})}; why {dict(agg.get('expression_fallback_reasons') or {})}); "
        f"{int(agg['spacing_tokens'])} spacing tokens laid out by printc/pretty.rs, a Rust port "
        "of EmitPrettyPrint (algorithm third-party, code first-party)")
    row("postprocess", "identifiers in the export-c text", "run",
        {"rust_first_party": share(agg["renamed_identifiers"], agg["identifiers"]),
         "cpp_vendored": share(agg["identifiers"] - agg["renamed_identifiers"], agg["identifiers"])},
        f"{int(agg['renamed_identifiers'])} of {int(agg['identifiers'])} identifier tokens are `temp_*`/`sp*` "
        "names emit_m2c gave decompiler locals; the rest keep the name the decompiler printed")
    return rows


def headline(report: dict) -> dict:
    images = {k: v for k, v in report["images"].items() if v.get("status") == "ran"}
    agg = total_of(images, lambda i: i["aggregate"])
    counter = {name: total_of(images, lambda i, n=name: i["counterfactual"].get(n)) for name in
               ("rust-structuring-none", "ir-none", "rust-expressions-off", "either")}
    totals = (report.get("coverage") or {}).get("totals") or {}
    executed = {owner: (totals.get(owner) or {}).get("executed") for owner in OWNERS}
    known = [v for v in executed.values() if v is not None]
    return {
        "images_ran": len(images),
        "functions_printed": int(agg["functions"]),
        "printed_text_tokens_emitted_by_rust": share(agg["block_layer_tokens"] + agg.get("rust_expression_tokens", 0),
                                                     agg["tokens"]),
        "printed_text_tokens_emitted_by_rust_block_layer": share(agg["block_layer_tokens"], agg["tokens"]),
        "printed_text_tokens_emitted_by_rust_expressions": share(agg.get("rust_expression_tokens", 0), agg["tokens"]),
        "printed_text_tokens_replayed_from_cpp_fragments": share(agg["fragment_tokens"], agg["tokens"]),
        "printed_constructs_created_by_rust": share(agg["printed_constructs"] - agg["kept_constructs"],
                                                    agg["printed_constructs"]),
        "p_code_operations_edited_by_rust": share(agg["edits"], agg["operations"]),
        "functions_whose_text_changes_without_rust_components": share(
            counter["either"]["different"], counter["either"]["compared"]),
        "functions_changed_by_rust_structuring": share(
            counter["rust-structuring-none"]["different"], counter["rust-structuring-none"]["compared"]),
        "functions_changed_by_rust_ir_passes": share(
            counter["ir-none"]["different"], counter["ir-none"]["compared"]),
        "functions_changed_by_rust_expression_printer": share(
            counter["rust-expressions-off"]["different"], counter["rust-expressions-off"]["compared"])
        if counter["rust-expressions-off"]["compared"] else None,
        "executed_lines": executed,
        "executed_lines_rust_share": share(
            (executed["rust_first_party"] or 0) + (executed["rust_third_party"] or 0),
            sum(known)) if known else None,
        "executed_lines_first_party_rust_share": share(executed["rust_first_party"] or 0, sum(known))
        if known else None,
    }


def fmt(value) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{100 * value:.1f}%"
    return str(value)


def markdown(report: dict) -> str:
    out = ["# Ownership: Rust against the vendored Ghidra C++", "",
           f"Generated {report['generated']} by `benchmarks/ownership.py`; definitions, stage attribution and "
           "reproduction in [docs/ownership.md](../../docs/ownership.md). "
           f"Tree: `{json.dumps(report['tree'])}`; tools fingerprint `{report.get('tools')}`; "
           f"n = {report['n']} functions per image, seed {report['seed']}.", ""]
    head = report.get("headline") or {}
    out += ["## Headline", "", "| measure | value |", "|---|---|"]
    labels = {
        "functions_printed": "functions printed (all images)",
        "printed_text_tokens_emitted_by_rust": "printed text tokens emitted by Rust (block layer and expression printer)",
        "printed_text_tokens_replayed_from_cpp_fragments": "printed text tokens replayed from PrintC's fragments (C++)",
        "printed_text_tokens_emitted_by_rust_block_layer": "printed text tokens emitted by the Rust block layer",
        "printed_text_tokens_emitted_by_rust_expressions": "printed text tokens of expressions the Rust expression printer emitted",
        "printed_constructs_created_by_rust": "printed control-flow constructs created by the Rust structuring models",
        "p_code_operations_edited_by_rust": "final p-code operations edited by a Rust transform",
        "functions_whose_text_changes_without_rust_components": "functions whose text changes with Rust structuring and IR passes off",
        "functions_changed_by_rust_structuring": "functions changed by Rust structuring alone",
        "functions_changed_by_rust_ir_passes": "functions changed by the Rust IR passes alone",
        "functions_changed_by_rust_expression_printer": "functions whose text differs with the Rust expression printer off (PrintC's fragments instead)",
        "executed_lines_first_party_rust_share": "executed code lines that are first-party Rust",
        "executed_lines_rust_share": "executed code lines that are Rust (first-party + kuna-sleigh)",
    }
    for key, label in labels.items():
        out.append(f"| {label} | {fmt(head.get(key))} |")
    out += [""]
    out += ["## Stage attribution", "",
            "Shares are of the stage's own unit; the rows do not add up to one number "
            "(docs/ownership.md explains why).", "",
            "| stage | unit | basis | Rust (first-party) | Rust (kuna-sleigh) | C++ ours | C++ vendored | detail |",
            "|---|---|---|---|---|---|---|---|"]
    for item in report.get("stage_table") or []:
        owners = item["owners"]
        out.append(f"| {item['stage']} | {item['unit']} | {item['basis']} | "
                   f"{fmt(owners['rust_first_party'])} | {fmt(owners['rust_third_party'])} | "
                   f"{fmt(owners['cpp_ours'])} | {fmt(owners['cpp_vendored'])} | {item['detail']} |")
    out += [""]
    out += ["## Per image", "",
            "| image | printed / sampled | tokens | Rust-emitted | constructs created by Rust | gotos Ghidra -> printed | "
            "edits / operations | printed differently without Rust: either (structuring alone / IR passes alone) | stored dispatches Rust-VSA |",
            "|---|---|---|---|---|---|---|---|---|"]
    for name, image in report["images"].items():
        if image.get("status") != "ran":
            out.append(f"| {name} | {image.get('status')}: {image.get('reason', '')} | | | | | | | |")
            continue
        a = image["aggregate"]
        c = image["counterfactual"]
        s = image["switch"]
        out.append(
            f"| {name} | {a['functions']} / {image['default_pass']['sampled']} | {a['tokens']} | "
            f"{pct(a['block_layer_tokens'] + a.get('rust_expression_tokens', 0), a['tokens'])} | "
            f"{pct(a['printed_constructs'] - a['kept_constructs'], a['printed_constructs'])} | "
            f"{a['gotos_ghidra']} -> {a['gotos_printed']} | {a['edits']} / {a['operations']} | "
            f"{c['either']['different']}/{c['either']['compared']} "
            f"({c['rust-structuring-none']['different']} / {c['ir-none']['different']}) | "
            f"{s['rust_vsa_dispatches']} of {s['stored_dispatches']} |")
    out += [""]
    out += ["## Persisted-prototype profile", "",
            "The same worker over the projects the research runs left after `infer_prototypes` "
            "(inferred-types merge on). `origin` names the project copied.", "",
            "| image | origin tools | job seconds | printed | stored prototype | calls with stored prototype | "
            "parameter types upgraded by Rust | prototype sources |", "|---|---|---|---|---|---|---|---|"]
    for name, image in report["images"].items():
        p = image.get("persisted_prototypes") if image.get("status") == "ran" else None
        if not p:
            out.append(f"| {name} | none usable | | | | | | |")
            continue
        a = p["aggregate"]
        out.append(f"| {name} | {p['origin_tools']} | {p['job']['seconds']} | {a['functions']} / {p['sampled']} | "
                   f"{a['functions_with_stored_prototype']} | {a['calls_with_stored_prototype']} / {a['calls']} | "
                   f"{a.get('inferred_slot_upgrades', 0)} | {a.get('prototype_sources')} |")
    out += [""]
    cov = report.get("coverage") or {}
    if cov.get("by_stage"):
        out += ["## Executed code lines by stage and owner", "",
                "Lines with a nonzero count in the merged profiles of the default run (imports, the default "
                "decompile pass and the persisted-prototype pass; ablation passes are not merged). "
                "Each cell is executed/executable lines of the files the stage owns. Executable counts come from "
                "two different coverage mappings (clang for C++, rustc for Rust: lines with at least one "
                "mapped region), so compare executed lines, not percentages, across languages; a Rust "
                "line is a statement-sized unit, a C++ line often is too, but neither is a weighted "
                "work measure.", "",
                "| stage | " + " | ".join(OWNERS) + " |", "|---|" + "---|" * len(OWNERS)]
        for stage, _ in STAGES:
            cells = cov["by_stage"][stage]
            out.append(f"| {stage} | " + " | ".join(
                f"{cells[owner]['executed']}/{cells[owner]['executable']}" for owner in OWNERS) + " |")
        totals = cov["totals"]
        out.append("| **total** | " + " | ".join(
            f"{totals[owner]['executed']}/{totals[owner]['executable']}" for owner in OWNERS) + " |")
        out += ["", f"Other crates and std linked into the Rust binaries: "
                f"{cov['rust_dependencies']['executed']}/{cov['rust_dependencies']['executable']} (not an owner).", ""]
        out += ["Most-executed vendored C++ files (lines executed, stage):", ""]
        for relative, lines, stage in cov["top_executed_vendored"][:15]:
            out.append(f"- `{relative}`: {lines} ({stage})")
        out += ["", "Most-executed first-party Rust files:", ""]
        for relative, lines, stage in cov["top_executed_first_party"][:15]:
            out.append(f"- `{relative}`: {lines} ({stage})")
        if cov.get("unassigned_rust_files"):
            out += ["", "Executed first-party Rust files no stage rule claims (counted under `host`): "
                    + ", ".join(f"`{k}` {v}" for k, v in cov["unassigned_rust_files"].items())]
        out += [""]
    inv = report["inventory"]
    out += ["## Lines of code", "", f"Unit: {inv['unit']}.", "",
            "| owner | code lines | executable (coverage map) | executed in this run |", "|---|---|---|---|"]
    totals = cov.get("totals") or {}
    static = {"rust_first_party": inv["rust_first_party"]["code"],
              "rust_third_party": list(inv["rust_third_party_vendored"].values())[0],
              "cpp_ours": inv["cpp_ours"]["code"], "cpp_vendored": inv["cpp_vendored"]["code"]}
    for owner in OWNERS:
        t = totals.get(owner, {})
        out.append(f"| {owner} | {static[owner]} | {t.get('executable', 'n/a')} | {t.get('executed', 'n/a')} |")
    out += ["", "First-party Rust by crate (code / test): " + ", ".join(
        f"{name} {value['code']}/{value['test']}" for name, value in inv["rust_first_party"]["crates"].items()),
        "", f"Ours C++: {inv['cpp_ours']['patch_added_code']} patch-added code lines in "
        f"{inv['cpp_ours']['patch_files']} files, {inv['cpp_ours']['headers_code']} in native/romwright_*.hh. "
        f"Vendored: {inv['cpp_vendored']['note']}.", ""]
    return "\n".join(out) + "\n"


def compare_reports(paths: list[Path]) -> str:
    """Markdown before -> after tables over earlier reports (oldest first) from the
    reports' own numbers: the headline lenses, every stage row's owner shares and
    the line inventory. A cell a report does not have (a lens added later, a
    coverage block a run did not take) reads `n/a`."""
    reports = [json.loads(path.read_text()) for path in paths]
    names = [path.stem for path in paths]
    out = ["| report | generated | tools | images | functions printed |", "|---|---|---|---|---|"]
    for name, report in zip(names, reports):
        head = report.get("headline") or {}
        out.append(f"| {name} | {report['generated']} | `{report.get('tools')}` | {len(report['images'])} | "
                   f"{head.get('functions_printed')} |")
    out += ["", "| lens | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for key in ("printed_text_tokens_emitted_by_rust", "printed_text_tokens_emitted_by_rust_block_layer",
                "printed_text_tokens_emitted_by_rust_expressions",
                "printed_text_tokens_replayed_from_cpp_fragments", "printed_constructs_created_by_rust",
                "p_code_operations_edited_by_rust", "functions_whose_text_changes_without_rust_components",
                "functions_changed_by_rust_structuring", "functions_changed_by_rust_ir_passes",
                "functions_changed_by_rust_expression_printer", "executed_lines_first_party_rust_share",
                "executed_lines_rust_share"):
        out.append(f"| {key} | " + " | ".join(
            fmt((report.get("headline") or {}).get(key)) for report in reports) + " |")
    for owner in OWNERS:
        out.append(f"| executed lines, {owner} | " + " | ".join(
            str(((report.get("headline") or {}).get("executed_lines") or {}).get(owner)) for report in reports) + " |")
    stages = []
    for report in reports:
        for row in report.get("stage_table") or []:
            if row["stage"] not in stages:
                stages.append(row["stage"])
    out += ["", "| stage (owner share) | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for stage in stages:
        cells = []
        for report in reports:
            row = next((r for r in report.get("stage_table") or [] if r["stage"] == stage), None)
            cells.append("n/a" if row is None else ", ".join(
                f"{owner.replace('rust_first_party', 'Rust').replace('rust_third_party', 'kuna').replace('cpp_ours', 'ours C++').replace('cpp_vendored', 'vendored')} {fmt(share)}"
                for owner, share in row["owners"].items() if share is not None) or "n/a")
        out.append(f"| {stage} | " + " | ".join(cells) + " |")
    out += ["", "| inventory (code lines) | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    rows = [
        ("first-party Rust, all crates", lambda i: i["rust_first_party"]["code"]),
        ("first-party Rust, pipeline crates", lambda i: i["rust_first_party"].get("pipeline_code")),
        ("kuna-sleigh", lambda i: list(i["rust_third_party_vendored"].values())[0]),
        ("our C++ (patch added + headers)", lambda i: i["cpp_ours"]["code"]),
        ("  patch-added lines", lambda i: i["cpp_ours"]["patch_added_code"]),
        ("  native/romwright_*.hh", lambda i: i["cpp_ours"]["headers_code"]),
        ("vendored C++", lambda i: i["cpp_vendored"]["code"]),
    ]
    for label, get in rows:
        out.append(f"| {label} | " + " | ".join(str(get(report["inventory"])) for report in reports) + " |")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=Path.home() / "ventris-corpus" / "extracted")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "romwright" / "ownership")
    parser.add_argument("--target-dir", type=Path, help="cargo target dir of the instrumented build")
    parser.add_argument("--cov-build", type=Path, help="ownership_build_coverage.sh output dir")
    parser.add_argument("--source-root", type=Path, help="repository root the Rust binaries were built from "
                        "(default: this checkout)")
    parser.add_argument("--out", type=Path, default=ROOT / "benchmarks" / "reports" / "ownership.json")
    parser.add_argument("--images", default="", help="comma-separated image ids (default: all present)")
    parser.add_argument("-n", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20261006)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--shards", type=int, default=0,
                        help="ROMWRIGHT_CONSOLE_SHARDS for every run; 0 keeps the build's default (4). "
                             "Other counts change what the import finds on mixed-ISA images")
    parser.add_argument("--prototype-cache", action="append", type=Path, default=None,
                        help="research cache root with infer_prototypes projects (repeatable; later wins)")
    parser.add_argument("--inventory-only", action="store_true", help="print the static line counts and stop")
    parser.add_argument("--compare", nargs="+", type=Path, metavar="REPORT",
                        help="print before -> after tables over these reports (oldest first) and stop")
    parser.add_argument("--report-only", action="store_true",
                        help="rebuild the report from the cached image results and the profiles; runs nothing")
    parser.add_argument("--carry-from", type=Path,
                        help="with --report-only: take the tree, tools, inventory and coverage blocks from this "
                             "earlier report instead of recomputing them, for when the binaries and profiles that "
                             "produced the cached results have since been rebuilt (merging old profiles into a "
                             "rebuilt binary would drop the functions that changed)")
    args = parser.parse_args()
    if args.compare:
        print(compare_reports(args.compare), end="")
        return 0

    patch = parse_patch(ROOT / "native" / "ghidra-opt-sleigh.patch")
    report = {"schema": SCHEMA, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "tree": source_digest(), "n": args.n, "seed": args.seed, "inventory": inventory(),
              "stages": [{"stage": s, "scope": d} for s, d in STAGES], "images": {}}
    if args.inventory_only:
        print(json.dumps(report["inventory"], indent=1))
        return 0
    if not (args.target_dir and args.cov_build):
        parser.error("--target-dir and --cov-build are required (see the docstring)")
    args.prototype_caches = ([(path.name, path) for path in args.prototype_cache]
                             if args.prototype_cache else PROTOTYPE_CACHES)
    args.cache.mkdir(parents=True, exist_ok=True)
    args.profraw = args.cache / "profraw"
    args.profraw_ablation = args.cache / "profraw-ablation"
    args.profraw.mkdir(exist_ok=True)
    args.profraw_ablation.mkdir(exist_ok=True)
    os.environ["CARGO_TARGET_DIR"] = str(args.target_dir)
    CR = load_module("console_research", ROOT / "benchmarks" / "console_research.py")
    CR.GHIDRA_OPT = args.cov_build / "ghidra_opt"
    tools = CR.Tools(args.target_dir)
    # The lane count shapes what is found on images that mix instruction sets
    # (RuntimeConfig::console_shards, default 4, the reference measurements'
    # count): set only when --shards asks, and then it owns the differences.
    if args.shards:
        base_env = tools.env
        tools.env = lambda extra: base_env({"ROMWRIGHT_CONSOLE_SHARDS": str(args.shards), **extra})
    report["tools"] = tools.fingerprint
    carried = None
    if args.carry_from:
        if not args.report_only:
            parser.error("--carry-from needs --report-only")
        carried = json.loads(args.carry_from.read_text())
        for block in ("tree", "tools", "inventory", "coverage"):
            report[block] = carried[block]
        report["carried_from"] = {"file": args.carry_from.name, "generated": carried["generated"],
                                  "blocks": ["tree", "tools", "inventory", "coverage"]}
    results_tools = report["tools"]
    wanted = {item for item in args.images.split(",") if item}
    for spec in CR.IMAGES:
        if wanted and spec["id"] not in wanted:
            continue
        if args.report_only:
            hits = sorted((args.cache / "results" / results_tools).glob(f"{spec['id']}-{args.n}-{args.seed}.json"))
            cached = CR.read_json(hits[0]) if hits else None
            report["images"][spec["id"]] = cached["image"] if cached else {"status": "missing"}
            continue
        try:
            report["images"][spec["id"]] = run_image(args, CR, tools, spec, args.cache)
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
            report["images"][spec["id"]] = {"status": "error", "reason": str(error)[-1000:]}
            log(f"{spec['id']}: ERROR {str(error)[-300:]}")
    if carried is None:
        report["coverage"] = coverage(args, patch)
    report["stage_table"] = stage_table(report)
    report["headline"] = headline(report)
    CR.write_json(args.out, report)
    args.out.with_suffix(".md").write_text(markdown(report))
    log(f"report {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
