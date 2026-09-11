#!/usr/bin/env python3
"""m18-001: BSim-style semantic matching over p-code data-flow.

Claim: hashing normalised p-code features of a function's data-flow lets
two builds of the same source match where relocation churn defeats the
shape anchors, as an additional evidence class that never loses a match
it does not replace.

What is normalised away, and why: opcode identity is kept (the
translator's canonical names carry no encoding detail); operand kinds
(constant / register / unique / RAM / stack) and varnode sizes are kept
while register numbers and offsets are dropped (a rebuild reallocates
registers and reloads at different addresses); each operation also keeps
the opcodes producing its inputs to depth two (the computation's shape,
not its schedule). A constant is kept by value only when small
(<= 0xfff: zeroing, structure offsets, small masks); anything larger is
an address that moves between builds and is abstracted away.

The semantic term only ever raises. A low similarity is the expected
state of two builds the optimiser rewrote differently, so blending it
into the content mean would dilute structural scores that already clear
the floor -- measured on the many.c pair below, where a 0.53 similarity
pushed a 0.9052 structural score under the commit rule and cost a
correct `main` match. Only similarities at or above the match floor
join the mean; anything below leaves the structural score untouched
(unit test `low_similarity_leaves_the_structural_score_untouched` pins
this). The pass takes mutual-best pairs at or above the same floor.

Honest limit, measured: many.c is 400 near-duplicate functions
(`fn_N(x) = x+N*3`) that differ by one small constant. True O0/O2 pairs
score a median 0.56 while sibling false pairs score up to 0.63 -- the
order is inverted, so no floor or mutual-best rule can match them and
the class abstains there. That abstention is correct behaviour; the gate
holds it (lost must be 0) rather than asking the class to do the
impossible.

Pairs, both same-source:

* `many`: `tests/corpus-src/many.c` built `-O0` and `-O2 -fno-inline`
  (409 functions a side). Same source at different optimisation levels;
  the class abstains on the duplicates and must lose nothing.
* `pie`: corpus `x86_64_plain_o0` against `x86_64_plain_pie`. Same
  source, different link; relocation churn breaks the shape anchors (3
  anchors where the o2 pair has 11) and the semantic class fires: 3/3
  correct, gaining `__do_global_dtors_aux` the structural run misses.

Ground truth: symbol tables the matcher never opens -- the unstripped
o2 twin for both pairs. A reference entry maps to the target entry
holding the same name when that name is unique and the stripped import
recovered it.

Thresholds, set from what was measured (see
`benchmarks/reports/m18-001.json`):

* `many.precision` 1.0, `pie.precision` 1.0 -- measured 1.0 under both
  settings on both pairs. Any false match is a bug, not noise.
* `many.recall` 0.02 -- measured 0.0220 (9/409) under both settings.
  Recall is not the claim on a corpus of 400 near-duplicates; the floor
  sits just below measured to catch collapse and nothing else.
* `pie.recall` 0.80 -- measured 0.875 with the class, 0.75 without.
  The floor sits between the two: it holds the gain.
* No-loss rule (the hard gate): on every pair, the correct matches the
  semantic-off run finds must all survive the semantic-on run. A class
  that costs a single true match anywhere fails, however the floors
  look.
* Gain rule: correct matches found only by the semantic-on run must be
  greater than zero on at least one pair. A class that fires nowhere
  and changes nothing is decoration; the pie pair is where it proves
  otherwise (currently +1: `__do_global_dtors_aux`).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import os
import platform
import shutil
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"
MANY_C = ROOT / "tests" / "corpus-src" / "many.c"

# Thresholds with the measured reason in the module docstring.
THRESHOLDS = {
    "many.precision": 1.0,
    "many.recall": 0.02,
    "pie.precision": 1.0,
    "pie.recall": 0.80,
}

GENERATED = ("FUN_", "LAB_", "SUB_", "DAT_", "UNK_", "EXT_", "OFF_", "PTR_")


def is_generated(name: str) -> bool:
    bare = name.removeprefix("thunk_")
    return any(bare.startswith(prefix) for prefix in GENERATED)


def run(arguments: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        [str(CLI), *arguments],
        capture_output=True,
        text=True,
        env=environment,
    )
    if result.returncode:
        raise ValueError(f"{' '.join(arguments)} failed: {result.stderr[-800:]}")
    return result.stdout


def build_many(work: Path) -> tuple[Path, Path, Path]:
    """Compiles the many.c pair: -O0 reference, -O2 target and its
    unstripped twin for truth. Needs a C compiler and objcopy, the same
    tools that build the corpus."""
    if not MANY_C.is_file():
        raise ValueError(f"missing {MANY_C}")
    if shutil.which("gcc") is None or shutil.which("objcopy") is None:
        raise ValueError("m18-001 needs gcc and objcopy to build its many.c pair")
    work.mkdir(parents=True, exist_ok=True)
    many_o0 = work / "many_o0"
    many_o2_unstripped = work / "many_o2.unstripped"
    many_o2 = work / "many_o2"
    subprocess.run(
        ["gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-o", str(many_o0), str(MANY_C)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["gcc", "-O2", "-fno-inline", "-g", "-fno-pie", "-no-pie",
         "-o", str(many_o2_unstripped), str(MANY_C)],
        check=True,
        capture_output=True,
    )
    shutil.copy(many_o2_unstripped, many_o2)
    subprocess.run(
        ["objcopy", "--strip-debug", "--strip-all", str(many_o2)],
        check=True,
        capture_output=True,
    )
    return many_o0, many_o2, many_o2_unstripped


def import_program(binary: Path, project: Path, name: str, environment: dict[str, str]) -> None:
    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    run(["import", str(binary), "--project", str(project), "--name", name], environment)


def index_semantics(binary: Path, project: Path, name: str, environment: dict[str, str]) -> int:
    out = run(
        ["index-semantics", str(binary), name, "--project", str(project)],
        environment,
    )
    return int(out.strip().split()[1])


def function_names(project: Path, program: str) -> dict[int, str]:
    connection = sqlite3.connect(project / "project.sqlite")
    rows = connection.execute(
        "SELECT f.entry, f.name FROM functions f JOIN programs p ON p.id = f.program_id"
        " WHERE p.name = ?",
        (program,),
    ).fetchall()
    return {int(entry, 16): name for entry, name in rows}


def signature_coverage(project: Path, program: str) -> tuple[int, int]:
    connection = sqlite3.connect(project / "project.sqlite")
    rows = connection.execute(
        "SELECT COUNT(*) FROM semantic_signatures ss"
        " JOIN programs p ON p.id = ss.program_id WHERE p.name = ?",
        (program,),
    ).fetchone()
    total = connection.execute(
        "SELECT COUNT(*) FROM functions f JOIN programs p ON p.id = f.program_id"
        " WHERE p.name = ?",
        (program,),
    ).fetchone()[0]
    return (rows[0] or 0, total)


def diff(
    target_project: Path,
    target: str,
    reference_project: Path,
    reference: str,
    semantic: bool,
    environment: dict[str, str],
) -> dict:
    arguments = [
        "diff", target,
        "--project", str(target_project),
        "--reference", str(reference_project),
        "--reference-name", reference,
        "--json",
    ]
    if not semantic:
        arguments.append("--no-semantic")
    return json.loads(run(arguments, environment))


def name_truth(
    reference_names: dict[int, str],
    target_named: dict[int, str],
    target_recovered: dict[int, str],
) -> dict[int, int]:
    """Reference entry -> target entry, by the name both symbol tables hold.

    A name the target holds at two addresses proves nothing about which one
    is meant, and a name at an address the stripped import did not recover as
    a function cannot be matched at all; both are left out.
    """
    by_name: dict[str, list[int]] = {}
    for address, name in target_named.items():
        by_name.setdefault(name, []).append(address)
    truth = {}
    for address, name in reference_names.items():
        if is_generated(name):
            continue
        candidates = [
            candidate for candidate in by_name.get(name, []) if candidate in target_recovered
        ]
        if len(candidates) == 1:
            truth[address] = candidates[0]
    return truth


def score(
    identifier: str,
    kind: str,
    setting: str,
    report: dict,
    truth: dict[int, int],
    reference_names: dict[int, str],
) -> dict:
    matched = {
        (row["reference"]["offset"], row["target"]["offset"]) for row in report["matches"]
    }
    judged = [(left, right) for left, right in matched if left in truth]
    correct = sorted(left for left, right in judged if truth[left] == right)
    classes: dict[str, list[int]] = {}
    for row in report["matches"]:
        left, right = row["reference"]["offset"], row["target"]["offset"]
        if left not in truth:
            continue
        bucket = classes.setdefault(row["evidence"], [0, 0])
        bucket[0] += 1
        bucket[1] += int(truth[left] == right)
    return {
        "id": identifier,
        "kind": kind,
        "setting": setting,
        "truth": len(truth),
        "matched": len(matched),
        "judged": len(judged),
        "correct": len(correct),
        "correct_names": sorted(reference_names[left] for left in correct),
        "correct_refs": sorted(f"{left:08x}" for left in correct),
        "precision": round(len(correct) / len(judged), 4) if judged else 0.0,
        "recall": round(len(correct) / len(truth), 4) if truth else 0.0,
        "evidence": {
            name: {"judged": judged_count, "correct": correct_count}
            for name, (judged_count, correct_count) in sorted(classes.items())
        },
        "anchors": report["anchors"],
        "reference_functions": report["reference_functions"],
        "target_functions": report["target_functions"],
    }


def score_pair(
    identifier: str,
    kind: str,
    reference_binary: Path,
    target_binary: Path,
    named_binary: Path,
    work: Path,
    environment: dict[str, str],
    rows: list[dict],
) -> tuple[dict, dict]:
    reference_project = work / f"{identifier}-reference"
    target_project = work / f"{identifier}-stripped"
    named_project = work / f"{identifier}-named"
    import_program(reference_binary, reference_project, "reference", environment)
    import_program(target_binary, target_project, "target", environment)
    import_program(named_binary, named_project, "named", environment)
    reference_names = function_names(reference_project, "reference")
    target_recovered = function_names(target_project, "target")
    target_named = function_names(named_project, "named")
    truth = name_truth(reference_names, target_named, target_recovered)
    if not truth:
        raise ValueError(f"{identifier}: no truth")
    indexed_reference = index_semantics(reference_binary, reference_project, "reference", environment)
    indexed_target = index_semantics(target_binary, target_project, "target", environment)
    covered_reference, total_reference = signature_coverage(reference_project, "reference")
    covered_target, total_target = signature_coverage(target_project, "target")
    scored: dict[str, dict] = {}
    for setting, semantic in (("with", True), ("without", False)):
        report = diff(target_project, "target", reference_project, "reference", semantic, environment)
        row = score(identifier, kind, setting, report, truth, reference_names)
        row["indexed_reference"] = indexed_reference
        row["indexed_target"] = indexed_target
        row["coverage_reference"] = [covered_reference, total_reference]
        row["coverage_target"] = [covered_target, total_target]
        rows.append(row)
        scored[setting] = row
        print(json.dumps(row), flush=True)
    return scored["with"], scored["without"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault("VENTRIS_CONSOLE", str(ROOT / "native/build/decomp_native"))
    environment["VENTRIS_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)

    rows: list[dict] = []
    failures: list[str] = []
    gained_somewhere = False

    many_o0, many_o2, many_o2_unstripped = build_many(arguments.work / "many-src")
    for identifier, kind, binaries in [
        ("many", "many", (many_o0, many_o2, many_o2_unstripped)),
        ("pie", "pie", (
            arguments.corpus_dir / "x86_64_plain_o0.unstripped",
            arguments.corpus_dir / "x86_64_plain_pie.bin",
            arguments.corpus_dir / "x86_64_plain_pie.unstripped",
        )),
    ]:
        for path in binaries:
            if not path.is_file():
                failures.append(f"{identifier}: missing input {path}")
        if any(failure.startswith(identifier) for failure in failures):
            continue
        with_row, without_row = score_pair(
            identifier, kind, *binaries, arguments.work, environment, rows,
        )
        correct_with = set(with_row["correct_refs"])
        correct_without = set(without_row["correct_refs"])
        lost = sorted(correct_without - correct_with)
        gained = sorted(correct_with - correct_without)
        with_row["gained_refs"] = gained
        without_row["lost_refs"] = lost
        if lost:
            failures.append(f"{identifier}: semantic run lost correct matches {lost}")
        if gained:
            gained_somewhere = True
        # Floors hold the shipped configuration (semantic on). The off
        # run is the baseline the no-loss and gain rules compare against,
        # and on pie it is expected to sit lower.
        for metric in ("precision", "recall"):
            key = f"{kind}.{metric}"
            threshold = THRESHOLDS[key]
            if with_row[metric] < threshold:
                failures.append(f"{identifier} with {key} {with_row[metric]} < {threshold}")

    if not gained_somewhere and not failures:
        failures.append("no pair gained a correct match from the semantic class")

    semantic_rows = [row for row in rows if row["setting"] == "with"]
    semantic_judged = sum(row["evidence"].get("semantic", {}).get("judged", 0) for row in semantic_rows)
    semantic_correct = sum(row["evidence"].get("semantic", {}).get("correct", 0) for row in semantic_rows)
    measured = {
        "semantic": {
            "judged": semantic_judged,
            "correct": semantic_correct,
            "precision": round(semantic_correct / semantic_judged, 4) if semantic_judged else 1.0,
        },
    }

    report = {
        "id": "m18-001",
        "milestone": "M18",
        "criterion": "BSim-style semantic matching over p-code data-flow",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "thresholds": THRESHOLDS,
        "measured": measured,
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
    print(
        "m18-001: PASS (semantic class"
        f" {semantic_correct}/{semantic_judged} correct where it fires)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
