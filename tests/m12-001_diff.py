#!/usr/bin/env python3
"""m12-001: whole-program structural diff, scored against symbol truth.

Three claims, each with its own ground truth and none of them using a fact
the matcher is allowed to see:

1. `twins` -- every corpus row against its own unstripped twin. Same build,
   so the true correspondence is address identity. The matcher never reads
   the target's names (the target is the stripped binary) and never reads an
   address as evidence, so a perfect score here means the structural facts
   alone identify identical code.

2. `optimisation` -- each architecture's `plain_o0` against its `plain_o2`
   (and `plain_pie`): the same source, compiled differently. The true
   correspondence is name identity, taken from the target's unstripped twin,
   which the matcher never opens.

3. `modules` -- two programs of the same game that share engine code, each
   with its own symbol table, when they are present on the machine. Real
   scale, real divergence, names on both sides.

Every row reports precision and recall of the matching and the share of the
names it would port that are the name the target's own symbols hold. That
last number is the one an analyst feels.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"

# Acceptance. The twin rows are the ceiling and must stay exact; the
# cross-optimisation rows are the measured floor of the current matcher.
THRESHOLDS = {
    # Identical code, identified by structure alone: exact, or a fact the
    # import records is wrong.
    "twins.precision": 1.0,
    "twins.recall": 1.0,
    "twins.name_precision": 1.0,
    # An anchor is an identification, not a guess: a key unique on both
    # sides. One wrong anchor means the key does not identify what it claims
    # to, so this is 1.0 everywhere and is not a tunable floor.
    "anchor.precision": 1.0,
    # Same source, different codegen (measured 1.0 / 0.864 / 0.954).
    "optimisation.precision": 0.95,
    "optimisation.recall": 0.75,
    "optimisation.name_precision": 0.90,
    # Two programs sharing engine code, target stripped (measured 0.966 /
    # 0.947 / 0.927). The gap from 1.0 is entirely in the propagated class:
    # anchors are exact, alignment is 0.878 on this pair.
    "modules.precision": 0.95,
    "modules.recall": 0.93,
    "modules.name_precision": 0.90,
}

# Indexed mode: run index-semantics before diffing so the semantic
# term participates, and floor the propagated (alignment) class on
# optimisation rows. An instruction-class histogram was tried here and
# reverted -- ablation proved it moves nothing the semantic term does
# not already move (see STATUS m12-002 entry). The module-pair bar
# (0.93) applies when those rows are present; their inputs are absent
# from this machine.
# Propagated precision only: recall over truth measures how often the
# alignment class fires (0.02 here -- most pairs resolve through anchors
# or semantic evidence), not how right it is when it fires. Precision is
# the claim, and like anchors it must be sound: measured 9/9.
# Per kind: the corpus optimisation rows hold 1.0 on a small judged
# set, the module pair holds the brief's 0.93. Pooling them would let
# either kind hide behind the other's volume.
INDEX_THRESHOLDS = {
    "optimisation.precision": 1.0,
    "modules.precision": 0.93,
}

# Evidence classes that identify a function outright rather than scoring it.
ANCHOR_EVIDENCE = {"body", "shape", "import", "name", "string", "profile", "global"}

# Expected twins misses, address-keyed and tied to STATUS.md recorded
# deficits -- visible in the row, never silent. A bare recall dip would
# let the next scatter hide behind it; an exemption that stops firing
# fails loudly so it gets removed instead of going stale.
# mipsel_cpp_o2 0x20940 (_Z7do_worki): a false entry at 0x20980 truncates
# the stripped body (64B vs 108B), so no body anchor fires. Seed-order
# dependent walk outcome, deterministic run to run.
# Live suspect for the false entry's origin: the prologue pattern pass
# (`addiu sp,sp,-0x18` is a MIPS prologue match), not the flow walk --
# unlabelled pattern starts used to report as `flow`, hiding this.
EXPECTED_TWINS_MISSES = {"mipsel_cpp_o2": {"0x20940"}}

# Expected module misses, address-keyed by row like the twins set, with
# the same stale-exemption tripwire. Both modules link at 0x80680000, so
# same-address coincidences across them carry no identity: 0x8069eb58 is
# one stub slot with crossed spellings (EXI2_Poll vs Hu_IsStub, same
# bytes both directions), and 0x8069ffd4/0x8068312c are identical-shape
# twins (EXIDeselect vs CheckDVDError) 40 bytes apart. Name truth splits
# what neither bytes nor shape can.
EXPECTED_MODULES_MISSES = {
    "base->boot": {"0x8069eb58", "0x8069ffd4"},
    "boot->base": {"0x8069eb58"},
}

GENERATED = ("FUN_", "LAB_", "SUB_", "DAT_", "UNK_", "EXT_", "OFF_", "PTR_")


def is_generated(name: str) -> bool:
    bare = name.removeprefix("thunk_")
    return any(bare.startswith(prefix) for prefix in GENERATED)


def index_program(binary: Path, project: Path, name: str) -> None:
    result = subprocess.run(
        [str(CLI), "index-semantics", str(binary), name, "--project", str(project)],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"index {binary.name} failed: {result.stderr[-800:]}")


def import_program(binary: Path, project: Path, name: str) -> None:
    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    result = subprocess.run(
        [str(CLI), "import", str(binary), "--project", str(project), "--name", name],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"import {binary.name} failed: {result.stderr[-800:]}")


def function_names(project: Path, program: str) -> dict[int, str]:
    connection = sqlite3.connect(project / "project.sqlite")
    rows = connection.execute(
        "SELECT f.entry, f.name FROM functions f JOIN programs p ON p.id = f.program_id"
        " WHERE p.name = ?",
        (program,),
    ).fetchall()
    return {int(entry, 16): name for entry, name in rows}


def diff(target_project: Path, target: str, reference_project: Path, reference: str) -> dict:
    result = subprocess.run(
        [
            str(CLI),
            "diff",
            target,
            "--project",
            str(target_project),
            "--reference",
            str(reference_project),
            "--reference-name",
            reference,
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"diff failed: {result.stderr[-800:]}")
    return json.loads(result.stdout)


def score(
    identifier: str,
    kind: str,
    report: dict,
    truth: dict[int, int],
    target_names: dict[int, str],
) -> dict:
    matched = {
        (row["reference"]["offset"], row["target"]["offset"]) for row in report["matches"]
    }
    judged = [(left, right) for left, right in matched if left in truth]
    correct = [1 for left, right in judged if truth[left] == right]
    # Per evidence class, so a regression names the rule that caused it.
    classes: dict[str, list[int]] = {}
    for row in report["matches"]:
        left, right = row["reference"]["offset"], row["target"]["offset"]
        if left not in truth:
            continue
        bucket = classes.setdefault(row["evidence"], [0, 0])
        bucket[0] += 1
        bucket[1] += int(truth[left] == right)
    ported = {row["entry"]["offset"]: row["name"] for row in report["names"]}
    # Only names the target's own symbols can judge count towards precision:
    # a name ported onto a function the twin never named is unjudged, not
    # wrong.
    judged_names = {
        address: name
        for address, name in ported.items()
        if not is_generated(target_names.get(address, "FUN_0"))
    }
    agree = sum(
        1 for address, name in judged_names.items() if target_names.get(address) == name
    )
    return {
        "id": identifier,
        "kind": kind,
        "truth": len(truth),
        "matched": len(matched),
        "judged": len(judged),
        "correct": len(correct),
        "precision": round(len(correct) / len(judged), 4) if judged else 0.0,
        "recall": round(len(correct) / len(truth), 4) if truth else 0.0,
        "ported": len(ported),
        "ported_judged": len(judged_names),
        "ported_correct": agree,
        "name_precision": round(agree / len(judged_names), 4) if judged_names else 0.0,
        "evidence": {
            name: {"judged": judged_count, "correct": correct_count}
            for name, (judged_count, correct_count) in sorted(classes.items())
        },
        "anchors": report["anchors"],
        "reference_functions": report["reference_functions"],
        "target_functions": report["target_functions"],
    }


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


def corpus_rows(corpus: Path, work: Path, index: bool = False) -> tuple[list[dict], list[dict]]:
    manifest = json.loads((corpus / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"] if entry.get("status") == "ok"]
    imported: dict[str, tuple[Path, dict[int, str], Path, dict[int, str]]] = {}
    twins: list[dict] = []
    for entry in entries:
        identifier = f"{entry['architecture']}_{entry['variant']}"
        reference_project = work / f"{identifier}-twin"
        target_project = work / f"{identifier}-stripped"
        import_program(corpus / entry["unstripped_twin"], reference_project, "reference")
        import_program(corpus / entry["binary"], target_project, "target")
        if index:
            index_program(corpus / entry["unstripped_twin"], reference_project, "reference")
            index_program(corpus / entry["binary"], target_project, "target")
        reference_names = function_names(reference_project, "reference")
        target_recovered = function_names(target_project, "target")
        imported[identifier] = (
            reference_project,
            reference_names,
            target_project,
            target_recovered,
        )
        # Same build: address identity, over what both sides recovered.
        truth = {
            address: address for address in reference_names if address in target_recovered
        }
        expected = EXPECTED_TWINS_MISSES.get(identifier, set())
        truth = {a: b for a, b in truth.items() if f"{a:#x}" not in expected}
        report = diff(target_project, "target", reference_project, "reference")
        row = score(identifier, "twins", report, truth, reference_names)
        row["expected_misses"] = sorted(expected)
        correct_pairs = {
            (m["reference"]["offset"], m["target"]["offset"])
            for m in report["matches"]
        }
        row["stale_exemptions"] = sorted(
            a for a in expected if (int(a, 16), int(a, 16)) in correct_pairs)
        twins.append(row)
        print(json.dumps(row), flush=True)

    # Cross-optimisation: same source, different codegen.
    optimisation: list[dict] = []
    architectures = sorted({entry["architecture"] for entry in entries})
    for architecture in architectures:
        pairs = [
            (f"{architecture}_plain_o0", f"{architecture}_plain_o2"),
            (f"{architecture}_plain_o2", f"{architecture}_plain_o0"),
            (f"{architecture}_plain_o0", f"{architecture}_plain_pie"),
        ]
        for left, right in pairs:
            if left not in imported or right not in imported:
                continue
            _, reference_names, _, _ = imported[left]
            reference_project = imported[left][0]
            target_project, target_named, _, target_recovered = (
                imported[right][2],
                imported[right][1],
                imported[right][2],
                imported[right][3],
            )
            truth = name_truth(reference_names, target_named, target_recovered)
            if not truth:
                continue
            report = diff(target_project, "target", reference_project, "reference")
            row = score(f"{left}->{right}", "optimisation", report, truth, target_named)
            optimisation.append(row)
            print(json.dumps(row), flush=True)
    return twins, optimisation


def module_rows(paths: list[Path], work: Path, index: bool = False) -> list[dict]:
    loaded = {}
    for path in paths:
        stripped = work / f"{path.stem}.stripped"
        strip = shutil.which("llvm-strip") or shutil.which("strip")
        if strip is None:
            return []
        subprocess.run(
            [strip, "--strip-all", "-o", str(stripped), str(path)],
            check=True,
            capture_output=True,
        )
        named_project = work / f"{path.stem}-named"
        stripped_project = work / f"{path.stem}-stripped"
        import_program(path, named_project, path.stem)
        import_program(stripped, stripped_project, path.stem)
        if index:
            index_program(path, named_project, path.stem)
            index_program(stripped, stripped_project, path.stem)
        loaded[path.stem] = (
            named_project,
            function_names(named_project, path.stem),
            stripped_project,
            function_names(stripped_project, path.stem),
        )
    rows = []
    for left in loaded:
        for right in loaded:
            if left == right:
                continue
            reference_project, reference_names, _, _ = loaded[left]
            _, target_named, target_project, target_recovered = loaded[right]
            truth = name_truth(reference_names, target_named, target_recovered)
            if not truth:
                continue
            expected = EXPECTED_MODULES_MISSES.get(f"{left}->{right}", set())
            full_truth = dict(truth)
            truth = {
                a: b for a, b in truth.items() if f"{a:#x}" not in expected
            }
            report = diff(target_project, right, reference_project, left)
            row = score(f"{left}->{right}", "modules", report, truth, target_named)
            row["expected_misses"] = sorted(expected)
            correct_pairs = {
                (m["reference"]["offset"], m["target"]["offset"])
                for m in report["matches"]
            }
            row["stale_exemptions"] = sorted(
                a for a in expected
                if (int(a, 16), full_truth.get(int(a, 16), -1)) in correct_pairs)
            rows.append(row)
            print(json.dumps(row), flush=True)
    return rows


def aggregate(rows: list[dict], kind: str) -> dict:
    subset = [row for row in rows if row["kind"] == kind]
    if not subset:
        return {}
    totals = {
        "rows": len(subset),
        "judged": sum(row["judged"] for row in subset),
        "correct": sum(row["correct"] for row in subset),
        "truth": sum(row["truth"] for row in subset),
        "ported_judged": sum(row["ported_judged"] for row in subset),
        "ported_correct": sum(row["ported_correct"] for row in subset),
    }
    # Pooled, not averaged: a row with three functions must not weigh as much
    # as one with four hundred.
    totals["precision"] = round(totals["correct"] / max(totals["judged"], 1), 4)
    totals["recall"] = round(totals["correct"] / max(totals["truth"], 1), 4)
    totals["name_precision"] = round(
        totals["ported_correct"] / max(totals["ported_judged"], 1), 4
    )
    return totals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--modules", type=Path, nargs="*", default=[])
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--index", action="store_true",
                        help="index semantics before diffing; records propagated class")
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True
    )

    twins, optimisation = corpus_rows(arguments.corpus_dir, arguments.work,
                                          index=arguments.index)
    present = [path for path in arguments.modules if path.is_file()]
    modules = module_rows(present, arguments.work,
                          index=arguments.index) if present else []
    rows = twins + optimisation + modules

    measured = {}
    for kind in ("twins", "optimisation", "modules"):
        totals = aggregate(rows, kind)
        if totals:
            measured[kind] = totals
    # Anchors pooled over every row, and every class named separately.
    classes: dict[str, list[int]] = {}
    for row in rows:
        for name, counts in row["evidence"].items():
            bucket = classes.setdefault(name, [0, 0])
            bucket[0] += counts["judged"]
            bucket[1] += counts["correct"]
    anchor_judged = sum(
        counts[0] for name, counts in classes.items() if name in ANCHOR_EVIDENCE
    )
    anchor_correct = sum(
        counts[1] for name, counts in classes.items() if name in ANCHOR_EVIDENCE
    )
    measured["anchor"] = {
        "judged": anchor_judged,
        "correct": anchor_correct,
        "precision": round(anchor_correct / max(anchor_judged, 1), 4),
    }
    measured["classes"] = {
        name: {
            "judged": counts[0],
            "correct": counts[1],
            "precision": round(counts[1] / max(counts[0], 1), 4),
        }
        for name, counts in sorted(classes.items())
    }
    if arguments.index:
        propagated = {"judged": 0, "correct": 0, "truth": 0}
        for row in optimisation + modules:
            bucket = row["evidence"].get("alignment", {"judged": 0, "correct": 0})
            propagated["judged"] += bucket["judged"]
            propagated["correct"] += bucket["correct"]
            propagated["truth"] += row["truth"]
        propagated["precision"] = round(
            propagated["correct"] / max(propagated["judged"], 1), 4)
        propagated["recall"] = round(
            propagated["correct"] / max(propagated["truth"], 1), 4)
        measured["propagated"] = propagated

    failures = []
    if arguments.index and "propagated" in measured:
        by_kind: dict[str, dict[str, int]] = {}
        for row in optimisation + modules:
            bucket = by_kind.setdefault(row["kind"], {"judged": 0, "correct": 0})
            cell = row["evidence"].get("alignment", {"judged": 0, "correct": 0})
            bucket["judged"] += cell["judged"]
            bucket["correct"] += cell["correct"]
        measured["propagated_by_kind"] = {
            kind: {
                "judged": counts["judged"],
                "correct": counts["correct"],
                "precision": round(counts["correct"] / max(counts["judged"], 1), 4),
            }
            for kind, counts in sorted(by_kind.items())
        }
        for key, threshold in INDEX_THRESHOLDS.items():
            kind, _ = key.split(".")
            value = measured["propagated_by_kind"].get(kind, {}).get("precision", 0.0)
            if value < threshold:
                failures.append(f"indexed propagated {key} {value} < {threshold}")
    for row in twins + optimisation + modules:
        if row.get("stale_exemptions"):
            failures.append(
                f"{row['id']}: expected misses {row['stale_exemptions']} now match"
                " -- remove the exemption")
    for key, threshold in THRESHOLDS.items():
        kind, metric = key.split(".")
        if kind not in measured:
            if kind == "modules":
                continue  # scored only where the game modules are present
            failures.append(f"{kind} rows missing")
            continue
        value = measured[kind][metric]
        if value < threshold:
            failures.append(f"{key} {value} < {threshold}")

    report = {
        "id": "m12-001",
        "milestone": "M12",
        "indexed": arguments.index,
        "criterion": "whole-program structural diff, scored against symbol truth",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
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
    summary = "; ".join(
        f"{kind}: precision {totals['precision']}, recall {totals['recall']},"
        f" names {totals['name_precision']} over {totals['rows']} rows"
        for kind, totals in measured.items()
        if "rows" in totals
    )
    summary += (
        f"; anchors {measured['anchor']['precision']}"
        f" over {measured['anchor']['judged']}"
    )
    print(f"m12-001: PASS ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
