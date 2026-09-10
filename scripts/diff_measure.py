#!/usr/bin/env python3
"""Measures the structural diff against ground truth.

Two experiment kinds, both with real ground truth and neither using the
addresses the matcher is not allowed to see:

`twins`   -- a stripped corpus binary against its unstripped twin. The same
             build, so the true correspondence is address identity. This
             measures the ceiling: whatever the matcher cannot do here it
             cannot do anywhere.
`modules` -- two different programs that share code, each with its own
             symbol table (the Agent Under Fire modules). The true
             correspondence is name identity, and the addresses differ, so
             this measures the case the tool is actually for.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sqlite3
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"


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


def names(project: Path, program: str) -> dict[int, str]:
    connection = sqlite3.connect(project / "project.sqlite")
    rows = connection.execute(
        "SELECT f.entry, f.name FROM functions f JOIN programs p ON p.id = f.program_id"
        " WHERE p.name = ?",
        (program,),
    ).fetchall()
    return {int(entry, 16): name for entry, name in rows}


MATCHER = "nap"


def run_diff(target_project: Path, target: str, reference_project: Path, reference: str) -> dict:
    started = time.time()
    result = subprocess.run(
        [
            str(CLI),
            "diff",
            target,
            "--matcher",
            MATCHER,
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
    report = json.loads(result.stdout)
    report["wall_s"] = round(time.time() - started, 3)
    return report


def score(report: dict, truth: dict[int, int]) -> dict:
    """Precision and recall of the matching against `truth` (reference entry
    -> target entry). Only pairs whose reference side is in the ground truth
    are judged: a match onto a function the truth says nothing about is
    neither right nor wrong."""
    matched = {
        (row["reference"]["offset"], row["target"]["offset"]) for row in report["matches"]
    }
    judged = [(left, right) for left, right in matched if left in truth]
    correct = [(left, right) for left, right in judged if truth[left] == right]
    precision = len(correct) / len(judged) if judged else 0.0
    recall = len(correct) / len(truth) if truth else 0.0
    return {
        "truth": len(truth),
        "matched": len(matched),
        "judged": len(judged),
        "correct": len(correct),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "wall_s": report["wall_s"],
        "anchors": report["anchors"],
        "reference_functions": report["reference_functions"],
        "target_functions": report["target_functions"],
    }


def twins(corpus: Path, work: Path, rows: list[str] | None) -> list[dict]:
    manifest = json.loads((corpus / "manifest.json").read_text())
    out = []
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        identifier = f"{entry['architecture']}_{entry['variant']}"
        if rows and identifier not in rows:
            continue
        binary = corpus / entry["binary"]
        twin = corpus / entry["unstripped_twin"]
        reference_project = work / f"{identifier}-ref"
        target_project = work / f"{identifier}-tgt"
        import_program(twin, reference_project, "reference")
        import_program(binary, target_project, "target")
        # Same build: the true correspondence is address identity, over the
        # functions both sides actually recovered.
        left = names(reference_project, "reference")
        right = names(target_project, "target")
        truth = {entry_address: entry_address for entry_address in left if entry_address in right}
        report = run_diff(target_project, "target", reference_project, "reference")
        row = {"id": identifier, "kind": "twins", **score(report, truth)}
        ported = {name["entry"]["offset"]: name["name"] for name in report["names"]}
        agree = sum(1 for address, name in ported.items() if left.get(address) == name)
        row["ported"] = len(ported)
        row["ported_correct"] = agree
        row["name_precision"] = round(agree / len(ported), 4) if ported else 0.0
        out.append(row)
        print(json.dumps(row), flush=True)
    return out


def modules(paths: list[Path], work: Path) -> list[dict]:
    """Ports names from each program onto every other program, stripped.

    The target is stripped before import, so the matcher sees no name on that
    side and cannot match by one; the ground truth comes from the target's
    unstripped twin, which the matcher never reads. This is the workflow the
    tool is for: carry a build's names onto an image that has none.
    """
    loaded = {}
    for path in paths:
        stripped = work / f"{path.stem}.stripped"
        subprocess.run(
            ["llvm-strip", "--strip-all", "-o", str(stripped), str(path)],
            check=True,
            capture_output=True,
        )
        named_project = work / f"{path.stem}-named"
        stripped_project = work / f"{path.stem}-stripped"
        import_program(path, named_project, path.stem)
        import_program(stripped, stripped_project, path.stem)
        loaded[path.stem] = (
            named_project,
            names(named_project, path.stem),
            stripped_project,
            names(stripped_project, path.stem),
        )
    out = []
    stems = list(loaded)
    for left_stem in stems:
        for right_stem in stems:
            if left_stem == right_stem:
                continue
            left_project, left_names, _, _ = loaded[left_stem]
            _, right_named, right_project, right_stripped = loaded[right_stem]
            # Truth: a name the reference holds, at the address the target's
            # own symbols put it -- and only where the stripped import
            # recovered a function at that address to match.
            by_name_target: dict[str, list[int]] = {}
            for address, name in right_named.items():
                by_name_target.setdefault(name, []).append(address)
            truth = {}
            for address, name in left_names.items():
                if is_generated(name):
                    continue
                candidates = [
                    candidate
                    for candidate in by_name_target.get(name, [])
                    if candidate in right_stripped
                ]
                if len(candidates) == 1:
                    truth[address] = candidates[0]
            report = run_diff(right_project, right_stem, left_project, left_stem)
            row = {
                "id": f"{left_stem}->{right_stem}",
                "kind": "modules",
                **score(report, truth),
            }
            ported = {name["entry"]["offset"]: name["name"] for name in report["names"]}
            judged = {
                address: name
                for address, name in ported.items()
                if not is_generated(right_named.get(address, "FUN_0"))
            }
            agree = sum(
                1 for address, name in judged.items() if right_named.get(address) == name
            )
            row["ported"] = len(ported)
            row["ported_judged"] = len(judged)
            row["ported_correct"] = agree
            row["name_precision"] = round(agree / len(judged), 4) if judged else 0.0
            out.append(row)
            print(json.dumps(row), flush=True)
    return out


def is_generated(name: str) -> bool:
    bare = name.removeprefix("thunk_")
    return any(
        bare.startswith(prefix)
        for prefix in ("FUN_", "LAB_", "SUB_", "DAT_", "UNK_", "EXT_", "OFF_", "PTR_")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path)
    parser.add_argument("--modules", type=Path, nargs="*", default=[])
    parser.add_argument("--rows", nargs="*")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--matcher", default="nap", choices=["nap", "greedy"])
    arguments = parser.parse_args()
    global MATCHER
    MATCHER = arguments.matcher
    work = arguments.work or Path(tempfile.mkdtemp(prefix="diff-measure-"))
    work.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    if arguments.corpus_dir:
        rows += twins(arguments.corpus_dir, work, arguments.rows)
    if arguments.modules:
        rows += modules(list(arguments.modules), work)
    summary = {
        "rows": rows,
        "median_precision": sorted(row["precision"] for row in rows)[len(rows) // 2]
        if rows
        else 0.0,
        "median_recall": sorted(row["recall"] for row in rows)[len(rows) // 2]
        if rows
        else 0.0,
    }
    print(json.dumps(summary["median_precision"]), json.dumps(summary["median_recall"]))
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
