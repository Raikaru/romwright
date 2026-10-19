#!/usr/bin/env python3
"""m10-004: multi-image projects as one milestone, enumerated from the dispatch.

Three gates exist (`m10-001`..`m10-003`) and each writes its own report.
Nothing states the milestone-level claim, and nothing notices when a method
that takes a `program` appears with no per-program isolation behind it.

The methods are enumerated from `crates/romwright-api/src/lib.rs` -- every dispatch
arm that reads `params.program` -- and then driven against a project holding
two images:

  * **reads answer for the named program only**: every read is called on the
    two-image project and on a project holding that image alone, and the two
    answers must be identical, in both directions;
  * **writes touch the named program only**: every write is applied to the
    first image, and every read for the second image must answer exactly as it
    did before, while the write's own effect must be visible on the first;
  * **nothing is silently undriven**: a program-taking method that is neither
    read nor written here fails the gate unless it is excused with a recorded
    reason, and an excuse that no longer holds fails too;
  * **the claim**: each of the three gates must exist, pass, and carry the
    metric it claims.

Usage:
    python3 tests/m10-004_multi_image_milestone.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "benchmarks" / "reports"
DISPATCH = ROOT / "crates/romwright-api/src/lib.rs"
ELF = ROOT / "tests/fixtures-src/tiny_bin"
PE = ROOT / "tests/fixtures-src/tiny_pe32.exe"
ARM = re.compile(r'\n            "([a-z_0-9]+)" =>')
CLAIMS = {
    "m10-001": ["images.programs", "images.reads_compared",
                "images.overlapping_address"],
    "m10-002": ["images.follow_facts_compared", "images.ui_programs",
                "images.ui_switch_functions"],
    "m10-003": ["edits.reads_compared", "edits.revision_after_second_import"],
}
# A program-taking method driven by neither sweep needs a reason here. The
# gate fails when a method is missing from every list, and when a reason below
# stops holding.
# `import_native` needs no excuse: it names a program with `name`, not
# `program`, so the scan below does not claim it.
# The three below are the worker-job arms: they read `program` through
# `job_request`, which `infer_nonreturning` and `infer_prototypes` share and
# which the write sweep drives through those two.
EXCUSED: dict[str, str] = {
    "job_submit": "enqueues one of decompile_doc, infer_prototypes, "
                  "infer_nonreturning, match_source or matching and answers a "
                  "job id; the first three run through the same job_request "
                  "resolution as the direct methods driven here, the last two "
                  "are the two entries below",
    "matching_run": "runs a trial, search or calibration, which needs a compiler "
                    "recipe, objdiff and a matching workspace set up first; "
                    "tests/matching_regressions.py drives it against a real "
                    "compiler, and this job installs no objdiff to do the same",
    "match_source": "compiles a source file with a recipe's compiler and diffs "
                    "it against the program with objdiff; no objdiff is "
                    "installed here and no other gate calls it",
}


class Api:
    """One `romwright-api` process bound to one project."""

    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(ROOT / "target/release/romwright-api"), "--project", str(project)],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.identity = 0

    def call(self, method: str, **params) -> dict:
        self.identity += 1
        self.process.stdin.write(json.dumps(
            {"api": 2, "id": self.identity, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"the service closed on {method}"
        return json.loads(line)

    def result(self, method: str, **params):
        answer = self.call(method, **params)
        assert "result" in answer, f"{method} failed: {answer}"
        return answer["result"]

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=60)


def program_taking_methods() -> list[str]:
    """Every dispatch arm that reads `params.program`.

    The dispatch is two matches: `dispatch` answers `decompile_doc` with raw
    text and hands every other method to `dispatch_tree`. An arm reads the
    program directly (`string_param(params, "program")`) or through
    `self.job_request(params)`, which resolves it for the worker jobs.
    """
    source = DISPATCH.read_text(encoding="utf-8")
    body = source[source.index("    fn dispatch(&self"):
                  source.index("DispatchError::UnknownMethod(method")]
    arms = re.split(r'\n(?=            "[a-z_0-9]+" =>)', "\n" + body)
    taking = []
    for arm in arms:
        head = re.match(r'\s*"([a-z_0-9]+)" =>', arm)
        if head and ('params, "program"' in arm or "self.job_request(params)" in arm):
            taking.append(head.group(1))
    assert len(taking) > 20, f"the dispatch scan found only {taking}"
    return taking


def imported(binary: Path, name: str, project: Path) -> None:
    result = subprocess.run(
        [str(ROOT / "target/release/romwright-cli"), "import", str(binary),
         "--name", name, "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"import of {binary.name} as {name} failed: {result.stderr.strip()}")


def address_of(api: Api, program: str) -> dict:
    """The first function entry, so address-taking reads name real code."""
    functions = sorted(api.result("functions", program=program),
                       key=lambda row: row["entry"]["offset"])
    assert functions, f"{program} has no functions to address"
    return functions[0]["entry"]


def read_recipes(entry: dict) -> dict[str, dict]:
    return {
        "open": {},
        "classes": {},
        "signature_matches": {},
        "functions": {},
        "functions_page": {"offset": 0, "limit": 8},
        "function_at": {"address": entry["offset"]},
        "function_evidence": {"address": entry},
        "matching_runs": {"after": 0, "limit": 16},
        "matching_workspace": {"operation": {"operation": "list", "after": 0, "limit": 16}},
        "symbols": {},
        "symbols_page": {"offset": 0, "limit": 8},
        "xrefs": {"address": entry},
        "xrefs_page": {"address": entry, "offset": 0, "limit": 8},
        "comments": {},
        "datatypes": {},
        "strings": {},
        "search": {"term": "a", "limit": 16},
        "function_graph": {},
        "memory_regions": {},
        "return_behaviors": {},
        "thunks": {},
        "bookmarks": {},
        "patches": {},
        "type_defs": {},
        "type_fields": {},
        "prototypes": {},
        "stack_variables": {},
        "type_graph": {},
        "trace_events": {"since": 0, "limit": 16},
        "collab_ops": {},
        "events_since": {"since": 0},
    }


def write_recipes(binary: Path, entry: dict) -> list[dict]:
    """Writes in order, each with the read that must show its effect.

    `observe` receives the reads for the written program and returns True when
    the write is visible. A write that is inert on this fixture carries a
    reason instead, and the gate fails if it stops being inert.
    """
    # A rename op carries the rename it replays, so applying it is a real
    # write and not an empty acknowledgement.
    operation = {"op_id": "m10-004-op", "actor": "gate", "lamport": 1,
                 "kind": "rename",
                 "payload": json.dumps({"address": entry, "name": "m10_004_replayed"}),
                 "applied": False, "provenance": "analyst"}
    return [
        {"method": "recover_classes", "params": {"binary": str(binary)},
         "inert": "the fixture declares no RTTI or typeinfo, so no class is "
                  "recovered for either image",
         "empty": ["classes"]},
        {"method": "apply_signatures", "params": {"binary": str(binary)},
         "inert": "no signature database is passed, so no match is stored",
         "empty": ["signature_matches"]},
        {"method": "infer_nonreturning", "params": {"binary": str(binary)},
         "observe": lambda reads: bool(reads["return_behaviors"])},
        {"method": "infer_prototypes",
         "params": {"binary": str(binary), "budget_ms": 30000},
         "observe": lambda reads: bool(reads["prototypes"])},
        {"method": "analyse_function",
         "params": {"binary": str(binary), "address": entry},
         "inert": "the demand walk answers with its own report (state, "
                  "instructions, calls); no read here lists what it stored, and "
                  "the isolation check above covers that it moves nothing in "
                  "the other image",
         "empty": []},
        {"method": "decompile_doc",
         "params": {"binary": str(binary), "address": entry},
         "inert": "decompiling reads the image and returns a document; it "
                  "stores no fact of its own",
         "empty": []},
        {"method": "propagate_type_links", "params": {},
         "inert": "the fixture carries no type links to propagate",
         "empty": ["type_defs", "type_fields"]},
        {"method": "set_bookmark",
         "params": {"bookmark": {"address": entry, "label": "m10-004",
                                 "comment": "written by the milestone gate"}},
         "observe": lambda reads: any(row["label"] == "m10-004"
                                      for row in reads["bookmarks"])},
        {"method": "set_patch",
         "params": {"patch": {"address": entry, "original": [0x90],
                              "patched": [0xcc], "enabled": True}},
         "observe": lambda reads: any(row["patched"] == [0xcc]
                                      for row in reads["patches"])},
        {"method": "append_trace_event",
         "params": {"event": {"sequence": 1, "at": "2026-01-01T00:00:00Z",
                              "thread": "main", "address": entry,
                              "kind": "step", "payload": "{}",
                              "provenance": "analyst"}},
         "observe": lambda reads: bool(reads["trace_events"])},
        {"method": "append_collab_op", "params": {"operation": operation},
         "observe": lambda reads: any(row["op_id"] == "m10-004-op"
                                      for row in reads["collab_ops"])},
        {"method": "apply_collab_op", "params": {"op_id": "m10-004-op"},
         "observe": lambda reads: (
             any(row["op_id"] == "m10-004-op" and row["applied"]
                 for row in reads["collab_ops"])
             and any(row["name"] == "m10_004_replayed"
                     for row in reads["functions"]))},
        {"method": "rename", "params": {"address": entry, "name": "m10_004_named"},
         "observe": lambda reads: any(row["name"] == "m10_004_named"
                                      for row in reads["functions"])},
        {"method": "comment", "params": {"address": entry, "text": "m10-004 comment"},
         "observe": lambda reads: any(row["text"] == "m10-004 comment"
                                      for row in reads["comments"])},
        {"method": "undo", "params": {},
         "observe": lambda reads: (
             not any(row["text"] == "m10-004 comment" for row in reads["comments"])
             and any(row["name"] == "m10_004_named" for row in reads["functions"]))},
    ]


def snapshot(api: Api, program: str, recipes: dict[str, dict]) -> dict:
    return {method: api.result(method, program=program, **params)
            for method, params in recipes.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                    "-p", "romwright-api"], cwd=ROOT, check=True)

    methods = program_taking_methods()
    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m10-004-") as directory:
        work = Path(directory)
        pe = work / PE.name
        shutil.copy2(PE, pe)
        subprocess.run(["llvm-strip", "--strip-all", str(pe)], check=True)
        images = {"tiny": ELF, "win": pe}

        both = work / "both"
        for name, binary in images.items():
            imported(binary, name, both)
        solo = {}
        for name, binary in images.items():
            solo[name] = work / f"solo-{name}"
            imported(binary, name, solo[name])

        shared = Api(both)
        alone = {name: Api(project) for name, project in solo.items()}
        try:
            entries = {name: address_of(shared, name) for name in images}
            recipes = {name: read_recipes(entries[name]) for name in images}
            driven = set(recipes["tiny"]) | {
                recipe["method"] for recipe in write_recipes(ELF, entries["tiny"])}
            undriven = sorted(set(methods) - driven - set(EXCUSED))
            assert not undriven, (
                f"these methods take a program and nothing here proves they "
                f"answer for one: {undriven}")
            stale = sorted(set(EXCUSED) - set(methods))
            assert not stale, f"these excuses name no dispatch arm: {stale}"

            # 1. Reads answer for the named program only.
            differing, discriminating, empty_both = [], [], []
            for name in images:
                for method, params in recipes[name].items():
                    beside = shared.result(method, program=name, **params)
                    only = alone[name].result(method, program=name, **params)
                    if beside != only:
                        differing.append(f"{name}.{method}")
            assert not differing, (
                f"these reads answered differently in a two-image project than "
                f"in a project holding that image alone: {differing}")
            for method in recipes["tiny"]:
                left = shared.result(method, program="tiny", **recipes["tiny"][method])
                right = shared.result(method, program="win", **recipes["win"][method])
                if left != right and (left or right):
                    discriminating.append(method)
                elif not left and not right:
                    empty_both.append(method)
            assert discriminating, "no read told the two images apart"
            findings["discriminating"] = sorted(discriminating)
            findings["empty_both"] = sorted(empty_both)

            # 2. Writes touch the named program only.
            inert_but_active, unseen = [], []
            for recipe in write_recipes(ELF, entries["tiny"]):
                method, params = recipe["method"], recipe["params"]
                before = snapshot(shared, "win", recipes["win"])
                shared.result(method, program="tiny", **params)
                after = snapshot(shared, "win", recipes["win"])
                moved = sorted(read for read in recipes["win"]
                               if before[read] != after[read])
                assert not moved, (
                    f"{method} on tiny changed win's {moved}")
                reads = snapshot(shared, "tiny", recipes["tiny"])
                if "observe" in recipe:
                    if not recipe["observe"](reads):
                        unseen.append(method)
                else:
                    stored = [read for read in recipe["empty"] if reads[read]]
                    if stored:
                        inert_but_active.append(f"{method} -> {stored}")
            assert not unseen, (
                f"these writes reported success and left no trace on the "
                f"program they named: {unseen}")
            assert not inert_but_active, (
                f"these writes are excused as inert but stored something: "
                f"{inert_but_active}")
            findings["writes"] = [recipe["method"]
                                  for recipe in write_recipes(ELF, entries["tiny"])]
            findings["inert"] = {recipe["method"]: recipe["inert"]
                                 for recipe in write_recipes(ELF, entries["tiny"])
                                 if "inert" in recipe}
            findings["reads_isolated"] = sum(len(recipe) for recipe in recipes.values())
        finally:
            shared.close()
            for api in alone.values():
                api.close()

    # 3. The three gates carry the claim.
    milestone, missing = {}, []
    for identifier, wanted in CLAIMS.items():
        path = REPORTS / f"{identifier}.json"
        if not path.is_file():
            missing.append(f"{identifier}: no report")
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        if not report.get("passed"):
            missing.append(f"{identifier}: report does not pass")
        held = {}
        for metric in wanted:
            if metric not in report.get("metrics", {}):
                missing.append(f"{identifier}: {metric} not measured")
            else:
                held[metric] = report["metrics"][metric]
        milestone[identifier] = held
    assert not missing, f"the milestone claim is unsupported: {missing}"

    reads = len(findings["discriminating"]) + len(findings["empty_both"])
    metrics = {
        "images.methods_program_scoped": len(methods),
        "images.methods_excused": len(EXCUSED),
        "images.reads_isolated": findings["reads_isolated"],
        "images.reads_discriminating": len(findings["discriminating"]),
        "images.writes_isolated": len(findings["writes"]),
        "images.writes_inert": len(findings["inert"]),
    }
    summary = (f"{len(methods)} methods take a program and every one is driven or "
               f"excused with a reason; {metrics['images.reads_isolated']} reads "
               f"answered identically beside another image and alone, "
               f"{metrics['images.reads_discriminating']} of {reads} telling the "
               f"images apart; {metrics['images.writes_isolated']} writes left the "
               f"other image byte-identical across every read while showing their "
               f"own effect; three gates carry the milestone claim")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m10-004",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "discriminating_reads": findings["discriminating"],
            "reads_equal_and_empty": findings["empty_both"],
            "writes_inert": findings["inert"],
            "methods_excused": EXCUSED,
            "milestone": milestone,
        }, indent=1) + "\n")
    print(f"m10-004: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
