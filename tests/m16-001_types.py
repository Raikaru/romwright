#!/usr/bin/env python3
"""m16-001: parameter and return types inferred from p-code, scored against DWARF.

The inference is constraint-based (`romwright-core/src/types_infer.rs`): every
operation an operand takes part in is a constraint, constraints join over a
small lattice, and nothing is claimed where nothing constrained it. This
gate scores it against what the compiler said, using TIE's two measures
rather than one accuracy number, because the two failures are not the same
failure:

* **Conservativeness.** An answer is conservative when it is a *generalisation*
  of the truth: `num32` where the source said `int32` says less than the
  truth but nothing false. A type inference that is never wrong and often
  vague is usable; one that is confidently wrong is not.
* **Distance.** How far the answer sits from the truth, in lattice steps:
  0 exact, 1 a generalisation (sign or pointer-ness dropped), 2 unknown, and
  a wrong answer scores as wrong rather than as distance.

The subject is a fixture built here at two optimisation levels, not a corpus
row: the locked corpus is integer arithmetic, so its DWARF states `int32`
almost everywhere, and a constant that answered `int32` would score well on
it. `tests/fixtures-src/types_fixture.c` states each class at least twice,
signed and unsigned, through a pointer and behind an indirect call.

Argument storage is assigned by the compiler spec's own model, walking the
integer and float sequences separately, because the ABI does: parameter `i`
names a register only once the argument's class is known. The truth's class
picks the sequence; it never grades the answer.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from dwarf_types import extract  # noqa: E402

CLI = ROOT / "target/release/romwright-cli"
FIXTURE = ROOT / "tests/fixtures-src/types_fixture.c"
LEVELS = ("O0", "O2")
# Measured (gcc 16.2.1): exact 0.544, conservative 1.0, no contradiction out of
# 68. The thresholds sit just outside the old numbers so the gate catches a
# regression rather than pinning today's arithmetic.
#
# The inference tracks registers, not SSA values, so a register the body
# reuses as scratch stops carrying its entry identity and evidence from after
# the reuse can land on a parameter; value numbering is the next increment
# and not a threshold change. Four contradictions on this fixture's O2 build
# were three smaller faults of the same kind, none of them the compiler's
# (gcc 16 vectorises `mixed`'s loop and lays zeroing paths last): `xor eax,
# eax` read as an unsigned use and as the register's last write, `test r, r`
# read as an unsigned mask where the branch after it reads the sign, and a
# register's old `lea` address surviving a `mov` into it, which typed
# `length` as a pointer. Each is a unit test in `types_infer`.
WRONG_CEILING = 0.05
EXACT_FLOOR = 0.45
CONSERVATIVE_FLOOR = 0.90


def generalises(answer: str, truth: str) -> int | None:
    """Lattice distance from `truth` up to `answer`, or None if `answer`
    contradicts the truth."""
    if answer == truth:
        return 0
    if answer == "unknown":
        return 2
    width = None
    for prefix in ("int", "uint", "num", "float"):
        if truth.startswith(prefix) and truth[len(prefix):].isdigit():
            width = int(truth[len(prefix):])
            break
    # `numN` is "an N-bit value with no sign evidence": a generalisation of
    # every N-bit scalar, and of a pointer where N is the pointer width.
    # A wider answer of the same kind is a generalisation: an 8-bit value
    # lives in a 32-bit slot and the register is what the inference sees.
    # A *narrower* answer claims the value does not fit, which is wrong.
    if answer.startswith("num") and answer[3:].isdigit():
        answered = int(answer[3:])
        if width is not None and answered >= width:
            return 1
        if truth in ("ptr", "code") and answered == 64:
            return 1
        return None
    # `int-or-uintN` is an N-bit integer whose sign the evidence does not
    # settle (signed and unsigned uses of one value): the join of `intN` and
    # `uintN`, so a generalisation of either, as `numN` is of every N-bit
    # scalar. It claims an integer, so a float or a pointer contradicts it.
    if answer.startswith("int-or-uint") and answer[len("int-or-uint"):].isdigit():
        answered = int(answer[len("int-or-uint"):])
        if truth.startswith(("int", "uint")) and width is not None and answered >= width:
            return 1
        return None
    for prefix in ("int", "uint", "float"):
        if answer.startswith(prefix) and answer[len(prefix):].isdigit():
            if truth.startswith(prefix) and width is not None:
                return 1 if int(answer[len(prefix):]) >= width else None
            return None
    # A code pointer is a pointer; the reverse drops information the truth
    # has, which is still a generalisation.
    if answer == "ptr" and truth == "code":
        return 1
    if answer == "top":
        # Conflicting evidence claims nothing, so it cannot be wrong -- but
        # it is further away than silence, because it took a position and
        # then withdrew it.
        return 2
    return None


def assign_storage(truths: list[str], integers: list[str], floats: list[str]) -> list[str | None]:
    """The inferred class at the register each parameter is passed in."""
    answers: list[str | None] = []
    next_integer = 0
    next_float = 0
    for truth in truths:
        if truth.startswith("float"):
            answers.append(floats[next_float] if next_float < len(floats) else None)
            next_float += 1
        else:
            answers.append(integers[next_integer] if next_integer < len(integers) else None)
            next_integer += 1
    return answers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    environment = os.environ.copy()
    environment["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], cwd=ROOT, check=True)

    report = {
        "gate": "m16-001",
        "milestone": "M16",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                          text=True).strip(),
        "date": datetime.now(timezone.utc).date().isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "thresholds": {"exact": EXACT_FLOOR, "conservative": CONSERVATIVE_FLOOR,
                       "wrong": WRONG_CEILING},
        "levels": [],
    }
    failures = []
    totals = {"scored": 0, "exact": 0, "conservative": 0, "wrong": 0, "unknown": 0}
    wrong_examples = []

    with tempfile.TemporaryDirectory(prefix="m16-001-") as temporary:
        work = Path(temporary)
        for level in LEVELS:
            unstripped = work / f"types.{level}"
            stripped = work / f"types.{level}.stripped"
            build = subprocess.run(
                ["gcc", f"-{level}", "-g", "-fno-inline", "-fno-pie", "-no-pie",
                 "-o", str(unstripped), str(FIXTURE)],
                capture_output=True, text=True, timeout=300)
            if build.returncode:
                raise SystemExit(f"fixture build failed: {build.stderr[-500:]}")
            subprocess.run(["objcopy", "--strip-debug", str(unstripped), str(stripped)],
                           check=True, timeout=120)
            truth = extract(unstripped)["functions"]
            named = {entry: row for entry, row in truth.items() if row["name"]}
            project = work / f"project-{level}"
            subprocess.run([str(CLI), "import", str(stripped), "--project", str(project),
                            "--name", "types", "--no-analysis"],
                           cwd=ROOT, env=environment, check=True, capture_output=True,
                           timeout=600)
            result = subprocess.run(
                [str(CLI), "infer-types", str(stripped), "types", ",".join(named),
                 "--project", str(project), "--json"],
                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=600)
            if result.returncode:
                raise SystemExit(f"inference failed: {result.stderr[-500:]}")
            answers = {row["entry"]: row for row in
                       (json.loads(line) for line in result.stdout.splitlines()
                        if line.startswith("{"))}
            rows = []
            for entry, row in sorted(named.items()):
                answer = answers.get(entry)
                if answer is None:
                    failures.append(f"{level} {row['name']}: no answer")
                    continue
                storage = assign_storage(row["parameters"], answer["parameters"],
                                         answer["float_parameters"])
                scored = []
                for index, truth_class in enumerate(row["parameters"]):
                    if truth_class in ("unknown", "aggregate", "void"):
                        continue  # truth this measure does not state
                    given = storage[index] or "unknown"
                    distance = generalises(given, truth_class)
                    scored.append({"index": index, "truth": truth_class, "ours": given,
                                   "distance": distance})
                if row["returns"] not in ("unknown", "aggregate", "void"):
                    distance = generalises(answer["returns"], row["returns"])
                    scored.append({"index": "return", "truth": row["returns"],
                                   "ours": answer["returns"], "distance": distance})
                for item in scored:
                    totals["scored"] += 1
                    if item["distance"] is None:
                        totals["wrong"] += 1
                        if len(wrong_examples) < 10:
                            wrong_examples.append(
                                {"level": level, "function": row["name"], **item})
                    else:
                        totals["conservative"] += 1
                        if item["distance"] == 0:
                            totals["exact"] += 1
                        elif item["ours"] in ("unknown", "top"):
                            totals["unknown"] += 1
                rows.append({"function": row["name"], "entry": entry, "scored": scored})
            report["levels"].append({"level": level, "functions": len(rows), "rows": rows})

    scored = totals["scored"]
    if not scored:
        raise SystemExit("nothing scored: the fixture stated no comparable types")
    metrics = {
        "scored": scored,
        "exact": totals["exact"],
        "exact_rate": round(totals["exact"] / scored, 4),
        "conservative_rate": round(totals["conservative"] / scored, 4),
        "wrong": totals["wrong"],
        "wrong_rate": round(totals["wrong"] / scored, 4),
        "silent": totals["unknown"],
        "wrong_examples": wrong_examples,
    }
    report["metrics"] = metrics
    if metrics["wrong_rate"] > WRONG_CEILING:
        failures.append(
            f"{metrics['wrong']} of {scored} answers contradict the compiler "
            f"({metrics['wrong_rate']}), over the {WRONG_CEILING} ceiling")
    if metrics["exact_rate"] < EXACT_FLOOR:
        failures.append(
            f"exact on {metrics['exact_rate']} of {scored} answers, under the "
            f"{EXACT_FLOOR} floor")
    if metrics["conservative_rate"] < CONSERVATIVE_FLOOR:
        failures.append(
            f"conservative on {metrics['conservative_rate']}, under the "
            f"{CONSERVATIVE_FLOOR} floor")
    report["passed"] = not failures
    report["failures"] = failures
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(
        f"m16-001: PASS ({scored} typed positions over two optimisation levels; "
        f"exact {metrics['exact_rate']}, conservative {metrics['conservative_rate']}, "
        f"contradicting the compiler {metrics['wrong']}, silent {metrics['silent']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
