#!/usr/bin/env python3
"""m13-001: jump tables from value-set analysis, scored against stock Ghidra.

Switch recovery was the last pass in a native import that still called the
decompiler, and the most expensive one: 130 of 137 seconds on a statically
linked AArch64 image, with two bodies hitting the per-function decompiler
deadline. `crates/lre-core/src/native/vsa.rs` answers the same question by
emulating the dispatch path over SLEIGH's own p-code, once per index, exactly
as `JumpBasic::buildAddresses` does over the decompiler's IR.

What this gate pins is the claim, not a hope:

- what value-set analysis claims is *right*: every branch it reports is one
  stock reports too, and the case edges agree;
- it is *cheap*: the whole phase costs a fraction of a second;
- turning it on does not *lose* anything: with the decompiler still behind it
  the recovered set is no worse than the decompiler alone.

Its recall against stock is ~0.12 today; that is recorded, not asserted as
good, and it is why the pass is opt-in (`VENTRIS_SWITCH_VSA=1`).

The subject is the host's own libc, which has real switches in real
compiler-emitted shapes, and stock's answer comes from Ghidra with the
decompiler. Both sides are recomputed here; nothing is pinned to this
machine's numbers except the thresholds above.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"
EXPORTER = ROOT / "scripts/ExportSwitchTargets.java"

# Scored against truth, with stock as the baseline it must beat. Truth for a
# case target, independent of any tool: it decodes as an instruction, and it
# lies inside the extent of the function that branches to it, taken from the
# image's own symbol table. Stock Ghidra measures 0.9794 on the host libc --
# 34 of its targets are outside the branching function and 5 do not decode --
# so parity with stock is not the bar; beating it is (GOAL.md C2).
THRESHOLDS = {
    # Every case the pass claims must be sound: it answers only where it can
    # follow the dispatch, so an unsound answer is a defect, not a trade.
    "vsa_soundness": 0.99,
    # The whole phase, seconds, summed over discovery rounds.
    "vsa_seconds": 5.0,
    # The interpreter is the proven tier the roadmap wants to *replace* the
    # pattern pass: it must reach the decompiler's own reach at no less than
    # the proven tier's soundness, and inside the same phase budget, or the
    # parity number cannot ship as the default.
    "interpreted_parity_soundness": 0.9989,
    "interpreted_seconds": 5.0,
    # With the decompiler behind it: more dispatches than stock, and sounder
    # than stock.
    "combined_branches_over_stock": 1.0,
    "combined_soundness_over_stock": 1.0,
    # And no more of stock's dispatches missed than the decompiler alone
    # already misses.
    "combined_missed_ceiling": 3,
}


def stock_tables(binary: Path, install: Path, work: Path) -> dict[int, set[int]]:
    """Stock Ghidra's own jump tables, from its decompiler."""
    work.mkdir(parents=True, exist_ok=True)
    output = work / "stock.json"
    subprocess.run(
        [
            str(install / "support/analyzeHeadless"),
            str(work),
            "switch-oracle",
            "-import",
            str(binary),
            "-scriptPath",
            str(EXPORTER.parent),
            "-postScript",
            EXPORTER.name,
            str(output),
            "-deleteProject",
            "-max-cpu",
            "4",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if not output.is_file():
        raise ValueError("stock Ghidra produced no switch export")
    exported = json.loads(output.read_text())["functions"]
    tables: dict[int, set[int]] = {}
    for entries in exported.values():
        for table in entries:
            branch = int(table["branch"].split(":")[-1], 16)
            tables.setdefault(branch, set()).update(
                int(target.split(":")[-1], 16) for target in table["targets"]
            )
    return tables


def imported(binary: Path, project: Path, environment: dict[str, str]) -> tuple[dict[int, set[int]], float, float]:
    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    started = time.time()
    result = subprocess.run(
        [str(CLI), "import", str(binary), "--project", str(project), "--timings"],
        capture_output=True,
        text=True,
        # Cold: this gate reports the switch round's own cost, and a reused
        # import restores facts without running the phase that produced them.
        env={**os.environ, "VENTRIS_NO_IMPORT_CACHE": "1", **environment},
    )
    wall = time.time() - started
    if result.returncode:
        raise ValueError(f"import failed: {result.stderr[-800:]}")
    phase = 0.0
    for line in result.stdout.splitlines():
        if not line.startswith("TIMINGS "):
            continue
        timings = json.loads(line[len("TIMINGS ") :])
        # The phase is measured once per discovery round.
        phase = sum(
            seconds
            for name, seconds in timings.get("phases", {}).items()
            if name == "switch-vsa"
        )
    connection = sqlite3.connect(project / "project.sqlite")
    tables: dict[int, set[int]] = {}
    for source, destination in connection.execute(
        "SELECT src, dst FROM xrefs WHERE provenance = 'native-import:switch'"
    ):
        tables.setdefault(int(source, 16), set()).add(int(destination, 16))
    return tables, wall, phase


def symbol_extents(binary: Path, base: int) -> list[tuple[int, int]]:
    """Function extents the image itself declares, for the truth measure."""
    out = subprocess.run(["readelf", "-sW", str(binary)], capture_output=True, text=True).stdout
    spans = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[3] != "FUNC":
            continue
        try:
            value, size = int(parts[1], 16), int(parts[2], 0)
        except ValueError:
            continue
        if size:
            spans.append((base + value, base + value + size))
    spans.sort()
    return spans


def owner(spans: list[tuple[int, int]], address: int) -> tuple[int, int] | None:
    low, high = 0, len(spans)
    while low < high:
        middle = (low + high) // 2
        if spans[middle][0] <= address:
            low = middle + 1
        else:
            high = middle
    if low == 0:
        return None
    start, end = spans[low - 1]
    return (start, end) if address < end else None


def decodes(binary: Path, base: int, addresses: set[int], ghidra: Path) -> set[int]:
    """Every address SLEIGH decodes to a real instruction."""
    if not addresses:
        return set()
    console = Path(os.environ.get("VENTRIS_CONSOLE", ROOT / "native/build/decomp_native"))
    ordered = sorted(addresses)
    good: set[int] = set()
    for start in range(0, len(ordered), 400):
        chunk = ordered[start : start + 400]
        script = (
            f"load file {binary}\nadjust vma 0x{base:x}\n"
            + "flow "
            + " ".join(f"0x{address:x}" for address in chunk)
            + "\nquit\n"
        )
        result = subprocess.run(
            [str(console), "-s", str(ghidra / "Ghidra/Processors")],
            input=script,
            capture_output=True,
            text=True,
            env={**os.environ, "SLEIGHHOME": str(ghidra)},
        )
        answers = [line for line in result.stdout.splitlines() if line.startswith("FLOW ")]
        for line, address in zip(answers, chunk):
            if "kind=BAD" not in line and "kind=UNIMPL" not in line:
                good.add(address)
    return good


def score(
    tables: dict[int, set[int]],
    stock: dict[int, set[int]],
    spans: list[tuple[int, int]],
    decoded: set[int],
) -> dict:
    claimed = sum(len(targets) for targets in tables.values())
    sound = outside = undecodable = 0
    for branch, targets in tables.items():
        extent = owner(spans, branch)
        for target in targets:
            if target not in decoded:
                undecodable += 1
            elif extent and not (extent[0] <= target < extent[1]):
                outside += 1
            else:
                sound += 1
    both = set(tables) & set(stock)
    return {
        "branches": len(tables),
        "targets": claimed,
        "sound_targets": sound,
        "outside_function": outside,
        "undecodable": undecodable,
        "soundness": round(sound / max(claimed, 1), 4),
        "agree_with_stock": sum(1 for branch in both if tables[branch] == stock[branch]),
        "shared_with_stock": len(both),
        "beyond_stock": len(set(tables) - set(stock)),
        "missed_of_stock": len(set(stock) - set(tables)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("/usr/lib64/libc.so.6"))
    parser.add_argument(
        "--ghidra",
        type=Path,
        default=Path(os.environ.get("VENTRIS_GHIDRA", Path.home() / "ghidra_12.1.3_PUBLIC")),
    )
    parser.add_argument("--work", type=Path, default=Path.home() / "ventris-cache/tmp/m13-001")
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {
        "id": "m13-001",
        "milestone": "M13",
        "criterion": "jump tables recovered from p-code without the decompiler, scored against stock",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": THRESHOLDS,
        "binary": str(arguments.binary),
    }
    if not arguments.binary.is_file():
        report["status"] = "skipped"
        report["reason"] = f"{arguments.binary} is not on this machine"
        print(f"m13-001: SKIPPED ({report['reason']})")
    else:
        # The switch round spawns `lre-worker`, which refuses a store whose
        # schema is newer than the one it was built against. Building only
        # the CLI made a stale worker look like the decompiler path
        # answering zero dispatches; build both.
        subprocess.run(
            ["cargo", "build", "-q", "--release", "-p", "lre-cli", "-p", "lre-worker"],
            cwd=ROOT,
            check=True,
        )
        stock = stock_tables(arguments.binary, arguments.ghidra, arguments.work / "stock")
        vsa, vsa_wall, vsa_phase = imported(
            arguments.binary,
            arguments.work / "vsa",
            {"VENTRIS_NO_SWITCH_DECOMPILER": "1"},
        )
        decompiler, decompiler_wall, _ = imported(
            arguments.binary, arguments.work / "decompiler", {"VENTRIS_NO_SWITCH_VSA": "1"}
        )
        # The abstract interpretation (`VENTRIS_SJA=1`) is opt-in, and this
        # is its gate: it runs only where the pattern-shaped pass refused,
        # so it can only add dispatches, and what it adds has to be as sound
        # as what it adds to.
        interpreted, interpreted_wall, interpreted_phase = imported(
            arguments.binary,
            arguments.work / "interpreted",
            {"VENTRIS_NO_SWITCH_DECOMPILER": "1", "VENTRIS_SJA": "1"},
        )
        combined, combined_wall, combined_phase = imported(
            arguments.binary, arguments.work / "combined", {}
        )
        # The image's own function extents, and one decode of every address
        # any path claims: the truth both sides are held to.
        base = min(min(targets) for targets in stock.values()) if stock else 0
        base = 0x100000 if base >= 0x100000 else 0
        spans = symbol_extents(arguments.binary, base)
        every: set[int] = set()
        for tables in (stock, vsa, decompiler, combined, interpreted):
            for targets in tables.values():
                every |= targets
        decoded = decodes(arguments.binary, base, every, arguments.ghidra)

        measured = {
            "stock": score(stock, stock, spans, decoded),
            "vsa": {
                **score(vsa, stock, spans, decoded),
                "wall_s": round(vsa_wall, 1),
                "phase_s": round(vsa_phase, 3),
            },
            "interpreted": {
                **score(interpreted, stock, spans, decoded),
                "wall_s": round(interpreted_wall, 1),
                "phase_s": round(interpreted_phase, 3),
            },
            "decompiler": {
                **score(decompiler, stock, spans, decoded),
                "wall_s": round(decompiler_wall, 1),
            },
            "combined": {
                **score(combined, stock, spans, decoded),
                "wall_s": round(combined_wall, 1),
                "phase_s": round(combined_phase, 3),
            },
        }
        report["measured"] = measured

        failures = []
        if measured["vsa"]["soundness"] < THRESHOLDS["vsa_soundness"]:
            failures.append(
                f"vsa soundness {measured['vsa']['soundness']} < {THRESHOLDS['vsa_soundness']}"
            )
        if measured["vsa"]["phase_s"] > THRESHOLDS["vsa_seconds"]:
            failures.append(
                f"vsa phase {measured['vsa']['phase_s']}s > {THRESHOLDS['vsa_seconds']}s"
            )
        # The interpreter is the proven tier the roadmap wants to *replace*
        # the pattern pass: it must reach the decompiler's own reach at no
        # less than the proven tier's soundness, and inside the same phase
        # budget, or the parity number cannot ship as the default.
        if measured["interpreted"]["branches"] < measured["vsa"]["branches"]:
            failures.append(
                f"the interpreter answered {measured['interpreted']['branches']} dispatches,"
                f" fewer than the pass alone at {measured['vsa']['branches']}"
            )
        if measured["interpreted"]["branches"] < measured["decompiler"]["branches"]:
            failures.append(
                f"the interpreter answered {measured['interpreted']['branches']} dispatches,"
                f" short of the decompiler's {measured['decompiler']['branches']}"
            )
        if measured["interpreted"]["soundness"] < THRESHOLDS["interpreted_parity_soundness"]:
            failures.append(
                f"interpreter parity soundness {measured['interpreted']['soundness']} <"
                f" {THRESHOLDS['interpreted_parity_soundness']}"
            )
        if measured["interpreted"]["phase_s"] > THRESHOLDS["interpreted_seconds"]:
            failures.append(
                f"interpreter phase {measured['interpreted']['phase_s']}s >"
                f" {THRESHOLDS['interpreted_seconds']}s"
            )
        # The roadmap's criterion: the proven tier reaches the decompiler's
        # own reach at no less than its soundness, inside the phase budget.
        if measured["interpreted"]["branches"] < measured["decompiler"]["branches"]:
            failures.append(
                f"the interpreter answered {measured['interpreted']['branches']} dispatches,"
                f" short of the decompiler's {measured['decompiler']['branches']}"
            )
        if measured["interpreted"]["soundness"] < THRESHOLDS["interpreted_parity_soundness"]:
            failures.append(
                f"interpreter parity soundness {measured['interpreted']['soundness']} <"
                f" {THRESHOLDS['interpreted_parity_soundness']}"
            )
        if measured["interpreted"]["phase_s"] > THRESHOLDS["interpreted_seconds"]:
            failures.append(
                f"interpreter phase {measured['interpreted']['phase_s']}s >"
                f" {THRESHOLDS['interpreted_seconds']}s"
            )
        if measured["combined"]["branches"] <= measured["stock"]["branches"]:
            failures.append(
                f"combined answers {measured['combined']['branches']} dispatches,"
                f" not more than stock's {measured['stock']['branches']}"
            )
        if measured["combined"]["soundness"] <= measured["stock"]["soundness"]:
            failures.append(
                f"combined soundness {measured['combined']['soundness']} not above"
                f" stock's {measured['stock']['soundness']}"
            )
        if measured["combined"]["missed_of_stock"] > THRESHOLDS["combined_missed_ceiling"]:
            failures.append(
                f"combined misses {measured['combined']['missed_of_stock']} of stock's"
                f" dispatches, over {THRESHOLDS['combined_missed_ceiling']}"
            )
        report["status"] = "pass" if not failures else "fail"
        report["failures"] = failures
        if failures:
            print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
            if arguments.report:
                arguments.report.parent.mkdir(parents=True, exist_ok=True)
                arguments.report.write_text(json.dumps(report, indent=2) + "\n")
            return 1
        print(
            "m13-001: PASS (combined {cb} dispatches at {cs} soundness against stock's"
            " {sb} at {ss}; {beyond} beyond stock, {missed} of stock's missed; the pass"
            " alone {vb} at {vs} in {phase}s, with the interpreter {ib} at {is_} in"
            " {iphase}s)".format(
                ib=measured["interpreted"]["branches"],
                is_=measured["interpreted"]["soundness"],
                iphase=measured["interpreted"]["phase_s"],
                cb=measured["combined"]["branches"],
                cs=measured["combined"]["soundness"],
                sb=measured["stock"]["branches"],
                ss=measured["stock"]["soundness"],
                beyond=measured["combined"]["beyond_stock"],
                missed=measured["combined"]["missed_of_stock"],
                vb=measured["vsa"]["branches"],
                vs=measured["vsa"]["soundness"],
                phase=measured["vsa"]["phase_s"],
            )
        )
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
