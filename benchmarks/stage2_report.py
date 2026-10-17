#!/usr/bin/env python3
"""Stage 2 (types/casts) gate report: per gate, the decompiler-casts arm (`off`) against the worker-casts default build.

  stage2_report.py --out DIR [--reports benchmarks/reports] [--tag g5] [--date 20261013]

Reads, from DIR (the measurement host's out directory):
  m22-002-<tag>-<arm>-l<N>.json       m22-002 reports (lanes 1 = MWCC seed 20261010, 2 = seed 20261011, 3 = ee-gcc)
  m22003-<lane>-<tag>-<arm>.json      m22-003 reports, and m22003-<lane>-<tag>-<arm>-functions.json (the rows)
and writes `stage2_gates_<date>.{json,md}` into the reports directory: exact / compiled / mean per arm, the paired
better / worse / same counts, the functions that lost an exact match or a compile, and the compile-failure classes
(tests/m22-003/classes.py `classify_message` of the first diagnostic) of every arm. Arms: `off` = ROMWRIGHT_NATIVE_CASTS=1
and the compiler rule `mwcc-void-pointer-arithmetic` disabled (the build before this stage), `def` = the default build,
`parity` = the worker's casts with the rule disabled (the port alone), `noagg` = `ROMWRIGHT_RUST_CASTS_AGGREGATE=off`.
`def` of the MWCC gates (m22-002, dc, dk, p4) is the final build, `def_before_final_rebuild` the earlier build of the same day (see docs/types-port.md, Result).
Nothing is hand-edited.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tests" / "m22-003"))
import classes  # noqa: E402
import gate_pair  # noqa: E402

LANES002 = {"1": "m22-002 MWCC seed 20261010", "2": "m22-002 MWCC seed 20261011", "3": "m22-002 ee-gcc"}
LANES003 = ["dds", "rc", "p4", "gh", "ff", "dc", "dk"]
ARMS = ["def", "parity", "noagg"]


def failure_classes(report: Path) -> dict[str, int]:
    data = json.load(open(report))
    counts: collections.Counter[str] = collections.Counter()
    for row in data["functions"].values():
        layer = row.get("layers", {}).get("romwright", {})
        context = layer.get("variants", {}).get("context") or layer.get("context") or {}
        if context.get("compiled") or not context.get("produced", True):
            continue
        message = (context.get("errors") or [context.get("error") or "unknown"])[0]
        counts[classes.classify_message(message)] += 1
    return dict(counts)


def gate(name: str, off: Path, arms: dict[str, Path], off_report: Path | None, arm_reports: dict[str, Path]) -> dict:
    result = {"gate": name, "off": gate_pair.summary(gate_pair.rows(str(off))), "arms": {}}
    if off_report:
        result["off"]["failure_classes"] = failure_classes(off_report)
    base = gate_pair.rows(str(off))
    for arm, path in arms.items():
        rows = gate_pair.rows(str(path))
        paired = gate_pair.pair(base, rows)
        entry = {"summary": gate_pair.summary(rows), **paired}
        for key in ("better_addresses", "worse_addresses"):
            entry[key] = entry[key][:40]
        if arm in arm_reports:
            entry["summary"]["failure_classes"] = failure_classes(arm_reports[arm])
        result["arms"][arm] = entry
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reports", type=Path, default=HERE / "reports")
    parser.add_argument("--tag", default="g5")
    parser.add_argument("--extra-tag", default="g5x", help="tag of the single-arm experiments (noagg)")
    parser.add_argument("--final-m22002-tag", default="g8", help="tag prefix of the m22-002 default-arm reruns on the final build (one lane per run: g8a, g8b, g8c)")
    parser.add_argument("--final-m22003-arm", default="def8", help="arm name of the m22-003 default-arm reruns on the final build")
    parser.add_argument("--lane3-out", type=Path, help="directory with m22-002-<lane3-tag>-<arm>-l3.json: the ee-gcc lane run with a fresh work directory per arm "
                        "(the lanes of one arm share a work directory in the main runs, which is order-dependent)")
    parser.add_argument("--lane3-tag", default="f1")
    parser.add_argument("--date", default="20261013")
    args = parser.parse_args()
    out = args.out
    gates = []
    for lane, label in LANES002.items():
        if lane == "3" and args.lane3_out:
            fresh = {a: args.lane3_out / f"m22-002-{args.lane3_tag}-{a}-l3.json" for a in ("off", "parity", "def")}
            if all(p.exists() for p in fresh.values()):
                gates.append(gate(label + " (fresh work dir per arm)", fresh.pop("off"), fresh, None, {}))
                continue
        off = out / f"m22-002-{args.tag}-off-l{lane}.json"
        if not off.exists():
            continue
        arms = {a: out / f"m22-002-{args.tag}-{a}-l{lane}.json" for a in ARMS}
        arms = {a: p for a, p in arms.items() if p.exists()}
        final = out / f"m22-002-{args.final_m22002_tag}{'abc'[int(lane) - 1]}-def-l{lane}.json"
        if final.exists():
            arms["def_before_final_rebuild"] = arms.pop("def", None) or final
            arms["def"] = final
        gates.append(gate(label, off, arms, None, {}))
    for lane in LANES003:
        off = out / f"m22003-{lane}-{args.tag}-off-functions.json"
        if not off.exists():
            continue
        arms, reports = {}, {}
        for a in ARMS:
            tag = args.extra_tag if a == "noagg" else args.tag
            path = out / f"m22003-{lane}-{tag}-{a}-functions.json"
            if a == "def" and (out / f"m22003-{lane}-{tag}-{args.final_m22003_arm}-functions.json").exists():
                arms["def_before_final_rebuild"] = path
                reports["def_before_final_rebuild"] = out / f"m22003-{lane}-{tag}-{a}.json"
                path = out / f"m22003-{lane}-{tag}-{args.final_m22003_arm}-functions.json"
                reports[a] = out / f"m22003-{lane}-{tag}-{args.final_m22003_arm}.json"
                arms[a] = path
            elif path.exists():
                arms[a] = path
                reports[a] = out / f"m22003-{lane}-{tag}-{a}.json"
        label = f"m22-003 {lane}" + (" (pristine repo copy: a smaller build than the harness clone, see stage2_followup)" if lane == "gh" else "")
        gates.append(gate(label, off, arms, out / f"m22003-{lane}-{args.tag}-off.json",
                          {a: p for a, p in reports.items() if p.exists()}))
    report = {"benchmark": "stage2_gates", "date": args.date, "tag": args.tag, "gates": gates}
    args.reports.mkdir(parents=True, exist_ok=True)
    stem = args.reports / f"stage2_gates_{args.date}"
    stem.with_suffix(".json").write_text(json.dumps(report, indent=1))
    lines = [f"# Stage 2 (types/casts) gates, {args.date}", "",
             "`off` = the decompiler casts (`ROMWRIGHT_NATIVE_CASTS=1`, rule `mwcc-void-pointer-arithmetic` disabled): the build before this stage. "
             "`def` = the default build. `parity` = the worker's casts with the rule disabled (the port alone). `noagg` = "
             "`ROMWRIGHT_RUST_CASTS_AGGREGATE=off`. exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.", "",
             "| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled |", "|---|---|---|---|---|---|---|---|---|---|"]
    for g in gates:
        o = g["off"]
        lines.append(f"| {g['gate']} | off | {o['exact']} | {o['compiled']} | {o['mean_percent']} | | | | | |")
        for arm, e in g["arms"].items():
            s = e["summary"]
            lines.append(f"| {g['gate']} | {arm} | {s['exact']} | {s['compiled']} | {s['mean_percent']} | {e['better']} | {e['worse']} | "
                         f"{e['same']} | {len(e['lost_exact'])} | {len(e['lost_compiled'])} |")
    lines += ["", "## Compile-failure classes per m22-003 lane (functions that did not compile, by the compiler's first diagnostic)", "",
              "| lane | arm | classes |", "|---|---|---|"]
    for g in gates:
        if "failure_classes" in g["off"]:
            lines.append(f"| {g['gate']} | off | {json.dumps(g['off']['failure_classes'], sort_keys=True)} |")
            for arm, e in g["arms"].items():
                if "failure_classes" in e["summary"]:
                    lines.append(f"| {g['gate']} | {arm} | {json.dumps(e['summary']['failure_classes'], sort_keys=True)} |")
    lines += ["", "## Functions that lost an exact match or a compile (default build against `off`)", ""]
    for g in gates:
        e = g["arms"].get("def")
        if e and (e["lost_exact"] or e["lost_compiled"]):
            lines.append(f"- {g['gate']}: lost exact {e['lost_exact']}, lost compiled {e['lost_compiled']}")
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n")
    print(f"wrote {stem}.json and {stem}.md ({len(gates)} gates)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
