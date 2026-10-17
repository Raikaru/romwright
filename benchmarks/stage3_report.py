#!/usr/bin/env python3
"""Stage 3 (merge, explicit/implied, names, for-loop moves) gate report: the worker's decisions against the decompiler's own.

  stage3_report.py --out DIR [--reports benchmarks/reports] [--tag f1] [--date 20261014] [--extra FILE.json ...]

Reads, from DIR (the measurement host's out directory; arms `off` = `ROMWRIGHT_NATIVE_MERGE=1` plus every quality
switch of this stage disabled, `def` = the default build, `fix-<key>`/`no-<key>` = one quality fix alone / left out):
  m2-l<N>-<tag>-<arm>.json                m22-002 reports (lane 1 = MWCC seed 20261010, 2 = seed 20261011, 3 = ee-gcc)
  m3-<lane>-<tag>-<arm>.json and -functions.json    m22-003 reports and per-function rows
  m21-001_<arm>.json, ps2_success_<arm>*.json, printer_diff_<tag>.json, merge_diff_<tag>.json, merge_verify_<tag>.json
and writes `stage3_gates_<date>.{json,md}`: per gate exact / compiled / mean percent off and default, paired better / worse
/ same by match percent, the functions that lost an exact match or a compile, and the compile-failure classes
(`tests/m22-003/classes.py`) off against default. Nothing is hand-edited.
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
LANES003 = {
    "dds": "m22-003 dds", "rc": "m22-003 rc", "p4": "m22-003 p4", "ghclone": "m22-003 gh (harness clone)",
    "ff": "m22-003 ff", "dc": "m22-003 dc", "dk": "m22-003 dk",
}


def first_diagnostic(row: dict):
    layer = row.get("layers", {}).get("romwright", {})
    context = layer.get("variants", {}).get("context") or layer.get("context") or {}
    if context.get("compiled") or not context.get("produced", True):
        return None
    diagnostics = context.get("diagnostics") or []
    if diagnostics:
        item = diagnostics[0]
        return item.get("message") or ""
    errors = context.get("errors") or [context.get("error") or "unknown"]
    return errors[0]


def failure_classes(report: Path) -> dict:
    data = json.load(open(report))
    counts: collections.Counter[str] = collections.Counter()
    for row in data["functions"].values():
        message = first_diagnostic(row)
        if message is not None:
            counts[classes.classify_message(message)] += 1
    return dict(counts)


def gate(name: str, off: Path, arms: dict[str, Path], reports: dict[str, Path]) -> dict:
    rows = gate_pair.rows(str(off))
    result = {"gate": name, "off": gate_pair.summary(rows), "arms": {}}
    if "off" in reports:
        result["off"]["classes"] = failure_classes(reports["off"])
    for arm, path in arms.items():
        new = gate_pair.rows(str(path))
        entry = {"summary": gate_pair.summary(new), **gate_pair.pair(rows, new)}
        for key in ("better_addresses", "worse_addresses"):
            entry[key] = entry[key][:60]
        if arm in reports:
            entry["summary"]["classes"] = failure_classes(reports[arm])
        result["arms"][arm] = entry
    return result


def load(path: Path):
    return json.load(open(path)) if path.exists() else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reports", type=Path, default=HERE / "reports")
    parser.add_argument("--tag", default="f1")
    parser.add_argument("--date", default="20261014")
    parser.add_argument("--extra", type=Path, action="append", default=[], help="JSON blobs merged under `extra` by file stem")
    args = parser.parse_args()
    out, tag = args.out, args.tag
    gates = []
    for lane, label in LANES002.items():
        off = out / f"m2-l{lane}-{tag}-off.json"
        if not off.exists():
            continue
        arms = {a: out / f"m2-l{lane}-{tag}-{a}.json" for a in ("def",)}
        gates.append(gate(label, off, {a: p for a, p in arms.items() if p.exists()}, {}))
    for lane, label in LANES003.items():
        off = out / f"m3-{lane}-{tag}-off-functions.json"
        if not off.exists():
            continue
        reports = {"off": out / f"m3-{lane}-{tag}-off.json"}
        arms = {}
        for a in ("def",):
            path = out / f"m3-{lane}-{tag}-{a}-functions.json"
            if path.exists():
                arms[a] = path
                reports[a] = out / f"m3-{lane}-{tag}-{a}.json"
        gates.append(gate(label, off, arms, {a: p for a, p in reports.items() if p.exists()}))
    extra = {}
    for item in args.extra:
        if item.exists():
            extra[item.stem] = json.load(open(item))
    success = {}
    for arm in ("off", "def"):
        for path in sorted(out.glob(f"ps2_success_{arm}*.json")):
            data = json.load(open(path))["games"]
            success[arm] = {game: {"sampled": g["sampled"], "decompiled": g["decompiled"]} for game, g in data.items()}
    if success:
        extra["ps2_decompile_success"] = success
        if len(success) == 2:
            total = {arm: [sum(g["decompiled"] for g in games.values()), sum(g["sampled"] for g in games.values())]
                     for arm, games in success.items()}
            extra["ps2_decompile_success_total"] = {
                "off [decompiled, sampled]": total["off"], "def [decompiled, sampled]": total["def"],
                "games that differ": [g for g in success["def"] if success["def"][g] != success["off"].get(g)]}
    for arm in ("off", "def"):
        data = load(out / f"m21-001_{arm}.json")
        if data:
            rows = data.get("rows", {})
            extra[f"m21-001_{arm}"] = {"status": data.get("status"), "failures": data.get("failures"),
                                       "rows": {image: {k: row[k] for k in ("truth", "found", "recall", "precision", "size_exact") if k in row}
                                                for image, row in rows.items() if isinstance(row, dict)}}
    data = load(out / f"printer_diff_{tag}.json")
    if data:
        extra["printer_differential"] = {key: data.get(key) for key in ("decompiled", "identical", "identical_rate")}
    data = load(out / f"merge_diff_{tag}.json")
    if data:
        extra["merge_differential"] = {
            "decompiled": data["decompiled"], "identical": data["identical"],
            "images": {i["image"]: {k: i.get(k) for k in ("decompiled", "identical", "worker_merge_functions", "declined_functions",
                                                          "decline_reasons", "verify_mismatches", "verify_verified")} for i in data["images"]}}
    data = load(out / f"merge_verify_{tag}.json")
    if data:
        extra["merge_verify_ps2_wave"] = {"totals": data["totals"], "images": {
            k: {x: v[x] for x in ("decided", "verified", "mismatch", "declined", "decline_reasons")} for k, v in data["images"].items()}}
    report = {"benchmark": "stage3_gates", "date": args.date, "tag": tag, "gates": gates, "extra": extra}
    args.reports.mkdir(parents=True, exist_ok=True)
    stem = args.reports / f"stage3_gates_{args.date}"
    stem.with_suffix(".json").write_text(json.dumps(report, indent=1))

    L = [f"# Stage 3 (merge, explicit/implied, names, for-loop moves) gates, {args.date}", "",
         "`off` = `ROMWRIGHT_NATIVE_MERGE=1` (the decompiler's merge actions, `ActionMarkExplicit`/`ActionMarkImplied`, `ActionNameVars` and the "
         "for-loop moves in `romwright_structure.hh`: the previous default byte for byte). `def` = the default build (the worker decides). "
         "exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.", "",
         "How the arms ran: one release build (`romwright-cli`, `romwright-worker`, the pinned `ghidra_opt`), each arm a wrapper binary that sets "
         "its switches and `ROMWRIGHT_ARM` (the m22-002 harness drops `ROMWRIGHT_*` from the environment), `ROMWRIGHT_NO_IMPORT_CACHE=1`, "
         "`ROMWRIGHT_NO_FACT_PACK=1`. An m22-003 arm restores the lane's prepared work directory and repo from a pristine snapshot taken after "
         "its prepare stage (same path) and imports the retail image afresh; an m22-002 arm prepares its own work directory and repo copy.", "",
         "| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled | gained exact | gained compiled |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for g in gates:
        o = g["off"]
        L.append(f"| {g['gate']} | off | {o['exact']} | {o['compiled']} | {o['mean_percent']} | | | | | | | |")
        for arm, e in g["arms"].items():
            s = e["summary"]
            L.append(f"| {g['gate']} | {arm} | {s['exact']} | {s['compiled']} | {s['mean_percent']} | {e['better']} | {e['worse']} | {e['same']} | "
                     f"{len(e['lost_exact'])} | {len(e['lost_compiled'])} | {len(e['gained_exact'])} | {len(e['gained_compiled'])} |")
    L += ["", "## Compile-failure classes per m22-003 lane, off against def (functions that did not compile, by the compiler's first diagnostic)", "",
          "| lane | arm | classes |", "|---|---|---|"]
    total = {"off": collections.Counter(), "def": collections.Counter()}
    for g in gates:
        if "classes" in g["off"]:
            L.append(f"| {g['gate']} | off | {json.dumps(g['off']['classes'], sort_keys=True)} |")
            total["off"].update(g["off"]["classes"])
            e = g["arms"].get("def")
            if e and "classes" in e["summary"]:
                L.append(f"| {g['gate']} | def | {json.dumps(e['summary']['classes'], sort_keys=True)} |")
                total["def"].update(e["summary"]["classes"])
    names = sorted(set(total["off"]) | set(total["def"]))
    L += ["", "All lanes together (m22-003, the first diagnostic of every function that did not compile):", "",
          "| class | off | def |", "|---|---|---|"]
    for n in names:
        L.append(f"| {n} | {total['off'][n]} | {total['def'][n]} |")
    L.append(f"| **functions that do not compile** | {sum(total['off'].values())} | {sum(total['def'].values())} |")
    L += ["", "## Functions that lost an exact match or a compile (default build against `off`)", ""]
    lost = False
    for g in gates:
        e = g["arms"].get("def")
        if e and (e["lost_exact"] or e["lost_compiled"]):
            lost = True
            L.append(f"- {g['gate']}: lost exact {e['lost_exact']}, lost compiled {e['lost_compiled']}")
    if not lost:
        L.append("none")
    for name, blob in extra.items():
        L += ["", f"## {name}", "", "```json", json.dumps(blob, indent=1)[:6000], "```"]
    stem.with_suffix(".md").write_text("\n".join(L) + "\n")
    print(f"wrote {stem}.json and {stem}.md ({len(gates)} gates)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
