#!/usr/bin/env python3
"""Combined gate: one build of the shared tree against the latest per-agent reports.

Reads the reports one run of the tree wrote (m21-001, m22-002 x3, `ps2_decompile_success.py`, two
`console_research.py --corpus-wave` runs) and the frozen reports they are compared with, and writes
`combined_gate_<tag>.{json,md}`: every number beside the number it is compared with, the paired
m22-002 functions that moved, and the decompile failures of the PS2 samples. Nothing is measured here.

    python3 benchmarks/combined_gate.py --tag 20261012 [--reports DIR] [--new-dir DIR]

`--reports` is where the frozen reports live (default benchmarks/reports); `--new-dir` where the run's
reports are (default: the same). The new files carry the suffix `_combined_<tag>` (m22-002, m21-001,
the success report) or `console_research_wave_<tag>_{ps2,other,psp_n200}_combined`.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

REPORTS = Path(__file__).resolve().parent / "reports"

# Numbers that exist only in STATUS.md prose (no report file of their own), with their sources.
PROSE = {
    "m21 capcom (Ps2Precision, STATUS 'PS2 discovery precision')": {"ps2-capcom-fighting-evolution": (0.9741, 0.9945)},
    "m21 capcom before it (same section)": {"ps2-capcom-fighting-evolution": (0.9762, 0.9924)},
}
# Ps2Precision's PSP rows, `-n 200`, default, overflow-checked build (STATUS, 'PSP overflow'): recall / precision.
PSP_N200 = {
    "psp-psp-camera-01": (0.9597, 0.9585), "psp-tetris": (0.9876, 0.9671), "psp-hot-pixel": (0.8884, 0.9057),
    "psp-melodie": (0.9605, 0.9477), "psp-pac-man-rally": (0.9074, 0.9280),
}
M22_BASELINES = {
    "MWCC seed 20261010": ("m22-ps2_p4.json", "m22-ps2_p4_combined_{tag}.json"),
    "MWCC seed 20261011": ("m22-ps2_p4_seed20261011.json", "m22-ps2_p4_seed20261011_combined_{tag}.json"),
    "ee-gcc seed 20261010": ("m22-ps2_p4_eegcc.json", "m22-ps2_p4_eegcc_combined_{tag}.json"),
}
PS2_SUCCESS_BASELINES = {
    "RustStructure (handoff default)": "ps2_decompile_success_handoff_default.json",
    "Ps2CMatch (after)": "ps2_decompile_success_after_20261011.json",
}


def load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join("-" if cell is None else str(cell) for cell in row) + " |" for row in rows]
    return out


def fmt(value, digits=4):
    return "-" if value is None else (f"{value:.{digits}f}" if isinstance(value, float) else str(value))


def delta(new, old, digits=4):
    if new is None or old is None:
        return "-"
    return f"{new - old:+.{digits}f}"


def m21_section(new_dir: Path, tag: str, out: dict) -> list[str]:
    new = load(new_dir / f"m21-001_combined_{tag}.json")
    without = load(new_dir / f"m21-001_old_{tag}.json")  # the same tree, ghidra_opt before GP-7003
    before = load(REPORTS / "ghidra_master_trial" / "data" / "m21_base.json")  # earlier tree, same harness
    md = ["## m21-001 (7 images)", ""]
    if not new:
        return md + ["not run", ""]
    out["m21"] = {"status": new["status"], "failures": new.get("failures"), "rows": {}}
    rows = []
    for game, row in new["rows"].items():
        old = (before or {}).get("rows", {}).get(game, {})
        plain = ((without or {}).get("rows") or {}).get(game)
        capcom = PROSE["m21 capcom (Ps2Precision, STATUS 'PS2 discovery precision')"].get(game)
        out["m21"]["rows"][game] = {"recall": row["recall"], "precision": row["precision"], "size_exact": row.get("size_exact"),
                                    "without_gp7003": {"recall": plain["recall"], "precision": plain["precision"]} if plain else None,
                                    "earlier_tree": {"recall": old.get("recall"), "precision": old.get("precision")},
                                    "ps2precision": capcom}
        rows.append([game, fmt(row["recall"]), fmt(row["precision"]), row.get("size_exact"),
                     f"{fmt(plain['recall'])} / {fmt(plain['precision'])}" if plain else "-",
                     f"{fmt(old.get('recall'))} / {fmt(old.get('precision'))}",
                     f"{capcom[0]} / {capcom[1]}" if capcom else "-"])
    md += [f"Status {new['status']}, failures {new.get('failures') or 'none'}. `without GP-7003` = the same tree with the previous `ghidra_opt` "
           "(15396033...). `earlier tree` = the 2026-10-12 master-trial base arm "
           "(`ghidra_opt` dbd7e74b, before the PS2 discovery work); Ps2Precision's figure is the capcom row it recorded.", ""]
    md += table(["image", "recall", "precision", "size exact", "without GP-7003 recall / precision", "earlier tree recall / precision",
                 "Ps2Precision recall / precision"], rows) + [""]
    return md


def m22_section(new_dir: Path, tag: str, out: dict) -> list[str]:
    md = ["## m22-002 (PS2 C match, romwright layer, context variant, 200 functions)", ""]
    out["m22"] = {}
    rows = []
    moved: list[str] = []
    for lane, (frozen_name, new_name) in M22_BASELINES.items():
        frozen = load(REPORTS / frozen_name)
        new = load(new_dir / new_name.format(tag=tag))
        if not new or not frozen:
            rows.append([lane, "not run" if not new else "no frozen report", "", "", "", "", "", ""])
            continue
        a = frozen["summary"]["overall"]["all"]["romwright"]["context"]
        b = new["summary"]["overall"]["all"]["romwright"]["context"]
        better, worse, same = [], [], 0
        gained, lost = [], []
        for address, fn in new["functions"].items():
            x = frozen["functions"].get(address)
            if x is None:
                continue
            va = x["layers"]["romwright"]["variants"]["context"]
            vb = fn["layers"]["romwright"]["variants"]["context"]
            if vb["percent"] > va["percent"] + 1e-9:
                better.append((address, fn["name"], va["percent"], vb["percent"]))
            elif vb["percent"] < va["percent"] - 1e-9:
                worse.append((address, fn["name"], va["percent"], vb["percent"]))
            else:
                same += 1
            if vb["exact"] and not va["exact"]:
                gained.append(fn["name"])
            if va["exact"] and not vb["exact"]:
                lost.append(fn["name"])
        out["m22"][lane] = {"frozen": {k: a[k] for k in ("exact", "compiled", "mean_percent", "compile_failure_share")},
                            "new": {k: b[k] for k in ("exact", "compiled", "mean_percent", "compile_failure_share")},
                            "better": better, "worse": worse, "same": same, "exact_gained": gained, "exact_lost": lost}
        rows.append([lane, f"{a['exact']} / {a['compiled']} / {a['mean_percent']}", f"{b['exact']} / {b['compiled']} / {b['mean_percent']}",
                     f"{b['exact'] - a['exact']:+d} / {b['compiled'] - a['compiled']:+d} / {b['mean_percent'] - a['mean_percent']:+.3f}",
                     f"{len(better)} / {len(worse)} / {same}", f"{len(gained)} / {len(lost)}"])
        for kind, items in (("worse", worse), ("better", better)):
            for address, name, pa, pb in items:
                moved.append(f"- {lane}, {kind}: `{name}` {address} {pa:.2f} -> {pb:.2f} %")
    md += ["Each row: exact / compiled / mean percent. `frozen` = the report the lane's last owner wrote "
           "(`m22-ps2_p4*.json`: Ps2CMatch's 55 / 76.624, 57 / 78.321, 106 / 86.406); RustStructure measured 55 / 76.976 on lane 1 "
           "with the same code (its tree carried other agents' work).", ""]
    md += table(["lane", "frozen", "this build", "delta exact / compiled / mean", "paired better / worse / same", "exact gained / lost"], rows) + [""]
    old = load(new_dir / f"m22-ps2_p4_old_{tag}.json")
    new1 = load(new_dir / M22_BASELINES["MWCC seed 20261010"][1].format(tag=tag))
    if old and new1:
        score = lambda fn: tuple(fn["layers"]["romwright"]["variants"]["context"][k] for k in ("compiled", "exact", "percent"))
        changed = [address for address, fn in new1["functions"].items() if score(fn) != score(old["functions"][address])]
        c = old["summary"]["overall"]["all"]["romwright"]["context"]
        out["m22"]["same_tree_without_gp7003_seed20261010"] = {
            "exact": c["exact"], "compiled": c["compiled"], "mean_percent": c["mean_percent"], "functions_that_differ_from_this_build": changed}
        md += [f"The same tree without GP-7003 (`ghidra_opt` 15396033..., the build before this patch), MWCC seed 20261010: {c['exact']} / "
               f"{c['compiled']} / {c['mean_percent']}; {len(changed)} of 200 functions score differently from this build.", ""]
    if moved:
        md += ["Functions whose percent moved:", ""] + moved + [""]
    return md


def success_section(new_dir: Path, tag: str, out: dict) -> list[str]:
    md = ["## PS2 decompile success on the wave's samples (`ps2_decompile_success.py`, 11 projects)", ""]
    new = load(new_dir / f"ps2_decompile_success_combined_{tag}.json")
    if not new:
        return md + ["not run", ""]
    baselines = {name: load(REPORTS / file) for name, file in PS2_SUCCESS_BASELINES.items()}
    games = new["games"]
    out["ps2_success"] = {"games": {}, "bin": new.get("bin"), "wave": new.get("wave")}
    total = sum(g["sampled"] for g in games.values())
    ok = sum(g["decompiled"] for g in games.values())
    rows = []
    for game, g in games.items():
        cells = [game, f"{g['decompiled']} / {g['sampled']}"]
        entry = {"decompiled": g["decompiled"], "sampled": g["sampled"], "failures": g.get("failures", [])}
        for name, base in baselines.items():
            b = (base or {}).get("games", {}).get(game)
            cells.append(f"{b['decompiled']} / {b['sampled']}" if b else "-")
            entry[name] = b["decompiled"] if b else None
        rows.append(cells)
        out["ps2_success"]["games"][game] = entry
    totals = ["all", f"{ok} / {total}"]
    for name, base in baselines.items():
        games_b = (base or {}).get("games", {})
        totals.append(f"{sum(v['decompiled'] for v in games_b.values())} / {sum(v['sampled'] for v in games_b.values())}")
    rows.append(totals)
    md += table(["game", "this build"] + list(baselines), rows) + [""]
    failing = [(game, f) for game, g in games.items() for f in g.get("failures", [])]
    base_fail = {(game, f["address"]) for game, g in (baselines["RustStructure (handoff default)"] or {}).get("games", {}).items()
                 for f in g.get("failures", [])}
    if failing:
        md += ["Failed functions (`*` = also failing in RustStructure's run):", ""]
        for game, f in failing:
            md.append(f"- {'*' if (game, f['address']) in base_fail else ' '} {game} {f['address']}: {f.get('class') or f.get('error', '')[:120]}")
        md.append("")
    out["ps2_success"]["total"] = [ok, total]
    return md


def wave_rows(report: dict, frozen: dict | None, games: list[str] | None = None, tool: str = "default"):
    rows = []
    entries = {}
    for game, image in report["images"].items():
        if games and game not in games:
            continue
        config = (image.get("configs") or {}).get(tool)
        if not config or "summary" not in config:
            rows.append([game, image.get("status")] + [None] * 8)
            continue
        s = config["summary"]
        f = None
        if frozen:
            fc = ((frozen["images"].get(game) or {}).get("configs") or {}).get(tool)
            f = fc["summary"] if fc and "summary" in fc else None
        entries[game] = {"summary": {k: s.get(k) for k in ("sampled", "decompiled", "success_rate", "recall", "precision", "gotos", "labels",
                                                          "native_warnings", "wall_seconds")},
                         "frozen": {k: f.get(k) for k in ("sampled", "decompiled", "success_rate", "recall", "precision", "gotos", "labels")} if f else None}
        rows.append([game, image.get("status"), f"{s['decompiled']} / {s['sampled']}", fmt(s["success_rate"]), fmt(s["recall"]),
                     delta(s["recall"], f and f.get("recall")), fmt(s["precision"]), delta(s["precision"], f and f.get("precision")),
                     f"{s.get('gotos')} / {s.get('labels')}", f"{(f or {}).get('gotos', '-')} / {(f or {}).get('labels', '-')}"])
    return rows, entries


WAVE_HEADER = ["image", "status", "decompiled / sampled", "success", "recall", "vs frozen", "precision", "vs frozen", "gotos / labels",
               "frozen gotos / labels"]


def ps2_wave_section(new_dir: Path, tag: str, out: dict) -> list[str]:
    md = ["## PS2 wave (8 games and symtab variants, `--corpus-wave --stock`, n = 500, seeds 1,2)", ""]
    new = load(new_dir / f"console_research_wave_{tag}_ps2_combined.json")
    frozen = load(REPORTS / "console_research_wave_20261011_ps2_precision.json")
    if not new:
        return md + ["not run", ""]
    rows, entries = wave_rows(new, frozen)
    out["ps2_wave"] = {"tools": new.get("tools"), "frozen_tools": (frozen or {}).get("tools"), "images": entries}
    md += [f"Tools fingerprint `{new.get('tools')}` against `{(frozen or {}).get('tools')}` (Ps2Precision's "
           "`console_research_wave_20261011_ps2_precision`, whose success column is 0.0: the printer and `ghidra_opt` disagreed on the "
           "IR version, so its decompile numbers are not a baseline; recall and precision are).", ""]
    md += table(WAVE_HEADER, rows) + [""]
    stock_rows = []
    for game, image in new["images"].items():
        s = image.get("stock")
        d = ((image.get("configs") or {}).get("default") or {}).get("summary")
        c = ((s or {}).get("combined") or {}).get("summary")
        if c and d:
            stock_rows.append([game, fmt(d["recall"]), fmt(c["recall"]), fmt(d["precision"]), fmt(c["precision"])])
    if stock_rows:
        md += ["Against stock Ghidra (cached, same samples):", ""]
        md += table(["image", "default recall", "stock recall", "default precision", "stock precision"], stock_rows) + [""]
    off = []
    for game, image in new["images"].items():
        v = ((image.get("configs") or {}).get("default") or {}).get("vs_baseline_off")
        if v:
            off.append([game, fmt(v["recall"]["from"]), fmt(v["recall"]["to"]), fmt(v["precision"]["from"]), fmt(v["precision"]["to"]),
                        ((image["configs"]["default"]).get("verdict"))])
    if off:
        md += ["Default against baseline-off (this build):", ""]
        md += table(["image", "baseline-off recall", "default recall", "baseline-off precision", "default precision", "verdict"], off) + [""]
    return md


def other_section(new_dir: Path, tag: str, out: dict) -> list[str]:
    md = ["## gc / n64 / gba / nds / psp decompile success and discovery (`--corpus-wave`, default, n = 500, seeds 1,2)", ""]
    new = load(new_dir / f"console_research_wave_{tag}_other_combined.json")
    frozen = load(REPORTS / "console_research_wave_20261010.json")
    if not new:
        return md + ["not run", ""]
    rows, entries = wave_rows(new, frozen)
    out["other_platforms"] = {"tools": new.get("tools"), "frozen_tools": (frozen or {}).get("tools"), "images": entries}
    md += [f"Frozen = `console_research_wave_20261010` (tools `{(frozen or {}).get('tools')}`; the last wave that ran these images).", ""]
    md += table(WAVE_HEADER, rows) + [""]
    psp = load(new_dir / f"console_research_wave_{tag}_psp_n200_combined.json")
    if psp:
        rows = []
        out["psp_n200"] = {}
        for game, image in psp["images"].items():
            s = ((image.get("configs") or {}).get("default") or {}).get("summary")
            if not s:
                continue
            ref = PSP_N200.get(game)
            out["psp_n200"][game] = {"recall": s["recall"], "precision": s["precision"], "ps2precision": ref,
                                     "success_rate": s["success_rate"]}
            rows.append([game, s["decompiled"], fmt(s["success_rate"]), fmt(s["recall"]), fmt(ref[0] if ref else None),
                         fmt(s["precision"]), fmt(ref[1] if ref else None)])
        md += ["PSP at `-n 200` (Ps2Precision's measurement of 2026-10-12, overflow-checked build):", ""]
        md += table(["image", "decompiled", "success", "recall", "Ps2Precision recall", "precision", "Ps2Precision precision"], rows) + [""]
    return md


def gp7003_section(new_dir: Path, tag: str, out: dict) -> list[str]:
    md = ["## What GP-7003 changes on four images (same tree, build with and without it)", ""]
    old = load(new_dir / f"console_research_wave_old_{tag}.json")
    if not old:
        return md + ["not run", ""]
    arms = [load(new_dir / f"console_research_wave_{tag}_ps2_combined.json"), load(new_dir / f"console_research_wave_{tag}_other_combined.json")]
    keys = ("decompiled", "success_rate", "gotos", "labels", "lines", "native_warnings", "text_warnings", "recall", "precision")
    rows = []
    out["gp7003_effect"] = {}
    for game, image in old["images"].items():
        before = ((image.get("configs") or {}).get("default") or {}).get("summary")
        after = None
        for report in arms:
            candidate = ((((report or {}).get("images") or {}).get(game) or {}).get("configs") or {}).get("default")
            if candidate and "summary" in candidate:
                after = candidate["summary"]
        if not before or not after:
            continue
        out["gp7003_effect"][game] = {"without": {k: before.get(k) for k in keys}, "with": {k: after.get(k) for k in keys}}
        rows.append([game] + [f"{before.get(k)} -> {after.get(k)}" for k in ("decompiled", "gotos", "labels", "lines", "native_warnings", "recall", "precision")])
    md += ["`ghidra_opt` 15396033... (the tree's patch before GP-7003) -> 4561fbea... (with it), same cli and worker, each imported with its own build, "
           "`--corpus-wave` default config, n = 500, seeds 1,2.", ""]
    md += table(["image", "decompiled", "gotos", "labels", "lines", "native warnings", "recall", "precision"], rows) + [""]
    return md


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--new-dir", type=Path, default=REPORTS)
    parser.add_argument("--notes", type=Path, help="JSON with summary_md / explanations_md written by hand")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    out_base = args.out or REPORTS / f"combined_gate_{args.tag}"
    out: dict = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tag": args.tag}
    notes = json.loads(args.notes.read_text()) if args.notes else {}
    out["notes"] = notes
    md = [f"# Combined gate {args.tag}", ""]
    if notes.get("summary_md"):
        md += [notes["summary_md"], ""]
    md += m21_section(args.new_dir, args.tag, out)
    md += m22_section(args.new_dir, args.tag, out)
    md += success_section(args.new_dir, args.tag, out)
    md += ps2_wave_section(args.new_dir, args.tag, out)
    md += other_section(args.new_dir, args.tag, out)
    md += gp7003_section(args.new_dir, args.tag, out)
    if notes.get("explanations_md"):
        md += [notes["explanations_md"], ""]
    out_base.with_suffix(".json").write_text(json.dumps(out, indent=1, default=str) + "\n")
    out_base.with_suffix(".md").write_text("\n".join(md) + "\n")
    print(f"wrote {out_base.with_suffix('.json')} and {out_base.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
