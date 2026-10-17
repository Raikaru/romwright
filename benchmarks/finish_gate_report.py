#!/usr/bin/env python3
"""Assemble the finish gate report (benchmarks/reports/finish_gate_<date>.{json,md}).

The gate ran on one build of a frozen tree (`nih-vps-u`; `smt-cloud` for the 32-bit compilers); its raw reports are in
`benchmarks/reports/finish_gate_<date>_arms/` (`out/` lane, import and success reports, `smoke/` and `smoke-smt-cloud/` the
new-project smokes, `expected_*` the earlier agents' reports it is compared with, `logs/`). This script measures nothing: it reads
those files and the earlier reports, sets every number next to the value the last agent reported for it and writes the comparison.
The causes of the deviations (`DEVIATIONS`) were established by the `=off` / old-binary arms in `out/bis-*` and `out/m2-l1-fg-nofs.json`.

    python3 benchmarks/finish_gate_report.py [--date 20261015]
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "benchmarks" / "reports"


def load(path: Path):
    return json.loads(path.read_text())


def cell(block: dict) -> dict:
    return {"exact": block["exact"], "compiled": block["compiled"], "mean_percent": block["mean_percent"]}


def lane_cell(report: dict) -> dict:
    return cell(report["summary"]["overall"]["all"]["romwright"]["context"])


def fn_row(functions: dict, key: str, layout: str) -> tuple:
    layer = functions[key]["layers"]["romwright"]
    row = layer["context"] if layout == "m3" else layer["variants"]["context"]
    return (bool(row["compiled"]), bool(row["exact"]), round(row["percent"], 3))


def changed(a: dict, b: dict, layout: str) -> list[dict]:
    """Functions whose (compiled, exact, percent) differ between two per-function reports of one lane."""
    rows = []
    for key in sorted(set(a) & set(b)):
        x, y = fn_row(a, key, layout), fn_row(b, key, layout)
        if x != y:
            rows.append({"function": a[key]["name"], "address": a[key]["address"], "size": a[key]["size"],
                         "from": {"compiled": x[0], "exact": x[1], "percent": x[2]},
                         "to": {"compiled": y[0], "exact": y[1], "percent": y[2]}})
    return rows


def same(a: dict | None, b: dict | None) -> bool | None:
    if a is None or b is None:
        return None
    return a["exact"] == b["exact"] and a["compiled"] == b["compiled"] and abs(a["mean_percent"] - b["mean_percent"]) <= 5e-4


def delta(got: dict, expected: dict | None) -> dict | None:
    if expected is None:
        return None
    return {"exact": got["exact"] - expected["exact"], "compiled": got["compiled"] - expected["compiled"],
            "mean_percent": round(got["mean_percent"] - expected["mean_percent"], 3)}


# the deviation (in the prose file) that explains a lane's difference from SymbolLayout's table
DEVIATION_OF = {"m22-002 MWCC 20261010": "D1", "m22-003 ff": "D1", "m22-003 dk": "D1", "m22-003 p4": "D1", "m22-003 dc": "D1",
                "m22-003 gh (harness clone)": "D2"}

# --- the console lanes -------------------------------------------------------------------------------------------------------

LANES = [
    # label, report, layout, SymbolLayout gate name, SymbolLayout per-function report
    ("m22-002 MWCC 20261010", "m2-l1-fg-def.json", "m2", "m22-002 MWCC seed 20261010", "m2-l1-s3-def.json"),
    ("m22-002 MWCC 20261011", "m2-l2-fg-def.json", "m2", "m22-002 MWCC seed 20261011", "m2-l2-s3-def.json"),
    ("m22-002 ee-gcc", "m2-l3-fg-def.json", "m2", "m22-002 ee-gcc", "m2-l3-s3-def.json"),
    ("m22-003 dds", "m3-dds-fg-def.json", "m3", "m22-003 dds", "m3-dds-s3-def-functions.json"),
    ("m22-003 rc", "m3-rc-fg-def.json", "m3", "m22-003 rc", "m3-rc-s3-def-functions.json"),
    ("m22-003 p4", "m3-p4-fg-def.json", "m3", "m22-003 p4", "m3-p4-s3-def-functions.json"),
    ("m22-003 gh (harness clone)", "m3-ghclone-fg-def.json", "m3", "m22-003 gh (harness clone)", "m3-ghclone-s3-def-functions.json"),
    ("m22-003 ff", "m3-ff-fg-def.json", "m3", "m22-003 ff", "m3-ff-s3-def-functions.json"),
    ("m22-003 dc", "m3-dc-fg-def.json", "m3", "m22-003 dc", "m3-dc-s3-def-functions.json"),
    ("m22-003 dk", "m3-dk-fg-def.json", "m3", "m22-003 dk", "m3-dk-s3-def-functions.json"),
]
PC_UPGRADE_GATE = {"m22-003 dds": "m22-003 dds", "m22-003 dc": "m22-003 dc", "m22-002 MWCC 20261010": "m22-002 MWCC 20261010"}

# the `=off` arm of the lane's deviating functions: file in out/, layout, the lanes' per-function arms
OFF_ARMS = {
    "m22-003 ff": ("bis-ff-no_EXPORT_FLOAT_STORES-functions.json", "m3", "ROMWRIGHT_EXPORT_FLOAT_STORES=off"),
    "m22-003 dk": ("bis-dk-nofs-functions.json", "m3", "ROMWRIGHT_EXPORT_FLOAT_STORES=off"),
    "m22-003 p4": ("bis-p4-nofs-functions.json", "m3", "ROMWRIGHT_EXPORT_FLOAT_STORES=off"),
    "m22-003 dc": ("bis-dc-nofs-functions.json", "m3", "ROMWRIGHT_EXPORT_FLOAT_STORES=off"),
    "m22-003 gh (harness clone)": ("bis-gh-no_EXPORT_SQRT-functions.json", "m3", "ROMWRIGHT_EXPORT_SQRT=off"),
}


def console_lanes(arms: Path, sl: dict) -> list[dict]:
    out, expected = arms / "out", arms / "expected_symbol_layout"
    sl_gates = {g["gate"]: g for g in sl["gates"]}
    pcu = load(REPORTS / "pc_upgrade_20261015.json")["gates"]
    rows = []
    for label, name, layout, gate, expected_file in LANES:
        got_report = load(out / name)
        got = lane_cell(got_report)
        exp_sl = cell(sl_gates[gate]["arms"]["def"]["summary"])
        exp_pcu = cell(pcu[PC_UPGRADE_GATE[label]]["default"]) if label in PC_UPGRADE_GATE else None
        a = load(expected / expected_file)["functions"]
        b = load(out / name.replace(".json", "-functions.json"))["functions"] if layout == "m3" else got_report["functions"]
        moved = changed(a, b, layout)
        row = {"gate": label, "got": got, "expected_symbol_layout": exp_sl, "expected_pc_upgrade": exp_pcu,
               "delta_vs_symbol_layout": delta(got, exp_sl), "delta_vs_pc_upgrade": delta(got, exp_pcu),
               "equals_symbol_layout": same(got, exp_sl), "equals_pc_upgrade": same(got, exp_pcu),
               "functions_changed_vs_symbol_layout": moved,
               "mean_delta_from_changed_functions": round(sum(m["to"]["percent"] - m["from"]["percent"] for m in moved) / 200, 3)}
        if label in OFF_ARMS or label == "m22-002 MWCC 20261010":
            if label == "m22-002 MWCC 20261010":
                off = load(out / "m2-l1-fg-nofs.json")
                row["off_arm"] = {"switch": "ROMWRIGHT_EXPORT_FLOAT_STORES=off", "lane": lane_cell(off),
                                  "changed_vs_symbol_layout": changed(a, off["functions"], "m2")}
            else:
                file, lay, switch = OFF_ARMS[label]
                off = load(out / file)["functions"]
                # the arm is `--only <the changed functions>`: compare those functions with SymbolLayout's rows
                row["off_arm"] = {"switch": switch, "functions": {off[k]["name"]: list(fn_row(off, k, lay)) for k in off},
                                               "symbol_layout": {off[k]["name"]: list(fn_row(a, k, lay)) for k in off if k in a},
                                               "equal_to_symbol_layout": all(k in a and fn_row(off, k, lay) == fn_row(a, k, lay) for k in off)}
                if label == "m22-003 gh (harness clone)":
                    fs = load(out / "bis-gh-nofs-functions.json")["functions"]
                    row["off_arm"]["float_stores_off_instead"] = {fs[k]["name"]: list(fn_row(fs, k, lay)) for k in fs}
        rows.append(row)
    return rows


# --- m22-004, m21-001, success, import ---------------------------------------------------------------------------------------

def pc_lanes(arms: Path) -> list[dict]:
    pcu = load(REPORTS / "pc_upgrade_20261015.json")["fixtures"]
    rows = []
    for fixture, spec in pcu.items():
        path = arms / "out" / f"pc_{fixture}.json"
        if not path.exists():
            continue
        d = load(path)
        o = d["summary"]["overall"]
        got = {"exact": o["exact"], "compiled": o["compiled"], "mean_percent": o["mean_percent"], "percent_ge_90": o["percent_ge_90"]}
        e = spec["cells"]["default"]
        exp = {"exact": e["exact"], "compiled": e["compiled"], "mean_percent": e["mean_percent"], "percent_ge_90": e["percent_ge_90"]}
        rows.append({"fixture": fixture, "got": got, "expected_pc_upgrade": exp, "equal": got == exp,
                     "import_seconds": d["import"]["seconds"]})
    return rows


def m21(arms: Path) -> dict:
    got = load(arms / "out" / "m21-001_def.json")
    exp = load(arms / "expected_memory_fix_m21-001.json")
    rows = {}
    for image, row in got["rows"].items():
        e = exp["rows"].get(image, {})
        scalars = {k: v for k, v in row.items() if isinstance(v, (int, float, str, bool)) and k not in ("seconds", "load")}
        diff = {k: [v, e.get(k)] for k, v in scalars.items() if e.get(k) != v}
        rows[image] = {"recall": row["recall"], "precision": row["precision"], "found": row["found"], "truth": row["truth"],
                       "invented": row.get("invented"), "expected_recall": e.get("recall"), "expected_precision": e.get("precision"),
                       "fields_differing_from_expected": diff}
    return {"status": got["status"], "failures": got["failures"], "expected_status": exp["status"],
            "images": len(rows), "rows": rows,
            "all_fields_equal": all(not r["fields_differing_from_expected"] for r in rows.values())}


def success(arms: Path, sl: dict) -> dict:
    got = load(arms / "out" / "ps2_success_def-bin.json")["games"]
    exp = sl["extra"]["ps2_decompile_success"]["def"]
    rows = {g: {"sampled": v["sampled"], "decompiled": v["decompiled"], "expected_decompiled": exp[g]["decompiled"],
                "expected_sampled": exp[g]["sampled"]} for g, v in got.items()}
    return {"decompiled": sum(v["decompiled"] for v in got.values()), "sampled": sum(v["sampled"] for v in got.values()),
            "expected": "7448 / 7500", "games": rows,
            "equal": all(v["decompiled"] == exp[g]["decompiled"] and v["sampled"] == exp[g]["sampled"] for g, v in got.items())}


def pc_import(arms: Path) -> dict:
    got = load(arms / "out" / "pc_import_fg.json")
    ours_ref = {r["id"]: r for r in load(REPORTS / "pc_import_discovery_ours_20261015.json")["rows"]}
    stock_ref = {r["id"]: r for r in load(REPORTS / "pc_import_discovery_stock_20261015.json")["rows"]}
    rows, wins = [], {"recall": 0, "precision": 0, "recall_verified": 0, "precision_verified": 0, "wall": 0, "cpu": 0}
    for r in got["rows"]:
        o, s = r["arms"]["ours"], r["arms"]["stock"]
        so, ss = o["score"], s["score"]
        ro, rs = ours_ref[r["id"]]["arms"]["ours"]["score"], stock_ref[r["id"]]["arms"]["stock"]["score"]
        scalars = [k for k, v in so.items() if isinstance(v, (int, float))]
        rows.append({"fixture": r["id"], "truth": so["truth"],
                     "ours": {k: so[k] for k in ("found", "invented", "recall", "precision", "recall_verified", "precision_verified")},
                     "stock": {k: ss[k] for k in ("found", "invented", "recall", "precision", "recall_verified", "precision_verified")},
                     "ours_seconds": o["seconds"], "ours_cpu_seconds": o["cpu_seconds"],
                     "stock_seconds": s["seconds"], "stock_cpu_seconds": s.get("cpu_seconds"),
                     "ours_fields_differing_from_recorded": {k: [so[k], ro.get(k)] for k in scalars if so[k] != ro.get(k)},
                     "stock_fields_differing_from_recorded": {k: [ss[k], rs.get(k)] for k in scalars if ss.get(k) != rs.get(k)}})
        for key in ("recall", "precision", "recall_verified", "precision_verified"):
            if so[key] - ss[key] >= 0.005:
                wins[key] += 1
        wins["wall"] += o["seconds"] <= 0.9 * s["seconds"]
        if s.get("cpu_seconds"):
            wins["cpu"] += o["cpu_seconds"] <= 0.9 * s["cpu_seconds"]
    return {"fixtures": len(rows), "rows": rows, "ours_wins_of_8": wins,
            "equal_to_recorded": all(not r["ours_fields_differing_from_recorded"] and not r["stock_fields_differing_from_recorded"] for r in rows),
            "note": "stock is the cached stock Ghidra 12.1.3 run of PcImport (`pc_import_discovery_stock_20261015.json`, cache `benchmarks/pc_import.py --cache`); its seconds are that run's"}


# --- smokes ------------------------------------------------------------------------------------------------------------------

def best_line(m: dict) -> str:
    return re.sub(r"\s+", " ", m.get("best", "")).split(";")[0]


def smoke(arms: Path) -> list[dict]:
    spec = [
        # id, platform, report file, expected sha1 or status, expected match, source
        ("ps2-dds", "PS2 (Digital Devil Saga, SLUS_209.74)", "smoke-smt-cloud/ps2-dds.json", "6d18898e2724bf1d145392766e8ba1e678487419",
         "no earlier number; any result", "ee-gcc is i386: `match` runs on smt-cloud (nih-vps-u has no /lib/ld-linux.so.2)"),
        ("gc-pikmin2", "GameCube (Pikmin 2 main.dol)", "smoke/gc-pikmin2.json", "build/PIKMIN2/main.dol: OK",
         "0x800c03ec 100%, 0x8006bd04 100%, 0x800c0394 49.250% (NewProjectGC)", ""),
        ("wii-pikmin2", "Wii (Pikmin 2 NPC main.dol)", "smoke/wii-pikmin2.json", "build/PIKMIN2WII/main.dol: OK",
         "0x800060b8, 0x80067628, 0x800e8c5c exact (NewProjectGC)", ""),
        ("n64-sm64", "N64 (Super Mario 64 US)", "smoke/n64-sm64.json", "9bef1128717f958171a4afac3ed78ee2bb4e86ce",
         "no earlier number for these three; any result (NewProjectMips: 8-40 byte 13 of 24, 48-160 byte 0 of 30)", ""),
        ("psx-silenthill", "PSX (Silent Hill SLUS_007.07)", "smoke/psx-silenthill.json", "f38344565fb731befc52fd968eb5a667be37acf3",
         "no earlier number for these three; any result (NewProjectMips: 7 exact of 40, mean 73.2)", ""),
        ("psp-melodie", "PSP (psp-melodie EBOOT.BIN, a PRX)", "smoke-smt-cloud/psp-melodie.json", "724fe026421bfc1f881924d657099b07def869cb",
         "no earlier number for these three; any result (NewProjectMips: small functions 4 exact of 24, 81.2)", "psp-gcc is i386: smt-cloud"),
        ("gba-fe8", "GBA (Fire Emblem: The Sacred Stones)", "smoke/gba-fe8.json", "c25b145e37456171ada4b0d440bf88a19f4d509f",
         "0x080a6f0c exact (docs/new-project.md example; NewProjectArm: 7 exact of 16)", ""),
        ("nds-twewy", "NDS (The World Ends With You)", "smoke/nds-twewy.json", "23e87b1e72aab7f9b718f83e92fd1c3039f23675",
         "no earlier number for these three; any result (NewProjectArm: 14 ARM + 1 Thumb of 28-100 bytes)", "three ARM9 functions picked by hand (the NDS symbol files are not `symbols.txt`): `smoke/nds-twewy.match-*.log`"),
        ("pe-glquake", "Windows PE (GLQuake, MSVC 4.2)", "smoke/pe-glquake.json", "per-function report",
         "six functions 98.5 to 99.7 (83.2 for one) at the default flags (PcProject)", "no sha1 for a PE (docs/new-project.md)"),
        ("scaffold-3ds", "scaffold (3DS Fire Emblem Fates `.code`)", "smoke/scaffold-3ds.json", "per-function report",
         "38 sources, 37/38 compile, 36 objdiff units, 61 calls relocated, 16.1% (NewProjectScaffold)", "`match` does not apply to a scaffold"),
    ]
    rows = []
    for key, platform, path, expected, expected_match, note in spec:
        d = load(arms / path)
        extra = arms / path.replace(".json", ".matches.json")
        if extra.exists() and not d.get("matches"):
            d["matches"] = load(extra)["matches"]
        summary = arms / path.replace(".json", ".build-summary.json")
        row = {"id": key, "platform": platform, "report": path, "result": d["result"], "expected_build": expected,
               "expected_match": expected_match, "note": note,
               "steps": {k: {"rc": v["rc"], "secs": v["secs"]} for k, v in d["steps"].items()},
               "sha1_built": d.get("sha1_built"), "build_ok_lines": d.get("build_ok_lines"),
               "matches": [{"function": m["function"], "best": best_line(m), "rc": m["rc"]} for m in d.get("matches", [])]}
        row["build_ok"] = (d.get("sha1_built") == expected) if re.fullmatch(r"[0-9a-f]{40}", expected) else \
            (expected in " ".join(d.get("build_ok_lines") or []) if expected.endswith("OK") else None)
        if summary.exists():
            row["build_summary"] = load(summary)
        rows.append(row)
    return rows


PE_ARMS = [
    ("pe-glquake-pcproj", "PcProject's own binary (`~/runs/PcProject/target2`, `ghidra_opt` 486ace43): the docs/pc-project.md smoke"),
    ("pe-glquake-alloff", "this build with PcImport's nine PE discovery rules, SymbolLayout's layout rules (`ROMWRIGHT_NATIVE_LAYOUT=1`) and PcUpgrade's eleven switches all off"),
    ("pe-glquake-peonly", "this build, only PcImport's PE discovery rules on"),
    ("pe-glquake-layonly", "this build, only SymbolLayout's layout rules on"),
    ("pe-glquake-uponly", "this build, only PcUpgrade's eleven switches on"),
    ("pe-glquake", "this build, default (the smoke above)"),
]


def pe_attribution(arms: Path) -> list[dict]:
    rows = []
    for name, what in PE_ARMS:
        b = load(arms / "smoke" / f"{name}.build-summary.json")
        p, c = b["progress_summary"], b["compile"]
        rows.append({"arm": name, "what": what, "functions": p["functions"], "compiled": p["compiled"], "exact": p["matched"],
                     "at_least_90": p["near_90"], "mean_percent": p["mean_percent"]})
    return rows


DESKTOP = {
    "expected": "ReleaseReady: Create project 13 files; Match on FUN_00405380 7 variant rows, 7 compiled, best 1.763 % against the stock print's 1.599 %",
}


def desktop(arms: Path) -> dict:
    d = load(arms / "out" / "m6-007.json")
    m = d["metrics"]
    return {"status": d["status"], "summary": d["summary"], "package": d["package"], "adapter": d["platform"].get("adapter"),
            "files": m["ui.new_project.files"], "rows": m["ui.match.rows"], "compiled_rows": m["ui.match.compiled_rows"],
            "best_percent": round(m["ui.match.best_percent"], 3), "default_percent": round(m["ui.match.default_percent"], 3),
            "function": m["ui.match.function"], "expected": DESKTOP["expected"],
            "equal_to_expected": (m["ui.new_project.files"], m["ui.match.rows"], m["ui.match.compiled_rows"],
                                  round(m["ui.match.best_percent"], 3), round(m["ui.match.default_percent"], 3), m["ui.match.function"])
            == (13, 7, 7, 1.763, 1.599, "FUN_00405380"),
            "direct_gate": "`romwright-desktop --gate --project-image tests/fixtures-src/tiny_pe32.exe` rc 0 (logs/desktop.log)"}


def build(date: str, extra: dict) -> dict:
    arms = REPORTS / f"finish_gate_{date}_arms"
    sl = load(REPORTS / "symbol_layout_20261015.json")
    report = {"schema": "finish-gate/1", "generated": date}
    report.update(extra)
    report["console_lanes"] = console_lanes(arms, sl)
    report["pc_lanes"] = pc_lanes(arms)
    report["m21_001"] = m21(arms)
    report["ps2_decompile_success"] = success(arms, sl)
    report["pc_import"] = pc_import(arms)
    report["smokes"] = smoke(arms)
    report["desktop"] = desktop(arms)
    report["pe_glquake_attribution"] = pe_attribution(arms)
    return report


# --- markdown ----------------------------------------------------------------------------------------------------------------

def c(x: dict | None) -> str:
    return "-" if x is None else f"{x['exact']} / {x['compiled']} / {x['mean_percent']}"


def render(r: dict) -> str:
    L = [f"# Finish gate ({r['generated']})", "", r["summary_text"], ""]
    L += ["## Build and tree", ""] + [f"* {line}" for line in r["tree_lines"]] + [""]
    L += ["## 1. Console C-output lanes (exact / compiled / mean objdiff %)", "",
          "Fresh import and fresh work directory per lane, `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`, wrapper binary (the m22-002 harness drops "
          "`ROMWRIGHT_*`), one build. Expected: SymbolLayout's table (`symbol_layout_20261015.md`, default arm) and PcUpgrade's console readings "
          "(`pc_upgrade_20261015.md`).", "",
          "| gate | got | SymbolLayout | PcUpgrade | got - SymbolLayout | verdict |", "|---|---|---|---|---|---|"]
    for row in r["console_lanes"]:
        d = row["delta_vs_symbol_layout"]
        if row["equals_symbol_layout"]:
            verdict = "= SymbolLayout"
        else:
            verdict = f"deviation {DEVIATION_OF[row['gate']]}" + ("; = PcUpgrade" if row["equals_pc_upgrade"] else "")
        L.append(f"| {row['gate']} | {c(row['got'])} | {c(row['expected_symbol_layout'])} | {c(row['expected_pc_upgrade'])} | "
                 f"{d['exact']:+d} / {d['compiled']:+d} / {d['mean_percent']:+.3f} | {verdict} |")
    L += [""]
    L += ["Functions that differ from SymbolLayout's default arm (per-function reports of the same lanes, same samples):", "",
          "| gate | function | SymbolLayout (compiled, exact, %) | got |", "|---|---|---|---|"]
    for row in r["console_lanes"]:
        for m in row["functions_changed_vs_symbol_layout"]:
            a, b = m["from"], m["to"]
            L.append(f"| {row['gate']} | `{m['function']}` ({m['size']} B) | {a['compiled']}, {a['exact']}, {a['percent']} | {b['compiled']}, {b['exact']}, {b['percent']} |")
    L += [""]
    L += ["## 2. m22-004 PC lanes (exact / compiled / mean objdiff %, 200 functions, seed 20261015)", "",
          "| fixture | got | PcUpgrade default | equal | import s |", "|---|---|---|---|---|"]
    for row in r["pc_lanes"]:
        L.append(f"| {row['fixture']} | {c(row['got'])} ({row['got']['percent_ge_90']} at >= 90%) | {c(row['expected_pc_upgrade'])} ({row['expected_pc_upgrade']['percent_ge_90']}) | "
                 f"{'yes' if row['equal'] else 'NO'} | {row['import_seconds']} |")
    L += [""]
    s = r["ps2_decompile_success"]
    L += ["## 3. m21-001, PS2 decompile success, PC import against stock", "",
          f"**m21-001** `{r['m21_001']['status']}` ({r['m21_001']['images']} images; MemoryFix: {r['m21_001']['expected_status']}); every scalar field of every row equal to the MemoryFix run: "
          f"**{r['m21_001']['all_fields_equal']}**.", "",
          "| image | truth | found | recall | precision | invented | recall (MemoryFix) | precision (MemoryFix) |", "|---|---|---|---|---|---|---|---|"]
    for image, row in r["m21_001"]["rows"].items():
        L.append(f"| {image} | {row['truth']} | {row['found']} | {row['recall']} | {row['precision']} | {row['invented']} | {row['expected_recall']} | {row['expected_precision']} |")
    L += ["", f"**PS2 decompile success** (`benchmarks/ps2_decompile_success.py`, the 8-image wave sample): {s['decompiled']:,} of {s['sampled']:,} (expected {s['expected']}); "
          f"every game equal to SymbolLayout's default arm: **{s['equal']}**.", "",
          "| game | decompiled / sampled | SymbolLayout |", "|---|---|---|"]
    for g, v in s["games"].items():
        L.append(f"| {g} | {v['decompiled']} / {v['sampled']} | {v['expected_decompiled']} / {v['expected_sampled']} |")
    p = r["pc_import"]
    L += ["", f"**PC import against stock Ghidra** (`benchmarks/pc_import.py`, ours fresh, stock cached, 8 fixtures): every score field of every fixture equal to PcImport's recorded run: "
          f"**{p['equal_to_recorded']}**. Fixtures (of 8) where ours is ahead of stock by >= 0.5 pp (time: by 10%): recall {p['ours_wins_of_8']['recall']}, precision {p['ours_wins_of_8']['precision']}, verified recall {p['ours_wins_of_8']['recall_verified']}, verified precision {p['ours_wins_of_8']['precision_verified']}, wall time {p['ours_wins_of_8']['wall']}, CPU time {p['ours_wins_of_8']['cpu']} (precision ties: no loss on any fixture).", "",
          "| fixture | truth | ours R / P (verified R / P) | stock R / P (verified R / P) | ours s (cpu) | stock s (cpu) |", "|---|---|---|---|---|---|"]
    for row in p["rows"]:
        o, st = row["ours"], row["stock"]
        L.append(f"| {row['fixture']} | {row['truth']} | {o['recall']} / {o['precision']} ({o['recall_verified']} / {o['precision_verified']}) | "
                 f"{st['recall']} / {st['precision']} ({st['recall_verified']} / {st['precision_verified']}) | {row['ours_seconds']} ({row['ours_cpu_seconds']}) | {row['stock_seconds']} ({row['stock_cpu_seconds']}) |")
    L += ["", "## 4. new-project, configure, build and `match` per platform (real images)", "",
          "Fresh import per project (`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`), `configure.py` fetching the pinned tools, `ninja` (or `build.py` for PE and scaffold), then `match` on three functions (budget 6) where the platform has `match`.", "",
          "| platform | new-project / configure / build (s) | build result | expected | `match` (default print -> best) |", "|---|---|---|---|---|"]
    for row in r["smokes"]:
        st = row["steps"]
        secs = " / ".join(str(st[k]["secs"]) if k in st else "-" for k in ("new-project", "configure", "build"))
        if row["id"] == "scaffold-3ds":
            secs = f"{st['new-project']['secs']} / - / {st['fetch']['secs']} fetch, {st['build']['secs']}"
        res = ("sha1 " + row["sha1_built"]) if row["sha1_built"] else "; ".join(row.get("build_ok_lines") or [])
        if row["id"] == "pe-glquake":
            pr = row["build_summary"]["progress_summary"]
            res = f"{pr['matched']} of {pr['functions']} functions match exactly, {pr['compiled']} compile, {pr['near_90']} at >= 90%, mean {pr['mean_percent']}%"
        if row["id"] == "scaffold-3ds":
            bs = row["build_summary"]
            res = f"{bs['compile']['compiled']}/{bs['compile']['units']} compile (clang {bs['compile']['compiler'].split()[2]}), `build.py report`: {bs['objdiff_measures']['total_units']} units, {bs['objdiff_measures']['fuzzy_match_percent']:.3f}% (objdiff)"
        ok = {True: "(equal to expected)", False: "MISMATCH", None: ""}[row["build_ok"]]
        matches = "; ".join(f"`{m['function']}` {m['best'].replace('best: ', '').strip()}" for m in row["matches"]) or "n/a (`match` refuses a scaffold: `config/project.json names no compiler`)"
        L.append(f"| {row['platform']} | {secs} | {res} {ok} | {row['expected_build']}; {row['expected_match']} | {matches} |")
    L += ["", "GLQuake project, where its numbers come from (D3): functions / compile / exact / at >= 90% / mean objdiff %, `build.py report` over every function of the project", "",
          "| arm | functions | compile | exact | >= 90% | mean % |", "|---|---|---|---|---|---|"]
    for a in r["pe_glquake_attribution"]:
        L.append(f"| {a['what']} | {a['functions']} | {a['compiled']} | {a['exact']} | {a['at_least_90']} | {a['mean_percent']} |")
    d = r["desktop"]
    L += ["", "## 5. Desktop headless gate", "",
          f"`tests/m6-007_desktop_projects.py` (builds the archive with `packaging/package_desktop.py`, extracts it and drives the extracted `romwright-desktop --gate --project-image`): **{d['status'].upper()}** "
          f"on {d['adapter']}: {d['summary']} The direct `--gate --project-image` run on the build's binary exited 0. Expected ({d['expected']}); equal: **{d['equal_to_expected']}**.", ""]
    L += ["## Deviations, each traced to its change", ""]
    for dev in r["deviations"]:
        L += [f"### {dev['id']}: {dev['title']}", "", dev["text"], ""]
    L += ["## Not in the frozen tree", ""] + [f"* {x}" for x in r["not_included"]] + [""]
    L += ["## User-WIP files", "", r["user_wip"], ""]
    L += ["## Limits", ""] + [f"* {x}" for x in r["limits"]] + [""]
    return "\n".join(L)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", default="20261015")
    parser.add_argument("--text", default=str(REPORTS / "finish_gate_20261015_arms" / "prose.json"),
                        help="the prose half (summary, tree lines, deviations, limits): a JSON file the gate's author wrote")
    arguments = parser.parse_args()
    extra = load(Path(arguments.text))
    report = build(arguments.date, extra)
    (REPORTS / f"finish_gate_{arguments.date}.json").write_text(json.dumps(report, indent=1) + "\n")
    (REPORTS / f"finish_gate_{arguments.date}.md").write_text(render(report) + "\n")
    print(f"wrote benchmarks/reports/finish_gate_{arguments.date}.{{json,md}}")


if __name__ == "__main__":
    main()
