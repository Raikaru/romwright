#!/usr/bin/env python3
"""The PC import report: per-fixture recall/precision/time against stock Ghidra, sign tests, the PE rules'
leave-one-out, compiler detection accuracy and the no-truth rows, as `benchmarks/reports/pc_import_<date>.{json,md}`.

Inputs are the outputs of the tools that measured them:

* `--ours`, `--stock`   `benchmarks/pc_import.py` reports (arms `ours` and `stock`; discovery only);
* `--wave`              the `console_research.py --corpus-wave --images pc-... --stock --no-truth ...` report
                        (decompile success, stock on the sampled addresses, the no-truth rows);
* `--loo`               `benchmarks/pc_rules_loo.py`;
* `--detect`            `benchmarks/compiler_detection_accuracy.py` (fixtures and controls).

    benchmarks/pc_import_report.py --ours A.json --stock B.json --wave W.json --loo L.json --detect D.json \\
        --out benchmarks/reports/pc_import_20261015
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import console_research_wave as wave  # noqa: E402


def load(path: str | None):
    return json.loads(Path(path).read_text()) if path else None


def arms(report: dict | None, name: str) -> dict:
    return {row["id"]: row["arms"].get(name) for row in (report or {}).get("rows", []) if "arms" in row}


def fmt(value, digits: int = 4) -> str:
    return "-" if value is None else (f"{value:.{digits}f}" if isinstance(value, float) else str(value))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ours", required=True)
    p.add_argument("--stock", required=True)
    p.add_argument("--wave")
    p.add_argument("--loo")
    p.add_argument("--detect")
    p.add_argument("--baseline", help="a pc_import.py ours report of the tree before the PE rules")
    p.add_argument("--repeats", nargs="*", default=[], help="more `pc_import.py --arms ours` reports of the same tree: "
                   "the time columns are the median of all runs (the scores of the first are reported)")
    p.add_argument("--out", required=True, help="path prefix; .json and .md are written")
    p.add_argument("--note", default="")
    args = p.parse_args()
    ours_report, stock_report = load(args.ours), load(args.stock)
    ours, stock = arms(ours_report, "ours"), arms(stock_report, "stock")
    import statistics
    runs = [ours] + [arms(load(path), "ours") for path in args.repeats]
    for fixture, o in ours.items():
        seconds = [run[fixture]["seconds"] for run in runs if fixture in run and "seconds" in run[fixture]]
        cpus = [run[fixture].get("cpu_seconds") for run in runs if fixture in run and run[fixture].get("cpu_seconds") is not None]
        o["seconds_runs"] = seconds
        o["seconds"] = round(statistics.median(seconds), 2)
        if cpus:
            o["cpu_seconds"] = round(statistics.median(cpus), 2)
    baseline = arms(load(args.baseline), "ours")
    wave_report, loo, detect = load(args.wave), load(args.loo), load(args.detect)
    meta = {}
    for fixture in ours:
        path = Path.home() / "romwright-corpus" / "extracted" / fixture / "truth" / "meta.json"
        if path.is_file():
            meta[fixture] = json.loads(path.read_text())
    rows = []
    for fixture, o in ours.items():
        s = stock.get(fixture) or {}
        row = {"id": fixture, "compiler": (meta.get(fixture) or {}).get("compiler"),
               "arch": (meta.get(fixture) or {}).get("arch"), "truth_functions": o["score"]["truth"],
               "ours": {k: o["score"][k] for k in ("recall", "precision", "recall_verified", "precision_verified",
                                                   "hits", "invented", "found")}
                       | {"seconds": o["seconds"], "cpu_seconds": o.get("cpu_seconds"), "load": o.get("load_at_start")}}
        if "score" in s:
            row["stock"] = {k: s["score"][k] for k in ("recall", "precision", "recall_verified", "precision_verified",
                                                       "hits", "invented", "found")} | {
                "seconds": s["seconds"], "cpu_seconds": s.get("cpu_seconds"), "load": s.get("load_at_start"),
                "ghidra_compiler": s.get("ghidra_compiler")}
        if fixture in baseline and "score" in baseline[fixture]:
            b = baseline[fixture]["score"]
            row["before_rules"] = {"recall": b["recall"], "precision": b["precision"], "invented": b["invented"]}
        elif loo and fixture in (loo["rules"].get("ALL") or {}) and "recall" in loo["rules"]["ALL"][fixture]:
            # every PE rule switched off (the leave-one-out's ALL arm) is the importer as it was before them
            a = loo["rules"]["ALL"][fixture]
            row["before_rules"] = {"recall": a["recall"][0], "precision": a["precision"][0], "invented": a["invented"][0]}
        if wave_report:
            image = (wave_report.get("images") or {}).get(fixture) or {}
            default = (image.get("configs") or {}).get("default") or {}
            summary = default.get("summary") or {}
            row["export_c"] = {"success_rate": summary.get("success_rate"), "sampled": summary.get("sampled"),
                               "median_seconds": summary.get("median_seconds")}
            stock_wave = (image.get("stock") or {}).get("combined", {}).get("summary") or {}
            if stock_wave:
                row["export_c"]["stock_decompile_success"] = stock_wave.get("success_rate")
        rows.append(row)
    both = [r for r in rows if "stock" in r]
    tests = {}
    for metric in ("recall", "precision", "recall_verified", "precision_verified"):
        pairs = [(r["ours"][metric], r["stock"][metric]) for r in both
                 if r["ours"][metric] is not None and r["stock"][metric] is not None]
        tests[metric] = wave.sign_test(pairs)
    # time: ours is a win when it is faster by 10% (wall), the unit being a fixture
    tests["wall_time"] = wave.sign_test([(r["stock"]["seconds"] / max(r["ours"]["seconds"], 1e-9),
                                          1.0) for r in both], threshold=0.1)
    cpu_pairs = [(r["stock"]["cpu_seconds"] / max(r["ours"]["cpu_seconds"], 1e-9), 1.0) for r in both
                 if r["stock"].get("cpu_seconds") and r["ours"].get("cpu_seconds")]
    if cpu_pairs:
        tests["cpu_time"] = wave.sign_test(cpu_pairs, threshold=0.1)
    report = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "note": args.note,
              "tools": ours_report.get("tools"), "fixtures": rows, "sign_tests": tests,
              "rules_loo": loo, "detector": detect,
              "no_truth": (wave_report or {}).get("no_truth")}
    Path(args.out + ".json").write_text(json.dumps(report, indent=1) + "\n")
    lines = [f"# PC import: Windows PE / x86 against stock Ghidra ({report['generated']})", "", args.note, "",
             "Discovery on the staged (stripped) image of every `pc-*` truth fixture: our `romwright-cli import` and "
             "stock Ghidra 12.1.3 `analyzeHeadless` (default analyzers, the PE loader's own language and compiler), both "
             "scored by `console_research_wave.score_found` over the image's executable sections "
             "(`benchmarks/pc_import.py`; docs/console-research.md \"Windows PC\"). `verified` = every truth row "
             "(boundary is the compiler's or linker's).", "",
             "## Recall, precision, time", "",
             "| fixture | compiler | truth | ours R | ours P | stock R | stock P | dR | dP | ours s (cpu), median of 3 | stock s (cpu) |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        o, s = r["ours"], r.get("stock")
        if s:
            lines.append(
                f"| {r['id']} | {(r['compiler'] or '')[:22]} | {r['truth_functions']} | {fmt(o['recall'])} | {fmt(o['precision'])} | "
                f"{fmt(s['recall'])} | {fmt(s['precision'])} | {o['recall'] - s['recall']:+.4f} | "
                f"{o['precision'] - s['precision']:+.4f} | {o['seconds']} ({fmt(o.get('cpu_seconds'), 1)}) | "
                f"{s['seconds']} ({fmt(s.get('cpu_seconds'), 1)}) |")
        else:
            lines.append(f"| {r['id']} | | {r['truth_functions']} | {fmt(o['recall'])} | {fmt(o['precision'])} | "
                         f"stock: no result | | | | {o['seconds']} | |")
    lines += ["", "Verified supplement (the same, over `verified=1` rows; `precision_verified` counts only entries inside a "
              "verified function's extent):", "", "| fixture | ours Rv | ours Pv | stock Rv | stock Pv |", "|---|---|---|---|---|"]
    for r in rows:
        o, s = r["ours"], r.get("stock") or {}
        lines.append(f"| {r['id']} | {fmt(o['recall_verified'])} | {fmt(o['precision_verified'])} | "
                     f"{fmt(s.get('recall_verified'))} | {fmt(s.get('precision_verified'))} |")
    lines += ["", "## Sign tests (ours against stock, over fixtures; win = ahead by at least 0.5 pp, time by 10%)", "",
              "| metric | fixtures | wins | losses | ties | p (one-sided) |", "|---|---|---|---|---|---|"]
    for metric, t in tests.items():
        lines.append(f"| {metric} | {t['games']} | {t['wins']} | {t['losses']} | {t['ties']} | {t['p_value']} |")
    if any("before_rules" in r for r in rows):
        lines += ["", "## Before the PE rules (the tree this work started from)", "",
                  "Every PE rule switched off (`ROMWRIGHT_COMPILER_RULES_DISABLE`, the leave-one-out's `ALL` arm) on the final truth: the importer as it was.", "",
                  "| fixture | before R | before P | before invented | now R | now P | now invented |", "|---|---|---|---|---|---|---|"]
        for r in rows:
            b = r.get("before_rules")
            if b:
                lines.append(f"| {r['id']} | {fmt(b['recall'])} | {fmt(b['precision'])} | {b['invented']} | "
                             f"{fmt(r['ours']['recall'])} | {fmt(r['ours']['precision'])} | {r['ours']['invented']} |")
    if wave_report:
        lines += ["", "## Decompiled C (export-c) on a sample of each fixture's functions", "",
                  "| fixture | sampled | export-c success | stock decompile success |", "|---|---|---|---|"]
        for r in rows:
            e = r.get("export_c") or {}
            lines.append(f"| {r['id']} | {e.get('sampled', '-')} | {fmt(e.get('success_rate'))} | "
                         f"{fmt(e.get('stock_decompile_success'))} |")
    if loo:
        fixtures = list(loo["baseline"])
        lines += ["", "## Leave-one-out of the PE rules (`benchmarks/pc_rules_loo.py`)", "",
                  "Each rule switched off against all on, every fixture: `R off->on`, `P off->on`. `derived_from` fixtures "
                  "are the ones a rule was written on (never evidence for it).", "",
                  "| rule | " + " | ".join(f.removeprefix("pc-") for f in fixtures) + " |", "|---|" + "---|" * len(fixtures)]
        for rule, cell in loo["rules"].items():
            row = []
            for f in fixtures:
                c = cell[f]
                row.append(c["verdict"] if "recall" not in c else
                           f"{c['verdict']} R {c['recall'][0]:.4f}>{c['recall'][1]:.4f} P {c['precision'][0]:.4f}>{c['precision'][1]:.4f}")
            lines.append(f"| {rule} | " + " | ".join(row) + " |")
    if detect:
        lines += ["", "## Compiler detection", "", "| image | truth | detected | verdict | evidence |", "|---|---|---|---|---|"]
        for g in detect["games"]:
            lines.append(f"| {g['game']} | {g.get('truth') or '-'} | {g.get('detected', '-')} | {g.get('verdict', g.get('status'))} | "
                         f"{(g.get('evidence') or '').split('): ', 1)[-1][:90]} |")
        for c in detect.get("controls", []):
            lines.append(f"| {c['name']} (control) | {c['truth']} | {c.get('detected', '-')} | {c.get('verdict', c.get('status'))} | "
                         f"{(c.get('evidence') or '').split('): ', 1)[-1][:90]} |")
        lines += ["", f"Totals: {detect.get('totals')}"]
    if report["no_truth"]:
        lines += ["", "## No-truth rows (success and time only)", "",
                  "| image | size | import s | functions | export-c ok | stock s | stock functions | both / ours only / stock only |",
                  "|---|---|---|---|---|---|---|---|"]
        for row in report["no_truth"].values():
            st = row.get("stock") or {}
            ag = st.get("agreement") or {}
            lines.append(f"| {row['id']} | {row.get('size', 0):,} | {row['import']['seconds']} | {row['import']['functions']} | "
                         f"{row['decompile']['success']}/{row['decompile']['sampled']} | {st.get('seconds', st.get('failure', ''))} | "
                         f"{st.get('functions', '')} | {ag.get('both', '')} / {ag.get('ours_only', '')} / {ag.get('stock_only', '')} |")
    Path(args.out + ".md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:40]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
