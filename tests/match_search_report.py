#!/usr/bin/env python3
"""Roll the m22-003 `--search` arms up into benchmarks/reports/match_search_<date>.{json,md}.

For each lane two reports are read (written by the lane harness, tests/m22-003_ps2_multigame_c.py):

  <lane>-<tag>-def.json   the default arm: a fresh import, the romwright layer as every earlier run of the lane
  <lane>-<tag>-s<N>.json  the search arm: a fresh import, the `romwright` layer (the default print) and the
                          `romwright-search` layer (the best of the near-miss search's prints per function)

The table is the headline (`context`) compile of the lane harness, objdiff `match_percent` with functionRelocDiffs=none,
`exact` = same length and every byte equal outside relocation fields. Only functions whose default print compiles and is
not exact are searched; the rest keep their default print in the search layer.

    python3 tests/match_search_report.py --dir ~/runs/MatchSearch/out --tag m1 --budget 24 --runs ~/runs/MatchSearch/logs/runs.log \
        --out benchmarks/reports/match_search_20261014
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

# The default-arm baseline table of the brief: lane -> (exact, compiled, mean percent).
BASELINE = {"dds": (61, 200, 77.224), "rc": (26, 200, 68.158), "p4": (60, 193, 79.4), "gh": (78, 199, 82.119),
            "ff": (21, 195, 61.753), "dc": (38, 186, 69.844), "dk": (29, 189, 75.561)}
ORDER = ["dds", "rc", "p4", "gh", "ff", "dc", "dk"]
# The m22-002 lanes (tests/m22-002_ps2_c_output.py on the Persona 4 decompilation): label -> (file stem, baseline of the brief).
M22_002 = {"m22-002 MWCC seed 20261010": ("m2-l1", (55, 193, 76.968)), "m22-002 MWCC seed 20261011": ("m2-l2", (57, 194, 78.316)),
           "m22-002 ee-gcc": ("m2-l3", (106, 197, 86.403))}


def block(report, layer, variant="context"):
    b = report["summary"]["overall"]["all"][layer][variant]
    return {"functions": b["functions"], "exact": b["exact"], "compiled": b["compiled"], "mean_percent": b["mean_percent"]}


def runs_seconds(path, tag):
    seconds = {}
    if path and Path(path).exists():
        for line in Path(path).read_text().splitlines():
            found = re.match(rf"run {re.escape(tag)} (\S+) (\S+) rc=(\d+) secs=(\d+)", line)
            if found:
                seconds[(found.group(1), found.group(2))] = int(found.group(4))
            found = re.match(rf"m2 {re.escape(tag)} l(\d) (\S+) rc=(\d+) secs=(\d+)", line)
            if found:
                seconds[(f"m2-l{found.group(1)}", found.group(2))] = int(found.group(4))
    return seconds


def classify(entry):
    """The byte-difference class of a candidate's context compile, when the harness recorded one."""
    diff = entry["variants"]["context"].get("diff")
    if isinstance(diff, dict):
        kind = diff.get("kind") or "unclassified"
        return kind.split(":")[0] if kind.startswith("single instruction") or kind.startswith("same length") else kind
    return "unclassified"


def lane_row(lane, directory, tag, budget, seconds, stem=None, baseline=None, harness="m22-003"):
    """`stem` is the report file prefix (`<lane>` for m22-003 lanes, `m2-l<n>` for m22-002 ones)."""
    stem = stem or lane
    default = json.loads((directory / f"{stem}-{tag}-def.json").read_text())
    searched = json.loads((directory / f"{stem}-{tag}-s{budget}.json").read_text())
    functions = searched["functions"]
    improved, newly_exact, histogram, classes_improved = [], 0, collections.Counter(), collections.Counter()
    classes_searched = collections.Counter()
    decompiles = compiles = searched_count = 0
    search_seconds = 0.0
    percent_gain = 0.0
    for key, entry in functions.items():
        base, best = entry["layers"]["romwright"]["variants"]["context"], entry["layers"]["romwright-search"]["variants"]["context"]
        search = entry["layers"]["romwright-search"]["produce"].get("search")
        if search:
            classes_searched[classify(entry["layers"]["romwright"])] += 1
            searched_count += 1
            decompiles += search["decompiles"]
            compiles += search["compiles"]
            search_seconds += search["seconds"]
        gain = best["percent"] - base["percent"]
        got_exact = best["exact"] and not base["exact"]
        if search and (gain > 1e-9 or got_exact):
            improved.append({"name": entry["name"], "address": entry["address"], "variant": search["winner"], "from": round(base["percent"], 3),
                             "to": round(best["percent"], 3), "exact_gained": got_exact, "size": entry["size"]})
            histogram[search["winner"]] += 1
            percent_gain += gain
            newly_exact += got_exact
            classes_improved[classify(entry["layers"]["romwright"])] += 1
        elif search and gain < -1e-9:
            raise SystemExit(f"{lane} {entry['name']}: the searched print scores below the default ({best['percent']} < {base['percent']})")
    in_run_default = block(searched, "romwright")
    baseline = baseline or BASELINE.get(lane)
    default_arm = block(default, "romwright")
    row = {
        "lane": lane, "harness": harness, "game": searched.get("game", "ps2-persona-4"), "functions": default_arm["functions"],
        "default": default_arm,
        "default_in_search_run": in_run_default,
        "default_equals_baseline_table": baseline is not None and (default_arm["exact"], default_arm["compiled"], round(default_arm["mean_percent"], 3)) == baseline,
        "default_arms_agree": default_arm == in_run_default,
        "searched": block(searched, "romwright-search"),
        "searched_standalone": block(searched, "romwright-search", "standalone"),
        "default_standalone": block(searched, "romwright", "standalone"),
        "functions_searched": searched_count,
        "functions_improved": len(improved),
        "newly_exact": newly_exact,
        "improved_percent_points": round(percent_gain, 3),
        "winners": dict(histogram.most_common()),
        "searched_by_default_failure_class": dict(classes_searched.most_common()),
        "improved_by_default_failure_class": dict(classes_improved.most_common()),
        "decompiles": decompiles, "compiles": compiles,
        "search_seconds_sum": round(search_seconds, 1),
        "wall_seconds_default_arm": seconds.get((stem, "def")) or seconds.get((lane, "def")),
        "wall_seconds_search_arm": seconds.get((stem, f"s{budget}")) or seconds.get((lane, f"s{budget}")),
        "improved": sorted(improved, key=lambda r: (not r["exact_gained"], -(r["to"] - r["from"]))),
        "tools": searched["compilers"] if isinstance(searched.get("compilers"), (dict, list)) else None,
    }
    return row


def markdown(report):
    lines = [f"# Near-miss search (`romwright-cli match`) on the PS2 lanes (m22-003, and m22-002 where listed)", "",
             f"Generated {report['generated']}. Budget {report['budget']} variants per searched function; the plan is the product command's "
             f"(`romwright-cli match --plan`), see docs/match.md. Every arm is a fresh import and a fresh work-dir snapshot; "
             f"`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`; ghidra_opt sha256 `{report['ghidra_opt_sha256'][:12]}` (unchanged).", "",
             "Scores are the lane harness's headline (`context`) compile: `exact` = same length and every byte equal outside relocation fields; "
             "`mean %` = objdiff `match_percent` (functionRelocDiffs=none) over all sampled functions, a function that does not compile counting 0. "
             "Only functions whose default print compiles and is not exact are searched; the retail bytes and the pinned compiler are the only oracle "
             "(no lane truth C is read by the search).", "",
             "| lane | n | default exact / compiled / mean % | searched exact / compiled / mean % | searched functions | improved | newly exact | winners (improved functions) | decompiles | compiles | wall s default arm | wall s search arm |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for row in report["lanes"]:
        d, s = row["default"], row["searched"]
        winners = ", ".join(f"{k} {v}" for k, v in row["winners"].items()) or "-"
        lines.append(f"| {row['lane']} | {row['functions']} | {d['exact']} / {d['compiled']} / {d['mean_percent']:.3f} | "
                     f"{s['exact']} / {s['compiled']} / {s['mean_percent']:.3f} | {row['functions_searched']} | {row['functions_improved']} | {row['newly_exact']} | "
                     f"{winners} | {row['decompiles']} | {row['compiles']} | {row['wall_seconds_default_arm']} | {row['wall_seconds_search_arm']} |")
    lines.append("")
    for harness, total in report["total"].items():
        lines += [f"{harness} lanes: {total['functions']} functions, default exact {total['default_exact']} -> searched {total['searched_exact']} "
                  f"(+{total['searched_exact'] - total['default_exact']}), {total['functions_searched']} functions searched, {total['functions_improved']} improved, "
                  f"{total['decompiles']} decompiles and {total['compiles']} compiles. Winners: " +
                  (", ".join(f"{k} {v}" for k, v in total["winners"].items()) or "-") + ".", ""]
    lines += ["The m22-002 lanes sample the same Persona 4 decompilation as the p4 lane (a different harness, sample and context handling): their functions overlap the p4 lane's and are not added to it.", "",
              "Default-arm check against the baseline table: " + ", ".join(f"{r['lane']} {'ok' if r['default_equals_baseline_table'] else 'DIFFERS'}" for r in report["lanes"]) + ".", "",
              "Default arm of the search run (the `romwright` layer of the `--search` run) equals the separate default arm: " +
              ", ".join(f"{r['lane']} {'yes' if r['default_arms_agree'] else 'NO'}" for r in report["lanes"]) + ".", ""]
    for row in report["lanes"]:
        lines += [f"## {row['lane']}", "",
                  f"Standalone compile (no context): default {row['default_standalone']['exact']} exact / mean {row['default_standalone']['mean_percent']:.3f}, "
                  f"searched {row['searched_standalone']['exact']} exact / mean {row['searched_standalone']['mean_percent']:.3f}. "
                  f"Improved / searched by the default print's byte-difference class: " +
                  (", ".join(f"{k} {row['improved_by_default_failure_class'].get(k, 0)}/{v}" for k, v in row["searched_by_default_failure_class"].items()) or "-") + ". "
                  f"Search time summed over functions {row['search_seconds_sum']} s.", ""]
        if row["improved"]:
            lines += ["| function | size | winner | from % | to % | exact |", "|---|---|---|---|---|---|"]
            for item in row["improved"][:25]:
                lines.append(f"| {item['name']} | {item['size']} | {item['variant']} | {item['from']} | {item['to']} | {'yes' if item['exact_gained'] else ''} |")
            if len(row["improved"]) > 25:
                lines.append(f"| ... {len(row['improved']) - 25} more in the JSON | | | | | |")
            lines.append("")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--budget", type=int, required=True)
    parser.add_argument("--runs", type=Path)
    parser.add_argument("--lanes", default=",".join(ORDER))
    parser.add_argument("--ghidra-opt-sha256", default="486ace43c12ed3017508f527344dd06552b7ee62304c861566430ca18074ff94")
    parser.add_argument("--out", type=Path, required=True, help="path without extension")
    args = parser.parse_args()
    seconds = runs_seconds(args.runs, args.tag)
    lanes = [lane_row(lane, args.dir, args.tag, args.budget, seconds) for lane in args.lanes.split(",")
             if (args.dir / f"{lane}-{args.tag}-s{args.budget}.json").exists()]
    for label, (stem, baseline) in M22_002.items():
        if (args.dir / f"{stem}-{args.tag}-s{args.budget}.json").exists() and (args.dir / f"{stem}-{args.tag}-def.json").exists():
            lanes.append(lane_row(label, args.dir, args.tag, args.budget, seconds, stem, baseline, "m22-002"))
    totals = {}
    for harness in ("m22-003", "m22-002"):
        rows = [r for r in lanes if r["harness"] == harness]
        if not rows:
            continue
        histogram = collections.Counter()
        for row in rows:
            histogram.update(row["winners"])
        totals[harness] = {"functions": sum(r["functions"] for r in rows), "default_exact": sum(r["default"]["exact"] for r in rows),
                           "searched_exact": sum(r["searched"]["exact"] for r in rows),
                           "functions_searched": sum(r["functions_searched"] for r in rows),
                           "functions_improved": sum(r["functions_improved"] for r in rows),
                           "decompiles": sum(r["decompiles"] for r in rows), "compiles": sum(r["compiles"] for r in rows),
                           "winners": dict(histogram.most_common())}
    import time
    report = {"schema": "match-search/1", "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "budget": args.budget, "tag": args.tag,
              "ghidra_opt_sha256": args.ghidra_opt_sha256, "lanes": lanes, "total": totals}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.with_suffix(".json").write_text(json.dumps(report, indent=1))
    args.out.with_suffix(".md").write_text(markdown(report))
    print(f"wrote {args.out}.json and .md: {len(lanes)} lanes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
