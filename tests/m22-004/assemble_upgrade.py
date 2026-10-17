#!/usr/bin/env python3
"""Headline report of the PC upgrade (benchmarks/reports/pc_upgrade_<date>.{json,md}): the arms of the m22-004 lane per fixture, the
classes before and after, the leave-one-out arms, the near-miss search layer and the console gates.

    assemble_upgrade.py OUT_STEM MANIFEST.json

MANIFEST: {"date": ..., "build": {...},
           "fixtures": {fixture: {"arms": {label: {"report": LANE_REPORT.json, "classes": FAILURE_CLASSES.json}}}},
           "switches": {label: "ROMWRIGHT_..."},
           "gates": {gate: {arm: {"exact": n, "compiled": n, "mean_percent": x}}}}
Arm labels used: `off` (this work's switches off), `default`, `no_<switch>` (leave one out), `search` (default with --search).
Writes OUT_STEM.json and OUT_STEM.md.
"""
import json
import math
import sys
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text())


def sign_p(wins, losses):
    n = wins + losses
    if not n:
        return 1.0
    k = min(wins, losses)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def cell(report):
    o = report["summary"]["overall"]
    return {"exact": o["exact"], "compiled": o["compiled"], "mean_percent": o["mean_percent"], "percent_ge_90": o["percent_ge_90"],
            "functions": o["functions"]}


def fmt(c):
    return f"{c['exact']} / {c['compiled']} / {c['mean_percent']:.3f}"


def paired(a, b):
    """b against a (same sample): percent wins/losses/same, exact gained/lost."""
    rows_a = {e["address"]: e for e in a["functions"]}
    wins = losses = same = 0
    gained, lost = [], []
    for e in b["functions"]:
        old = rows_a.get(e["address"])
        if old is None:
            continue
        if e["percent"] > old["percent"] + 0.0005:
            wins += 1
        elif e["percent"] < old["percent"] - 0.0005:
            losses += 1
        else:
            same += 1
        if e["exact"] and not old["exact"]:
            gained.append(e["address"])
        if old["exact"] and not e["exact"]:
            lost.append(e["address"])
    return {"better": wins, "worse": losses, "same": same, "p": float(f"{sign_p(wins, losses):.3g}"), "exact_gained": len(gained), "exact_lost": len(lost)}


def class_table(classes_a, classes_b):
    names = sorted(set(classes_a["classes"]) | set(classes_b["classes"]), key=lambda n: -(classes_b["classes"].get(n, 0) + classes_a["classes"].get(n, 0)))
    return [(n, classes_a["classes"].get(n, 0), classes_b["classes"].get(n, 0)) for n in names]


def main():
    stem = Path(sys.argv[1])
    manifest = load(sys.argv[2])
    out = {"schema": "pc-upgrade/1", "generated": manifest["date"], "build": manifest.get("build", {}), "fixtures": {}, "gates": {}}
    lines = [f"# PC upgrade: the m22-004 lane before and after ({manifest['date']})", "",
             "Cells are exact / compiled / mean objdiff percent over each fixture's 200-function sample (seed 20261015), fresh import per arm "
             "(`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`), the fixture's own compiler, the lane as fixed by this work "
             "(retail-relocation objdiff target, strict relocation targets, DWARF game-code sample, `-fno-strict-aliasing` for ioq3). "
             "`off` is the final build with every switch of this work off (the integrated tree without this work's product rules); "
             "`default` is the final build.", ""]
    for line in manifest.get("notes", []):
        lines.append(line)
    if manifest.get("notes"):
        lines.append("")
    lines += ["## Per fixture", "", "| fixture | compiler | off | default | default vs off (percent better / worse / same, sign-test p) | exact gained / lost |",
              "|---|---|---|---|---|---|"]
    details = []
    for fixture, spec in manifest["fixtures"].items():
        arms = {label: {"report": load(a["report"]), "classes": load(a["classes"]) if a.get("classes") else None} for label, a in spec["arms"].items()}
        entry = {"cells": {label: cell(a["report"]) for label, a in arms.items()}}
        d, off = arms["default"]["report"], arms["off"]["report"]
        entry["default_vs_off"] = paired(off, d)
        entry["classes"] = {"off": arms["off"]["classes"]["classes"], "default": arms["default"]["classes"]["classes"]}
        entry["tags"] = {"off": arms["off"]["classes"]["tags"], "default": arms["default"]["classes"]["tags"]}
        loo = {}
        for label, switch in manifest.get("switches", {}).items():
            arm = arms.get(f"no_{label}")
            if arm:
                loo[label] = {"switch": switch, "cell": cell(arm["report"]), "default_vs_arm": paired(arm["report"], d)}
        entry["leave_one_out"] = loo
        if "search" in arms:
            entry["search"] = {"default_layer": arms["search"]["report"]["summary"]["default_layer"], "best_of_search": cell(arms["search"]["report"]),
                               "improved": sum(1 for e in arms["search"]["report"]["functions"] if e.get("search", {}).get("improved")),
                               "searched": sum(1 for e in arms["search"]["report"]["functions"] if e.get("search"))}
        out["fixtures"][fixture] = entry
        c = entry["cells"]
        p = entry["default_vs_off"]
        lines.append(f"| `{fixture}` | {d['compiler']['id']} | {fmt(c['off'])} | **{fmt(c['default'])}** | "
                     f"{p['better']} / {p['worse']} / {p['same']} (p {p['p']:.3g}) | +{p['exact_gained']} / -{p['exact_lost']} |")
        details.append((fixture, entry, arms))
    for fixture, entry, arms in details:
        lines += ["", f"### `{fixture}`", "", "Failure classes (functions; first error or first byte-difference class; see tests/m22-004/failure_classes.py):", "",
                  "| class | off | default |", "|---|---|---|"]
        names = sorted(set(entry["classes"]["default"]) | set(entry["classes"]["off"]),
                       key=lambda n: -(entry["classes"]["off"].get(n, 0) + entry["classes"]["default"].get(n, 0)))
        for name in names:
            lines.append(f"| {name} | {entry['classes']['off'].get(name, 0)} | {entry['classes']['default'].get(name, 0)} |")
        tags = sorted(set(entry["tags"]["off"]) | set(entry["tags"]["default"]))
        lines += ["", "Tags (functions whose differing instructions involve it): " + ", ".join(
            f"{t} {entry['tags']['off'].get(t, 0)} -> {entry['tags']['default'].get(t, 0)}" for t in tags), ""]
        if entry["leave_one_out"]:
            lines += ["Leave one out (the default build with one switch off): exact / compiled / mean, and the default's paired percent against that arm:", "",
                      "| switch off | exact / compiled / mean | default better / worse / same (p) | exact gained |", "|---|---|---|---|"]
            for label, row in entry["leave_one_out"].items():
                pr = row["default_vs_arm"]
                lines.append(f"| `{row['switch']}` | {fmt(row['cell'])} | {pr['better']} / {pr['worse']} / {pr['same']} (p {pr['p']:.3g}) | +{pr['exact_gained']} / -{pr['exact_lost']} |")
            lines.append("")
        if "search" in entry:
            s = entry["search"]
            lines += [f"Near-miss search (`--search`, docs/match.md), default print -> best of the plan's variants: "
                      f"{fmt(s['default_layer'])} -> {fmt(s['best_of_search'])}; the search found a better print for {s['improved']} of the {s['searched']} functions it tried.", ""]
    for gate, arms in manifest.get("gates", {}).items():
        # a gate arm is a `{"exact", "compiled", "mean_percent"}` cell (read off the console lane's own report by the caller)
        out["gates"][gate] = {arm: dict(cell_) for arm, cell_ in arms.items()}
    if out["gates"]:
        lines += ["## Console gates (no regression)", "", "| gate | " + " | ".join(next(iter(out["gates"].values()))) + " |",
                  "|---|" + "---|" * len(next(iter(out["gates"].values())))]
        for gate, cells in out["gates"].items():
            lines.append(f"| {gate} | " + " | ".join(fmt(c) for c in cells.values()) + " |")
        lines.append("")
    for line in manifest.get("limits", []):
        lines.append(line)
    stem.with_suffix(".json").write_text(json.dumps(out, indent=1) + "\n")
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n")
    print(stem.with_suffix(".md"))


if __name__ == "__main__":
    main()
