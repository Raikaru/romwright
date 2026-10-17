#!/usr/bin/env python3
"""Compares two combined-gate reports number by number.

`benchmarks/combined_gate.py` writes one report per run of the gates (m21-001, m22-002 x3, the PS2 decompile
success, the console-research wave). This reads a frozen one and a new one and lists every number that moved,
so "the numbers are unchanged or better" is a table rather than a sentence:

    python3 benchmarks/compiler_rules_gate_compare.py --old benchmarks/reports/combined_gate_20261012.json \
        --new benchmarks/reports/combined_gate_compiler_rules_20261012.json \
        --out benchmarks/reports/compiler_rules_gate_vs_20261012.json

Rates and counts where more is better (recall, precision, success, decompiled, size exact, m22 exact / compiled /
mean) are judged better / worse; structure statistics (gotos, labels, native warnings) are listed as changed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HIGHER_IS_BETTER = {"recall", "precision", "success_rate", "decompiled", "size_exact", "exact", "compiled", "mean_percent",
                    "paired_better"}
STATISTICS = {"gotos", "labels", "native_warnings", "sampled"}


def flatten(report: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for image, row in (report.get("m21", {}).get("rows") or {}).items():
        for key in ("recall", "precision", "size_exact"):
            if isinstance(row.get(key), (int, float)):
                out[f"m21 {image} {key}"] = row[key]
    for lane, row in (report.get("m22") or {}).items():
        new = row.get("new") if isinstance(row, dict) else None
        if isinstance(new, dict):
            for key in ("exact", "compiled", "mean_percent"):
                if isinstance(new.get(key), (int, float)):
                    out[f"m22 {lane} {key}"] = new[key]
    success = report.get("ps2_success") or {}
    for game, row in (success.get("games") or {}).items():
        if isinstance(row, dict) and isinstance(row.get("decompiled"), (int, float)):
            out[f"ps2 success {game} decompiled"] = row["decompiled"]
    for section, name in (("ps2_wave", "ps2 wave"), ("other_platforms", "wave")):
        for image, row in ((report.get(section) or {}).get("images") or {}).items():
            summary = row.get("summary") or {}
            for key in ("success_rate", "recall", "precision", "gotos", "labels", "native_warnings", "decompiled", "sampled"):
                if isinstance(summary.get(key), (int, float)):
                    out[f"{name} {image} {key}"] = summary[key]
    for image, row in (report.get("psp_n200") or {}).items():
        for key in ("recall", "precision", "success_rate"):
            if isinstance(row.get(key), (int, float)):
                out[f"psp n=200 {image} {key}"] = row[key]
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    old, new = flatten(json.loads(args.old.read_text())), flatten(json.loads(args.new.read_text()))
    rows = []
    for key in sorted(set(old) | set(new)):
        before, after = old.get(key), new.get(key)
        metric = key.rsplit(" ", 1)[1]
        if before is None or after is None:
            verdict = "missing in " + ("new" if after is None else "old")
        elif after == before:
            verdict = "same"
        elif metric in HIGHER_IS_BETTER:
            verdict = "better" if after > before else "worse"
        else:
            verdict = "changed"
        rows.append({"metric": key, "old": before, "new": after, "verdict": verdict})
    counts = {v: sum(1 for r in rows if r["verdict"] == v) for v in sorted({r["verdict"] for r in rows})}
    report = {"old": str(args.old.name), "new": str(args.new.name), "counts": counts, "rows": rows}
    args.out.write_text(json.dumps(report, indent=1) + "\n")
    moved = [r for r in rows if r["verdict"] != "same"]
    lines = [f"# Gate comparison: `{args.new.name}` against `{args.old.name}`", "",
             f"{len(rows)} numbers compared: " + ", ".join(f"{n} {v}" for v, n in counts.items()) + ".", ""]
    if moved:
        lines += ["| metric | old | new | verdict |", "|---|---|---|---|"]
        lines += [f"| {r['metric']} | {r['old']} | {r['new']} | {r['verdict']} |" for r in moved]
    else:
        lines.append("Every number is identical.")
    lines.append("")
    args.out.with_suffix(".md").write_text("\n".join(lines))
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
