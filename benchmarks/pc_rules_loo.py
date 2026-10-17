#!/usr/bin/env python3
"""Leave-one-out of the PE discovery rules (`compiler_rules/pe.json`) on the `pc-*` truth fixtures.

For every rule: one fresh import of every fixture with the rule switched off
(`ROMWRIGHT_COMPILER_RULES_DISABLE=<id>`), against the all-on import. The imports are deterministic, so
every difference is real; a rule `helps` a fixture when recall or precision improves and neither worsens,
`hurts` in the reverse case, `mixed` when both happen. Also the all-off arm (every PE rule disabled).

    CARGO_TARGET_DIR=~/runs/X/romwright/target benchmarks/pc_rules_loo.py --work ~/runs/X/pc-work \\
        --out benchmarks/reports/pc_rules_loo_<tag>.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ["pe-jump-table-relocs", "pe-dense-case-tables", "pe-x86-memory-operands", "pe-x86-scope-tables",
         "pe-x86-local-calls", "pe-x86-trailing-data", "pe-import-stub-position", "pe-x86-fill-starts", "pe-x86-case-runs"]


def arm(args, tag: str, disabled: list[str]) -> dict:
    out = args.work / f"loo-{tag}.json"
    env = json.dumps({"ROMWRIGHT_COMPILER_RULES_DISABLE": ",".join(disabled)} if disabled else {})
    argv = [sys.executable, str(ROOT / "benchmarks" / "pc_import.py"), "--work", str(args.work), "--out", str(out),
            "--arms", "ours", "--env", env, "--corpus", str(args.corpus)]
    if args.images:
        argv += ["--images", args.images]
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)
    report = json.loads(out.read_text())
    return {row["id"]: row["arms"]["ours"] for row in report["rows"]}


def verdict(base: dict, off: dict) -> str:
    """What the rule does, judged by switching it off: `base` is rule on, `off` rule off."""
    better = worse = False
    for metric in ("recall", "precision"):
        a, b = base["score"][metric], off["score"][metric]
        if a > b + 1e-9:
            better = True
        elif a < b - 1e-9:
            worse = True
    return "mixed" if better and worse else "helps" if better else "hurts" if worse else "neutral"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--corpus", type=Path, default=Path.home() / "romwright-corpus" / "extracted")
    p.add_argument("--images", default="")
    p.add_argument("--rules", default=",".join(RULES))
    p.add_argument("--only-arms", default="", help="run just these arms (rule ids, ALL, base) into --work and stop: several processes "
                   "with distinct --work directories split a run; `--assemble` joins their arm files")
    p.add_argument("--assemble", nargs="*", default=None, metavar="WORKDIR",
                   help="build the report from the arm files (`loo-<arm>.json`) found in these work directories instead of running")
    args = p.parse_args()
    rules = [r for r in args.rules.split(",") if r]
    if args.only_arms:
        for tag in [t for t in args.only_arms.split(",") if t]:
            arm(args, tag, [] if tag == "base" else rules if tag == "ALL" else [tag])
        return 0
    if args.assemble is not None:
        def load(tag: str) -> dict:
            for directory in args.assemble:
                path = Path(directory) / f"loo-{tag}.json"
                if path.is_file():
                    return {row["id"]: row["arms"]["ours"] for row in json.loads(path.read_text())["rows"]}
            raise SystemExit(f"no loo-{tag}.json in {args.assemble}")
        base = load("base")
        loaded = {tag: load(tag) for tag in rules + ["ALL"]}
    else:
        base = arm(args, "base", [])
        loaded = None
    report = {"rules": {}, "baseline": {k: v["score"] for k, v in base.items()}}
    for rule in rules + ["ALL"]:
        off = loaded[rule] if loaded is not None else arm(args, rule, rules if rule == "ALL" else [rule])
        cell = {}
        for fixture, on in base.items():
            if "score" not in off.get(fixture, {}):
                cell[fixture] = {"verdict": "arm failed"}
                continue
            a, b = on["score"], off[fixture]["score"]
            cell[fixture] = {"verdict": verdict(on, off[fixture]),
                             "recall": [b["recall"], a["recall"]], "precision": [b["precision"], a["precision"]],
                             "invented": [b["invented"], a["invented"]], "hits": [b["hits"], a["hits"]],
                             "seconds": [off[fixture]["seconds"], on["seconds"]]}
        report["rules"][rule] = cell
    args.out.write_text(json.dumps(report, indent=1) + "\n")
    lines = ["| rule (off -> on) | " + " | ".join(base) + " |", "|---|" + "---|" * len(base)]
    for rule, cell in report["rules"].items():
        row = []
        for fixture in base:
            c = cell[fixture]
            row.append(c["verdict"] if "recall" not in c else
                       f"{c['verdict']}: R {c['recall'][0]:.4f}->{c['recall'][1]:.4f} P {c['precision'][0]:.4f}->{c['precision'][1]:.4f}")
        lines.append(f"| {rule} | " + " | ".join(row) + " |")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
