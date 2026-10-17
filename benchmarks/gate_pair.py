#!/usr/bin/env python3
"""Paired comparison of two C-output runs (m22-002 reports, or m22-003 `--functions-out` files).

Per function (romwright layer, `context` variant, the headline), the second run against the first:
better / worse / same by match percent, and the functions that lost an exact match or a compile.

  gate_pair.py OFF.json DEFAULT.json [--label NAME] [--examples N]

Both files may be a report (`functions` keyed by address with `layers.romwright.variants.context`) or a
`m22-003-functions/1` file (`functions` keyed by address with `layers.romwright.context`). The text goes to stdout, a
JSON object (counts and the lost functions) after it when `--json OUT` is given.
"""
from __future__ import annotations

import argparse
import json
import sys


def rows(path: str) -> dict[str, dict]:
    data = json.load(open(path))
    out = {}
    for address, row in data["functions"].items():
        layer = row.get("layers", {}).get("romwright", {})
        context = layer.get("variants", {}).get("context") or layer.get("context")
        if context is None:
            continue
        out[address] = {
            "name": row.get("name"),
            "compiled": bool(context.get("compiled")),
            "exact": bool(context.get("exact")),
            "percent": float(context.get("percent") or 0.0),
        }
    return out


def summary(rows_: dict[str, dict]) -> dict:
    n = len(rows_)
    return {
        "functions": n,
        "exact": sum(r["exact"] for r in rows_.values()),
        "compiled": sum(r["compiled"] for r in rows_.values()),
        "mean_percent": round(sum(r["percent"] for r in rows_.values()) / n, 3) if n else None,
    }


def pair(off: dict[str, dict], new: dict[str, dict], tolerance: float = 1e-4) -> dict:
    better, worse, same = [], [], []
    lost_exact, lost_compiled, gained_exact, gained_compiled = [], [], [], []
    for address in sorted(set(off) & set(new)):
        a, b = off[address], new[address]
        delta = b["percent"] - a["percent"]
        if abs(delta) <= tolerance and a["exact"] == b["exact"] and a["compiled"] == b["compiled"]:
            same.append(address)
        elif delta > tolerance:
            better.append(address)
        elif delta < -tolerance:
            worse.append(address)
        else:
            same.append(address)
        if a["exact"] and not b["exact"]:
            lost_exact.append(address)
        if b["exact"] and not a["exact"]:
            gained_exact.append(address)
        if a["compiled"] and not b["compiled"]:
            lost_compiled.append(address)
        if b["compiled"] and not a["compiled"]:
            gained_compiled.append(address)
    return {
        "paired": len(set(off) & set(new)),
        "better": len(better),
        "worse": len(worse),
        "same": len(same),
        "lost_exact": lost_exact,
        "lost_compiled": lost_compiled,
        "gained_exact": gained_exact,
        "gained_compiled": gained_compiled,
        "better_addresses": better,
        "worse_addresses": worse,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("off")
    parser.add_argument("default")
    parser.add_argument("--label", default="")
    parser.add_argument("--json")
    args = parser.parse_args()
    off, new = rows(args.off), rows(args.default)
    result = {"label": args.label, "off": summary(off), "default": summary(new), **pair(off, new)}
    s0, s1 = result["off"], result["default"]
    print(f"{args.label:12} off {s0['exact']:3}/{s0['compiled']:3}/{s0['mean_percent']}  default {s1['exact']:3}/{s1['compiled']:3}/{s1['mean_percent']}"
          f"  paired {result['paired']}: better {result['better']} worse {result['worse']} same {result['same']}"
          f"  lost exact {len(result['lost_exact'])} lost compiled {len(result['lost_compiled'])}")
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(result, handle, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
