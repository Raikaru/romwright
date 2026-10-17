#!/usr/bin/env python3
"""Per-function comparison of an m22-003 report with an m22-002 report on the same functions (the harness's validation on
Persona 4): for each layer, how many functions agree on `exact`, how the compiled counts and the mean percent compare, and where
the percents differ by more than a point. Usage: compare_m22_002.py M22_002.json M22_003.json [--json OUT]"""
import json
import sys


def main(argv):
    old, new = (json.load(open(path)) for path in argv[:2])
    old_rows = {int(k, 16): v for k, v in old["functions"].items()}
    new_rows = {int(k, 16): v for k, v in new["functions"].items()}
    common = sorted(set(old_rows) & set(new_rows))
    out = {"m22_002_functions": len(old_rows), "m22_003_functions": len(new_rows), "common": len(common), "layers": {}}
    for layer in [l for l in old["layers"] if l in new["layers"]]:
        rows = []
        for address in common:
            a = old_rows[address]["layers"][layer]["variants"]["context"]
            b = new_rows[address]["layers"][layer]["variants"]["context"]
            rows.append((address, a, b))
        n = len(rows)
        out["layers"][layer] = {
            "m22_002": {"exact": sum(a["exact"] for _, a, _ in rows), "compiled": sum(a["compiled"] for _, a, _ in rows),
                        "mean_percent": round(sum(a["percent"] for _, a, _ in rows) / max(n, 1), 3)},
            "m22_003": {"exact": sum(b["exact"] for _, _, b in rows), "compiled": sum(b["compiled"] for _, _, b in rows),
                        "mean_percent": round(sum(b["percent"] for _, _, b in rows) / max(n, 1), 3)},
            "same_exact": sum(a["exact"] == b["exact"] for _, a, b in rows),
            "same_compiled": sum(a["compiled"] == b["compiled"] for _, a, b in rows),
            "percent_within_1": sum(abs(a["percent"] - b["percent"]) <= 1.0 for _, a, b in rows),
            "percent_differs_gt_10": sum(abs(a["percent"] - b["percent"]) > 10 for _, a, b in rows),
            "differing": [{"address": f"{address:#x}", "name": old_rows[address]["name"], "m22_002": round(a["percent"], 1),
                           "m22_003": round(b["percent"], 1)} for address, a, b in rows if abs(a["percent"] - b["percent"]) > 10][:25],
        }
    print(json.dumps(out, indent=1))
    if "--json" in argv:
        open(argv[argv.index("--json") + 1], "w").write(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
