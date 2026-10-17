#!/usr/bin/env python3
"""Headline report of the PC C-output lane: the arms of several fixtures side by side, paired on/off comparisons.

    assemble_report.py OUT_STEM ARM_REPORT.json...   (each: the lane's --report .json; the arm name is its `tag`)

Writes OUT_STEM.json and OUT_STEM.md. The per-arm reports stay beside it (they hold every function).
"""
import json
import math
import sys
from pathlib import Path


def sign_p(wins, losses):
    n = wins + losses
    if not n:
        return 1.0
    k = min(wins, losses)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def main():
    stem = Path(sys.argv[1])
    reports = [json.loads(Path(p).read_text()) for p in sys.argv[2:]]
    fixtures = {}
    for r in reports:
        fixtures.setdefault(r["fixture"]["id"], []).append(r)
    out = {"schema": "pc-c-output-headline/1", "generated": reports[0]["generated"], "fixtures": {}}
    lines = ["# PC C output (x86 PE): exact / compiled / mean objdiff percent, 200-function samples", "",
             f"Generated {out['generated']} by `tests/m22-004_pc_c_output.py` (seed {reports[0]['sample']['seed']}); fresh import per arm "
             "(`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`). `off` sets "
             "`ROMWRIGHT_PE_WINDOWS_SPEC=off ROMWRIGHT_PE_CONVENTIONS=off ROMWRIGHT_PE_IAT_REGIONS=off ROMWRIGHT_EXPORT_LONG_DOUBLE=off "
             "ROMWRIGHT_EXPORT_CALLEE_CONVENTIONS=off`; the other arms name the switch they turn off (or `on`: nothing off).", ""]
    for fid, arms in fixtures.items():
        first = arms[0]
        lines += [f"## {fid} ({first['compiler']['id']}, `{first['compiler']['cl_banner']}`)", "",
                  f"Flags `{' '.join(first['compiler']['flags'])}`; sample {first['sample']['n']} of {first['sample']['eligible']} "
                  f"functions of {first['sample']['size_window'][0]}-{first['sample']['size_window'][1]} bytes drawn from {first['sample']['drawn_from']}.", "",
                  "| arm | functions | produced | compiled | exact | mean % | mean % (compiled) | >= 90% |", "|---|---|---|---|---|---|---|---|"]
        out["fixtures"][fid] = {"compiler": first["compiler"], "sample": first["sample"], "arms": {}}
        for r in arms:
            o = r["summary"]["overall"]
            out["fixtures"][fid]["arms"][r["tag"]] = {"summary": r["summary"], "env": r["env"]}
            lines.append(f"| {r['tag']} | {o['functions']} | {o['produced']} | {o['compiled']} | {o['exact']} | {o['mean_percent']} | "
                         f"{o['mean_percent_compiled']} | {o['percent_ge_90']} |")
        by_tag = {r["tag"]: r for r in arms}
        pairs = [("on2", "off")] if "on2" in by_tag and "off" in by_tag else []
        for a, b in pairs:
            rows = {f["address"]: f for f in by_tag[b]["functions"]}
            wins = losses = ties = 0
            for f in by_tag[a]["functions"]:
                d = f["percent"] - rows[f["address"]]["percent"]
                wins += d > 0.01
                losses += d < -0.01
                ties += abs(d) <= 0.01
            p = sign_p(wins, losses)
            lines += ["", f"Paired, `{a}` against `{b}` on percent: better {wins}, worse {losses}, same {ties} (two-sided sign test p = {p:.3g})."]
            out["fixtures"][fid][f"paired_{a}_vs_{b}"] = {"better": wins, "worse": losses, "same": ties, "p_two_sided": p}
        errors = by_tag.get("on2", arms[-1])["summary"]["compile_errors"]
        lines += ["", "Compile failures of the `on2` arm (first error, normalised): " + ("; ".join(f"{m} x{c}" for m, c in errors.items()) or "none"), ""]
    stem.with_suffix(".json").write_text(json.dumps(out, indent=1) + "\n")
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n")
    print(stem.with_suffix(".md"))


if __name__ == "__main__":
    main()
