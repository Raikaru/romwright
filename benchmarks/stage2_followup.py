#!/usr/bin/env python3
"""Follow-up to the stage 2 gates (docs/types-port.md): the m22-002 ee-gcc lane with fresh work directories per arm, the gh lane
on the baseline's layers, and the full PS2 decompile-success set, on one fresh build of the integrated tree.

  stage2_followup.py --out DIR --reports benchmarks/reports [--date 20261013]

DIR holds (written by the measurement host):
  m22-002-<tag>-<arm>-l3.json                 ee-gcc lane, one fresh work dir per arm (arms off / parity / def)
  m22003-gh-<tag>-m2c-functions.json          gh with `--layers romwright,m2c` (the layers of the baseline rows)
  ps2_decompile_success_stage2_followup.json  `ps2_decompile_success.py` over the wave's 11 projects
Writes `stage2_followup_<date>.{json,md}`. Nothing is hand-edited.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate_pair  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reports", type=Path, default=HERE / "reports")
    parser.add_argument("--tag", default="f1")
    parser.add_argument("--date", default="20261013")
    args = parser.parse_args()
    out = args.out
    result: dict = {"benchmark": "stage2_followup", "date": args.date, "tag": args.tag}
    lines = [f"# Stage 2 follow-up, {args.date}", ""]

    arms = {a: out / f"m22-002-{args.tag}-{a}-l3.json" for a in ("off", "parity", "def")}
    if all(p.exists() for p in arms.values()):
        base = gate_pair.rows(str(arms["off"]))
        lane = {"off": gate_pair.summary(base)}
        for arm in ("parity", "def"):
            rows = gate_pair.rows(str(arms[arm]))
            lane[arm] = {"summary": gate_pair.summary(rows), **gate_pair.pair(base, rows)}
        result["m22-002 ee-gcc"] = lane
        o = lane["off"]
        lines += ["## m22-002 ee-gcc, three arms, each with a fresh import and work directory", "",
                  "off = `ROMWRIGHT_NATIVE_CASTS=1` with rule `mwcc-void-pointer-arithmetic` disabled; parity = the worker's casts with the rule "
                  "disabled; default = the build as is. exact / compiled / mean %; paired against off.", "",
                  "| arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled |", "|---|---|---|---|---|---|---|---|---|",
                  f"| off | {o['exact']} | {o['compiled']} | {o['mean_percent']} | | | | | |"]
        for arm in ("parity", "def"):
            e = lane[arm]
            s = e["summary"]
            lines.append(f"| {arm} | {s['exact']} | {s['compiled']} | {s['mean_percent']} | {e['better']} | {e['worse']} | {e['same']} | "
                         f"{e['lost_exact']} | {e['lost_compiled']} |")
        lines += ["Arms really differ in the process that decompiles: the m22-002 harness passes only `ROMWRIGHT_GHIDRA` and `ROMWRIGHT_STRUCTS` "
                  "through, so the arms are wrapper binaries (`ghidra_opt_native` sets `ROMWRIGHT_NATIVE_CASTS=1`; `romwright-cli-novoid` sets "
                  "`ROMWRIGHT_COMPILER_RULES_DISABLE=mwcc-void-pointer-arithmetic`; each report's `argv[0]` names the CLI that ran). Checked on the "
                  "default arm's project: `export-c` with `ghidra_opt` writes a `cast_ok` line to `ROMWRIGHT_RUST_CASTS_LOG`, with `ghidra_opt_native` "
                  "none (the decompiler cast); `romwright-cli-novoid compiler-rules` lists the rule `inactive`, `romwright-cli` `active`. "
                  "On this lane all 200 functions are identical in the three arms.", ""]

    gh = out / f"m22003-gh-{args.tag}-m2c-functions.json"
    clone_def, clone_off = out / "m22003-gh-f2-clone-functions.json", out / "m22003-gh-f3-clone-off-functions.json"
    if gh.exists():
        s = result["gh, Ps2Lanes pristine repo copy (default arm)"] = gate_pair.summary(gate_pair.rows(str(gh)))
        lines += ["## gh (`--layers romwright,m2c`, fresh import)", "",
                  "The 196 compiled of the stage 2 gates came from the lane run on the pristine repo copy `~/runs/Ps2Lanes/repos/gh`, whose own build "
                  "matched 6,250 functions (4,866 in the size window); the harness cloning the repository itself matches 7,367 (5,544 in the window), "
                  "which is what the 199-compiled baselines were measured on. A different matched set is a different 200-function sample, so the "
                  "two are not comparable; the build under test is the same.", "",
                  "| run | matched | exact | compiled | mean % |", "|---|---|---|---|---|",
                  f"| default arm, pristine repo copy | 6,250 | {s['exact']} | {s['compiled']} | {s['mean_percent']} |"]
        if clone_def.exists():
            c = result["gh, harness clone (default arm)"] = gate_pair.summary(gate_pair.rows(str(clone_def)))
            lines.append(f"| default arm, harness clone | 7,367 | {c['exact']} | {c['compiled']} | {c['mean_percent']} |")
        if clone_off.exists() and clone_def.exists():
            base = gate_pair.rows(str(clone_off))
            o = result["gh, harness clone (off arm)"] = gate_pair.summary(base)
            lines.append(f"| off arm (`ROMWRIGHT_NATIVE_CASTS=1`, rule disabled), harness clone | 7,367 | {o['exact']} | {o['compiled']} | {o['mean_percent']} |")
            pr = gate_pair.pair(base, gate_pair.rows(str(clone_def)))
            result["gh clone, default against off"] = pr
            lines += ["", f"Default against off on the harness clone: better {pr['better']}, worse {pr['worse']}, same {pr['same']}; lost exact {pr['lost_exact']}, "
                          f"lost compiled {pr['lost_compiled']}.", ""]
        else:
            lines.append("")

    succ = out / "ps2_decompile_success_stage2_followup.json"
    if succ.exists():
        data = json.load(open(succ))
        games = data["games"]
        sampled = sum(g["sampled"] for g in games.values())
        decompiled = sum(g["decompiled"] for g in games.values())
        result["ps2_decompile_success"] = {"sampled": sampled, "decompiled": decompiled,
                                           "games": {n: {"sampled": g["sampled"], "decompiled": g["decompiled"], "failures": g.get("failures", [])}
                                                     for n, g in games.items()}}
        lines += ["## `ps2_decompile_success.py`, the wave's 11 projects, default build", "",
                  f"{decompiled} of {sampled}", "", "| game | sampled | decompiled | failures |", "|---|---|---|---|"]
        for name, g in games.items():
            lines.append(f"| {name} | {g['sampled']} | {g['decompiled']} | {len(g.get('failures', []))} |")
        lines.append("")
    stem = args.reports / f"stage2_followup_{args.date}"
    args.reports.mkdir(parents=True, exist_ok=True)
    stem.with_suffix(".json").write_text(json.dumps(result, indent=1))
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n")
    print(f"wrote {stem}.json and {stem}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
