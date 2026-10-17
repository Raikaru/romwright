#!/usr/bin/env python3
"""Upgrade round 1 (compile-failure classes) gate report: every fix on its own and all of them together, against all of them off.

  upgrade1_report.py --out DIR [--reports benchmarks/reports] [--tag p1] [--date 20261014] [--extra FILE.json]

Reads, from DIR (the measurement host's out directory):
  m2-l<N>-<tag>-<arm>.json                m22-002 reports (lane 1 = MWCC seed 20261010, 2 = seed 20261011, 3 = ee-gcc)
  m3-<lane>-<tag>-<arm>.json and -functions.json    m22-003 reports and per-function rows
  m21-001_<arm>.json, ps2_success_<arm>.json, printer_diff_<arm>.json    when present
and writes `upgrade1_gates_<date>.{json,md}`. Arms: `off` = every switch of this round disabled, `def` = the default build,
`only-<key>` = that fix alone (every other switch off). Switch of each key: SWITCHES below. The compile-failure class of a function
is `tests/m22-003/classes.py classify_message` of its first diagnostic; the sub-classes this round names (`c1`: a byte-array local
assigned a scalar or an array cast; `odd`: an `undefinedN` of a width no C type has; `partial`: `_off_w_` members; `union members`:
`.u4`/`.whole`) are matched on the first diagnostic's source line. Nothing is hand-edited.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tests" / "m22-003"))
import classes  # noqa: E402
import gate_pair  # noqa: E402

LANES002 = {"1": "m22-002 MWCC seed 20261010", "2": "m22-002 MWCC seed 20261011", "3": "m22-002 ee-gcc"}
LANES003 = ["dds", "rc", "p4", "gh", "ghclone", "ff", "dc", "dk"]
SWITCHES = {
    "sub": ("ROMWRIGHT_EXPORT_SUBPIECE_ARITY", "SUBPIECE intrinsic macro takes the printed offset argument"),
    "odd": ("ROMWRIGHT_EXPORT_ODD_WIDTHS", "`undefined3/5/6/7` declared as byte arrays"),
    "loc": ("ROMWRIGHT_EXPORT_LOCAL_VIEWS", "byte-array locals: whole-array values and `_off_w_` members"),
    "mis": ("ROMWRIGHT_EXPORT_MISMATCH_NAMES", "`_NAME` / `stack0x...` / `_DAT_...` mismatch-symbol uses"),
    "dec": ("ROMWRIGHT_EXPORT_DECLARED_VIEWS", "globals the header declares are read through that declaration"),
    "ctx": ("ROMWRIGHT_EXPORT_CONTEXT_NAMES", "`void (*T[])(..)` is a declared name"),
    "ptr": ("ROMWRIGHT_STRUCT_POINTEE_RUNS", "struct pointer field to a scalar run is `T *`"),
    "flt": ("ROMWRIGHT_EXPORT_FLOAT_ARGS", "integer literal passed to a `float` parameter is the float its bits spell"),
    "acc": ("ROMWRIGHT_EXPORT_DECLARED_ACCESS", "a header object of another shape than the printed one is read through its address"),
}
SUB = [
    ("syntax: undefinedN", lambda m, s: bool(re.search(r"\bundefined\d+\b", s))),
    ("syntax: macro arity", lambda m, s: "romwright_subpiece" in s or bool(re.search(r"\w+\([^()]*,\s*\d+\)", s)) and "')' expected" in m),
    ("c1: byte-array local value", lambda m, s: "cast specifies array type" in m or bool(re.match(r"\s*\w+\s*=\s*\((unsigned char|byte)\s*\*\)\s*0x", s))),
    ("b: partial member `_o_w_`", lambda m, s: bool(re.search(r"\._\d+_\d+_", s))),
    ("b: union members (.uN/.whole)", lambda m, s: bool(re.search(r"\.(u[1248]|s[1248]|f[48]|whole)\b", s))),
    ("undeclared `_NAME`/stack0x", lambda m, s: bool(re.search(r"\b_\w+Stack_|\bstack0x|\b_DAT_", s + " " + m))),
]


def first_diagnostic(row: dict):
    layer = row.get("layers", {}).get("romwright", {})
    context = layer.get("variants", {}).get("context") or layer.get("context") or {}
    if context.get("compiled") or not context.get("produced", True):
        return None
    diagnostics = context.get("diagnostics") or []
    if diagnostics:
        item = diagnostics[0]
        return item.get("message") or "", item.get("source") or ""
    errors = context.get("errors") or [context.get("error") or "unknown"]
    return errors[0], ""


def failure_classes(report: Path, keys: set | None = None) -> dict:
    data = json.load(open(report))
    counts: collections.Counter[str] = collections.Counter()
    sub: collections.Counter[str] = collections.Counter()
    for address, row in data["functions"].items():
        if keys is not None and address not in keys:
            continue
        first = first_diagnostic(row)
        if first is None:
            continue
        message, source = first
        counts[classes.classify_message(message)] += 1
        for name, test in SUB:
            if test(message, source):
                sub[name] += 1
    return {"classes": dict(counts), "named": dict(sub)}


def gate(name: str, base: Path, arms: dict[str, Path], reports: dict[str, Path]) -> dict:
    rows = gate_pair.rows(str(base))
    result = {"gate": name, "off": gate_pair.summary(rows), "arms": {}}
    if "off" in reports:
        result["off"].update(failure_classes(reports["off"]))
    def_rows = gate_pair.rows(str(arms["def"])) if "def" in arms else None
    for arm, path in arms.items():
        new = gate_pair.rows(str(path))
        if arm.startswith("no-") and def_rows is not None:
            # leave-one-out: every fix on but one, against the default on the same functions
            ref = {k: v for k, v in def_rows.items() if k in new}
            entry = {"summary": gate_pair.summary(new), **gate_pair.pair(ref, new), "def_on_same_functions": gate_pair.summary(ref)}
            result["arms"][arm] = entry
            continue
        entry = {"summary": gate_pair.summary(new), **gate_pair.pair(rows, new)}
        for key in ("better_addresses", "worse_addresses"):
            entry[key] = entry[key][:60]
        if arm in reports:
            entry["summary"].update(failure_classes(reports[arm]))
        if len(new) < len(rows):
            # an isolation arm ran on the functions whose outcome differs between off and def: off on those functions
            entry["off_on_same_functions"] = gate_pair.summary({k: v for k, v in rows.items() if k in new})
            if "off" in reports:
                entry["off_on_same_functions"].update(failure_classes(reports["off"], set(new)))
        result["arms"][arm] = entry
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reports", type=Path, default=HERE / "reports")
    parser.add_argument("--tag", default="p2", help="tag of the runs on the final build; the earlier tags in --earlier fill in what that build did not rerun")
    parser.add_argument("--earlier", default="p1", help="comma list of earlier tags (the previous build, same code for every switch it had)")
    parser.add_argument("--date", default="20261014")
    parser.add_argument("--extra", type=Path, action="append", default=[], help="JSON blobs (name=path) merged under `extra`")
    args = parser.parse_args()
    out = args.out
    tags = [args.tag] + [t for t in args.earlier.split(",") if t]

    def find(pattern: str):
        for t in tags:
            path = out / pattern.format(tag=t)
            if path.exists():
                return path
        return None

    gates = []
    for lane, label in LANES002.items():
        base = find(f"m2-l{lane}-{{tag}}-off.json")
        if base is None:
            continue
        arms = {a: find(f"m2-l{lane}-{{tag}}-{a}.json") for a in ["def"] + [f"only-{k}" for k in SWITCHES]}
        arms = {a: p for a, p in arms.items() if p is not None}
        gates.append(gate(label, base, arms, {}))
    for lane in LANES003:
        base = find(f"m3-{lane}-{{tag}}-off-functions.json")
        if base is None:
            continue
        arms, reports = {}, {"off": Path(str(base).replace("-functions.json", ".json"))}
        for a in ["def"] + [f"only-{k}" for k in SWITCHES] + [f"no-{k}" for k in SWITCHES]:
            path = find(f"m3-{lane}-{{tag}}-{a}-functions.json")
            if path is not None:
                arms[a] = path
                reports[a] = Path(str(path).replace("-functions.json", ".json"))
        label = f"m22-003 {lane}" if lane not in ("gh", "ghclone") else (
            "m22-003 gh (pristine repo copy: a smaller build than the harness clone)" if lane == "gh" else "m22-003 gh (harness clone)")
        gates.append(gate(label, base, arms, {a: p for a, p in reports.items() if p.exists()}))
    extra = {}
    for item in args.extra:
        if item.exists():
            extra[item.stem] = json.load(open(item))
    # decompile success on the PS2 wave images (fresh import per arm), m21-001 and the printer differential
    success = {}
    for arm in ("off", "def"):
        path = out / f"ps2_success_{arm}-bin3.json"
        if path.exists():
            data = json.load(open(path))["games"]
            success[arm] = {game: {"sampled": g["sampled"], "decompiled": g["decompiled"]} for game, g in data.items()}
    if success:
        extra["ps2_decompile_success"] = success
        if len(success) == 2:
            total = {arm: [sum(g["decompiled"] for g in games.values()), sum(g["sampled"] for g in games.values())] for arm, games in success.items()}
            extra["ps2_decompile_success_total"] = {"off [decompiled, sampled]": total["off"], "def [decompiled, sampled]": total["def"],
                                                    "games that differ": [g for g in success["def"] if success["def"][g] != success["off"].get(g)]}
    for arm in ("off", "def"):
        path = out / f"m21-001_{arm}.json"
        if path.exists():
            data = json.load(open(path))
            rows = data.get("rows", {})
            extra[f"m21-001_{arm}"] = {"status": data.get("status"), "failures": data.get("failures"),
                                       "rows": {image: {k: row[k] for k in ("truth", "found", "recall", "precision", "size_exact") if k in row}
                                                for image, row in rows.items() if isinstance(row, dict)}}
    for name in ("printer_diff_bin3-def.json", "printer_diff_bin3.json"):
        path = out / name
        if path.exists():
            data = json.load(open(path))
            extra["printer_differential"] = {key: data.get(key) for key in ("decompiled", "identical", "identical_rate")}
            break
    pointer_fields = {}
    for path in sorted(out.glob("ptrfields-*-def.json")):
        game = path.name[len("ptrfields-"):-len("-def.json")]
        off = path.with_name(path.name.replace("-def.json", "-off.json"))
        if off.exists():
            pointer_fields[game] = {"default": {k: v for k, v in json.load(open(path)).items() if k in ("addresses", "structs_printed", "pointer_fields", "scalar_pointee_types")},
                                    "runs_off": {k: v for k, v in json.load(open(off)).items() if k in ("structs_printed", "pointer_fields", "scalar_pointee_types")}}
    if pointer_fields:
        extra["struct_pointer_fields"] = pointer_fields
    report = {"benchmark": "upgrade1_gates", "date": args.date, "tag": args.tag,
              "switches": {k: {"env": v[0], "what": v[1]} for k, v in SWITCHES.items()}, "gates": gates, "extra": extra}
    args.reports.mkdir(parents=True, exist_ok=True)
    stem = args.reports / f"upgrade1_gates_{args.date}"
    stem.with_suffix(".json").write_text(json.dumps(report, indent=1))

    L = [f"# Upgrade round 1 (compile-failure classes) gates, {args.date}", "",
         "`off` = every switch of this round disabled. `def` = the default build (all on). `only-<key>` = that fix alone. "
         "exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.", "",
         "| key | switch (`=off` disables) | fix |", "|---|---|---|"]
    for k, (env, what) in SWITCHES.items():
        L.append(f"| {k} | `{env}` | {what} |")
    L += ["", "How the arms ran: one release build (`romwright-cli`, `romwright-worker`, the pinned `ghidra_opt`), each arm a wrapper binary that sets its switches and "
          "`ROMWRIGHT_ARM` (the m22-002 harness drops `ROMWRIGHT_*` from the environment), `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`. An m22-003 arm "
          "restores the lane's prepared work directory and repo from a pristine snapshot taken after its prepare stage (the prepare records absolute paths, so the same "
          "path is restored, never a copy at another path) and imports the retail image afresh; an m22-002 arm prepares its own work directory and repo copy. "
          "The final-gate arms (`off`, `def`) of every lane are full 200-function runs; the m22-002 lane-1 isolation arms (the m22-002 runs of the nine fixes alone) "
          "are full runs too, those of the first nine-fix build (tag p1) for `sub`..`ptr` and of the final build (tag p2) for `flt` and `acc` (`--earlier p1`: the code of those "
          "seven fixes is the same in both builds). An m22-003 isolation arm and every leave-one-out arm ran `--only` the functions whose outcome differs between "
          "`off` and `def` (what a fix can change); rc `only-loc` ran in full. gh: the `gh` rows are the pristine repo copy (`~/runs/Ps2Lanes/repos/gh`, a smaller "
          "build), `ghclone` the repository as the harness clones it; their 200-function samples differ. Isolation arms first started with unknown arm names "
          "and ran as the default; those results were discarded (`out/invalid_defaults/`) and the arms re-run."]
    L += ["", "## Final gate: every fix off against every fix on (one build, a fresh import and work directory per arm)", "",
          "| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled | gained exact | gained compiled |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for g in gates:
        o = g["off"]
        L.append(f"| {g['gate']} | off | {o['exact']} | {o['compiled']} | {o['mean_percent']} | | | | | | | |")
        for arm, e in g["arms"].items():
            if arm != "def":
                continue
            s = e["summary"]
            L.append(f"| {g['gate']} | {arm} | {s['exact']} | {s['compiled']} | {s['mean_percent']} | {e['better']} | {e['worse']} | {e['same']} | "
                     f"{len(e['lost_exact'])} | {len(e['lost_compiled'])} | {len(e['gained_exact'])} | {len(e['gained_compiled'])} |")
    L += ["", "## Each fix alone (every other switch off) against everything off", "",
          "An m22-002 arm is the whole 200-function sample. An m22-003 arm ran on the functions whose outcome differs between `off` and `def` "
          "(the others cannot change; `functions` is that count) and is compared with `off` on the same functions.", "",
          "| gate | fix | functions | off exact / compiled / mean % | fix alone exact / compiled / mean % | better / worse / same | lost exact | lost compiled | gained exact | gained compiled |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for g in gates:
        for arm, e in g["arms"].items():
            if not arm.startswith("only-"):
                continue
            o = e.get("off_on_same_functions", g["off"])
            s = e["summary"]
            L.append(f"| {g['gate']} | {arm} | {s['functions']} | {o['exact']} / {o['compiled']} / {o['mean_percent']} | {s['exact']} / {s['compiled']} / {s['mean_percent']} | "
                     f"{e['better']} / {e['worse']} / {e['same']} | {len(e['lost_exact'])} | {len(e['lost_compiled'])} | {len(e['gained_exact'])} | {len(e['gained_compiled'])} |")
    L += ["", "## Each fix left out of the default (every other switch on), against the default on the same functions", "",
          "A fix whose removal loses a compile or an exact match is carrying it in the default; a fix that only works with another is visible here "
          "and not in the table above.", "",
          "| gate | without | functions | default exact / compiled / mean % | without it exact / compiled / mean % | lost exact | lost compiled | functions worse by percent |",
          "|---|---|---|---|---|---|---|---|"]
    for g in gates:
        for arm, e in g["arms"].items():
            if not arm.startswith("no-"):
                continue
            d, s = e["def_on_same_functions"], e["summary"]
            # `pair` is (default -> without it): "lost" there is what the default had and the arm lacks
            L.append(f"| {g['gate']} | {arm[3:]} | {s['functions']} | {d['exact']} / {d['compiled']} / {d['mean_percent']} | {s['exact']} / {s['compiled']} / {s['mean_percent']} | "
                     f"{len(e['lost_exact'])} | {len(e['lost_compiled'])} | {e['worse']} |")
    L += ["", "## Compile-failure classes per m22-003 lane, off against def (functions that did not compile, by the compiler's first diagnostic)", "",
          "| lane | arm | classes |", "|---|---|---|"]
    for g in gates:
        if "classes" in g["off"]:
            L.append(f"| {g['gate']} | off | {json.dumps(g['off']['classes'], sort_keys=True)} |")
            e = g["arms"].get("def")
            if e and "classes" in e["summary"]:
                L.append(f"| {g['gate']} | def | {json.dumps(e['summary']['classes'], sort_keys=True)} |")
    names = [n for n, _ in SUB]
    L += ["", "## Named sub-classes, off against def (first diagnostic's source line)", "", "| lane | arm | " + " | ".join(names) + " |",
          "|---|---|" + "---|" * len(SUB)]
    for g in gates:
        if "named" in g["off"]:
            for arm, block in [("off", g["off"]), ("def", (g["arms"].get("def") or {}).get("summary", {}))]:
                if "named" in block:
                    L.append(f"| {g['gate']} | {arm} | " + " | ".join(str(block["named"].get(n, 0)) for n in names) + " |")
    L += ["", "## Named sub-classes, each fix alone against off on the same functions", "", "| lane | fix | off | fix alone |", "|---|---|---|---|"]
    for g in gates:
        for arm, e in g["arms"].items():
            if not arm.startswith("only-") or "named" not in e["summary"] or "off_on_same_functions" not in e:
                continue
            show = lambda block: ", ".join(f"{n}: {block['named'][n]}" for n in names if block["named"].get(n)) or "none"
            L.append(f"| {g['gate']} | {arm} | {show(e['off_on_same_functions'])} | {show(e['summary'])} |")
    L += ["", "## Functions that lost an exact match or a compile (default build against `off`)", ""]
    lost = False
    for g in gates:
        e = g["arms"].get("def")
        if e and (e["lost_exact"] or e["lost_compiled"]):
            lost = True
            L.append(f"- {g['gate']}: lost exact {e['lost_exact']}, lost compiled {e['lost_compiled']}")
    if not lost:
        L.append("none")
    for name, blob in extra.items():
        L += ["", f"## {name}", "", "```json", json.dumps(blob, indent=1)[:6000], "```"]
    stem.with_suffix(".md").write_text("\n".join(L) + "\n")
    print(f"wrote {stem}.json and {stem}.md ({len(gates)} gates)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
