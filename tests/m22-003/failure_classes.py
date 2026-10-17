#!/usr/bin/env python3
"""Where romwright's C output loses on the m22-003 lanes: compile-failure classes, byte-difference classes, the functions m2c gets
exact and romwright does not, and a ranking of the classes by the exact matches they plausibly recover.

    python3 tests/m22-003/failure_classes.py [--reports benchmarks/reports] [--suffix diag] [--out benchmarks/reports/m22-003_failure_classes]

Reads `m22-003_<lane>_<suffix>.json` (the harness's per-function rows: first compile diagnostics with the offending line, the
byte-difference class of every compiled candidate) and writes `<out>.json` and `<out>.md`. Nothing is hand-edited: the owner of
a class is a table in this file (OWNERS), each entry with the evidence it rests on.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import classes  # noqa: E402

LANES = ["dds", "ff", "rc", "dc", "dk", "gh", "rcpal", "p4", "p4-eegcc"]
HEADLINE = "context"

# class -> (owner layer, why). Layers: printer (printc), export context (emit_m2c declarations and dependencies), types/prototypes,
# harness (this harness or its lane descriptor). Entries are filled from the examples in the report, not guessed: see OWNER_EVIDENCE.
PRINTER, CONTEXT, TYPES, HARNESS = "printer (printc)", "export context (emit_m2c declarations/dependencies)", "types/prototypes", "lane harness"
OWNERS: dict[str, tuple[str, str]] = {
    "type mismatch": (f"{TYPES}; printer for the array casts", "ff: constants printed as array casts `(unsigned char [8])0x3f3333333f000000`; "
        "struct arrays indexed as scalars (`ene_wrk[temp_v2 + 0x11] = param_2`, `door_keep[..] = 1` with the context's struct-array types); "
        "VU intrinsic `_vrnext(in_vuR)` assigned to an int. dc/dk: `(float **)` casts passed for `sceVu0FMATRIX` parameters."),
    "member access on a type the context lacks": (TYPES, "the printed access uses Ghidra's synthetic storage members (`key_now.u4[0]`, `eff_focus.u4[0]`, "
        "`GiftagAD.u4[0]`, `uStack_8._4_4_`) although the context declares the global with its real type (`extern u_short *key_now[32]`, "
        "`extern EFF_FOCUS eff_focus`, `extern sceGifTag GiftagAD`, `extern float SysCur[3]`); standalone compiles fail too, none are context-only."),
    "syntax error": (PRINTER, "Ghidra placeholder types printed as C types: `extern undefined6 _530;`, `extern undefined3 _4574;`, `undefined7 whole;` "
        "(sizes 3/5/6/7 have no C type); the same text fails standalone."),
    "illegal or unknown type name": (PRINTER, "address arithmetic on a `void *` global (`*(unsigned int *)(nowMonster + 0x1490)`, "
        "`edit_info + 0x70`, `edit_info + week_no * 0x300`): MWCC rejects void-pointer arithmetic, m2c's text for the same functions compiles and is "
        "exact in 3 (the cast to `char *`/`int` is missing)."),
    "call does not match prototype": (TYPES, "calls whose argument count or types disagree with the context's callee prototype (`sceVu0CopyVector(float *)` with a "
        "2-parameter prototype; `sceVu0UnitMatrix()`); romwright guessed the callee because the harness could not assert array-typedef parameters "
        "(harness artifact, fixed: `typedef_table_with_arrays`, see the fixed-artifacts table); what remains is the printer's call arguments."),
    "undeclared identifier": (PRINTER, "locals the text uses but does not declare (`undefined7 uStack_c0`, `_DAT_00252bf0.whole`, `_iStack_70`, `_abStack_170`)."),
    "no candidate produced": (PRINTER, "export-c emitted no function for the address (gh 1, rcpal 1)."),
    "conflicting types": (f"{CONTEXT}; the K&R share is harness-owned and fixed",
        "20 of 23 first-round ff failures were `T f();` K&R declarations against romwright's `unsigned int f(void)` head: the harness asserted no signature but compiled "
        "against the declaration (fixed: the unasserted target declaration is dropped from romwright's compile context). Left: `extern unsigned char "
        "BCommJmpTbl[84]` re-declaring a global the context already declares as `void (*BCommJmpTbl[])(ENE_WRK *)`."),
    "unit post-processing rejected": (HARNESS, "dc `ChangeSetUnit`: the repo's postprocess_object.py for dng_main.cpp raises 'expected one debug event stack' on any "
        "candidate that lacks the unit's own static; the unit's build step cannot be dropped without changing the object (left, 1 function)."),
    "incomplete type": (TYPES, "dk `LoadScript`: `EdScriptBuffer.u4[0]` on a context type that is an incomplete struct."),
    "compile: other": (PRINTER, "ff `SetMyLight` uses the value of a `void` call, `StageTitleLoad` an aggregate as an integer."),
    "other": (PRINTER, "ff `SetMyLight` uses the value of a `void` call, `StageTitleLoad` an aggregate as an integer."),
    "access width or signedness": (TYPES, "load/store width or signedness differs: the declared type of the object."),
    "length differs: extension instructions": (TYPES, "sign/zero extension differs: the declared type or a cast."),
    "single instruction": (PRINTER, "one instruction differs (register, immediate or opcode): expression shape or a constant's spelling."),
    "register allocation and stack layout": (PRINTER, "same instructions, different registers and frame slots: local variable count, order and lifetimes."),
    "register allocation": (PRINTER, "same instructions, different registers: temporaries and expression order."),
    "stack layout": (PRINTER, "same instructions, different frame offsets: local declaration order and arrays."),
    "few instructions differ": (PRINTER, "at most four instructions differ: expression shape."),
    "same instructions, different order": (PRINTER, "statement and expression order (scheduling)."),
    "length differs: few instructions": (PRINTER, "a few instructions more or fewer: redundant temporaries or folded expressions."),
    "length differs": (PRINTER, "different instruction count: control-flow shape, expression shape, loop forms."),
    "same length, many instructions differ": (PRINTER, "same size, different code: expression shape or control-flow form."),
}
OWNER_EVIDENCE: dict[str, str] = {}

HARNESS_ARTIFACTS = [
    ("context declarations the unit's compiler rejects", "`void * __asm__(\" \");`, bad typedef order: the harness compiled romwright against a context it could not compile (rcpal 67 of 96 failures; "
     "also m2c)", "per-unit context repair: drop the rejected declarations, retry", "rcpal, p4, dds"),
    ("SN ee-gcc 2.95.3 `long long` is 128-bit", "'unsupported wide integer operation' (rcpal 35, gh 13) and the size-check typedef (gh 3)",
     "descriptor `candidate_type_aliases`: `long long` -> `long` for SN units", "gh, rcpal"),
    ("K&R / unspellable target declaration", "romwright's head conflicts with a declaration it was never given a signature for",
     "romwright's compile context drops the target's declaration when none was asserted", "ff (20 conflicts), dc, dk"),
    ("array-typedef parameters", "`typedef float sceVu0FVECTOR[4]` was not in the typedef table, so callees were left unasserted and guessed",
     "`typedef_table_with_arrays`", "ff 33 fns, dc 13, dk 16"),
    ("C++ rename skipped", "the definition head regex matched across a comment that names the function", "rename on comment-masked text", "dc 1 (EndPrim)"),
    ("MWCC `__2` duplicate-name suffix", "the unit's build renames a function whose name it knows: 'no symbol' for a compiled candidate",
     "score the unique `<name>__<n>` symbol", "dc 2 (_CAMERA_QUAKE, _SCALE_VECTOR)"),
    ("GH wrapper `--extern-jtbl`", "the SN wrapper aborts on a jump-table argument that candidates do not have", "descriptor `candidate_drop_args`", "gh 2"),
]


def first_class(entry):
    for item in entry.get("diagnostics") or []:
        again = classes.classify_message(item["message"])  # the rules may be newer than the report
        return (again if item["class"] == "other" else item["class"]), item
    errors = entry.get("errors") or ([entry["error"]] if entry.get("error") else [])
    message = errors[0] if errors else "?"
    return classes.classify_message(message), {"message": message, "line": None, "source": None}


def load(path: Path):
    return json.loads(path.read_text())


def lane_rows(report):
    for key, row in report["functions"].items():
        yield key, row


NEAR_MISS = ("single instruction", "register allocation", "stack layout", "access width", "few instructions", "extension instructions",
             "nops and register copies", "same instructions, different order")


def headline(report, layer):
    b = report["summary"]["overall"]["all"].get(layer, {}).get(HEADLINE)
    return None if not b else {"exact": b["exact"], "compiled": b["compiled"], "mean_percent": b["mean_percent"], "functions": b["functions"]}


def analyse(reports: Path, suffix: str, baseline: str | None = None, overrides: dict | None = None):
    out = {"suffix": suffix, "suffix_overrides": overrides or {}, "baseline_suffix": baseline, "lanes": {}, "classes": {}, "m2c_ahead": {}, "harness_fixes": {}}
    for lane in LANES:
        lane_suffix = (overrides or {}).get(lane, suffix)
        path = reports / (f"m22-003_{lane}_{lane_suffix}.json" if lane_suffix else f"m22-003_{lane}.json")
        if not path.is_file():
            out["lanes"][lane] = {"missing": str(path)}
            continue
        report = load(path)
        layers = report["layers"]
        base_path = reports / (f"m22-003_{lane}_{baseline}.json" if baseline else f"m22-003_{lane}.json")
        if baseline is not None and base_path.is_file() and base_path != path:
            before = load(base_path)
            out["harness_fixes"][lane] = {layer: {"before": headline(before, layer), "after": headline(report, layer)}
                                          for layer in ("romwright", "m2c") if layer in layers}
        rom = [(k, r, r["layers"]["romwright"]["variants"]) for k, r in lane_rows(report)]
        failing = [(k, r, v) for k, r, v in rom if not v[HEADLINE]["compiled"]]
        compiled = [(k, r, v) for k, r, v in rom if v[HEADLINE]["compiled"]]
        exact = sum(v[HEADLINE]["exact"] for _k, _r, v in rom)
        rate = exact / max(len(compiled), 1)
        by_class: dict[str, dict] = {}
        for key, row, variants in failing:
            cls, diag = first_class(variants[HEADLINE])
            bucket = by_class.setdefault(cls, {"count": 0, "context_only": 0, "m2c_exact": 0, "examples": []})
            bucket["count"] += 1
            standalone = variants["standalone"]
            if standalone["compiled"]:
                bucket["context_only"] += 1  # the same text compiles without the unit's declarations: the context is what breaks it
            m2c = row["layers"].get("m2c", {}).get("variants", {}).get(HEADLINE, {})
            if m2c.get("exact"):
                bucket["m2c_exact"] += 1
            if len(bucket["examples"]) < 2:
                bucket["examples"].append({"address": row["address"], "name": row["name"], "message": diag["message"][:160],
                                           "line": diag.get("line"), "source": diag.get("source")})
        diff_classes: dict[str, int] = {}
        for _key, _row, variants in compiled:
            entry = variants[HEADLINE]
            if not entry["exact"]:
                kind = (entry.get("diff") or {}).get("kind", "not classified")
                diff_classes[kind.split(":")[0] if kind.startswith("single instruction") else kind] = \
                    diff_classes.get(kind.split(":")[0] if kind.startswith("single instruction") else kind, 0) + 1
        out["lanes"][lane] = {
            "functions": len(rom), "compile_failures": len(failing), "romwright_exact": exact,
            "m2c_exact": sum(r["layers"]["m2c"]["variants"][HEADLINE]["exact"] for _k, r, _v in rom) if "m2c" in layers else None,
            "exact_rate_among_compiled": round(rate, 3), "failure_classes": by_class,
            "byte_difference_classes_of_compiled_not_exact": dict(sorted(diff_classes.items(), key=lambda kv: -kv[1])),
        }
        # functions m2c gets exact and romwright does not
        ahead = []
        for key, row, variants in rom:
            m2c = row["layers"].get("m2c", {}).get("variants", {}).get(HEADLINE, {})
            entry = variants[HEADLINE]
            if m2c.get("exact") and not entry["exact"]:
                if not entry["compiled"]:
                    cls, diag = first_class(entry)
                    cause, detail = "compile failure: " + cls, diag["message"][:120]
                else:
                    diff = entry.get("diff") or {}
                    cause, detail = diff.get("kind", "not classified"), f"{diff.get('differing_words', '?')} word(s), {entry['percent']:.1f}%"
                    stand = variants["standalone"]
                    if stand.get("exact"):
                        cause, detail = "context variant only (standalone is exact)", detail
                ahead.append({"address": row["address"], "name": row["name"], "size": row["size"], "cause": cause, "detail": detail,
                              "romwright_percent": round(entry["percent"], 1)})
        out["m2c_ahead"][lane] = ahead
    # classes across lanes
    totals: dict[str, dict] = {}
    for lane, data in out["lanes"].items():
        if "failure_classes" not in data:
            continue
        for cls, bucket in data["failure_classes"].items():
            t = totals.setdefault("compile: " + cls, {"functions": 0, "context_only": 0, "m2c_exact": 0, "expected_exact_recovered": 0.0,
                                                     "lanes": {}, "kind": "compile failure"})
            t["functions"] += bucket["count"]
            t["context_only"] += bucket["context_only"]
            t["m2c_exact"] += bucket["m2c_exact"]
            t["expected_exact_recovered"] += bucket["count"] * data["exact_rate_among_compiled"]
            t["lanes"][lane] = bucket["count"]
        for kind, count in data["byte_difference_classes_of_compiled_not_exact"].items():
            t = totals.setdefault("bytes: " + kind, {"functions": 0, "m2c_exact": 0, "expected_exact_recovered": 0.0, "lanes": {},
                                                    "kind": "byte difference"})
            t["functions"] += count
            t["lanes"][lane] = count
    for lane, ahead in out["m2c_ahead"].items():
        for item in ahead:
            key = ("compile: " + item["cause"].split(": ", 1)[1]) if item["cause"].startswith("compile failure") else "bytes: " + item["cause"]
            if key in totals:
                totals[key]["m2c_exact"] = totals[key].get("m2c_exact", 0) + (0 if item["cause"].startswith("compile failure") else 1)
    for name, t in totals.items():
        label = name.split(": ", 1)[1]
        owner = OWNERS.get(label) or next((v for k, v in OWNERS.items() if label.startswith(k)), ("unassigned", ""))
        t["owner"], t["owner_evidence"] = owner[0], owner[1]
        t["expected_exact_recovered"] = round(t["expected_exact_recovered"], 1)
        # plausible gain: a compile failure recovers the lane's exact rate among compiled candidates; a byte difference of a near-miss
        # kind recovers every function (one fix makes it exact), any other byte difference none
        near = t["kind"] == "byte difference" and label.startswith(NEAR_MISS)
        t["plausible_exact_gain"] = t["expected_exact_recovered"] if t["kind"] == "compile failure" else (t["functions"] if near else 0)
    out["classes"] = dict(sorted(totals.items(), key=lambda kv: (-kv[1]["plausible_exact_gain"], -kv[1]["m2c_exact"], -kv[1]["functions"])))
    return out


def markdown(result):
    lines = ["# m22-003 failure classes: where romwright's C output loses", "",
             f"Source: `m22-003_<lane>_{result['suffix']}.json` of the nine lanes{(' (except ' + ', '.join(f'{k}: `_{v}`' for k, v in result['suffix_overrides'].items()) + ')') if result['suffix_overrides'] else ''} (headline `context` variant, 200 functions per lane). "
             "A compile failure is classified by the compiler's first diagnostic; a compiled candidate that is not exact by a word-level "
             "comparison against the retail bytes. `context only` counts failures whose same text compiles without the unit's declarations "
             "(the standalone variant), i.e. where the context is what breaks it. `m2c exact` counts the functions m2c gets exact in the same class.", ""]
    lines += ["## Per lane", "", "| lane | romwright exact | m2c exact | compile failures | exact rate among compiled |", "|---|---|---|---|---|"]
    for lane, d in result["lanes"].items():
        if "functions" in d:
            lines.append(f"| {lane} | {d['romwright_exact']} | {d['m2c_exact']} | {d['compile_failures']} of {d['functions']} | {d['exact_rate_among_compiled']:.2f} |")
    lines += ["", "## Ranked classes (across lanes)", "",
              "Ranked by plausible exact gain: a compile-failure class recovers (failures x the lane's exact rate among the candidates that "
              "compile); a byte-difference class recovers all its functions when it is a near miss (a single instruction, register or stack "
              "difference, a few instructions, an extension or width, a reordering) and none otherwise. `m2c exact` is the number of those "
              "functions that m2c gets exact.", "",
              "| rank | class | functions | plausible exact gain | m2c exact | context only | owner | per lane |", "|---|---|---|---|---|---|---|---|"]
    for rank, (name, t) in enumerate(result["classes"].items(), 1):
        lane_text = ", ".join(f"{lane} {n}" for lane, n in t["lanes"].items())
        lines.append(f"| {rank} | {name} | {t['functions']} | {t['plausible_exact_gain']} | {t['m2c_exact']} | {t.get('context_only', '-')} | "
                     f"{t['owner']} | {lane_text} |")
    if result.get("harness_fixes"):
        lines += ["", "## Harness-owned classes fixed in this round (romwright / m2c at the `context` variant: exact / compiled / mean %)", "",
                  "| lane | romwright before | romwright after | m2c before | m2c after |", "|---|---|---|---|---|"]
        for lane, d in result["harness_fixes"].items():
            def fmt(h):
                return "-" if not h else f"{h['exact']} / {h['compiled']} / {h['mean_percent']:.1f}"
            lines.append(f"| {lane} | {fmt(d['romwright']['before'])} | {fmt(d['romwright']['after'])} | "
                         f"{fmt(d.get('m2c', {}).get('before'))} | {fmt(d.get('m2c', {}).get('after'))} |")
    lines += ["", "## Harness artifacts found (and fixed unless noted)", "", "| artifact | symptom | fix | lanes |", "|---|---|---|---|"]
    lines += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in HARNESS_ARTIFACTS]
    lines += ["", "### Owners and the evidence for them", ""]
    for name, t in result["classes"].items():
        if t["owner_evidence"]:
            lines.append(f"- **{name}** -> {t['owner']}: {t['owner_evidence']}")
    lines += ["", "## Compile failures per lane, with two examples per class", ""]
    for lane, d in result["lanes"].items():
        if "failure_classes" not in d:
            continue
        lines += [f"### {lane}: {d['compile_failures']} of {d['functions']}", "", "| class | count | context only | m2c exact | example 1 | example 2 |", "|---|---|---|---|---|---|"]
        for cls, b in sorted(d["failure_classes"].items(), key=lambda kv: -kv[1]["count"]):
            ex = [f"`{e['address']}` {e['name']}: `{(e['source'] or e['message'])[:90]}` ({e['message'][:60]})" for e in b["examples"]]
            ex += [""] * (2 - len(ex))
            lines.append(f"| {cls} | {b['count']} | {b['context_only']} | {b['m2c_exact']} | {ex[0]} | {ex[1]} |")
        lines.append("")
    lines += ["## Functions m2c gets exact and romwright does not", ""]
    for lane in ("dk", "rcpal", "dc") + tuple(l for l in LANES if l not in ("dk", "rcpal", "dc")):
        ahead = result["m2c_ahead"].get(lane)
        if ahead is None:
            continue
        counts: dict[str, int] = {}
        for item in ahead:
            counts[item["cause"]] = counts.get(item["cause"], 0) + 1
        lines += [f"### {lane}: {len(ahead)} functions", "", "| cause | count |", "|---|---|"]
        lines += [f"| {c} | {n} |" for c, n in sorted(counts.items(), key=lambda kv: -kv[1])]
        lines += ["", "| address | function | bytes | cause | detail |", "|---|---|---|---|---|"]
        for item in sorted(ahead, key=lambda i: i["address"]):
            lines.append(f"| {item['address']} | {item['name'][:40]} | {item['size']} | {item['cause']} | {item['detail']} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--reports", type=Path, default=Path(__file__).resolve().parents[2] / "benchmarks" / "reports")
    parser.add_argument("--suffix", default="fix2", help="reports analysed: m22-003_<lane>_<suffix>.json")
    parser.add_argument("--lane-suffix", default="", help="per-lane report suffix, e.g. ff=fix3,dc=fix3")
    parser.add_argument("--baseline", default="", help="earlier report suffix to show the harness fixes against ('' = m22-003_<lane>.json)")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    out = args.out or args.reports / "m22-003_failure_classes"
    result = analyse(args.reports, args.suffix, args.baseline,
                     dict(item.split("=") for item in args.lane_suffix.split(",") if item))
    out.with_suffix(".json").write_text(json.dumps(result, indent=1))
    out.with_suffix(".md").write_text(markdown(result))
    print(f"wrote {out.with_suffix('.json')} and {out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
