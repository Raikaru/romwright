#!/usr/bin/env python3
"""The struct gate against the audit truth.

`types_infer`/`subtype.rs` give a pointer parameter a `Ty::Ptr(Ty::Struct)` whenever its body reads or writes
it at two or more offsets. The audit (`struct_inference_audit.py`, docs/console-research.md "Struct recovery
audit") measured that 47.7% of truth `void *` and 56% of truth typed scalar pointers get one too. Printing a
struct for those is a false claim, so the product gates the layout (`struct_types::gate`). This script scores
candidate gates with the audit's own truth and parameter population: it reuses `parse_inferred`,
`StructIndex` and the truth/dump files `struct_inference_audit.py` writes, and changes none of them.

    python3 benchmarks/struct_gate_sweep.py --work DIR [--games g1,g2] [--out OUT.json]

`DIR` holds `truth/<game>.json` and `dump/dump-<game>.json` (the audit's `--work` layout). The dump's `iso`
variant is scored: every function solved alone, which is what the shipped path equals to 0.1 point
(docs/console-research.md). A game with no dump is skipped.

Per gate and game, over the parameters the audit scores (`slot_clean`, a truth type):

  struct recall      truth struct pointers that get a layout and pass the gate / truth struct pointers
  false struct rate  truth non-struct pointers (void, scalar, pointer-to-pointer, code) that pass / those pointers
  non-pointer rate   truth non-pointer parameters (integers, floats) that pass / those parameters
  precision          passed truth struct pointers / passed pointer parameters of any truth kind
  offset precision   fields of the passed truth struct pointers at a truth field start / their fields
"""
import argparse
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fact_pack"))
import struct_inference_audit as audit  # noqa: E402

POINTER_KINDS = ("struct_ptr",) + audit.NON_STRUCT_KINDS


def placed(fields):
    """The fields `struct_types::placed` keeps: at a non-negative multiple of their natural alignment (at most 8),
    none overlapping an earlier one (the wider wins a tie). The gate measures these, as the product does."""
    kept, covered = {}, 0
    for offset, (size, family, bits) in sorted(fields.items(), key=lambda kv: (kv[0], -kv[1][0])):
        if offset < 0 or size <= 0 or offset % min(size, 8) != 0 or offset < covered:
            continue
        covered = offset + size
        kept[offset] = (size, family, bits)
    return kept


def features(fields):
    """The measures of a layout the candidate gates read; `run` is `romwright_core::struct_types::array_run`. Keep the two in step."""
    widths = {size for (size, _, _) in fields.values()}
    ordered = sorted(fields.items())
    dense = len(widths) == 1 and all(offset == index * next(iter(widths)) for index, (offset, _) in enumerate(ordered))
    run = len(widths) == 1 and all(b[0] - a[0] == next(iter(widths)) for a, b in zip(ordered, ordered[1:]))
    typed = any(family in ("ptr", "code", "float") or size > 4 for (size, family, _) in fields.values())
    span = max((offset + size for offset, (size, _, _) in fields.items()), default=0)
    qword = any(size == 8 and family not in ("float", "ptr") for (size, family, _) in fields.values())
    return {"fields": len(fields), "widths": len(widths), "dense": dense, "run": run, "typed": typed, "span": span, "qword": qword}


GATES = {
    "any struct (no gate)": lambda f: f["fields"] >= 1,
    "fields >= 2": lambda f: f["fields"] >= 2,
    "fields >= 3": lambda f: f["fields"] >= 3,
    "fields >= 4": lambda f: f["fields"] >= 4,
    "fields >= 2, not a dense scalar array": lambda f: f["fields"] >= 2 and not (f["dense"] and not f["typed"]),
    "fields >= 3, not a dense scalar array": lambda f: f["fields"] >= 3 and not (f["dense"] and not f["typed"]),
    "fields >= 2, two widths or typed": lambda f: f["fields"] >= 2 and (f["widths"] >= 2 or f["typed"]),
    "fields >= 3, two widths or typed": lambda f: f["fields"] >= 3 and (f["widths"] >= 2 or f["typed"]),
    "fields >= 4, two widths or typed": lambda f: f["fields"] >= 4 and (f["widths"] >= 2 or f["typed"]),
    "fields >= 3, not dense, span >= 16": lambda f: f["fields"] >= 3 and not (f["dense"] and not f["typed"]) and f["span"] >= 16,
    "fields >= 2, not a dense array of any type": lambda f: f["fields"] >= 2 and not f["dense"],
    "fields >= 3, not a dense array of any type": lambda f: f["fields"] >= 3 and not f["dense"],
    "fields >= 4, not a dense array of any type": lambda f: f["fields"] >= 4 and not f["dense"],
    "fields >= 3, not a run of one width": lambda f: f["fields"] >= 3 and not f["run"],
    "fields >= 3, not a run of one width, no 8-byte integer": lambda f: f["fields"] >= 3 and not f["run"] and not f["qword"],
    "fields >= 4, not a run of one width": lambda f: f["fields"] >= 4 and not f["run"],
}
# the gate struct_types::gate implements: MIN_FIELDS fields that are not a contiguous run of one width
SHIPPED = "fields >= 3, not a run of one width"


def population(game, work):
    truth = json.loads((work / "truth" / f"{game}.json").read_text())
    dump = json.loads((work / "dump" / f"dump-{game}.json").read_text())
    funcs = {r["entry"]: r for r in dump["functions"]}
    nslots = len(dump["int_slots"])
    sidx = {k: audit.StructIndex(v) for k, v in truth["structs"].items() if v.get("ok")}
    rows = []
    for addr, ft in truth["functions"].items():
        row = funcs.get(addr)
        if row is None or "iso" not in row:
            continue
        for p in ft["params"]:
            if "slot" not in p or not p.get("slot_clean") or p["slot"] >= nslots:
                continue
            kind = p["kind"]
            if kind in POINTER_KINDS:
                group = kind
            elif kind in ("int", "float", "wide"):
                group = "non_pointer"
            else:
                continue
            inferred = audit.parse_inferred(row["iso"][p["slot"]])
            record = {"group": group, "struct": inferred["kind"] == "struct", "has_body": bool(ft.get("access", {}).get(str(p.get("i")))) if kind == "struct_ptr" else None}
            if record["struct"]:
                fields = placed(inferred["fields"])
                record.update(features(fields))
                if kind == "struct_ptr" and p.get("key") in sidx:
                    S = sidx[p["key"]]
                    record["on_field"] = sum(1 for o in fields if S.match(o)[0] == "exact")
                    record["offsets"] = len(fields)
            rows.append(record)
    return rows


def score(rows, gate):
    c = collections.Counter()
    for r in rows:
        c["n:" + r["group"]] += 1
        if r["struct"] and gate(r):
            c["pass:" + r["group"]] += 1
            if r["group"] == "struct_ptr":
                c["on_field"] += r.get("on_field", 0)
                c["offsets"] += r.get("offsets", 0)
    non_struct = sum(c["n:" + k] for k in audit.NON_STRUCT_KINDS)
    non_struct_pass = sum(c["pass:" + k] for k in audit.NON_STRUCT_KINDS)
    passed_pointers = c["pass:struct_ptr"] + non_struct_pass
    pct = audit.pct
    return {
        "truth_struct_ptr": c["n:struct_ptr"], "struct_recall": pct(c["pass:struct_ptr"], c["n:struct_ptr"]),
        "truth_non_struct_ptr": non_struct, "false_struct_rate": pct(non_struct_pass, non_struct),
        "false_by_kind": {k: pct(c["pass:" + k], c["n:" + k]) for k in audit.NON_STRUCT_KINDS if c["n:" + k]},
        "non_pointer_params": c["n:non_pointer"], "non_pointer_rate": pct(c["pass:non_pointer"], c["n:non_pointer"]),
        "precision": pct(c["pass:struct_ptr"], passed_pointers),
        "offset_precision": pct(c["on_field"], c["offsets"]),
        "passed_struct_ptr": c["pass:struct_ptr"], "passed_false": non_struct_pass,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--games", default="")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    games = [g for g in args.games.split(",") if g] or sorted(p.name[5:-5] for p in (args.work / "dump").glob("dump-*.json"))
    per_game = {}
    pooled = []
    for game in games:
        if not (args.work / "truth" / f"{game}.json").exists():
            continue
        rows = population(game, args.work)
        per_game[game] = {name: score(rows, gate) for name, gate in GATES.items()}
        pooled += rows
        print(f"{game}: {len(rows)} parameters", file=sys.stderr)
    result = {"games": games, "shipped_gate": SHIPPED, "per_game": per_game,
              "pooled": {name: score(pooled, gate) for name, gate in GATES.items()}}
    header = ["gate", "struct recall %", "false struct %", "(void/scalar/ptr-ptr/code)", "non-pointer %", "precision %", "offset precision %"]
    print("| " + " | ".join(header) + " |\n|" + "---|" * len(header))
    for name, s in result["pooled"].items():
        by = "/".join(str(s["false_by_kind"].get(k)) for k in audit.NON_STRUCT_KINDS)
        print(f"| {name} | {s['struct_recall']} | {s['false_struct_rate']} | {by} | {s['non_pointer_rate']} | {s['precision']} | {s['offset_precision']} |")
    if args.out:
        args.out.write_text(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
