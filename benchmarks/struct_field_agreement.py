#!/usr/bin/env python3
"""Field agreement: how much of the truth source's member access a candidate prints as member access.

The truth is what the donor decompilation's own source does with each struct-pointer parameter: the audit
(`struct_inference_audit.py donor-truth`) records, per function and parameter, every field the body reads or
writes as `(offset, size, class, target)`. The candidate is a romwright `export-c` file of the same function
(m22-002 writes it under `functions/<addr>_<name>/romwright/export/`). A truth access is *agreed* when the
candidate prints a member access (`param->field`, or `((S *)param)->field` where an asserted `void *`
signature keeps the parameter untyped) whose field sits at that offset in the struct definition the file
carries; the offsets are read from the `/* +0xN */` the definitions end each field with.

    field agreement = distinct (function, parameter, offset) truth accesses agreed / all of them

Also reported: the member accesses the candidate prints that the source does not make at that offset (printed
but not agreed), and the share of functions with at least one truth access that print at least one member
access. The same measure on a candidate that prints pointer arithmetic is 0.

    python3 benchmarks/struct_field_agreement.py --report M22.json --work M22WORK --truth TRUTH.json [--out OUT.json]

`--report` is an m22-002 report (its `functions` name the sample), `--work` the harness's `--work` directory the
candidates sit in, `--truth` the audit's truth file for the donor (`ps2-persona-4.json`).
"""
import argparse
import json
import re
from pathlib import Path

STRUCT = re.compile(r"struct\s+(\w+)\s*\{(.*?)\n\};", re.S)
FIELD_LINE = re.compile(r"^\s*(?P<decl>[^;/\n]+);\s*/\*\s*\+0x(?P<offset>[0-9a-fA-F]+)\s*\*/", re.M)


def field_name(declaration):
    """The declared identifier of one field line: `int (*cb)()`, `Foo *tab[3]`, `float x`."""
    declaration = re.sub(r"\[[^\]]*\]", "", declaration)
    declaration = re.sub(r"\)\s*\([^)]*\)\s*$", ")", declaration)
    names = re.findall(r"[A-Za-z_]\w*", declaration)
    return names[-1] if names else None


def structs_of(text):
    out = {}
    for name, body in STRUCT.findall(text):
        fields = {}
        for line in FIELD_LINE.finditer(body):
            field = field_name(line.group("decl"))
            if field:
                fields[field] = int(line.group("offset"), 16)
        out[name] = fields
    return out


def parameters(text, function):
    """`[(type, name)]` of `function`'s definition, or None."""
    found = re.search(r"\b" + re.escape(function) + r"\s*\(([^)]*)\)\s*\{", text)
    if not found:
        return None
    rows = []
    for part in found.group(1).split(","):
        part = part.strip()
        match = re.match(r"(.*?)(\w+)\s*(?:\[[^\]]*\])?$", part)
        if part and part != "void" and part != "..." and match:
            rows.append((match.group(1).strip(), match.group(2)))
    return rows


def member_accesses(text, structs, name, header_type):
    """Offsets printed as member accesses through parameter `name`."""
    offsets = set()
    typed = header_type.replace("*", "").strip()
    forms = [re.compile(r"\b" + re.escape(name) + r"\s*->\s*(\w+)")]
    if typed in structs:
        for field in forms[0].findall(text):
            if field in structs[typed]:
                offsets.add(structs[typed][field])
    for struct, field in re.findall(r"\(\(\s*(\w+)\s*\*\s*\)\s*" + re.escape(name) + r"\s*\)\s*->\s*(\w+)", text):
        if struct in structs and field in structs[struct]:
            offsets.add(structs[struct][field])
    # a parameter the body writes is read through a local of the struct type (`S *param_1_s = (S *)param_1;`)
    alias = re.search(r"\b(\w+)\s*\*\s*" + re.escape(name) + r"_s\s*=", text)
    if alias and alias.group(1) in structs:
        for field in re.findall(r"\b" + re.escape(name) + r"_s\s*->\s*(\w+)", text):
            if field in structs[alias.group(1)]:
                offsets.add(structs[alias.group(1)][field])
    return offsets


def is_float(type_text):
    return bool(re.search(r"\b(float|double)\b", type_text)) and "*" not in type_text


def agreement(report, work, truth):
    rows = []
    totals = dict(functions=0, with_truth=0, with_candidate=0, truth_accesses=0, agreed=0, printed=0, printed_wrong=0,
                  printing_functions=0)
    for key, entry in sorted(report["functions"].items()):
        address, name = int(entry["address"], 16), entry["name"]
        ft = truth["functions"].get(f"{address:08x}")
        totals["functions"] += 1
        if not ft:
            continue
        files = sorted((work / "functions" / f"{address:08x}_{name}" / "romwright" / "export").glob("*.c"))
        text = "\n".join(f.read_text(errors="replace") for f in files)
        structs = structs_of(text)
        params = parameters(text, name) if text else None
        row = dict(function=name, address=f"{address:08x}", truth=0, agreed=0, printed=0, printed_wrong=0)
        ints = [(t, n) for t, n in (params or []) if not is_float(t)]
        for p in ft["params"]:
            if p["kind"] != "struct_ptr" or not p.get("slot_clean") or "slot" not in p:
                continue
            if p.get("key") not in truth["structs"] or not truth["structs"][p["key"]].get("ok"):
                continue
            wanted = {a[0] for a in ft.get("access", {}).get(str(p["i"]), []) if a[2] != "agg"}
            if not wanted:
                continue
            row["truth"] += len(wanted)
            if text and p["slot"] < len(ints):
                header_type, pname = ints[p["slot"]]
                printed = member_accesses(text, structs, pname, header_type)
                row["agreed"] += len(wanted & printed)
                row["printed"] += len(printed)
                row["printed_wrong"] += len(printed - wanted)
        if not row["truth"]:
            continue
        rows.append(row)
        totals["with_truth"] += 1
        totals["truth_accesses"] += row["truth"]
        totals["agreed"] += row["agreed"]
        totals["printed"] += row["printed"]
        totals["printed_wrong"] += row["printed_wrong"]
        totals["with_candidate"] += int(bool(text))
        totals["printing_functions"] += int(row["printed"] > 0)
    totals["field_agreement"] = round(totals["agreed"] / totals["truth_accesses"], 4) if totals["truth_accesses"] else None
    totals["functions_printing_members"] = (
        round(totals["printing_functions"] / totals["with_truth"], 4) if totals["with_truth"] else None)
    return totals, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--truth", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    totals, rows = agreement(json.loads(args.report.read_text()), args.work, json.loads(args.truth.read_text()))
    print(json.dumps(totals))
    if args.out:
        args.out.write_text(json.dumps({"report": str(args.report), "totals": totals, "functions": rows}, indent=1))


if __name__ == "__main__":
    main()
