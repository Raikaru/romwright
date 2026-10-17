#!/usr/bin/env python3
"""P4.6 match-shaped emission: m22 context + standalone, token distance to m2c, diff classes.

Drives tests/m22-001_c_output.py's extraction, context, candidate producers and
agbcc/objdiff scoring on the 33 pokeemerald functions, but (unlike that file's
`main`) does not stop at reference-reassembly parity: ConvertIntToDecimalStringN
reassembles at 99.94% (one literal-pool relocation spelled against another
symbol), which is recorded, not fatal. m2c runs out-of-process only.

Per layer (romwright, m2c, stock) and wrapping (context, standalone) it reports
mean objdiff similarity and exact count; for the non-exact romwright functions
it classifies every differing instruction row of the objdiff record into the
classes in CLASSES. The plan gate (docs/game-decomp-plan.md P4.6) is evaluated
over the whole set and over the functions stock has output for.

Usage (VPS, repository root):
  benchmarks/match_emit.py --work ~/runs/NAME/m22 --report out.json [--env K=V ...]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_m22():
    spec = importlib.util.spec_from_file_location("m22_c_output", ROOT / "tests" / "m22-001_c_output.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["m22_c_output"] = module
    spec.loader.exec_module(module)
    return module


def rows_of(record, side, name):
    """The instruction rows of `name` on one side of an objdiff JSON record."""
    for symbol in json.loads(Path(record).read_text()).get(side, {}).get("symbols", []):
        if symbol.get("name") == name:
            return symbol.get("instructions", [])
    return []


def formatted(row):
    return (row.get("instruction") or {}).get("formatted", "")


def classify_function(record, name):
    """-> list of (class, target text, candidate text) for each differing row."""
    left, right = rows_of(record, "left", name), rows_of(record, "right", name)
    out = []
    for index, row in enumerate(left):
        kind = row.get("diff_kind", "DIFF_NONE")
        if kind == "DIFF_NONE":
            continue
        other = right[index] if index < len(right) else {}
        out.append((kind, formatted(row), formatted(other)))
    for index in range(len(left), len(right)):
        if right[index].get("diff_kind", "DIFF_NONE") != "DIFF_NONE":
            out.append(("DIFF_INSERT", "", formatted(right[index])))
    return out


def mnemonic(text):
    return text.split()[0] if text.split() else ""


def diff_class(kind, target, candidate):
    tm, cm = mnemonic(target), mnemonic(candidate)
    if kind in ("DIFF_INSERT", "DIFF_DELETE") or not target or not candidate:
        return "extra-or-missing-instruction"
    if kind == "DIFF_ARG_MISMATCH" or tm == cm:
        t_ops = re.findall(r"r\d+|#-?\w+|\w+", target)[1:]
        c_ops = re.findall(r"r\d+|#-?\w+|\w+", candidate)[1:]
        if tm in ("bl", "b") or (tm.startswith("b") and len(tm) <= 4 and tm != "bic"):
            return "branch-target-or-label"
        if any(o.startswith("#") for o in t_ops + c_ops) and [o for o in t_ops if not o.startswith("#")] == [
                o for o in c_ops if not o.startswith("#")]:
            return "constant"
        if tm.startswith("ldr") or tm.startswith("str"):
            return "memory-operand"
        return "register-allocation"
    if {tm.rstrip("s"), cm.rstrip("s")} <= {"lsl", "lsr", "asr", "mul", "add", "sub", "and", "orr", "eor", "mov", "neg"}:
        return "arithmetic-shape"
    if tm.startswith("b") or cm.startswith("b"):
        return "control-flow-shape"
    if tm.rstrip("s") in ("ldrb", "ldrh", "ldrsb", "ldrsh", "lsl", "lsr", "asr") and cm.rstrip("s") in (
            "ldrb", "ldrh", "ldrsb", "ldrsh", "lsl", "lsr", "asr", "and"):
        return "extension-or-cast"
    return "other-opcode"


def export_with_context(m, project, binary, address, outdir, context, *, env=None, extra=()):
    """`export-c --context HEADER`: the same export, minus what HEADER declares."""
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)
    argv = [m.CLI, "export-c", binary, m.PROGRAM, outdir, "--address", f"{address:x}", "--project", project, *extra]
    if context is not None:
        argv += ["--context", context]
    m.run(argv, env={**m.cli_env(), **(env or {})}, timeout=600)
    files = sorted(outdir.glob("*.c"))
    return "\n".join(f.read_text(errors="replace") for f in files) if files else None


# The reference with every product pass off: Ghidra's PrintC structure, no IR pass, no
# transform (console_research.py's `baseline-off`), over the same asserted names/prototypes.
STOCK_OFF = {"ROMWRIGHT_IR_PASSES": "", "ROMWRIGHT_RUST_STRUCTURING": "none", "ROMWRIGHT_NO_CANONICAL": "all"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--target", type=Path, default=ROOT / "target")
    parser.add_argument("--layers", default="romwright,romwright-elf,m2c,stock")
    parser.add_argument("--only", default="")
    parser.add_argument("--env", action="append", default=[], metavar="K=V",
                        help="environment for the romwright CLI (repeatable)")
    parser.add_argument("--fresh-import", action="store_true")
    args = parser.parse_args()
    for spec in args.env:
        key, value = spec.split("=", 1)
        os.environ[key] = value
    m = load_m22()
    target = args.target if args.target.is_absolute() else ROOT / args.target
    m.CLI = target / "release" / "romwright-cli"
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    layers = args.layers.split(",")
    log = lambda message: print(message, file=sys.stderr, flush=True)  # noqa: E731
    for tool in (m.ROM, m.ELF, m.DRIVER, m.M2C, m.M2C_MACROS, m.AGBCC, m.AS, m.OBJDUMP, m.OBJDIFF, m.CLI, m.CONSOLE):
        if not Path(tool).exists():
            raise SystemExit(f"missing prerequisite: {tool}")
    selected = [(n, u) for n, u in m.FUNCTIONS if not args.only or n in args.only.split(",")]
    elf_functions, elf_objects = m.load_elf_symbols()
    decls = m.Declarations()

    extracted, report_functions = [], {}
    for name, unit in selected:
        target_object = m.OBJ_ROOT / f"{unit}.o"
        fdir = work / "functions" / name
        fdir.mkdir(parents=True, exist_ok=True)
        asm, refs = m.extract_asm(target_object, name)
        (fdir / "target.s").write_text(asm)
        addresses = {a for a, _ in elf_functions.get(name, [])}
        if len(addresses) != 1:
            raise SystemExit(f"{name}: ELF address missing or ambiguous")
        assembled = m.run([m.AS, "-mcpu=arm7tdmi", "-o", fdir / "target.o", fdir / "target.s"])
        _, parity = m.objdiff(target_object, fdir / "target.o", name, fdir / "parity-objdiff.json")
        extracted.append((name, unit, refs))
        report_functions[name] = {"unit": unit, "target_object": str(target_object),
                                  "address": f"{addresses.pop():#x}", "asm_parity": parity,
                                  "assembled": assembled["exit"], "layers": {}}
    context_text, prototypes, notes = m.build_context(extracted, decls, elf_objects, elf_functions)
    context_path = work / "context.h"
    context_path.write_text(context_text)
    # m2c parses a context without directives (it has no preprocessor).
    m2c_context = work / "context-m2c.h"
    preprocessed = m.run(["gcc", "-E", "-P", "-undef", "-nostdinc", "-std=gnu89", "-x", "c", context_path, "-o", m2c_context])
    if preprocessed["exit"] != 0:
        raise SystemExit(f"cannot preprocess the m2c context: {preprocessed['stderr']}")
    if "stock-off" in layers and "romwright" not in layers:
        raise SystemExit("stock-off reuses the romwright project: name the romwright layer too")
    projects = {}
    for layer, binary in (("romwright", m.ROM), ("romwright-elf", m.ELF)):
        if layer in layers:
            projects[layer], _ = m.romwright_project(work, layer, binary, elf_functions, prototypes,
                                                     args.fresh_import, log)

    for name, unit, _refs in extracted:
        entry = report_functions[name]
        address = int(entry["address"], 16)
        target_object = Path(entry["target_object"])
        log(f"{name}")
        texts = {}
        for layer in layers:
            ldir = work / "layers" / layer / name
            shutil.rmtree(ldir, ignore_errors=True)
            ldir.mkdir(parents=True)
            context_text_candidate = None
            if layer in projects:
                binary = m.ROM if layer == "romwright" else m.ELF
                text, produce = m.romwright_export(projects[layer], binary, address, ldir / "export")
                # The context wrapping: the export told which names the header declares.
                context_text_candidate = export_with_context(m, projects[layer], binary, address,
                                                             ldir / "export-context", context_path)
            elif layer == "m2c":
                text, produce = m.m2c_candidate(work / "functions" / name / "target.s", name, m2c_context)
            elif layer == "stock-off":
                text = export_with_context(m, projects["romwright"], m.ROM, address, ldir / "export", None,
                                           env=STOCK_OFF, extra=("--transforms", ""))
                produce = {"exit": 0 if text else 1}
            else:
                text, produce = m.stock_candidate(name, ldir)
            if text is not None:
                (ldir / "candidate.c").write_text(text)
            texts[layer] = text
            variants = m.score(ldir, name, text, context_text, target_object)
            if context_text_candidate is not None:
                with_context = m.score(ldir, name, context_text_candidate, context_text, target_object)
                variants["context"] = with_context["context"]
            entry["layers"][layer] = {"produce_exit": produce.get("exit"), "candidate": str(ldir / "candidate.c") if text else None,
                                      "variants": variants}
        reference = texts.get("m2c") and m.function_definition(texts["m2c"], name)
        reference_tokens = m.tokens(reference) if reference else None
        for layer in layers:
            definition = texts[layer] and m.function_definition(texts[layer], name)
            if reference_tokens is None or not definition:
                entry["layers"][layer]["token_distance_to_m2c"] = None
                continue
            own = m.tokens(definition)
            entry["layers"][layer]["token_distance_to_m2c"] = m.levenshtein(own, reference_tokens)

    def sim(row, layer, variant):
        return row["layers"][layer]["variants"][variant]["similarity"]

    summary = {}
    for layer in layers:
        available = [f for f in report_functions.values() if f["layers"][layer]["candidate"] or layer != "stock"]
        summary[layer] = {"functions": len(available)}
        for variant in ("context", "standalone"):
            values = [sim(f, layer, variant) for f in available]
            summary[layer][variant] = {
                "mean": round(sum(values) / len(values), 3) if values else None,
                "exact": sum(v >= 100.0 for v in values),
                "compiled": sum(f["layers"][layer]["variants"][variant]["compile_exit"] == 0 for f in available)}
        distances = [f["layers"][layer]["token_distance_to_m2c"] for f in available]
        distances = [d for d in distances if d is not None]
        summary[layer]["token_distance_to_m2c"] = {"total": sum(distances), "functions": len(distances)}

    gate = {}
    if {"romwright", "m2c"} <= set(layers):
        for variant in ("context", "standalone"):
            wins = [n for n, f in report_functions.items() if sim(f, "romwright", variant) >= sim(f, "m2c", variant)]
            gate[f"objdiff_ours_ge_m2c_{variant}"] = {"functions": len(wins), "of": len(report_functions),
                                                       "fraction": round(len(wins) / len(report_functions), 4)}
        if "stock" in layers:
            common = [n for n, f in report_functions.items() if f["layers"]["stock"]["candidate"]
                      and f["layers"]["stock"]["token_distance_to_m2c"] is not None]
            ours = sum(report_functions[n]["layers"]["romwright"]["token_distance_to_m2c"] or 0 for n in common)
            stock = sum(report_functions[n]["layers"]["stock"]["token_distance_to_m2c"] for n in common)
            gate["token_distance_on_stock_functions"] = {"functions": common, "ours": ours, "stock": stock,
                                                         "ours_lt_stock": ours < stock}
        if "stock-off" in layers:
            both = [n for n, f in report_functions.items()
                    if f["layers"]["stock-off"]["token_distance_to_m2c"] is not None
                    and f["layers"]["romwright"]["token_distance_to_m2c"] is not None]
            ours = sum(report_functions[n]["layers"]["romwright"]["token_distance_to_m2c"] for n in both)
            off = sum(report_functions[n]["layers"]["stock-off"]["token_distance_to_m2c"] for n in both)
            closer = [n for n in both if report_functions[n]["layers"]["romwright"]["token_distance_to_m2c"]
                      < report_functions[n]["layers"]["stock-off"]["token_distance_to_m2c"]]
            gate["token_distance_vs_pass_off_reference"] = {
                "functions": len(both), "ours": ours, "pass_off": off, "ours_lt_pass_off": ours < off,
                "functions_closer": len(closer)}
        whole = [f["layers"]["romwright"]["token_distance_to_m2c"] for f in report_functions.values()]
        gate["token_distance_ours_vs_m2c_all"] = sum(d for d in whole if d is not None)

    classes = Counter()
    misses = {}
    if "romwright" in layers:
        for name, entry in report_functions.items():
            variant = entry["layers"]["romwright"]["variants"]["context"]
            if variant["similarity"] >= 100.0 or not variant.get("objdiff_record"):
                continue
            rows = classify_function(variant["objdiff_record"], name)
            tagged = [(diff_class(*row), *row) for row in rows]
            for cls, *_ in tagged:
                classes[cls] += 1
            misses[name] = {"similarity": variant["similarity"], "rows": tagged}

    report = {"schema": "match-emit/1", "context_notes": notes, "summary": summary, "gate": gate,
              "diff_classes": dict(classes.most_common()), "misses": misses, "functions": report_functions}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=1))
    print(json.dumps({"summary": summary, "gate": gate, "diff_classes": dict(classes.most_common())}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
