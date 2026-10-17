#!/usr/bin/env python3
"""Hex-Rays (IDA Pro 9.4, idalib) as a comparator column for the corpus wave. INTERNAL ONLY.

Hex-Rays' EULA section 2.1(v) restricts benchmarking the Software and publishing performance data
"without first inviting HEX-RAYS to review the results". This script writes its own report,
`benchmarks/reports/console_research_wave_hexrays_<date>.{json,md}`, and nothing else: no Hex-Rays
number goes into console_research_wave_<date>.* or any other report (the join contract of
docs/console-research.md, "Join contract for another tool's comparator column").

Join. `--wave-report` (repeatable; a later report wins per image id) names the console_research.py
--corpus-wave report(s) that hold the samples: `images.<id>.samples.<seed>` and `.sample`, address
labels `%08x` (main module) or `<module>:%08x`. This script never draws a sample; it scores exactly
those labels. The images, truth, the stripped-variant rule (an ELF with a .symtab is run stripped,
llvm-strip --strip-all, by console_research.prepared_binary), the metrics (console_research_wave.
score_found, console_research.dwarf_scores, locals of the frozen definitions), the sign test
(console_research_wave.sign_test) and the summary keys are the harness's own, imported not copied.

Scope, per image. IDA covers the **main module** only (the one program it opens). Overlays, RELs and
other modules are listed per image as not covered. Where IDA has no loader (GBA, NDS, DOL, XEX
payloads) the main module is handed over as a flat image at the importer's load address with the
importer's entry point seeded; creation of a function at a sampled address where IDA's own analysis
made none is for the decompile metrics only. Discovery rows are IDA's own function list, never
given the truth. Headline IDA is the install as Hex-Rays ships it (benchmarks/hexrays_research.py
`shipped`), auto-analysis only (no FLIRT beyond what a loader applies by default, no Lumina).

Phases (cached under --cache; a re-run resumes):
  analyze    IDA load + auto-analysis per image, wall time with load, the function list: needs no sample
  decompile  Hex-Rays on the image's main-module sample labels: needs a wave report with its samples
  --analyze-only runs the first only.

Usage
  python3 benchmarks/hexrays_wave.py --analyze-only                       # sample-independent phase
  python3 benchmarks/hexrays_wave.py --wave-report benchmarks/reports/console_research_wave_20261010.json
  python3 benchmarks/hexrays_wave.py --wave-report A.json --wave-report B.json --images gc-melee,psx-rage-racer
  python3 benchmarks/hexrays_wave.py --render-only --out benchmarks/reports/console_research_wave_hexrays_20261010.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import console_research as cr  # noqa: E402
import console_research_wave as wave  # noqa: E402
import hexrays_research as hr  # noqa: E402

M21 = cr.M21
REPORTS = ROOT / "benchmarks" / "reports"
CACHE = Path.home() / ".cache" / "romwright" / "hexrays-eval" / "wave"
EULA = ("Hex-Rays' EULA (`license.txt` in the IDA install), section 2.1(v): the Customer will not \"use the Software if "
        "You are a competitor, or use the Software in any manner that competes with HEX-RAYS, including but not "
        "limited to, benchmarking, collecting and publishing data or analysis relating to the performance of the "
        "Software, or developing or marketing a product that is competitive with any Software or service without "
        "first inviting HEX-RAYS to review the results\". This report is benchmarking data of that kind. Hex-Rays "
        "has not been invited to review it. INTERNAL ONLY: do not publish, quote or commit it to a public "
        "repository.")
FEATURES = {"gba": "arm", "nds": "arm", "gc": "gekko", "wii": "gekko", "n64": "mips", "psx": "mips",
            "ps1": "mips", "ps2": "r5900", "psp": "psp", "x360": "xenon"}


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# What IDA is given, per platform
# ---------------------------------------------------------------------------

class NotCovered(Exception):
    """The image (or its main module) cannot be given to IDA; the message is the reason."""


def main_module(spec: dict) -> dict:
    info = spec["wave"]
    declared = next((m for m in info["modules"] if m["name"] == wave.MAIN), None) or {}
    return declared


def main_file(spec: dict, corpus: Path) -> Path:
    """The file holding the main module: the staged image, or the DOL a disc image's meta.json names."""
    info = spec["wave"]
    declared = main_module(spec)
    relative = declared.get("image") or info["meta"]["image"]
    path = corpus / info["label"] / relative
    if not path.is_file():
        raise NotCovered(f"main module file {relative} absent")
    return path


def hex_of(value, default=None):
    return wave.hex_int(value) if value is not None else default


def prepare_arm_rom(spec, corpus: Path, cache: Path) -> hr.Prepared:
    declared = main_module(spec)
    base = hex_of(declared.get("load_address"), 0x08000000)
    path = main_file(spec, corpus)
    size = path.stat().st_size
    return hr.Prepared(path, True, hr.paragraph_args("arm", base), "arm",
                       f"the raw ROM as one segment at {base:#x} (IDA has no GBA loader), processor ARM, entry {base:#x} "
                       "seeded as ARM code, as the loaders seed the reset vector",
                       entries=[{"ea": base, "thumb": False}], base=base, ranges=[(base, base + size)],
                       default_thumb="auto")


def prepare_nds_arm9(spec, corpus: Path, cache: Path) -> hr.Prepared:
    data = main_file(spec, corpus).read_bytes()
    offset, entry, ram, size = struct.unpack_from("<4I", data, 0x20)
    module = data[offset:offset + size]
    chunks = []
    at = next((a for a in range(0, len(module) - 8, 4)
               if struct.unpack_from("<2I", module, a) == (0xDEC00621, 0x2106C0DE)), None)
    note = "static module stored uncompressed (no NitroSDK module params found)"
    if at is not None:
        params = struct.unpack_from("<9I", module, at - 28)
        if params[5]:
            unpacked = hr.uncompress_backward(module, ram, params[5])
            if unpacked is None:
                raise NotCovered("the ARM9 static module did not decompress")
            module, note = unpacked, "static module decompressed (MIi_UncompressBackward)"
        source = params[2] - ram
        for at2 in range(params[0] - ram, params[1] - ram, 12):
            address, length, _bss = struct.unpack_from("<3I", module, at2)
            if 0x01FF8000 <= address < 0x02000000:
                chunks.append((address, module[source:source + length]))
            source += length
    chunks.insert(0, (ram, module))
    out = cache / "prepared" / spec["id"] / "arm9.bin"
    base = hr.write_flat(chunks, out)
    end = max(a + len(d) for a, d in chunks)
    return hr.Prepared(out, True, hr.paragraph_args("arm", base), "arm",
                       f"the ARM9 static module ({note}) at {ram:#x} with its ITCM autoload block, raw (IDA has no NDS "
                       f"loader), processor ARM, entry {entry:#x} seeded as ARM; ARM7 and overlays not loaded",
                       entries=[{"ea": entry, "thumb": False}], base=base, ranges=[(base, end)], default_thumb="auto")


def prepare_dol(spec, corpus: Path, cache: Path) -> hr.Prepared:
    data = main_file(spec, corpus).read_bytes()
    offsets, addresses, sizes = (struct.unpack_from(">18I", data, at) for at in (0, 0x48, 0x90))
    chunks = [(addresses[i], data[offsets[i]:offsets[i] + sizes[i]]) for i in range(18) if sizes[i] and addresses[i]]
    exec_ranges = [(addresses[i], addresses[i] + sizes[i]) for i in range(7) if sizes[i] and addresses[i]]
    entry, = struct.unpack_from(">I", data, 0xE0)
    out = cache / "prepared" / spec["id"] / "main.bin"
    base = hr.write_flat(chunks, out)
    return hr.Prepared(out, True, hr.paragraph_args("ppc", base), "gekko",
                       f"the DOL's sections raw at their load addresses (IDA has no DOL loader), processor ppc "
                       f"big-endian, entry {entry:#x} seeded; RELs not loaded",
                       entries=[{"ea": entry, "thumb": False}], base=base, ranges=exec_ranges)


def prepare_native(spec, corpus: Path, cache: Path) -> hr.Prepared:
    """An image IDA's own loader reads: PS2/PSP ELF and PRX (stripped when it carries a .symtab), PSX-EXE, N64 ROM."""
    platform = spec["wave"]["platform"]
    binary = cr.prepared_binary(spec, corpus, cache)
    note = {"ps2": "ELF, IDA's ELF loader picks the R5900", "psp": "PRX/ELF, IDA's ELF loader picks Allegrex",
            "psx": "PS-X EXE, IDA's PSX loader (it applies the `psyq` signatures by default)",
            "ps1": "PS-X EXE, IDA's PSX loader", "n64": "z64 ROM, IDA's n64rom loader"}.get(platform, "IDA's own loader")
    if spec.get("strip") is True:
        note += "; run stripped (llvm-strip --strip-all), the file the importer and stock Ghidra read"
    ranges = None
    if platform in ("psx", "ps1"):
        head = binary.read_bytes()[:0x20]
        if head[:8] == b"PS-X EXE":
            address, length = struct.unpack_from("<II", head, 0x18)
            ranges = [(address, address + length)]  # the text segment; IDA's loader gives it no execute bit
    return hr.Prepared(binary, False, None, "mips", note, ranges=ranges)


def pe_at_base(path: Path, base: int | None, out: Path) -> tuple[Path, str]:
    """A PE file whose header ImageBase is `base`, as the XEX it came from loads it (a copy; the staged file is
    never touched). Without this IDA's PE loader maps the PE at its own preferred base."""
    data = bytearray(path.read_bytes())
    at = struct.unpack_from("<I", data, 0x3C)[0] + 24 + 28
    old = struct.unpack_from("<I", data, at)[0]
    if base is None or old == base:
        return path, f"at its header base {old:#x}"
    struct.pack_into("<I", data, at, base)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return out, f"ImageBase patched {old:#x} -> {base:#x} in a copy (the XEX's load address)"


def prepare_xex(spec, corpus: Path, cache: Path) -> hr.Prepared:
    path = main_file(spec, corpus)
    head = path.read_bytes()[:4]
    if head[:2] == b"MZ":
        staged, how = pe_at_base(path, hex_of(main_module(spec).get("load_address")), cache / "prepared" / spec["id"] / path.name)
        return hr.Prepared(staged, False, None, "xenon", f"the staged PE {path.name}, IDA's PE loader (PPC big-endian), {how}")
    declared = main_module(spec)
    try:
        prepared = hr.prepare_xex({"id": spec["id"], "image": f"{spec['wave']['label']}/{spec['wave']['meta']['image']}"},
                                  corpus, cache)
    except RuntimeError as error:
        stem = path.with_suffix("")
        for candidate in (stem.with_suffix(".pe"), stem.with_suffix(".exe")):
            if candidate.is_file() and candidate.read_bytes()[:2] == b"MZ":
                staged, how = pe_at_base(candidate, hex_of(declared.get("load_address")),
                                         cache / "prepared" / spec["id"] / candidate.name)
                return hr.Prepared(staged, False, None, "xenon",
                                   f"the staged {candidate.name} (the XEX's decoded PE; the builder's meta.json says so), "
                                   f"IDA's PE loader, {how}; the XEX itself needs LZX: {error}")
        raise NotCovered(str(error))
    prepared.input += f"; load address {hex_of(declared.get('load_address'), 0):#x}"
    return prepared


PREPARE = {"gba": prepare_arm_rom, "nds": prepare_nds_arm9, "gc": prepare_dol, "wii": prepare_dol,
           "ps2": prepare_native, "psp": prepare_native, "psx": prepare_native, "ps1": prepare_native,
           "n64": prepare_native, "x360": prepare_xex}


# ---------------------------------------------------------------------------
# Samples
# ---------------------------------------------------------------------------

def load_wave_reports(paths: list[Path]) -> dict[str, dict]:
    """{image id: image entry} merged over the reports (later wins); each entry carries its report's tools."""
    merged: dict[str, dict] = {}
    for path in paths:
        report = json.loads(path.read_text())
        for image_id, image in report["images"].items():
            if image.get("status") == "ran" and image.get("samples"):
                merged[image_id] = dict(image, _report=str(path), _tools=report.get("tools"),
                                        _generated=report.get("generated"), _seeds=report.get("seeds"),
                                        _n=report.get("n"))
    return merged


def main_labels(labels: list[str]) -> list[str]:
    return [label for label in labels if ":" not in label]


# ---------------------------------------------------------------------------
# One image
# ---------------------------------------------------------------------------

def module_summary(spec: dict, modules: dict, scored_modules: list[str] | None) -> dict:
    """Which modules of the truth IDA covers: the main module only."""
    others = [name for name in modules if name != wave.MAIN]
    return {"covered": [wave.MAIN] if wave.MAIN in modules else [],
            "not_covered": others, "not_covered_functions": sum(len(modules[m]["truth"]) for m in others),
            "main_truth_functions": len(modules.get(wave.MAIN, {"truth": {}})["truth"])}


def discovery(modules: dict, analysis: dict, ranges: list[tuple[int, int]]) -> dict:
    entry = modules[wave.MAIN]
    found = {f["entry"]: f["size"] for f in analysis["functions"]}
    row = wave.score_found(found, entry["truth"], entry["verified"], ranges)
    row["nested"] = wave.nesting(entry["truth"])
    return row


def run_image(spec: dict, args, samples: dict[str, dict], gate) -> dict:
    image_id, platform = spec["id"], spec["wave"]["platform"]
    meta = spec["wave"]["meta"]
    out: dict = {"status": "ran", "game": meta.get("game"), "platform": platform,
                 "version_match": meta.get("version_match", True), "truth_kind": meta.get("truth_kind")}
    modules = wave.load_modules(args.corpus / spec["truth"][1], spec["wave"]["modules"])
    out["modules"] = module_summary(spec, modules, None)
    if wave.MAIN not in modules:
        raise NotCovered("the truth has no main-module rows")
    prepared = PREPARE[platform](spec, args.corpus, args.cache)
    prepared.features = FEATURES.get(platform, prepared.features)
    if prepared.flat:
        # Several formats look like some other loader's input (a DOL read as an SNES ROM): force the raw loader.
        prepared.args += ' -T"Binary file"'
    out["input"] = {"file": str(prepared.path), "flat": prepared.flat, "ida_args": prepared.args,
                    "what": prepared.input, "entries": prepared.entries}
    run_dir = args.cache / "runs" / image_id
    ida_dir = hr.ida_dir_for("shipped", argparse.Namespace(cache=args.cache))
    with gate:
        analysis = hr.run_analysis(image_id, prepared, run_dir, ida_dir)
    out["analysis"] = {k: analysis.get(k) for k in (
        "ida_version", "hexrays_version", "open_s", "auto_wait_s", "analysis_s", "save_s", "processor", "segments",
        "signatures", "entry_points", "args", "flat", "worker_peak_rss_mb", "census")}
    out["analysis"]["process"] = {k: analysis["process"].get(k) for k in (
        "wall_s", "cpu_s", "user_s", "sys_s", "load_before", "load_after")}
    out["analysis"]["functions_total"] = len(analysis["functions"])
    # --- discovery: IDA's own function list over the main module's ranges
    sampled = samples.get(image_id)
    ranges, source = None, None
    if sampled:
        main_unit = next((u for u in sampled.get("units", []) if u["module"] == wave.MAIN), None)
        if main_unit and main_unit.get("ranges"):
            ranges, source = [tuple(r) for r in main_unit["ranges"]], f"the importer's main-module ranges ({sampled['_report']})"
    if ranges is None and wave.parse_ranges(meta.get("ranges")):
        ranges, source = wave.parse_ranges(meta.get("ranges")), "meta.json ranges"
    if ranges is None and prepared.ranges:
        ranges, source = [tuple(r) for r in prepared.ranges], "the loaded image's executable sections"
    if ranges is None:
        ranges = [(s["start"], s["end"]) for s in analysis["segments"] if s["perm"] & 1]
        source = "IDA's executable segments"
    out["ranges"] = {"source": source, "ranges": [list(r) for r in ranges]}
    out["discovery"] = discovery(modules, analysis, ranges)
    # --- decompile on the sample
    if not sampled:
        out["decompile"] = {"status": "no sample", "reason": "no --wave-report holds samples for this image"}
        return out
    if args.analyze_only or (args.decompile_images and image_id not in args.decompile_images):
        out["decompile"] = {"status": "not run", "reason": "analysis only" if args.analyze_only
                            else "not in --decompile-images (pipeline validation subset)"}
        return out
    labels = {seed: main_labels(items) for seed, items in sampled["samples"].items()}
    union = main_labels(sampled["sample"])
    out["sample"] = {"report": sampled["_report"], "tools": sampled["_tools"], "n": sampled["_n"],
                     "seeds": sampled["_seeds"], "union_labels": len(sampled["sample"]), "main_labels": len(union),
                     "other_module_labels": len(sampled["sample"]) - len(union),
                     "per_seed_main": {seed: len(items) for seed, items in labels.items()}}
    if not union:
        out["decompile"] = {"status": "no main labels", "reason": "every sampled label is in another module"}
        return out
    with gate:
        rows = hr.run_decompile(image_id, prepared, analysis, union, run_dir, args.stall, ida_dir)
    by_address = {r["address"]: r for r in rows}
    harness = {a: hr.harness_row(r) for a, r in by_address.items()}
    dwarf, dwarf_info = cr.wave_dwarf(spec, args.corpus, args.cache, hr.sha256_file(args.corpus / spec["image"]))
    dwarf_main = {k: v for k, v in (dwarf or {}).items() if isinstance(k, int)} or None

    def summarize(selection: list[str]) -> dict:
        view = {}
        for name in ("all", "found"):
            picked = hr.subset([harness[a] for a in selection], name)
            summary = hr.tool_summary(picked, dwarf_main, sampled=len(selection) if name == "all" else None)
            view[name] = summary
        view["created"] = sum(1 for a in selection if harness[a].get("created"))
        view["existed"] = sum(1 for a in selection if harness[a].get("existed"))
        return view

    out["hexrays"] = {"combined": summarize(union),
                      "per_seed": {seed: summarize(items) for seed, items in labels.items()}}
    out["dwarf"] = dwarf_info
    out["categories"] = hr.categorize(list(by_address.values()))
    out["per_function"] = {r["address"]: {k: r.get(k) for k in (
        "ok", "existed", "created", "decode_mode", "error", "seconds", "size", "instructions", "returns", "parameters",
        "gotos", "asm_blocks", "jumpouts", "feature_insns")} for r in rows}
    out["decompile"] = {"status": "ran"}
    return out


# ---------------------------------------------------------------------------
# Join with the wave report
# ---------------------------------------------------------------------------

def romwright_row(image: dict | None) -> dict | None:
    if not image:
        return None
    summary = (image.get("configs", {}).get("default") or {}).get("summary")
    if not summary:
        return None
    stock = ((image.get("stock") or {}).get("combined") or {}).get("summary")
    failure = ((image.get("stock") or {}).get("failure") or {}).get("label") if not stock else None
    return {"default": summary, "stock": stock, "stock_excluded": failure, "report": image.get("_report"),
            "tools": image.get("_tools")}


def hexrays_summary(row: dict) -> dict:
    """The hexrays image result as the harness's summary keys (`wave.rollup` / `metric_of` read these)."""
    d = row["discovery"]
    summary = {"recall": d["recall"], "precision": d["precision"], "recall_verified": d["recall_verified"],
               "precision_verified": d["precision_verified"], "discovered": d["found"],
               "recall_main": d["recall"], "precision_main": d["precision"],
               "recall_verified_main": d["recall_verified"], "precision_verified_main": d["precision_verified"]}
    combined = ((row.get("hexrays") or {}).get("combined") or {}).get("all")
    if combined:
        for key in ("sampled", "decompiled", "success_rate", "gotos", "labels", "lines", "arity_accuracy",
                    "type_exact_rate", "dwarf_functions"):
            summary[key] = combined.get(key)
    return summary


# metric -> needs the Romwright summary to be on the same labels as Hex-Rays (main module only)
DECOMPILE_METRICS = ["success_rate", "arity_accuracy", "type_exact_rate"]
DISCOVERY_METRICS = ["recall", "precision", "recall_verified", "precision_verified"]


def comparable_decompile(row: dict) -> bool:
    """Romwright's success/arity/type come from every sampled label, overlays and RELs included: they are
    on the same functions as Hex-Rays' only when the sample has no label outside the main module."""
    sample = row.get("sample") or {}
    return bool(sample) and sample.get("other_module_labels", 1) == 0


def sign_rows(games: dict) -> dict:
    """Sign tests of Romwright default against Hex-Rays over `games` {id: {romwright, hexrays, comparable}}."""
    tests = {}
    for metric in DISCOVERY_METRICS + DECOMPILE_METRICS:
        pairs = []
        for game in games.values():
            if metric in DECOMPILE_METRICS and not game["comparable_decompile"]:
                continue
            a = wave.metric_of(game["romwright"], metric, main=True)
            b = wave.metric_of(game["hexrays"], metric, main=True)
            if a is not None and b is not None:
                pairs.append((a, b))
        if pairs:
            tests[f"{metric}: Romwright default vs Hex-Rays"] = wave.sign_test(pairs)
    return tests


def build_not_covered(report: dict, skipped: list[dict], args) -> list[dict]:
    """Everything this report does not cover, with the reason."""
    out = [{"id": row.get("id") or row["dir"], "reason": f"skipped by the contract: {row['reason']}"} for row in skipped]
    staged = {p.parent.parent.name for p in args.corpus.glob("*/truth/meta.json")}
    for path in sorted(args.corpus.iterdir()):
        if path.is_dir() and path.name not in staged:
            out.append({"id": path.name, "reason": "no truth contract (no truth/meta.json): not a corpus-wave image"})
    for image_id, row in report["images"].items():
        if row.get("status") != "ran":
            out.append({"id": image_id, "reason": f"{row.get('status')}: {row.get('reason')}"})
            continue
        status = (row.get("decompile") or {}).get("status")
        if status == "no sample":
            out.append({"id": image_id, "reason": "decompile metrics (success, gotos, arity, type exact): no sample for this "
                        "image in the given wave report(s); discovery and timing are filled"})
        elif status == "not run":
            out.append({"id": image_id, "reason": f"decompile metrics not run: {row['decompile']['reason']}"})
        elif status == "no main labels":
            out.append({"id": image_id, "reason": "decompile metrics: every sampled label is in another module"})
        mods = row["modules"]
        if mods["not_covered"]:
            out.append({"id": image_id, "reason": f"{len(mods['not_covered'])} non-main modules ({mods['not_covered_functions']} "
                        f"truth functions) not covered: IDA opens one program (the main module; RELs, overlays and "
                        f"separately staged modules are other files it was not given)"})
        found = row["discovery"]["found"]
        if found <= 1 and row["discovery"]["truth"]:
            out.append({"id": image_id, "reason": f"IDA found {found} function(s) in the main module's ranges: its loader "
                        "gives it nothing to analyze there (the code is not in the ROM's plain boot view), so every "
                        "discovery cell is zero and the decompile cells need functions created from the truth"})
        sample = row.get("sample")
        if sample and sample["other_module_labels"]:
            out.append({"id": image_id, "reason": f"{sample['other_module_labels']} of {sample['union_labels']} sampled labels are "
                        "in non-main modules: not decompiled; Romwright's success/arity/type cells for this image are over "
                        "all labels and are left out of the comparison"})
    out.append({"id": "*-symtab variants", "reason": "not run (`--symtab-variants` supplement of the wave; a symtab-bearing ELF "
                "is scored stripped, as the contract says, and IDA reads the stripped copy)"})
    return out


def rollup(report: dict) -> dict:
    platforms: dict[str, dict] = {}
    mismatch: dict[str, dict] = {}
    for image_id, row in report["images"].items():
        if row.get("status") != "ran":
            continue
        rw = (row.get("romwright") or {}).get("default")
        if not rw:
            continue
        game = {"romwright": rw, "hexrays": hexrays_summary(row), "comparable_decompile": comparable_decompile(row),
                "game": row.get("game"), "stock": (row.get("romwright") or {}).get("stock")}
        if row.get("decompile", {}).get("status") != "ran":
            game["hexrays"] = {k: v for k, v in game["hexrays"].items() if k in DISCOVERY_METRICS + ["discovered"]
                               or k.endswith("_main")}
        if row["version_match"] is False:
            mismatch[image_id] = game
        else:
            platforms.setdefault(row["platform"], {"games": {}})["games"][image_id] = game
    for entry in platforms.values():
        entry["tests"] = sign_rows(entry["games"])
    pooled = {i: g for e in platforms.values() for i, g in e["games"].items()}
    return {"platforms": platforms, "mismatch": mismatch, "all": {"games": sorted(pooled), "tests": sign_rows(pooled)},
            "sign_test": {"rate_threshold": wave.RATE_THRESHOLD,
                          "note": "one-sided, P(X >= wins), X ~ Binomial(wins + losses, 1/2); ties dropped; "
                                  "success/arity/type only over images whose whole sample is main-module labels"}}


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def f(value, digits=4):
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def triple(a, b, c=None, digits=4):
    return f"{f(a, digits)} / {f(b, digits)}" if c is None else f"{f(a, digits)} / {f(b, digits)} / {f(c, digits)}"


def markdown(report: dict) -> str:
    out = [f"# Hex-Rays on the corpus wave ({report['generated']})", "", f"> **INTERNAL ONLY. {report['eula']}**", "",
           "Generated by `benchmarks/hexrays_wave.py`. Joined to the wave report(s) below on image id and sample label "
           "(docs/console-research.md, 'Join contract'); no sample was drawn here. R = Romwright `default` "
           "(`*_main` keys: the main module, the scope IDA covers), H = Hex-Rays (IDA " + str(report.get("ida_version"))
           + " / Hex-Rays " + str(report.get("hexrays_version")) + ", no plugins, auto-analysis only). Stock Ghidra "
           "(main module) is added where the wave report has it.", ""]
    out += ["Wave reports: " + ", ".join(f"`{w['path']}` (tools `{w['tools']}`, {w['generated']}, n={w['n']}, "
                                         f"seeds {w['seeds']}, {w['images']} images)" for w in report["wave_reports"])
            if report["wave_reports"] else "No wave report given: samples absent, so only the sample-independent "
            "discovery and timing columns are filled.", ""]
    ran = {i: r for i, r in report["images"].items() if r.get("status") == "ran"}
    headline = {i: r for i, r in ran.items() if r["version_match"] is not False}
    mismatch = {i: r for i, r in ran.items() if r["version_match"] is False}

    def table(images: dict) -> list[str]:
        lines = ["| image | modules covered | recall R / [G /] H | precision R / [G /] H | success R / H | gotos R / H | arity R / [G /] H | "
                 "type exact R / [G /] H | verified recall R / [G /] H | verified precision R / [G /] H | IDA analysis s (process s, load 1m before / after) |",
                 "|---|---|---|---|---|---|---|---|---|---|---|"]
        for i, r in images.items():
            rw = (r.get("romwright") or {}).get("default") or {}
            d = r["discovery"]
            h = ((r.get("hexrays") or {}).get("combined") or {}).get("all") or {}
            same = comparable_decompile(r)
            rs = (lambda key: rw.get(key)) if same else (lambda key: None)
            a = r["analysis"]
            p = a["process"]
            mods = f"main ({r['modules']['main_truth_functions']} truth fns)" + (
                f"; not: {len(r['modules']['not_covered'])} modules, {r['modules']['not_covered_functions']} fns"
                if r["modules"]["not_covered"] else "")
            g = (r.get("romwright") or {}).get("stock") or {}

            def cell(key, digits=4, hex_=None, rwv=None, same_scope=True):
                """R / G / H (R / H when the wave report has no stock row)."""
                r_value = rw.get(f"{key}_main", rw.get(key)) if rwv is None else rwv
                g_value = g.get(f"{key}_main", g.get(key)) if g else None
                if not g and (r.get("romwright") or {}).get("stock_excluded"):
                    return f"{f(r_value, digits)} / stock {'DNF' if 'DNF' in str(r['romwright']['stock_excluded']) else 'crashed'} / {f(hex_, digits)}"
                return triple(r_value, g_value, hex_, digits) if g else triple(r_value, hex_, digits=digits)

            lines.append(
                f"| {i} | {mods} | {cell('recall', hex_=d['recall'])} | {cell('precision', hex_=d['precision'])} | "
                f"{triple(rs('success_rate'), h.get('success_rate'), digits=3)} | {triple(rs('gotos'), h.get('gotos'))} | "
                f"{cell('arity_accuracy', hex_=h.get('arity_accuracy'), rwv=rs('arity_accuracy'))} | "
                f"{cell('type_exact_rate', hex_=h.get('type_exact_rate'), rwv=rs('type_exact_rate'))} | "
                f"{cell('recall_verified', hex_=d['recall_verified'])} | {cell('precision_verified', hex_=d['precision_verified'])} | "
                f"{f(a['analysis_s'], 1)} ({f(p['wall_s'], 1)}, {f((p.get('load_before') or [None])[0], 2)} / "
                f"{f((p.get('load_after') or [None])[0], 2)}) |")
        return lines

    out += ["## Per image (headline games: `version_match` true)", "",
            "A `–` in the R column of success, gotos, arity or type exact means Romwright's number is over a sample that "
            "also holds overlay/REL labels (IDA covers the main module only), so it is not on the same functions; "
            "the H column is always over the main-module labels of the sample. Success, gotos, arity and type exact are "
            "over the combined (union) sample, the view where every sampled address is decompiled (a function IDA did "
            "not find is created for the decompile metrics only; `found` and per-seed views are in the JSON).", ""]
    out += table(headline) + [""]
    if mismatch:
        out += ["## Supplement: version-mismatch images (out of the sign tests)", ""] + table(mismatch) + [""]
    out += ["## Sign tests: Romwright default vs Hex-Rays (supplement)", "",
            "A win is Romwright ahead by at least 0.5 pp (the harness's `RATE_THRESHOLD`), a loss behind by as much; "
            "ties are dropped. One-sided P(X >= wins). Joined from the wave report(s) above; "
            "recompute by re-running with the final wave report.", ""]
    roll = report["rollup"]
    out += ["| scope | metric | games | Romwright wins | losses | ties | p |", "|---|---|---|---|---|---|---|"]
    for scope, entry in [(p, e) for p, e in sorted(roll["platforms"].items())] + [("all platforms", roll["all"])]:
        for metric, t in entry["tests"].items():
            out.append(f"| {scope} | {metric.split(':')[0]} | {t['games']} | {t['wins']} | {t['losses']} | {t['ties']} | "
                       f"{f(t['p_value'], 5)} |")
    out += [""]
    out += ["## What IDA was given, and what it applied", "",
            "| image | input | processor / loader | signatures applied | functions found (all ranges) | ranges source |",
            "|---|---|---|---|---|---|"]
    for i, r in ran.items():
        a = r["analysis"]
        out.append(f"| {i} | {r['input']['what']} | {a['processor']['procname']} ({'BE' if a['processor']['big_endian'] else 'LE'}) / "
                   f"{a['processor']['filetype']} | {', '.join(s[0] for s in a['signatures']) or 'none'} | "
                   f"{a['functions_total']} | {r['ranges']['source']} |")
    out += [""]
    failures = {i: r for i, r in ran.items() if r.get("categories")}
    if failures:
        out += ["## Decompile failures and unsupported instructions (sampled main-module functions)", "",
                "| image | Hex-Rays failures by code | functions with a feature-category instruction (instructions) | top `__asm` mnemonics | created at sampled addresses |",
                "|---|---|---|---|---|"]
        for i, r in failures.items():
            c = r["categories"]
            asm = ", ".join(f"{m}×{n}" for m, n in c["asm_mnemonics_top"][:6]) or "none"
            feat = ", ".join(f"{k} {c['functions_with_feature_instructions'][k]} ({c['feature_instructions'][k]})"
                             for k in c["feature_instructions"]) or "none"
            out.append(f"| {i} | {json.dumps(c['failures']) if c['failures'] else 'none'} | {feat} | {asm} | "
                       f"{r['hexrays']['combined']['created']} of {r['hexrays']['combined']['all']['sampled']} |")
        out += [""]
    out += ["## Not covered", ""]
    out += [f"- **{row['id']}**: {row['reason']}" for row in report["not_covered"]] or ["- none"]
    out += ["", "## Reproduce", "", "```", report["command"], "```", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=M21.CORPUS)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--wave-report", type=Path, action="append", default=[],
                        help="console_research.py --corpus-wave JSON holding the samples (repeatable; later wins)")
    parser.add_argument("--images", default="", help="comma-separated image ids (default: every contract image)")
    parser.add_argument("--analyze-only", action="store_true", help="IDA analysis and discovery only (no sample needed)")
    parser.add_argument("--decompile-images", default="",
                        help="run Hex-Rays only on these images (default: every image with a sample)")
    parser.add_argument("--jobs", type=int, default=2, help="concurrent IDA processes (2 is the cap)")
    parser.add_argument("--stall", type=int, default=hr.STALL_S)
    parser.add_argument("--min-age-s", type=float, default=60.0)
    parser.add_argument("--date", default=datetime.now().strftime("%Y%m%d"))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--render-only", action="store_true", help="re-render the markdown (and rollup) from --out")
    parser.add_argument("--prune-db", action="store_true", help="delete an image's IDA database once its rows are written")
    args = parser.parse_args()
    args.jobs = max(1, min(args.jobs, 2))
    args.decompile_images = {i for i in args.decompile_images.split(",") if i}
    out = args.out or REPORTS / f"console_research_wave_hexrays_{args.date}.json"
    if args.render_only:
        report = json.loads(out.read_text())
        report["rollup"] = rollup(report)
        cr.write_json(out, report)
        out.with_suffix(".md").write_text(markdown(report))
        return 0

    wanted = {i for i in args.images.split(",") if i}
    specs, skipped = wave.discover(args.corpus, wanted, args.min_age_s)
    samples = load_wave_reports(args.wave_report)
    for spec in specs:
        spec["limit_s"] = 7200
    command = "python3 benchmarks/hexrays_wave.py" + "".join(f" --wave-report {p}" for p in args.wave_report) + (
        " --analyze-only" if args.analyze_only else "") + (f" --images {args.images}" if args.images else "") + (
        f" --decompile-images {','.join(sorted(args.decompile_images))}" if args.decompile_images else "")
    report = {"schema": "console-research-hexrays-wave/1", "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "eula": EULA, "internal_only": True, "command": command, "ida_dir": str(hr.IDA_DIR),
              "host": {"cpus": os.cpu_count(), "load_at_start": [round(x, 2) for x in os.getloadavg()]},
              "wave_reports": [{"path": str(p), "tools": next((v["_tools"] for v in samples.values() if v["_report"] == str(p)), None),
                                "generated": next((v["_generated"] for v in samples.values() if v["_report"] == str(p)), None),
                                "n": next((v["_n"] for v in samples.values() if v["_report"] == str(p)), None),
                                "seeds": next((v["_seeds"] for v in samples.values() if v["_report"] == str(p)), None),
                                "images": sum(1 for v in samples.values() if v["_report"] == str(p))}
                               for p in args.wave_report],
              "images": {}, "not_covered": [{"id": s.get("id") or s["dir"], "reason": s["reason"]} for s in skipped]}
    gate = threading.Semaphore(args.jobs)
    todo = [s for s in specs]

    def work(spec):
        try:
            return spec["id"], run_image(spec, args, samples, gate)
        except NotCovered as error:
            return spec["id"], {"status": "not covered", "reason": str(error)}
        except hr.AnalysisTimeout as error:
            return spec["id"], {"status": "DNF", "reason": f"{error} (1 h limit, as stock Ghidra's: a labelled row, never a timing)",
                                "game": spec["wave"]["meta"].get("game"), "platform": spec["wave"]["platform"],
                                "version_match": spec["wave"]["meta"].get("version_match", True)}
        except Exception as error:  # noqa: BLE001 - one image must not lose the others
            log(f"{spec['id']}: ERROR {type(error).__name__}: {str(error)[-300:]}")
            return spec["id"], {"status": "error", "reason": f"{type(error).__name__}: {str(error)[-500:]}"}

    def flush():
        report["images"] = {k: report["images"][k] for k in sorted(report["images"])}
        report["not_covered"] = build_not_covered(report, skipped, args)
        report["rollup"] = rollup(report)
        cr.write_json(out, report)
        out.with_suffix(".md").write_text(markdown(report))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(work, s) for s in todo]
        for future in concurrent.futures.as_completed(futures):
            image_id, row = future.result()
            spec = next(s for s in specs if s["id"] == image_id)
            if row.get("status") == "ran":
                if samples.get(image_id):
                    row["romwright"] = romwright_row(samples[image_id])
                    row["units"] = samples[image_id].get("units")
                if args.prune_db and row.get("decompile", {}).get("status") == "ran":
                    shutil.rmtree(args.cache / "runs" / image_id / "db", ignore_errors=True)
            report["images"][image_id] = row
            for row_ in (row,):
                if row_.get("status") == "ran" and "ida_version" not in report:
                    report["ida_version"] = row_["analysis"]["ida_version"]
                    report["hexrays_version"] = row_["analysis"]["hexrays_version"]
            flush()
            log(f"{image_id}: {row.get('status')}")
    flush()
    log(f"report {out} / {out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
