#!/usr/bin/env python3
"""Spurious gotos: printed gotos the real C source does not have (a fake-match metric).

In matching decompilation a match that only holds through `goto` reproduces the
bytes, not the source's control flow. This is a documented *supplement* to the
printed-goto counts of benchmarks/structuring_models.py (whose definitions are
unchanged): it counts, per function with real source, whether the printed C has
gotos the source does not.

Images with C source (the research images' unstripped ELF names every function):

  gba-pokeemerald         ~/opt/pokeemerald-src/src/**/*.c   (symbols from pokeemerald.elf;
                          a local symbol is looked up in the file its STT_FILE names)
  nds-pokeheartgold-arm9  ~/opt/pokeheartgold-src/src/**/*.c (pokeheartgold.elf; no STT_FILE:
                          a name defined in several files is ambiguous and not scored)

Set: the 200-function research samples of the structuring gate set plus, for
pokeemerald, the m22-001 function set (tests/m22-001_c_output.py FUNCTIONS).
Functions map to source by symbol name. The source's gotos are `goto` tokens in
the function body after comments, strings and character literals are removed.
A function whose definition is `asm`/`NAKED` (no C control flow to compare), has
no definition in the scanned source (macro-generated, asm-only) or is ambiguous
is counted separately and not scored.

Per configuration and image:

  functions                 scored (mapped, C source)
  print_gotos               printed gotos over the scored functions
  source_gotos              gotos in the source of the scored functions
  spurious_functions        scored functions printing >= 1 goto whose source has none
  spurious_gotos            sum over scored functions of max(0, printed - source)
  source_goto_functions     scored functions whose source has a goto (their gotos are
                            legitimate; spurious_gotos still counts the excess)

Configurations are the `--config NAME=MODELS` of structuring_models.py
(ROMWRIGHT_RUST_STRUCTURING), baseline = `none`, default = the production default.

Usage (from the repository root):
  benchmarks/spurious_gotos.py --ghidra-opt native/build/ghidra_opt \\
      --target target/p --report benchmarks/reports/spurious_gotos.json
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODELS = load("structuring_models", ROOT / "benchmarks/structuring_models.py")
DIFF = MODELS.DIFF

HOME = Path.home()
CORPUS = HOME / "romwright-corpus/extracted"
IMAGES = {
    "gba-pokeemerald": {
        "elf": CORPUS / "gba-pokeemerald/pokeemerald.elf",
        "src": HOME / "opt/pokeemerald-src/src",
        "files": True,
    },
    "nds-pokeheartgold-arm9": {
        "elf": CORPUS / "nds-pokeheartgold/pokeheartgold.elf",
        "src": HOME / "opt/pokeheartgold-src/src",
        "files": False,
    },
}


# ---------------------------------------------------------------------------
# Source side
# ---------------------------------------------------------------------------

def blank(text: str) -> str:
    """`text` with comments, string and character literals and preprocessor
    lines replaced by spaces (newlines kept), so braces and keywords are code."""
    out = []
    i, n = 0, len(text)
    line_start = True
    while i < n:
        c = text[i]
        if line_start and c == "#":
            # Preprocessor line, with continuations.
            while i < n and text[i] != "\n":
                if text[i] == "\\" and i + 1 < n and text[i + 1] == "\n":
                    out.append("  ")
                    i += 2
                    continue
                out.append(" ")
                i += 1
            continue
        if c == "\n":
            out.append(c)
            i += 1
            line_start = True
            continue
        if not c.isspace():
            line_start = False
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append(re.sub(r"[^\n]", " ", text[i:end]))
            i = end
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(" " * (min(j + 1, n) - i))
            i = min(j + 1, n)
            continue
        out.append(c)
        i += 1
    return "".join(out)


HEADER_NAME = re.compile(r"([A-Za-z_]\w*)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*$", re.S)


def definitions(path: Path) -> dict[str, list[tuple[str, str]]]:
    """name -> [(header, body)] for the function definitions at brace depth 0."""
    code = blank(path.read_text(errors="replace"))
    found: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    depth = 0
    head_start = 0
    body_start = 0
    header = ""
    name = None
    for i, c in enumerate(code):
        if c == "{":
            if depth == 0:
                header = code[head_start:i]
                match = HEADER_NAME.search(header.rstrip())
                name = match.group(1) if match and not re.search(r"\b(struct|union|enum)\s*\w*\s*$", header) \
                    and "=" not in header else None
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                if name:
                    found[name].append((header, code[body_start:i + 1]))
                head_start = i + 1
                name = None
            elif depth < 0:
                depth = 0
                head_start = i + 1
        elif c == ";" and depth == 0:
            head_start = i + 1
    return found


def source_index(src: Path) -> dict[str, dict[str, list[tuple[str, str]]]]:
    """file stem -> definitions, for every .c under `src`."""
    index: dict[str, dict] = {}
    for path in sorted(src.rglob("*.c")):
        index.setdefault(path.stem, {})
        for name, bodies in definitions(path).items():
            index[path.stem].setdefault(name, []).extend(bodies)
    return index


def assembly(header: str) -> bool:
    return bool(re.search(r"\b(asm|__asm|NAKED|__declspec)\b", header))


def source_gotos(index: dict, name: str, stem: str | None) -> tuple[str, int | None]:
    """(status, goto count): status `scored`, `no-source`, `ambiguous` or `asm`."""
    if stem is not None and stem in index and name in index[stem]:
        candidates = index[stem][name]
    else:
        candidates = [d for file in index.values() for d in file.get(name, [])]
    if not candidates:
        return "no-source", None
    counts = {len(re.findall(r"\bgoto\b", body)) for _, body in candidates}
    if all(assembly(header) for header, _ in candidates):
        return "asm", None
    candidates = [d for d in candidates if not assembly(d[0])]
    if len(candidates) > 1 and len({body for _, body in candidates}) > 1:
        counts = {len(re.findall(r"\bgoto\b", body)) for _, body in candidates}
        if len(counts) > 1:
            return "ambiguous", None
    return "scored", len(re.findall(r"\bgoto\b", candidates[0][1]))


def elf_names(elf: Path, files: bool) -> dict[int, tuple[str, str | None]]:
    """address -> (symbol name, the source file stem its STT_FILE names)."""
    from elftools.elf.elffile import ELFFile

    names: dict[int, tuple[str, str | None]] = {}
    current = None
    with open(elf, "rb") as handle:
        table = ELFFile(handle).get_section_by_name(".symtab")
        for symbol in table.iter_symbols():
            kind = symbol["st_info"]["type"]
            if kind == "STT_FILE":
                current = Path(symbol.name).stem
            elif kind == "STT_FUNC" and not symbol.name.startswith("$") and symbol["st_size"]:
                names.setdefault(symbol["st_value"] & ~1,
                                 (symbol.name, current if files and
                                  symbol["st_info"]["bind"] == "STB_LOCAL" else None))
    return names


def m22_names() -> list[str]:
    text = (ROOT / "tests/m22-001_c_output.py").read_text()
    block = text[text.index("FUNCTIONS = ["):]
    block = block[:block.index("\n]")]
    return re.findall(r"\('(\w+)',\s*'\w+'\)", block)


# ---------------------------------------------------------------------------
# Printed side
# ---------------------------------------------------------------------------

def decompile(worker: Path, ghidra_opt: Path, target: dict, models: str, passes: str | None,
              chunk: int, jobs: int) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    chunks = [target["addresses"][i:i + chunk] for i in range(0, len(target["addresses"]), chunk)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for part, _stats in pool.map(
                lambda c: MODELS.run_chunk(worker, ghidra_opt, target, c, models, passes, False), chunks):
            rows.update(part)
    return rows


def score(rows: dict[str, dict], names: dict[int, tuple[str, str | None]], index: dict) -> dict:
    result = collections.Counter()
    per_function = {}
    for address, row in rows.items():
        entry = names.get(int(address, 16))
        if entry is None:
            result["unnamed"] += 1
            continue
        name, stem = entry
        status, src = source_gotos(index, name, stem)
        if status != "scored":
            result[status] += 1
            continue
        printed = row["gotos"]
        result["functions"] += 1
        result["print_gotos"] += printed
        result["source_gotos"] += src
        result["source_goto_functions"] += src > 0
        result["spurious_functions"] += printed > 0 and src == 0
        result["spurious_gotos"] += max(0, printed - src)
        per_function[address] = {"name": name, "printed": printed, "source": src}
    return {"totals": dict(result), "functions": per_function}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, default=DIFF.CACHE)
    parser.add_argument("--images", help="comma-separated image ids (default: both)")
    parser.add_argument("--configs", help="comma-separated configurations (default: baseline,default)")
    parser.add_argument("--config", action="append", default=[], metavar="NAME=MODELS",
                        help="an extra configuration: ROMWRIGHT_RUST_STRUCTURING=MODELS (repeatable)")
    parser.add_argument("--target", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")))
    parser.add_argument("--ghidra-opt", type=Path, required=True)
    parser.add_argument("--ir-passes", help="ROMWRIGHT_IR_PASSES for every run (default: unset)")
    parser.add_argument("--sample-key", default="23c94218619e781c",
                        help="the samples' and default projects' key (research-eval 23c94218619e781c; "
                             "research-final cdbbf0f7d1273898 or f0a287d0caf6f2b0 with --cache)")
    parser.add_argument("--chunk", type=int, default=25)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    DIFF.SAMPLE_SUFFIX = DIFF.SAMPLE_SUFFIX.replace("23c94218619e781c", args.sample_key)
    DIFF.PROJECT_PATTERN = DIFF.PROJECT_PATTERN.replace("23c94218619e781c", args.sample_key)
    target_dir = args.target if args.target.is_absolute() else ROOT / args.target
    worker = target_dir / "release/romwright-worker"
    # `default` is every model (ROMWRIGHT_RUST_STRUCTURING unset equals `all`).
    known = {"baseline": "none", "default": "all", **dict(spec.split("=", 1) for spec in args.config)}
    names = args.configs.split(",") if args.configs else ["baseline", "default"]
    configs = {name: known[name] for name in names}
    configs.update(dict(spec.split("=", 1) for spec in args.config))

    wanted = set(args.images.split(",")) if args.images else set(IMAGES)
    targets = DIFF.console_targets(args.cache, wanted)
    report = {"benchmark": "spurious_gotos",
              "date": datetime.now(timezone.utc).date().isoformat(),
              "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                       text=True).stdout.strip(),
              "ghidra_opt": str(args.ghidra_opt), "ir_passes": args.ir_passes,
              "configs": configs, "images": {}}
    totals = {config: collections.Counter() for config in configs}
    for target in targets:
        image = target["image"]
        spec = IMAGES[image]
        symbols = elf_names(spec["elf"], spec["files"])
        index = source_index(spec["src"])
        sample = set(target["addresses"])
        extra = []
        if image == "gba-pokeemerald":
            by_name = {name: address for address, (name, _) in symbols.items()}
            extra = [f"{by_name[name]:08x}" for name in m22_names() if name in by_name]
        target = dict(target, addresses=target["addresses"] + [a for a in extra if a not in sample])
        report["images"][image] = {"sample": len(sample), "m22_extra": len(target["addresses"]) - len(sample),
                                   "configs": {}}
        for config, models in configs.items():
            rows = decompile(worker, args.ghidra_opt, target, models, args.ir_passes, args.chunk, args.jobs)
            scored = score(rows, symbols, index)
            scored["decompiled"] = len(rows)
            report["images"][image]["configs"][config] = scored
            totals[config].update({key: value for key, value in scored["totals"].items()})
            t = scored["totals"]
            print(f"{image:26} {config:10} decompiled {len(rows):3} scored {t.get('functions', 0):3} "
                  f"print {t.get('print_gotos', 0):3} source {t.get('source_gotos', 0):3} "
                  f"spurious functions {t.get('spurious_functions', 0):3} gotos {t.get('spurious_gotos', 0):3}",
                  flush=True)
    for config, total in totals.items():
        print(f"total {config:10} scored {total['functions']:4} print {total['print_gotos']:4} "
              f"source {total['source_gotos']:3} spurious functions {total['spurious_functions']:4} "
              f"gotos {total['spurious_gotos']:4}")
    report["totals"] = {config: dict(total) for config, total in totals.items()}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
