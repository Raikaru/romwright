#!/usr/bin/env python3
"""Stack/global symbol layout classes over a PS2 wave (docs/merge-port.md section 12, docs/types-port.md section 13).

Decompiles every address of a `ps2_decompile_success.py` wave with the worker (one `romwright-worker auto` call per
chunk, so the printed C is the decompiler's own text before the export layer), keeps the text of every function and counts,
per image and in total, the functions that print each layout symptom:

  partial   a member of a local or global the printer named by offset and width (`local_10._2_2_`); `partial_of` splits the
            functions by what the member is of: a register value (`auVar8._0_4_`), a parameter, a stack local or a global
  stack0x   a stack address the decompiler gave no symbol (`stack0xffffffe8`)
  odd       an `undefinedN` type of a width no C type has (3, 5, 6, 7, 9 and up)
  mismatch  a `_NAME` use: a varnode at a symbol's address whose width is not the symbol's
  whole     a store or load of a whole array (`auStack_20 = value`)

  symbol_layout_wave.py --wave WAVE.json --bin BINDIR --out TEXTS.json [--env KEY=VALUE ...] [--jobs 6]
  symbol_layout_wave.py --compare BEFORE.json AFTER.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CLASSES = {
    "partial": re.compile(r"\w\._\d+_\d+_"),
    "stack0x": re.compile(r"\bstack0x[0-9a-fA-F]+"),
    "odd": re.compile(r"\bundefined(?:[3567]|\d\d+)\b"),
    "mismatch": re.compile(r"(?<![\w.])_(?:local_|[a-z]{1,3}Stack_|[a-z]{1,3}Var\d)\w*"),
}


def run(binary: Path, project: Path, program: str, chunk: list[str], env_extra: dict):
    argv = [str(binary / "romwright-worker"), str(binary / "ghidra_opt"), "auto", program, *chunk, "--project", str(project)]
    if len(chunk) == 1:
        argv.append(chunk[0])  # a single address answers as plain text; repeat it so the answer is a JSON object
    result = subprocess.run(argv, capture_output=True, text=True, timeout=3600, env=dict(os.environ, **env_extra))
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


# What a partial member is a member of: the name before `._offset_width_`.
PARTIAL = re.compile(r"(\w+)\._\d+_\d+_")
PARTIAL_KINDS = {
    "register": re.compile(r"[a-z]{1,3}Var\d+|in_\w+|unaff_\w+|extraout_\w+|temp_\w+"),
    "parameter": re.compile(r"param_\d+"),
    "stack": re.compile(r"\w*Stack\w*|local_\w+"),
}


def partial_kinds(text: str) -> set[str]:
    """The kinds of symbol the function's partial members are of (`global` is every other name)."""
    return {next((kind for kind, pattern in PARTIAL_KINDS.items() if pattern.fullmatch(name)), "global")
            for name in PARTIAL.findall(text)}


def classify(text: str) -> list[str]:
    return [name for name, pattern in CLASSES.items() if pattern.search(text)]


def tally(texts: dict[str, dict[str, str]]) -> dict:
    out = {"functions": 0, "classes": {name: 0 for name in CLASSES}, "any": 0, "partial_of": {}, "images": {}}
    for image, rows in texts.items():
        counts = {"functions": len(rows), "classes": {name: 0 for name in CLASSES}, "any": 0, "partial_of": {}}
        for text in rows.values():
            found = classify(text)
            for kind in partial_kinds(text):
                counts["partial_of"][kind] = counts["partial_of"].get(kind, 0) + 1
            for name in found:
                counts["classes"][name] += 1
            counts["any"] += bool(found)
        out["images"][image] = counts
        out["functions"] += counts["functions"]
        out["any"] += counts["any"]
        for kind, number in counts["partial_of"].items():
            out["partial_of"][kind] = out["partial_of"].get(kind, 0) + number
        for name in CLASSES:
            out["classes"][name] += counts["classes"][name]
    return out


def collect(args) -> int:
    env_extra = dict(item.split("=", 1) for item in args.env)
    wave = json.loads(args.wave.read_text())
    texts: dict[str, dict[str, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for image, entry in wave["images"].items():
            if args.games and image not in args.games.split(","):
                continue
            rows = json.loads(Path(entry["configs"]["default"]["results_file"]).read_text())
            project = Path(rows["project"])
            program = json.loads((project / "done.json").read_text())["program"]
            addresses = sorted({row["address"].lower().removeprefix("0x").zfill(8) for row in rows["functions"]})
            for i in range(0, len(addresses), args.chunk):
                futures.setdefault(image, []).append(pool.submit(run, args.bin, project, program, addresses[i:i + args.chunk], env_extra))
        chunks = {}
        for image, entry in wave["images"].items():
            if image in futures:
                rows = json.loads(Path(entry["configs"]["default"]["results_file"]).read_text())
                chunks[image] = (Path(rows["project"]), json.loads((Path(rows["project"]) / "done.json").read_text())["program"],
                                 sorted({row["address"].lower().removeprefix("0x").zfill(8) for row in rows["functions"]}))
        for image, jobs in futures.items():
            texts[image] = {}
            for job in jobs:
                texts[image].update({a: t for a, t in job.result().items() if isinstance(t, str)})
            # A chunk the decompiler answers nothing for (a function past its deadline on a busy host) is asked once more, as
            # the chunks of the first pass were; the chunks that fail every time are the wave's own 91 (docs/merge-port.md).
            project, program, addresses = chunks[image]
            missing = [a for a in addresses if a not in texts[image]]
            for i in range(0, len(missing), args.chunk):
                texts[image].update({a: t for a, t in run(args.bin, project, program, missing[i:i + args.chunk], env_extra).items()
                                     if isinstance(t, str)})
            missing = [a for a in addresses if a not in texts[image]]
            print(f"{image:30} {len(texts[image])} functions ({len(missing)} do not decompile)", flush=True)
    result = {"bin": str(args.bin), "env": env_extra, "tally": tally(texts), "texts": texts}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result))
    print(json.dumps(result["tally"]["classes"]), result["tally"]["functions"], result["tally"]["any"])
    return 0


def compare(before: Path, after: Path) -> int:
    b, a = json.loads(before.read_text()), json.loads(after.read_text())
    print("| class | before | after |\n|---|---|---|")
    for name in CLASSES:
        print(f"| {name} | {b['tally']['classes'][name]} | {a['tally']['classes'][name]} |")
    print(f"| any | {b['tally']['any']} | {a['tally']['any']} |")
    changed = same = 0
    for image, rows in b["texts"].items():
        for address, text in rows.items():
            other = a["texts"].get(image, {}).get(address)
            if other is None:
                continue
            if other == text:
                same += 1
            else:
                changed += 1
    print(f"functions printed the same {same}, changed {changed}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wave", type=Path)
    parser.add_argument("--bin", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("--games", default="")
    parser.add_argument("--chunk", type=int, default=40)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--compare", nargs=2, type=Path)
    args = parser.parse_args()
    if args.compare:
        return compare(*args.compare)
    if not (args.wave and args.bin and args.out):
        parser.error("--wave, --bin and --out are required")
    return collect(args)


if __name__ == "__main__":
    sys.exit(main())
