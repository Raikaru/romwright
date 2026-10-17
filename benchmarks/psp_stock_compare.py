#!/usr/bin/env python3
"""Stock Ghidra on Puzzle Bobble Pocket (PSP), scored like console_research.py.

The reference for benchmarks/console_research.py's two PSP images. Stock
Ghidra's headless analyzer imports the same stripped twins and is asked for

* discovery: the functions its analysis created (before anything is forced),
  scored with m21-001's `score` against the section-corrected symtab truth
  (`M21.elf_functions`), over the executable blocks stock itself loaded;
* types: the decompiler's printed signature (scripts/ExportDecompiledSignatures.java) at every DWARF function entry
  (a function the analysis did not create there is created, and counted in
  `existed`), scored with console_research's `dwarf_scores`: arity and
  per-slot type agreement against the DWARF 2 truth.

Languages: the stock ELF loader's own choice for this image (`MIPS:LE:32:
default`: Ghidra's MIPS.opinion does not know e_type 0xffa0) and the installed
Allegrex module forced with `-processor`.

  python3 benchmarks/psp_stock_compare.py --work DIR [--ghidra DIR] [--out JSON]

Stock runs on a loaded host take ~2 minutes each (JVM + analysis).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CR = load("console_research", ROOT / "benchmarks" / "console_research.py")
SPEED = load("import_speed", ROOT / "benchmarks" / "import_speed.py")
M21 = CR.M21

CONFIGS = [
    # (id, twin, language or None for the loader's choice)
    ("strip-all/loader-choice", "strip-all", None),
    ("strip-all/Allegrex", "strip-all", "Allegrex:LE:32:default"),
    ("symtab/loader-choice", "symtab", None),
    ("symtab/Allegrex", "symtab", "Allegrex:LE:32:default"),
]
SCRIPTS = ROOT / "benchmarks" / "ghidra"
ORACLE_SCRIPTS = ROOT / "scripts"  # ExportDecompiledSignatures.java, shared with abi_signature_gate.py


def twin(kind: str, image: Path, work: Path) -> Path:
    out = work / f"{kind}-{image.name}"
    if kind == "strip-all":
        subprocess.run(["llvm-strip", "--strip-all", "-o", str(out), str(image)], check=True)
    else:
        subprocess.run(["llvm-objcopy", "--strip-debug", str(image), str(out)], check=True)
    return out


def run_stock(headless: Path, binary: Path, language: str | None, addresses: Path, work: Path) -> tuple[dict, list[dict], str]:
    project = work / "project"
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    entries, signatures = work / "entries.json", work / "signatures.json"
    argv = [str(headless), str(project), "proj", "-import", str(binary)]
    if language:
        argv += ["-processor", language]
    argv += ["-scriptPath", f"{SCRIPTS};{ORACLE_SCRIPTS}", "-postScript", "ExportFunctionEntries.java", str(entries),
             "-postScript", "ExportDecompiledSignatures.java", str(addresses), str(signatures), "120", "-deleteProject"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_")}
    env.update(GHIDRA_HEADLESS_MAXMEM="4G", DEBUGINFOD_URLS="")
    result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=3600)
    shutil.rmtree(project, ignore_errors=True)
    if not entries.is_file() or not signatures.is_file():
        raise RuntimeError("stock run failed:\n" + (result.stdout + result.stderr)[-1500:])
    rows = [{"address": line, "existed": row.get("existed", False), "signature": row.get("signature", "")}
            for line, row in json.loads(signatures.read_text())["functions"].items()]
    return json.loads(entries.read_text()), rows, result.stdout


def printed_rows(rows: list[dict]) -> list[dict]:
    """console_research row shape: parameters/returns parsed from the printed signature."""
    out = []
    for row in rows:
        parsed = None
        if row["signature"]:
            signature = row["signature"].rstrip().rstrip(";")
            name = signature.split("(")[0].split()[-1].lstrip("*")
            parsed = CR.signature(signature + "\n{", name)
        out.append({"address": f"{int(row['address'], 16):08x}", "success": parsed is not None,
                    "parameters": parsed[1] if parsed else None, "returns": parsed[0] if parsed else None,
                    "existed": row["existed"]})
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=M21.CORPUS)
    parser.add_argument("--work", type=Path, default=Path(tempfile.mkdtemp(prefix="psp-stock-")))
    parser.add_argument("--ghidra", type=Path, default=SPEED.GHIDRA)
    parser.add_argument("--only", default="", help="comma-separated config ids")
    parser.add_argument("--out", type=Path, default=ROOT / "benchmarks" / "reports" / "psp_stock_compare.json")
    args = parser.parse_args()
    image = args.corpus / CR.PSP_BOOT
    truth = M21.elf_functions(image)
    dwarf = CR.dwarf_truth(image)["functions"]
    args.work.mkdir(parents=True, exist_ok=True)
    addresses = args.work / "addresses.txt"
    addresses.write_text("".join(f"{address:x}\n" for address in sorted(dwarf)))
    headless = args.ghidra / "support" / "analyzeHeadless"
    report = {"schema": "romwright.psp_stock_compare/1", "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "ghidra": SPEED.ghidra_version(args.ghidra), "truth_functions": len(truth), "dwarf_functions": len(dwarf),
              "configs": {}}
    wanted = set(filter(None, args.only.split(",")))
    for config_id, kind, language in CONFIGS:
        if wanted and config_id not in wanted:
            continue
        work = args.work / config_id.replace("/", "-")
        work.mkdir(parents=True, exist_ok=True)
        binary = twin(kind, image, work)
        exported, rows, _log = run_stock(headless, binary, language, addresses, work)
        ranges = [(b["start"], b["start"] + b["size"]) for b in exported["blocks"]
                  if b["execute"] and b["initialized"] and not b["overlay"]]
        functions = {f["entry"]: f["size"] for f in exported["functions"] if not f["overlay"]}
        discovery = SPEED.score_entries(functions, truth, ranges, work / "score")
        discovery.pop("missed_sample", None)
        discovery.pop("invented_sample", None)
        printed = printed_rows(rows)
        found = [row for row in printed if row["existed"]]
        report["configs"][config_id] = {
            "language": exported["language"], "compiler": exported["compiler"], "functions": len(functions),
            "discovery": discovery,
            "dwarf_entries_with_a_stock_function": len(found),
            "types_all_dwarf_entries": CR.dwarf_scores(printed, dwarf),
            "types_stock_found_entries": CR.dwarf_scores(found, dwarf),
        }
        print(config_id, json.dumps(report["configs"][config_id]["discovery"]),
              json.dumps(report["configs"][config_id]["types_all_dwarf_entries"]), flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
