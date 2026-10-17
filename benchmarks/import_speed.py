#!/usr/bin/env python3
"""Import speed against stock Ghidra, never without quality.

"State-of-the-art import speed" is a claim against a reference: stock Ghidra
12.1.3 headless auto-analysis of the same console image, configured with the
processor/language our import picks. Per image this harness runs, one process
at a time and alternating tools run by run:

  ours    `romwright-cli import IMAGE --name N --project DIR --timings`
          (release build of the current tree, ROMWRIGHT_NO_IMPORT_CACHE=1,
          every other ROMWRIGHT_* variable cleared, so no JVM can be used);
  ghidra  `analyzeHeadless WORK proj -import IMAGE [-loader L ...]
          -processor LANG -postScript ExportFunctionEntries.java OUT
          -deleteProject` with default analyzers.

and records per run: wall time, CPU time (user+sys of the process and every
descendant it reaped), peak RSS of the largest single process (`wait4`
ru_maxrss), the load average before and after, and each tool's phases (ours:
the TIMINGS line; Ghidra: JVM startup, the analysis-time summary per
analyzer, and the remainder: load, post-script, save, exit).

Quality: both tools' function entries are scored by m21-001's `score()`
against the image's truth (ELF symbols, PSX/MSVC maps, Vita BINMAP), over
the same address ranges. Ghidra's entries are scored by writing them into a
throwaway database with the three tables `score()` reads; functions in
overlay address spaces (NDS overlays) are not the scored program and are
dropped, as m21 scores only the `nds.arm9` program of our import. When m21
gives no ranges, both are scored over our import's executable regions.

Gate, per image with truth (the GameCube DOL has none: speed only):

* speed:   median wall ratio ours/Ghidra < 1 - tol, with
           tol = max(SPEED_TOLERANCE_FLOOR, worst relative run spread
           (max-min)/median of either tool on that image). A speed claim
           has to clear the noise this shared host showed on that very
           image; the 5% floor is there because two or three runs
           underestimate spread (the 2026-10-07 GBA A/B in STATUS.md
           repeated at 201 s vs 207 s, 3%, on the same build). A ratio
           inside 1 +- tol is "inconclusive" and fails: faster has to be
           shown, not assumed.
* quality: ours recall >= Ghidra recall - QUALITY_MARGIN and the same for
           precision. The 0.01 margin is the one m21-001 uses for its
           floors. Discovery is deterministic in both tools, so this is a
           materiality floor, not a noise estimate; runs whose scores differ
           are flagged. Precision is m21-001's, except where the truth
           cannot name the functions a tool finds (PSX_PRECISION_METRIC):
           there the gate uses m21-001's supplementary
           `precision_corroborated` (psx_corroborated; justification in
           docs/import-speed.md); `precision` is still reported and its
           delta recorded, only not gated.

The overall verdict passes when every image that ran passes; images that
could not run are listed with the reason. Results are cached per run under
--work, keyed by the binaries' sha256, the Ghidra install, the post-script
and the configuration, so an interrupted run resumes. The report
(benchmarks/reports/import-speed.{json,md}) is written by this script only;
a run with --only replaces just the rows it ran and keeps the other images'
rows of the existing report.

Usage:
  python3 benchmarks/import_speed.py [--only ID ...] [--runs N] [--no-build]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target" / "speedgate"))
# ghidra_opt; --native points at another directory (e.g. a
# copy taken before a rebuild, so a resumed run keeps its tool fingerprint).
NATIVE = ROOT / "native" / "build"
GHIDRA = Path(os.environ.get("ROMWRIGHT_GHIDRA") or Path.home() / "ghidra_12.1.3_PUBLIC")
SCRIPT = ROOT / "benchmarks" / "ghidra" / "ExportFunctionEntries.java"
# Both tools write their project here, on disk (not tmpfs /tmp). Ghidra
# refuses a project location with a path element starting with '.', so not
# under ~/.cache.
WORK = Path("/var/tmp/romwright-import-speed")
REPORTS = ROOT / "benchmarks" / "reports"
# The bridge's heap (romwright-cli `bridge_vm_options`, ROMWRIGHT_BRIDGE_MAXMEM):
# the stock 2G default runs out on the large images, which would time
# Ghidra's garbage collector rather than its analysis.
GHIDRA_MAXMEM = "8G"
LIMIT_S = 3600

SPEED_TOLERANCE_FLOOR = 0.05
QUALITY_MARGIN = 0.01
# Images whose precision gate is m21-001's supplementary metric: the truth map
# lists globals only, so the file-local statics a tool finds are "invented".
# Justification: docs/import-speed.md. Bump the tag when the metric's rule
# changes, so cached runs scored under the old rule are not reused.
PSX_PRECISION_METRIC = {"psx-darkstalkers-3": "precision_corroborated"}
SCORING_TAG = "psx_corroborated-1"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M21 = load_module("m21_real_images", ROOT / "tests" / "m21-001_real_images.py")

# Stock Ghidra configuration per image: the language our import selects
# (programs.language of a default import), the loader that produces that
# language from this container, and the loader options. `why` is copied
# into the report.
GHIDRA_CONFIG = {
    "gba-pokeemerald": {
        "language": "ARM:LE:32:v4t", "loader": "GBALoader", "options": [],
        "why": "gba-ghidra-loader extension (GBALoader), forced because the ROM has no "
               "container a stock loader recognises."},
    "nds-pokeheartgold-arm9": {
        "language": "ARM:LE:32:v5t", "loader": "NTRGhidraLoader",
        "options": ["-loader-cpu", "ARM9", "-loader-overlays", "true"],
        "why": "NdsLoader (NTRGhidra) extension, ARM9 CPU; ARM9 overlays loaded into overlay "
               "spaces (our import also analyses them) but not scored. The loader takes one CPU "
               "per program: the ARM7 binary our import also analyses (161 KB) is not loaded, "
               "a small advantage to Ghidra."},
    "ps2-capcom-fighting-evolution": {
        "language": "r5900:LE:32:default", "loader": None, "options": [],
        "why": "Stock ELF loader with the emotionengine-reloaded R5900 language; stripped ELF "
               "(llvm-strip --strip-all), the same file our import reads."},
    "ps2-dungeon-game": {
        "language": "r5900:LE:32:default", "loader": None, "options": [],
        "why": "Stock ELF loader, R5900 language; stripped ELF, the same file our import reads."},
    "psx-darkstalkers-3": {
        "language": "MIPS:LE:32:default", "loader": None, "options": [],
        "why": "Stock Ghidra's own MIPS:LE:32:default (the R3000A is MIPS I) under the PsxLoader "
               "extension's PS-EXE loader (auto-selected; the loader only lays out the image). Our "
               "import uses PSX:LE:32:default (native/languages/psx: this MIPS plus the GTE). "
               "Ghidra on PSX:LE:32:default (its own or ours) finds only 1011 functions (recall "
               "0.5844); the cause is not established (the extension keys its function-start patterns to MIPS); MIPS "
               "finds 2012 (0.9205), the recorded stock numbers."},
    "psv-need-for-speed-most-wanted": {
        "language": "ARM:LE:32:v8", "loader": None, "options": [],
        "why": "Stock ELF loader (auto-selected) on the decrypted eboot.elf (e_type 0xFE00, "
               "SCE executable), ARM:LE:32:v8 as our import."},
    "x360-black-ops-2": {
        "language": "PowerPC:BE:64:A2ALT-32addr", "loader": None, "options": [],
        "why": "XEXLoaderWV extension. Our language, PowerPC:BE:64:Xenon-32addr, is built by "
               "native/languages/xenon/install.sh (A2 + VMX128) and is not a Ghidra module (no "
               "Module.manifest), so stock Ghidra cannot load it; A2ALT-32addr (A2 + AltiVec) is "
               "the stock language it extends. VMX128 instructions do not decode there, so "
               "Ghidra's flow stops at them. The MSVC map is not given to either tool."},
    "gc-animal-crossing": {
        "language": "PowerPC:BE:32:Gekko_Broadway", "loader": None, "options": [],
        "why": "GameCubeLoader extension (DOL sections at their load addresses), Gekko/Broadway."},
}

# Copied into the report.
FAIRNESS = [
    "One process at a time, tools alternating run by run, so host-load drift lands on both; "
    "the host is shared (1-min load before each run is recorded), so compare ratios, not seconds.",
    "Both tools at default parallelism; CPU time and CPU/wall are reported beside wall.",
    "Both projects are written under the same --work directory on disk; Ghidra's wall includes "
    "JVM startup and saving its project, ours writing project.sqlite (the ratio without JVM "
    "startup is reported, not gated).",
    "Our import runs with every ROMWRIGHT_* variable cleared except the native tool paths and "
    "ROMWRIGHT_NO_IMPORT_CACHE=1: no import cache, no JVM.",
    "Ghidra heap 8G (the bridge default); default analyzers; language as our import except X360 "
    "(stock A2ALT-32addr; our Xenon language is not a Ghidra module).",
    "NDS: our import also analyses ARM7 and all overlays; Ghidra loads ARM9 plus overlays. "
    "Overlays are scored on neither side.",
    "PSX: VS.MAP lists globals only (m21-001), so `precision` is a floor for both tools and the "
    "gate uses `precision_corroborated`: the same image-bytes rule (psx_corroborated) applied to "
    "both tools' entries; `precision` is reported beside it.",
    "Peak RSS is the largest single process (wait4 ru_maxrss), not the process-tree sum.",
]

# m21-001's images plus the GameCube DOL (no truth: speed only). Small images
# get three runs, the large ones two.
IMAGES = [dict(spec) for spec in M21.IMAGES] + [
    {"id": "gc-animal-crossing", "image": "gc-animal-crossing/main.dol", "program": "gc",
     "truth": None, "ranges": None},
]
RUNS = {"psx-darkstalkers-3": 3, "ps2-dungeon-game": 3, "ps2-capcom-fighting-evolution": 3,
        "gc-animal-crossing": 3, "x360-black-ops-2": 2, "psv-need-for-speed-most-wanted": 2,
        "nds-pokeheartgold-arm9": 2, "gba-pokeemerald": 2}
# Shortest first, so a partial run already has complete images.
ORDER = ["psx-darkstalkers-3", "ps2-dungeon-game", "gc-animal-crossing",
         "ps2-capcom-fighting-evolution", "x360-black-ops-2", "psv-need-for-speed-most-wanted",
         "nds-pokeheartgold-arm9", "gba-pokeemerald"]


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=1) + "\n")
    temporary.replace(path)


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def ghidra_version(install: Path) -> str:
    properties = (install / "Ghidra" / "application.properties").read_text()
    version = re.search(r"application\.version=(\S+)", properties)
    return version.group(1) if version else "unknown"


def measured(argv: list[str], env: dict, cwd: Path, timeout: int) -> dict:
    """Run one process to completion; wall, CPU and peak RSS from wait4.

    The child leads its own process group so a timeout kills Ghidra's JVM
    and our workers with it. ru_utime/ru_stime of wait4 include every
    descendant the child reaped; ru_maxrss is the largest single process."""
    load_before = os.getloadavg()
    started = time.monotonic()
    with open(cwd / "stdout.txt", "w") as out:
        process = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env,
                                   cwd=cwd, start_new_session=True)
        deadline = started + timeout
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic() > deadline:
                os.killpg(process.pid, signal.SIGKILL)
                pid, status, usage = os.wait4(process.pid, 0)
                process.returncode = -9
                return {"timed_out": True, "wall_s": round(time.monotonic() - started, 2),
                        "load_before": load_before}
            time.sleep(0.05)
    wall = time.monotonic() - started
    try:
        os.killpg(process.pid, signal.SIGKILL)  # stray grandchildren, if any
    except ProcessLookupError:
        pass
    process.returncode = os.waitstatus_to_exitcode(status)
    return {"timed_out": False, "returncode": process.returncode, "wall_s": round(wall, 2),
            "cpu_s": round(usage.ru_utime + usage.ru_stime, 2),
            "user_s": round(usage.ru_utime, 2), "sys_s": round(usage.ru_stime, 2),
            "peak_rss_mb": round(usage.ru_maxrss / 1024),
            "load_before": [round(x, 2) for x in load_before],
            "load_after": [round(x, 2) for x in os.getloadavg()],
            "output": (cwd / "stdout.txt").read_text(errors="replace")}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def executable_ranges(project: Path, program: str) -> list[tuple[int, int]]:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    ranges = [(int(start, 16), int(start, 16) + size) for start, size, permissions in
              db.execute("SELECT start, size, permissions FROM memory_regions WHERE program_id = ?",
                         (pid,)) if "x" in permissions]
    db.close()
    return ranges


def program_name(project: Path, wanted: str) -> str:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    names = [row[0] for row in db.execute("SELECT name FROM programs")]
    db.close()
    if wanted in names:
        return wanted
    if len(names) == 1:
        return names[0]
    raise RuntimeError(f"program {wanted!r} not among {names}")


def score_entries(functions: dict[int, int], truth, ranges, scratch: Path,
                  corroborated: dict[int, str] | None = None) -> dict:
    """m21's score() over a function set that is not a RomWright project.

    `score()` reads programs, memory_regions and functions; this writes the
    three tables it reads (ranges are always explicit here, so
    memory_regions stays empty) and calls it unchanged."""
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    db = sqlite3.connect(scratch / "project.sqlite")
    db.executescript("CREATE TABLE programs (id INTEGER, name TEXT);"
                     "CREATE TABLE memory_regions (program_id INTEGER, start TEXT, size INTEGER,"
                     " permissions TEXT);"
                     "CREATE TABLE functions (program_id INTEGER, entry TEXT, size INTEGER);"
                     "INSERT INTO programs VALUES (1, 'ghidra');")
    db.executemany("INSERT INTO functions VALUES (1, ?, ?)",
                   [(f"{entry:08x}", size) for entry, size in functions.items()])
    db.commit()
    db.close()
    try:
        return M21.score(scratch, "ghidra", truth, ranges, corroborated)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def corroboration(spec: dict, binary: Path, ranges) -> dict[int, str] | None:
    """The image-corroborated entries (m21's `psx_corroborated`) for images scored by it."""
    if spec["id"] not in PSX_PRECISION_METRIC:
        return None
    return M21.psx_corroborated(binary, [tuple(r) for r in ranges])


def quality_fields(row: dict | None) -> dict | None:
    if row is None:
        return None
    keys = ("truth", "found", "recall", "precision", "invented", "sizes_compared",
            "size_exact", "size_short", "size_long", "precision_corroborated",
            "invented_corroborated", "invented_corroborated_by", "invented_uncorroborated",
            "corroborated_unfound")
    return {key: row[key] for key in keys if key in row}


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------

class Tools:
    def __init__(self, target: Path, native: Path, ghidra: Path):
        self.cli = target / "release" / "romwright-cli"
        self.worker = target / "release" / "romwright-worker"
        self.ghidra_opt = native / "ghidra_opt"
        for path in (self.cli, self.worker, self.ghidra_opt):
            if not path.is_file():
                raise SystemExit(f"missing {path}: build with CARGO_TARGET_DIR={target} "
                                 "cargo build --release -p romwright-cli -p romwright-worker")
        self.ours = hashlib.sha256("".join(
            sha256_file(p) for p in (self.cli, self.worker, self.ghidra_opt)).encode()
        ).hexdigest()[:16]
        self.headless = ghidra / "support" / "analyzeHeadless"
        self.ghidra_available = self.headless.is_file()
        self.ghidra_version = ghidra_version(ghidra) if self.ghidra_available else None
        self.script = sha256_file(SCRIPT)[:16]

    def ours_env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_")}
        env.update(ROMWRIGHT_GHIDRA_OPT=str(self.ghidra_opt),
                   ROMWRIGHT_WORKER=str(self.worker), ROMWRIGHT_NO_IMPORT_CACHE="1")
        return env

    def ghidra_env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_")}
        env.update(GHIDRA_HEADLESS_MAXMEM=GHIDRA_MAXMEM, DEBUGINFOD_URLS="")
        return env


def ours_argv(tools: Tools, binary: Path, spec: dict, project: Path) -> list[str]:
    return [str(tools.cli), "import", str(binary), "--name", spec["program"].split(".")[0],
            "--project", str(project), "--timings"]


def ghidra_argv(headless: Path, binary: Path, config: dict, project_dir: Path, out: Path) -> list[str]:
    argv = [str(headless), str(project_dir), "proj", "-import", str(binary)]
    if config["loader"]:
        argv += ["-loader", config["loader"], *config["options"]]
    return argv + ["-processor", config["language"], "-scriptPath", str(SCRIPT.parent),
                   "-postScript", SCRIPT.name, str(out), "-deleteProject"]


def run_ours(tools: Tools, spec: dict, binary: Path, run_dir: Path, truth) -> dict:
    project = run_dir / "project"
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    argv = ours_argv(tools, binary, spec, project)
    row = measured(argv, tools.ours_env(), run_dir, LIMIT_S)
    output = row.pop("output", "")
    row["argv"] = argv
    if row["timed_out"] or row["returncode"]:
        row["status"] = "timeout" if row["timed_out"] else "error"
        row["error"] = output[-600:]
        shutil.rmtree(project, ignore_errors=True)
        return row
    timings = {}
    for line in output.splitlines():
        if line.startswith("TIMINGS "):
            timings = json.loads(line[len("TIMINGS "):])
    program = program_name(project, spec["program"])
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    language = db.execute("SELECT language FROM programs WHERE name = ?", (program,)).fetchone()[0]
    db.close()
    ranges = spec["ranges"] or executable_ranges(project, program)
    row.update(status="ok", program=program, language=language,
               phases={"total": timings.get("total"), **(timings.get("phases") or {})},
               functions_all_programs=timings.get("functions"),
               degraded=[d["message"] for d in timings.get("diagnostics", [])
                         if d.get("severity") == "degraded"],
               ranges=[[lo, hi] for lo, hi in ranges])
    if truth is not None:
        row["score"] = quality_fields(M21.score(project, program, truth, ranges,
                                                corroboration(spec, binary, ranges)))
    shutil.rmtree(project, ignore_errors=True)
    return row


def ghidra_phases(output: str, wall: float) -> dict:
    startup = re.search(r"Headless startup complete \((\d+) ms\)", output)
    total = re.search(r"Total Time\s+(\d+) secs", output)
    analyzers = {name.strip(): float(seconds) for name, seconds in
                 re.findall(r"^\s{4}(\S.*?)\s+([\d.]+) secs$", output, re.M)}
    startup_s = int(startup.group(1)) / 1000 if startup else None
    analysis_s = float(total.group(1)) if total else None
    phases = {"jvm_startup": startup_s, "analysis": analysis_s}
    if startup_s is not None and analysis_s is not None:
        phases["load_script_save_exit"] = round(wall - startup_s - analysis_s, 2)
    top = sorted(analyzers.items(), key=lambda item: -item[1])[:8]
    phases["top_analyzers"] = dict(top)
    return phases


def run_ghidra(tools: Tools, headless: Path, spec: dict, config: dict, binary: Path, run_dir: Path,
               truth, ranges) -> dict:
    project_dir = run_dir / "ghidra-project"
    shutil.rmtree(project_dir, ignore_errors=True)
    project_dir.mkdir(parents=True)
    out = run_dir / "ghidra-functions.json"
    out.unlink(missing_ok=True)
    argv = ghidra_argv(headless, binary, config, project_dir, out)
    row = measured(argv, tools.ghidra_env(), run_dir, LIMIT_S)
    output = row.pop("output", "")
    row["argv"] = argv
    shutil.rmtree(project_dir, ignore_errors=True)
    exported = read_json(out)
    if row["timed_out"] or row["returncode"] or not exported \
            or "REPORT: Import succeeded" not in output:
        row["status"] = "timeout" if row["timed_out"] else "error"
        row["error"] = "\n".join(line for line in output.splitlines()
                                 if "ERROR" in line or "Exception" in line)[-1200:] or output[-600:]
        return row
    loader = re.search(r"Using Loader: (.*?) \(ProgramLoader\)", output)
    functions = {f["entry"]: f["size"] for f in exported["functions"] if not f["overlay"]}
    if not ranges:
        ranges = [(b["start"], b["start"] + b["size"]) for b in exported["blocks"]
                  if b["execute"] and b["initialized"] and not b["overlay"]]
    row.update(status="ok", language=exported["language"], compiler=exported["compiler"],
               format=exported["format"], image_base=exported["image_base"],
               loader=loader.group(1) if loader else None,
               functions_total=len(exported["functions"]),
               functions_overlay=sum(1 for f in exported["functions"] if f["overlay"]),
               phases=ghidra_phases(output, row["wall_s"]))
    if exported["language"] != config["language"]:
        row["status"] = "error"
        row["error"] = f"Ghidra chose {exported['language']}, configured {config['language']}"
        return row
    if truth is not None:
        row["score"] = quality_fields(score_entries(functions, truth, ranges, run_dir / "score",
                                                    corroboration(spec, binary, ranges)))
    out.unlink(missing_ok=True)
    return row


def prepared_binary(spec: dict, corpus: Path, work: Path) -> Path:
    image = corpus / spec["image"]
    if not spec.get("strip"):
        return image
    out = work / "binaries" / spec["id"] / f"{image.name}.stripped"
    if not out.is_file():
        out.parent.mkdir(parents=True, exist_ok=True)
        M21.strip(image, out.parent)
    return out


def truth_for(spec: dict, corpus: Path):
    if not spec.get("truth"):
        return None
    kind, path = spec["truth"]
    loader = {"elf": M21.elf_functions, "psx-map": M21.psx_map_functions,
              "msvc-map": M21.msvc_map_functions, "binmap": M21.binmap_functions}[kind]
    return loader(corpus / path)


def reusable(cached: dict | None, key: dict) -> bool:
    """A cached run counts unless it timed out under a shorter limit than now."""
    if not cached or cached.get("key") != key:
        return False
    row = cached["row"]
    return row["status"] != "timeout" or row["wall_s"] >= LIMIT_S


def run_image(tools: Tools, spec: dict, corpus: Path, work: Path, runs: int) -> dict:
    image = corpus / spec["image"]
    if not image.is_file():
        return {"status": "skipped", "reason": f"{image} absent"}
    if spec.get("truth") and not (corpus / spec["truth"][1]).is_file():
        return {"status": "skipped", "reason": "truth absent"}
    binary = prepared_binary(spec, corpus, work)
    truth = truth_for(spec, corpus)
    config = GHIDRA_CONFIG[spec["id"]]
    image_sha = sha256_file(binary)
    key_ours = {"tools": tools.ours, "image": image_sha}
    # `why` is prose for the report; it does not change what Ghidra runs.
    key_ghidra = {"ghidra": tools.ghidra_version, "script": tools.script, "image": image_sha,
                  "config": {k: v for k, v in config.items() if k != "why"}, "maxmem": GHIDRA_MAXMEM}
    headless = tools.headless
    if spec["id"] in PSX_PRECISION_METRIC:
        key_ours["scoring"] = key_ghidra["scoring"] = SCORING_TAG
    ours_rows, ghidra_rows = [], []
    for index in range(runs):
        # Alternate tools run by run, so drift in the host's load lands on
        # both rather than on whichever ran second.
        run_dir = work / "runs" / spec["id"] / f"ours-{index}"
        cached = read_json(run_dir / "result.json")
        if reusable(cached, key_ours):
            row = cached["row"]
        else:
            log(f"{spec['id']}: romwright run {index + 1}/{runs}")
            run_dir.mkdir(parents=True, exist_ok=True)
            row = run_ours(tools, spec, binary, run_dir, truth)
            write_json(run_dir / "result.json", {"key": key_ours, "row": row})
        log(f"{spec['id']}: romwright {row['status']} {row['wall_s']} s"
            + (f" r/p {row['score']['recall']}/{row['score']['precision']}" if row.get("score") else ""))
        ours_rows.append(row)
        if not tools.ghidra_available:
            continue
        ranges = [tuple(r) for r in row["ranges"]] if row.get("ranges") else spec["ranges"]
        run_dir = work / "runs" / spec["id"] / f"ghidra-{index}"
        cached = read_json(run_dir / "result.json")
        if reusable(cached, key_ghidra):
            row = cached["row"]
        else:
            log(f"{spec['id']}: ghidra run {index + 1}/{runs}")
            run_dir.mkdir(parents=True, exist_ok=True)
            row = run_ghidra(tools, headless, spec, config, binary, run_dir, truth, ranges)
            write_json(run_dir / "result.json", {"key": key_ghidra, "row": row})
        log(f"{spec['id']}: ghidra {row['status']} {row['wall_s']} s"
            + (f" r/p {row['score']['recall']}/{row['score']['precision']}" if row.get("score") else ""))
        ghidra_rows.append(row)
    return judge(spec, config, ours_rows, ghidra_rows, truth is not None)


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def summary(rows: list[dict]) -> dict | None:
    ok = [row for row in rows if row["status"] == "ok"]
    if not ok:
        return None
    walls = [row["wall_s"] for row in ok]
    median = statistics.median(walls)
    scores = [json.dumps(row.get("score"), sort_keys=True) for row in ok]
    return {"runs": len(ok), "wall_s": walls, "wall_median_s": round(median, 2),
            "spread": round((max(walls) - min(walls)) / median, 4) if median else 0.0,
            "cpu_median_s": round(statistics.median(row["cpu_s"] for row in ok), 2),
            "cpu_per_wall": round(statistics.median(row["cpu_s"] / row["wall_s"] for row in ok), 2),
            "peak_rss_mb_max": max(row["peak_rss_mb"] for row in ok),
            "load_1min": [row["load_before"][0] for row in ok],
            "score": ok[0].get("score"), "score_stable": len(set(scores)) == 1,
            "phases_first_run": ok[0].get("phases"), "language": ok[0].get("language"),
            "argv": ok[0]["argv"]}


def judge(spec: dict, config: dict, ours_rows: list[dict], ghidra_rows: list[dict],
          has_truth: bool) -> dict:
    ours, ghidra = summary(ours_rows), summary(ghidra_rows)
    result = {"status": None, "ghidra_config": config, "ours": ours, "ghidra": ghidra,
              "ours_runs": ours_rows, "ghidra_runs": ghidra_rows, "failures": []}
    errors = [f"{tool}: {row['status']}: {row.get('error', '')[-300:]}"
              for tool, rows in (("romwright", ours_rows), ("ghidra", ghidra_rows))
              for row in rows if row["status"] != "ok"]
    if ours is None or ghidra is None:
        result["status"] = "incomplete"
        result["failures"] = errors or ["Ghidra not available"]
        if ours is not None and ghidra_rows and all(row["status"] == "timeout" for row in ghidra_rows):
            # Ghidra never finished: the ratio is only bounded, and with no
            # Ghidra function list there is no quality comparison, so the
            # image cannot pass.
            walls = sorted(row["wall_s"] for row in ghidra_rows)
            bound = ours["wall_median_s"] / walls[0]
            result.update(speed="faster (bound)" if bound < 1 - SPEED_TOLERANCE_FLOOR else "inconclusive",
                          wall_ratio_upper_bound=round(bound, 4),
                          quality="unknown (Ghidra did not finish)")
            result["failures"] = [f"Ghidra auto-analysis did not finish in any of {len(walls)} runs "
                                  f"(killed at {', '.join(f'{w:.0f}' for w in walls)} s): wall ratio "
                                  f"< {bound:.3f}, but no Ghidra function list, so quality is not "
                                  "comparable"]
        return result
    ratio = ours["wall_median_s"] / ghidra["wall_median_s"]
    tolerance = max(SPEED_TOLERANCE_FLOOR, ours["spread"], ghidra["spread"])
    result.update(wall_ratio=round(ratio, 4), cpu_ratio=round(ours["cpu_median_s"] / ghidra["cpu_median_s"], 4),
                  rss_ratio=round(ours["peak_rss_mb_max"] / ghidra["peak_rss_mb_max"], 4),
                  speed_tolerance=round(tolerance, 4))
    # Informational, not gated: Ghidra's wall without its JVM start, the
    # most a resident Ghidra (GUI session) could save on each import.
    startups = [row["phases"]["jvm_startup"] for row in ghidra_rows
                if row["status"] == "ok" and row["phases"].get("jvm_startup") is not None]
    if startups:
        result["wall_ratio_ex_jvm_startup"] = round(
            ours["wall_median_s"] / (ghidra["wall_median_s"] - statistics.median(startups)), 4)
    if ratio < 1 - tolerance:
        result["speed"] = "faster"
    elif ratio < 1 + tolerance:
        result["speed"] = "inconclusive"
        result["failures"].append(f"wall ratio {ratio:.3f} within 1 +- {tolerance:.3f}")
    else:
        result["speed"] = "slower"
        result["failures"].append(f"slower: wall ratio {ratio:.3f} (>= {1 + tolerance:.3f})")
    if has_truth:
        quality = []
        precision_metric = PSX_PRECISION_METRIC.get(spec["id"], "precision")
        result["precision_gate"] = precision_metric
        # `precision` is always reported; it is gated unless the image names another metric.
        for metric in dict.fromkeys(("recall", "precision", precision_metric)):
            delta = round(ours["score"][metric] - ghidra["score"][metric], 4)
            result[f"{metric}_delta"] = delta
            if metric in ("recall", precision_metric) and delta < -QUALITY_MARGIN:
                quality.append(f"{metric} {ours['score'][metric]} vs Ghidra "
                               f"{ghidra['score'][metric]} ({delta:+.4f} < -{QUALITY_MARGIN})")
        result["quality"] = "worse" if quality else "not-worse"
        # Informational, not gated: each metric is gated on its own above.
        f1 = lambda s: round(2 * s["recall"] * s["precision"] / max(s["recall"] + s["precision"], 1e-9), 4)
        result["f1"] = {"romwright": f1(ours["score"]), "ghidra": f1(ghidra["score"])}
        result["failures"] += quality
    else:
        result["quality"] = "n/a (no truth)"
    for tool, summary_row in (("romwright", ours), ("ghidra", ghidra)):
        if not summary_row["score_stable"]:
            result["failures"].append(f"{tool} scores differ between runs")
    for row in ours_rows:
        if row.get("degraded"):
            result["failures"].append("romwright analysis degraded: " + "; ".join(row["degraded"])[:200])
            break
    result["failures"] += errors
    result["status"] = "fail" if result["failures"] else "pass"
    return result


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def markdown(report: dict) -> str:
    lines = [
        "# Import speed vs stock Ghidra (generated)",
        "",
        "Written by `benchmarks/import_speed.py`; do not edit by hand. Method, tolerance and "
        "fairness rules: the script's docstring and `docs/import-speed.md`.",
        "",
        f"Recorded {report['recorded_at']} on {report['host']['cpus']} threads "
        f"(shared host), Ghidra {report['ghidra_version']}, romwright tools "
        f"`{report['romwright_tools']}` (native tools from `{report['native_dir']}`), "
        f"Ghidra heap {GHIDRA_MAXMEM}, per-run limit {report['limit_s']} s. "
        f"Verdict: **{report['status'].upper()}**.",
        "",
        "| image | romwright wall s (median, runs) | Ghidra wall s (median, runs) | wall ratio | tol "
        "| ratio ex JVM start | CPU s ours / Ghidra | peak RSS MB ours / Ghidra | recall ours / Ghidra "
        "| precision ours / Ghidra | verdict |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    score = lambda s, k: f"{s['score'][k]:.4f}" if s.get("score") else "n/a"

    def precision_cell(row: dict, ours: dict | None, ghidra: dict | None) -> str:
        cell = f"{score(ours, 'precision') if ours else '-'} / {score(ghidra, 'precision') if ghidra else '-'}"
        gate = row.get("precision_gate", "precision")
        if gate != "precision" and ours and ghidra:
            cell += f"; gated `{gate}` {score(ours, gate)} / {score(ghidra, gate)}"
        return cell
    for name, row in report["rows"].items():
        ours, ghidra = row.get("ours"), row.get("ghidra")
        if not ours or not ghidra:
            bound = row.get("wall_ratio_upper_bound")
            timed_out = [r["wall_s"] for r in row.get("ghidra_runs", []) if r["status"] == "timeout"]
            lines.append(f"| {name} | {ours['wall_median_s'] if ours else '-'} "
                         f"({', '.join(str(r['wall_s']) for r in row.get('ours_runs', []))}) "
                         f"| {'> ' + str(min(timed_out)) + ' (timeout)' if timed_out else '-'} "
                         f"| {'< ' + format(bound, '.3f') if bound else '-'} | - | - | - | - "
                         f"| {score(ours, 'recall') if ours else '-'} / - "
                         f"| {precision_cell(row, ours, ghidra)} | {row['status']} |")
            continue
        lines.append(
            f"| {name} | {ours['wall_median_s']} ({', '.join(map(str, ours['wall_s']))}) "
            f"| {ghidra['wall_median_s']} ({', '.join(map(str, ghidra['wall_s']))}) "
            f"| **{row['wall_ratio']:.3f}** | {row['speed_tolerance']:.3f} "
            f"| {row.get('wall_ratio_ex_jvm_startup', '-')} "
            f"| {ours['cpu_median_s']} / {ghidra['cpu_median_s']} "
            f"| {ours['peak_rss_mb_max']} / {ghidra['peak_rss_mb_max']} "
            f"| {score(ours, 'recall')} / {score(ghidra, 'recall')} "
            f"| {precision_cell(row, ours, ghidra)} | {row['status']} |")
    lines += ["", "## Failures", ""]
    failing = [(name, row) for name, row in report["rows"].items() if row["status"] != "pass"]
    lines += [f"- **{name}** ({row['status']}): " + "; ".join(row.get("failures") or [row.get("reason", "")])
              for name, row in failing] or ["None."]
    lines += ["", "## Per image", ""]
    for name, row in report["rows"].items():
        lines += [f"### {name}", ""]
        if row["status"] == "skipped":
            lines += [f"Skipped: {row['reason']}", ""]
            continue
        config = row["ghidra_config"]
        lines.append(f"Ghidra: `{config['language']}`, loader "
                     f"{'`' + config['loader'] + '` ' + ' '.join(config['options']) if config['loader'] else 'auto-selected'}"
                     f" -- {config['why']}")
        lines.append("")
        if "wall_ratio" in row:
            lines += [f"Speed {row['speed']} (wall ratio {row['wall_ratio']}, CPU ratio {row['cpu_ratio']}, "
                      f"peak RSS ratio {row['rss_ratio']}); quality {row['quality']}"
                      + (f"; F1 (informational) romwright {row['f1']['romwright']} / Ghidra "
                         f"{row['f1']['ghidra']}" if row.get("f1") else "") + ".", ""]
        for tool, key in (("romwright", "ours"), ("Ghidra", "ghidra")):
            summary_row = row.get(key)
            if not summary_row:
                for index, run in enumerate(row.get(f"{key}_runs") or []):
                    lines += [f"- {tool} run {index + 1}: {run['status']} after {run['wall_s']} s"
                              + (f": {run['error'][-200:]}" if run.get("error") else ""),
                              f"  - command: `{' '.join(run['argv'])}`"]
                continue
            first = (row[f"{key}_runs"] or [{}])[0]
            extra = (f", loader `{first.get('loader')}`, {first.get('functions_total')} functions "
                     f"({first.get('functions_overlay')} in overlays, unscored)") if key == "ghidra" else ""
            lines += [f"- {tool}: language `{summary_row['language']}`{extra}; CPU/wall "
                      f"{summary_row['cpu_per_wall']}; 1-min load before runs {summary_row['load_1min']}; "
                      f"score {json.dumps(summary_row['score'])}",
                      f"  - phases (first run, s): `{json.dumps(summary_row['phases_first_run'])}`",
                      f"  - command: `{' '.join(summary_row['argv'])}`"]
        lines.append("")
    lines += ["## Gate", "",
              f"- speed: median wall ratio ours/Ghidra < 1 - tol, tol = max({SPEED_TOLERANCE_FLOOR}, "
              "worst (max-min)/median run spread of either tool on the image); inside 1 +- tol is "
              "inconclusive and fails.",
              f"- quality: recall and precision each >= Ghidra's - {QUALITY_MARGIN} (m21-001's floor margin), "
              "both scored by m21-001 `score()` over the same ranges. "
              f"Images in PSX_PRECISION_METRIC ({', '.join(PSX_PRECISION_METRIC)}) gate m21-001's "
              "supplementary `precision_corroborated` instead of `precision` (both reported; "
              "docs/import-speed.md).", "",
              "## Fairness", ""]
    lines += [f"- {note}" for note in FAIRNESS] + [""]
    return "\n".join(lines) + "\n"


def main() -> int:
    global LIMIT_S
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=M21.CORPUS)
    parser.add_argument("--work", type=Path, default=WORK)
    parser.add_argument("--ghidra", type=Path, default=GHIDRA)
    parser.add_argument("--target", type=Path, default=TARGET)
    parser.add_argument("--native", type=Path, default=NATIVE,
                        help="directory holding ghidra_opt")
    parser.add_argument("--report", type=Path, default=REPORTS / "import-speed.json")
    parser.add_argument("--only", nargs="*", help="image ids to run")
    parser.add_argument("--runs", type=int, help="runs per tool per image (default: 3 small, 2 large)")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--limit", type=int, default=LIMIT_S,
                        help=f"seconds per run before it is killed (default {LIMIT_S})")
    arguments = parser.parse_args()
    LIMIT_S = arguments.limit
    if not arguments.no_build:
        subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                       cwd=ROOT, check=True, env={**os.environ, "CARGO_TARGET_DIR": str(arguments.target)})
    tools = Tools(arguments.target, arguments.native, arguments.ghidra)
    arguments.work = arguments.work.resolve()
    if any(part.startswith(".") for part in arguments.work.parts):
        raise SystemExit(f"--work {arguments.work}: Ghidra rejects project paths with a '.' element")
    arguments.work.mkdir(parents=True, exist_ok=True)
    by_id = {spec["id"]: spec for spec in IMAGES}
    rows = {}
    # A partial run keeps the other images' rows of the report it overwrites.
    previous = (read_json(arguments.report) or {}).get("rows", {}) if arguments.only else {}
    for name in ORDER:
        if arguments.only and name not in arguments.only:
            continue
        rows[name] = run_image(tools, by_id[name], arguments.corpus, arguments.work,
                               arguments.runs or RUNS[name])
        row = rows[name]
        log(f"{name}: {row['status']}"
            + (f" ratio {row['wall_ratio']}" if "wall_ratio" in row else "")
            + (f" -- {'; '.join(row['failures'])}" if row.get("failures") else ""))
    rows = {name: rows[name] if name in rows else previous[name]
            for name in ORDER if name in rows or name in previous}
    judged = [row for row in rows.values() if row["status"] != "skipped"]
    status = "pass" if judged and all(row["status"] == "pass" for row in judged) else "fail"
    report = {
        "id": "import-speed", "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": {"cpus": os.cpu_count(), "load_at_end": [round(x, 2) for x in os.getloadavg()]},
        "ghidra_version": tools.ghidra_version, "ghidra_maxmem": GHIDRA_MAXMEM,
        "romwright_tools": tools.ours, "native_dir": str(arguments.native), "script_sha256_16": tools.script,
        "speed_tolerance_floor": SPEED_TOLERANCE_FLOOR, "quality_margin": QUALITY_MARGIN,
        "limit_s": LIMIT_S, "status": status, "rows": rows,
        "failures": {name: row.get("failures") or [row.get("reason")] for name, row in rows.items()
                     if row["status"] != "pass"},
    }
    write_json(arguments.report, report)
    arguments.report.with_suffix(".md").write_text(markdown(report))
    print(f"import-speed: {status.upper()} -> {arguments.report}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
