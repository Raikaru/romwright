#!/usr/bin/env python3
"""M22-004: romwright C for x86 PE functions, compiled with the fixture's own compiler and scored against its bytes.

The PC counterpart of m22-003. The truth is a PC fixture in the truth contract (docs/console-research.md "The truth
contract"; docs/pc-project.md "Fixtures"): `<fixture>/<image>.exe` plus `truth/{meta.json,functions.tsv}`, where `meta.json`
names the `compiler` (a manifest id of `crates/romwright-core/src/new_project/toolchains.json`: `msvc4.2`, `msvc6.0`,
`msvc7.0`, `msvc7.1`, `msvc8.0`) and the `flags` the game was built with.

  prepare  install the pinned tools (wibo, objdiff-cli, the compiler; sha256-checked by the generated projects' own
           `download_tool.py`), import the image into a fresh romwright project, draw the sample.
  run      for each sampled function: `export-c --address`, the dialect prelude (Ghidra's type names), the compiler
           (`cl.exe` under wibo, the fixture's flags, `/c`), the function's bytes and relocation fields out of the COFF
           object, and the score against the retail bytes: exact (the code bytes equal outside the relocation fields,
           after it nothing but jump-table words and padding, and every relocation the candidate names by an address
           resolves to the operand the retail instruction has: `--no-strict-relocs` drops that check), compiled (the object
           defines the function), and objdiff-cli 3.6.1 `match_percent` (`functionRelocDiffs=none`) on one-function ELF i386
           objects: the candidate's with its own relocations, the retail function's with the relocation fields read off its
           linked bytes (`pcobj.retail_relocations`; `--target-relocs candidate` is the original rule that copied the
           candidate's fields into the retail bytes, which desynchronised the x86 decode after the first difference in length).
  search   `--search N`: for every function that compiled and is not exact, the product's near-miss plan (docs/match.md,
           `romwright-cli match --plan`) of printing variants, each exported, compiled and scored like the default print; the report's
           headline is then the best print per function and `summary.default_layer` the default print.
  classify `--artifacts DIR` keeps every candidate's C, compile log and bytes; `tests/m22-004/failure_classes.py REPORT DIR` sorts the
           non-exact functions into compile-failure classes and byte-difference classes (needs the capstone Python module).

    python3 tests/m22-004_pc_c_output.py --fixture ~/ventris-corpus/extracted/pc-quake-gl --tag arm0

Exit status is non-zero only when the harness itself breaks. See docs/pc-project.md.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import importlib.util
import json
import os
import platform
import random
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
HOME = Path.home()
sys.path.insert(0, str(HERE / "m22-004"))
sys.path.insert(0, str(HERE))
import match_search_arm  # noqa: E402
import pcobj  # noqa: E402

MANIFEST = REPO / "crates/romwright-core/src/new_project/toolchains.json"
TOOLS_DIR = REPO / "crates/romwright-core/src/new_project/templates/ps2/tools"
SEED = 20261015
SAMPLE = 200
SIZE_MIN, SIZE_MAX = 16, 1024
# what the tool is told to leave to the harness: the object name and any debug-info output
DROP_FLAGS = re.compile(r"^/(Fo|Fd|Fp|Fe|FR|Fr|Yu|Yc|Yd|Zi|ZI|Z7|Zd|c|nologo|MP)", re.I)

PRELUDE = """typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned __int64 undefined8;
typedef unsigned char byte;
typedef signed char sbyte;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef __int64 longlong;
typedef unsigned __int64 ulonglong;
typedef double longdouble;
typedef unsigned char bool;
typedef int (*code)();
"""


# `long long` and the `LL`/`ULL` suffixes do not exist in Visual C++ before 7.1 and `__int64`/`i64` exist in all of them: the
# same rewrite as new_project/pe.rs `msvc_dialect` (strings and comments untouched)
DIALECT_TOKEN = re.compile(r"""("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|/\*.*?\*/|//[^\n]*)|\blong\s+long\b|\b(0[xX][0-9a-fA-F]+|[0-9]+)([uU]?[lL][lL])\b""", re.S)


def msvc_dialect(text):
    def one(match):
        if match.group(1):
            return match.group(1)
        if match.group(2):
            return match.group(2) + ("ui64" if match.group(3)[0] in "uU" else "i64")
        return "__int64"
    return DIALECT_TOKEN.sub(one, text)


# C23 (GCC's default from 15) makes `bool` a keyword: the typedef is only for the dialects that need it
GCC_PRELUDE = PRELUDE.replace("__int64", "long long").replace(
    "typedef unsigned char bool;", "#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L\ntypedef unsigned char bool;\n#endif")


def thiscall_as_fastcall(text):
    """Visual C's C mode has no `__thiscall`: the definition is a `__fastcall` with an unused `edx` (new_project/pe.rs)."""
    at = text.find("__thiscall")
    if at < 0:
        return text
    after = at + len("__thiscall")
    open_ = text.find("(", after)
    if open_ < 0 or not re.fullmatch(r"\w*", text[after:open_].strip()):
        return text
    depth, close, comma = 0, None, None
    for i in range(open_, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
        elif c == "," and depth == 1 and comma is None:
            comma = i
    if close is None or not text[close + 1:].lstrip().startswith("{"):
        return text
    where = comma if comma is not None else close
    return text[:at] + "__fastcall" + text[after:where] + ", int edx_unused" + text[where:]


class HarnessError(Exception):
    pass


def log(message):
    print(message, file=sys.stderr, flush=True)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


download_tool = load_module("pc_download_tool", TOOLS_DIR / "download_tool.py")


def run(argv, *, timeout=600, env=None, cwd=None):
    started = time.monotonic()
    try:
        result = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd,
                                errors="replace")
        code, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code, out, err = -9, error.stdout or "", f"timeout after {timeout}s"
        out = out.decode(errors="replace") if isinstance(out, bytes) else out
    except OSError as error:
        code, out, err = 127, "", f"cannot run: {error}"
    return {"exit": code, "stdout": out, "stderr": err, "seconds": round(time.monotonic() - started, 3)}


# ---------------------------------------------------------------------------
# Fixture and tools
# ---------------------------------------------------------------------------

class Fixture:
    def __init__(self, path):
        self.dir = Path(path).expanduser().resolve()
        meta_path = self.dir / "truth" / "meta.json"
        if not meta_path.is_file():
            raise HarnessError(f"{meta_path}: not a truth-contract fixture")
        self.meta = json.loads(meta_path.read_text())
        self.image = self.dir / self.meta["image"]
        self.id = self.meta.get("id", self.dir.name)
        rows = []
        for line in (self.dir / "truth" / "functions.tsv").read_text().splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            rows.append({"address": int(parts[0], 16), "size": int(parts[1]), "name": parts[2],
                         "module": parts[3] if len(parts) > 3 else "main", "verified": parts[4] == "1" if len(parts) > 4 else True})
        self.rows = sorted(rows, key=lambda r: r["address"])
        self.pe = pcobj.PeImage(self.image)

    def next_start(self, row):
        """The next truth function's start (the end of this one's span, jump tables and padding included)."""
        later = [r["address"] for r in self.rows if r["address"] > row["address"]]
        return min(later) if later else row["address"] + row["size"] + 64


class Tools:
    """The pinned tools (installed by download_tool, sha256-checked) and how to run the compiler."""

    def __init__(self, cache, compiler_id, mingw_root=None):
        if compiler_id == "mingw-gcc":
            # MinGW GCC is not in the manifest (Fedora's RPMs would need an rpm unpacker in download_tool): a local tree of
            # the fixture's own compiler, its sha256 recorded in the report
            if not mingw_root:
                raise HarnessError("a MinGW fixture needs --mingw-root DIR (a tree with usr/bin/i686-w64-mingw32-gcc)")
            manifest = download_tool.load_manifest(MANIFEST)
            cache.mkdir(parents=True, exist_ok=True)
            self.dirs = {"objdiff-cli": download_tool.install(manifest["objdiff-cli"], cache, cache / ".cache")}
            self.pins = {"objdiff-cli": next(iter(manifest["objdiff-cli"]["assets"].values()))["sha256"]}
            self.objdiff = self.dirs["objdiff-cli"] / "objdiff-cli"
            self.gcc = Path(mingw_root).expanduser() / "usr/bin/i686-w64-mingw32-gcc"
            if not self.gcc.is_file():
                raise HarnessError(f"{self.gcc}: missing")
            self.pins["mingw-gcc"] = download_tool.sha256_file(self.gcc)
            self.compiler_id, self.cl, self.wibo, self.include = compiler_id, self.gcc, None, ""
            return
        manifest = download_tool.load_manifest(MANIFEST)
        cache.mkdir(parents=True, exist_ok=True)
        self.dirs, self.pins = {}, {}
        for tool_id in ("wibo", "objdiff-cli", compiler_id):
            if tool_id not in manifest:
                raise HarnessError(f"{tool_id}: not in {MANIFEST}")
            self.dirs[tool_id] = download_tool.install(manifest[tool_id], cache, cache / ".cache")
            self.pins[tool_id] = next(iter(manifest[tool_id]["assets"].values()))["sha256"]
        tool = manifest[compiler_id]
        self.compiler_id = compiler_id
        self.wibo = self.dirs["wibo"] / "wibo"
        self.objdiff = self.dirs["objdiff-cli"] / "objdiff-cli"
        self.cl = self.dirs[compiler_id] / tool["entry"]
        includes = [self.dirs[compiler_id] / v for k, v in (tool.get("provides") or {}).items() if "include" in k]
        self.include = ";".join("Z:" + str(p).replace("/", "\\") for p in includes)
        if not self.cl.is_file():
            raise HarnessError(f"{self.cl}: compiler entry missing after install")

    def compile(self, source: Path, obj: Path, flags, cwd):
        if self.wibo is None:
            env = dict(os.environ, PATH=str(self.gcc.parent) + ":" + os.environ.get("PATH", ""))
            return run([self.gcc, "-c", *flags, "-o", obj.name, source.name], env=env, cwd=cwd, timeout=300)
        env = dict(os.environ, INCLUDE=self.include)
        command = [self.wibo, self.cl, "/nologo", "/c", *flags, f"/Fo{obj.name}", source.name]
        return run(command, env=env, cwd=cwd, timeout=300)


def resolve_compiler(meta):
    """The manifest id for a fixture's `compiler` text: a manifest id as is, else the `cl` version the text names
    (`MSVC 10.20 (Visual C++ 4.2, ...)`)."""
    text = meta.get("compiler") or ""
    manifest = download_tool.load_manifest(MANIFEST)
    if text in manifest:
        return text
    by_cl = {"10.20": "msvc4.2", "12.00": "msvc6.0", "13.00": "msvc7.0", "13.10": "msvc7.1", "14.00": "msvc8.0"}
    found = re.search(r"MSVC\s+(\d+\.\d+)", text)
    if found and found.group(1) in by_cl:
        return by_cl[found.group(1)]
    if re.search(r"mingw|gcc", text, re.I):
        return "mingw-gcc"
    return None


def fixture_flags(fixture, override):
    """cl flags from the fixture's `flags` text: what precedes the first `;` (the rest is the link line), parenthesised
    remarks dropped, `/D NAME` spelled `/DNAME`."""
    text = override if override is not None else fixture.meta.get("flags") or fixture.meta.get("cflags") or "/O2"
    text = re.sub(r"\([^)]*\)", " ", text.split(";")[0])
    tokens = shlex.split(text)
    merged, index = [], 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("/D", "/I", "/U") and index + 1 < len(tokens):
            merged.append(token + tokens[index + 1])
            index += 2
            continue
        merged.append(token)
        index += 1
    if fixture_is_gcc(fixture, override):
        return [t for t in merged if t.startswith("-") and not re.match(r"^-(g\d*|o|c|MD|MF|MMD|MT|flto.*|D_FORTIFY.*)$", t) and not t.startswith("-o")] + ["-w", "-fpermissive", "-Wno-int-conversion", "-Wno-incompatible-pointer-types"]
    return [t for t in merged if t.startswith("/") and not DROP_FLAGS.match(t)]


def fixture_is_gcc(fixture, override=None):
    return resolve_compiler(fixture.meta) == "mingw-gcc"


# ---------------------------------------------------------------------------
# romwright
# ---------------------------------------------------------------------------

def romwright_env(args, extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_") or k in ("ROMWRIGHT_GHIDRA",)}
    env.update(ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    if args.ghidra_opt:
        env["ROMWRIGHT_GHIDRA_OPT"] = str(args.ghidra_opt)
    if args.worker:
        env["ROMWRIGHT_WORKER"] = str(args.worker)
    env.update(extra)
    return env


def import_project(args, fixture, work, env):
    project = work / "project"
    shutil.rmtree(project, ignore_errors=True)
    started = time.monotonic()
    result = run([args.cli, "import", fixture.image, "--name", "pc", "--project", project], env=env, timeout=3600)
    record = {"seconds": round(time.monotonic() - started, 1), "exit": result["exit"], "stdout_tail": result["stdout"][-400:],
              "stderr_tail": result["stderr"][-600:]}
    if result["exit"] != 0 or "degraded" in result["stdout"] + result["stderr"]:
        raise HarnessError(f"romwright import failed or degraded: {(result['stdout'] + result['stderr'])[-600:]}")
    listing = run([args.cli, "functions", "pc", "--project", project], env=env, timeout=300) if args.count_functions else None
    if listing and listing["exit"] == 0:
        record["functions_listed"] = len([l for l in listing["stdout"].splitlines() if l.strip()])
    return project, record


def game_code_ranges(fixture):
    """-> (list of (start, end) address ranges the fixture's own sources compiled to, how it was told) or (None, why).
    The sample is drawn from game code only: the statically linked C runtime was built with the vendor's flags, not the
    fixture's. Told by the link map (`Lib:Object` column: a library prefix means runtime) or, with only a PDB, by
    `llvm-pdbutil` (a module that is a bare `.obj` is game code; `x.lib(y.obj)` is runtime)."""
    build = fixture.dir / "truth" / "build"
    maps = sorted(build.glob("*.map")) if build.is_dir() else []
    maps = [m for m in maps if "-debug" not in m.name] or maps
    pe = fixture.pe
    if maps:
        text = maps[0].read_text(errors="replace")
        rows = []
        for line in text.splitlines():
            found = re.match(r"\s*0001:[0-9a-f]+\s+\S+\s+([0-9a-f]+)\s+f\s+(\S+)", line)
            if found:
                rows.append((int(found.group(1), 16), found.group(2)))
        if rows:
            game = {address for address, obj in rows if ":" not in obj and not obj.lower().endswith(".lib")}
            ranges = []
            for row in fixture.rows:
                if row["address"] in game:
                    ranges.append((row["address"], row["address"] + max(row["size"], 1)))
            return ranges, f"link map {maps[0].name}"
    pdbs = sorted(build.glob("*.pdb")) if build.is_dir() else []
    if pdbs and shutil.which("llvm-pdbutil"):
        modules = run(["llvm-pdbutil", "dump", "-modules", pdbs[0]], timeout=300)["stdout"]
        game_modules = set()
        for found in re.finditer(r"^\s*Mod (\d+) \| `([^`]*)`", modules, re.M):
            path = found.group(2)
            # the build's own objects carry the absolute path they were compiled at; a runtime object keeps the vendor's
            # relative path (`build\\intel\\mt_obj\\memset.obj`) or its library (`libcmt.lib(memset.obj)`)
            if re.match(r"[A-Za-z]:", path) and path.lower().endswith(".obj") and ".lib(" not in path.lower():
                game_modules.add(int(found.group(1)))
        contribs = run(["llvm-pdbutil", "dump", "-section-contribs", pdbs[0]], timeout=300)["stdout"]
        ranges = []
        for found in re.finditer(r"SC\[[^\]]*\]\s+\| mod = (\d+), (\d+):(\d+), size = (\d+)", contribs):
            module, section, offset, size = int(found.group(1)), int(found.group(2)), int(found.group(3)), int(found.group(4))
            if module in game_modules and 1 <= section <= len(pe.sections):
                start = pe.sections[section - 1][1] + offset
                ranges.append((start, start + size))
        if ranges:
            return ranges, f"llvm-pdbutil on {pdbs[0].name}"
    dwarf = [p for p in sorted(build.glob("*.exe")) + sorted(build.glob("*.dll")) if p.is_file()] if build.is_dir() else []
    if dwarf and shutil.which("llvm-dwarfdump"):
        found = dwarf_game_ranges(dwarf[0], fixture)
        if found:
            return found, f"llvm-dwarfdump on {dwarf[0].name}"
    return None, "no link map and no readable PDB"


def dwarf_game_ranges(binary, fixture):
    """The address ranges of the subprograms of the compile units that are the game's own: DWARF of a GCC build names a unit by the
    path it was compiled from, and a unit of the C runtime or a library the toolchain's distribution built (compiled elsewhere, a
    relative path under its own build directory) is not under the game's repository directory (`meta.json` `repo`'s last component)."""
    repo = re.sub(r"(\.git)?/*$", "", fixture.meta.get("repo") or "").rsplit("/", 1)[-1]
    text = run(["llvm-dwarfdump", "--debug-info", binary], timeout=600)["stdout"]
    ranges, unit_ok, current, low, high = [], False, None, None, None

    def flush():
        if current == "subprogram" and unit_ok and low is not None and high is not None:
            ranges.append((low, high if high > low else low + high))

    for line in text.splitlines():
        tag = re.match(r"0x[0-9a-f]+:\s+DW_TAG_(\w+)", line)
        if tag:
            flush()
            current, low, high = tag.group(1), None, None
            if current == "compile_unit":
                unit_ok = False
            continue
        attr = re.match(r"\s+DW_AT_(\w+)\s+\((.*)\)", line)
        if not attr:
            continue
        if current == "compile_unit" and attr.group(1) in ("name", "comp_dir"):
            # a unit is the game's when the path it was compiled from, or the directory it was compiled in, is under the repository
            text_value = attr.group(2).strip('"')
            unit_ok = unit_ok or (bool(repo) and f"/{repo}/" in text_value + "/") or (not repo and text_value.startswith("/"))
        elif current == "subprogram" and attr.group(1) in ("low_pc", "high_pc"):
            value = re.match(r"0x([0-9a-f]+)", attr.group(2))
            if value:
                if attr.group(1) == "low_pc":
                    low = int(value.group(1), 16)
                else:
                    high = int(value.group(1), 16)
    flush()
    return ranges


def draw_sample(fixture, n, seed, game_only=True):
    eligible = [r for r in fixture.rows if r["verified"] and r["module"] == "main" and SIZE_MIN <= r["size"] <= SIZE_MAX
                and r["name"] and not re.match(r"^(sub_|FUN_|j_)", r["name"])]
    how = "all truth functions"
    if game_only:
        ranges, how = game_code_ranges(fixture)
        if ranges:
            ranges.sort()
            import bisect
            starts = [r[0] for r in ranges]

            def inside(address):
                index = bisect.bisect_right(starts, address) - 1
                return index >= 0 and ranges[index][0] <= address < ranges[index][1]

            eligible = [r for r in eligible if inside(r["address"])]
        else:
            how = f"all truth functions ({how})"
    rng = random.Random(seed)
    sample = rng.sample(eligible, min(n, len(eligible)))
    return sorted(sample, key=lambda r: r["address"]), len(eligible), how


# ---------------------------------------------------------------------------
# One function
# ---------------------------------------------------------------------------

ERROR_CODE = re.compile(r"error (C\d+):\s*([^\n]*)|(error):\s*([^\n]*)")


def normalise(message):
    message = re.sub(r"'[^']*'", "'_'", message)
    message = re.sub(r"\b\d+\b", "N", message)
    return message.strip()[:110]


def score_function(args, fixture, tools, flags, env, project, workdir, row):
    address = row["address"]
    stem = f"FUN_{address:08x}"
    fdir = workdir / f"{address:08x}"
    shutil.rmtree(fdir, ignore_errors=True)
    fdir.mkdir(parents=True)
    entry = {"name": row["name"], "address": f"{address:08x}", "size": row["size"], "produced": False, "compiled": False,
             "exact": False, "percent": 0.0}
    _, truth_cc, truth_args = pcobj.undecorate(row["name"])
    entry["truth_cc"] = truth_cc if truth_args is not None or truth_cc == "cdecl" else None
    export = fdir / "export"
    export.mkdir()
    result = run([args.cli, "export-c", fixture.image, "pc", export, "--address", f"{address:x}", "--project", project],
                 env=env, timeout=900)
    files = sorted(export.glob("*.c"))
    entry["export_seconds"] = result["seconds"]
    if result["exit"] != 0 or not files:
        entry["error"] = "no export: " + (result["stderr"].strip().splitlines() or ["?"])[-1][:200]
        entry["error_class"] = "not produced"
        return entry
    text = "\n".join(f.read_text(errors="replace") for f in files)
    entry["produced"] = True
    try:  # the export's own warnings (callees it could not declare, irregular bodies): classification input
        entry["export_warnings"] = [w.get("message", "") for w in json.loads(result["stdout"]).get("warnings", [])][:8]
    except ValueError:
        entry["export_warnings"] = []
    entry = score_candidate(args, fixture, tools, flags, fdir, row, entry, text)
    if args.search and entry["compiled"] and not entry["exact"]:
        search_layer(args, fixture, tools, flags, env, project, workdir, row, entry, text)
    return entry


def search_layer(args, fixture, tools, flags, env, project, workdir, row, entry, text):
    """The near-miss search (docs/match.md) on one function whose default print compiled and is not exact: the product's plan
    (`romwright-cli match --plan`) of printing variants, each exported with its switches, compiled and scored like the default
    print; the best print replaces the entry's numbers (`entry["default"]` keeps the default print's)."""
    address = row["address"]
    sdir = workdir / f"{address:08x}-search"
    sdir.mkdir(parents=True, exist_ok=True)
    keys = ("exact", "compiled", "percent", "byte_differences", "candidate_size", "candidate_cc", "relocs_checked", "relocs_wrong", "exact_masked")
    default = {k: entry.get(k) for k in keys}
    inner = argparse.Namespace(**{**vars(args), "artifacts": None, "keep": False})

    def export(words, tag):
        outdir = sdir / tag / "export"
        shutil.rmtree(outdir, ignore_errors=True)
        outdir.mkdir(parents=True)
        variant_env = dict(env)
        variant_env.update(word.split("=", 1) for word in words)
        result = run([args.cli, "export-c", fixture.image, "pc", outdir, "--address", f"{address:x}", "--project", project],
                     env=variant_env, timeout=900)
        files = sorted(outdir.glob("*.c"))
        return "\n".join(f.read_text(errors="replace") for f in files) if files else None

    def score(candidate, tag):
        scored_dir = sdir / tag / "score"
        scored_dir.mkdir(parents=True, exist_ok=True)
        fresh = {"name": row["name"], "address": f"{address:08x}", "size": row["size"], "produced": True, "compiled": False,
                 "exact": False, "percent": 0.0}
        return {"context": score_candidate(inner, fixture, tools, flags, scored_dir, row, fresh, candidate)}

    try:
        label, winner, variants, record = match_search_arm.search_row(
            args.cli, args.search, args.search_pool, sdir, export, score, text, {"context": dict(default)})
    finally:
        shutil.rmtree(sdir, ignore_errors=True)
    entry["default"] = default
    entry["search"] = {"winner": label, "improved": record["improved"], "variants": len(record["variants"]),
                       "decompiles": record["decompiles"], "compiles": record["compiles"], "seconds": record["seconds"]}
    if record["improved"]:
        best = variants["context"]
        entry.update({k: best.get(k) for k in keys if k in best})
        entry["error_class"] = None if best.get("exact") else "compiled, not exact"


def score_candidate(args, fixture, tools, flags, fdir, row, entry, text):
    """Compile `text` (a romwright export) with the fixture's compiler and score it against the retail bytes of `row`."""
    address = row["address"]
    stem = f"FUN_{address:08x}"
    (fdir / "candidate.c").write_text((PRELUDE + thiscall_as_fastcall(msvc_dialect(text))) if tools.wibo else (GCC_PRELUDE + text))
    obj = fdir / "candidate.obj"
    compiled = tools.compile(fdir / "candidate.c", obj, flags, fdir)
    log_text = compiled["stdout"] + compiled["stderr"]
    entry["compile_seconds"] = compiled["seconds"]
    if args.artifacts:
        adir = Path(args.artifacts) / f"{address:08x}"
        adir.mkdir(parents=True, exist_ok=True)
        (adir / "candidate.c").write_text((fdir / "candidate.c").read_text())
        (adir / "compile.log").write_text(log_text)
    if compiled["exit"] != 0 or not obj.exists():
        errors = [(a or c, b or d) for a, b, c, d in ERROR_CODE.findall(log_text)]
        entry["error"] = "; ".join(f"{c}: {m}" for c, m in errors[:2]) or log_text.strip()[-200:]
        entry["error_class"] = errors[0][0] + " " + normalise(errors[0][1]) if errors else "compiler failed"
        entry["calling_convention_in_text"] = bool(re.search(r"__(stdcall|fastcall|thiscall)", text))
        return entry
    try:
        coff = pcobj.CoffObject(obj.read_bytes())
        defined = [n for n, _s, _v in coff.functions()]
        # the export names the entry point `_entry`, not FUN_<address>: the one function the object defines is the candidate
        symbol = next((n for n in defined if stem in n), defined[0] if len(defined) == 1 else None)
        if symbol is None:
            raise KeyError(stem)
        body, relocations = coff.function(symbol)
    except (KeyError, pcobj.PcObjError) as error:
        entry["error"] = f"no function {stem} in the object ({error})"
        entry["error_class"] = "object lacks the function"
        return entry
    entry["compiled"] = True
    _, cand_cc, cand_args = pcobj.undecorate(symbol)
    entry["candidate_cc"] = cand_cc
    body = pcobj.trim_padding(body)
    entry["candidate_size"] = len(body)
    size = row["size"]
    span = fixture.next_start(row) - address
    retail = fixture.pe.bytes_at(address, max(span, len(body), size))
    mask = pcobj.field_mask(len(body), relocations)
    tail_ok = all(mask[i] == 0 or body[i] in (0xCC, 0x90, 0x00) for i in range(size, len(body))) if len(body) > size else True
    cut = size if (len(body) >= size and tail_ok) else len(body)
    differences = pcobj.compare(body[:cut], [r for r in relocations if r["offset"] + 4 <= cut], retail)
    entry["byte_differences"] = differences if cut == size else None
    entry["exact"] = len(body) >= size and tail_ok and differences == 0
    # a function whose bytes are equal outside the relocation fields: a relocation the candidate names by an address
    # (`FUN_00401230`, `DAT_00461210`, `PTR_x_00461210`) must resolve to the operand the retail instruction has, or the masked
    # field was a way to match with a wrong callee or global (only meaningful when the instruction streams are equal)
    entry["exact_masked"] = entry["exact"]
    if entry["exact"]:
        checked, wrong = pcobj.check_relocation_targets(body[:cut], [r for r in relocations if r["offset"] + 4 <= cut], retail, address)
        entry["relocs_checked"], entry["relocs_wrong"] = checked, wrong
        if wrong and args.strict_relocs:
            entry["exact"] = False
    if args.artifacts:
        adir = Path(args.artifacts) / f"{address:08x}"
        (adir / "bytes.json").write_text(json.dumps({"candidate": body.hex(), "retail": bytes(retail[:max(size, len(body))]).hex(),
                                                     "size": size, "address": address, "relocations": relocations, "symbol": symbol}))
    # objdiff: one-function ELF objects with relocations on both sides. The candidate's carry the candidate's; the target's are
    # the retail function's own, read off its linked bytes (`--target-relocs candidate` is the original rule: the candidate's
    # relocation fields copied into the retail bytes, which desynchronises an x86 decode wherever the two streams differ in
    # length, and objdiff then scores everything after the first difference 0)
    cand = body[:cut]
    relocs = [r for r in relocations if r["offset"] + 4 <= cut]
    target = bytearray(retail[:size])
    if args.target_relocs == "retail":
        lo = min(base for _n, base, *_ in fixture.pe.sections)
        hi = max(base + length for _n, base, length, *_ in fixture.pe.sections)
        target_relocs = pcobj.retail_relocations(bytes(target), address, lo, hi)
        for reloc in target_relocs:
            target[reloc["offset"]:reloc["offset"] + 4] = b"\0\0\0\0"
    else:
        cand_mask = pcobj.field_mask(len(cand), relocs)
        for i in range(min(len(target), len(cand))):
            if not cand_mask[i]:
                target[i] = cand[i]
        target_relocs = [r for r in relocs if r["offset"] + 4 <= len(target)]
    (fdir / "target.o").write_bytes(pcobj.object_for_objdiff(bytes(target), [r for r in target_relocs if r["offset"] + 4 <= len(target)], stem))
    (fdir / "base.o").write_bytes(pcobj.object_for_objdiff(cand, relocs, stem))
    record = fdir / "objdiff.json"
    done = run([tools.objdiff, "diff", "-1", fdir / "target.o", "-2", fdir / "base.o", stem, "--format", "json", "-o", record,
                "-c", "functionRelocDiffs=none"], timeout=120)
    if done["exit"] == 0 and record.exists():
        for symbol_row in json.loads(record.read_text()).get("left", {}).get("symbols", []):
            if symbol_row.get("name") == stem:
                entry["percent"] = round(float(symbol_row.get("match_percent", 0.0)), 3)
    else:
        entry["error"] = "objdiff failed: " + done["stderr"][-300:]
    if not entry["exact"]:
        entry["error_class"] = "compiled, not exact"
    if not args.keep:
        shutil.rmtree(fdir, ignore_errors=True)
    return entry


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def bucket(entries):
    n = len(entries)
    if not n:
        return {"functions": 0}
    compiled = [e for e in entries if e["compiled"]]
    percents = [e["percent"] for e in entries]
    return {"functions": n, "produced": sum(e["produced"] for e in entries), "compiled": len(compiled),
            "exact": sum(e["exact"] for e in entries), "mean_percent": round(statistics.fmean(percents), 3),
            "mean_percent_compiled": round(statistics.fmean([e["percent"] for e in compiled]), 3) if compiled else 0.0,
            "percent_ge_90": sum(p >= 90 for p in percents)}


def summarise(entries):
    sizes = {"16-63": (16, 63), "64-255": (64, 255), "256-1024": (256, 1024)}
    classes = {}
    for e in entries:
        if e.get("error_class") and not e["compiled"]:
            classes[e["error_class"]] = classes.get(e["error_class"], 0) + 1
    cc = {}
    for e in entries:
        if e.get("truth_cc") and e["compiled"]:
            key = f"{e['truth_cc']} -> {e.get('candidate_cc')}"
            cc[key] = cc.get(key, 0) + 1
    searched = any("default" in e for e in entries)
    default_layer = [dict(e, **e["default"]) if "default" in e else e for e in entries] if searched else None
    return {"overall": bucket(entries), "default_layer": bucket(default_layer) if searched else None,
            "by_size": {label: bucket([e for e in entries if lo <= e["size"] <= hi]) for label, (lo, hi) in sizes.items()},
            "compile_errors": dict(sorted(classes.items(), key=lambda kv: -kv[1])),
            "calling_convention_truth_to_candidate": cc}


def markdown(report):
    s, o = report["summary"], report["summary"]["overall"]
    lines = [f"# m22-004: C output on {report['fixture']['id']} (x86 PE, {report['compiler']['id']})", "",
             f"Generated {report['generated']}. Sample {o['functions']} functions (seed {report['sample']['seed']}) of "
             f"{report['sample']['eligible']} functions of {SIZE_MIN}-{SIZE_MAX} bytes drawn from {report['sample']['drawn_from']} ({report['fixture']['functions']} in the truth). "
             f"Fixture `{report['fixture']['image']}`; compiler `{report['compiler']['id']}` (`{report['compiler']['cl_banner']}`), "
             f"flags `{' '.join(report['compiler']['flags'])}`; tag `{report['tag']}`; romwright environment `{json.dumps(report['env']) if report['env'] else 'default'}`.", "",
             "| functions | produced | compiled | exact | mean percent | mean percent (compiled) | percent >= 90 |", "|---|---|---|---|---|---|---|",
             f"| {o['functions']} | {o['produced']} | {o['compiled']} | {o['exact']} | {o['mean_percent']} | {o['mean_percent_compiled']} | {o['percent_ge_90']} |", "",
             ]
    if s.get("default_layer"):
        d = s["default_layer"]
        lines += ["Near-miss search (`--search`, docs/match.md): the table above is the best print per function; the default print alone:", "",
                  "| layer | exact | compiled | mean percent | percent >= 90 |", "|---|---|---|---|---|",
                  f"| default print | {d['exact']} | {d['compiled']} | {d['mean_percent']} | {d['percent_ge_90']} |",
                  f"| best of search | {o['exact']} | {o['compiled']} | {o['mean_percent']} | {o['percent_ge_90']} |", ""]
    lines += ["## By function size (bytes)", "", "| size | n | compiled | exact | mean percent |", "|---|---|---|---|---|"]
    for label, b in s["by_size"].items():
        if b["functions"]:
            lines.append(f"| {label} | {b['functions']} | {b['compiled']} | {b['exact']} | {b['mean_percent']} |")
    lines += ["", "## Compile failures (first error, normalised)", ""]
    lines += [f"- {m} x{c}" for m, c in s["compile_errors"].items()] or ["none"]
    if s["calling_convention_truth_to_candidate"]:
        lines += ["", "## Calling convention (the truth name's decoration -> the candidate's)", ""]
        lines += [f"- {k}: {v}" for k, v in sorted(s["calling_convention_truth_to_candidate"].items())]
    lines += ["", "## Limits", ""] + [f"- {item}" for item in report["limits"]]
    return "\n".join(lines) + "\n"


LIMITS = [
    "The candidate is romwright's `export-c` for one function with no context: callees are undeclared (implicit `int f()`), "
    "so a caller of a `__stdcall` function pays the `add esp` the callee's `ret N` would have removed, exactly as a reader who "
    "pastes the export into a project would.",
    "exact: the function's code bytes (the truth size) equal the retail bytes outside the object's relocation fields "
    "(`DIR32`, `REL32`), and anything after them in the candidate is a relocated jump-table word or padding. Percent is objdiff-cli "
    "3.6.1 `match_percent` (`functionRelocDiffs=none`) between two one-function ELF i386 objects: the candidate with its relocations and "
    "the retail function with the relocation fields read off its linked bytes (an absolute displacement or immediate that is an image "
    "address, a `call`/`jmp rel32` out of the function).",
    "A relocation the candidate names by an address (`FUN_<hex>`, `DAT_<hex>`) must resolve to the operand the retail instruction has for "
    "a function to count as exact (`relocs_checked`/`relocs_wrong`); relocations of other symbols (imports, string literals, constants of "
    "the unit) are masked and unchecked.",
    "Functions romwright did not discover at the truth address have no export and score 0 (the importer's recall is part of the number).",
    "The sample is a seeded draw of truth functions the truth marks verified; functions are not independent (they share units).",
]


def cl_banner(tools):
    if tools.wibo is None:
        return (run([tools.gcc, "--version"], timeout=60)["stdout"].splitlines() or ["?"])[0]
    result = run([tools.wibo, tools.cl], env=dict(os.environ, INCLUDE=tools.include), timeout=60)
    text = result["stdout"] + result["stderr"]
    found = re.search(r"Version ([\d.]+) for 80x86", text)
    return found.group(1) if found else text.strip().splitlines()[0][:80] if text.strip() else "?"


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--fixture", required=True)
    p.add_argument("--work", default=None)
    p.add_argument("--tag", default="default")
    p.add_argument("--n", type=int, default=SAMPLE)
    p.add_argument("--seed", type=int, default=SEED)
    p.add_argument("--jobs", type=int, default=3)
    p.add_argument("--cli", default=str(REPO / "target/release/romwright-cli"))
    p.add_argument("--ghidra-opt", default=os.environ.get("ROMWRIGHT_GHIDRA_OPT") or str(REPO / "native/build/ghidra_opt"))
    p.add_argument("--worker", default=os.environ.get("ROMWRIGHT_WORKER"))
    p.add_argument("--mingw-root", default=None, help="a MinGW tree (usr/bin/i686-w64-mingw32-gcc) for a GCC fixture")
    p.add_argument("--tools-cache", default=str(HOME / ".cache/romwright/pc/tools"))
    p.add_argument("--compiler", default=None, help="manifest id; default meta.json `compiler`")
    p.add_argument("--flags", default=None, help="compiler flags; default meta.json `flags`")
    p.add_argument("--env", action="append", default=[], help="KEY=VALUE for the romwright CLI processes")
    p.add_argument("--report", default=None, help="report path stem (writes .json and .md)")
    p.add_argument("--functions-out", default=None)
    p.add_argument("--artifacts", default=None, help="directory for per-function candidate.c, compile.log and bytes.json (classification input)")
    p.add_argument("--no-strict-relocs", dest="strict_relocs", action="store_false",
                   help="count a function exact when only a relocation names the wrong address (the original, masked-only rule)")
    p.add_argument("--search", type=int, default=0, metavar="N",
                   help="near-miss search (docs/match.md): for each compiled, not exact function try up to N printing variants of the "
                        "product's plan; the report's headline is then the best print per function and `default_layer` the default print")
    p.add_argument("--target-relocs", choices=("retail", "candidate"), default="retail",
                   help="relocations of the objdiff target: the retail function's own (default) or the candidate's, copied (the original rule)")
    p.add_argument("--keep", action="store_true", help="keep per-function work directories")
    p.add_argument("--all-code", action="store_true", help="sample the runtime library code too")
    p.add_argument("--count-functions", action="store_true")
    p.add_argument("--reuse-import", action="store_true", help="reuse <work>/project (only when no import behaviour changed)")
    args = p.parse_args()

    fixture = Fixture(args.fixture)
    compiler_id = args.compiler or resolve_compiler(fixture.meta)
    if not compiler_id:
        raise HarnessError(f"cannot tell the compiler from meta.json `compiler` ({fixture.meta.get('compiler')!r}); pass --compiler")
    work = Path(args.work or HOME / ".cache/romwright/pc/work" / f"{fixture.id}-{args.tag}").expanduser()
    work.mkdir(parents=True, exist_ok=True)
    extra_env = dict(item.split("=", 1) for item in args.env)
    env = romwright_env(args, extra_env)
    env["TMPDIR"] = str(work / "tmp")
    (work / "tmp").mkdir(exist_ok=True)
    log("installing the pinned tools")
    tools = Tools(Path(args.tools_cache).expanduser(), compiler_id, args.mingw_root)
    flags = fixture_flags(fixture, args.flags)
    banner = cl_banner(tools)
    log(f"compiler {compiler_id}: cl {banner}, flags {flags}")
    if args.reuse_import and (work / "project/project.sqlite").exists():
        project, import_record = work / "project", {"reused": True}
    else:
        log("importing into a fresh project")
        project, import_record = import_project(args, fixture, work, env)
    sample, eligible, sample_how = draw_sample(fixture, args.n, args.seed, not args.all_code)
    log(f"sample {len(sample)} of {eligible} eligible truth functions ({sample_how})")
    entries = []
    workdir = work / "functions"
    args.search_pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) if args.search else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(score_function, args, fixture, tools, flags, env, project, workdir, row): row for row in sample}
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            entries.append(future.result())
            if index % 20 == 0:
                log(f"  {index}/{len(sample)}")
    entries.sort(key=lambda e: e["address"])
    report = {"schema": "m22-004/1", "generated": datetime.date.today().isoformat(), "tag": args.tag, "env": extra_env,
              "fixture": {"id": fixture.id, "image": fixture.image.name, "functions": len(fixture.rows),
                          "meta": {k: fixture.meta.get(k) for k in ("game", "compiler", "flags", "repo", "commit")}},
              "compiler": {"id": compiler_id, "cl_banner": banner, "flags": flags, "pin": tools.pins[compiler_id]},
              "sample": {"n": len(sample), "seed": args.seed, "eligible": eligible, "size_window": [SIZE_MIN, SIZE_MAX], "drawn_from": sample_how},
              "import": import_record, "summary": summarise(entries), "functions": entries, "limits": LIMITS,
              "host": platform.node()}
    stem = Path(args.report) if args.report else REPO / "benchmarks/reports" / f"pc_c_output_{datetime.date.today():%Y%m%d}"
    stem.parent.mkdir(parents=True, exist_ok=True)
    stem.with_suffix(".json").write_text(json.dumps(report, indent=1) + "\n")
    stem.with_suffix(".md").write_text(markdown(report))
    if args.functions_out:
        Path(args.functions_out).write_text(json.dumps({"schema": "m22-004-functions/1", "tag": args.tag, "functions": {e["address"]: e for e in entries}}))
    o = report["summary"]["overall"]
    print(json.dumps({"exact": o["exact"], "compiled": o["compiled"], "produced": o["produced"], "functions": o["functions"],
                      "mean_percent": o["mean_percent"], "report": str(stem)}))


if __name__ == "__main__":
    try:
        main()
    except HarnessError as error:
        print(f"harness error: {error}", file=sys.stderr)
        sys.exit(2)
