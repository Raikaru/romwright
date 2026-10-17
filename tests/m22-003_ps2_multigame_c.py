#!/usr/bin/env python3
"""M22-003: decompiled C against matched functions of several PS2 decompilations.

The generic, multi-game counterpart of m22-002 (which is Persona 4 only). One
harness, one descriptor per game (`tests/m22-003/<lane>.json`: repo URL and
commit, retail image, compiler ids per unit, build entry point). For each lane:

  prepare   clone the repo at the pinned commit; install the pinned compilers
            (crates/romwright-core/src/new_project/toolchains.json, through the
            generated project's own tools/download_tool.py: sha256-checked,
            shared cache); run the descriptor's `setup` steps (the repo's own
            configure/split, with the repo's compiler paths pointed at the
            pinned binaries); take every unit's exact compile command from the
            repo's own build (`ninja -t compdb`, or the descriptor's command
            list) and build every unit with it.
  matched   a function is *matched* when it is compiled from C by that build
            (not an INCLUDE_ASM body) and its bytes equal the retail image at
            its address modulo relocation fields (m22's comparator,
            tests/m22-003/elfobj.py). No repo verify script is used; the count
            is cross-checked against the repo's own progress where it has one.
  sample    a fixed seeded sample (default seed 20261012, 200) of matched
            functions of 32..1024 bytes whose definition is found in the
            preprocessed unit and has no inline assembly; one shared context per
            function (the unit's own declarations, m22-002's context rule).
  run       candidates per layer -- romwright (`export-c` + `assert-names` +
            `assert-prototypes`), m2c (`-t mipsee-*-c` on splat assembly of the
            retail bytes), optionally stock Ghidra and `oracle` (the unit's own
            text for the function, a pipeline check that must score 100) --
            compiled with that unit's own compile command and scored against the
            retail bytes (exact / compiled / objdiff percent), as m22-002.

    python3 tests/m22-003_ps2_multigame_c.py dds                 # whole lane
    python3 tests/m22-003_ps2_multigame_c.py dds --stage prepare # stop after the matched set
    python3 tests/m22-003_ps2_multigame_c.py dds --layers romwright --env ROMWRIGHT_COMPILER_RULES_DISABLE=ID \
        --tag rule-off --functions-out out.json                  # one layer under an environment (CompilerRules)

Exit status is non-zero only when the harness itself breaks. See docs/c-output-lanes.md.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
HOME = Path.home()
LANE_DIR = HERE / "m22-003"
sys.path.insert(0, str(LANE_DIR))
sys.path.insert(0, str(HERE))
import classes  # noqa: E402
import elfobj  # noqa: E402
import match_search_arm  # noqa: E402

TOOLS_DIR = REPO / "crates/romwright-core/src/new_project/templates/ps2/tools"
MANIFEST = REPO / "crates/romwright-core/src/new_project/toolchains.json"
SEED = 20261012
SAMPLE = 200
SIZE_MIN, SIZE_MAX = 32, 1024
VARIANTS = ("context", "standalone")
SANDBOX_MARK = "M22_003_SANDBOX"
DEFAULT_ROOT = HOME / ".cache" / "romwright" / "m22-003"
GLIBC32 = Path(os.environ.get("M22_003_GLIBC32") or HOME / "opt" / "glibc32" / "usr" / "lib")
GHIDRA = Path(os.environ.get("ROMWRIGHT_GHIDRA") or HOME / "ghidra_12.1.3_PUBLIC")


class HarnessError(Exception):
    """The measurement itself is broken (not a candidate losing)."""


def log(message):
    print(message, file=sys.stderr, flush=True)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m22 = load_module("m22_002", HERE / "m22-002_ps2_c_output.py")
download_tool = load_module("m22_003_download_tool", TOOLS_DIR / "download_tool.py")


def run(argv, *, timeout=600, env=None, cwd=None, shell=False):
    started = time.monotonic()
    try:
        result = subprocess.run(argv if shell else [str(a) for a in argv], capture_output=True, text=True, timeout=timeout,
                                env=env, cwd=cwd, shell=shell, errors="replace")
        code, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code, out, err = -9, error.stdout or "", f"timeout after {timeout}s"
        out = out.decode(errors="replace") if isinstance(out, bytes) else out
    except OSError as error:
        code, out, err = 127, "", f"cannot run: {error}"
    return {"exit": code, "stdout": out, "stderr": err, "seconds": round(time.monotonic() - started, 3),
            "argv": argv if isinstance(argv, str) else [str(a) for a in argv]}


def sha256_file(path):
    return download_tool.sha256_file(path)


def expand(path):
    return Path(os.path.expanduser(str(path)))


# ---------------------------------------------------------------------------
# Descriptor
# ---------------------------------------------------------------------------

def load_descriptor(lane):
    path = LANE_DIR / f"{lane}.json"
    if not path.is_file():
        known = sorted(p.stem for p in LANE_DIR.glob("*.json"))
        raise HarnessError(f"no descriptor {path} (lanes: {', '.join(known)})")
    desc = json.loads(path.read_text())
    desc.setdefault("lane", lane)
    return desc


class Lane:
    """A descriptor plus where everything lives for this run."""

    def __init__(self, desc, args):
        self.desc, self.args = desc, args
        self.name = desc["lane"]
        self.work = (args.work or DEFAULT_ROOT / "work") / self.name
        self.work.mkdir(parents=True, exist_ok=True)
        self.tools_cache = args.tools_cache
        self.repo = expand(args.repo) if args.repo else self.work / "repo"
        self.retail = expand(args.retail or desc["retail"]["path"])
        self.tools = {}
        self.family = desc["build"].get("family", "gcc")
        self.python = sys.executable
        self.context_repair = None
        self.repair_log = []
        store = self.work / "context-repairs.json"
        self.repairs = json.loads(store.read_text()) if store.exists() else {}

    # placeholder expansion for descriptor strings
    def fmt(self, text):
        def sub(match):
            key = match.group(1)
            if key.startswith("tool:"):
                return str(self.tools[key[5:]])
            return {"repo": str(self.repo), "work": str(self.work), "tools": str(self.tools_cache), "retail": str(self.retail),
                    "python": str(self.python), "glibc32": str(args_glibc(self.args)), "home": str(HOME),
                    "jobs": str(self.args.jobs), "lane_tools": str(LANE_DIR / "tools")}[key]
        return re.sub(r"\{([a-z0-9:_.\-+]+)\}", sub, text)

    def env(self):
        env = dict(os.environ)
        path = [str(Path(self.python).parent)]
        for tool_id, install in self.tools.items():
            for sub in ("bin", ""):
                if (install / sub).is_dir():
                    path.append(str(install / sub))
        env["PATH"] = os.pathsep.join(path + [env.get("PATH", "")])
        if str(self.python) != sys.executable:
            env["VIRTUAL_ENV"] = str(Path(self.python).parent.parent)
        env.update({k: self.fmt(v) for k, v in self.desc.get("env", {}).items()})
        return env


def args_glibc(args):
    return args.glibc32


# ---------------------------------------------------------------------------
# Provisioning: tools, loader, repo, setup
# ---------------------------------------------------------------------------

def provision_tools(lane):
    manifest = download_tool.load_manifest(MANIFEST)
    cache = lane.tools_cache
    cache.mkdir(parents=True, exist_ok=True)
    out = {}
    for tool_id in lane.desc.get("tools", []):
        if tool_id not in manifest:
            raise HarnessError(f"{tool_id}: not in {MANIFEST}")
        out[tool_id] = download_tool.install(manifest[tool_id], cache, cache / ".cache")
    lane.tools = out
    return {tool_id: {"dir": str(path), "sha256": next(iter(manifest[tool_id]["assets"].values()))["sha256"]}
            for tool_id, path in out.items()}


def ensure_venv(lane):
    """A per-lane virtualenv for the repo's own python requirements (the repos pin different splat releases)."""
    spec = lane.desc.get("venv")
    if not spec:
        return None
    venv = lane.work / "venv"
    requirements = expand(lane.fmt(spec["requirements"])) if spec.get("requirements") else None
    key = hashlib.sha256(((requirements.read_text() if requirements else "") + json.dumps(spec.get("extra", []))).encode()).hexdigest()
    stamp = venv / ".m22-003"
    if not (stamp.exists() and stamp.read_text() == key):
        log(f"creating the lane virtualenv {venv}")
        shutil.rmtree(venv, ignore_errors=True)
        for argv in ([sys.executable, "-m", "venv", venv],
                     [venv / "bin" / "python", "-m", "pip", "install", "-q", *(["-r", requirements] if requirements else []), *spec.get("extra", [])]):
            result = run(argv, timeout=1800)
            if result["exit"] != 0:
                raise HarnessError(f"{' '.join(map(str, argv))} failed: {result['stderr'][-500:]}")
        stamp.write_text(key)
    lane.python = venv / "bin" / "python"
    return str(lane.python)


def reexec_if_needed(lane_desc, args):
    """ee-gcc 2.9x drivers are i386 ELFs with the fixed interpreter /lib/ld-linux.so.2, and ee-gcc's output can
    depend on its heap layout. When the descriptor says so, re-run this process with ASLR off and, where the host has
    no 32-bit loader, inside a bubblewrap mount namespace that supplies the user's glibc32 at that path (nothing on
    the host is written)."""
    if os.environ.get(SANDBOX_MARK):
        return
    argv = [sys.executable, *sys.argv]
    wrap = []
    if lane_desc.get("no_aslr") and shutil.which("setarch"):
        wrap = ["setarch", os.uname().machine, "-R"]
    if lane_desc.get("i386_loader") and not Path("/lib/ld-linux.so.2").exists():
        loader = args.glibc32 / "ld-linux.so.2"
        if not shutil.which("bwrap"):
            raise HarnessError("this lane needs /lib/ld-linux.so.2 or bwrap (bubblewrap) to provide it")
        if not loader.is_file():
            raise HarnessError(f"32-bit loader missing: {loader} (--glibc32)")
        lib = os.path.realpath("/lib")
        wrap += ["bwrap", "--dev-bind", "/", "/", "--overlay-src", lib, "--tmp-overlay", lib,
                 "--bind", str(loader), f"{lib}/ld-linux.so.2"]
    if not wrap:
        return
    os.environ[SANDBOX_MARK] = "1"
    os.execvp(wrap[0], [*wrap, *argv])


def ensure_repo(lane):
    spec = lane.desc["repo"]
    repo = lane.repo
    if not (repo / ".git").exists():
        log(f"cloning {spec['url']} into {repo}")
        result = run(["git", "clone", "--quiet", spec["url"], repo], timeout=1800)
        if result["exit"] != 0:
            raise HarnessError(f"git clone failed: {result['stderr'][-500:]}")
    head = run(["git", "-C", repo, "rev-parse", "HEAD"])["stdout"].strip()
    if head != spec["commit"]:
        if lane.args.repo:
            raise HarnessError(f"{repo} is at {head}, not the pinned {spec['commit']}")
        result = run(["git", "-C", repo, "checkout", "--quiet", "--detach", spec["commit"]])
        if result["exit"] != 0:
            raise HarnessError(f"git checkout {spec['commit']} failed: {result['stderr'][-500:]}")
    return head


def check_retail(lane):
    sha1 = lane.desc["retail"].get("sha1")
    if not lane.retail.is_file():
        raise HarnessError(f"retail image missing: {lane.retail} (--retail)")
    actual = hashlib.sha1(lane.retail.read_bytes()).hexdigest()
    if sha1 and actual != sha1:
        raise HarnessError(f"retail image sha1 {actual} is not {sha1}")
    return actual


def run_setup(lane, tool_record):
    """The descriptor's setup steps, once per (commit, steps, tool pins). A step that fails stops the lane with the
    missing prerequisite."""
    steps = lane.desc.get("setup", [])
    key = hashlib.sha256(json.dumps([lane.desc["repo"]["commit"], steps, tool_record, lane.desc.get("env")],
                                    sort_keys=True).encode()).hexdigest()
    stamp = lane.work / "setup.stamp"
    if stamp.exists() and stamp.read_text() == key and not lane.args.redo_setup:
        return {"cached": True}
    records = []
    for step in steps:
        command = lane.fmt(step) if isinstance(step, str) else lane.fmt(step["run"])
        log(f"setup: {command[:140]}")
        result = run(["bash", "-e", "-c", command], cwd=lane.repo, env=lane.env(), timeout=7200)
        records.append({"command": command, "exit": result["exit"], "seconds": result["seconds"],
                        "tail": (result["stdout"] + result["stderr"])[-400:]})
        if result["exit"] != 0:
            raise HarnessError(f"setup step failed ({command[:100]}): {(result['stdout'] + result['stderr'])[-800:]}")
    stamp.write_text(key)
    return {"cached": False, "steps": records}


# ---------------------------------------------------------------------------
# Units: the repo's own compile commands
# ---------------------------------------------------------------------------

class Unit:
    """One compile edge of the repo's build. `file`/`output` are as the command sees them (relative to `directory`);
    `src`/`out` are the same paths relative to the repo root."""

    def __init__(self, file, output, command, directory, repo, script=False):
        self.file, self.output, self.command, self.directory = file, output, command, directory
        self.script = script  # a multi-line recipe (make): never split into `&&` segments
        self.src = os.path.relpath(os.path.normpath(directory / file), repo)
        self.out = os.path.relpath(os.path.normpath(directory / output), repo)
        self.object = repo / self.out  # where the baseline object lives (trace lanes: replaced by build_units)

    def segments(self, drop):
        if self.script:
            return [self.command]
        parts = [part.strip() for part in self.command.split(" && ")]
        return [part for part in parts if not any(re.search(pattern, part) for pattern in drop)]


def unit_commands(lane):
    build = lane.desc["build"]
    if build["kind"] == "trace":
        return traced_commands(lane)
    if build["kind"] == "make":
        return make_commands(lane)
    directory = lane.repo / build.get("dir", ".")
    if build["kind"] != "ninja":
        raise HarnessError(f"unknown build kind {build['kind']!r}")
    result = run(["ninja", "-C", directory, "-t", "compdb", *build.get("compdb_rules", [])], env=lane.env(), timeout=600)
    if result["exit"] != 0:
        raise HarnessError(f"ninja -t compdb failed: {result['stderr'][-500:]}")
    keep, skip = re.compile(build.get("output_regex", ".")), re.compile(build["exclude_regex"]) if build.get("exclude_regex") else None
    only_commands = re.compile(build["command_regex"]) if build.get("command_regex") else None
    units, seen = [], set()
    for entry in json.loads(result["stdout"]):
        if not keep.search(entry["output"]) or (skip and skip.search(entry["output"])) or entry["output"] in seen:
            continue
        if only_commands and not only_commands.search(entry["command"]):
            continue
        if not re.search(r"\.(c|cc|cpp)$", entry["file"]):  # not compiled from C: an object copied or converted from retail
            continue
        seen.add(entry["output"])
        units.append(Unit(entry["file"], entry["output"], entry["command"], Path(entry["directory"]), lane.repo))
    return units


def make_commands(lane):
    """Unit commands of a make build: the descriptor lists the object targets (`objects_command`, one per line), and
    `make -n -B` prints each target's recipe as the repo's own Makefile expands it. The recipe is the unit's command
    (a multi-line script: compiler, the repo's rewriting steps, assembler); `source` maps a target to its source file."""
    build = lane.desc["build"]
    env = lane.env()
    listing = run(["bash", "-c", lane.fmt(build["objects_command"])], cwd=lane.repo, env=env, timeout=300)
    if listing["exit"] != 0:
        raise HarnessError(f"objects_command failed: {listing['stderr'][-300:]}")
    makefile = build.get("makefile", "Makefile")
    units = []
    for target in sorted(set(listing["stdout"].split())):
        source = next((re.sub(pattern, replacement, target) for pattern, replacement in build["source"]
                       if re.search(pattern, target)), None)
        if source is None or not (lane.repo / source).is_file():
            continue
        result = run(["make", "-n", "-B", "-f", makefile, target], cwd=lane.repo, env=env, timeout=300)
        lines = [line for line in result["stdout"].splitlines() if line.strip() and not line.startswith(("make:", "make["))]
        if result["exit"] != 0 or not lines:
            continue
        units.append(Unit(source, target, "set -e\n" + "\n".join(lines), lane.repo, lane.repo, script=True))
    return units


def traced_commands(lane):
    """Unit commands of a build with no dry-run mode (a python script): the repo's own build is run once with
    tests/m22-003/tools/trace/sitecustomize.py recording every subprocess it spawns; the compile commands are the recorded
    ones matching the descriptor's regex."""
    build = lane.desc["build"]
    log_path = Path(lane.fmt(build["trace_log"])) if build.get("trace_log") else lane.work / "build-trace.jsonl"
    if build.get("trace_run") is None and not log_path.exists():
        raise HarnessError(f"{log_path} is missing: run the lane that records the shared build trace first")
    if build.get("trace_run") is not None and (not log_path.exists() or lane.args.rebuild):
        log_path.unlink(missing_ok=True)
        env = lane.env()
        env["M22_003_TRACE"] = str(log_path)
        env["PYTHONPATH"] = os.pathsep.join([str(LANE_DIR / "tools" / "trace"), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
        log(f"running the repo's own build once to record its compile commands: {build['trace_run']}")
        result = run(["bash", "-c", lane.fmt(build["trace_run"])], cwd=lane.repo, env=env, timeout=7200)
        if not log_path.exists():
            raise HarnessError(f"the traced build recorded nothing: {(result['stdout'] + result['stderr'])[-600:]}")
    keep = re.compile(build["command_regex"])
    units, seen = [], set()
    for line in log_path.read_text().splitlines():
        row = json.loads(line)
        argv = row["argv"]
        text = " ".join(argv)
        if row["shell"] or not keep.search(text):
            continue
        source = next((a for a in argv if re.search(r"\.(c|cpp)$", a)), None)
        output = next((a for a in argv if a.endswith(".o")), None)
        if source is None or output is None:
            continue
        key = os.path.normpath(os.path.join(row["cwd"], output))
        if key in seen:
            continue
        seen.add(key)
        command = shlex.join(argv)
        if os.path.relpath(key, lane.repo).startswith(".."):
            # the build compiled into a temporary directory: the replay writes under the repo's build/ instead
            moved = str(lane.repo / "build" / "m22-003-trace" / (hashlib.sha1(key.encode()).hexdigest()[:12] + ".o"))
            argv = [moved if os.path.normpath(os.path.join(row["cwd"], a)) == key else a for a in argv]
            command, output = shlex.join(argv), moved
        units.append(Unit(source, output, command, Path(row["cwd"]), lane.repo))
    return units


def build_units(lane, units):
    """The repo's own build of every unit object (so INCLUDE_ASM dependencies get generated too)."""
    build = lane.desc["build"]
    if build["kind"] in ("trace", "make"):
        return replay_units(lane, units)
    directory = lane.repo / build.get("dir", ".")
    outputs = [u.output for u in units]
    if lane.args.rebuild:
        for output in outputs:
            for suffix in ("", ".s", ".proof.json"):
                (directory / (output + suffix)).unlink(missing_ok=True)
    todo = [o for o in outputs if not (directory / o).exists()]
    done = lane.work / "build.done"  # units that fail to build are not retried on every run
    if todo and done.exists() and done.read_text() == str(len(outputs)) and not lane.args.rebuild:
        todo = []
    record = {"units": len(units), "built_now": len(todo)}
    if todo:
        log(f"building {len(todo)} unit objects with the repo's own commands")
        failed = []
        for start in range(0, len(todo), 400):
            result = run(["ninja", "-C", directory, f"-j{lane.args.jobs}", "-k", "0", *todo[start:start + 400]],
                         env=lane.env(), timeout=build.get("timeout", 7200))
            failed.append((result["stdout"] + result["stderr"])[-2000:] if result["exit"] != 0 else "")
        record["ninja_tail"] = [text for text in failed if text][:2]
        done.write_text(str(len(outputs)))
    missing = [o for o in outputs if not (directory / o).exists()]
    record["objects"] = len(outputs) - len(missing)
    record["missing_objects"] = missing[:50]
    return record


def replay_units(lane, units):
    """Replay each traced command in its own overlay of the repo (the recorded command, the pinned compiler, the unmodified
    source) and keep the object under <work>/objects/."""
    objects = lane.work / "objects"
    objects.mkdir(exist_ok=True)

    def one(unit):
        target = objects / (hashlib.sha1(unit.out.encode()).hexdigest()[:16] + ".o")
        unit.object = target
        if target.exists() and not lane.args.rebuild:
            return None
        root = lane.work / "replay" / target.stem
        output, errors, record, text = compile_candidate(lane, unit, None, root, "u")
        if output is None:
            return unit.src, (errors or [text[-300:]])[0]
        shutil.copyfile(output, target)
        shutil.rmtree(root, ignore_errors=True)
        return None

    log(f"replaying {len(units)} traced compile commands")
    with concurrent.futures.ThreadPoolExecutor(max_workers=lane.args.jobs) as pool:
        failures = [f for f in pool.map(one, units) if f]
    missing = [u.src for u in units if not u.object.exists()]
    return {"units": len(units), "objects": len(units) - len(missing), "missing_objects": missing[:50],
            "replay_failures": failures[:20], "replay": True}


# ---------------------------------------------------------------------------
# Names and addresses
# ---------------------------------------------------------------------------

SPLAT_SYMBOL = re.compile(r"\s*([A-Za-z_][\w.$]*)\s*=\s*(0x[0-9A-Fa-f]+)\s*;(.*)$")


def load_symbols(lane):
    """{name: (address, kind)} from the descriptor's symbol sources: truth TSV (start,size,name), splat
    symbol_addrs files, the retail ELF's own symbol table."""
    names, ambiguous, every = {}, set(), {}

    def add(name, address, kind, size=None):
        every.setdefault(name, {}).setdefault(address, (address, kind, size))
        if name in names and names[name][0] != address:
            ambiguous.add(name)
        names.setdefault(name, (address, kind, size))

    for source in lane.desc.get("symbols", []):
        path = expand(lane.fmt(source["path"]))
        if not path.is_file():
            raise HarnessError(f"symbol source missing: {path}")
        kind = source["kind"]
        if kind == "truth_tsv":
            for line in path.read_text().splitlines()[1:]:
                cols = line.split("\t")
                if len(cols) >= 3 and cols[0].startswith("0x"):
                    add(cols[2], int(cols[0], 16), "func", int(cols[1]))
        elif kind == "splat":
            for line in path.read_text().splitlines():
                found = SPLAT_SYMBOL.match(line)
                if found:
                    meta = found.group(3)
                    typed = re.search(r"type:(\w+)", meta)
                    size = re.search(r"size:(0x[0-9A-Fa-f]+|\d+)", meta)
                    add(found.group(1), int(found.group(2), 16), typed.group(1) if typed else None,
                        int(size.group(1), 0) if size else None)
        elif kind == "elf_symtab":
            obj = elfobj.ElfObject(path.read_bytes())
            for symbol in obj.symbols:
                if symbol["name"] and symbol["shndx"] and symbol["info"] & 0xF in (1, 2):
                    add(symbol["name"], symbol["value"], "func" if symbol["info"] & 0xF == 2 else "data", symbol["size"])
        else:
            raise HarnessError(f"unknown symbol source kind {kind}")
    for name in ambiguous:
        names.pop(name, None)
    load_symbols.every = every  # all addresses a name was given (statics repeat across units)
    return names, ambiguous


def one_name_per_address(names, preferred=None):
    """{name: (address, kind, size)} reduced to one name per address (splat refuses two names for one address; the
    importer takes one): the preferred name of the address, else a real name over a func_<addr> placeholder."""
    preferred = preferred or {}
    best = {}
    for name, (address, kind, size) in sorted(names.items()):
        rank = (0 if preferred.get(address) == name else 1, 1 if re.fullmatch(r"(func|D|jtbl|L)_?[0-9A-Fa-f]{6,8}", name) else 0, name)
        if address not in best or rank < best[address][0]:
            best[address] = (rank, name, (address, kind, size))
    return {name: value for _rank, name, value in best.values()}


def find_by_content(image, body, relocations):
    """Retail addresses where `body` matches modulo relocation fields (longest unmasked run as the needle)."""
    masked = bytearray(len(body))
    for reloc in relocations:
        for byte in range(4):
            if reloc["offset"] + byte < len(masked):
                masked[reloc["offset"] + byte] = 1
    best, run_start = (0, 0), None
    for index in range(len(body) + 1):
        if index < len(body) and not masked[index]:
            run_start = index if run_start is None else run_start
        elif run_start is not None:
            best = max(best, (index - run_start, run_start))
            run_start = None
    length, start = best
    if length < 8:
        return []
    needle = body[start:start + length]
    found = []
    for vaddr, filesz, offset in image.code_segments():
        blob = image.data[offset:offset + filesz]
        position = blob.find(needle)
        while position >= 0:
            address = vaddr + position - start
            if address >= vaddr and not (address & 3):
                try:
                    if elfobj.compare(body, relocations, image.bytes_at(address, len(body))) == 0:
                        found.append(address)
                except KeyError:
                    pass
            position = blob.find(needle, position + 1)
    return found


# ---------------------------------------------------------------------------
# Matched functions
# ---------------------------------------------------------------------------

def include_asm_names(source, patterns):
    names = set()
    for pattern in patterns:
        for found in re.finditer(pattern, source):
            names.add(found.group(1))
    return names


def jal_target(word, address):
    return ((address + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)


def collect_matched(lane, units, image, names):
    patterns = lane.desc.get("include_asm_regex", [r"\bINCLUDE_ASM\s*\([^()]*?,\s*(\w+)\s*\)"])
    matched, stats = [], {"objects": 0, "c_functions": 0, "included_asm": 0, "matched": 0, "mismatch": 0, "no_address": 0,
                          "ambiguous_address": 0, "unparsable_objects": 0, "found_by_content": 0}
    mismatched, pending = [], []

    def record(unit, obj, name, shndx, value, size, address, how):
        body, relocations = obj.function_at(shndx, value, size)
        stats["matched"] += 1
        retail = image.bytes_at(address, size)
        rel_rows = []
        for reloc in relocations:
            row = {k: reloc[k] for k in ("offset", "r_type", "symbol")}
            word = int.from_bytes(retail[reloc["offset"]:reloc["offset"] + 4], "little")
            if reloc["r_type"] == elfobj.R_MIPS_26:
                row["retail_target"] = f"{jal_target(word, address + reloc['offset']):x}"
            if reloc["r_type"] == elfobj.R_MIPS_GPREL16:
                row["addend"] = f"{reloc['word'] & 0xFFFF:x}"
            rel_rows.append(row)
        matched.append({"name": name, "address": address, "size": size, "file": unit.src, "output": unit.out,
                        "found_by": how, "relocations": rel_rows, "e_flags": obj.e_flags, "section": shndx, "offset": value})

    for unit in units:
        path = unit.object
        source_path = lane.repo / unit.src
        if not path.exists() or not source_path.exists():
            continue
        try:
            obj = elfobj.ElfObject(path.read_bytes())
        except (elfobj.ElfError, struct_error):
            stats["unparsable_objects"] += 1
            continue
        stats["objects"] += 1
        source = source_path.read_text(errors="replace")
        skip = include_asm_names(source, patterns)
        for name, shndx, value, size in obj.functions():
            if name in skip:
                stats["included_asm"] += 1
                continue
            stats["c_functions"] += 1
            body, relocations = obj.function_at(shndx, value, size)
            address, how = None, "name"
            hit = names.get(name)
            for candidate in sorted(load_symbols.every.get(name, {}).values()) if hit or name in load_symbols.every else []:
                try:
                    if elfobj.compare(body, relocations, image.bytes_at(candidate[0], size)) == 0:
                        address, hit = candidate[0], candidate
                        break
                except KeyError:
                    pass
            if address is None:
                hits = find_by_content(image, body, relocations)
                if len(hits) == 1:
                    address, how = hits[0], "content"
                    stats["found_by_content"] += 1
                elif len(hits) > 1:
                    pending.append((unit, name, shndx, value, size, hits))
                    continue
                else:
                    stats["mismatch" if hit else "no_address"] += 1
                    mismatched.append(name)
                    continue
            record(unit, obj, name, shndx, value, size, address, how)
    # identical bodies at several retail addresses: a unit lays its functions out in order, so the nearest resolved
    # neighbours (before and after, by offset in the object) bound where the function can be
    order = {}
    for row in matched:
        order.setdefault(row["file"], []).append((row["section"], row["offset"], row["address"], row["size"]))
    progress = True
    while pending and progress:
        progress = False
        for item in list(pending):
            unit, name, shndx, value, size, hits = item
            rows = order.get(unit.src, [])
            before = max(((o, a, z) for sec, o, a, z in rows if sec == shndx and o < value), default=None)
            after = min(((o, a, z) for sec, o, a, z in rows if sec == shndx and o > value), default=None)
            low = before[1] + before[2] if before else 0
            high = after[1] if after else 1 << 32
            inside = [a for a in hits if low <= a and a + size <= high]
            if len(inside) == 1:
                obj = elfobj.ElfObject(unit.object.read_bytes())
                record(unit, obj, name, shndx, value, size, inside[0], "content-between-neighbours")
                order.setdefault(unit.src, []).append((shndx, value, inside[0], size))
                stats["found_by_content"] += 1
                pending.remove(item)
                progress = True
    # adjacent identical functions (same body, same candidate addresses): assigned in object order
    groups = {}
    for item in pending:
        groups.setdefault((item[0].src, item[2], tuple(item[5])), []).append(item)
    for (_src, _shndx, hits), items in groups.items():
        items.sort(key=lambda item: item[3])
        if len(items) == len(hits):
            for item, address in zip(items, sorted(hits)):
                unit, name, shndx, value, size, _hits = item
                record(unit, elfobj.ElfObject(unit.object.read_bytes()), name, shndx, value, size, address, "content-identical-run")
                stats["found_by_content"] += 1
                pending.remove(item)
    # last resort: the one candidate inside the unit's resolved address span (+-0x400)
    spans = {}
    for row in matched:
        low, high = spans.get(row["file"], (row["address"], row["address"] + row["size"]))
        spans[row["file"]] = (min(low, row["address"]), max(high, row["address"] + row["size"]))
    for item in list(pending):
        unit, name, shndx, value, size, hits = item
        low, high = spans.get(unit.src, (0, 0))
        inside = [a for a in hits if low - 0x400 <= a <= high + 0x400]
        if len(inside) == 1:
            record(unit, elfobj.ElfObject(unit.object.read_bytes()), name, shndx, value, size, inside[0], "content-in-unit-span")
            stats["found_by_content"] += 1
            pending.remove(item)
    stats["ambiguous_address"] += len(pending)
    stats["mismatched_names_sample"] = mismatched[:20]
    return matched, stats


try:  # struct.error without importing struct at module top for one use
    from struct import error as struct_error
except ImportError:  # pragma: no cover
    struct_error = ValueError


# ---------------------------------------------------------------------------
# Preprocessing a unit and building the shared context
# ---------------------------------------------------------------------------

def compile_segment(lane, unit):
    drop = lane.desc["build"].get("drop_segments", [])
    segments = unit.segments(drop)
    for segment in segments:
        if unit.file in segment:
            return segment
    return segments[0] if segments else unit.command


def preprocess_command(lane, unit):
    """The unit's preprocess command, derived from its own compile command."""
    spec = lane.desc["build"].get("preprocess", {"mode": "driver-E"})
    segment = compile_segment(lane, unit)
    tokens = shlex.split(segment)
    extra = [lane.fmt(x) for x in spec.get("defines", [])]
    if spec["mode"] == "host-cpp":
        keep = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if re.match(r"-[DUI]", token) or token in ("-nostdinc",):
                keep.append(token)
                if token in ("-D", "-U", "-I") and index + 1 < len(tokens):
                    keep.append(tokens[index + 1])
                    index += 1
            elif token in ("-include", "-isystem", "-iquote") and index + 1 < len(tokens):
                keep += [token, tokens[index + 1]]
                index += 1
            index += 1
        return ["cpp", "-E", "-undef", "-P", *keep, *extra, unit.file]
    if spec["mode"] == "driver-E":
        out, index = [], 0
        while index < len(tokens):
            token = tokens[index]
            if token in ("-c", "-S"):
                pass
            elif token == "-o":
                index += 1
            elif token.startswith("-MF") or token in ("-MD", "-MMD", "-MP"):
                if token in ("-MF", "-MT"):
                    index += 1
            else:
                out.append(token)
            index += 1
        return [*out[:1], "-E", *extra, *out[1:]]
    if spec["mode"] == "flags":
        # the preprocessor is named by the descriptor; the flags that matter to it are harvested from the unit's own command
        keep, index = [], 0
        while index < len(tokens):
            token = tokens[index]
            if re.match(r"-[DUI]", token):
                keep.append(token)
                if token in ("-D", "-U", "-I") and index + 1 < len(tokens):
                    keep.append(tokens[index + 1])
                    index += 1
            index += 1
        tool = spec["tool"] if isinstance(spec["tool"], list) else [spec["tool"]]
        return [*[lane.fmt(t) for t in tool], "-E", *[lane.fmt(x) for x in spec.get("flags", [])], *keep, *extra, unit.file]
    if spec["mode"] == "mwccgap-E":
        # tools/mwccgap's command line: SRC OUT then its own options, then the compiler's flags; the compiler is --mwcc-path
        own = {"--mwcc-path", "--asm-dir-prefix", "--symbol-map", "--macro-inc-path", "--as-march", "--as-mabi", "--as-path",
               "--target-encoding", "--c-file-encoding", "--gas-path", "--wibo-path", "--as-flags"}
        compiler, flags, index, positional = None, [], 0, 0
        while index < len(tokens):
            token = tokens[index]
            if token == "--mwcc-path":
                compiler = tokens[index + 1]
                index += 2
            elif token in own:
                index += 2
            elif token.endswith("mwccgap.py") or token.endswith("python") or token.endswith("python3"):
                index += 1
            elif positional < 2 and not token.startswith("-"):
                positional += 1
                index += 1
            else:
                flags.append(token)
                index += 1
        return [*([] if compiler.endswith(".sh") else ["wibo"]), compiler, "-E", *flags, *extra, unit.file]
    raise HarnessError(f"unknown preprocess mode {spec['mode']}")


class UnitCache:
    """Preprocessed units for context building, one preprocess per unit file."""

    def __init__(self, lane, units):
        self.lane = lane
        self.by_file = {u.src: u for u in units}
        self.cache = {}

    def get(self, file):
        if file in self.cache:
            return self.cache[file]
        unit = self.by_file[file]
        argv = preprocess_command(self.lane, unit)
        env = self.lane.env()
        result = run(argv, cwd=unit.directory, env=env, timeout=300)
        text = re.sub(r"(?m)^# \d+ .*$", "", result["stdout"])
        text = re.sub(r"/\* #line [^\n]*\*/", "", text)
        for pattern in self.lane.desc["build"].get("preprocess", {}).get("strip", []):  # e.g. a section attribute before every name
            text = re.sub(pattern, "", text)
        if result["exit"] != 0 or not text.strip():
            self.cache[file] = (None, (result["stderr"] + result["stdout"])[-300:])
            return self.cache[file]
        source = (self.lane.repo / file).read_text(errors="replace")
        self.cache[file] = ({"chunks": m22.split_chunks(text), "source": source, "path": self.lane.repo / file,
                             "compiler": argv[0], "flags": argv[1:]}, None)
        return self.cache[file]


def definition_line(source, name):
    for found in re.finditer(r"(?m)^[^\n;]*\b" + re.escape(name) + r"\s*\(", source):
        return source.count("\n", 0, found.start()) + 1
    return 1


def full_context(unit, name):
    """The unit's declarations with no type erasure (m22-002's declaration_text only): what the original text of the function
    compiles against. Used by the `oracle` layer, a check of the compile-and-score pipeline."""
    lines, seen = [], set()
    for chunk in unit["chunks"]:
        if chunk["kind"] == "pp":
            continue
        text = m22.declaration_text(chunk)
        if text is None or text in seen or (chunk["kind"] == "funcdef" and chunk.get("name") == name):
            continue
        seen.add(text)
        lines.append(text)
    return "\n".join(lines) + "\n"


def shared_context(lane):
    """(context text, prototypes) from the lane's one context file (C++ lanes: the repo's own C-compatible m2c context, which
    flattens classes to structs), reduced as m22-002 reduces a unit: typedefs, tag definitions, externs and prototypes kept,
    data definitions turned into externs."""
    spec = lane.desc["shared_context"]
    text = (lane.repo / lane.fmt(spec["file"])).read_text(errors="replace")
    lines, protos, seen, typedefs = [], {}, set(), {}
    for chunk in m22.split_chunks(text):
        if chunk["kind"] == "pp":
            continue
        decl = m22.declaration_text(chunk)
        if decl is None:
            continue
        masked = m22.squash(chunk["masked"])
        if masked.startswith("typedef"):
            m22.update_typedefs(typedefs, masked)
        else:
            proto = m22.prototype_of(chunk) if "=" not in chunk["masked"].split("{")[0] else None
            if proto:
                proto = m22.erase_prototype(proto, typedefs)
                if proto[2] in protos:  # an overload flattened by the C-compatible context: the first declaration stands
                    continue
                protos[proto[2]] = proto
                decl = f"{proto[0]} {proto[2]}({proto[1]});"
            else:
                decl = m22.erase_extern(decl, typedefs)
                found = re.match(r"extern\b[^;=()]*?\b(\w+)\s*(?:\[[^\]]*\]\s*)*;$", decl)
                if found:
                    if ("var", found.group(1)) in seen:
                        continue
                    seen.add(("var", found.group(1)))
        if decl in seen:
            continue
        seen.add(decl)
        lines.append(decl)
    return "\n".join(lines) + "\n", protos


MWCC_ERROR_LINE = re.compile(r"^#\s+(\d+):\s", re.M)
GCC_ERROR_LINE = re.compile(r"^[^\n:]*:(\d+):(?>(?:\d+:)?\s*)(?!warning)", re.M)


def repair_text(lane, unit, text, rounds_limit=150):
    """Compile `text` (a context) alone with `unit`'s own command and drop every declaration the compiler's errors point at, until
    it compiles. A context is reduced from the preprocessed unit by m22-002's rule, and the reduction (or the repo's m2c-oriented
    context) can leave a declaration the unit's compiler rejects (an `extern` whose name is also a type, a typedef of a struct
    declared later, a SN header's `void * __asm__(" ")`): without this every candidate compiled against it fails whatever it says.
    -> (text, {rounds, dropped, ok, first_dropped})"""
    prefix = m22.missing_typedefs(text)
    lines = text.split("\n")
    offset = prefix.count("\n")
    dropped, ok, rounds = [], False, 0
    for rounds in range(1, rounds_limit + 1):
        source = prefix + "\n".join(lines) + "\nint m22_003_probe(int a) { return a + 1; }\n"
        output, _errors, _record, log_text = compile_candidate(lane, unit, source, lane.work / "repair", "r")
        if output is not None:
            ok = True
            break
        numbers = {int(n) - 1 - offset for n in MWCC_ERROR_LINE.findall(log_text) + GCC_ERROR_LINE.findall(log_text)}
        numbers = {n for n in numbers if 0 <= n < len(lines) and lines[n]}
        if not numbers:
            break
        for n in sorted(numbers):
            dropped.append(lines[n][:160])
            lines[n] = ""
    return "\n".join(lines), {"rounds": rounds, "dropped": len(dropped), "ok": ok, "first_dropped": dropped[:12], "context_lines": len(lines)}


def repair_context(lane, cache, text):
    """The shared context of a C++ lane (the repo's m2c-oriented ctx.c), repaired once against a representative unit."""
    spec = lane.desc["shared_context"]
    unit = next(iter(cache.by_file.values()))
    key = hashlib.sha256((text + unit.command + str(spec.get("repair_rounds", 150))).encode()).hexdigest()[:16]
    saved = lane.work / "context.repaired.json"
    if saved.exists() and not lane.args.resample:
        record = json.loads(saved.read_text())
        if record["key"] == key:
            return record["text"], record["repair"]
    repaired, record = repair_text(lane, unit, text, spec.get("repair_rounds", 150))
    saved.write_text(json.dumps({"key": key, "text": repaired, "repair": record}))
    return repaired, record


def repaired_unit_context(lane, cache, unit_file, text):
    """Per-unit contexts: repaired once per (unit, context text) and remembered across functions and runs."""
    if not lane.desc.get("context_repair", True) or not text.strip():
        return text
    unit = cache.by_file[unit_file]
    key = hashlib.sha1((unit_file + "\0" + text + "\0" + unit.command).encode()).hexdigest()
    store = lane.repairs
    if key not in store:
        store[key] = repair_text(lane, unit, text)
        (lane.work / "context-repairs.json").write_text(json.dumps(store))
    repaired, record = store[key]
    lane.repair_log.append(record)
    return repaired


def select_sample(lane, matched, cache, args, image):
    """The seeded sample: size window, a definition in the preprocessed unit, no inline asm, a context."""
    rows, seen_address = [], set()
    for r in sorted((r for r in matched if SIZE_MIN <= r["size"] <= SIZE_MAX), key=lambda r: (r["address"], r["file"], r["name"])):
        if r["address"] not in seen_address:  # one function compiled in two units (a promoted copy) is sampled once
            seen_address.add(r["address"])
            rows.append(r)
    order = list(range(len(rows)))
    random.Random(args.seed).shuffle(order)
    chosen, rejected = [], {}

    def reject(why):
        rejected[why] = rejected.get(why, 0) + 1

    gcc = lane.family == "gcc"
    only = set(args.only.split(",")) if args.only else None
    shared = shared_context(lane) if lane.desc.get("shared_context") else None
    if shared and lane.desc["shared_context"].get("repair"):
        text, lane.context_repair = repair_context(lane, cache, shared[0])
        shared = (text, shared[1])
        log(f"context repair: {lane.context_repair}")
    for index in order:
        if len(chosen) >= args.n and not only:
            break
        row = rows[index]
        if only and row["name"] not in only:
            continue
        if shared:  # C++ units: no per-unit preprocess; one context for every function, no own text to hand the oracle
            chosen.append(dict(row, line=1, context=shared[0], pragmas=[], protos=shared[1], oracle=None, context_full=None,
                               retail=image.bytes_at(row["address"], row["size"]).hex()))
            continue
        unit, why = cache.get(row["file"])
        if unit is None:
            reject("unit does not preprocess")
            continue
        line = definition_line(unit["source"], row["name"])
        built = m22.build_context(unit, row["name"], line)
        if built is None:
            reject("no definition in the preprocessed unit")
            continue
        context, pragmas, protos, chunk = built
        if re.search(r"\basm\b|__asm", chunk["body"]):
            reject("inline assembly in the body")
            continue
        context = repaired_unit_context(lane, cache, row["file"], context)
        chosen.append(dict(row, line=line, context=context, pragmas=[] if gcc else pragmas, protos=protos,
                           oracle=re.sub(r"^\s*(?:static\s+|inline\s+|__inline__\s+)+", "", chunk["text"]),
                           context_full=repaired_unit_context(lane, cache, row["file"], full_context(unit, row["name"])), retail=image.bytes_at(row["address"], row["size"]).hex()))
    chosen.sort(key=lambda r: r["address"])
    return chosen, rejected, len(rows)


# ---------------------------------------------------------------------------
# Candidate compile: the unit's own command, run in a scratch overlay of the repo
# ---------------------------------------------------------------------------

def overlay(root, repo, files, empty=()):
    """`root` mirrors `repo` with symlinks, except along `files` (relative paths): their directories are real
    directories in `root` holding symlinks to every sibling, and the files themselves are left for the caller. The
    directories in `empty` are real and hold nothing: a compiler writes its intermediates next to its output, and a
    sibling symlink would let it write through into the repo's own build."""
    empty = {Path(e) for e in empty}
    real_dirs, real_files = set(), {Path(f) for f in files}
    for name in files:
        path = Path(name).parent
        while True:
            real_dirs.add(path)
            if path == Path("."):
                break
            path = path.parent
    for directory in sorted(real_dirs, key=lambda p: len(p.parts)):
        (root / directory).mkdir(parents=True, exist_ok=True)
        source = repo / directory
        if not source.is_dir() or directory in empty:
            continue
        for entry in os.listdir(source):
            relative = directory / entry
            if relative in real_dirs or relative in real_files:
                continue
            link = root / relative
            if not (link.exists() or link.is_symlink()):
                link.symlink_to(source / entry)


# a gcc-style `file:line: message` that is not a warning (m22-002's pattern also took ` warning: ...` lines)
COMPILER_ERROR_LINE = re.compile(r"^[^\n:]*:\d+:(?>(?:\d+:)?\s*)(?!warning)([^\n]+)", re.M)


def compile_candidate(lane, unit, source_text, workdir, tag):
    """Compile `source_text` as the unit's source with the unit's own commands, run from a scratch overlay of the repo in
    which only the source file and the output directory are real. -> (object path or None, errors, record, log)"""
    root = workdir / f"root_{tag}"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    src = unit.src
    rewrite = lane.desc.get("candidate_source")
    if rewrite and src.endswith(rewrite["from"]):  # C++ lanes: the candidate is C, so it goes in a `.c` file
        src = src[:-len(rewrite["from"])] + rewrite["to"]
    overlay(root, lane.repo, [src, unit.out], empty=[os.path.dirname(unit.out)])
    if source_text is not None:
        (root / src).unlink(missing_ok=True)
        (root / src).write_text(source_text)
    else:
        (root / src).unlink(missing_ok=True)
        (root / src).symlink_to(lane.repo / src)
    (root / unit.out).parent.mkdir(parents=True, exist_ok=True)
    (root / unit.out).unlink(missing_ok=True)
    segments = unit.segments(lane.desc["build"].get("drop_segments", []))
    command = " && ".join(segments).replace(str(lane.repo), str(root))
    if source_text is not None:  # flags that describe the original unit's shape (a jump table it has), not the compile
        for pattern in lane.desc.get("candidate_drop_args", []):
            command = re.sub(pattern, "", command)
    if src != unit.src:  # the object name keeps the unit's extension: protect it while the source path is rewritten
        command = command.replace(unit.out, "\0OUT\0").replace(unit.src, src).replace("\0OUT\0", unit.out)
    cwd = root / os.path.relpath(unit.directory, lane.repo)
    result = run(["bash", "-c", command], cwd=cwd, env=lane.env(), timeout=300)
    text = result["stdout"] + result["stderr"]
    errors = m22.ERROR_LINE.findall(text) + COMPILER_ERROR_LINE.findall(text)
    output = root / unit.out
    record = {"exit": result["exit"], "seconds": result["seconds"]}
    return (output if result["exit"] == 0 and output.exists() else None), errors, record, text


def objdiff_percent(lane, name, retail, body, relocations, e_flags, directory, objdiff):
    target, base = directory / "target.o", directory / "base.o"
    target.write_bytes(elfobj.object_for_objdiff(retail, [], name, e_flags))
    base.write_bytes(elfobj.object_for_objdiff(body, relocations, name, e_flags))
    record = directory / "objdiff.json"
    record.unlink(missing_ok=True)
    result = run([objdiff, "diff", "-1", target, "-2", base, name, "--format", "json", "-o", record,
                  "-c", "functionRelocDiffs=none"], timeout=120)
    if result["exit"] == 0 and record.exists():
        for symbol in json.loads(record.read_text()).get("left", {}).get("symbols", []):
            if symbol.get("name") == name:
                return float(symbol.get("match_percent", 0.0)), None
    return 0.0, "objdiff failed: " + result["stderr"][-400:]


def score_object(lane, row, output, directory, objdiff):
    entry = {"symbol": False, "exact": False, "percent": 0.0}
    try:
        obj = elfobj.ElfObject(output.read_bytes())
        try:
            body, relocations = obj.function(row["name"])
        except KeyError:
            # MWCC renames a function whose name its unit already knows (`f__2`): the unit's build, not the candidate, did it
            renamed = [f for f in obj.functions() if re.fullmatch(re.escape(row["name"]) + r"__\d+", f[0])]
            if len(renamed) != 1:
                raise
            body, relocations = obj.function_at(renamed[0][1], renamed[0][2], renamed[0][3])
    except (KeyError, elfobj.ElfError, OSError, ValueError) as error:
        entry["error"] = f"no symbol {row['name']} in the object ({error})"
        return entry
    retail = bytes.fromhex(row["retail"])
    entry.update(symbol=True, size=len(body))
    differences = elfobj.compare(body, relocations, retail)
    entry["byte_differences"] = differences if len(body) == row["size"] else None
    entry["exact"] = len(body) == row["size"] and differences == 0
    mask = elfobj.field_mask(len(body), relocations)
    entry["body"], entry["mask"] = body.hex(), mask.hex()  # kept so the byte-difference classes can be recomputed without a compile
    if not entry["exact"]:
        entry["diff"] = classes.classify_diff(body, mask, retail)
    entry["percent"], error = objdiff_percent(lane, row["name"], retail, body, relocations, row.get("e_flags", obj.e_flags),
                                              directory, objdiff)
    if error:
        entry["error"] = error
    return entry


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

def apply_aliases(lane, unit, source):
    """Type spellings the unit's compiler needs (SN ProDG's EE gcc has a 128-bit `long long`: its 64-bit type is `long`)."""
    for rule in lane.desc.get("candidate_type_aliases", []):
        if rule.get("command") and not re.search(rule["command"], unit.command):
            continue
        for pattern, replacement in rule["patterns"]:
            source = re.sub(pattern, replacement, source)
    return source


def score_candidate(lane, units_by_file, row, layer, text, context, pragmas, macros, extra_prelude, workdir, objdiff, drop_target=False):
    unit = units_by_file[row["file"]]
    ldir = workdir / layer
    ldir.mkdir(parents=True, exist_ok=True)
    variants = {}
    for variant in VARIANTS:
        vdir = ldir / variant
        vdir.mkdir(parents=True, exist_ok=True)
        entry = {"compiled": False, "produced": text is not None, "exact": False, "exact_symbols": False, "percent": 0.0}
        variants[variant] = entry
        if text is None:
            entry["error"] = "no candidate"
            entry["diagnostics"] = [{"message": "no candidate", "line": None, "source": None, "class": "no candidate produced"}]
            continue
        shown = row["context_full"] if layer == "oracle" and row.get("context_full") else context
        if layer in ("stock", "oracle") or drop_target:  # these print their own signature for the target
            shown = "\n".join(line for line in shown.splitlines()
                              if not re.search(r"\b" + re.escape(row["name"]) + r"\s*\(", line))
        source = apply_aliases(lane, unit, m22.compose(variant, shown, pragmas, macros, text, extra_prelude))
        (vdir / "candidate.c").write_text(source)
        output, errors, record, log_text = compile_candidate(lane, unit, source, vdir, "c")
        entry["compile_exit"], entry["seconds"] = record["exit"], record["seconds"]
        if output is None:
            entry["errors"] = errors[:5]
            entry["error"] = "; ".join(errors[:2]) or log_text[-300:].strip()
            entry["log_tail"] = log_text[-700:]
            entry["diagnostics"] = classes.parse_diagnostics(log_text, source, 3) or [
                {"message": next((l for l in log_text.splitlines() if "rror" in l), log_text.strip().splitlines()[-1] if log_text.strip() else "?")[:200],
                 "line": None, "source": None}]
            for item in entry["diagnostics"]:
                item.setdefault("class", classes.classify_message(item["message"]))
            continue
        scored = score_object(lane, row, output, vdir, objdiff)
        entry.update(scored)
        entry["compiled"] = scored["symbol"]
        if not scored["symbol"]:
            entry["diagnostics"] = [{"message": scored.get("error", "no symbol"), "line": None, "source": None,
                                     "class": "object lacks the target symbol"}]
        shutil.rmtree(vdir / "root_c", ignore_errors=True)
    parts = list(variants.values())
    variants["best"] = {key: (any(v[key] for v in parts) if key != "percent" else max(v[key] for v in parts))
                        for key in ("produced", "compiled", "exact", "exact_symbols", "percent")}
    return variants


def romwright_env(lane, args, extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_") or k == "ROMWRIGHT_GHIDRA"}
    env.update(ROMWRIGHT_GHIDRA_OPT=str(args.ghidra_opt), ROMWRIGHT_WORKER=str(args.worker), ROMWRIGHT_NO_IMPORT_CACHE="1",
               ROMWRIGHT_NO_FACT_PACK="1", ROMWRIGHT_GHIDRA=str(GHIDRA), TMPDIR=str(lane.work / "tmp"))
    env.update(extra)
    return env


def import_romwright(lane, args, env):
    project = lane.work / "project"
    program = lane.desc["program"]
    exists = (project / "project.sqlite").exists()
    if exists and args.fresh_import:
        shutil.rmtree(project)
        exists = False
    if exists:
        listing = run([args.cli, "programs", "--project", project], env=env, timeout=120)
        exists = listing["exit"] == 0 and program in listing["stdout"]
        if not exists:
            shutil.rmtree(project)
    record = {"project": str(project), "binary": str(lane.retail)}
    base = lane.work / "project.base"
    if exists and base.exists():
        # every run starts from the freshly imported project: asserted names and prototypes accumulate within a run (m22-002's
        # sequential assertion) but never leak from one run into the next, so runs under different --env are comparable
        shutil.rmtree(project)
        shutil.copytree(base, project, symlinks=True)
        record["import"] = {"reused": True, "from_snapshot": str(base)}
        return project, record
    if exists:
        shutil.copytree(project, base, symlinks=True)
        record["import"] = {"reused": True, "snapshot_taken": str(base)}
        return project, record
    log("importing the retail ELF into the romwright project")
    result = run([args.cli, "import", lane.retail, "--name", program, "--project", project], env=env, timeout=3600)
    record["import"] = {k: result[k] for k in ("argv", "exit", "seconds")}
    record["import"]["stderr_tail"] = result["stderr"][-1500:]
    if result["exit"] != 0 or "degraded" in result["stdout"] + result["stderr"]:
        raise HarnessError(f"romwright import failed or degraded: {(result['stdout'] + result['stderr'])[-600:]}")
    shutil.rmtree(base, ignore_errors=True)
    shutil.copytree(project, base, symlinks=True)
    return project, record


def romwright_names(lane, args, env, names):
    names = one_name_per_address(names)
    pairs = [{"function": f"{address:x}", "name": name}
             for name, (address, kind, _size) in sorted(names.items(), key=lambda kv: kv[1][0]) if kind == "func"]
    path = lane.work / "names.json"
    path.write_text(json.dumps(pairs))
    result = run([args.cli, "assert-names", lane.desc["program"], path, "--project", lane.work / "project"], env=env, timeout=900)
    return {"supplied": len(pairs), "exit": result["exit"], "stdout": result["stdout"].strip()[-300:],
            "stderr": result["stderr"][-500:]}


DEFINITION_HEAD = re.compile(r"(?m)^[^\n;{}()=]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\n?\{")


def rename_definition(text, name):
    """romwright prints a C++ symbol demangled (`ClsMes_SetHalfFontWPercent`); the unit's object defines the retail mangled
    symbol, so the function the text defines is renamed to the target's own name (m22-002 does the same for stock Ghidra's
    FUN_ names). -> (text, previous name or None)"""
    # preprocessor lines blanked too: a function-like macro (`#define romwright_subpiece_8_4_4(value, offset) (...)`) is not the definition
    masked = re.sub(r"(?m)^[ \t]*#[^\n]*$", lambda line: " " * len(line.group(0)), m22.mask_c(text))
    found = DEFINITION_HEAD.search(masked)  # comments blanked: a comment can mention the name and a `(`
    if not found or found.group(1) == name:
        return text, None
    old = found.group(1)
    return re.sub(r"\b" + re.escape(old) + r"\b", name, text), old


ARRAY_TYPEDEF = re.compile(r"typedef\s+([A-Za-z_][\w\s]*?)\s+(\w+)\s*(?:\[[^\]]*\]\s*)+(?:__attribute__\s*\(\(.*?\)\)\s*)?;")


class TypedefTable(dict):
    arrays: set

    def __init__(self, *args):
        super().__init__(*args)
        self.arrays = set()


def typedef_table_with_arrays(context):
    """m22-002's typedef table skips `typedef float sceVu0FVECTOR[4];`, so every prototype with such a parameter was left
    unasserted and romwright guessed the callee. A parameter of array type is a pointer to the element: record it so."""
    table = TypedefTable(m22.typedef_table(context))
    for found in ARRAY_TYPEDEF.finditer(m22.mask_c(context)):
        table.setdefault(found.group(2), found.group(1).strip() + " *")
        table.arrays.add(found.group(2))
    return table


def romwright_candidate(lane, args, env, row, fdir, context_path, typedefs, needed, names):
    program, project = lane.desc["program"], lane.work / "project"
    named = {row["address"]: row["name"]}
    for reloc in row["relocations"]:
        if reloc["r_type"] == elfobj.R_MIPS_26 and reloc.get("symbol") and reloc.get("retail_target"):
            named[int(reloc["retail_target"], 16)] = reloc["symbol"]
    by_name = {symbol: address for address, symbol in named.items()}
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "names.json").write_text(json.dumps([{"function": f"{a:x}", "name": n} for a, n in sorted(named.items())]))
    result = run([args.cli, "assert-names", program, fdir / "names.json", "--project", project], env=env, timeout=300)
    record = {"assert_names": {"supplied": len(named), "exit": result["exit"], "stderr": result["stderr"][-300:]}}
    asserted, notes = [], []
    for symbol in needed:
        proto = row["protos"].get(symbol)
        address = by_name.get(symbol) or (names[symbol][0] if symbol in names else None)
        if address is None and (found := re.fullmatch(r"func_([0-9A-Fa-f]{8})", symbol)):
            address = int(found.group(1), 16)
        if proto is None or address is None:
            continue
        signature, why = m22.asserted_signature(proto, typedefs)
        if signature is None:
            notes.append(f"{symbol}: not asserted ({why})")
            continue
        asserted.append({"function": f"{address:x}", "signature": signature})
    # an asserted `float *` head conflicts with a declared `float (*)[4]` (an array typedef parameter): the declaration is dropped as well
    target_proto = row["protos"].get(row["name"])
    array_head = bool(target_proto and getattr(typedefs, "arrays", None)
                      and any(re.search(rf"\b{re.escape(n)}\b", target_proto[1]) for n in typedefs.arrays))
    record.update(asserted=len(asserted), notes=notes,
                  target_asserted=not array_head and any(a["function"] == f"{row['address']:x}" for a in asserted))
    if asserted:
        path = fdir / "prototypes.json"
        path.write_text(json.dumps(asserted, indent=1))
        result = run([args.cli, "assert-prototypes", program, path, "--source", "m22-003 unit declarations",
                      "--project", project], env=env, timeout=300)
        record["assert_prototypes"] = {"exit": result["exit"], "stderr": result["stderr"][-500:]}
    outdir = fdir / "export"
    shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir()
    result = run([args.cli, "export-c", lane.retail, program, outdir, "--address", f"{row['address']:x}",
                  "--context", context_path, "--project", project], env=env, timeout=900)
    files = sorted(outdir.glob("*.c"))
    text = "\n".join(f.read_text(errors="replace") for f in files) if files else None
    record.update(argv=[str(a) for a in result["argv"]], exit=result["exit"], seconds=result["seconds"],
                  stderr=result["stderr"][-1500:])
    if text is not None and lane.desc.get("rename_target"):
        text, old = rename_definition(text, row["name"])
        record["renamed_from"] = old
    return text, record


# --- the near-miss search (docs/match.md): the same export under other printing switches -------------------------------
# The plan, the ranking and the search itself are tests/match_search_arm.py (shared with m22-002); this is the lane's export.

def variant_text(lane, args, env, row, fdir, context_path, words, tag):
    """The romwright export of one function with the printing switches `words` (`K=V` strings) set for the CLI process,
    renamed like the default candidate. The store is only read, so variants of one function run side by side."""
    program, project = lane.desc["program"], lane.work / "project"
    outdir = fdir / "search" / tag / "export"
    shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir(parents=True)
    variant_env = dict(env)
    variant_env.update(word.split("=", 1) for word in words)
    result = run([args.cli, "export-c", lane.retail, program, outdir, "--address", f"{row['address']:x}",
                  "--context", context_path, "--project", project], env=variant_env, timeout=900)
    files = sorted(outdir.glob("*.c"))
    text = "\n".join(f.read_text(errors="replace") for f in files) if files else None
    shutil.rmtree(outdir.parent, ignore_errors=True)
    if text is not None and lane.desc.get("rename_target"):
        text, _ = rename_definition(text, row["name"])
    return text


# --- m2c: splat assembly of the retail bytes -----------------------------------------------------------------------

class SplatProject:
    """What m22-002's m2c input helpers read from a `project`: names, addresses, a flat retail image, per-address asm."""

    def __init__(self, image, names, asm):
        self.names = {n: (a, k) for n, (a, k, _s) in names.items()}
        self.addresses = {}
        for name, (address, _kind, _size) in sorted(names.items()):
            self.addresses.setdefault(address, name)
        self.asm = asm
        base = min(v for v, *_ in image.segments)
        top = max(v + m for v, m, *_ in image.segments)
        flat = bytearray(top - base)
        for vaddr, memsz, offset, filesz, _f in image.segments:
            flat[vaddr - base:vaddr - base + filesz] = image.data[offset:offset + filesz]
        self.image = bytes(flat)
        self.base = base


SPLAT_TYPES = {"func", "jtbl", "jtbl_label", "label", "asciz"}


def splat_asm(lane, image, rows, names):
    """Splat's assembly (what m2c is fed everywhere) of exactly the sampled functions, from a yaml generated for the
    retail ELF the way new-project does it (header databin, each file-backed PT_LOAD a code segment, the rest binary)."""
    root = lane.work / "splat"
    shutil.rmtree(root / "asm", ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    names = one_name_per_address(names, {r["address"]: r["name"] for r in rows})
    symbols = []
    for name, (address, kind, size) in sorted(names.items(), key=lambda kv: kv[1][0]):
        meta = ("type:func" if kind == "func" else (f"type:{kind}" if kind in SPLAT_TYPES else "")) + (f" size:{size:#x}" if size else "")
        symbols.append(f"{re.sub(r'[^A-Za-z0-9_.$]', '_', name)} = {address:#x}; // {meta}".rstrip())
    (root / "symbol_addrs.txt").write_text("\n".join(symbols) + "\n")
    wanted = {r["address"]: r for r in rows}
    gp = lane.desc.get("gp")
    out = ["options:", "  basename: image", f"  target_path: {lane.retail}", f"  base_path: {root}", "  platform: ps2",
           f"  compiler: {lane.desc.get('splat_compiler', 'GCC')}", "  asm_path: asm", "  symbol_addrs_path: symbol_addrs.txt",
           "  ld_script_path: image.ld", "  find_file_boundaries: False", "  disasm_unknown: True", "  subalign: 1",
           "  create_c_files: False", "  create_asm_dependencies: False"]
    if gp:
        out.append(f"  gp_value: {int(gp, 16):#x}" if isinstance(gp, str) else f"  gp_value: {gp:#x}")
    out.append("segments:")
    out.append("  - name: header\n    type: databin\n    start: 0x0\n    align: 1")
    loads = sorted(image.segments, key=lambda s: s[2])
    for number, (vaddr, memsz, offset, filesz, flags) in enumerate(loads):
        if not filesz:
            continue
        if not flags & 1:
            out.append(f"  - name: data{number}\n    type: databin\n    start: {offset:#x}\n    align: 1")
            continue
        out.append(f"  - name: code{number}\n    type: code\n    start: {offset:#x}\n    vram: {vaddr:#x}\n    align: 1\n"
                   "    subalign: 1\n    subsegments:")
        cursor = vaddr
        end = vaddr + filesz
        for address in sorted(a for a in wanted if vaddr <= a < end):
            size = wanted[address]["size"]
            if address > cursor:
                out.append(f"      - [{offset + cursor - vaddr:#x}, textbin, gap_{cursor:08x}]")
            out.append(f"      - [{offset + address - vaddr:#x}, asm, f_{address:08x}]")
            cursor = address + size
        if cursor < end:
            out.append(f"      - [{offset + cursor - vaddr:#x}, textbin, gap_{cursor:08x}]")
    out.append(f"  - [{len(image.data):#x}]")
    yaml = root / "image.yaml"
    yaml.write_text("\n".join(out) + "\n")
    result = run([sys.executable, "-m", "splat", "split", yaml], cwd=root, env=lane.env(), timeout=3600)
    if result["exit"] != 0:
        raise HarnessError(f"splat failed on the retail image: {(result['stdout'] + result['stderr'])[-800:]}")
    asm = {}
    for row in rows:
        paths = list((root / "asm").rglob(f"f_{row['address']:08x}.s"))
        if not paths:
            continue
        lines = paths[0].read_text(errors="replace").splitlines()
        body = []
        for line in lines:
            if re.match(r"\s*(glabel|endlabel|nonmatching|\.size|\.set|\.section|\.text|\.align|\.global|\.type)\b", line) \
                    and not m22.ASM_ADDRESS.search(line):
                continue
            body.append(line)
        asm[row["address"]] = (row["name"], body)
    return asm, {"splat": result["seconds"], "functions_with_asm": len(asm)}


def m2c_assembly(project, row):
    m22.GP = int(project_gp, 16) if isinstance(project_gp, str) else project_gp
    m22.IMAGE_VRAM = project.base
    relocations = [dict(r, addend=r.get("addend")) for r in row["relocations"]]
    for r in relocations:
        if r["r_type"] != 7:
            r.pop("addend", None)
    return m22.m2c_assembly(project, row["name"], row["address"], relocations)


project_gp = 0


def m2c_candidate(work_dir, name, assembly, context_path, target, use_cache):
    """m2c as m22-002 runs it; `use_cache` lets m2c keep its parsed-context cache (a context of hundreds of KB is parsed once)."""
    asm_path = work_dir / "input.s"
    asm_path.write_text(assembly)
    base = ["m2c", "-t", target, "--valid-syntax", *([] if use_cache else ["--no-cache"]), "-f", name]
    result = run([*base, "--context", context_path, asm_path], timeout=600)
    note = None
    if result["exit"] != 0 or not result["stdout"].strip():
        first = result
        result = run([*base, asm_path], timeout=600)
        note = {"context_dropped": True, "context_error": (first["stderr"] + first["stdout"])[-600:]}
    text = result["stdout"] if result["exit"] == 0 and result["stdout"].strip() else None
    return text, {"argv": result["argv"], "exit": result["exit"], "seconds": result["seconds"],
                  "stderr": result["stderr"][-1500:], **(note or {})}


# --- stock Ghidra (optional layer) -------------------------------------------------------------------------------

def stock_export(lane, args, addresses, directory):
    directory.mkdir(parents=True, exist_ok=True)
    listing = directory / "addresses.txt"
    listing.write_text("".join(f"{a:x}\n" for a in addresses))
    output = directory / "signatures.json"
    key = hashlib.sha256(json.dumps([sorted(addresses), m22.GHIDRA_LANGUAGE,
                                     sha256_file(m22.GHIDRA_SCRIPTS / "ExportDecompiledC.java"), str(lane.retail)]).encode()).hexdigest()[:16]
    stamp = directory / "signatures.key"
    if output.exists() and stamp.exists() and stamp.read_text() == key:
        return json.loads(output.read_text()), {"cached": True, "key": key}
    project = directory / "project"
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir()
    argv = [str(GHIDRA / "support" / "analyzeHeadless"), str(project), "proj", "-import", str(lane.retail), "-processor",
            m22.GHIDRA_LANGUAGE, "-scriptPath", str(m22.GHIDRA_SCRIPTS), "-postScript", "ExportDecompiledC.java", str(listing),
            str(output), "120", "-deleteProject"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_")}
    env.update(GHIDRA_HEADLESS_MAXMEM=os.environ.get("GHIDRA_HEADLESS_MAXMEM", "8G"), DEBUGINFOD_URLS="")
    result = run(argv, env=env, timeout=args.stock_timeout)
    shutil.rmtree(project, ignore_errors=True)
    (directory / "headless.log").write_text(result["stdout"] + result["stderr"])
    if not output.exists():
        raise HarnessError(f"stock Ghidra produced no export (log {directory / 'headless.log'})")
    stamp.write_text(key)
    return json.loads(output.read_text()), {"cached": False, "key": key, "seconds": result["seconds"], "ghidra": str(GHIDRA)}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def family_of(row, depth=1):
    parts = Path(row["file"]).parts
    stem = [p for p in parts if p not in ("src", "ps2", "source")]
    return "/".join(stem[:min(depth, len(stem) - 1)]) if len(stem) > 1 else "(top)"


def markdown(report):
    s, layers = report["summary"], report["layers"]
    lines = [f"# m22-003: C output on matched {report['game']} functions (PS2, {report['lane']} lane)", "",
             f"Generated {report['generated']}. Sample: {report['sample']['n']} matched functions, seed {report['sample']['seed']}, "
             f"from {report['matched']['eligible_in_size_window']} matched functions of {SIZE_MIN}-{SIZE_MAX} bytes "
             f"({report['matched']['count']} matched in all). Repo {report['repo']['url']} at `{report['repo']['commit'][:12]}`.", "",
             f"Compiler ids: {', '.join(report['compilers'])}. Environment passed to romwright: "
             f"{json.dumps(report['env']) if report['env'] else 'none'}.", "",
             "Matched set: " + report["matched"]["definition"], ""]
    cross = report["matched"].get("cross_check")
    if cross:
        lines += [f"Cross-check against the repo's own count: {cross}", ""]
    for variant in m22.REPORTED:
        lines += [f"## {variant} variant" + (" (headline)" if variant == "context" else ""), "",
                  "| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for layer in layers:
            b = s["overall"]["all"][layer][variant]
            lines.append(f"| {layer} | {b['functions']} | {b['produced']} | {b['compiled']} | {b['compile_failure_share']:.1%} | "
                         f"{b['exact']} | {b['mean_percent']} | {b['mean_percent_compiled']} | {b['percent_ge_90']} |")
        lines.append("")
    lines += ["## Paired comparison on percent (first layer better / worse / same)", "",
              "| pair | better | worse | same | two-sided sign-test p |", "|---|---|---|---|---|"]
    for key, row in s["paired"].items():
        lines.append(f"| {key} | {row['wins']} | {row['losses']} | {row['ties']} | {row['p_two_sided']} |")
    for group, title in (("by_family", "unit directory"), ("by_compiler", "compiler"), ("by_size", "function size (bytes)")):
        lines += ["", f"## By {title}, context variant", "",
                  "| group | n | " + " | ".join(f"{layer} exact / mean % / fail" for layer in layers) + " |",
                  "|---|---|" + "---|" * len(layers)]
        for label, block in s[group].items():
            cells = []
            for layer in layers:
                b = block[layer]["context"]
                cells.append(f"{b['exact']} / {b['mean_percent']} / {b['compile_failure_share']:.0%}" if b else "-")
            lines.append(f"| {label} | {block['n']} | " + " | ".join(cells) + " |")
    lines += ["", "## Compile failures of the context variant (first error, normalised)", ""]
    for layer in layers:
        lines.append(f"**{layer}**: " + ("; ".join(f"{m} x{c}" for m, c in s["compile_errors_context"][layer].items()) or "none"))
        lines.append("")
    repair = report.get("context_repair")
    if repair and repair.get("per_unit"):
        lines += [f"Each function's context is compiled alone with its unit's own command before use; {repair['contexts_repaired']} of {repair['contexts']} "
                  f"contexts had declarations the unit's compiler rejects, {repair['dropped']} declaration(s) in all were dropped "
                  f"(up to {repair['rounds']} round(s); {'every context then compiles' if repair['ok'] else 'some still fail'}); "
                  f"first dropped: `{'`, `'.join(repair['first_dropped'][:4])}`.", ""]
    elif repair:
        lines += [f"The repo's C-compatible context did not compile with the unit's compiler as written; {repair['dropped']} declaration(s) the "
                  f"compiler's errors named were dropped in {repair['rounds']} compile round(s) ({'it then compiles' if repair['ok'] else 'it still fails'}); "
                  f"first dropped: `{'`, `'.join(repair['first_dropped'][:4])}`.", ""]
    note = report.get("m2c_context")
    if note and note["dropped"]:
        lines += [f"m2c read the unit context for {note['used']} of {note['used'] + note['dropped']} functions; for {note['dropped']} m2c failed "
                  f"with it and was run again without it (first error: {note['first_error']}), which the compile then contradicts "
                  "wherever the candidate declares what the context declares.", ""]
    lines += ["## Limits", ""] + [f"- {item}" for item in report["limits"]]
    return "\n".join(lines) + "\n"


LIMITS = [
    "The matched set is the decompilation's own: its sources were written against the retail bytes, often with m2c in the loop, "
    "so the m2c column is an upper bound on unseen code, as m22-002 says of Persona 4's promoted units.",
    "Per-function `#pragma` state (MWCC) is replayed from the unit's source for every layer; `#if` branches by m22-002's fixed rule. "
    "ee-gcc units have no per-function pragma state.",
    "Each candidate is compiled twice with the unit's own compile command: `context` (the unit's own declarations as the compiler "
    "sees them, m22-002's context rule) and `standalone`; `best` is the better of the two. Percent is objdiff-cli "
    "`match_percent` with `functionRelocDiffs=none`; exact is same length and every byte equal outside the object's relocation fields.",
    "The comparator masks the relocation fields the object declares; it does not check that a relocation's symbol resolves to the retail operand "
    "(m22-002's `exact_symbols` is not computed in the generic path).",
    "The sample is up to 200 functions; sign tests treat functions as independent although they share units, so p values are indicative.",
    "m2c reads splat assembly generated from the retail ELF for the sampled functions (names from the repo's symbol files, gp-relative operands "
    "and jump tables adapted as m22-002 does), with call and gp symbols taken from the object's relocations.",
    "romwright's import of the retail ELF is one project per lane; a matched function the import did not discover has no `export-c` candidate.",
]


def lane_limits(lane):
    return list(lane.desc.get("limits", [])) + LIMITS


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def stage_prepare(lane, args, image):
    result = {}
    result["repo_head"] = ensure_repo(lane)
    result["retail_sha1"] = check_retail(lane)
    tool_record = provision_tools(lane)
    result["tools"] = tool_record
    result["venv"] = ensure_venv(lane)
    result["setup"] = run_setup(lane, tool_record)
    units = unit_commands(lane)
    result["build"] = build_units(lane, units)
    names, ambiguous = load_symbols(lane)
    matched, stats = collect_matched(lane, units, image, names)
    stats["ambiguous_names"] = len(ambiguous)
    result["matched_stats"] = stats
    result["cross_check"] = cross_check(lane, image, matched, stats, names)
    (lane.work / "matched.json").write_text(json.dumps({"matched": matched, "stats": stats}, indent=1))
    return result, units, names, matched, stats


def cross_check(lane, image, matched, stats, names):
    """The repo's own number, where it has one: a committed/produced progress report (kind json), or the repo's own
    linked executable compared with the retail ELF function by function (kind linked_elf)."""
    spec = lane.desc.get("cross_check")
    if not spec:
        return None
    what = spec.get("what", "repo count")
    if spec.get("run"):
        result = run(["bash", "-c", lane.fmt(spec["run"])], cwd=lane.repo, env=lane.env(), timeout=3600)
        if result["exit"] != 0 and not spec.get("run_may_fail"):
            return f"{what}: `{spec['run']}` failed: {(result['stdout'] + result['stderr'])[-300:]}"
    path = lane.repo / lane.fmt(spec["file"])
    if not path.exists():
        return f"{what}: {path} not produced"
    if spec.get("kind") == "linked_elf":
        built = elfobj.RetailImage(path)
        retail_sha1 = hashlib.sha1(lane.retail.read_bytes()).hexdigest()
        built_sha1 = hashlib.sha1(path.read_bytes()).hexdigest()
        starts = sorted((a, n) for n, (a, k, _s) in names.items() if k == "func")
        first = None
        for vaddr, filesz, offset in image.code_segments():
            other = built.bytes_at(vaddr, filesz) if built.contains(vaddr, filesz) else b""
            ours = image.bytes_at(vaddr, filesz)
            for word in range(0, min(len(ours), len(other)) // 4 * 4, 4):
                if ours[word:word + 4] != other[word:word + 4]:
                    first = vaddr + word
                    break
            if first is not None:
                break
        near = max((s for s in starts if first is not None and s[0] <= first), default=(0, "?"))
        return (f"{what}: linked ELF is {'byte-identical to retail' if built_sha1 == retail_sha1 else 'not identical to retail'}"
                f" (size {path.stat().st_size} vs {lane.retail.stat().st_size}); "
                + ("no code difference" if first is None else f"first code difference at {first:#x} in {near[1]}")
                + f". The repo's gate is whole-image equality, so its own matched count is every C function it compiles "
                f"({stats['c_functions']}); this harness matched {stats['matched']} ({stats['mismatch']} differ, "
                f"{stats['ambiguous_address']} had no unique address)")
    try:
        data = json.loads(path.read_text())
        for key in spec["path"].split("."):
            data = data[int(key)] if isinstance(data, list) else data[key]
    except (ValueError, KeyError, IndexError, TypeError) as error:
        return f"{what}: {path} unreadable ({error})"
    return f"{what} = {data}; this harness matched {stats['matched']} of {stats['c_functions']} C functions"


def compiler_ids(lane, rows, units_by_file):
    """Compiler id per function: the descriptor's rules match the unit's source path (`match`) or its own command (`command`)."""
    rules = lane.desc.get("unit_compilers", [])
    default = lane.desc.get("compiler", "unknown")
    for row in rows:
        command = units_by_file[row["file"]].command if row["file"] in units_by_file else ""
        row["compiler"] = next((r["id"] for r in rules if (r.get("match") and re.search(r["match"], row["file"]))
                               or (r.get("command") and re.search(r["command"], command))), default)
    return sorted({row["compiler"] for row in rows})


def functions_dir(lane, row):
    return lane.work / "functions" / f"{row['address']:08x}_{re.sub(r'[^A-Za-z0-9_.-]', '_', row['name'])[:60]}"


def stage_run(lane, args, image, units, names, matched, prepare_info):
    cache = UnitCache(lane, units)
    units_by_file = {u.src: u for u in units}
    sample_path = lane.work / "sample.json"
    if sample_path.exists() and not args.resample and not args.only:
        saved = json.loads(sample_path.read_text())
        sample, rejected, eligible = saved["sample"], saved["rejected"], saved["eligible"]
        lane.context_repair = saved.get("context_repair")
        for row in sample:
            row["protos"] = {k: tuple(v) for k, v in row["protos"].items()}
        if args.only:
            sample = [r for r in sample if r["name"] in set(args.only.split(","))]
    else:
        log("selecting the sample")
        sample, rejected, eligible = select_sample(lane, matched, cache, args, image)
        if lane.repair_log and not lane.context_repair:
            seen = {id(r): r for r in lane.repair_log}.values()
            lane.context_repair = {"per_unit": True, "contexts": len(seen), "contexts_repaired": sum(1 for r in seen if r["dropped"]),
                                   "dropped": sum(r["dropped"] for r in seen), "rounds": max(r["rounds"] for r in seen),
                                   "ok": all(r["ok"] for r in seen),
                                   "first_dropped": [d for r in seen for d in r["first_dropped"]][:12]}
        if not args.only:  # a partial (--only) selection is not the lane's sample
            sample_path.write_text(json.dumps({"sample": sample, "rejected": rejected, "eligible": eligible, "seed": args.seed,
                                               "context_repair": lane.context_repair}))
    compilers = compiler_ids(lane, sample, units_by_file)
    log(f"{len(sample)} functions ({eligible} matched in the size window; rejected {rejected})")
    if args.sample_out:
        args.sample_out.write_text("".join(f"{r['address']:x}\n" for r in sample))
        return None
    layers = args.layers
    global project_gp
    project_gp = lane.desc.get("gp", 0)
    macros_info = m22.m2c_info()
    macros = m22.m2c_macros(lane.work, macros_info["commit"])
    objdiff = lane.tools["objdiff-cli"] / "objdiff-cli"
    env_extra = dict(item.split("=", 1) for item in args.env)
    cli_env = romwright_env(lane, args, env_extra)
    (lane.work / "tmp").mkdir(exist_ok=True)
    romwright_record = None
    if "romwright" in layers:
        _, romwright_record = import_romwright(lane, args, cli_env)
        romwright_record["assert_names"] = romwright_names(lane, args, cli_env, names)
    stock = None
    if "stock" in layers:
        data, info = stock_export(lane, args, sorted(r["address"] for r in sample), lane.work / "stock")
        stock = {"functions": {f"{int(k, 16):x}": v for k, v in data["functions"].items()}, "info": info}
    project = None
    if "m2c" in layers:
        asm, splat_info = splat_asm(lane, image, sample, names)
        project = SplatProject(image, names, asm)
        project.splat_info = splat_info
    typedef_cache = {}
    search_pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) if args.search else None
    args.search_tmp = lane.work / "tmp"

    def prelude(context):
        """What the stock and romwright layers add in front: the Ghidra types the context does not already define."""
        return "".join(line + "\n" for line in m22.GHIDRA_PRELUDE.splitlines()
                       if not re.search(r"\btypedef\b[^;{]*\b" + re.escape(re.findall(r"(\w+)\)?\(?\)?;$", line)[0]) + r"\b", context))

    def search_layer(row, fdir, context_path, context, produced):
        """The `romwright-search` layer: the default print is scored here (not in the parallel stage) because the search needs it,
        and the variants are exported now, while the store is in the state this function's default print saw."""
        text, record = produced
        extra = prelude(context)
        drop = not record.get("target_asserted", True)

        def score_text(candidate, tag):
            return score_candidate(lane, units_by_file, row, "search-" + tag, candidate, context, row["pragmas"], macros, extra, fdir,
                                   objdiff, drop_target=drop)

        default_variants = score_text(text, "default")
        record["_variants"] = default_variants
        headline = default_variants["context"]
        if not headline["compiled"] or headline["exact"]:
            result = text, {"search": None, "reason": "exact" if headline["exact"] else "default does not compile", "_variants": default_variants}
        else:
            label, winner, variants, search = match_search_arm.search_row(
                args.cli, args.search, search_pool, args.search_tmp,
                lambda words, tag: variant_text(lane, args, cli_env, row, fdir, context_path, words, tag), score_text, text, default_variants)
            result = winner, {"search": search, "_variants": variants}
        for stale in fdir.glob("search-*"):
            shutil.rmtree(stale, ignore_errors=True)
        return result

    def produce(row):
        fdir = functions_dir(lane, row)
        fdir.mkdir(parents=True, exist_ok=True)
        context_path = fdir / "context.c"
        context = m22.missing_typedefs(row["context"]) + row["context"]
        context_path.write_text(context)
        outputs = {}
        needed = [row["name"]]
        # the callees whose prototypes are asserted: the retail jal targets the unit's relocations name, so a romwright-only run asserts
        # the same callees as one that also runs m2c (whose splat assembly adds nothing the relocations lack)
        needed += sorted({r["symbol"] for r in row["relocations"]
                          if r["r_type"] == elfobj.R_MIPS_26 and r.get("symbol") and r.get("retail_target")} - {row["name"]})
        assembly = asm_note = None
        if "m2c" in layers:
            if row["address"] not in project.asm:
                outputs["m2c"] = (None, {"error": "no splat assembly"})
            else:
                assembly, asm_note = m2c_assembly(project, row)
                needed += sorted(set(re.findall(r"\b(?:jal|j)\s+([A-Za-z_]\w*)", assembly)) - {row["name"]} - set(needed))
        for layer in layers:
            if layer == "romwright":
                typedefs = typedef_table_with_arrays(context)
                outputs[layer] = romwright_candidate(lane, args, cli_env, row, fdir / "romwright", context_path, typedefs, needed, names)
                if args.search:
                    outputs["romwright-search"] = search_layer(row, fdir, context_path, context, outputs[layer]) \
                        if outputs[layer][0] is not None else (None, {"search": None, "reason": "no candidate"})
            elif layer == "m2c" and "m2c" not in outputs:
                mdir = fdir / "m2c"
                mdir.mkdir(exist_ok=True)
                text, record = m2c_candidate(mdir, row["name"], assembly, context_path,
                                             "mipsee-gcc-c" if lane.family == "gcc" else "mipsee-mwcc-c",
                                             bool(lane.desc.get("m2c_cache")))
                record.update(asm_note)
                outputs[layer] = (text, record)
            elif layer == "stock":
                outputs[layer] = m22.stock_candidate(dict(row, address=row["address"]), stock)
            elif layer == "oracle":
                outputs[layer] = (row["oracle"], {"source": "the unit's own text for the function"})
        return fdir, context, outputs

    # candidate production is sequential (the romwright project is one sqlite store); scoring runs in parallel
    produced = []
    for row in sample:
        log(f"{row['name']} {row['address']:08x} ({row['file']}, {row['size']} bytes)")
        produced.append((row,) + produce(row))
    log("compiling and scoring")

    def score(item):
        row, fdir, context, outputs = item
        extra = ""
        entry = {"name": row["name"], "address": f"{row['address']:#x}", "file": row["file"], "line": row["line"],
                 "size": row["size"], "compiler": row["compiler"], "flags": [], "origin": family_of(row, lane.desc.get("family_depth", 1)), "family": family_of(row, lane.desc.get("family_depth", 1)),
                 "pragmas": row["pragmas"], "retail": row["retail"], "layers": {}}
        for layer in layers:
            text, record = outputs[layer]
            if text is not None:
                (fdir / layer).mkdir(exist_ok=True)
                (fdir / layer / "raw.c").write_text(text)
            extra = prelude(context) if layer in ("stock", "romwright", "romwright-search") else ""
            # romwright was given no signature for the target when its declaration is K&R (`T f();`) or has a parameter the
            # assertion cannot spell (an array, a struct): it prints its own, so the compile must not hold it to the declaration
            variants = record.pop("_variants", None) or score_candidate(
                lane, units_by_file, row, layer, text, context, row["pragmas"], macros, extra, fdir, objdiff,
                drop_target=layer == "romwright" and not record.get("target_asserted", True))
            entry["layers"][layer] = {"produce": record, "variants": variants}
        return f"{row['address']:08x}", entry

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        out = dict(pool.map(score, produced))
    m2c_context = None
    if "m2c" in layers:
        rows = [v["layers"]["m2c"]["produce"] for v in out.values()]
        dropped = [p for p in rows if p.get("context_dropped")]
        m2c_context = {"used": len(rows) - len(dropped), "dropped": len(dropped),
                       "first_error": " ".join((dropped[0].get("context_error") or "").split())[:300] if dropped else None}
    summary = summarise_functions(out, layers)
    return {"functions": out, "summary": summary, "sample": sample, "rejected": rejected, "eligible": eligible,
            "m2c_context": m2c_context, "context_repair": lane.context_repair,
            "compilers": compilers, "romwright_project": romwright_record,
            "stock": stock["info"] if stock else None, "m2c": macros_info,
            "splat": getattr(project, "splat_info", None)}, None


def summarise_functions(functions, layers):
    summary = m22.summarise(functions, layers)
    summary.pop("by_origin", None)
    for group in summary.values():  # m22-002's exact_symbols is not computed here
        for block in (group.values() if isinstance(group, dict) else ()):
            for layer_block in (block.values() if isinstance(block, dict) else ()):
                for variant_block in (layer_block.values() if isinstance(layer_block, dict) else ()):
                    if isinstance(variant_block, dict):
                        variant_block.pop("exact_symbols", None)
    return summary


def redo_report(path):
    """Recompute the summary, limits and markdown of an existing report from its function rows (no tool runs): after a change to the
    summary code or the report wording."""
    report = json.loads(path.read_text())
    desc = load_descriptor(report["lane"])
    for row in report["functions"].values():  # byte-difference classes again, from the stored candidate bytes
        for layer in row["layers"].values():
            for entry in layer["variants"].values():
                if entry.get("body") and row.get("retail"):
                    if entry["exact"]:
                        entry.pop("diff", None)
                    else:
                        entry["diff"] = classes.classify_diff(bytes.fromhex(entry["body"]), bytes.fromhex(entry["mask"]), bytes.fromhex(row["retail"]))
    report["summary"] = summarise_functions(report["functions"], report["layers"])
    report["limits"] = list(desc.get("limits", [])) + LIMITS
    path.write_text(json.dumps(report, indent=1))
    path.with_suffix(".md").write_text(markdown(report))
    print(f"m22-003 report rewritten: {path}")


def write_report(lane, args, prepare_info, matched, stats, run_info, tool_versions):
    desc = lane.desc
    summary = run_info["summary"]
    in_window = sum(1 for r in matched if SIZE_MIN <= r["size"] <= SIZE_MAX)
    report = {
        "schema": "m22-003-ps2-multigame-c/1", "lane": lane.name, "game": desc["game"], "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "layers": args.layers, "env": dict(item.split("=", 1) for item in args.env), "tag": args.tag,
        "repo": {"url": desc["repo"]["url"], "commit": desc["repo"]["commit"]},
        "compilers": run_info["compilers"],
        "matched": {"count": len(matched), "eligible_in_size_window": in_window, "stats": stats,
                    "definition": "a function compiled from C (not an INCLUDE_ASM body) by the repo's own build, with that unit's own "
                                  "compile command and the pinned compiler, whose bytes equal the retail image at its address modulo the "
                                  "object's relocation fields (tests/m22-003/elfobj.py); no repo verify script is used.",
                    "cross_check": prepare_info.get("cross_check"), "repo_reported": desc.get("repo_reported")},
        "sample": {"n": len(run_info["functions"]), "requested": args.n, "seed": args.seed, "eligible": run_info["eligible"],
                   "rejected": run_info["rejected"], "size_bytes": [SIZE_MIN, SIZE_MAX], "partial": bool(args.only)},
        "toolchain": {"tools": prepare_info["tools"], "retail_sha1": prepare_info["retail_sha1"], "m2c": run_info["m2c"],
                      "objdiff": str(lane.tools["objdiff-cli"]),
                      "romwright": {"cli": str(args.cli), "cli_sha256": sha256_file(args.cli), "worker_sha256": sha256_file(args.worker),
                                    "ghidra_opt_sha256": sha256_file(args.ghidra_opt)},
                      "tools_cache": str(lane.tools_cache)},
        "build": prepare_info["build"], "setup": prepare_info["setup"], "romwright_project": run_info["romwright_project"],
        "stock": run_info["stock"], "splat": run_info["splat"], "m2c_context": run_info["m2c_context"], "context_repair": run_info.get("context_repair"), "summary": summary, "limits": lane_limits(lane),
        "functions": run_info["functions"],
    }
    return report


def functions_interface(report):
    """The CompilerRules interface: one flat row per function and layer, nothing else."""
    rows = {}
    for key, entry in report["functions"].items():
        rows[key] = {"name": entry["name"], "address": entry["address"], "size": entry["size"], "file": entry["file"],
                     "compiler": entry["compiler"], "layers": {
                         layer: {variant: {k: data["variants"][variant][k] for k in ("produced", "compiled", "exact", "percent")}
                                 for variant in m22.REPORTED}
                         for layer, data in entry["layers"].items()}}
    return {"schema": "m22-003-functions/1", "lane": report["lane"], "game": report["game"], "tag": report["tag"],
            "env": report["env"], "layers": report["layers"], "seed": report["sample"]["seed"], "n": report["sample"]["n"],
            "matched_count": report["matched"]["count"], "functions": rows}


def selftest():
    """Unit checks of the parts that need no tools: the object parser and comparator, the objdiff object writer, the overlay,
    the C++ rename, name disambiguation and the preprocess-command derivations."""
    import tempfile
    body = bytes.fromhex("0000a48c" "00000000" "0100022c")  # lw $a0,0($a1) ; nop ; one word the relocation owns
    relocs = [{"offset": 8, "r_type": elfobj.R_MIPS_LO16, "symbol": "x"}]
    retail = bytes.fromhex("0000a48c" "00000000" "5634022c") + b"\0" * 4
    assert elfobj.compare(body, relocs, retail) == 0 and elfobj.compare(body, [], retail) != 0
    assert elfobj.exact(body, relocs, retail, 12) and not elfobj.exact(body, relocs, retail, 16)
    blob = elfobj.object_for_objdiff(body, [{"offset": 8, "r_type": elfobj.R_MIPS_26, "symbol": "callee"}], "f", 0x20924001)
    obj = elfobj.ElfObject(blob)
    (name, shndx, value, size), = obj.functions()
    assert (name, size) == ("f", 12), obj.functions()
    got, rel = obj.function("f")
    assert got == body and rel[0]["symbol"] == "callee" and rel[0]["r_type"] == elfobj.R_MIPS_26 and obj.e_flags == 0x20924001
    with tempfile.TemporaryDirectory() as tmp:
        repo, root = Path(tmp) / "repo", Path(tmp) / "root"
        (repo / "src" / "a").mkdir(parents=True)
        (repo / "src" / "a" / "x.c").write_text("x")
        (repo / "src" / "a" / "y.h").write_text("y")
        (repo / "build" / "o").mkdir(parents=True)
        (repo / "build" / "o" / "old.s").write_text("old")
        (repo / "include").mkdir()
        root.mkdir()
        overlay(root, repo, ["src/a/x.c", "build/o/x.o"], empty=["build/o"])
        assert (root / "src" / "a" / "y.h").is_symlink() and not (root / "src" / "a").is_symlink()
        assert not (root / "src" / "a" / "x.c").exists() and (root / "include").is_symlink()
        assert (root / "build" / "o").is_dir() and not list((root / "build" / "o").iterdir())
    text = "extern int g(int);\nvoid ClsMes_Set(float a)\n{\n  g(1);\n}\n"
    assert rename_definition(text, "Set__6ClsMesFf") == (text.replace("ClsMes_Set", "Set__6ClsMesFf"), "ClsMes_Set")
    assert rename_definition(text, "ClsMes_Set")[1] is None
    names = {"a": (0x100, "func", 4), "func_00000200": (0x200, "func", 4), "b": (0x200, "func", 4)}
    assert set(one_name_per_address(names, {})) == {"a", "b"} and set(one_name_per_address(names, {0x200: "func_00000200"})) == {"a", "func_00000200"}
    assert COMPILER_ERROR_LINE.findall("a.c:12:1: warning: no newline\na.c:13: foo undeclared\nb.c:4:2: error: bad")[:2] == ["foo undeclared", "error: bad"]

    class FakeLane:
        def fmt(self, text):
            return text.replace("{tool:ee-gcc2.96}", "/t/ee-gcc2.96")

        desc = {"build": {"drop_segments": [], "preprocess": {"mode": "flags", "tool": "{tool:ee-gcc2.96}/bin/ee-gcc", "flags": ["-O2"]}}}
    unit = Unit("src/x.c", "build/x.o", "/t/bin/ee-gcc -c -Iinclude -DA=1 -O2 src/x.c -o build/x.o", Path("/r"), Path("/r"))
    assert preprocess_command(FakeLane(), unit) == ["/t/ee-gcc2.96/bin/ee-gcc", "-E", "-O2", "-Iinclude", "-DA=1", "src/x.c"]
    FakeLane.desc = {"build": {"drop_segments": [], "preprocess": {"mode": "mwccgap-E"}}}
    unit = Unit("src/x.c", "build/x.o", "python tools/mwccgap/mwccgap.py src/x.c build/x.o --mwcc-path /m/mwcc.sh --as-march r5900 -O2 -Iinclude", Path("/r"), Path("/r"))
    assert preprocess_command(FakeLane(), unit) == ["/m/mwcc.sh", "-E", "-O2", "-Iinclude", "src/x.c"], preprocess_command(FakeLane(), unit)
    print("m22-003 selftest ok")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--redo-report", type=Path, metavar="REPORT_JSON",
                        help="recompute summary, limits and markdown of an existing report from its function rows (no tools run)")
    parser.add_argument("--selftest", action="store_true", help="unit checks of the parsers, comparator, overlay and command derivations (no tools)")
    parser.add_argument("lane", nargs="?", help="descriptor name under tests/m22-003/ (dds, dc, ff, rc, dk, p4-mwcc, p4-eegcc, ...)")
    parser.add_argument("--list", action="store_true", help="list the lane descriptors")
    parser.add_argument("--stage", choices=("prepare", "run", "all"), default="all",
                        help="prepare = repo, tools, setup, build and matched set only; run = + sample and candidates (default all)")
    parser.add_argument("--work", type=Path, help=f"work root (default {DEFAULT_ROOT}/work); <work>/<lane> holds the clone, builds and per-function files")
    parser.add_argument("--tools-cache", type=Path, default=Path(os.environ.get("M22_003_TOOLS") or DEFAULT_ROOT / "tools"),
                        help="shared cache of the pinned compilers and tools (default %(default)s)")
    parser.add_argument("--glibc32", type=Path, default=GLIBC32, help="directory with the 32-bit ld-linux.so.2 and libc.so.6")
    parser.add_argument("--repo", type=Path, help="existing checkout of the decompilation at the pinned commit")
    parser.add_argument("--retail", type=Path, help="retail ELF (default: the descriptor's path)")
    parser.add_argument("--n", type=int, default=SAMPLE)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--layers", default="romwright,m2c", help="comma list of romwright, m2c, stock, oracle")
    parser.add_argument("--only", default="", help="comma-separated function names (debugging; the report is then partial)")
    parser.add_argument("--only-report", type=Path, metavar="REPORT_JSON",
                        help="score exactly the functions of an m22-002/m22-003 report (names from its `functions` rows): the same "
                             "functions, not the same seed, which is how P4 is compared with m22-002")
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                        help="environment for the romwright CLI processes (import, assert-*, export-c), e.g. ROMWRIGHT_COMPILER_RULES_DISABLE=ID")
    parser.add_argument("--tag", default="", help="label for this run (recorded in the report; names the default output files)")
    parser.add_argument("--report", type=Path, help="JSON report (default benchmarks/reports/m22-003_<game>.json; with --tag, <work>/runs/<tag>.json)")
    parser.add_argument("--functions-out", type=Path, help="also write the per-function JSON interface (m22-003-functions/1) here")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4))
    parser.add_argument("--cli", type=Path, default=Path(os.environ.get("ROMWRIGHT_CLI") or REPO / "target/release/romwright-cli"))
    parser.add_argument("--worker", type=Path, default=Path(os.environ.get("ROMWRIGHT_WORKER") or REPO / "target/release/romwright-worker"))
    parser.add_argument("--ghidra-opt", type=Path, default=Path(os.environ.get("ROMWRIGHT_GHIDRA_OPT") or REPO / "native/build/ghidra_opt"))
    parser.add_argument("--stock-timeout", type=int, default=3600)
    parser.add_argument("--fresh-import", action="store_true")
    parser.add_argument("--redo-setup", action="store_true")
    parser.add_argument("--rebuild", action="store_true", help="rebuild every unit object with the repo's commands")
    parser.add_argument("--resample", action="store_true", help="select the sample again (the saved sample.json is reused otherwise)")
    parser.add_argument("--sample-out", type=Path, metavar="FILE", help="write the sample's hex addresses and stop")
    parser.add_argument("--search", type=int, default=0, metavar="N",
                        help="near-miss search (docs/match.md): for each function whose default romwright print compiles but is not exact, "
                             "try up to N alternative printings (the product command's plan, `romwright-cli match --plan`) and add the "
                             "`romwright-search` layer, the best print per function; the `romwright` layer is the default print, as without --search")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.redo_report:
        redo_report(args.redo_report)
        return 0
    if args.list:
        for path in sorted(LANE_DIR.glob("*.json")):
            desc = json.loads(path.read_text())
            print(f"{path.stem:12} {desc.get('game', '')}: {desc.get('title', '')}")
        return 0
    if not args.lane:
        parser.error("a lane is required (--list shows them)")
    args.layers = [layer for layer in args.layers.split(",") if layer]
    if args.search:
        if "romwright" not in args.layers:
            parser.error("--search needs the romwright layer")
        args.layers.insert(args.layers.index("romwright") + 1, "romwright-search")
    if args.only_report:
        names = [row["name"] for row in json.loads(args.only_report.read_text())["functions"].values()]
        args.only = ",".join(names + ([args.only] if args.only else []))
    desc = load_descriptor(args.lane)
    args.seed = args.seed if args.seed is not None else desc.get("seed", SEED)
    reexec_if_needed(desc, args)
    lane = Lane(desc, args)
    log(f"lane {lane.name}: {desc.get('title', desc['game'])}")
    check_retail(lane)
    image = elfobj.RetailImage(lane.retail)
    prepare_info, units, names, matched, stats = stage_prepare(lane, args, image)
    log(f"matched {stats['matched']} functions ({stats})")
    if args.stage == "prepare":
        print(json.dumps({"lane": lane.name, "matched": stats["matched"], "stats": stats}, indent=1))
        return 0
    for needed in (args.cli, args.worker, args.ghidra_opt):
        if "romwright" in args.layers and not needed.is_file():
            raise HarnessError(f"missing: {needed}")
    run_info, _ = stage_run(lane, args, image, units, names, matched, prepare_info)
    if run_info is None:
        return 0
    report = write_report(lane, args, prepare_info, matched, stats, run_info, None)
    default = REPO / "benchmarks" / "reports" / f"m22-003_{lane.name}.json"
    target = args.report or (lane.work / "runs" / f"{args.tag}.json" if args.tag else default)
    if target.exists() and not args.tag and not args.report and "frozen" in target.read_text()[:400]:
        raise HarnessError(f"{target} is frozen")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=1))
    target.with_suffix(".md").write_text(markdown(report))
    if args.functions_out:
        args.functions_out.parent.mkdir(parents=True, exist_ok=True)
        args.functions_out.write_text(json.dumps(functions_interface(report), indent=1))
    parts = []
    for layer in args.layers:
        b = report["summary"]["overall"]["all"][layer]["context"]
        parts.append(f"{layer}: exact {b['exact']}/{b['functions']} compiled {b['compiled']} mean {b['mean_percent']}%")
    print(f"m22-003 {lane.name} matched {len(matched)} | " + " | ".join(parts) + f" | report {target}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessError as error:
        print(f"m22-003 harness error: {error}", file=sys.stderr)
        sys.exit(2)
