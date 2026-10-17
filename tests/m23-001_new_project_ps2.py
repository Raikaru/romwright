#!/usr/bin/env python3
"""M23-001: `romwright new-project` on PlayStation 2.

Two measurements.

1. Compiler detection (`romwright-cli detect-compiler`) over every PS2
   executable of the corpus that has a `truth/meta.json`, scored against that
   file's `compiler` field. Family accuracy, version-class accuracy and the
   share of suggested manifest compilers that name the build the decomp repo
   uses are reported separately. The version classes were designed with this
   corpus in view, so those two numbers are in-sample.

2. The bootstrap gate, on a Metrowerks game (Persona 4, SLUS_217.82) and an
   ee-gcc game (Fatal Frame, SLUS_203.88):

     new-project  ->  configure.py (splat split)  ->  ninja
       the all-assembly build must be byte-identical to the retail ELF;
     python3 configure.py swap <function> --src <C>  ->  ninja
       one function, replaced by the matching C of the game's own decomp repo
       (taken from a local clone as test data), must still be byte-identical,
       and objdiff.json must name the unit;
     a deliberately wrong C file must break the build with a MISMATCH that
     names the function.

   Fatal Frame builds with the pinned manifest, so the generated project's
   download path is exercised against the network (binutils, wibo and the
   ee-gcc 2.9-991111 Windows build from decomp.me's compilers release).
   Persona 4 builds with a user toolchain profile over the local /var/tmp/p4ci
   MWCC (profile mode), and, with --offline-manifest, again from a local
   manifest whose file:// URLs point at copies of those tools (the path for a
   machine without network).

Import (the heavy step) can run on a remote host: --import-host HOST
--host-cli PATH. splat, ninja and the builds are light and always run here.

Usage:
    python3 tests/m23-001_new_project_ps2.py [--cli PATH] [--work DIR]
        [--detection-only] [--games fatal-frame,persona-4] [--offline-manifest]
        [--import-host HOST --host-cli PATH --host-work DIR] [--report-dir DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = Path(os.environ.get("ROMWRIGHT_CORPUS", Path.home() / "ventris-corpus" / "extracted"))
REPOS = Path(os.environ.get("ROMWRIGHT_PS2_REPOS", Path.home() / "ventris-scratch" / "ps2-truth" / "repos"))
P4CI = Path("/var/tmp/p4ci")

# --------------------------------------------------------------------------
# Detection accuracy
# --------------------------------------------------------------------------

# (corpus dir, image file). The first eight have truth/meta.json.
SCORED = [
    ("ps2-dark-cloud", "SCUS_971.11"),
    ("ps2-dark-chronicle", "SCES_511.90"),
    ("ps2-persona-4", "SLUS_217.82"),
    ("ps2-digital-devil-saga", "SLUS_209.74"),
    ("ps2-fatal-frame", "SLUS_203.88"),
    ("ps2-god-hand", "SLUS_215.03"),
    ("ps2-ratchet-clank", "SCUS_971.99"),
    ("ps2-ratchet-clank-pal", "SCES_509.16"),
]
# Images with no meta.json: truth from the corpus manifest or the image's own
# DWARF producer string, so supplementary and reported apart.
SUPPLEMENTARY = [
    ("ps2-capcom-fighting-evolution", "SLUS_209.50", "mwcc-ps2", "manifest: Metrowerks CodeWarrior DWARF 1 sections"),
    ("ps2-dungeon-game", "dungeon_game.elf", "ee-gcc", "DWARF producer `GNU C 3.2.2` in .debug_info"),
]


def expected_from_meta(compiler: str) -> dict:
    """The family and version class a meta.json `compiler` string implies."""
    text = compiler.strip()
    if text.startswith("MWCC PS2"):
        version = re.search(r"MWCC PS2 (\d+\.\d+)", text)
        major_minor = version.group(1) if version else ""
        return {"family": "mwcc-ps2", "lineage": "mwcc", "class": "mwcc-2.3" if major_minor == "2.3" else "mwcc-2.4"}
    if "SN ProDG" in text:
        return {"family": "sn-prodg", "lineage": "gcc", "class": "sn-prodg"}
    if text.startswith("EE GCC"):
        if "2.9-991111" in text:
            cls = "gcc-2.9-ee"
        elif "2.96" in text:
            cls = "gcc-2.95-2.96"
        else:
            cls = "gcc-2.9x"
        return {"family": "ee-gcc", "lineage": "gcc", "class": cls}
    raise SystemExit(f"cannot derive an expectation from compiler field: {compiler!r}")


def tool_version_tokens(meta_compiler: str) -> list[str]:
    """Version strings of the meta compiler field, to compare with a manifest id."""
    return re.findall(r"\d+\.\d+(?:\.\d+)?(?:-\d+)?", meta_compiler)


def run_detect(cli: Path, image: Path) -> dict:
    out = subprocess.run([str(cli), "detect-compiler", str(image), "--json"], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def detection_accuracy(cli: Path) -> dict:
    rows = []
    for game, image in SCORED:
        meta = json.loads((CORPUS / game / "truth" / "meta.json").read_text())
        want = expected_from_meta(meta["compiler"])
        got = run_detect(cli, CORPUS / game / image)
        tokens = tool_version_tokens(meta["compiler"])
        tool = got["suggested_tool"]
        exact_version = any(tok in tool for tok in tokens if tok.count(".") >= 2 or "-" in tok)
        class_version = any(tool.split("-", 1)[-1].startswith(tok) for tok in tokens)
        rows.append({
            "game": game,
            "meta_compiler": meta["compiler"],
            "expected": want,
            "detected": {k: got[k] for k in ("family", "version", "version_class", "confidence", "splat_compiler", "suggested_tool")},
            "family_ok": got["family"] == want["family"],
            "lineage_ok": ("mwcc" if got["family"] == "mwcc-ps2" else "gcc") == want["lineage"],
            "class_ok": got["version_class"] == want["class"],
            "tool_names_meta_version": bool(exact_version or class_version),
            "evidence": got["evidence"],
        })
    supplementary = []
    for game, image, family, source in SUPPLEMENTARY:
        got = run_detect(cli, CORPUS / game / image)
        supplementary.append({"game": game, "truth_family": family, "truth_source": source,
                              "detected_family": got["family"], "ok": got["family"] == family,
                              "version": got["version"], "confidence": got["confidence"]})
    n = len(rows)
    return {
        "scored": rows,
        "supplementary": supplementary,
        "summary": {
            "games": n,
            "family_correct": sum(r["family_ok"] for r in rows),
            "lineage_correct": sum(r["lineage_ok"] for r in rows),
            "version_class_correct": sum(r["class_ok"] for r in rows),
            "suggested_tool_matches_meta_version": sum(r["tool_names_meta_version"] for r in rows),
            "supplementary_correct": sum(s["ok"] for s in supplementary),
            "supplementary_games": len(supplementary),
        },
    }


# --------------------------------------------------------------------------
# Gate helpers
# --------------------------------------------------------------------------

def run(cmd, cwd=None, env=None, timeout=3600, check=True, quiet=False):
    started = time.monotonic()
    result = subprocess.run([str(c) for c in cmd], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise SystemExit(
            f"FAILED ({result.returncode}): {' '.join(str(c) for c in cmd)}\n--- stdout\n{result.stdout[-3000:]}\n--- stderr\n{result.stderr[-3000:]}"
        )
    if not quiet:
        print(f"  [{time.monotonic() - started:6.1f}s] {' '.join(str(c) for c in cmd)[:150]}", flush=True)
    return result


def sha1_of(path: Path) -> str:
    return hashlib.sha1(path.read_bytes()).hexdigest()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_tool(name: str) -> str:
    found = shutil.which(name) or shutil.which(name, path=str(Path.home() / ".local" / "bin"))
    if not found:
        raise SystemExit(f"required tool `{name}` not found (pip install ninja splat64==0.39.1)")
    return found


def function_source(path: Path, name: str) -> str:
    """The definition of `name` in a C file, by brace matching."""
    text = path.read_text(errors="replace")
    match = re.search(rf"^[A-Za-z_][\w \*]*[ \*]{re.escape(name)}\s*\([^)]*\)\s*\{{", text, re.M)
    if not match:
        raise SystemExit(f"{path}: no definition of {name}")
    depth, i = 0, match.end() - 1
    while True:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[match.start(): i + 1]
        i += 1


def project_symbols(project: Path) -> dict[int, str]:
    names = {}
    for line in (project / "config" / "symbol_addrs.txt").read_text().splitlines():
        m = re.match(r"(\S+) = (0x[0-9a-fA-F]+);", line)
        if m:
            names.setdefault(int(m.group(2), 16), m.group(1))
    return names


# Each game: where its image and decomp repo are, which function is swapped,
# and how the repo's C is adapted to the project's own symbol names.
GAMES = {
    "persona-4": {
        "corpus": "ps2-persona-4", "image": "SLUS_217.82", "family": "mwcc-ps2",
        "repo_file": "p4/src/Kosaka/Field/sequenceList.c", "repo_function": "K_Fldrc_DestroyArchives",
        "address": 0x00102E70, "callees": [0x00192E90, 0x00193730],
        "callee_pattern": r"func_([0-9a-f]{8})",
        "wrong": ("{func_0}();\n    {func_1}();", "{func_1}();\n    {func_0}();"),
        "cflags": "-O2",
    },
    "fatal-frame": {
        "corpus": "ps2-fatal-frame", "image": "SLUS_203.88", "family": "ee-gcc",
        "repo_file": "ff1/src/os/eeiop/cdvd/eecdvd.c", "repo_function": "CdvdInitIop",
        "address": 0x0010CEA8, "callees": [],
        "wrong": ("SetIopCmdSm(12, 0, 0, 0)", "SetIopCmdSm(13, 0, 0, 0)"),
        "cflags": "-O2",
    },
}


def swap_source(game: dict, project: Path) -> tuple[str, list[str]]:
    """The repo's C for the swapped function, in the project's names."""
    body = function_source(REPOS / game["repo_file"], game["repo_function"])
    names = project_symbols(project)
    notes = []
    if re.match(r"\s*static\s", body):
        # The caller now lives in another object; a static definition would be invisible to it.
        body = re.sub(r"^\s*static\s+", "", body)
        notes.append("dropped `static` (callers are in other objects)")
    target_name = names[game["address"]]
    # The definition takes the project's symbol for its address (objdiff
    # pairs functions by name).
    body = re.sub(rf"\b{re.escape(game['repo_function'])}\b", target_name, body, count=1)
    if target_name != game["repo_function"]:
        notes.append(f"definition renamed {game['repo_function']} -> {target_name}")
    declarations = []
    if game["callees"]:
        for address in game["callees"]:
            repo_name = f"func_{address:08x}"
            project_name = names[address]
            body = body.replace(repo_name, project_name)
            declarations.append(f"void {project_name}(void);")
            notes.append(f"callee {repo_name} -> {project_name}")
    else:
        # Fatal Frame calls SetIopCmdSm, a symbol the ELF names itself.
        declarations.append("extern void SetIopCmdSm(int, int, int, int);")
        notes.append("declared SetIopCmdSm (the repo declares it in a header)")
    return "\n".join(declarations) + "\n\n" + body + "\n", notes


def local_profile(path: Path, wibo: str) -> None:
    """A user toolchain profile over the local Persona 4 CI kit: the compiler and its
    launcher only. The binutils stay the manifest's: distribution binutils lack the
    R5900 multimedia instructions (`padduw`) splat emits."""
    tools = {
        "compiler": {"path": str(P4CI / "mwccps2.exe"), "digest": sha256_of(P4CI / "mwccps2.exe")},
        "wibo": {"path": wibo, "digest": ""},
    }
    path.write_text(json.dumps({
        "name": "local-p4ci",
        "recipe": {"compiler": wibo, "arguments": [], "environment": {}},
        "tools": tools,
    }, indent=2))


def local_manifest(path: Path, work: Path, wibo: str, binutils_archive: Path) -> None:
    """A manifest whose URLs are file:// copies of tools already on this machine."""
    store = work / "local-tools"
    store.mkdir(parents=True, exist_ok=True)
    compiler_archive = store / "mwcps2-p4ci.tar.gz"
    with tarfile.open(compiler_archive, "w:gz") as archive:
        for name in ("mwccps2.exe", "mwldps2.exe"):
            archive.add(P4CI / name, arcname=name)
    base = json.loads((ROOT / "crates/romwright-core/src/new_project/toolchains.json").read_text())
    entries = {t["id"]: t for t in base["tools"]}
    wibo_copy = store / "wibo"
    shutil.copyfile(wibo, wibo_copy)

    def entry(source, archive, copy):
        return {"url": copy.resolve().as_uri(), "sha256": sha256_of(copy), "size": copy.stat().st_size, "archive": archive}

    tools = []
    binutils = dict(entries["binutils-mips-ps2-decompals"])
    binutils["assets"] = {"linux-x86_64": entry("local", "tar.gz", binutils_archive)}
    binutils["provenance"] = f"local copy of {binutils_archive.name} (test fixture)"
    tools.append(binutils)
    runtime = dict(entries["wibo"])
    runtime["assets"] = {"linux-x86_64": entry("local", "raw", wibo_copy)}
    runtime["provenance"] = f"local copy of {wibo} (test fixture)"
    tools.append(runtime)
    compiler = dict(entries["mwcps2-3.0.1b210-060308"])
    compiler["assets"] = {"any": entry("local", "tar.gz", compiler_archive)}
    compiler["provenance"] = "local copy of /var/tmp/p4ci (test fixture)"
    tools.append(compiler)
    tools.append(dict(entries["objdiff-cli"]))
    path.write_text(json.dumps({"schema": 1, "revision": "test-local", "note": "file:// fixture", "tools": tools}, indent=1))


def new_project(args, cli: Path, game_key: str, outdir: Path, extra: list[str]) -> dict:
    game = GAMES[game_key]
    image = CORPUS / game["corpus"] / game["image"]
    env = dict(os.environ, ROMWRIGHT_NO_FACT_PACK="1")
    command = ["new-project", None, outdir, "--name", game_key.replace("-", "_"), "--cflags", game["cflags"], "--json", *extra]
    if args.import_host:
        host_work = f"{args.host_work}/{game_key}"
        run(["ssh", args.import_host, f"rm -rf {host_work} && mkdir -p {host_work}"])
        run(["rsync", "-a", str(image), f"{args.import_host}:{host_work}/"])
        remote = ["ROMWRIGHT_NO_FACT_PACK=1", args.host_cli, "new-project", f"{host_work}/{game['image']}", f"{host_work}/out",
                  "--name", game_key.replace("-", "_"), "--cflags", game["cflags"], "--json"]
        result = run(["ssh", args.import_host, " ".join(remote)])
        if outdir.exists():
            shutil.rmtree(outdir)
        run(["rsync", "-a", "--exclude", ".romwright", f"{args.import_host}:{host_work}/out/", f"{outdir}/"])
        if extra:
            # --toolchain / --manifest files are local; apply them here.
            for flag, value in zip(extra[::2], extra[1::2]):
                if flag == "--toolchain":
                    shutil.copyfile(value, outdir / "config" / "toolchain.local.json")
                elif flag == "--manifest":
                    shutil.copyfile(value, outdir / "config" / "toolchain.json")
        return json.loads(result.stdout)
    command[1] = image
    if outdir.exists():
        shutil.rmtree(outdir)
    result = run([cli, *command], env=env)
    return json.loads(result.stdout)


def build_all_asm(project: Path, game: dict, python: str, ninja: str, configure_args: list[str]) -> dict:
    image = game["image"]
    retail = CORPUS / game["corpus"] / image
    timings = {}
    started = time.monotonic()
    run([python, "configure.py", *configure_args], cwd=project)
    timings["configure_split_s"] = round(time.monotonic() - started, 1)
    started = time.monotonic()
    result = run([ninja], cwd=project)
    timings["ninja_s"] = round(time.monotonic() - started, 1)
    built = project / "build" / image
    built_sha, retail_sha = sha1_of(built), sha1_of(retail)
    if built_sha != retail_sha:
        raise SystemExit(f"all-asm build differs from retail: {built_sha} != {retail_sha}\n{result.stdout[-1500:]}")
    return {"sha1": built_sha, "bytes": built.stat().st_size, **timings}


def swap_check(project: Path, game: dict, python: str, ninja: str, configure_args: list[str], work: Path) -> dict:
    image = game["image"]
    retail_sha = sha1_of(CORPUS / game["corpus"] / image)
    source, notes = swap_source(game, project)
    candidate = work / f"{game['repo_function']}.c"
    candidate.write_text(source)
    address = f"0x{game['address']:08x}"
    run([python, "configure.py", *configure_args, "swap", address, "--src", candidate], cwd=project)
    result = run([ninja], cwd=project)
    built_sha = sha1_of(project / "build" / image)
    if built_sha != retail_sha:
        raise SystemExit(f"build with the C unit differs from retail: {built_sha}\n{result.stdout[-1500:]}")
    objdiff = json.loads((project / "objdiff.json").read_text())
    unit_name = project_symbols(project)[game["address"]]
    named = [u["name"] for u in objdiff["units"] if u["name"].endswith("/" + unit_name)]
    if not named:
        raise SystemExit(f"objdiff.json does not name the swapped unit {unit_name}: {[u['name'] for u in objdiff['units']]}")
    unit = next(u for u in objdiff["units"] if u["name"] == named[0])
    base = project / unit["base_path"]
    if not base.exists():
        raise SystemExit(f"the C unit's object {base} was not built")
    target_ok = "target_path" in unit and (project / unit["target_path"]).exists()
    # Negative control: a wrong C file must not pass.
    wrong_from, wrong_to = game["wrong"]
    if game["callees"]:
        names = project_symbols(project)
        fills = {f"func_{i}": names[a] for i, a in enumerate(game["callees"])}
        wrong_from, wrong_to = wrong_from.format(**fills), wrong_to.format(**fills)
    unit_c = project / "src" / (named[0] + ".c")
    good = unit_c.read_text()
    if wrong_from not in good:
        raise SystemExit(f"negative control: {wrong_from!r} not found in the swapped source")
    unit_c.write_text(good.replace(wrong_from, wrong_to))
    broken = run([ninja], cwd=project, check=False, quiet=True)
    unit_c.write_text(good)
    if broken.returncode == 0:
        raise SystemExit("negative control: a wrong C file still produced the retail image")
    names_function = unit_name in broken.stdout or unit_name in broken.stderr
    report = {
        "function": unit_name, "address": address, "unit": named[0], "source_notes": notes,
        "objdiff_units": len(objdiff["units"]), "target_object": target_ok,
        "negative_control_names_function": names_function,
        "negative_control_message": (broken.stdout + broken.stderr).strip().splitlines()[-3:],
    }
    if not names_function:
        raise SystemExit(f"negative control: the MISMATCH message did not name {unit_name}\n{broken.stdout[-800:]}")
    # And the restored source builds again.
    run([ninja], cwd=project, quiet=True)
    return report


def gate(args, cli: Path) -> dict:
    python = sys.executable
    ninja = find_tool("ninja")
    work = args.work
    work.mkdir(parents=True, exist_ok=True)
    scenarios = []
    games = [g.strip() for g in args.games.split(",")]
    wibo = find_tool("wibo")
    for key in games:
        game = GAMES[key]
        modes = []
        if key == "fatal-frame":
            modes.append(("pinned-manifest", [], []))
        else:
            profile = work / "profile-p4ci.json"
            local_profile(profile, wibo)
            modes.append(("toolchain-profile", ["--toolchain", str(profile)], ["--toolchain", str(profile)]))
        if key == "persona-4" and args.offline_manifest:
            modes.append(("local-manifest", None, None))
        for mode, new_args, configure_args in modes:
            print(f"== {key} [{mode}]", flush=True)
            project = work / f"{key}-{mode}"
            if mode == "local-manifest" and not (args.reuse and project.exists()):
                archive = args.binutils_archive or next(
                    iter(sorted((work / "fatal-frame-pinned-manifest" / "build" / "tools" / ".cache").glob("*"), key=lambda p: -p.stat().st_size)), None)
                if archive is None:
                    raise SystemExit("--offline-manifest needs --binutils-archive (or a pinned run first to populate its cache)")
                manifest = work / "local-manifest.json"
                local_manifest(manifest, work, wibo, Path(archive))
                new_args, configure_args = ["--manifest", str(manifest)], []
            started = time.monotonic()
            summary_path = project / ".m23-summary.json"
            if args.reuse and summary_path.exists():
                summary = json.loads(summary_path.read_text())
            else:
                summary = new_project(args, cli, key, project, new_args)
                summary_path.write_text(json.dumps(summary))
            import_seconds = round(time.monotonic() - started, 1)
            detection = summary["detection"]
            if detection["family"] != game["family"]:
                raise SystemExit(f"{key}: detected {detection['family']}, expected {game['family']}")
            checksum = (project / "config" / "checksum.sha1").read_text().split()[0]
            if checksum != sha1_of(CORPUS / game["corpus"] / game["image"]):
                raise SystemExit(f"{key}: checksum.sha1 is not the retail sha1")
            row = {"game": key, "mode": mode, "new_project_s": import_seconds, "detection": {
                       k: detection[k] for k in ("family", "version", "version_class", "confidence", "splat_compiler", "suggested_tool")},
                   "summary": {k: v for k, v in summary.items() if k not in ("detection",)}}
            row["all_asm"] = build_all_asm(project, game, python, ninja, configure_args)
            row["swap"] = swap_check(project, game, python, ninja, configure_args, work)
            if (project / "build" / "tools" / "objdiff-cli" / "objdiff-cli").exists():
                run(["ninja", "progress"], cwd=project, quiet=True)
                report = json.loads((project / "build" / "report.json").read_text())
                measures = report.get("measures", {})
                row["progress"] = {k: measures.get(k) for k in ("total_functions", "matched_functions", "fuzzy_match_percent")}
                if measures.get("matched_functions") != 1 or measures.get("fuzzy_match_percent") != 100.0:
                    raise SystemExit(f"objdiff does not see the swapped unit as a 100% match: {measures}")
            scenarios.append(row)
            print(f"   OK all-asm sha1 {row['all_asm']['sha1']}; swap {row['swap']['function']} matched", flush=True)
    return {"scenarios": scenarios}


def markdown(report: dict) -> str:
    lines = ["# M23-001: PS2 `new-project`", "", f"Generated {report['generated']} by `tests/m23-001_new_project_ps2.py`.", ""]
    det = report["detection"]
    s = det["summary"]
    lines += [
        "## Compiler detection",
        "",
        f"Scored against `truth/meta.json` `compiler` over {s['games']} PS2 games: "
        f"**family {s['family_correct']}/{s['games']}**, toolchain lineage (MWCC vs GNU/SN) {s['lineage_correct']}/{s['games']}, "
        f"version class {s['version_class_correct']}/{s['games']} (in-sample), suggested manifest compiler names the meta version "
        f"{s['suggested_tool_matches_meta_version']}/{s['games']}. Supplementary (truth from manifest/DWARF): "
        f"{s['supplementary_correct']}/{s['supplementary_games']}.",
        "",
        "| game | meta compiler | detected | class | confidence | suggested tool | family | class ok |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in det["scored"]:
        d = r["detected"]
        lines.append(f"| {r['game']} | {r['meta_compiler'][:60]} | {d['family']} | {d['version_class']} | {d['confidence']} | "
                     f"{d['suggested_tool']} | {'yes' if r['family_ok'] else '**no**'} | {'yes' if r['class_ok'] else '**no**'} |")
    lines += ["", "| supplementary game | truth | detected | ok |", "| --- | --- | --- | --- |"]
    for r in det["supplementary"]:
        lines.append(f"| {r['game']} | {r['truth_family']} ({r['truth_source']}) | {r['detected_family']} | {'yes' if r['ok'] else '**no**'} |")
    if "gate" in report:
        lines += ["", "## Bootstrap gate", "", "| game | tools | new-project s | split s | ninja s | all-asm sha1 | swapped function | matched |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for r in report["gate"]["scenarios"]:
            a, w = r["all_asm"], r["swap"]
            lines.append(f"| {r['game']} | {r['mode']} | {r['new_project_s']} | {a['configure_split_s']} | {a['ninja_s']} | `{a['sha1']}` | "
                         f"`{w['function']}` @ {w['address']} | yes |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cli", type=Path, default=Path(os.environ.get("ROMWRIGHT_CLI") or ROOT / "target/release/romwright-cli"))
    parser.add_argument("--work", type=Path, default=Path.home() / ".cache" / "romwright" / "m23-001")
    parser.add_argument("--games", default="fatal-frame,persona-4")
    parser.add_argument("--detection-only", action="store_true")
    parser.add_argument("--offline-manifest", action="store_true", help="also build Persona 4 from a local file:// manifest")
    parser.add_argument("--binutils-archive", type=Path, help="binutils tarball for the local manifest (default: the pinned run's download cache)")
    parser.add_argument("--reuse", action="store_true", help="keep an existing project dir from a previous run (skips new-project)")
    parser.add_argument("--import-host")
    parser.add_argument("--host-cli")
    parser.add_argument("--host-work")
    parser.add_argument("--report-dir", type=Path, help="write m23-001 reports here (default: the work dir)")
    args = parser.parse_args()
    if args.import_host and not (args.host_cli and args.host_work):
        parser.error("--import-host needs --host-cli and --host-work")
    cli = args.cli
    if not cli.exists():
        raise SystemExit(f"{cli}: build romwright-cli first")
    report = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
              "cli": str(cli), "detection": detection_accuracy(cli)}
    s = report["detection"]["summary"]
    print(f"detection: family {s['family_correct']}/{s['games']}, lineage {s['lineage_correct']}/{s['games']}, "
          f"class {s['version_class_correct']}/{s['games']}, tool {s['suggested_tool_matches_meta_version']}/{s['games']}")
    if s["lineage_correct"] != s["games"] or s["family_correct"] < s["games"] - 1:
        raise SystemExit("compiler detection fell below its floor (lineage 8/8, family >= 7/8)")
    if not args.detection_only:
        report["gate"] = gate(args, cli)
    out = args.report_dir or args.work
    out.mkdir(parents=True, exist_ok=True)
    stem = "m23-001_compiler_detection" if args.detection_only else "m23-001_new_project_ps2"
    (out / f"{stem}.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / f"{stem}.md").write_text(markdown(report))
    print(f"wrote {out / (stem + '.json')}")
    print("PASS")


if __name__ == "__main__":
    main()
