"""Where each truth module of a corpus game lives in its cached default import.

Shared by build_pack.py (donor ingestion) and benchmarks/fact_pack_eval.py. The placement is
console_research.wave_units, unchanged: this file only adds what a fact-pack run needs around it,
which is (1) finding the default-environment project the research harness cached for a game,
(2) pointing wave_units at that cache read-only (a work cache of symlinks; nothing under
~/.cache/romwright/research-eval is ever written), and (3) copying the projects, because both
`facts add-donor` and `facts apply` open the project read-write.

A *program unit* is `{program, project (real cache dir), modules: [names], truth: {addr: (size, name)},
verified: {addr}}`: every truth module that wave_units placed in one program of one project, merged
(a GBA's `main` and `gba:ram.*` rows, a DOL and the RELs the importer merged into it).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "benchmarks"))

DEFAULT_ENV_KEY = "4f53cda18c2b"  # console_research.env_key({}): the default import environment
CORPUS = Path.home() / "romwright-corpus" / "extracted"
CACHE = Path.home() / ".cache" / "romwright" / "research-eval"
TSV_HEADER = "start\tsize\tname\tmodule\tverified"


def tool_env(cli: Path, ghidra: Path, ghidra_opt: Path, worker: Path | None = None) -> dict:
    """The environment `romwright-cli facts ...` runs in: no inherited ROMWRIGHT_* variable;
    ROMWRIGHT_NO_FACT_PACK=1 (a pack is only ever passed with --pack: a research run must never pick one up
    implicitly); the Ghidra language specs and worker that `facts` reads prototype types with."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_")}
    env.update(ROMWRIGHT_NO_FACT_PACK="1", ROMWRIGHT_GHIDRA=str(ghidra), ROMWRIGHT_GHIDRA_OPT=str(ghidra_opt),
               ROMWRIGHT_WORKER=str(worker or cli.parent / "romwright-worker"))
    return env


def research():
    """(console_research, console_research_wave), imported on first use (they pull in the whole harness)."""
    import console_research as cr
    import console_research_wave as wave
    return cr, wave


def find_project(cache: Path, game: str, fingerprint: str | None = None) -> tuple[Path, str] | None:
    """The newest finished default-environment project of `game`: (dir, tool fingerprint). The directory is
    `<game>-<sha12>-<default env key>-<fingerprint>`; a game's other projects (`<game>@module` raw imports,
    `-symtab`, `-proto-`, other environments) do not match the pattern."""
    pattern = re.compile(rf"^{re.escape(game)}-[0-9a-f]{{12}}-{DEFAULT_ENV_KEY}-([0-9a-f]{{16}})$")
    found = []
    for path in (cache / "projects").iterdir():
        match = pattern.match(path.name)
        marker = path / "done.json"
        if match and marker.is_file() and (fingerprint is None or match[1].startswith(fingerprint)):
            found.append((marker.stat().st_mtime, path, match[1]))
    if not found:
        return None
    _, path, fp = max(found)
    return path, fp


def work_cache(cache: Path, work: Path, game: str, fingerprint: str) -> Path:
    """A cache directory of its own whose `projects/` holds symlinks to `game`'s cached projects (its
    separately imported modules included): console_research reads them and writes only into `work`."""
    root = work / "cache"
    (root / "projects").mkdir(parents=True, exist_ok=True)
    (root / "binaries").mkdir(exist_ok=True)
    for path in (cache / "projects").glob(f"{game}*-{fingerprint}"):
        link = root / "projects" / path.name
        if not link.exists():
            link.symlink_to(path)
    return root


def stub_tools(fingerprint: str):
    """console_research.Tools without the binaries: wave_units only needs `fingerprint` to name cached
    projects. A project the cache lacks would be imported with `cli`, which does not exist, so it fails
    (and the module is reported unresolved) instead of importing anything."""
    return types.SimpleNamespace(fingerprint=fingerprint, cli=Path("/nonexistent/romwright-cli"),
                                 env=lambda extra: {})


def game_units(game: str, corpus: Path = CORPUS, cache: Path = CACHE, work: Path | None = None,
               fingerprint: str | None = None, jobs: int = 2) -> dict:
    """Resolve `game` to program units. Returns {game, project, fingerprint, units: [program unit],
    unresolved: [{module, reason, functions}], warnings: [..], platform, truth_kind, modules: {module: n}}
    or {game, error} when there is no cached project or the truth cannot be placed."""
    cr, wave = research()
    found = find_project(cache, game, fingerprint)
    if found is None:
        return {"game": game, "error": f"no finished default-environment project in {cache}/projects"}
    project, fp = found
    specs, skipped = wave.discover(corpus, {game}, 0.0)
    if not specs:
        return {"game": game, "error": f"truth directory unusable: {skipped}"}
    spec = specs[0]
    meta = spec["wave"]["meta"]
    modules = wave.load_modules(corpus / spec["truth"][1], spec["wave"]["modules"])
    marker = json.loads((project / "done.json").read_text())
    work = work or Path.home() / "runs" / "FactEval" / "work" / game
    root = work_cache(cache, work, game, fp)
    try:
        units, unresolved = cr.wave_units(stub_tools(fp), spec, modules, project, marker, corpus / spec["image"],
                                          {}, root, corpus, jobs)
    except (RuntimeError, OSError, KeyError, ValueError) as error:
        return {"game": game, "project": str(project), "fingerprint": fp, "error": f"placement failed: {error}"}
    merged: dict[tuple[str, str], dict] = {}
    warnings = []
    for unit in units:
        real = Path(unit["project"]).resolve() if unit["project"] else project
        entry = modules[unit["module"]]
        key = (str(real), unit["program"])
        target = merged.setdefault(key, {"program": unit["program"], "project": str(real), "modules": [],
                                         "truth": {}, "rows": [], "verified": set(), "ranges": []})
        target["modules"].append(unit["module"])
        target["ranges"] += unit["ranges"]
        for address, value in entry["truth"].items():
            if address not in target["truth"]:
                target["truth"][address] = value
                target["rows"].append((address, value[0], value[1], unit["module"], int(address in entry["verified"])))
        target["verified"] |= entry["verified"]
        if unit.get("warning"):
            warnings.append(f"{unit['module']}: {unit['warning']}")
    return {"game": game, "platform": spec["wave"]["platform"], "truth_kind": meta.get("truth_kind"),
            "compiler": meta.get("compiler"),
            "project": str(project), "fingerprint": fp, "units": list(merged.values()), "unresolved": unresolved,
            "warnings": warnings, "modules": {name: len(entry["truth"]) for name, entry in modules.items()}}


def copy_project(source: str | Path, destination: Path) -> Path:
    """A private copy of a project directory (the commands write to it)."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(destination, ignore_errors=True)
    subprocess.run(["cp", "-a", "--reflink=auto", str(source), str(destination)], check=True)
    return destination


def write_truth_tsv(path: Path, unit: dict) -> int:
    """The unit's truth in the contract's tsv form, filtered to that program (`romwright facts add-donor
    --truth`): every row keeps its module name. Returns the row count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [TSV_HEADER] + [f"{a:#x}\t{size}\t{name}\t{module}\t{verified}"
                            for a, size, name, module, verified in sorted(unit["rows"])]
    path.write_text("\n".join(lines) + "\n")
    return len(unit["rows"])
