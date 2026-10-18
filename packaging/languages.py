#!/usr/bin/env python3
"""Compile and install the SLEIGH languages romwright carries itself.

Ghidra's own processors come out of the release zip as data
(`packaging/ghidra_data.py`). romwright also resolves languages the release does
not have, from sources in this repository:

    PSX:LE:32:default             native/languages/psx   + third_party/ghidra/languages/mips
    r5900:LE:32:default           native/languages/r5900
    RSP:BE:32:default             native/languages/rsp
    VU:LE:64:micro                native/languages/vu
    PowerPC:BE:64:Xenon-32addr    native/languages/xenon + the PowerPC sincs of the Ghidra data
    PowerPC:BE:32:Gekko_Broadway  third_party/ghidra/languages/gamecube

Each is compiled to a `.sla` and installed as an extension module of the Ghidra
data directory, `<ghidra>/Ghidra/Extensions/<Module>/data/languages/`, where
`architecture::discover` finds it with the stock languages. This is the logic of
`native/languages/*/install.sh` (which call this script), in Python so it runs on
Windows, Linux and macOS alike.

The compiler is, in order: `--sleigh`; the `sleigh` of a full Ghidra install at
`--ghidra`; the one in the pinned release zip (`Ghidra/Features/Decompiler/os/
<os>_x86_64/`, extracted into the cache, only for hosts the release ships it
for); else `sleigh_opt` built from the pinned sources by `native/build_sleigh.sh`
(macOS, Linux on ARM).

    python packaging/languages.py --ghidra build/ghidra [--only r5900,xenon] [--force]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
import ghidra_data  # noqa: E402

LANG = ROOT / "native" / "languages"
THIRD = ROOT / "third_party" / "ghidra" / "languages"
MARKER = ".romwright-languages.json"
EXE = ".exe" if os.name == "nt" else ""
# Bump when the install layout changes, so an old installation is redone.
LAYOUT_VERSION = 1

# The stock PowerPC sources xenon.slaspec includes (copied from the Ghidra data;
# the Ghidra install holds them, the repository does not).
XENON_STOCK = (
    "ppc_isa.sinc ppc_a2.sinc quicciii.sinc FPRC.sinc ppc_instructions.sinc ppc_common.sinc "
    "ppc_embedded.sinc 4xx.sinc evx.sinc g2.sinc lmwInstructions.sinc lswInstructions.sinc "
    "mulhwInstructions.sinc ppc_vle.sinc SPE_APU.sinc SPE_EFSD.sinc SPE_EFV.sinc "
    "SPE_FloatMulAdd.sinc SPEF_SCR.sinc Scalar_SPFP.sinc stmwInstructions.sinc "
    "stswiInstructions.sinc vsx.sinc altivec.sinc").split()


class Spec:
    """One language: where its sources come from and what is installed."""

    def __init__(self, name, language_id, module, slaspec, copy_to_stage, install, inputs,
                 extension_properties=None):
        self.name = name
        self.language_id = language_id
        self.module = module
        self.slaspec = slaspec  # file name inside the stage directory
        self.copy_to_stage = copy_to_stage  # [(source path, stage file name)]
        self.install = install  # [(source: "stage" | Path, name)] copied beside the .sla
        self.inputs = inputs  # source trees hashed for the currency marker
        self.extension_properties = extension_properties


def _files(directory: Path, *names: str) -> list:
    return [(directory / name, name) for name in names]


def specs() -> list[Spec]:
    psx = LANG / "psx"
    r5900 = LANG / "r5900"
    xenon = LANG / "xenon"
    mips = THIRD / "mips"
    gamecube = THIRD / "gamecube"
    return [
        Spec("psx", "PSX:LE:32:default", "RomwrightPsx", "psx.slaspec",
             _files(mips, "mips.sinc", "mips32Instructions.sinc", "mipsfloat.sinc")
             + _files(psx, "gte.sinc", "psx.slaspec"),
             # The JVM checks psx.sla against psx.slaspec and its includes, so the staged
             # sources install beside the sla.
             [("stage", name) for name in ("psx.slaspec", "mips.sinc", "mips32Instructions.sinc",
                                           "mipsfloat.sinc", "gte.sinc")]
             + _files(psx, "psx.ldefs", "psx.pspec", "psx.cspec"),
             [psx, mips],
             extension_properties=(
                 "name=RomwrightPsx\n"
                 "description=PlayStation R3000A language with GTE (COP2) definitions, built "
                 "from Ghidra's MIPS32 spec and psx-spx\n"
                 "author=romwright\nversion=12.1.3\n")),
        Spec("r5900", "r5900:LE:32:default", "ghidra-emotionengine-reloaded", "r5900.slaspec",
             [(path, path.name) for path in sorted(r5900.glob("*.sinc"))]
             + _files(r5900, "r5900.slaspec"),
             [("stage", path.name) for path in sorted(r5900.glob("*.sinc"))]
             + _files(r5900, "r5900.slaspec", "r5900.pspec", "r5900.cspec", "emotionengine.ldefs",
                      "r5900.opinion"),
             [r5900]),
        Spec("rsp", "RSP:BE:32:default", "RSP", "rsp.slaspec",
             _files(LANG / "rsp", "rsp.slaspec"),
             _files(LANG / "rsp", "rsp.ldefs", "rsp.pspec", "rsp.cspec"), [LANG / "rsp"]),
        Spec("vu", "VU:LE:64:micro", "VU", "vu.slaspec",
             _files(LANG / "vu", "vu.slaspec"),
             _files(LANG / "vu", "vu.ldefs", "vu.pspec", "vu.cspec"), [LANG / "vu"]),
        Spec("xenon", "PowerPC:BE:64:Xenon-32addr", "Xenon", "xenon.slaspec",
             # The stock sincs are added from the Ghidra data by `stage()`.
             [(path, path.name) for path in sorted(xenon.glob("*.sinc"))]
             + _files(xenon, "xenon.slaspec"),
             _files(xenon, "xenon.ldefs", "ppc_64.pspec", "ppc_64_be.cspec"), [xenon]),
        Spec("gekko", "PowerPC:BE:32:Gekko_Broadway", "RomwrightGekko",
             "ppc_gekko_broadway.slaspec",
             [(path, path.name) for path in sorted(gamecube.glob("*.sinc"))]
             + _files(gamecube, "ppc_gekko_broadway.slaspec"),
             _files(gamecube, "ppc_gekko_broadway.ldefs", "ppc_gekko_broadway.pspec",
                    "ppc_gekko_broadway.cspec"),
             [gamecube]),
    ]


def digest_inputs(selected: list[Spec], ghidra: Path) -> str:
    """Hash of everything the compiled languages depend on: their sources, and for
    Xenon the stock sincs of the Ghidra data."""
    digest = hashlib.sha256(f"layout {LAYOUT_VERSION}\n".encode())
    for spec in selected:
        digest.update(f"[{spec.name}]\n".encode())
        roots = sorted({path for source in spec.inputs for path in source.rglob("*") if path.is_file()})
        for path in roots:
            digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
            digest.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
        if spec.name == "xenon":
            for name in XENON_STOCK:
                stock = _stock_ppc(ghidra) / name
                digest.update(name.encode() + b"\0")
                digest.update(stock.read_bytes() if stock.is_file() else b"missing")
    return digest.hexdigest()


def _stock_ppc(ghidra: Path) -> Path:
    return ghidra / "Ghidra" / "Processors" / "PowerPC" / "data" / "languages"


def installed_ids(ghidra: Path) -> list[str]:
    try:
        return json.loads((ghidra / MARKER).read_text(encoding="utf-8")).get("languages", [])
    except (OSError, ValueError):
        return []


def is_current(ghidra: Path, only: list[str] | None = None) -> bool:
    """True when `ghidra` holds every selected language compiled from the current sources."""
    selected = select(only)
    try:
        marker = json.loads((ghidra / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if marker.get("inputs", {}).get("layout") != LAYOUT_VERSION:
        return False
    for spec in selected:
        entry = marker.get("inputs", {}).get(spec.name)
        if entry != digest_inputs([spec], ghidra):
            return False
        sla = ghidra / "Ghidra" / "Extensions" / spec.module / "data" / "languages"
        if not any(sla.glob("*.sla")):
            return False
    return True


def select(only: list[str] | None) -> list[Spec]:
    chosen = specs()
    if only:
        names = {spec.name for spec in chosen}
        unknown = [name for name in only if name not in names]
        if unknown:
            raise ghidra_data.SetupError(
                f"unknown language {', '.join(unknown)}; choose from {', '.join(sorted(names))}")
        chosen = [spec for spec in chosen if spec.name in only]
    return chosen


# -- the compiler -----------------------------------------------------------

def host_os_dir() -> str | None:
    """The `os/` directory of the Ghidra release that holds a sleigh for this host."""
    machine = platform.machine().lower()
    if machine not in ("x86_64", "amd64"):
        return None
    if sys.platform == "win32":
        return "win_x86_64"
    if sys.platform.startswith("linux"):
        return "linux_x86_64"
    return None


def usable(sleigh: Path) -> bool:
    """True when the compiler starts (it prints usage and exits nonzero with no arguments)."""
    try:
        subprocess.run([str(sleigh)], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def find_sleigh(ghidra: Path, cache_dir: Path, sleigh: Path | None, zip_path: Path | None,
                jobs: int) -> Path:
    if sleigh is not None:
        if not usable(sleigh):
            raise ghidra_data.SetupError(f"--sleigh {sleigh} does not run")
        return sleigh
    os_dir = host_os_dir()
    if os_dir is not None:
        name = f"sleigh{EXE}"
        installed = ghidra / "Ghidra" / "Features" / "Decompiler" / "os" / os_dir / name
        if installed.is_file() and usable(installed):
            return installed
        cached = cache_dir / f"sleigh-{ghidra_data.VERSION}" / os_dir / name
        if cached.is_file() and usable(cached):
            return cached
        archive = zip_path or ghidra_data.download(cache_dir)
        member = f"{ghidra_data.ZIP_ROOT}/Ghidra/Features/Decompiler/os/{os_dir}/{name}"
        cached.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle, bundle.open(member) as source, \
                open(cached, "wb") as sink:
            shutil.copyfileobj(source, sink)
        cached.chmod(0o755)
        if usable(cached):
            print(f"  sleigh compiler: {cached} (from the Ghidra {ghidra_data.VERSION} release)")
            return cached
        print(f"  the release's {name} does not run on this host; building one from source")
    return build_sleigh(cache_dir, jobs)


def build_sleigh(cache_dir: Path, jobs: int) -> Path:
    if os.name == "nt":
        raise ghidra_data.SetupError(
            "no sleigh compiler runs on this Windows host; the Ghidra release ships one for "
            "x86-64 only. Pass --sleigh PATH")
    out = cache_dir / f"sleigh-{ghidra_data.VERSION}" / "source"
    binary = out / "sleigh_opt"
    if binary.is_file() and usable(binary):
        return binary
    print("  building sleigh_opt from third_party/ghidra/decompiler (native/build_sleigh.sh)", flush=True)
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(["bash", str(ROOT / "native" / "build_sleigh.sh"), "--jobs", str(jobs), str(out)],
                   check=True)
    return binary


def git() -> str:
    """`git`, or Git for Windows where it is installed but not on PATH."""
    found = shutil.which("git")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"), r"C:\Program Files"):
        if base and (Path(base) / "Git" / "cmd" / "git.exe").is_file():
            return str(Path(base) / "Git" / "cmd" / "git.exe")
    raise ghidra_data.SetupError("git is needed to apply native/languages/psx/stock-cop2.patch "
                                 "(Git for Windows: https://git-scm.com/download/win)")


def compile_sla(sleigh: Path, stage: Path, slaspec: str) -> Path:
    target = stage / (Path(slaspec).stem + ".sla")
    result = subprocess.run([str(sleigh), str(stage / slaspec), str(target)], cwd=stage,
                            capture_output=True, text=True, errors="replace")
    if result.returncode != 0 or not target.is_file():
        raise ghidra_data.SetupError(
            f"sleigh failed on {slaspec} (exit code {result.returncode}):\n"
            + (result.stdout + result.stderr).strip()[-3000:])
    return target


# -- install ----------------------------------------------------------------

def build_one(spec: Spec, sleigh: Path, ghidra: Path) -> None:
    with tempfile.TemporaryDirectory(prefix=f"romwright-{spec.name}-") as scratch:
        stage = Path(scratch)
        if spec.name == "xenon":
            stock = _stock_ppc(ghidra)
            for name in XENON_STOCK:
                if not (stock / name).is_file():
                    raise ghidra_data.SetupError(f"no PowerPC language source {stock / name}")
                shutil.copy2(stock / name, stage / name)
        for source, name in spec.copy_to_stage:
            shutil.copyfile(source, stage / name)
        if spec.name == "psx":
            patch = LANG / "psx" / "stock-cop2.patch"
            applied = subprocess.run([git(), "apply", "-p1", "--whitespace=nowarn",
                                      "--ignore-space-change", str(patch)], cwd=stage,
                                     capture_output=True, text=True)
            if applied.returncode != 0:
                raise ghidra_data.SetupError(f"git apply stock-cop2.patch failed: {applied.stderr.strip()}")
        if spec.name == "r5900":
            check = subprocess.run([sys.executable, str(LANG / "r5900" / "gen_vu.py"), "--check"],
                                   capture_output=True, text=True)
            if check.returncode != 0:
                raise ghidra_data.SetupError(
                    "r5900's generated sources do not match gen_vu.py:\n" + (check.stdout + check.stderr))
        sla = compile_sla(sleigh, stage, spec.slaspec)

        extension = ghidra / "Ghidra" / "Extensions" / spec.module
        destination = extension / "data" / "languages"
        if spec.name == "psx":
            # A PsxLoader extension from an older setup also registers PSX:LE:32:default; a
            # duplicate id is ambiguous (Ghidra scans every .ldefs below the install), so its
            # languages move outside the scanned tree.
            old = ghidra / "Ghidra" / "Extensions" / "PsxLoader" / "data" / "languages"
            if old.is_dir():
                kept = ghidra / ".romwright-replaced" / "PsxLoader-languages"
                kept.parent.mkdir(parents=True, exist_ok=True)
                shutil.rmtree(kept, ignore_errors=True)
                shutil.move(str(old), str(kept))
        shutil.rmtree(destination, ignore_errors=True)
        destination.mkdir(parents=True)
        if spec.extension_properties is not None:
            # Ghidra's JVM only reads languages from a module: Module.manifest marks one and
            # extension.properties names it.
            (extension / "Module.manifest").write_bytes(b"")
            (extension / "extension.properties").write_text(
                spec.extension_properties, encoding="utf-8", newline="\n")
        shutil.copyfile(sla, destination / sla.name)
        for source, name in spec.install:
            shutil.copyfile(stage / name if source == "stage" else source, destination / name)


def install(ghidra: Path, cache_dir: Path, only: list[str] | None = None, force: bool = False,
            sleigh: Path | None = None, zip_path: Path | None = None, jobs: int = 4) -> str:
    """Compiles and installs the selected languages; returns "kept" or "installed"."""
    ghidra = ghidra.resolve()
    if not (ghidra / "Ghidra").is_dir():
        raise ghidra_data.SetupError(
            f"{ghidra} holds no Ghidra data; run packaging/ghidra_data.py --dest {ghidra} first")
    selected = select(only)
    todo = [spec for spec in selected
            if force or not is_current(ghidra, [spec.name])]
    if not todo:
        return "kept"
    compiler = find_sleigh(ghidra, cache_dir, sleigh, zip_path, jobs)
    print(f"  compiling {', '.join(spec.name for spec in todo)} with {compiler}", flush=True)
    with ThreadPoolExecutor(max_workers=min(len(todo), max(jobs, 1))) as pool:
        for future in [pool.submit(build_one, spec, compiler, ghidra) for spec in todo]:
            future.result()
    try:
        marker = json.loads((ghidra / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        marker = {}
    inputs = marker.get("inputs", {})
    inputs["layout"] = LAYOUT_VERSION
    ids = set(marker.get("languages", []))
    for spec in todo:
        inputs[spec.name] = digest_inputs([spec], ghidra)
        ids.add(spec.language_id)
    (ghidra / MARKER).write_text(json.dumps(
        {"inputs": inputs, "languages": sorted(ids)}, indent=2) + "\n", encoding="utf-8", newline="\n")
    for spec in todo:
        print(f"  installed {spec.language_id} -> Extensions/{spec.module}")
    return "installed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ghidra", type=Path, required=True,
                        help="Ghidra install or extracted data directory to install into")
    parser.add_argument("--only", help="comma-separated subset: psx,r5900,rsp,vu,xenon,gekko")
    parser.add_argument("--force", action="store_true", help="compile again even if current")
    parser.add_argument("--sleigh", type=Path, help="the sleigh compiler to use")
    parser.add_argument("--cache-dir", type=Path, default=ghidra_data.default_cache_dir())
    parser.add_argument("--ghidra-zip", type=Path,
                        help=f"{ghidra_data.ZIP_NAME}, if the sleigh compiler is to be taken from it")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    arguments = parser.parse_args()
    try:
        print(install(arguments.ghidra, arguments.cache_dir,
                      arguments.only.split(",") if arguments.only else None, arguments.force,
                      arguments.sleigh, arguments.ghidra_zip, arguments.jobs))
    except ghidra_data.SetupError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"error: {' '.join(map(str, error.cmd))} failed with exit code {error.returncode}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
