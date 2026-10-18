#!/usr/bin/env python3
"""Set romwright up from a source checkout with one command.

    python setup.py

(`python3 setup.py` on Linux and macOS; Python 3.8+, standard library only.)

It is not a setuptools script: romwright is a Rust workspace, and this file
does what a download of the source needs before `romwright-cli` can decompile:

 1. checks the prerequisites and, for each one missing, says how to get it
    (Rust via rustup; a C++11 compiler, make, zlib and git; on Windows
    MSYS2 MinGW64 with `mingw-w64-x86_64-gcc mingw-w64-x86_64-make
    mingw-w64-x86_64-zlib`, and Git for Windows);
 2. downloads the pinned Ghidra 12.1.3 release (cached, SHA-256 verified) and
    extracts only the language data romwright reads into `build/ghidra`, where
    romwright finds it without an environment variable
    (`packaging/ghidra_data.py`);
 3. builds the patched decompiler `native/build/ghidra_opt`
    (`native/build_ghidra_opt.sh`; on Windows through MSYS2's bash);
 4. runs `cargo build --release -p romwright-cli -p romwright-worker`;
 5. smoke-tests: imports `tests/fixtures-src/tiny_bin` into a temporary project
    and decompiles 00400466, which must print `return param_2 + param_1;`.

Rerunning skips what is done: the Ghidra data when its marker matches, the
download when the cache holds the verified zip, the decompiler when it is newer
than its sources, cargo when nothing changed.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "packaging"))
import ghidra_data  # noqa: E402  (stdlib-only helper shared with the release workflow)

WINDOWS = os.name == "nt"
EXE = ".exe" if WINDOWS else ""
DEFAULT_GHIDRA_DIR = ROOT / "build" / "ghidra"  # runtime_paths::CHECKOUT_GHIDRA
NATIVE_BINARY = ROOT / "native" / "build" / f"ghidra_opt{EXE}"
MSYS_PACKAGES = ("mingw-w64-x86_64-gcc", "mingw-w64-x86_64-make", "mingw-w64-x86_64-zlib")
FIXTURE = ROOT / "tests" / "fixtures-src" / "tiny_bin"
SMOKE_ADDRESS = "00400466"
SMOKE_EXPECTED = "return param_2 + param_1;"
# Sources `native/build_ghidra_opt.sh` builds from: a newer one means a rebuild.
NATIVE_INPUTS = (ROOT / "native" / "build_ghidra_opt.sh", ROOT / "native" / "ghidra-opt-sleigh.patch")
NATIVE_INPUT_TREES = (ROOT / "native", ROOT / "third_party" / "ghidra" / "decompiler")
NATIVE_SUFFIXES = {".cc", ".cpp", ".hh", ".h", ".y", ".l", ".sh", ".patch", ".slaspec"}


class Missing(Exception):
    pass


def say(message: str = "") -> None:
    print(message, flush=True)


def step(number: int, title: str) -> None:
    say(f"\n[{number}/4] {title}")


def run(command: list[str], cwd: Path = ROOT, env: dict | None = None) -> None:
    say("  $ " + " ".join(str(part) for part in command))
    subprocess.run([str(part) for part in command], cwd=cwd, env=env, check=True)


def capture(command: list[str], **kwargs) -> str | None:
    try:
        result = subprocess.run([str(part) for part in command], capture_output=True,
                                text=True, **kwargs)
    except OSError:
        return None
    return result.stdout if result.returncode == 0 else None


# -- prerequisites ---------------------------------------------------------

def find_cargo() -> Path | None:
    found = shutil.which("cargo")
    if found:
        return Path(found)
    candidate = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo") / "bin" / f"cargo{EXE}"
    if candidate.is_file():
        os.environ["PATH"] = str(candidate.parent) + os.pathsep + os.environ.get("PATH", "")
        return candidate
    return None


def workspace_rust_version() -> tuple[int, int]:
    match = re.search(r'^rust-version\s*=\s*"(\d+)\.(\d+)', (ROOT / "Cargo.toml").read_text(
        encoding="utf-8"), re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def check_rust(problems: list[str]) -> None:
    cargo = find_cargo()
    rustup_hint = ("Rust is missing. Install it with rustup: https://rustup.rs "
                   + ("(download and run rustup-init.exe)" if WINDOWS else
                      "(curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)")
                   + ", then open a new terminal.")
    if cargo is None:
        problems.append(rustup_hint)
        return
    version = capture(["rustc", "-vV"]) or ""
    release = re.search(r"^release: (\d+)\.(\d+)", version, re.MULTILINE)
    wanted = workspace_rust_version()
    if release and (int(release.group(1)), int(release.group(2))) < wanted:
        problems.append(f"Rust {release.group(1)}.{release.group(2)} is older than the {wanted[0]}."
                        f"{wanted[1]} this workspace needs. Run: rustup update stable")
    if WINDOWS and "msvc" in version and not shutil.which("link.exe") and not vs_build_tools():
        problems.append(
            "The Rust MSVC toolchain needs the Visual Studio C++ build tools, and none were found.\n"
            "      Install them: winget install Microsoft.VisualStudio.2022.BuildTools --override "
            "\"--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended\"")


def vs_build_tools() -> bool:
    program_files = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    vswhere = Path(program_files) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        return False
    found = capture([vswhere, "-products", "*", "-requires",
                     "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property",
                     "installationPath"])
    return bool(found and found.strip())


def linux_install_hint() -> str:
    release = ""
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8").lower()
    except OSError:
        pass
    ids = " ".join(re.findall(r'^id(?:_like)?="?([^"\n]*)', release, re.MULTILINE))
    if re.search(r"debian|ubuntu", ids):
        return "sudo apt-get install build-essential zlib1g-dev git"
    if re.search(r"fedora|rhel|centos|suse", ids):
        return "sudo dnf install gcc-c++ make zlib-devel git"
    if "arch" in ids:
        return "sudo pacman -S base-devel zlib git"
    if "alpine" in ids:
        return "sudo apk add build-base zlib-dev git bash"
    return "install a C++11 compiler (c++), make, the zlib development files and git"


def check_unix_toolchain(problems: list[str]) -> None:
    hint = ("xcode-select --install   (Command Line Tools: clang++, make, git, zlib), "
            "or brew install git" if sys.platform == "darwin" else linux_install_hint())
    for tool, what in (("c++", "a C++11 compiler (`c++`)"), ("make", "`make`"), ("git", "`git`"),
                       ("bash", "`bash`")):
        if not shutil.which(tool):
            problems.append(f"{what} is missing. Install: {hint}")
    compiler = shutil.which("c++")
    if compiler:
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / "z.cc"
            source.write_text("#include <zlib.h>\nint main() { return zlibVersion() == 0; }\n")
            built = subprocess.run([compiler, "-std=c++11", str(source), "-lz", "-o",
                                    str(Path(scratch) / "z")], capture_output=True)
            if built.returncode != 0:
                problems.append(f"zlib (headers and library) is missing for `{compiler}`. "
                                f"Install: {hint}")


def locate_msys2(explicit: str | None) -> Path | None:
    for candidate in (explicit, os.environ.get("MSYS2_ROOT"), os.environ.get("MSYS2_PATH"),
                      r"C:\msys64"):
        if candidate and (Path(candidate) / "usr" / "bin" / "bash.exe").is_file():
            return Path(candidate)
    return None


def msys_missing_packages(msys2: Path) -> list[str]:
    mingw = msys2 / "mingw64"
    missing = []
    if not (mingw / "bin" / "g++.exe").is_file():
        missing.append("mingw-w64-x86_64-gcc")
    if not (mingw / "bin" / "mingw32-make.exe").is_file():
        missing.append("mingw-w64-x86_64-make")
    if not (mingw / "include" / "zlib.h").is_file():
        missing.append("mingw-w64-x86_64-zlib")
    return missing


def find_windows_git(msys2: Path | None) -> Path | None:
    """Directory holding git.exe: on PATH, in Git for Windows, or in MSYS2."""
    found = shutil.which("git")
    if found:
        return Path(found).parent
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"),
                 r"C:\Program Files", os.environ.get("LOCALAPPDATA") and
                 str(Path(os.environ["LOCALAPPDATA"]) / "Programs")):
        if base and (Path(base) / "Git" / "cmd" / "git.exe").is_file():
            return Path(base) / "Git" / "cmd"
    if msys2 and (msys2 / "usr" / "bin" / "git.exe").is_file():
        return msys2 / "usr" / "bin"
    return None


def install_msys_packages(msys2: Path, packages: list[str]) -> None:
    env = dict(os.environ, MSYSTEM="MINGW64", CHERE_INVOKING="1")
    run([msys2 / "usr" / "bin" / "bash.exe", "-lc",
         "pacman -S --needed --noconfirm " + " ".join(packages)], env=env)


def check_prerequisites(arguments) -> tuple[Path | None, Path | None]:
    """Reports every missing prerequisite at once; returns (msys2, git dir) on Windows."""
    say("Checking prerequisites")
    problems: list[str] = []
    check_rust(problems)
    msys2 = git_dir = None
    if WINDOWS:
        msys2 = locate_msys2(arguments.msys2)
        if msys2 is None:
            problems.append(
                "MSYS2 was not found (looked for C:\\msys64, --msys2 and %MSYS2_ROOT%).\n"
                "      Install it from https://www.msys2.org (or: winget install MSYS2.MSYS2), then in\n"
                "      an MSYS2 MINGW64 shell run: pacman -S --needed " + " ".join(MSYS_PACKAGES))
        else:
            missing = msys_missing_packages(msys2)
            if missing and arguments.install_msys2_packages:
                install_msys_packages(msys2, missing)
                missing = msys_missing_packages(msys2)
            if missing:
                problems.append(
                    f"MSYS2 ({msys2}) lacks packages: {', '.join(missing)}.\n"
                    "      In an MSYS2 MINGW64 shell run: pacman -S --needed " + " ".join(MSYS_PACKAGES)
                    + "\n      (or rerun this script with --install-msys2-packages)")
        git_dir = find_windows_git(msys2)
        if git_dir is None:
            problems.append("Git is missing. Install Git for Windows: https://git-scm.com/download/win "
                            "(or: winget install Git.Git)")
    else:
        check_unix_toolchain(problems)
    if problems:
        say("\nMissing prerequisites:")
        for number, problem in enumerate(problems, 1):
            say(f"  {number}. {problem}")
        raise Missing("install the above and run this script again")
    say("  rust:     " + (capture(["rustc", "--version"]) or "?").strip())
    if WINDOWS:
        say(f"  msys2:    {msys2} (mingw64 gcc, make, zlib present)")
        say(f"  git:      {git_dir}")
    else:
        say(f"  c++:      {shutil.which('c++')}   make: {shutil.which('make')}   zlib: ok")
    return msys2, git_dir


# -- steps -----------------------------------------------------------------

def provision_ghidra(arguments) -> None:
    dest = arguments.ghidra_dir.resolve()
    if os.environ.get("ROMWRIGHT_GHIDRA") and Path(os.environ["ROMWRIGHT_GHIDRA"]).resolve() != dest:
        say(f"  note: ROMWRIGHT_GHIDRA={os.environ['ROMWRIGHT_GHIDRA']} is set and overrides "
            f"{dest} when romwright runs")
    if arguments.skip_ghidra:
        say("  skipped (--skip-ghidra)")
        return
    result = ghidra_data.provision(dest, arguments.cache_dir, arguments.ghidra_zip,
                                   arguments.force_ghidra)
    if result == "kept":
        say(f"  already extracted: {dest}")
    say(f"  Ghidra {ghidra_data.VERSION} language data: {dest}")


def newest_native_source() -> float:
    newest = 0.0
    for path in NATIVE_INPUTS:
        newest = max(newest, path.stat().st_mtime)
    for tree in NATIVE_INPUT_TREES:
        for base, directories, files in os.walk(tree):
            directories[:] = [d for d in directories if d != "build"]
            for name in files:
                if Path(name).suffix in NATIVE_SUFFIXES:
                    newest = max(newest, (Path(base) / name).stat().st_mtime)
    return newest


def build_native(arguments, msys2: Path | None, git_dir: Path | None) -> None:
    if arguments.skip_native:
        say("  skipped (--skip-native)")
        return
    if (NATIVE_BINARY.is_file() and not arguments.rebuild_native
            and NATIVE_BINARY.stat().st_mtime >= newest_native_source()):
        say(f"  up to date: {NATIVE_BINARY}")
        return
    jobs = str(arguments.jobs)
    if WINDOWS:
        # MSYS2's login shell with MSYSTEM=MINGW64 puts mingw64/bin first on PATH;
        # Git for Windows is appended for the `git apply` the script does.
        script = ('export PATH="$PATH:$(cygpath -u "$RW_GIT_DIR")"; '
                  'TMPDIR=$(cygpath -u "$RW_TMP") bash native/build_ghidra_opt.sh --jobs "$RW_JOBS"')
        env = dict(os.environ, MSYSTEM="MINGW64", CHERE_INVOKING="1", RW_JOBS=jobs,
                   RW_GIT_DIR=str(git_dir), RW_TMP=tempfile.gettempdir())
        run([msys2 / "usr" / "bin" / "bash.exe", "-lc", script], env=env)
    else:
        run(["bash", "native/build_ghidra_opt.sh", "--jobs", jobs])
    if not NATIVE_BINARY.is_file():
        raise SystemExit(f"error: the native build did not produce {NATIVE_BINARY}")
    say(f"  built: {NATIVE_BINARY}")


def cargo_target_dir() -> Path:
    out = capture(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT)
    if out:
        return Path(json.loads(out)["target_directory"])
    return Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")


def build_rust(arguments) -> Path:
    if not arguments.skip_cargo:
        run(["cargo", "build", "--release", "-p", "romwright-cli", "-p", "romwright-worker"])
    else:
        say("  skipped (--skip-cargo)")
    release = cargo_target_dir() / "release"
    for name in ("romwright-cli", "romwright-worker"):
        if not (release / f"{name}{EXE}").is_file():
            raise SystemExit(f"error: {release / (name + EXE)} is missing; run without --skip-cargo")
    say(f"  binaries: {release}")
    return release


def smoke_test(arguments, release: Path) -> None:
    if arguments.skip_smoke:
        say("  skipped (--skip-smoke)")
        return
    # romwright must find its own files by default, so the environment it runs
    # in carries no ROMWRIGHT_* variable -- except the Ghidra directory when the
    # data was put somewhere other than the default on request.
    env = {key: value for key, value in os.environ.items() if not key.startswith("ROMWRIGHT_")}
    env["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    if arguments.ghidra_dir.resolve() != DEFAULT_GHIDRA_DIR.resolve():
        env["ROMWRIGHT_GHIDRA"] = str(arguments.ghidra_dir.resolve())
        say(f"  ROMWRIGHT_GHIDRA={env['ROMWRIGHT_GHIDRA']} (custom --ghidra-dir)")
    else:
        say("  no ROMWRIGHT_* variable set: romwright resolves its files by default")
    cli = release / f"romwright-cli{EXE}"
    with tempfile.TemporaryDirectory(prefix="romwright-smoke-") as project:
        for command in ([cli, "import", FIXTURE, "--project", project],
                        [cli, "decompile", FIXTURE, SMOKE_ADDRESS, "--project", project]):
            say("  $ " + " ".join(str(part) for part in command))
            result = subprocess.run([str(part) for part in command], cwd=project, env=env,
                                    capture_output=True, text=True, errors="replace")
            if result.returncode != 0:
                say(result.stdout)
                say(result.stderr)
                raise SystemExit(f"error: `{command[1]}` failed with exit code {result.returncode}")
            output = result.stdout
        say("  " + "\n  ".join(output.rstrip().splitlines()))
    if SMOKE_EXPECTED not in output:
        raise SystemExit(f"error: the decompile of {SMOKE_ADDRESS} lacks `{SMOKE_EXPECTED}`")
    say(f"  ok: decompiled {SMOKE_ADDRESS} to `{SMOKE_EXPECTED}`")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="check the prerequisites and stop")
    parser.add_argument("--ghidra-dir", type=Path, default=DEFAULT_GHIDRA_DIR,
                        help="where the Ghidra language data is extracted (default: %(default)s; "
                             "any other place needs ROMWRIGHT_GHIDRA to point at it)")
    parser.add_argument("--cache-dir", type=Path, default=ghidra_data.default_cache_dir(),
                        help="where the Ghidra zip is kept (default: %(default)s)")
    parser.add_argument("--ghidra-zip", type=Path,
                        help=f"use this {ghidra_data.ZIP_NAME} instead of downloading it")
    parser.add_argument("--force-ghidra", action="store_true", help="extract the Ghidra data again")
    parser.add_argument("--msys2", help=r"MSYS2 root on Windows (default: C:\msys64, %%MSYS2_ROOT%%)")
    parser.add_argument("--install-msys2-packages", action="store_true",
                        help="Windows: run pacman for the missing MinGW64 packages")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2,
                        help="parallel jobs for the native build (default: %(default)s)")
    parser.add_argument("--rebuild-native", action="store_true", help="rebuild ghidra_opt")
    for name, what in (("ghidra", "the Ghidra download and extraction"),
                       ("native", "building ghidra_opt"), ("cargo", "cargo build"),
                       ("smoke", "the smoke test")):
        parser.add_argument(f"--skip-{name}", action="store_true", help=f"skip {what}")
    arguments = parser.parse_args()

    say(f"romwright setup ({platform.system()} {platform.machine()}, Python {platform.python_version()})")
    try:
        msys2, git_dir = check_prerequisites(arguments)
        if arguments.check:
            return 0
        step(1, "Ghidra language data")
        provision_ghidra(arguments)
        step(2, "native decompiler (ghidra_opt)")
        build_native(arguments, msys2, git_dir)
        step(3, "romwright-cli and romwright-worker")
        release = build_rust(arguments)
        step(4, "smoke test")
        smoke_test(arguments, release)
        say("\nromwright is set up.")
    except Missing as error:
        say(f"\nerror: {error}")
        return 2
    except ghidra_data.SetupError as error:
        say(f"\nerror: {error}")
        return 1
    except subprocess.CalledProcessError as error:
        say(f"\nerror: a step failed (exit code {error.returncode}): {' '.join(map(str, error.cmd))}")
        return 1
    cli = release / f"romwright-cli{EXE}"
    say(f"  romwright-cli: {cli}")
    say("  try:  " + f"{cli} decompile {FIXTURE} {SMOKE_ADDRESS}")
    say(f"  put {release} on PATH to run romwright-cli from anywhere; docs/getting-started.md "
        "walks through a first project.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
