#!/usr/bin/env python3
"""Assemble the portable romwright archive from built artifacts.

    python packaging/stage_portable.py --binaries target/dist --ghidra-opt native/build/ghidra_opt \\
        --ghidra-data build/ghidra --output dist-portable [--smoke]

writes `romwright-<version>-<os>-<arch>.zip` (Windows) or `.tar.gz` and a
`.sha256` file beside it. The archive has one top-level directory that unpacks
and runs from anywhere with no environment variable, because the runtime looks
for its files relative to the running executable first
(`crates/romwright-core/src/runtime_paths.rs`, `docs/environment.md`):

    romwright-<version>-<os>-<arch>/
        bin/romwright-cli[.exe]  bin/romwright-worker[.exe]  bin/ghidra_opt[.exe]
        share/romwright/specs/                      native/specs
        share/romwright/library-prototypes-v1/      oracle/library-prototypes-v1
        share/romwright/ghidra/                     Ghidra 12.1.3 language data subset
        share/doc/romwright/                        LICENSE, NOTICE, THIRD_PARTY_NOTICES.md,
                                                    GHIDRA-LICENSE (Apache-2.0)

`--smoke` then unpacks the archive into a temporary directory and, from a
working directory outside any checkout and with every ROMWRIGHT_* variable
removed, imports `tests/fixtures-src/tiny_bin` and decompiles 00400466. The
release workflow runs exactly this on each platform before it uploads.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
import ghidra_data  # noqa: E402

EXE = ".exe" if os.name == "nt" else ""
DOCUMENTS = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
FIXTURE = ROOT / "tests" / "fixtures-src" / "tiny_bin"
SMOKE_ADDRESS = "00400466"
SMOKE_EXPECTED = "return param_2 + param_1;"

README = """romwright {version} ({os}-{arch})

Unpack anywhere and run bin/{cli}. Nothing needs installing and no environment
variable needs setting: the decompiler (bin/ghidra_opt), the language specs and
the Ghidra {ghidra} language data are found relative to the executable
(share/romwright/).

    bin/{cli} import <binary> --project <dir>
    bin/{cli} decompile <binary> <address> --project <dir>

Put bin/ on PATH to run romwright-cli from anywhere. Licences: share/doc/romwright/.
"""


def version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^\[workspace\.package\][^\[]*?^version\s*=\s*"([^"]+)"', text,
                      re.MULTILINE | re.DOTALL)
    if not match:
        raise SystemExit("error: no [workspace.package] version in Cargo.toml")
    return match.group(1)


def os_name() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def arch_name() -> str:
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64",
            "aarch64": "aarch64"}.get(machine, machine)


def need(path: Path, what: str) -> Path:
    if not path.exists():
        raise SystemExit(f"error: {what} not found: {path}")
    return path


def stage(arguments, staging: Path, name: str) -> Path:
    top = staging / name
    bin_dir, share, doc = top / "bin", top / "share" / "romwright", top / "share" / "doc" / "romwright"
    for directory in (bin_dir, share, doc):
        directory.mkdir(parents=True)
    for binary in ("romwright-cli", "romwright-worker"):
        shutil.copy2(need(arguments.binaries / f"{binary}{EXE}", f"{binary} (cargo build --profile dist)"),
                     bin_dir / f"{binary}{EXE}")
    shutil.copy2(need(arguments.ghidra_opt, "ghidra_opt (native/build_ghidra_opt.sh)"),
                 bin_dir / f"ghidra_opt{EXE}")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(need(arguments.specs, "spec bundles"), share / "specs", ignore=ignore)
    shutil.copytree(need(arguments.prototypes, "library prototypes"),
                    share / "library-prototypes-v1", ignore=ignore)
    data = need(arguments.ghidra_data, "Ghidra language data (packaging/ghidra_data.py)")
    if not ghidra_data.is_installed(data):
        raise SystemExit(f"error: {data} is not a complete extraction of the pinned Ghidra "
                         f"{ghidra_data.VERSION} data; run packaging/ghidra_data.py --dest {data}")
    shutil.copytree(data, share / "ghidra")
    for document in DOCUMENTS:
        shutil.copy2(need(ROOT / document, document), doc / document)
    shutil.copy2(share / "ghidra" / "LICENSE", doc / "GHIDRA-LICENSE")
    if (share / "ghidra" / "NOTICE").is_file():
        shutil.copy2(share / "ghidra" / "NOTICE", doc / "GHIDRA-NOTICE")
    (top / "README.txt").write_text(README.format(
        version=arguments.version, os=arguments.os, arch=arguments.arch,
        cli=f"romwright-cli{EXE}", ghidra=ghidra_data.VERSION), encoding="utf-8", newline="\n")
    return top


def pack(top: Path, output: Path, windows: bool) -> Path:
    name = top.name
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (f"{name}.zip" if windows else f"{name}.tar.gz")
    partial = archive.with_name(archive.name + ".partial")
    files = sorted(path for path in top.rglob("*") if path.is_file())
    if windows:
        with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for path in files:
                bundle.write(path, f"{name}/{path.relative_to(top).as_posix()}")
    else:
        def clean(info: tarfile.TarInfo) -> tarfile.TarInfo:
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if info.name.split("/")[1:2] == ["bin"] else 0o644
            return info

        with tarfile.open(partial, "w:gz", compresslevel=9) as bundle:
            for path in files:
                bundle.add(path, f"{name}/{path.relative_to(top).as_posix()}", filter=clean)
    partial.replace(archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n")
    return archive


def smoke(archive: Path, name: str) -> None:
    """Unpacks the archive away from any checkout and decompiles the fixture."""
    with tempfile.TemporaryDirectory(prefix="romwright-portable-") as scratch:
        scratch_dir = Path(scratch)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(scratch_dir / "unpacked")
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(scratch_dir / "unpacked")
        cli = scratch_dir / "unpacked" / name / "bin" / f"romwright-cli{EXE}"
        project = scratch_dir / "project"
        project.mkdir()
        env = {key: value for key, value in os.environ.items() if not key.startswith("ROMWRIGHT_")}
        env["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
        output = ""
        for command in ([cli, "import", FIXTURE, "--project", project],
                        [cli, "decompile", FIXTURE, SMOKE_ADDRESS, "--project", project]):
            print("  $ " + " ".join(str(part) for part in command), flush=True)
            result = subprocess.run([str(part) for part in command], cwd=project, env=env,
                                    capture_output=True, text=True, errors="replace")
            if result.returncode != 0:
                print(result.stdout, result.stderr, sep="\n", file=sys.stderr)
                raise SystemExit(f"error: `{command[1]}` from the unpacked archive failed "
                                 f"(exit code {result.returncode})")
            output = result.stdout
        print("  " + "\n  ".join(output.rstrip().splitlines()))
        if SMOKE_EXPECTED not in output:
            raise SystemExit(f"error: the unpacked archive did not decompile {SMOKE_ADDRESS} "
                             f"to `{SMOKE_EXPECTED}`")
        print(f"  ok: the unpacked archive decompiled {SMOKE_ADDRESS}")


def main() -> int:
    target = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binaries", type=Path, default=target / "dist",
                        help="directory holding romwright-cli and romwright-worker (default: %(default)s)")
    parser.add_argument("--ghidra-opt", type=Path, default=ROOT / "native" / "build" / f"ghidra_opt{EXE}")
    parser.add_argument("--ghidra-data", type=Path, default=ROOT / "build" / "ghidra",
                        help="extracted Ghidra language data (packaging/ghidra_data.py)")
    parser.add_argument("--specs", type=Path, default=ROOT / "native" / "specs")
    parser.add_argument("--prototypes", type=Path, default=ROOT / "oracle" / "library-prototypes-v1")
    parser.add_argument("--output", type=Path, default=ROOT / "dist-portable")
    parser.add_argument("--version", default=version(), help="default: the workspace version")
    parser.add_argument("--os", default=os_name())
    parser.add_argument("--arch", default=arch_name())
    parser.add_argument("--smoke", action="store_true",
                        help="unpack the archive elsewhere and decompile the tiny fixture with it")
    arguments = parser.parse_args()

    name = f"romwright-{arguments.version}-{arguments.os}-{arguments.arch}"
    with tempfile.TemporaryDirectory(prefix="romwright-stage-") as staging:
        top = stage(arguments, Path(staging), name)
        archive = pack(top, arguments.output.resolve(), arguments.os == "windows")
    print(f"{archive} ({archive.stat().st_size / 1e6:.1f} MB)")
    if arguments.smoke:
        smoke(archive, name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
