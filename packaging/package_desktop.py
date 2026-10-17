#!/usr/bin/env python3
"""Build and package the desktop workstation as a relocatable archive.

`cargo build --profile dist` (the shipping profile, `Cargo.toml`) produces
`romwright-desktop` (Core, worker client and
renderer statically linked, fonts embedded), the `romwright-worker` it spawns
for decompilation and the `romwright-cli` it runs for **Create project**
(`new-project`; the CLI carries the project templates and the tool manifest).
This writes all three into
`romwright-<version>-<system>-<machine>.tar.gz` -- the name `stage_release.py`
looks for -- under a single top-level directory:

    romwright-<version>-<system>-<machine>/
        bin/romwright-desktop[.exe]
        bin/romwright-worker[.exe]
        bin/romwright-cli[.exe]
        share/doc/romwright/LICENSE, NOTICE, THIRD_PARTY_NOTICES.md
        share/doc/romwright/fonts/*-OFL.txt

The worker and the CLI sit beside the app because the app looks for them there
first, so the archive extracts and runs from any directory. Prints the archive
path.
"""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# What ships is built with the `dist` profile: fat LTO, one code-generation unit
# (`Cargo.toml`); `release` is the faster-to-build development profile.
PROFILE = "dist"
BINARIES = ("romwright-desktop", "romwright-worker", "romwright-cli")
DOCUMENTS = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
FONTS = ROOT / "crates" / "romwright-desktop" / "assets" / "fonts"


def version() -> str:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    return manifest["workspace"]["package"]["version"]


def target_dir() -> Path:
    configured = os.environ.get("CARGO_TARGET_DIR")
    return Path(configured).resolve() if configured else ROOT / "target"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=target_dir() / "package",
                        help="directory the archive is written to")
    parser.add_argument("--no-build", action="store_true",
                        help="package the existing dist build without running cargo")
    arguments = parser.parse_args()

    if not arguments.no_build:
        command = ["cargo", "build", "--profile", PROFILE]
        for binary in BINARIES:
            command += ["-p", binary]
        subprocess.run(command, cwd=ROOT, check=True)

    suffix = ".exe" if os.name == "nt" else ""
    built = target_dir() / PROFILE
    executables = [built / f"{binary}{suffix}" for binary in BINARIES]
    missing = [str(path) for path in executables if not path.is_file()]
    if missing:
        print(f"error: not built: {', '.join(missing)}", file=sys.stderr)
        return 1

    name = f"romwright-{version()}-{platform.system()}-{platform.machine()}"
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{name}.tar.gz"
    documents = [(ROOT / document, f"share/doc/romwright/{document}")
                 for document in DOCUMENTS]
    documents += [(path, f"share/doc/romwright/fonts/{path.name}")
                  for path in sorted(FONTS.glob("*-OFL.txt"))]

    def executable(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mode = 0o755
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    def regular(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mode = 0o644
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    partial = archive.with_name(archive.name + ".partial")
    with tarfile.open(partial, "w:gz") as bundle:
        for path in executables:
            bundle.add(path, f"{name}/bin/{path.name}", filter=executable)
        for path, member in documents:
            bundle.add(path, f"{name}/{member}", filter=regular)
    partial.replace(archive)
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
