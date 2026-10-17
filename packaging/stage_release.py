#!/usr/bin/env python3
"""Copy the built release artifacts into one directory.

The binaries come from the `dist` build (`cargo build --profile dist`,
`Cargo.toml`), the service from `dist-service`: what ships is not the
development `release` profile.

Release artifacts have platform-specific names -- `.exe` suffixes, a desktop
archive named after the system and processor -- so the set cannot be a
hand-written list in a document. This stages whatever the build produced and
prints what it staged.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARIES = ("romwright-cli", "romwright-api", "romwright-worker")
TARGET = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")
# The profile directory each binary is built into; the long-lived service is
# size-optimised (`Cargo.toml`, docs/releasing.md).
PROFILES = {"romwright-api": "dist-service"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path,
                        default=Path(os.environ.get("ROMWRIGHT_RELEASE_DIR", "release")))
    parser.add_argument("--binaries", type=Path, default=None,
                        help="one directory holding every binary; by default each is read from "
                             "its profile's directory under the target directory")
    parser.add_argument("--package", type=Path, default=None,
                        help="directory holding the archive packaging/package_desktop.py wrote")
    arguments = parser.parse_args()

    release = arguments.release.resolve()
    release.mkdir(parents=True, exist_ok=True)
    staged = []
    for name in BINARIES:
        directory = arguments.binaries or TARGET / PROFILES.get(name, "dist")
        candidates = [directory / name, directory / f"{name}.exe"]
        source = next((path for path in candidates if path.is_file()), None)
        if source is None:
            print(f"error: {name} is not built under {directory}",
                  file=sys.stderr)
            return 1
        shutil.copy2(source, release / source.name)
        staged.append(source.name)

    if arguments.package is not None:
        archives = [path for path in arguments.package.glob("romwright-*.tar.gz")
                    if path.is_file()]
        if not archives:
            print(f"error: no desktop archive under {arguments.package}",
                  file=sys.stderr)
            return 1
        newest = max(archives, key=lambda path: path.stat().st_mtime)
        shutil.copy2(newest, release / newest.name)
        staged.append(newest.name)

    print(f"staged {len(staged)} artifacts in {release}: {', '.join(staged)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
