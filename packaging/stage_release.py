#!/usr/bin/env python3
"""Copy the built release artifacts into one directory.

Release artifacts have platform-specific names -- `.exe` suffixes, a CPack
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
PACKAGE_SUFFIXES = (".tar.gz", ".zip", ".dmg")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path,
                        default=Path(os.environ.get("ROMWRIGHT_RELEASE_DIR", "release")))
    parser.add_argument("--binaries", type=Path, default=ROOT / "target" / "release")
    parser.add_argument("--package", type=Path, default=None,
                        help="CPack build directory holding the desktop archive")
    arguments = parser.parse_args()

    release = arguments.release.resolve()
    release.mkdir(parents=True, exist_ok=True)
    staged = []
    for name in BINARIES:
        candidates = [arguments.binaries / name, arguments.binaries / f"{name}.exe"]
        source = next((path for path in candidates if path.is_file()), None)
        if source is None:
            print(f"error: {name} is not built under {arguments.binaries}",
                  file=sys.stderr)
            return 1
        shutil.copy2(source, release / source.name)
        staged.append(source.name)

    if arguments.package is not None:
        archives = [path for path in sorted(arguments.package.iterdir())
                    if path.is_file() and path.name.startswith("romwright-")
                    and any(path.name.endswith(suffix) for suffix in PACKAGE_SUFFIXES)]
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
