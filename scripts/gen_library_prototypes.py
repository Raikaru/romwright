#!/usr/bin/env python3
"""Exports the C library declarations a pinned Ghidra type archive holds.

Oracle-only: this runs the JVM once, against the pinned install, and commits
the table it produces. The runtime never reads the packed archive -- a Ghidra
database parser in the JVM-free path would be a lot of format for one table of
names -- so the table is the durable artifact, carrying the archive's hash so
a changed archive is a failure rather than a silent drift.

Usage:
    python3 scripts/gen_library_prototypes.py [--ghidra DIR] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "scripts/ExportLibraryPrototypes.java"
OUTPUT = ROOT / "oracle/library-prototypes-v1/generic_clib_64.json"
# The 64-bit archive: the corpus rows this feeds are LP64 ELF images. The
# vendored 32-bit archive is the same shape when a 32-bit row needs it.
ARCHIVE = "Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt"


def export(install: Path, archive: Path, timeout: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="library-prototypes-") as directory:
        work = Path(directory)
        output = work / "prototypes.json"
        command = [str(install / "support/analyzeHeadless"), str(work), "library-prototypes",
                   "-scriptPath", str(EXPORTER.parent), "-postScript", EXPORTER.stem,
                   str(archive), str(output), ARCHIVE, "-deleteProject"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True,
                                   start_new_session=True,
                                   env=dict(os.environ, DEBUGINFOD_URLS=""))
        try:
            log, _ = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        if process.returncode or not output.is_file():
            raise SystemExit(f"archive export failed:\n{log[-4000:]}")
        return json.loads(output.read_text())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--check", action="store_true",
                        help="verify the committed table against the archive")
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    archive = arguments.ghidra / ARCHIVE
    if not archive.is_file():
        raise SystemExit(f"the pinned archive is missing: {archive}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    if arguments.check:
        if not OUTPUT.is_file():
            raise SystemExit(f"{OUTPUT.relative_to(ROOT)} is missing")
        table = json.loads(OUTPUT.read_text())
        if table.get("archive_sha256") != digest:
            raise SystemExit(
                f"{archive.name} changed since the table was exported: "
                f"{digest} against {table.get('archive_sha256')}")
        print(f"{OUTPUT.relative_to(ROOT)} matches {archive.name} "
              f"({len(table['functions'])} declarations)")
        return 0

    table = export(arguments.ghidra, archive, arguments.timeout)
    if table.get("archive_sha256") != digest:
        raise SystemExit("the exporter hashed a different archive than this one")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    # Compact: 6,600 declarations are a table, not a document to read.
    OUTPUT.write_text(json.dumps(table, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(table['functions'])} declarations "
          f"from {archive.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
