#!/usr/bin/env python3
"""Fetch the pinned Ghidra release and extract the data romwright reads.

romwright never runs Ghidra. It reads the SLEIGH language data of the pinned
Ghidra 12.1.3 release -- `Ghidra/Processors/<processor>/data/**`: the compiled
`.sla` files, `.ldefs`, `.pspec`, `.cspec`, `.opinion` and pattern files, plus
the `.slaspec`/`.sinc` sources the language installers (`native/languages/`)
link against -- and nothing else (`crates/romwright-core/src/architecture.rs`,
`native_runtime/lift.rs`, `opinion.rs`). The 569 MB release zip is downloaded
once into a per-user cache (streamed, resumed, SHA-256 verified), and only that
subset (about 28 MB, without `data/manuals`) plus Ghidra's `LICENSE` is
extracted into the install directory romwright is pointed at:

    <dest>/LICENSE
    <dest>/Ghidra/Processors/<processor>/data/...

Used by `setup.py` (source checkout, `<repo>/build/ghidra`) and by the release
workflow (`share/romwright/ghidra` of the archive). Standard library only.

    python packaging/ghidra_data.py --dest build/ghidra
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

VERSION = "12.1.3"
ZIP_NAME = "ghidra_12.1.3_PUBLIC_20260817.zip"
URL = ("https://github.com/NationalSecurityAgency/ghidra/releases/download/"
       f"Ghidra_{VERSION}_build/{ZIP_NAME}")
SHA256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
SIZE = 569445154
# Top-level directory inside the zip.
ZIP_ROOT = "ghidra_12.1.3_PUBLIC"
MARKER = ".romwright-ghidra.json"
# Bump when `wanted` changes what is extracted, so an old extraction is redone.
SUBSET_VERSION = 1
# A file every extraction must hold; the x86-64 language is romwright's default.
SENTINEL = "Ghidra/Processors/x86/data/languages/x86-64.sla"
# Files at the zip root that are copied (Apache-2.0 requires the licence text).
ROOT_FILES = ("LICENSE", "NOTICE")


class SetupError(Exception):
    """A failure to report to the user without a traceback."""


def default_cache_dir() -> Path:
    """`%LOCALAPPDATA%\\romwright\\cache`, `~/Library/Caches/romwright`, or
    `$XDG_CACHE_HOME/romwright` (`~/.cache/romwright`)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "romwright" / "cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "romwright"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "romwright"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _progress(done: int, total: int, started: float, state: dict) -> None:
    percent = done * 100 // total if total else 0
    if sys.stderr.isatty():
        sys.stderr.write(f"\r  {done / 1e6:7.1f} / {total / 1e6:.1f} MB ({percent}%)")
        sys.stderr.flush()
    elif percent >= state.get("next", 0):
        rate = done / max(time.monotonic() - started, 1e-6) / 1e6
        print(f"  {percent}% ({done / 1e6:.0f} / {total / 1e6:.0f} MB, {rate:.1f} MB/s)",
              flush=True)
        state["next"] = percent + 10


def _fetch(url: str, part: Path, size: int) -> None:
    """Streams `url` into `part`, resuming from what `part` already holds."""
    have = part.stat().st_size if part.exists() else 0
    if have > size:
        part.unlink()
        have = 0
    headers = {"User-Agent": "romwright-setup"}
    if have:
        headers["Range"] = f"bytes={have}-"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        if have and response.status != 206:
            have = 0  # the server ignored the range: start over
        mode = "ab" if have else "wb"
        started = time.monotonic()
        state: dict = {}
        with open(part, mode) as out:
            done = have
            while True:
                block = response.read(1 << 20)
                if not block:
                    break
                out.write(block)
                done += len(block)
                _progress(done, size, started, state)
    if sys.stderr.isatty():
        sys.stderr.write("\n")


def download(cache_dir: Path, url: str = URL, sha256: str = SHA256, size: int = SIZE,
             name: str = ZIP_NAME, attempts: int = 4) -> Path:
    """Returns the verified zip in `cache_dir`, downloading it only when the
    cache holds no copy with the pinned digest."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / name
    if target.is_file():
        if sha256_of(target) == sha256:
            print(f"  cached: {target}")
            return target
        print(f"  cached copy fails its SHA-256; discarding {target}")
        target.unlink()
    part = target.with_name(name + ".part")
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        print(f"  downloading {url} (attempt {attempt}/{attempts})", flush=True)
        try:
            _fetch(url, part, size)
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            last = error
            print(f"  download interrupted: {error}", flush=True)
            time.sleep(min(2 * attempt, 10))
            continue
        digest = sha256_of(part)
        if digest == sha256:
            part.replace(target)
            print(f"  verified SHA-256 {digest}")
            return target
        # Not a prefix of the pinned file: a resume would only extend the damage.
        part.unlink()
        last = SetupError(f"SHA-256 mismatch: got {digest}, expected {sha256}")
        print(f"  {last}", flush=True)
    raise SetupError(f"could not download {url}: {last}\n"
                     f"  download {ZIP_NAME} yourself, check its SHA-256 is {sha256}, and pass it "
                     f"with --ghidra-zip")


def wanted(member: str) -> str | None:
    """The install-relative path a zip member is extracted to, or None.

    Keeps `Ghidra/Processors/<processor>/data/**` except `data/manuals/`, and
    the root licence files.
    """
    parts = PurePosixPath(member).parts
    if not parts or parts[0] != ZIP_ROOT or ".." in parts or member.endswith("/"):
        return None
    rest = parts[1:]
    if len(rest) == 1 and rest[0] in ROOT_FILES:
        return rest[0]
    if (len(rest) >= 5 and rest[0] == "Ghidra" and rest[1] == "Processors"
            and rest[3] == "data" and rest[4] != "manuals"):
        return "/".join(rest)
    return None


def is_installed(dest: Path, sha256: str = SHA256) -> bool:
    try:
        marker = json.loads((dest / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (marker.get("version") == VERSION and marker.get("sha256") == sha256
            and marker.get("subset") == SUBSET_VERSION and (dest / SENTINEL).is_file())


def _move_directory(source: Path, dest: Path) -> None:
    """Renames `source` to `dest`. Windows refuses to rename a directory a virus
    scanner or an indexer is still reading (WinError 5), so retry, and copy when
    the rename keeps failing."""
    for attempt in range(10):
        try:
            source.replace(dest)
            return
        except PermissionError:
            time.sleep(0.5 * (attempt + 1))
    shutil.copytree(source, dest)
    shutil.rmtree(source, ignore_errors=True)


def extract(zip_path: Path, dest: Path, sha256: str = SHA256) -> int:
    """Extracts the subset into `dest` (replacing it); returns the file count."""
    dest = dest.resolve()
    staging = dest.with_name(dest.name + f".partial-{os.getpid()}")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    count = 0
    try:
        with zipfile.ZipFile(zip_path) as archive:
            for info in archive.infolist():
                relative = wanted(info.filename)
                if relative is None:
                    continue
                out = staging / relative
                out.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, open(out, "wb") as sink:
                    shutil.copyfileobj(source, sink, 1 << 20)
                count += 1
        if not (staging / SENTINEL).is_file():
            raise SetupError(f"{zip_path} does not hold {SENTINEL}: not the pinned Ghidra release")
        (staging / MARKER).write_text(json.dumps(
            {"version": VERSION, "sha256": sha256, "subset": SUBSET_VERSION, "files": count},
            indent=2) + "\n", encoding="utf-8")
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        _move_directory(staging, dest)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return count


def provision(dest: Path, cache_dir: Path, zip_path: Path | None = None,
              force: bool = False) -> str:
    """Makes `dest` hold the Ghidra data; returns "kept" or "extracted"."""
    if not force and is_installed(dest):
        return "kept"
    if zip_path is not None:
        digest = sha256_of(zip_path)
        if digest != SHA256:
            raise SetupError(f"{zip_path} has SHA-256 {digest}, expected {SHA256} "
                             f"({ZIP_NAME} from the Ghidra {VERSION} release)")
    else:
        zip_path = download(cache_dir)
    print(f"  extracting the language data to {dest}")
    count = extract(zip_path, dest)
    print(f"  extracted {count} files")
    return "extracted"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", type=Path, required=True,
                        help="install directory to hold Ghidra/Processors/*/data")
    parser.add_argument("--cache-dir", type=Path, default=default_cache_dir(),
                        help="where the downloaded zip is kept (default: %(default)s)")
    parser.add_argument("--ghidra-zip", type=Path,
                        help=f"use this {ZIP_NAME} instead of downloading it")
    parser.add_argument("--force", action="store_true", help="extract again even if present")
    arguments = parser.parse_args()
    try:
        print(provision(arguments.dest, arguments.cache_dir, arguments.ghidra_zip,
                        arguments.force))
    except SetupError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
