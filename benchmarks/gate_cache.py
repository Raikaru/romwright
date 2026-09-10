#!/usr/bin/env python3
"""Reusable stores for gates, keyed by the provenance that produced them.

Analysing the same unchanged bytes with the same unchanged analyser is the
largest cost in a gate run: `m4-003` alone imported sixteen corpus rows
through the JVM bridge twice per invocation. Nothing about that work is
uncertain, so it is cached -- but only under the key that *is* its provenance:

* an **oracle** artifact depends on the binary, on the bridge sources
  (`bridge_sources_sha256`, the same digest `gen_oracle.py` pins into every
  committed reference) and on the pinned install's `upstream_revision`;
* a **native** artifact depends on the binary and on the executables that
  produced it -- the release `lre-cli` and `lre-worker` -- which is the
  m4-014 lesson: a stale worker silently drove a measurement for three
  rounds, and a cache keyed on anything less would reintroduce it.

A miss, a mismatch, a missing marker or a partially written directory all fall
through to real work. Set `VENTRIS_GATE_CACHE=` (empty) to disable reuse
entirely; a cost gate must, since it measures the work this module skips.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_oracle import provenance  # noqa: E402

MARKER = "gate-cache.json"


def digest(path: Path) -> str:
    """SHA-256 of one file, or `"absent"` when it is not there."""
    if not Path(path).is_file():
        return "absent"
    hashed = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hashed.update(chunk)
    return hashed.hexdigest()


def cache_root() -> Path | None:
    """Where reusable stores live, or `None` when reuse is switched off."""
    configured = os.environ.get("VENTRIS_GATE_CACHE")
    if configured is not None:
        return Path(configured) if configured.strip() else None
    return Path(tempfile.gettempdir()) / "ventris-gate-cache"


def oracle_key(binary: Path, install: Path, **extra: str) -> dict:
    """What an oracle artifact depends on, and nothing else."""
    producer = provenance(Path(install))
    return {
        "kind": "oracle",
        "binary_sha256": digest(Path(binary)),
        "bridge_sources_sha256": producer["bridge_sources_sha256"],
        "upstream_version": producer["upstream_version"],
        "upstream_revision": producer["upstream_revision"],
        **extra,
    }


def stock_key(binary: Path, install: Path, **extra: str) -> dict:
    """What a raw `analyzeHeadless` answer depends on.

    Our bridge is not in this path, so its digest is not in the key: including
    an input the artifact does not depend on would invalidate a good cache for
    no reason.
    """
    producer = provenance(Path(install))
    return {
        "kind": "stock",
        "binary_sha256": digest(Path(binary)),
        "upstream_version": producer["upstream_version"],
        "upstream_revision": producer["upstream_revision"],
        **extra,
    }


def native_key(binary: Path, **extra: str) -> dict:
    """What a native artifact depends on: the bytes and the build that read them.

    The spec bundles are part of the build: a store imported while a bundle
    was absent carries no inferred prototypes, and a key that omitted the
    bundle would serve that degraded store forever. The bundle manifests are
    committed, so their digests name the input exactly.
    """
    specs = hashlib.sha256()
    for manifest in sorted((ROOT / "native/specs").glob("*.manifest.json")):
        specs.update(manifest.name.encode() + b"\0" + manifest.read_bytes())
    return {
        "kind": "native",
        "binary_sha256": digest(Path(binary)),
        "cli_sha256": digest(ROOT / "target/release/lre-cli"),
        "worker_sha256": digest(ROOT / "target/release/lre-worker"),
        "spec_bundles_sha256": specs.hexdigest(),
        **extra,
    }


def _slot(key: dict) -> str:
    payload = json.dumps(key, sort_keys=True).encode()
    return f"{key.get('kind', 'artifact')}-{hashlib.sha256(payload).hexdigest()[:32]}"


def store(key: dict, build: Callable[[Path], None]) -> Path:
    """A populated directory for `key`, built once and reused afterwards.

    `build` receives an empty directory and must populate it; it is called
    only on a miss. The directory is published by rename, so a crash mid-build
    leaves no half-written store behind for the next run to trust.
    """
    root = cache_root()
    if root is None:
        directory = Path(tempfile.mkdtemp(prefix="gate-uncached-"))
        build(directory)
        return directory
    root.mkdir(parents=True, exist_ok=True)
    slot = root / _slot(key)
    marker = slot / MARKER
    if marker.is_file():
        try:
            if json.loads(marker.read_text()) == key:
                return slot
        except (OSError, ValueError):
            pass
        shutil.rmtree(slot, ignore_errors=True)
    pending = Path(tempfile.mkdtemp(prefix="gate-pending-", dir=root))
    try:
        build(pending)
        (pending / MARKER).write_text(json.dumps(key, sort_keys=True, indent=1) + "\n")
        try:
            pending.rename(slot)
        except OSError:
            # Another process published the same slot first; its content is
            # keyed identically, so use it and drop ours.
            shutil.rmtree(pending, ignore_errors=True)
            if marker.is_file():
                return slot
            raise
        return slot
    except BaseException:
        shutil.rmtree(pending, ignore_errors=True)
        raise


def document(key: dict, build: Callable[[], object]) -> object:
    """One JSON-shaped answer for `key`, computed once and reused afterwards."""
    root = cache_root()
    if root is None:
        return build()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{_slot(key)}.json"
    if path.is_file():
        try:
            held = json.loads(path.read_text())
            if held.get("key") == key:
                return held["value"]
        except (OSError, ValueError, KeyError):
            path.unlink(missing_ok=True)
    value = build()
    with tempfile.NamedTemporaryFile("w", dir=root, delete=False) as handle:
        json.dump({"key": key, "value": value}, handle, sort_keys=True)
        pending = Path(handle.name)
    pending.replace(path)
    return value


def copy_of(source: Path, destination: Path) -> Path:
    """A private copy of a cached store, for a caller that will write to it."""
    shutil.copytree(source, destination, dirs_exist_ok=True)
    (destination / MARKER).unlink(missing_ok=True)
    return destination
