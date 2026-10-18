#!/usr/bin/env python3
"""m6-008: the Ghidra data fetch `setup.py` and the release workflow share.

`packaging/ghidra_data.py` downloads a release zip once, refuses one whose
SHA-256 is not the pinned digest, and extracts only what romwright reads. This
gate exercises that against a local `file://` zip (no network): a verified
download is cached and not repeated, a wrong digest is refused and leaves
nothing behind, the extraction keeps `Ghidra/Processors/*/data/**` (minus
`data/manuals`) and the licence and nothing else, a second extraction is
skipped, and a damaged marker or missing sentinel makes it run again.

Usage:
    python3 tests/m6-008_ghidra_data.py
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
import ghidra_data  # noqa: E402

P = f"{ghidra_data.ZIP_ROOT}/Ghidra/Processors"
MEMBERS = {
    f"{ghidra_data.ZIP_ROOT}/LICENSE": b"licence",
    f"{ghidra_data.ZIP_ROOT}/ghidraRun": b"launcher",
    f"{ghidra_data.ZIP_ROOT}/Ghidra/Framework/Utility/lib/Utility.jar": b"jar",
    f"{P}/x86/data/languages/x86-64.sla": b"sla",
    f"{P}/x86/data/languages/x86.ldefs": b"ldefs",
    f"{P}/x86/data/patterns/x86_patterns.xml": b"patterns",
    f"{P}/x86/data/manuals/x86.idx": b"manual",
    f"{P}/x86/lib/x86.jar": b"jar",
    f"{P}/x86/Module.manifest": b"manifest",
}
KEPT = {
    "LICENSE",
    "Ghidra/Processors/x86/data/languages/x86-64.sla",
    "Ghidra/Processors/x86/data/languages/x86.ldefs",
    "Ghidra/Processors/x86/data/patterns/x86_patterns.xml",
}


def make_zip(path: Path) -> str:
    with zipfile.ZipFile(path, "w") as bundle:
        for name, data in MEMBERS.items():
            bundle.writestr(name, data)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class GhidraData(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)
        self.source = self.root / "source.zip"
        self.digest = make_zip(self.source)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def test_wanted_keeps_only_processor_data(self) -> None:
        kept = {ghidra_data.wanted(name) for name in MEMBERS} - {None}
        self.assertEqual(kept, KEPT)
        self.assertIsNone(ghidra_data.wanted(f"{ghidra_data.ZIP_ROOT}/../evil"))
        self.assertIsNone(ghidra_data.wanted("other_root/Ghidra/Processors/x86/data/a"))

    def test_download_is_verified_then_cached(self) -> None:
        cache = self.root / "cache"
        url = self.source.as_uri()
        first = ghidra_data.download(cache, url, self.digest, self.source.stat().st_size, "g.zip")
        self.assertEqual(first.read_bytes(), self.source.read_bytes())
        self.source.unlink()  # a second call that downloaded again would fail
        second = ghidra_data.download(cache, url, self.digest, 1, "g.zip")
        self.assertEqual(second, first)

    def test_a_wrong_digest_is_refused_and_leaves_nothing(self) -> None:
        cache = self.root / "cache"
        with self.assertRaises(ghidra_data.SetupError):
            ghidra_data.download(cache, self.source.as_uri(), "0" * 64,
                                 self.source.stat().st_size, "g.zip", attempts=2)
        self.assertEqual(list(cache.iterdir()), [])

    def test_a_cached_copy_with_the_wrong_digest_is_discarded(self) -> None:
        cache = self.root / "cache"
        cache.mkdir()
        (cache / "g.zip").write_bytes(b"truncated")
        path = ghidra_data.download(cache, self.source.as_uri(), self.digest,
                                    self.source.stat().st_size, "g.zip")
        self.assertEqual(ghidra_data.sha256_of(path), self.digest)

    def test_extract_keeps_the_subset_and_is_not_repeated(self) -> None:
        dest = self.root / "ghidra"
        # The sentinel is the real x86-64 path, which MEMBERS holds.
        self.assertFalse(ghidra_data.is_installed(dest, self.digest))
        count = ghidra_data.extract(self.source, dest, self.digest)
        self.assertEqual(count, len(KEPT))
        on_disk = {path.relative_to(dest).as_posix() for path in dest.rglob("*") if path.is_file()}
        self.assertEqual(on_disk, KEPT | {ghidra_data.MARKER})
        self.assertTrue(ghidra_data.is_installed(dest, self.digest))
        self.assertFalse(ghidra_data.is_installed(dest, "1" * 64))
        (dest / ghidra_data.SENTINEL).unlink()
        self.assertFalse(ghidra_data.is_installed(dest, self.digest))

    def test_a_zip_that_is_not_ghidra_is_refused(self) -> None:
        other = self.root / "other.zip"
        with zipfile.ZipFile(other, "w") as bundle:
            bundle.writestr("readme.txt", "nothing")
        with self.assertRaises(ghidra_data.SetupError):
            ghidra_data.extract(other, self.root / "ghidra")
        self.assertFalse((self.root / "ghidra").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
