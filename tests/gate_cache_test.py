#!/usr/bin/env python3
"""The gate cache reuses work only under the provenance that produced it.

A cache that answers when an input changed is the m4-014 trap in a new
costume: a stale worker drove three measurement rounds and their conclusion.
These tests pin the properties that make reuse safe -- the key is the
provenance, a changed input misses, a failed build leaves nothing behind, and
`ROMWRIGHT_GATE_CACHE=` switches reuse off entirely for the gates that measure
the work itself.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402


class GateCache(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="gate-cache-test-")
        self.work = Path(self.temporary.name)
        self.previous = os.environ.get("ROMWRIGHT_GATE_CACHE")
        os.environ["ROMWRIGHT_GATE_CACHE"] = str(self.work / "cache")

    def tearDown(self) -> None:
        if self.previous is None:
            os.environ.pop("ROMWRIGHT_GATE_CACHE", None)
        else:
            os.environ["ROMWRIGHT_GATE_CACHE"] = self.previous
        self.temporary.cleanup()

    def test_a_store_is_built_once_and_reused(self):
        calls = []

        def build(directory: Path) -> None:
            calls.append(directory)
            (directory / "answer.txt").write_text("42")

        key = {"kind": "native", "binary_sha256": "abc"}
        first = gate_cache.store(key, build)
        second = gate_cache.store(key, build)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1, "a hit must not rebuild")
        self.assertEqual((first / "answer.txt").read_text(), "42")

    def test_a_changed_input_misses(self):
        calls = []

        def build(directory: Path) -> None:
            calls.append(directory)
            (directory / "answer.txt").write_text("42")

        gate_cache.store({"kind": "native", "binary_sha256": "abc"}, build)
        gate_cache.store({"kind": "native", "binary_sha256": "def"}, build)
        # The same bytes analysed by a different build is also a miss: the
        # executables that read them are part of the key.
        gate_cache.store({"kind": "native", "binary_sha256": "abc",
                          "worker_sha256": "other"}, build)
        self.assertEqual(len(calls), 3)

    def test_a_failed_build_leaves_no_store_to_trust(self):
        def explode(directory: Path) -> None:
            (directory / "half-written.txt").write_text("partial")
            raise RuntimeError("analysis failed")

        key = {"kind": "oracle", "binary_sha256": "abc"}
        with self.assertRaises(RuntimeError):
            gate_cache.store(key, explode)
        root = Path(os.environ["ROMWRIGHT_GATE_CACHE"])
        left = [path for path in root.glob("*") if path.is_dir()] if root.is_dir() else []
        self.assertEqual(left, [], f"a crashed build left {left}")

        calls = []
        gate_cache.store(key, lambda directory: calls.append(directory))
        self.assertEqual(len(calls), 1, "the next run must do the work itself")

    def test_a_corrupt_marker_is_not_believed(self):
        def build(directory: Path) -> None:
            (directory / "answer.txt").write_text("42")

        key = {"kind": "native", "binary_sha256": "abc"}
        slot = gate_cache.store(key, build)
        (slot / gate_cache.MARKER).write_text("{not json")
        calls = []

        def rebuild(directory: Path) -> None:
            calls.append(directory)
            (directory / "answer.txt").write_text("42")

        gate_cache.store(key, rebuild)
        self.assertEqual(len(calls), 1)

    def test_documents_round_trip_and_key_on_their_inputs(self):
        calls = []

        def build() -> dict:
            calls.append(1)
            return {"code": "int main(void) { return 0; }"}

        key = {"kind": "oracle", "binary_sha256": "abc", "artifact": "decompile"}
        self.assertEqual(gate_cache.document(key, build),
                         {"code": "int main(void) { return 0; }"})
        self.assertEqual(gate_cache.document(key, build),
                         {"code": "int main(void) { return 0; }"})
        gate_cache.document({**key, "addresses": "beef"}, build)
        self.assertEqual(len(calls), 2,
                         "one build, one hit, and one build for a new address set")

    def test_an_empty_setting_disables_reuse(self):
        os.environ["ROMWRIGHT_GATE_CACHE"] = ""
        calls = []

        def build(directory: Path) -> None:
            calls.append(directory)

        key = {"kind": "native", "binary_sha256": "abc"}
        first = gate_cache.store(key, build)
        second = gate_cache.store(key, build)
        self.assertNotEqual(first, second, "a cost gate must get real work twice")
        self.assertEqual(len(calls), 2)
        answers = []
        gate_cache.document(key, lambda: answers.append(1) or "x")
        gate_cache.document(key, lambda: answers.append(1) or "x")
        self.assertEqual(len(answers), 2)

    def test_the_oracle_key_carries_the_provenance_it_depends_on(self):
        install = Path(os.environ.get("ROMWRIGHT_GHIDRA",
                                      Path.home() / "ghidra_12.1.3_PUBLIC"))
        if not (install / "Ghidra/application.properties").is_file():
            self.skipTest(f"no pinned install at {install}")
        binary = self.work / "bytes.bin"
        binary.write_bytes(b"\x7fELF payload")
        key = gate_cache.oracle_key(binary, install)
        self.assertEqual(key["kind"], "oracle")
        for field in ("binary_sha256", "bridge_sources_sha256", "upstream_revision"):
            self.assertTrue(key[field], f"{field} is empty")
        binary.write_bytes(b"\x7fELF other payload")
        self.assertNotEqual(gate_cache.oracle_key(binary, install)["binary_sha256"],
                            key["binary_sha256"])
        # A raw-headless answer does not go through our bridge, so its key
        # does not carry the bridge's digest.
        self.assertNotIn("bridge_sources_sha256",
                         gate_cache.stock_key(binary, install))

    def test_the_native_key_carries_the_build_that_produced_it(self):
        binary = self.work / "bytes.bin"
        binary.write_bytes(b"\x7fELF payload")
        key = gate_cache.native_key(binary)
        self.assertEqual(key["kind"], "native")
        self.assertIn("cli_sha256", key)
        self.assertIn("worker_sha256", key)
        self.assertEqual(json.loads(json.dumps(key)), key)


if __name__ == "__main__":
    unittest.main()
