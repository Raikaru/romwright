#!/usr/bin/env python3
"""console_research_wave: the TSV loader, scoring against m21-001's `score`, placement helpers, sign test."""
import importlib.util
import random
import sqlite3
import tempfile
import unittest
from pathlib import Path

import console_research_wave as wave

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("m21_for_test", ROOT / "tests" / "m21-001_real_images.py")
M21 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M21)


class ScoringTests(unittest.TestCase):
    def setUp(self):
        rng = random.Random(3)
        self.truth = {a: (rng.choice([0, 8, 40, 100]), f"f{a}") for a in rng.sample(range(0x1000, 0x9000, 4), 800)}
        self.found = {a: 8 for a in rng.sample(range(0x1000, 0x9000, 4), 900)}
        for a in list(self.truth)[:500]:
            self.found[a] = self.truth[a][0] or 8
        self.ranges = [(0x2000, 0x8000)]

    def test_frozen_metric_equals_m21_score(self):
        with tempfile.TemporaryDirectory() as temporary:
            db = sqlite3.connect(Path(temporary) / "project.sqlite")
            db.executescript("CREATE TABLE programs (id INTEGER, name TEXT);"
                             "CREATE TABLE memory_regions (program_id INTEGER, start TEXT, size INTEGER, permissions TEXT);"
                             "CREATE TABLE functions (program_id INTEGER, entry TEXT, size INTEGER);"
                             "INSERT INTO programs VALUES (1, 'p');")
            db.executemany("INSERT INTO functions VALUES (1, ?, ?)", [(f"{a:08x}", s) for a, s in self.found.items()])
            db.commit()
            db.close()
            old = M21.score(Path(temporary), "p", self.truth, self.ranges)
        new = wave.score_found(self.found, self.truth, set(list(self.truth)[::3]), self.ranges)
        for key in ("truth", "found", "recall", "precision", "invented", "sizes_compared", "size_exact",
                    "size_short", "size_long", "missed_sample", "invented_sample"):
            self.assertEqual(old[key], new[key], key)
        pooled = wave.aggregate([new])
        self.assertEqual((pooled["recall"], pooled["precision"]), (new["recall"], new["precision"]))

    def test_verified_supplement(self):
        truth = {0x100: (0x20, "a"), 0x140: (0x20, "b"), 0x200: (0, "c")}
        found = {0x100: 0x20, 0x110: 4, 0x140: 0x20, 0x160: 4}  # 0x110 splits verified a; 0x160 is a gap
        row = wave.score_found(found, truth, {0x100, 0x140, 0x200}, [(0x100, 0x300)])
        self.assertEqual((row["verified_truth"], row["verified_hits"], row["verified_split"]), (3, 2, 1))
        self.assertEqual(row["recall_verified"], round(2 / 3, 4))
        self.assertEqual(row["precision_verified"], round(2 / 3, 4))
        self.assertIsNone(wave.score_found({}, {}, set(), [(0, 1)])["recall_verified"])


class HelperTests(unittest.TestCase):
    def test_sign_test(self):
        test = wave.sign_test([(0.9, 0.8)] * 6 + [(0.5, 0.6)] + [(0.5, 0.501)])
        self.assertEqual((test["wins"], test["losses"], test["ties"], test["p_value"]), (6, 1, 1, 0.0625))
        self.assertIsNone(wave.sign_test([(0.5, 0.5)])["p_value"])

    def test_alias_and_ranges(self):
        self.assertEqual(wave.alias("foresta.rel.szs"), "foresta")
        self.assertEqual(wave.alias("overlay_0005"), wave.alias("nds.ov5".split(".")[-1]))
        self.assertEqual(wave.subtract([(0, 100)], [(10, 20), (50, 60)]), [(0, 10), (20, 50), (60, 100)])
        self.assertEqual(wave.intersect([(0, 100)], 90, 200), [(90, 100)])
        self.assertEqual(wave.parse_ranges([["0x10", 32]]), [(16, 32)])

    def test_tsv_rows_and_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "functions.tsv"
            path.write_text("start\tsize\tname\tmodule\tverified\n0x10\t8\ta\tmain\t1\n0x10\t4\tb\tov1\t0\n0x20\t0\tc\tmain\t0\n")
            modules = wave.load_modules(path, [{"name": "ov1"}])
            self.assertEqual(list(modules), ["main", "ov1"])
            self.assertEqual(modules["main"]["verified"], {0x10})
            self.assertEqual(M21.tsv_functions(path)[0x10], (8, "a"))
            path.write_text("start\tsize\tname\tmodule\n")
            with self.assertRaises(ValueError):
                M21.tsv_rows(path)

    def test_nesting_counts_nested_and_straddling_rows(self):
        truth = {0x100: (0x40, "a"), 0x110: (0, "b"), 0x120: (0x40, "c"), 0x140: (8, "d"), 0x200: (4, "e")}
        self.assertEqual(wave.nesting(truth), {"nested": 3, "nested_size0": 1, "straddling": 1})

    def test_failed_image_stays_in_the_rollup(self):
        report = {"images": {"x360-a": {"status": "error", "reason": "import failed: lzx"}}}
        roll = wave.rollup(report)
        self.assertIn("x360-a", roll["platforms"]["x360"]["failures"])
        self.assertIn("did not run", wave.markdown(dict(report, generated="t", tools="f", n=1, seeds=[1]), roll))

    def test_rollup_keeps_version_mismatch_out_of_headline_and_sign_tests(self):
        def image(recall, other, match):
            summary = lambda value: {"summary": {"recall": value, "sampled": 1}}  # noqa: E731
            return {"status": "ran", "wave": {"game": "g", "version_match": match},
                    "configs": {"default": summary(recall), "baseline-off": summary(other)}}
        report = {"images": {"gc-a": image(0.9, 0.8, True), "gc-b": image(0.9, 0.8, False), "ps2-c": image(0.9, 0.8, True)}}
        roll = wave.rollup(report)
        self.assertEqual(roll["all"]["tests"]["recall vs baseline-off"]["games"], 2)
        self.assertEqual(sorted(roll["platforms"]), ["gc", "ps2"])
        self.assertEqual(sorted(roll["platforms"]["gc"]["games"]), ["gc-a"])
        self.assertEqual(sorted(roll["mismatch"]), ["gc-b"])
        text = wave.markdown(dict(report, generated="t", tools="f", n=1, seeds=[1]), roll)
        self.assertIn("Supplement: version-mismatch images", text)
        self.assertEqual(wave.rollup(report, True)["all"]["tests"]["recall vs baseline-off"]["games"], 3)

    def test_stock_dnf_is_labelled_and_counts_neither_way(self):
        summary = lambda value: {"summary": {"recall": value, "sampled": 1}}  # noqa: E731
        dnf = {"kind": "dnf", "label": "stock DNF (>4 h auto-analysis)", "limit_s": 14400}
        report = {"images": {
            "gba-a": {"status": "ran", "wave": {"game": "a"}, "stock": {"combined": summary(0.5)},
                      "configs": {"default": summary(0.9), "baseline-off": summary(0.9)}},
            "gba-b": {"status": "ran", "wave": {"game": "b"}, "stock": {"error": dnf["label"], "failure": dnf},
                      "configs": {"default": summary(0.9), "baseline-off": summary(0.9)}}}}
        roll = wave.rollup(report)
        self.assertEqual(roll["all"]["tests"]["recall vs stock"]["games"], 1)
        self.assertEqual(roll["platforms"]["gba"]["stock_excluded"], {"gba-b": dnf["label"]})
        text = wave.markdown(dict(report, generated="t", tools="f", n=1, seeds=[1]), roll)
        self.assertIn("| gba-b | stock Ghidra | **stock DNF (>4 h auto-analysis)** |", text)

    def test_symtab_variants_are_supplement_and_ids_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "ps2-x" / "truth").mkdir(parents=True)
            elf = root / "ps2-x" / "game.elf"
            subprocess_run = __import__("subprocess").run
            source = root / "t.c"
            source.write_text("int main(void){return 0;}")
            cc = subprocess_run(["cc", "-o", str(elf), str(source)], capture_output=True)
            if cc.returncode:
                self.skipTest("no C compiler")
            (root / "ps2-x" / "truth" / "functions.tsv").write_text("start\tsize\tname\tmodule\tverified\n0x1\t4\ta\tmain\t1\n")
            (root / "ps2-x" / "truth" / "meta.json").write_text(
                '{"id": "ps2-x", "image": "game.elf", "truth_kind": "decomp-symbols"}')
            specs, _ = wave.discover(root, set(), 0, symtab_variants=True)
            self.assertEqual([s["id"] for s in specs], ["ps2-x", "ps2-x-symtab"])
            self.assertEqual([s["strip"] for s in specs], [True, "debug"])
            self.assertEqual(specs[1]["wave"]["variant"], "symtab")
            self.assertIsNone(specs[0]["wave"].get("variant"))
        report = {"images": {"ps2-x": {"status": "ran", "wave": {"game": "g", "version_match": True},
                                       "configs": {"default": {"summary": {"recall": 1, "sampled": 1}}}},
                             "ps2-x-symtab": {"status": "ran", "wave": {"game": "g", "version_match": True, "variant": "symtab"},
                                              "configs": {"default": {"summary": {"recall": 1, "sampled": 1}}}}}}
        roll = wave.rollup(report)
        self.assertEqual(sorted(roll["platforms"]["ps2"]["games"]), ["ps2-x"])
        self.assertEqual(sorted(roll["variants"]), ["ps2-x-symtab"])

    def test_header_only_truth_is_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "wii-x" / "truth").mkdir(parents=True)
            (root / "wii-x" / "main.dol").write_bytes(b"\0" * 8)
            (root / "wii-x" / "truth" / "functions.tsv").write_text("start\tsize\tname\tmodule\tverified\n")
            (root / "wii-x" / "truth" / "meta.json").write_text(
                '{"id": "wii-x", "image": "main.dol", "truth_kind": "decomp-symbols"}')
            specs, skipped = wave.discover(root, set(), 0)
            self.assertEqual(specs, [])
            self.assertIn("header-only", skipped[0]["reason"])


if __name__ == "__main__":
    unittest.main()
