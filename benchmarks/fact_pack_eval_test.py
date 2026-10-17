#!/usr/bin/env python3
"""fact_pack_eval: name normalization, demangling to base names, generic names, scoring, twin exclusion."""
import unittest

import fact_pack_eval as ev


class NameTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(ev.normalize("__memcpy"), ev.normalize("MemCpy".replace("C", "c")))
        self.assertEqual(ev.normalize("_Strstr"), "strstr")

    def test_generic(self):
        for name in ["func_80123456", "FUN_00123456", "sub_80123456", "fn_800A1234", "lbl_8000ABCD",
                     "func_ov5_0200A4B8", "Func_0200A4B8", "FUN_ov3_02001234", "sub_8012", "sub_menu", "FUN_x", "text80123456", "func0123abcd"]:
            self.assertTrue(ev.is_generic(name), name)
        for name in ["strstr", "memcpy", "UberBond::Update", "func", "func_init", "Update__8UberBondFv", "fn_foo_bar", "fn_add_bead", "subdead"]:
            self.assertFalse(ev.is_generic(name), name)

    def test_base_names(self):
        cases = {
            "Update__8UberBondFv": "Update", "__ct__8UberBondFv": "__ct", "my__init__8UberBondFv": "my__init",
            "Render__8UberBondCFv": "Render", "foo__Fv": "foo", "UberBond::Update(float)": "Update",
            "ns::Foo<int>::bar": "bar", "_ZN3foo3barEv": "bar", "_Z3bazv": "baz", "?bar@foo@@YAXXZ": "bar",
            "strstr": "strstr", "my__name": "my__name", "__ct__8UberBondFv_x": "__ct",
        }
        for name, base in cases.items():
            self.assertEqual(ev.base_name(name), base, name)

    def test_judge(self):
        self.assertEqual(ev.judge("strstr", "_strstr"), "correct_strict")
        self.assertEqual(ev.judge("memcpy", "MemCpy"), "correct_strict")
        self.assertEqual(ev.judge("Update", "Update__8UberBondFv"), "correct")
        self.assertEqual(ev.judge("UberBond::Update", "Update__8UberBondFv"), "correct")
        self.assertEqual(ev.judge("FindSubstring", "strstr"), "wrong")
        self.assertEqual(ev.judge("strstr", "func_80123456"), "generic")

    def test_pair_kind(self):
        names = {"isopen", "update"}
        self.assertEqual(ev.pair_kind("Foo_Bar", "FooBar"), "spelling")
        self.assertEqual(ev.pair_kind("C_MTXLightPerspective", "MTXLightPerspective"), "affix")
        self.assertEqual(ev.pair_kind("IsOpen", "canRide__3FooFv", names), "collision")
        self.assertEqual(ev.pair_kind("FindSubstring", "strstr", names), "different")
        self.assertEqual(ev.pair_kind("isWipeOpen__2MRFv", "canRide__Q34Game8ItemHole4ItemFv", names), "collision")

    def test_scope(self):
        cases = {"Update__8UberBondFv": "UberBond", "Update__Q23foo3barFv": "foo::bar", "foo__Fv": None,
                 "_ZN3foo3barEv": "foo", "_Z3bazv": None, "?bar@foo@@YAXXZ": "foo", "A::B::f(int)": "A::B", "strstr": None,
                 "Render__8UberBondCFv": "UberBond"}
        for name, scope in cases.items():
            self.assertEqual(ev.scope_of(name), scope, name)
        self.assertEqual(ev.judge("Update__3FooFv", "Update__3BarFv"), "correct_scope")
        self.assertEqual(ev.judge("Update", "Update__3BarFv"), "correct")


class CompilerTests(unittest.TestCase):
    def test_family(self):
        cases = [("agbcc (pret/agbcc, -O2 -g) with old_agbcc", "gba", "agbcc"), ("agscc (GCC 2.96 snapshot", "gba", "agbcc"),
                 ("MWCC GC/2.6 (95.7%)", "gc", "MWCC"), ("mwccarm 2.0/sp1p6", "nds", "MWCC"),
                 ("MWCC PS2 3.0 (CodeWarrior for PS2", "ps2", "MWCC"), ("Metrowerks CodeWarrior for PSP", "psp", "MWCC"),
                 ("CodeWarrior for PlayStation R4 (mwccpsx", "psx", "MWCC"), ("IDO 7.1 (game code) + IDO 5.3", "n64", "IDO"),
                 ("KMC GCC 2.7.2", "n64", "gcc"), ("GCC 2.8.1 (pmret/gcc-papermario)", "n64", "gcc"),
                 ("EE GCC 2.96 (ee-gcc; ee-as 2.9-ee)", "ps2", "ee-gcc"), ("SN ProDG ee-gcc 2.95.3 (matched TUs)", "ps2", "ee-gcc"),
                 ("SN ProDG 3.01 (ee-gcc 2.95-based) for game code", "ps2", "ee-gcc"),
                 ("Psy-Q GCC 2.7.2-cdk", "psx", "psyq"), ("SN/PsyQ 4.3: cc1 GNU C 2.8.0", "psx", "psyq"),
                 ("GCC 2.8.1 (PSX cc1) + maspsx", "psx", "psyq"), ("GNU C 3.3.3+allegrex-2.2.2-psp", "psp", "gcc"),
                 ("Microsoft (R) Optimizing Compiler 16.0", "x360", "other"), (None, None, "other")]
        for text, platform, family in cases:
            self.assertEqual(ev.compiler_family(text, platform), family, text)


class TwinTests(unittest.TestCase):
    donors = {"a": {"twin_group": "t"}, "b": {"twin_group": "t"}, "c": {"twin_group": None}, "d": {}}

    def test_twin_games(self):
        self.assertEqual(ev.twin_games("a", self.donors), {"a", "b"})
        self.assertEqual(ev.twin_games("c", self.donors), {"c"})
        self.assertEqual(ev.twin_games("psp-x", self.donors), {"psp-x"})


class ScoreTests(unittest.TestCase):
    truth = {0x100: (32, "strstr"), 0x200: (64, "func_80000200"), 0x300: (40, "Update__8UberBondFv"), 0x400: (16, "other"),
             0x800: (24, "entry")}

    def match(self, address, length, name, found=True, our=None, action="renamed", donors=("g1",), ambiguous=False):
        return {"address": address, "length": length, "name": name, "found": found, "our_size": our,
                "action": action, "donors": list(donors), "ambiguous": ambiguous}

    def test_counts(self):
        matches = [
            self.match(0x100, 32, "_strstr", our=32),                      # correct (strict), size equal
            self.match("0x200", 64, "foo", our=60),                        # truth generic
            self.match(0x300, 40, "Update", our=36),                       # correct via base name; pack fixes size
            self.match(0x400, 20, "FindIt", our=16),                       # wrong; pack breaks size
            self.match(0x500, 16, "nope", our=16),                         # no truth
            self.match(0x600, 8, None, our=8, action="abstained"),         # nameless
            self.match(0x700, 8, "x", ambiguous=True, our=8, action="abstained"),
            self.match(0x700, 12, "y", our=8, action="abstained"),         # second length of the same match
            self.match(0x1100, 32, "scanhit", found=False, action="scan_only"),   # outside ranges
            self.match(0x800, 24, "entry", found=False, action="scan_only", donors=("g2",)),  # scan start hit, length ok
            self.match(0x804, 24, "entry", found=False, action="scan_only"),               # scan miss
        ]
        score = ev.score_unit(matches, self.truth, [(0, 0x1000)], {"g2"})
        c = score["counts"]
        self.assertEqual(c["matched"], 9)
        self.assertEqual(c["out_of_scope"], 1)
        self.assertEqual(c["renamed"], 5)
        self.assertEqual((c["renamed.correct"], c["renamed.correct_strict"], c["renamed.wrong"]), (2, 1, 1))
        self.assertEqual(c["renamed.generic_truth"], 1)
        self.assertEqual(c["renamed.no_truth"], 1)
        self.assertEqual(c["abstained_nameless"], 1)
        self.assertEqual(c["abstained_ambiguous"], 1)
        self.assertEqual(c["leaks"], 1)
        self.assertEqual((c["scan.correct"], c["scan.no_truth"]), (1, 1))
        self.assertEqual((c["scan_start_hit"], c["scan_start_miss"], c["scan_length_equals_truth"]), (1, 1, 1))
        self.assertEqual(c["found_size_compared"], 7)
        self.assertEqual(c["found_size_equals_pack"], 4)  # strstr 32/32, nope 16/16, nameless 8/8, 0x700 8/8
        self.assertEqual(score["pairs"]["renamed"], [["other", "FindIt", "different", 1]])
        # truth-based size effects: 0x200 (ours 60 vs truth 64 vs pack 64) fixes, 0x300 fixes, 0x400 breaks
        self.assertEqual((c["found_pack_fixes"], c["found_pack_breaks"]), (2, 1))

    def test_gated_and_function_wrong(self):
        truth = dict(self.truth)
        truth[0x900] = (16, "Other")   # "other" is a truth name at 0x400 and 0x900 is named differently below
        matches = [
            self.match(0x100, 32, "strstr", our=32, action="gated"),                  # held back: no rename, no size row
            self.match(0x400, 20, "Update", our=16),                                   # wrong, and Update is 0x300's name: function-wrong
            self.match(0x900, 16, "zzzzname", our=16),                                 # wrong, unrelated: not function-wrong
        ]
        c = ev.score_unit(matches, truth, None, set())["counts"]
        self.assertEqual(c["gated"], 1)
        self.assertEqual(c["matched"], 3)
        self.assertNotIn("abstained_nameless", c)
        self.assertEqual((c["renamed"], c["renamed.wrong"], c["renamed.function_wrong"]), (2, 2, 1))
        self.assertEqual(c["found_size_compared"], 2)
        m = ev.metrics(c)
        self.assertEqual(m["renamed.function_wrong_rate"], 0.5)

    def test_donor_families(self):
        matches = [self.match(0x100, 32, "strstr", donors=("a", "b")), self.match(0x400, 16, "bad", donors=("a",)),
                   self.match(0x300, 40, "Update", donors=("zzz",))]
        c = ev.score_unit(matches, self.truth, None, set(), {"a": "MWCC", "b": "MWCC"})["counts"]
        self.assertEqual((c["renamed.correct_from.MWCC"], c["renamed.wrong_from.MWCC"], c["renamed.correct_from.unknown"]), (1, 1, 1))

    def test_rates_and_merge(self):
        a = ev.score_unit([self.match(0x100, 32, "strstr", our=32), self.match(0x400, 16, "bad", our=16)], self.truth, None, set())
        b = ev.score_unit([self.match(0x100, 32, "strstr", our=32)], self.truth, None, set())
        merged = ev.merge_scores([a, b])
        m = ev.metrics(merged["counts"])
        self.assertEqual(m["renamed.scoreable"], 3)
        self.assertAlmostEqual(m["renamed.wrong_rate"], 1 / 3, places=4)
        self.assertEqual(ev.top_pairs([a, b], "renamed")[0]["count"], 1)

    def test_scan_rates(self):
        c = {"matched_scan": 4, "scan_start_hit": 3, "scan_hit_sized": 3, "scan_length_equals_truth": 2}
        m = ev.metrics(c)
        self.assertEqual(m["scan_start_precision"], 0.75)
        self.assertAlmostEqual(m["scan_length_given_start"], 0.6667, places=4)
        self.assertEqual(m["scan_length_exact_of_matches"], 0.5)


if __name__ == "__main__":
    unittest.main()
