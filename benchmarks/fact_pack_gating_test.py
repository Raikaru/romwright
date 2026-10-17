#!/usr/bin/env python3
"""fact_pack_gating: row classification, the two wrong definitions, gate semantics, best-gate choice."""
import unittest

import fact_pack_gating as g

NAMES = frozenset({"strstr", "other", "iswipeopen"})


def row(**kw):
    base = {"verdict": "correct", "why": "correct_strict", "length": 40, "n_donors": 1, "n_sources": 1, "donor_families": ["MWCC"],
            "target_family": "MWCC", "detected_family": "MWCC"}
    base.update(kw)
    return base


class ClassifyTests(unittest.TestCase):
    def test_verdicts(self):
        self.assertEqual(g.classify("_strstr", "strstr", NAMES)["verdict"], "correct")
        self.assertEqual(g.classify("x", None, NAMES), {"verdict": "unscoreable", "why": "no_truth"})
        self.assertEqual(g.classify("x", "func_80123456", NAMES)["why"], "generic_truth")
        wrong = g.classify("isWipeOpen", "canRide", NAMES)
        self.assertEqual((wrong["verdict"], wrong["collision_source"]), ("collision", "name_in_target"))
        mangled = g.classify("a__2MRFv", "b__Q23foo3barFv", NAMES)
        self.assertEqual((mangled["verdict"], mangled["collision_source"]), ("collision", "mangled"))
        self.assertEqual(g.classify("zzzname", "yyyname2", NAMES)["verdict"], "different")

    def test_function_wrong_includes_affix_with_name_in_target(self):
        affix = g.classify("C_strstr", "strstr", frozenset({"c_strstr"}))
        self.assertEqual(affix["verdict"], "affix")
        self.assertTrue(g.function_wrong(affix))
        self.assertTrue(g.strict_wrong(affix))
        self.assertFalse(g.function_wrong(g.classify("zzzname", "yyyname2", NAMES)))


class GateTests(unittest.TestCase):
    def test_keeps(self):
        short = row(length=40)
        self.assertTrue(g.keeps(short, 32, None, "none"))
        self.assertFalse(g.keeps(short, 48, None, "none"))
        self.assertFalse(g.keeps(short, 32, 64, "none"))
        self.assertTrue(g.keeps(row(length=40, n_donors=2), 32, 64, "none"))
        self.assertTrue(g.keeps(row(length=70), 32, 64, "none"))
        self.assertTrue(g.keeps(short, 32, None, "detected_any"))
        self.assertFalse(g.keeps(row(donor_families=["ee-gcc"]), 32, None, "detected_any"))
        self.assertTrue(g.keeps(row(donor_families=["ee-gcc", "MWCC"]), 32, None, "detected_any"))
        self.assertFalse(g.keeps(row(donor_families=["ee-gcc", "MWCC"]), 32, None, "detected_all"))
        self.assertFalse(g.keeps(row(detected_family="psyq"), 32, None, "detected_any"))
        self.assertTrue(g.keeps(row(detected_family="psyq"), 32, None, "oracle_any"))

    def test_tally_and_gates(self):
        rows = [row(), row(verdict="different"), row(verdict="collision", length=100),
                row(verdict="unscoreable", why="no_truth"), row(length=200)]
        t = g.tally(rows)
        self.assertEqual((t["kept"], t["scoreable"], t["correct"], t["strict_wrong"], t["function_wrong"]), (5, 4, 2, 2, 1))
        self.assertEqual(t["strict_rate"], 0.5)
        gates = g.evaluate_gates(rows)
        self.assertEqual(gates[0]["gate"], "len>=32 (any)")
        self.assertEqual(len({tuple(x["gate"] for x in gates)}), 1)
        names = [x["gate"] for x in gates]
        self.assertEqual(len(names), len(set(names)))
        best = g.best_gates(gates, 0.34)
        self.assertEqual((best["kept"], best["strict_wrong"]), (1, 0))  # only the 200-byte correct row survives len>=128

    def test_always_two_donors_and_breakdown(self):
        rows = [row(n_donors=1, length=500), row(n_donors=3, length=500, verdict="different")]
        self.assertFalse(g.keeps(rows[0], 32, g.ALWAYS, "none"))
        self.assertTrue(g.keeps(rows[1], 32, g.ALWAYS, "none"))
        twins = row(n_donors=2, n_sources=1, length=40)
        self.assertTrue(g.keeps(twins, 32, g.ALWAYS, "none"))
        self.assertFalse(g.keeps(twins, 32, g.ALWAYS, "none", True))
        self.assertIn(">=2 donors", g.gate_name(32, g.ALWAYS, "none"))
        b = g.breakdowns(rows)
        self.assertEqual([x["kept"] for x in b["by_donors"]], [1, 0, 1, 0])
        self.assertEqual(b["by_length"][-1]["kept"], 2)

    def test_best_none(self):
        self.assertIsNone(g.best_gates([{"strict_rate": 0.5, "correct": 1, "strict_wrong": 1}], 0.1))


if __name__ == "__main__":
    unittest.main()
