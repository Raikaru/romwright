#!/usr/bin/env python3
"""Boundary tolerance and matched-denominator checks for m2-008."""
import unittest
from nonreturn_gate import bounds_score


def function(entry, size):
    return dict(entry=dict(space='Ram', offset=entry), size=size)


class BoundsTest(unittest.TestCase):
    def test_symmetric_end_tolerance_and_exact_entry_matching(self):
        reference = {
            '00001000': [['00001000', '0000100f']],
            '00002000': [['00002000', '0000202f']],
            '00003000': [['00003000', '0000300f']],
            '00004000': [['00004000', '0000400f']],
        }
        score = bounds_score([function(0x1000, 0x20), function(0x2000, 0x20),
            function(0x3000, 0x21), function(0x4001, 0x10)], reference, set(reference))
        self.assertEqual((score['matched'], score['correct']), (3, 2))
        self.assertEqual(score['fn.bounds'], 2 / 3)
        self.assertEqual([row['entry'] for row in score['mismatches']], ['00003000'])

    def test_interior_gaps_and_unknown_extents_do_not_disappear(self):
        reference = {
            '00001000': [['00001000', '0000100f'], ['00002000', '0000200f']],
            '00003000': [['00003000', '0000300f']],
        }
        score = bounds_score([function(0x1000, 0x1010), function(0x3000, 0)],
            reference, set(reference))
        self.assertEqual((score['matched'], score['correct']), (2, 0))
        self.assertEqual(score['fn.bounds'], 0)


if __name__ == '__main__':
    unittest.main()
