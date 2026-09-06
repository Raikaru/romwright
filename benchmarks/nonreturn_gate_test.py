#!/usr/bin/env python3
"""Boundary tolerance and matched-denominator checks for m2-008."""
import unittest
from nonreturn_gate import bounds_score, compare_return_flags


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

    def test_range_start_padding_does_not_shift_the_matched_entry(self):
        reference = {
            '00001000': [['00000ff0', '0000100f']],
            '00002000': [['00001fef', '0000200f']],
        }
        score = bounds_score([function(0x1000, 0x10), function(0x2000, 0x10)],
            reference, set(reference))
        self.assertEqual((score['matched'], score['correct']), (2, 1))
        self.assertEqual([row['entry'] for row in score['mismatches']], ['00002000'])


class ReturnMetadataTest(unittest.TestCase):
    def test_unflagged_stock_function_is_not_a_returning_assertion(self):
        comparison = compare_return_flags({'00001000', '00002000'}, {'00002000'})
        self.assertTrue(comparison['stock_positives_covered'])
        self.assertEqual(comparison['native_only'], ['00001000'])

    def test_missing_stock_positive_is_still_a_failure(self):
        comparison = compare_return_flags({'00001000'}, {'00002000'})
        self.assertFalse(comparison['stock_positives_covered'])
        self.assertEqual(comparison['stock_only'], ['00002000'])


if __name__ == '__main__':
    unittest.main()
