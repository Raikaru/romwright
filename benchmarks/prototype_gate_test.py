#!/usr/bin/env python3
"""Freeze matched-function arity scoring before adding the M2 comparator."""
import unittest
from prototype_gate import score_arity


class PrototypeArityTests(unittest.TestCase):
    def test_missing_prototype_still_counts_as_a_matched_function(self):
        truth = {'00000100': {'arity': 1}, '00000200': {'arity': 2}, '00000300': {'arity': 0}}
        observed = {'00000100': 1, '00000200': None, '00000400': 0}
        score = score_arity(truth, observed)
        self.assertEqual(score['matched'], 2)
        self.assertEqual(score['correct'], 1)
        self.assertEqual(score['value'], 0.5)
        self.assertEqual(score['unmatched_truth'], ['00000300'])
        self.assertEqual(score['incorrect'], [
            {'entry': '00000200', 'expected': 2, 'actual': None}])

    def test_no_matched_functions_cannot_claim_perfect_arity(self):
        with self.assertRaises(ValueError):
            score_arity({'00000100': {'arity': 0}}, {'00000200': 0})


if __name__ == '__main__':
    unittest.main()
