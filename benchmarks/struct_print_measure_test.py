#!/usr/bin/env python3
"""The printed-field-access counters must see `*(T *)(x + 0xN)` as pointer arithmetic and `p->f` as a member
access, and must not count what a struct definition or a comment says."""
import unittest

import struct_print_measure as spm

ARITHMETIC = """void f(void *pw)
{
  if (*(int *)((int)pw + 0x94) < 0) {
    *(char *)((int)pw + 7) = *(signed char *)((int)pw + 7) + '\\x01';
  }
  g(*(unsigned int **)(pbVar3 + 0x118), 1.5);
}
"""

MEMBERS = """typedef struct fn_1_arg0 fn_1_arg0;
struct fn_1_arg0 {
    int field_0x0; /* +0x0 */
    unsigned char pad_0x4[0x4];
};
void f(fn_1_arg0 *pw)
{
  /* pw->nothing */
  if (pw->field_0x94 < 0) {
    pw->field_0x7 = pw->field_0x7 + 1;
  }
  h(local.value, 0.5);
}
"""


class CounterTests(unittest.TestCase):
    def test_pointer_arithmetic_is_not_a_member_access(self):
        found = spm.counts(ARITHMETIC)
        self.assertEqual(found, {"members": 0, "offsets": 4})

    def test_members_count_and_definitions_and_comments_do_not(self):
        found = spm.counts(MEMBERS)
        self.assertEqual(found, {"members": 4, "offsets": 0})  # three on pw, one on local; no float literal

    def test_a_dot_in_a_string_or_character_literal_is_not_an_access(self):
        found = spm.counts('void f() { puts("a.b->c"); x = p->q; y = \'.\'; }')
        self.assertEqual(found, {"members": 1, "offsets": 0})

    def test_the_share_is_members_over_both(self):
        rows = [{"ok": True, "members": 3, "offsets": 1, "structs": True},
                {"ok": True, "members": 0, "offsets": 4, "structs": False},
                {"ok": False, "address": "1000"}]
        summary = spm.summarise(rows)
        self.assertEqual(summary["member_share"], 0.375)
        self.assertEqual((summary["ok"], summary["functions_with_members"], summary["failed"]), (2, 1, ["1000"]))


if __name__ == "__main__":
    unittest.main()
