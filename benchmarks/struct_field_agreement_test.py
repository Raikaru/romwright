#!/usr/bin/env python3
"""The field-agreement reader must tell a printed member access from pointer arithmetic, and read offsets
from the definitions the candidate carries, not from the field names."""
import tempfile
import unittest
from pathlib import Path

import struct_field_agreement as sfa

CANDIDATE = """typedef struct fn_00001000_arg0 fn_00001000_arg0;
struct fn_00001000_arg0 {
    undefined4 field_0x0; /* +0x0 */
    unsigned char pad_0x4[0x4];
    float x; /* +0x8 */
    int (*callback)(); /* +0xc */
    unsigned char *names[2]; /* +0x10 */
};
void func_00001000(fn_00001000_arg0 *param_1, float param_2, int param_3)
{
  param_1->field_0x0 = param_3;
  param_1->x = param_2;
  *(int *)((int)param_1 + 0x14) = 1;
}
"""


class FieldAgreementTests(unittest.TestCase):
    def test_offsets_come_from_the_comment_not_the_name(self):
        structs = sfa.structs_of(CANDIDATE)
        self.assertEqual(structs["fn_00001000_arg0"], {"field_0x0": 0, "x": 8, "callback": 0xC, "names": 0x10})

    def test_a_float_parameter_does_not_shift_the_integer_slots(self):
        params = sfa.parameters(CANDIDATE, "func_00001000")
        ints = [(t, n) for t, n in params if not sfa.is_float(t)]
        self.assertEqual([n for _, n in ints], ["param_1", "param_3"])

    def test_only_member_access_counts_not_pointer_arithmetic(self):
        structs = sfa.structs_of(CANDIDATE)
        printed = sfa.member_accesses(CANDIDATE, structs, "param_1", "fn_00001000_arg0 *")
        self.assertEqual(printed, {0, 8})  # +0x14 is arithmetic

    def test_a_cast_through_an_untyped_signature_is_a_member_access(self):
        text = CANDIDATE.replace("fn_00001000_arg0 *param_1", "void *param_1").replace(
            "param_1->x", "((fn_00001000_arg0 *)param_1)->x")
        structs = sfa.structs_of(text)
        self.assertEqual(sfa.member_accesses(text, structs, "param_1", "void *"), {8})

    def test_a_typed_local_for_a_written_parameter_is_a_member_access(self):
        text = CANDIDATE.replace("fn_00001000_arg0 *param_1", "void *param_1").replace(
            "{\n  param_1->field_0x0", "{\n  fn_00001000_arg0 *param_1_s = (fn_00001000_arg0 *)param_1;\n  param_1_s->field_0x0").replace(
            "param_1->x", "param_1_s->x")
        structs = sfa.structs_of(text)
        self.assertEqual(sfa.member_accesses(text, structs, "param_1", "void *"), {0, 8})

    def test_agreement_is_the_share_of_truth_offsets_printed_at_the_same_offset(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            export = work / "functions" / "00001000_func_00001000" / "romwright" / "export"
            export.mkdir(parents=True)
            (export / "f.c").write_text(CANDIDATE)
            report = {"functions": {"00001000": {"address": "0x1000", "name": "func_00001000"}}}
            truth = {
                "structs": {"S": {"ok": True}},
                "functions": {"00001000": {"params": [{"kind": "struct_ptr", "key": "S", "i": 0, "slot": 0, "slot_clean": True}],
                                           "access": {"0": [[0, 4, "int", None], [8, 4, "float", None], [0x14, 4, "int", None]]}}},
            }
            totals, rows = sfa.agreement(report, work, truth)
            self.assertEqual(totals["truth_accesses"], 3)
            self.assertEqual(totals["agreed"], 2)  # +0x14 is printed as arithmetic
            self.assertEqual(totals["printed_wrong"], 0)
            self.assertAlmostEqual(totals["field_agreement"], 0.6667, places=4)
            # the same candidate with no definitions prints no member access
            (export / "f.c").write_text(CANDIDATE.replace("param_1->", "param_1_"))
            totals, _ = sfa.agreement(report, work, truth)
            self.assertEqual(totals["agreed"], 0)


if __name__ == "__main__":
    unittest.main()
