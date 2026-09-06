#!/usr/bin/env python3
"""DWARF arity: inheritance, indexed addresses, and formal-parameter boundaries."""
import unittest
from dwarf_arity import parse_info


class DwarfArityTests(unittest.TestCase):
    def test_concrete_origin_preserves_optimized_out_and_artificial_parameters(self):
        info = '''
 <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)
 <1><20>: Abbrev Number: 2 (DW_TAG_subprogram)
    <21> DW_AT_name : (strx1) (offset: 0x8): method
    <22> DW_AT_type : (ref4) <0x90>
 <2><30>: Abbrev Number: 3 (DW_TAG_formal_parameter)
    <31> DW_AT_name : (string) this
    <32> DW_AT_artificial : (flag_present) 1
 <2><40>: Abbrev Number: 3 (DW_TAG_formal_parameter)
    <41> DW_AT_name : (string) unused
 <2><50>: Abbrev Number: 4 (DW_TAG_unspecified_parameters)
 <2><51>: Abbrev Number: 0
 <1><60>: Abbrev Number: 5 (DW_TAG_subprogram)
    <61> DW_AT_low_pc : (addrx) (index: 0x2): 0x401010
    <62> DW_AT_high_pc : (data4) 0x20
    <63> DW_AT_abstract_origin : (ref4) <0x20>
 <2><70>: Abbrev Number: 6 (DW_TAG_formal_parameter)
    <71> DW_AT_abstract_origin : (ref4) <0x30>
 <2><80>: Abbrev Number: 7 (DW_TAG_inlined_subroutine)
    <81> DW_AT_low_pc : (addr) 0x401018
 <3><85>: Abbrev Number: 3 (DW_TAG_formal_parameter)
 <3><86>: Abbrev Number: 0
 <2><87>: Abbrev Number: 0
 <1><90>: Abbrev Number: 8 (DW_TAG_base_type)
    <91> DW_AT_name : (string) int
 <1><95>: Abbrev Number: 0
'''
        functions = parse_info(info)
        self.assertEqual(set(functions), {0x401010})
        function = functions[0x401010]
        self.assertEqual(function['name'], 'method')
        self.assertEqual(function['arity'], 2)
        self.assertTrue(function['variadic'])
        self.assertEqual([parameter['artificial'] for parameter in function['parameters']], [True, False])

    def test_missing_origin_is_not_a_zero_argument_function(self):
        with self.assertRaises(ValueError):
            parse_info('''
 <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)
 <1><20>: Abbrev Number: 2 (DW_TAG_subprogram)
    <21> DW_AT_low_pc : (addr) 0x401000
    <22> DW_AT_abstract_origin : (ref4) <0x999>
 <1><30>: Abbrev Number: 0
''')


if __name__ == '__main__':
    unittest.main()
