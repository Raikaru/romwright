# Stage 2 (types/casts) gates, 20261013

`off` = the decompiler casts (`ROMWRIGHT_NATIVE_CASTS=1`, rule `mwcc-void-pointer-arithmetic` disabled): the build before this stage. `def` = the default build. `parity` = the worker's casts with the rule disabled (the port alone). `noagg` = `ROMWRIGHT_RUST_CASTS_AGGREGATE=off`. exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.

| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled |
|---|---|---|---|---|---|---|---|---|---|
| m22-002 MWCC seed 20261010 | off | 55 | 193 | 76.976 | | | | | |
| m22-002 MWCC seed 20261010 | parity | 55 | 193 | 76.968 | 0 | 1 | 199 | 0 | 0 |
| m22-002 MWCC seed 20261010 | def_before_final_rebuild | 55 | 193 | 76.968 | 0 | 1 | 199 | 0 | 0 |
| m22-002 MWCC seed 20261010 | def | 55 | 193 | 76.968 | 0 | 1 | 199 | 0 | 0 |
| m22-002 MWCC seed 20261011 | off | 57 | 194 | 78.321 | | | | | |
| m22-002 MWCC seed 20261011 | parity | 57 | 194 | 78.316 | 0 | 1 | 199 | 0 | 0 |
| m22-002 MWCC seed 20261011 | def_before_final_rebuild | 57 | 194 | 78.316 | 0 | 1 | 199 | 0 | 0 |
| m22-002 MWCC seed 20261011 | def | 57 | 194 | 78.316 | 0 | 1 | 199 | 0 | 0 |
| m22-002 ee-gcc (fresh work dir per arm) | off | 106 | 197 | 86.403 | | | | | |
| m22-002 ee-gcc (fresh work dir per arm) | parity | 106 | 197 | 86.403 | 0 | 0 | 200 | 0 | 0 |
| m22-002 ee-gcc (fresh work dir per arm) | def | 106 | 197 | 86.403 | 0 | 0 | 200 | 0 | 0 |
| m22-003 dds | off | 61 | 196 | 76.818 | | | | | |
| m22-003 dds | def | 61 | 196 | 76.818 | 0 | 0 | 200 | 0 | 0 |
| m22-003 rc | off | 26 | 199 | 68.13 | | | | | |
| m22-003 rc | def | 26 | 199 | 68.113 | 0 | 1 | 199 | 0 | 0 |
| m22-003 p4 | off | 60 | 193 | 79.129 | | | | | |
| m22-003 p4 | def_before_final_rebuild | 60 | 193 | 79.4 | 2 | 0 | 198 | 0 | 0 |
| m22-003 p4 | def | 60 | 193 | 79.4 | 2 | 0 | 198 | 0 | 0 |
| m22-003 p4 | parity | 60 | 193 | 79.4 | 2 | 0 | 198 | 0 | 0 |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone, see stage2_followup) | off | 78 | 196 | 79.062 | | | | | |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone, see stage2_followup) | def | 78 | 196 | 79.062 | 0 | 0 | 200 | 0 | 0 |
| m22-003 ff | off | 20 | 145 | 49.294 | | | | | |
| m22-003 ff | def | 20 | 145 | 49.35 | 1 | 0 | 199 | 0 | 0 |
| m22-003 ff | noagg | 20 | 145 | 49.35 | 1 | 0 | 199 | 0 | 0 |
| m22-003 dc | off | 36 | 166 | 62.625 | | | | | |
| m22-003 dc | def_before_final_rebuild | 38 | 176 | 66.605 | 17 | 0 | 183 | 0 | 0 |
| m22-003 dc | def | 38 | 176 | 66.605 | 17 | 0 | 183 | 0 | 0 |
| m22-003 dc | parity | 36 | 166 | 63.314 | 7 | 0 | 193 | 0 | 0 |
| m22-003 dk | off | 28 | 169 | 67.36 | | | | | |
| m22-003 dk | def_before_final_rebuild | 29 | 176 | 70.804 | 15 | 0 | 185 | 0 | 0 |
| m22-003 dk | def | 29 | 176 | 70.804 | 15 | 0 | 185 | 0 | 0 |
| m22-003 dk | parity | 28 | 169 | 68.054 | 8 | 0 | 192 | 0 | 0 |
| m22-003 dk | noagg | 29 | 176 | 70.804 | 15 | 0 | 185 | 0 | 0 |

## Compile-failure classes per m22-003 lane (functions that did not compile, by the compiler's first diagnostic)

| lane | arm | classes |
|---|---|---|
| m22-003 dds | off | {"member access on a type the context lacks": 1, "type mismatch (assignment, operand, return, cast)": 1, "undeclared identifier": 2} |
| m22-003 dds | def | {"member access on a type the context lacks": 1, "type mismatch (assignment, operand, return, cast)": 1, "undeclared identifier": 2} |
| m22-003 rc | off | {"type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 rc | def | {"type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 p4 | off | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 p4 | def_before_final_rebuild | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 p4 | def | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 p4 | parity | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone, see stage2_followup) | off | {"assembler rejected the compiler's output": 1, "member access on a type the context lacks": 1, "undeclared identifier": 1} |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone, see stage2_followup) | def | {"assembler rejected the compiler's output": 1, "member access on a type the context lacks": 1, "undeclared identifier": 1} |
| m22-003 ff | off | {"call does not match prototype": 2, "conflicting types / redeclaration": 1, "member access on a type the context lacks": 25, "other": 1, "syntax error": 1, "type mismatch (assignment, operand, return, cast)": 22, "undeclared identifier": 3} |
| m22-003 ff | def | {"call does not match prototype": 2, "conflicting types / redeclaration": 1, "member access on a type the context lacks": 25, "other": 1, "syntax error": 1, "type mismatch (assignment, operand, return, cast)": 22, "undeclared identifier": 3} |
| m22-003 ff | noagg | {"call does not match prototype": 2, "conflicting types / redeclaration": 1, "member access on a type the context lacks": 25, "other": 1, "syntax error": 1, "type mismatch (assignment, operand, return, cast)": 22, "undeclared identifier": 3} |
| m22-003 dc | off | {"call does not match prototype": 1, "illegal or unknown type name": 11, "member access on a type the context lacks": 2, "syntax error": 11, "type mismatch (assignment, operand, return, cast)": 8, "unit post-processing rejected the candidate object": 1} |
| m22-003 dc | def_before_final_rebuild | {"call does not match prototype": 2, "member access on a type the context lacks": 2, "syntax error": 11, "type mismatch (assignment, operand, return, cast)": 8, "unit post-processing rejected the candidate object": 1} |
| m22-003 dc | def | {"call does not match prototype": 2, "member access on a type the context lacks": 2, "syntax error": 11, "type mismatch (assignment, operand, return, cast)": 8, "unit post-processing rejected the candidate object": 1} |
| m22-003 dc | parity | {"call does not match prototype": 1, "illegal or unknown type name": 11, "member access on a type the context lacks": 2, "syntax error": 11, "type mismatch (assignment, operand, return, cast)": 8, "unit post-processing rejected the candidate object": 1} |
| m22-003 dk | off | {"illegal or unknown type name": 8, "incomplete type": 1, "member access on a type the context lacks": 6, "syntax error": 8, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |
| m22-003 dk | def_before_final_rebuild | {"illegal or unknown type name": 1, "incomplete type": 1, "member access on a type the context lacks": 6, "syntax error": 8, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |
| m22-003 dk | def | {"illegal or unknown type name": 1, "incomplete type": 1, "member access on a type the context lacks": 6, "syntax error": 8, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |
| m22-003 dk | parity | {"illegal or unknown type name": 8, "incomplete type": 1, "member access on a type the context lacks": 6, "syntax error": 8, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |
| m22-003 dk | noagg | {"illegal or unknown type name": 1, "incomplete type": 1, "member access on a type the context lacks": 6, "syntax error": 8, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |

## Functions that lost an exact match or a compile (default build against `off`)

