# Upgrade round 1 (compile-failure classes) gates, 20261014

`off` = every switch of this round disabled. `def` = the default build (all on). `only-<key>` = that fix alone. exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.

| key | switch (`=off` disables) | fix |
|---|---|---|
| sub | `ROMWRIGHT_EXPORT_SUBPIECE_ARITY` | SUBPIECE intrinsic macro takes the printed offset argument |
| odd | `ROMWRIGHT_EXPORT_ODD_WIDTHS` | `undefined3/5/6/7` declared as byte arrays |
| loc | `ROMWRIGHT_EXPORT_LOCAL_VIEWS` | byte-array locals: whole-array values and `_off_w_` members |
| mis | `ROMWRIGHT_EXPORT_MISMATCH_NAMES` | `_NAME` / `stack0x...` / `_DAT_...` mismatch-symbol uses |
| dec | `ROMWRIGHT_EXPORT_DECLARED_VIEWS` | globals the header declares are read through that declaration |
| ctx | `ROMWRIGHT_EXPORT_CONTEXT_NAMES` | `void (*T[])(..)` is a declared name |
| ptr | `ROMWRIGHT_STRUCT_POINTEE_RUNS` | struct pointer field to a scalar run is `T *` |
| flt | `ROMWRIGHT_EXPORT_FLOAT_ARGS` | integer literal passed to a `float` parameter is the float its bits spell |
| acc | `ROMWRIGHT_EXPORT_DECLARED_ACCESS` | a header object of another shape than the printed one is read through its address |

How the arms ran: one release build (`romwright-cli`, `romwright-worker`, the pinned `ghidra_opt`), each arm a wrapper binary that sets its switches and `ROMWRIGHT_ARM` (the m22-002 harness drops `ROMWRIGHT_*` from the environment), `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`. An m22-003 arm restores the lane's prepared work directory and repo from a pristine snapshot taken after its prepare stage (the prepare records absolute paths, so the same path is restored, never a copy at another path) and imports the retail image afresh; an m22-002 arm prepares its own work directory and repo copy. The final-gate arms (`off`, `def`) of every lane are full 200-function runs; the m22-002 lane-1 isolation arms (the m22-002 runs of the nine fixes alone) are full runs too, those of the first nine-fix build (tag p1) for `sub`..`ptr` and of the final build (tag p2) for `flt` and `acc` (`--earlier p1`: the code of those seven fixes is the same in both builds). An m22-003 isolation arm and every leave-one-out arm ran `--only` the functions whose outcome differs between `off` and `def` (what a fix can change); rc `only-loc` ran in full. gh: the `gh` rows are the pristine repo copy (`~/runs/Ps2Lanes/repos/gh`, a smaller build), `ghclone` the repository as the harness clones it; their 200-function samples differ. Isolation arms first started with unknown arm names and ran as the default; those results were discarded (`out/invalid_defaults/`) and the arms re-run.

## Final gate: every fix off against every fix on (one build, a fresh import and work directory per arm)

| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled | gained exact | gained compiled |
|---|---|---|---|---|---|---|---|---|---|---|---|
| m22-002 MWCC seed 20261010 | off | 55 | 193 | 76.968 | | | | | | | |
| m22-002 MWCC seed 20261010 | def | 55 | 193 | 76.968 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261011 | off | 57 | 194 | 78.316 | | | | | | | |
| m22-002 MWCC seed 20261011 | def | 57 | 194 | 78.316 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-002 ee-gcc | off | 106 | 197 | 86.403 | | | | | | | |
| m22-002 ee-gcc | def | 106 | 197 | 86.403 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 dds | off | 61 | 196 | 76.818 | | | | | | | |
| m22-003 dds | def | 61 | 200 | 77.224 | 2 | 0 | 198 | 0 | 0 | 0 | 4 |
| m22-003 rc | off | 26 | 199 | 68.113 | | | | | | | |
| m22-003 rc | def | 26 | 200 | 68.158 | 1 | 0 | 199 | 0 | 0 | 0 | 1 |
| m22-003 p4 | off | 60 | 193 | 79.4 | | | | | | | |
| m22-003 p4 | def | 60 | 193 | 79.4 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | off | 78 | 196 | 79.062 | | | | | | | |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | def | 78 | 198 | 79.157 | 1 | 0 | 199 | 0 | 0 | 0 | 2 |
| m22-003 gh (harness clone) | off | 78 | 199 | 82.119 | | | | | | | |
| m22-003 gh (harness clone) | def | 78 | 199 | 82.119 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 ff | off | 20 | 145 | 49.35 | | | | | | | |
| m22-003 ff | def | 21 | 195 | 61.753 | 58 | 1 | 141 | 0 | 0 | 1 | 50 |
| m22-003 dc | off | 38 | 176 | 66.605 | | | | | | | |
| m22-003 dc | def | 38 | 186 | 69.844 | 10 | 0 | 190 | 0 | 0 | 0 | 10 |
| m22-003 dk | off | 29 | 176 | 70.804 | | | | | | | |
| m22-003 dk | def | 29 | 189 | 75.561 | 14 | 0 | 186 | 0 | 0 | 0 | 13 |

## Each fix alone (every other switch off) against everything off

An m22-002 arm is the whole 200-function sample. An m22-003 arm ran on the functions whose outcome differs between `off` and `def` (the others cannot change; `functions` is that count) and is compared with `off` on the same functions.

| gate | fix | functions | off exact / compiled / mean % | fix alone exact / compiled / mean % | better / worse / same | lost exact | lost compiled | gained exact | gained compiled |
|---|---|---|---|---|---|---|---|---|---|
| m22-002 MWCC seed 20261010 | only-sub | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-odd | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-loc | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-mis | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-dec | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-ctx | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-ptr | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-flt | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261010 | only-acc | 200 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 | 0 | 0 | 0 |
| m22-003 dds | only-loc | 4 | 0 / 0 / 0.0 | 0 / 2 / 2.368 | 1 / 0 / 3 | 0 | 0 | 0 | 2 |
| m22-003 dds | only-mis | 4 | 0 / 0 / 0.0 | 0 / 0 / 0.0 | 0 / 0 / 4 | 0 | 0 | 0 | 0 |
| m22-003 rc | only-loc | 200 | 26 / 199 / 68.113 | 26 / 200 / 68.158 | 1 / 0 / 199 | 0 | 0 | 0 | 1 |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | only-mis | 2 | 0 / 0 / 0.0 | 0 / 1 / 9.5 | 1 / 0 / 1 | 0 | 0 | 0 | 1 |
| m22-003 ff | only-odd | 65 | 0 / 15 / 13.445 | 0 / 15 / 13.445 | 0 / 0 / 65 | 0 | 0 | 0 | 0 |
| m22-003 ff | only-loc | 65 | 0 / 15 / 13.445 | 0 / 17 / 15.03 | 2 / 0 / 63 | 0 | 0 | 0 | 2 |
| m22-003 ff | only-mis | 65 | 0 / 15 / 13.445 | 0 / 15 / 13.445 | 0 / 0 / 65 | 0 | 0 | 0 | 0 |
| m22-003 ff | only-dec | 65 | 0 / 15 / 13.445 | 0 / 38 / 29.452 | 20 / 0 / 45 | 0 | 0 | 0 | 23 |
| m22-003 ff | only-ctx | 65 | 0 / 15 / 13.445 | 0 / 16 / 14.378 | 1 / 0 / 64 | 0 | 0 | 0 | 1 |
| m22-003 ff | only-ptr | 65 | 0 / 15 / 13.445 | 0 / 15 / 13.445 | 0 / 0 / 65 | 0 | 0 | 0 | 0 |
| m22-003 ff | only-flt | 65 | 0 / 15 / 13.445 | 0 / 15 / 13.445 | 0 / 0 / 65 | 0 | 0 | 0 | 0 |
| m22-003 ff | only-acc | 65 | 0 / 15 / 13.445 | 1 / 29 / 27.11 | 27 / 1 / 37 | 0 | 0 | 1 | 14 |
| m22-003 dc | only-sub | 12 | 0 / 0 / 0.0 | 0 / 4 / 23.782 | 2 / 0 / 8 | 0 | 0 | 0 | 2 |
| m22-003 dc | only-odd | 12 | 0 / 0 / 0.0 | 0 / 6 / 36.031 | 4 / 0 / 6 | 0 | 0 | 0 | 4 |
| m22-003 dc | only-dec | 12 | 0 / 0 / 0.0 | 0 / 3 / 15.981 | 1 / 0 / 9 | 0 | 0 | 0 | 1 |
| m22-003 dc | only-ptr | 12 | 0 / 0 / 0.0 | 0 / 2 / 10.632 | 0 / 0 / 10 | 0 | 0 | 0 | 0 |
| m22-003 dc | only-flt | 12 | 0 / 0 / 0.0 | 0 / 2 / 10.632 | 0 / 0 / 10 | 0 | 0 | 0 | 0 |
| m22-003 dc | only-acc | 12 | 0 / 0 / 0.0 | 0 / 2 / 10.632 | 0 / 0 / 10 | 0 | 0 | 0 | 0 |
| m22-003 dk | only-sub | 14 | 0 / 1 / 6.357 | 0 / 2 / 11.266 | 1 / 0 / 13 | 0 | 0 | 0 | 1 |
| m22-003 dk | only-odd | 14 | 0 / 1 / 6.357 | 0 / 3 / 15.839 | 2 / 0 / 12 | 0 | 0 | 0 | 2 |
| m22-003 dk | only-dec | 14 | 0 / 1 / 6.357 | 0 / 5 / 29.07 | 4 / 0 / 10 | 0 | 0 | 0 | 4 |
| m22-003 dk | only-ptr | 14 | 0 / 1 / 6.357 | 0 / 1 / 6.357 | 0 / 0 / 14 | 0 | 0 | 0 | 0 |
| m22-003 dk | only-flt | 14 | 0 / 1 / 6.357 | 0 / 1 / 6.357 | 0 / 0 / 14 | 0 | 0 | 0 | 0 |
| m22-003 dk | only-acc | 14 | 0 / 1 / 6.357 | 0 / 2 / 10.262 | 2 / 0 / 12 | 0 | 0 | 0 | 1 |

## Each fix left out of the default (every other switch on), against the default on the same functions

A fix whose removal loses a compile or an exact match is carrying it in the default; a fix that only works with another is visible here and not in the table above.

| gate | without | functions | default exact / compiled / mean % | without it exact / compiled / mean % | lost exact | lost compiled | functions worse by percent |
|---|---|---|---|---|---|---|---|
| m22-003 dds | loc | 4 | 0 / 4 / 20.283 | 0 / 0 / 0.0 | 0 | 4 | 2 |
| m22-003 dds | mis | 4 | 0 / 4 / 20.283 | 0 / 2 / 2.368 | 0 | 2 | 1 |
| m22-003 rc | loc | 1 | 0 / 1 / 8.878 | 0 / 0 / 0.0 | 0 | 1 | 1 |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | mis | 2 | 0 / 2 / 9.5 | 0 / 1 / 0.0 | 0 | 1 | 1 |
| m22-003 ff | odd | 65 | 1 / 65 / 51.608 | 1 / 64 / 50.597 | 0 | 1 | 3 |
| m22-003 ff | loc | 65 | 1 / 65 / 51.608 | 1 / 58 / 46.455 | 0 | 7 | 8 |
| m22-003 ff | mis | 65 | 1 / 65 / 51.608 | 1 / 61 / 49.522 | 0 | 4 | 5 |
| m22-003 ff | dec | 65 | 1 / 65 / 51.608 | 1 / 34 / 30.704 | 0 | 31 | 26 |
| m22-003 ff | ctx | 65 | 1 / 65 / 51.608 | 1 / 64 / 50.672 | 0 | 1 | 3 |
| m22-003 ff | ptr | 65 | 1 / 65 / 51.608 | 1 / 65 / 51.607 | 0 | 0 | 2 |
| m22-003 ff | flt | 65 | 1 / 65 / 51.608 | 1 / 65 / 51.607 | 0 | 0 | 2 |
| m22-003 ff | acc | 65 | 1 / 65 / 51.608 | 0 / 47 / 34.527 | 1 | 18 | 36 |
| m22-003 dc | sub | 12 | 0 / 10 / 64.783 | 0 / 8 / 43.829 | 0 | 4 | 4 |
| m22-003 dc | odd | 12 | 0 / 10 / 64.783 | 0 / 7 / 34.495 | 0 | 5 | 5 |
| m22-003 dc | dec | 12 | 0 / 10 / 64.783 | 0 / 10 / 56.823 | 0 | 2 | 2 |
| m22-003 dc | acc | 12 | 0 / 10 / 64.783 | 0 / 12 / 64.615 | 0 | 0 | 1 |
| m22-003 dk | sub | 14 | 0 / 14 / 74.314 | 0 / 11 / 60.18 | 0 | 3 | 3 |
| m22-003 dk | odd | 14 | 0 / 14 / 74.314 | 0 / 9 / 48.079 | 0 | 5 | 5 |
| m22-003 dk | dec | 14 | 0 / 14 / 74.314 | 0 / 7 / 34.331 | 0 | 7 | 7 |
| m22-003 dk | acc | 14 | 0 / 14 / 74.314 | 0 / 13 / 70.589 | 0 | 1 | 2 |

## Compile-failure classes per m22-003 lane, off against def (functions that did not compile, by the compiler's first diagnostic)

| lane | arm | classes |
|---|---|---|
| m22-003 dds | off | {"member access on a type the context lacks": 1, "type mismatch (assignment, operand, return, cast)": 1, "undeclared identifier": 2} |
| m22-003 dds | def | {} |
| m22-003 rc | off | {"type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 rc | def | {} |
| m22-003 p4 | off | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 p4 | def | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | off | {"assembler rejected the compiler's output": 1, "member access on a type the context lacks": 1, "undeclared identifier": 1} |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | def | {"assembler rejected the compiler's output": 1} |
| m22-003 gh (harness clone) | off | {} |
| m22-003 gh (harness clone) | def | {} |
| m22-003 ff | off | {"call does not match prototype": 2, "conflicting types / redeclaration": 1, "member access on a type the context lacks": 25, "other": 1, "syntax error": 1, "type mismatch (assignment, operand, return, cast)": 22, "undeclared identifier": 3} |
| m22-003 ff | def | {"type mismatch (assignment, operand, return, cast)": 5} |
| m22-003 dc | off | {"call does not match prototype": 2, "member access on a type the context lacks": 2, "syntax error": 11, "type mismatch (assignment, operand, return, cast)": 8, "unit post-processing rejected the candidate object": 1} |
| m22-003 dc | def | {"call does not match prototype": 2, "type mismatch (assignment, operand, return, cast)": 10, "undeclared identifier": 1, "unit post-processing rejected the candidate object": 1} |
| m22-003 dk | off | {"illegal or unknown type name": 1, "incomplete type": 1, "member access on a type the context lacks": 6, "syntax error": 8, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |
| m22-003 dk | def | {"illegal or unknown type name": 1, "member access on a type the context lacks": 2, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |

## Named sub-classes, off against def (first diagnostic's source line)

| lane | arm | syntax: undefinedN | syntax: macro arity | c1: byte-array local value | b: partial member `_o_w_` | b: union members (.uN/.whole) | undeclared `_NAME`/stack0x |
|---|---|---|---|---|---|---|---|
| m22-003 dds | off | 0 | 0 | 1 | 1 | 0 | 2 |
| m22-003 dds | def | 0 | 0 | 0 | 0 | 0 | 0 |
| m22-003 rc | off | 0 | 0 | 1 | 0 | 0 | 0 |
| m22-003 rc | def | 0 | 0 | 0 | 0 | 0 | 0 |
| m22-003 p4 | off | 0 | 0 | 0 | 0 | 0 | 1 |
| m22-003 p4 | def | 0 | 0 | 0 | 0 | 0 | 1 |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | off | 0 | 0 | 0 | 1 | 0 | 1 |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | def | 0 | 0 | 0 | 0 | 0 | 0 |
| m22-003 gh (harness clone) | off | 0 | 0 | 0 | 0 | 0 | 0 |
| m22-003 gh (harness clone) | def | 0 | 0 | 0 | 0 | 0 | 0 |
| m22-003 ff | off | 2 | 0 | 4 | 1 | 25 | 2 |
| m22-003 ff | def | 0 | 0 | 0 | 0 | 0 | 0 |
| m22-003 dc | off | 7 | 4 | 0 | 0 | 7 | 0 |
| m22-003 dc | def | 1 | 0 | 0 | 0 | 1 | 0 |
| m22-003 dk | off | 7 | 3 | 0 | 1 | 7 | 0 |
| m22-003 dk | def | 0 | 0 | 0 | 0 | 0 | 0 |

## Named sub-classes, each fix alone against off on the same functions

| lane | fix | off | fix alone |
|---|---|---|---|
| m22-003 dds | only-loc | c1: byte-array local value: 1, b: partial member `_o_w_`: 1, undeclared `_NAME`/stack0x: 2 | undeclared `_NAME`/stack0x: 2 |
| m22-003 dds | only-mis | c1: byte-array local value: 1, b: partial member `_o_w_`: 1, undeclared `_NAME`/stack0x: 2 | c1: byte-array local value: 1, b: partial member `_o_w_`: 3 |
| m22-003 gh (pristine repo copy: a smaller build than the harness clone) | only-mis | b: partial member `_o_w_`: 1, undeclared `_NAME`/stack0x: 1 | b: partial member `_o_w_`: 1 |
| m22-003 ff | only-odd | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | c1: byte-array local value: 5, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 26, undeclared `_NAME`/stack0x: 2 |
| m22-003 ff | only-loc | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | syntax: undefinedN: 2, b: union members (.uN/.whole): 28, undeclared `_NAME`/stack0x: 2 |
| m22-003 ff | only-mis | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 2, b: union members (.uN/.whole): 25 |
| m22-003 ff | only-dec | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | syntax: undefinedN: 1, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 1, undeclared `_NAME`/stack0x: 2 |
| m22-003 ff | only-ctx | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 |
| m22-003 ff | only-ptr | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 |
| m22-003 ff | only-flt | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 |
| m22-003 ff | only-acc | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 25, undeclared `_NAME`/stack0x: 2 | syntax: undefinedN: 2, c1: byte-array local value: 4, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 27, undeclared `_NAME`/stack0x: 3 |
| m22-003 dc | only-sub | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 | syntax: undefinedN: 5, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 3 |
| m22-003 dc | only-odd | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 | syntax: macro arity: 4, b: union members (.uN/.whole): 6 |
| m22-003 dc | only-dec | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 | syntax: undefinedN: 5, syntax: macro arity: 3, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 3 |
| m22-003 dc | only-ptr | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 |
| m22-003 dc | only-flt | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 |
| m22-003 dc | only-acc | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 | syntax: undefinedN: 5, syntax: macro arity: 3, b: union members (.uN/.whole): 5 |
| m22-003 dk | only-sub | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 | syntax: undefinedN: 5, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 5 |
| m22-003 dk | only-odd | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 | syntax: macro arity: 3, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 9 |
| m22-003 dk | only-dec | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 2 |
| m22-003 dk | only-ptr | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 |
| m22-003 dk | only-flt | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 |
| m22-003 dk | only-acc | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 | syntax: undefinedN: 5, syntax: macro arity: 2, b: partial member `_o_w_`: 1, b: union members (.uN/.whole): 6 |

## Functions that lost an exact match or a compile (default build against `off`)

none

## ps2_decompile_success

```json
{
 "off": {
  "ps2-fatal-frame": {
   "sampled": 942,
   "decompiled": 942
  },
  "ps2-ratchet-clank-pal": {
   "sampled": 859,
   "decompiled": 858
  },
  "ps2-god-hand": {
   "sampled": 980,
   "decompiled": 980
  },
  "ps2-digital-devil-saga": {
   "sampled": 977,
   "decompiled": 977
  },
  "ps2-dark-chronicle": {
   "sampled": 969,
   "decompiled": 969
  },
  "ps2-ratchet-clank": {
   "sampled": 861,
   "decompiled": 859
  },
  "ps2-persona-4": {
   "sampled": 975,
   "decompiled": 974
  },
  "ps2-dark-cloud": {
   "sampled": 937,
   "decompiled": 888
  }
 },
 "def": {
  "ps2-fatal-frame": {
   "sampled": 942,
   "decompiled": 942
  },
  "ps2-ratchet-clank-pal": {
   "sampled": 859,
   "decompiled": 858
  },
  "ps2-god-hand": {
   "sampled": 980,
   "decompiled": 980
  },
  "ps2-digital-devil-saga": {
   "sampled": 977,
   "decompiled": 977
  },
  "ps2-dark-chronicle": {
   "sampled": 969,
   "decompiled": 969
  },
  "ps2-ratchet-clank": {
   "sampled": 861,
   "decompiled": 859
  },
  "ps2-persona-4": {
   "sampled": 975,
   "decompiled": 974
  },
  "ps2-dark-cloud": {
   "sampled": 937,
   "decompiled": 888
  }
 }
}
```

## ps2_decompile_success_total

```json
{
 "off [decompiled, sampled]": [
  7447,
  7500
 ],
 "def [decompiled, sampled]": [
  7447,
  7500
 ],
 "games that differ": []
}
```

## m21-001_off

```json
{
 "status": "pass",
 "failures": [],
 "rows": {
  "gba-pokeemerald": {
   "truth": 15856,
   "found": 15520,
   "recall": 0.9761,
   "precision": 0.9972,
   "size_exact": 15421
  },
  "nds-pokeheartgold-arm9": {
   "truth": 11078,
   "found": 10801,
   "recall": 0.9735,
   "precision": 0.9984,
   "size_exact": 9888
  },
  "ps2-capcom-fighting-evolution": {
   "truth": 8794,
   "found": 8613,
   "recall": 0.9741,
   "precision": 0.9945,
   "size_exact": 8548
  },
  "ps2-dungeon-game": {
   "truth": 783,
   "found": 786,
   "recall": 0.9872,
   "precision": 0.9835,
   "size_exact": 751
  },
  "psx-darkstalkers-3": {
   "truth": 818,
   "found": 2206,
   "recall": 0.9878,
   "precision": 0.3663,
   "size_exact": 0
  },
  "psv-need-for-speed-most-wanted": {
   "truth": 26495,
   "found": 26535,
   "recall": 0.9734,
   "precision": 0.9719,
   "size_exact": 16304
  },
  "x360-black-ops-2": {
   "truth": 27730,
   "found": 27364,
   "recall": 0.9833,
   "precision": 0.9964,
   "size_exact": 0
  }
 }
}
```

## m21-001_def

```json
{
 "status": "pass",
 "failures": [],
 "rows": {
  "gba-pokeemerald": {
   "truth": 15856,
   "found": 15520,
   "recall": 0.9761,
   "precision": 0.9972,
   "size_exact": 15421
  },
  "nds-pokeheartgold-arm9": {
   "truth": 11078,
   "found": 10801,
   "recall": 0.9735,
   "precision": 0.9984,
   "size_exact": 9888
  },
  "ps2-capcom-fighting-evolution": {
   "truth": 8794,
   "found": 8613,
   "recall": 0.9741,
   "precision": 0.9945,
   "size_exact": 8548
  },
  "ps2-dungeon-game": {
   "truth": 783,
   "found": 786,
   "recall": 0.9872,
   "precision": 0.9835,
   "size_exact": 751
  },
  "psx-darkstalkers-3": {
   "truth": 818,
   "found": 2206,
   "recall": 0.9878,
   "precision": 0.3663,
   "size_exact": 0
  },
  "psv-need-for-speed-most-wanted": {
   "truth": 26495,
   "found": 26535,
   "recall": 0.9734,
   "precision": 0.9719,
   "size_exact": 16304
  },
  "x360-black-ops-2": {
   "truth": 27730,
   "found": 27364,
   "recall": 0.9833,
   "precision": 0.9964,
   "size_exact": 0
  }
 }
}
```

## printer_differential

```json
{
 "decompiled": 1800,
 "identical": 1800,
 "identical_rate": 1.0
}
```

## struct_pointer_fields

```json
{
 "ps2-dark-chronicle": {
  "default": {
   "addresses": 400,
   "structs_printed": 27,
   "pointer_fields": {
    "fields": 497,
    "void *": 1,
    "non-pointer fields read through a pointer cast": 15
   },
   "scalar_pointee_types": {}
  },
  "runs_off": {
   "structs_printed": 27,
   "pointer_fields": {
    "fields": 497,
    "void *": 1,
    "non-pointer fields read through a pointer cast": 15
   },
   "scalar_pointee_types": {}
  }
 },
 "ps2-digital-devil-saga": {
  "default": {
   "addresses": 400,
   "structs_printed": 28,
   "pointer_fields": {
    "fields": 142,
    "non-pointer fields read through a pointer cast": 19
   },
   "scalar_pointee_types": {}
  },
  "runs_off": {
   "structs_printed": 28,
   "pointer_fields": {
    "fields": 142,
    "non-pointer fields read through a pointer cast": 19
   },
   "scalar_pointee_types": {}
  }
 },
 "ps2-fatal-frame": {
  "default": {
   "addresses": 400,
   "structs_printed": 20,
   "pointer_fields": {
    "fields": 105,
    "non-pointer fields read through a pointer cast": 7
   },
   "scalar_pointee_types": {}
  },
  "runs_off": {
   "structs_printed": 20,
   "pointer_fields": {
    "fields": 105,
    "non-pointer fields read through a pointer cast": 7
   },
   "scalar_pointee_types": {}
  }
 },
 "ps2-god-hand": {
  "default": {
   "addresses": 400,
   "structs_printed": 49,
   "pointer_fields": {
    "fields": 378,
    "non-pointer fields read through a pointer cast": 15
   },
   "scalar_pointee_types": {}
  },
  "runs_off": {
   "structs_printed": 49,
   "pointer_fields": {
    "fields": 378,
    "non-pointer fields read through a pointer cast": 15
   },
   "scalar_pointee_types": {}
  }
 },
 "ps2-persona-4": {
  "default": {
   "addresses": 400,
   "structs_printed": 25,
   "pointer_fields": {
    "fields": 186,
    "failed": 1,
    "non-pointer fields read through a pointer cast": 17
   },
   "scalar_pointee_types": {}
  },
  "runs_off": {
   "structs_printed": 25,
   "pointer_fields": {
    "fields": 186,
    "failed": 1,
    "non-pointer fields read through a pointer cast": 17
   },
   "scalar_pointee_types": {}
  }
 }
}
```
