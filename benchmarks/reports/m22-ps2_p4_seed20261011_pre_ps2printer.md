# m22-002: C output on matched Persona 4 functions (PS2)

Generated 2026-10-10T23:35:32-0400. Sample: 200 matched functions, seed 20261011, from 6445 eligible rows of the repo's verify report. Repo https://github.com/Raikaru/Persona4-Decompilation.git at `509519da5809`.

Scores are against the retail bytes of each function. `exact` is verify.py's MATCH criterion; `percent` is objdiff `match_percent` (functionRelocDiffs=none); a candidate that was not produced or does not compile counts as 0. `compile-failure share` = 1 - compiled / functions, so a function a tool produced nothing for is a failure.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 163 | 18.5% | 28 | 28 | 60.951 | 74.786 | 59 |
| m2c | 200 | 200 | 122 | 39.0% | 50 | 50 | 50.873 | 83.398 | 72 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 147 | 26.5% | 23 | 23 | 51.907 | 70.622 | 46 |
| m2c | 200 | 200 | 55 | 72.5% | 21 | 21 | 22.328 | 81.192 | 28 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 181 | 9.5% | 28 | 28 | 66.632 | 73.626 | 61 |
| m2c | 200 | 200 | 127 | 36.5% | 51 | 51 | 52.52 | 82.708 | 74 |

## Paired comparison on percent (functions where the first layer scores higher / lower)

| pair | wins | losses | ties | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 78 | 75 | 47 | 0.871618 |
| romwright_vs_m2c_standalone | 101 | 23 | 76 | 0.0 |
| romwright_vs_m2c_best | 87 | 76 | 37 | 0.433567 |

## By unit family (promoted = src/promoted, produced with m2c in the loop), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| other | 89 | 11 / 54.597 / 27% | 19 / 47.265 / 45% |
| promoted | 111 | 17 / 66.045 / 12% | 31 / 53.765 / 34% |

## By code origin, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| main | 171 | 28 / 64.623 / 19% | 50 / 56.844 / 34% |
| third_party | 29 | 0 / 39.297 / 17% | 0 / 15.664 / 66% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| b119 -O4,p | 8 | 0 / 25.923 / 38% | 0 / 14.807 / 75% |
| b210 -O2 | 184 | 28 / 62.92 / 18% | 50 / 54.041 / 36% |
| b210 -O2,p | 8 | 0 / 50.687 / 12% | 0 / 14.077 / 75% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| 32-63 | 35 | 19 / 78.912 / 9% | 20 / 70.768 / 23% |
| 64-127 | 63 | 6 / 65.323 / 11% | 18 / 54.239 / 35% |
| 128-255 | 47 | 2 / 60.361 / 19% | 10 / 50.327 / 43% |
| 256-1024 | 55 | 1 / 45.016 / 33% | 2 / 34.822 / 51% |

## Compile failures of the context variant (first error, normalised)

**romwright**: illegal implicit conversion from 'X' to x25; undefined identifier 'X' x3; identifier 'X' redeclared x2; illegal constant expression x2; identifier 'X' x1; identifier 'func_002b5fd0(unsigned char *, struct , struct , union , union x1; function call 'X' does not x1; identifier 'func_0033d630(struct , short, float, unsigned char, signed x1

**m2c**: call of non-function x23; illegal implicit conversion from 'X' to x18; illegal operands 'X' + 'X' x15; illegal operand x4; undefined identifier 'X' x4; pointer/array required x4; identifier 'X' redeclared x2; illegal constant expression x2

## Limits

- Persona 4 only; MWCCPS2 3.0.1 b210 (default, `-O2`), b210 `-O2,p` speed units and b119 (`-O4,p`) units are in scope; units built with ee-gcc 2.96 (`config/gcc_units.txt`) are excluded, because the supplied ee-gcc and Sony assembler are i386 binaries with a fixed `/lib/ld-linux.so.2` loader that this host does not have.
- The matched set is the decompilation's own, and its sources were produced with m2c (and sometimes romwright) in the loop (`tools/m2c_bulk.py` promotes verified m2c candidates into `src/promoted`). The `promoted` and `other` strata are reported separately; the m2c number on `promoted` is an upper bound, not a measure of m2c on unseen code.
- Per-function `#pragma` state (optimisation level, scheduling) is replayed from the unit's source for every layer: it is the compiler configuration the match depends on, but a decompiler cannot choose it. `#if` branches are evaluated by a fixed rule (`#if 0`, `NON_MATCHING`, `RWDEBUG`, `RWSUPPRESSINLINE`, `DUNROAMIN` inactive).
- The context is the unit's own declarations, including the target's prototype and every data declaration of the unit, as in m22-001. romwright and m2c are given them (assert-prototypes / --context); stock Ghidra is not: its text keeps its own signatures, so the unit's prototype for the target is dropped from the context of its compiles, and its globals are declared as Ghidra typed them (`ExportDecompiledC.java`; gp-named globals the script could not resolve from the prefix Ghidra put on the name).
- romwright prototypes are asserted sequentially in address order into one project; a callee absent from a unit's declarations keeps a prototype asserted for an earlier unit.
- m2c reads the repo's splat assembly. Its input differs from the repo file only by `%gp_rel(symbol)($gp)` operands and jump-table rows (recorded per function). Reassembly parity is not checked (the repo's own regenerate-asm proves the fallback files byte-exact; the rewrite preserves register and offset by construction).
- Retail bytes carry no relocations, so objdiff ignores relocation targets (`functionRelocDiffs=none`); `exact_symbols` is the stricter count.
- A function counts as compiled only if the object defines the target symbol; the compile-failure share counts a function the tool produced no text for as a failure (`produced` is the other column).
- 200 functions from 6445 eligible rows; the sign tests treat functions as independent although they share units and pragma state, so their p values are indicative.
- romwright's import of the retail ELF is `partial` (switch decompile budget on a few functions, recorded under `romwright_project`); a matched function that import did not discover has no `export-c` candidate.
- Stock Ghidra's text is not meant to compile; its candidates get typedefs for Ghidra's primitive names and nothing else (no CONCAT/SUB macros).
