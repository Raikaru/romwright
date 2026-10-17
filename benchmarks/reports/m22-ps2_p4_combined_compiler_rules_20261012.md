# m22-002: C output on matched Persona 4 functions (PS2, MWCCPS2 units)

Generated 2026-10-13T07:27:08+0000. Sample: 200 matched functions, seed 20261010, from 6445 eligible rows of the repo's verify report. Repo https://github.com/Raikaru/Persona4-Decompilation.git at `509519da5809`.

Scores are against the retail bytes of each function. `exact` is verify.py's MATCH criterion; `percent` is objdiff `match_percent` (functionRelocDiffs=none); a candidate that was not produced or does not compile counts as 0. `compile-failure share` = 1 - compiled / functions, so a function a tool produced nothing for is a failure.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 193 | 3.5% | 55 | 55 | 76.976 | 79.768 | 91 |
| m2c | 200 | 199 | 101 | 49.5% | 32 | 32 | 40.41 | 80.02 | 52 |
| stock | 200 | 200 | 110 | 45.0% | 7 | 7 | 37.7 | 68.546 | 21 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 148 | 26.0% | 42 | 42 | 56.976 | 76.995 | 63 |
| m2c | 200 | 199 | 44 | 78.0% | 12 | 12 | 15.965 | 72.566 | 17 |
| stock | 200 | 200 | 125 | 37.5% | 8 | 8 | 43.114 | 68.983 | 23 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 196 | 2.0% | 56 | 56 | 78.144 | 79.739 | 91 |
| m2c | 200 | 199 | 106 | 47.0% | 32 | 32 | 42.362 | 79.929 | 54 |
| stock | 200 | 200 | 127 | 36.5% | 8 | 8 | 43.685 | 68.795 | 23 |

## Paired comparison on percent (functions where the first layer scores higher / lower)

| pair | wins | losses | ties | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 130 | 33 | 37 | 0.0 |
| romwright_vs_m2c_standalone | 123 | 14 | 63 | 0.0 |
| romwright_vs_m2c_best | 131 | 34 | 35 | 0.0 |
| romwright_vs_stock_context | 163 | 11 | 26 | 0.0 |
| romwright_vs_stock_standalone | 115 | 37 | 48 | 0.0 |
| romwright_vs_stock_best | 165 | 10 | 25 | 0.0 |
| m2c_vs_stock_context | 79 | 58 | 63 | 0.087133 |
| m2c_vs_stock_standalone | 26 | 105 | 69 | 0.0 |
| m2c_vs_stock_best | 76 | 69 | 55 | 0.618445 |

## By unit family (promoted = src/promoted, produced with m2c in the loop), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| cri | 7 | 0 / 40.46 / 0% | 0 / 11.677 / 71% | 0 / 31.829 / 29% |
| other | 91 | 24 / 76.169 / 3% | 13 / 37.013 / 53% | 1 / 37.512 / 46% |
| promoted | 102 | 31 / 80.201 / 4% | 19 / 45.413 / 45% | 6 / 38.271 / 45% |

## By code origin, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| main | 174 | 51 / 80.677 / 4% | 30 / 44.068 / 47% | 6 / 39.493 / 45% |
| third_party | 26 | 4 / 52.203 / 0% | 2 / 15.928 / 69% | 1 / 25.703 / 42% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| b119 -O4,p | 7 | 1 / 39.71 / 0% | 0 / 12.714 / 86% | 0 / 12.416 / 57% |
| b210 -O2 | 188 | 53 / 78.332 / 4% | 31 / 41.984 / 47% | 7 / 38.85 / 44% |
| b210 -O2,p | 5 | 1 / 78.167 / 0% | 1 / 20.0 / 80% | 0 / 29.867 / 60% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| 32-63 | 29 | 21 / 87.058 / 0% | 13 / 56.022 / 38% | 6 / 41.761 / 45% |
| 64-127 | 55 | 23 / 83.776 / 2% | 15 / 57.236 / 35% | 1 / 54.302 / 33% |
| 128-255 | 51 | 8 / 71.142 / 2% | 4 / 24.954 / 65% | 0 / 32.009 / 47% |
| 256-1024 | 65 | 3 / 71.301 / 8% | 0 / 31.334 / 55% | 0 / 26.306 / 54% |

## Compile failures of the context variant (first error, normalised)

**romwright**: illegal implicit conversion from 'X' to x3; undefined identifier 'X' x2; 'X' expected x1; illegal constant expression x1

**m2c**: illegal implicit conversion from 'X' to x31; call of non-function x23; illegal operands 'X' + 'X' x15; undefined identifier 'X' x10; pointer/array required x6; identifier 'X' redeclared x5; illegal explicit conversion from 'X' to x3; illegal use of type 'X' x2

**stock**: call of non-function x31; identifier 'X' redeclared x19; undefined identifier 'X' x14; declaration syntax error x9; illegal implicit conversion from 'X' to x6; 'X' expected x4; no symbol func_0011ac70 in the object ('X') x1; identifier 'func_001d4780(unsigned char *, unsigned char *, unsigned char x1

## Limits

- Persona 4 only; MWCCPS2 3.0.1 b210 (default, `-O2`), b210 `-O2,p` speed units and b119 (`-O4,p`) units are in scope; units built with ee-gcc 2.96 (`config/gcc_units.txt`) are the separate `--compiler eegcc` lane (`m22-ps2_p4_eegcc.{json,md}`).
- The matched set is the decompilation's own, and its sources were produced with m2c (and sometimes romwright) in the loop (`tools/m2c_bulk.py` promotes verified m2c candidates into `src/promoted`). The `promoted` and `other` strata are reported separately; the m2c number on `promoted` is an upper bound, not a measure of m2c on unseen code.
- Per-function `#pragma` state (optimisation level, scheduling) is replayed from the unit's source for every layer: it is the compiler configuration the match depends on, but a decompiler cannot choose it. `#if` branches are evaluated by a fixed rule (`#if 0`, `NON_MATCHING`, `RWDEBUG`, `RWSUPPRESSINLINE`, `DUNROAMIN` inactive).
- The context is the unit's own declarations, including the target's prototype and every data declaration of the unit, as in m22-001. romwright and m2c are given them (assert-prototypes / --context); stock Ghidra is not: its text keeps its own signatures, so the unit's prototype for the target is dropped from the context of its compiles, and its globals are declared as Ghidra typed them (`ExportDecompiledC.java`; gp-named globals the script could not resolve from the prefix Ghidra put on the name).
- romwright prototypes are asserted sequentially in address order into one project; a callee absent from a unit's declarations keeps a prototype asserted for an earlier unit.
- `export-c --context` also hands the unit's declarations to the printer, which casts a pointer where the context declares an integer (and the reverse), takes the declared return type for a local a callee's result is assigned to, prints the target with the declared parameter types and drops arguments a declaration does not have. The standalone variant is the same text compiled without those declarations, so what it fails on is what the text leaves to them (a callee left to `Supplied declaration required`, a callee result assigned to a local of the other kind).
- m2c reads the repo's splat assembly. Its input differs from the repo file only by `%gp_rel(symbol)($gp)` operands and jump-table rows (recorded per function). Reassembly parity is not checked (the repo's own regenerate-asm proves the fallback files byte-exact; the rewrite preserves register and offset by construction).
- Retail bytes carry no relocations, so objdiff ignores relocation targets (`functionRelocDiffs=none`); `exact_symbols` is the stricter count.
- A function counts as compiled only if the object defines the target symbol; the compile-failure share counts a function the tool produced no text for as a failure (`produced` is the other column).
- The sample is up to 200 functions from the eligible rows; the sign tests treat functions as independent although they share units and pragma state, so their p values are indicative.
- romwright's import of the retail ELF is `partial` (switch decompile budget on a few functions, recorded under `romwright_project`); a matched function that import did not discover has no `export-c` candidate.
- Stock Ghidra's text is not meant to compile; its candidates get typedefs for Ghidra's primitive names and nothing else (no CONCAT/SUB macros).
