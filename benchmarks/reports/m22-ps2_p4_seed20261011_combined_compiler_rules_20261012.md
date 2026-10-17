# m22-002: C output on matched Persona 4 functions (PS2, MWCCPS2 units)

Generated 2026-10-13T07:34:43+0000. Sample: 200 matched functions, seed 20261011, from 6445 eligible rows of the repo's verify report. Repo https://github.com/Raikaru/Persona4-Decompilation.git at `509519da5809`.

Scores are against the retail bytes of each function. `exact` is verify.py's MATCH criterion; `percent` is objdiff `match_percent` (functionRelocDiffs=none); a candidate that was not produced or does not compile counts as 0. `compile-failure share` = 1 - compiled / functions, so a function a tool produced nothing for is a failure.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 194 | 3.0% | 57 | 57 | 78.321 | 80.744 | 95 |
| m2c | 200 | 200 | 122 | 39.0% | 50 | 50 | 50.873 | 83.398 | 72 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 148 | 26.0% | 38 | 38 | 56.463 | 76.302 | 64 |
| m2c | 200 | 200 | 55 | 72.5% | 21 | 21 | 22.328 | 81.192 | 28 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 198 | 1.0% | 57 | 57 | 79.501 | 80.304 | 96 |
| m2c | 200 | 200 | 127 | 36.5% | 51 | 51 | 52.52 | 82.708 | 74 |

## Paired comparison on percent (functions where the first layer scores higher / lower)

| pair | wins | losses | ties | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 113 | 45 | 42 | 0.0 |
| romwright_vs_m2c_standalone | 110 | 14 | 76 | 0.0 |
| romwright_vs_m2c_best | 115 | 46 | 39 | 0.0 |

## By unit family (promoted = src/promoted, produced with m2c in the loop), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| cri | 9 | 0 / 38.167 / 0% | 0 / 8.254 / 67% |
| other | 80 | 23 / 79.456 / 5% | 19 / 51.654 / 42% |
| promoted | 111 | 34 / 80.76 / 2% | 31 / 53.765 / 34% |

## By code origin, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| main | 171 | 57 / 83.416 / 4% | 50 / 56.844 / 34% |
| third_party | 29 | 0 / 48.28 / 0% | 0 / 15.664 / 66% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| b119 -O4,p | 8 | 0 / 40.794 / 0% | 0 / 14.807 / 75% |
| b210 -O2 | 184 | 57 / 80.7 / 3% | 50 / 54.041 / 36% |
| b210 -O2,p | 8 | 0 / 61.138 / 0% | 0 / 14.077 / 75% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| 32-63 | 35 | 25 / 83.246 / 0% | 20 / 70.768 / 23% |
| 64-127 | 63 | 21 / 77.37 / 2% | 18 / 54.239 / 35% |
| 128-255 | 47 | 9 / 82.644 / 0% | 10 / 50.327 / 43% |
| 256-1024 | 55 | 2 / 72.584 / 9% | 2 / 34.822 / 51% |

## Compile failures of the context variant (first error, normalised)

**romwright**: illegal implicit conversion from 'X' to x2; illegal constant expression x2; undefined identifier 'X' x1; identifier 'func_002b5fd0(unsigned char *, struct , struct , union , union x1

**m2c**: call of non-function x23; illegal implicit conversion from 'X' to x18; illegal operands 'X' + 'X' x15; illegal operand x4; undefined identifier 'X' x4; pointer/array required x4; identifier 'X' redeclared x2; illegal constant expression x2

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
