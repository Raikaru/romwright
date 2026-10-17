# m22-002: C output on matched Persona 4 functions (PS2, ee-gcc 2.96 units)

Generated 2026-10-11T18:31:55-0400. Sample: 200 matched functions, seed 20261010, from 592 eligible rows of the repo's verify report. Repo https://github.com/Raikaru/Persona4-Decompilation.git at `509519da5809`.

Scores are against the retail bytes of each function. `exact` is verify.py's MATCH criterion; `percent` is objdiff `match_percent` (functionRelocDiffs=none); a candidate that was not produced or does not compile counts as 0. `compile-failure share` = 1 - compiled / functions, so a function a tool produced nothing for is a failure.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 197 | 1.5% | 106 | 106 | 86.406 | 87.722 | 126 |
| m2c | 200 | 200 | 164 | 18.0% | 101 | 101 | 74.41 | 90.744 | 119 |
| stock | 200 | 200 | 173 | 13.5% | 55 | 55 | 65.526 | 75.752 | 78 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 182 | 9.0% | 100 | 100 | 79.649 | 87.526 | 119 |
| m2c | 200 | 200 | 143 | 28.5% | 82 | 82 | 64.933 | 90.815 | 103 |
| stock | 200 | 200 | 173 | 13.5% | 55 | 55 | 65.526 | 75.752 | 78 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 197 | 1.5% | 110 | 110 | 86.753 | 88.074 | 130 |
| m2c | 200 | 200 | 171 | 14.5% | 105 | 105 | 77.716 | 90.896 | 124 |
| stock | 200 | 200 | 173 | 13.5% | 55 | 55 | 65.526 | 75.752 | 78 |

## Paired comparison on percent (functions where the first layer scores higher / lower)

| pair | wins | losses | ties | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 61 | 30 | 109 | 0.001517 |
| romwright_vs_m2c_standalone | 73 | 38 | 89 | 0.001151 |
| romwright_vs_m2c_best | 55 | 30 | 115 | 0.008836 |
| romwright_vs_stock_context | 116 | 17 | 67 | 0.0 |
| romwright_vs_stock_standalone | 100 | 29 | 71 | 0.0 |
| romwright_vs_stock_best | 117 | 15 | 68 | 0.0 |
| m2c_vs_stock_context | 99 | 41 | 60 | 1e-06 |
| m2c_vs_stock_standalone | 82 | 57 | 61 | 0.041398 |
| m2c_vs_stock_best | 103 | 37 | 60 | 0.0 |

## By unit family (promoted = src/promoted, produced with m2c in the loop), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| cri | 191 | 97 / 85.765 / 2% | 93 / 73.247 / 19% | 48 / 64.065 / 14% |
| promoted | 9 | 9 / 100.0 / 0% | 8 / 99.111 / 0% | 7 / 96.524 / 0% |

## By code origin, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| third_party | 200 | 106 / 86.406 / 2% | 101 / 74.41 / 18% | 55 / 65.526 / 14% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| ee-gcc 2.96 -O2 -G0 | 200 | 106 / 86.406 / 2% | 101 / 74.41 / 18% | 55 / 65.526 / 14% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | stock exact / mean % / fail |
|---|---|---|---|---|
| 32-63 | 81 | 62 / 94.701 / 1% | 61 / 84.963 / 14% | 40 / 72.779 / 12% |
| 64-127 | 77 | 39 / 85.678 / 1% | 37 / 78.765 / 10% | 15 / 66.626 / 8% |
| 128-255 | 31 | 5 / 76.309 / 3% | 3 / 55.778 / 29% | 0 / 53.535 / 19% |
| 256-1024 | 11 | 0 / 58.874 / 0% | 0 / 18.733 / 73% | 0 / 38.203 / 45% |

## Compile failures of the context variant (first error, normalised)

**romwright**: too few arguments to function `strlen' x2

**m2c**: warning: conflicting types for built-in function `memcpy' x10; `sp' undeclared (first use in this function) x8; invalid type argument of `unary *' x4; warning: dereferencing `void *' pointer x3; too few arguments to function `strlen' x2; warning: conflicting types for built-in function `memcmp' x1; warning: assignment makes pointer from integer without a cast x1; conflicting types for `ADX_DecodeInfoAu' x1

**stock**: warning: conflicting types for built-in function `memcpy' x7; `true' undeclared (first use in this function) x4; warning: comparison of distinct pointer types lacks a cast x4; called object is not a function x2; parse error before "ACSSBADX_CreateHndl" x1; no symbol ADXERR_ItoA in the object ('X') x1; no symbol ADXSJE_Create in the object ('X') x1; `bool' undeclared (first use in this function) x1

## Limits

- Persona 4 only; the units retail built with ee-gcc 2.96-ee-001003-1 (`config/gcc_units.txt`: the CRI ADX/SFD/ACS library, the Sony SDK and a few promoted units), compiled `-O2 -G0` through the repo's `tools/eegcc_shim.py` and GNU `as` 2.12-ee. ee-gcc and the EE assembler are i386 ELFs with a fixed `/lib/ld-linux.so.2` interpreter; on a host without it the harness runs inside a bubblewrap mount namespace that supplies the user's 32-bit loader at that path (tmpfs overlay, nothing on the host changes). Every function is vendor code (CRI middleware, Sony SDK): the decompilation's sources for it were written by hand against retail, with no m2c in the loop. m2c runs as `-t mipsee-gcc-c`; there is no per-function `#pragma` state (ee-gcc is configured by the shim's fixed flags), and the context is `ee-gcc -E` of the unit with INCLUDE_ASM/INCLUDE_RODATA removed.
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
