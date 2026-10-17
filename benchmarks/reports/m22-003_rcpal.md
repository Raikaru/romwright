# m22-003: C output on matched ps2-ratchet-clank-pal functions (PS2, rcpal lane)

Generated 2026-10-12T21:43:41+0000. Sample: 200 matched functions, seed 20261012, from 1003 matched functions of 32-1024 bytes (1372 matched in all). Repo https://github.com/OpenRAC/rac1-decomp.git at `0fe9b5129b83`.

Compiler ids: ee-gcc2.9-991111, ee-gcc2.95.3-114. Environment passed to romwright: none.

Matched set: a function compiled from C (not an INCLUDE_ASM body) by the repo's own build, with that unit's own compile command and the pinned compiler, whose bytes equal the retail image at its address modulo the object's relocation fields (tests/m22-003/elfobj.py); no repo verify script is used.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 104 | 48.0% | 15 | 36.515 | 70.221 | 28 |
| m2c | 200 | 200 | 76 | 62.0% | 23 | 30.41 | 80.026 | 37 |
| oracle | 200 | 200 | 155 | 22.5% | 148 | 76.474 | 98.676 | 150 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 159 | 20.5% | 22 | 53.141 | 66.844 | 38 |
| m2c | 200 | 200 | 84 | 58.0% | 20 | 30.617 | 72.897 | 27 |
| oracle | 200 | 200 | 47 | 76.5% | 38 | 21.913 | 93.249 | 41 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 161 | 19.5% | 25 | 54.887 | 68.183 | 40 |
| m2c | 200 | 200 | 126 | 37.0% | 33 | 48.738 | 77.362 | 51 |
| oracle | 200 | 200 | 160 | 20.0% | 153 | 78.99 | 98.737 | 155 |

## Paired comparison on percent (first layer better / worse / same)

| pair | better | worse | same | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 41 | 46 | 113 | 0.668285 |
| romwright_vs_m2c_standalone | 95 | 40 | 65 | 2e-06 |
| romwright_vs_m2c_best | 61 | 73 | 66 | 0.342015 |

## By unit directory, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | oracle exact / mean % / fail |
|---|---|---|---|---|
| core | 58 | 6 / 51.537 / 28% | 6 / 33.123 / 57% | 58 / 99.941 / 0% |
| game | 142 | 9 / 30.379 / 56% | 17 / 29.301 / 64% | 90 / 66.889 / 32% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | oracle exact / mean % / fail |
|---|---|---|---|---|
| ee-gcc2.9-991111 | 44 | 5 / 59.114 / 16% | 5 / 38.833 / 50% | 44 / 99.978 / 0% |
| ee-gcc2.95.3-114 | 156 | 10 / 30.141 / 57% | 18 / 28.034 / 65% | 104 / 69.845 / 29% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | oracle exact / mean % / fail |
|---|---|---|---|---|
| 32-63 | 41 | 10 / 49.551 / 37% | 11 / 42.092 / 54% | 34 / 82.852 / 17% |
| 64-127 | 46 | 3 / 42.105 / 39% | 10 / 42.321 / 46% | 37 / 81.084 / 17% |
| 128-255 | 53 | 2 / 37.135 / 51% | 2 / 26.616 / 68% | 34 / 64.133 / 36% |
| 256-1024 | 60 | 0 / 22.772 / 60% | 0 / 16.646 / 75% | 43 / 79.482 / 18% |

## Compile failures of the context variant (first error, normalised)

**romwright**: parse error before `__asm__' x52; unsupported wide integer operation x27; parse error before `D_001D6448_t' x15; `_DAT_00160920' undeclared (first use in this function) x1

**m2c**: parse error before `__asm__' x52; `sp' undeclared (first use in this function) x17; parse error before `D_001D6448_t' x15; void value not ignored as it ought to be x6; `s128' undeclared (first use in this function) x5; invalid type argument of `unary *' x4; invalid operands to binary - x2; conflicting types for `func_00115098' x1

**oracle**: parse error before `MenuItem' x29; parse error before `D_001D6448_t' x15; `D_0013CA40' undeclared (first use in this function) x1

m2c read the unit context for 133 of 200 functions; for 67 m2c failed with it and was run again without it (first error: /* Decompilation failure: Syntax error when parsing C context. before: __asm__ at line 62, column 8 void * __asm__(" "); */), which the compile then contradicts wherever the candidate declares what the context declares.

## Limits

- Ratchet & Clank PAL (OpenRAC rac1-decomp): the repo's Makefile.sn is run with `make -n -B` for each object of `config/core_text.objects` / `text.objects` that has a `src/core|game/*.c` source; the recipe it prints (the SN compiler, the repo's python rewriting steps, the SN assembler) is the unit's command. The SN ProDG compilers are the pinned `ee-gcc2.95.3-114` (v1.14: the repo's `toolchain/sn-prodg-24` = AngheloAlf/sce_ps2_sdk_24, same cc1.exe sha1 6c232dd6...) and `ee-gcc2.9-991111`/`-01`, run under wibo (`WINE=wibo`) instead of wine; libgcc and data objects, which have no single C source, are not units of this lane.
- The matched set is the decompilation's own: its sources were written against the retail bytes, often with m2c in the loop, so the m2c column is an upper bound on unseen code, as m22-002 says of Persona 4's promoted units.
- Per-function `#pragma` state (MWCC) is replayed from the unit's source for every layer; `#if` branches by m22-002's fixed rule. ee-gcc units have no per-function pragma state.
- Each candidate is compiled twice with the unit's own compile command: `context` (the unit's own declarations as the compiler sees them, m22-002's context rule) and `standalone`; `best` is the better of the two. Percent is objdiff-cli `match_percent` with `functionRelocDiffs=none`; exact is same length and every byte equal outside the object's relocation fields.
- The comparator masks the relocation fields the object declares; it does not check that a relocation's symbol resolves to the retail operand (m22-002's `exact_symbols` is not computed in the generic path).
- The sample is up to 200 functions; sign tests treat functions as independent although they share units, so p values are indicative.
- m2c reads splat assembly generated from the retail ELF for the sampled functions (names from the repo's symbol files, gp-relative operands and jump tables adapted as m22-002 does), with call and gp symbols taken from the object's relocations.
- romwright's import of the retail ELF is one project per lane; a matched function the import did not discover has no `export-c` candidate.
