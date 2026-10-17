# m22-003: C output on matched ps2-persona-4 functions (PS2, p4-eegcc lane)

Generated 2026-10-12T22:30:57+0000. Sample: 195 matched functions, seed 20261010, from 648 matched functions of 32-1024 bytes (1290 matched in all). Repo https://github.com/Raikaru/Persona4-Decompilation.git at `509519da5809`.

Compiler ids: ee-gcc2.96. Environment passed to romwright: none.

Matched set: a function compiled from C (not an INCLUDE_ASM body) by the repo's own build, with that unit's own compile command and the pinned compiler, whose bytes equal the retail image at its address modulo the object's relocation fields (tests/m22-003/elfobj.py); no repo verify script is used.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 195 | 194 | 192 | 1.5% | 104 | 86.169 | 87.516 | 122 |
| m2c | 195 | 195 | 160 | 17.9% | 92 | 74.196 | 90.426 | 115 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 195 | 194 | 178 | 8.7% | 98 | 79.662 | 87.27 | 115 |
| m2c | 195 | 195 | 136 | 30.3% | 72 | 63.058 | 90.414 | 97 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 195 | 194 | 192 | 1.5% | 108 | 86.525 | 87.877 | 126 |
| m2c | 195 | 195 | 167 | 14.4% | 95 | 77.328 | 90.293 | 119 |

## Paired comparison on percent (first layer better / worse / same)

| pair | better | worse | same | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 61 | 31 | 103 | 0.002315 |
| romwright_vs_m2c_standalone | 77 | 37 | 81 | 0.000227 |
| romwright_vs_m2c_best | 57 | 30 | 108 | 0.005014 |

## By unit directory, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| cri | 186 | 95 / 85.5 / 2% | 84 / 72.99 / 19% |
| promoted | 9 | 9 / 100.0 / 0% | 8 / 99.111 / 0% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| ee-gcc2.96 | 195 | 104 / 86.169 / 2% | 92 / 74.196 / 18% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| 32-63 | 77 | 59 / 94.482 / 1% | 59 / 86.779 / 12% |
| 64-127 | 76 | 39 / 85.767 / 1% | 33 / 78.117 / 11% |
| 128-255 | 31 | 6 / 76.208 / 3% | 0 / 53.008 / 32% |
| 256-1024 | 11 | 0 / 58.834 / 0% | 0 / 18.733 / 73% |

## Compile failures of the context variant (first error, normalised)

**romwright**: too few arguments to function `strlen' x2

**m2c**: `sp' undeclared (first use in this function) x11; invalid type argument of `unary *' x6; void value not ignored as it ought to be x4; invalid use of void expression x2; too few arguments to function `strlen' x2; too few arguments to function `memcmp' x1; conflicting types for `ADX_DecodeInfoAu' x1; too many arguments to function `ADX_DecodeInfoWav' x1

## Limits

- The ee-gcc 2.96 units of Persona 4 (config/gcc_units.txt), compiled with the repo's tools/eegcc_shim.py and the pinned ee-gcc 2.96 + EE assembler. The repo must already be prepared by the `p4` lane (same --repo): this lane's setup only rewrites the compiler wrappers.
- The ee-gcc units' assembler is the pinned `ee-gcc2.96` package's `ee/bin/as` (GNU as for the EE) behind a wrapper that drops the `-march=r5900 -mabi=eabi` flags the repo's shim passes and that assembler does not know.
- The matched set is the decompilation's own: its sources were written against the retail bytes, often with m2c in the loop, so the m2c column is an upper bound on unseen code, as m22-002 says of Persona 4's promoted units.
- Per-function `#pragma` state (MWCC) is replayed from the unit's source for every layer; `#if` branches by m22-002's fixed rule. ee-gcc units have no per-function pragma state.
- Each candidate is compiled twice with the unit's own compile command: `context` (the unit's own declarations as the compiler sees them, m22-002's context rule) and `standalone`; `best` is the better of the two. Percent is objdiff-cli `match_percent` with `functionRelocDiffs=none`; exact is same length and every byte equal outside the object's relocation fields.
- The comparator masks the relocation fields the object declares; it does not check that a relocation's symbol resolves to the retail operand (m22-002's `exact_symbols` is not computed in the generic path).
- The sample is up to 200 functions; sign tests treat functions as independent although they share units, so p values are indicative.
- m2c reads splat assembly generated from the retail ELF for the sampled functions (names from the repo's symbol files, gp-relative operands and jump tables adapted as m22-002 does), with call and gp symbols taken from the object's relocations.
- romwright's import of the retail ELF is one project per lane; a matched function the import did not discover has no `export-c` candidate.
