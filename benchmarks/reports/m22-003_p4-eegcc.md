# m22-003: C output on matched ps2-persona-4 functions (PS2, p4-eegcc lane)

Generated 2026-10-12T22:26:44+0000. Sample: 200 matched functions, seed 20261010, from 648 matched functions of 32-1024 bytes (1290 matched in all). Repo https://github.com/Raikaru/Persona4-Decompilation.git at `509519da5809`.

Compiler ids: ee-gcc2.96. Environment passed to romwright: none.

Matched set: a function compiled from C (not an INCLUDE_ASM body) by the repo's own build, with that unit's own compile command and the pinned compiler, whose bytes equal the retail image at its address modulo the object's relocation fields (tests/m22-003/elfobj.py); no repo verify script is used.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 197 | 1.5% | 96 | 83.972 | 85.251 | 120 |
| m2c | 200 | 200 | 164 | 18.0% | 85 | 72.68 | 88.634 | 114 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 185 | 7.5% | 90 | 78.932 | 85.332 | 114 |
| m2c | 200 | 200 | 137 | 31.5% | 65 | 60.21 | 87.897 | 95 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 199 | 0.5% | 100 | 85.188 | 85.617 | 125 |
| m2c | 200 | 200 | 170 | 15.0% | 87 | 74.768 | 87.962 | 117 |

## Paired comparison on percent (first layer better / worse / same)

| pair | better | worse | same | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 65 | 40 | 95 | 0.018741 |
| romwright_vs_m2c_standalone | 83 | 42 | 75 | 0.00031 |
| romwright_vs_m2c_best | 64 | 37 | 99 | 0.009335 |

## By unit directory, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| cri | 193 | 89 / 83.391 / 2% | 78 / 71.689 / 19% |
| promoted | 7 | 7 / 100.0 / 0% | 7 / 100.0 / 0% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| ee-gcc2.96 | 200 | 96 / 83.972 / 2% | 85 / 72.68 / 18% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail |
|---|---|---|---|
| 32-63 | 80 | 60 / 95.137 / 0% | 59 / 89.921 / 8% |
| 64-127 | 71 | 30 / 79.73 / 4% | 24 / 75.307 / 13% |
| 128-255 | 37 | 6 / 75.497 / 0% | 2 / 45.806 / 35% |
| 256-1024 | 12 | 0 / 60.774 / 0% | 0 / 25.053 / 67% |

## Compile failures of the context variant (first error, normalised)

**romwright**: too few arguments to function `strlen' x1; conflicting types for `allocCvFsHn' x1; sizeof applied to an incomplete type x1

**m2c**: `sp' undeclared (first use in this function) x14; invalid type argument of `unary *' x4; void value not ignored as it ought to be x3; too few arguments to function `memcmp' x2; invalid use of void expression x2; conflicting types for `ADX_DecodeInfoAiff' x1; too many arguments to function `ADX_DecodeInfoWav' x1; conflicting types for `ADX_DecodeSte4' x1

m2c read the unit context for 199 of 200 functions; for 1 m2c failed with it and was run again without it (first error: /* Decompilation failure: Failed to evaluate expression sftst_msg_hdr at compile time; only simple arithmetic is supported for now */), which the compile then contradicts wherever the candidate declares what the context declares.

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
