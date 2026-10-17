# m22-003: C output on matched ps2-ratchet-clank-pal functions (PS2, rcpal lane)

Generated 2026-10-13T01:09:01+0000. Sample: 200 matched functions, seed 20261012, from 1003 matched functions of 32-1024 bytes (1372 matched in all). Repo https://github.com/OpenRAC/rac1-decomp.git at `0fe9b5129b83`.

Compiler ids: ee-gcc2.9-991111, ee-gcc2.95.3-114. Environment passed to romwright: none.

Matched set: a function compiled from C (not an INCLUDE_ASM body) by the repo's own build, with that unit's own compile command and the pinned compiler, whose bytes equal the retail image at its address modulo the object's relocation fields (tests/m22-003/elfobj.py); no repo verify script is used.

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 191 | 4.5% | 28 | 63.732 | 66.735 | 44 |
| m2c | 200 | 200 | 117 | 41.5% | 34 | 46.921 | 80.207 | 54 |
| oracle | 200 | 200 | 195 | 2.5% | 186 | 96.428 | 98.901 | 189 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 187 | 6.5% | 26 | 61.075 | 65.32 | 42 |
| m2c | 200 | 200 | 45 | 77.5% | 17 | 17.222 | 76.542 | 21 |
| oracle | 200 | 200 | 48 | 76.0% | 39 | 22.413 | 93.389 | 42 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 199 | 191 | 4.5% | 29 | 63.829 | 66.837 | 45 |
| m2c | 200 | 200 | 121 | 39.5% | 36 | 48.425 | 80.042 | 56 |
| oracle | 200 | 200 | 195 | 2.5% | 186 | 96.428 | 98.901 | 189 |

## Paired comparison on percent (first layer better / worse / same)

| pair | better | worse | same | two-sided sign-test p |
|---|---|---|---|---|
| romwright_vs_m2c_context | 93 | 71 | 36 | 0.100749 |
| romwright_vs_m2c_standalone | 147 | 20 | 33 | 0.0 |
| romwright_vs_m2c_best | 90 | 76 | 34 | 0.312974 |

## By unit directory, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | oracle exact / mean % / fail |
|---|---|---|---|---|
| core | 58 | 12 / 71.428 / 2% | 8 / 40.334 / 48% | 58 / 99.999 / 0% |
| game | 142 | 16 / 60.588 / 6% | 26 / 49.612 / 39% | 128 / 94.97 / 4% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | oracle exact / mean % / fail |
|---|---|---|---|---|
| ee-gcc2.9-991111 | 44 | 7 / 69.179 / 2% | 7 / 48.338 / 39% | 44 / 99.998 / 0% |
| ee-gcc2.95.3-114 | 156 | 21 / 62.196 / 5% | 27 / 46.521 / 42% | 142 / 95.421 / 3% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail | m2c exact / mean % / fail | oracle exact / mean % / fail |
|---|---|---|---|---|
| 32-63 | 41 | 19 / 79.032 / 2% | 18 / 62.399 / 32% | 40 / 97.561 / 2% |
| 64-127 | 46 | 7 / 66.054 / 2% | 14 / 60.377 / 24% | 44 / 96.318 / 2% |
| 128-255 | 53 | 2 / 64.609 / 4% | 2 / 45.882 / 42% | 52 / 99.994 / 0% |
| 256-1024 | 60 | 0 / 50.722 / 8% | 0 / 26.946 / 62% | 50 / 92.589 / 5% |

## Compile failures of the context variant (first error, normalised)

**romwright**: cast specifies array type x3; `_DAT_00160920' undeclared (first use in this function) x1; `_DAT_00160940' undeclared (first use in this function) x1; request for member `_0_2_' in something not a structure or union x1; `undefined6' undeclared (first use in this function) x1; request for member `_0_4_' in something not a structure or union x1

**m2c**: `sp' undeclared (first use in this function) x20; void value not ignored as it ought to be x7; `s128' undeclared (first use in this function) x7; invalid type argument of `unary *' x5; invalid operands to binary - x3; incompatible types in assignment x2; conflicting types for `func_00115098' x1; conflicting types for `func_00116F68' x1

**oracle**: `D_0013CA40' undeclared (first use in this function) x4; invalid use of undefined type `struct S' x1

Each function's context is compiled alone with its unit's own command before use; 61 of 255 contexts had declarations the unit's compiler rejects, 108 declaration(s) in all were dropped (up to 2 round(s); every context then compiles); first dropped: `void * __asm__(" ");`, `void * __asm__(" ");`, `struct S D_00187040_19C08 __asm__(" ");`, `void * __asm__(" ");`.

## Limits

- Ratchet & Clank PAL (OpenRAC rac1-decomp): the repo's Makefile.sn is run with `make -n -B` for each object of `config/core_text.objects` / `text.objects` that has a `src/core|game/*.c` source; the recipe it prints (the SN compiler, the repo's python rewriting steps, the SN assembler) is the unit's command. The SN ProDG compilers are the pinned `ee-gcc2.95.3-114` (v1.14: the repo's `toolchain/sn-prodg-24` = AngheloAlf/sce_ps2_sdk_24, same cc1.exe sha1 6c232dd6...) and `ee-gcc2.9-991111`/`-01`, run under wibo (`WINE=wibo`) instead of wine; libgcc and data objects, which have no single C source, are not units of this lane.
- SN ProDG's EE gcc 2.95.3 has a 128-bit `long long` (`sizeof(long long)` is not 8 and any arithmetic on it is "unsupported wide integer operation"): its 64-bit integer type is `long`. romwright and m2c both print the 64-bit type as `long long`, so for units compiled with that compiler the harness rewrites `long long` to `long` in the composed source (prelude, context and candidate). Without it a quarter of the candidates fail to compile whatever else they say.
- The matched set is the decompilation's own: its sources were written against the retail bytes, often with m2c in the loop, so the m2c column is an upper bound on unseen code, as m22-002 says of Persona 4's promoted units.
- Per-function `#pragma` state (MWCC) is replayed from the unit's source for every layer; `#if` branches by m22-002's fixed rule. ee-gcc units have no per-function pragma state.
- Each candidate is compiled twice with the unit's own compile command: `context` (the unit's own declarations as the compiler sees them, m22-002's context rule) and `standalone`; `best` is the better of the two. Percent is objdiff-cli `match_percent` with `functionRelocDiffs=none`; exact is same length and every byte equal outside the object's relocation fields.
- The comparator masks the relocation fields the object declares; it does not check that a relocation's symbol resolves to the retail operand (m22-002's `exact_symbols` is not computed in the generic path).
- The sample is up to 200 functions; sign tests treat functions as independent although they share units, so p values are indicative.
- m2c reads splat assembly generated from the retail ELF for the sampled functions (names from the repo's symbol files, gp-relative operands and jump tables adapted as m22-002 does), with call and gp symbols taken from the object's relocations.
- romwright's import of the retail ELF is one project per lane; a matched function the import did not discover has no `export-c` candidate.
