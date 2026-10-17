# m22-003: C output on matched ps2-digital-devil-saga functions (PS2, dds lane)

Generated 2026-10-13T05:13:58+0000. Sample: 200 matched functions, seed 20261012, from 7211 matched functions of 32-1024 bytes (9022 matched in all). Repo https://github.com/Megami-Decomps/dds-decomp.git at `92a331e880e0`.

Compiler ids: ee-gcc2.96. Environment passed to romwright: none.

Matched set: a function compiled from C (not an INCLUDE_ASM body) by the repo's own build, with that unit's own compile command and the pinned compiler, whose bytes equal the retail image at its address modulo the object's relocation fields (tests/m22-003/elfobj.py); no repo verify script is used.

Cross-check against the repo's own count: the repo's own link (`ninja dds1`) with the pinned compiler: linked ELF is not identical to retail (size 2895728 vs 2895680); first code difference at 0x100198 in _start. The repo's gate is whole-image equality, so its own matched count is every C function it compiles (9036); this harness matched 9022 (14 differ, 0 had no unique address)

## context variant (headline)

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 196 | 2.0% | 61 | 76.802 | 78.37 | 81 |

## standalone variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 188 | 6.0% | 48 | 72.054 | 76.653 | 73 |

## best variant

| layer | functions | produced | compiled | compile-failure share | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|---|---|
| romwright | 200 | 200 | 196 | 2.0% | 61 | 77.173 | 78.748 | 81 |

## Paired comparison on percent (first layer better / worse / same)

| pair | better | worse | same | two-sided sign-test p |
|---|---|---|---|---|

## By unit directory, context variant

| group | n | romwright exact / mean % / fail |
|---|---|---|
| dds1/basic | 3 | 2 / 82.606 / 0% |
| dds1/effect | 11 | 3 / 67.181 / 9% |
| dds1/event | 4 | 2 / 95.488 / 0% |
| dds1/field | 7 | 2 / 80.66 / 0% |
| dds1/game | 154 | 44 / 76.651 / 2% |
| dds1/interface | 2 | 1 / 76.925 / 0% |
| dds1/kernel | 5 | 2 / 75.282 / 0% |
| dds1/mc | 2 | 0 / 65.896 / 0% |
| dds1/model | 1 | 1 / 100.0 / 0% |
| dds1/newdata | 5 | 1 / 63.363 / 0% |
| dds1/script | 2 | 2 / 100.0 / 0% |
| dds1/sdf | 4 | 1 / 85.997 / 0% |

## By compiler, context variant

| group | n | romwright exact / mean % / fail |
|---|---|---|
| ee-gcc2.96 | 200 | 61 / 76.802 / 2% |

## By function size (bytes), context variant

| group | n | romwright exact / mean % / fail |
|---|---|---|
| 32-63 | 40 | 24 / 89.522 / 0% |
| 64-127 | 71 | 32 / 83.394 / 0% |
| 128-255 | 53 | 5 / 72.153 / 4% |
| 256-1024 | 36 | 0 / 56.514 / 6% |

## Compile failures of the context variant (first error, normalised)

**romwright**: cast specifies array type x1; request for member `_0_8_' in something not a structure or union x1; `_iStack_70' undeclared (first use in this function) x1; `_iStack_50' undeclared (first use in this function) x1

Each function's context is compiled alone with its unit's own command before use; 2 of 284 contexts had declarations the unit's compiler rejects, 2 declaration(s) in all were dropped (up to 2 round(s); every context then compiles); first dropped: `extern SolarNoiseDebugData evtSolarNoiseDebugData __attribute__((section(".sdata;`, `extern SolarNoiseDebugData evtSolarNoiseDebugData __attribute__((section(".sdata;`.

## Limits

- Pinned compiler: toolchains.json `ee-gcc2.96` (decomp.me build), run unpatched under `setarch -R` with the repo's own `-O2` cc1 and EE assembler flags; the repo's download_tools.py ASLR/assembler patches are not applied, so the matched set can be smaller than the repo's own count.
- Units are compiled with the repo's own command (ninja compdb), the `cpp -MM` dependency step and the production-report recorder dropped.
- The matched set is the decompilation's own: its sources were written against the retail bytes, often with m2c in the loop, so the m2c column is an upper bound on unseen code, as m22-002 says of Persona 4's promoted units.
- Per-function `#pragma` state (MWCC) is replayed from the unit's source for every layer; `#if` branches by m22-002's fixed rule. ee-gcc units have no per-function pragma state.
- Each candidate is compiled twice with the unit's own compile command: `context` (the unit's own declarations as the compiler sees them, m22-002's context rule) and `standalone`; `best` is the better of the two. Percent is objdiff-cli `match_percent` with `functionRelocDiffs=none`; exact is same length and every byte equal outside the object's relocation fields.
- The comparator masks the relocation fields the object declares; it does not check that a relocation's symbol resolves to the retail operand (m22-002's `exact_symbols` is not computed in the generic path).
- The sample is up to 200 functions; sign tests treat functions as independent although they share units, so p values are indicative.
- m2c reads splat assembly generated from the retail ELF for the sampled functions (names from the repo's symbol files, gp-relative operands and jump tables adapted as m22-002 does), with call and gp symbols taken from the object's relocations.
- romwright's import of the retail ELF is one project per lane; a matched function the import did not discover has no `export-c` candidate.
