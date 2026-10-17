# GP-7003 cherry-pick (2026-10-12)

**Verdict: GP-7003 is safe to cherry-pick only with the fix in `gp7003-12.1.3.cpfix.patch`. As first cherry-picked (and as it stands in upstream master) it loses jump tables 12.1.3 recovers. With the fix it loses none, gains 4 and changes nothing else measured.**

`gp7003-12.1.3.cpfix.patch` is GP-7003 (`64606271a`) plus two corrections, applied to 12.1.3 plus the current `native/ghidra-opt-sleigh.patch` (a/decompiler paths, `patch -p1` or `git apply`; 6 files, no fuzz against the 765c93cc patch). Builds compared: `base` = the pinned decompiler (`ghidra_opt` dbd7e74b), `cp7003` = the first cherry-pick, `remguard` = cherry-pick with the first correction only, `cpfix` = both corrections, `master` = upstream master 918d44e with the rebased patch (binary built for this run, sha256 e61fcfda6e0b95fa..., not byte-identical to the earlier trial's). One Rust CLI/worker pair for all.

1. **God Hand 0x274828 has six targets, not five.** Retail bytes: `jal irand; li v1,5; divu v0,v1; mfhi a0; sltiu v0,a0,6; beq v0,zero,default; ... lw; jr`. The guard admits indices 0..5 and the table at 0x4475c0 holds six words (0x274830, 0x274848, 0x274860, 0x274878, 0x274c80, 0x274890). The decomp repo (LucasPicoli/god-hand-decomp, 58bcee16, `src/cod/002744e0.c`) has `switch ((unsigned int)irand() % 5)` with cases 0 to 5; case 5 is dead at run time and present in the binary. 12.1.3's six is right. GP-7003 reads `x % 5` as the range [0,5), tighter than the guard's [0,6), and drops the sixth. Correction 1: the `INT_REM`/`INT_SREM` bound applies only when no guard bounds the switch variable (`calcRange` runs a second pass without it). It also repairs God Hand 0x20f78c.
2. **A second flaw, found by widening, loses whole tables.** Starting every range from the non-zero mask gives a shifted byte (`(x-1) << 24`, God Hand 0x37a9f8) the range [0,0xff000020) with step 32 (the stride is capped at 32). The guard reaches that Varnode as [0,0xa000000) with step 2^24. `CircleRange::intersect` raises the step with `newStride`, whose right edge rounds past 2^32, wraps to 0, and is reported as an empty range. Size 0 is the smallest range of all, so it is chosen as the switch variable and the table is lost. Correction 2 (5 lines in `calcRange`): a guard that empties a range keeps the estimate instead (`rng = before; continue`). Switching the non-zero-mask start off (`t3`) or reverting the corrected hunk both restore the tables; dropping the REM bound (`norem`) and the preferred-range tie-break (`t1`) do not.
3. **Upstream master has both flaws** (same `calcRange`, same `newStride`): it loses the same 20 tables in 7 of the 11 non-N64 games, 102 more on Nintendo 64 through GP-7310, and has the same two fewer-target tables. The earlier trial compared stored tables only and recorded one God Hand table; stored tables hide most of it, as the stored table below shows (3 lost in God Hand for the first cherry-pick). Whoever re-pins takes the correction with it.

## Decompiler-only switch recovery (stored tables removed), per game

Reference build: `base`. For every function with a stored computed jump the stored tables were removed; each build recovered them itself.

| game | functions | base tables / targets | cp tables / targets | cp: same | gained | lost | fewer targets | more targets | different targets | failed fns | rg tables / targets | rg: same | gained | lost | fewer targets | more targets | different targets | failed fns | cf tables / targets | cf: same | gained | lost | fewer targets | more targets | different targets | failed fns | master tables / targets | master: same | gained | lost | fewer targets | more targets | different targets | failed fns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | 315 | 363 / 3304 | 359 / 3259 | 359 | 0 | 4 | 0 | 0 | 0 | 0 -> 0 | 359 / 3259 | 359 | 0 | 4 | 0 | 0 | 0 | 0 -> 0 | 363 / 3304 | 363 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 359 / 3259 | 359 | 0 | 4 | 0 | 0 | 0 | 0 -> 0 |
| gc-pikmin-2 | 142 | 161 / 1874 | 161 / 1874 | 161 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 161 / 1874 | 161 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 161 / 1874 | 161 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 161 / 1874 | 161 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 |
| n64-super-mario-64 | 123 | 145 / 1202 | 145 / 1202 | 145 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 145 / 1202 | 145 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 145 / 1202 | 145 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 43 / 358 | 43 | 0 | 102 | 0 | 0 | 0 | 0 -> 94 |
| nds-kh-358-2-days | 924 | 42 / 348 | 42 / 348 | 42 | 0 | 0 | 0 | 0 | 0 | 887 -> 887 | 42 / 348 | 42 | 0 | 0 | 0 | 0 | 0 | 887 -> 887 | 42 / 348 | 42 | 0 | 0 | 0 | 0 | 0 | 887 -> 887 | 42 / 348 | 42 | 0 | 0 | 0 | 0 | 0 | 887 -> 887 |
| ps2-dark-chronicle | 105 | 118 / 994 | 117 / 983 | 117 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 | 117 / 983 | 117 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 | 118 / 994 | 118 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 117 / 983 | 117 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 |
| ps2-dark-cloud | 63 | 74 / 598 | 73 / 587 | 73 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 | 73 / 587 | 73 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 | 74 / 598 | 74 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 73 / 587 | 73 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 |
| ps2-digital-devil-saga | 260 | 294 / 2013 | 294 / 2013 | 294 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 294 / 2013 | 294 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 294 / 2013 | 294 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 294 / 2013 | 294 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 |
| ps2-fatal-frame | 244 | 272 / 2194 | 275 / 2259 | 272 | 3 | 0 | 0 | 0 | 0 | 0 -> 0 | 275 / 2259 | 272 | 3 | 0 | 0 | 0 | 0 | 0 -> 0 | 275 / 2259 | 272 | 3 | 0 | 0 | 0 | 0 | 0 -> 0 | 275 / 2259 | 272 | 3 | 0 | 0 | 0 | 0 | 0 -> 0 |
| ps2-god-hand | 554 | 990 / 7840 | 982 / 7779 | 979 | 1 | 9 | 2 | 0 | 0 | 0 -> 0 | 982 / 7784 | 981 | 1 | 9 | 0 | 0 | 0 | 0 -> 0 | 991 / 7846 | 990 | 1 | 0 | 0 | 0 | 0 | 0 -> 0 | 982 / 7779 | 979 | 1 | 9 | 2 | 0 | 0 | 0 -> 0 |
| ps2-persona-4 | 293 | 326 / 2601 | 325 / 2582 | 325 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 | 325 / 2582 | 325 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 | 326 / 2601 | 326 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 325 / 2582 | 325 | 0 | 1 | 0 | 0 | 0 | 0 -> 0 |
| ps2-ratchet-clank | 32 | 40 / 322 | 38 / 305 | 38 | 0 | 2 | 0 | 0 | 0 | 0 -> 0 | 38 / 305 | 38 | 0 | 2 | 0 | 0 | 0 | 0 -> 0 | 40 / 322 | 40 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 38 / 305 | 38 | 0 | 2 | 0 | 0 | 0 | 0 -> 0 |
| ps2-ratchet-clank-pal | 32 | 40 / 328 | 38 / 311 | 38 | 0 | 2 | 0 | 0 | 0 | 0 -> 0 | 38 / 311 | 38 | 0 | 2 | 0 | 0 | 0 | 0 -> 0 | 40 / 328 | 40 | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 38 / 311 | 38 | 0 | 2 | 0 | 0 | 0 | 0 -> 0 |
| all | 3087 | 2865 / 23618 | 2849 / 23502 | 2843 | 4 | 20 | 2 | 0 | 0 |  | 2849 / 23507 | 2845 | 4 | 20 | 0 | 0 | 0 |  | 2869 / 23689 | 2865 | 4 | 0 | 0 | 0 | 0 |  | 2747 / 22658 | 2741 | 4 | 122 | 2 | 0 | 0 |  |

### Differing branches, `cp` against `base`

- gba-kh-chain-of-memories lost: function 0800a774 branch 0800a7e8
- gba-kh-chain-of-memories lost: function 0800ad90 branch 0800ae46
- gba-kh-chain-of-memories lost: function 080b13d0 branch 080b13f6
- gba-kh-chain-of-memories lost: function 080c4708 branch 080c474e
- ps2-dark-chronicle lost: function 00111ad8 branch 00111b54
- ps2-dark-cloud lost: function 00115e88 branch 00115f04
- ps2-fatal-frame gained: function 001ca528 branch 001ca5ec
- ps2-fatal-frame gained: function 001ca9d8 branch 001caab4
- ps2-fatal-frame gained: function 001ca9d8 branch 001cab80
- ps2-god-hand lost: function 001471f0 branch 00147238
- ps2-god-hand lost: function 001471f0 branch 00147324
- ps2-god-hand lost: function 00160b90 branch 00160c18
- ps2-god-hand lost: function 00163598 branch 00163708
- ps2-god-hand lost: function 002ff748 branch 002ff7a8
- ps2-god-hand lost: function 002ff8a0 branch 002ff918
- ps2-god-hand lost: function 0037a9c8 branch 0037a9f8
- ps2-god-hand lost: function 003a9d88 branch 003a9e10
- ps2-god-hand fewer_targets: function 0020f3c0 branch 0020f78c, lost ['0020f7c4', '0020f7d4', '0020f7ec', '0020f804'], gained []
- ps2-god-hand fewer_targets: function 002744e0 branch 00274828, lost ['00274890'], gained []
- ps2-god-hand gained: function 0025b6e8 branch 0025b830
- ps2-persona-4 lost: function 004235c8 branch 0042367c
- ps2-ratchet-clank lost: function 00119da0 branch 00119e2c
- ps2-ratchet-clank lost: function 00216c48 branch 00216ebc
- ps2-ratchet-clank-pal lost: function 0011a0a0 branch 0011a12c
- ps2-ratchet-clank-pal lost: function 00217ae8 branch 00217d5c

### Differing branches, `rg` against `base`

- gba-kh-chain-of-memories lost: function 0800a774 branch 0800a7e8
- gba-kh-chain-of-memories lost: function 0800ad90 branch 0800ae46
- gba-kh-chain-of-memories lost: function 080b13d0 branch 080b13f6
- gba-kh-chain-of-memories lost: function 080c4708 branch 080c474e
- ps2-dark-chronicle lost: function 00111ad8 branch 00111b54
- ps2-dark-cloud lost: function 00115e88 branch 00115f04
- ps2-fatal-frame gained: function 001ca528 branch 001ca5ec
- ps2-fatal-frame gained: function 001ca9d8 branch 001caab4
- ps2-fatal-frame gained: function 001ca9d8 branch 001cab80
- ps2-god-hand lost: function 001471f0 branch 00147238
- ps2-god-hand lost: function 001471f0 branch 00147324
- ps2-god-hand lost: function 00160b90 branch 00160c18
- ps2-god-hand lost: function 00163598 branch 00163708
- ps2-god-hand lost: function 002ff748 branch 002ff7a8
- ps2-god-hand lost: function 002ff8a0 branch 002ff918
- ps2-god-hand lost: function 0037a9c8 branch 0037a9f8
- ps2-god-hand lost: function 003a9d88 branch 003a9e10
- ps2-god-hand gained: function 0025b6e8 branch 0025b830
- ps2-persona-4 lost: function 004235c8 branch 0042367c
- ps2-ratchet-clank lost: function 00119da0 branch 00119e2c
- ps2-ratchet-clank lost: function 00216c48 branch 00216ebc
- ps2-ratchet-clank-pal lost: function 0011a0a0 branch 0011a12c
- ps2-ratchet-clank-pal lost: function 00217ae8 branch 00217d5c

### Differing branches, `cf` against `base`

- ps2-fatal-frame gained: function 001ca528 branch 001ca5ec
- ps2-fatal-frame gained: function 001ca9d8 branch 001caab4
- ps2-fatal-frame gained: function 001ca9d8 branch 001cab80
- ps2-god-hand gained: function 0025b6e8 branch 0025b830

### Differing branches, `master` against `base`

- gba-kh-chain-of-memories lost: function 0800a774 branch 0800a7e8
- gba-kh-chain-of-memories lost: function 0800ad90 branch 0800ae46
- gba-kh-chain-of-memories lost: function 080b13d0 branch 080b13f6
- gba-kh-chain-of-memories lost: function 080c4708 branch 080c474e
- n64-super-mario-64 lost: function 80170b1c branch 80170b4c
- n64-super-mario-64 lost: function 801731a8 branch 801732f0
- n64-super-mario-64 lost: function 80173430 branch 80173460
- n64-super-mario-64 lost: function 801746f8 branch 80174724
- n64-super-mario-64 lost: function 80175238 branch 80175348
- n64-super-mario-64 lost: function 801764e0 branch 80176518
- n64-super-mario-64 lost: function 8017c300 branch 8017c448
- n64-super-mario-64 lost: function 8017f704 branch 8017f9e4
- ps2-dark-chronicle lost: function 00111ad8 branch 00111b54
- ps2-dark-cloud lost: function 00115e88 branch 00115f04
- ps2-fatal-frame gained: function 001ca528 branch 001ca5ec
- ps2-fatal-frame gained: function 001ca9d8 branch 001caab4
- ps2-fatal-frame gained: function 001ca9d8 branch 001cab80
- ps2-god-hand lost: function 001471f0 branch 00147238
- ps2-god-hand lost: function 001471f0 branch 00147324
- ps2-god-hand lost: function 00160b90 branch 00160c18
- ps2-god-hand lost: function 00163598 branch 00163708
- ps2-god-hand lost: function 002ff748 branch 002ff7a8
- ps2-god-hand lost: function 002ff8a0 branch 002ff918
- ps2-god-hand lost: function 0037a9c8 branch 0037a9f8
- ps2-god-hand lost: function 003a9d88 branch 003a9e10
- ps2-god-hand fewer_targets: function 0020f3c0 branch 0020f78c, lost ['0020f7c4', '0020f7d4', '0020f7ec', '0020f804'], gained []
- ps2-god-hand fewer_targets: function 002744e0 branch 00274828, lost ['00274890'], gained []
- ps2-god-hand gained: function 0025b6e8 branch 0025b830
- ps2-persona-4 lost: function 004235c8 branch 0042367c
- ps2-ratchet-clank lost: function 00119da0 branch 00119e2c
- ps2-ratchet-clank lost: function 00216c48 branch 00216ebc
- ps2-ratchet-clank-pal lost: function 0011a0a0 branch 0011a12c
- ps2-ratchet-clank-pal lost: function 00217ae8 branch 00217d5c

## Printed C of the functions the builds disagree on, plus a control of functions they agree on

| game | functions printed | identical text in every build | differing (first 60 in the JSON) |
|---|---|---|---|
| gba-kh-chain-of-memories | 64 | 60 | 4 |
| gc-pikmin-2 | 60 | 60 | 0 |
| n64-super-mario-64 | 60 | 60 | 0 |
| nds-kh-358-2-days | 60 | 60 | 0 |
| ps2-dark-chronicle | 61 | 60 | 1 |
| ps2-dark-cloud | 61 | 60 | 1 |
| ps2-digital-devil-saga | 60 | 60 | 0 |
| ps2-fatal-frame | 62 | 60 | 2 |
| ps2-god-hand | 70 | 60 | 10 |
| ps2-persona-4 | 61 | 60 | 1 |
| ps2-ratchet-clank | 32 | 30 | 2 |
| ps2-ratchet-clank-pal | 32 | 30 | 2 |

## Stored switch tables, whole games (each build imported the game itself)

Reference: `base`. Tables and edges are counted in the stored computed-jump xrefs.

| build | tables (ref -> build) | edges (ref -> build) | tables only in ref | tables only in build | different targets |
|---|---|---|---|---|---|
| cp7003 | 3874 -> 3874 | 35145 -> 35178 | ps2-god-hand: 00147238 0037a9f8 003a9e10 | ps2-fatal-frame: 001caab4 001cab80; ps2-god-hand: 0022cca8 | ps2-god-hand: 0020f78c 00274828 |
| remguard | 3874 -> 3874 | 35145 -> 35183 | ps2-god-hand: 00147238 0037a9f8 003a9e10 | ps2-fatal-frame: 001caab4 001cab80; ps2-god-hand: 0022cca8 | none |
| cpfix | 3874 -> 3877 | 35145 -> 35196 | none | ps2-fatal-frame: 001caab4 001cab80; ps2-god-hand: 0022cca8 | none |

## m21 function discovery (7 images)

Builds: base, cp7003, remguard, cpfix. Status: base pass, cp7003 pass, remguard pass, cpfix pass.

| image | recall | precision | size exact | across builds |
|---|---|---|---|---|
| gba-pokeemerald | 0.9761 | 0.9972 | 5748 | identical in every build |
| nds-pokeheartgold-arm9 | 0.9735 | 0.9984 | 5156 | identical in every build |
| ps2-capcom-fighting-evolution | 0.9762 | 0.9924 | 8567 | identical in every build |
| ps2-dungeon-game | 0.9885 | 0.9822 | 751 | identical in every build |
| psx-darkstalkers-3 | 0.9878 | 0.3663 | 0 | identical in every build |
| psv-need-for-speed-most-wanted | 0.9734 | 0.9719 | 16304 | identical in every build |
| x360-black-ops-2 | 0.9833 | 0.9964 | 0 | identical in every build |

## m22-002 (PS2 C match, 200 functions per run, context variant)

| run | build | exact | compiled | mean percent | best exact | paired vs ref: better / worse / same | exact gained / lost |
|---|---|---|---|---|---|---|---|
| MWCC seed 20261010 | base | 45/200 | 190 | 74.725 | 46 | - | - |
| MWCC seed 20261010 | cp7003 | 45/200 | 190 | 74.725 | 46 | 0 / 0 / 200 | 0 / 0 |
| MWCC seed 20261010 | remguard | 45/200 | 190 | 74.725 | 46 | 0 / 0 / 200 | 0 / 0 |
| MWCC seed 20261010 | cpfix | 45/200 | 190 | 74.725 | 46 | 0 / 0 / 200 | 0 / 0 |
| MWCC seed 20261011 | base | 45/200 | 190 | 76.361 | 45 | - | - |
| MWCC seed 20261011 | cp7003 | 45/200 | 190 | 76.361 | 45 | 0 / 0 / 200 | 0 / 0 |
| MWCC seed 20261011 | remguard | 45/200 | 190 | 76.361 | 45 | 0 / 0 / 200 | 0 / 0 |
| MWCC seed 20261011 | cpfix | 45/200 | 190 | 76.361 | 45 | 0 / 0 / 200 | 0 / 0 |
| ee-gcc seed 20261010 | base | 94/200 | 196 | 84.558 | 98 | - | - |
| ee-gcc seed 20261010 | cp7003 | 94/200 | 196 | 84.558 | 98 | 0 / 0 / 200 | 0 / 0 |
| ee-gcc seed 20261010 | remguard | 94/200 | 196 | 84.558 | 98 | 0 / 0 / 200 | 0 / 0 |
| ee-gcc seed 20261010 | cpfix | 94/200 | 196 | 84.558 | 98 | 0 / 0 / 200 | 0 / 0 |

## Upstream decompiler datatests (decomp_opt `load test file` + `execute test command`)

84 XML tests (12.1.3's `datatests` directory plus master's `switchmask.xml`), each decompiled by pre, cp7003, remguard, cpfix, norem; the printed C was compared. 83 tests print identical text in every build.

- `switchmask.xml`: pre | cp7003+cpfix+remguard | norem


## Findings

- **Datatests.** The upstream datatest `switchmask.xml` (added by GP-7003: `switchrem` is an unguarded `x % 10` switch, `switchmask` an unguarded mask) is the check that the REM bound is worth keeping. 12.1.3 fails it (`switchrem` prints `UNRECOVERED_JUMPTABLE`, 16 `case` lines in the file), `cp7003`, `remguard` and `cpfix` recover the ten-case switch (26 lines), `norem` recovers it with a `Control flow encountered bad instruction data` warning. So `cpfix` keeps GP-7003's benefit; dropping the REM bound entirely does not.
- **Gains, checked against retail.** Fatal Frame 0x1caab4 (34 targets), 0x1cab80 (10) and 0x1ca5ec (the last only in the decompiler-only run); God Hand 0x22cca8 (guard `sltiu v0,v1,0x12`, 18 targets) and 0x25b830 (guard `sltiu v0,v1,6`, 6 targets). 12.1.3 recovered none of them.
- **Printed C** (stored tables removed, 683 functions, the ones where any build differs plus 60 per game that agree): `cp7003` differs from `base` in 23 functions (31 -> 16 `switch`, 586 -> 230 `case` over those functions), `remguard` in 21, `cpfix` in 3, all three gains: Fatal Frame 0x1ca528 (1 -> 2 switches, `jumptable_warning` gone), 0x1ca9d8 (1 -> 3 switches, 30 -> 70 cases), God Hand 0x25b6e8 (0 -> 1).
- **m21 and m22 are blind to it.** All 7 m21 images and all three m22 runs are identical in every build, 0 / 0 / 200 functions changed in each m22 run: the 200-function samples contain none of the changed switches. Absence of a change there is not evidence for the patch; the switch-table gates above and the datatests are.
- **Why the first run looked fine.** The first trial stored the tables from each build's own import and compared only those; the loss shows in the stored comparison only for 3 God Hand tables (and 0x274828 as fewer targets), and in none of them in the earlier master run. The decompiler-only recovery here is the stricter measure; the difference between the two runs' stored results is not explained (the Rust CLI/worker pair differs: Oct 11 20:26 build here).
- **Port reference.** For GP-7003 the Rust jump-table stage should implement `cpfix` semantics, not upstream's: the REM/SREM bound only without a guard, and a guard that would empty an estimated range is ignored. Cases to port as tests: God Hand 0x274828 (6 targets), 0x37a9f8 (10 entries, shifted byte), Fatal Frame `FActExecOccur` (33/34/10), `switchmask.xml`.
- **Limits.** Gates ran on 12 games for tables and printed C, 7 images (m21), 3 m22 runs, 84 datatests. The Rust CLI/worker pair is the 2026-10-11 20:26 build (tools tree FactPack), because the newer pair expects printer IR version 5; m22 numbers are therefore the older pipeline's and only comparable within this table. `master` was built once, with the rebased patch of the first trial.

