# Universal fact pack: leave-one-out evaluation

Generated 2026-10-11T20:43:12+00:00 by `benchmarks/fact_pack_eval.py`. Tools `cli a59ec836f8aa7be7`.

## Pack

- file: `fact-pack.sqlite`, **106.0 MB** on disk (105,955,328 bytes), format 2, mask version 1
- 48 donor games, 483,248 masked bodies (386,975 named), 373,710 prototypes
- donor licenses, recorded verbatim, none filtered (NONE = no license file): CC0-1.0 16, GPL-3.0 2, MIT 8, NOASSERTION 5, NONE 16, Unlicense 1

## Headline (leave-one-out, donor games)

- games evaluated: 48 of 48 donor games (failures listed below)
- functions probed 651,950; matched 49,272; abstained 7,904; **gated 17,396** (held back by the rename gate: >=2 independent donors (twin group counted once) when the body is < 128 B); renamed (`FUN_` -> donor name) **23,466**
- **function-wrong renames (the name of another function put on this one): 26 of 20,144 scoreable = 0.13%**
- **wrong-name rate on scoreable renames: 2.3% (457 wrong of 20,144 scoreable; 19,687 correct, of which 19,581 equal after normalizing and the rest after demangling to the base name (84 of those name a different class than the truth's); 3,322 unscoreable)**
- prototypes applied as inferences: 20,894
- wrong-name rate over every name proposed at a found function: 2.3% (461 of 20,204)
- **scan boundary precision: 89.2% of 657 scan matches start at a truth function (586 hits, 71 misses); of the hits with a known size, 84.9% (494 of 582) have the exact truth length (75.2% of all scan matches have a correct start and length)**
- scan-found names: 33.8% wrong (115 of 340 scoreable)
- matches on found functions: our size = pack length for 91.7% (28,638 of 31,219); against truth the pack length fixes 2,287 sizes the import had wrong and breaks 241 it had right (of 31,029 compared; where ours differs from truth it is shorter 2,372 times, longer 36)
- twin-group leaks (a donor of the excluded game or its twin in a match): 0

## The rename gate: gated against ungated (leave-one-out, donor games)

Gate: >=2 independent donors (twin group counted once) when the body is < 128 B. The **ungated** rows are the same leave-one-out renames before the gate, taken from `fact_pack_gating.json` (generated 2026-10-11, `romwright-cli` c3b621287fddc706), not re-measured here. Strict wrong = every scoreable rename whose name is not correct; function-wrong = the name of another function of the target (or of a different method) put on this one.

| platform | state | renames | gated (withheld) | scoreable | strict wrong | strict rate | function-wrong | function rate |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| gba | ungated, 2026-10-11 | 306 | 0 | 299 | 40 | 13.4% | 0 | 0.00% |
| gba | gated | 196 | 126 | 195 | 31 | 15.9% | 0 | 0.00% |
| gc | ungated, 2026-10-11 | 8,744 | 0 | 8,712 | 135 | 1.6% | 54 | 0.62% |
| gc | gated | 6,478 | 9,656 | 6,478 | 28 | 0.43% | 7 | 0.11% |
| n64 | ungated, 2026-10-11 | 2,826 | 0 | 2,748 | 339 | 12.3% | 5 | 0.18% |
| n64 | gated | 1,646 | 1,750 | 1,610 | 126 | 7.8% | 4 | 0.25% |
| nds | ungated, 2026-10-11 | 2,954 | 0 | 1,642 | 279 | 17.0% | 11 | 0.67% |
| nds | gated | 1,995 | 1,003 | 955 | 152 | 15.9% | 6 | 0.63% |
| ps2 | ungated, 2026-10-11 | 2,887 | 0 | 1,736 | 40 | 2.3% | 1 | 0.06% |
| ps2 | gated | 2,475 | 566 | 1,600 | 19 | 1.2% | 1 | 0.06% |
| psx | ungated, 2026-10-11 | 1,595 | 0 | 1,408 | 198 | 14.1% | 2 | 0.14% |
| psx | gated | 1,274 | 361 | 1,167 | 73 | 6.3% | 2 | 0.17% |
| wii | ungated, 2026-10-11 | 11,492 | 0 | 9,994 | 166 | 1.7% | 88 | 0.88% |
| wii | gated | 9,402 | 3,934 | 8,139 | 28 | 0.34% | 6 | 0.07% |
| all | ungated, 2026-10-11 | 30,804 | 0 | 26,539 | 1,197 | 4.5% | 161 | 0.61% |
| all | gated | 23,466 | 17,396 | 20,144 | 457 | 2.3% | 26 | 0.13% |

## Per platform, donor games (leave-one-out)

| platform | probed fns | matched | abstained | gated | renamed | correct | wrong | unscoreable | wrong rate (strict) | function-wrong | scan matches | start hit | start miss | length = truth | our size = pack length |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gba (5) | 25894 | 491 | 152 | 126 | 196 | 164 | 31 | 1 | 15.9% | 0 (0.00%) | 31 | 31 | 0 | 28 | 39.2% |
| gc (8) | 167830 | 16971 | 782 | 9656 | 6478 | 6450 | 28 | 0 | 0.43% | 7 (0.11%) | 33 | 18 | 15 | 18 | 99.1% |
| n64 (9) | 53799 | 3909 | 462 | 1750 | 1646 | 1484 | 126 | 36 | 7.8% | 4 (0.25%) | 85 | 73 | 12 | 73 | 98.9% |
| nds (5) | 80730 | 4335 | 1243 | 1003 | 1995 | 803 | 152 | 1040 | 15.9% | 6 (0.63%) | 132 | 110 | 22 | 107 | 46.3% |
| ps2 (8) | 54538 | 5869 | 2822 | 566 | 2475 | 1581 | 19 | 875 | 1.2% | 1 (0.06%) | 5 | 1 | 4 | 1 | 96.2% |
| psx (8) | 47866 | 2579 | 735 | 361 | 1274 | 1094 | 73 | 107 | 6.3% | 2 (0.17%) | 312 | 304 | 8 | 218 | 95.4% |
| wii (5) | 221293 | 15118 | 1708 | 3934 | 9402 | 8111 | 28 | 1263 | 0.34% | 6 (0.07%) | 59 | 49 | 10 | 49 | 97.5% |
| **all (48)** | 651950 | 49272 | 7904 | 17396 | 23466 | 19687 | 457 | 3322 | 2.3% | 26 (0.13%) | 657 | 586 | 71 | 494 | 91.7% |

## Out of corpus: non-donor games (psp, x360; dwarf / pdb truth)

| platform | probed fns | matched | abstained | gated | renamed | correct | wrong | unscoreable | wrong rate (strict) | function-wrong | scan matches | start hit | start miss | length = truth | our size = pack length |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| psp (5) | 34060 | 910 | 909 | 1 | 0 | 0 | 0 | 0 | - | 0 (-) | 16 | 7 | 9 | 0 | 0.56% |
| x360 (5) | 175930 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | - |
| **all (10)** | 209990 | 910 | 909 | 1 | 0 | 0 | 0 | 0 | - | 0 (-) | 16 | 7 | 9 | 0 | 0.56% |

## Per compiler family of the target game, donor games (leave-one-out)

| compiler family | probed fns | matched | abstained | gated | renamed | correct | wrong | unscoreable | wrong rate (strict) | function-wrong | scan matches | start hit | start miss | length = truth | our size = pack length |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| MWCC (22) | 498361 | 39310 | 4997 | 14976 | 19101 | 16308 | 216 | 2577 | 1.3% | 20 (0.12%) | 237 | 189 | 48 | 186 | 91.3% |
| IDO (7) | 49727 | 3702 | 444 | 1687 | 1524 | 1362 | 126 | 36 | 8.5% | 4 (0.27%) | 66 | 55 | 11 | 55 | 99.2% |
| agbcc (5) | 25894 | 491 | 152 | 126 | 196 | 164 | 31 | 1 | 15.9% | 0 (0.00%) | 31 | 31 | 0 | 28 | 39.2% |
| psyq (7) | 44595 | 2313 | 684 | 324 | 1108 | 933 | 68 | 107 | 6.8% | 2 (0.20%) | 300 | 292 | 8 | 206 | 94.8% |
| ee-gcc (5) | 29301 | 3249 | 1609 | 220 | 1415 | 798 | 16 | 601 | 2.0% | 0 (0.00%) | 4 | 1 | 3 | 1 | 94.1% |
| gcc (2) | 4072 | 207 | 18 | 63 | 122 | 122 | 0 | 0 | 0.00% | 0 (0.00%) | 19 | 18 | 1 | 18 | 94.4% |

Renames by the donors' compiler family (correct / wrong; a rename counts once per distinct donor family among its donors), rows = the target's family:

| target \ donor | MWCC | IDO | agbcc | psyq | ee-gcc | gcc |
|---|---:|---:|---:|---:|---:|---:|
| MWCC | 15944 / 210 | 0 / 0 | 0 / 0 | 161 / 5 | 723 / 3 | 0 / 0 |
| IDO | 0 / 0 | 1360 / 126 | 0 / 0 | 0 / 0 | 0 / 0 | 29 / 0 |
| agbcc | 0 / 0 | 0 / 0 | 164 / 31 | 0 / 0 | 0 / 0 | 0 / 0 |
| psyq | 548 / 15 | 0 / 0 | 0 / 0 | 906 / 63 | 0 / 0 | 0 / 0 |
| ee-gcc | 777 / 16 | 0 / 0 | 0 / 0 | 0 / 0 | 569 / 14 | 0 / 0 |
| gcc | 0 / 0 | 17 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 121 / 0 |

## Per compiler family of the target game, non-donor games

| compiler family | probed fns | matched | abstained | gated | renamed | correct | wrong | unscoreable | wrong rate (strict) | function-wrong | scan matches | start hit | start miss | length = truth | our size = pack length |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| MWCC (2) | 14292 | 436 | 435 | 1 | 0 | 0 | 0 | 0 | - | 0 (-) | 1 | 1 | 0 | 0 | 0.92% |
| gcc (3) | 19768 | 474 | 474 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 15 | 6 | 9 | 0 | 0.22% |
| other (5) | 175930 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | - |

Renames by the donors' compiler family (correct / wrong; a rename counts once per distinct donor family among its donors), rows = the target's family:

| target \ donor |  |
|---|
| MWCC |  |
| gcc |  |
| other |  |

Correct renames per target game by the donors' compiler family:

| game | target family | MWCC | IDO | agbcc | psyq | ee-gcc | gcc |
|---|---|---:|---:|---:|---:|---:|---:|
| gba-fire-emblem-sacred-stones | agbcc | 0 | 0 | 59 | 0 | 0 | 0 |
| gba-golden-sun | agbcc | 0 | 0 | 0 | 0 | 0 | 0 |
| gba-kh-chain-of-memories | agbcc | 0 | 0 | 38 | 0 | 0 | 0 |
| gba-klonoa-empire-of-dreams | agbcc | 0 | 0 | 9 | 0 | 0 | 0 |
| gba-nascar-heat-2002 | agbcc | 0 | 0 | 58 | 0 | 0 | 0 |
| gc-mario-party-4 | MWCC | 702 | 0 | 0 | 0 | 0 | 0 |
| gc-melee | MWCC | 498 | 0 | 0 | 0 | 0 | 0 |
| gc-pikmin | MWCC | 340 | 0 | 0 | 0 | 0 | 0 |
| gc-pikmin-2 | MWCC | 876 | 0 | 0 | 0 | 0 | 0 |
| gc-super-mario-strikers | MWCC | 835 | 0 | 0 | 0 | 0 | 0 |
| gc-tiger-woods-2004 | MWCC | 662 | 0 | 0 | 0 | 0 | 0 |
| gc-twilight-princess | MWCC | 1311 | 0 | 0 | 0 | 0 | 0 |
| gc-wind-waker | MWCC | 1226 | 0 | 0 | 0 | 0 | 0 |
| n64-banjo-kazooie | IDO | 0 | 70 | 0 | 0 | 0 | 1 |
| n64-dr-mario-64 | gcc | 0 | 8 | 0 | 0 | 0 | 61 |
| n64-majoras-mask | IDO | 0 | 395 | 0 | 0 | 0 | 8 |
| n64-ocarina-of-time | IDO | 0 | 417 | 0 | 0 | 0 | 6 |
| n64-paper-mario | gcc | 0 | 9 | 0 | 0 | 0 | 60 |
| n64-perfect-dark | IDO | 0 | 131 | 0 | 0 | 0 | 5 |
| n64-star-fox-64 | IDO | 0 | 116 | 0 | 0 | 0 | 0 |
| n64-super-mario-64 | IDO | 0 | 95 | 0 | 0 | 0 | 4 |
| n64-super-smash-bros | IDO | 0 | 136 | 0 | 0 | 0 | 5 |
| nds-dragon-quest-iv | MWCC | 115 | 0 | 0 | 0 | 0 | 0 |
| nds-kh-358-2-days | MWCC | 236 | 0 | 0 | 0 | 0 | 0 |
| nds-kh-recoded | MWCC | 0 | 0 | 0 | 0 | 0 | 0 |
| nds-pokemon-platinum | MWCC | 301 | 0 | 0 | 0 | 0 | 0 |
| nds-world-ends-with-you | MWCC | 151 | 0 | 0 | 0 | 0 | 0 |
| ps2-dark-chronicle | MWCC | 288 | 0 | 0 | 0 | 441 | 0 |
| ps2-dark-cloud | MWCC | 288 | 0 | 0 | 0 | 271 | 0 |
| ps2-digital-devil-saga | ee-gcc | 100 | 0 | 0 | 0 | 88 | 0 |
| ps2-fatal-frame | ee-gcc | 383 | 0 | 0 | 0 | 227 | 0 |
| ps2-god-hand | ee-gcc | 70 | 0 | 0 | 0 | 70 | 0 |
| ps2-persona-4 | MWCC | 4 | 0 | 0 | 0 | 11 | 0 |
| ps2-ratchet-clank | ee-gcc | 224 | 0 | 0 | 0 | 184 | 0 |
| ps2-ratchet-clank-pal | ee-gcc | 0 | 0 | 0 | 0 | 0 | 0 |
| psp-hot-pixel | gcc | 0 | 0 | 0 | 0 | 0 | 0 |
| psp-melodie | gcc | 0 | 0 | 0 | 0 | 0 | 0 |
| psp-pac-man-rally | gcc | 0 | 0 | 0 | 0 | 0 | 0 |
| psp-psp-camera-01 | MWCC | 0 | 0 | 0 | 0 | 0 | 0 |
| psp-tetris | MWCC | 0 | 0 | 0 | 0 | 0 | 0 |
| psx-digimon-world | MWCC | 0 | 0 | 0 | 161 | 0 | 0 |
| psx-legend-of-mana | psyq | 80 | 0 | 0 | 146 | 0 | 0 |
| psx-nfs-high-stakes | psyq | 0 | 0 | 0 | 0 | 0 | 0 |
| psx-parasite-eve | psyq | 110 | 0 | 0 | 181 | 0 | 0 |
| psx-parasite-eve-2 | psyq | 112 | 0 | 0 | 197 | 0 | 0 |
| psx-rage-racer | psyq | 26 | 0 | 0 | 36 | 0 | 0 |
| psx-silent-hill | psyq | 134 | 0 | 0 | 191 | 0 | 0 |
| psx-vagrant-story | psyq | 86 | 0 | 0 | 155 | 0 | 0 |
| wii-mario-strikers-charged | MWCC | 1766 | 0 | 0 | 0 | 0 | 0 |
| wii-npc-pikmin-2 | MWCC | 2122 | 0 | 0 | 0 | 0 | 0 |
| wii-rock-band-3 | MWCC | 654 | 0 | 0 | 0 | 0 | 0 |
| wii-skyward-sword | MWCC | 1500 | 0 | 0 | 0 | 0 | 0 |
| wii-super-mario-galaxy | MWCC | 2069 | 0 | 0 | 0 | 0 | 0 |
| x360-amped-3 | other | 0 | 0 | 0 | 0 | 0 | 0 |
| x360-burnout-crash | other | 0 | 0 | 0 | 0 | 0 | 0 |
| x360-call-of-duty-advanced-warfare | other | 0 | 0 | 0 | 0 | 0 | 0 |
| x360-call-of-duty-modern-warfare-2 | other | 0 | 0 | 0 | 0 | 0 | 0 |
| x360-forza-horizon-2-prototype | other | 0 | 0 | 0 | 0 | 0 | 0 |

## Self mode: no exclusion (a game that has a decomp)

| game | probed fns | matched | abstained | gated | renamed | correct | wrong | unscoreable | wrong rate (strict) | function-wrong | scan matches | start hit | start miss | length = truth | our size = pack length |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gba-kh-chain-of-memories | 5226 | 3823 | 25 | 1674 | 2065 | 2065 | 0 | 0 | 0.00% | 0 (0.00%) | 60 | 60 | 0 | 59 | 28.2% |
| n64-super-mario-64 | 5008 | 3209 | 29 | 879 | 2295 | 2294 | 1 | 0 | 0.04% | 0 (0.00%) | 6 | 4 | 2 | 4 | 96.9% |
| gc-pikmin | 8095 | 5802 | 48 | 1915 | 3832 | 3832 | 0 | 0 | 0.00% | 0 (0.00%) | 5 | 3 | 2 | 3 | 99.7% |

## Per game (leave-one-out)

| game | probed fns | matched | abstained | gated | renamed | correct | wrong | unscoreable | wrong rate (strict) | function-wrong | scan matches | start hit | start miss | length = truth | our size = pack length |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gba-fire-emblem-sacred-stones | 8214 | 135 | 32 | 40 | 59 | 59 | 0 | 0 | 0.00% | 0 (0.00%) | 6 | 6 | 0 | 6 | 49.4% |
| gba-golden-sun | 10847 | 49 | 4 | 9 | 30 | 0 | 29 | 1 | 100.0% | 0 (0.00%) | 6 | 6 | 0 | 5 | 14.7% |
| gba-kh-chain-of-memories | 5226 | 59 | 11 | 9 | 38 | 38 | 0 | 0 | 0.00% | 0 (0.00%) | 1 | 1 | 0 | 0 | 51.0% |
| gba-klonoa-empire-of-dreams | 524 | 60 | 36 | 12 | 11 | 9 | 2 | 0 | 18.2% | 0 (0.00%) | 7 | 7 | 0 | 6 | 24.4% |
| gba-nascar-heat-2002 | 1083 | 188 | 69 | 56 | 58 | 58 | 0 | 0 | 0.00% | 0 (0.00%) | 11 | 11 | 0 | 11 | 38.8% |
| gc-mario-party-4 | 11002 | 936 | 30 | 191 | 707 | 702 | 5 | 0 | 0.71% | 1 (0.14%) | 4 | 2 | 2 | 2 | 98.5% |
| gc-melee | 19836 | 824 | 164 | 155 | 501 | 498 | 3 | 0 | 0.60% | 0 (0.00%) | 5 | 3 | 2 | 3 | 99.4% |
| gc-pikmin | 8095 | 502 | 35 | 115 | 346 | 340 | 6 | 0 | 1.7% | 1 (0.29%) | 5 | 3 | 2 | 3 | 98.4% |
| gc-pikmin-2 | 24991 | 1876 | 197 | 792 | 879 | 876 | 3 | 0 | 0.34% | 1 (0.11%) | 4 | 2 | 2 | 2 | 99.1% |
| gc-super-mario-strikers | 8634 | 1305 | 112 | 348 | 837 | 835 | 2 | 0 | 0.24% | 1 (0.12%) | 4 | 2 | 2 | 2 | 99.0% |
| gc-tiger-woods-2004 | 7656 | 1046 | 114 | 264 | 663 | 662 | 1 | 0 | 0.15% | 0 (0.00%) | 3 | 2 | 1 | 2 | 99.1% |
| gc-twilight-princess | 48222 | 5523 | 82 | 4118 | 1315 | 1311 | 4 | 0 | 0.30% | 2 (0.15%) | 4 | 2 | 2 | 2 | 99.2% |
| gc-wind-waker | 39394 | 4959 | 48 | 3673 | 1230 | 1226 | 4 | 0 | 0.33% | 1 (0.08%) | 4 | 2 | 2 | 2 | 99.2% |
| n64-banjo-kazooie | 6794 | 592 | 173 | 330 | 85 | 70 | 6 | 9 | 7.9% | 1 (1.3%) | 4 | 4 | 0 | 4 | 98.8% |
| n64-dr-mario-64 | 1333 | 94 | 1 | 31 | 61 | 61 | 0 | 0 | 0.00% | 0 (0.00%) | 2 | 1 | 1 | 1 | 95.1% |
| n64-majoras-mask | 16419 | 1191 | 94 | 630 | 451 | 397 | 52 | 2 | 11.6% | 0 (0.00%) | 18 | 15 | 3 | 15 | 99.5% |
| n64-ocarina-of-time | 12787 | 1187 | 79 | 613 | 477 | 417 | 53 | 7 | 11.3% | 0 (0.00%) | 19 | 17 | 2 | 17 | 99.5% |
| n64-paper-mario | 2739 | 113 | 17 | 32 | 61 | 61 | 0 | 0 | 0.00% | 0 (0.00%) | 17 | 17 | 0 | 17 | 93.8% |
| n64-perfect-dark | 5491 | 203 | 27 | 35 | 139 | 131 | 8 | 0 | 5.8% | 3 (2.2%) | 2 | 0 | 2 | 0 | 98.8% |
| n64-star-fox-64 | 1593 | 198 | 28 | 29 | 136 | 116 | 3 | 17 | 2.5% | 0 (0.00%) | 6 | 4 | 2 | 4 | 98.8% |
| n64-super-mario-64 | 5008 | 124 | 11 | 13 | 98 | 95 | 3 | 0 | 3.1% | 0 (0.00%) | 2 | 0 | 2 | 0 | 100.0% |
| n64-super-smash-bros | 1635 | 207 | 32 | 37 | 138 | 136 | 1 | 1 | 0.73% | 0 (0.00%) | 15 | 15 | 0 | 15 | 98.1% |
| nds-dragon-quest-iv | 7911 | 866 | 224 | 104 | 517 | 115 | 10 | 392 | 8.0% | 0 (0.00%) | 31 | 31 | 0 | 30 | 45.7% |
| nds-kh-358-2-days | 20753 | 1138 | 496 | 311 | 309 | 236 | 40 | 33 | 14.5% | 6 (2.2%) | 34 | 22 | 12 | 21 | 48.9% |
| nds-kh-recoded | 8411 | 442 | 73 | 124 | 238 | 0 | 1 | 237 | 100.0% | 0 (0.00%) | 13 | 5 | 8 | 5 | 58.4% |
| nds-pokemon-platinum | 30872 | 1002 | 265 | 347 | 368 | 301 | 43 | 24 | 12.5% | 0 (0.00%) | 28 | 26 | 2 | 26 | 41.6% |
| nds-world-ends-with-you | 12783 | 887 | 185 | 117 | 563 | 151 | 58 | 354 | 27.8% | 0 (0.00%) | 26 | 26 | 0 | 25 | 43.0% |
| ps2-dark-chronicle | 7862 | 606 | 60 | 75 | 471 | 471 | 0 | 0 | 0.00% | 0 (0.00%) | 0 | 0 | 0 | 0 | 99.6% |
| ps2-dark-cloud | 4193 | 385 | 50 | 32 | 303 | 301 | 2 | 0 | 0.66% | 1 (0.33%) | 0 | 0 | 0 | 0 | 99.2% |
| ps2-digital-devil-saga | 10338 | 465 | 171 | 60 | 233 | 103 | 0 | 130 | 0.00% | 0 (0.00%) | 0 | 0 | 0 | 0 | 86.7% |
| ps2-fatal-frame | 4253 | 453 | 43 | 23 | 387 | 386 | 1 | 0 | 0.26% | 0 (0.00%) | 0 | 0 | 0 | 0 | 98.4% |
| ps2-god-hand | 11295 | 1621 | 1316 | 71 | 232 | 78 | 2 | 152 | 2.5% | 0 (0.00%) | 2 | 0 | 2 | 0 | 94.1% |
| ps2-persona-4 | 13182 | 1629 | 1103 | 239 | 286 | 11 | 1 | 274 | 8.3% | 0 (0.00%) | 1 | 0 | 1 | 0 | 98.6% |
| ps2-ratchet-clank | 1707 | 355 | 40 | 33 | 281 | 231 | 13 | 37 | 5.3% | 0 (0.00%) | 1 | 0 | 1 | 0 | 96.0% |
| ps2-ratchet-clank-pal | 1708 | 355 | 39 | 33 | 282 | 0 | 0 | 282 | - | 0 (-) | 1 | 1 | 0 | 1 | 96.0% |
| psp-hot-pixel (non-donor) | 9896 | 238 | 238 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 6 | 6 | 0 | 0 | 0.43% |
| psp-melodie (non-donor) | 3467 | 62 | 62 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | 0.00% |
| psp-pac-man-rally (non-donor) | 6405 | 174 | 174 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 9 | 0 | 9 | 0 | 0.00% |
| psp-psp-camera-01 (non-donor) | 6404 | 230 | 230 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | 0.87% |
| psp-tetris (non-donor) | 7888 | 206 | 205 | 1 | 0 | 0 | 0 | 0 | - | 0 (-) | 1 | 1 | 0 | 0 | 0.98% |
| psx-digimon-world | 3271 | 266 | 51 | 37 | 166 | 161 | 5 | 0 | 3.0% | 0 (0.00%) | 12 | 12 | 0 | 12 | 100.0% |
| psx-legend-of-mana | 6273 | 449 | 141 | 65 | 177 | 149 | 28 | 0 | 15.8% | 0 (0.00%) | 70 | 69 | 1 | 69 | 97.5% |
| psx-nfs-high-stakes | 3461 | 35 | 21 | 14 | 0 | 0 | 0 | 0 | - | 0 (-) | 9 | 9 | 0 | 0 | 75.0% |
| psx-parasite-eve | 9909 | 381 | 110 | 29 | 230 | 186 | 9 | 35 | 4.6% | 1 (0.51%) | 19 | 19 | 0 | 18 | 98.8% |
| psx-parasite-eve-2 | 13235 | 397 | 89 | 56 | 218 | 203 | 1 | 14 | 0.49% | 0 (0.00%) | 34 | 32 | 2 | 32 | 99.0% |
| psx-rage-racer | 1143 | 66 | 11 | 9 | 41 | 36 | 5 | 0 | 12.2% | 1 (2.4%) | 7 | 6 | 1 | 6 | 100.0% |
| psx-silent-hill | 6433 | 503 | 210 | 41 | 229 | 204 | 12 | 13 | 5.6% | 0 (0.00%) | 102 | 98 | 4 | 22 | 82.5% |
| psx-vagrant-story | 4141 | 482 | 102 | 110 | 213 | 155 | 13 | 45 | 7.7% | 0 (0.00%) | 59 | 59 | 0 | 59 | 97.8% |
| wii-mario-strikers-charged | 17695 | 2383 | 178 | 420 | 1774 | 1766 | 8 | 0 | 0.45% | 2 (0.11%) | 7 | 5 | 2 | 5 | 97.5% |
| wii-npc-pikmin-2 | 28170 | 2983 | 220 | 625 | 2125 | 2122 | 3 | 0 | 0.14% | 1 (0.05%) | 9 | 7 | 2 | 7 | 97.5% |
| wii-rock-band-3 | 58450 | 2915 | 259 | 714 | 1919 | 654 | 4 | 1261 | 0.61% | 0 (0.00%) | 19 | 17 | 2 | 17 | 98.0% |
| wii-skyward-sword | 75032 | 3876 | 697 | 1654 | 1508 | 1500 | 8 | 0 | 0.53% | 0 (0.00%) | 17 | 15 | 2 | 15 | 96.6% |
| wii-super-mario-galaxy | 41946 | 2961 | 354 | 521 | 2076 | 2069 | 5 | 2 | 0.24% | 3 (0.14%) | 7 | 5 | 2 | 5 | 97.9% |
| x360-amped-3 (non-donor) | 35573 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | - |
| x360-burnout-crash (non-donor) | 10928 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | - |
| x360-call-of-duty-advanced-warfare (non-donor) | 36515 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | - |
| x360-call-of-duty-modern-warfare-2 (non-donor) | 14978 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | - |
| x360-forza-horizon-2-prototype (non-donor) | 77936 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | 0 (-) | 0 | 0 | 0 | 0 | - |

## Wrong names on renames: conventions against collisions

Donor games, `FUN_` renames the truth names differently. `kind`, as far as the names show: **spelling** = equal once `_` and case are dropped; **affix** = one base name holds the other (a prefix/suffix convention); **collision** = two different functions share a masked body (the pack's name is also the name of another function of the target, or both names are mangled / qualified methods with different names); **different** = unrelated plain names: another naming convention for the same function, or a collision with a function the truth leaves unnamed; the names cannot tell these apart.

Wrong names by kind: spelling 19, affix 90, collision 15, different 333

### Most frequent wrong (truth, pack) pairs (top 20)

| truth | pack | count | kind |
|---|---|---:|---|
| `sharedFunc_800D81B0_0_s01` | `CdMix` | 6 | different |
| `MTXLightPerspective` | `C_MTXLightPerspective` | 2 | affix |
| `print_f__10JUTConsoleFPCce` | `Mail_sprintf` | 2 | affix |
| `Actor_ChangeAnimationByInfo` | `Animation_ChangeByInfo` | 1 | different |
| `AddMpegCallback` | `sceMpegAddCallback` | 1 | different |
| `Animation_ChangeByInfo` | `Actor_ChangeAnimationByInfo` | 1 | different |
| `Attention_SetNaviState` | `Attention_SetTatlState` | 1 | different |
| `Attention_SetTatlState` | `Attention_SetNaviState` | 1 | different |
| `AudioEffects_UpdateAdsr` | `Audio_AdsrUpdate` | 1 | different |
| `AudioEngine_Initialize` | `SoundInit` | 1 | different |
| `AudioEngine_ResumeDirectSound` | `m4aSoundVSyncOn` | 1 | different |
| `AudioEngine_SetMode` | `m4aSoundMode` | 1 | different |
| `AudioEngine_SetPcmRate` | `SampleFreqSet` | 1 | different |
| `AudioEngine_StopAllChannels` | `SoundClear` | 1 | different |
| `AudioEngine_SuspendDirectSound` | `m4aSoundVSyncOff` | 1 | different |
| `AudioList_InitNoteFreeList` | `Audio_InitNoteFreeList` | 1 | different |
| `AudioPlayback_AllocNote` | `Audio_AllocNote` | 1 | different |
| `AudioPlayback_BuildSyntheticWave` | `Audio_BuildSyntheticWave` | 1 | different |
| `AudioPlayback_GetDrum` | `Audio_GetDrum` | 1 | different |
| `AudioPlayback_GetInstrumentInner` | `Audio_GetInstrumentInner` | 1 | different |

### Pack names that were wrong most often (top 20)

One donor name on many different functions is a shared body, not a convention.

| pack name | wrong | truth names (examples) |
|---|---:|---|
| `CdMix` | 6 | `sharedFunc_800D81B0_0_s01` |
| `SpuInit` | 4 | `stop_checkps_song`, `field_stop_song`, `stop_title_music` |
| `AudioSeq_SequenceChannelEnable` | 2 | `AudioScript_SequenceChannelEnable`, `sequence_channel_enable` |
| `C_MTXLightPerspective` | 2 | `MTXLightPerspective`, `MTXLightPerspective` |
| `MPlayMain` | 2 | `MusicPlayer_Tick`, `MP2KPlayerMain` |
| `Mail_sprintf` | 2 | `print_f__10JUTConsoleFPCce`, `print_f__10JUTConsoleFPCce` |
| `ply_note` | 2 | `MusicTrack_HandleNote`, `MP2K_event_nxx` |
| `Actor_ChangeAnimationByInfo` | 1 | `Animation_ChangeByInfo` |
| `Animation_ChangeByInfo` | 1 | `Actor_ChangeAnimationByInfo` |
| `Attention_SetNaviState` | 1 | `Attention_SetTatlState` |
| `Attention_SetTatlState` | 1 | `Attention_SetNaviState` |
| `AudioEffects_UpdateAdsr` | 1 | `Audio_AdsrUpdate` |
| `AudioList_ClearNotePool` | 1 | `Audio_NotePoolClear` |
| `AudioList_FillNotePool` | 1 | `Audio_NotePoolFill` |
| `AudioList_FindNodeWithPrioLessThan` | 1 | `Audio_FindNodeWithPrioLessThan` |
| `AudioList_InitNoteFreeList` | 1 | `Audio_InitNoteFreeList` |
| `AudioLoad_GetSampleBank` | 1 | `botinv_drop_all` |
| `AudioPlayback_AllocNote` | 1 | `Audio_AllocNote` |
| `AudioPlayback_AllocNoteFromActive` | 1 | `Audio_AllocNoteFromActive` |
| `AudioPlayback_AllocNoteFromDisabled` | 1 | `Audio_AllocNoteFromDisabled` |

## Games that did not run in full

- `n64-banjo-kazooie`: 14 truth modules (1,636 functions) not placed in any import program, not scored: 14 x the importer does not place this module (not in the import's modules table or programs) (e.g. CC, MMM, GV, TTC)
- `n64-majoras-mask`: 617 truth modules (13,062 functions) not placed in any import program, not scored: 617 x the importer does not place this module (not in the import's modules table or programs) (e.g. ovl_Arms_Hook, ovl_Arrow_Fire, ovl_Arrow_Ice, ovl_Arrow_Light)
- `n64-ocarina-of-time`: 469 truth modules (10,252 functions) not placed in any import program, not scored: 469 x the importer does not place this module (not in the import's modules table or programs) (e.g. n64dd, ovl_Arms_Hook, ovl_Arrow_Fire, ovl_Arrow_Ice)
- `n64-paper-mario`: 726 truth modules (9,823 functions) not placed in any import program, not scored: 726 x the importer does not place this module (not in the import's modules table or programs) (e.g. action_cmd_air_lift, action_cmd_air_raid, action_cmd_body_slam, action_cmd_bomb)
- `n64-star-fox-64`: 9 truth modules (1,242 functions) not placed in any import program, not scored: 9 x the importer does not place this module (not in the import's modules table or programs) (e.g. ovl_ending, ovl_i1, ovl_i2, ovl_i3)
- `n64-super-mario-64`: 1 truth modules (284 functions) not placed in any import program, not scored: 1 x the importer does not place this module (not in the import's modules table or programs) (e.g. engine)
- `n64-super-smash-bros`: 67 truth modules (6,291 functions) not placed in any import program, not scored: 67 x the importer does not place this module (not in the import's modules table or programs) (e.g. scmanager, ovl0, ovl2, ovl3)

