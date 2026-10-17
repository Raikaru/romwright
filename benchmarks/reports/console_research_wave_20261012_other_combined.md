# Console research wave (2026-10-12T06:31:36+00:00)

Tools fingerprint `b2368ce6b5673309`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | Kingdom Hearts: Chain of Memories | USA (B8CE) | True | decomp-build | agbcc (pret/agbcc, -O2) + binutils 2.10 legacy assembler; libgcc/libc members prebuilt | 100.0 | 5257 | 5137 | 0 (0) | main | 0 | False | ran |
| gc-pikmin-2 | Pikmin 2 | GPVE01 USA Rev 0 | True | decomp-symbols | MWCC GC/2.6 (95.7% of linked code bytes), GC/1.2.5n (4.3% of linked code bytes) | 98.09 | 24956 | 24625 | 0 (0) | main | 0 | False | ran |
| n64-super-mario-64 | Super Mario 64 | USA (VERSION=us) | True | decomp-build | IDO 5.3 (ido-static-recomp built from tools/ido-static-recomp) | 100.0 | 3813 | 3806 | 0 (0) | main | 284 | False | ran |
| nds-kh-358-2-days | Kingdom Hearts 358/2 Days | EU (YKGP) | True | decomp-symbols | mwccarm 3.0 build 139 (a few precompiled-middleware units with an older mwccarm per config/arm9/file_compilers.json), mwldarm | 100.0 | 23233 | 23233 | 0 (0) | main, ov0, ov1, ov2 (+293) | 0 | False | ran |
| psp-hot-pixel | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 9983 | 9983 | 3 (0) | main | 0 | True | ran |
| psp-melodie | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3242 | 3242 | 0 (0) | main | 0 | True | ran |
| psp-pac-man-rally | Pac-Man Rally | Europe, Beta 2007-05-01 | True | dwarf | GNU C 4.0.3+allegrex-2.2.3-psp-2.4.1.internal -g (DW_AT_producer); also an 'SN Systems 1.1.07' string | 100.0 | 6379 | 6379 | 0 (0) | main | 0 | True | ran |
| psp-psp-camera-01 | PSP Camera 01 | Japan | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug (10.5 MB) | 100.0 | 6516 | 6516 | 0 (0) | main | 0 | True | ran |
| psp-tetris | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8513 | 8513 | 0 (0) | main | 0 | True | ran |

## gba

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | default | 0.9582 | 0.9640 | 1.0000 | – | – | 0.9634 | 0.9924 | 961 |
| gba-kh-chain-of-memories | baseline-off | 0.9426 | 0.9634 | 0.9771 | – | – | 0.9474 | 0.9923 | 961 |

**Sign tests, gba**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| recall_verified vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |

## gc

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| gc-pikmin-2 | default | 0.9998 | 0.9984 | 1.0000 | – | – | 0.9998 | 0.9985 | 986 |
| gc-pikmin-2 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 0.9998 | 0.9942 | 986 |

**Sign tests, gc**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |

## n64

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| n64-super-mario-64 | default | 0.9974 | 0.9053 | 1.0000 | – | – | 0.9974 | 0.9052 | 923 |
| n64-super-mario-64 | baseline-off | 0.9974 | 0.9053 | 1.0000 | – | – | 0.9974 | 0.9052 | 923 |

**Sign tests, n64**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |

## nds

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| nds-kh-358-2-days | default | 0.8863 | 0.9922 | 1.0000 | – | – | 0.8863 | 0.9993 | 987 |
| nds-kh-358-2-days | baseline-off | 0.8758 | 0.9921 | 0.9889 | – | – | 0.8758 | 0.9994 | 987 |

**Sign tests, nds**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| recall_verified vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |

## psp

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.8884 | 0.9057 | 1.0000 | 0.8426 | 0.3415 | 0.8884 | 0.9304 | 940 |
| psp-hot-pixel | baseline-off | 0.8879 | 0.8384 | 1.0000 | 0.8426 | 0.3415 | 0.8879 | 0.8596 | 940 |
| psp-melodie | default | 0.9605 | 0.9477 | 1.0000 | 0.9146 | 0.7025 | 0.9605 | 0.9805 | 851 |
| psp-melodie | baseline-off | 0.9602 | 0.7933 | 0.9988 | 0.9146 | 0.7025 | 0.9602 | 0.8162 | 851 |
| psp-pac-man-rally | default | 0.9074 | 0.9280 | 1.0000 | 0.8889 | 0.7205 | 0.9074 | 0.9573 | 862 |
| psp-pac-man-rally | baseline-off | 0.9066 | 0.7936 | 1.0000 | 0.8889 | 0.7205 | 0.9066 | 0.8150 | 862 |
| psp-psp-camera-01 | default | 0.9597 | 0.9585 | 1.0000 | 0.8177 | 0.3995 | 0.9597 | 0.9909 | 938 |
| psp-psp-camera-01 | baseline-off | 0.9591 | 0.9484 | 1.0000 | 0.8177 | 0.3995 | 0.9591 | 0.9802 | 938 |
| psp-tetris | default | 0.9876 | 0.9671 | 1.0000 | 0.7714 | 0.5811 | 0.9876 | 0.9894 | 939 |
| psp-tetris | baseline-off | 0.9876 | 0.9210 | 1.0000 | 0.7714 | 0.5811 | 0.9876 | 0.9413 | 939 |

**Sign tests, psp**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision vs baseline-off | 5 | 5 | 0 | 0 | 0.0312 |
| success_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| arity_accuracy vs baseline-off | 5 | 0 | 0 | 5 | – |
| type_exact_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision_verified vs baseline-off | 5 | 5 | 0 | 0 | 0.0312 |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 9 | 2 | 0 | 7 | 0.2500 |
| precision vs baseline-off | 9 | 5 | 0 | 4 | 0.0312 |
| success_rate vs baseline-off | 9 | 2 | 0 | 7 | 0.2500 |
| arity_accuracy vs baseline-off | 5 | 0 | 0 | 5 | – |
| type_exact_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 9 | 2 | 0 | 7 | 0.2500 |
| precision_verified vs baseline-off | 9 | 5 | 0 | 4 | 0.0312 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | 1 | default | 0.9582 | 0.9640 | 1.0000 | – | – | 500 |
| gba-kh-chain-of-memories | 1 | baseline-off | 0.9426 | 0.9634 | 0.9760 | – | – | 500 |
| gba-kh-chain-of-memories | 2 | default | 0.9582 | 0.9640 | 1.0000 | – | – | 500 |
| gba-kh-chain-of-memories | 2 | baseline-off | 0.9426 | 0.9634 | 0.9800 | – | – | 500 |
| gc-pikmin-2 | 1 | default | 0.9998 | 0.9984 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 1 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 2 | default | 0.9998 | 0.9984 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 2 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 1 | default | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 1 | baseline-off | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 2 | default | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 2 | baseline-off | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| nds-kh-358-2-days | 1 | default | 0.8863 | 0.9922 | 1.0000 | – | – | 500 |
| nds-kh-358-2-days | 1 | baseline-off | 0.8758 | 0.9921 | 0.9940 | – | – | 500 |
| nds-kh-358-2-days | 2 | default | 0.8863 | 0.9922 | 1.0000 | – | – | 500 |
| nds-kh-358-2-days | 2 | baseline-off | 0.8758 | 0.9921 | 0.9840 | – | – | 500 |
| psp-hot-pixel | 1 | default | 0.8884 | 0.9057 | 1.0000 | 0.8640 | 0.3497 | 500 |
| psp-hot-pixel | 1 | baseline-off | 0.8879 | 0.8384 | 1.0000 | 0.8640 | 0.3497 | 500 |
| psp-hot-pixel | 2 | default | 0.8884 | 0.9057 | 1.0000 | 0.8260 | 0.3361 | 500 |
| psp-hot-pixel | 2 | baseline-off | 0.8879 | 0.8384 | 1.0000 | 0.8260 | 0.3361 | 500 |
| psp-melodie | 1 | default | 0.9605 | 0.9477 | 1.0000 | 0.9146 | 0.7025 | 500 |
| psp-melodie | 1 | baseline-off | 0.9602 | 0.7933 | 1.0000 | 0.9146 | 0.7025 | 500 |
| psp-melodie | 2 | default | 0.9605 | 0.9477 | 1.0000 | 0.9146 | 0.7025 | 500 |
| psp-melodie | 2 | baseline-off | 0.9602 | 0.7933 | 0.9980 | 0.9146 | 0.7025 | 500 |
| psp-pac-man-rally | 1 | default | 0.9074 | 0.9280 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-pac-man-rally | 1 | baseline-off | 0.9066 | 0.7936 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-pac-man-rally | 2 | default | 0.9074 | 0.9280 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-pac-man-rally | 2 | baseline-off | 0.9066 | 0.7936 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-psp-camera-01 | 1 | default | 0.9597 | 0.9585 | 1.0000 | 0.8480 | 0.3977 | 500 |
| psp-psp-camera-01 | 1 | baseline-off | 0.9591 | 0.9484 | 1.0000 | 0.8480 | 0.3977 | 500 |
| psp-psp-camera-01 | 2 | default | 0.9597 | 0.9585 | 1.0000 | 0.7860 | 0.4004 | 500 |
| psp-psp-camera-01 | 2 | baseline-off | 0.9591 | 0.9484 | 1.0000 | 0.7860 | 0.4004 | 500 |
| psp-tetris | 1 | default | 0.9876 | 0.9671 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 1 | baseline-off | 0.9876 | 0.9210 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 2 | default | 0.9876 | 0.9671 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 2 | baseline-off | 0.9876 | 0.9210 | 1.0000 | 0.7714 | 0.5811 | 500 |


# Console research components (2026-10-12T06:31:36+00:00)

Tools fingerprint `b2368ce6b5673309`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-kh-chain-of-memories | gc-pikmin-2 | n64-super-mario-64 | nds-kh-358-2-days | psp-hot-pixel | psp-melodie | psp-pac-man-rally | psp-psp-camera-01 | psp-tetris |
|---|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps | helps | helps | helps | mixed |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-kh-chain-of-memories | helps | recall +1.6pp, precision +0.1pp~, success_rate +2.3pp, gotos -571, labels -270, irregular_functions -3~, native_warnings +2~, lines +1101, recall_verified +1.6pp, precision_verified +0.0pp | no change | recall +1.6pp, precision +0.1pp~, success_rate +2.3pp, gotos -571, labels -270, irregular_functions -3~, native_warnings +2~, lines +1101, recall_verified +1.6pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | gc-pikmin-2 | helps | precision +0.4pp~, gotos -60, labels -28, irregular_functions -4~, native_warnings +2~, text_warnings +1~, lines +178, precision_verified +0.4pp | no change | precision +0.4pp~, gotos -60, labels -28, irregular_functions -4~, native_warnings +2~, text_warnings +1~, lines +178, precision_verified +0.4pp |
| all research (default vs baseline-off) | n64-super-mario-64 | helps | gotos -16, labels -8, lines +249 | no change | gotos -16, labels -8, lines +249 |
| all research (default vs baseline-off) | nds-kh-358-2-days | helps | recall +1.1pp, precision +0.0pp~, success_rate +1.1pp, gotos -50, labels -27, irregular_functions -1~, native_warnings +1~, lines +207, recall_verified +1.1pp, precision_verified -0.0pp | no change | recall +1.1pp, precision +0.0pp~, success_rate +1.1pp, gotos -50, labels -27, irregular_functions -1~, native_warnings +1~, lines +207, recall_verified +1.1pp, precision_verified -0.0pp |
| all research (default vs baseline-off) | psp-hot-pixel | helps | recall +0.1pp~, precision +6.7pp, gotos -730, labels -437, irregular_functions -20, lines +1180, recall_verified +0.1pp, precision_verified +7.1pp | no change | recall +0.1pp~, precision +6.7pp, gotos -730, labels -437, irregular_functions -20, lines +1180, recall_verified +0.1pp, precision_verified +7.1pp |
| all research (default vs baseline-off) | psp-melodie | helps | recall +0.0pp~, precision +15.4pp, success_rate +0.1pp~, gotos -112, labels -60, irregular_functions -11, native_warnings -2~, lines +113, recall_verified +0.0pp, precision_verified +16.4pp | no change | recall +0.0pp~, precision +15.4pp, success_rate +0.1pp~, gotos -112, labels -60, irregular_functions -11, native_warnings -2~, lines +113, recall_verified +0.0pp, precision_verified +16.4pp |
| all research (default vs baseline-off) | psp-pac-man-rally | helps | recall +0.1pp~, precision +13.4pp, gotos -184, labels -94, irregular_functions -5, native_warnings +2~, text_warnings +2~, lines +307, recall_verified +0.1pp, precision_verified +14.2pp | no change | recall +0.1pp~, precision +13.4pp, gotos -184, labels -94, irregular_functions -5, native_warnings +2~, text_warnings +2~, lines +307, recall_verified +0.1pp, precision_verified +14.2pp |
| all research (default vs baseline-off) | psp-psp-camera-01 | helps | recall +0.1pp~, precision +1.0pp, gotos -84, labels -46, irregular_functions -3~, lines +347, recall_verified +0.1pp, precision_verified +1.1pp | no change | recall +0.1pp~, precision +1.0pp, gotos -84, labels -46, irregular_functions -3~, lines +347, recall_verified +0.1pp, precision_verified +1.1pp |
| all research (default vs baseline-off) | psp-tetris | mixed | precision +4.6pp, gotos -204, labels -102, irregular_functions -12, native_warnings +2~, text_warnings +1, lines +320, precision_verified +4.8pp | no change | precision +4.6pp, gotos -204, labels -102, irregular_functions -12, native_warnings +2~, text_warnings +1, lines +320, precision_verified +4.8pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | default | 1.0000 | 68 | 36 | 837 | 3124 | 41947 | 0.9582 | 0.9640 | – | – | – | – | 0.9180 |
| gba-kh-chain-of-memories | baseline-off | 0.9771 | 639 | 306 | 832 | 3090 | 40401 | 0.9426 | 0.9634 | – | – | – | – | 0.8400 |
| gc-pikmin-2 | default | 1.0000 | 59 | 31 | 634 | 2628 | 46430 | 0.9998 | 0.9984 | – | – | – | – | 0.8430 |
| gc-pikmin-2 | baseline-off | 1.0000 | 119 | 59 | 638 | 2626 | 46252 | 0.9998 | 0.9942 | – | – | – | – | 0.8290 |
| n64-super-mario-64 | default | 1.0000 | 15 | 4 | 633 | 1754 | 25384 | 0.9974 | 0.9053 | – | – | – | – | 0.4530 |
| n64-super-mario-64 | baseline-off | 1.0000 | 31 | 12 | 633 | 1754 | 25135 | 0.9974 | 0.9053 | – | – | – | – | 0.3620 |
| nds-kh-358-2-days | default | 1.0000 | 24 | 10 | 865 | 2673 | 44697 | 0.8863 | 0.9922 | – | – | – | – | 1.1730 |
| nds-kh-358-2-days | baseline-off | 0.9889 | 74 | 37 | 863 | 2666 | 43941 | 0.8758 | 0.9921 | – | – | – | – | 1.1640 |
| psp-hot-pixel | default | 1.0000 | 614 | 312 | 715 | 2580 | 65423 | 0.8884 | 0.9057 | 0.8426 | 0.3415 | – | – | 0.5520 |
| psp-hot-pixel | baseline-off | 1.0000 | 1344 | 749 | 735 | 2580 | 64243 | 0.8879 | 0.8384 | 0.8426 | 0.3415 | – | – | 0.5480 |
| psp-melodie | default | 1.0000 | 114 | 54 | 561 | 2030 | 45718 | 0.9605 | 0.9477 | 0.9146 | 0.7025 | – | – | 0.1830 |
| psp-melodie | baseline-off | 0.9988 | 226 | 114 | 571 | 2030 | 45570 | 0.9602 | 0.7933 | 0.9146 | 0.7025 | – | – | 0.1850 |
| psp-pac-man-rally | default | 1.0000 | 61 | 28 | 472 | 1839 | 33577 | 0.9074 | 0.9280 | 0.8889 | 0.7205 | – | – | 0.9190 |
| psp-pac-man-rally | baseline-off | 1.0000 | 245 | 122 | 477 | 1837 | 33270 | 0.9066 | 0.7936 | 0.8889 | 0.7205 | – | – | 0.9210 |
| psp-psp-camera-01 | default | 1.0000 | 48 | 22 | 590 | 2049 | 33342 | 0.9597 | 0.9585 | 0.8177 | 0.3995 | – | – | 0.2730 |
| psp-psp-camera-01 | baseline-off | 1.0000 | 132 | 68 | 593 | 2049 | 32995 | 0.9591 | 0.9484 | 0.8177 | 0.3995 | – | – | 0.2720 |
| psp-tetris | default | 1.0000 | 105 | 65 | 504 | 1467 | 38305 | 0.9876 | 0.9671 | 0.7714 | 0.5811 | – | – | 0.3360 |
| psp-tetris | baseline-off | 1.0000 | 309 | 167 | 516 | 1465 | 37985 | 0.9876 | 0.9210 | 0.7714 | 0.5811 | – | – | 0.3370 |
