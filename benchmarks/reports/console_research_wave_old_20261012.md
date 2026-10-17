# Console research wave (2026-10-12T07:38:40+00:00)

Tools fingerprint `52f49563eda17be4`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gc-pikmin-2 | Pikmin 2 | GPVE01 USA Rev 0 | True | decomp-symbols | MWCC GC/2.6 (95.7% of linked code bytes), GC/1.2.5n (4.3% of linked code bytes) | 98.09 | 24956 | 24625 | 0 (0) | main | 0 | False | ran |
| ps2-fatal-frame | Fatal Frame (Project Zero) | USA NTSC-U SLUS-20388 | True | decomp-symbols | EE GCC 2.9-991111 (ee-gcc, repo config compiler EEGCC; platform ps2) | 69.84 | 4250 | 3437 | 0 (0) | main | 0 | True | ran |
| ps2-god-hand | God Hand | USA NTSC-U SLUS-21503 (disc 1.00) | True | decomp-symbols | SN ProDG ee-gcc 2.95.3 (matched TUs) + EE GCC 2.96 (dvp-as, ee-ld); SN small-data (.sndata) | 43.53 | 11233 | 7946 | 0 (0) | main | 0 | False | ran |
| psp-hot-pixel | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 9983 | 9983 | 3 (0) | main | 0 | True | ran |

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

## ps2

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-fatal-frame | default | 0.9958 | 0.9993 | 1.0000 | – | – | 0.9959 | 0.9997 | 942 |
| ps2-fatal-frame | baseline-off | 0.9958 | 0.9927 | 1.0000 | – | – | 0.9959 | 0.9945 | 942 |
| ps2-god-hand | default | 0.9976 | 0.9943 | 1.0000 | – | – | 0.9980 | 1.0000 | 980 |
| ps2-god-hand | baseline-off | 0.9976 | 0.8815 | 1.0000 | – | – | 0.9980 | 0.9176 | 980 |

**Sign tests, ps2**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision vs baseline-off | 2 | 2 | 0 | 0 | 0.2500 |
| success_rate vs baseline-off | 2 | 0 | 0 | 2 | – |
| recall_verified vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision_verified vs baseline-off | 2 | 2 | 0 | 0 | 0.2500 |

## psp

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.8884 | 0.9057 | 1.0000 | 0.8426 | 0.3415 | 0.8884 | 0.9304 | 940 |
| psp-hot-pixel | baseline-off | 0.8879 | 0.8384 | 1.0000 | 0.8426 | 0.3415 | 0.8879 | 0.8596 | 940 |

**Sign tests, psp**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| arity_accuracy vs baseline-off | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 4 | 0 | 0 | 4 | – |
| precision vs baseline-off | 4 | 3 | 0 | 1 | 0.1250 |
| success_rate vs baseline-off | 4 | 0 | 0 | 4 | – |
| arity_accuracy vs baseline-off | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 4 | 0 | 0 | 4 | – |
| precision_verified vs baseline-off | 4 | 3 | 0 | 1 | 0.1250 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| gc-pikmin-2 | 1 | default | 0.9998 | 0.9984 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 1 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 2 | default | 0.9998 | 0.9984 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 2 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 1 | default | 0.9958 | 0.9993 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 1 | baseline-off | 0.9958 | 0.9927 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 2 | default | 0.9958 | 0.9993 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 2 | baseline-off | 0.9958 | 0.9927 | 1.0000 | – | – | 500 |
| ps2-god-hand | 1 | default | 0.9976 | 0.9943 | 1.0000 | – | – | 500 |
| ps2-god-hand | 1 | baseline-off | 0.9976 | 0.8815 | 1.0000 | – | – | 500 |
| ps2-god-hand | 2 | default | 0.9976 | 0.9943 | 1.0000 | – | – | 500 |
| ps2-god-hand | 2 | baseline-off | 0.9976 | 0.8815 | 1.0000 | – | – | 500 |
| psp-hot-pixel | 1 | default | 0.8884 | 0.9057 | 1.0000 | 0.8640 | 0.3497 | 500 |
| psp-hot-pixel | 1 | baseline-off | 0.8879 | 0.8384 | 1.0000 | 0.8640 | 0.3497 | 500 |
| psp-hot-pixel | 2 | default | 0.8884 | 0.9057 | 1.0000 | 0.8260 | 0.3361 | 500 |
| psp-hot-pixel | 2 | baseline-off | 0.8879 | 0.8384 | 1.0000 | 0.8260 | 0.3361 | 500 |


# Console research components (2026-10-12T07:38:40+00:00)

Tools fingerprint `52f49563eda17be4`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gc-pikmin-2 | ps2-fatal-frame | ps2-god-hand | psp-hot-pixel |
|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gc-pikmin-2 | helps | precision +0.4pp~, gotos -60, labels -28, irregular_functions -4~, native_warnings +2~, text_warnings +1~, lines +178, precision_verified +0.4pp | no change | precision +0.4pp~, gotos -60, labels -28, irregular_functions -4~, native_warnings +2~, text_warnings +1~, lines +178, precision_verified +0.4pp |
| all research (default vs baseline-off) | ps2-fatal-frame | helps | precision +0.7pp, gotos -548, labels -261, irregular_functions -14, native_warnings +6~, text_warnings -5, lines +885, precision_verified +0.5pp | no change | precision +0.7pp, gotos -548, labels -261, irregular_functions -14, native_warnings +6~, text_warnings -5, lines +885, precision_verified +0.5pp |
| all research (default vs baseline-off) | ps2-god-hand | helps | precision +11.3pp, gotos -397, labels -196, irregular_functions -12, native_warnings -1~, text_warnings -1~, lines +706, precision_verified +8.2pp | no change | precision +11.3pp, gotos -397, labels -196, irregular_functions -12, native_warnings -1~, text_warnings -1~, lines +706, precision_verified +8.2pp |
| all research (default vs baseline-off) | psp-hot-pixel | helps | recall +0.1pp~, precision +6.7pp, gotos -730, labels -437, irregular_functions -20, lines +1180, recall_verified +0.1pp, precision_verified +7.1pp | no change | recall +0.1pp~, precision +6.7pp, gotos -730, labels -437, irregular_functions -20, lines +1180, recall_verified +0.1pp, precision_verified +7.1pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gc-pikmin-2 | default | 1.0000 | 59 | 31 | 634 | 2628 | 46430 | 0.9998 | 0.9984 | – | – | – | – | 0.8310 |
| gc-pikmin-2 | baseline-off | 1.0000 | 119 | 59 | 638 | 2626 | 46252 | 0.9998 | 0.9942 | – | – | – | – | 0.8070 |
| ps2-fatal-frame | default | 1.0000 | 247 | 93 | 633 | 2969 | 61387 | 0.9958 | 0.9993 | – | – | – | – | 0.1690 |
| ps2-fatal-frame | baseline-off | 1.0000 | 795 | 354 | 647 | 2963 | 60502 | 0.9958 | 0.9927 | – | – | – | – | 0.1580 |
| ps2-god-hand | default | 1.0000 | 186 | 95 | 685 | 2063 | 45366 | 0.9976 | 0.9943 | – | – | – | – | 0.4010 |
| ps2-god-hand | baseline-off | 1.0000 | 583 | 291 | 697 | 2064 | 44660 | 0.9976 | 0.8815 | – | – | – | – | 0.4160 |
| psp-hot-pixel | default | 1.0000 | 614 | 312 | 715 | 2580 | 65426 | 0.8884 | 0.9057 | 0.8426 | 0.3415 | – | – | 0.5510 |
| psp-hot-pixel | baseline-off | 1.0000 | 1344 | 749 | 735 | 2580 | 64246 | 0.8879 | 0.8384 | 0.8426 | 0.3415 | – | – | 0.5480 |
