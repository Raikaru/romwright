# Console research wave (2026-10-12T07:34:43+00:00)

Tools fingerprint `b2368ce6b5673309`; sample n=200 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 9983 | 9983 | 3 (0) | main | 0 | True | ran |
| psp-melodie | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3242 | 3242 | 0 (0) | main | 0 | True | ran |
| psp-pac-man-rally | Pac-Man Rally | Europe, Beta 2007-05-01 | True | dwarf | GNU C 4.0.3+allegrex-2.2.3-psp-2.4.1.internal -g (DW_AT_producer); also an 'SN Systems 1.1.07' string | 100.0 | 6379 | 6379 | 0 (0) | main | 0 | True | ran |
| psp-psp-camera-01 | PSP Camera 01 | Japan | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug (10.5 MB) | 100.0 | 6516 | 6516 | 0 (0) | main | 0 | True | ran |
| psp-tetris | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8513 | 8513 | 0 (0) | main | 0 | True | ran |

## psp

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.8884 | 0.9057 | 0.9974 | 0.8295 | 0.3642 | 0.8884 | 0.9304 | 387 |
| psp-hot-pixel | baseline-off | 0.8879 | 0.8384 | 0.9974 | 0.8295 | 0.3668 | 0.8879 | 0.8596 | 387 |
| psp-melodie | default | 0.9605 | 0.9477 | 1.0000 | 0.9146 | 0.7025 | 0.9605 | 0.9805 | 312 |
| psp-melodie | baseline-off | 0.9602 | 0.7933 | 1.0000 | 0.9146 | 0.7025 | 0.9602 | 0.8162 | 312 |
| psp-pac-man-rally | default | 0.9074 | 0.9280 | 1.0000 | 0.8889 | 0.7205 | 0.9074 | 0.9573 | 292 |
| psp-pac-man-rally | baseline-off | 0.9066 | 0.7936 | 1.0000 | 0.8889 | 0.7205 | 0.9066 | 0.8150 | 292 |
| psp-psp-camera-01 | default | 0.9597 | 0.9585 | 1.0000 | 0.7918 | 0.4097 | 0.9597 | 0.9909 | 389 |
| psp-psp-camera-01 | baseline-off | 0.9591 | 0.9484 | 1.0000 | 0.7918 | 0.4097 | 0.9591 | 0.9802 | 389 |
| psp-tetris | default | 0.9876 | 0.9671 | 1.0000 | 0.7714 | 0.5811 | 0.9876 | 0.9894 | 362 |
| psp-tetris | baseline-off | 0.9876 | 0.9210 | 1.0000 | 0.7714 | 0.5811 | 0.9876 | 0.9413 | 362 |

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
| recall vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision vs baseline-off | 5 | 5 | 0 | 0 | 0.0312 |
| success_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| arity_accuracy vs baseline-off | 5 | 0 | 0 | 5 | – |
| type_exact_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision_verified vs baseline-off | 5 | 5 | 0 | 0 | 0.0312 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | 1 | default | 0.8884 | 0.9057 | 1.0000 | 0.8300 | 0.3744 | 200 |
| psp-hot-pixel | 1 | baseline-off | 0.8879 | 0.8384 | 0.9950 | 0.8250 | 0.3744 | 200 |
| psp-hot-pixel | 2 | default | 0.8884 | 0.9057 | 0.9950 | 0.8350 | 0.3505 | 200 |
| psp-hot-pixel | 2 | baseline-off | 0.8879 | 0.8384 | 0.9950 | 0.8350 | 0.3557 | 200 |
| psp-melodie | 1 | default | 0.9605 | 0.9477 | 1.0000 | 0.9146 | 0.7025 | 200 |
| psp-melodie | 1 | baseline-off | 0.9602 | 0.7933 | 1.0000 | 0.9146 | 0.7025 | 200 |
| psp-melodie | 2 | default | 0.9605 | 0.9477 | 1.0000 | 0.9146 | 0.7025 | 200 |
| psp-melodie | 2 | baseline-off | 0.9602 | 0.7933 | 1.0000 | 0.9146 | 0.7025 | 200 |
| psp-pac-man-rally | 1 | default | 0.9074 | 0.9280 | 1.0000 | 0.8889 | 0.7205 | 200 |
| psp-pac-man-rally | 1 | baseline-off | 0.9066 | 0.7936 | 1.0000 | 0.8889 | 0.7205 | 200 |
| psp-pac-man-rally | 2 | default | 0.9074 | 0.9280 | 1.0000 | 0.8889 | 0.7205 | 200 |
| psp-pac-man-rally | 2 | baseline-off | 0.9066 | 0.7936 | 1.0000 | 0.8889 | 0.7205 | 200 |
| psp-psp-camera-01 | 1 | default | 0.9597 | 0.9585 | 1.0000 | 0.7800 | 0.4077 | 200 |
| psp-psp-camera-01 | 1 | baseline-off | 0.9591 | 0.9484 | 1.0000 | 0.7800 | 0.4077 | 200 |
| psp-psp-camera-01 | 2 | default | 0.9597 | 0.9585 | 1.0000 | 0.8050 | 0.4115 | 200 |
| psp-psp-camera-01 | 2 | baseline-off | 0.9591 | 0.9484 | 1.0000 | 0.8050 | 0.4115 | 200 |
| psp-tetris | 1 | default | 0.9876 | 0.9671 | 1.0000 | 0.7714 | 0.5811 | 200 |
| psp-tetris | 1 | baseline-off | 0.9876 | 0.9210 | 1.0000 | 0.7714 | 0.5811 | 200 |
| psp-tetris | 2 | default | 0.9876 | 0.9671 | 1.0000 | 0.7714 | 0.5811 | 200 |
| psp-tetris | 2 | baseline-off | 0.9876 | 0.9210 | 1.0000 | 0.7714 | 0.5811 | 200 |


# Console research components (2026-10-12T07:34:43+00:00)

Tools fingerprint `b2368ce6b5673309`; sample n=200 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | psp-hot-pixel | psp-melodie | psp-pac-man-rally | psp-psp-camera-01 | psp-tetris |
|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | psp-hot-pixel | helps | recall +0.1pp~, precision +6.7pp, gotos -302, labels -181, irregular_functions -7, lines +545, type_exact_rate -0.3pp~, recall_verified +0.1pp, precision_verified +7.1pp | no change | recall +0.1pp~, precision +6.7pp, gotos -302, labels -181, irregular_functions -7, lines +545, type_exact_rate -0.3pp~, recall_verified +0.1pp, precision_verified +7.1pp |
| all research (default vs baseline-off) | psp-melodie | helps | recall +0.0pp~, precision +15.4pp, gotos -49, labels -23, irregular_functions -6, lines +88, recall_verified +0.0pp, precision_verified +16.4pp | no change | recall +0.0pp~, precision +15.4pp, gotos -49, labels -23, irregular_functions -6, lines +88, recall_verified +0.0pp, precision_verified +16.4pp |
| all research (default vs baseline-off) | psp-pac-man-rally | helps | recall +0.1pp~, precision +13.4pp, gotos -31, labels -13, irregular_functions -2, lines +73, recall_verified +0.1pp, precision_verified +14.2pp | no change | recall +0.1pp~, precision +13.4pp, gotos -31, labels -13, irregular_functions -2, lines +73, recall_verified +0.1pp, precision_verified +14.2pp |
| all research (default vs baseline-off) | psp-psp-camera-01 | helps | recall +0.1pp~, precision +1.0pp, gotos -49, labels -23, lines +136, recall_verified +0.1pp, precision_verified +1.1pp | no change | recall +0.1pp~, precision +1.0pp, gotos -49, labels -23, lines +136, recall_verified +0.1pp, precision_verified +1.1pp |
| all research (default vs baseline-off) | psp-tetris | helps | precision +4.6pp, gotos -112, labels -65, irregular_functions -6, native_warnings +1~, lines +292, precision_verified +4.8pp | no change | precision +4.6pp, gotos -112, labels -65, irregular_functions -6, native_warnings +1~, lines +292, precision_verified +4.8pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.9974 | 190 | 108 | 295 | 852 | 22895 | 0.8884 | 0.9057 | 0.8295 | 0.3642 | – | – | 0.5500 |
| psp-hot-pixel | baseline-off | 0.9974 | 714 | 406 | 302 | 860 | 26977 | 0.8879 | 0.8384 | 0.8295 | 0.3668 | – | – | 0.5500 |
| psp-melodie | default | 1.0000 | 24 | 12 | 205 | 794 | 15968 | 0.9605 | 0.9477 | 0.9146 | 0.7025 | – | – | 0.1840 |
| psp-melodie | baseline-off | 1.0000 | 73 | 35 | 211 | 794 | 15880 | 0.9602 | 0.7933 | 0.9146 | 0.7025 | – | – | 0.1910 |
| psp-pac-man-rally | default | 1.0000 | 28 | 11 | 164 | 898 | 10050 | 0.9074 | 0.9280 | 0.8889 | 0.7205 | – | – | 1.3140 |
| psp-pac-man-rally | baseline-off | 1.0000 | 59 | 24 | 166 | 898 | 9977 | 0.9066 | 0.7936 | 0.8889 | 0.7205 | – | – | 1.2940 |
| psp-psp-camera-01 | default | 1.0000 | 12 | 6 | 241 | 908 | 14062 | 0.9597 | 0.9585 | 0.7918 | 0.4097 | – | – | 0.3230 |
| psp-psp-camera-01 | baseline-off | 1.0000 | 61 | 29 | 241 | 908 | 13926 | 0.9591 | 0.9484 | 0.7918 | 0.4097 | – | – | 0.3780 |
| psp-tetris | default | 1.0000 | 76 | 25 | 191 | 557 | 18250 | 0.9876 | 0.9671 | 0.7714 | 0.5811 | – | – | 0.4710 |
| psp-tetris | baseline-off | 1.0000 | 188 | 90 | 197 | 556 | 17958 | 0.9876 | 0.9210 | 0.7714 | 0.5811 | – | – | 0.4740 |
