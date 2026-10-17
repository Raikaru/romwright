# Console research wave (2026-10-15T01:12:53+00:00)

Tools fingerprint `013b5a2d6181c841`; sample n=60 per seed, seeds [1]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| n64-super-mario-64 | Super Mario 64 | USA (VERSION=us) | True | decomp-build | IDO 5.3 (ido-static-recomp built from tools/ido-static-recomp) | 100.0 | 3813 | 3806 | 0 (0) | main | 284 | False | ran |
| nds-kh-358-2-days | Kingdom Hearts 358/2 Days | EU (YKGP) | True | decomp-symbols | mwccarm 3.0 build 139 (a few precompiled-middleware units with an older mwccarm per config/arm9/file_compilers.json), mwldarm | 100.0 | 23233 | 23233 | 0 (0) | main, ov0, ov1, ov2 (+293) | 0 | False | ran |
| nds-kh-recoded | Kingdom Hearts Re:coded | USA (BK9E) revision 0 | True | decomp-symbols | mwccarm 4.0 build 1036 and 3.0 build 139, mwldarm | 67.83 | 10386 | 9573 | 0 (0) | main, ov0, ov1, ov2 (+102) | 0 | False | ran |
| nds-pokemon-platinum | Pokemon Platinum | USA (CPUE) revision 0 (builds with ROM_REVISION=0; repo default is rev 1) | True | decomp-build | mwccarm 2.0/sp2p2 (meson/cross.ini; mwasmarm/mwldarm via metroskrew 0.1.3; NitroSDK 4.2.30001, NitroSystem, NitroDWC, NitroWiFi built from source subprojects) | None | 34671 | 34669 | 0 (0) | main, ov1, ov4, ov5 (+113) | 0 | False | ran |
| nds-world-ends-with-you | The World Ends With You | USA (AWLE) | True | decomp-symbols | mwccarm 2.0/sp1p5 package (tools/configure.py MWCC_DEFAULT_VERSION; request list gives banner 3.0 build 131), 1.2/sp4 for assembly units, mwldarm | 17.43 | 14413 | 2732 | 0 (0) | main, ov0, ov1, ov2 (+40) | 0 | False | ran |

## n64

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| n64-super-mario-64 | default | 0.9966 | 0.9952 | 1.0000 | – | – | 0.9974 | 0.9952 | 60 |
| n64-super-mario-64 | baseline-off | 0.9966 | 0.9952 | 1.0000 | – | – | 0.9974 | 0.9952 | 60 |
| n64-super-mario-64 | stock Ghidra | 0.9547 | 0.9997 | 1.0000 | – | – | 0.9554 | 0.9997 | 60 |

**Sign tests, n64**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs stock | 1 | 0 | 0 | 1 | – |
| recall_verified vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs stock | 1 | 0 | 0 | 1 | – |

## nds

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| nds-kh-358-2-days | default | 0.8927 | 0.9978 | 1.0000 | – | – | 0.8927 | 0.9993 | 60 |
| nds-kh-358-2-days | baseline-off | 0.8823 | 0.9979 | 1.0000 | – | – | 0.8823 | 0.9994 | 60 |
| nds-kh-358-2-days | stock Ghidra | 0.8388 | 0.9497 | 0.8571 | – | – | 0.8388 | 0.9994 | 7 |
| nds-kh-358-2-days | default (main module only) | 0.9371 | 0.9995 | 1.0000 | – | – | 0.9371 | 0.9995 | 60 |
| nds-kh-recoded | default | 0.7923 | 0.9760 | 1.0000 | – | – | 0.7887 | 0.9992 | 60 |
| nds-kh-recoded | baseline-off | 0.7770 | 0.9761 | 0.9833 | – | – | 0.7730 | 0.9991 | 60 |
| nds-kh-recoded | stock Ghidra | 0.8685 | 0.9682 | 1.0000 | – | – | 0.8879 | 1.0000 | 16 |
| nds-kh-recoded | default (main module only) | 0.9441 | 0.9984 | 1.0000 | – | – | 0.9565 | 1.0000 | 60 |
| nds-pokemon-platinum | default | 0.8888 | 0.9981 | 1.0000 | – | – | 0.8888 | 0.9996 | 60 |
| nds-pokemon-platinum | baseline-off | 0.8481 | 0.9979 | 0.9000 | – | – | 0.8481 | 0.9994 | 60 |
| nds-pokemon-platinum | stock Ghidra | 0.8500 | 0.9939 | 1.0000 | – | – | 0.8499 | 0.9996 | 22 |
| nds-pokemon-platinum | default (main module only) | 0.9766 | 0.9952 | 1.0000 | – | – | 0.9766 | 0.9995 | 60 |
| nds-world-ends-with-you | default | 0.8865 | 0.9993 | 1.0000 | – | – | 0.8540 | 1.0000 | 60 |
| nds-world-ends-with-you | baseline-off | 0.8779 | 0.9991 | 1.0000 | – | – | 0.8525 | 0.9991 | 60 |
| nds-world-ends-with-you | stock Ghidra | 0.9068 | 0.9972 | 1.0000 | – | – | 0.8961 | 1.0000 | 12 |
| nds-world-ends-with-you | default (main module only) | 0.9087 | 0.9972 | 1.0000 | – | – | 0.9028 | 1.0000 | 60 |

**Sign tests, nds**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 4 | 4 | 0 | 0 | 0.0625 |
| precision vs baseline-off | 4 | 0 | 0 | 4 | – |
| success_rate vs baseline-off | 4 | 2 | 0 | 2 | 0.2500 |
| recall_verified vs baseline-off | 4 | 3 | 0 | 1 | 0.1250 |
| precision_verified vs baseline-off | 4 | 0 | 0 | 4 | – |
| recall vs stock | 4 | 3 | 0 | 1 | 0.1250 |
| precision vs stock | 4 | 2 | 0 | 2 | 0.2500 |
| recall_verified vs stock | 4 | 4 | 0 | 0 | 0.0625 |
| precision_verified vs stock | 4 | 0 | 0 | 4 | – |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 4 | 0 | 1 | 0.0625 |
| precision vs baseline-off | 5 | 0 | 0 | 5 | – |
| success_rate vs baseline-off | 5 | 2 | 0 | 3 | 0.2500 |
| recall_verified vs baseline-off | 5 | 3 | 0 | 2 | 0.1250 |
| precision_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall vs stock | 5 | 4 | 0 | 1 | 0.0625 |
| precision vs stock | 5 | 2 | 0 | 3 | 0.2500 |
| recall_verified vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision_verified vs stock | 5 | 0 | 0 | 5 | – |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.


# Console research components (2026-10-15T01:12:53+00:00)

Tools fingerprint `013b5a2d6181c841`; sample n=60 seeds=[1]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | n64-super-mario-64 | nds-kh-358-2-days | nds-kh-recoded | nds-pokemon-platinum | nds-world-ends-with-you |
|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | neutral | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | n64-super-mario-64 | neutral | lines +4 | no change | lines +4 |
| all research (default vs baseline-off) | nds-kh-358-2-days | helps | recall +1.0pp, precision -0.0pp~, gotos -5, labels -2, lines +16, recall_verified +1.0pp, precision_verified -0.0pp | no change | recall +1.0pp, precision -0.0pp~, gotos -5, labels -2, lines +16, recall_verified +1.0pp, precision_verified -0.0pp |
| all research (default vs baseline-off) | nds-kh-recoded | helps | recall +1.5pp, precision -0.0pp~, success_rate +1.7pp, gotos -8, labels -3, lines +11, recall_verified +1.6pp, precision_verified +0.0pp | no change | recall +1.5pp, precision -0.0pp~, success_rate +1.7pp, gotos -8, labels -3, lines +11, recall_verified +1.6pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | nds-pokemon-platinum | helps | recall +4.1pp, precision +0.0pp~, success_rate +10.0pp, gotos -7, labels -2, lines +26, recall_verified +4.1pp, precision_verified +0.0pp | no change | recall +4.1pp, precision +0.0pp~, success_rate +10.0pp, gotos -7, labels -2, lines +26, recall_verified +4.1pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | nds-world-ends-with-you | helps | recall +0.9pp, precision +0.0pp~, gotos -7, labels -3, lines +15, recall_verified +0.1pp, precision_verified +0.1pp | no change | recall +0.9pp, precision +0.0pp~, gotos -7, labels -3, lines +15, recall_verified +0.1pp, precision_verified +0.1pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| n64-super-mario-64 | default | 1.0000 | 0 | 0 | 39 | 117 | 1628 | 0.9966 | 0.9952 | – | – | – | – | 1.2640 |
| n64-super-mario-64 | baseline-off | 1.0000 | 0 | 0 | 39 | 117 | 1624 | 0.9966 | 0.9952 | – | – | – | – | 1.7880 |
| nds-kh-358-2-days | default | 1.0000 | 2 | 1 | 53 | 148 | 2465 | 0.8927 | 0.9978 | – | – | – | – | 6.4870 |
| nds-kh-358-2-days | baseline-off | 1.0000 | 7 | 3 | 53 | 148 | 2449 | 0.8823 | 0.9979 | – | – | – | – | 4.0070 |
| nds-kh-recoded | default | 1.0000 | 2 | 1 | 47 | 168 | 2697 | 0.7923 | 0.9760 | – | – | – | – | 2.1310 |
| nds-kh-recoded | baseline-off | 0.9833 | 10 | 4 | 47 | 168 | 2662 | 0.7770 | 0.9761 | – | – | – | – | 2.0900 |
| nds-pokemon-platinum | default | 1.0000 | 0 | 0 | 51 | 156 | 1566 | 0.8888 | 0.9981 | – | – | – | – | 1.3610 |
| nds-pokemon-platinum | baseline-off | 0.9000 | 7 | 2 | 47 | 147 | 1443 | 0.8481 | 0.9979 | – | – | – | – | 1.4600 |
| nds-world-ends-with-you | default | 1.0000 | 0 | 0 | 51 | 139 | 2202 | 0.8865 | 0.9993 | – | – | – | – | 0.7880 |
| nds-world-ends-with-you | baseline-off | 1.0000 | 7 | 3 | 51 | 139 | 2187 | 0.8779 | 0.9991 | – | – | – | – | 0.7900 |
