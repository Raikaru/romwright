# Console research wave (2026-10-12T23:35:57+00:00)

Tools fingerprint `2bcde8b0d87bc254`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | Kingdom Hearts: Chain of Memories | USA (B8CE) | True | decomp-build | agbcc (pret/agbcc, -O2) + binutils 2.10 legacy assembler; libgcc/libc members prebuilt | 100.0 | 5257 | 5137 | 0 (0) | main | 0 | False | ran |
| nds-kh-358-2-days | Kingdom Hearts 358/2 Days | EU (YKGP) | True | decomp-symbols | mwccarm 3.0 build 139 (a few precompiled-middleware units with an older mwccarm per config/arm9/file_compilers.json), mwldarm | 100.0 | 23233 | 23233 | 0 (0) | main, ov0, ov1, ov2 (+293) | 0 | False | ran |

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

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 2 | 2 | 0 | 0 | 0.2500 |
| precision vs baseline-off | 2 | 0 | 0 | 2 | – |
| success_rate vs baseline-off | 2 | 2 | 0 | 0 | 0.2500 |
| recall_verified vs baseline-off | 2 | 2 | 0 | 0 | 0.2500 |
| precision_verified vs baseline-off | 2 | 0 | 0 | 2 | – |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | 1 | default | 0.9582 | 0.9640 | 1.0000 | – | – | 500 |
| gba-kh-chain-of-memories | 1 | baseline-off | 0.9426 | 0.9634 | 0.9760 | – | – | 500 |
| gba-kh-chain-of-memories | 2 | default | 0.9582 | 0.9640 | 1.0000 | – | – | 500 |
| gba-kh-chain-of-memories | 2 | baseline-off | 0.9426 | 0.9634 | 0.9800 | – | – | 500 |
| nds-kh-358-2-days | 1 | default | 0.8863 | 0.9922 | 1.0000 | – | – | 500 |
| nds-kh-358-2-days | 1 | baseline-off | 0.8758 | 0.9921 | 0.9940 | – | – | 500 |
| nds-kh-358-2-days | 2 | default | 0.8863 | 0.9922 | 1.0000 | – | – | 500 |
| nds-kh-358-2-days | 2 | baseline-off | 0.8758 | 0.9921 | 0.9840 | – | – | 500 |


# Console research components (2026-10-12T23:35:57+00:00)

Tools fingerprint `2bcde8b0d87bc254`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-kh-chain-of-memories | nds-kh-358-2-days |
|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-kh-chain-of-memories | helps | recall +1.6pp, precision +0.1pp~, success_rate +2.3pp, gotos -571, labels -270, irregular_functions -3~, native_warnings +2~, lines +1101, recall_verified +1.6pp, precision_verified +0.0pp | no change | recall +1.6pp, precision +0.1pp~, success_rate +2.3pp, gotos -571, labels -270, irregular_functions -3~, native_warnings +2~, lines +1101, recall_verified +1.6pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | nds-kh-358-2-days | helps | recall +1.1pp, precision +0.0pp~, success_rate +1.1pp, gotos -50, labels -27, irregular_functions -1~, native_warnings +1~, lines +207, recall_verified +1.1pp, precision_verified -0.0pp | no change | recall +1.1pp, precision +0.0pp~, success_rate +1.1pp, gotos -50, labels -27, irregular_functions -1~, native_warnings +1~, lines +207, recall_verified +1.1pp, precision_verified -0.0pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | default | 1.0000 | 68 | 36 | 837 | 3124 | 41947 | 0.9582 | 0.9640 | – | – | – | – | 2.2800 |
| gba-kh-chain-of-memories | baseline-off | 0.9771 | 639 | 306 | 832 | 3090 | 40401 | 0.9426 | 0.9634 | – | – | – | – | 2.3490 |
| nds-kh-358-2-days | default | 1.0000 | 24 | 10 | 865 | 2673 | 44697 | 0.8863 | 0.9922 | – | – | – | – | 4.3400 |
| nds-kh-358-2-days | baseline-off | 0.9889 | 74 | 37 | 863 | 2666 | 43941 | 0.8758 | 0.9921 | – | – | – | – | 3.5720 |
