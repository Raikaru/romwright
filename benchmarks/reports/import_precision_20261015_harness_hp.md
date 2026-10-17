# Console research wave (2026-10-15T01:57:42+00:00)

Tools fingerprint `de5bce17d6a06237`; sample n=60 per seed, seeds [1]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 10216 | 9983 | 3 (0) | main | 0 | True | ran |
| psp-hot-pixel-symtab | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 10216 | 9983 | 3 (0) | main | 0 | debug | ran |

## psp

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.8924 | 0.9965 | 1.0000 | 0.9000 | 0.3791 | 0.8899 | 0.9990 | 60 |
| psp-hot-pixel | baseline-off | 0.8916 | 0.9680 | 1.0000 | 0.9000 | 0.3791 | 0.8891 | 0.9696 | 60 |
| psp-hot-pixel | stock Ghidra | 0.5839 | 0.9988 | 1.0000 | 0.9000 | 0.3516 | 0.5763 | 1.0000 | 60 |

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
| recall vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs stock | 1 | 0 | 0 | 1 | – |
| arity_accuracy vs stock | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| recall_verified vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs stock | 1 | 0 | 0 | 1 | – |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| arity_accuracy vs baseline-off | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| recall vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs stock | 1 | 0 | 0 | 1 | – |
| arity_accuracy vs stock | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| recall_verified vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs stock | 1 | 0 | 0 | 1 | – |

## Supplement: symtab variants

The staged ELF with its symbol table kept and only DWARF removed (`<id>-symtab`). It isolates type/arity recovery from discovery: its discovery numbers are the symtab's and say nothing about discovery. Not in the per-platform tables or the sign tests.

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel-symtab | default | 1.0000 | 0.9975 | 1.0000 | 0.8167 | 0.3547 | 1.0000 | 0.9999 | 60 |
| psp-hot-pixel-symtab | baseline-off | 1.0000 | 0.9874 | 1.0000 | 0.8167 | 0.3547 | 1.0000 | 0.9896 | 60 |
| psp-hot-pixel-symtab | stock Ghidra | 1.0000 | 0.9991 | 1.0000 | 0.8167 | 0.3218 | 1.0000 | 1.0000 | 60 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.


# Console research components (2026-10-15T01:57:42+00:00)

Tools fingerprint `de5bce17d6a06237`; sample n=60 seeds=[1]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | psp-hot-pixel | psp-hot-pixel-symtab |
|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | psp-hot-pixel | helps | recall +0.1pp~, precision +2.9pp, gotos -59, labels -34, irregular_functions -1, lines +112, recall_verified +0.1pp, precision_verified +2.9pp | no change | recall +0.1pp~, precision +2.9pp, gotos -59, labels -34, irregular_functions -1, lines +112, recall_verified +0.1pp, precision_verified +2.9pp |
| all research (default vs baseline-off) | psp-hot-pixel-symtab | helps | precision +1.0pp, gotos -26, labels -19, irregular_functions -1, lines +44, precision_verified +1.0pp | no change | precision +1.0pp, gotos -26, labels -19, irregular_functions -1, lines +44, precision_verified +1.0pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 1.0000 | 70 | 31 | 50 | 153 | 5054 | 0.8924 | 0.9965 | 0.9000 | 0.3791 | – | – | 0.8630 |
| psp-hot-pixel | baseline-off | 1.0000 | 129 | 65 | 51 | 153 | 4942 | 0.8916 | 0.9680 | 0.9000 | 0.3791 | – | – | 0.8490 |
| psp-hot-pixel-symtab | default | 1.0000 | 28 | 14 | 44 | 160 | 3484 | 1.0000 | 0.9975 | 0.8167 | 0.3547 | – | – | 0.7440 |
| psp-hot-pixel-symtab | baseline-off | 1.0000 | 54 | 33 | 45 | 160 | 3440 | 1.0000 | 0.9874 | 0.8167 | 0.3547 | – | – | 0.7360 |
