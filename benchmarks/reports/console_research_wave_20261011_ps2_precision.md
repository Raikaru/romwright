# Console research wave (2026-10-12T01:19:30+00:00)

Tools fingerprint `8089735f6fb1f18e`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | Dark Chronicle (Dark Cloud 2) | PAL SCES-51190 (En,Fr,De,Es,It) | True | decomp-symbols | MWCC PS2 3.0 (CodeWarrior for PS2, via Satans Fiddle/wibo; repo config compiler: MWCCPS2) | 88.18 | 7837 | 7714 | 0 (0) | main | 0 | True | ran |
| ps2-dark-chronicle-symtab | Dark Chronicle (Dark Cloud 2) | PAL SCES-51190 (En,Fr,De,Es,It) | True | decomp-symbols | MWCC PS2 3.0 (CodeWarrior for PS2, via Satans Fiddle/wibo; repo config compiler: MWCCPS2) | 88.18 | 7837 | 7714 | 0 (0) | main | 0 | debug | ran |
| ps2-dark-cloud | Dark Cloud | USA NTSC SCUS-97111 (v1.02 per repo) | True | decomp-symbols | MWCC PS2 2.3.3 (Metrowerks CodeWarrior for PS2; repo config compiler: MWCCPS2) | 100.0 | 4181 | 4181 | 0 (0) | main, title, dun | 0 | True | ran |
| ps2-dark-cloud-symtab | Dark Cloud | USA NTSC SCUS-97111 (v1.02 per repo) | True | decomp-symbols | MWCC PS2 2.3.3 (Metrowerks CodeWarrior for PS2; repo config compiler: MWCCPS2) | 100.0 | 4181 | 4181 | 0 (0) | main, title, dun | 0 | debug | ran |
| ps2-digital-devil-saga | Shin Megami Tensei: Digital Devil Saga | USA SLUS-20974 | True | decomp-symbols | EE GCC 2.96 (ee-gcc; ee-as 2.9-ee; repo config compiler EEGCC) | 76.02 | 10352 | 9864 | 0 (0) | main | 0 | False | ran |
| ps2-fatal-frame | Fatal Frame (Project Zero) | USA NTSC-U SLUS-20388 | True | decomp-symbols | EE GCC 2.9-991111 (ee-gcc, repo config compiler EEGCC; platform ps2) | 69.84 | 4250 | 3437 | 0 (0) | main | 0 | True | ran |
| ps2-fatal-frame-symtab | Fatal Frame (Project Zero) | USA NTSC-U SLUS-20388 | True | decomp-symbols | EE GCC 2.9-991111 (ee-gcc, repo config compiler EEGCC; platform ps2) | 69.84 | 4250 | 3437 | 0 (0) | main | 0 | debug | ran |
| ps2-god-hand | God Hand | USA NTSC-U SLUS-21503 (disc 1.00) | True | decomp-symbols | SN ProDG ee-gcc 2.95.3 (matched TUs) + EE GCC 2.96 (dvp-as, ee-ld); SN small-data (.sndata) | 43.53 | 11233 | 7946 | 0 (0) | main | 0 | False | ran |
| ps2-persona-4 | Shin Megami Tensei: Persona 4 | USA SLUS-21782 v1.00 | True | decomp-symbols | MWCC PS2 3.0.1 build 210 (-O2) for Atlus code; MWCC build 119 (-O4,p -inline auto) for RenderWare; EE GCC 2.96 (-O2 -G0) for configured CRI/other units | 72.65 | 13102 | 9857 | 0 (0) | main | 0 | False | ran |
| ps2-ratchet-clank | Ratchet & Clank | USA NTSC-U SCUS-97199 | True | decomp-symbols | EE GCC 2.95.2 (ee-gcc, repo config compiler EEGCC; some units use an optional patched EE-GCC profile) | 68.41 | 1823 | 1643 | 0 (0) | main | 0 | False | ran |
| ps2-ratchet-clank-pal | Ratchet & Clank | PAL SCES-50916 v2.00 (En,Fr,De,Es,It) | True | decomp-symbols | SN ProDG 3.01 (ee-gcc 2.95-based) for game code; SCE SDK 2.4 objects (ee29) for SDK code | 61.22 | 1822 | 1605 | 0 (0) | main | 0 | False | ran |

## ps2

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | default | 0.9987 | 0.9963 | 0.0000 | – | – | 0.9987 | 0.9996 | 969 |
| ps2-dark-chronicle | baseline-off | 0.9987 | 0.9962 | 0.0000 | – | – | 0.9987 | 0.9995 | 969 |
| ps2-dark-chronicle | stock Ghidra | 0.9288 | 0.9982 | 1.0000 | – | – | 0.9278 | 0.9997 | 969 |
| ps2-dark-cloud | default | 0.9988 | 0.9907 | 0.0000 | – | – | 0.9988 | 0.9990 | 937 |
| ps2-dark-cloud | baseline-off | 0.9988 | 0.9907 | 0.0000 | – | – | 0.9988 | 0.9990 | 937 |
| ps2-dark-cloud | stock Ghidra | 0.9173 | 0.9850 | 1.0000 | – | – | 0.9173 | 0.9856 | 890 |
| ps2-dark-cloud | default (main module only) | 0.9992 | 0.9907 | 0.0000 | – | – | 0.9992 | 0.9990 | 937 |
| ps2-digital-devil-saga | default | 0.9974 | 0.9987 | 0.0000 | – | – | 0.9976 | 0.9993 | 977 |
| ps2-digital-devil-saga | baseline-off | 0.9973 | 0.9762 | 0.0000 | – | – | 0.9975 | 0.9811 | 977 |
| ps2-digital-devil-saga | stock Ghidra | 0.8630 | 1.0000 | 1.0000 | – | – | 0.8585 | 1.0000 | 977 |
| ps2-fatal-frame | default | 0.9958 | 0.9993 | 0.0000 | – | – | 0.9959 | 0.9997 | 942 |
| ps2-fatal-frame | baseline-off | 0.9958 | 0.9927 | 0.0000 | – | – | 0.9959 | 0.9945 | 942 |
| ps2-fatal-frame | stock Ghidra | 0.8334 | 1.0000 | 1.0000 | – | – | 0.8484 | 1.0000 | 942 |
| ps2-god-hand | default | 0.9976 | 0.9943 | 0.0000 | – | – | 0.9980 | 1.0000 | 980 |
| ps2-god-hand | baseline-off | 0.9976 | 0.8815 | 0.0000 | – | – | 0.9980 | 0.9176 | 980 |
| ps2-god-hand | stock Ghidra | 0.8552 | 0.9988 | 1.0000 | – | – | 0.8919 | 1.0000 | 980 |
| ps2-persona-4 | default | 0.9992 | 0.9967 | 0.0000 | – | – | 0.9993 | 0.9990 | 975 |
| ps2-persona-4 | baseline-off | 0.9992 | 0.9961 | 0.0000 | – | – | 0.9993 | 0.9983 | 975 |
| ps2-persona-4 | stock Ghidra | 0.9028 | 0.9997 | 1.0000 | – | – | 0.8991 | 0.9997 | 975 |
| ps2-ratchet-clank | default | 0.9281 | 0.9965 | 0.0000 | – | – | 0.9245 | 0.9993 | 861 |
| ps2-ratchet-clank | baseline-off | 0.9281 | 0.9953 | 0.0000 | – | – | 0.9245 | 0.9980 | 861 |
| ps2-ratchet-clank | stock Ghidra | 0.7175 | 1.0000 | 0.9988 | – | – | 0.7961 | 1.0000 | 861 |
| ps2-ratchet-clank-pal | default | 0.9276 | 0.9947 | 0.0000 | – | – | 0.9184 | 0.9986 | 859 |
| ps2-ratchet-clank-pal | baseline-off | 0.9276 | 0.9935 | 0.0000 | – | – | 0.9184 | 0.9973 | 859 |
| ps2-ratchet-clank-pal | stock Ghidra | 0.7184 | 1.0000 | 0.9988 | – | – | 0.6960 | 1.0000 | 859 |

**Sign tests, ps2**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| success_rate vs baseline-off | 8 | 0 | 0 | 8 | – |
| recall_verified vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision_verified vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| recall vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision vs stock | 8 | 1 | 1 | 6 | 0.7500 |
| recall_verified vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision_verified vs stock | 8 | 1 | 0 | 7 | 0.5000 |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| success_rate vs baseline-off | 8 | 0 | 0 | 8 | – |
| recall_verified vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision_verified vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| recall vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision vs stock | 8 | 1 | 1 | 6 | 0.7500 |
| recall_verified vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision_verified vs stock | 8 | 1 | 0 | 7 | 0.5000 |

## Supplement: symtab variants

The staged ELF with its symbol table kept and only DWARF removed (`<id>-symtab`). It isolates type/arity recovery from discovery: its discovery numbers are the symtab's and say nothing about discovery. Not in the per-platform tables or the sign tests.

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle-symtab | default | 1.0000 | 0.9973 | 0.0000 | – | – | 1.0000 | 0.9997 | 962 |
| ps2-dark-chronicle-symtab | baseline-off | 1.0000 | 0.9972 | 0.0000 | – | – | 1.0000 | 0.9996 | 962 |
| ps2-dark-chronicle-symtab | stock Ghidra | 1.0000 | 0.9995 | 1.0000 | – | – | 1.0000 | 0.9997 | 962 |
| ps2-dark-cloud-symtab | default | 0.9995 | 0.9448 | 0.0000 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-dark-cloud-symtab | baseline-off | 0.9995 | 0.9448 | 0.0000 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-dark-cloud-symtab | stock Ghidra | 1.0000 | 0.9267 | 1.0000 | – | – | 1.0000 | 0.9818 | 884 |
| ps2-fatal-frame-symtab | default | 1.0000 | 0.9998 | 0.0000 | – | – | 1.0000 | 1.0000 | 940 |
| ps2-fatal-frame-symtab | baseline-off | 1.0000 | 0.9984 | 0.0000 | – | – | 1.0000 | 0.9983 | 940 |
| ps2-fatal-frame-symtab | stock Ghidra | 1.0000 | 1.0000 | 1.0000 | – | – | 1.0000 | 1.0000 | 940 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | 1 | default | 0.9987 | 0.9963 | 0.0000 | – | – | 500 |
| ps2-dark-chronicle | 1 | baseline-off | 0.9987 | 0.9962 | 0.0000 | – | – | 500 |
| ps2-dark-chronicle | 2 | default | 0.9987 | 0.9963 | 0.0000 | – | – | 500 |
| ps2-dark-chronicle | 2 | baseline-off | 0.9987 | 0.9962 | 0.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 1 | default | 1.0000 | 0.9973 | 0.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 1 | baseline-off | 1.0000 | 0.9972 | 0.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 2 | default | 1.0000 | 0.9973 | 0.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 2 | baseline-off | 1.0000 | 0.9972 | 0.0000 | – | – | 500 |
| ps2-dark-cloud | 1 | default | 0.9988 | 0.9907 | 0.0000 | – | – | 500 |
| ps2-dark-cloud | 1 | baseline-off | 0.9988 | 0.9907 | 0.0000 | – | – | 500 |
| ps2-dark-cloud | 2 | default | 0.9988 | 0.9907 | 0.0000 | – | – | 500 |
| ps2-dark-cloud | 2 | baseline-off | 0.9988 | 0.9907 | 0.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | default | 0.9995 | 0.9448 | 0.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | baseline-off | 0.9995 | 0.9448 | 0.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | default | 0.9995 | 0.9448 | 0.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | baseline-off | 0.9995 | 0.9448 | 0.0000 | – | – | 500 |
| ps2-digital-devil-saga | 1 | default | 0.9974 | 0.9987 | 0.0000 | – | – | 500 |
| ps2-digital-devil-saga | 1 | baseline-off | 0.9973 | 0.9762 | 0.0000 | – | – | 500 |
| ps2-digital-devil-saga | 2 | default | 0.9974 | 0.9987 | 0.0000 | – | – | 500 |
| ps2-digital-devil-saga | 2 | baseline-off | 0.9973 | 0.9762 | 0.0000 | – | – | 500 |
| ps2-fatal-frame | 1 | default | 0.9958 | 0.9993 | 0.0000 | – | – | 500 |
| ps2-fatal-frame | 1 | baseline-off | 0.9958 | 0.9927 | 0.0000 | – | – | 500 |
| ps2-fatal-frame | 2 | default | 0.9958 | 0.9993 | 0.0000 | – | – | 500 |
| ps2-fatal-frame | 2 | baseline-off | 0.9958 | 0.9927 | 0.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 1 | default | 1.0000 | 0.9998 | 0.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 1 | baseline-off | 1.0000 | 0.9984 | 0.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 2 | default | 1.0000 | 0.9998 | 0.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 2 | baseline-off | 1.0000 | 0.9984 | 0.0000 | – | – | 500 |
| ps2-god-hand | 1 | default | 0.9976 | 0.9943 | 0.0000 | – | – | 500 |
| ps2-god-hand | 1 | baseline-off | 0.9976 | 0.8815 | 0.0000 | – | – | 500 |
| ps2-god-hand | 2 | default | 0.9976 | 0.9943 | 0.0000 | – | – | 500 |
| ps2-god-hand | 2 | baseline-off | 0.9976 | 0.8815 | 0.0000 | – | – | 500 |
| ps2-persona-4 | 1 | default | 0.9992 | 0.9967 | 0.0000 | – | – | 500 |
| ps2-persona-4 | 1 | baseline-off | 0.9992 | 0.9961 | 0.0000 | – | – | 500 |
| ps2-persona-4 | 2 | default | 0.9992 | 0.9967 | 0.0000 | – | – | 500 |
| ps2-persona-4 | 2 | baseline-off | 0.9992 | 0.9961 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank | 1 | default | 0.9281 | 0.9965 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank | 1 | baseline-off | 0.9281 | 0.9953 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank | 2 | default | 0.9281 | 0.9965 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank | 2 | baseline-off | 0.9281 | 0.9953 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 1 | default | 0.9276 | 0.9947 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 1 | baseline-off | 0.9276 | 0.9935 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 2 | default | 0.9276 | 0.9947 | 0.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 2 | baseline-off | 0.9276 | 0.9935 | 0.0000 | – | – | 500 |


# Console research components (2026-10-12T01:19:30+00:00)

Tools fingerprint `8089735f6fb1f18e`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | ps2-dark-chronicle | ps2-dark-chronicle-symtab | ps2-dark-cloud | ps2-dark-cloud-symtab | ps2-digital-devil-saga | ps2-fatal-frame | ps2-fatal-frame-symtab | ps2-god-hand | ps2-persona-4 | ps2-ratchet-clank | ps2-ratchet-clank-pal |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | neutral | neutral | neutral | neutral | helps | helps | neutral | helps | neutral | neutral | neutral |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | ps2-dark-chronicle | neutral | precision +0.0pp~, precision_verified +0.0pp | no change | precision +0.0pp~, precision_verified +0.0pp |
| all research (default vs baseline-off) | ps2-dark-chronicle-symtab | neutral | precision +0.0pp~, precision_verified +0.0pp | no change | precision +0.0pp~, precision_verified +0.0pp |
| all research (default vs baseline-off) | ps2-dark-cloud | neutral | no change | no change | no change |
| all research (default vs baseline-off) | ps2-dark-cloud-symtab | neutral | no change | no change | no change |
| all research (default vs baseline-off) | ps2-digital-devil-saga | helps | recall +0.0pp~, precision +2.2pp, recall_verified +0.0pp, precision_verified +1.8pp | no change | recall +0.0pp~, precision +2.2pp, recall_verified +0.0pp, precision_verified +1.8pp |
| all research (default vs baseline-off) | ps2-fatal-frame | helps | precision +0.7pp, precision_verified +0.5pp | no change | precision +0.7pp, precision_verified +0.5pp |
| all research (default vs baseline-off) | ps2-fatal-frame-symtab | neutral | precision +0.1pp~, precision_verified +0.2pp | no change | precision +0.1pp~, precision_verified +0.2pp |
| all research (default vs baseline-off) | ps2-god-hand | helps | precision +11.3pp, precision_verified +8.2pp | no change | precision +11.3pp, precision_verified +8.2pp |
| all research (default vs baseline-off) | ps2-persona-4 | neutral | precision +0.1pp~, precision_verified +0.1pp | no change | precision +0.1pp~, precision_verified +0.1pp |
| all research (default vs baseline-off) | ps2-ratchet-clank | neutral | precision +0.1pp~, precision_verified +0.1pp | no change | precision +0.1pp~, precision_verified +0.1pp |
| all research (default vs baseline-off) | ps2-ratchet-clank-pal | neutral | precision +0.1pp~, precision_verified +0.1pp | no change | precision +0.1pp~, precision_verified +0.1pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9987 | 0.9963 | – | – | – | – | – |
| ps2-dark-chronicle | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9987 | 0.9962 | – | – | – | – | – |
| ps2-dark-chronicle-symtab | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 1.0000 | 0.9973 | – | – | – | – | – |
| ps2-dark-chronicle-symtab | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 1.0000 | 0.9972 | – | – | – | – | – |
| ps2-dark-cloud | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9988 | 0.9907 | – | – | – | – | – |
| ps2-dark-cloud | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9988 | 0.9907 | – | – | – | – | – |
| ps2-dark-cloud-symtab | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9995 | 0.9448 | – | – | – | – | – |
| ps2-dark-cloud-symtab | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9995 | 0.9448 | – | – | – | – | – |
| ps2-digital-devil-saga | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9974 | 0.9987 | – | – | – | – | – |
| ps2-digital-devil-saga | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9973 | 0.9762 | – | – | – | – | – |
| ps2-fatal-frame | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9958 | 0.9993 | – | – | – | – | – |
| ps2-fatal-frame | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9958 | 0.9927 | – | – | – | – | – |
| ps2-fatal-frame-symtab | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 1.0000 | 0.9998 | – | – | – | – | – |
| ps2-fatal-frame-symtab | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 1.0000 | 0.9984 | – | – | – | – | – |
| ps2-god-hand | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9976 | 0.9943 | – | – | – | – | – |
| ps2-god-hand | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9976 | 0.8815 | – | – | – | – | – |
| ps2-persona-4 | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9992 | 0.9967 | – | – | – | – | – |
| ps2-persona-4 | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9992 | 0.9961 | – | – | – | – | – |
| ps2-ratchet-clank | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9281 | 0.9965 | – | – | – | – | – |
| ps2-ratchet-clank | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9281 | 0.9953 | – | – | – | – | – |
| ps2-ratchet-clank-pal | default | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9276 | 0.9947 | – | – | – | – | – |
| ps2-ratchet-clank-pal | baseline-off | 0.0000 | 0 | 0 | 0 | 0 | 0 | 0.9276 | 0.9935 | – | – | – | – | – |
