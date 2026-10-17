# Console research wave (2026-10-13T07:11:10+00:00)

Tools fingerprint `d1f2cf0f0a648b08`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

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
| ps2-dark-chronicle | default | 0.9987 | 0.9963 | 1.0000 | – | – | 0.9987 | 0.9996 | 969 |
| ps2-dark-chronicle | baseline-off | 0.9987 | 0.9962 | 1.0000 | – | – | 0.9987 | 0.9995 | 969 |
| ps2-dark-cloud | default | 0.9988 | 0.9907 | 0.9989 | – | – | 0.9988 | 0.9990 | 937 |
| ps2-dark-cloud | baseline-off | 0.9988 | 0.9907 | 1.0000 | – | – | 0.9988 | 0.9990 | 937 |
| ps2-digital-devil-saga | default | 0.9974 | 0.9987 | 1.0000 | – | – | 0.9976 | 0.9993 | 977 |
| ps2-digital-devil-saga | baseline-off | 0.9973 | 0.9762 | 1.0000 | – | – | 0.9975 | 0.9811 | 977 |
| ps2-fatal-frame | default | 0.9958 | 0.9993 | 1.0000 | – | – | 0.9959 | 0.9997 | 942 |
| ps2-fatal-frame | baseline-off | 0.9958 | 0.9927 | 1.0000 | – | – | 0.9959 | 0.9945 | 942 |
| ps2-god-hand | default | 0.9976 | 0.9943 | 1.0000 | – | – | 0.9980 | 1.0000 | 980 |
| ps2-god-hand | baseline-off | 0.9976 | 0.8815 | 1.0000 | – | – | 0.9980 | 0.9176 | 980 |
| ps2-persona-4 | default | 0.9992 | 0.9967 | 0.9990 | – | – | 0.9993 | 0.9990 | 975 |
| ps2-persona-4 | baseline-off | 0.9992 | 0.9961 | 1.0000 | – | – | 0.9993 | 0.9983 | 975 |
| ps2-ratchet-clank | default | 0.9281 | 0.9965 | 1.0000 | – | – | 0.9245 | 0.9993 | 861 |
| ps2-ratchet-clank | baseline-off | 0.9281 | 0.9953 | 1.0000 | – | – | 0.9245 | 0.9980 | 861 |
| ps2-ratchet-clank-pal | default | 0.9276 | 0.9947 | 1.0000 | – | – | 0.9184 | 0.9986 | 859 |
| ps2-ratchet-clank-pal | baseline-off | 0.9276 | 0.9935 | 1.0000 | – | – | 0.9184 | 0.9973 | 859 |

**Sign tests, ps2**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| success_rate vs baseline-off | 8 | 0 | 0 | 8 | – |
| recall_verified vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision_verified vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| success_rate vs baseline-off | 8 | 0 | 0 | 8 | – |
| recall_verified vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision_verified vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |

## Supplement: symtab variants

The staged ELF with its symbol table kept and only DWARF removed (`<id>-symtab`). It isolates type/arity recovery from discovery: its discovery numbers are the symtab's and say nothing about discovery. Not in the per-platform tables or the sign tests.

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle-symtab | default | 1.0000 | 0.9973 | 1.0000 | – | – | 1.0000 | 0.9997 | 962 |
| ps2-dark-chronicle-symtab | baseline-off | 1.0000 | 0.9972 | 1.0000 | – | – | 1.0000 | 0.9996 | 962 |
| ps2-dark-cloud-symtab | default | 0.9995 | 0.9448 | 1.0000 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-dark-cloud-symtab | baseline-off | 0.9995 | 0.9448 | 1.0000 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-fatal-frame-symtab | default | 1.0000 | 0.9998 | 1.0000 | – | – | 1.0000 | 1.0000 | 940 |
| ps2-fatal-frame-symtab | baseline-off | 1.0000 | 0.9984 | 1.0000 | – | – | 1.0000 | 0.9983 | 940 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | 1 | default | 0.9987 | 0.9963 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle | 1 | baseline-off | 0.9987 | 0.9962 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle | 2 | default | 0.9987 | 0.9963 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle | 2 | baseline-off | 0.9987 | 0.9962 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 1 | default | 1.0000 | 0.9973 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 1 | baseline-off | 1.0000 | 0.9972 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 2 | default | 1.0000 | 0.9973 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 2 | baseline-off | 1.0000 | 0.9972 | 1.0000 | – | – | 500 |
| ps2-dark-cloud | 1 | default | 0.9988 | 0.9907 | 1.0000 | – | – | 500 |
| ps2-dark-cloud | 1 | baseline-off | 0.9988 | 0.9907 | 1.0000 | – | – | 500 |
| ps2-dark-cloud | 2 | default | 0.9988 | 0.9907 | 0.9980 | – | – | 500 |
| ps2-dark-cloud | 2 | baseline-off | 0.9988 | 0.9907 | 1.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | default | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | baseline-off | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | default | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | baseline-off | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-digital-devil-saga | 1 | default | 0.9974 | 0.9987 | 1.0000 | – | – | 500 |
| ps2-digital-devil-saga | 1 | baseline-off | 0.9973 | 0.9762 | 1.0000 | – | – | 500 |
| ps2-digital-devil-saga | 2 | default | 0.9974 | 0.9987 | 1.0000 | – | – | 500 |
| ps2-digital-devil-saga | 2 | baseline-off | 0.9973 | 0.9762 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 1 | default | 0.9958 | 0.9993 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 1 | baseline-off | 0.9958 | 0.9927 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 2 | default | 0.9958 | 0.9993 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 2 | baseline-off | 0.9958 | 0.9927 | 1.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 1 | default | 1.0000 | 0.9998 | 1.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 1 | baseline-off | 1.0000 | 0.9984 | 1.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 2 | default | 1.0000 | 0.9998 | 1.0000 | – | – | 500 |
| ps2-fatal-frame-symtab | 2 | baseline-off | 1.0000 | 0.9984 | 1.0000 | – | – | 500 |
| ps2-god-hand | 1 | default | 0.9976 | 0.9943 | 1.0000 | – | – | 500 |
| ps2-god-hand | 1 | baseline-off | 0.9976 | 0.8815 | 1.0000 | – | – | 500 |
| ps2-god-hand | 2 | default | 0.9976 | 0.9943 | 1.0000 | – | – | 500 |
| ps2-god-hand | 2 | baseline-off | 0.9976 | 0.8815 | 1.0000 | – | – | 500 |
| ps2-persona-4 | 1 | default | 0.9992 | 0.9967 | 1.0000 | – | – | 500 |
| ps2-persona-4 | 1 | baseline-off | 0.9992 | 0.9961 | 1.0000 | – | – | 500 |
| ps2-persona-4 | 2 | default | 0.9992 | 0.9967 | 0.9980 | – | – | 500 |
| ps2-persona-4 | 2 | baseline-off | 0.9992 | 0.9961 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank | 1 | default | 0.9281 | 0.9965 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank | 1 | baseline-off | 0.9281 | 0.9953 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank | 2 | default | 0.9281 | 0.9965 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank | 2 | baseline-off | 0.9281 | 0.9953 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 1 | default | 0.9276 | 0.9947 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 1 | baseline-off | 0.9276 | 0.9935 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 2 | default | 0.9276 | 0.9947 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 2 | baseline-off | 0.9276 | 0.9935 | 1.0000 | – | – | 500 |


# Console research components (2026-10-13T07:11:10+00:00)

Tools fingerprint `d1f2cf0f0a648b08`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | ps2-dark-chronicle | ps2-dark-chronicle-symtab | ps2-dark-cloud | ps2-dark-cloud-symtab | ps2-digital-devil-saga | ps2-fatal-frame | ps2-fatal-frame-symtab | ps2-god-hand | ps2-persona-4 | ps2-ratchet-clank | ps2-ratchet-clank-pal |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | ps2-dark-chronicle | helps | precision +0.0pp~, gotos -64, labels -30, irregular_functions -4~, native_warnings +3~, text_warnings -2, lines +485, precision_verified +0.0pp | no change | precision +0.0pp~, gotos -64, labels -30, irregular_functions -4~, native_warnings +3~, text_warnings -2, lines +485, precision_verified +0.0pp |
| all research (default vs baseline-off) | ps2-dark-chronicle-symtab | helps | precision +0.0pp~, gotos -89, labels -41, irregular_functions -4~, native_warnings -1~, text_warnings -2, lines +751, precision_verified +0.0pp | no change | precision +0.0pp~, gotos -89, labels -41, irregular_functions -4~, native_warnings -1~, text_warnings -2, lines +751, precision_verified +0.0pp |
| all research (default vs baseline-off) | ps2-dark-cloud | helps | success_rate -0.1pp~, gotos -32, labels -17, irregular_functions -1~, lines +306 | no change | success_rate -0.1pp~, gotos -32, labels -17, irregular_functions -1~, lines +306 |
| all research (default vs baseline-off) | ps2-dark-cloud-symtab | helps | gotos -61, labels -30, irregular_functions -4~, lines +258 | no change | gotos -61, labels -30, irregular_functions -4~, lines +258 |
| all research (default vs baseline-off) | ps2-digital-devil-saga | helps | recall +0.0pp~, precision +2.2pp, gotos -211, labels -97, irregular_functions -9, native_warnings +2~, text_warnings -1, lines +390, recall_verified +0.0pp, precision_verified +1.8pp | no change | recall +0.0pp~, precision +2.2pp, gotos -211, labels -97, irregular_functions -9, native_warnings +2~, text_warnings -1, lines +390, recall_verified +0.0pp, precision_verified +1.8pp |
| all research (default vs baseline-off) | ps2-fatal-frame | helps | precision +0.7pp, gotos -575, labels -267, irregular_functions -14, native_warnings -19~, text_warnings -4~, lines +444, precision_verified +0.5pp | no change | precision +0.7pp, gotos -575, labels -267, irregular_functions -14, native_warnings -19~, text_warnings -4~, lines +444, precision_verified +0.5pp |
| all research (default vs baseline-off) | ps2-fatal-frame-symtab | helps | precision +0.1pp~, gotos -600, labels -296, irregular_functions -17, native_warnings -14~, text_warnings -11, lines +595, precision_verified +0.2pp | no change | precision +0.1pp~, gotos -600, labels -296, irregular_functions -17, native_warnings -14~, text_warnings -11, lines +595, precision_verified +0.2pp |
| all research (default vs baseline-off) | ps2-god-hand | helps | precision +11.3pp, gotos -397, labels -196, irregular_functions -12, native_warnings -1~, text_warnings -1~, lines +706, precision_verified +8.2pp | no change | precision +11.3pp, gotos -397, labels -196, irregular_functions -12, native_warnings -1~, text_warnings -1~, lines +706, precision_verified +8.2pp |
| all research (default vs baseline-off) | ps2-persona-4 | helps | precision +0.1pp~, success_rate -0.1pp~, gotos -135, labels -98, irregular_functions -4~, lines +303, precision_verified +0.1pp | no change | precision +0.1pp~, success_rate -0.1pp~, gotos -135, labels -98, irregular_functions -4~, lines +303, precision_verified +0.1pp |
| all research (default vs baseline-off) | ps2-ratchet-clank | helps | precision +0.1pp~, gotos -300, labels -158, irregular_functions -9, lines +365, precision_verified +0.1pp | no change | precision +0.1pp~, gotos -300, labels -158, irregular_functions -9, lines +365, precision_verified +0.1pp |
| all research (default vs baseline-off) | ps2-ratchet-clank-pal | helps | precision +0.1pp~, gotos -267, labels -147, irregular_functions -10, lines +263, precision_verified +0.1pp | no change | precision +0.1pp~, gotos -267, labels -147, irregular_functions -10, lines +263, precision_verified +0.1pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | default | 1.0000 | 49 | 27 | 610 | 2497 | 44191 | 0.9987 | 0.9963 | – | – | – | – | 0.4320 |
| ps2-dark-chronicle | baseline-off | 1.0000 | 113 | 57 | 614 | 2494 | 43706 | 0.9987 | 0.9962 | – | – | – | – | 0.3500 |
| ps2-dark-chronicle-symtab | default | 1.0000 | 84 | 41 | 596 | 2281 | 47348 | 1.0000 | 0.9973 | – | – | – | – | 0.4320 |
| ps2-dark-chronicle-symtab | baseline-off | 1.0000 | 173 | 82 | 600 | 2282 | 46597 | 1.0000 | 0.9972 | – | – | – | – | 0.6140 |
| ps2-dark-cloud | default | 0.9989 | 48 | 21 | 636 | 2569 | 48345 | 0.9988 | 0.9907 | – | – | – | – | 0.2100 |
| ps2-dark-cloud | baseline-off | 1.0000 | 143 | 40 | 638 | 2698 | 51086 | 0.9988 | 0.9907 | – | – | – | – | 0.1920 |
| ps2-dark-cloud-symtab | default | 1.0000 | 80 | 39 | 599 | 2398 | 53957 | 0.9995 | 0.9448 | – | – | – | – | 0.3110 |
| ps2-dark-cloud-symtab | baseline-off | 1.0000 | 141 | 69 | 603 | 2398 | 53699 | 0.9995 | 0.9448 | – | – | – | – | 0.4720 |
| ps2-digital-devil-saga | default | 1.0000 | 73 | 43 | 626 | 2337 | 37632 | 0.9974 | 0.9987 | – | – | – | – | 0.7030 |
| ps2-digital-devil-saga | baseline-off | 1.0000 | 284 | 140 | 635 | 2335 | 37242 | 0.9973 | 0.9762 | – | – | – | – | 0.4840 |
| ps2-fatal-frame | default | 1.0000 | 247 | 93 | 633 | 2968 | 61386 | 0.9958 | 0.9993 | – | – | – | – | 0.2460 |
| ps2-fatal-frame | baseline-off | 1.0000 | 822 | 360 | 647 | 2987 | 60942 | 0.9958 | 0.9927 | – | – | – | – | 0.2290 |
| ps2-fatal-frame-symtab | default | 1.0000 | 263 | 105 | 592 | 2412 | 60795 | 1.0000 | 0.9998 | – | – | – | – | 0.3460 |
| ps2-fatal-frame-symtab | baseline-off | 1.0000 | 863 | 401 | 609 | 2426 | 60200 | 1.0000 | 0.9984 | – | – | – | – | 0.3380 |
| ps2-god-hand | default | 1.0000 | 186 | 95 | 685 | 2063 | 45366 | 0.9976 | 0.9943 | – | – | – | – | 0.9840 |
| ps2-god-hand | baseline-off | 1.0000 | 583 | 291 | 697 | 2064 | 44660 | 0.9976 | 0.8815 | – | – | – | – | 0.9200 |
| ps2-persona-4 | default | 0.9990 | 101 | 80 | 647 | 1841 | 39173 | 0.9992 | 0.9967 | – | – | – | – | 0.6160 |
| ps2-persona-4 | baseline-off | 1.0000 | 238 | 179 | 652 | 1950 | 42668 | 0.9992 | 0.9961 | – | – | – | – | 0.5540 |
| ps2-ratchet-clank | default | 1.0000 | 226 | 117 | 592 | 3495 | 59866 | 0.9281 | 0.9965 | – | – | – | – | 0.1550 |
| ps2-ratchet-clank | baseline-off | 1.0000 | 526 | 275 | 601 | 3495 | 59501 | 0.9281 | 0.9953 | – | – | – | – | 0.0930 |
| ps2-ratchet-clank-pal | default | 1.0000 | 230 | 97 | 590 | 3492 | 58132 | 0.9276 | 0.9947 | – | – | – | – | 0.0950 |
| ps2-ratchet-clank-pal | baseline-off | 1.0000 | 497 | 244 | 600 | 3492 | 57869 | 0.9276 | 0.9935 | – | – | – | – | 0.0940 |
