# Console research wave (2026-10-15T01:28:41+00:00)

Tools fingerprint `02fd4917ccfce59f`; sample n=60 per seed, seeds [1]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 10216 | 9983 | 3 (0) | main | 0 | True | ran |
| psp-hot-pixel-symtab | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 10216 | 9983 | 3 (0) |  |  |  | error: import failed: thread 'main' (2348971) panicked at crates/romwright-core/src/native.rs:1171:54:
attempt to add with over |
| psp-melodie | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3341 | 3242 | 0 (0) | main | 0 | True | ran |
| psp-melodie-symtab | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3341 | 3242 | 0 (0) | main | 0 | debug | ran |
| psp-pac-man-rally | Pac-Man Rally | Europe, Beta 2007-05-01 | True | dwarf | GNU C 4.0.3+allegrex-2.2.3-psp-2.4.1.internal -g (DW_AT_producer); also an 'SN Systems 1.1.07' string | 100.0 | 6579 | 6379 | 0 (0) | main | 0 | True | ran |
| psp-pac-man-rally-symtab | Pac-Man Rally | Europe, Beta 2007-05-01 | True | dwarf | GNU C 4.0.3+allegrex-2.2.3-psp-2.4.1.internal -g (DW_AT_producer); also an 'SN Systems 1.1.07' string | 100.0 | 6579 | 6379 | 0 (0) | main | 0 | debug | ran |
| psp-psp-camera-01 | PSP Camera 01 | Japan | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug (10.5 MB) | 100.0 | 6722 | 6516 | 0 (0) | main | 0 | True | ran |
| psp-psp-camera-01-symtab | PSP Camera 01 | Japan | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug (10.5 MB) | 100.0 | 6722 | 6516 | 0 (0) | main | 0 | debug | ran |
| psp-tetris | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8700 | 8513 | 0 (0) | main | 0 | True | ran |
| psp-tetris-symtab | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8700 | 8513 | 0 (0) | main | 0 | debug | ran |

## psp

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.8924 | 0.9965 | 1.0000 | 0.9000 | 0.3791 | 0.8899 | 0.9990 | 60 |
| psp-hot-pixel | baseline-off | 0.8916 | 0.9680 | 1.0000 | 0.9000 | 0.3791 | 0.8891 | 0.9696 | 60 |
| psp-hot-pixel | stock Ghidra | 0.5839 | 0.9988 | 1.0000 | 0.9000 | 0.3516 | 0.5763 | 1.0000 | 60 |
| psp-melodie | default | 0.9620 | 0.9917 | 1.0000 | 0.9000 | 0.6648 | 0.9608 | 0.9949 | 60 |
| psp-melodie | baseline-off | 0.9620 | 0.9886 | 1.0000 | 0.9000 | 0.6648 | 0.9608 | 0.9917 | 60 |
| psp-melodie | stock Ghidra | 0.5145 | 0.9971 | 1.0000 | 0.9000 | 0.6264 | 0.5126 | 0.9982 | 60 |
| psp-pac-man-rally | default | 0.9077 | 0.9967 | 1.0000 | 0.8500 | 0.7126 | 0.9067 | 0.9971 | 60 |
| psp-pac-man-rally | baseline-off | 0.9077 | 0.9712 | 1.0000 | 0.8500 | 0.7126 | 0.9067 | 0.9708 | 60 |
| psp-pac-man-rally | stock Ghidra | 0.3127 | 0.9976 | 1.0000 | 0.8333 | 0.6337 | 0.3099 | 0.9980 | 60 |
| psp-psp-camera-01 | default | 0.9606 | 0.9935 | 1.0000 | 0.8333 | 0.4157 | 0.9594 | 0.9944 | 60 |
| psp-psp-camera-01 | baseline-off | 0.9599 | 0.9926 | 1.0000 | 0.8333 | 0.4157 | 0.9586 | 0.9935 | 60 |
| psp-psp-camera-01 | stock Ghidra | 0.6486 | 0.9979 | 1.0000 | 0.8500 | 0.3626 | 0.6421 | 0.9978 | 60 |
| psp-tetris | default | 0.9879 | 0.9939 | 1.0000 | 0.7714 | 0.5811 | 0.9876 | 0.9938 | 60 |
| psp-tetris | baseline-off | 0.9879 | 0.9711 | 1.0000 | 0.7714 | 0.5811 | 0.9876 | 0.9706 | 60 |
| psp-tetris | stock Ghidra | 0.5183 | 1.0000 | 1.0000 | 0.8000 | 0.4868 | 0.5079 | 1.0000 | 60 |
| psp-hot-pixel-symtab | **did not run** | – | – | – | – | – | – | – | error: import failed: thread 'main' (2348971) panicked at crates/romwright-core/src/native.rs:1171:54:
attempt to add with overflow
note: run with `RUST_BACKTRA |

**Sign tests, psp**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision vs baseline-off | 5 | 3 | 0 | 2 | 0.1250 |
| success_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| arity_accuracy vs baseline-off | 5 | 0 | 0 | 5 | – |
| type_exact_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision_verified vs baseline-off | 5 | 3 | 0 | 2 | 0.1250 |
| recall vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision vs stock | 5 | 0 | 2 | 3 | 1.0000 |
| arity_accuracy vs stock | 5 | 1 | 2 | 2 | 0.8750 |
| type_exact_rate vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| recall_verified vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision_verified vs stock | 5 | 0 | 1 | 4 | 1.0000 |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision vs baseline-off | 5 | 3 | 0 | 2 | 0.1250 |
| success_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| arity_accuracy vs baseline-off | 5 | 0 | 0 | 5 | – |
| type_exact_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision_verified vs baseline-off | 5 | 3 | 0 | 2 | 0.1250 |
| recall vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision vs stock | 5 | 0 | 2 | 3 | 1.0000 |
| arity_accuracy vs stock | 5 | 1 | 2 | 2 | 0.8750 |
| type_exact_rate vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| recall_verified vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision_verified vs stock | 5 | 0 | 1 | 4 | 1.0000 |

## Supplement: symtab variants

The staged ELF with its symbol table kept and only DWARF removed (`<id>-symtab`). It isolates type/arity recovery from discovery: its discovery numbers are the symtab's and say nothing about discovery. Not in the per-platform tables or the sign tests.

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-melodie-symtab | default | 1.0000 | 0.9940 | 1.0000 | 0.8833 | 0.7176 | 1.0000 | 0.9972 | 60 |
| psp-melodie-symtab | baseline-off | 1.0000 | 0.9917 | 1.0000 | 0.8833 | 0.7176 | 1.0000 | 0.9948 | 60 |
| psp-melodie-symtab | stock Ghidra | 1.0000 | 0.9976 | 1.0000 | 0.9667 | 0.7247 | 1.0000 | 1.0000 | 60 |
| psp-pac-man-rally-symtab | default | 0.9983 | 0.9976 | 1.0000 | 0.9500 | 0.7644 | 1.0000 | 0.9980 | 60 |
| psp-pac-man-rally-symtab | baseline-off | 0.9983 | 0.9893 | 1.0000 | 0.9500 | 0.7644 | 1.0000 | 0.9895 | 60 |
| psp-pac-man-rally-symtab | stock Ghidra | 0.9959 | 0.9997 | 1.0000 | 0.9667 | 0.7257 | 1.0000 | 1.0000 | 60 |
| psp-psp-camera-01-symtab | default | 1.0000 | 0.9984 | 1.0000 | 0.0667 | 0.0402 | 1.0000 | 0.9994 | 60 |
| psp-psp-camera-01-symtab | baseline-off | 1.0000 | 0.9978 | 1.0000 | 0.0667 | 0.0402 | 1.0000 | 0.9988 | 60 |
| psp-psp-camera-01-symtab | stock Ghidra | 0.9988 | 0.9978 | 1.0000 | 0.8333 | 0.4023 | 1.0000 | 0.9986 | 60 |
| psp-tetris-symtab | default | 1.0000 | 0.9996 | 1.0000 | 0.0286 | 0.0132 | 1.0000 | 0.9998 | 60 |
| psp-tetris-symtab | baseline-off | 1.0000 | 0.9996 | 1.0000 | 0.0286 | 0.0132 | 1.0000 | 0.9998 | 60 |
| psp-tetris-symtab | stock Ghidra | 1.0000 | 1.0000 | 1.0000 | 0.8000 | 0.4868 | 1.0000 | 1.0000 | 60 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.


# Console research components (2026-10-15T01:28:41+00:00)

Tools fingerprint `02fd4917ccfce59f`; sample n=60 seeds=[1]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | psp-hot-pixel | psp-melodie | psp-melodie-symtab | psp-pac-man-rally | psp-pac-man-rally-symtab | psp-psp-camera-01 | psp-psp-camera-01-symtab | psp-tetris | psp-tetris-symtab |
|---|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | neutral | neutral | helps | helps | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | psp-hot-pixel | helps | recall +0.1pp~, precision +2.9pp, gotos -59, labels -34, irregular_functions -1, lines +112, recall_verified +0.1pp, precision_verified +2.9pp | no change | recall +0.1pp~, precision +2.9pp, gotos -59, labels -34, irregular_functions -1, lines +112, recall_verified +0.1pp, precision_verified +2.9pp |
| all research (default vs baseline-off) | psp-melodie | neutral | precision +0.3pp~, lines +10, precision_verified +0.3pp | no change | precision +0.3pp~, lines +10, precision_verified +0.3pp |
| all research (default vs baseline-off) | psp-melodie-symtab | neutral | precision +0.2pp~, lines +8, precision_verified +0.2pp | no change | precision +0.2pp~, lines +8, precision_verified +0.2pp |
| all research (default vs baseline-off) | psp-pac-man-rally | helps | precision +2.5pp, lines +16, precision_verified +2.6pp | no change | precision +2.5pp, lines +16, precision_verified +2.6pp |
| all research (default vs baseline-off) | psp-pac-man-rally-symtab | helps | precision +0.8pp, lines +8, precision_verified +0.9pp | no change | precision +0.8pp, lines +8, precision_verified +0.9pp |
| all research (default vs baseline-off) | psp-psp-camera-01 | helps | recall +0.1pp~, precision +0.1pp~, gotos -5, labels -2, lines +21, recall_verified +0.1pp, precision_verified +0.1pp | no change | recall +0.1pp~, precision +0.1pp~, gotos -5, labels -2, lines +21, recall_verified +0.1pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | psp-psp-camera-01-symtab | helps | precision +0.1pp~, gotos -9, labels -6, irregular_functions -2, lines +5, precision_verified +0.1pp | no change | precision +0.1pp~, gotos -9, labels -6, irregular_functions -2, lines +5, precision_verified +0.1pp |
| all research (default vs baseline-off) | psp-tetris | helps | precision +2.3pp, gotos -5, labels -2, irregular_functions -1, lines +23, precision_verified +2.3pp | no change | precision +2.3pp, gotos -5, labels -2, irregular_functions -1, lines +23, precision_verified +2.3pp |
| all research (default vs baseline-off) | psp-tetris-symtab | helps | gotos -7, labels -4, irregular_functions -1, lines +16 | no change | gotos -7, labels -4, irregular_functions -1, lines +16 |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 1.0000 | 70 | 31 | 50 | 153 | 5054 | 0.8924 | 0.9965 | 0.9000 | 0.3791 | – | – | 1.2800 |
| psp-hot-pixel | baseline-off | 1.0000 | 129 | 65 | 51 | 153 | 4942 | 0.8916 | 0.9680 | 0.9000 | 0.3791 | – | – | 1.4320 |
| psp-melodie | default | 1.0000 | 0 | 0 | 32 | 238 | 3181 | 0.9620 | 0.9917 | 0.9000 | 0.6648 | – | – | 0.6070 |
| psp-melodie | baseline-off | 1.0000 | 0 | 0 | 32 | 238 | 3171 | 0.9620 | 0.9886 | 0.9000 | 0.6648 | – | – | 0.5140 |
| psp-melodie-symtab | default | 1.0000 | 0 | 0 | 31 | 258 | 2595 | 1.0000 | 0.9940 | 0.8833 | 0.7176 | – | – | 0.5790 |
| psp-melodie-symtab | baseline-off | 1.0000 | 0 | 0 | 31 | 258 | 2587 | 1.0000 | 0.9917 | 0.8833 | 0.7176 | – | – | 0.5480 |
| psp-pac-man-rally | default | 1.0000 | 2 | 1 | 42 | 336 | 1751 | 0.9077 | 0.9967 | 0.8500 | 0.7126 | – | – | 2.0340 |
| psp-pac-man-rally | baseline-off | 1.0000 | 2 | 1 | 42 | 336 | 1735 | 0.9077 | 0.9712 | 0.8500 | 0.7126 | – | – | 1.8770 |
| psp-pac-man-rally-symtab | default | 1.0000 | 0 | 0 | 46 | 426 | 2332 | 0.9983 | 0.9976 | 0.9500 | 0.7644 | – | – | 1.9660 |
| psp-pac-man-rally-symtab | baseline-off | 1.0000 | 0 | 0 | 46 | 426 | 2324 | 0.9983 | 0.9893 | 0.9500 | 0.7644 | – | – | 1.8140 |
| psp-psp-camera-01 | default | 1.0000 | 2 | 1 | 38 | 142 | 2778 | 0.9606 | 0.9935 | 0.8333 | 0.4157 | – | – | 1.1490 |
| psp-psp-camera-01 | baseline-off | 1.0000 | 7 | 3 | 38 | 142 | 2757 | 0.9599 | 0.9926 | 0.8333 | 0.4157 | – | – | 1.1330 |
| psp-psp-camera-01-symtab | default | 1.0000 | 0 | 0 | 38 | 123 | 2097 | 1.0000 | 0.9984 | 0.0667 | 0.0402 | – | – | 1.1550 |
| psp-psp-camera-01-symtab | baseline-off | 1.0000 | 9 | 6 | 40 | 123 | 2092 | 1.0000 | 0.9978 | 0.0667 | 0.0402 | – | – | 1.0950 |
| psp-tetris | default | 1.0000 | 9 | 6 | 33 | 102 | 2174 | 0.9879 | 0.9939 | 0.7714 | 0.5811 | – | – | 0.7920 |
| psp-tetris | baseline-off | 1.0000 | 14 | 8 | 34 | 102 | 2151 | 0.9879 | 0.9711 | 0.7714 | 0.5811 | – | – | 0.7180 |
| psp-tetris-symtab | default | 1.0000 | 3 | 2 | 29 | 96 | 2165 | 1.0000 | 0.9996 | 0.0286 | 0.0132 | – | – | 0.7680 |
| psp-tetris-symtab | baseline-off | 1.0000 | 10 | 6 | 30 | 96 | 2149 | 1.0000 | 0.9996 | 0.0286 | 0.0132 | – | – | 0.8040 |
