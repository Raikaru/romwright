# Console research components (2026-10-09T00:20:08+00:00)

Tools fingerprint `6071cd339255a3d8`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | ps2-capcom-fighting-evolution | psp-puzzle-bobble-pocket | psp-puzzle-bobble-pocket-symtab |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps | mixed | mixed |
| inferred types -> prototypes | inferred-types-off | infer-prototypes | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | ps2-capcom-fighting-evolution | helps | recall -0.2pp~, precision +1.0pp, gotos -8, labels -5, lines +11 | no change | recall -0.2pp~, precision +1.0pp, gotos -8, labels -5, lines +11 |
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket | helps | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +217, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ | no change | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +217, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ |
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket-symtab | helps | recall +0.2pp~, precision +3.9pp, success_rate +0.5pp, gotos -166, labels -92, irregular_functions -8, lines +213, type_exact_rate +0.7pp | no change | recall +0.2pp~, precision +3.9pp, success_rate +0.5pp, gotos -166, labels -92, irregular_functions -8, lines +213, type_exact_rate +0.7pp |
| persisted prototypes (infer_prototypes job) | ps2-capcom-fighting-evolution | helps | irregular_functions -123, native_warnings -485, lines -198, arity_accuracy +0.5pp, type_exact_rate +36.9pp | irregular_functions -123, native_warnings -485, lines -198, arity_accuracy +0.5pp, type_exact_rate +36.9pp | gotos -8, labels -5, irregular_functions -123, native_warnings -485, lines -187, arity_accuracy +0.5pp, type_exact_rate +36.9pp |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket | mixed | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -82, arity_accuracy +0.7pp, type_exact_rate +20.2pp | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -82, arity_accuracy +0.7pp, type_exact_rate +20.2pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -163, text_warnings +2, lines +136, arity_accuracy +1.4pp, type_exact_rate +20.7pp |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket-symtab | mixed | gotos +2, labels +2, irregular_functions -60, native_warnings -36, text_warnings +2, arity_accuracy +0.8pp, type_exact_rate +18.0pp | gotos +2, labels +2, irregular_functions -60, native_warnings -36, text_warnings +2, arity_accuracy +0.8pp, type_exact_rate +18.0pp | success_rate +0.5pp, gotos -164, labels -90, irregular_functions -69, native_warnings -38, text_warnings +2, lines +210, arity_accuracy +0.8pp, type_exact_rate +18.8pp |
| inferred types -> prototypes | ps2-capcom-fighting-evolution | helps | lines +77, type_exact_rate -37.9pp | irregular_functions -123, native_warnings -485, lines -121, arity_accuracy +0.5pp, type_exact_rate -0.9pp | gotos -8, labels -5, irregular_functions -123, native_warnings -485, lines -110, arity_accuracy +0.5pp, type_exact_rate -0.9pp |
| inferred types -> prototypes | psp-puzzle-bobble-pocket | helps | lines -10, type_exact_rate -7.6pp | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -92, arity_accuracy +0.7pp, type_exact_rate +12.6pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -163, text_warnings +2, lines +126, arity_accuracy +1.4pp, type_exact_rate +13.1pp |
| inferred types -> prototypes | psp-puzzle-bobble-pocket-symtab | helps | lines +5, type_exact_rate -8.4pp | gotos +2, labels +2, irregular_functions -60, native_warnings -36, text_warnings +2, lines +5, arity_accuracy +0.8pp, type_exact_rate +9.6pp | success_rate +0.5pp, gotos -164, labels -90, irregular_functions -69, native_warnings -38, text_warnings +2, lines +215, arity_accuracy +0.8pp, type_exact_rate +10.4pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-capcom-fighting-evolution | default | 0.9950 | 2 | 1 | 160 | 545 | 9516 | 0.9414 | 0.9964 | 0.9800 | 0.4988 | – | – | 0.3020 |
| ps2-capcom-fighting-evolution | baseline-off | 0.9950 | 10 | 6 | 160 | 545 | 9505 | 0.9434 | 0.9867 | 0.9800 | 0.4988 | – | – | 0.2840 |
| ps2-capcom-fighting-evolution | infer-prototypes | 0.9950 | 2 | 1 | 37 | 60 | 9318 | – | – | 0.9850 | 0.8682 | – | – | 0.2530 |
| ps2-capcom-fighting-evolution | inferred-types-off | 0.9950 | 2 | 1 | 37 | 60 | 9395 | – | – | 0.9850 | 0.4894 | – | – | 0.3030 |
| psp-puzzle-bobble-pocket | default | 1.0000 | 160 | 79 | 121 | 324 | 13302 | 0.9453 | 0.8571 | 0.7153 | 0.4110 | – | – | 0.0820 |
| psp-puzzle-bobble-pocket | baseline-off | 0.9850 | 311 | 160 | 130 | 323 | 13063 | 0.9373 | 0.6999 | 0.7083 | 0.4064 | – | – | 0.0710 |
| psp-puzzle-bobble-pocket | infer-prototypes | 1.0000 | 162 | 81 | 58 | 160 | 13220 | – | – | 0.7222 | 0.6134 | – | – | 0.0780 |
| psp-puzzle-bobble-pocket | inferred-types-off | 1.0000 | 162 | 81 | 58 | 160 | 13210 | – | – | 0.7222 | 0.5370 | – | – | 0.0800 |
| psp-puzzle-bobble-pocket-symtab | default | 0.9950 | 147 | 66 | 123 | 316 | 13151 | 0.9084 | 0.4397 | 0.7099 | 0.4123 | – | – | 0.0910 |
| psp-puzzle-bobble-pocket-symtab | baseline-off | 0.9900 | 313 | 158 | 131 | 316 | 12863 | 0.9068 | 0.4009 | 0.7099 | 0.4049 | – | – | 0.0720 |
| psp-puzzle-bobble-pocket-symtab | infer-prototypes | 0.9950 | 149 | 68 | 63 | 280 | 13151 | – | – | 0.7176 | 0.5926 | – | – | 0.0830 |
| psp-puzzle-bobble-pocket-symtab | inferred-types-off | 0.9950 | 149 | 68 | 63 | 280 | 13156 | – | – | 0.7176 | 0.5086 | – | – | 0.0740 |
