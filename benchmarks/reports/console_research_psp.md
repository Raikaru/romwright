# Console research components (2026-10-09T19:49:32+00:00)

Tools fingerprint `6f5ecccc046d7f48`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | psp-puzzle-bobble-pocket | psp-puzzle-bobble-pocket-symtab |
|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | mixed | mixed |
| joined register pairs -> prototypes | join-pairs-off | infer-prototypes | neutral | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket | helps | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +217, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ | no change | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +217, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ |
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket-symtab | helps | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +174 | no change | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +174 |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket | mixed | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -82, arity_accuracy +0.7pp, type_exact_rate +20.2pp | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -82, arity_accuracy +0.7pp, type_exact_rate +20.2pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -163, text_warnings +2, lines +136, arity_accuracy +1.4pp, type_exact_rate +20.7pp |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket-symtab | mixed | gotos +1~, labels +1, irregular_functions -50, native_warnings -102, text_warnings +2, lines -96, arity_accuracy +2.1pp, type_exact_rate +21.3pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -102, text_warnings +2, lines -96, arity_accuracy +2.1pp, type_exact_rate +21.3pp | gotos -152, labels -85, irregular_functions -61, native_warnings -102, text_warnings +2, lines +78, arity_accuracy +2.1pp, type_exact_rate +21.3pp |
| joined register pairs -> prototypes | psp-puzzle-bobble-pocket | neutral | no change | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -82, arity_accuracy +0.7pp, type_exact_rate +20.2pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -163, text_warnings +2, lines +136, arity_accuracy +1.4pp, type_exact_rate +20.7pp |
| joined register pairs -> prototypes | psp-puzzle-bobble-pocket-symtab | helps | native_warnings -1~, lines +31, arity_accuracy -2.8pp, type_exact_rate -2.3pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -103, text_warnings +2, lines -65, arity_accuracy -0.7pp, type_exact_rate +19.1pp | gotos -152, labels -85, irregular_functions -61, native_warnings -103, text_warnings +2, lines +109, arity_accuracy -0.7pp, type_exact_rate +19.1pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-puzzle-bobble-pocket | default | 1.0000 | 160 | 79 | 121 | 324 | 13278 | 0.9453 | 0.8559 | 0.7153 | 0.4110 | – | – | 0.1610 |
| psp-puzzle-bobble-pocket | baseline-off | 0.9850 | 311 | 160 | 130 | 323 | 13039 | 0.9373 | 0.6990 | 0.7083 | 0.4064 | – | – | 0.1650 |
| psp-puzzle-bobble-pocket | infer-prototypes | 1.0000 | 162 | 81 | 58 | 160 | 13196 | – | – | 0.7222 | 0.6134 | – | – | 0.1760 |
| psp-puzzle-bobble-pocket | join-pairs-off | 1.0000 | 162 | 81 | 58 | 160 | 13196 | – | – | 0.7222 | 0.6134 | – | – | 0.1160 |
| psp-puzzle-bobble-pocket-symtab | default | 1.0000 | 137 | 61 | 109 | 245 | 12285 | 1.0000 | 0.8627 | 0.8828 | 0.5833 | – | – | 0.1860 |
| psp-puzzle-bobble-pocket-symtab | baseline-off | 1.0000 | 290 | 147 | 120 | 245 | 12111 | 1.0000 | 0.7785 | 0.8828 | 0.5833 | – | – | 0.1730 |
| psp-puzzle-bobble-pocket-symtab | infer-prototypes | 1.0000 | 138 | 62 | 59 | 143 | 12189 | – | – | 0.9034 | 0.7968 | – | – | 0.1740 |
| psp-puzzle-bobble-pocket-symtab | join-pairs-off | 1.0000 | 138 | 62 | 59 | 142 | 12220 | – | – | 0.8759 | 0.7740 | – | – | 0.1400 |
