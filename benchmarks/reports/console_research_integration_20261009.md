# Console research components (2026-10-09T22:50:15+00:00)

Tools fingerprint `c5abc7e47c3417ac`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | psp-puzzle-bobble-pocket-symtab |
|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | mixed |
| joined register pairs -> prototypes | join-pairs-off | infer-prototypes | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket-symtab | helps | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +165 | no change | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +165 |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket-symtab | mixed | gotos +1~, labels +1, irregular_functions -50, native_warnings -102, text_warnings +2, lines -94, arity_accuracy +2.1pp, type_exact_rate +21.3pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -102, text_warnings +2, lines -94, arity_accuracy +2.1pp, type_exact_rate +21.3pp | gotos -152, labels -85, irregular_functions -61, native_warnings -102, text_warnings +2, lines +71, arity_accuracy +2.1pp, type_exact_rate +21.3pp |
| joined register pairs -> prototypes | psp-puzzle-bobble-pocket-symtab | helps | native_warnings -1~, lines +29, arity_accuracy -2.8pp, type_exact_rate -2.3pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -103, text_warnings +2, lines -65, arity_accuracy -0.7pp, type_exact_rate +19.1pp | gotos -152, labels -85, irregular_functions -61, native_warnings -103, text_warnings +2, lines +100, arity_accuracy -0.7pp, type_exact_rate +19.1pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psp-puzzle-bobble-pocket-symtab | default | 1.0000 | 137 | 61 | 109 | 245 | 12296 | 1.0000 | 0.8627 | 0.8828 | 0.5833 | – | – | 0.0600 |
| psp-puzzle-bobble-pocket-symtab | baseline-off | 1.0000 | 290 | 147 | 120 | 245 | 12131 | 1.0000 | 0.7785 | 0.8828 | 0.5833 | – | – | 0.0600 |
| psp-puzzle-bobble-pocket-symtab | infer-prototypes | 1.0000 | 138 | 62 | 59 | 143 | 12202 | – | – | 0.9034 | 0.7968 | – | – | 0.0800 |
| psp-puzzle-bobble-pocket-symtab | join-pairs-off | 1.0000 | 138 | 62 | 59 | 142 | 12231 | – | – | 0.8759 | 0.7740 | – | – | 0.0790 |
