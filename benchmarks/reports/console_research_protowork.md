# Console research components (2026-10-09T13:32:06+00:00)

Tools fingerprint `dd85b94735d35bf0`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-pokeemerald | nds-pokeheartgold-arm9 | ps2-capcom-fighting-evolution | ps2-dungeon-game | psp-puzzle-bobble-pocket | psp-puzzle-bobble-pocket-symtab |
|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps | helps | helps | helps | mixed | mixed |
| inferred types -> prototypes | inferred-types-off | infer-prototypes | helps | helps | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-pokeemerald | helps | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -52, labels -22, lines +32, arity_accuracy +3.5pp, type_exact_rate +1.6pp | no change | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -52, labels -22, lines +32, arity_accuracy +3.5pp, type_exact_rate +1.6pp |
| all research (default vs baseline-off) | nds-pokeheartgold-arm9 | helps | recall +2.2pp, precision +0.0pp~, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +32, arity_accuracy +1.0pp, type_exact_rate +0.9pp | no change | recall +2.2pp, precision +0.0pp~, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +32, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| all research (default vs baseline-off) | ps2-capcom-fighting-evolution | helps | recall -0.2pp~, precision +1.0pp, gotos -10, labels -6, lines +107 | no change | recall -0.2pp~, precision +1.0pp, gotos -10, labels -6, lines +107 |
| all research (default vs baseline-off) | ps2-dungeon-game | helps | precision +6.9pp, gotos -100, labels -69, irregular_functions -6, lines +71 | no change | precision +6.9pp, gotos -100, labels -69, irregular_functions -6, lines +71 |
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket | helps | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +226, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ | no change | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +226, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ |
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket-symtab | helps | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +176 | no change | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +176 |
| persisted prototypes (infer_prototypes job) | gba-pokeemerald | helps | native_warnings -367, lines -38, arity_accuracy +0.5pp, type_exact_rate +9.8pp | native_warnings -367, lines -38, arity_accuracy +0.5pp, type_exact_rate +9.8pp | success_rate +3.5pp, gotos -52, labels -22, native_warnings -348, lines -6, arity_accuracy +4.0pp, type_exact_rate +11.4pp |
| persisted prototypes (infer_prototypes job) | nds-pokeheartgold-arm9 | helps | irregular_functions -106, native_warnings -300, lines -23, arity_accuracy +12.0pp, type_exact_rate +18.6pp | irregular_functions -106, native_warnings -300, lines -23, arity_accuracy +12.0pp, type_exact_rate +18.6pp | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -105, native_warnings -295, lines +3, arity_accuracy +13.0pp, type_exact_rate +19.5pp |
| persisted prototypes (infer_prototypes job) | ps2-capcom-fighting-evolution | helps | irregular_functions -130, native_warnings -474, lines -265, arity_accuracy +0.5pp, type_exact_rate +40.8pp | irregular_functions -130, native_warnings -474, lines -265, arity_accuracy +0.5pp, type_exact_rate +40.8pp | gotos -10, labels -6, irregular_functions -130, native_warnings -474, lines -158, arity_accuracy +0.5pp, type_exact_rate +40.8pp |
| persisted prototypes (infer_prototypes job) | ps2-dungeon-game | helps | irregular_functions -62, native_warnings -202, lines +36, type_exact_rate +1.6pp | irregular_functions -62, native_warnings -202, lines +36, type_exact_rate +1.6pp | gotos -100, labels -69, irregular_functions -68, native_warnings -202, lines +107, type_exact_rate +1.6pp |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket | mixed | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -81, arity_accuracy +0.7pp, type_exact_rate +20.2pp | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -81, arity_accuracy +0.7pp, type_exact_rate +20.2pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -163, text_warnings +2, lines +146, arity_accuracy +1.4pp, type_exact_rate +20.7pp |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket-symtab | mixed | gotos +1~, labels +1, irregular_functions -50, native_warnings -103, text_warnings +2, lines -65, arity_accuracy -0.7pp, type_exact_rate +19.1pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -103, text_warnings +2, lines -65, arity_accuracy -0.7pp, type_exact_rate +19.1pp | gotos -152, labels -85, irregular_functions -61, native_warnings -103, text_warnings +2, lines +111, arity_accuracy -0.7pp, type_exact_rate +19.1pp |
| inferred types -> prototypes | gba-pokeemerald | helps | lines -2, type_exact_rate -10.4pp | native_warnings -367, lines -40, arity_accuracy +0.5pp, type_exact_rate -0.5pp | success_rate +3.5pp, gotos -52, labels -22, native_warnings -348, lines -8, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| inferred types -> prototypes | nds-pokeheartgold-arm9 | helps | lines -24, type_exact_rate -10.8pp | irregular_functions -106, native_warnings -300, lines -47, arity_accuracy +12.0pp, type_exact_rate +7.8pp | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -105, native_warnings -295, lines -21, arity_accuracy +13.0pp, type_exact_rate +8.7pp |
| inferred types -> prototypes | ps2-capcom-fighting-evolution | helps | lines +98, type_exact_rate -38.9pp | irregular_functions -130, native_warnings -474, lines -167, arity_accuracy +0.5pp, type_exact_rate +1.9pp | gotos -10, labels -6, irregular_functions -130, native_warnings -474, lines -60, arity_accuracy +0.5pp, type_exact_rate +1.9pp |
| inferred types -> prototypes | ps2-dungeon-game | helps | type_exact_rate -8.2pp | irregular_functions -62, native_warnings -202, lines +36, type_exact_rate -6.6pp | gotos -100, labels -69, irregular_functions -68, native_warnings -202, lines +107, type_exact_rate -6.6pp |
| inferred types -> prototypes | psp-puzzle-bobble-pocket | helps | lines -10, type_exact_rate -7.6pp | gotos +2, labels +2, irregular_functions -63, native_warnings -164, text_warnings +2, lines -91, arity_accuracy +0.7pp, type_exact_rate +12.6pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -163, text_warnings +2, lines +136, arity_accuracy +1.4pp, type_exact_rate +13.1pp |
| inferred types -> prototypes | psp-puzzle-bobble-pocket-symtab | helps | lines -12, type_exact_rate -8.7pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -103, text_warnings +2, lines -77, arity_accuracy -0.7pp, type_exact_rate +10.4pp | gotos -152, labels -85, irregular_functions -61, native_warnings -103, text_warnings +2, lines +99, arity_accuracy -0.7pp, type_exact_rate +10.4pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | default | 1.0000 | 4 | 2 | 189 | 566 | 5679 | 0.9737 | 0.9971 | 0.9750 | 0.5931 | – | – | 0.4830 |
| gba-pokeemerald | baseline-off | 0.9650 | 56 | 24 | 183 | 541 | 5544 | 0.9504 | 0.9970 | 0.9400 | 0.5771 | – | – | 0.4480 |
| gba-pokeemerald | infer-prototypes | 1.0000 | 4 | 2 | 189 | 199 | 5641 | – | – | 0.9800 | 0.6915 | – | – | 0.5140 |
| gba-pokeemerald | inferred-types-off | 1.0000 | 4 | 2 | 189 | 199 | 5639 | – | – | 0.9800 | 0.5878 | – | – | 0.5070 |
| nds-pokeheartgold-arm9 | default | 1.0000 | 0 | 0 | 128 | 342 | 5150 | 0.9729 | 0.9984 | 0.7300 | 0.4154 | – | – | 0.4740 |
| nds-pokeheartgold-arm9 | baseline-off | 0.9750 | 12 | 7 | 125 | 333 | 4921 | 0.9504 | 0.9980 | 0.7200 | 0.4062 | – | – | 0.4520 |
| nds-pokeheartgold-arm9 | infer-prototypes | 1.0000 | 0 | 0 | 22 | 42 | 5127 | – | – | 0.8500 | 0.6014 | – | – | 0.5000 |
| nds-pokeheartgold-arm9 | inferred-types-off | 1.0000 | 0 | 0 | 22 | 42 | 5103 | – | – | 0.8500 | 0.4929 | – | – | 0.6320 |
| ps2-capcom-fighting-evolution | default | 1.0000 | 4 | 1 | 163 | 532 | 9260 | 0.9412 | 0.9964 | 0.9850 | 0.4834 | – | – | 0.2810 |
| ps2-capcom-fighting-evolution | baseline-off | 1.0000 | 14 | 7 | 163 | 532 | 9153 | 0.9435 | 0.9867 | 0.9850 | 0.4834 | – | – | 0.2700 |
| ps2-capcom-fighting-evolution | infer-prototypes | 1.0000 | 4 | 1 | 33 | 58 | 8995 | – | – | 0.9900 | 0.8910 | – | – | 0.2090 |
| ps2-capcom-fighting-evolution | inferred-types-off | 1.0000 | 4 | 1 | 33 | 58 | 9093 | – | – | 0.9900 | 0.5024 | – | – | 0.2070 |
| ps2-dungeon-game | default | 1.0000 | 42 | 22 | 123 | 359 | 11408 | 0.9438 | 0.9880 | 1.0000 | 0.4262 | – | – | 0.0590 |
| ps2-dungeon-game | baseline-off | 1.0000 | 142 | 91 | 129 | 359 | 11337 | 0.9438 | 0.9192 | 1.0000 | 0.4262 | – | – | 0.0590 |
| ps2-dungeon-game | infer-prototypes | 1.0000 | 42 | 22 | 61 | 157 | 11444 | – | – | 1.0000 | 0.4426 | – | – | 0.0600 |
| ps2-dungeon-game | inferred-types-off | 1.0000 | 42 | 22 | 61 | 157 | 11444 | – | – | 1.0000 | 0.3607 | – | – | 0.0600 |
| psp-puzzle-bobble-pocket | default | 1.0000 | 160 | 79 | 121 | 324 | 13311 | 0.9453 | 0.8559 | 0.7153 | 0.4110 | – | – | 0.0540 |
| psp-puzzle-bobble-pocket | baseline-off | 0.9850 | 311 | 160 | 130 | 323 | 13063 | 0.9373 | 0.6990 | 0.7083 | 0.4064 | – | – | 0.0540 |
| psp-puzzle-bobble-pocket | infer-prototypes | 1.0000 | 162 | 81 | 58 | 160 | 13230 | – | – | 0.7222 | 0.6134 | – | – | 0.0550 |
| psp-puzzle-bobble-pocket | inferred-types-off | 1.0000 | 162 | 81 | 58 | 160 | 13220 | – | – | 0.7222 | 0.5370 | – | – | 0.0550 |
| psp-puzzle-bobble-pocket-symtab | default | 1.0000 | 137 | 61 | 109 | 245 | 12296 | 1.0000 | 0.8627 | 0.8828 | 0.5833 | – | – | 0.0590 |
| psp-puzzle-bobble-pocket-symtab | baseline-off | 1.0000 | 290 | 147 | 120 | 245 | 12120 | 1.0000 | 0.7785 | 0.8828 | 0.5833 | – | – | 0.0550 |
| psp-puzzle-bobble-pocket-symtab | infer-prototypes | 1.0000 | 138 | 62 | 59 | 142 | 12231 | – | – | 0.8759 | 0.7740 | – | – | 0.0600 |
| psp-puzzle-bobble-pocket-symtab | inferred-types-off | 1.0000 | 138 | 62 | 59 | 142 | 12219 | – | – | 0.8759 | 0.6872 | – | – | 0.0590 |
