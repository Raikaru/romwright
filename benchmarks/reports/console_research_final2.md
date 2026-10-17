# Console research components (2026-10-09T09:37:30+00:00)

Tools fingerprint `ea27c70333bb669d`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-pokeemerald | nds-pokeheartgold-arm9 | ps2-capcom-fighting-evolution | ps2-dungeon-game | psx-darkstalkers-3 | psv-need-for-speed-most-wanted | x360-black-ops-2 | gc-animal-crossing | psp-puzzle-bobble-pocket | psp-puzzle-bobble-pocket-symtab |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps |
| Rust structuring (SAILR-style models) | rust-structuring-none | default | mixed | helps | helps | helps | helps | helps | helps | helps | helps | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps | helps | helps | helps | helps | mixed | helps | helps | mixed | mixed |
| inferred types -> prototypes | inferred-types-off | infer-prototypes | helps | helps | helps | helps | neutral | neutral | neutral | neutral | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-pokeemerald | helps | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -52, labels -22, lines +32, arity_accuracy +3.5pp, type_exact_rate +1.6pp | no change | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -52, labels -22, lines +32, arity_accuracy +3.5pp, type_exact_rate +1.6pp |
| all research (default vs baseline-off) | nds-pokeheartgold-arm9 | helps | recall +2.2pp, precision +0.0pp~, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +32, arity_accuracy +1.0pp, type_exact_rate +0.9pp | no change | recall +2.2pp, precision +0.0pp~, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +32, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| all research (default vs baseline-off) | ps2-capcom-fighting-evolution | helps | recall -0.2pp~, precision +1.0pp, gotos -10, labels -6, lines +107 | no change | recall -0.2pp~, precision +1.0pp, gotos -10, labels -6, lines +107 |
| all research (default vs baseline-off) | ps2-dungeon-game | helps | precision +6.9pp, gotos -100, labels -69, irregular_functions -6, lines +71 | no change | precision +6.9pp, gotos -100, labels -69, irregular_functions -6, lines +71 |
| all research (default vs baseline-off) | psx-darkstalkers-3 | helps | recall +0.1pp~, precision +0.0pp~, gotos -44, labels -27, irregular_functions -4, lines +77 | no change | recall +0.1pp~, precision +0.0pp~, gotos -44, labels -27, irregular_functions -4, lines +77 |
| all research (default vs baseline-off) | psv-need-for-speed-most-wanted | helps | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -20, labels -13, irregular_functions -1~, lines +23 | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -20, labels -13, irregular_functions -1~, lines +23 |
| all research (default vs baseline-off) | x360-black-ops-2 | helps | recall +0.3pp~, gotos -57, labels -28, lines +72 | no change | recall +0.3pp~, gotos -57, labels -28, lines +72 |
| all research (default vs baseline-off) | gc-animal-crossing | helps | gotos -29, labels -10, irregular_functions -1~, lines +106 | no change | gotos -29, labels -10, irregular_functions -1~, lines +106 |
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket | helps | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +226, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ | no change | recall +0.8pp, precision +15.7pp, success_rate +1.5pp, gotos -151, labels -81, irregular_functions -10, lines +226, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ |
| all research (default vs baseline-off) | psp-puzzle-bobble-pocket-symtab | helps | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +176 | no change | precision +8.4pp, gotos -153, labels -86, irregular_functions -11, lines +176 |
| Rust structuring (SAILR-style models) | gba-pokeemerald | mixed | gotos +51, labels +22, lines -30, m22_mean_similarity +0.9pp, m22_standalone_similarity +0.9pp | gotos +51, labels +22, lines -30, m22_mean_similarity +0.9pp, m22_standalone_similarity +0.9pp | success_rate +3.5pp, gotos -1, lines +2, arity_accuracy +3.5pp, type_exact_rate +1.6pp |
| Rust structuring (SAILR-style models) | nds-pokeheartgold-arm9 | helps | gotos +12, labels +7, irregular_functions +1~, lines -34 | gotos +12, labels +7, irregular_functions +1~, lines -34 | success_rate +2.5pp, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| Rust structuring (SAILR-style models) | ps2-capcom-fighting-evolution | helps | gotos +10, labels +6, lines -106 | gotos +10, labels +6, lines -106 | lines +1 |
| Rust structuring (SAILR-style models) | ps2-dungeon-game | helps | gotos +97, labels +67, irregular_functions +6, lines -75 | gotos +97, labels +67, irregular_functions +6, lines -75 | gotos -3, labels -2, lines -4 |
| Rust structuring (SAILR-style models) | psx-darkstalkers-3 | helps | gotos +43, labels +26, irregular_functions +4, lines -76 | gotos +43, labels +26, irregular_functions +4, lines -76 | gotos -1, labels -1, lines +1 |
| Rust structuring (SAILR-style models) | psv-need-for-speed-most-wanted | helps | gotos +19, labels +12, irregular_functions +1~, lines -36 | gotos +19, labels +12, irregular_functions +1~, lines -36 | success_rate +1.0pp, gotos -1, labels -1, lines -13 |
| Rust structuring (SAILR-style models) | x360-black-ops-2 | helps | gotos +53, labels +27, lines -74 | gotos +53, labels +27, lines -74 | gotos -4, labels -1, lines -2 |
| Rust structuring (SAILR-style models) | gc-animal-crossing | helps | gotos +28, labels +10, irregular_functions +1~, lines -102 | gotos +28, labels +10, irregular_functions +1~, lines -102 | gotos -1, lines +4 |
| Rust structuring (SAILR-style models) | psp-puzzle-bobble-pocket | helps | gotos +143, labels +80, irregular_functions +10, lines -208 | gotos +143, labels +80, irregular_functions +10, lines -208 | success_rate +1.5pp, gotos -8, labels -1~, lines +18, arity_accuracy +0.7pp, type_exact_rate +0.5pp~ |
| Rust structuring (SAILR-style models) | psp-puzzle-bobble-pocket-symtab | helps | gotos +145, labels +85, irregular_functions +11, lines -187 | gotos +145, labels +85, irregular_functions +11, lines -187 | gotos -8, labels -1~, lines -11 |
| persisted prototypes (infer_prototypes job) | gba-pokeemerald | helps | native_warnings -367, lines -42, arity_accuracy +0.5pp, type_exact_rate +8.8pp | native_warnings -367, lines -42, arity_accuracy +0.5pp, type_exact_rate +8.8pp | success_rate +3.5pp, gotos -52, labels -22, native_warnings -348, lines -10, arity_accuracy +4.0pp, type_exact_rate +10.4pp |
| persisted prototypes (infer_prototypes job) | nds-pokeheartgold-arm9 | helps | irregular_functions -106, native_warnings -300, lines -22, arity_accuracy +12.0pp, type_exact_rate +18.2pp | irregular_functions -106, native_warnings -300, lines -22, arity_accuracy +12.0pp, type_exact_rate +18.2pp | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -105, native_warnings -295, lines +4, arity_accuracy +13.0pp, type_exact_rate +19.2pp |
| persisted prototypes (infer_prototypes job) | ps2-capcom-fighting-evolution | helps | irregular_functions -130, native_warnings -474, lines -265, arity_accuracy +0.5pp, type_exact_rate +40.8pp | irregular_functions -130, native_warnings -474, lines -265, arity_accuracy +0.5pp, type_exact_rate +40.8pp | gotos -10, labels -6, irregular_functions -130, native_warnings -474, lines -158, arity_accuracy +0.5pp, type_exact_rate +40.8pp |
| persisted prototypes (infer_prototypes job) | ps2-dungeon-game | helps | irregular_functions -62, native_warnings -201, lines +35, type_exact_rate +1.6pp | irregular_functions -62, native_warnings -201, lines +35, type_exact_rate +1.6pp | gotos -100, labels -69, irregular_functions -68, native_warnings -201, lines +106, type_exact_rate +1.6pp |
| persisted prototypes (infer_prototypes job) | psx-darkstalkers-3 | helps | irregular_functions -80, native_warnings -189, lines -84 | irregular_functions -80, native_warnings -189, lines -84 | gotos -44, labels -27, irregular_functions -84, native_warnings -189, lines -7 |
| persisted prototypes (infer_prototypes job) | psv-need-for-speed-most-wanted | mixed | success_rate -1.0pp, irregular_functions -50, native_warnings -193, text_warnings -4, lines -95 | success_rate -1.0pp, irregular_functions -50, native_warnings -193, text_warnings -4, lines -95 | gotos -19, labels -12, irregular_functions -51, native_warnings -193, text_warnings -4, lines -72 |
| persisted prototypes (infer_prototypes job) | x360-black-ops-2 | helps | irregular_functions -118, native_warnings -568, text_warnings -3, lines -90 | irregular_functions -118, native_warnings -568, text_warnings -3, lines -90 | gotos -57, labels -28, irregular_functions -118, native_warnings -568, text_warnings -3, lines -18 |
| persisted prototypes (infer_prototypes job) | gc-animal-crossing | helps | irregular_functions -57, native_warnings -391, text_warnings +1~, lines +202 | irregular_functions -57, native_warnings -391, text_warnings +1~, lines +202 | gotos -29, labels -10, irregular_functions -58, native_warnings -391, text_warnings +1~, lines +308 |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket | mixed | gotos +2, labels +2, irregular_functions -63, native_warnings -163, text_warnings +2, lines -83, arity_accuracy +0.7pp, type_exact_rate +19.1pp | gotos +2, labels +2, irregular_functions -63, native_warnings -163, text_warnings +2, lines -83, arity_accuracy +0.7pp, type_exact_rate +19.1pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -162, text_warnings +2, lines +144, arity_accuracy +1.4pp, type_exact_rate +19.6pp |
| persisted prototypes (infer_prototypes job) | psp-puzzle-bobble-pocket-symtab | mixed | gotos +1~, labels +1, irregular_functions -50, native_warnings -100, text_warnings +2, lines -61, arity_accuracy -0.7pp, type_exact_rate +17.7pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -100, text_warnings +2, lines -61, arity_accuracy -0.7pp, type_exact_rate +17.7pp | gotos -152, labels -85, irregular_functions -61, native_warnings -100, text_warnings +2, lines +115, arity_accuracy -0.7pp, type_exact_rate +17.7pp |
| inferred types -> prototypes | gba-pokeemerald | helps | lines -2, type_exact_rate -10.4pp | native_warnings -367, lines -44, arity_accuracy +0.5pp, type_exact_rate -1.6pp | success_rate +3.5pp, gotos -52, labels -22, native_warnings -348, lines -12, arity_accuracy +4.0pp |
| inferred types -> prototypes | nds-pokeheartgold-arm9 | helps | lines -24, type_exact_rate -10.9pp | irregular_functions -106, native_warnings -300, lines -46, arity_accuracy +12.0pp, type_exact_rate +7.4pp | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -105, native_warnings -295, lines -20, arity_accuracy +13.0pp, type_exact_rate +8.3pp |
| inferred types -> prototypes | ps2-capcom-fighting-evolution | helps | lines +98, type_exact_rate -38.9pp | irregular_functions -130, native_warnings -474, lines -167, arity_accuracy +0.5pp, type_exact_rate +1.9pp | gotos -10, labels -6, irregular_functions -130, native_warnings -474, lines -60, arity_accuracy +0.5pp, type_exact_rate +1.9pp |
| inferred types -> prototypes | ps2-dungeon-game | helps | type_exact_rate -8.2pp | irregular_functions -62, native_warnings -201, lines +35, type_exact_rate -6.6pp | gotos -100, labels -69, irregular_functions -68, native_warnings -201, lines +106, type_exact_rate -6.6pp |
| inferred types -> prototypes | psx-darkstalkers-3 | neutral | no change | irregular_functions -80, native_warnings -189, lines -84 | gotos -44, labels -27, irregular_functions -84, native_warnings -189, lines -7 |
| inferred types -> prototypes | psv-need-for-speed-most-wanted | neutral | lines -29 | success_rate -1.0pp, irregular_functions -50, native_warnings -193, text_warnings -4, lines -124 | gotos -19, labels -12, irregular_functions -51, native_warnings -193, text_warnings -4, lines -101 |
| inferred types -> prototypes | x360-black-ops-2 | neutral | lines -4 | irregular_functions -118, native_warnings -568, text_warnings -3, lines -94 | gotos -57, labels -28, irregular_functions -118, native_warnings -568, text_warnings -3, lines -22 |
| inferred types -> prototypes | gc-animal-crossing | neutral | lines -9 | irregular_functions -57, native_warnings -391, text_warnings +1~, lines +193 | gotos -29, labels -10, irregular_functions -58, native_warnings -391, text_warnings +1~, lines +299 |
| inferred types -> prototypes | psp-puzzle-bobble-pocket | helps | lines -10, type_exact_rate -7.6pp | gotos +2, labels +2, irregular_functions -63, native_warnings -163, text_warnings +2, lines -93, arity_accuracy +0.7pp, type_exact_rate +11.5pp | success_rate +1.5pp, gotos -149, labels -79, irregular_functions -72, native_warnings -162, text_warnings +2, lines +134, arity_accuracy +1.4pp, type_exact_rate +11.9pp |
| inferred types -> prototypes | psp-puzzle-bobble-pocket-symtab | helps | lines -12, type_exact_rate -8.7pp | gotos +1~, labels +1, irregular_functions -50, native_warnings -100, text_warnings +2, lines -73, arity_accuracy -0.7pp, type_exact_rate +9.0pp | gotos -152, labels -85, irregular_functions -61, native_warnings -100, text_warnings +2, lines +103, arity_accuracy -0.7pp, type_exact_rate +9.0pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | default | 1.0000 | 4 | 2 | 189 | 566 | 5679 | 0.9737 | 0.9971 | 0.9750 | 0.5931 | 0.7573 | 0.7573 | 1.1660 |
| gba-pokeemerald | baseline-off | 0.9650 | 56 | 24 | 183 | 541 | 5544 | 0.9504 | 0.9970 | 0.9400 | 0.5771 | – | – | 1.1010 |
| gba-pokeemerald | rust-structuring-none | 1.0000 | 55 | 24 | 189 | 566 | 5649 | – | – | 0.9750 | 0.5931 | 0.7660 | 0.7660 | 1.7300 |
| gba-pokeemerald | infer-prototypes | 1.0000 | 4 | 2 | 189 | 199 | 5637 | – | – | 0.9800 | 0.6809 | – | – | 0.8740 |
| gba-pokeemerald | inferred-types-off | 1.0000 | 4 | 2 | 189 | 199 | 5635 | – | – | 0.9800 | 0.5771 | – | – | 0.7790 |
| nds-pokeheartgold-arm9 | default | 1.0000 | 0 | 0 | 128 | 342 | 5150 | 0.9729 | 0.9984 | 0.7300 | 0.4154 | – | – | 0.6610 |
| nds-pokeheartgold-arm9 | baseline-off | 0.9750 | 12 | 7 | 125 | 333 | 4921 | 0.9504 | 0.9980 | 0.7200 | 0.4062 | – | – | 0.6400 |
| nds-pokeheartgold-arm9 | rust-structuring-none | 1.0000 | 12 | 7 | 129 | 342 | 5116 | – | – | 0.7300 | 0.4154 | – | – | 0.6720 |
| nds-pokeheartgold-arm9 | infer-prototypes | 1.0000 | 0 | 0 | 22 | 42 | 5128 | – | – | 0.8500 | 0.5979 | – | – | 0.6840 |
| nds-pokeheartgold-arm9 | inferred-types-off | 1.0000 | 0 | 0 | 22 | 42 | 5104 | – | – | 0.8500 | 0.4893 | – | – | 0.6940 |
| ps2-capcom-fighting-evolution | default | 1.0000 | 4 | 1 | 163 | 532 | 9260 | 0.9412 | 0.9964 | 0.9850 | 0.4834 | – | – | 0.3060 |
| ps2-capcom-fighting-evolution | baseline-off | 1.0000 | 14 | 7 | 163 | 532 | 9153 | 0.9435 | 0.9867 | 0.9850 | 0.4834 | – | – | 0.3110 |
| ps2-capcom-fighting-evolution | rust-structuring-none | 1.0000 | 14 | 7 | 163 | 532 | 9154 | – | – | 0.9850 | 0.4834 | – | – | 0.3090 |
| ps2-capcom-fighting-evolution | infer-prototypes | 1.0000 | 4 | 1 | 33 | 58 | 8995 | – | – | 0.9900 | 0.8910 | – | – | 0.3400 |
| ps2-capcom-fighting-evolution | inferred-types-off | 1.0000 | 4 | 1 | 33 | 58 | 9093 | – | – | 0.9900 | 0.5024 | – | – | 0.3120 |
| ps2-dungeon-game | default | 1.0000 | 42 | 22 | 123 | 359 | 11408 | 0.9438 | 0.9880 | 1.0000 | 0.4262 | – | – | 0.0870 |
| ps2-dungeon-game | baseline-off | 1.0000 | 142 | 91 | 129 | 359 | 11337 | 0.9438 | 0.9192 | 1.0000 | 0.4262 | – | – | 0.2000 |
| ps2-dungeon-game | rust-structuring-none | 1.0000 | 139 | 89 | 129 | 359 | 11333 | – | – | 1.0000 | 0.4262 | – | – | 0.1900 |
| ps2-dungeon-game | infer-prototypes | 1.0000 | 42 | 22 | 61 | 158 | 11443 | – | – | 1.0000 | 0.4426 | – | – | 0.2690 |
| ps2-dungeon-game | inferred-types-off | 1.0000 | 42 | 22 | 61 | 158 | 11443 | – | – | 1.0000 | 0.3607 | – | – | 0.2220 |
| psx-darkstalkers-3 | default | 1.0000 | 7 | 4 | 107 | 225 | 6695 | 0.9878 | 0.3663 | – | – | – | – | 0.2530 |
| psx-darkstalkers-3 | baseline-off | 1.0000 | 51 | 31 | 111 | 225 | 6618 | 0.9866 | 0.3660 | – | – | – | – | 0.2710 |
| psx-darkstalkers-3 | rust-structuring-none | 1.0000 | 50 | 30 | 111 | 225 | 6619 | – | – | – | – | – | – | 0.1530 |
| psx-darkstalkers-3 | infer-prototypes | 1.0000 | 7 | 4 | 27 | 36 | 6611 | – | – | – | – | – | – | 0.1700 |
| psx-darkstalkers-3 | inferred-types-off | 1.0000 | 7 | 4 | 27 | 36 | 6611 | – | – | – | – | – | – | 0.1300 |
| psv-need-for-speed-most-wanted | default | 1.0000 | 26 | 19 | 124 | 505 | 14057 | 0.9731 | 0.9713 | – | – | – | – | 3.4070 |
| psv-need-for-speed-most-wanted | baseline-off | 0.9900 | 46 | 32 | 125 | 505 | 14020 | 0.9697 | 0.9712 | – | – | – | – | 1.4800 |
| psv-need-for-speed-most-wanted | rust-structuring-none | 1.0000 | 45 | 31 | 125 | 505 | 14021 | – | – | – | – | – | – | 1.6670 |
| psv-need-for-speed-most-wanted | infer-prototypes | 0.9900 | 24 | 18 | 72 | 288 | 13253 | – | – | – | – | – | – | 1.6950 |
| psv-need-for-speed-most-wanted | inferred-types-off | 0.9900 | 24 | 18 | 72 | 288 | 13224 | – | – | – | – | – | – | 1.5110 |
| x360-black-ops-2 | default | 1.0000 | 6 | 3 | 166 | 641 | 10210 | 0.9833 | 0.9964 | – | – | – | – | 3.0930 |
| x360-black-ops-2 | baseline-off | 1.0000 | 63 | 31 | 166 | 641 | 10138 | 0.9803 | 0.9964 | – | – | – | – | 3.0200 |
| x360-black-ops-2 | rust-structuring-none | 1.0000 | 59 | 30 | 166 | 641 | 10136 | – | – | – | – | – | – | 1.5890 |
| x360-black-ops-2 | infer-prototypes | 1.0000 | 6 | 3 | 48 | 73 | 10120 | – | – | – | – | – | – | 1.5440 |
| x360-black-ops-2 | inferred-types-off | 1.0000 | 6 | 3 | 48 | 73 | 10116 | – | – | – | – | – | – | 1.5480 |
| gc-animal-crossing | default | 1.0000 | 12 | 6 | 134 | 594 | 10261 | – | – | – | – | – | – | 0.4870 |
| gc-animal-crossing | baseline-off | 1.0000 | 41 | 16 | 135 | 594 | 10155 | – | – | – | – | – | – | 0.3470 |
| gc-animal-crossing | rust-structuring-none | 1.0000 | 40 | 16 | 135 | 594 | 10159 | – | – | – | – | – | – | 0.2000 |
| gc-animal-crossing | infer-prototypes | 1.0000 | 12 | 6 | 77 | 203 | 10463 | – | – | – | – | – | – | 0.2030 |
| gc-animal-crossing | inferred-types-off | 1.0000 | 12 | 6 | 77 | 203 | 10454 | – | – | – | – | – | – | 0.2060 |
| psp-puzzle-bobble-pocket | default | 1.0000 | 160 | 79 | 121 | 324 | 13311 | 0.9453 | 0.8559 | 0.7153 | 0.4110 | – | – | 0.0780 |
| psp-puzzle-bobble-pocket | baseline-off | 0.9850 | 311 | 160 | 130 | 323 | 13063 | 0.9373 | 0.6990 | 0.7083 | 0.4064 | – | – | 0.0770 |
| psp-puzzle-bobble-pocket | rust-structuring-none | 1.0000 | 303 | 159 | 131 | 324 | 13103 | – | – | 0.7153 | 0.4110 | – | – | 0.0770 |
| psp-puzzle-bobble-pocket | infer-prototypes | 1.0000 | 162 | 81 | 58 | 161 | 13228 | – | – | 0.7222 | 0.6019 | – | – | 0.0790 |
| psp-puzzle-bobble-pocket | inferred-types-off | 1.0000 | 162 | 81 | 58 | 161 | 13218 | – | – | 0.7222 | 0.5255 | – | – | 0.0790 |
| psp-puzzle-bobble-pocket-symtab | default | 1.0000 | 137 | 61 | 109 | 245 | 12296 | 1.0000 | 0.8627 | 0.8828 | 0.5833 | – | – | 0.0830 |
| psp-puzzle-bobble-pocket-symtab | baseline-off | 1.0000 | 290 | 147 | 120 | 245 | 12120 | 1.0000 | 0.7785 | 0.8828 | 0.5833 | – | – | 0.0810 |
| psp-puzzle-bobble-pocket-symtab | rust-structuring-none | 1.0000 | 282 | 146 | 120 | 245 | 12109 | – | – | 0.8828 | 0.5833 | – | – | 0.0840 |
| psp-puzzle-bobble-pocket-symtab | infer-prototypes | 1.0000 | 138 | 62 | 59 | 145 | 12235 | – | – | 0.8759 | 0.7603 | – | – | 0.0850 |
| psp-puzzle-bobble-pocket-symtab | inferred-types-off | 1.0000 | 138 | 62 | 59 | 145 | 12223 | – | – | 0.8759 | 0.6735 | – | – | 0.0850 |
