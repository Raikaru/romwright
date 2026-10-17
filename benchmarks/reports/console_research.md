# Console research components (2026-10-07T02:07:52+00:00)

Tools fingerprint `23c94218619e781c`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-pokeemerald | nds-pokeheartgold-arm9 | ps2-capcom-fighting-evolution | ps2-dungeon-game | psx-darkstalkers-3 | psv-need-for-speed-most-wanted | x360-black-ops-2 | gc-animal-crossing |
|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | mixed | mixed | mixed | mixed | hurts | mixed | hurts | hurts |
| IR passes (all three) | ir-none | default | hurts | hurts | hurts | hurts | hurts | hurts | hurts | hurts |
| IR pass structure alone | ir-only-structure | ir-none | hurts | hurts | hurts | hurts | hurts | hurts | hurts | hurts |
| IR pass canonical_helpers alone | ir-only-canonical_helpers | ir-none | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| IR pass additive_inverse alone | ir-only-additive_inverse | ir-none | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| switch VSA | switch-vsa-off | default | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| switch decompiler | switch-decompiler-off | default | helps | helps | helps | helps | neutral | helps | neutral | neutral |
| register params (decompile-time) | register-params | default | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| promote tailcalls | promote-tailcalls | default | hurts | neutral | hurts | hurts | neutral | neutral | neutral | neutral |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-pokeemerald | mixed | recall +2.3pp, precision +0.1pp~, success_rate +4.5pp, gotos +12, lines -1, arity_accuracy +4.0pp, type_exact_rate +1.1pp | no change | recall +2.3pp, precision +0.1pp~, success_rate +4.5pp, gotos +12, lines -1, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| all research (default vs baseline-off) | nds-pokeheartgold-arm9 | mixed | recall +2.2pp, success_rate +2.5pp, gotos +4, lines -1, arity_accuracy +1.0pp, type_exact_rate +0.9pp | no change | recall +2.2pp, success_rate +2.5pp, gotos +4, lines -1, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| all research (default vs baseline-off) | ps2-capcom-fighting-evolution | mixed | recall -0.2pp~, precision +0.8pp, gotos +5, labels +3, native_warnings -1~, lines -3 | no change | recall -0.2pp~, precision +0.8pp, gotos +5, labels +3, native_warnings -1~, lines -3 |
| all research (default vs baseline-off) | ps2-dungeon-game | mixed | precision +6.6pp, gotos +33, labels +9, lines -53 | no change | precision +6.6pp, gotos +33, labels +9, lines -53 |
| all research (default vs baseline-off) | psx-darkstalkers-3 | hurts | gotos +1, labels +1, lines -2 | no change | gotos +1, labels +1, lines -2 |
| all research (default vs baseline-off) | psv-need-for-speed-most-wanted | mixed | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos +1, labels +1, native_warnings +1~, lines +11 | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos +1, labels +1, native_warnings +1~, lines +11 |
| all research (default vs baseline-off) | x360-black-ops-2 | hurts | recall +0.3pp~, gotos +6, labels +1, lines -10 | no change | recall +0.3pp~, gotos +6, labels +1, lines -10 |
| all research (default vs baseline-off) | gc-animal-crossing | hurts | gotos +85, labels +3, native_warnings +2~, lines -16 | no change | gotos +85, labels +3, native_warnings +2~, lines -16 |
| IR passes (all three) | gba-pokeemerald | hurts | gotos -12, lines +1 | gotos -12, lines +1 | success_rate +4.5pp, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| IR passes (all three) | nds-pokeheartgold-arm9 | hurts | gotos -4, lines +1 | gotos -4, lines +1 | success_rate +2.5pp, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR passes (all three) | ps2-capcom-fighting-evolution | hurts | gotos -5, labels -3, native_warnings +1~, lines +3 | gotos -5, labels -3, native_warnings +1~, lines +3 | no change |
| IR passes (all three) | ps2-dungeon-game | hurts | gotos -33, labels -9, lines +53 | gotos -33, labels -9, lines +53 | no change |
| IR passes (all three) | psx-darkstalkers-3 | hurts | gotos -1, labels -1, lines +2 | gotos -1, labels -1, lines +2 | no change |
| IR passes (all three) | psv-need-for-speed-most-wanted | hurts | gotos -1, labels -1, native_warnings -1~, lines -11 | gotos -1, labels -1, native_warnings -1~, lines -11 | success_rate +1.0pp |
| IR passes (all three) | x360-black-ops-2 | hurts | gotos -6, labels -1, lines +10 | gotos -6, labels -1, lines +10 | no change |
| IR passes (all three) | gc-animal-crossing | hurts | gotos -85, labels -3, native_warnings -2~, lines +16 | gotos -85, labels -3, native_warnings -2~, lines +16 | no change |
| IR pass structure alone | gba-pokeemerald | hurts | gotos +12, lines -1 | no change | success_rate +4.5pp, gotos +12, lines -1, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| IR pass structure alone | nds-pokeheartgold-arm9 | hurts | gotos +4, lines -1 | no change | success_rate +2.5pp, gotos +4, lines -1, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR pass structure alone | ps2-capcom-fighting-evolution | hurts | gotos +5, labels +3, native_warnings -1~, lines -3 | no change | gotos +5, labels +3, native_warnings -1~, lines -3 |
| IR pass structure alone | ps2-dungeon-game | hurts | gotos +33, labels +9, lines -53 | no change | gotos +33, labels +9, lines -53 |
| IR pass structure alone | psx-darkstalkers-3 | hurts | gotos +1, labels +1, lines -2 | no change | gotos +1, labels +1, lines -2 |
| IR pass structure alone | psv-need-for-speed-most-wanted | hurts | gotos +1, labels +1, native_warnings +1~, lines +11 | no change | success_rate +1.0pp, gotos +1, labels +1, native_warnings +1~, lines +11 |
| IR pass structure alone | x360-black-ops-2 | hurts | gotos +6, labels +1, lines -9 | lines +1 | gotos +6, labels +1, lines -9 |
| IR pass structure alone | gc-animal-crossing | hurts | gotos +85, labels +3, native_warnings +2~, lines -16 | no change | gotos +85, labels +3, native_warnings +2~, lines -16 |
| IR pass canonical_helpers alone | gba-pokeemerald | neutral | no change | gotos -12, lines +1 | success_rate +4.5pp, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| IR pass canonical_helpers alone | nds-pokeheartgold-arm9 | neutral | no change | gotos -4, lines +1 | success_rate +2.5pp, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR pass canonical_helpers alone | ps2-capcom-fighting-evolution | neutral | no change | gotos -5, labels -3, native_warnings +1~, lines +3 | no change |
| IR pass canonical_helpers alone | ps2-dungeon-game | neutral | no change | gotos -33, labels -9, lines +53 | no change |
| IR pass canonical_helpers alone | psx-darkstalkers-3 | neutral | no change | gotos -1, labels -1, lines +2 | no change |
| IR pass canonical_helpers alone | psv-need-for-speed-most-wanted | neutral | no change | gotos -1, labels -1, native_warnings -1~, lines -11 | success_rate +1.0pp |
| IR pass canonical_helpers alone | x360-black-ops-2 | neutral | no change | gotos -6, labels -1, lines +10 | no change |
| IR pass canonical_helpers alone | gc-animal-crossing | neutral | no change | gotos -85, labels -3, native_warnings -2~, lines +16 | no change |
| IR pass additive_inverse alone | gba-pokeemerald | neutral | no change | gotos -12, lines +1 | success_rate +4.5pp, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| IR pass additive_inverse alone | nds-pokeheartgold-arm9 | neutral | no change | gotos -4, lines +1 | success_rate +2.5pp, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR pass additive_inverse alone | ps2-capcom-fighting-evolution | neutral | no change | gotos -5, labels -3, native_warnings +1~, lines +3 | no change |
| IR pass additive_inverse alone | ps2-dungeon-game | neutral | no change | gotos -33, labels -9, lines +53 | no change |
| IR pass additive_inverse alone | psx-darkstalkers-3 | neutral | no change | gotos -1, labels -1, lines +2 | no change |
| IR pass additive_inverse alone | psv-need-for-speed-most-wanted | neutral | no change | gotos -1, labels -1, native_warnings -1~, lines -11 | success_rate +1.0pp |
| IR pass additive_inverse alone | x360-black-ops-2 | neutral | lines -1 | gotos -6, labels -1, lines +9 | lines -1 |
| IR pass additive_inverse alone | gc-animal-crossing | neutral | no change | gotos -85, labels -3, native_warnings -2~, lines +16 | no change |
| switch VSA | gba-pokeemerald | neutral | no change | no change | recall +2.3pp, precision +0.1pp~, success_rate +4.5pp, gotos +12, lines -1, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| switch VSA | nds-pokeheartgold-arm9 | neutral | no change | no change | recall +2.2pp, success_rate +2.5pp, gotos +4, lines -1, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| switch VSA | ps2-capcom-fighting-evolution | neutral | no change | no change | recall -0.2pp~, precision +0.8pp, gotos +5, labels +3, native_warnings -1~, lines -3 |
| switch VSA | ps2-dungeon-game | neutral | no change | no change | precision +6.6pp, gotos +33, labels +9, lines -53 |
| switch VSA | psx-darkstalkers-3 | neutral | no change | no change | gotos +1, labels +1, lines -2 |
| switch VSA | psv-need-for-speed-most-wanted | neutral | no change | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos +1, labels +1, native_warnings +1~, lines +11 |
| switch VSA | x360-black-ops-2 | neutral | no change | no change | recall +0.3pp~, gotos +6, labels +1, lines -10 |
| switch VSA | gc-animal-crossing | neutral | no change | no change | gotos +85, labels +3, native_warnings +2~, lines -16 |
| switch decompiler | gba-pokeemerald | helps | recall -2.3pp, precision -0.1pp~, success_rate -4.5pp, arity_accuracy -4.0pp, type_exact_rate -1.1pp | recall -2.3pp, precision -0.1pp~, success_rate -4.5pp, arity_accuracy -4.0pp, type_exact_rate -1.1pp | gotos +12, lines -1 |
| switch decompiler | nds-pokeheartgold-arm9 | helps | recall -1.1pp, success_rate -1.5pp, arity_accuracy -0.5pp, type_exact_rate -0.5pp | recall -1.1pp, success_rate -1.5pp, arity_accuracy -0.5pp, type_exact_rate -0.5pp | recall +1.2pp, success_rate +1.0pp, gotos +4, lines -1, arity_accuracy +0.5pp, type_exact_rate +0.4pp~ |
| switch decompiler | ps2-capcom-fighting-evolution | helps | recall +0.2pp~, precision -0.8pp | recall +0.2pp~, precision -0.8pp | gotos +5, labels +3, native_warnings -1~, lines -3 |
| switch decompiler | ps2-dungeon-game | helps | precision -6.6pp | precision -6.6pp | gotos +33, labels +9, lines -53 |
| switch decompiler | psx-darkstalkers-3 | neutral | no change | no change | gotos +1, labels +1, lines -2 |
| switch decompiler | psv-need-for-speed-most-wanted | helps | recall -0.3pp~, precision -0.0pp~, success_rate -1.0pp | recall -0.3pp~, precision -0.0pp~, success_rate -1.0pp | gotos +1, labels +1, native_warnings +1~, lines +11 |
| switch decompiler | x360-black-ops-2 | neutral | recall -0.3pp~ | recall -0.3pp~ | gotos +6, labels +1, lines -10 |
| switch decompiler | gc-animal-crossing | neutral | no change | no change | gotos +85, labels +3, native_warnings +2~, lines -16 |
| register params (decompile-time) | gba-pokeemerald | neutral | no change | no change | success_rate +4.5pp, gotos +12, lines -1, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| register params (decompile-time) | nds-pokeheartgold-arm9 | neutral | no change | no change | success_rate +2.5pp, gotos +4, lines -1, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| register params (decompile-time) | ps2-capcom-fighting-evolution | neutral | no change | no change | gotos +5, labels +3, native_warnings -1~, lines -3 |
| register params (decompile-time) | ps2-dungeon-game | neutral | no change | no change | gotos +33, labels +9, lines -53 |
| register params (decompile-time) | psx-darkstalkers-3 | neutral | no change | no change | gotos +1, labels +1, lines -2 |
| register params (decompile-time) | psv-need-for-speed-most-wanted | neutral | no change | no change | success_rate +1.0pp, gotos +1, labels +1, native_warnings +1~, lines +11 |
| register params (decompile-time) | x360-black-ops-2 | neutral | no change | no change | gotos +6, labels +1, lines -10 |
| register params (decompile-time) | gc-animal-crossing | neutral | no change | no change | gotos +85, labels +3, native_warnings +2~, lines -16 |
| promote tailcalls | gba-pokeemerald | hurts | precision -1.5pp | precision -1.5pp | recall +2.3pp, precision -1.4pp, success_rate +4.5pp, gotos +12, lines -1, arity_accuracy +4.0pp, type_exact_rate +1.1pp |
| promote tailcalls | nds-pokeheartgold-arm9 | neutral | precision -0.0pp~ | precision -0.0pp~ | recall +2.2pp, precision -0.0pp~, success_rate +2.5pp, gotos +4, lines -1, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| promote tailcalls | ps2-capcom-fighting-evolution | hurts | recall +0.1pp~, precision -10.8pp, irregular_functions +2, native_warnings +11, lines +21 | recall +0.1pp~, precision -10.8pp, irregular_functions +2, native_warnings +11, lines +21 | recall -0.1pp~, precision -10.0pp, gotos +5, labels +3, irregular_functions +2, native_warnings +10, lines +18 |
| promote tailcalls | ps2-dungeon-game | hurts | precision -0.8pp | precision -0.8pp | precision +5.7pp, gotos +33, labels +9, lines -53 |
| promote tailcalls | psx-darkstalkers-3 | neutral | no change | no change | gotos +1, labels +1, lines -2 |
| promote tailcalls | psv-need-for-speed-most-wanted | neutral | no change | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos +1, labels +1, native_warnings +1~, lines +11 |
| promote tailcalls | x360-black-ops-2 | neutral | precision -0.0pp~, irregular_functions +1~, native_warnings +1~, lines -13 | precision -0.0pp~, irregular_functions +1~, native_warnings +1~, lines -13 | recall +0.3pp~, precision -0.0pp~, gotos +6, labels +1, irregular_functions +1~, native_warnings +1~, lines -23 |
| promote tailcalls | gc-animal-crossing | neutral | no change | no change | gotos +85, labels +3, native_warnings +2~, lines -16 |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | default | 1.0000 | 88 | 34 | 189 | 857 | 6201 | 0.9736 | 0.9689 | 0.9700 | 0.3085 | 0.0000 | 1.3000 |
| gba-pokeemerald | baseline-off | 0.9550 | 76 | 34 | 182 | 835 | 6039 | 0.9504 | 0.9681 | 0.9300 | 0.2974 | – | 0.8870 |
| gba-pokeemerald | ir-none | 1.0000 | 76 | 34 | 189 | 857 | 6202 | – | – | 0.9700 | 0.3085 | 0.0000 | 1.0280 |
| gba-pokeemerald | ir-only-structure | 1.0000 | 88 | 34 | 189 | 857 | 6201 | – | – | 0.9700 | 0.3085 | 0.0000 | 0.9380 |
| gba-pokeemerald | ir-only-canonical_helpers | 1.0000 | 76 | 34 | 189 | 857 | 6202 | – | – | 0.9700 | 0.3085 | 0.0000 | 1.2860 |
| gba-pokeemerald | ir-only-additive_inverse | 1.0000 | 76 | 34 | 189 | 857 | 6202 | – | – | 0.9700 | 0.3085 | 0.0000 | 1.2890 |
| gba-pokeemerald | switch-vsa-off | 1.0000 | 88 | 34 | 189 | 857 | 6201 | 0.9736 | 0.9689 | 0.9700 | 0.3085 | – | 0.9380 |
| gba-pokeemerald | switch-decompiler-off | 0.9550 | 88 | 34 | 182 | 835 | 6038 | 0.9504 | 0.9681 | 0.9300 | 0.2974 | – | 0.8470 |
| gba-pokeemerald | register-params | 1.0000 | 88 | 34 | 189 | 857 | 6201 | – | – | 0.9700 | 0.3085 | 0.0000 | 0.9580 |
| gba-pokeemerald | promote-tailcalls | 1.0000 | 88 | 34 | 189 | 857 | 6201 | 0.9736 | 0.9544 | 0.9700 | 0.3085 | – | 1.1070 |
| nds-pokeheartgold-arm9 | default | 1.0000 | 16 | 7 | 129 | 342 | 5116 | 0.9729 | 0.9973 | 0.7300 | 0.4154 | – | 1.3780 |
| nds-pokeheartgold-arm9 | baseline-off | 0.9750 | 12 | 7 | 125 | 333 | 4922 | 0.9504 | 0.9973 | 0.7200 | 0.4062 | – | 1.4330 |
| nds-pokeheartgold-arm9 | ir-none | 1.0000 | 12 | 7 | 129 | 342 | 5117 | – | – | 0.7300 | 0.4154 | – | 1.4230 |
| nds-pokeheartgold-arm9 | ir-only-structure | 1.0000 | 16 | 7 | 129 | 342 | 5116 | – | – | 0.7300 | 0.4154 | – | 1.3700 |
| nds-pokeheartgold-arm9 | ir-only-canonical_helpers | 1.0000 | 12 | 7 | 129 | 342 | 5117 | – | – | 0.7300 | 0.4154 | – | 1.4030 |
| nds-pokeheartgold-arm9 | ir-only-additive_inverse | 1.0000 | 12 | 7 | 129 | 342 | 5117 | – | – | 0.7300 | 0.4154 | – | 0.9380 |
| nds-pokeheartgold-arm9 | switch-vsa-off | 1.0000 | 16 | 7 | 129 | 342 | 5116 | 0.9729 | 0.9973 | 0.7300 | 0.4154 | – | 1.2490 |
| nds-pokeheartgold-arm9 | switch-decompiler-off | 0.9850 | 16 | 7 | 126 | 334 | 5009 | 0.9624 | 0.9973 | 0.7250 | 0.4099 | – | 0.9400 |
| nds-pokeheartgold-arm9 | register-params | 1.0000 | 16 | 7 | 129 | 342 | 5116 | – | – | 0.7300 | 0.4154 | – | 1.0990 |
| nds-pokeheartgold-arm9 | promote-tailcalls | 1.0000 | 16 | 7 | 129 | 342 | 5116 | 0.9729 | 0.9969 | 0.7300 | 0.4154 | – | 0.9290 |
| ps2-capcom-fighting-evolution | default | 1.0000 | 19 | 10 | 150 | 330 | 6305 | 0.9413 | 0.9890 | – | – | – | 0.4800 |
| ps2-capcom-fighting-evolution | baseline-off | 1.0000 | 14 | 7 | 150 | 331 | 6308 | 0.9435 | 0.9808 | – | – | – | 0.3900 |
| ps2-capcom-fighting-evolution | ir-none | 1.0000 | 14 | 7 | 150 | 331 | 6308 | – | – | – | – | – | 0.3890 |
| ps2-capcom-fighting-evolution | ir-only-structure | 1.0000 | 19 | 10 | 150 | 330 | 6305 | – | – | – | – | – | 0.3760 |
| ps2-capcom-fighting-evolution | ir-only-canonical_helpers | 1.0000 | 14 | 7 | 150 | 331 | 6308 | – | – | – | – | – | 0.3780 |
| ps2-capcom-fighting-evolution | ir-only-additive_inverse | 1.0000 | 14 | 7 | 150 | 331 | 6308 | – | – | – | – | – | 0.3870 |
| ps2-capcom-fighting-evolution | switch-vsa-off | 1.0000 | 19 | 10 | 150 | 330 | 6305 | 0.9413 | 0.9890 | – | – | – | 0.3940 |
| ps2-capcom-fighting-evolution | switch-decompiler-off | 1.0000 | 19 | 10 | 150 | 330 | 6305 | 0.9435 | 0.9808 | – | – | – | 0.3620 |
| ps2-capcom-fighting-evolution | register-params | 1.0000 | 19 | 10 | 150 | 330 | 6305 | – | – | – | – | – | 0.3710 |
| ps2-capcom-fighting-evolution | promote-tailcalls | 1.0000 | 19 | 10 | 152 | 341 | 6326 | 0.9422 | 0.8809 | – | – | – | 0.6530 |
| ps2-dungeon-game | default | 1.0000 | 182 | 107 | 135 | 412 | 11266 | 0.9400 | 0.9305 | 1.0000 | 0.3934 | – | 0.2600 |
| ps2-dungeon-game | baseline-off | 1.0000 | 149 | 98 | 135 | 412 | 11319 | 0.9400 | 0.8649 | 1.0000 | 0.3934 | – | 0.1290 |
| ps2-dungeon-game | ir-none | 1.0000 | 149 | 98 | 135 | 412 | 11319 | – | – | 1.0000 | 0.3934 | – | 0.1250 |
| ps2-dungeon-game | ir-only-structure | 1.0000 | 182 | 107 | 135 | 412 | 11266 | – | – | 1.0000 | 0.3934 | – | 0.1250 |
| ps2-dungeon-game | ir-only-canonical_helpers | 1.0000 | 149 | 98 | 135 | 412 | 11319 | – | – | 1.0000 | 0.3934 | – | 0.1220 |
| ps2-dungeon-game | ir-only-additive_inverse | 1.0000 | 149 | 98 | 135 | 412 | 11319 | – | – | 1.0000 | 0.3934 | – | 0.1620 |
| ps2-dungeon-game | switch-vsa-off | 1.0000 | 182 | 107 | 135 | 412 | 11266 | 0.9400 | 0.9305 | 1.0000 | 0.3934 | – | 0.1190 |
| ps2-dungeon-game | switch-decompiler-off | 1.0000 | 182 | 107 | 135 | 412 | 11266 | 0.9400 | 0.8649 | 1.0000 | 0.3934 | – | 0.1330 |
| ps2-dungeon-game | register-params | 1.0000 | 182 | 107 | 135 | 412 | 11266 | – | – | 1.0000 | 0.3934 | – | 0.1250 |
| ps2-dungeon-game | promote-tailcalls | 1.0000 | 182 | 107 | 135 | 412 | 11266 | 0.9400 | 0.9223 | 1.0000 | 0.3934 | – | 0.1260 |
| psx-darkstalkers-3 | default | 1.0000 | 19 | 12 | 158 | 440 | 4387 | 0.9866 | 0.3660 | – | – | – | 0.2710 |
| psx-darkstalkers-3 | baseline-off | 1.0000 | 18 | 11 | 158 | 440 | 4389 | 0.9866 | 0.3660 | – | – | – | 0.2020 |
| psx-darkstalkers-3 | ir-none | 1.0000 | 18 | 11 | 158 | 440 | 4389 | – | – | – | – | – | 0.2080 |
| psx-darkstalkers-3 | ir-only-structure | 1.0000 | 19 | 12 | 158 | 440 | 4387 | – | – | – | – | – | 0.3060 |
| psx-darkstalkers-3 | ir-only-canonical_helpers | 1.0000 | 18 | 11 | 158 | 440 | 4389 | – | – | – | – | – | 0.2720 |
| psx-darkstalkers-3 | ir-only-additive_inverse | 1.0000 | 18 | 11 | 158 | 440 | 4389 | – | – | – | – | – | 0.2350 |
| psx-darkstalkers-3 | switch-vsa-off | 1.0000 | 19 | 12 | 158 | 440 | 4387 | 0.9866 | 0.3660 | – | – | – | 0.1930 |
| psx-darkstalkers-3 | switch-decompiler-off | 1.0000 | 19 | 12 | 158 | 440 | 4387 | 0.9866 | 0.3660 | – | – | – | 0.1900 |
| psx-darkstalkers-3 | register-params | 1.0000 | 19 | 12 | 158 | 440 | 4387 | – | – | – | – | – | 0.1780 |
| psx-darkstalkers-3 | promote-tailcalls | 1.0000 | 19 | 12 | 158 | 440 | 4387 | 0.9866 | 0.3660 | – | – | – | 0.2660 |
| psv-need-for-speed-most-wanted | default | 0.9900 | 36 | 24 | 101 | 500 | 14489 | 0.9724 | 0.9570 | – | – | – | 2.6440 |
| psv-need-for-speed-most-wanted | baseline-off | 0.9800 | 35 | 23 | 100 | 498 | 14466 | 0.9691 | 0.9569 | – | – | – | 2.6280 |
| psv-need-for-speed-most-wanted | ir-none | 0.9900 | 35 | 23 | 101 | 499 | 14478 | – | – | – | – | – | 1.8590 |
| psv-need-for-speed-most-wanted | ir-only-structure | 0.9900 | 36 | 24 | 101 | 500 | 14489 | – | – | – | – | – | 1.8810 |
| psv-need-for-speed-most-wanted | ir-only-canonical_helpers | 0.9900 | 35 | 23 | 101 | 499 | 14478 | – | – | – | – | – | 3.8360 |
| psv-need-for-speed-most-wanted | ir-only-additive_inverse | 0.9900 | 35 | 23 | 101 | 499 | 14478 | – | – | – | – | – | 1.6980 |
| psv-need-for-speed-most-wanted | switch-vsa-off | 0.9900 | 36 | 24 | 101 | 500 | 14489 | 0.9724 | 0.9570 | – | – | – | 2.8980 |
| psv-need-for-speed-most-wanted | switch-decompiler-off | 0.9800 | 36 | 24 | 100 | 499 | 14477 | 0.9691 | 0.9569 | – | – | – | 2.0480 |
| psv-need-for-speed-most-wanted | register-params | 0.9900 | 36 | 24 | 101 | 500 | 14489 | – | – | – | – | – | 1.9660 |
| psv-need-for-speed-most-wanted | promote-tailcalls | 0.9900 | 36 | 24 | 101 | 500 | 14489 | 0.9724 | 0.9570 | – | – | – | 1.6900 |
| x360-black-ops-2 | default | 0.9600 | 61 | 28 | 158 | 611 | 9372 | 0.9833 | 0.9956 | – | – | – | 1.6660 |
| x360-black-ops-2 | baseline-off | 0.9600 | 55 | 27 | 158 | 611 | 9382 | 0.9803 | 0.9956 | – | – | – | 1.6380 |
| x360-black-ops-2 | ir-none | 0.9600 | 55 | 27 | 158 | 611 | 9382 | – | – | – | – | – | 1.6820 |
| x360-black-ops-2 | ir-only-structure | 0.9600 | 61 | 28 | 158 | 611 | 9373 | – | – | – | – | – | 1.6650 |
| x360-black-ops-2 | ir-only-canonical_helpers | 0.9600 | 55 | 27 | 158 | 611 | 9382 | – | – | – | – | – | 1.6580 |
| x360-black-ops-2 | ir-only-additive_inverse | 0.9600 | 55 | 27 | 158 | 611 | 9381 | – | – | – | – | – | 1.6840 |
| x360-black-ops-2 | switch-vsa-off | 0.9600 | 61 | 28 | 158 | 611 | 9372 | 0.9833 | 0.9956 | – | – | – | 1.6900 |
| x360-black-ops-2 | switch-decompiler-off | 0.9600 | 61 | 28 | 158 | 611 | 9372 | 0.9803 | 0.9956 | – | – | – | 1.6450 |
| x360-black-ops-2 | register-params | 0.9600 | 61 | 28 | 158 | 611 | 9372 | – | – | – | – | – | 1.8210 |
| x360-black-ops-2 | promote-tailcalls | 0.9600 | 61 | 28 | 159 | 612 | 9359 | 0.9833 | 0.9955 | – | – | – | 1.7910 |
| gc-animal-crossing | default | 0.9900 | 138 | 27 | 137 | 554 | 9454 | – | – | – | – | – | 0.3630 |
| gc-animal-crossing | baseline-off | 0.9900 | 53 | 24 | 137 | 552 | 9470 | – | – | – | – | – | 0.2460 |
| gc-animal-crossing | ir-none | 0.9900 | 53 | 24 | 137 | 552 | 9470 | – | – | – | – | – | 0.2470 |
| gc-animal-crossing | ir-only-structure | 0.9900 | 138 | 27 | 137 | 554 | 9454 | – | – | – | – | – | 0.2470 |
| gc-animal-crossing | ir-only-canonical_helpers | 0.9900 | 53 | 24 | 137 | 552 | 9470 | – | – | – | – | – | 0.2470 |
| gc-animal-crossing | ir-only-additive_inverse | 0.9900 | 53 | 24 | 137 | 552 | 9470 | – | – | – | – | – | 0.2500 |
| gc-animal-crossing | switch-vsa-off | 0.9900 | 138 | 27 | 137 | 554 | 9454 | – | – | – | – | – | 0.2460 |
| gc-animal-crossing | switch-decompiler-off | 0.9900 | 138 | 27 | 137 | 554 | 9454 | – | – | – | – | – | 0.2460 |
| gc-animal-crossing | register-params | 0.9900 | 138 | 27 | 137 | 554 | 9454 | – | – | – | – | – | 0.2570 |
| gc-animal-crossing | promote-tailcalls | 0.9900 | 138 | 27 | 137 | 554 | 9454 | – | – | – | – | – | 0.2460 |
