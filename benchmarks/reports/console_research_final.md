# Console research components (2026-10-08T12:31:43+00:00)

Tools fingerprint `cdbbf0f7d1273898`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-pokeemerald | nds-pokeheartgold-arm9 | ps2-capcom-fighting-evolution | ps2-dungeon-game | psx-darkstalkers-3 | psv-need-for-speed-most-wanted | x360-black-ops-2 | gc-animal-crossing |
|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps | helps | helps | helps |
| IR passes (all three) | ir-none | default | helps | neutral | neutral | helps | neutral | helps | neutral | helps |
| IR pass structure alone | ir-only-structure | ir-none | helps | neutral | neutral | helps | neutral | helps | neutral | helps |
| IR pass canonical_helpers alone | ir-only-canonical_helpers | ir-none | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| IR pass additive_inverse alone | ir-only-additive_inverse | ir-none | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| Rust structuring (SAILR-style models) | rust-structuring-none | default | helps | helps | helps | helps | helps | helps | helps | helps |
| switch VSA | switch-vsa-off | default | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| switch decompiler | switch-decompiler-off | default | neutral | helps | helps | helps | neutral | helps | neutral | neutral |
| register params (decompile-time) | register-params | default | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| promote tailcalls | promote-tailcalls | default | neutral | neutral | hurts | neutral | neutral | neutral | neutral | neutral |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | mixed | helps | helps | mixed | helps | neutral | mixed | helps |
| register params (persisted) | infer-prototypes+register-params | infer-prototypes | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| inferred types -> prototypes | inferred-types | infer-prototypes | helps | helps | neutral | helps | neutral | neutral | hurts | neutral |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-pokeemerald | helps | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -73, labels -30, lines +55, arity_accuracy +3.5pp, type_exact_rate +0.5pp | no change | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -73, labels -30, lines +55, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| all research (default vs baseline-off) | nds-pokeheartgold-arm9 | helps | recall +2.2pp, precision +0.1pp~, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp | no change | recall +2.2pp, precision +0.1pp~, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| all research (default vs baseline-off) | ps2-capcom-fighting-evolution | helps | recall -0.2pp~, precision +1.0pp, gotos -14, labels -8, irregular_functions -1~, lines +17 | no change | recall -0.2pp~, precision +1.0pp, gotos -14, labels -8, irregular_functions -1~, lines +17 |
| all research (default vs baseline-off) | ps2-dungeon-game | helps | precision +6.9pp, gotos -97, labels -67, irregular_functions -6, lines +90 | no change | precision +6.9pp, gotos -97, labels -67, irregular_functions -6, lines +90 |
| all research (default vs baseline-off) | psx-darkstalkers-3 | helps | recall +0.1pp~, precision +0.0pp~, gotos -14, labels -9, irregular_functions -1~, lines +23 | no change | recall +0.1pp~, precision +0.0pp~, gotos -14, labels -9, irregular_functions -1~, lines +23 |
| all research (default vs baseline-off) | psv-need-for-speed-most-wanted | helps | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| all research (default vs baseline-off) | x360-black-ops-2 | helps | recall +0.3pp~, gotos -44, labels -21, lines +50 | no change | recall +0.3pp~, gotos -44, labels -21, lines +50 |
| all research (default vs baseline-off) | gc-animal-crossing | helps | gotos -42, labels -18, irregular_functions -1~, lines +52 | no change | gotos -42, labels -18, irregular_functions -1~, lines +52 |
| IR passes (all three) | gba-pokeemerald | helps | gotos +3, labels +1, lines -8, m22_standalone_similarity +0.3pp~ | gotos +3, labels +1, lines -8, m22_standalone_similarity +0.3pp~ | success_rate +3.5pp, gotos -70, labels -29, lines +47, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| IR passes (all three) | nds-pokeheartgold-arm9 | neutral | no change | no change | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR passes (all three) | ps2-capcom-fighting-evolution | neutral | no change | no change | gotos -14, labels -8, irregular_functions -1~, lines +17 |
| IR passes (all three) | ps2-dungeon-game | helps | gotos +5, labels +5, lines +8 | gotos +5, labels +5, lines +8 | gotos -92, labels -62, irregular_functions -6, lines +98 |
| IR passes (all three) | psx-darkstalkers-3 | neutral | no change | no change | gotos -14, labels -9, irregular_functions -1~, lines +23 |
| IR passes (all three) | psv-need-for-speed-most-wanted | helps | gotos +5, labels +5 | gotos +5, labels +5 | success_rate +1.0pp, gotos -10, labels -6, irregular_functions -1~, lines +9 |
| IR passes (all three) | x360-black-ops-2 | neutral | lines +1 | lines +1 | gotos -44, labels -21, lines +51 |
| IR passes (all three) | gc-animal-crossing | helps | gotos +1, lines -6 | gotos +1, lines -6 | gotos -41, labels -18, irregular_functions -1~, lines +46 |
| IR pass structure alone | gba-pokeemerald | helps | gotos -3, labels -1, lines +3 | lines -5, m22_standalone_similarity +0.3pp~ | success_rate +3.5pp, gotos -73, labels -30, lines +50, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| IR pass structure alone | nds-pokeheartgold-arm9 | neutral | no change | no change | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR pass structure alone | ps2-capcom-fighting-evolution | neutral | no change | no change | gotos -14, labels -8, irregular_functions -1~, lines +17 |
| IR pass structure alone | ps2-dungeon-game | helps | gotos -5, labels -5, lines -8 | no change | gotos -97, labels -67, irregular_functions -6, lines +90 |
| IR pass structure alone | psx-darkstalkers-3 | neutral | no change | no change | gotos -14, labels -9, irregular_functions -1~, lines +23 |
| IR pass structure alone | psv-need-for-speed-most-wanted | helps | gotos -5, labels -5, lines +1 | lines +1 | success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +10 |
| IR pass structure alone | x360-black-ops-2 | neutral | no change | lines +1 | gotos -44, labels -21, lines +51 |
| IR pass structure alone | gc-animal-crossing | helps | gotos -1, lines +5 | lines -1 | gotos -42, labels -18, irregular_functions -1~, lines +51 |
| IR pass canonical_helpers alone | gba-pokeemerald | neutral | no change | gotos +3, labels +1, lines -8, m22_standalone_similarity +0.3pp~ | success_rate +3.5pp, gotos -70, labels -29, lines +47, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| IR pass canonical_helpers alone | nds-pokeheartgold-arm9 | neutral | no change | no change | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR pass canonical_helpers alone | ps2-capcom-fighting-evolution | neutral | no change | no change | gotos -14, labels -8, irregular_functions -1~, lines +17 |
| IR pass canonical_helpers alone | ps2-dungeon-game | neutral | no change | gotos +5, labels +5, lines +8 | gotos -92, labels -62, irregular_functions -6, lines +98 |
| IR pass canonical_helpers alone | psx-darkstalkers-3 | neutral | no change | no change | gotos -14, labels -9, irregular_functions -1~, lines +23 |
| IR pass canonical_helpers alone | psv-need-for-speed-most-wanted | neutral | no change | gotos +5, labels +5 | success_rate +1.0pp, gotos -10, labels -6, irregular_functions -1~, lines +9 |
| IR pass canonical_helpers alone | x360-black-ops-2 | neutral | no change | lines +1 | gotos -44, labels -21, lines +51 |
| IR pass canonical_helpers alone | gc-animal-crossing | neutral | no change | gotos +1, lines -6 | gotos -41, labels -18, irregular_functions -1~, lines +46 |
| IR pass additive_inverse alone | gba-pokeemerald | neutral | m22_standalone_similarity -0.3pp~ | gotos +3, labels +1, lines -8 | success_rate +3.5pp, gotos -70, labels -29, lines +47, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| IR pass additive_inverse alone | nds-pokeheartgold-arm9 | neutral | no change | no change | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| IR pass additive_inverse alone | ps2-capcom-fighting-evolution | neutral | no change | no change | gotos -14, labels -8, irregular_functions -1~, lines +17 |
| IR pass additive_inverse alone | ps2-dungeon-game | neutral | no change | gotos +5, labels +5, lines +8 | gotos -92, labels -62, irregular_functions -6, lines +98 |
| IR pass additive_inverse alone | psx-darkstalkers-3 | neutral | no change | no change | gotos -14, labels -9, irregular_functions -1~, lines +23 |
| IR pass additive_inverse alone | psv-need-for-speed-most-wanted | neutral | lines -1 | gotos +5, labels +5, lines -1 | success_rate +1.0pp, gotos -10, labels -6, irregular_functions -1~, lines +8 |
| IR pass additive_inverse alone | x360-black-ops-2 | neutral | lines -1 | no change | gotos -44, labels -21, lines +50 |
| IR pass additive_inverse alone | gc-animal-crossing | neutral | lines +1 | gotos +1, lines -5 | gotos -41, labels -18, irregular_functions -1~, lines +47 |
| Rust structuring (SAILR-style models) | gba-pokeemerald | helps | gotos +73, labels +31, lines -50, m22_standalone_similarity -0.0pp~ | gotos +73, labels +31, lines -50, m22_standalone_similarity -0.0pp~ | success_rate +3.5pp, gotos -2, lines +5, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| Rust structuring (SAILR-style models) | nds-pokeheartgold-arm9 | helps | gotos +12, labels +7, irregular_functions +1~, lines -18 | gotos +12, labels +7, irregular_functions +1~, lines -18 | success_rate +2.5pp, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| Rust structuring (SAILR-style models) | ps2-capcom-fighting-evolution | helps | gotos +14, labels +8, irregular_functions +1~, lines -17 | gotos +14, labels +8, irregular_functions +1~, lines -17 | no change |
| Rust structuring (SAILR-style models) | ps2-dungeon-game | helps | gotos +94, labels +65, irregular_functions +6, lines -94 | gotos +94, labels +65, irregular_functions +6, lines -94 | gotos -3, labels -2, lines -4 |
| Rust structuring (SAILR-style models) | psx-darkstalkers-3 | helps | gotos +14, labels +9, irregular_functions +1~, lines -23 | gotos +14, labels +9, irregular_functions +1~, lines -23 | no change |
| Rust structuring (SAILR-style models) | psv-need-for-speed-most-wanted | helps | gotos +11, labels +6, irregular_functions +1~, lines -13 | gotos +11, labels +6, irregular_functions +1~, lines -13 | success_rate +1.0pp, gotos -4, labels -5, lines -4 |
| Rust structuring (SAILR-style models) | x360-black-ops-2 | helps | gotos +40, labels +20, lines -52 | gotos +40, labels +20, lines -52 | gotos -4, labels -1, lines -2 |
| Rust structuring (SAILR-style models) | gc-animal-crossing | helps | gotos +38, labels +17, irregular_functions +1~, lines -52 | gotos +38, labels +17, irregular_functions +1~, lines -52 | gotos -4, labels -1 |
| switch VSA | gba-pokeemerald | neutral | no change | no change | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -73, labels -30, lines +55, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| switch VSA | nds-pokeheartgold-arm9 | neutral | no change | no change | recall +2.2pp, precision +0.1pp~, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| switch VSA | ps2-capcom-fighting-evolution | neutral | no change | no change | recall -0.2pp~, precision +1.0pp, gotos -14, labels -8, irregular_functions -1~, lines +17 |
| switch VSA | ps2-dungeon-game | neutral | no change | no change | precision +6.9pp, gotos -97, labels -67, irregular_functions -6, lines +90 |
| switch VSA | psx-darkstalkers-3 | neutral | recall -0.1pp~, precision -0.0pp~ | recall -0.1pp~, precision -0.0pp~ | gotos -14, labels -9, irregular_functions -1~, lines +23 |
| switch VSA | psv-need-for-speed-most-wanted | neutral | no change | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| switch VSA | x360-black-ops-2 | neutral | no change | no change | recall +0.3pp~, gotos -44, labels -21, lines +50 |
| switch VSA | gc-animal-crossing | neutral | no change | no change | gotos -42, labels -18, irregular_functions -1~, lines +52 |
| switch decompiler | gba-pokeemerald | neutral | recall -0.4pp~, precision -0.0pp~ | recall -0.4pp~, precision -0.0pp~ | recall +1.9pp, precision +0.0pp~, success_rate +3.5pp, gotos -73, labels -30, lines +55, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| switch decompiler | nds-pokeheartgold-arm9 | helps | recall -0.5pp~, precision -0.0pp~, success_rate -0.5pp, type_exact_rate -0.2pp~ | recall -0.5pp~, precision -0.0pp~, success_rate -0.5pp, type_exact_rate -0.2pp~ | recall +1.8pp, precision +0.0pp~, success_rate +2.0pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.7pp |
| switch decompiler | ps2-capcom-fighting-evolution | helps | recall +0.3pp~, precision -1.0pp | recall +0.3pp~, precision -1.0pp | recall +0.0pp~, gotos -14, labels -8, irregular_functions -1~, lines +17 |
| switch decompiler | ps2-dungeon-game | helps | precision -6.4pp | precision -6.4pp | precision +0.4pp~, gotos -97, labels -67, irregular_functions -6, lines +90 |
| switch decompiler | psx-darkstalkers-3 | neutral | no change | no change | recall +0.1pp~, precision +0.0pp~, gotos -14, labels -9, irregular_functions -1~, lines +23 |
| switch decompiler | psv-need-for-speed-most-wanted | helps | recall -0.1pp~, success_rate -0.5pp | recall -0.1pp~, success_rate -0.5pp | recall +0.2pp~, precision +0.0pp~, success_rate +0.5pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| switch decompiler | x360-black-ops-2 | neutral | recall -0.1pp~ | recall -0.1pp~ | recall +0.2pp~, gotos -44, labels -21, lines +50 |
| switch decompiler | gc-animal-crossing | neutral | no change | no change | gotos -42, labels -18, irregular_functions -1~, lines +52 |
| register params (decompile-time) | gba-pokeemerald | neutral | no change | no change | success_rate +3.5pp, gotos -73, labels -30, lines +55, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| register params (decompile-time) | nds-pokeheartgold-arm9 | neutral | no change | no change | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| register params (decompile-time) | ps2-capcom-fighting-evolution | neutral | no change | no change | gotos -14, labels -8, irregular_functions -1~, lines +17 |
| register params (decompile-time) | ps2-dungeon-game | neutral | no change | no change | gotos -97, labels -67, irregular_functions -6, lines +90 |
| register params (decompile-time) | psx-darkstalkers-3 | neutral | no change | no change | gotos -14, labels -9, irregular_functions -1~, lines +23 |
| register params (decompile-time) | psv-need-for-speed-most-wanted | neutral | no change | no change | success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| register params (decompile-time) | x360-black-ops-2 | neutral | no change | no change | gotos -44, labels -21, lines +50 |
| register params (decompile-time) | gc-animal-crossing | neutral | no change | no change | gotos -42, labels -18, irregular_functions -1~, lines +52 |
| promote tailcalls | gba-pokeemerald | neutral | precision -0.5pp~ | precision -0.5pp~ | recall +2.3pp, precision -0.4pp~, success_rate +3.5pp, gotos -73, labels -30, lines +55, arity_accuracy +3.5pp, type_exact_rate +0.5pp |
| promote tailcalls | nds-pokeheartgold-arm9 | neutral | precision -0.1pp~ | precision -0.1pp~ | recall +2.2pp, success_rate +2.5pp, gotos -12, labels -7, irregular_functions -1~, lines +18, arity_accuracy +1.0pp, type_exact_rate +0.9pp |
| promote tailcalls | ps2-capcom-fighting-evolution | hurts | recall +0.1pp~, precision -3.4pp, native_warnings +4, lines +28 | recall +0.1pp~, precision -3.4pp, native_warnings +4, lines +28 | recall -0.1pp~, precision -2.4pp, gotos -14, labels -8, irregular_functions -1~, native_warnings +4, lines +45 |
| promote tailcalls | ps2-dungeon-game | neutral | precision -0.4pp~ | precision -0.4pp~ | precision +6.5pp, gotos -97, labels -67, irregular_functions -6, lines +90 |
| promote tailcalls | psx-darkstalkers-3 | neutral | no change | no change | recall +0.1pp~, precision +0.0pp~, gotos -14, labels -9, irregular_functions -1~, lines +23 |
| promote tailcalls | psv-need-for-speed-most-wanted | neutral | no change | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| promote tailcalls | x360-black-ops-2 | neutral | irregular_functions +1~, native_warnings +1~, lines -13 | irregular_functions +1~, native_warnings +1~, lines -13 | recall +0.3pp~, gotos -44, labels -21, irregular_functions +1~, native_warnings +1~, lines +37 |
| promote tailcalls | gc-animal-crossing | neutral | irregular_functions +1~, native_warnings +3~, lines -1 | irregular_functions +1~, native_warnings +3~, lines -1 | gotos -42, labels -18, native_warnings +3~, lines +51 |
| persisted prototypes (infer_prototypes job) | gba-pokeemerald | mixed | gotos -2, labels -1, native_warnings -376, text_warnings +1~, lines +70, arity_accuracy -1.5pp, type_exact_rate -0.5pp | gotos -2, labels -1, native_warnings -376, text_warnings +1~, lines +70, arity_accuracy -1.5pp, type_exact_rate -0.5pp | success_rate +3.5pp, gotos -75, labels -31, native_warnings -357, text_warnings +1~, lines +125, arity_accuracy +2.0pp |
| persisted prototypes (infer_prototypes job) | nds-pokeheartgold-arm9 | helps | irregular_functions -85, native_warnings -259, lines +138, arity_accuracy +3.0pp, type_exact_rate +7.8pp | irregular_functions -85, native_warnings -259, lines +138, arity_accuracy +3.0pp, type_exact_rate +7.8pp | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -84, native_warnings -254, lines +148, arity_accuracy +4.0pp, type_exact_rate +8.7pp |
| persisted prototypes (infer_prototypes job) | ps2-capcom-fighting-evolution | helps | irregular_functions -106, native_warnings -235, lines -24 | irregular_functions -106, native_warnings -235, lines -24 | gotos -14, labels -8, irregular_functions -107, native_warnings -235, lines -7 |
| persisted prototypes (infer_prototypes job) | ps2-dungeon-game | mixed | irregular_functions -52, native_warnings +169, lines +796, type_exact_rate -4.9pp | irregular_functions -52, native_warnings +169, lines +796, type_exact_rate -4.9pp | gotos -97, labels -67, irregular_functions -58, native_warnings +169, lines +886, type_exact_rate -4.9pp |
| persisted prototypes (infer_prototypes job) | psx-darkstalkers-3 | helps | irregular_functions -42, native_warnings -179, lines -74 | irregular_functions -42, native_warnings -179, lines -74 | gotos -14, labels -9, irregular_functions -43, native_warnings -179, lines -51 |
| persisted prototypes (infer_prototypes job) | psv-need-for-speed-most-wanted | neutral | no change | no change | success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| persisted prototypes (infer_prototypes job) | x360-black-ops-2 | mixed | success_rate -2.0pp, gotos -2, labels -1, irregular_functions -98, native_warnings -490, text_warnings -8, lines +193 | success_rate -2.0pp, gotos -2, labels -1, irregular_functions -98, native_warnings -490, text_warnings -8, lines +193 | success_rate -2.0pp, gotos -43, labels -20, irregular_functions -98, native_warnings -490, text_warnings -8, lines +238 |
| persisted prototypes (infer_prototypes job) | gc-animal-crossing | helps | irregular_functions -85, native_warnings -300, lines +506 | irregular_functions -85, native_warnings -300, lines +506 | gotos -42, labels -18, irregular_functions -86, native_warnings -300, lines +558 |
| register params (persisted) | gba-pokeemerald | neutral | no change | gotos -2, labels -1, native_warnings -376, text_warnings +1~, lines +70, arity_accuracy -1.5pp, type_exact_rate -0.5pp | success_rate +3.5pp, gotos -75, labels -31, native_warnings -357, text_warnings +1~, lines +125, arity_accuracy +2.0pp |
| register params (persisted) | nds-pokeheartgold-arm9 | neutral | no change | irregular_functions -85, native_warnings -259, lines +138, arity_accuracy +3.0pp, type_exact_rate +7.8pp | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -84, native_warnings -254, lines +148, arity_accuracy +4.0pp, type_exact_rate +8.7pp |
| register params (persisted) | ps2-capcom-fighting-evolution | neutral | no change | irregular_functions -106, native_warnings -235, lines -24 | gotos -14, labels -8, irregular_functions -107, native_warnings -235, lines -7 |
| register params (persisted) | ps2-dungeon-game | neutral | no change | irregular_functions -52, native_warnings +169, lines +796, type_exact_rate -4.9pp | gotos -97, labels -67, irregular_functions -58, native_warnings +169, lines +886, type_exact_rate -4.9pp |
| register params (persisted) | psx-darkstalkers-3 | neutral | no change | irregular_functions -42, native_warnings -179, lines -74 | gotos -14, labels -9, irregular_functions -43, native_warnings -179, lines -51 |
| register params (persisted) | psv-need-for-speed-most-wanted | neutral | no change | no change | success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| register params (persisted) | x360-black-ops-2 | neutral | no change | success_rate -2.0pp, gotos -2, labels -1, irregular_functions -98, native_warnings -490, text_warnings -8, lines +193 | success_rate -2.0pp, gotos -43, labels -20, irregular_functions -98, native_warnings -490, text_warnings -8, lines +238 |
| register params (persisted) | gc-animal-crossing | neutral | no change | irregular_functions -85, native_warnings -300, lines +506 | gotos -42, labels -18, irregular_functions -86, native_warnings -300, lines +558 |
| inferred types -> prototypes | gba-pokeemerald | helps | lines +3, type_exact_rate +11.4pp | gotos -2, labels -1, native_warnings -376, text_warnings +1~, lines +73, arity_accuracy -1.5pp, type_exact_rate +10.9pp | success_rate +3.5pp, gotos -75, labels -31, native_warnings -357, text_warnings +1~, lines +128, arity_accuracy +2.0pp, type_exact_rate +11.4pp |
| inferred types -> prototypes | nds-pokeheartgold-arm9 | helps | lines +29, type_exact_rate +11.2pp | irregular_functions -85, native_warnings -259, lines +167, arity_accuracy +3.0pp, type_exact_rate +19.0pp | success_rate +2.5pp, gotos -12, labels -7, irregular_functions -84, native_warnings -254, lines +177, arity_accuracy +4.0pp, type_exact_rate +19.9pp |
| inferred types -> prototypes | ps2-capcom-fighting-evolution | neutral | lines -22 | irregular_functions -106, native_warnings -235, lines -46 | gotos -14, labels -8, irregular_functions -107, native_warnings -235, lines -29 |
| inferred types -> prototypes | ps2-dungeon-game | helps | lines -18, type_exact_rate +8.2pp | irregular_functions -52, native_warnings +169, lines +778, type_exact_rate +3.3pp | gotos -97, labels -67, irregular_functions -58, native_warnings +169, lines +868, type_exact_rate +3.3pp |
| inferred types -> prototypes | psx-darkstalkers-3 | neutral | no change | irregular_functions -42, native_warnings -179, lines -74 | gotos -14, labels -9, irregular_functions -43, native_warnings -179, lines -51 |
| inferred types -> prototypes | psv-need-for-speed-most-wanted | neutral | no change | no change | success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| inferred types -> prototypes | x360-black-ops-2 | hurts | success_rate -0.5pp~, irregular_functions +7, native_warnings +29, text_warnings +5, lines +55 | success_rate -2.5pp, gotos -2, labels -1, irregular_functions -90, native_warnings -455, text_warnings -3, lines +240 | success_rate -2.5pp, gotos -43, labels -20, irregular_functions -90, native_warnings -455, text_warnings -3, lines +285 |
| inferred types -> prototypes | gc-animal-crossing | neutral | native_warnings +1~, lines +5 | irregular_functions -85, native_warnings -299, lines +511 | gotos -42, labels -18, irregular_functions -86, native_warnings -299, lines +563 |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | default | 1.0000 | 20 | 7 | 189 | 808 | 6243 | 0.9737 | 0.9904 | 0.9750 | 0.2633 | 0.0000 | 0.6414 | 0.5160 |
| gba-pokeemerald | baseline-off | 0.9650 | 93 | 37 | 183 | 775 | 6071 | 0.9504 | 0.9901 | 0.9400 | 0.2580 | – | – | 0.4860 |
| gba-pokeemerald | ir-none | 1.0000 | 23 | 8 | 189 | 808 | 6235 | – | – | 0.9750 | 0.2633 | 0.0000 | 0.6441 | 0.5160 |
| gba-pokeemerald | ir-only-structure | 1.0000 | 20 | 7 | 189 | 808 | 6238 | – | – | 0.9750 | 0.2633 | 0.0000 | 0.6441 | 0.5200 |
| gba-pokeemerald | ir-only-canonical_helpers | 1.0000 | 23 | 8 | 189 | 808 | 6235 | – | – | 0.9750 | 0.2633 | 0.0000 | 0.6441 | 0.5180 |
| gba-pokeemerald | ir-only-additive_inverse | 1.0000 | 23 | 8 | 189 | 808 | 6235 | – | – | 0.9750 | 0.2633 | 0.0000 | 0.6414 | 0.5220 |
| gba-pokeemerald | rust-structuring-none | 1.0000 | 93 | 38 | 189 | 808 | 6193 | – | – | 0.9750 | 0.2633 | 0.0000 | 0.6414 | 0.5230 |
| gba-pokeemerald | switch-vsa-off | 1.0000 | 20 | 7 | 189 | 808 | 6243 | 0.9737 | 0.9904 | 0.9750 | 0.2633 | – | – | 0.5220 |
| gba-pokeemerald | switch-decompiler-off | 1.0000 | 20 | 7 | 189 | 808 | 6243 | 0.9699 | 0.9903 | 0.9750 | 0.2633 | – | – | 0.5140 |
| gba-pokeemerald | register-params | 1.0000 | 20 | 7 | 189 | 808 | 6243 | – | – | 0.9750 | 0.2633 | 0.0000 | 0.6414 | 0.5190 |
| gba-pokeemerald | promote-tailcalls | 1.0000 | 20 | 7 | 189 | 808 | 6243 | 0.9737 | 0.9858 | 0.9750 | 0.2633 | – | – | 0.5230 |
| gba-pokeemerald | infer-prototypes | 1.0000 | 18 | 6 | 189 | 432 | 6313 | – | – | 0.9600 | 0.2580 | – | – | 0.5560 |
| gba-pokeemerald | infer-prototypes+register-params | 1.0000 | 18 | 6 | 189 | 432 | 6313 | – | – | 0.9600 | 0.2580 | – | – | 0.5540 |
| gba-pokeemerald | inferred-types | 1.0000 | 18 | 6 | 189 | 432 | 6316 | – | – | 0.9600 | 0.3723 | – | – | 0.5570 |
| nds-pokeheartgold-arm9 | default | 1.0000 | 0 | 0 | 128 | 342 | 5135 | 0.9729 | 0.9981 | 0.7300 | 0.4154 | – | – | 0.5220 |
| nds-pokeheartgold-arm9 | baseline-off | 0.9750 | 12 | 7 | 125 | 333 | 4922 | 0.9504 | 0.9976 | 0.7200 | 0.4062 | – | – | 0.5050 |
| nds-pokeheartgold-arm9 | ir-none | 1.0000 | 0 | 0 | 128 | 342 | 5135 | – | – | 0.7300 | 0.4154 | – | – | 0.5240 |
| nds-pokeheartgold-arm9 | ir-only-structure | 1.0000 | 0 | 0 | 128 | 342 | 5135 | – | – | 0.7300 | 0.4154 | – | – | 0.5270 |
| nds-pokeheartgold-arm9 | ir-only-canonical_helpers | 1.0000 | 0 | 0 | 128 | 342 | 5135 | – | – | 0.7300 | 0.4154 | – | – | 0.5260 |
| nds-pokeheartgold-arm9 | ir-only-additive_inverse | 1.0000 | 0 | 0 | 128 | 342 | 5135 | – | – | 0.7300 | 0.4154 | – | – | 0.5240 |
| nds-pokeheartgold-arm9 | rust-structuring-none | 1.0000 | 12 | 7 | 129 | 342 | 5117 | – | – | 0.7300 | 0.4154 | – | – | 0.5300 |
| nds-pokeheartgold-arm9 | switch-vsa-off | 1.0000 | 0 | 0 | 128 | 342 | 5135 | 0.9729 | 0.9981 | 0.7300 | 0.4154 | – | – | 0.5190 |
| nds-pokeheartgold-arm9 | switch-decompiler-off | 0.9950 | 0 | 0 | 127 | 340 | 5069 | 0.9682 | 0.9978 | 0.7300 | 0.4136 | – | – | 0.5180 |
| nds-pokeheartgold-arm9 | register-params | 1.0000 | 0 | 0 | 128 | 342 | 5135 | – | – | 0.7300 | 0.4154 | – | – | 0.5260 |
| nds-pokeheartgold-arm9 | promote-tailcalls | 1.0000 | 0 | 0 | 128 | 342 | 5135 | 0.9729 | 0.9976 | 0.7300 | 0.4154 | – | – | 0.5260 |
| nds-pokeheartgold-arm9 | infer-prototypes | 1.0000 | 0 | 0 | 43 | 83 | 5273 | – | – | 0.7600 | 0.4929 | – | – | 0.5410 |
| nds-pokeheartgold-arm9 | infer-prototypes+register-params | 1.0000 | 0 | 0 | 43 | 83 | 5273 | – | – | 0.7600 | 0.4929 | – | – | 0.5480 |
| nds-pokeheartgold-arm9 | inferred-types | 1.0000 | 0 | 0 | 43 | 83 | 5302 | – | – | 0.7600 | 0.6050 | – | – | 0.5470 |
| ps2-capcom-fighting-evolution | default | 1.0000 | 11 | 5 | 148 | 366 | 6467 | 0.9412 | 0.9964 | – | – | – | – | 0.2200 |
| ps2-capcom-fighting-evolution | baseline-off | 1.0000 | 25 | 13 | 149 | 366 | 6450 | 0.9435 | 0.9867 | – | – | – | – | 0.2150 |
| ps2-capcom-fighting-evolution | ir-none | 1.0000 | 11 | 5 | 148 | 366 | 6467 | – | – | – | – | – | – | 0.2170 |
| ps2-capcom-fighting-evolution | ir-only-structure | 1.0000 | 11 | 5 | 148 | 366 | 6467 | – | – | – | – | – | – | 0.2190 |
| ps2-capcom-fighting-evolution | ir-only-canonical_helpers | 1.0000 | 11 | 5 | 148 | 366 | 6467 | – | – | – | – | – | – | 0.2190 |
| ps2-capcom-fighting-evolution | ir-only-additive_inverse | 1.0000 | 11 | 5 | 148 | 366 | 6467 | – | – | – | – | – | – | 0.2180 |
| ps2-capcom-fighting-evolution | rust-structuring-none | 1.0000 | 25 | 13 | 149 | 366 | 6450 | – | – | – | – | – | – | 0.2200 |
| ps2-capcom-fighting-evolution | switch-vsa-off | 1.0000 | 11 | 5 | 148 | 366 | 6467 | 0.9412 | 0.9964 | – | – | – | – | 0.2190 |
| ps2-capcom-fighting-evolution | switch-decompiler-off | 1.0000 | 11 | 5 | 148 | 366 | 6467 | 0.9439 | 0.9867 | – | – | – | – | 0.2160 |
| ps2-capcom-fighting-evolution | register-params | 1.0000 | 11 | 5 | 148 | 366 | 6467 | – | – | – | – | – | – | 0.2180 |
| ps2-capcom-fighting-evolution | promote-tailcalls | 1.0000 | 11 | 5 | 148 | 370 | 6495 | 0.9421 | 0.9625 | – | – | – | – | 0.2260 |
| ps2-capcom-fighting-evolution | infer-prototypes | 1.0000 | 11 | 5 | 42 | 131 | 6443 | – | – | – | – | – | – | 0.2360 |
| ps2-capcom-fighting-evolution | infer-prototypes+register-params | 1.0000 | 11 | 5 | 42 | 131 | 6443 | – | – | – | – | – | – | 0.2350 |
| ps2-capcom-fighting-evolution | inferred-types | 1.0000 | 11 | 5 | 42 | 131 | 6421 | – | – | – | – | – | – | 0.2380 |
| ps2-dungeon-game | default | 1.0000 | 45 | 24 | 124 | 403 | 12344 | 0.9438 | 0.9880 | 1.0000 | 0.3934 | – | – | 0.0750 |
| ps2-dungeon-game | baseline-off | 1.0000 | 142 | 91 | 130 | 403 | 12254 | 0.9438 | 0.9192 | 1.0000 | 0.3934 | – | – | 0.0740 |
| ps2-dungeon-game | ir-none | 1.0000 | 50 | 29 | 124 | 403 | 12352 | – | – | 1.0000 | 0.3934 | – | – | 0.0730 |
| ps2-dungeon-game | ir-only-structure | 1.0000 | 45 | 24 | 124 | 403 | 12344 | – | – | 1.0000 | 0.3934 | – | – | 0.0740 |
| ps2-dungeon-game | ir-only-canonical_helpers | 1.0000 | 50 | 29 | 124 | 403 | 12352 | – | – | 1.0000 | 0.3934 | – | – | 0.0720 |
| ps2-dungeon-game | ir-only-additive_inverse | 1.0000 | 50 | 29 | 124 | 403 | 12352 | – | – | 1.0000 | 0.3934 | – | – | 0.0740 |
| ps2-dungeon-game | rust-structuring-none | 1.0000 | 139 | 89 | 130 | 403 | 12250 | – | – | 1.0000 | 0.3934 | – | – | 0.0740 |
| ps2-dungeon-game | switch-vsa-off | 1.0000 | 45 | 24 | 124 | 403 | 12344 | 0.9438 | 0.9880 | 1.0000 | 0.3934 | – | – | 0.0750 |
| ps2-dungeon-game | switch-decompiler-off | 1.0000 | 45 | 24 | 124 | 403 | 12344 | 0.9438 | 0.9237 | 1.0000 | 0.3934 | – | – | 0.0750 |
| ps2-dungeon-game | register-params | 1.0000 | 45 | 24 | 124 | 403 | 12344 | – | – | 1.0000 | 0.3934 | – | – | 0.0740 |
| ps2-dungeon-game | promote-tailcalls | 1.0000 | 45 | 24 | 124 | 403 | 12344 | 0.9438 | 0.9840 | 1.0000 | 0.3934 | – | – | 0.0740 |
| ps2-dungeon-game | infer-prototypes | 1.0000 | 45 | 24 | 72 | 572 | 13140 | – | – | 1.0000 | 0.3443 | – | – | 0.0760 |
| ps2-dungeon-game | infer-prototypes+register-params | 1.0000 | 45 | 24 | 72 | 572 | 13140 | – | – | 1.0000 | 0.3443 | – | – | 0.0760 |
| ps2-dungeon-game | inferred-types | 1.0000 | 45 | 24 | 72 | 572 | 13122 | – | – | 1.0000 | 0.4262 | – | – | 0.0760 |
| psx-darkstalkers-3 | default | 1.0000 | 4 | 2 | 156 | 440 | 4420 | 0.9878 | 0.3663 | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | baseline-off | 1.0000 | 18 | 11 | 157 | 440 | 4397 | 0.9866 | 0.3660 | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | ir-none | 1.0000 | 4 | 2 | 156 | 440 | 4420 | – | – | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | ir-only-structure | 1.0000 | 4 | 2 | 156 | 440 | 4420 | – | – | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | ir-only-canonical_helpers | 1.0000 | 4 | 2 | 156 | 440 | 4420 | – | – | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | ir-only-additive_inverse | 1.0000 | 4 | 2 | 156 | 440 | 4420 | – | – | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | rust-structuring-none | 1.0000 | 18 | 11 | 157 | 440 | 4397 | – | – | – | – | – | – | 0.0840 |
| psx-darkstalkers-3 | switch-vsa-off | 1.0000 | 4 | 2 | 156 | 440 | 4420 | 0.9866 | 0.3660 | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | switch-decompiler-off | 1.0000 | 4 | 2 | 156 | 440 | 4420 | 0.9878 | 0.3663 | – | – | – | – | 0.0840 |
| psx-darkstalkers-3 | register-params | 1.0000 | 4 | 2 | 156 | 440 | 4420 | – | – | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | promote-tailcalls | 1.0000 | 4 | 2 | 156 | 440 | 4420 | 0.9878 | 0.3663 | – | – | – | – | 0.0850 |
| psx-darkstalkers-3 | infer-prototypes | 1.0000 | 4 | 2 | 114 | 261 | 4346 | – | – | – | – | – | – | 0.0890 |
| psx-darkstalkers-3 | infer-prototypes+register-params | 1.0000 | 4 | 2 | 114 | 261 | 4346 | – | – | – | – | – | – | 0.0890 |
| psx-darkstalkers-3 | inferred-types | 1.0000 | 4 | 2 | 114 | 261 | 4346 | – | – | – | – | – | – | 0.0890 |
| psv-need-for-speed-most-wanted | default | 1.0000 | 36 | 21 | 112 | 455 | 12908 | 0.9720 | 0.9712 | – | – | – | – | 1.1130 |
| psv-need-for-speed-most-wanted | baseline-off | 0.9900 | 51 | 32 | 113 | 455 | 12861 | 0.9686 | 0.9711 | – | – | – | – | 1.0800 |
| psv-need-for-speed-most-wanted | ir-none | 1.0000 | 41 | 26 | 112 | 455 | 12908 | – | – | – | – | – | – | 1.1090 |
| psv-need-for-speed-most-wanted | ir-only-structure | 1.0000 | 36 | 21 | 112 | 455 | 12909 | – | – | – | – | – | – | 1.1160 |
| psv-need-for-speed-most-wanted | ir-only-canonical_helpers | 1.0000 | 41 | 26 | 112 | 455 | 12908 | – | – | – | – | – | – | 1.1180 |
| psv-need-for-speed-most-wanted | ir-only-additive_inverse | 1.0000 | 41 | 26 | 112 | 455 | 12907 | – | – | – | – | – | – | 1.1010 |
| psv-need-for-speed-most-wanted | rust-structuring-none | 1.0000 | 47 | 27 | 113 | 455 | 12895 | – | – | – | – | – | – | 1.1070 |
| psv-need-for-speed-most-wanted | switch-vsa-off | 1.0000 | 36 | 21 | 112 | 455 | 12908 | 0.9720 | 0.9712 | – | – | – | – | 1.1130 |
| psv-need-for-speed-most-wanted | switch-decompiler-off | 0.9950 | 36 | 21 | 112 | 455 | 12879 | 0.9705 | 0.9712 | – | – | – | – | 1.1040 |
| psv-need-for-speed-most-wanted | register-params | 1.0000 | 36 | 21 | 112 | 455 | 12908 | – | – | – | – | – | – | 1.1080 |
| psv-need-for-speed-most-wanted | promote-tailcalls | 1.0000 | 36 | 21 | 112 | 455 | 12908 | 0.9720 | 0.9712 | – | – | – | – | 1.1250 |
| psv-need-for-speed-most-wanted | infer-prototypes | 1.0000 | 36 | 21 | 112 | 455 | 12908 | – | – | – | – | – | – | 1.0970 |
| psv-need-for-speed-most-wanted | infer-prototypes+register-params | 1.0000 | 36 | 21 | 112 | 455 | 12908 | – | – | – | – | – | – | 1.1110 |
| psv-need-for-speed-most-wanted | inferred-types | 1.0000 | 36 | 21 | 112 | 455 | 12908 | – | – | – | – | – | – | 1.1060 |
| x360-black-ops-2 | default | 0.9600 | 11 | 6 | 158 | 611 | 9432 | 0.9833 | 0.9964 | – | – | – | – | 1.1790 |
| x360-black-ops-2 | baseline-off | 0.9600 | 55 | 27 | 158 | 611 | 9382 | 0.9803 | 0.9964 | – | – | – | – | 1.1610 |
| x360-black-ops-2 | ir-none | 0.9600 | 11 | 6 | 158 | 611 | 9433 | – | – | – | – | – | – | 1.1600 |
| x360-black-ops-2 | ir-only-structure | 0.9600 | 11 | 6 | 158 | 611 | 9433 | – | – | – | – | – | – | 1.1630 |
| x360-black-ops-2 | ir-only-canonical_helpers | 0.9600 | 11 | 6 | 158 | 611 | 9433 | – | – | – | – | – | – | 1.1720 |
| x360-black-ops-2 | ir-only-additive_inverse | 0.9600 | 11 | 6 | 158 | 611 | 9432 | – | – | – | – | – | – | 1.1650 |
| x360-black-ops-2 | rust-structuring-none | 0.9600 | 51 | 26 | 158 | 611 | 9380 | – | – | – | – | – | – | 1.1690 |
| x360-black-ops-2 | switch-vsa-off | 0.9600 | 11 | 6 | 158 | 611 | 9432 | 0.9833 | 0.9964 | – | – | – | – | 1.1790 |
| x360-black-ops-2 | switch-decompiler-off | 0.9600 | 11 | 6 | 158 | 611 | 9432 | 0.9820 | 0.9964 | – | – | – | – | 1.1750 |
| x360-black-ops-2 | register-params | 0.9600 | 11 | 6 | 158 | 611 | 9432 | – | – | – | – | – | – | 1.1610 |
| x360-black-ops-2 | promote-tailcalls | 0.9600 | 11 | 6 | 159 | 612 | 9419 | 0.9833 | 0.9964 | – | – | – | – | 1.1680 |
| x360-black-ops-2 | infer-prototypes | 0.9400 | 7 | 4 | 56 | 67 | 8946 | – | – | – | – | – | – | 1.2430 |
| x360-black-ops-2 | infer-prototypes+register-params | 0.9400 | 7 | 4 | 56 | 67 | 8946 | – | – | – | – | – | – | 1.2320 |
| x360-black-ops-2 | inferred-types | 0.9350 | 7 | 4 | 63 | 96 | 8930 | – | – | – | – | – | – | 1.2380 |
| gc-animal-crossing | default | 0.9900 | 44 | 15 | 134 | 465 | 9262 | – | – | – | – | – | – | 0.1630 |
| gc-animal-crossing | baseline-off | 0.9900 | 86 | 33 | 135 | 465 | 9210 | – | – | – | – | – | – | 0.1590 |
| gc-animal-crossing | ir-none | 0.9900 | 45 | 15 | 134 | 465 | 9256 | – | – | – | – | – | – | 0.1610 |
| gc-animal-crossing | ir-only-structure | 0.9900 | 44 | 15 | 134 | 465 | 9261 | – | – | – | – | – | – | 0.1600 |
| gc-animal-crossing | ir-only-canonical_helpers | 0.9900 | 45 | 15 | 134 | 465 | 9256 | – | – | – | – | – | – | 0.1590 |
| gc-animal-crossing | ir-only-additive_inverse | 0.9900 | 45 | 15 | 134 | 465 | 9257 | – | – | – | – | – | – | 0.1610 |
| gc-animal-crossing | rust-structuring-none | 0.9900 | 82 | 32 | 135 | 465 | 9210 | – | – | – | – | – | – | 0.1600 |
| gc-animal-crossing | switch-vsa-off | 0.9900 | 44 | 15 | 134 | 465 | 9262 | – | – | – | – | – | – | 0.1610 |
| gc-animal-crossing | switch-decompiler-off | 0.9900 | 44 | 15 | 134 | 465 | 9262 | – | – | – | – | – | – | 0.1630 |
| gc-animal-crossing | register-params | 0.9900 | 44 | 15 | 134 | 465 | 9262 | – | – | – | – | – | – | 0.1600 |
| gc-animal-crossing | promote-tailcalls | 0.9900 | 44 | 15 | 135 | 468 | 9261 | – | – | – | – | – | – | 0.1620 |
| gc-animal-crossing | infer-prototypes | 0.9900 | 44 | 15 | 49 | 165 | 9768 | – | – | – | – | – | – | 0.1670 |
| gc-animal-crossing | infer-prototypes+register-params | 0.9900 | 44 | 15 | 49 | 165 | 9768 | – | – | – | – | – | – | 0.1670 |
| gc-animal-crossing | inferred-types | 0.9900 | 44 | 15 | 49 | 166 | 9773 | – | – | – | – | – | – | 0.1680 |
