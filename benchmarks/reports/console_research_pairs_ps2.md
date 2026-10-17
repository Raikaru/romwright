# Console research components (2026-10-09T19:14:13+00:00)

Tools fingerprint `61a108d4b6fc3e88`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | ps2-capcom-fighting-evolution | ps2-dungeon-game |
|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | ps2-capcom-fighting-evolution | helps | recall -0.2pp~, precision +1.0pp, gotos -7, labels -4, lines +2 | no change | recall -0.2pp~, precision +1.0pp, gotos -7, labels -4, lines +2 |
| all research (default vs baseline-off) | ps2-dungeon-game | helps | precision +6.9pp, gotos -100, labels -69, irregular_functions -6, lines +103 | no change | precision +6.9pp, gotos -100, labels -69, irregular_functions -6, lines +103 |
| persisted prototypes (infer_prototypes job) | ps2-capcom-fighting-evolution | helps | irregular_functions -125, native_warnings -500, lines -222, type_exact_rate +40.0pp | irregular_functions -125, native_warnings -500, lines -222, type_exact_rate +40.0pp | gotos -7, labels -4, irregular_functions -125, native_warnings -500, lines -220, type_exact_rate +40.0pp |
| persisted prototypes (infer_prototypes job) | ps2-dungeon-game | helps | irregular_functions -62, native_warnings -202, lines +35, type_exact_rate +1.6pp | irregular_functions -62, native_warnings -202, lines +35, type_exact_rate +1.6pp | gotos -100, labels -69, irregular_functions -68, native_warnings -202, lines +138, type_exact_rate +1.6pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-capcom-fighting-evolution | default | 1.0000 | 2 | 1 | 159 | 548 | 9720 | 0.9418 | 0.9964 | 1.0000 | 0.5098 | – | – | 0.4080 |
| ps2-capcom-fighting-evolution | baseline-off | 1.0000 | 9 | 5 | 159 | 548 | 9718 | 0.9435 | 0.9867 | 1.0000 | 0.5098 | – | – | 0.5440 |
| ps2-capcom-fighting-evolution | infer-prototypes | 1.0000 | 2 | 1 | 34 | 48 | 9498 | – | – | 1.0000 | 0.9093 | – | – | 0.4640 |
| ps2-dungeon-game | default | 1.0000 | 42 | 22 | 123 | 359 | 11440 | 0.9438 | 0.9880 | 1.0000 | 0.4262 | – | – | 0.1690 |
| ps2-dungeon-game | baseline-off | 1.0000 | 142 | 91 | 129 | 359 | 11337 | 0.9438 | 0.9192 | 1.0000 | 0.4262 | – | – | 0.1720 |
| ps2-dungeon-game | infer-prototypes | 1.0000 | 42 | 22 | 61 | 157 | 11475 | – | – | 1.0000 | 0.4426 | – | – | 0.1770 |
