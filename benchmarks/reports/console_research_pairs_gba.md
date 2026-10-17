# Console research components (2026-10-09T19:32:32+00:00)

Tools fingerprint `61a108d4b6fc3e88`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-pokeemerald |
|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-pokeemerald | helps | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -50, labels -21, lines +13, arity_accuracy +3.5pp, type_exact_rate +1.9pp | no change | recall +2.3pp, precision +0.0pp~, success_rate +3.5pp, gotos -50, labels -21, lines +13, arity_accuracy +3.5pp, type_exact_rate +1.9pp |
| persisted prototypes (infer_prototypes job) | gba-pokeemerald | helps | native_warnings -372, lines -33, arity_accuracy +0.5pp, type_exact_rate +8.0pp | native_warnings -372, lines -33, arity_accuracy +0.5pp, type_exact_rate +8.0pp | success_rate +3.5pp, gotos -50, labels -21, native_warnings -352, lines -20, arity_accuracy +4.0pp, type_exact_rate +9.9pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | default | 1.0000 | 4 | 2 | 189 | 570 | 5713 | 0.9736 | 0.9971 | 0.9700 | 0.6160 | – | – | 1.2060 |
| gba-pokeemerald | baseline-off | 0.9650 | 54 | 23 | 183 | 544 | 5581 | 0.9503 | 0.9970 | 0.9350 | 0.5973 | – | – | 1.0560 |
| gba-pokeemerald | infer-prototypes | 1.0000 | 4 | 2 | 189 | 198 | 5680 | – | – | 0.9750 | 0.6960 | – | – | 0.9890 |
