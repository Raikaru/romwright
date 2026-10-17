# Console research components (2026-10-08T16:29:54+00:00)

Tools fingerprint `08df1a6eff7987ed`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | psv-need-for-speed-most-wanted |
|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps |
| inferred types -> prototypes | inferred-types-off | infer-prototypes | neutral |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | psv-need-for-speed-most-wanted | helps | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -15, labels -11, irregular_functions -1~, lines +9 |
| persisted prototypes (infer_prototypes job) | psv-need-for-speed-most-wanted | helps | irregular_functions -43, native_warnings -176, lines +107 | irregular_functions -43, native_warnings -176, lines +107 | success_rate +1.0pp, gotos -15, labels -11, irregular_functions -44, native_warnings -176, lines +116 |
| inferred types -> prototypes | psv-need-for-speed-most-wanted | neutral | lines -10 | irregular_functions -43, native_warnings -176, lines +97 | success_rate +1.0pp, gotos -15, labels -11, irregular_functions -44, native_warnings -176, lines +106 |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psv-need-for-speed-most-wanted | default | 1.0000 | 36 | 21 | 112 | 455 | 12908 | 0.9720 | 0.9712 | – | – | – | – | 1.0620 |
| psv-need-for-speed-most-wanted | baseline-off | 0.9900 | 51 | 32 | 113 | 455 | 12861 | 0.9686 | 0.9711 | – | – | – | – | 0.8380 |
| psv-need-for-speed-most-wanted | infer-prototypes | 1.0000 | 36 | 21 | 69 | 279 | 13015 | – | – | – | – | – | – | 0.8330 |
| psv-need-for-speed-most-wanted | inferred-types-off | 1.0000 | 36 | 21 | 69 | 279 | 13005 | – | – | – | – | – | – | 0.8360 |
