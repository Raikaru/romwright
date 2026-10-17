# Console research components (2026-10-09T17:11:29+00:00)

Tools fingerprint `50e639161adfeb6f`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | psv-need-for-speed-most-wanted |
|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps |
| inferred types -> prototypes | inferred-types-off | infer-prototypes | neutral |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | psv-need-for-speed-most-wanted | helps | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -20, labels -13, irregular_functions -1~, lines +23 | no change | recall +0.3pp~, precision +0.0pp~, success_rate +1.0pp, gotos -20, labels -13, irregular_functions -1~, lines +23 |
| persisted prototypes (infer_prototypes job) | psv-need-for-speed-most-wanted | helps | gotos -2, labels -1, irregular_functions -51, native_warnings -199, text_warnings -4, lines -392 | gotos -2, labels -1, irregular_functions -51, native_warnings -199, text_warnings -4, lines -392 | success_rate +1.0pp, gotos -22, labels -14, irregular_functions -52, native_warnings -199, text_warnings -4, lines -369 |
| inferred types -> prototypes | psv-need-for-speed-most-wanted | neutral | lines -32 | gotos -2, labels -1, irregular_functions -51, native_warnings -199, text_warnings -4, lines -424 | success_rate +1.0pp, gotos -22, labels -14, irregular_functions -52, native_warnings -199, text_warnings -4, lines -401 |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| psv-need-for-speed-most-wanted | default | 1.0000 | 26 | 19 | 124 | 505 | 14057 | 0.9731 | 0.9713 | – | – | – | – | 1.1230 |
| psv-need-for-speed-most-wanted | baseline-off | 0.9900 | 46 | 32 | 125 | 505 | 14020 | 0.9697 | 0.9712 | – | – | – | – | 1.3590 |
| psv-need-for-speed-most-wanted | infer-prototypes | 1.0000 | 24 | 18 | 73 | 306 | 13665 | – | – | – | – | – | – | 1.2560 |
| psv-need-for-speed-most-wanted | inferred-types-off | 1.0000 | 24 | 18 | 73 | 306 | 13633 | – | – | – | – | – | – | 1.0380 |
