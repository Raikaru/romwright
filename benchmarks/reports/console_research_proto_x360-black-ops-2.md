# Console research components (2026-10-08T16:29:54+00:00)

Tools fingerprint `08df1a6eff7987ed`; sample n=200 seed=20261006. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | x360-black-ops-2 |
|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps |
| persisted prototypes (infer_prototypes job) | infer-prototypes | default | helps |
| inferred types -> prototypes | inferred-types-off | infer-prototypes | neutral |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | x360-black-ops-2 | helps | recall +0.3pp~, gotos -49, labels -24, lines +54 | no change | recall +0.3pp~, gotos -49, labels -24, lines +54 |
| persisted prototypes (infer_prototypes job) | x360-black-ops-2 | helps | gotos -2, labels -1, irregular_functions -105, native_warnings -558, text_warnings -8, lines +201 | gotos -2, labels -1, irregular_functions -105, native_warnings -558, text_warnings -8, lines +201 | gotos -51, labels -25, irregular_functions -105, native_warnings -558, text_warnings -8, lines +255 |
| inferred types -> prototypes | x360-black-ops-2 | neutral | lines -9 | gotos -2, labels -1, irregular_functions -105, native_warnings -558, text_warnings -8, lines +192 | gotos -51, labels -25, irregular_functions -105, native_warnings -558, text_warnings -8, lines +246 |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| x360-black-ops-2 | default | 1.0000 | 14 | 7 | 166 | 641 | 10193 | 0.9833 | 0.9964 | – | – | – | – | 1.2410 |
| x360-black-ops-2 | baseline-off | 1.0000 | 63 | 31 | 166 | 641 | 10139 | 0.9803 | 0.9964 | – | – | – | – | 1.1530 |
| x360-black-ops-2 | infer-prototypes | 1.0000 | 12 | 6 | 61 | 83 | 10394 | – | – | – | – | – | – | 0.9450 |
| x360-black-ops-2 | inferred-types-off | 1.0000 | 12 | 6 | 61 | 83 | 10385 | – | – | – | – | – | – | 0.9380 |
