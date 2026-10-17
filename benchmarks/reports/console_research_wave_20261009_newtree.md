# Console research wave (2026-10-10T04:54:34+00:00)

Tools fingerprint `e2e3ae408552483e`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-golden-sun | Golden Sun (The Broken Seal) | USA/Europe English (AGSE) -- alchemy edition tbs-en | True | decomp-build | agscc (GCC 2.96 snapshot 2000-07-31, Thumb, -O2 -mthumb-interwork -fcall-used-r4) for game code; pret agbcc for MusicPlayer2000/flash library; agbcc_arm for RAM ARM code | 89.93 | 11884 | 5758 | 0 (0) | main, ov0, ov1, ov2 (+93) | 0 | False | ran |
| gba-nascar-heat-2002 | NASCAR Heat 2002 | USA (ANHE) | True | decomp-build | old_agbcc (Dream-Atelier/agbcc submodule a0f70c9, -O2), arm-none-eabi binutils; libgcc/newlib members compiled from tools/agbcc | 100.0 | 1316 | 1023 | 0 (0) | main, gba:ram.02000000, gba:ram.02000b96 | 0 | False | ran |
| x360-amped-3 | AMPED 3 | 2005-10-15 default build (PyroXenon Release Final Xenon) | True | pdb | Microsoft (R) Optimizing Compiler 14.0.1863 (S_COMPILE3 in PDB); linker 8.0 (pre-release Xenon toolchain) | 100.0 | 36152 | 36152 | 14740 (14740) | main | 0 | False | ran |

## gba

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| gba-golden-sun | default | 0.8873 | 0.9766 | 1.0000 | – | – | 0.9043 | 0.9977 | 984 |
| gba-golden-sun | baseline-off | 0.8875 | 0.9766 | 1.0000 | – | – | 0.9043 | 0.9977 | 984 |
| gba-nascar-heat-2002 | default | 0.8009 | 0.9741 | 1.0000 | – | – | 0.8094 | 0.9869 | 769 |
| gba-nascar-heat-2002 | baseline-off | 0.8009 | 0.9741 | 1.0000 | – | – | 0.8094 | 0.9869 | 769 |

**Sign tests, gba**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision vs baseline-off | 2 | 0 | 0 | 2 | – |
| success_rate vs baseline-off | 2 | 0 | 0 | 2 | – |
| recall_verified vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision_verified vs baseline-off | 2 | 0 | 0 | 2 | – |

## x360

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| x360-amped-3 | default | 0.9756 | 0.9915 | 1.0000 | 0.7727 | 0.3043 | 0.9756 | 0.9931 | 981 |
| x360-amped-3 | baseline-off | 0.9747 | 0.9874 | 1.0000 | 0.7727 | 0.3043 | 0.9747 | 0.9890 | 981 |

**Sign tests, x360**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| arity_accuracy vs baseline-off | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 3 | 0 | 0 | 3 | – |
| precision vs baseline-off | 3 | 0 | 0 | 3 | – |
| success_rate vs baseline-off | 3 | 0 | 0 | 3 | – |
| arity_accuracy vs baseline-off | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 3 | 0 | 0 | 3 | – |
| precision_verified vs baseline-off | 3 | 0 | 0 | 3 | – |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on).

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| gba-golden-sun | 1 | default | 0.8873 | 0.9766 | 1.0000 | – | – | 500 |
| gba-golden-sun | 1 | baseline-off | 0.8875 | 0.9766 | 1.0000 | – | – | 500 |
| gba-golden-sun | 2 | default | 0.8873 | 0.9766 | 1.0000 | – | – | 500 |
| gba-golden-sun | 2 | baseline-off | 0.8875 | 0.9766 | 1.0000 | – | – | 500 |
| gba-nascar-heat-2002 | 1 | default | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| gba-nascar-heat-2002 | 1 | baseline-off | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| gba-nascar-heat-2002 | 2 | default | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| gba-nascar-heat-2002 | 2 | baseline-off | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| x360-amped-3 | 1 | default | 0.9756 | 0.9915 | 1.0000 | 0.7920 | 0.3070 | 500 |
| x360-amped-3 | 1 | baseline-off | 0.9747 | 0.9874 | 1.0000 | 0.7920 | 0.3070 | 500 |
| x360-amped-3 | 2 | default | 0.9756 | 0.9915 | 1.0000 | 0.7580 | 0.2992 | 500 |
| x360-amped-3 | 2 | baseline-off | 0.9747 | 0.9874 | 1.0000 | 0.7580 | 0.2992 | 500 |


# Console research components (2026-10-10T04:54:34+00:00)

Tools fingerprint `e2e3ae408552483e`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-golden-sun | gba-nascar-heat-2002 | x360-amped-3 |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-golden-sun | helps | recall -0.0pp~, gotos -80, labels -38, irregular_functions -1~, lines +143 | no change | recall -0.0pp~, gotos -80, labels -38, irregular_functions -1~, lines +143 |
| all research (default vs baseline-off) | gba-nascar-heat-2002 | helps | gotos -149, labels -75, irregular_functions -4~, lines +252 | no change | gotos -149, labels -75, irregular_functions -4~, lines +252 |
| all research (default vs baseline-off) | x360-amped-3 | helps | recall +0.1pp~, precision +0.4pp~, gotos -318, labels -154, irregular_functions -3~, lines +563, recall_verified +0.1pp, precision_verified +0.4pp | no change | recall +0.1pp~, precision +0.4pp~, gotos -318, labels -154, irregular_functions -3~, lines +563, recall_verified +0.1pp, precision_verified +0.4pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-golden-sun | default | 1.0000 | 42 | 19 | 972 | 3876 | 30388 | 0.8873 | 0.9766 | – | – | – | – | 0.4200 |
| gba-golden-sun | baseline-off | 1.0000 | 122 | 57 | 973 | 3876 | 30245 | 0.8875 | 0.9766 | – | – | – | – | 0.3140 |
| gba-nascar-heat-2002 | default | 1.0000 | 122 | 66 | 612 | 2197 | 30379 | 0.8009 | 0.9741 | – | – | – | – | 0.1210 |
| gba-nascar-heat-2002 | baseline-off | 1.0000 | 271 | 141 | 616 | 2197 | 30127 | 0.8009 | 0.9741 | – | – | – | – | 0.1560 |
| x360-amped-3 | default | 1.0000 | 145 | 82 | 806 | 3699 | 59801 | 0.9756 | 0.9915 | 0.7727 | 0.3043 | – | – | 1.2310 |
| x360-amped-3 | baseline-off | 1.0000 | 463 | 236 | 809 | 3699 | 59238 | 0.9747 | 0.9874 | 0.7727 | 0.3043 | – | – | 1.2450 |
