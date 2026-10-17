# Console research: what helps, measured

Question: how well does the decompiler research help console games?
Every number below comes from a committed report or a `STATUS.md` entry
named next to it. Nothing here is estimated. Anything not observed is marked
`[INFERENCE]`.

Short answer, as measured on the final tree:

- **Printed C, structure.** The research prints far fewer gotos on every
  console image. Default against the same tree with research off: 482 -> 171
  gotos and 251 -> 80 labels over the 8 images' 200-function samples. The Rust
  structuring models account for 296 of those 311 gotos. Compile check on
  the gate set: 0 functions with a gcc diagnostic Ghidra's structure lacks
  (SB). No test measures that the C matches the original source better: m22
  objdiff similarity on pokeemerald moves 64.142 -> 64.143.
- **Import (functions found).** Precision rose by up to 5.8 pp (dungeon) on
  the seven scored images, with recall within 0.4 pp of pass 1. The
  switch-table work (either recoverer) makes up to 3.5 pp more of a GBA sample
  decompile at all.
- **Prototypes and types.** In the final run (F) the `infer_prototypes` job
  helps on 4 images (nds, capcom, psx, gc), is mixed on 3 (gba, dungeon,
  x360) and did not finish on Vita. The two reruns with a raised budget
  (X for x360, V for Vita) both read `helps`: x360 irregular 166 -> 61,
  native warnings 641 -> 83; Vita irregular 112 -> 69, native warnings
  455 -> 279. The inferred-types step adds 8-11 pp of DWARF-exact parameter
  types on the three images that have DWARF. Its one regression in F (x360)
  was a job-budget artefact plus an emitter defect, now fixed: in X, and in V
  for Vita, types on against types off is `neutral` in the printed C (Vita
  has no DWARF, so its type accuracy is unmeasured).
  **`ROMWRIGHT_INFERRED_TYPES` is now on by default** (`=0` turns it off for
  ablation; harness config `inferred-types-off`), per S:Inferred parameter
  types are on in `infer_prototypes`.
- **Not helping:** register parameters (no output change anywhere), the
  `canonical_helpers` and `additive_inverse` passes, tail-call promotion
  (hurts Capcom precision by 3.4 pp, helps nowhere), and VSA in isolation
  (no output change anywhere when the decompiler path stays on). Details in
  [What does not help](#what-does-not-help-on-consoles).
- **Against stock Ghidra (GOAL.md C1):** this study ablates our own
  components. It does not decompile with Ghidra's own front end, so it is not
  a C1 verdict. `baseline-off` is the closest proxy: our import, Ghidra's
  structure and none of the research. For function discovery the Ghidra
  comparison is [import speed](#import-speed-against-ghidra-1213).

## Contents

1. [Method and how to read the numbers](#method-and-how-to-read-the-numbers)
2. [Verdict per console](#verdict-per-console)
3. [Components](#components)
4. [Pass 1 against the final tree](#pass-1-against-the-final-tree)
5. [What does not help on consoles](#what-does-not-help-on-consoles)
6. [Import speed against Ghidra 12.1.3](#import-speed-against-ghidra-1213)
7. [Open issues](#open-issues)
8. [Truth-contract images (`--corpus-wave`)](#truth-contract-images---corpus-wave-2026-10-09-harnesswave)
9. [Reproduce](#reproduce)
10. [Windows PC (PE / x86)](#windows-pc-pe--x86-truth-fixtures-discovery-against-stock-ghidra-compiler-detection-2026-10-15-pcimport)

Sources, cited by tag:

| tag | file |
|---|---|
| **F** | `benchmarks/reports/console_research_final.{json,md}` (2026-10-08T12:31:43+00:00, tools `cdbbf0f7d1273898`) |
| **P1** | `benchmarks/reports/console_research.{json,md}` (2026-10-07T02:07:52+00:00, tools `23c94218619e781c`, the original tree) |
| **IS** | `benchmarks/reports/import-speed.{json,md}`, regenerated on the final tree: recorded 2026-10-08T16:57:11+00:00, tools `df1615627a4ff383`. The earlier snapshot (2026-10-07T21:21:49+00:00, tools `55b5a2a8be92e7e5`) is called **IS0** |
| **X** | `benchmarks/reports/console_research_proto_x360-black-ops-2.{json,md}` (2026-10-08T16:29:54+00:00, tools `08df1a6eff7987ed`): x360 rerun with the job budget raised, configs default, baseline-off, infer-prototypes, inferred-types-off |
| **V** | `benchmarks/reports/console_research_proto_psv-need-for-speed-most-wanted.{json,md}` (2026-10-08T16:29:54+00:00, tools `08df1a6eff7987ed`): the same four configs on Vita |
| **SB** | `docs/structuring-baseline.md` |
| **PI** | `docs/printer-ir.md` |
| **S:\<heading\>** | the `STATUS.md` entry with that heading (2026-10-06..08) |

## Method and how to read the numbers

`benchmarks/console_research.py` runs each image once per configuration
(docstring: lines 1-59). Each research component is a runtime toggle:

| config (F) | env | meaning |
|---|---|---|
| `default` | none | everything the product runs: IR passes `additive_inverse,canonical_helpers,structure`, Rust structuring `all` (budget 5), switch VSA and decompiler, no tail-call promotion, no register params, no `infer_prototypes` job |
| `baseline-off` | `ROMWRIGHT_IR_PASSES=""`, `ROMWRIGHT_NO_SWITCH_VSA=1`, `ROMWRIGHT_NO_SWITCH_DECOMPILER=1`, `ROMWRIGHT_RUST_STRUCTURING=none` | no IR passes, no switch-table recovery at all, Ghidra's own structure |
| `ir-none`, `ir-only-*` | `ROMWRIGHT_IR_PASSES` | IR pass ablation |
| `rust-structuring-none` | `ROMWRIGHT_RUST_STRUCTURING=none` | Ghidra's structure, byte-identical to PrintC |
| `switch-vsa-off`, `switch-decompiler-off` | `ROMWRIGHT_NO_SWITCH_VSA`, `ROMWRIGHT_NO_SWITCH_DECOMPILER` | one switch recoverer left |
| `register-params` | `ROMWRIGHT_REGISTER_PARAMS=1` | |
| `promote-tailcalls` | `ROMWRIGHT_PROMOTE_TAILCALLS=1` | |
| `infer-prototypes` | none, plus the `infer_prototypes` job | persisted prototypes |
| `infer-prototypes+register-params` | `ROMWRIGHT_REGISTER_PARAMS=1` plus the job | |
| `inferred-types` | `ROMWRIGHT_INFERRED_TYPES=1` plus the job | inferred types merged into prototypes |

Metrics, per image: **n = 200** functions sampled per image, seed 20261006,
drawn from the default import.

- m21 recall and precision against symbol or map truth (import-time configs
  only).
- Printed gotos, labels, `/* irregular */` functions, decompiler warnings and
  lines, from `export-c --address` text (the m2c-shaped C that m22 compiles).
- Decompile success rate.
- DWARF parameter arity and type-slot exact rate, on gba and nds (200
  functions each) and ps2-dungeon (**20** libgcc functions, 61 slots). The
  other five images have no type truth.
- m22 objdiff similarity, on pokeemerald only (33 functions).

Reading the report:

- **Deterministic.** Decompiler output is deterministic, so a difference
  between two configs on the same sample is exact. The thresholds (rates
  0.5 pp, counts 1% of the reference, minimum 1) are a materiality floor, not
  a noise estimate. `~` marks a change below it.
- **Direction.** In F's Deltas table, "vs reference" is *this config minus
  its reference*. For ablations (`ir-none`, `rust-structuring-none`,
  `switch-*-off`) a positive goto delta therefore means the component removes
  gotos. The verdict is already sign-corrected: `helps` means the component
  is good.
- **Goto counts differ by method.** F counts `goto` in `export-c` text. SB
  counts `goto` in the printer's DecompDoc tokens over a different gate set
  (the same console samples plus 200 libc functions). Compare like with like.
- **Samples shift between passes.** The sample is drawn from each tree's
  default import. `baseline-off` is Ghidra's structure in both passes, yet
  its gotos differ (gba 76 in P1, 93 in F; gc 53 and 86). `[INFERENCE]` the
  sample membership moved with discovery. **Compare deltas within one pass,
  never absolutes across passes.**
- **m22 is a weak signal.** Its `context` variant fails for every candidate:
  the generated `context.h` redeclares `memset` under agbcc `-Werror`. m22 is
  user work in progress and was not modified. Only the standalone similarity
  (33 functions) is usable (F, m22 columns; SB "m22 standalone match").
- **Import wall times in F are single runs on a shared host.** The numbers
  are indicative only. STATUS records identical runs differing by up to 30%
  (S:Switch VSA: no table lost, gate note).

## Verdict per console

F's verdict matrix, verbatim (`console_research_final.md`, "Verdict matrix"):

| component | config | reference | gba | nds | capcom | dungeon | psx | psv | x360 | gc |
|---|---|---|---|---|---|---|---|---|---|---|
| all research | default | baseline-off | helps | helps | helps | helps | helps | helps | helps | helps |
| IR passes (all three) | ir-none | default | helps | neutral | neutral | helps | neutral | helps | neutral | helps |
| IR `structure` alone | ir-only-structure | ir-none | helps | neutral | neutral | helps | neutral | helps | neutral | helps |
| IR `canonical_helpers` alone | ir-only-canonical_helpers | ir-none | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| IR `additive_inverse` alone | ir-only-additive_inverse | ir-none | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| Rust structuring | rust-structuring-none | default | helps | helps | helps | helps | helps | helps | helps | helps |
| switch VSA | switch-vsa-off | default | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| switch decompiler | switch-decompiler-off | default | neutral | helps | helps | helps | neutral | helps | neutral | neutral |
| register params (decompile) | register-params | default | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| promote tailcalls | promote-tailcalls | default | neutral | neutral | **hurts** | neutral | neutral | neutral | neutral | neutral |
| persisted prototypes | infer-prototypes | default | mixed | helps | helps | mixed | helps | neutral | mixed | helps |
| register params (persisted) | infer-prototypes+register-params | infer-prototypes | neutral | neutral | neutral | neutral | neutral | neutral | neutral | neutral |
| inferred types | inferred-types | infer-prototypes | helps | helps | neutral | helps | neutral | neutral | **hurts** | neutral |

The same verdicts with the key number, one row per console. All numbers are
from F's "Absolute values" and "Deltas" tables. "X -> Y" is
reference -> config as printed in F. Switch columns give what the **ablation**
costs, so "−1.0 pp" under *decompiler* means turning the decompiler off loses
1.0 pp:

| console | all research | Rust structuring | IR passes | switch VSA | switch decompiler | tail calls | persisted prototypes | inferred types |
|---|---|---|---|---|---|---|---|---|
| **gba-pokeemerald** | helps: gotos 93 -> 20, recall +2.3 pp, success +3.5 pp, arity +3.5 pp | helps: gotos 93 -> 20 | helps: gotos 23 -> 20 | neutral (528 tables answered) | neutral: recall −0.4 pp~ off | neutral: precision −0.5 pp~ | **mixed**: warnings 808 -> 432, arity 0.975 -> 0.960, type exact 0.263 -> 0.258 | helps: type exact 0.258 -> 0.372 |
| **nds-pokeheartgold-arm9** | helps: gotos 12 -> 0, recall +2.2 pp, success +2.5 pp, type exact +0.9 pp | helps: 12 -> 0 | neutral | neutral (341) | helps: success −0.5 pp off | neutral: precision −0.1 pp~ | helps: irregular 128 -> 43, warnings 342 -> 83, arity 0.73 -> 0.76, type exact 0.415 -> 0.493 | helps: type exact 0.493 -> 0.605 |
| **ps2-capcom-fighting-evolution** | helps: precision 0.9867 -> 0.9964, gotos 25 -> 11 | helps: 25 -> 11 | neutral | neutral (126) | helps: precision −1.0 pp off | **hurts: precision 0.9964 -> 0.9625 (−3.4 pp), warnings +4** | helps: irregular 148 -> 42, warnings 366 -> 131 | neutral (lines −22) |
| **ps2-dungeon-game** | helps: precision 0.9192 -> 0.9880 (+6.9 pp), gotos 142 -> 45 | helps: 139 -> 45 | helps: gotos 50 -> 45 | neutral (4) | helps: precision −6.4 pp off | neutral: precision −0.4 pp~ | **mixed**: irregular 124 -> 72 but warnings 403 -> 572, type exact 0.393 -> 0.344 | helps: type exact 0.344 -> 0.426 |
| **psx-darkstalkers-3** | helps: gotos 18 -> 4 (recall +0.1 pp~) | helps: 18 -> 4 | neutral | neutral (19) | neutral | neutral | helps: irregular 156 -> 114, warnings 440 -> 261 | neutral |
| **psv-need-for-speed-most-wanted** | helps: gotos 51 -> 36, success +1.0 pp | helps: 47 -> 36 | helps: 41 -> 36 | neutral (435) | helps: success −0.5 pp off | neutral (no change) | F: **no data** (job hit its 1200 s budget, 0 prototypes changed). **V: helps** (irregular 112 -> 69, native warnings 455 -> 279, success 1.0, gotos 36 / 36) | F: **no data**. **V: neutral** (types on vs off: lines −10, nothing else moves; no Vita DWARF, so type accuracy is unmeasured) |
| **x360-black-ops-2** | helps: gotos 55 -> 11, recall +0.3 pp~ | helps: 51 -> 11 | neutral (lines +1) | neutral (196) | neutral: recall −0.1 pp~ | neutral | F: **mixed** (irregular 158 -> 56, warnings 611 -> 67, success 0.96 -> 0.94). **X: helps** (irregular 166 -> 61, warnings 641 -> 83, success 1.0 both) | F: **hurts** (irregular 56 -> 63, warnings 67 -> 96). **X: neutral** (types on vs off: success 1.0 both, gotos 12 / 12, lines +9) |
| **gc-animal-crossing** | helps: gotos 86 -> 44, labels 33 -> 15 | helps: 82 -> 44 | helps: gotos 45 -> 44 | neutral (94) | neutral | neutral (warnings +3~) | helps: irregular 134 -> 49, warnings 465 -> 165 | neutral |

Register parameters: `neutral` on all 8 images, both at decompile time and
persisted (F matrix rows 8 and 12; every "vs reference" cell reads "no
change").

**x360 cells superseded by X.** F's x360 `persisted prototypes` (mixed) and
`inferred types` (hurts) cells, and the F matrix row above, are from a run
where the type-merge job hit its 1200 s budget in round 2 and one function
failed export on a stale round-2 callee prototype (see the component
section). X reran x360 with a raised job budget and the emitter fix: both
jobs ran 3 rounds to the round limit, and the verdicts are `helps` and
`neutral`. **Vita is superseded the same way by V** (Vita rerun, budget
raised, both jobs 3 rounds to the round limit): `helps` and `neutral`. F's
other six images are unchanged.

## Components

### Structuring: native `structure` cuts

What: the `structure` IR pass forces goto cuts into the structured tree. A cut
is kept only when the printed function has fewer gotos. That is the
StructureGotos guard in `worker.rs` `finalize_document`.

Before the guard (P1, original tree): the pass added gotos on all 8 images
(default over `ir-none`: gba +12, nds +4, capcom +5, dungeon +33, psx +1, psv
+1, x360 +6, gc +85; sum +147). SB (the guard section) records the cause over
about 1,600 console functions: forcing cuts improved 7 functions by 1 goto each
and worsened 28 by 154 gotos in total. The native structurer re-collapses
around the cuts.

Final (F): the same pass removes gotos on four images and is neutral on four.
Default against `ir-none`: gba −3, dungeon −5, psv −5, gc −1 (sum −14); nds,
capcom, psx, x360 unchanged (`ir-only-structure` over `ir-none`: gba −3,
dungeon −5, psv −5, gc −1, rest "no change").

On top of the Rust models it still pays for itself in SB's gate set
(S:Rust printer and structuring are the default; SB "Default cutover"):
consoles 106 -> 91 gotos, total 919 -> 854 (20 functions fewer, none more), at
+34 lines. m22 standalone is unchanged (64.143, 6/33 exact).

**Verdict: small but positive.** It is at most 5 gotos per image. The Rust
models do the real work.

### Structuring: Rust SAILR-style models

What: the worker prints C itself from an exported printer IR (PI). Before
printing, `printc/structure.rs` rewrites Ghidra's structured tree. The models
are `break_continue`, `collapsed_edges`, `switch_tails`, `loop_exits`,
`irreducible_entry`, `else_join`, `sink_join`, with a copy budget of 4 printed
lines per removed goto. Every rewrite is checked against the block graph and
kept only when the goto count drops. The SAILR-style work (Basque et al.,
USENIX Security 2024; worked from the paper only) classifies the remaining
gotos by cause and reverts the commonest. Design: PI. Numbers: SB.

Progress on SB's gate set (8 console samples + 200 libc functions, 1,800
functions, printed DecompDoc gotos):

| step (SB) | consoles gotos / labels | total gotos / labels | functions better / worse |
|---|---:|---:|---:|
| baseline (Ghidra's structure) | 312 / 231 | 1511 / 934 | -- |
| five models, fixed copy bound (6 statements / 3 blocks) | 133 / 107 | 868 / 585 | 176 / 0 |
| + `else_join`, `sink_join`, copy budget 4  | **91 / 78** | **854 / 576** | **187 / 0** |
| + switch `sink_join`, `cond_merge`, `thread_test`, follow-ups until affordable, budget 5 (**`all`, default**) | **84 / 72** | **811 / 551** | **189 / 0** |

Checks on SB's runs (SB "Structuring models", "SAILR-style passes"):

- 0 functions with a gcc diagnostic the baseline lacks (12 configurations x
  1,800 functions).
- 0 functions with more gotos than Ghidra's own structure.
- Printer differential 1800/1800 byte-identical with structuring off.
- m22 standalone 64.142 -> 64.143; m15-001 unchanged at 0.8478 of stock
  (2133 against 2516 unstructured edges; it calls `structuring::structure`,
  which this work does not touch).
- Libc is not a win everywhere: it goes 735 -> 763 gotos when the budget
  replaced the fixed bound, for 531 fewer lines.

F, the 8 console samples, `rust-structuring-none` over `default`:

| image | gotos off -> on | labels off -> on |
|---|---:|---:|
| gba | 93 -> 20 | 38 -> 7 |
| nds | 12 -> 0 | 7 -> 0 |
| capcom | 25 -> 11 | 13 -> 5 |
| dungeon | 139 -> 45 | 89 -> 24 |
| psx | 18 -> 4 | 11 -> 2 |
| psv | 47 -> 36 | 27 -> 21 |
| x360 | 51 -> 11 | 26 -> 6 |
| gc | 82 -> 44 | 32 -> 15 |
| **sum** | **467 -> 171** | |

(F "Absolute values". The sum is mine.) The models add printed lines: +50
gba, +18 nds, +17 capcom, +94 dungeon, +23 psx, +13 psv, +52 x360, +52 gc
(default lines minus `rust-structuring-none` lines, F "Absolute values").

Remaining on consoles (`all`, 84 by cause, SB "Fake-match metric and the goto
passes"): into_loop 28, loop_exit 18, cross_arm 11, exit_nested 8, into_arm
7, skip_after 5, backward 6, other 1. Judged against real source
(`benchmarks/spurious_gotos.py`: pokeemerald and pokeheartgold, functions
whose C has no goto but whose printed C does): Ghidra's structure 31
spurious functions / 67 gotos on the gate set's 424 scored functions, the
former default 1 / 1, now 0 / 0; on the final export's samples 34 / 81 ->
6 / 14 -> 3 / 4. Not built: loop re-rolling, switch-lowering reversal (it
removes no goto by itself).

### IR passes `canonical_helpers` and `additive_inverse`

F: each pass alone against `ir-none` is `neutral` on all 8 images. The only
differences are ±1 printed line (x360, psv, gc) and, on gba, an m22 standalone
move of −0.3 pp~ for `additive_inverse` alone (0.6441 -> 0.6414). That is
below the harness threshold and matches SB's cached 64.14 (default) against
64.40 (`ir-none`). P1 had the same result (`neutral` everywhere).

**Verdict: no measurable effect on consoles.** `additive_inverse` is
marginally negative on m22, within the threshold.

### Switch-table recovery: VSA against the decompiler

What: value-set analysis (`native/vsa.rs`, `native/switch_tables.rs`) answers
jump-table dispatches directly. The decompiler recovers the rest. Both
feed `COMPUTED_JUMP` tables to discovery.

Pass 1 to final:

- **Before** (S:Switch VSA answers console dispatches): VSA resolved 0 tables
  on every console image except NDS (261). P1's `vsa_resolved` column agrees:
  0 everywhere but NDS 261. Causes found, per ISA: MIPS delay-slot index
  scaling, PowerPC conditional return (`bgtlr`) and CR packing, GBA literal
  pools, Vita `tbb/tbh` via CALLOTHER, NDS `addls pc`.
- **After** (S:Switch tables: truth to the binary decides, gate table, tag
  `h5`): VSA keeps gba 528, vita 435, nds 341, x360 196, capcom 126, gc 94,
  psx 19, dungeon 4 tables. F's `switch_stats.vsa_resolved` equals these.
  The GBA hand-off fix alone took VSA-kept tables from 0 to 528 of 563 (it had
  counted Thumb `pop {rX}; bx rX` returns as unanswered dispatches).
- Policy changed to "truth to the binary, not agreement with Ghidra". Ghidra's
  folded default entry (guard target, no case label) is not a switch target,
  so VSA no longer appends one and the worker drops the unlabelled trailing
  entry. Of the tables that differed at some point, per-image rulings (summed
  from S:Switch tables, per-image table): VSA right 2 (nds 1, x360 1),
  decompiler right 23 (gc 4, nds 13, vita 6), both once the default is dropped
  74, neither exact 1 (nds `__strtoul`, sound superset kept). No table is
  A-only on any image.
- m13 (libc), before the 10-08 rulings (S:Switch VSA: no table lost): VSA
  branches 0 -> 38 at soundness 1.0, 37 agreeing with stock. **Re-run on the
  current tree (2026-10-08, host load 9-15 on 8 vCPUs,
  `benchmarks/reports/m13-001-rerun-20261008.json`, S:Ownership metric and m13 rerun):** stock
  132 dispatches at soundness 0.981; VSA alone 41 at 1.0, 30 agreeing with
  stock, none beyond it; interpreter (`ROMWRIGHT_SJA=1`) 67 at 1.0; decompiler
  alone 126 at 0.9977 (1 beyond stock, 7 of stock missed); combined 130 at
  0.9978 (1 beyond, 3 of stock missed, 114 agreeing). Both pre-existing
  failures stand: interpreter 67 < decompiler 126, combined 130 not above
  stock 132. VSA soundness (1.0) and phase time (2.6 s) pass.
  **Re-run after the decompiler-off fix (2026-10-09, S:m13 gaps,
  `benchmarks/reports/m13-001-rerun-20261009.json`, before:
  `...-before-fix.json`, host load 14-16):** the interpreter's 67 was a
  defect, not a reach limit: a table that reached code not decoded yet, or a
  dispatch in the last switch round, was left to a decompiler pass that
  `ROMWRIGHT_NO_SWITCH_DECOMPILER=1` had switched off, and so recorded by
  nobody (`switch_tables.rs`, `decompiler_follows`). Now VSA alone 92 (was
  41, soundness 1.0), interpreter 134 at 1.0 (was 67; 23 beyond stock, 21 of
  stock missed; phase 4.9 s), decompiler 130, combined 130 unchanged. The
  interpreter checks pass; **one failure stands: combined 130 not above
  stock 132.** Per case, and the `ROMWRIGHT_SJA=1` combined number (150), in
  STATUS.md "m13 gaps".

- Stored tables reach the decompiler (2026-10-09, S:Stored switch tables fed
  to the decompiler, `docs/ownership.md`): the tables the import stores are now
  the authority for the decompile-time `switch`, and `jumptable.cc` only labels
  and folds guards. Census over the 8 images (sample 55 of 55 printed switches
  supplied by the stored table; 2666 of 2667 over every function holding one):
  `jumptable.cc` alone agreed with the stored address set on 2661 and differed
  on 2 (nds 0x20a7514, x360 0x823bff98); for seven more stored tables it
  failed or removed the switch. Rulings from the bytes: stored right on seven classes
  (capcom 0x1a2d6c and 0x20c9b4, dungeon 0x129d10, x360 0x823bff98 and
  0x827c8864 applied; nds 0x20a7514, 0x2001764 and 0x2001794 kept as
  `jumptable.cc` prints them because the override has no normalized switch
  variable), decompiler right on one (psv 0x8140c5d8, a superset recovered with
  the `unreachable` action off). Gotos, compile diagnostics, m22 standalone
  (64.14, 6/33), m15 and the printer differential (1800/1800) are unchanged;
  m13 (import-time recovery, never fed) is as in its rerun.

Effect on decompiled output and discovery (F):

| image | VSA off: effect (vs default) | decompiler off, VSA only (vs default) | both off (`baseline-off`) vs default |
|---|---|---|---|
| gba | no change | recall −0.4 pp~ | recall −2.3 pp, success −3.5 pp, arity −3.5 pp |
| nds | no change | recall −0.5 pp~, success −0.5 pp | recall −2.2 pp, success −2.5 pp |
| capcom | no change | **precision −1.0 pp** | precision −1.0 pp |
| dungeon | no change | **precision −6.4 pp** | precision −6.9 pp |
| psx | recall −0.1 pp~ | no change | recall −0.1 pp~ |
| psv | no change | success −0.5 pp | success −1.0 pp |
| x360 | no change | recall −0.1 pp~ | recall −0.3 pp~ |
| gc | no change | no change | no change |

(The two middle columns are F "vs default" for `switch-vsa-off` and
`switch-decompiler-off`. The last column is `default` "vs baseline-off" with
the sign flipped.)

Reading it plainly:

- **Switch recovery as a whole matters.** With neither recoverer, 7 of 200
  GBA functions and 5 of 200 NDS functions fail to decompile (success 0.965
  against 1.0, 0.975 against 1.0). Capcom and dungeon lose 1.0 and 6.9 pp of
  precision, because case blocks stay as invented functions.
- **Either recoverer alone recovers almost all of the GBA, NDS and Vita
  gain.** VSA alone gets GBA to 0.9699 recall (default 0.9737). On Capcom and
  dungeon the
  decompiler is still needed: VSA answers 126 of Capcom's tables and 4 of
  dungeon's 13 (S: gate table, tables A/B 12/13 for dungeon).
- **VSA-off shows no material change on any image**, although VSA finds
  tables the decompiler does not: with VSA off the tables are 12 against 13
  (dungeon), 466/468 (capcom), 1459/1464 (nds), 603/606 (vita), 247/248
  (x360) and 0/19 (psx) (S:Switch tables, gate table, tag `h5`). Those extra
  tables do not move recall or precision past the harness threshold (psx
  recall moves +0.1 pp~, 0.9866 -> 0.9878 in that gate).
- **Import wall time (F, single runs, shared host).**

| image | default s | VSA off s | decompiler off (VSA only) s | both off s |
|---|---:|---:|---:|---:|
| gba | 60.6 | 59.5 | 47.8 | 45.2 |
| nds | 99.7 | 100.9 | 41.6 | 30.1 |
| capcom | 38.2 | 38.5 | 7.5 | 7.1 |
| dungeon | 2.2 | 2.2 | 1.6 | 1.6 |
| psx | 2.1 | 1.9 | 1.7 | 1.5 |
| psv | 169.0 | 213.5 | 56.6 | 51.5 |
| x360 | 39.7 | 39.2 | 26.5 | 24.9 |
| gc | 3.6 | 3.5 | 2.7 | 2.3 |

VSA-only imports are 1.2-5.1x faster than default (capcom 7.5 against 38.2;
nds 41.6 against 99.7; psv 56.6 against 169.0) but pay the precision loss
above on dungeon and capcom. Only Vita shows VSA itself saving time
(213.5 -> 169.0 s). The tree's own gate records the same: the switch phase
"barely moves" on capcom, nds and gba because most dispatches still need the
decompiler (S:Switch VSA answers console dispatches, "Not done").

**Verdict.** VSA: neutral on every measured output; it keeps 528 (gba), 435
(vita), 341 (nds) and 196 (x360) tables on the four largest images
(19-126 on the rest, 4 on dungeon). The decompiler path: helps (precision on
Capcom and dungeon, one function on nds/psv). Together they take the GBA
sample from 96.5% to 100% decompile success.

### Tail-call promotion (`ROMWRIGHT_PROMOTE_TAILCALLS`)

What: promote a branch target to a function when it has address and flow
evidence (`native/discovery.rs`). Stock Ghidra creates none of these.

| image | recall (promote − default) | precision | native warnings | lines |
|---|---:|---:|---:|---:|
| capcom | +0.1 pp~ | **−3.4 pp** (0.9964 -> 0.9625) | +4 | +28 |
| gba | 0 | −0.5 pp~ (0.9904 -> 0.9858) | 0 | 0 |
| dungeon | 0 | −0.4 pp~ (0.9880 -> 0.9840) | 0 | 0 |
| nds | 0 | −0.1 pp~ | 0 | 0 |
| psx, psv, x360, gc | 0 | 0 | 0 to +3~ | 0 to −13 |

(F: `promote-tailcalls` "vs default"; absolutes from F.) Pass 1 was worse: it
cost Capcom 10.8 pp, gba 1.5 pp and dungeon 0.8 pp of precision (P1:
`promote-tailcalls` "vs default"). The discovery precision rules below
removed most of that. It still **never improves recall by more than 0.1 pp~**.

**Verdict: hurts Capcom, helps nowhere. Keep it off.** GOAL.md keeps
default-enabling M4 passes reserved (GOAL.md:46-47) and this data gives no
argument to change that for consoles.

### Register parameters (`ROMWRIGHT_REGISTER_PARAMS`)

What: commit registers the decompiler's `in_<REG>` evidence names as
parameters, restricted to registers a call destroys
(`register_params.rs`). It was written for the i386 clang `ECX` convention.

F: the decompile-time variant and the persisted variant
(`infer-prototypes+register-params`) change **no metric on any image**: every
"vs reference" cell reads "no change", and the absolute values are identical
row for row (e.g. gba default and `register-params` both 20 gotos, 189
irregular, 808 warnings, 6243 lines, 0.2633 type exact, m22 0.6414; the
persisted rows equal `infer-prototypes`). P1 also: "no change".

`[INFERENCE]` console ABIs (ARM, MIPS, PowerPC) are fully modelled by the
shipped cspecs, so there is no unexplained register input to commit. This
study did not trace why.

**Verdict: neutral on all 8 consoles.** No evidence supports enabling it
there.

### Persisted prototypes (`infer_prototypes` job)

What: a worker-client job decompiles every function in rounds and persists the
decompiler's recovered prototypes, which later decompiles apply.

F, `infer-prototypes` against `default` ("vs reference"):

| image | irregular | native warnings | lines | arity | type exact | verdict |
|---|---:|---:|---:|---:|---:|---|
| gba | 189 -> 189 | **−376** (808 -> 432) | +70 | **−1.5 pp** (0.975 -> 0.960) | −0.5 pp | mixed |
| nds | **−85** (128 -> 43) | −259 | +138 | +3.0 pp | **+7.8 pp** | helps |
| capcom | **−106** (148 -> 42) | −235 | −24 | n/a | n/a | helps |
| dungeon | −52 (124 -> 72) | **+169** (403 -> 572) | **+796** | 0 | **−4.9 pp** (0.393 -> 0.344) | mixed |
| psx | −42 (156 -> 114) | −179 | −74 | n/a | n/a | helps |
| psv | **−43** (112 -> 69) | **−176** (455 -> 279) | +107 | n/a | n/a | F: neutral (job did not finish, 0 changed). **V: helps**, below |
| x360 | **−98** (158 -> 56) | **−490** (611 -> 67) | +193 | n/a | n/a | mixed in F (success −2.0 pp, 0.96 -> 0.94); **helps in X**, below |
| gc | −85 (134 -> 49) | −300 | +506 | n/a | n/a | helps |

The job reports (F, `prototypes.report`): gba analyzed 34,619 changed 20,052;
nds 22,916 / 17,939; capcom 17,510 / 13,007; dungeon 1,449 / 1,043; psx 4,053
/ 2,450; x360 65,466 / 49,006; gc 5,942 / 4,384. All stopped at the round
limit (3). **Vita (psv) in F: analyzed 9,901, changed 0, rounds 0, stop reason
`budget` at 1200.1 s.** F's psv row is an unfinished job, not evidence about
the pass; V replaces it.

**Vita rerun (V).** V reran Vita on the same tree as X (tools
`08df1a6eff7987ed`, 2026-10-08T16:29:54+00:00; the report does not record
the job budget, which the run description gives as 3 h) with configs default, baseline-off,
infer-prototypes and inferred-types-off. Both jobs ran 3 rounds to the round
limit, with 26 decompiler failures each and 0 worker deaths (V,
`prototypes.report`):

| job | analyzed | changed | rounds | stop | failures | worker deaths | recycles | job s |
|---|---:|---:|---:|---|---:|---:|---:|---:|
| infer-prototypes (types on) | 49,510 | 35,596 | 3 | round_limit | 26 | 0 | 86 | 5,201.7 |
| inferred-types-off | 48,958 | 34,289 | 3 | round_limit | 26 | 0 | 84 | 4,605.3 |

Printed C on the 200-function sample (V "Absolute values"):

| config | success | gotos | labels | irregular | warnings | lines |
|---|---:|---:|---:|---:|---:|---:|
| default | 1.0000 | 36 | 21 | 112 | 455 | 12908 |
| baseline-off | 0.9900 | 51 | 32 | 113 | 455 | 12861 |
| infer-prototypes (types on) | 1.0000 | 36 | 21 | 69 | 279 | 13015 |
| inferred-types-off | 1.0000 | 36 | 21 | 69 | 279 | 13005 |

`infer-prototypes` against `default` (V "vs default"): irregular −43, native
warnings −176, lines +107, gotos and success unchanged: verdict **helps**.
Types on against off: lines −10 (types on minus off, V "vs reference"),
nothing else moves: **neutral**. Vita has no DWARF, so type accuracy cannot
be measured on it. The cost of types on is +13.0% job time (5,201.7 s against
4,605.3 s, single runs). V's `default` row equals F's `default` row (36
gotos, 12,908 lines).

**x360 rerun (X).** F's x360 numbers came from a run whose type-merge job hit
its 1200 s budget; X reran x360 on a newer tree with the job budget raised
(10,800,000 ms; the report does not record the budget). Both jobs ran 3
rounds to the round limit (`infer-prototypes` analyzed 65,502, changed
48,998; `inferred-types-off` analyzed 65,466, changed 49,006), 8 decompiler
failures each and 0 worker deaths (X, `prototypes.report`). X's absolute
values, from X "Absolute values":

| config | success | gotos | labels | irregular | warnings | lines | job s |
|---|---:|---:|---:|---:|---:|---:|---:|
| default | 1.0000 | 14 | 7 | 166 | 641 | 10193 | - |
| baseline-off | 1.0000 | 63 | 31 | 166 | 641 | 10139 | - |
| infer-prototypes (types on) | 1.0000 | 12 | 6 | 61 | 83 | 10394 | 1559.9 |
| inferred-types-off | 1.0000 | 12 | 6 | 61 | 83 | 10385 | 1358.2 |

`infer-prototypes` against `default` (X "vs default"): gotos −2, labels −1,
irregular −105 (166 -> 61), native warnings −558 (641 -> 83), text warnings
−8, lines +201: verdict **helps**. The mixed F verdict (success 0.96 -> 0.94)
is gone: success is 1.0000 in every X config.

Note what moved between F and X. X's `default` row (14 gotos, 166 irregular,
641 warnings, 10,193 lines, success 1.0000) differs from F's `default` row
(11, 158, 611, 9,432, success 0.9600) with no config change. The only
change recorded for it is the emitter fix in
`crates/romwright-core/src/emit_m2c/storage.rs`: an in-bounds read aligned to
its own width at its absolute address was refused, which failed export of
x360 `0x8258d150` (S:Inferred parameter types are on in `infer_prototypes`).
`[INFERENCE]` F's 8 failed exports (success 0.96 of 200) and the +761 lines
are the functions that now export; this study did not diff the per-function
results. **Compare X's numbers only with X's.**

Cost, F (`prototypes.seconds`, one run each): the job is the slow stage on
large images (x360 1,172.8 s, gba 303.0 s, capcom 289.5 s, psv 1,200.1 s
budget-stopped; nds 89.2 s, gc 47.2 s, psx 8.4 s, dungeon 26.9 s). With types
on the job is slower: X has 1,559.9 s against 1,358.2 s off (+14.9%, single
runs); S:Inferred parameter types are on records +13-19% on stripped ELF and
x360 local 3,123 -> 3,520 s, because the merge solves every recovered function
once, single-threaded. Under a fixed budget that can cost a round, which is
what happened to F's x360 run.

Robustness: on x360 and gc the job aborted the whole program before the
2026-10-08 fixes. Two native defects (a printer-IR label on an empty block on
gc, a SLEIGH operand-array overflow on the Xenon `vsubuhm` constructor on
x360) and a Rust path that turned one function's crash into the program's
failure were fixed. The job now skips and counts a function whose worker died
(`worker_deaths`). In F, `worker_deaths` is 0 on all 8 images. The 8 x360
refusals are `Bad decompile address` (5) and `FunctionIR operation identity
changed` (3, uninvestigated) (S:`infer_prototypes` survives a worker death).

**Verdict: the largest quality lever after structuring on four images (nds,
capcom, psx, gc), and on x360 once the job finishes (X), but not a clean
win.** It cuts irregular functions by 42-106 (of 200) and
warnings by 179-558 on nds, capcom, psx, gc and x360. It regresses DWARF arity
on gba (−1.5 pp), dungeon warnings (+169) and dungeon type exact (−4.9 pp).
The causes were not investigated in this study. The type merge is the only
component here that moves DWARF type agreement.

### Rust type inference into prototypes (TIE / TRex / BinSub-style)

What:

- `types_infer.rs` (module doc): TIE-shaped constraints over p-code joined
  in a small lattice. Unknown is an answer. 32-bit aware since the Types32
  work: `Machine { pointer_size, stack_pointer }` comes from the cspec.
- `subtype.rs` (module doc): a BinSub-style subtype solver propagates
  capabilities along copies to a fixpoint. A TRex-style structural layer
  covers struct, array and pointer shapes.
- `types_infer/prototypes.rs` merges that into the prototypes the job
  persists. It upgrades `undefined<N>` and register-width `int`/`uint`
  parameters to a pointer on structural evidence, and `undefined<N>` to a
  signed integer on signed evidence. It never changes arity, order, names,
  convention or register, never touches asserted or import-supplied
  prototypes (`protected`), and leaves returns alone.

Measured opt-in against off (F, `inferred-types` against `infer-prototypes`,
i.e. `ROMWRIGHT_INFERRED_TYPES=1` against unset when F was made; the harness
config is now `inferred-types-off`, the ablation):

| image | DWARF type-exact slots off -> on | exact rate | arity | other effects |
|---|---|---:|---:|---|
| gba | 97 -> 140 of 376 | 0.258 -> **0.372** (+11.4 pp) | 0.960 (no change) | lines +3 |
| nds | 277 -> 340 of 562 | 0.493 -> **0.605** (+11.2 pp) | 0.76 (no change) | lines +29 |
| dungeon | 21 -> 26 of 61 | 0.344 -> **0.426** (+8.2 pp) | 1.0 (no change) | lines −18 |
| capcom, psx, psv, gc | no type truth | | | neutral |
| x360 | no type truth | | | F: **hurts** (irregular +7, native warnings +29, success 0.9400 -> 0.9350), caused by the budget stop and the emitter defect. **X: neutral**: success 1.0 both, gotos 12 / 12, irregular 61 / 61, warnings 83 / 83, lines +9 (types on minus off) |

Against `default` (no job) the inferred-types config on gba is type exact
0.3723 against 0.2633 (+10.9 pp), nds 0.6050 against 0.4154 (+19.0 pp),
dungeon 0.4262 against 0.3934 (+3.3 pp) (F, "vs default"). On dungeon it
recovers the −4.9 pp the plain job lost and ends above the default.

Hand-off measurements on **stripped-ELF** imports, recorded in S:Inferred
parameter types are on in `infer_prototypes` (250 DWARF functions): gba exact
0.338 -> 0.462, nds arm9 0.300 -> 0.391. Same entry: no printed pointer was
wrong, no slot went from exact to wrong. The earlier Types32 hand-off measured
false structural pointers on scalar GBA parameters falling from 3,963 to 4 and
67 pointer parameters newly recovered (history://Types32; not in a committed
report: treat as a pointer to where to look).

Limits, measured:

- Absolute exact rates stay low: 37% on gba, 61% on nds, 43% on dungeon.
  Most slots are still wrong (gba 236 of 376 wrong with inferred types, F).
- DWARF truth exists for only three images, and dungeon's is 20 libgcc
  functions.
- **The F x360 regression was not an upgraded slot.** With types on, F's job
  stopped after round 2 (analyzed 62,543, changed 40,950) while the types-off
  job finished round 3 (65,466 / 49,006). At the stop, callee `0x8250f158`
  still had its round-2 arity of 8 (round 3 gives 3), so the decompiler
  printed a word read of a 13-byte string the emitter then refused
  (S:Inferred parameter types are on in `infer_prototypes`). The emitter now
  prints that read. X has both jobs finishing and types on against off is
  `neutral` on x360.
- Vita type accuracy is unmeasured: no DWARF for it. V shows types on against
  off changes nothing in the printed C there (lines −10 only).

Default: `ROMWRIGHT_INFERRED_TYPES` is on in `infer_prototypes` (`=0`
ablates); upgrades are named in the prototype's provenance source
(S:Inferred parameter types are on in `infer_prototypes`).

Default status: see docs/environment.md.

### Discovery precision rules

What (S:Discovery: junk entries refused; S:Discovery: interior entries
retracted): rules that keep data out of the function list.

1. A repeated-byte run limit as in Ghidra's `Disassembler` (17th identical
   instruction refused), calls into fill refused, Thumb-1 entries that do not
   decode refused.
2. `interior_entries`: retract an entry nothing calls and nothing declares
   when it sits inside another function (fallthrough or conditional-branch
   reach, switch case target after its dispatch, MIPS prologue rule). Rules
   were scored offline against truth and kept only when they lost 0-1 true
   entries per image.

Final against pass 1 (m21 recall / precision on the full image, not the
200-function sample; P1 `default` rows and F `default` rows; invented from
STATUS):

| image | recall P1 -> F | precision P1 -> F | invented before -> after |
|---|---|---|---|
| gba | 0.9736 -> 0.9737 | 0.9689 -> **0.9904** (+2.2 pp) | 496 -> 150 |
| nds | 0.9729 -> 0.9729 | 0.9973 -> 0.9981 | 29 -> 21 |
| capcom | 0.9413 -> 0.9412 | 0.9890 -> **0.9964** (+0.7 pp) | 93 -> 30 |
| dungeon | 0.9400 -> **0.9438** | 0.9305 -> **0.9880** (+5.8 pp) | 56 -> 9 |
| psx | 0.9866 -> 0.9878 | 0.3660 -> 0.3663 | 1398 -> 1398 |
| psv | 0.9724 -> 0.9720 | 0.9570 -> **0.9712** (+1.4 pp) | 1157 -> 764 |
| x360 | 0.9833 -> 0.9833 | 0.9956 -> 0.9964 | 121 -> 98 |
| gc | no truth | no truth | 3,019 -> 3,007 functions |

(Invented counts: S:Discovery: junk entries refused (rules off) and
S:Discovery: interior entries retracted (rules on); gc function counts from
the latter.) Costs: Vita loses 11 functions (recall 0.9724 -> 0.9720), Capcom
loses `pl0b_sp23`. Precision on psx is a floor: VS.MAP lists globals only,
and S:Import speed tracked against stock Ghidra documents most of its 1,398
"invented" as real.

Capcom's residual (0.9964 against Ghidra 0.9979): 13 of the 30 invented
functions are real code the truth (FUNC symbols only) cannot see, and 16 more
decode bytes in `.data`. Counted as hits, precision is 0.9978
(S:Discovery: interior entries retracted).

**Verdict: helps.** It is the main reason the final import beats the original
on precision with recall within 0.4 pp. It is also why tail-call promotion
went from −10.8 pp to −3.4 pp on Capcom.

### Speed work

Import-time engineering that made the research affordable. All numbers are
controlled A/B runs recorded in STATUS (shared host, load 5-18):

| change | measured | source |
|---|---|---|
| reference propagation was quadratic (`getCallSpecs`) | GBA 822 s and 1219 s -> 201 s and 207 s; Vita 417 -> 339 s; output identical row for row | S:GBA import 4-6x faster |
| p-code lifted in process (kuna-sleigh) | 246,386 caller lifts, 0 diffs vs console; per 1M instructions caller lifts 38.2 s -> 19.8 s, flow starts 58.9 s -> 18.7 s | S:P-code lifted in process |
| discovery flow decoded in process | 10,511,755 flow answers, 0 differing; total wall gba 191.5 -> 149.5 s, vita 321.7 -> 301.3 s, nds 279.2 -> 214.9 s, gc 21.0 -> 6.9 s | S:Discovery flow decoded in process |
| junk-entry rules + cheaper later walks | gba wall 217 -> 131 -> 88 s (off / rules / rules + walk rework); discovery 70.9 -> 34.6 -> 17.5 s | S:Discovery: junk entries refused |

Net: the gba default import in F took 60.6 s with all research on and 45.2 s
with the switch recoverers off (single runs; P1's 922.7 s for the same image
ran on the original tree under heavy concurrency and is **not** a controlled
comparison).

## Pass 1 against the final tree

P1 is the "before" picture: the original tree, 10 configurations (no
`rust-structuring-none`, no prototype configs). F is the final tree with 14.
Deltas within each pass (`default` against `baseline-off`, "vs baseline-off"
in each report):

| image | P1 gotos | F gotos | P1 labels | F labels | P1 other effects | F other effects |
|---|---:|---:|---:|---:|---|---|
| gba | **+12** | **−73** | 0 | −30 | recall +2.3 pp, success +4.5 pp, arity +4.0 pp | recall +2.3 pp, success +3.5 pp, arity +3.5 pp |
| nds | +4 | **−12** | 0 | −7 | recall +2.2 pp, success +2.5 pp | recall +2.2 pp, success +2.5 pp |
| capcom | +5 | **−14** | +3 | −8 | precision +0.8 pp | precision +1.0 pp |
| dungeon | +33 | **−97** | +9 | −67 | precision +6.6 pp | precision +6.9 pp |
| psx | +1 | **−14** | +1 | −9 | none | recall +0.1 pp~ |
| psv | +1 | **−15** | +1 | −11 | success +1.0 pp | success +1.0 pp |
| x360 | +6 | **−44** | +1 | −21 | recall +0.3 pp~ | recall +0.3 pp~ |
| gc | **+85** | **−42** | +3 | −18 | none | none |
| **sum** | **+147** | **−311** | | **−171** (F) | | |

Verdicts, "all research (default vs baseline-off)": P1 had 5 `mixed` and 3
`hurts` (psx, x360, gc). F has 8 `helps`.

What changed, in cause order:

| change | P1 | F | cause (source) |
|---|---|---|---|
| structure pass | added gotos on 8 of 8 images (+147) | removes 14 (4 images) | forced-cut guard: cuts kept only when printed gotos drop (SB) |
| structuring as a whole | no such config | `rust-structuring-none` -> default: gotos 467 -> 171 (−296) | Rust printer + models, default since 2026-10-07 (S:Rust printer and structuring are the default) |
| switch VSA | 0 tables on 7 of 8 images (nds 261) | 528 / 435 / 341 / 196 / 126 / 94 / 19 / 4 | per-ISA fixes (S:Switch VSA answers console dispatches) |
| decompiler-only recall | gba −2.3 pp, nds −1.1 pp when off | gba −0.4 pp~, nds −0.5 pp~ | VSA now answers what the decompiler did |
| tail-call promotion | hurts gba (−1.5 pp), capcom (−10.8 pp), dungeon (−0.8 pp) precision | hurts capcom (−3.4 pp) only | interior-entry and junk rules |
| precision | see discovery table | dungeon +5.8 pp, gba +2.2 pp, psv +1.4 pp | discovery rules |
| IR-pass verdict | `hurts` on 8 of 8 | `helps` on 4, `neutral` on 4 | same as the structure pass |
| m22 standalone, gba | 64.14 (default) / 64.40 (ir-none) | 0.6414 / 0.6441 | unchanged (SB, F) |
| import speed gate (vs Ghidra 12.1.3) | IS0 (2026-10-07): FAIL, psx and dungeon precision, GBA incomplete; dungeon precision 0.9305 against 0.9863, capcom 0.9890 against 0.9979; NDS CPU 1.12x Ghidra's | IS (2026-10-08): FAIL only on GBA (Ghidra timed out); dungeon 0.9880 against 0.9863, capcom 0.9964 against 0.9979; psx passes on `precision_corroborated` 0.9968 against 1.0000; NDS CPU 0.93x | discovery precision rules (above), PSX corroborated metric (S:PSX precision vs Ghidra...) |
| x360 default export success | 0.9600 | 0.9600 (F); 1.0000 in the later X rerun | emitter fix in `emit_m2c/storage.rs` (S:Inferred parameter types are on in `infer_prototypes`); F and X are different trees, compare each report only with itself |

Note: P1's "IR passes" hurt verdict was entirely the `structure` pass
(`ir-only-structure`: `hurts` on 8 of 8). `canonical_helpers` and
`additive_inverse` were `neutral` then and are `neutral` now.

## What does not help on consoles

Plainly, measured:

- **Register parameters:** zero change on all 8 images, decompile-time and
  persisted. No effect on any metric.
- **`canonical_helpers`:** zero effect (±1 line at most). **`additive_inverse`:**
  zero effect on gotos or DWARF; −0.3 pp~ on m22 standalone.
- **Tail-call promotion:** recall never rises above +0.1 pp~; Capcom precision
  drops 3.4 pp (0.9964 -> 0.9625), +4 warnings, +28 lines. It is the only
  `hurts` in the decompile-side matrix.
- **Switch VSA, as an ablation:** no metric moves on any of the 8 images
  (the decompiler reaches the same tables) and, apart from Vita (169.0 s
  against 213.5 s without it), it does not make the import faster. Its value
  is that it answers 19-528 tables per image (gba 528 .. psx 19) itself,
  which the metrics here do not reward.
- **The native `structure` pass:** at most 5 gotos per image, 0 on four images.
- **Structuring and m22:** 64.142 -> 64.143. It removes gotos, not
  instruction-level mismatch. No metric here shows the C is closer to the
  original source.
- **Type accuracy is still low:** at best 37% (gba), 61% (nds) and 43%
  (dungeon) of parameter slots are DWARF-exact even with inferred types.
- **Prototype persistence is not a free win:** dungeon gets +169 warnings and
  −4.9 pp type exact, gba loses 1.5 pp arity.
- **PSX:** only structuring (18 -> 4 gotos) and prototype persistence
  (irregular 156 -> 114) move anything. Every import-side component is
  neutral there, and its precision (0.366) is a floor set by a globals-only
  truth map.
- **gc and psx have no DWARF or symbol truth for types**, so the type work
  there is unmeasured.
- **Vita type work is unmeasured:** no DWARF for it. V (prototype rerun)
  shows types on against off is `neutral` in the printed C (lines −10).

## Import speed against Ghidra 12.1.3

`benchmarks/import_speed.py` times `romwright-cli import` against
`analyzeHeadless` auto-analysis of the same image and scores both tools'
function entries with m21-001's `score()` over the same ranges. Method:
`docs/import-speed.md`. Our import runs with every `ROMWRIGHT_*` variable
cleared except the native tool paths and `ROMWRIGHT_NO_IMPORT_CACHE=1` (no JVM).
Tools alternate run by run, one at a time, on a shared 12-thread host.
Ghidra heap 8G, default analyzers, our language except X360 (stock
`A2ALT-32addr`, whose VMX128 does not decode).

**These are the numbers in `benchmarks/reports/import-speed.md`,
regenerated on the final tree and recorded 2026-10-08T16:57:11+00:00 (tools
`df1615627a4ff383`).** Report verdict: **FAIL**, and its only listed failure
is GBA (below). `benchmarks/reports/import-speed.{json,md}` are overwritten by
each rerun; if they have moved on, these numbers are that run's, not the
file's. Wall seconds are the medians over 3 runs (psx, dungeon, gc, capcom) or
2 runs (x360, psv, nds, gba) and the host is shared, so compare ratios.

| image | ours s | Ghidra s | wall ratio | tol | CPU s ours / Ghidra | peak RSS MB ours / Ghidra | recall ours / Ghidra | precision ours / Ghidra | gate |
|---|---:|---:|---:|---:|---|---|---|---|---|
| psx-darkstalkers-3 | 4.57 | 29.27 | 0.156 | 0.398 | 15.34 / 51.76 | 190 / 800 | 0.9878 / 0.5844 | 0.3663 / 0.4728; gated `precision_corroborated` 0.9968 / 1.0000 | pass |
| ps2-dungeon-game | 6.73 | 33.32 | 0.202 | 0.474 | 15.57 / 68.41 | 114 / 852 | 0.9438 / 0.7356 | 0.9880 / 0.9863 | pass |
| gc-animal-crossing | 6.97 | 52.64 | 0.132 | 0.209 | 20.61 / 105.99 | 203 / 1212 | no truth | no truth | pass (speed only) |
| ps2-capcom | 74.26 | 299.76 | 0.248 | 0.277 | 271.64 / 465.19 | 264 / 1448 | 0.9412 / 0.7562 | 0.9964 / 0.9979 | pass |
| x360-black-ops-2 | 90.13 | 291.43 | 0.309 | 0.088 | 262.42 / 432.52 | 1442 / 6812 | 0.9833 / 0.7628 | 0.9964 / 0.9965 | pass |
| psv-need-for-speed | 252.14 | 572.23 | 0.441 | 0.050 | 824.46 / 1051.93 | 1676 / 3314 | 0.9720 / 0.7035 | 0.9712 / 0.9657 | pass |
| nds-pokeheartgold-arm9 | 183.0 | 557.32 | 0.328 | 0.053 | 526.04 / 564.49 | 755 / 2648 | 0.9729 / 0.8643 | 0.9981 / 0.9983 | pass |
| gba-pokeemerald | 91.72 | > 3600 (timeout) | < 0.025 | - | - | - | 0.9737 / - | 0.9904 / - | incomplete |

Reading it:

- **Wall time:** faster on every image, ratio 0.132-0.441 on the seven
  comparable ones (2.3-7.6x). Ghidra did not finish GBA in either run (killed
  at 10,800 s and 3,600 s; its log has 17,257 "Unable to resolve
  constructor" warnings, S:Import speed tracked against stock Ghidra), so GBA
  quality is not comparable and it is the report's only failure. Ours took
  86.58 s and 96.86 s (median 91.72 s); the earlier snapshot (IS0) had 206.75 s.
- **Memory and CPU:** peak RSS ratio 0.13-0.51. CPU time is lower than
  Ghidra's on all seven comparable images (ratio 0.19-0.93; NDS 526.04 s
  against 564.49 s, where we also analyse ARM7 and every overlay). IS0 had NDS
  above Ghidra's CPU (630.31 s, ratio 1.12).
- **Recall:** ours is higher than Ghidra's on all six scored images, by 0.11
  (nds) to 0.40 (psx).
- **Precision, all images but psx:** ours is within the gate's margin on
  all five, and above Ghidra's on two:

| image | ours | Ghidra | difference |
|---|---:|---:|---:|
| dungeon | 0.9880 | 0.9863 | **+0.0017** |
| psv | 0.9712 | 0.9657 | **+0.0055** |
| x360 | 0.9964 | 0.9965 | −0.0001 |
| nds | 0.9981 | 0.9983 | −0.0002 |
| capcom | 0.9964 | 0.9979 | −0.0015 |

  (Differences are mine, from the report's precision column.) IS0 had
  dungeon 0.9305 against 0.9863 and capcom 0.9890 against 0.9979.
- **psx precision, and why it now passes:** map-only `precision` is 0.3663
  against Ghidra's 0.4728 and is still reported. The gate now uses
  `precision_corroborated`, 0.9968 against 1.0000 (docs/import-speed.md,
  "PSX precision: why the gate uses `precision_corroborated`"; S:PSX
  precision vs Ghidra: the invented entries are real statics; gate uses a
  corroborated metric). `VS.MAP` lists globals only, so map-only precision
  charges both tools for real file-local functions. The 1,398 entries the
  map does not name were classified from the image's bytes: 545 `jal` targets
  after a `jr $ra`, 803 function-pointer-table entries, 43 frame-opening
  address-taken entries, **7 uncorroborated** (S:PSX precision...; report
  `invented_corroborated_by`: `jal` 545, `table` 803, `frame+address-taken`
  43). Ghidra's 533 invented entries are corroborated by the same rule (521
  `jal`, 12 table). We recover 808 of the 818 named functions against Ghidra's
  478 (S:PSX precision...). This is a supplementary metric added beside, not
  instead of, `precision`; it is a measure we defined, so treat the psx row
  as passing under that metric, not as map-precision parity. The rule also
  corroborates 52 entries we do not find (Ghidra misses 910); not gated.
- **m21 on the final tree** (the scores in the report's romwright rows are
  the same ones): gba 0.9737 / 0.9904, nds 0.9729 / 0.9981, capcom 0.9412 /
  0.9964, dungeon 0.9438 / 0.988, psx 0.9878 / 0.3663, vita 0.972 / 0.9712,
  x360 0.9833 / 0.9964. That all seven pass their m21 floors is from a host
  run reported by Main; no committed report here records the pass/fail.

## Open issues

Each item is observed in the cited source and not resolved by this study.

1. **Prototype persistence regressed gba arity, dungeon warnings and
   Capcom returns; resolved.** F's `infer-prototypes` row (gba arity −1.5 pp,
   dungeon +169 warnings, +796 lines, type exact −4.9 pp) came from
   prototypes that were persisted as locked and then read at every call site.
   Five causes, found by diffing the job's per-round prototypes against DWARF
   over all 15.3k pokeemerald functions (S:Prototype persistence regressions,
   2026-10-09): (a) a Thumb `pop {r1}; bx r1` return the decompiler could not
   prove when the saved `lr` reached the pop through a join, so 24% of
   sampled gba functions printed `(*UNRECOVERED_JUMPTABLE)(r0)` and their
   callees persisted as `void`, with `r1` leaking into return recovery (fixed
   in `native/ghidra-opt-sleigh.patch`; this is the P2.5 return-address gap,
   not the cspec register set); (b) variadic functions: the register-save
   area read as 8 parameters (dungeon, `...` now); (c) one optional trailing
   argument, `GetMonData(mon, field[, data])`, was 207 of the 234 remaining
   gba arity leaks (a slot at most 60% of callers set is now `...`); (d) `swi`
   wrappers persisted as `void(void)` and erased their callers' arguments
   (trap-bearing bodies get no prototype); (e) a function that only forwards
   a callee's result inherited its type (Capcom returns, 160/200 exact against
   174 for default; now 174/200). Arity over all 15.3k pokeemerald functions:
   default 96.25%, persisted before 93.81%, after 96.73%. Harness, 200-function
   samples (`console_research_protowork.{json,md}`, tools `f594ea74cd7b0de3`;
   before = a run of the previous tree): gba arity 0.975 default, 0.96 →
   0.98 persisted; dungeon warnings 403 default, 572 → 202 persisted, type
   exact 0.3934 → 0.4262 default and 0.4262 → 0.4426 persisted; nds warnings
   342 default, 83 → 42 persisted; Capcom type exact 0.4834 → 0.891. Verdict `helps` on all four images.
   The default row itself moved (gba gotos 20 → 4, warnings 808 → 566,
   type exact 0.2633 → 0.5931) because the return fix and other native work
   landed together; the ablation of the native hunks alone was not run. x360
   and Vita were not re-run. Not fixed: 2 Capcom truth-void returns still
   typed (one a genuine gain, one loss), and rows a previous job version stored
   for functions the job now skips stay until overwritten. Two later findings
   (FinalGate, S: Prototype persistence regressions, second section): the
   forwarded-return rule first voided seven PSP functions DWARF types as
   values (type exact 0.6134 → 0.6019 stripped, 0.774 → 0.7603 symtab); it now
   needs no evidence anywhere along the forwarded chain (a callee read by ≥10%
   of its call sites, a syscall stub, an import or an unresolved indirect
   call each are evidence), which restores PSP to 0.6134 / 0.774 and keeps
   Capcom's returns at 174/200. And on Vita 72 of 1,009 stored float-parameter
   prototypes made their own function fail to decompile
   (`Overlapping input varnodes`: a locked `float param_1` at `s0` against the
   `q0` input heritage builds when the body touches `q0`/`d0` whole); the job
   now persists none for a function whose float parameter register the body
   touches at another width, seen in the lifted p-code or in the decompiler's
   recovery: 0 of 1,009 fail, 143 rows skipped (72 that failed, 71 that did
   not). The full 2.5 h Vita job was not re-run with this build.
2. **Type exactness is low and DWARF truth is thin** (gba, nds; dungeon only
   20 libgcc functions). No arity or type truth on five of eight images,
   including Vita (V: types on against off is neutral in the printed C, but
   accuracy is not scored).
3. **m22 context variant broken for every candidate** (generated `context.h`
   redeclares `memset` under agbcc `-Werror`; user work in progress). The end
   to end signal is standalone similarity on 33 functions of one image. The
   m22-001 harness itself stops at reference reassembly parity
   (ConvertIntToDecimalStringN 99.94%, S:Rust printer and structuring are the
   default, "pre-existing failures").
4. **Remaining gotos.** 84 on the consoles' gate set after `all` (SB, down
   from 91; F's export-c count of 171 predates it and counts the m2c-shaped
   file). Against real source only 0 (gate set) / 3 (final export) of 424
   scored pokeemerald and pokeheartgold functions still print a goto their
   C does not have. Built: switch sink, `cond_merge`, jump-threading reversal
   (`thread_test`; it removes none on the gate set, one in the final
   export). Not built: loop re-rolling (the 28 `into_loop`, unrolled loops
   with remainder entries), switch-lowering reversal (removes no goto by
   itself), de-duplication of compiler-copied regions, and proving
   *statements* equal across paths (SB, "Fake-match metric and the goto
   passes").
5. **Switch recovery.** Folded-default divergence from Ghidra is now
   deliberate (VSA and the worker drop it). m13 was re-run on 2026-10-08 after
   the rulings: its two failures stood (item above, section "Switch-table
   recovery"); on 2026-10-09 the interpreter one was fixed (decompiler-off
   imports no longer drop tables the decompiler was to take) and only
   "combined not above stock" stands (STATUS, "m13 gaps"). VSA-only import
   (decompiler off) is up to 5x faster but loses 6.4 pp of dungeon and 1.0 pp
   of Capcom precision (measured before that fix; after it, decompiler-off
   recall rose on gba, nds, vita and x360 by 0.07-0.4 pp at equal precision,
   dungeon and capcom precision unchanged); no mode that keeps both is
   measured.
6. **Discovery residuals.** Measured after the 2026-10-08 DiscoveryResidual
   work (STATUS, "Discovery residuals: interior rule, Thumb labels, GameCube
   fill"; same binary, the new rules on against off): invented functions gba
   45 (140 off; 150 in F), vita 762 (764), nds 17 (21), capcom 30, x360 98,
   dungeon 9 (those three unchanged). Vita's interior rule lost 11 true
   functions because an ARM pattern matched Thumb trampolines the vtables
   name; 10 are back (recall 0.9720 -> 0.9731), one (0x81063a60) is not. What
   is left is mostly real code the truth cannot see: x360's 98 are all named
   by `.pdata` unwind rows (69) or called (29); of vita's 764 (before the
   work), 278 are called by real functions, 156 start right after a return
   with a `push` and 116 are named by a vtable word (the BINMAP sizes stretch
   over them); capcom's 30 are 13 NOTYPE assembler routines and 16 VU
   microcode and data words the stripped image does not mark; dungeon's 9 are
   crt0 and helpers. gba's 45: 20 pattern starts in `.rodata` and
   `multiboot_data`, 4 calls inside that blob, 11 `bl` targets and 6 flow
   starts inside a function (agbcc's long jump to a label, in a function that
   opens with a `push`), 2 in `script_data`, 2 at the vectors. Not solved:
   those `bl` labels, the pattern starts in data, capcom's VU words. GameCube
   is scored as a supplement (`benchmarks/gc_discovery.py`): bond 55 -> 32
   invented, base 27 -> 4, Animal Crossing `main.dol` 115 -> 92, recall
   unchanged, no unaligned entry left.
7. **Import speed gate.** The regenerated report (IS, 2026-10-08T16:57:11) is
   FAIL only because Ghidra did not finish GBA (3600 s and 10800 s), so GBA
   quality is not comparable; every other image passes (psx on the
   supplementary `precision_corroborated`, map-only 0.3663 against Ghidra's
   0.4728). Capcom precision is 0.0015 below Ghidra's (0.9964 against
   0.9979), inside the 0.01 margin. psx's 7 uncorroborated invented entries
   are the known gap, and the rule corroborates 52 entries we do not find.
   The gate verdict will stay FAIL until Ghidra finishes GBA.
8. **Cost of the type merge; parallelized, big-image gain unmeasured.** The
   merge (`types_infer::prototypes::Core::parameter_types`) walks and lifts
   every recovered function, then solves it. Both phases now run on worker
   threads: the walk and lift on one extra handle on the image per 2,000
   functions (own console and lifter, slices of the function list returned in
   order), the solve on `job_workers` threads. Output is byte-identical to
   serial: the stored `prototypes` table has the same sha256 with the merge
   forced serial and parallel (dungeon, 4 runs, `5d274198…`; gba,
   `b188ae04…`), and the in-run comparison of the serial and parallel solve
   reported `identical=true` on 15,583 gba functions. Paired, same binary,
   `taskset -c 0-3`, host load average 16-20 (job wall time is not comparable
   at that load, so only the merge's own phases are quoted): gba merge 24.5 s
   (walk and lift 19.7 s, solve 4.8 s) → 8.3 s (7.2 s, 1.1 s); dungeon
   (748 functions, below the handle threshold, so only the solve is
   threaded) 1.4 s → 1.5 s, which is within noise. The merge was 2.9% of the
   serial gba job (832.8 s), so the job cannot gain more than that there; the
   +13-19% F/X/V measured on x360, Vita and stripped ELF were not re-measured
   here and their share of walk/lift against solve is unknown.
   [INFERENCE] they scale with function count, so the thread split helps
   most on those images. The pass now also runs with `ROMWRIGHT_INFERRED_TYPES=0`
   (the arity repairs need its p-code), so the types ablation no longer
   saves the walk.
9. **Samples are one seed, n = 200.** The thresholds are a materiality floor,
   not a significance test. Within a pass the comparison is exact, but a
   different 200-function sample could shift small verdicts (`~` rows).
10. **Harness drift.** `ROMWRIGHT_INFERRED_TYPES` is now on by default. The
    harness names the ablation `inferred-types-off`
    (`ROMWRIGHT_INFERRED_TYPES=0`, reference `infer-prototypes`, sign −1)
    rather than F's `inferred-types`, so F's `infer-prototypes` row (types
    off, measured when the default was off) is what a current run calls
    `inferred-types-off`, and F's `inferred-types` row is what a current
    `infer-prototypes` run measures. X and V are the reports in the new
    naming.

## Two more type-truth images: Capcom (DWARF 1) and Puzzle Bobble (PSP) (2026-10-08)

Report: `benchmarks/reports/console_research_dwarf1.{json,md}` (written by the
harness, tools `6071cd339255a3d8`, n=200, seed 20261006, configs `default`,
`infer-prototypes`, `inferred-types-off`, `baseline-off` as `default`'s
reference), plus `benchmarks/reports/dwarf1_differential.json`.

**Truth.** Capcom Fighting Evolution (`SLUS_209.50`) carries Metrowerks DWARF 1,
which readelf and pyelftools do not read. `benchmarks/dwarf1_types.py` reads it
with code that shares nothing with the Rust importer
(`native/mdebug/dwarf1.rs`) and emits the same DIE graph
`dwarf_types.parse` builds, so `dwarf_types.classify` and `dwarf_truth` score it
like gba/nds/dungeon: 5,221 subprograms, none dropped as conflicting, every
name and entry equal to the `.symtab`'s. The width of `long` (8 bytes) is
measured from struct layouts (303 members, none 4). Puzzle Bobble Pocket
(`BOOT.BIN`, DWARF 2, GCC 3.3.3 allegrex) is read by readelf: 145 functions with
types. In both, the research input is a stripped twin, so the import cannot read
its own truth: `llvm-strip --strip-all` (no `.debug`, `.line`, `.symtab`).

**Differential (Rust importer vs Python reader, SLUS_209.50).** 5,221 of 5,221
functions agree on arity, return class and every parameter class (10,808 of
10,808 slots, 100%); the importer's C spelling of each prototype maps back to
the stated class for 5,221 of 5,221. No disagreement to explain. The two
readers were written by one author from one reading of the DWARF 1.1.0 draft, so
this checks the code, not the reading; the readings that carry the weight were
checked against the image (names/entries against `.symtab`, `long`'s width
against struct layout, nesting against sibling chains).

**What the importer now does with it.** Importing the *unstripped* SLUS_209.50
types 5,221 of its 8,824 functions (59%) with source `native-import:debug-info`
(`DEBUG_INFO_SOURCE`, `native/store.rs`). It is `Declared` evidence, written
after the type-archive pass so it wins over it, and `protected()` keeps
`infer_prototypes` off it; a user assertion still outranks it. A prototype is
written only when every type has a C spelling the language's own type documents
declare (a struct or union by value, or the 16-byte `I128`, leaves the function
to inference). All 5,221 have one. Decompiling typed functions (`code *`,
`char`, `byte`, `short`, `longlong`) works. m21-001 on the stripped twin:
`--only ps2-capcom-fighting-evolution` passes at recall 0.9411, precision 0.9964
(recorded 0.9412 / 0.9964; floors 0.931 / 0.986). The research input is
stripped, so the debug path cannot touch these numbers. ECOFF `.mdebug` is not
read for types: SLUS_209.50 has no ECOFF section (its `.debug` is DWARF 1),
dungeon's has 695 `stProc` but no
`stParam`/`stLocal` symbols and 1,775 aux words (return types at most, no
arity), and the PSP image's `.mdebug.eabi32` is empty.

| image | config | scored functions | arity | type slots exact / scored |
|---|---|---|---|---|
| capcom | `default` | 200 | 0.9800 | 212 / 425 = 0.4988 |
| capcom | `infer-prototypes` | 200 | 0.9850 | 369 / 425 = 0.8682 |
| capcom | `inferred-types-off` | 200 | 0.9850 | 208 / 425 = 0.4894 |
| psp, strip-all | `default` | 144 | 0.7153 | 180 / 438 = 0.4110 |
| psp, strip-all | `infer-prototypes` | 144 | 0.7222 | 265 / 432 = 0.6134 |
| psp, strip-all | `inferred-types-off` | 144 | 0.7222 | 232 / 432 = 0.5370 |
| psp, symtab kept | `default` | 131 | 0.7099 | 167 / 405 = 0.4123 |
| psp, symtab kept | `infer-prototypes` | 131 | 0.7176 | 240 / 405 = 0.5926 |
| psp, symtab kept | `inferred-types-off` | 131 | 0.7176 | 206 / 405 = 0.5086 |

Reading it.

- **Capcom.** The persisted prototypes with inferred types lift type agreement
  from 0.4988 to 0.8682 (+37 pp); with types off it is 0.4894, so the lift is
  the inferred types. The `default` misses are mostly the pointer parameters the
  decompiler leaves as `int` (88) or `unsigned long long` (80) against truth `ptr`
  (this game's functions are `void f(struct *)`: 4,893 of the 10,808 slots of
  all 5,221 truth functions are `ptr`); the job leaves 3 of those 168 wrong. The 56
  slots still wrong are mainly `int32` against `unsigned int` (10) or
  `unsigned long long` (8), and `void` returns typed `unsigned char` (8). The
  job also removes 123 irregular functions and 485 native warnings from the
  sample. Discovery on the stripped twin is the m21 figure (recall 0.9414,
  precision 0.9964 in the harness import).
- **Puzzle Bobble, strip-all.** 144 of the 200 sampled functions have DWARF.
  Discovery on the stripped image: recall 0.9453, precision 0.8571 against the
  symtab's functions. The job lifts type agreement 20.2 pp (7.6 pp of it the
  inferred types, against `inferred-types-off`) and arity 0.7 pp, and removes 63
  irregular functions and 164 native warnings; its harness verdict is `mixed`
  only because it adds 2 gotos and 2 labels. The slot counts differ between
  configs because the harness scores `zip(truth, printed)` and a shorter printed
  list scores fewer slots: compare rates, not counts.
- **Puzzle Bobble, symtab kept** (`psp-puzzle-bobble-pocket-symtab`,
  `llvm-objcopy --strip-debug`: the symbols stay, only the DWARF goes). 131
  DWARF functions in the sample. Its discovery columns are the symtab's, not a
  measurement, and its precision (0.4397) comes from the importer placing this
  image's `.symtab` names at the unrelocated section-relative values (e.g.
  `malloc16` at 0x3b0 where the function is at 0x3f0), which PspImport fixed in
  `native/elf.rs` after this run (rows here predate it); 13 fewer DWARF functions
  line up than in the strip-all image (`[INFERENCE]`: the same cause). Same direction as
  strip-all: +18.0 pp type agreement from the job, 7.6 pp of it the types.
- **Truth alignment (retracted finding).** A first run of this section scored the
  PSP images against truth addresses 0x40 too low (`.symtab` and unrelocated
  DWARF `DW_AT_low_pc` are offsets into `.text`, which sits at 0x40:
  `M21.section_relative_bases`) and reported a weak discovery (recall 0.0209);
  that was the truth, not the importer, and is withdrawn. The numbers above are
  the rerun with the corrected truth, same tools (`6071cd339255a3d8`).

Cost. The 20-function rehearsal took 66 min wall (22:03-23:09 UTC, load 6-11),
32 min of it Capcom's first prototype job; the 200-function run 32 min
(23:13-23:45, load 7-12), Capcom's two prototype jobs 687 s and 700 s. A
prototype job does not depend on n; decompiling 200 Capcom functions took about
30 s per config. These are unpaired timings under shared load, not speed
measurements.

Reproduce: `python3 benchmarks/console_research.py --images
ps2-capcom-fighting-evolution,psp-puzzle-bobble-pocket,psp-puzzle-bobble-pocket-symtab
--configs default,infer-prototypes,inferred-types-off -n 200 --jobs 2 --no-m22
--out benchmarks/reports/console_research_dwarf1.json`; differential:
`ROMWRIGHT_DWARF1_ELF=<elf> ROMWRIGHT_DWARF1_OUT=rust.json cargo test -p
romwright-core --lib dump_dwarf1 -- --ignored`, then `python3
benchmarks/dwarf1_diff.py <elf> rust.json --out
benchmarks/reports/dwarf1_differential.json`.

## Correction: the PSP truth was section-relative (2026-10-08, PspImport)

The Puzzle Bobble numbers above (strip-all recall 0.0209 / precision 0.0190;
symtab arity 0.0966) were measured against a truth 64 bytes off. `BOOT.BIN` is
an unlinked-at-base-0 PRX (`e_type` 0xffa0): `.init` is 0x24 bytes at 0, `.text`
follows at `sh_addr` 0x40, and both `.symtab` and the unrelocated DWARF
`DW_AT_low_pc` hold offsets *into their section*, not addresses. The code bytes
are already final: of the 535 `jal` targets in `.text`, 440 minus 0x40 are
`.symtab` values (8 equal one), and the 1,054 `lui`/`addiu` pairs into `.rodata`
hold absolute addresses. So discovery found the real entries (e.g. 0x3f0) and the
truth said 0x3b0: the "nearest found entry is exactly 64 bytes after the symbol"
was the discovery being right. Stock Ghidra reads the same symtab correctly
(recall 1.0 on the symtab twin).

**Fix.** `M21.section_relative_bases` (tests/m21-001) adds `sh_addr` of the
symbol's section in `elf_functions`; `console_research.dwarf_truth` and
`locals_truth.Truth.collect` add `.text`'s to the DWARF entries. The importer
(`native/elf.rs::psp_symbols_are_section_relative`) does the same for the
symtab twin's names: before, every symbol named an address 0x40 below the real
function, so the sampled "functions" began mid-way through the previous one (the
`in_f2`/`in_f3` irregular inputs and the arity 0.10 were registers read by a
function's tail, not float arguments the ABI lost). The importer decides
relative vs absolute from the symbols (a linked PRX such as psp.rs's fixture
carries absolute values): symbols only an offset reading puts inside their
section vote relative, symbols only an address reading does vote absolute.
Unit test `native::tests::psp_symbol_values_are_offsets_into_their_section`.

**Measured** (host nih-vps-u, tools `7dfece5e9bc3a674`, n=200, seed 20261006,
`benchmarks/reports/console_research_psp.{json,md}`; stock: `benchmarks/
psp_stock_compare.py` -> `psp_stock_compare.json`, Ghidra 12.1.3 headless; stock's
choice for this ELF is `MIPS:LE:32:default`, the installed Allegrex module forced
as the second row). Discovery against the 622 symtab functions, each tool over
the executable blocks it loaded:

| image | tool | functions | recall | precision |
|---|---|---|---|---|
| strip-all | before (raw symbol truth) | 687 | 0.0209 | 0.0190 |
| strip-all | **ours** | 687 | **0.9453** | **0.8559** |
| strip-all | stock, loader's MIPS | 588 | 0.7990 | 0.8452 |
| strip-all | stock, Allegrex | 468 | 0.6350 | 0.8440 |
| symtab | ours (names now at the real entries) | 721 | 1.0000 | 0.8627 |
| symtab | stock (either language) | 720 | 1.0000 | 0.8639 |

DWARF agreement on the 145 DWARF functions (the strip-all sample holds 144):

| image | tool | arity | type slots exact |
|---|---|---|---|
| symtab | before, `default` / `infer-prototypes` | 0.0966 / 0.1172 | 40/232 = 0.1724 / 65/277 = 0.2347 |
| symtab | ours before the symbol-name library typing, `default` / `infer-prototypes` | 0.7172 / 0.7241 | 179/444 = 0.4032 / 270/438 = 0.6164 |
| symtab | ours with symbol-name library typing (C library table only), `default` / `infer-prototypes` | 0.7862 / 0.7793 | 215/444 = 0.4842 / 300/438 = 0.6849 |
| symtab | **ours, `default`** (+ run-time helper table) | **0.8828** | 259/444 = **0.5833** |
| symtab | **ours, `infer-prototypes`** (+ run-time helper table) | **0.8759** | 339/438 = **0.7740** |
| symtab | stock, Allegrex / MIPS | 0.7931 / 0.7517 | 222/447 = 0.4966 / 211/432 = 0.4884 |
| strip-all | ours, `default` / `infer-prototypes` | 0.7153 / 0.7222 | 0.4110 / **0.6134** |
| strip-all | stock, Allegrex / MIPS (all 145 entries, a function created where analysis made none) | 0.7103 / 0.6690 | 0.3716 / 0.3521 |

Ours beats stock on strip-all discovery and arity, and (with `infer_prototypes`)
on type agreement everywhere; the first measurement above left stock ahead on
symtab-twin arity by 7 points, through one mechanism: 12 of the 16 functions
where exactly one side was right were libc/libm names (`cos`, `sin`, `fabs`,
`floor`, `scalbn`, `copysign`, `isnan`, `isinf`, `matherr`, `_read_r`, `_write_r`,
`_lseek_r`) that stock types by symbol name from its C-library archive, while ours
typed imports and mangled names only.

**Symbol-name library typing.** `native/store.rs::apply_symbol_library_prototypes`
now types a function the image's symbol table names after a declaration the pinned
library table holds (`oracle/library-prototypes-v1/generic_clib_64.json`; the
32-bit archive was exported to check: same names, no `_r` newlib entries in
either). It is the weakest prototype source: merged before the import-name pass,
outranked by the debug stream, never overwriting an assertion, provenance
`native-import:symbol-library-prototype` (protected from the `infer_prototypes`
job, which only refines its own output), and only where `symbol_named` says the
image named the function, so a stripped image gets nothing. Tests:
`store::mwcc_names::symbol_named_library_functions_are_typed_with_their_own_provenance`,
`..::symbol_library_prototypes_yield_to_stronger_sources`. Effect on the symtab
twin (`default`): arity 0.7172 -> **0.7862**, type exact 0.4032 -> **0.4842**; with
the job 0.7241 -> 0.7793 and 0.6164 -> **0.6849**. Stock Allegrex is 0.7931 /
0.4966: the remaining arity gap is one function, `matherr` (its declared
`exception *` names a struct the language's type documents lack, so the row is
left out rather than approximated). `cos` now prints `double cos(double __x)` with
its argument in `a1:a0`, which is the Allegrex join rule below at work. The job
lowers symtab arity by 0.7 pp against `default` (`_start` 2 -> 0 and `_read_r`,
`_write_r`, `_lseek_r` 4 -> 2: trailing parameters it prunes; it repairs `_printf_r`,
`_sprintf_r`, `__sbprintf`); that is the existing job, not this change.
Regression check on the other twins: gba (`.gba` ROM), nds (`.nds` ROM), and the
stripped dungeon/Capcom ELFs carry no symbol table, so the pass applies to none
of them (imports: 0 rows with the new provenance for gba, nds and stripped
dungeon; the dungeon `--strip-debug` twin takes 33 rows, none of whose functions
has DWARF, libc being built without `-g`, so there is no truth to move there).

**Run-time helper table.** The 14 libgcc helpers that were left (`__adddf3`,
`__udivdi3`, ...) have no entry in Ghidra's C-library archive.
`oracle/library-prototypes-v1/runtime_helpers.json` (243 routines, written by
`scripts/gen_runtime_helpers.py`) declares them from two documents, facts only
and no library source read: GCC Internals' "The GCC low-level runtime library"
(sections 3.1 integer and 3.2 soft-float routines) and Arm's Run-time ABI
(`__aeabi_*`); citations in `docs/third-party.md`. The GCC document types the
routines by machine mode with illustrative C types (`long` for `DImode`), so the
table stores the mode (`si`, `di`, `df`, ...) and `library_types/helpers.rs`
resolves it against the language's own widths: `DImode` is `longlong` on the PSP,
`long` on r5900 (where `long` is 8 bytes), `longdouble` only for x87 `XFmode`, a
mode with no type of that width (16-byte integers on a 32-bit language, IEEE quad
anywhere, `CMPtype` off a 32-bit word) drops the routine instead of approximating.
Rows go through the same symbol-name pass, provenance and precedence as above
(the C library table wins a name both hold). Decimal-float and fixed-point
routines are not in the table: their types are in no language document, so no row
could be applied. Effect on the symtab twin (`default`): arity 0.7862 ->
**0.8828** (stock Allegrex 0.7931), type exact 0.4842 -> **0.5833** (stock
0.4966); with `infer_prototypes` 0.7793 -> **0.8759** and 0.6849 -> **0.7740**.
Arity misses 31 -> 17; of those 8-byte parameters remain in `__ieee754_rem_pio2`,
`__kernel_cos/sin`, `__make_dp`, `cvt`, `_dtoa_r`, `_ulp`, `_d2b` (newlib/fdlibm
internals no document declares: their register pairs still print as two words).
Rows applied elsewhere (import of each symtab twin, new provenance): dungeon
`--strip-debug` 38 (5 with DWARF, all five arity-correct: `__muldi3`, `__udivdi3`,
`__umoddi3`, two `__udivmoddi4`; they print `long`/`ulong`, which are 8 bytes in
the r5900 language, and `console_research.C_SCALARS` scores any `long` as 32-bit,
so its slot score marks them wrong: a scorer assumption, not changed here since
metric definitions are frozen), Capcom unstripped 50 (none has a DWARF 1
subprogram), pokeemerald `--strip-debug` 43 (none has DWARF). Stripped twins get
none. The PSP strip-all twin is unchanged.

**The ABI.** Float arguments were never the problem: `f12`..`f19` for `float`,
`a0..a3`,`t0..t3` for the rest is what the Allegrex cspec says and what the
binary does (DWARF puts `__kernel_sinf`'s `x`,`y` in `f12`,`f13`; `scalbnf`'s `x`
in `f12`). What the cspec lacked is an assignment rule for 8-byte values: the
PSP has no double-precision hardware, a `double`/`long long` is an aligned
integer pair (`__adddf3` spills `a0:a1`, `a2:a3`, returns `v0:v1`;
`__make_dp(int, uint, int, uint64)` reads `a0`,`a1`,`a2` and `t0:t1`, never `a3`),
so a *declared* `double a` printed as a stack argument with the pair left as
`in_a1`/`in_a2`. `worker/specs.rs::with_allegrex_argument_rules` adds the stock
MIPS-EABI rule set (float -> FPU registers or stack, `double` and every other
value -> `join align`, aggregates over 4 bytes by pointer) next to the Gekko one.
Tests: `allegrex_rules_are_added_once_and_only_for_the_psp`, and the ignored
`allegrex_declared_arguments_follow_the_psp_eabi` (a `double`, a `ulonglong` after
three words, a `float` then a `double`): it failed without the transform
(`void probe(double a,int *b){undefined4 in_a1; ...}`) and passes with it. The
rules only govern *declared* prototypes: the harness numbers were identical before
and after the transform alone (0.7172/0.7241 both runs), because nothing in the
sample declared a `double` until the symbol-name typing above, and the decompiler's recovery of an undeclared pair is two
4-byte parameters whatever the cspec says (join entries in the input list were
tried and change nothing). That is the remaining distance to the 8-byte DWARF
parameters: after the symbol-name typing 22 of the 31 remaining arity misses
(`default`; 8 of the 17 after the helper table) are functions with a `double`/`uint64` parameter seen as two words
(the 14 libgcc helpers are typed by the run-time helper table below; the rest are
newlib/fdlibm internals), the
rest unused or variadic parameters.

Reproduce: `python3 benchmarks/console_research.py --images
psp-puzzle-bobble-pocket,psp-puzzle-bobble-pocket-symtab --configs
default,infer-prototypes -n 200 --jobs 2 --no-m22 --out
benchmarks/reports/console_research_psp.json`; stock: `python3
benchmarks/psp_stock_compare.py --work DIR`.

## Eight-byte parameters in register pairs (2026-10-09, PspImport)

The 8 PSP functions left with an 8-byte parameter printed as two words
(`__ieee754_rem_pio2 __kernel_cos __kernel_sin __make_dp cvt _dtoa_r _ulp _d2b`)
were examined for general evidence, not name-based. Evidence is read off the
decompiler's SSA (the recovery's `FunctionIr` plus the per-call callee
prototypes), not guessed from a body's shape.

**Sound evidence: an entry pair handed whole to a declared 8-byte parameter.**
In the SSA a call argument is `CAST(PIECE(in_hi, in_lo))` (or the `PIECE` as the
call's joined storage) where `in_hi`/`in_lo` are the *function's own entry values*
of an aligned register pair (`a0:a1`, `a2:a3`, `t0:t1`), in the ABI's word order,
and the callee's prototype declares an 8-byte parameter there (a documented libm
or run-time helper, a debug-info prototype, or a prototype this pass joined in an
earlier round, so the evidence climbs the call graph). The function receives one
value in that pair and passes it on whole. `types_infer/pair_params.rs` turns the
two single-register parameters at that pair into one parameter of the callee's
declared type (`double`, `longlong`), after the slot-wise type upgrades, in the
`infer_prototypes` job (`worker-client`, before the retain; `ROMWRIGHT_JOIN_PAIRS=0`
turns it off; harness config `join-pairs-off`). Both halves must be 4-byte
unknown/int/uint parameters (a pointer or float in the pair is evidence of two
values), every sighting of a pair must name the same declared type, the pair
starts at an even slot, and the machine's registers must be half the value's
width (a 64-bit-register target has no pair). The binary is the same either way:
the ABI puts the value in exactly those registers; the join is what makes the
signature and the callers' call sites say one value. A function that really took
two `int` halves and forwarded them to an 8-byte parameter is the one false
reading, and it is the same code.

**The alignment hole.** An 8-byte parameter after an odd number of 4-byte ones
skips a register (`f(int a, double b)`: `a0`, hole `a1`, `a2:a3`); the recovery
invents a parameter for the hole. When nothing reads the hole register's entry
value in the body, the pass drops that parameter with the join. An unused
parameter that is really there looks identical in the registers; an odd count of
4-byte parameters before a `double` is how such functions are written, an unused
one the exception, so the pair's evidence decides for the hole. The flag is
sticky across rounds: a later round's recovery reads the register when a callee's
newly persisted prototype keeps its own hole as a parameter (the caller passes the
register through), which says nothing about the body.

**Result** (symtab twin, n=200, `benchmarks/reports/console_research_psp.{json,md}`,
config `infer-prototypes` against `join-pairs-off`, same tools): arity 0.8759 ->
**0.9034**, type exact 339/438 = 0.7740 -> **349/438 = 0.7968**; stock Allegrex
0.7931 / 0.4966. Four functions joined, all four equal their DWARF prototype:
`__ieee754_rem_pio2(double, double *)`, `__kernel_cos(double, double)`,
`__kernel_sin(double, double, int)`, `cvt(ptr, double, int, int, ptr, ptr, int,
ptr)` (the last with its `a1` hole dropped). Four joins in a 721-function image,
none wrong. The strip-all twin has no declared 8-byte callee, so no sighting:
unchanged (0.7222 / 0.6134). The default configuration is unchanged (0.8828 /
0.5833): the pass is a job pass.

**Non-regression.** The pass changes a prototype only by joining, and a join
needs a declared 8-byte callee parameter and 4-byte argument registers. Capcom,
dungeon and pokeemerald, with the job on (`benchmarks/reports/
console_research_pairs_{ps2,gba}.{json,md}`), hold 0 `joined-pairs` rows of
8,159, 707 and 15,460, so their prototypes are exactly the ones the job writes
with the pass off: Capcom arity 1.0000 / type exact 371/408, dungeon 1.0000 /
27/61, GBA arity 0.975 / type exact 261/375 (r5900 registers are 8 bytes; the
stripped GBA ROM names no helper).

**Cost.** The join prints the value's halves as `SUB84(param_1,0)` where the
body reads one word; the printer in the measured tools has no `SUBPIECE`
intrinsic, so `__ieee754_rem_pio2` and `cvt` gain a native warning (`irregular`
+2 in the sample's 145, offset by `__kernel_cos`'s 1 -> 0 and the rest). `cvt`'s
print also shows `in_a1`: it passes its own (unread) `a1` to `_dtoa_r`, whose
prototype keeps the hole as a parameter because `_dtoa_r` has no evidence of its
own (below).

**What has no sound evidence** (the four left; IR facts from the same recovery):

- `_ulp(double)`: no direct caller; the body reads only `a1` (`INT_AND`) and never
  `a0`; the one `PIECE` in it joins two computed temporaries.
- `__make_dp(int, uint, int, uint64)`: the body copies `a0 a1 a2 t0 t1` to stack
  words (`COPY` only); its single caller builds `t1:t0` as `(x << 30) | (y >> 2)`, a
  64-bit shift written in 32-bit halves. The 8-byte-ness is in the shift idiom, not
  in a typed use.
- `_d2b(ptr, double, int *, int *)`: `a2` feeds `COPY`/`INT_EQUAL`, `a3` an
  `INT_AND`, both are stored to adjacent frame words whose address goes to
  `_lo0bits`: two spills to adjacent slots are what two `int`s do too.
- `_dtoa_r(ptr, double, int, int, int *, int *, char **)`: the pair is
  `PIECE(MULTIEQUAL(a3_in, a3_in & 0x7fffffff), a2_in)`: a *derived* pair, its high
  half the entry word or the entry word with the sign bit cleared. Accepting
  derived pairs means accepting any `(hi & mask, lo)` of two `int`s. The caller
  side is real (its caller `cvt` passes the two halves of its own joined double in
  slots 2 and 3) but needs every call site to agree on halves of one 8-byte value,
  gains this image one function, and is the rule a function taking `(lo, hi)`
  of two `int`s from a caller that splits a `double` would trip.

Tests: `cargo test -p romwright-core --lib -- types_infer` (52 -> 61 with the nine
`pair_params` tests: sightings through `CAST`/`COPY`/`PIECE`, misaligned or swapped
or non-entry halves, the hole, conflicting types, a wide-register target, a round
carrying evidence forward) and `cargo test -p romwright-worker-client --lib`.

Reproduce: `python3 benchmarks/console_research.py --images
psp-puzzle-bobble-pocket,psp-puzzle-bobble-pocket-symtab --configs
default,infer-prototypes,join-pairs-off -n 200 --jobs 2 --no-m22 --out
benchmarks/reports/console_research_psp.json`.

## Supplement: locals, stack slots and return classes against DWARF (2026-10-08)

`benchmarks/locals_truth.py` scores what DWARF says about a function's body
and return that `console_research.py` does not report apart; report
`benchmarks/reports/locals_truth.{json,md}`. Printed C is read by one parser for
ours (the harness's kept `*.c`, tools `6071cd339255a3d8`, n=200 sample) and stock
Ghidra 12.1.3 (`benchmarks/locals_stock.py`, default analyzers, same stripped
twin and languages as `import_speed.py`, the sampled functions decompiled in
the project stock analysed; a sampled address that is not a stock function is
not scored for either tool in the `common` rows). Definitions: count of
declared automatic locals against DWARF's (not statics, not variables with no
location), stack slots by entry-relative offset (MIPS only: DWARF gives
`sp`-after-prologue offsets and the frame size is read from the function's
`addiu/daddiu sp`), the class of each local as a per-function multiset, and the
return class by `type_headtohead.score`. DWARF's locals include source
variables the compiler kept in registers, so the counts show distance from the
source's variable set, not correctness.

**Which names show a stack slot.** Our printed C is m2c-shaped: `export-c`
renames the decompiler's `local_<hex>` and `auStack_<hex>` symbols to `temp_*`
(`emit_m2c::is_generated_name`), so a stack slot the decompiler has can be
absent from the printed names (Capcom `0x20c050`: the array at -0x30 is
`unsigned char temp_v8 [8]`). Stack slots are therefore read from the
decompiler's own names in `decompile-doc` (`benchmarks/locals_doc.py`, written
beside the printed C as `<address>.stack`), plus the slots our `*_stack` frame
comment lists. Counted from the printed names alone ours scored stack recall
7/11 on Capcom, 13/28 on dungeon and 4/138 on PSP; that first reading, and the
propagation gap I attributed it to, were wrong (below).

| image | tool | common fns | DWARF locals / printed | stack recall (decompiler names) / slots | local class recall / precision | return exact |
|---|---|---|---|---|---|---|
| capcom | ours default | 146 | 117 / 495 | 11/11 = 1.00 / 125 | 0.49 / 0.12 | 129/146 = 0.88 |
| capcom | ours infer-prototypes | 146 | 117 / 424 | 11/11 = 1.00 / 118 | 0.56 / 0.16 | 121/146 = 0.83 |
| capcom | stock | 146 | 117 / 498 | 11/11 = 1.00 / 125 | 0.51 / 0.12 | 89/146 = 0.61 |
| dungeon (libgcc) | ours default | 20 | 156 / 128 | 28/28 = 1.00 / 44 | 0.33 / 0.40 | 8/20 |
| dungeon (libgcc) | ours infer-prototypes | 20 | 156 / 129 | 28/28 = 1.00 / 44 | 0.33 / 0.40 | 9/20 |
| dungeon (libgcc) | stock | 20 | 156 / 128 | 28/28 = 1.00 / 44 | 0.35 / 0.43 | 5/20 |
| nds | ours default | 175 | 214 / 382 | not scored (ARM) | 0.43 / 0.24 | 106/175 = 0.61 |
| nds | stock | 175 | 214 / 386 | not scored (ARM) | 0.46 / 0.25 | 90/175 = 0.51 |
| gba | ours default | 200 | 184 / 455 | not scored (ARM) | 0.49 / 0.20 | 167/200 = 0.84 |
| psp strip-all | ours default / infer | 144 | 647 / 875 / 881 | 133/138 = 0.96 / 135/138 = 0.98 (782 / 783 slots) | 0.53 / 0.40 | 56 / 68 of 144 |

What the numbers say.

1. **Stack slots: ours equals stock.** From the decompiler's names ours has every
   DWARF stack local stock has (Capcom 11/11 and dungeon 28/28, with the same
   125 and 44 slots as stock) and 133-135 of 138 on PSP (stock was not run
   here). The earlier "gap" (ours 0.64 against stock 1.00) came from the
   printer's renaming. I also built, and then dropped, a propagation change for
   the R5900, which stores no stack variable (0 rows in Capcom and dungeon;
   Allegrex has 2,467 in the PSP image): SLEIGH's 8-byte `sp` and 4-byte `sp_lo`
   are two views of the stack pointer, the spec names `sp_lo`, and
   `Propagation::initialState` seeds the stack base only on an exact size match
   while `State::get` and `evaluate` have no rule for a relative value across a
   width change. Aliasing the views and adding SUBPIECE/INT_SEXT rules made the
   store hold 16,748 rows in 6,100 Capcom functions, left recall at 11/11 and
   raised the frame comment's slots from 125 to 383 (spill slots), so it bought
   nothing and was reverted before any rebuild was deployed.
2. **Return class**: ours beats stock on Capcom (0.88 vs 0.61) and NDS (0.61 vs
   0.51) and is behind it nowhere measured, but infer-prototypes costs 12 of
   Capcom's 199 returns (0.89 to 0.83): every one a truth-`void` function
   (state handlers called through pointer tables) whose tail call is to a callee
   the job typed non-void, so the decompiler forwards the callee's return
   register. Only the callers can say whether the value is used; these have no
   direct callers (`types_infer/call_support.rs` counts direct call sites only),
   so there is no evidence to void them with and none was invented. PSP and
   dungeon returns are mostly float returns (`f0`) printed `void`/`int` by both
   tools.
3. **Local counts** are within 1 of stock on common functions (Capcom 495 vs
   498, NDS 382 vs 386): ours declares about 2.6 locals more per function than
   DWARF's source variables on Capcom, which are mostly the printer's `temp_*`
   register temporaries (stock's `iVar*`); the job cuts it to 424.

**Debug-info locals as import facts** (unstripped SLUS_209.50 only). The DWARF 1
reader puts scalar (1-8 byte) stack locals into the same `stack_variables`
table the analyzer's frame goes into, the table the worker already hands the
decompiler as the function's declared locals. A debug local replaces every
analyzer slot it overlaps and carries the source name (made unique within the
function) and, when its C spelling is a core type of the language at the slot's
width, that type instead of `undefined<N>`; `storage` ends `:debug-info`
(the table has no provenance column). The frame size, which DWARF 1 needs to
place `sp+c` against the entry stack pointer, is the function's own
`addiu/daddiu sp, sp, -N` (`mdebug::mips_frame_size`). Result on the unstripped
image: 100 locals in 59 functions (the rest are aggregates over 8 bytes,
statics and register-held locals, which no stack slot can carry); all 59
functions decompile with their source names (59 of 59 print at least one, e.g.
`int cmd_posx_tbl;` for a 4-byte slot at -4) and the stack-frame comment
names them. Capcom's DWARF 1 carries 5,598 locals; 2,844 are register-held and
2,379 statics.

Reproduce: `python3 benchmarks/locals_stock.py IMAGE --report <harness json>
--binary <stripped twin> --out stock.json`, `python3 benchmarks/locals_doc.py ...`
(the decompiler's stack slots beside the printed C), then `python3
benchmarks/locals_truth.py --spec spec.json --out
benchmarks/reports/locals_truth.json` (spec: image to `{"ours": {label:
results dir}, "stock": stock.json}`).

## Supplement: PS2 VU0 macro mode as per-lane float p-code (P4.3, 2026-10-08, Vu0Semantics)

**What was opaque.** The vendored `vuupper.sinc` already wrote the four-lane
arithmetic (`vadd`, `vmul`, `vmadd*`, `vsub*`, ...) as masked 128-bit read-modify-write
p-code, with the x lane at the *top* word of the register, while `lqc2`, `sqc2`,
`qmfc2`, `qmtc2`, `cfc2`, `ctc2`, `vdiv`, `vsqrt`, `vrsqrt`, `vftoi*`, `vitof*`,
`vmax*`, `vmini*`, the `vi*` integer ops and every `*ai`/`*aq` accumulator form were
`CALLOTHER`s (`_lqc2(...)` and the rest). The arithmetic was printed through
`romwright_subpiece_16_4_0(temp >> romwright_zext_16_16(0x60))` helpers and could not
connect to a load, because `_lqc2` returned an opaque 16-byte value. Four faults sat in
the old constructors as well: `vsubai` read Q instead of I, `vopmula`/`vopmsub` computed the
whole cross product instead of its two halves, `vclip` was opaque, `vsqi` wrote Q, and `cfc2`/`ctc2` indexed the `vc0..vc15` display registers instead of the
architectural control file.

**Census** (stripped images; "VU0 instruction" = COP2 arithmetic and lower ops, `lqc2`, `sqc2`,
`qmfc2`, `qmtc2`, `cfc2`, `ctc2`, `bc2*`; counted over the discovered function ranges of the
`default` import, which excludes the VU microcode words that sit in `.text`/data):

| image | executable words | VU0 instructions, whole image | in discovered functions | functions | of those with `CALLOTHER` p-code |
|---|---|---|---|---|---|
| Capcom `SLUS_209.50` | 567,552 | 2,054 | 1,234 | 61 of 8,307 | 652 |
| dungeon `dungeon_game.elf` | 993,633 | 19,577 | 1,320 | 31 of 748 | 698 |

Both images use VU0 enough to matter (`lqc2`/`sqc2` alone are 371 and 568 of the in-function
instructions, and none of them could connect to the lane arithmetic). Printed-C opaque
calls (`export-c`, `_v*`, `_lqc2`, `_sqc2`, `_cfc2`, `_ctc2`, `_qmfc2`, `_qmtc2`), on every
function that holds one of those instructions plus the n=200 research sample, same tools,
same imported project, old versus new language (`/tmp` census script, one row per function in
the run's JSON):

| set | functions | printed `_v*`-style calls before | after | gotos | warnings | decompile success |
|---|---|---|---|---|---|---|
| Capcom, VU0 functions | 61 | 883 (60 functions) | **14** (6) | 9 -> 9 | 19 -> 15 | 60/61 -> **61/61** |
| dungeon, VU0 functions | 31 | 984 (31) | **12** (4) | 10 -> 10 | 28 -> 24 | 31/31 |
| Capcom, VU0 + sample union | 261 | 883 | 14 | 20 -> 20 | 48 -> 44 | 260 -> 261 |
| dungeon, VU0 + sample union | 220 | 984 | 12 | 48 -> 48 | 31 -> 27 | 220 |

The 26 that remain are all `_cfc2` of the Status or MAC flag register: nothing here
models the flags, so a read stays opaque (see "Not modelled").

**Representation (decided).** Four 4-byte float lanes per VF register, not a typed struct.
`vf1x vf1y vf1z vf1w` are registers at `0x4110 + 4k`, x at the *lowest* address (the lane
order of `lqc2`/`sqc2`/`qmfc2`/`qmtc2`, which move memory word *k* to lane *k*; the old
language had x at the top word, which could not agree with `lqc2`). `vuACCx..w`, `vuI`,
`vuQ` and `vuCF` (CLIP) are plain registers; VI0-VI15 are the 4-byte `vi0..vi15`,
holding a 16-bit value zero-extended, every write masks to 16 bits, `vi0` reads 0 and ignores
writes. The decompiler's SSA then does the rest: a `lqc2` is four `*(float *)(p + 4k)`
loads that print as `param[k]`, an `sqc2` four stores, and a 4x4 matrix product is 16
statements of `temp = a * b + c * d + ...` with no 128-bit value anywhere
(Capcom's 61 VU0 functions print in 3,938 lines instead of 6,027, the 31 dungeon ones in
7,962 instead of 10,154; `FUN_00211dd0` goes from 603 to 224 lines, and the old text opened
with `romwright_uint128` / `romwright_subpiece_16_4_0` helper macros and `unsigned char[16]`
temporaries). A struct would have required
16-byte varnodes, `PIECE`/`SUBPIECE` and a type the decompiler cannot keep through
arithmetic.

The dest mask is resolved at *decode* time by lane tables (`native/languages/r5900/vulanes.sinc`):
`Dx`..`Dw` export the register lane when the mask keeps it and `fd != vf0`, a dead unique
otherwise; `Sx`.. read `vf0` as the constants `(0, 0, 0, 1.0)`; `Bv` picks the broadcast
lane. So `vmul.x vf3, vf2, vf1` lifts to one `FLOAT_MULT` and `vmax.xyzw` to four
`if (a < b) a = b` blocks, with no mask arithmetic and no dead-lane code in the printed
output. 82 constructors are generated from one table by
`native/languages/r5900/gen_vu.py` (`--check` verifies the committed `.sinc` files) and
`native/languages/r5900/install.sh` compiles and installs the language.

**What is exact.** All 16 dest masks and the four broadcast fields of ADD/SUB/MUL/MADD/MSUB
(vector, `i`, `q`, broadcast, and the `a` accumulator forms), MAX/MINI, ABS, MOVE, MR32,
FTOI0/4/12/15, ITOF0/4/12/15, OPMULA/OPMSUB (x, y, z only), CLIP (`CF = (CF << 6) | six
compare bits`, 24 bits), DIV, SQRT, RSQRT (`sqrt(|ft|)`, as the manual states), MFIR,
MTIR, IADD/ISUB/IADDI/IAND/IOR (16-bit), ILWR/ISWR, LQI/LQD/SQI/SQD (VU0 data memory
at `0x11004000 + (VI & 0xff) * 16`), `lqc2`/`sqc2`, `qmfc2`/`qmtc2`, and `cfc2`/`ctc2` of
VI, CLIP, I and Q (CTC2 keeps 16 bits of a VI, 24 of CLIP; CFC2 sign-extends the 32-bit
value as the manual says).

**Not modelled** (each is the reason a thing is opaque or approximate, not an omission by
accident): the MAC and status flag side effects of every arithmetic op, so `cfc2` of
Status/MAC (and the R, TPC, FBRST, VPU-STAT, CMSAR registers the hardware changes
without a macro instruction) stays an opaque `_cfc2`; reading a stale constant there would
fold a flag-test branch away (the first version of this change did exactly that on
`ctc2 zero, vc0; vsub...; cfc2 t0, vc0; andi t0, 0xc0; bnel`, a warning delta of +3 on the
dungeon sample, and was corrected); the VU's round-toward-zero arithmetic and its +-MAX
clamping (the p-code is IEEE binary32 round-to-nearest, so the last bit can differ);
FTOI saturation; `vrget`/`vrnext`/`vrinit`/`vrxor` (the R register stays an opaque
`_vr*`); `vcallms`/`vcallmsr` (a micro subroutine may rewrite any VF or VI register; the
p-code has no such effect, as before; `vcallmsr` now reads CMSAR0 so a preceding `ctc2` is
not dead); `bc2*`; `lqc2`/`sqc2` do not trap on a misaligned address. The VU's `vu0.data`
aliasing of the VU1 registers above 256 quadwords is not modelled either.

**Tests.**

- Disassembly. Over every word of the three primary opcodes that carry COP2 (`cop2`, `lqc2`,
  `sqc2`: 3 x 2^26 = 201,326,592 words) the old and the new `.sla` print identical
  mnemonic, operands and length (`native/sleigh_diff.cc cop2hash`, a libsla program: equal FNV-1a hash per
  opcode and equal count of undecodable words, 35,858,431 of the `cop2` words). Over every
  aligned word of the executable segments of both images (567,552 + 993,633) the
  disassembly is byte-identical, and the normalized p-code of every non-VU0 word is identical;
  the only non-VU0 words whose p-code differs are branches with a VU0 instruction in the
  delay slot (31 and 1,907), and 0 changed without one. 2,018 + 19,449 VU0 words changed their
  p-code, 35 + 107 did not (`bc2*`, `vcallms`, `vrget` and similar).
- Semantics, `tests/p4-3_vu0_macro.py`: the lifted p-code of 534-1,531 decoded forms and
  708-4,720 instructions (`--cases 6..40`: every family above, all 16 dest masks, the four
  broadcast fields, aliased `fd == fs == ft`, `vf0` as source and destination, random ACC/I/Q/VI/VU0
  memory) runs in a small p-code interpreter and is compared bit for bit with an independent
  reference of the VU User's Manual: 0 differences, 0 `CALLOTHER`. A mutated reference (`vmr32` rotating
  by two lanes) fails 5 of the 708, so the comparison does bite. Its
  decode half checks the mnemonic and dest suffix of every form, and its decompile half
  checks a ps2sdk-style routine prints with no unknown VU call.
- `cargo test -p romwright-core --lib -- register_params` (the bundle `registers.txt` lists the
  new lane names).

**Printed-C metrics for the two PS2 images** (`benchmarks/console_research.py`, configs `default`
and `baseline-off`, n=200, seed 20261006, `--jobs 2`, tools `bce16961a7784c25` both sides
(`ghidra_opt` `eed4c513` of the host copy; the fingerprint then also covered the SLEIGH console, since retired), only the language differs;
`m22` skipped). Only 1 Capcom and 11 dungeon sampled functions changed their printed C (all
of them VU0 functions), which is why the Capcom row barely moves:

| image | gotos | labels | irregular | native warnings | text warnings | lines | success, recall, precision, arity, type exact |
|---|---|---|---|---|---|---|---|
| Capcom `default` | 4 -> 4 | 1 -> 1 | 164 -> 163 | 539 -> **532** | 59 -> 58 | 9,252 -> 9,162 | unchanged (1.0, .9412, .9964, .9850, .4834) |
| dungeon `default` | 42 -> 42 | 22 -> 22 | 124 -> 123 | 403 -> **359** | 25 -> 23 | 12,357 -> 11,440 | unchanged (1.0, .9438, .9880, 1.0, .4262) |

`baseline-off` moves the same way (Capcom 539 -> 532 warnings, dungeon 403 -> 359). Median
wall time per function is reported, not judged: Capcom 0.203 -> 0.273 s with one sampled
function changed (host noise from other agents), dungeon 0.085 -> 0.066 s. m21-001 on both images
is identical before and after (Capcom recall 0.9412, precision 0.9964; dungeon 0.9438,
0.9880). A first harness pair ran while two other host jobs were saturating the CPUs and
showed a Capcom import that found 3 more functions (recall 0.9416); the quiet rerun did
not, so that was a timeout-sensitive switch stage and not the language.

**Reproduce.**

<!-- not gated: needs the r5900 sleigh toolchain and a Ghidra install; recorded recipe of a measurement -->
```sh
python3 native/languages/r5900/gen_vu.py          # regenerate vulanes.sinc, vuupper.sinc
native/languages/r5900/install.sh                 # compile and install r5900.sla
ROMWRIGHT_GHIDRA=<install> python3 tests/p4-3_vu0_macro.py --cases 40

# census: words in discovered function ranges, by mnemonic, and the unknown calls printed
python3 benchmarks/vu0_census.py words PROJECT BINARY --out ranges.json
python3 benchmarks/vu0_census.py printed PROJECT BINARY ranges.json out.json --sample sample.json
#   (once with the old install, once with the new one: ROMWRIGHT_GHIDRA=...)

# disassembly / p-code differential between two compiled languages (libsla, see the file header)
sleigh_diff OLD.sla pcode IMAGE.elf > old.pcode; sleigh_diff NEW.sla pcode IMAGE.elf > new.pcode
python3 benchmarks/pcode_diff.py old.pcode new.pcode
sleigh_diff OLD.sla cop2hash x; sleigh_diff NEW.sla cop2hash x      # all 3 x 2^26 COP2 words
```

**Gaps.** MAC/status/CLIP-by-arithmetic flags, round-toward-zero and +-MAX clamping are
approximated or absent (a flag-driven VU0 branch cannot be recovered; `vclip` itself is exact);
`vcallms` does not model its results; `vrget`/`vrnext`/`vrinit`/`vrxor` stay opaque;
the "libvux-style helper rendering" half of the plan item is not built (the lane form
needs none: a 4x4 product is already `a * b + c * d`).

## Truth-contract images: `--corpus-wave` (2026-10-09, HarnessWave)

`benchmarks/console_research.py --corpus-wave` runs every image a corpus
builder staged under `~/romwright-corpus/extracted/<id>/truth/`, with no entry
in the script: the image spec is read from `meta.json`. The built-in list and
the frozen m21 gate (`tests/m21-001_real_images.py` floors) are untouched; the
new images are **not** in m21's floors. The code is `benchmarks/console_research.py`
(pipeline) and `benchmarks/console_research_wave.py` (contract, scoring,
rollup, sign tests); the shared loader is `M21.tsv_rows` / `M21.tsv_functions`,
registered as truth kind `tsv` in `M21.LOADERS` (the table every truth kind goes
through).

### The truth contract

```
<corpus>/<id>/                 id = <platform>-<slug>, e.g. gc-melee, n64-majoras-mask
  <staged executables>         DOL/RELs, SCUS/SLUS/ELF/overlays, the ROM, PSP ELF/PRX, X360 XEX/EXE
  truth/functions.tsv          start<TAB>size<TAB>name<TAB>module<TAB>verified   (header line exact)
  truth/meta.json
  truth/types/functions.json   optional
```

`functions.tsv`: `start` hex `0x...` in the executable's load address space; `size`
decimal bytes (0 = unknown); `name`; `module` = `main` or an overlay/REL name;
`verified` = 1 when the function lies in a unit the decomp matched/linked (the
boundary is compiler truth), 0 when it comes only from the repo's own analysis.
`meta.json` required here: `id`, `image` (relative to `<corpus>/<id>/`, the file
`romwright-cli import` is given), `truth_kind`; read when present: `game`,
`platform`, `region_version`, `sha1_expected`/`sha1_actual` (`md5_*` may stand in: nothing
is checked against them, `version_match` is authoritative), `version_match`
(false moves the game to the supplement table and out of the sign tests),
`repo`, `commit`, `compiler`, `linked_percent`, `program_hint` (the
`--name`; default per platform), `ranges` (`[[lo, hi], ...]`, integers or hex
strings, main module only; null = every executable region), `modules`
(`{name, image, load_address[, ranges]}`; `name` equals the tsv `module`).
An ELF with a `.symtab` is run stripped (`llvm-strip --strip-all`, as the m21
specs do) so the importer cannot read the truth from the symbols (the headline is always
the stripped copy; `images.<id>.stripped` and the Images table's "stripped" column list
which images were); `"strip": false` opts out. A directory is skipped, with the reason in the report
(`wave_skipped`), when meta.json/functions.tsv/the image is missing, functions.tsv has a
header and no rows (header-only truth), or any of them changed less than `--min-age-s`
(60) seconds ago.

`truth/types/functions.json` has the shape of the harness's own DWARF cache
(`dwarf_truth`): `{"reader", "conflicts_dropped", "functions": {"%08x": {"name",
"arity", "returns", "parameters": [classes]}}}`, classes as `dwarf_types.classify`
returns (`int`, `uint`, `ptr`, `float`, `void`, `unknown`, ...); a key
`"<module>:%08x"` types a non-main module. It feeds `arity_accuracy` and
`type_exact_rate` exactly as the built-in DWARF images do. With no types file, a
`truth_kind: "dwarf"` image whose staged file still carries `.debug_info` is read
with `dwarf_truth` directly.

### Where a module is scored (matches how each importer places it)

The truth's modules are placed by what the import *did*, never by the truth's own
addresses (`wave_units`):

| module | placed as |
|---|---|
| `main` | the program the import made of `image` (`program_hint`; a container's `<name>.<part>` is found by prefix, else by the program holding most truth entries) over `ranges` or its executable regions, less the span of every REL/overlay row (the `kind` column of the `modules` table, `rel`/`overlay`) the program holds: a disc import's merged RELs, truth or not. The executable's own sections (`dol:N`, `prx:N`, kind `code`/`data`) are not modules |
| a REL merged by the disc import (`rel::attach`: DOL plus RELs in module-id order from `dol::rel_base`, 32-byte aligned) or an NDS overlay (`ov<N>`, its own program with one `modules` row) | the program meta.json names (`modules[].program`, e.g. a GBA `gba.ov<N>`) when the import has it and it is not the main program; else the project's `modules` table row, matched by exact name first and then by `alias` (`foresta.rel.szs` = `foresta`, `overlay_0005` = `ov5`), or the program whose last name component equals it (`<image>.ov5`): that program's executable regions inside the row's `[load, load + size)` (a module's own `ranges` replace them) |
| a module staged as its own file (`modules[].image` differs from `image`), or one whose `placement` in meta.json begins with `standalone` (the truth lists the addresses a standalone import gives, though a disc import also holds the REL merged) | imported on its own; a REL alone puts section *i* at `0x80000000 + i * 0x10000000` (so `.text`, section 1, is at `0x90000000`, which is what the GameCube truth lists for a standalone REL); a PS1 overlay without a PS-X EXE header, or a PS2 overlay that is not an ELF, is a flat dump at its `load_address` (`import --raw BASE --language` `PSX:LE:32:default` / `r5900:LE:32:default`: `wave.RAW_LANGUAGE`). Overlays sharing a load address are each their own program and project, never merged into main |
| a module inside the image that the importer does not place (an N64 overlay in the ROM: the ROM import maps the boot view, or a catalogued layout such as Perfect Dark's, and nothing else) | **unresolved**: not scored, listed in the report with its function count (`unresolved_modules`, `unplaced_functions`); never guessed from the truth's addresses |

A unit whose ranges hold under half of its module's truth addresses carries a
`warning` (the truth's address space is not the importer's for it). Several
modules may share an address (PSX map overlays, NDS overlays): every unit is
scored in its own program, and the sample, rows and types are keyed by module as
well as address.

A truth directory with `truth/types/functions.json` uses it and re-derives nothing from
DWARF. Only when it is absent, for a `dwarf` image whose staged ELF carries `.debug_info`,
is `dwarf_truth` called; if `dwarf1_types` refuses (`no struct layout measures long`,
`long width not established`: a DWARF 1 image whose structs do not fix the width of
`long`), the image runs **without** type truth and `images.<id>.dwarf.error` says why;
there is no silent default width. A builder who knows the ABI (PSP is ILP32, `long` = 4)
supplies the types file.

### Flags

| flag | default | meaning |
|---|---|---|
| `--corpus-wave` | off | run the contract images instead of the built-in list; `--images` filters by id; the configurations default to `default,baseline-off` |
| `-n N` | 200 (500 with `--corpus-wave`) | functions sampled per image and seed |
| `--seeds 1,2` | `1,2` with `--corpus-wave`; else `--seed` (20261006) | distinct seeds; one sample per seed |
| `--sample-verified` | off | draw only from `verified=1` functions |
| `--min-age-s` | 60 | skip a truth directory modified more recently |
| `--import-limit-s` | 7200 | per-import timeout |
| `--symtab-variants` | off | for every staged ELF that is run stripped, also run `<id>-symtab` (symbols kept, DWARF removed: `llvm-objcopy --strip-debug`), reported only in "Supplement: symtab variants" (like the PSP `-symtab` input: it isolates types from discovery, its discovery is the symtab's); not in the per-platform tables or sign tests |
| `--sign-include-mismatch` | off | treat `version_match: false` games as headline games (per-platform tables and sign tests) instead of the supplement table |
| `--no-truth NAME=PATH` | none | an image with no truth (a retail game), run for success and time only and reported as `pc-NAME` in an "Images without truth" table: import, export-c of up to 20 functions, with `--stock` stock's time and entry set and the agreement of the two (see "Windows PC") |
| `--stock` | off | run stock Ghidra on the main module (below) |
| `--ghidra`, `--stock-work`, `--stock-timeout` | `~/ghidra_12.1.3_PUBLIC`, `~/romwright-research-stock`, 14400 s | stock install; scratch project directory (Ghidra refuses a path element starting with `.`); per-run limit |
| `--out` | `benchmarks/reports/console_research_wave_<YYYYMMDD>.json` | the markdown is written next to it |

Results are per seed and combined. The sample of a seed is drawn exactly as the
built-in images' (`choose_sample`: size-stratified in four equal-count quartiles,
functions of the default import inside the unit ranges that the module's truth
names; DWARF-covered functions first), pooled over all placed units. **Combined is
the union of the seeds' samples, rows deduplicated by (module, address)**: the
decompiler is deterministic, so a function drawn twice is one function. The union
is decompiled once per configuration; the per-seed views are filtered from it.
`images.<id>.configs` is the combined result (the shape of the built-in report);
`images.<id>.per_seed.<seed>.configs` the per-seed ones. Cached samples are keyed
by the sha256 of `functions.tsv`, so a changed truth draws a new sample.

### Discovery: the frozen metric and the verified supplement

Headline recall/precision are m21-001's `score()` unchanged (truth entries inside
the ranges; hits = entries found; invented = found entries inside the ranges the
truth does not name), pooled over the placed modules (`score_found`; its equality
with `M21.score` is a test, `benchmarks/console_research_wave_test.py`). **Supplement**
(`recall_verified`, `precision_verified`, never judged, never in a verdict):

- `recall_verified` = verified entries found / verified entries inside the ranges;
- `precision_verified` = verified hits / (verified hits + found entries strictly
  inside a verified function's extent `[start, start + size)` that no truth row names).
  Such an entry is a false split of a function whose boundary is compiler truth.
  Entries elsewhere (padding, data, unverified code) are not judged, because a
  truth that only has the repo's own analysis there cannot say whether they are
  functions; a verified row of size 0 has no extent and judges only its own entry.

The headline stays the `verified`-blind number; the supplement answers "does the
score hold where the truth is compiler-exact". `recall_main` / `precision_main`
(and the verified pair) are the same over the main module alone, the scope stock
Ghidra is run on.

**Nested truth rows.** A map/PDB/DWARF truth can name addresses inside another function:
X360 `__unwind$N` SEH funclets (AMPED 3: 14,741 of its 17,210 size-0 rows) and `__savegprlr_N`/`__restfpr_N`
alternate entry points are size-0 rows nested in a parent's range; a DWARF size can also
straddle the next function's start (`psp-hot-pixel`: 3). Every such row is kept as a valid
discovery start (it counts in recall's truth and is a hit when found, and a found entry
at its address is never "invented"). Wherever a metric asks which function contains an
address (the supplement's extents above) the extent is the union of the sized rows, i.e.
the outermost function's, so a funclet inside a verified function never turns a found
entry into a "split" of itself. The count per image is reported as `nested_rows`
(`nested_size0_rows`: the size-0 ones; `straddling_rows`: nested rows whose own extent ends
past the outermost function's), per module in `truth_by_module`, and as the "nested (size 0)"
column of the markdown's Images table (`nesting()`).

**Images that do not run stay in the rollup.** An image whose import fails (or whose
files are absent) gets `status: error`/`skipped` with the reason, and a "did not run" row
in its platform table beside the games that ran; it is neither scored as zero nor dropped.

**Degraded imports are flagged.** Any import diagnostic of severity `degraded` (for example
`switch recovery decompile failed: native runtime: io: No such file or directory`, which a
missing `TMPDIR` or a tree without `native/build/ghidra_opt` causes) is copied to
`images.<id>.degraded_imports` (per configuration), logged, and shown in the Images table
of the markdown: such an import is not a valid measurement and the run is to be repeated on
a correct setup.

### Rollup, sign tests, stock Ghidra

The report (and its markdown, whose first sections are these) has one table per
platform (the id prefix): each game, with `default`, `baseline-off` and, with
`--stock`, stock Ghidra, over recall, precision, success rate, arity, type exact,
and the verified supplement. A multi-module image adds a "default (main module
only)" row beside stock.

The stock comparator is the existing one, not a new one: `analyzeHeadless`
configured as `benchmarks/import_speed.py` configures it per image
(`GHIDRA_CONFIG` for the built-in ids; `STOCK_PLATFORM` in the harness for the
platform prefixes it does not name: the same language/loader choices), default
analyzers, `benchmarks/ghidra/ExportFunctionEntries.java` for discovery and
`scripts/ExportDecompiledSignatures.java` at the sampled addresses for printed
signatures (as `benchmarks/psp_stock_compare.py` does). It reads the same stripped
twin our import reads (when `image` is a disc, which no stock loader opens, the main
module's own file, e.g. the DOL) and is scored by the same `score_found` over the same main
module ranges. It covers the **main module only** (a loader makes one program of
the staged image; a REL or overlay would need its own run), so the vs-stock rows
and sign tests use `*_main` for ours. Stock has no `export-c` success rate;
its `success_rate` is "the decompiler printed a parseable signature", shown but
not tested. Results are cached under `--cache/stock`; the language, loader and
reason are in the report.

**Stock that gives no result (2026-10-10).** A stock run has a time limit,
`--stock-timeout`: 3600 s with `--corpus-wave` (no game is worth more than an hour
of stock analysis; the slowest stock run that finished in the 2026-10-10 wave was
Golden Sun, 3,017 s at host load 9-18, the next 1,022 s), 14400 s otherwise. Over it, the run's whole process group is
killed (the JVM too; `analyzeHeadless` is a shell that forks it) and the game is
a **stock DNF**, labelled with the phase it was in (`stock DNF (>1 h
auto-analysis)` when `ExportFunctionEntries` had not run yet). When stock's own
analysis fails (`Import failed for file`, or the analyzer's `Abort due to
Headless analyzer error`), the game is a **stock crash**, labelled with the first
error the run reported and the analysis commands in its trace. Both are results
about stock: cached under `--cache/stock` like a success (a DNF is re-run only
when `--stock-timeout` exceeds the limit it was recorded at, or with
`--stock-retry-failed`), shown as a labelled stock row in the tables (not a
timing, not a zero), listed in `rollup().platforms.<p>.stock_excluded`, and in
**no** vs-stock sign test: such a game counts neither as a win nor as a loss.
A failure of our own export scripts is not one of these; it stays an uncached
harness error. `--stock-known-failure ID=SECONDS:EVIDENCE` records a DNF an
earlier run of the harness observed before failures were cached, with where
it is logged, instead of re-running stock to the same limit.

**Sign tests (supplement).** Over games, one-sided, for each headline metric
(recall, precision, success rate, arity, type exact) of `default` against
`baseline-off`, and (recall, precision, arity, type exact, and the verified pair)
against stock, per platform and over all games. A game is a win when `default`
beats the other by at least `RATE_THRESHOLD` (0.5 pp, the harness's materiality
floor), a loss when it trails by as much, otherwise a tie, which is dropped. The
p-value is P(X >= wins), X ~ Binomial(wins + losses, 1/2). With the 5-8 games per
platform the corpus has, p cannot go below 1/32 (5 games) to 1/256 (8): a platform
row that is 5/5 reads p = 0.03125 and is not "significant" at 0.01; the pooled
rows are the ones with power. Games with `version_match: false` (usable truth for another
build of the game) are **not** in the per-platform tables or the sign tests; they get their
own "Supplement: version-mismatch images" table (`rollup().mismatch`) unless
`--sign-include-mismatch` puts them back.

### Check: the TSV path reproduces the built-in numbers

For `gba-pokeemerald`, a scratch corpus directory (`~/runs/HarnessWave/scratch`,
not the corpus) holds a contract-shaped truth derived from the ELF's symbol table
(every `FUNC` symbol, `verified` 1, `ranges` = m21's, `truth/types/functions.json`
= the dwarf cache). The built-in spec and the TSV-driven spec, same cache, same
tools, `-n 200 --seeds 20261006`, `default` and `baseline-off`:

| config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|
| `default` (built-in spec = TSV spec) | 0.9761 | 0.9972 | 1.0000 | 0.9750 | 0.5732 | 200 |
| `baseline-off` (built-in spec = TSV spec) | 0.9504 | 0.9970 | 0.9650 | 0.9400 | 0.5608 | 200 |

The two reports (tools `4fea0a3df98a1a18`, host run 2026-10-10) agree on the sample
(the same 200 addresses, drawn again from the TSV: the cached sample is keyed by the
tsv's hash), the DWARF truth (15,678 functions, reader `pyelftools-tolerant`), and
**every key of both configurations' `summary`** (gotos, labels, warnings, lines,
recall, precision, arity, type slots, ...); the `vs_baseline_off` deltas agree on
every built-in metric. The TSV report adds only the supplement keys (`recall_verified`
0.9761 / 0.9504 = recall, since every ELF function is `verified`; `precision_verified`
0.9990 / 0.9988; `*_main` equal to the pooled values: one module). The scoring
functions are also checked on random data against `M21.score`, field for field, by
`benchmarks/console_research_wave_test.py`. The decompile result files are shared by the
two runs (same sample, project and tools give the same cache key; the decompiler is
deterministic), so what the check exercises independently is the sample draw, the DWARF
truth load, the module placement and the discovery scoring.

### First run (2026-10-09/10): what it measured and what it could not

`benchmarks/reports/console_research_wave_20261009.{json,md}` (tools `4fea0a3df98a1a18`, run on
nih-vps-u, written by the script): 14 staged images, `default` and `baseline-off`, stock
Ghidra on the main module, n = 500 per seed, seeds 1 and 2, `--symtab-variants`; 13 images
scored (gc: Melee, Wind Waker with its 415 RELs; n64: Ocarina of Time; nds: Pokemon Platinum
with 116 overlays; ps2: Dark Cloud, God Hand; psp: Hot Pixel, Melodie, Tetris; psx: Rage
Racer, Silent Hill with 49 overlays; wii: Super Mario Galaxy; x360: Burnout Crash) and one
that did not import. The numbers are in the report; these are the limits to read them with:

- **AMPED 3 (x360) did not import in the main report's build** (tools `4fea0a3df98a1a18`):
  `native: xex: PE image has no sections`; it is a "did not run" row in the x360 table, not a
  zero. The tree that has the XEX2 LZX fix imports it: a second, smaller report,
  `benchmarks/reports/console_research_wave_20261009_newtree.{json,md}` (tools
  `e2e3ae408552483e`, same flags, no stock), runs AMPED 3 (recall 0.9756, precision 0.9915; 14,740
  nested size-0 rows), Golden Sun (97 units: `main` plus `gba.ov0`..`gba.ov95`, placed by the
  `modules[].program` meta.json names) and NASCAR Heat 2002 (the RAM images `gba:ram.02000000` /
  `gba:ram.02000b96`, placed by their `modules` rows inside program `gba`). Its images are not in
  the main report's tables or sign tests.
- **Ocarina of Time scores 0.0446 recall because the N64 import maps only the boot view**
  (no segment layout in `n64_layouts.json` but Perfect Dark's): the compressed `code`
  segment and the 469 overlays (10,252 of 13,347 truth functions) are not in the import,
  listed as `unresolved_modules`. Stock Ghidra scores 0.0384 on the same bytes. It is an
  importer gap, not a decompiler measurement; it is in the tables and the sign tests.
- **Silent Hill and Dark Cloud overlays are flat dumps** imported with `--raw` at their
  load address; their discovery is what the flat-dump seeds give.
- **Stock covers the main module only**, on a sample of its addresses, so a multi-module
  image's stock row is not on the pooled truth (the "main module only" row beside it is).
- **Arity/type of a symtab variant is harness-limited when the names are mangled**:
  `psp-tetris-symtab` scores arity 0.03 / type exact 0.01 (stock 0.80 / 0.49), but 865 of its
  927 decompiled rows have no parsed signature: the symbol table makes the exported file's
  name the mangled one (`GetFileReadBuffer__9DTIniFileFv`) while the printed C names the
  function differently, and `signature()` finds a definition by name. The stripped
  `psp-tetris` row (arity 0.77) is unaffected. The frozen metric was not changed.
- The pooled sign tests (13 games, headline games only): `recall vs stock` 12 wins / 0 losses
  (p = 0.0002), `precision vs stock` 3 / 4 (p = 0.77), `precision vs baseline-off` 5 / 0
  (p = 0.0312), `recall vs baseline-off` 1 / 0 with 12 ties (the win is Pokemon Platinum,
  0.8884 against 0.8478). Per platform there are 1-3 games, so no per-platform p-value
  is below 0.125.

### Final run (2026-10-10): all 58 staged games

`benchmarks/reports/console_research_wave_20261010.{json,md}` (tools `5d47c57fe192c622`:
the tree after WiiDiscovery and ProgramOverhead, ghidra_opt `dbd7e74b`; run on nih-vps-u,
written by the script). Flags: `--corpus-wave --stock --symtab-variants`, n = 500 per seed,
seeds 1 and 2. That gives 66 rows: 58 games plus 8 `-symtab` supplements. Every row ran and
none is `degraded`. 55 games are headline games. Star Fox 64, Dragon Quest IV and NFS High
Stakes are `version_match: false` and appear in the supplement only.

The cache was warmed by parallel per-image workers (2 shards, then a queue of 4 workers),
and one serial pass assembled the report from it. Host load was 9–18 on 8 vCPU throughout,
so no wall time in this report is a timing claim; paired import timings are in STATUS.md.

Sign tests over games, as wins / losses / ties and one-sided p:

| platform | games | recall vs stock | precision vs stock | recall vs baseline-off | precision vs baseline-off |
|---|---|---|---|---|---|
| gba | 5 (3 with a stock result) | 3/0/0, p = 0.125 | 3/0/0, p = 0.125 | 2/0/3, p = 0.25 | 0/0/5 |
| gc | 8 | 8/0/0, p = 0.0039 | 0/0/8 | 0/0/8 | 5/0/3, p = 0.031 |
| n64 | 8 | 8/0/0, p = 0.0039 | 4/2/2, p = 0.34 | 2/0/6, p = 0.25 | 0/0/8 |
| nds | 4 | 3/0/1, p = 0.125 | 0/2/2, p = 1.0 | 4/0/0, p = 0.0625 | 0/0/4 |
| ps2 | 8 | 8/0/0, p = 0.0039 | 1/5/2, p = 0.98 | 0/0/8 | 6/0/2, p = 0.016 |
| psp | 5 | 5/0/0, p = 0.031 | 1/3/1, p = 0.94 | 0/0/5 | 5/0/0, p = 0.031 |
| psx | 7 | 7/0/0, p = 0.0078 | 5/0/2, p = 0.031 | 0/0/7 | 0/0/7 |
| wii | 5 | 5/0/0, p = 0.031 | 0/0/5 | 0/0/5 | 4/0/1, p = 0.0625 |
| x360 | 5 | 4/0/1, p = 0.0625 | 0/0/5 | 0/0/5 | 0/0/5 |
| **all** | 55 (53 with a stock result) | **51/0/2, p < 1e-5** | 14/12/27, p = 0.42 | **8/0/47, p = 0.0039** | **20/0/35, p < 1e-5** |

Arity and type are scored only where the truth carries types: 11 games against stock and
12 against baseline-off. Pooled arity vs stock is 6/2/3 (p = 0.14) and type exact vs stock
6/4/1 (p = 0.38). Per platform: x360 wins arity 5/0 but loses type exact 0/4; psp wins type
exact 5/0 and goes 1/2 on arity.

How to read it:

- **Discovery recall is the clear win over stock.**
  - It wins on every platform and loses on no game.
  - The largest gaps are on N64, where stock imports the ROM without a segment layout:
    Banjo-Kazooie 0.010, Ocarina 0.038, Perfect Dark 0.000, against ours at 0.95–0.99.
    GC and Wii follow: Skyward Sword 0.621 against ours at 0.989 on the main module, GC
    Pikmin 2 0.738 against 1.000.
- **Precision against stock is not won.**
  - Stock is more precise on most PS2 and PSP games and on two DS games. Pooled
    `precision_verified` vs stock is 6/12, against us.
  - The largest gaps are Super Mario 64 (0.905 vs stock 1.000) and God Hand (0.895 vs
    0.957).
  - Our extra functions on these platforms have not been classified yet. The Skyward Sword
    breakdown (WiiDiscovery in STATUS.md: mostly entries inside a truth function) is for
    one Wii game only.
  - Stock's own precision is lowest on two GBA games: Klonoa 0.015 and NASCAR 0.032.
- **Against baseline-off (switch recovery off, both the decompiler path and VSA), the
  research shows up as precision more than recall.**
  - Precision: 20 wins and 0 losses (GC, PS2, PSP and Wii).
  - Recall: 8 wins, 0 losses (DS 4/4, GBA 2, N64 2).
  - Success rate: 9/0.
- **Two games have no stock result.**
  - FE Sacred Stones is a stock DNF (>4 h auto-analysis).
  - KH Chain of Memories is a stock crash. In all three runs, Ghidra's auto-analysis
    stopped after warnings about the same function (`09df5f18`). It reported a
    `StackOverflowError` in `CreateFunctionCmd` / `CreateThunkFunctionCmd` twice, and once
    the locked-buffer assertion instead.
  - Both are labelled stock rows and are in no vs-stock test (section "Rollup, sign tests,
    stock Ghidra").
- **Multi-module images.** On images with overlays or RELs (Golden Sun, the DS games, PS1 games
  with overlays, Skyward Sword), the pooled recall and the main-module recall differ.
  Comparisons with stock use the main-module figure.

- **PS2 truth audit (2026-10-10, Ps2Truth).** The numbers above were measured on the PS2
  truth tables as extracted on 2026-10-09. Three of them were revised from the repos'
  own data; the old tables are kept as `truth/functions.pre-ps2audit.tsv`, every changed
  row with its evidence is in `truth/ps2audit-changes.tsv`, and meta.json `notes` says
  what changed. The frozen metrics are unchanged; only the truth differs, so the wave
  report above stays as written and a rerun against the revised tables is a new report.
  - **Ratchet & Clank (NTSC, PAL): padding rows removed.** 637 NTSC and 40 PAL rows were
    4-to-76-byte runs of `0x00000000` / `0xCDCDCDCD`. NTSC: every one lies in a raw
    `textbin` `text_gap_*` subsegment of `config/us/rnc1.us.yaml` (the extraction had
    switched the gaps to `asm`, so spimdisasm made each fill word a function), and none
    is in the repo's `config/ghidra/ghidra_functions.csv`. PAL: `docs/DECOMP_PROGRESS.md`
    and `src/libgcc/nonmatching_*.c` call them "not a real function / alignment padding /
    linker fill"; two verified 8-byte rows (0x1206A8, 0x1E9080) are the one-word
    remnants of dead-stripped functions (`src/libgcc/README.md`,
    `config/linker_remnants.txt`). None of the removed NTSC rows was verified.
  - **God Hand: 1,142 repo-named functions added, 203 unverified rows shortened.**
    `progress/unit_part_funcs.json` (`scripts/gen_part_funcs.py`: the start of every
    `glabel` in the uncarved fragments of the splat-disassembled `asm/cod/000000.s`)
    names 1,142 function starts that `carved_funcs` and `symbol_addrs.txt` do not: 865 in
    gaps between rows and 277 inside an unverified row. They are added with
    `verified=0`; the verified set (7,946) is unchanged. Our importer found 957 of them,
    stock 406.
  - **Audited and left alone.** God Hand 0x100000 and Digital Devil Saga 0x100000 are
    4-byte zero rows, but the repo declares both as functions (carved `func_00100000`;
    DDS takes its address as a function pointer in `.sdata`), so they stay. Dark
    Chronicle, Dark Cloud (main, title, dun), Fatal Frame and Persona 4 have no padding
    rows. Their truth is the retail symbol table or the repo's own function list, and
    every code subsegment of the repo's splat config has a row. Fatal Frame's one
    uncovered subsegment is VU microcode.

  | game (ours / stock) | truth rows | recall | precision | recall_verified | precision_verified |
  |---|---|---|---|---|---|
  | R&C NTSC, before | 2460 | 0.6463 / 0.5317 | 0.9882 / 1.0000 | 0.8850 / 0.7961 | 0.9911 / 1.0000 |
  | R&C NTSC, after | 1823 | 0.8607 / 0.7175 | 0.9751 / 1.0000 | 0.8850 / 0.7961 | 0.9911 / 1.0000 |
  | R&C PAL, before | 1862 | 0.8539 / 0.7030 | 0.9882 / 1.0000 | 0.8463 / 0.6951 | 0.9993 / 1.0000 |
  | R&C PAL, after | 1822 | 0.8595 / 0.7184 | 0.9733 / 1.0000 | 0.8474 / 0.6960 | 0.9993 / 1.0000 |
  | God Hand, before | 10091 | 0.9709 / 0.9117 | 0.8950 / 0.9565 | 0.9664 / 0.8919 | 0.9938 / 1.0000 |
  | God Hand, after | 11233 | 0.9574 / 0.8552 | 0.9825 / 0.9988 | 0.9664 / 0.8919 | 0.9938 / 1.0000 |

  Reading. R&C recall rises for both tools, and our precision falls 1.3-1.5 points
  because the importer makes a function of 21 (NTSC) and 24 (PAL) fill words; those
  entries were hits before and are invented now. That is an importer bug the old truth
  hid. On God Hand our invented entries drop from 1,149 to 192 (stock 418 to 12); 957 of
  the 1,149 were the repo's own functions. What is left of our precision loss is 48
  splits of verified functions, 104 entries inside unverified rows that the repo does not
  split, and 40 entries between rows. Baseline-off follows the same direction (God Hand
  precision 0.6375 to 0.6996, R&C NTSC 0.9117 to 0.8997, PAL 0.9112 to 0.8974). The other
  five PS2 truth sets are unchanged. No m21 truth reads these three tables; m21 uses the
  Capcom and dungeon-game ELF symbols only.

### PS2 rerun (2026-10-11): after Ps2Truth, Ps2Tables, Ps2Recall and Ps2Printer

`benchmarks/reports/console_research_wave_20261011_ps2.{json,md}` was written by the script on nih-vps-u from one build of the combined tree: tools `4b53a40d4bc45c90`, ghidra_opt `dbd7e74b`. Flags: `--corpus-wave --stock --symtab-variants`, the 8 PS2 games, n = 500, seeds 1,2, against the audited truth. All rows ran and none is degraded. m21-001 PASSes on the same build. Pairs are ours / stock.

| game | recall | precision | recall_verified | precision_verified |
|---|---|---|---|---|
| Dark Chronicle | 0.9987 / 0.9288 | 0.9955 / 0.9982 | 0.9987 / 0.9278 | 0.9996 / 0.9997 |
| Dark Cloud | 0.9988 / 0.9173 | 0.9889 / 0.9850 | 0.9988 / 0.9173 | 0.9978 / 0.9856 |
| Digital Devil Saga | 0.9974 / 0.8630 | 0.9987 / 1.0000 | 0.9976 / 0.8585 | 0.9993 / 1.0000 |
| Fatal Frame | 0.9958 / 0.8334 | 0.9951 / 1.0000 | 0.9959 / 0.8484 | 0.9951 / 1.0000 |
| God Hand | 0.9976 / 0.8552 | 0.9921 / 0.9988 | 0.9980 / 0.8919 | 0.9976 / 1.0000 |
| Persona 4 | 0.9992 / 0.9028 | 0.9931 / 0.9997 | 0.9993 / 0.8991 | 0.9986 / 0.9997 |
| Ratchet & Clank | 0.9281 / 0.7175 | 0.9912 / 1.0000 | 0.9245 / 0.7961 | 0.9941 / 1.0000 |
| R&C PAL | 0.9276 / 0.7184 | 0.9895 / 1.0000 | 0.9184 / 0.6960 | 0.9973 / 1.0000 |

- **Sign tests against stock** (wins/losses/ties):
  - recall 8/0/0 (p = 0.0039), recall_verified 8/0/0;
  - precision 0/4/4, where the 4 losses (God Hand, Persona 4, both R&C) are 0.66–1.05 points;
  - precision_verified 1/1/6.
- **Against baseline-off:** precision 5/0/3 (p = 0.031).
- **Stock's precision is near 1.0 on every PS2 game.** It creates only the functions its call-following analysis reaches, and it misses 7–21% of the truth doing so.
- **Our remaining invented entries:**
  - the switches Ps2Tables left refused: God Hand `cIDManager_getLocalFileName` and `func_0039A140`, Fatal Frame `FActExecOccur` and `SetRoomDirecPazzEne`;
  - R&C's hand-written `j`-target fragments, where no byte pattern separates function starts;
  - entries in stretches the truth does not cover.
- **Fatal Frame's decompile success** reads 0.9724, against 0.9796 on 2026-10-10. The two samples share only 213 of their functions, because the sample follows the import's function set. On those 213 the failures are 3 both times. Every failure in both runs is the same class: "partial access to `DAT_002527xx` has no scalar C type", in a global block at 0x252740–0x252760.

### PS2 precision (2026-10-12, Ps2Precision)

`benchmarks/reports/console_research_wave_20261011_ps2_precision.{json,md}` (script output, nih-vps-u, tools `8089735f6fb1f18e`, ghidra_opt `dbd7e74b`; `--corpus-wave --stock --symtab-variants`, the 8 PS2 games, n = 500, seeds 1,2; stock was reused from the cache). The report's decompile columns read 0.0000: the shared tree's `romwright-worker` printer now wants IR version 5 and this `ghidra_opt` emits 4 (`printer IR version 4 is not 5`, another agent's change; the native binary is not mine to rebuild). Discovery does not use that path, so recall, precision and the sign tests of discovery stand; the success column does not, and the 2026-10-11 report's numbers remain the last decompile measurement.

**Method.** Every "before" below is the same working tree with the rules of this section switched off, imported alike (the PS2 games with a symbol table are imported from the harness's stripped copy). The fill rule (6) is in both columns; Ratchet & Clank's 0x15eff8 is the only entry it changes. The frozen column is the 2026-10-11 report (tools 4b53a40d4bc45c90). Dark Cloud, Fatal Frame and Dark Chronicle are better than it by this section's rules (the call filter, the loop tails, the case blocks), checked in the same-tree comparison: 45 -> 37, 21 -> 3, 35 -> 29 invented, truth hits identical.

| game | recall | precision (was; frozen 2026-10-11) | precision, stock | recall_verified (unchanged) | gap to stock (was) |
|---|---|---|---|---|---|
| God Hand | 0.9976 | **0.9943** (0.9921) | 0.9988 | 0.9980 | 0.0045 (0.0067) |
| Persona 4 | 0.9992 | **0.9967** (0.9931) | 0.9997 | 0.9993 | 0.0030 (0.0066) |
| Ratchet & Clank | 0.9281 | **0.9965** (0.9912) | 1.0000 | 0.9245 | 0.0035 (0.0088) |
| R&C PAL | 0.9276 | **0.9947** (0.9895) | 1.0000 | 0.9184 | **0.0053** (0.0105) |
| Dark Chronicle | 0.9987 | 0.9963 (0.9955) | 0.9982 | 0.9987 | tie |
| Dark Cloud | 0.9988 | 0.9907 (0.9889) | 0.9850 | 0.9988 | win (+0.0057) |
| Digital Devil Saga | 0.9974 | 0.9987 (0.9987) | 1.0000 | 0.9976 | tie |
| Fatal Frame | 0.9958 | 0.9993 (0.9951) | 1.0000 | 0.9959 | tie |

- **Sign tests against stock** (wins/losses/ties): precision **1/1/6** (was 0/4/4; the loss is R&C PAL, 0.0003 past the 0.005 materiality floor, 9 invented entries where 8 would tie), precision_verified 1/0/7, recall 8/0/0 (p = 0.0039), recall_verified 8/0/0. Against baseline-off: precision 3/0/5.
- **recall_verified** is the same to four places on all 8 games; recall is the same on all 8 (hits identical in the paired imports: God Hand 11,206, Persona 4 13,091, R&C 1,692, PAL 1,690, Digital Devil Saga 10,325).
- **m21-001 PASS** on the same build (7 images). Capcom Fighting Evolution reads recall 0.9741 / precision 0.9945 (0.9762 / 0.9924 on 2026-10-11; floor 0.966) and dungeon_game 0.9872 / 0.9835 (0.9885 / 0.9822; floor 0.978). Capcom's truth is its own symbol table, and it names some case blocks the new case-block rule retracts (the rule off: 0.9763); the other five images are identical.
- **Other MIPS platforms** (PSP, PSX and N64 wave images, default configuration, `-n 4`, `gates_after`: the 24 images on the build of the report above; `gates_fix`: 9 of them on the final, gated build). The 9 N64 rows equal the 2026-10-10 report's to four places. PSX: Digimon World, NFS High Stakes, Parasite Eve 1 and 2, Legend of Mana equal it or move by 0.0003 or less (Legend of Mana recall 0.9695 -> 0.9698). The final build reads Silent Hill 0.9024 / 0.9883 (0.9879 before: the fill rule of the 2026-10-11 section, not this one), **Rage Racer** 0.9523 / 0.9948 as before, Vagrant Story 0.9481 / 0.9577 as before. PSP: **Tetris recall 0.9876, precision 0.9671; Camera 0.9597 / 0.9585** (floors 0.9600 and 0.9472; the older report: 0.9385 / 0.9710 and 0.9457 / 0.9600). The build the PS2 report ran on applied the off-grid-body rule and the call filter to every MIPS set: Persona 4's PS2 numbers are the same either way, but it dropped Rage Racer's truth function 0x80062dc4 (PS1 GTE words decode to nothing inside real functions) and gave Vagrant Story 0.9692. Both rules are now r5900-only, the PS1 and PSP rows read as before, and Vagrant Story's gain is given up. The PS2 numbers of the gated build are the report's (God Hand 64, Persona 4 43, R&C 6, PAL 9 invented; hits identical), and 498 `native::` tests pass on it.

**PSP overflow, found and fixed (2026-10-12).** The MIPS block of `interior_entries` and the new case-block / padding / hop rules read the word at `entry - 4`, `- 8`, `- 12` through a reader that added 4 to an offset unchecked. An entry at 0 or 4 of a PRX linked at base 0 (every PSP image here) wraps that address to the top of the space, and in a build with overflow checks `at + 4` panicked (`discovery.rs`, `attempt to add with overflow`); the release builds of the waves above wrap silently and read nothing, which is why no row of mine showed it. `word_at` now takes `checked_add`, `interior_entries` reads through it, and `has_undecodable_neighbour` saturates. Test: `the_mips_entry_rules_ask_about_no_address_below_an_image_linked_at_zero` (fails on the old reader with that panic, passes now). Measured on a release build with `overflow-checks = true`, 5 PSP wave images, default configuration, `-n 200`, seed 1, stock cached, against the 2026-10-10 report (recall / precision): Hot Pixel 0.8884 / 0.9057 (0.8883 / 0.8961), Melodie 0.9605 / 0.9477 (0.9605 / 0.8982), Pac-Man Rally 0.9074 / 0.9280 (0.9072 / 0.9035), **Camera 0.9597 / 0.9585 (0.9457 / 0.9600; floors 0.9600 / 0.9472)**, **Tetris 0.9876 / 0.9671 (0.9385 / 0.9710)**; no panic, no degraded import. Hot Pixel, Melodie and Pac-Man Rally are PRX images the 2026-10-11 notes say the MIPS rules do not apply to, so their movement is other agents' work in the shared tree, not isolated here. m21-001 PASS on the same build (Capcom 0.9741 / 0.9945, dungeon_game 0.9872 / 0.9835, Darkstalkers 3 0.9878 / 0.3663, the rest as before).

**Classes of invented entries**, before -> after (a function entry the import made that no truth row names; `where` = the truth row holding it, if any; classes assigned from the bytes by a script, `ps2_classify`-style, not by hand):

| game (invented) | in a verified function | in an unverified row | between rows |
|---|---|---|---|
| God Hand 87 -> 64 | case blocks 11 -> 0, branch target 6 -> 0 | case blocks 15 -> 12, branch target 2 -> 0, j target 4, tail 1, other 3 | frame-release tails 19, uncovered code 25, off-grid 1 -> 0 |
| Persona 4 91 -> 43 | called by data junk 3 -> 0, case block 1 -> 0, j target 1, other 9 | called 1 -> 0, off-grid 2 -> 0, branch target 1 -> 0, case blocks 4, j target 3, other 23 -> 22 | off-grid 35 -> 0, uncovered code 8 -> 4 |
| Ratchet & Clank 14 -> 6 | case blocks 6 -> 0, other 3 -> 1 | other 5 | - |
| R&C PAL 17 -> 9 | other 4 -> 2 | case block 7 -> 1, other 5 | uncovered 1 |
| Fatal Frame 21 -> 3 | case blocks 9 -> 0, branch targets 6 -> 0, other 2 -> 1 | branch targets 3 -> 1, other 1 | - |
| Dark Cloud 45 -> 37 | branch target 6 -> 1, other 3 | - | calls into the overlay window 31, off-grid 3 -> 0, uncovered 2 |
| Dark Chronicle 35 -> 29 | branch target 1, j target 1, other 1 | called 1 -> 0 | uncovered code 26 -> 24, off-grid 3 -> 0, called 1, case block 1 |
| Digital Devil Saga 13 -> 13 | case blocks 3 -> 4, branch target 1, other 2, off-grid 1 -> 0 | case blocks 6 | - |

**What each fix does** (all in `native/{discovery,switch_tables,vsa}.rs`; MIPS-only where marked; none has a truth row of its shape in the 8 games, except where said):

1. **Way-ins with a call or a sign-extension** (`vsa.rs`, `switch_tables.rs`). The dispatch of God Hand `cIDManager_getLocalFileName` 0x2ad018 is `sra s0,a3,24; jal; ...; sltiu v0,s0,7` on one way in and `lb s0` on the other, and the table base is a `lui` in the delay slot of the guard's branch. Three things kept it a NoStridedLoad: (a) any call in the line abandoned every candidate, though the ABI leaves the seed's callee-saved register alone (`Image::unaffected`, `SleighLifter::unaffected`); a call before the seed is defined changes nothing either; (b) a composed line (way in, guard, dispatch) seeded the index at the start of the line and the way in's own `sra`/`lb` overwrote it: the seed now holds where the leading part last defines it, only when that part defines before it reads (the ARM `movs r6,r0; moveq r0,#0; popeq` guard reads first and keeps the old reading), and a 32-bit definition widened by `INT_SEXT`/`INT_ZEXT` seeds the 64-bit register too; (c) `switch_lines` listed at most 3 ways in, and a loop dispatch has one per branch whose delay slot repeats the `sltiu` (func_0039A140: 5): now 8. God Hand `cIDManager_getLocalFileName`, `func_0039A140`, `_IO_vfscanf` and 0x22cbc8's 18-case table resolve (the last also needed the next rule).
2. **A table answered by VSA but cut off by another table's labels** (`switch_tables.rs`). Two dispatches in one function put the later one's case labels between the earlier one and its cases, so VSA sent the earlier table "outside" to the decompiler, which cannot bound it (0x22cca8). The next function now ignores the labels of every table answered in the round, for a table whose cases are all decoded; the table is held (`NativeImport::switch_deferred`, `settle_deferred_tables`) until the decompiler has answered its function, because the decompiler also answers the dispatches nested in that function, which taking the table at once lost (6 of God Hand 0x21a538's). What the decompiler leaves unanswered gets the VSA table.
3. **Case blocks of a dispatch no table was recovered for** (`interior_entries`, MIPS). An entry nothing calls, with no frame opener, not right after a `jr ra` or zero padding, held only by a run of 3 to 64 code pointers whose lowest target is within 16 bytes after an indirect `jr` through a register other than `ra`. Ratchet & Clank's 0x239b50.. are this: the index is `s8 = s7 << 2` defined in the loop head, a value-set pass with one seed per register cannot pair it with the guard on `s7`, which is why they are structural. A run of more than 64 words is a table indexed by a byte (DDS 0x30c344: 528 words, most of them the default 0x30c858, and the verified function 0x30c838 holds it).
4. **Loop tails laid out after the return** (`interior_entries`, MIPS): `sltu; bnez top; addiu; jr ra; move`, 20 bytes after the function's `jr ra`, reached by a branch from inside the function. The tail's own flow loops back into the function's code and reaches it first, so the existing "reached from another function's instruction" rule found no owner (God Hand 6, Fatal Frame 8, Dark Chronicle 3); the owner is the nearest entry below the branch, and only a piece that returns within 12 words and jumps nowhere before is taken.
5. **`jal`-shaped words of data** (`discover_mapped`, r5900): a scanned call with a word SLEIGH cannot decode within 16 words of it is not a call. Of Persona 4's 63,382 `jal` words, 63,039 of the 63,040 inside truth rows have none such near them and all 342 outside have (God Hand 2 of 40,411 inside); the data between the code and `.sdata` made 37 functions of 1 to 13 bytes in Persona 4 (Dark Cloud 3, Dark Chronicle 3). A body that proves a size off the 4-byte grid (decoded into undecodable bytes) is no function either (`undecodable_bodies`, r5900): 45 such entries in the 8 games, none of their ~54,000 truth rows.
6. **Fill** (`opens_with_alignment_fill`): three zero words followed by `cdcdcdcd` or by two code pointers are padding (Ratchet & Clank 0x15eff8, PAL 0x12f578).
7. **The block a jump hops over** (MIPS): the code right after `j L` / `b L` and its delay slot that is 8 to 32 plain instructions up to `L` is the jump's own function laid out between the jump and its target (R&C hand-written assembly: 0x217b38 under `j 0x217b58`, PAL 0x218a30). The separating evidence, from the bytes: a function that follows a jump to somewhere else returns or jumps before it gets there. Two truth rows have the shape (God Hand 0x347208, DDS 0x3059d0), both shorter than 8 words.

**What has no generic fix, and why.**
- **R&C `j`-target fragments: not one class.** 0x217b38 / 0x218a30 are the hopped block (7); the rest of R&C's remainder is truth's coarser granularity: in PAL's unverified rows the truth row starts at the tail pad `addiu sp,sp,16; nop` and runs on to the function (0x214770 -> ours 0x214778, 0x22f4c0 -> 0x22f4c8, 0x226808 -> 0x226818), where God Hand's truth lists the same pads as 513 rows of their own and 20 not at all. Which of the two a repository chose is the repository's, not a property of the bytes. The kernel exception handlers at 0x11d540..0x11d940 (`mfc0 ... eret`, one truth row for several) are real entries named by a data table.
- **God Hand, 64 left:** 20 pad tails of the above kind the truth lacks, 25 code entries in stretches the truth does not cover (0x3faf20.. past its last row: Sony library code, `lui a1,0x8007` register accessors, and gaps in the middle), 12 case-like entries held by data tables (the C++ exception tables 0x321694.. among them: landing pads next to real functions 0x3216b8 and 0x321738), 4 `j` targets, 3 other.
- **Persona 4, 43 left:** 9 `jr ra; nop` stubs inside rows the truth keeps as one function (func_004d6368 holds four), 13 Sony library functions at 0x70c6e0.. past the truth's gap, 4 `j` targets (crt0's loop at 0x100178 among them), 4 case-like entries, 13 singles in hand-written assembly and truth rows that start earlier than the function.
- **Dark Cloud: 31 calls into the overlay window** 0x1dabd00.. from main code. Those are real overlay functions (the title and dun modules at that address), scored against the main module's truth only.
- **SetRoomDirecPazzEne (Fatal Frame) does not reproduce:** the 2026-10-11 project already holds 0x147418 as an entry of 300 bytes and 7 targets at its `jr a0` (0x147440); the "host never found" was a classification script's miss, not the import.
- **R&C PAL is still a loss by 0.0003:** 9 invented entries where 8 would be a tie.

### Import precision against stock Ghidra (2026-10-15, ImportPrecision)

`benchmarks/reports/import_precision_20261015.{json,md}` (written by `benchmarks/import_precision.py`; nih-vps-u; tools `02fd4917ccfce59f`, `ghidra_opt` 486ace43 unchanged; the final tree adds only the two overflow guards of the harness paragraph below, which change no result);
the official-harness subset is `import_precision_20261015_harness_{psp,nds,hp}.{json,md}`; the rules-on-against-rules-off aggregate is `import_precision_20261015_loo.md`. The tool scores discovery only (nothing is decompiled): every image is a brand-new import
(`ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`, a cache of its own), scored by the wave scorer (`console_research.wave_units` / `score_units`, i.e. the frozen
`recall` / `precision` and the verified supplement, main module) against stock's function list taken from the research-eval stock cache (read-only; stock does not depend on our tree).
`import_precision.py` has `run`, `report` (sign tests, the per-image table, invented entries by class for both tools), `compare` (truth and invented entries gained or lost between two
runs, read off the two projects) and `features` (how each MIPS entry is reached). 53 headline games with a stock result (Star Fox 64, Dragon Quest IV and NFS High Stakes are version-mismatch
images and in no test; Fire Emblem and KH Chain of Memories are the stock DNF and crash).

**Result** (wins/losses/ties of ours against stock; a win or loss is 0.5 points or more):

| platform | precision before | precision after | precision_verified before | precision_verified after | recall after |
|---|---|---|---|---|---|
| all (53) | 13/10/30 (p = 0.34) | **15/2/36 (p = 0.0012)** | 6/9/37 | **6/2/44 (p = 0.15)** | 51/0/2 (p < 1e-5), recall_verified 52/0/1 |
| GBA 3 | 3/0/0 | 3/0/0 | 3/0/0 | 3/0/0 | 3/0/0 |
| GC 8, Wii 5, x360 5 | 0/0/18 | 0/0/18 | 0/0/18 | 0/0/18 | 8/0/0, 5/0/0, 4/0/1 |
| N64 8 | 4/2/2 | 4/0/4 | 2/3/2 | 2/0/5 | 8/0/0 |
| NDS 4 | 0/2/2 | 2/0/2 | 0/0/4 | 0/0/4 | 3/0/1 |
| PS2 8 | 1/1/6 | 1/0/7 | 1/0/7 | 1/0/7 | 8/0/0 |
| PSP 5 | 0/5/0 | 0/2/3 | 0/5/0 | 0/1/4 | 5/0/0 |
| PSX 7 | 5/0/2 | 5/0/2 | 0/1/6 | 0/1/6 | 7/0/0 |

"Before" is the tree at the start of the work (the PSP images rescored on the audited truth below; on the old truth the pooled precision was 14/8/30). Recall against stock is unchanged
(51/0/2) and every platform's precision is at or above stock's except two PSP games (Melodie 0.9917 against 0.9971, Tetris 0.9939 against 1.0, 0.54 and 0.61 points) and PSX's `precision_verified`
(Parasite Eve 2, below). Per-image numbers with before, stock and the invented entries by class are in the report. The imports of the platforms the work did not reach (GBA, GC, Wii, x360) equal the
2026-10-10 wave's to four places.

**What the invented entries were.** Each image's invented entries, classified by their position against the truth (inside a verified function, inside an unverified row, between rows, found by stock too),
by the entry's producer and by the bytes (`features`), before the work:

| class | where | cause |
|---|---|---|
| C++ landing pads | Hot Pixel 554 of the 656 entries inside verified functions | `.gcc_except_table` landing pads, entered by the unwinder only; the gap rule coins them after a `jr ra` |
| case blocks of a table that is not answered | Pac-Man Rally 258 (one 1,151-entry switch), Hot Pixel ~100, Tetris, Camera 01, Melodie 30-70 each | tables past 1,024 entries (value-set analysis and the decompiler both stop there), a default laid out before the dispatch, one table's words beside another's; the invented case entries then make the cases "outside" the function, which keeps the table unanswered |
| IDO's second return | Super Mario 64 362 (and Banjo-Kazooie, Majora's Mask, Ocarina: 1-12 each of another kind) | 320 of SM64's 3,813 truth functions end in `jr ra; nop; jr ra; nop`; nothing reaches the second return |
| dead epilogues after a loop that never exits | Dr. Mario 64, SM64, Banjo-Kazooie, Smash | `lw ra, N(sp)` or `b .+8` first: 0 of 26,000 truth starts opens that way |
| a branch table entered by `jr` | Tetris ~30 | `b L; slot` pairs |
| NDS autoload blocks | all four NDS games (KH 358/2 Days 117 of its 118 invented entries) | the ARM9's ITCM code was found as functions at the stored copy (0x020442a0..), and none of the 154 ITCM truth functions at 0x01ff8000 |
| fill before a pointer table | R&C PAL 1 | an 8-byte `rwx` region of zeros before a table that names `.rodata` |
| truth gaps | PSP, all five games: 187-233 stubs each | the DWARF truth cannot name `.sceStub.text` import stubs (8 bytes, `jr ra`); both tools find them and are charged for each. Audited below |
| coarser truth | PSX Parasite Eve 2, R&C PAL | not changed (below) |

**Is the metric fair to stock?** Stock's own invented entries (the report's right-hand columns): near zero on PS2 and N64 (stock does not invent, it misses 7-21% of the truth doing so);
tens to hundreds of shared "gap" entries on PSP, NDS, PSX and GC (real code the truth does not list, found by both); 18,793 and 24,327 on two GBA games (stock disassembles the whole ROM as code);
108 between truth rows on a PS1 game. So the shared entries are charged to both tools alike and stock's near-1.0 precision on PS2/PSP is real: it creates only what its call-following reaches.

**Truth audit (PSP stubs).** `truth/functions.pre-pspaudit.tsv` keeps the old table, `truth/pspaudit-changes.tsv` lists every added row with its evidence, `meta.json` `notes` carries the marker
"PSP TRUTH AUDIT 2026-10-14". Each of the five images has `.sceStub.text[.<library>]` sections: 8-byte stubs, every first word `jr ra` (checked), no truth row overlapping. Added as unverified 8-byte rows
(`sceStub_<addr>`): Hot Pixel 233, Melodie 99, Pac-Man Rally 200, Camera 01 206, Tetris 187. It raises stock's precision as much as ours (Hot Pixel stock 0.9633 -> 0.9988) and moves no verified metric; recall
rows change for both tools alike. The audit script was a throwaway (`~/romwright-scratch/ImportPrecision/pspaudit.py`).

**The fixes** (all generic; six `flag` rules in `compiler_rules/common.json`, read by `interior_entries`, switchable with `ROMWRIGHT_COMPILER_RULES_DISABLE`, `docs/compiler-rules.md` Appendix D; three non-rule fixes):

| fix | evidence |
|---|---|
| `landing-pad-not-entry`: an uncalled entry that is a landing pad of the image's own exception tables (`exception_sites`) | Hot Pixel with the rule off keeps 889 invented entries (361 with it, same build) and 27 fewer truth functions; 0 of its 9,983 truth functions is a landing pad; Hot Pixel is the only image of the corpus with exception tables, so the rule is neutral on the other 59 by construction |
| `wide-switch-case-blocks`, `case-run-in-one-function`, `branch-table-after-dispatch`: the case blocks of a dispatch that was not answered | invented entries before -> after, on the audited truth: Pac-Man Rally 261 -> 20, Hot Pixel 690 -> 32 (with the landing pads), Camera 01 64 -> 42, Melodie 73 -> 27, Tetris 87 -> 51; Digital Devil Saga 13 -> 3, God Hand 64 -> 57, Persona 4 43 -> 39 |
| `ido-leaf-return-pair` (compiler `ido`, and the image must do it: a quarter of its called frameless functions followed by a bare `jr ra; nop`) | SM64 368 -> 17; the first version, without the image's own habit, lost 29 truth functions of Banjo-Kazooie and 44 of Majora's Mask, whose real 8-byte stubs follow leaf functions |
| `epilogue-not-entry` | Banjo-Kazooie 12 -> 0, Ocarina 7 -> 0, Dr. Mario 64 15 -> 6, Majora's Mask 8 -> 3, Smash 9 -> 1 |
| NDS autoload blocks mapped at their run address (`native/nds.rs`; the stored copy is data) | KH 358/2 Days recall 0.8662 -> 0.9371 and precision 0.9395 -> 0.9995, Re:coded 0.8977 -> 0.9441 and 0.957 -> 0.9984, Platinum 0.9755 -> 0.9766, The World Ends With You 0.9042 -> 0.9087 (+300 truth functions, -241 invented on the four games); the ITCM functions decompile (harness subset below) |
| a zero word is no pointer in the run readers; fill before a pointer table that names any mapped address | Pac-Man Rally's runs had run into `.init` at 0; R&C PAL 9 -> 8 invented (0.9947 -> 0.9953, no longer a loss) |

**Leave-one-out.** `import_precision_20261015_loo.md`: the final build against the same build with the six rules off, 28 MIPS images (PS2, PSP, PSX, N64), each image a fresh import in both arms. The rules
removed 1,290 invented entries and cost 11 truth entries of about 110,000: SM64 3 (unverified `sub_` rows the repo's own disassembly splits, `jr ra; nop` each), Pac-Man Rally 4, Camera 01 2, Digital Devil
Saga 1 (0x30c838, a real function that a 528-word table of a state machine names), Hot Pixel 1 (and 27 gained); every other image identical in hits. The six rules are `on` by that evidence; held out
means every image the rule covers and was not derived on, so `landing-pad-not-entry` has no held-out game (no other image has exception tables) and `ido-leaf-return-pair` is held out on the 8 other
N64 games, which it does not touch (quorum). Two experiments are not in the tree: a PSP-relocation-only pointer rule (`R_MIPS_32` words only; Hot Pixel recall -24, invented -5) and a rule that
retracts every group of case blocks regardless of size (Pac-Man Rally -35 more truth functions, which are uncalled leaf methods; Persona 4 -7, Fatal Frame -3, Perfect Dark -5, Parasite Eve -3): the final
rule retracts a group only at 64 members or more.

**Not fixed.**
- PSP: Tetris (30 case blocks and branch tables left, 0.9939 against 1.0 and `precision_verified` 0.9938) and Melodie (precision 0.9917 against 0.9971). What is left there are tables whose words the importer
  reads as runs of other tables' words, and VFPU bodies that the decoder stops in (Allegrex VFPU words are undecodable: the walk ends and the next instruction is coined).
- PSX Parasite Eve 2 `precision_verified` 0.9542 against stock's 0.9622: 9 entries made by constant propagation and 8 others sit inside verified rows whose sizes come from a global-only map (the PS1 truth has
  no sizes for file-local functions: m21's `precision_corroborated`); stock shares 40 more. A truth property, not an importer error; left as it is.
- R&C PAL's 0x214778.. entries (the truth row starts at the tail pad), God Hand's 57 (real code in stretches the truth does not cover), Persona 4's 39 (Sony library code past the truth's last row): truth granularity.
- The rules' own cost: 11 truth entries of the 28 MIPS images (Leave-one-out above); recall against stock is unchanged on all of them.

**Gates.** m21-001 PASS, 7 images (`m21_final`: Capcom Fighting Evolution 0.9692 / 0.9945 against the 0.966 floor, was 0.9741 / 0.9945; dungeon_game 0.9885 / 0.9847; the other five unchanged). Filtered tests (`native::` and `compiler::`, 531 passed, 2 ignored)
including four new: `native::nds::tests::{the_autoload_list_names_where_each_block_is_stored, autoload_blocks_map_where_they_run_and_the_stored_copy_is_not_code}` and
`native::discovery::tests::{a_landing_pad_the_exception_tables_declare_is_not_a_function, a_block_that_reloads_the_return_address_first_is_the_epilogue_of_the_function_above}`.
**Official harness subset.** `console_research.py --corpus-wave --stock --symtab-variants --configs default -n 60 --seeds 1` on the five PSP games with their symtab twins, the four NDS games and Super Mario 64
(stock reused where the sample matched; a new sample runs stock again): every row that ran decompiled 100% of its sample (success 1.0000), and its recall and precision rows equal this tool's (Hot Pixel 0.8924 / 0.9965 / 0.9990,
stock 0.5839 / 0.9988 / 1.0). Over the five games of the NDS and SM64 run (tools `013b5a2d6181c841`, the build before the overflow guards and the final case-run scope; neither reaches ARM or SM64's rules): recall 4/0/1, precision 2/0/3 (Kingdom Hearts 358/2 Days and Re:coded), `precision_verified` 0/0/5, success 1.0000 on every row. Hot Pixel's symtab twin, rerun with the final build: precision 0.9975 / stock 0.9991, `precision_verified` 0.9999 / 1.0. A first PSP run failed Hot Pixel's symtab twin with `attempt to add with
overflow` in `src/native.rs` `mips_gap_starts` (its `word` closure, `at + 4`; the workspace builds with overflow checks): the twin's entry list changed with the rules and a body ending below 8 reached it. Both `word` closures of that
file now use `checked_add`, and the eight symtab twins (PS2 and PSP) import without a panic.

**Import wall time** (the baseline binary and the final one alternating, 3 repetitions each, one image at a time on a shared host at load 6-18; medians in seconds): GC Pikmin 22.6 -> 22.5, SM64 14.1 -> 15.2, KH Re:coded
21.8 -> 21.1, Fatal Frame 13.9 -> 10.3, Persona 4 40.1 -> 39.4, Tetris 13.0 -> 13.1, **Hot Pixel 34.2 -> 43.4 (+27%)**: its switch phase's decompiler lanes go from 7.2 to 12.3 s (the retracted case blocks no longer make the dispatches
"outside", so more of them reach the decompiler) and the rest is equal. So import time is not worse except on Hot Pixel. The report's per-image "import s" columns come from runs at load 6-60 and are not timing claims.

### Join contract for another tool's comparator column

Another tool's numbers are never written into these files. A comparator (any tool the
project may not publish beside the others, or one that simply is not a stage of this
harness) runs on the same images and writes **only its own report**,
`benchmarks/reports/console_research_wave_<tool>_<date>.{json,md}`, and joins to this
report on what the JSON carries:

- `images.<id>`: the key is the image id (`<platform>-<slug>`, the truth directory's `id`);
  `-symtab` twins are `<id>-symtab`. `schema` (`console-research/2`), `seeds`, `n` and
  `mode: "corpus-wave"` say how the sample was drawn.
- `images.<id>.samples.<seed>`: the sampled functions of each seed, as address labels
  `%08x` (the main module, in the address space the importer gives it) or
  `<module>:%08x` (another module); `images.<id>.sample` is their union (the combined
  result). A comparator scores exactly these labels, per seed and combined.
- `images.<id>.units[]`: where each scored module lives (`module`, `program`, `ranges`,
  `placement`, `warning`), so a label can be resolved; `images.<id>.wave` carries the
  contract's `meta.json` fields, `version_match`, the per-module truth counts, nested and
  unplaced counts. The truth itself is `<corpus>/<id>/truth/functions.tsv` and
  `types/functions.json`, never copied into the report.
- The comparator's rows use the summary keys of `images.<id>.configs.<name>.summary`
  (`recall`, `precision`, `success_rate`, `arity_accuracy`, `type_exact_rate`,
  `recall_verified`, `precision_verified`, `sampled`, ...), computed with the functions
  this harness already uses (`console_research_wave.score_found`,
  `console_research.dwarf_scores`; `rollup` / `tests_over` take any `{tool: summary}`), and
  carry the same image ids, so its own rollup and sign tests line up game for game with the
  ones here. The join is by id and label only; nothing in this report refers to the
  comparator.

A comparator that follows this contract and is internal-only (its vendor's licence restricts publishing benchmark data) exists: `benchmarks/hexrays_wave.py` writes `benchmarks/reports/console_research_wave_hexrays_<date>.{json,md}`, reading the samples from `--wave-report` and covering each image's main module only. Its numbers are in no other report or document.

### Reproduce

<!-- not gated: the corpus wave needs the staged contract images and hours of import time -->
```sh
# the contract images that have been staged, default configurations, n=500, seeds 1,2, stock Ghidra,
# and the symtab supplements
python3 benchmarks/console_research.py --corpus-wave --stock --symtab-variants \
    --out benchmarks/reports/console_research_wave_20261009.json
# a subset (a stock run needs a few GB of heap; GHIDRA_HEADLESS_MAXMEM=6G worked on a loaded host)
python3 benchmarks/console_research.py --corpus-wave --images gc-melee,psx-rage-racer --stock
# the pokeemerald check
python3 benchmarks/console_research.py --images gba-pokeemerald --configs default,baseline-off --no-m22 -n 200 --seed 20261006
python3 benchmarks/console_research.py --corpus-wave --corpus SCRATCH_CORPUS --min-age-s 0 --images gba-pokeemerald --configs default,baseline-off --no-m22 -n 200 --seeds 20261006
# discovery precision against stock's cached function lists (nothing decompiled), fresh imports; see "Import precision"
python3 benchmarks/import_precision.py run --cache DIR --out run.json --tools-target TARGET_DIR [image ...]
python3 benchmarks/import_precision.py report run.json [more.json] --before base.json --md out.md --json out.json
python3 benchmarks/import_precision.py compare base.json run.json      # truth entries gained or lost, per image
```

## Universal fact pack: leave-one-out on the 58 truth games (2026-10-11, FactEval)

`benchmarks/reports/fact_pack_loo.{json,md}` (written by `benchmarks/fact_pack_eval.py` on nih-vps-u; never edit by hand) measures the universal fact pack (`romwright_facts::pack`, built from the 48 decomp games by `benchmarks/fact_pack/build_pack.py`): a shipped, read-only SQLite file of one-way digests of relocation-masked function bodies plus facts (name, size, prototype text), each with its donor's game, repo, commit and SPDX license. It holds no code bytes. A function of a user's import whose masked body equals one a decomp named gets that name, that exact size, and the donor's prototype.

- **Method.** For each of the 58 truth games, `romwright facts apply --scan --json --exclude <game>` on a private copy of the game's default cached import (default environment key; apply writes, the research cache is untouched). The pack removes the game and its twin group (Pikmin 2 on GC and Wii, Ratchet & Clank NTSC and PAL) from every consensus, so one pack serves all 58 runs; a donor of the excluded game turning up in a match is counted as a leak (0). The 10 psp / x360 dwarf / pdb games are not donors and are reported apart. A **self** run (no exclusion) on three games shows what a user gets for a game that has a decomp.
- **Scoring.** Against each program unit's truth, over the unit's ranges, as `console_research.wave_units` places them (the harness reuses it; 7 N64 games leave 42,590 truth functions in unplaced overlays unscored, listed in the report). A rename is correct when the name equals the truth name after stripping leading underscores and case, or after reducing both to the base name (MWCC `Update__8UberBondFv` = `UberBond::Update`); a truth name that is generic (`func_80123456`, `FUN_`, `sub_`, `fn_`, `lbl_`, address-suffixed) is unscoreable. Correct names whose class differs from the truth's (same method name, different class) count as correct by that rule and are reported separately.
- **Pack.** 48 donors, every license recorded verbatim and none filtered (CC0-1.0 16, MIT 8, Unlicense 1, GPL-3.0 2, NOASSERTION 5, none 16); 483,248 masked bodies (386,975 named), 373,710 prototypes; **106.0 MB on disk** (a first build without prototypes, and before the PSX donors added bodies, was 63.8 MB).
- **Rename gate (shipped, stored in the pack's meta as `gate_min_donors` = 2 and `gate_short_body` = 128).** `facts apply` renames a `FUN_` function only when the matched body is at least 128 B, or at least 2 independent donors (a twin group counted once) agree on its name; shorter single-donor matches are reported as `gated` and write nothing. The gate comes from the gating study below.
- **Headline, leave-one-out over the 48 donor games, gated** (651,950 functions probed, 49,272 matched; 7,904 abstained for ambiguous or nameless donors; **17,396 gated**):
  - **23,466 `FUN_` renames** (ungated, 2026-10-11: 30,804). **Strict wrong-name rate 2.3% (457 wrong of 20,144 scoreable renames)**, against 4.5% (1,197 of 26,539) ungated. **Function-wrong renames (the name of another function put on this one) 26 = 0.13%**, against 161 = 0.61% ungated. 19,687 correct (19,581 equal after normalizing, 84 of the rest name a different class than the truth's; the remainder after demangling to the base name); 3,322 unscoreable (generic truth names or no truth row). The report's gate table sets the two side by side per platform, the ungated side read from `fact_pack_gating.json`.
  - Per platform, strict wrong rate gated (ungated): gc 0.4% (1.6%), wii 0.3% (1.7%), ps2 1.2% (2.3%), psx 6.3% (14.1%), n64 7.8% (12.3%), nds 15.9% (17.0%), gba 15.9% (13.4%). Function-wrong gated: gc 7, wii 6, nds 6, n64 4, psx 2, ps2 1, gba 0. The GBA and NDS rates are naming conventions several donors share (m4a names, NDS SDK names across versions), which a donor count cannot see.
  - Wrong names by kind, gated: 333 different plain names (another convention for the same function, or a collision the names cannot tell), 90 affix conventions, 19 spelling, 15 collisions. Convention mismatches are visible in the pair table; shared stub bodies show in the pack-name table.
  - **Prototypes applied as inferences: 20,894** (27,135 ungated: a gated match writes no prototype).
  - **Scan boundary precision** (scan rows are not gated and write nothing): of 657 scan matches, 586 (89.2%) start at a truth function; of the 582 hits with a known size, 494 (84.9%) have the exact truth length (75.2% of all scan matches have a correct start and length). Scan-found names are wrong 33.8% of the time (115 of 340 scoreable).
  - On functions the import already found (gated matches excluded), our size equals the pack length for 91.7% (28,638 of 31,219). Against truth the pack length fixes 2,287 sizes the import had wrong and breaks 241 it had right; where our size differs from truth it is shorter 2,372 times and longer 36 (ARM / Thumb: the import's size stops before the literal pool the truth includes, 39-46% agreement on gba / nds against 95-99% elsewhere).
  - **Self mode** (no exclusion, gate on): gba-kh-chain-of-memories 2,065 renames, 0 wrong (1,674 gated); gc-pikmin 3,832, 0 wrong (1,915 gated); n64-super-mario-64 2,295, 1 wrong (879 gated). A game's own bodies are one donor, so short bodies only it names stay gated.
  - **Out of corpus** (psp x5, x360 x5): 0 renames in 209,990 functions probed (1 gated; the 10 games' architectures and compilers have no donor: Allegrex and Xenon code against PS2 / PSX / Gekko donors), and 16 scan matches (7 starts hit); no x360 body matched.

**Gating study** (the decision behind the gate; `benchmarks/fact_pack_gating.{json,md}`, `benchmarks/fact_pack_gating.py`; per-rename rows stay on the host as `~/runs/FactEval/gating-renames.jsonl`). The same 30,804 leave-one-out renames, each kept with its length, agreeing donors and compiler families, replayed under candidate gates. Strict wrong = every scoreable non-correct rename (4.51%); function-wrong = a collision, the name of one function put on another (161, 0.61%). What predicts a wrong name is how few donors agree: 1 donor 8.48% strict (13,811 renames), 2 donors 3.52%, 3-4 donors 0.76%, 5+ donors 0.11%; by body length, 32-47 B 10.9%, 64-95 B 6.4%, 128+ B 2.3%. Gates on the pack's body length and donor count: `>=2 agreeing donors if the body is under 128 B` keeps 23,526 renames (76.4%; 19,727 of 25,342 correct) at 2.34% strict and 0.19% function-wrong; `>=2 donors` at any length keeps 16,993 (55.2%) at 1.35% strict and 0.16% function-wrong; counting a twin group once (`>=2 independent donors`) with `len>=48` keeps 15,282 (49.6%) at 0.97% strict and 0.04% function-wrong. A minimum length alone is a poor trade (`len>=128` keeps 53% for 2.32%). Requiring the donor compiler family to equal the target's, detected from the run's own donor vote or from the truth, removes only 1-4% of the renames and moves the strict rate from 4.51% to 4.41% (detected) / 4.48% (truth): wrong names are not cross-family. The detection also misreads the family of 7 of 8 PS2 units (the MWCC PS2 donors out-vote EE GCC). The gates do not fix GBA and NDS, whose wrong renames are naming conventions that several donors share (GBA 20.2% strict and NDS 13.7% with `>=2 donors`). Aliases against wrong functions inside the 826 `different` rows: rule A (the pack's name is another function's truth name in the target) is already how `collision` is assigned and settles none of them; rule B (another donor gives the truth name to the same digest) settles 7, all through a donor that holds the body twice, a shared stub, so more a collision than an alias; the excluded game's own row has the truth name on the same digest in 810 of 826, so it cannot separate them. 819 stay unsettled (20 random pairs in the report; most are convention differences of SDK and library names between donors).

Reproduce (host with the cached imports and a `romwright-cli` with `facts`):

<!-- not gated: needs cached imports and a built romwright-cli on a research host; recorded recipe -->
```sh
python3 benchmarks/fact_pack/build_pack.py --cli target/release/romwright-cli     # -> ~/runs/FactEval/fact-pack.sqlite (+ .manifest.json)
python3 benchmarks/fact_pack_eval.py --cli target/release/romwright-cli            # -> benchmarks/reports/fact_pack_loo.{json,md}
python3 benchmarks/fact_pack_gating.py --cli target/release/romwright-cli          # -> benchmarks/reports/fact_pack_gating.{json,md} (ungated renames; run with the gate off: facts set-meta --pack P gate_short_body 0)
(cd benchmarks && python3 -m unittest fact_pack_eval_test fact_pack_gating_test)                         # name normalization, scoring, twin exclusion
```

## Supplement: Hex-Rays comparator (internal only)

A Hex-Rays (IDA Pro 9.4, idalib) comparison exists, and its numbers are deliberately not in this document or in any shared report. Hex-Rays' EULA (`license.txt` in the IDA install), section 2.1(v), restricts benchmarking the Software and publishing performance data "without first inviting HEX-RAYS to review the results"; Hex-Rays has not been invited to review it. The reports are internal: do not publish, quote or commit them. `.gitignore` excludes `benchmarks/reports/*hexrays*`, so the files below exist only in the checkout that ran the comparator.

- Built-in images: `benchmarks/hexrays_research.py` writes `benchmarks/reports/console_research_hexrays.{json,md}`.
- Corpus wave: `benchmarks/hexrays_wave.py` writes `benchmarks/reports/console_research_wave_hexrays_<date>.{json,md}`. It joins the wave report(s) by image id and sample label (the join contract above) and never draws a sample.
- Method, no numbers: IDA runs auto-analysis only (no script, no Lumina) as Hex-Rays ships it; the install's three non-Hex-Rays plugins are left out of the headline. It scores with the harness's own functions (`console_research_wave.score_found`, `console_research.dwarf_scores`, `locals_truth.score_function`, `spurious_gotos.score`). Where IDA has no loader (GBA, NDS, DOL, Vita and XEX payloads) the main module is a flat image at the importer's load address with the importer's entry point seeded; a function IDA did not find at a sampled address is created for the decompile metrics only, never for discovery. IDA covers one program, the main module; overlays and RELs are listed as not covered. At most two IDA processes run at once.

## Supplement: C output on matched Persona 4 functions (m22-002, 2026-10-10, Ps2Match)

m22-001 compares C against agbcc objects on 33 GBA functions. m22-002 is the PS2
counterpart, `tests/m22-002_ps2_c_output.py`: report
`benchmarks/reports/m22-ps2_p4.{json,md}`. It answers one question: on functions
whose original source is known to compile to the retail bytes, how close is each
tool's C to that source's code, and how often does the C compile at all.

**Command** (needs `/var/tmp/p4ci`, `wibo`, `m2c`, `objdiff-cli`, the release
`romwright-cli`/`romwright-worker`, `native/build/ghidra_opt`, network for the first
clone; a stock run needs Ghidra 12.1.3, see below):

<!-- not gated: about 25 minutes cold and needs network plus cross toolchains; recorded recipe -->
```sh
python3 tests/m22-002_ps2_c_output.py                      # about 25 minutes cold, 200 functions
python3 tests/m22-002_ps2_c_output.py --selftest           # unit checks of the parsers, no tools
python3 tests/m22-002_ps2_c_output.py --sample-out FILE    # the sample's addresses (for a stock run elsewhere)
python3 tests/m22-002_ps2_c_output.py --stock-export-only FILE --work DIR --toolchain DIR   # stock Ghidra only
python3 tests/m22-002_ps2_c_output.py --stock-json DIR/stock/signatures.json               # reuse that export
python3 tests/m22-002_ps2_c_output.py --seed 20261011 --layers romwright,m2c \
    --report benchmarks/reports/m22-ps2_p4_seed20261011.json                               # the second sample
python3 tests/m22-002_ps2_c_output.py --compiler eegcc     # the ee-gcc 2.96 units (needs the i386 ee-gcc, EE assembler, --glibc32)
```

**What is pinned.** The decompilation `Raikaru/Persona4-Decompilation` at
`509519da5809d4958d55520e7d257b75cb69cd51` (the commit the corpus truth was made
from), cloned and set up by the script with the repo's own steps (`tools/build.py
--setup-only`, `make split`, `make regenerate-asm`) and scored with the repo's own
`tools/verify.py`. Toolchain: MWCCPS2 3.0.1 b210 (sha1 `f97b1b21…`) and b119
(`e1d2064e…`) from `/var/tmp/p4ci`, run under wibo; GNU r5900 assembler for the repo's
INCLUDE_ASM splice; objdiff-cli 3.6.1; m2c 0.1.0 (pip, git commit
`708d2d2cb2698f091a92492b328f73b24209f72d`, run as an external tool; its
`m2c_macros.h` is fetched at that commit and only included at compile time); stock
Ghidra 12.1.3 `r5900:LE:32:default`. The seed is 20261010 and the sample 200.

**Matched functions.** `verify.py --skip-gcc-units` reports 8474 MATCH functions; 6445
are 32 to 1024 bytes. Sampling shuffles them (sorted by address) with
`random.Random(20261010)` and takes the first 200 whose definition is found in the
preprocessed unit and whose body has no inline assembly (2 rejected). Each function
is compiled with its own unit's compiler and flags: b210 `-O2` (188 functions), b210
`-O2,p` speed units (5), b119 `-O4,p` RenderWare units (7).

**Candidates.**

| layer | input | how |
|---|---|---|
| romwright | stripped retail ELF | one import, then per function `assert-names` (the unit's own names for the target and its callees, from the verify report's relocation symbols), `assert-prototypes` (target and callees, from the unit's declarations erased to Ghidra primitives and `void *`), `export-c --context` |
| m2c | the function's splat assembly (`asm/code*.s`) | `-t mipsee-mwcc-c --valid-syntax --context`; mechanical edits only: gp-relative operands as `%gp_rel(symbol)($gp)` (symbol from the object's relocation, else the repo's symbol table), call targets named by the object's relocations, jump tables from the retail image |
| stock | the same ELF | Ghidra headless, default auto-analysis, `scripts/ExportDecompiledC.java` (C text, plus an `extern` per global it names); the decompiled name is replaced by the target's |

The context is the unit's own declarations as `mwccps2 -E` leaves them (typedefs,
struct/enum definitions, externs, prototypes; data definitions become externs,
function definitions prototypes; pointers to anything but integer/float types become
`void *`, as in m22-001) plus the `#pragma` lines in force at the target. Every
candidate is compiled twice through the repo's `mwccgap`: `context` (headline) and
`standalone` (typedef prelude, pragmas, m2c macros, candidate); `best` takes the
better of the two per function.

**Scores.** `exact` is `verify.py`'s MATCH criterion (same length, every byte equal
outside relocation fields, zero padding after); `exact (symbols too)` also requires
each relocation's symbol and addend to resolve to the retail operand. `percent` is
objdiff's `match_percent` (`functionRelocDiffs=none`, the repo's convention); an
unproduced or uncompilable candidate scores 0. The compile-failure share counts a
function a tool produced nothing for.

**Result** (200 functions; two complete runs gave identical rows and numbers):

| variant | layer | compiled | compile-failure share | exact | mean percent (all) | mean percent (compiled) |
|---|---|---|---|---|---|---|
| context | romwright | 143 | 28.5% | 14 | 52.1 | 72.9 |
| context | m2c | 101 | 49.5% | 32 | 40.4 | 80.0 |
| context | stock | 109 | 45.5% | 7 | 37.1 | 68.1 |
| standalone | romwright | 140 | 30.0% | 12 | 49.9 | 71.2 |
| standalone | m2c | 45 | 77.5% | 12 | 16.4 | 72.7 |
| standalone | stock | 125 | 37.5% | 8 | 42.8 | 68.6 |
| best | romwright | 169 | 15.5% | 16 | 62.1 | 73.5 |
| best | m2c | 107 | 46.5% | 32 | 42.8 | 79.9 |
| best | stock | 127 | 36.5% | 8 | 43.4 | 68.4 |

Paired on percent (context): romwright above m2c on 87 functions, below on 60 (sign
test p = 0.03); above stock on 100, below on 41 (p < 1e-5); m2c above stock on 79,
below on 57 (p = 0.07). On `best`, romwright beats m2c 96 to 62 (p = 0.008).

**Reading it.**

- m2c is ahead on exact matches (32 against 14 for romwright) and on the percent of what
  compiles (80.0 against 72.9); romwright is ahead on how much compiles and on the mean
  percent over all 200. Neither tool reaches exact on any function above 255 bytes.
- The matched set is partly m2c's own output: 102 of the 200 are in `src/promoted`
  (verified m2c candidates promoted by `tools/m2c_bulk.py`). On that stratum m2c is exact
  on 19, romwright on 12, stock on 6; on the other 98, m2c 13, romwright 2, stock 1. Read
  m2c's exact count as an upper bound for unseen code.
- 49.5% of m2c's context output does not compile as printed. The first errors are pointer
  and integer conversions (30), calls of non-functions (22: an indirect call through a
  global, printed `*D_00887300(0xEU, 0U)`, which C parses as a call of the global),
  pointer arithmetic on `void *` (15) and undeclared names (10, among them `s128` and
  stack slots). Compiled without the unit's declarations (`standalone`) 77.5% fail.
- romwright's 54 context failures: 40 are `illegal implicit conversion`. Six sampled
  ones, read at the failing line: three assign a callee's result to an integer local
  (`temp_v1 = func_0029d050();`, the asserted prototype returning a pointer), one stores
  a function address through `code **`, two are call arguments. 3 functions have no
  `export-c` candidate because the import never found a function there (0x2e6b20,
  0x3e3680, 0x501160). Measured in the update below: the declared return type taken into the
  local, and a cast at the other pointer/integer conversions, removes 39 of the 40 (the last passes a struct by value).
- stock's text is not meant to compile (26 `call of non-function`: `(*DAT_00887300)(0xe,0)`
  with the global typed `undefined4`; 18 undeclared names); it is scored the way m22-001
  scored it, so its percent is a lower bound on what a person reading it could use.

**Limits.** All of these are also in the report's `limits`.

- Persona 4 only, MWCC units only (as of this run; the ee-gcc units are the separate
  `--compiler eegcc` lane since Ps2CMatch, below). The 339 units listed in
  `config/gcc_units.txt` that hold functions were excluded here: the supplied ee-gcc 2.96
  and Sony assembler are i386 binaries whose loader path (`/lib/ld-linux.so.2`) this host
  lacks, and the repo cannot build them without it (`verify.py` gives COMPILE_ERROR for
  every function in them). The toolchain was not substituted in this run.
- Per-function `#pragma` state (optimisation level, scheduling) is replayed for every
  layer: no decompiler chooses it, and without it a function matched at `-O1` is
  unreachable at `-O2`.
- romwright's prototypes accumulate in one project in address order; a callee the unit
  does not declare keeps one asserted for an earlier unit.
- The matched sources came from a workflow with m2c (and romwright) in the loop; see above.
- The context was neutralised for pointer types only. A candidate that mentions a struct
  by value, or a function whose declared parameters the tool cannot match, still fails.
- m2c's input was not reassembled to check parity (the repo's `regenerate-asm` proves
  the fallback files byte-exact and the rewrite keeps register and offset).
- Retail bytes carry no relocations, so objdiff ignores relocation targets;
  `exact (symbols too)` is the stricter count (equal to `exact` in this run).
- No timing is claimed. The stock export ran on nih-vps-u (150 s, `GHIDRA_HEADLESS_MAXMEM`
  8G); everything else ran on this host under load 5 to 8.

### Update (2026-10-11, Ps2Printer): the printer conforms to the unit's declarations, and four EE/MWCC shapes

Everything above is the run of `Ps2Match` on its tree; the numbers there are kept as written. This update is the
same script, same pinned repo, toolchain, seed and sample, on the tree at the start of the work (the "re-measured"
column; discovery already finds the three functions the first run lacked, so all 200 are produced) and after the
change. Only the romwright layer moved; the m2c rows are identical (101 / 32 / 40.4 in context). The stock rows are
identical except one function, 0x4633f0, which compiles now (110 / 7 / 37.4): that is the context fix below, not a
stock change.

| tool | variant | frozen run | re-measured before | after | after, outside `src/promoted` |
|---|---|---|---|---|---|
| romwright | context | 143 / 14 / 52.1 | 147 / 14 / 53.2 | **190 / 45 / 74.7** | 18 exact, 71.6 |
| romwright | best | 169 / 16 / 62.1 | 171 / 16 / 62.5 | **194 / 46 / 75.9** | 18 exact, 72.3 |
| romwright | standalone | 140 / 12 / 49.9 | 142 / 12 / 50.4 | 148 / 36 / 56.0 | 12 exact, 48.0 |
| m2c | context | 101 / 32 / 40.4 | 101 / 32 / 40.4 | 101 / 32 / 40.4 | 13 exact, 35.2 |
| m2c | best | 107 / 32 / 42.8 | 106 / 32 / 42.4 | 106 / 32 / 42.4 | 13 exact, 37.4 |
| stock | context | 109 / 7 / 37.1 | 110 / 7 / 37.4 | 110 / 7 / 37.4 | 1 exact, 36.8 |
| stock | best | 127 / 8 / 43.4 | 127 / 8 / 43.4 | 127 / 8 / 43.4 | 1 exact, 40.5 |

(compiled / exact / mean percent over all 200.) The m2c `best` row moves by one function (0x46e7f0,
standalone) because its context is now the unit's real text, see below. Outside `src/promoted`, the stratum
that does not favour m2c, romwright is exact on 18 of 98 against m2c's 13 and stock's 1 (it was 2). Inside it
romwright is exact on 27 of 102 against m2c's 19. Paired on percent in context romwright is above m2c on 124
functions, below on 41 (35 ties), above stock on 154, below on 16.

Second sample, seed 20261011 (`benchmarks/reports/m22-ps2_p4_seed20261011.{json,md}`; 8 functions in common with
the first, 3 rejected for inline assembly; the stock layer was not run, its export is a Ghidra run on that
sample's addresses): romwright context 163 / 28 / 61.0 -> **190 / 45 / 76.4**, best 181 / 28 / 66.6 ->
**197 / 45 / 78.0**, standalone 147 / 23 / 51.9 -> 151 / 31 / 56.8; outside `src/promoted` 11 -> **19** exact
against m2c's 19; m2c 122 / 50 / 50.9 in context, unchanged. The rules were chosen on the first sample and
kept only where the second moved the same way (the one rule that did not, below, was removed); the pre-change
reports are `m22-ps2_p4_pre_ps2printer.*` and `m22-ps2_p4_seed20261011_pre_ps2printer.*`.

**What the 53 context compile failures were** (first sample; the second had 37), by compiler message and cause:

| n | MWCC message | cause | fix |
|---|---|---|---|
| 15 | illegal implicit conversion pointer <-> integer at `v = f();` | the callee is declared `u8 * f()` (K&R: its parameters are unspecified, so the harness asserts nothing and the decompiler types the result `unsigned long long`/`int`) | a local only ever assigned from such calls and only used where a pointer works unchanged takes the declared pointer type; otherwise the assignment is cast |
| 13 | illegal implicit conversion `unsigned char *` to `char *` | a string at an address no symbol names is declared `unsigned char LAB_x`; the callee takes `char *` | the argument is cast to the declared parameter type |
| 6 | illegal implicit conversion `void ()` to `int (**)(...)` | a function address stored through `*(code **)p`: Ghidra's `code` is a function type, the harness' prelude and the units define it as a pointer, and the store has the wrong level | `code` is spelled by a typedef the output defines (`romwright_code`, a function type), and a function address stored through a function-pointer slot of another signature is cast |
| 5 | illegal implicit conversion in a call argument | integer where `u8 *` is declared and the reverse | cast |
| 3 | function call does not match | the decompiler recovered more parameters than the project's declaration has | the arguments beyond the declaration are not printed |
| 3 | identifier redeclared | the printed definition's parameter types differ from the context's prototype (`long` against `int`, struct by value) | the definition takes the context's types (parameter names kept) when the parameter counts agree; struct-by-value parameters are not rewritten (2 remain) |
| 3 | undefined identifier | `stack0x...`, a function used as a value that the unit declares inside a function body, a `FUN_` name for data | not fixed |
| 2 | call of non-function | `(*param_6)(a, b)` with the asserted parameter erased to `void *` | the callee is cast to a function pointer |
| 2 | `';' expected` / illegal constant expression | the harness' own context text: a `typedef char X[sizeof(S) == 12 ? 1 : -1]` size check, and a type name the context does not define | not fixed (they are the same for every layer) |
| 1 | illegal implicit conversion `int` to `struct` | a struct passed by value | not fixed |

After: 10 remain, 3 of them struct-by-value arguments, 2 definitions whose declared parameters are structs, 3
undefined names, 2 context-text cases. The "`struct Data_... D_...[] __attribute__(void *);`" syntax error the
first run reported against the printer is in the harness: `prototype_of` read `extern T D[] __attribute__((aligned(8)));`
as a function named `__attribute__`, erased its "parameter" and rewrote the declaration for every layer. It is fixed
there (`strip_attributes`, with a selftest); 0x4633f0 and 0x46e7f0 now have the unit's real declaration.
Standalone failures (52 of 200 after) are the same text compiled without the declarations it leaves to the
project: 31 a callee's result assigned to a local of the other kind, 11 callees undeclared, 4 data names, 3 strings, 3 arguments.

**The rules** (all in the printer, `crates/romwright-core/src/emit_m2c/`; each has a unit test):

- `conform.rs`, the context-driven pass above (casts, local retyping, the target's declared signature, surplus
  arguments, a called `void *`), plus three spellings that mean one thing everywhere: a 4-byte `long` is `int`
  (MWCC's `long` is 64 bits and every `long` local cost a `dsll32`/`dsra32` pair), Ghidra's `code` is the output's
  own typedef, and a scalar whose address no 16-bit `$gp` offset reaches is declared as an array of unknown size and
  indexed (`x` -> `x[0]`, `&x` -> `x`): MWCC addresses a scalar of at most 8 bytes `$gp`-relative, so the original
  must have declared it larger (a `D_xxxxxxxx[]` table). The gp reach comes from the project's stored decode
  contexts; 209 of the mismatched instructions were that.
- `emit_m2c.rs`: a 4-byte float constant is printed `0.5f` (an unsuffixed literal is a double, and `x * 0.5` is a
  `fptodp`/`dpmul` call on an EE).
- `canonical.rs`: `K < x` is `x >= K + 1` (`6 < x` and `x > 6` compile to `slti at` and `x >= 7` to `slti v0`, which is
  what the originals have; not for 0, which has its own branches).

Ablation on the first sample (same binary, one rule off): without the conform pass 37 exact, 57.7 mean, 26.0%
compile failures (against 45, 74.7, 5.0%); without the comparison rule 44 exact, 74.715 mean. The spellings, the gp
arrays and the float suffix have no switch; together with the above they are the difference between 14 and 37.

**What was tried and dropped.** Printing a constant that the function's own instructions reference as data (the xref
table's `DATA` targets) as `(int)&DAT_xxxxxxxx`, to get the relocated `lui`/`addiu` pair instead of `lui`/`ori`: the
xref table holds colour constants (`0x313131`) and counts (`0x100000`) as targets, two functions lost 6 and 2
points, and the table has no entry for the cases that mattered (`D[i]` bases). Writing a pointer variable after the
scaled index it is offset by (`i * 0xa4 + (int)p`, the order the originals have): no effect on either sample.

**Still not matched**, from the instruction diffs of the 148 compiled but inexact functions (first sample, the better
variant of each): register allocation (a `daddu` or `lw` naming `s0` where the original has `s1`, 74 functions), a
global's address kept in a register across calls where ours reloads it (`D[0]` accesses), the arm order of an
`if`/`else` (`beq` against `bne` in 14 functions and the reverse in 5; `beqz`/`bnez` in 10 and 2), the signedness of
a narrow load the decompiler cannot see (`lhu` against `lh` in 9 functions and the reverse in 8, `lbu`/`lb` in 8 and 2),
adjacent constant byte stores that were one `sh` (6), a 32-bit sign extension where the original passes a value
unextended (31 functions have a `dsll32`/`dsra32` pair the original lacks), and an address printed as a number where the
original names an object (25: `ori` against `addiu`, which needs the symbol).

**Gates.** m22-001 (run with a copy of the script that accepts the host's reassembly parity, 99.94% and 99.87% on
two references, as in the P4.6 section) is unchanged: ROM 75.734 mean, 9 exact, 31 compiled; ELF 59.017, 10, 23.
m21-001 passes on the seven images present (7 scored). `cargo check --workspace --all-targets` has the one known
`return_size` warning. Where it ran: this host, `-j 2`, builds in `target/Ps2Printer`, load 5 to 14, no timings
claimed; the stock rows are the saved export of the first run.

### Update (2026-10-11, Ps2CMatch): partial-access failures gone, the ee-gcc lane, and five more MWCC shapes

Same script, same pinned repo, toolchain and seeds as above. "Before" is the tree at the start of this work (`bin-base`, built
from it); the MWCC-lane before rows are the reports as they stood (`benchmarks/reports/m22-ps2_p4*_pre_ps2cmatch.{json,md}`,
the Ps2Printer figures), and a re-run of that tree with the script as it is now gives the same 45 and 45 exact
(mean 74.736 and 76.364 against 74.725 and 76.361: the third decimal, run to run). The ee-gcc before row is such a re-run.
Everything ran on this host (the ee-gcc and EE-assembler binaries through the bubblewrap loader below) with the stock rows
from the saved exports; nothing here claims a timing.

**Decompile success on every PS2 wave sample** (`benchmarks/ps2_decompile_success.py`: the addresses of
`console_research_wave_20261011_ps2.json`, each decompiled with `export-c` against a copy of the cached project the wave used,
before = `bin-base`, after = this tree; a row of an overlay module runs against that module's own project; result files
`benchmarks/reports/ps2_decompile_success_{before,after}_20261011.json`, table `…_20261011.md`):

| game | sampled | before | after | failures before -> after |
|---|---|---|---|---|
| Dark Chronicle | 969 | 1.0000 (969) | 1.0000 (969) | 0 -> 0 |
| Dark Chronicle (symtab) | 962 | 0.9979 (960) | 1.0000 (962) | 2 -> 0 |
| Dark Cloud | 937 | 0.9979 (935) | 0.9989 (936) | 2 -> 1 |
| Dark Cloud (symtab) | 940 | 0.9989 (939) | 1.0000 (940) | 1 -> 0 |
| Digital Devil Saga | 977 | 1.0000 (977) | 1.0000 (977) | 0 -> 0 |
| Fatal Frame | 942 | 0.9724 (916) | **1.0000 (942)** | 26 -> 0 |
| Fatal Frame (symtab) | 940 | 0.9766 (918) | **1.0000 (940)** | 22 -> 0 |
| God Hand | 980 | 0.9990 (979) | 1.0000 (980) | 1 -> 0 |
| Persona 4 | 975 | 0.9990 (974) | 0.9990 (974) | 1 -> 1 |
| Ratchet & Clank | 861 | 0.9988 (860) | 0.9988 (860) | 1 -> 1 |
| Ratchet & Clank PAL | 859 | 0.9988 (858) | 0.9988 (858) | 1 -> 1 |
| all | 10342 | 0.9945 (10285) | **0.9996 (10338)** | 57 -> 4 |

The before column reproduces the wave report's per-game success rates (Fatal Frame 0.9724, symtab 0.9766, and so on).
Failure classes, all 57 before:

| class | before | after | cause and fix |
|---|---|---|---|
| `partial access to X has no scalar C type` | 53 (Fatal Frame 48, Dark Chronicle 2, Dark Cloud 2, God Hand 1) | 0 | A global typed `undefined8` (or another type with no member there) is read or written at an offset (`DAT_00252750._4_4_`) with a value that is a pointer. `emit_m2c/storage.rs` printed the access through the union member of the access's width and needed a scalar type for it; the value's own declared type is now the cast of the access (`(*(short **)&DAT_00252750.u1[4])`). An access that is misaligned or lies past the object's end is the same cast through the object's address (`(*(T *)((unsigned char *)&X.u1[0] + n))`); both were refusals (`needs typed context`, 2 more functions behind the first). A 3 to 7 byte read (`DAT_00357e30._1_3_`, one function) is its bytes put together in the target's byte order (the language id says which); a write of that width, which has no lvalue, is the one refusal left, and nothing in the samples reaches it. |
| `native runtime: execution deadline exceeded` (60 s) | 2 | 2 | Persona 4 `0x2be530` (49,720 bytes) and a Dark Cloud overlay function (`0x1db08a0`). The decompiler does not finish within the export budget. Not changed. |
| `decompiler exception: Low-level Error: Backward normalization not implemented` | 2 | 2 | Ratchet & Clank and its PAL build, the same 976-byte function (`0x239780`, `0x23aa38`). Raised by Ghidra's own C++ decompiler; `native/` is out of scope here. Not changed. |

**What changed in the printer** (clean room: tree-sitter over the printed text, the IR, the function's own instruction words;
no m2c or decomp-repo code; only `r5900` instructions are read, other MIPS targets are untouched):

- *An address is printed as an address* (`emit_m2c/addresses.rs`, `machine.rs`). MWCC and ee-gcc build an integer constant with
  `lui` + `ori` and an address with `lui` + `addiu`, whose low half the linker fills in. A constant the function's own code
  builds as a `lui`/`addiu` pair, that lies in the image, is printed `(char *)&name` (`&name` for a function passed as an
  argument), the project's symbol at the address, else `DAT_<address>` declared as an array of unknown size; a number built with
  `ori` is left alone (this is what the earlier attempt on the xref table lacked: it could not tell a colour from an address).
  The cast is to a pointer on purpose: with `(int)` MWCC schedules a call argument and an indexed base address differently
  (checked by compiling both spellings of four functions).
- *A narrow load keeps its extension* (`token_edits.rs`): the cast of a `*(short *)p` whose load operation is a `lhu` (at the
  operation's own instruction address) is made `unsigned short`, and the other three combinations likewise.
- *One store instruction is one store*: two byte stores of constants whose operations share an instruction address (a `sh`
  that the decompiler splits on a byte pointer) are one `*(unsigned short *)(p + n) = c`.
- *A function used as a value is declared* (`globals.rs`): `DAT_008873f8[0] != func_003e13d0` named a function the unit
  declares inside a function body; it now gets an `extern int name();` the project's own declaration replaces.
- *A structure passed by value* (`conform.rs`): a parameter the context declares as a structure (named or not) where the
  decompiler printed an integer register of the same kind keeps the declared type and its name, and the body reads its
  bytes through the integer type; a float parameter, which the decompiler lists first, is put at its declared position.
- Narrower: the typed partial access above, the odd-width read, and `ExportDecompiledC.java` (the stock script did not
  compile under Ghidra 12.1.3: `ClangNode.getText`, fixed; the saved stock exports of the earlier runs were made before the
  script was last edited and are reused as they are).

**m22-002, seed 20261010** (compiled / exact / mean percent over 200; m2c and stock did not move):

| tool | variant | before | after |
|---|---|---|---|
| romwright | context | 190 / 45 / 74.725 | **192 / 55 / 76.624** |
| romwright | best | 194 / 46 / 75.907 | 195 / 56 / 77.793 |
| romwright | standalone | 148 / 36 / 56.048 | 147 / 42 / 56.804 |
| m2c | context | 101 / 32 / 40.41 | 101 / 32 / 40.41 |
| stock | context | 110 / 7 / 37.434 | 110 / 7 / 37.434 |

Compile failures 5.0% -> 4.0%; paired on percent, romwright against m2c 129 / 33 / 38 (wins / losses / ties). Outside `src/promoted`:
24 exact, mean 75.4 (18 and 71.6 before).

**m22-002, seed 20261011**:

| tool | variant | before | after |
|---|---|---|---|
| romwright | context | 190 / 45 / 76.361 | **194 / 57 / 78.321** |
| romwright | best | 197 / 45 / 78.005 | 198 / 57 / 79.501 |
| romwright | standalone | 151 / 31 / 56.752 | 148 / 38 / 56.463 |
| m2c | context | 122 / 50 / 50.873 | 122 / 50 / 50.873 |

Compile failures 5.0% -> 3.0%; paired against m2c 113 / 45 / 42. The 12 functions that became exact on this sample and the
10 on the first were, by their diffs, one change each: a `lui`/`ori` against `lui`/`addiu` (the address constants), a `lh`
against a `lhu` (the narrow loads), two `sb` against one `sh` (the merged stores), the order of a call's arguments after an
address constant; two functions on this sample compile now because the function they use as a value is declared. The
standalone variant (no unit declarations) of the second sample moved from 56.752 to 56.463 mean (151 -> 148 compiled):
it compiles the text the context variant is given, so what that text leaves to the project's declarations is undefined
there, and the by-value structure types and a function named as a value now are (4 functions went that way, 1 came back).

Compile failures left in the context variant (8 functions on the first sample, 6 on the second), from the reports: five
`illegal implicit conversion` (a `short` or `int` where MWCC wants a pointer, or the reverse), a constant expression MWCC rejects in
the text (3), `stack0x…` names in the body (2), a structure-by-value definition whose four structure parameters the
declaration spells with an alias the printer does not follow (`0x2b5fd0`), a function symbol typed code used in arithmetic
(`FUN_0064f110 + n`), an undefined `int3`, a `';' expected`.

**The ee-gcc lane** (`--compiler eegcc`, `benchmarks/reports/m22-ps2_p4_eegcc.{json,md}`; before in
`…_eegcc_pre_ps2cmatch.{json,md}`). The units retail built with ee-gcc 2.96 (`config/gcc_units.txt`): 592 matched functions of 32
to 1024 bytes in the repo's verify report (`verify.py` run on those 406 files through `tools/eegcc_shim.py`: 1176 functions
MATCH, 265 ASM), nearly all vendor code (the CRI ADX/SFD/ACS middleware, 568 of the 592; 3 Sony SDK; 21 promoted units).
The first 200 of the seeded shuffle are the sample. The ee-gcc and EE assembler (`/var/tmp/p4ci/ee-gcc-2.96`, `ee-binutils`)
are i386 ELFs whose interpreter is the fixed `/lib/ld-linux.so.2`; this host has none. `~/opt/glibc32` holds a 32-bit glibc
tree, and `ld-linux.so.2 --library-path` runs the driver but not the `cc1`/`as` it spawns, so the harness re-executes
itself under `bwrap --dev-bind / / --overlay-src /lib --tmp-overlay /lib --bind <loader> /lib/ld-linux.so.2`: a tmpfs overlay in a
private mount namespace, nothing on the host written (`docs/toolchains.md`). The context is `ee-gcc -E` of the unit (INCLUDE_ASM
removed, line markers stripped), candidates are compiled by the repo's own shim (`-O2 -G0`, `-I` roots by unit key, GNU `as`
2.12-ee) and scored the same way; m2c runs as `-t mipsee-gcc-c`; the stock layer is the same retail ELF (a fresh export,
`ExportDecompiledC.java`, 200 of 200 functions).

| tool | variant | before | after |
|---|---|---|---|
| romwright | context | 196 / 94 / 84.558 | **197 / 106 / 86.406** |
| romwright | best | 196 / 98 / 84.938 | 197 / 110 / 86.753 |
| romwright | standalone | 181 / 89 / 78.108 | 182 / 100 / 79.649 |
| m2c | context | 164 / 101 / 74.41 | 164 / 101 / 74.41 |
| stock | context | 173 / 55 / 65.526 | 173 / 55 / 65.526 |

Compile failures: romwright 1.5%, m2c 18.0%, stock 13.5%. Paired on percent romwright wins 61, loses 30 against m2c, and
beats stock 116 to 17. By size: 32-63 bytes 62 / 81 exact (m2c 61), 64-127 39 / 77 (37), 128-255 5 / 31 (3), 256 and up none
exact for any tool (romwright 58.9 mean against m2c 18.7). Before the first measurement of the lane the harness lost most of
romwright's calls to a handle type: `typedef struct SFD_OBJ *SFD;` was not read as a typedef (the pattern wanted a space before the
name), so no prototype of the CRI library was asserted and every call printed without its arguments (65 exact, 68.7 mean, 17% compile
failures at the start of the work; the "before" row above is after that fix, which does not move the MWCC lane: 45 and 45 exact
before and after it). The 3 remaining romwright failures: `strlen` called with no argument where the unit includes `<string.h>`'s
prototype (2) and one function with no candidate. Limits: the matched sources of these units were written by hand against
retail with no m2c in the loop (CRI's library, as RE4 reconstructed it), so m2c is not favoured by promotion as it is on the MWCC
side; 191 of the 200 are CRI functions, so the lane says little about game code; ee-gcc is given only the unit's own includes.

**Not done.** The 74 functions of the first sample that differ in register allocation, `if`/`else` arm order (`beq` against `bne`
around a body the original lays out the other way), a loop-invariant load the source hoisted by hand, a `short` temporary whose
sign extension the decompiler places at the assignment where the source did it per use (32 functions still have the inserted
`dsll32`/`dsra32` pair), the order of an `addu`'s operands (`base + index * n` against `index * n + base`, 3 functions at
99.6%), a counter incremented in a condition (`++x >= n` against `x = x + 1; if (x >= n)`), floats copied through `lw`/`sw` where the
source typed them `float`, and callee prototypes that the decompiler orders unlike the declaration. The two deadline
functions and the two Ghidra low-level errors above. A write of a 3 to 7 byte partial access.

**Gates.** `cargo test -p romwright-core --lib emit_m2c::` 48 passed (2 ignored), 17 of them new (`storage`, `addresses`,
`machine`, `token_edits`, `conform`); `cargo check --workspace --all-targets` has the known `return_size` warning and one
`unused mut` in a `fact_pack` test; m21-001 PASS (7 images scored; the change does not touch import or discovery); the m22-002
`--selftest` passes. Builds and tests ran on nih-vps-u at `-j 2`.



## Supplement: PS2 discovery after fill, sweep and data pointers (2026-10-10, Ps2Recall)

The frozen wave report (`console_research_wave_20261010`) is unchanged. This is a measurement of the
same discovery metrics (`recall`, `precision`, `recall_verified`, `precision_verified`, computed by
`console_research_wave.score_found` through `console_research.wave_units` / `score_units`) on the
eight PS2 games, before and after the PS2 discovery change (STATUS.md, Ps2Recall), written by
`benchmarks/ps2_discovery.py`. It imports each image once per tools build with the default
environment, scores it, and decompiles nothing; the two builds alternate inside a repetition and each
import records the load average. Both builds are this tree with and without the change, ghidra_opt
`dbd7e74b`, `ROMWRIGHT_NO_IMPORT_CACHE=1`, on nih-vps-u.

Two truths are scored: the wave's (`functions.pre-ps2audit.tsv`) and the current `functions.tsv`
(Ps2Truth's audit: Ratchet & Clank's fill rows removed, God Hand's manifest functions added). Only
`recall` and `precision` depend on it; the verified rows are the same.

| game | recall (wave truth) | precision (wave truth) | recall_verified | precision_verified |
|---|---|---|---|---|
| Dark Chronicle | 0.9844 -> **0.9987** | 0.9972 -> 0.9955 | 0.9842 -> **0.9987** | 0.9997 -> 0.9996 |
| Dark Cloud | 0.9840 -> **0.9988** | 0.9906 -> 0.9889 | 0.9840 -> **0.9988** | 0.9990 -> 0.9978 |
| Digital Devil Saga | 0.9854 -> **0.9974** | 0.9917 -> 0.9925 | 0.9854 -> **0.9976** | 0.9932 -> 0.9944 |
| Fatal Frame | 0.9369 -> **0.9958** | 0.9893 -> 0.9930 | 0.9412 -> **0.9959** | 0.9890 -> 0.9936 |
| God Hand | 0.9709 -> **0.9983** | 0.8950 -> 0.8870 | 0.9664 -> **0.9980** | 0.9938 -> 0.9951 |
| Persona 4 | 0.9857 -> **0.9992** | 0.9973 -> 0.9931 | 0.9875 -> **0.9993** | 0.9990 -> 0.9986 |
| Ratchet & Clank | 0.6463 -> **0.6878** | 0.9882 -> 0.9912 | 0.8850 -> **0.9245** | 0.9911 -> 0.9941 |
| Ratchet & Clank PAL | 0.8539 -> **0.9076** | 0.9882 -> 0.9895 | 0.8463 -> **0.9172** | 0.9993 -> 0.9973 |

Against the current truth (before -> after): God Hand 0.9574 -> 0.9976 / 0.9825 -> 0.9866,
Ratchet & Clank 0.8607 -> 0.9281 / 0.9751 -> 0.9912, PAL 0.8595 -> 0.9276 / 0.9733 -> 0.9895; the
other five rows are the same as above. Stock Ghidra on the current truth: recall / precision God Hand
0.8552 / 0.9988, Ratchet & Clank 0.7175 / 1.0000, PAL 0.7184 / 1.0000; on the other games its
precision is 0.985-1.000 and its recall 0.833-0.929. Our precision is still below stock's on every
PS2 game: what stock does not find, it does not invent, and the entries we add and the truth does not
name are the evenly spaced blocks of switches whose table is not recovered (God Hand, Digital Devil
Saga, Fatal Frame) and functions in stretches the truth does not cover (Persona 4's truth covers 50%
of the scored ranges, Dark Chronicle's 7%, Dark Cloud's 4%).

Truth functions that none of ours covers and that start 64 or more bytes past the end of our
previous function (the miss class the sweep and the data pointers address; current truth, same
classifier as `~/romwright-scratch/ps2-diag/ps2_classify.py`, adapted to read the projects of
`benchmarks/ps2_discovery.py`): God Hand 109 -> 0, Fatal Frame 167 -> 1, Digital Devil Saga 52 -> 1,
Persona 4 43 -> 0, Dark Chronicle 40 -> 2, Dark Cloud 38 -> 1, Ratchet & Clank 4 -> 3, PAL 4 -> 3.
Functions covered by none of ours, all distances: 343 -> 11, 253 -> 17, 133 -> 11, 160 -> 5,
99 -> 9, 64 -> 2, 81 -> 18, 76 -> 15 in the same order. Functions of ours that open with a fill word
(`00000000`, `cdcdcdcd`): Ratchet & Clank 24 -> 1, PAL 24 -> 2.

What is left is Ratchet & Clank: 113 (PAL 117) truth starts lie inside a body of ours, 109 of them in
both versions targets of a `j` and of no `jal`. They are hand-written assembly routines that fall into
each other or are reached by `j`, with no `nop` and no frame opener before them; the rule that reads a
`j` target after a `nop` as a start took 31 of PAL's. No byte pattern of the image separates the rest
from the code they follow (STATUS.md, Ps2Recall).


## Reproduce

All from the repository root. The harness reads the private corpus
(`~/romwright-corpus/extracted`), `native/build/ghidra_opt` and
`readelf`; m22 also needs agbcc and objdiff; m22-002 needs the P4 CI kit in
`/var/tmp/p4ci`, wibo, m2c and objdiff (see its supplement).

Build:

<!-- not gated: research harness build that needs a ghidra_opt build tree; recorded recipe -->
```sh
native/build_ghidra_opt.sh --jobs 10
cargo build --release -p romwright-cli -p romwright-worker -p romwright-api
```

**The study (F).** F's tools fingerprint is the sha256 of `romwright-cli`,
`romwright-worker` and `ghidra_opt`, so a rebuild writes
fresh results, never mixing builds. F's prototype jobs stopped at 1200 s, so
the budget used was probably 1,200,000 ms (`[INFERENCE]`: the script default is
3,600,000):

<!-- not gated: research harness run over the cached corpus images, hours long; recorded recipe -->
```sh
python3 benchmarks/console_research.py --target-dir target \
    --cache ~/.cache/romwright/research-final \
    --prototype-budget-ms 1200000 \
    --out benchmarks/reports/console_research_final.json
# the markdown summary is written next to --out (.md)
```

Subsets (`--images` and `--configs` are comma lists; the references a verdict
needs are added automatically; `--no-m22` skips pokeemerald's objdiff):

<!-- not gated: research harness subsets over the cached corpus images; recorded recipe -->
```sh
python3 benchmarks/console_research.py --images gba-pokeemerald,ps2-capcom-fighting-evolution \
    --configs default,baseline-off,promote-tailcalls --no-m22 --out /tmp/cr.json
python3 benchmarks/console_research.py --configs infer-prototypes,inferred-types-off \
    --images x360-black-ops-2 --prototype-budget-ms 10800000 \
    --out benchmarks/reports/console_research_proto_x360-black-ops-2.json
```

The first command measures the tail-call result. The second is how X was
produced (STATUS gives the config name, the images and the output file; the
10,800,000 ms budget is from the run description, not recorded in the
report). Run it on the same tree as the numbers you compare to, and compare a
report only with itself (the emitter fix moved x360's `default` row between F
and X). The Vita rerun (V) is the same command with
`--images psv-need-for-speed-most-wanted --out
benchmarks/reports/console_research_proto_psv-need-for-speed-most-wanted.json`;
F's 1200 s budget did not finish round 1 there, V's did (V's budget is not
recorded in the report).

Under the new default, `infer-prototypes` now includes the type merge and
`inferred-types-off` is its ablation (open issue 10). `[INFERENCE]` the
current `infer-prototypes` row equals F's `inferred-types` row on the same
tree; the only checks are X (x360) and V (Vita), which measure the new-name
configs on their own tree and have no F row to compare for Vita.

**P1.** `python3 benchmarks/console_research.py --target-dir target/eval`
with binaries built from the original tree produced
`benchmarks/reports/console_research.json`. It cannot be rerun on the current
tree (the config set differs).

**Structuring (SB, each command block there):**

<!-- not gated: structuring study commands that need ghidra_opt builds and dumps outside the repository -->
```sh
native/build_ghidra_opt.sh /tmp/rw-structmodels-build
CARGO_TARGET_DIR=target/structmodels cargo build --release -p romwright-worker -p romwright-cli
benchmarks/structuring_models.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/structmodels --jobs 8 --report benchmarks/reports/structuring_models.json
benchmarks/structuring_m22.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/structmodels --report benchmarks/reports/structuring_m22.json
benchmarks/structuring_compile.py --dump /tmp/structuring-dump \
    --report benchmarks/reports/structuring_compile.json
python3 tests/m15-001_structuring.py --report /tmp/m15.json
benchmarks/printer_diff.py --ghidra-opt /tmp/rw-printer-build/ghidra_opt \
    --target target/printer --jobs 6 --report benchmarks/reports/printer_diff.json
```

The SAILR budget sweep is the `--config bN=all,budget=N` form in SB's
"Commands" block (`benchmarks/reports/structuring_sailr_budget.json`). The
cutover comparison (`structure` pass on or off) is SB's "Default cutover"
block (`benchmarks/reports/structuring_cutover*.json`).

**Discovery and switch gates.**

<!-- not gated: corpus gates that need the staged contract images; recorded recipe -->
```sh
python3 tests/m21-001_real_images.py            # recall/precision floors per image
python3 tests/m13-001_vsa_switch.py             # libc VSA soundness (re-run 10-09: one failure stands, combined not above stock)
```

The VSA A/B gate (A = `ROMWRIGHT_NO_SWITCH_VSA=1`, B = default) is
`gate.sh`/`summary.py` under `~/runs/VsaConsoles/vsa` on build host
`nih-vps-u`, not in the repository (S:Switch tables, "Commands"):
`./gate.sh h5 <image ids>` then `python3 summary.py h5 <image ids>`.

**Import speed vs Ghidra** (`docs/import-speed.md`; needs Ghidra 12.1.3 and
console loader extensions; about 3.6 h without the cache):

<!-- not gated: needs Ghidra 12.1.3 and the console loaders, about 3.6 h; recorded recipe -->
```sh
CARGO_TARGET_DIR=$PWD/target/speedgate python3 benchmarks/import_speed.py
python3 benchmarks/import_speed.py --no-build --native DIR     # reuse binaries
python3 benchmarks/import_speed.py --no-build --only gba-pokeemerald --runs 1 --limit 10800
```

Unit tests relevant to the numbers:
`cargo test -p romwright-core --lib -- vsa switch discovery native`,
`cargo test --release -p romwright-worker --lib printc`,
`cargo test -p romwright-core --lib types_infer subtype register_params`.


## Supplement: PS2 compiler detection and `new-project` (m23-001, 2026-10-11, Ps2Bootstrap)

`romwright-cli detect-compiler` / `romwright_core::new_project::compiler::detect_ps2_compiler` name the toolchain that linked a PS2 executable from linker-written evidence (`.comment`, section vocabulary, runtime-helper symbols), because PS2 images are mixed (a Metrowerks game links Sony's ee-gcc libraries). Scored against each game's `truth/meta.json` `compiler` field (report `benchmarks/reports/m23-001_compiler_detection.md`):

| game | meta compiler | detected | version class | suggested tool |
| --- | --- | --- | --- | --- |
| Dark Cloud | MWCC PS2 2.3.3 | mwcc-ps2 | mwcc-2.3 | mwcps2-2.3.3-000906 |
| Dark Chronicle | MWCC PS2 3.0 | mwcc-ps2 | mwcc-2.4 | mwcps2-3.0.1b210-060308 |
| Persona 4 | MWCC 3.0.1 b210 (+ b119 units, ee-gcc units) | mwcc-ps2 | mwcc-2.4 | mwcps2-3.0.1b210-060308 |
| Digital Devil Saga | EE GCC 2.96 | ee-gcc | gcc-2.95-2.96 | ee-gcc2.96 |
| Fatal Frame | EE GCC 2.9-991111 | ee-gcc | gcc-2.9-ee | ee-gcc2.9-991111 |
| God Hand | SN ProDG 2.95.3 + EE GCC 2.96 | sn-prodg | sn-prodg | ee-gcc2.95.3-136 |
| Ratchet & Clank | EE GCC 2.95.2 | ee-gcc | gcc-2.9x | ee-gcc2.95.2-273a |
| Ratchet & Clank PAL | SN ProDG 3.01 | ee-gcc (miss) | gcc-2.9x | ee-gcc2.95.2-273a |

Family 7/8, Metrowerks-vs-GNU lineage 8/8, version class 7/8 (in-sample: the classes were chosen after seeing these images), suggested manifest compiler names the meta version 6/8; two supplementary images with truth from the corpus manifest or DWARF (Capcom Fighting Evolution: Metrowerks; the dungeon image: `GNU C 3.2.2`) 2/2. Crt0 bytes and prologue statistics do not separate the families (all images share Sony's crt0; `sd $ra` appears in both) and are not used; the MWCC linker stamp names the linker (`2.3.1.01`, `2.4.1.01`), not the compiler build.

`new-project` and its gate (all-assembly rebuild byte-identical to the retail ELF on Fatal Frame and Persona 4, then a one-function C swap from each game's decomp repo that still matches) are described in `docs/new-project.md`:

<!-- not gated: needs network for the pinned manifests and a host with the retail images; recorded recipe -->
```sh
python3 tests/m23-001_new_project_ps2.py [--detection-only] [--offline-manifest] \
    [--import-host HOST --host-cli PATH --host-work DIR] --report-dir benchmarks/reports
```

## Struct recovery audit (2026-10-12, StructAudit)

Question: can printed C carry struct types, and from which source? Measurement only, no product change.
Report `benchmarks/reports/struct_inference_audit.{json,md}` (per-game tables, every number below);
script `benchmarks/struct_inference_audit.py`; driver `benchmarks/struct_audit_dump.rs` (built as a
`romwright-core` example in a scratch checkout, public API only). Import, driver and the Q3 compiles ran on
`nih-vps-u`; `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`.

**Method.** Truth for a pointer parameter is its declared type: the compiler's debug info where a debug build exists
(Capcom Fighting Evolution, MWCC DWARF 1; the Dungeon image, ee-gcc DWARF 2), otherwise the donor repository's function
definition with struct layouts computed by the script (Persona 4 MWCC; Fatal Frame, Ratchet & Clank, Digital Devil Saga
ee-gcc; God Hand SN ProDG). The driver reruns `infer_types` (lib.rs:1457-1584) over every function of the stripped image
in four configurations: `iso` (each function alone), `fwd` (callee -> caller injection only), `whatif` (the full fixpoint
with joins, all signatures `Inferred`) and `shipped` (the decompiler's FuncProto asserted `Strong`, as it runs). A struct
offset counts as right when it is the start of a truth leaf field (array elements included). No GameCube/MWCC image has
debug info in the corpus, so Q1 has no GC row. Limits are in the report.

**Q1, accuracy** (struct-pointer parameters with a truth layout and no float parameter before them; 8,817 over 7 games):

| truth | variant | params | gets `Ty::Struct` | field precision | width equal | class family | recall vs fields the body accesses |
|---|---|---|---|---|---|---|---|
| donor source (5 games) | `iso` | 4,347 | 70.4% | 95.6% | 95.8% | 68.1% | 75.2% |
| donor source | `fwd` | 4,347 | 78.8% | 94.9% | 85.3% | 70.9% | 75.4% |
| donor source | `whatif` | 4,347 | 80.6% | 46.2% | 45.8% | 84.8% | 79.2% |
| donor source | `shipped` | 4,347 | 70.4% | 95.6% | 95.8% | 68.2% | 75.3% |
| DWARF (Capcom, Dungeon) | `iso` | 4,470 | 98.3% | 96.5% | 99.8% | 83.4% | n/a |
| DWARF | `whatif` | 4,470 | 99.1% | 67.8% | 100% | 89.3% | n/a |

Per game, `iso`: Persona 4 65.3% / 94.7%, Fatal Frame 79.2% / 93.8%, God Hand 71.0% / 96.4%, Ratchet & Clank 78.4% / 97.7%,
Digital Devil Saga 64.7% / 96.0%, Capcom 98.3% / 96.5% (gets struct / offset precision). Recall against *all* truth fields is
1.5% (donor) and 1.7% (DWARF): a function touches few fields, so the layout is a partial view; against the fields its body
accesses it is 75%. Fields are `num`/`int`-classed: all 2,106 truth pointer fields that hit are typed as integers, and 1,457
of 2,198 float fields. **False structs:** 47.7% of truth `void *` and 56.4% of truth typed scalar pointers (Persona 4's
scalar-pointer truth is m2c-shaped; 24% on Capcom/Dungeon) get a `Ty::Struct`; a pointer indexed at constant offsets looks
like a struct. **`shipped` equals `iso` to 0.1 point on every game**: the FuncProto override means no structure is merged in the
product path (shipped join events: 0), so this is also what the product's inference would print today.

**Unification.** Functions that take the same truth struct agree little: mean Jaccard of their offset sets 0.33 (`iso`), 18.2% of
pairs identical (donor games). `fwd` raises it to 0.36, `whatif` to 0.38 for a large loss of precision: merging adds fields of which 94%
(`fwd`) or 43% (`whatif`) are real, per game 14-92%.

**(a) Nesting.** 15-66% of the truth structs scored hold a pointer to a struct (Persona 4 43%, Fatal Frame 19%, God Hand 38%,
Ratchet & Clank 22%, Digital Devil Saga 66%, Capcom 15%); 25-88% of their pointer fields point at a struct; 0-16% of the structs
are recursive through pointers. Of the 1,269 truth pointer-to-struct fields that the donor function bodies access, **0%
come out as `Ptr`**: 81% are present as a `num` field, 19% are absent. Cause: a loaded field's class is set from its first use
(`Float`, `Int`, else `Num`, subtype.rs:683-689) and a store always writes `Num` (:844); `Class::Ptr` reaches a field only by
injection from a callee. 25% of those fields (313) are dereferenced in the same body, so the pointee layout was in the p-code
and `Field` has nowhere to put it.

**(b) Polymorphic callees.** 7.0% of callee parameter slots that receive truth structs (191 of 2,744) are reached with
different structs, covering 25.7% of those call sites (2,813 of 10,960). With the joins on (`whatif`) the merged layout holds a field foreign to
some call site in 41.9% of those slots, 65.9% of the fields merging adds there are wrong for some call site, and 19.0% of the 593,287 fields pushed back into
callers' struct parameters are wrong (Persona 4 62%, Fatal Frame 54%, Digital Devil Saga 64%, God Hand 19%, Ratchet & Clank 11%). The damage is the
context-insensitive union through the call graph, visible far beyond polymorphic slots (donor games: only 43% of all fields the
joins add are real); the `fwd` direction alone is cheap (+8.5 points of coverage, -0.6 points of precision).

**Q2, donor transferability** (struct types in the signatures of matched functions, per donor; shared = same name and same
layout hash in at least two independent donors of the platform; twin repos count once):

| platform | donors | types (donor x type) | with layout | shared | shared of laid-out types | shared by function use | top shared |
|---|---|---|---|---|---|---|---|
| N64 | 9 | 2,309 | 1,906 | 24.0% | 29.1% | 13.7% | `OSIoMesg` `OSContStatus` `OSTask` `Gfx` |
| PSX | 8 | 1,005 | 943 | 12.3% | 13.2% | 5.9% | `CdlLOC` `RECT` `DRAWENV` `MATRIX` |
| GC | 8 | 9,409 | 2,587 | 8.4% | 30.7% | 4.7% | `OSThreadQueue` `DVDCommandBlock` `_GXRenderModeObj` |
| Wii | 5 | 9,950 | 2,586 | 8.0% | 30.6% | 3.3% | `OSAlarm` `DVDFileInfo` `ARCDir` |
| PS2 | 8 (7 independent) | 1,453 | 1,296 | 3.8% | 4.2% | 2.4% | `sceDmaEnv` `sceCdRMode` `sceGifPacket` |
| GBA | 5 | 1,151 | 1,112 | 1.6% | 1.6% | 3.0% | `SongHeader` `MusicPlayerTrack` `WaveData` |
| NDS | 5 | 3,222 | 2,317 | 1.0% | 1.4% | 1.4% | `_FILE` `FS_File` `VecFx32` |

GC/Wii lay out only a minority of types (C++ classes with bases or virtuals are not modelled; 6,822 of 9,409 GC types have no
layout), so their low whole-set figure is a lower bound; the laid-out figure is the better estimate. Shared types are SDK types
(libultra, PsyQ, Dolphin SDK, `sce*`); game-specific structs do not transfer. Same name with a different layout is common
(PS2 92 of 1,453, N64 317 of 2,309): name alone is not an identity.

**Q3, exactness.** Twenty m22-002 Persona 4 functions with member access (seed 20261012 from the 200-function sample),
compiled from the unit's preprocessed text with MWCC b210/b119, as is and with every `a->f` / `a.f` rewritten as
`(*(T *)((char *)(a) + off))` with the member's own type: **12 of 20 byte-identical** (object bytes and relocations), 8 differ
(+4 to +56 bytes, one -120). The whole eligible pool is 13 of 24. All 7 single-access functions are identical; of the 13 with two
or more accesses 5 are. The pattern in the losers is an extra `addiu` that materialises `base + off` once and reuses it instead of
folding the displacement into each load (`addiu a0,a2,56; lw v0,0(a0)` for `lw v0,56(a2)`), and in 3 functions `lq`/`sq` appear for what were word copies. Field access
syntax is therefore part of an exact recompile with MWCC: printing `p->f` where the source had it is not cosmetic. The layout
engine itself agrees with MWCC on 112 of 113 structs (size of `SceneVecBits` differs) and on all 637 checked member offsets.

**What blocks printing inferred structs.** Four links, none present:
(1) `types_infer/prototypes.rs:276-310` `upgrade` turns every `Ptr/Struct/Array` evidence into the pointee-less `pointer()` (:332),
and `Ty::c_name` (types_infer.rs:96-104) prints `void *`; (2) the decompiler resolves a named type in a prototype's C text
(`SetFunctionSignature::rawAction`, native/ghidra-opt-sleigh.patch ~:779-835, `parse_protopieces`) by asking the client
(`TypeFactoryGhidra::findById`, typegrp_ghidra.cc:20-35, `ArchitectureGhidra::getDataType`, ghidra_arch.cc:675-689);
(3) the worker answers that query in `answer_datatype` (crates/romwright-worker/src/provider.rs:1380-1431, dispatched at :1077) with a
1-byte placeholder whose metatype is guessed from text (`datatype_metatype` :2168); there is no struct encoder next to
`encode_basic_type` (wire.rs:706), and the decoder it must satisfy is `TypeStruct::decodeFields` (type.cc:2104-2260);
(4) `provider.datatypes` is filled from `db.datatypes` (provider.rs:443); the layout tables `type_defs`/`type_fields`
(romwright-db lib.rs:366/378, readers :2899/:2965) are read by nothing in the worker. The print IR already writes `TypeStruct`
fields (native/romwright_printir.hh:932-975) and the Rust printer reads them (`FieldDesc` tree.rs:95, `FieldRef` pretty.rs:207), so
`p->field` needs only a typed parameter; the struct definitions in the printed context are not emitted.

**Order.** Plumbing, DWARF layouts, inferred layouts (per function, bottom-up, gated), donor SDK layouts; no solver upgrade first.
DWARF is exact and proves the plumbing (Capcom: 4,460 scored parameters). Inferred layouts are precise where present
but need gating (false structs above) and two fixes (class `Ptr` on loaded fields; no caller -> callee joins). Donor layouts
transfer only as the shared SDK set. The algebraic-subtyping upgrade is not what limits printing: polymorphism hurts only
through the joins, which can be dropped, and a recovered nested pointee needs a cross-function type graph, not a better per-function solve.

Reproduce: `python3 benchmarks/struct_inference_audit.py selftest`; `donor-truth`, `dwarf-truth`, `host-run GAME --root <synced
checkout> [--strong-entries FILE]`, `score`, `transfer`, `exactness`, `validate-layouts`, `report` (docstring has the stage list).

## Windows PC (PE / x86): truth fixtures, discovery against stock Ghidra, compiler detection (2026-10-15, PcImport)

Finish item 5 of STATUS.md ("PC after the consoles"): the same import bar as the consoles. This section is the
fixtures, the harness change, the discovery rules and their leave-one-out, the x86 PE compiler detector, and the
numbers (`benchmarks/reports/pc_import_20261015.{json,md}`).

### The fixtures

Eight open-source PC programs, built here with real toolchains, with truth from the compiler's and linker's own
output, in the truth contract above (`<corpus>/pc-<slug>/<image>`, `truth/{meta.json,functions.tsv}`; the unstripped
build, PDB or map under `truth/build/`; the staged `image` is already stripped, `"strip": false`, `ranges` = the
image's executable sections, every row `verified` 1). Built on `nih-vps-u`; the recipes are `benchmarks/pc_fixtures/`
(`scripts_*.sh`, the cmake toolchain files, the build shims) and the extractor is `benchmarks/pc_truth.py`.

| id | image | compiler (toolchains.json id) | flags | source | rows (sized) | truth from |
|---|---|---|---|---|---|---|
| `pc-ioq3-ded-mingw32` | `ioq3ded.exe` PE32 | GCC 16.2.1, MinGW-w64 13.0.0, ld 2.46 | `-fno-lto -msse -mfpmath=387 -O2 -g -DNDEBUG -std=gnu99 -fno-strict-aliasing -fvisibility=hidden` | ioquake/ioq3 @ `87a99d18` (GPL-2.0+), dedicated server | 1,887 (1,760) | DWARF `DW_TAG_subprogram` + COFF function symbols, untyped external assembly labels, import stubs and `.cold` halves (size 0) |
| `pc-ioq3-ded-mingw64` | `ioq3ded.exe` PE32+ | same, x86_64 | `-fno-lto -O2 -g -DNDEBUG -std=gnu99 -fno-strict-aliasing -fvisibility=hidden` | same | 1,963 (1,755) | same |
| `pc-doomgeneric-mingw32` | `doomgeneric.exe` PE32 | GCC 16.2.1 MinGW-w64 | `-O2 -g -DSNDSERV -D_DEFAULT_SOURCE -w` | ozkl/doomgeneric @ `e257a095` (GPL-2.0+), Win32 GDI frontend | 1,077 (989) | same |
| `pc-quake2-msvc8` | `quake2.exe` PE32 | MSVC 14.00.50727.42 (VS2005), static CRT (`msvc8.0`) | `/O2 /MT /Zi /D WIN32 /D NDEBUG /D _WINDOWS /D _CRT_SECURE_NO_DEPRECATE /D _CRT_NONSTDC_NO_DEPRECATE /W1` (default `/GS`) | id-Software/Quake-2 @ `372afde4` (GPL-2.0+), client + server, null sound, ref DLLs loaded | 2,094 (2,094) | PDB `S_GPROC32`/`S_LPROC32` + public function symbols |
| `pc-quake2-game-msvc8` | `gamex86.dll` PE32 | same | same, `/DLL` | same, `game/` | 1,945 (1,945) | same |
| `pc-quake2-refgl-msvc8` | `ref_gl.dll` PE32 | same | same, `/DLL` | same, `ref_gl/` | 1,517 (1,517) | same |
| `pc-quake2-game-msvc8-debug` | `gamex86.dll` PE32 | same | `/Od /RTC1 /MTd /Zi`, link `/INCREMENTAL` (Debug: an incremental link table, run-time checks) | same, `game/` | 3,393 (3,393) | PDB + the 1,011 5-byte `jmp` thunks of the incremental link table (the `* Linker *` module's contribution) |
| `pc-glquake-msvc42` | `glquake.exe` PE32 | MSVC 10.20 (Visual C++ 4.2), static CRT `libc.lib` (`msvc4.2`) | `/O2 /G5 /ML /Z7`, link `/OPT:REF` | id-Software/Quake @ `bf4ac424` (GPL-2.0+), WinQuake GL target, C only | 1,331 (1,331) | COFF function symbols of a `/DEBUG /DEBUGTYPE:COFF` link with the same `.text` layout; size = to the next function symbol less the `int3`/`nop` fill (a switch table behind a function stays in its extent) |

Toolchains, none installed on the hosts: Fedora 44 `mingw32-/mingw64-gcc` 16.2.1, `-crt`, `-headers`, `-binutils` RPMs
unpacked with `rpm2cpio` (no root; relocatable); Visual C++ 8.0 (`widberg/msvc8.0` @ `936f93b9`, with its libraries
and Platform SDK) and 4.2 (`itsmattkc/msvc420` @ `df2c13aa`) run under **wine 11.0-3.fc44** unpacked the same way (new
WoW64, `WINESERVER=.../wineserver64`): `wibo` 1.2.0 runs `cl.exe` of every era but not 8.0's `link.exe` (missing
`lstrcmpiW`) nor 8.0's `cl /Zi` (`GetUserNameExW`), and the two trees with libraries are the only ones that link a program with a C runtime. Visual C++ 6.0
and 7.1 compilers exist as decomp.me assets (`msvc6.0`, `msvc7.0` = cl 13.10.3077) but ship no libraries, so they
are *controls* for detection (a freestanding program each, `benchmarks/pc_fixtures/controls/`), not fixtures.
Where a game needs the DirectX SDK (not part of either tree), the build uses a one-screen shim header
(`benchmarks/pc_fixtures/shim/`: `dsound.h` with two typedefs, `dinput.h` whose calls only type-check, a `Windows.h`
include-case alias) and, for WinQuake, the engine's own C-only switch (`id386 = 0`) in a copy of the tree.
No game source is in romwright; the images are test data.

Truth caveats: a COFF-symbol fixture has no sizes for the CRT objects it links (`size 0`: such a row judges its own
entry only, and is not an extent), MinGW's `.cold` half of a split function has a function symbol of its own and is a row,
`/DEBUG` PDBs carry the CRT's own symbols because the CRT libraries carry debug info (the 8.0 truth therefore names
the CRT functions too).


### The harness: `pc` platform and `--no-truth`

`benchmarks/console_research.py --corpus-wave` takes the fixtures unchanged (`PLATFORM_PROGRAM["pc"] = "pc"`,
`STOCK_PLATFORM["pc"] = (None, None, [])`: stock reads the PE header and chooses its own language and compiler spec,
as it does for a user; the import is `romwright-cli import <exe> --name pc`). A PE has no `.symtab` and the staged image
is already stripped, so the harness's strip step does not apply. Added: **`--no-truth NAME=PATH`**, an image with no
truth (the retail KOTOR II executable): `run_no_truth` imports it, export-c's up to 20 of its functions (success), and
with `--stock` runs stock on the same file (time, entry count, agreement of the two entry sets); the rows go to the
report's `no_truth` object and an "Images without truth (success and time only)" table. Nothing is scored there.
`benchmarks/pc_import.py` is the fast loop of the same measurement (discovery only: ours and stock scored by
`console_research_wave.score_found`, per-function miss and invented lists, the producer of every function we found,
CPU seconds and the host load at the start of each arm); the two give the same recall and precision for the same
tools (glquake: 0.9474 / 0.9953 in both).

### Discovery rules (`crates/romwright-core/compiler_rules/pe.json`)

The first measurement (below) showed ours ahead of stock on recall everywhere and behind on precision: the gaps were
things that look like entries to a relocation/constant/call reader and are not. Eight rules keep them out; a ninth adds
what the fill between functions proves. Nine general rules, each a `flag` rule of the compiler-rule layer
(so `ROMWRIGHT_COMPILER_RULES_DISABLE=<id>` is the leave-one-out switch, and the switches are in the import-cache key),
written from the invented entries of one fixture and held out on the others (`derived_from`):

| rule | covers | what it does |
|---|---|---|
| `pe-jump-table-relocs` | any PE | the ELF pointer-candidate table rule (`elf_pointers::jump_table_targets`) on a PE's relocated words naming code: a run of two or more adjacent words, one decoded inside a body and none (or fewer than the interior ones) an entry, is a jump table; its case labels are not entries. Words that name data (a struct array's strings) break the run |
| `pe-dense-case-tables` | any PE | the same for a table no walk has reached: three or more adjacent relocated words naming code, none an entry, two thirds of whose targets do not follow function fill (`int3`, `nop`, multi-byte nops, zero fill): labels packed inside one routine (the CRT's floating-point helpers) |
| `pe-x86-memory-operands` | any i386 PE | a code address a relocation or a propagated constant names only as the displacement of a memory operand (`[idx*s+disp32]`, `[disp32]`, `[base+disp32]`, moffs: the instruction bytes' ModRM/SIB) is data read, not a function pointer: the jump table Visual C++ puts behind its function. A reference that uses the address as a value (`push offset`, `mov reg, imm32`, a data pointer) keeps it a candidate |
| `pe-x86-scope-tables` | `msvc-*` | the filter and handler words of a structured-exception scope-table record (`{-1 or -2, filter or 0, handler}`) are blocks of the function that pushed the table, not entries. Only the `-1`/`-2` level counts: a float `0.0` or a count equals a nested level, and Quake 2's `mframe_t {aifunc, dist, thinkfunc}` arrays read as scope records with it (62 real functions, caught by the leave-one-out and fixed) |
| `pe-x86-local-calls` | `msvc-*` | a block only its predecessor calls, starting exactly where the predecessor's body ends (a `__finally` block, a CRT lock region), is folded into the predecessor |
| `pe-x86-trailing-data` | `msvc-*` | a block right behind a function whose address only that function takes as a value is the data a compiler puts behind its user (a Debug build's `/RTC1` frame descriptions): dropped |
| `pe-x86-case-runs` | any i386 PE | four or more adjacent relocated words naming code that all lie between two entries with evidence of their own (call, symbol, accepted pattern, stub), none such an entry, are the case labels of one function's switch: a label only those words name is dropped. For the tables no walk reached whose labels follow loop-alignment fill (GCC), which `pe-dense-case-tables` cannot tell from functions |
| `pe-x86-fill-starts` | any i386 PE | adds the function behind a walked function's fill: where a body's proven end is followed by `int3`/nop fill (the multi-byte `nop` and `lea esi,[esi+0]` forms of both compilers are recognised by their bytes), the first byte after it on a 4-byte boundary that no function covers, no relocated word or switch table names and no branch of the function before it targets is a start; or, with no fill, a 16-byte boundary right after a body that ends in a `ret`. One hop per pass, up to 32 passes per discovery (a run of unreferenced functions is found whole). Not retractable as a case label (`fill_starts`). Nothing is proposed behind a function that holds an indirect jump no switch table was recovered for (its last blocks are likely its own) |
| `pe-import-stub-position` | any PE | an `ff 25` resolving to an import slot is a linkage stub only behind fill, a `ret`, zero fill, the previous stub or at the section start; right after other instructions it is a function's own tail call through the import table (`jmp [slot]` was a "stub" in the middle of `NET_Shutdown`) |

Engines: `native/pe/x86_operands.rs` (operands, scope records, dense tables), `native/pe/local_calls.rs` (local calls,
trailing data; run in `native/store.rs` before the rows are written), `native/pe/x86_fill.rs` (fill starts; run in
`discover_seeded`), `native/pe_roots.rs` (stub position),
`native/elf_pointers.rs` (table runs), hooked at the three places that read relocation/constant candidates
(`native/discovery.rs`, `src/native.rs` `const_data_targets`).

Truth gaps found on the way and fixed in `pc_truth.py` (the fixtures were republished): MinGW's import-library
`jmp [__imp_X]` stubs are untyped COFF symbols (89 rows of the x86-64 image were missing from the truth); a COFF
function's extent ran to the next *symbol* instead of the next *function* symbol, so a hand-written CRT routine's
internal labels cut it short; and the untyped *external* symbols of hand-written assembly (`___chkstk_ms`) and the `.cold` halves GCC splits off a function are rows too (a function's `.cold` half is a start of code the compiler emitted; the fill-start rule finds them).

### x86 PE compiler detection

`compiler/detect.rs` `pe_x86_image` (PcProject wrote the first version: linker version and the GCC string; extended
here). The evidence, in the order the verdict reads it, each a fact of the image's bytes:

1. **MinGW**: the `GCC: (...) x.y.z` string. Every object a GCC-built PE links carries one (`.rdata$zzz`), so the image
   holds dozens; the verdict reads the *commonest* (ties to the later version), not the first: the Fedora MinGW CRT and
   libgcc objects are GCC 15.2.1 and the programs GCC 16.2.1 (83 stamps against 71 in `ioq3ded.exe`), and the first stamp in
   the file was the library's. The version is the number after the vendor parenthesis (`GCC: (GNU) 3.4.5 (mingw-vista
   special r3)` is 3, `(x86_64-win32-sjlj-rev0, Built by MinGW-W64 project) 8.1.0` is 8).
2. **Visual C++**: the optional header's linker version (4.x -> `cl` 10, 5 -> 11, 6 -> 12, 7.00 -> 13, 7.10 -> 13.1, 8 -> 14 ...,
   14.x -> 19), with the decoded **Rich header** (`DanS`/`Rich`, XOR key: product id, build and object count per entry;
   the build most objects came from is reported) making it high confidence, and the imported `msvcr*.dll` named as
   evidence. i386 and x86-64.

Ids: `msvc-<cl major>[.1]`, `mingw-gcc-<major>`; `unknown` for GNU ld / Borland (linker 2.x) without a GCC string.

Accuracy: `benchmarks/compiler_detection_accuracy.py` with `pc` truth from the fixtures' `meta.json` `compiler`, three
controls (`--control`: a freestanding VC6 program built with `cl` 12.00.8168 and `link` 6.00, a VC7.1 one built with 13.10.3077 and
7.10: `benchmarks/pc_fixtures/controls/`) and the retail KOTOR II executable, whose compiler Nihilus's notes name (MSVC 7.0, linker
7.0, 2005): 8 of 8 fixtures exact, 0 lineage only, 0 abstained, 0 wrong; controls kotor2 exact (msvc-13), vc6 exact (msvc-12), vc71 exact (msvc-13.1).

### Results

`benchmarks/reports/pc_import_20261015.{json,md}` (generated 2026-10-15 07:59 UTC, tools `262f665303b8a4dc`; discovery only: fresh import and work directory per arm, `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`, ours three times (the first is scored, the report's `seconds` are the first run's), stock Ghidra 12.1.3 once, uncached). The same fixtures through the full harness (`console_research_wave_pc_20261015.{json,md}`: `-n 100`, seeds 1 and 2, `default` and `baseline-off`, stock) give the export-c success column below.

#### Recall, precision, time against stock Ghidra

| fixture | compiler | truth | ours R | ours P | stock R | stock P | dR | dP | ours s (cpu), median of 3 | stock s (cpu) |
|---|---|---|---|---|---|---|---|---|---|---|
| pc-doomgeneric-mingw32 | GCC 16.2.1 MinGW-w64 1 | 1077 | 0.9499 | 1.0000 | 0.6546 | 1.0000 | +0.2953 | +0.0000 | 13.32 (11.0) | 36.4 (56.0) |
| pc-glquake-msvc42 | MSVC 10.20 (Visual C++ | 1331 | 0.9662 | 0.9938 | 0.8174 | 0.9802 | +0.1488 | +0.0136 | 11.71 (10.9) | 39.0 (51.3) |
| pc-ioq3-ded-mingw32 | GCC 16.2.1 MinGW-w64 1 | 1887 | 0.9417 | 1.0000 | 0.6386 | 1.0000 | +0.3031 | +0.0000 | 24.52 (23.3) | 54.2 (67.1) |
| pc-ioq3-ded-mingw64 | GCC 16.2.1 MinGW-w64 1 | 1963 | 1.0000 | 1.0000 | 0.9282 | 1.0000 | +0.0718 | +0.0000 | 17.22 (20.8) | 51.8 (70.1) |
| pc-quake2-game-msvc8 | MSVC 14.00.50727.42 (V | 1945 | 0.8463 | 0.9677 | 0.4931 | 0.9486 | +0.3532 | +0.0191 | 8.8 (9.2) | 56.2 (63.3) |
| pc-quake2-game-msvc8-debug | MSVC 14.00.50727.42 (V | 3393 | 0.8895 | 0.9714 | 0.7551 | 0.9249 | +0.1344 | +0.0465 | 59.55 (64.8) | 68.2 (117.4) |
| pc-quake2-msvc8 | MSVC 14.00.50727.42 (V | 2094 | 0.8367 | 0.9793 | 0.6055 | 0.9520 | +0.2312 | +0.0273 | 14.0 (13.9) | 35.1 (55.7) |
| pc-quake2-refgl-msvc8 | MSVC 14.00.50727.42 (V | 1517 | 0.7897 | 0.9638 | 0.4357 | 0.9323 | +0.3540 | +0.0315 | 6.98 (8.7) | 45.9 (62.7) |

Verified supplement (the same, over `verified=1` rows; `precision_verified` counts only entries inside a verified function's extent):

| fixture | ours Rv | ours Pv | stock Rv | stock Pv |
|---|---|---|---|---|
| pc-doomgeneric-mingw32 | 0.9499 | 1.0000 | 0.6546 | 1.0000 |
| pc-glquake-msvc42 | 0.9662 | 0.9938 | 0.8174 | 0.9802 |
| pc-ioq3-ded-mingw32 | 0.9417 | 1.0000 | 0.6386 | 1.0000 |
| pc-ioq3-ded-mingw64 | 1.0000 | 1.0000 | 0.9282 | 1.0000 |
| pc-quake2-game-msvc8 | 0.8463 | 0.9722 | 0.4931 | 0.9504 |
| pc-quake2-game-msvc8-debug | 0.8895 | 0.9751 | 0.7551 | 0.9273 |
| pc-quake2-msvc8 | 0.8367 | 0.9793 | 0.6055 | 0.9534 |
| pc-quake2-refgl-msvc8 | 0.7897 | 0.9646 | 0.4357 | 0.9323 |

Verified supplement and sign tests:

| metric | fixtures | wins | losses | ties | p (one-sided) |
|---|---|---|---|---|---|
| recall | 8 | 8 | 0 | 0 | 0.00391 |
| precision | 8 | 5 | 0 | 3 | 0.03125 |
| recall_verified | 8 | 8 | 0 | 0 | 0.00391 |
| precision_verified | 8 | 5 | 0 | 3 | 0.03125 |
| wall_time | 8 | 8 | 0 | 0 | 0.00391 |
| cpu_time | 8 | 8 | 0 | 0 | 0.00391 |

#### Before the PE rules and the fill starts

Every PE rule switched off (`ROMWRIGHT_COMPILER_RULES_DISABLE`, the leave-one-out's `ALL` arm) on the final truth: the importer as it was.

| fixture | before R | before P | before invented | now R | now P | now invented |
|---|---|---|---|---|---|---|
| pc-doomgeneric-mingw32 | 0.6890 | 0.9987 | 1 | 0.9499 | 1.0000 | 0 |
| pc-glquake-msvc42 | 0.9654 | 0.8936 | 153 | 0.9662 | 0.9938 | 8 |
| pc-ioq3-ded-mingw32 | 0.7366 | 0.9693 | 44 | 0.9417 | 1.0000 | 0 |
| pc-ioq3-ded-mingw64 | 1.0000 | 1.0000 | 0 | 1.0000 | 1.0000 | 0 |
| pc-quake2-game-msvc8 | 0.8093 | 0.9172 | 142 | 0.8463 | 0.9677 | 55 |
| pc-quake2-game-msvc8-debug | 0.8904 | 0.8465 | 548 | 0.8895 | 0.9714 | 89 |
| pc-quake2-msvc8 | 0.7717 | 0.9357 | 111 | 0.8367 | 0.9793 | 37 |
| pc-quake2-refgl-msvc8 | 0.7607 | 0.8638 | 182 | 0.7897 | 0.9638 | 45 |

#### Decompiled C

| fixture | sampled | export-c success | stock decompile success |
|---|---|---|---|
| pc-doomgeneric-mingw32 | 190 | 1.0000 | 1.0000 |
| pc-glquake-msvc42 | 190 | 1.0000 | 1.0000 |
| pc-ioq3-ded-mingw32 | 191 | 1.0000 | 1.0000 |
| pc-ioq3-ded-mingw64 | 193 | 0.9948 | 0.9948 |
| pc-quake2-game-msvc8 | 194 | 1.0000 | 1.0000 |
| pc-quake2-game-msvc8-debug | 194 | 1.0000 | 1.0000 |
| pc-quake2-msvc8 | 194 | 1.0000 | 1.0000 |
| pc-quake2-refgl-msvc8 | 195 | 1.0000 | 1.0000 |

#### Leave-one-out of the rules

Each rule switched off against all on, every fixture: `R off->on`, `P off->on`. `derived_from` fixtures are the ones a rule was written on (never evidence for it).

| rule | doomgeneric-mingw32 | glquake-msvc42 | ioq3-ded-mingw32 | ioq3-ded-mingw64 | quake2-game-msvc8 | quake2-game-msvc8-debug | quake2-msvc8 | quake2-refgl-msvc8 |
|---|---|---|---|---|---|---|---|---|
| pe-jump-table-relocs | neutral R 0.9499>0.9499 P 1.0000>1.0000 | helps R 0.9662>0.9662 P 0.9561>0.9938 | neutral R 0.9417>0.9417 P 1.0000>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | hurts R 0.8463>0.8463 P 0.9682>0.9677 | helps R 0.8895>0.8895 P 0.9670>0.9714 | neutral R 0.8367>0.8367 P 0.9793>0.9793 | helps R 0.7897>0.7897 P 0.9630>0.9638 |
| pe-dense-case-tables | neutral R 0.9499>0.9499 P 1.0000>1.0000 | mixed R 0.9692>0.9662 P 0.9908>0.9938 | neutral R 0.9417>0.9417 P 1.0000>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | mixed R 0.8488>0.8463 P 0.9672>0.9677 | helps R 0.8892>0.8895 P 0.9689>0.9714 | neutral R 0.8367>0.8367 P 0.9793>0.9793 | hurts R 0.7930>0.7897 P 0.9639>0.9638 |
| pe-x86-memory-operands | neutral R 0.9499>0.9499 P 1.0000>1.0000 | mixed R 0.9677>0.9662 P 0.9862>0.9938 | neutral R 0.9417>0.9417 P 1.0000>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | mixed R 0.8468>0.8463 P 0.9632>0.9677 | mixed R 0.8898>0.8895 P 0.9661>0.9714 | helps R 0.8367>0.8367 P 0.9733>0.9793 | helps R 0.7897>0.7897 P 0.9584>0.9638 |
| pe-x86-scope-tables | neutral R 0.9499>0.9499 P 1.0000>1.0000 | helps R 0.9662>0.9662 P 0.9923>0.9938 | neutral R 0.9417>0.9417 P 1.0000>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | mixed R 0.8468>0.8463 P 0.9321>0.9677 | helps R 0.8895>0.8895 P 0.9370>0.9714 | neutral R 0.8367>0.8367 P 0.9793>0.9793 | mixed R 0.7917>0.7897 P 0.9140>0.9638 |
| pe-x86-local-calls | neutral R 0.9499>0.9499 P 1.0000>1.0000 | hurts R 0.9669>0.9662 P 0.9938>0.9938 | neutral R 0.9417>0.9417 P 1.0000>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | mixed R 0.8468>0.8463 P 0.9526>0.9677 | mixed R 0.8898>0.8895 P 0.9461>0.9714 | helps R 0.8367>0.8367 P 0.9611>0.9793 | mixed R 0.7904>0.7897 P 0.9419>0.9638 |
| pe-x86-trailing-data | neutral R 0.9499>0.9499 P 1.0000>1.0000 | neutral R 0.9662>0.9662 P 0.9938>0.9938 | neutral R 0.9417>0.9417 P 1.0000>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | neutral R 0.8463>0.8463 P 0.9677>0.9677 | helps R 0.8895>0.8895 P 0.8963>0.9714 | helps R 0.8367>0.8367 P 0.9744>0.9793 | neutral R 0.7897>0.7897 P 0.9638>0.9638 |
| pe-import-stub-position | helps R 0.9499>0.9499 P 0.9990>1.0000 | neutral R 0.9662>0.9662 P 0.9938>0.9938 | helps R 0.9417>0.9417 P 0.9983>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | neutral R 0.8463>0.8463 P 0.9677>0.9677 | neutral R 0.8895>0.8895 P 0.9714>0.9714 | helps R 0.8367>0.8367 P 0.9788>0.9793 | neutral R 0.7897>0.7897 P 0.9638>0.9638 |
| pe-x86-fill-starts | helps R 0.6890>0.9499 P 1.0000>1.0000 | mixed R 0.9594>0.9662 P 0.9953>0.9938 | helps R 0.7356>0.9417 P 1.0000>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | mixed R 0.8051>0.8463 P 0.9697>0.9677 | mixed R 0.8892>0.8895 P 0.9739>0.9714 | mixed R 0.7722>0.8367 P 0.9800>0.9793 | helps R 0.7541>0.7897 P 0.9638>0.9638 |
| pe-x86-case-runs | neutral R 0.9499>0.9499 P 1.0000>1.0000 | neutral R 0.9662>0.9662 P 0.9938>0.9938 | helps R 0.9417>0.9417 P 0.9994>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | neutral R 0.8463>0.8463 P 0.9677>0.9677 | neutral R 0.8895>0.8895 P 0.9714>0.9714 | neutral R 0.8367>0.8367 P 0.9793>0.9793 | neutral R 0.7897>0.7897 P 0.9638>0.9638 |
| ALL | helps R 0.6890>0.9499 P 0.9987>1.0000 | helps R 0.9654>0.9662 P 0.8936>0.9938 | helps R 0.7366>0.9417 P 0.9693>1.0000 | neutral R 1.0000>1.0000 P 1.0000>1.0000 | helps R 0.8093>0.8463 P 0.9172>0.9677 | mixed R 0.8904>0.8895 P 0.8465>0.9714 | helps R 0.7717>0.8367 P 0.9357>0.9793 | helps R 0.7607>0.7897 P 0.8638>0.9638 |

Reading it (held-out fixtures only; the rule's own `derived_from` fixture is not evidence for it). Each cell compares the importer with the rule on against off, in functions:

| rule | held-out: helps / neutral / mixed / hurts | functions found with the rule on that were missed off (hits) | entries invented off -> on (all fixtures) |
|---|---|---|---|
| `pe-jump-table-relocs` | 3 / 3 / 0 / 1 | +0 | 299 -> 234 |
| `pe-dense-case-tables` | 1 / 4 / 1 / 1 | -9 | 247 -> 234 |
| `pe-x86-memory-operands` | 2 / 3 / 2 / 0 | -2 | 287 -> 234 |
| `pe-x86-scope-tables` | 2 / 4 / 1 / 0 | -1 | 483 -> 234 |
| `pe-x86-local-calls` | 1 / 3 / 2 / 1 | -3 | 407 -> 234 |
| `pe-x86-trailing-data` | 1 / 6 / 0 / 0 | +0 | 503 -> 234 |
| `pe-import-stub-position` | 2 / 5 / 0 / 0 | +0 | 239 -> 234 |
| `pe-x86-fill-starts` | 3 / 1 / 3 / 0 | +814 | 212 -> 234 |
| `pe-x86-case-runs` | 0 / 7 / 0 / 0 | +0 | 235 -> 234 |

All rules off (the importer before this work) against all on: doomgeneric-mingw32 R 0.6890 -> 0.9499, P 0.9987 -> 1.0000; glquake-msvc42 R 0.9654 -> 0.9662, P 0.8936 -> 0.9938; ioq3-ded-mingw32 R 0.7366 -> 0.9417, P 0.9693 -> 1.0000; ioq3-ded-mingw64 R 1.0000 -> 1.0000, P 1.0000 -> 1.0000; quake2-game-msvc8 R 0.8093 -> 0.8463, P 0.9172 -> 0.9677; quake2-game-msvc8-debug R 0.8904 -> 0.8895, P 0.8465 -> 0.9714; quake2-msvc8 R 0.7717 -> 0.8367, P 0.9357 -> 0.9793; quake2-refgl-msvc8 R 0.7607 -> 0.7897, P 0.8638 -> 0.9638.

A `hurts` or `mixed` cell is a recall cost of a few functions (a table label or a block the rule judged by its shape that a different fixture's compiler made a real function) against the invented entries it removes; the policy of docs/compiler-rules.md ("hurts no held-out game") is not met by every PE rule on every held-out fixture, and each such cell is in the table above with its numbers.


#### Compiler detection table

| image | truth | detected | verdict | evidence |
|---|---|---|---|---|
| pc-doomgeneric-mingw32 | mingw-gcc-16 | mingw-gcc-16 | exact | GCC stamp in the image: `GCC: (GNU) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)` (the com |
| pc-glquake-msvc42 | msvc-10 | msvc-10 | exact | PE optional header linker version 4.20 (cl 10.x) |
| pc-ioq3-ded-mingw32 | mingw-gcc-16 | mingw-gcc-16 | exact | GCC stamp in the image: `GCC: (GNU) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)` (the com |
| pc-ioq3-ded-mingw64 | mingw-gcc-16 | mingw-gcc-16 | exact | GCC stamp in the image: `GCC: (GNU) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)` (the com |
| pc-quake2-game-msvc8 | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |
| pc-quake2-game-msvc8-debug | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |
| pc-quake2-msvc8 | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |
| pc-quake2-refgl-msvc8 | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |
| kotor2 (control) | msvc-13 | msvc-13 | exact | PE optional header linker version 7.0 (cl 13.x) |
| vc6 (control) | msvc-12 | msvc-12 | exact | PE optional header linker version 6.0 (cl 12.x) |
| vc71 (control) | msvc-13.1 | msvc-13.1 | exact | PE optional header linker version 7.10 (cl 13.1.x) |

Totals: {'games': 8, 'exact': 8, 'lineage': 0, 'abstained': 0, 'wrong': 0}

#### KOTOR II (no truth)

| image | size | import s | functions | export-c ok | stock s | stock functions | both / ours only / stock only |
|---|---|---|---|---|---|---|---|
| pc-kotor2 | 4,964,352 | 2.7 | 7 | 7/7 | 21.3 | 8 | 7 / 0 / 1 |

### What remains (limits)

* The fixtures are two compiler families in three eras (GCC 16 MinGW-w64; Visual C++ 4.2 and 8.0; one Debug/incremental build,
  one x86-64) built from three id Software / Doom sources; no retail PC game has truth. Visual C++ 5.0/6.0/7.x and
  Borland are controls for detection only (no CRT libraries for a full link); no Visual C++ x86-64 and no Clang-built
  image (`clang-cl`, `lld-link` writes no Rich header) was measured.
* The truth of a COFF-symbol fixture has no sizes for CRT objects (`size 0`), so `size_exact`/extent checks cover the
  PDB fixtures; `pc-glquake-msvc42` sizes are gap-derived (a switch table behind a function sits inside its extent).
* i386 recall is 0.78-0.97, not 1.0: what stays missed is mostly functions nothing references (dead code the linker
  kept) on Visual C++ images and code behind unresolved jump tables; the x86-64 image is 1.0 because `.pdata` names every
  function. Switch recovery on i386 (value-set analysis) still refuses most `jmp [table+reg*4]` forms (`no_guard`,
  `no_strided_load`); the table rules above keep their labels out of the list but do not recover the switch for the decompiler.
* KOTOR II (`swkotor2.exe`, 2005, the retail image of the user's Nihilus project) is SteamStub-wrapped: `.text` is 8.0
  bits/byte of encrypted data until the stub runs, so both tools see a handful of functions. That is a property of the
  file (Nihilus's own notes reached the same count with IDA and RomWright), not a discovery measurement.
* Timings were taken on a shared host. Stock's arm ran at load 6-10 (8 vCPU); ours was re-run on the final build at
  load 13-25 (the other waves), so the wall-time gap understates ours (on the build before the last rule fix, at load 11-13, ours
  took 6.5-15.5 s per fixture and 53.6 s for the Debug one). The report carries CPU seconds and the load at
  the start of every arm. Stock is `analyzeHeadless` end to end (JVM start, import, all default analyzers, export), ours is
  `romwright-cli import` (native import, discovery, references, store); neither includes decompiling. The Debug fixture
  (3,393 functions, thousands of unresolved switch candidates) is ours slowest at 52-67 s against stock's 68 s.
* The harness's `baseline-off` arm (switch value-set analysis and decompiler off) is the only comparison arm; the rules
  are measured by their own leave-one-out (`pc_rules_loo.py`), not by `baseline-off`.

### Reproduce

```
# fixtures (nih-vps-u: toolchains unpacked under ~/runs/PcImport as benchmarks/pc_fixtures/wenv.sh and the scripts expect)
benchmarks/pc_fixtures/scripts_q2_msvc8.sh; scripts_q2dll_msvc8.sh; scripts_q2game_msvc8_debug.sh; scripts_wq_msvc42.sh
cmake -S <ioq3> -B build -DCMAKE_TOOLCHAIN_FILE=benchmarks/pc_fixtures/mingw32.cmake ... ; scripts_doom_mingw.sh i686 OUT -O2
benchmarks/pc_fixtures/publish_all.sh            # benchmarks/pc_truth.py -> ~/romwright-corpus/extracted/pc-*
# measurement (fresh import per arm; the harness sets ROMWRIGHT_NO_IMPORT_CACHE and ROMWRIGHT_NO_FACT_PACK)
CARGO_TARGET_DIR=<target> benchmarks/pc_import.py --work W --out ours.json --arms ours
CARGO_TARGET_DIR=<target> benchmarks/pc_import.py --work W --cache C --out stock.json --arms stock
CARGO_TARGET_DIR=<target> benchmarks/console_research.py --corpus-wave --stock --configs default,baseline-off -n 100 \
    --seeds 1,2 --out wave.json --no-truth kotor2=<swkotor2.exe>
CARGO_TARGET_DIR=<target> benchmarks/pc_rules_loo.py --work W --out loo.json
benchmarks/compiler_detection_accuracy.py --cli <romwright-cli> --games pc-... --control kotor2=<path>=msvc-13 --out detect.json
benchmarks/pc_import_report.py --ours ours.json --stock stock.json --wave wave.json --loo loo.json --detect detect.json \
    --out benchmarks/reports/pc_import_<date>
```
