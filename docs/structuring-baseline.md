# Structuring baseline

The numbers a structuring change (break/continue modelling, multi-exit and
multi-latch loops, switch shared tails, one goto per collapsed edge, tail
duplication, SAILR-style goto removal) is judged against: printed gotos per
image, m22 standalone match, and m15 not regressing. Recorded 2026-10-07 at
commit `7e29f17c` plus the working tree (StructureGotos guard in
`crates/romwright-worker/src/worker.rs` `finalize_document`: cuts are kept
only when printed gotos strictly drop). All commands run from the repository
root.

## Printed gotos per image (re-measured, current guarded build)

`benchmarks/structuring_baseline.py` decompiles the gate set through
`romwright-worker` batch mode and counts `goto` keywords in the printed
DecompDoc tokens -- the count the StructureGotos guard itself uses
(`printed_gotos`). Gate set: the console-research samples (200 functions per
image, `~/.cache/romwright/research-eval/samples/*-23c94218619e781c-200-20261006.json`
on the default projects `*-4f53cda18c2b-23c94218619e781c`) and the first 200
multi-block functions of x86 libc (`/usr/lib64/libc.so.6`, the m15-001 rule).

```
CARGO_TARGET_DIR=target/printer cargo build --release -p romwright-worker -p romwright-cli
benchmarks/structuring_baseline.py --ghidra-opt native/build/ghidra_opt \
    --target target/printer --jobs 6 --report benchmarks/reports/structuring_baseline.json
```

| image | decompiled | ir-none (stock) | default (passes, guarded) |
|---|---:|---:|---:|
| gba-pokeemerald | 200 | 53 | 53 |
| gc-animal-crossing | 200 | 44 | 44 |
| nds-pokeheartgold-arm9 | 200 | 9 | 9 |
| ps2-capcom-fighting-evolution | 200 | 8 | 8 |
| ps2-dungeon-game | 200 | 124 | 121 |
| psv-need-for-speed-most-wanted | 200 | 23 | 23 |
| psx-darkstalkers-3 | 200 | 13 | 13 |
| x360-black-ops-2 | 200 | 45 | 41 |
| x86-libc | 200 | 1228 | 1199 |

`ir-none` is `ROMWRIGHT_IR_PASSES=""`; `default` is the pass list
`additive_inverse,canonical_helpers,structure`. Per-function counts are in
the report. The Rust printer (`--rust-printer` with a `ghidra_opt` built from
the current patch) gives the same counts for both configurations on every
image.

The guard's deltas match what StructureGotos measured with `export-c` text
(`benchmarks/console_research.py`, `\bgoto\b` over the exported `.c`): gc
53->53, dungeon 149->146, gba 76->76, x360 55->51. The `export-c` counts are
higher in absolute terms because they count the m2c-shaped output file, not
the printer's tokens; compare like with like.

Before the guard, `benchmarks/reports/console_research.json` (generated
2026-10-07T02:07, `export-c` text) recorded forced cuts worsening printed
gotos:

| image | ir-none | default (unguarded) |
|---|---:|---:|
| gba-pokeemerald | 76 | 88 |
| gc-animal-crossing | 53 | 138 |
| nds-pokeheartgold-arm9 | 12 | 16 |
| ps2-capcom-fighting-evolution | 14 | 19 |
| ps2-dungeon-game | 149 | 182 |
| psv-need-for-speed-most-wanted | 35 | 36 |
| psx-darkstalkers-3 | 18 | 19 |
| x360-black-ops-2 | 55 | 61 |

Over ~1600 console functions forcing cuts improved 7 functions by 1 goto
each and worsened 28 by 154 gotos in total.

## m22 standalone match (not re-measured)

`tests/m22-001_c_output.py` (user work in progress; not modified here)
scores pokeemerald functions with objdiff after agbcc -O2. Its environment
reaches `export-c`, so the configurations are:

```
python3 tests/m22-001_c_output.py --report /tmp/m22-default.json
ROMWRIGHT_IR_PASSES= python3 tests/m22-001_c_output.py --report /tmp/m22-ir-none.json
```

Pass-1 cached results: standalone mean similarity **64.14** (default) and
**64.40** (ir-none), **6/33** functions exact. The `context` variant fails to
compile for every candidate: the generated `context.h` redeclares `memset`,
which agbcc rejects under `-Werror`, so only the standalone variant is a
usable signal until that is fixed in the script.

## m15-001 (not re-measured)

`tests/m15-001_structuring.py` runs `structuring::structure` (our Rust
structurer) and stock's `structureGraph` on the same libc control-flow
graphs. It does not go through the IR passes or the printer, so neither the
StructureGotos guard nor the Rust printer changes it.

```
python3 tests/m15-001_structuring.py --report benchmarks/reports/m15-001.json
```

Last run: ours **2133** unstructured edges against stock's **2516**,
**0.8478** of stock (gate 0.90). The committed report
(`benchmarks/reports/m15-001.json`, 2026-09-10) has 1998 / 2527 (0.7907)
from an earlier structurer. Not re-run here: the script rebuilds
`target/release` and imports libc twice with the import cache disabled.

## Printer differential

The Rust printer (docs/printer-ir.md) against PrintC on the same Funcdata,
packed markup compared byte for byte:

```
native/build_ghidra_opt.sh /tmp/rw-printer-build
CARGO_TARGET_DIR=target/printer cargo build --release -p romwright-worker -p romwright-cli
benchmarks/printer_diff.py --ghidra-opt /tmp/rw-printer-build/ghidra_opt \
    --target target/printer --jobs 6 --report benchmarks/reports/printer_diff.json
```

| image | identical |
|---|---:|
| gba-pokeemerald | 200/200 |
| gc-animal-crossing | 200/200 |
| nds-pokeheartgold-arm9 | 200/200 |
| ps2-capcom-fighting-evolution | 200/200 |
| ps2-dungeon-game | 200/200 |
| psv-need-for-speed-most-wanted | 200/200 |
| psx-darkstalkers-3 | 200/200 |
| x360-black-ops-2 | 200/200 |
| x86-libc | 200/200 |
| **total** | **1800/1800 (100%)** |

No remaining difference categories. The two found on the way were export
bugs, not printer differences: an `if` with an unstructured edge has only its
condition child (79 functions were refused), and a switch's unstructured
(`BlockMultiGoto`) cases point at blocks outside the switch (4 functions).
With the Rust printer, no structuring models and the default passes, the 200 gc functions'
DecompDoc tokens are identical to PrintC's, including those re-rendered by
`renderFunctionIR`.

Re-measured 2026-10-07 with printer IR version 2 (per-block labels,
out-edges and negated conditions, below): still 1800/1800 identical with
`ROMWRIGHT_RUST_STRUCTURING` unset.

## Structuring models

2026-10-07, working tree on `7e29f17c`. The Rust structuring passes
(`crates/romwright-worker/src/printc/structure.rs`, design in
[printer-ir.md](printer-ir.md#structuring-passes-default-romwright_rust_structuringall))
rewrite Ghidra's structured tree before the Rust printer prints it. Each
model alone and all together, against the baseline -- the Rust printer
without structuring, byte-identical to PrintC -- on the same Funcdata.
Counts are printed `goto`s / label definitions in the DecompDoc tokens.

```
native/build_ghidra_opt.sh /tmp/rw-structmodels-build
CARGO_TARGET_DIR=target/structmodels cargo build --release -p romwright-worker -p romwright-cli
benchmarks/structuring_models.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/structmodels --jobs 8 --dump /tmp/structuring-dump \
    --report benchmarks/reports/structuring_models.json
benchmarks/structuring_models.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/structmodels --jobs 8 --ir-passes "" \
    --report benchmarks/reports/structuring_models_ir_none.json
benchmarks/structuring_compile.py --dump /tmp/structuring-dump \
    --report benchmarks/reports/structuring_compile.json
benchmarks/structuring_m22.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/structmodels --report benchmarks/reports/structuring_m22.json
python3 tests/m15-001_structuring.py --report /tmp/m15.json
```

Default IR passes (what export-c and the desktop run), gotos / labels:

| image | baseline | break_continue | collapsed_edges | switch_tails | loop_exits | irreducible_entry | all |
|---|---:|---:|---:|---:|---:|---:|---:|
| gba-pokeemerald | 53 / 34 | 53 / 34 | 53 / 34 | 11 / 10 | 47 / 30 | 47 / 31 | **4 / 4** |
| gc-animal-crossing | 44 / 24 | 42 / 24 | 44 / 24 | 32 / 20 | 38 / 23 | 42 / 24 | **26 / 16** |
| nds-pokeheartgold-arm9 | 9 / 7 | 9 / 7 | 9 / 7 | 7 / 5 | 9 / 7 | 5 / 3 | **3 / 1** |
| ps2-capcom-fighting-evolution | 8 / 7 | 8 / 7 | 8 / 7 | 5 / 5 | 7 / 6 | 6 / 6 | **4 / 4** |
| ps2-dungeon-game | 121 / 95 | 121 / 95 | 121 / 95 | 82 / 71 | 117 / 91 | 87 / 72 | **53 / 48** |
| psv-need-for-speed-most-wanted | 23 / 23 | 23 / 23 | 23 / 23 | 21 / 21 | 22 / 22 | 21 / 21 | **18 / 18** |
| psx-darkstalkers-3 | 13 / 11 | 13 / 11 | 13 / 11 | 4 / 4 | 13 / 11 | 12 / 10 | **3 / 3** |
| x360-black-ops-2 | 41 / 30 | 40 / 29 | 41 / 30 | 24 / 15 | 41 / 30 | 40 / 29 | **22 / 13** |
| x86-libc | 1199 / 703 | 1198 / 702 | 1195 / 702 | 868 / 551 | 1089 / 651 | 1159 / 678 | **735 / 478** |
| **consoles** | 312 / 231 | 309 / 230 | 312 / 231 | 186 / 151 | 294 / 220 | 260 / 196 | **133 / 107** |
| **total** | 1511 / 934 | 1507 / 932 | 1507 / 933 | 1054 / 702 | 1383 / 871 | 1419 / 874 | **868 / 585** |
| functions fewer gotos | -- | 4 | 3 | 152 | 36 | 41 | 176 |
| functions more gotos | -- | 0 | 0 | 0 | 0 | 0 | **0** |

`ROMWRIGHT_IR_PASSES=""` (stock structuring, no forced cuts), totals:
baseline 1547 / 918, break_continue 1544 / 916, collapsed_edges 1547 / 918,
switch_tails 1106 / 701, loop_exits 1408 / 893, irreducible_entry
1470 / 866, all **900 / 610** (173 functions fewer, 0 more); per image in
`benchmarks/reports/structuring_models_ir_none.json`. `collapsed_edges`
only finds work after the `structure` pass's forced cuts split a condition
Ghidra would otherwise have joined with `||`.

Checks on the same runs:

- **Control flow.** The pass's checker (printed flow against every block's
  out-edges) accepted Ghidra's tree for 2244 of 2246 renders (default
  passes) and 1799 of 1800 (ir-none); the refusals are one libc function
  (`block 15 branches to [16] but prints flowing to Leaf(21)`, a shape the
  checker does not model), left exactly as Ghidra printed it. Rewrites the
  checker rejected are undone; none is printed.
- **Compile.** `benchmarks/structuring_compile.py` (`gcc -fsyntax-only
  -std=gnu89` with Ghidra's type names, differential per function,
  `undeclared` errors left out): every configuration, 1800 functions,
  0 functions with a diagnostic the baseline lacks; 1519 functions are
  error-free in the baseline and stay error-free (177 rewritten under `all`).
- **m22 standalone** (`benchmarks/structuring_m22.py`, the m22-001 scoring
  through console_research's `M22Runner`): baseline 64.142, every model
  64.142 except switch_tails and all 64.143 (GetMoveTarget 66.081 ->
  66.126); 6/33 exact everywhere. Only CreateTask and GetMoveTarget print
  gotos in this set (2 each); `all` removes them.
- **m15-001** runs `structuring::structure`, which this work does not
  touch: ours 2133 against stock's 2516 unstructured edges, **0.8478**,
  unchanged.
- **Printer differential** with structuring unset: 1800/1800 identical.
- Regression tests (`cargo test --release -p romwright-worker --lib printc`):
  small shapes cut from gc 0x8002bac0 / 0x80036140, gba 0x080824fc, dungeon
  0x0011de20, x360 0x823570c8 and libc 0x0010a940.

What is left (`all`, consoles 133): gotos into loops after an unrolled
prologue (a loop entered in the middle, which only loop duplication
removes), exits to tails longer than the copy bound (6 statements, 3
blocks), and jumps into the middle of another arm whose rest does not
rejoin where the jump's own position continues.

Recommendation: make `ROMWRIGHT_RUST_STRUCTURING=all` the default together
with the Rust printer. It removes 43% of printed gotos and 37% of labels
on the gate set (57% / 54% on the consoles) without a per-function
regression, a new compile diagnostic, or an m22/m15 regression. It needs
the Rust printer on by default first (its own cutover decision) and a
`native/build` rebuild with printer IR version 2.

## SAILR-style passes and the copy budget

2026-10-07, working tree on `7e29f17c`, same gate set, `ghidra_opt` and
default IR passes as above. Following Basque et al., "Ahoy SAILR! There is
No Need to DREAM of C" (USENIX Security 2024): classify the gotos that are
left by the compiler optimization (or structuring limitation) behind them,
and revert the commonest. Worked from the paper only; no angr code was read
or used, so there is no third-party notice to add.

### Remaining gotos by cause

`ROMWRIGHT_RUST_STRUCTURING_LOG` now carries, per render, the remaining
gotos by where the target sits relative to the goto (`classify` in
structure.rs); `structuring_models.py` keeps the log line of the render it
counts. Before this work (`all` with the fixed 6-statement / 3-block copy
bound, `benchmarks/reports/structuring_sailr_before.json`), consoles 133:

| image | into_loop | loop_exit | backward | cross_arm | into_arm | exit_nested | skip_after | other | total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gba-pokeemerald | 0 | 0 | 0 | 0 | 2 | 1 | 1 | 0 | 4 |
| gc-animal-crossing | 2 | 9 | 0 | 4 | 1 | 3 | 7 | 0 | 26 |
| nds-pokeheartgold-arm9 | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 3 |
| ps2-capcom-fighting-evolution | 0 | 2 | 1 | 0 | 0 | 0 | 1 | 0 | 4 |
| ps2-dungeon-game | 26 | 3 | 1 | 4 | 4 | 9 | 6 | 0 | 53 |
| psv-need-for-speed-most-wanted | 1 | 3 | 2 | 4 | 0 | 4 | 3 | 1 | 18 |
| psx-darkstalkers-3 | 0 | 0 | 0 | 2 | 0 | 0 | 1 | 0 | 3 |
| x360-black-ops-2 | 0 | 1 | 2 | 6 | 0 | 7 | 6 | 0 | 22 |
| **consoles** | 29 | 18 | 6 | 20 | 7 | 27 | 25 | 1 | **133** |

What produces them, from reading the functions:

- `exit_nested` (27; a goto from inside a statement to the statement right
  after it) and `skip_after` (25; past statements that follow it) are
  mostly *cross-jumping*: the compiler merged a tail out of the arms
  (x360 0x8247d8a8: both arms jump past the `FUN_82833c00(lVar3,lVar4)`
  they share) or *jump threading*: the path that already knows a test's
  outcome jumps past it (x360 0x8264bb68). *Switch lowering* produces
  them in bulk: a binary-search compare chain whose cases set a value and
  `goto` the join (gc 0x800a4578: 6, x360 0x8218cb60: 6, gba 0x081b31b0).
  Three structuring limitations also land here: Ghidra did not form the
  else arm (`if (c) { A; goto L; } R; L:`), Ghidra folded the statements
  ahead of an `if` into its condition block, which hid that shape from the
  models, and a do-while test carrying the goto's label was refused as a
  `continue` target (nds 0x0204babc: 3).
- `into_loop` (29, 26 in dungeon, 15 in 0x0010cc90 alone): a loop entered
  in the middle -- *loop unrolling* with a Duff-style remainder entry and
  *loop rotation*.
- `cross_arm` (20) / `into_arm` (7): one arm jumps into the middle of the
  other's code (partial cross-jumping) whose copy, up to where it rejoins,
  was over the copy bound or held a loop.
- `loop_exit` (18): loops with several exits whose target is not the
  loop's follow, typically *jump threading* past a post-loop test (psv
  0x8106a2a4: the exit sets `iVar4` as the code after the loop does and
  jumps past `if (local_48 != '\0')`, false on that path).
- `backward` (6): back edges Ghidra did not make a loop.

109 of the 133 had no copyable tail ending where the goto's own position
continues (`/no-tail`), so a bigger copy bound alone could not remove them.

### Passes

Changes, each in `printc/structure.rs`:

- **Condition-list hoist and labelled-test `continue`** (normalization,
  always on with any model): statements Ghidra folded into an if's
  condition block move in front of the `if` (same C), an arm left with
  one statement prints as that statement (`else if`), and a do-while test
  whose only printed content is the test is a `continue` target even when
  it carries a label.
- **`else_join`**: `if (c) { A; goto L; } R; L:` becomes
  `if (c) { A } else { R }`. Copies nothing.
- **`sink_join`**: reverts cross-jumping and jump threading by
  duplication -- M between an if holding a goto to L and L moves into the
  if's arms; the follow-up rewrites (negated if, `else_join`, dropped
  goto) must then remove a goto or the whole move is undone.
- **Copy budget** (`budget=N`) replaces the fixed bound: every rewrite may
  add at most N printed lines per goto it removes, lines counted as PrintC
  lays the tree out. Default 4 (next section).

Commands:

```
CARGO_TARGET_DIR=target/sailr cargo build --release -p romwright-worker -p romwright-cli
benchmarks/structuring_models.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/sailr --jobs 11 \
    --config five=break_continue,collapsed_edges,switch_tails,loop_exits,irreducible_entry \
    --config five_b6=break_continue,collapsed_edges,switch_tails,loop_exits,irreducible_entry,budget=6 \
    --config five_else=break_continue,collapsed_edges,else_join,switch_tails,loop_exits,irreducible_entry \
    --config no_else=break_continue,collapsed_edges,switch_tails,loop_exits,irreducible_entry,sink_join \
    --dump /tmp/sailr-final-dump --report benchmarks/reports/structuring_sailr.json
benchmarks/structuring_compile.py --dump /tmp/sailr-final-dump \
    --report benchmarks/reports/structuring_sailr_compile.json
benchmarks/structuring_m22.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/sailr --configs baseline,else_join,sink_join,all \
    --report benchmarks/reports/structuring_sailr_m22.json
benchmarks/structuring_models.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/sailr --jobs 11 --configs all --ir-passes "" \
    --config five=break_continue,collapsed_edges,switch_tails,loop_exits,irreducible_entry \
    --report benchmarks/reports/structuring_sailr_ir_none.json
benchmarks/structuring_models.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \
    --target target/sailr --jobs 11 --configs all --config b0=all,budget=0 \
    --config b2=all,budget=2 --config b3=all,budget=3 --config b5=all,budget=5 \
    --config b6=all,budget=6 --config b8=all,budget=8 --config b12=all,budget=12 \
    --config b16=all,budget=16 --report benchmarks/reports/structuring_sailr_budget.json
# m15 hard-codes target/release; it was run with its CLI and WORKER pointed
# at target/sailr and its own cargo build skipped:
python3 tests/m15-001_structuring.py --report /tmp/m15.json
```

Gotos / labels and printed lines / statements (non-blank lines, lines
ending in `;`) over the 1800 functions; budget 4 unless stated. "Before"
is the previous build's `all` (fixed bound). Every configuration: 0
functions with more gotos than the baseline, the same 2 refused renders
(the one libc function the checker does not model, left as Ghidra
printed it), 0 new gcc diagnostics.

| configuration | consoles gotos / labels | consoles lines / statements | total gotos / labels | total lines / statements | functions better |
|---|---:|---:|---:|---:|---:|
| baseline | 312 / 231 | 55403 / 36444 | 1511 / 934 | 77637 / 51200 | -- |
| before (`all`, fixed bound) | 133 / 107 | 55746 / 36632 | 868 / 585 | 79365 / 52109 | 176 |
| five models, `budget=6` (+ hoist, `continue`) | 124 / 99 | 55746 / 36645 | 849 / 569 | 79339 / 52110 | 180 |
| five models | 131 / 103 | 55687 / 36607 | 926 / 614 | 78828 / 51838 | 176 |
| five + `else_join` | 124 / 99 | 55698 / 36595 | 902 / 600 | 78792 / 51759 | 179 |
| five + `sink_join` (`all` without `else_join`) | 102 / 83 | 55742 / 36635 | 880 / 586 | 78900 / 51873 | 185 |
| **`all`** (five + both) | **91 / 78** | **55745 / 36621** | **854 / 576** | **78833 / 51766** | **187** |
| `else_join` alone | 301 / 228 | 55423 / 36431 | 1462 / 914 | 77667 / 51150 | 30 |
| `sink_join` alone | 312 / 231 | 55403 / 36444 | 1511 / 934 | 77637 / 51200 | 0 |

`sink_join` alone is a no-op by design (its follow-ups are the other
models); against `all` it removes 48 gotos for +41 lines, `else_join` 26
for -67 lines. Per image (baseline / before / `all`, gotos / labels /
lines):

| image | baseline | before | `all` |
|---|---:|---:|---:|
| gba-pokeemerald | 53 / 34 / 4806 | 4 / 4 / 4868 | 1 / 1 / 4875 |
| gc-animal-crossing | 44 / 24 / 7590 | 26 / 16 / 7645 | 21 / 14 / 7611 |
| nds-pokeheartgold-arm9 | 9 / 7 / 4003 | 3 / 1 / 4031 | 0 / 0 / 4022 |
| ps2-capcom-fighting-evolution | 8 / 7 / 5482 | 4 / 4 / 5497 | 4 / 4 / 5499 |
| ps2-dungeon-game | 121 / 95 / 10330 | 53 / 48 / 10443 | 40 / 35 / 10453 |
| psv-need-for-speed-most-wanted | 23 / 23 / 12403 | 18 / 18 / 12412 | 15 / 15 / 12416 |
| psx-darkstalkers-3 | 13 / 11 / 3034 | 3 / 3 / 3057 | 2 / 2 / 3058 |
| x360-black-ops-2 | 41 / 30 / 7755 | 22 / 13 / 7793 | 8 / 7 / 7811 |
| x86-libc | 1199 / 703 / 22234 | 735 / 478 / 23619 | 763 / 498 / 23088 |

Examples: gc 0x800a4578 6 -> 0 (the lowered switch prints as an else-if
chain with `uVar5 = 3;` twice), x360 0x8218cb60 6 -> 1, 0x8247d8a8 2 -> 0,
0x8264bb68 1 -> 0, nds 0x0204babc 3 -> 0. libc trades 28 more gotos than
before for 531 fewer lines: the budget prices its long copies out.

Other checks:

- **Compile** (`structuring_compile.py`, 12 configurations x 1800
  functions): 0 functions with a diagnostic the baseline lacks; the 1519
  error-free baseline functions stay error-free (188 rewritten in `all`).
- **m22 standalone**: baseline 64.142, `else_join` 64.142, `sink_join`
  64.142, `all` 64.143 (GetMoveTarget 66.081 -> 66.126, as before); 6/33
  exact everywhere.
- **m15-001**: PASS, ours 2133 against stock 2516, **0.8478**, unchanged
  (this work does not touch `structuring::structure`).
- **ir-none** (`ROMWRIGHT_IR_PASSES=""`): consoles 319 -> 106 gotos
  (before: 145), total 1547 -> 919 (before: 900), 186 functions better,
  0 worse, 1 refused render.
- **Tests** (`cargo test --release -p romwright-worker --lib printc`, 20
  pass): new shapes from gc 0x800a4578 (`else_join`), x360 0x8247d8a8
  (`sink_join`, and that it is a no-op alone) and nds 0x0204babc
  (`continue` to a labelled test); the settings parser.

### Copy budget

`all` at each budget (`benchmarks/reports/structuring_sailr_budget.json`,
`--config bN=all,budget=N`); the last column is the lines each step adds
per goto it removes, on the whole set:

| budget | total gotos / labels | total lines | consoles gotos / labels | consoles lines | step lines / goto |
|---:|---:|---:|---:|---:|---:|
| (baseline) | 1511 / 934 | 77637 | 312 / 231 | 55403 | |
| 0 | 1269 / 780 | 77652 | 215 / 163 | 55465 | 0.06 |
| 2 | 1053 / 668 | 78048 | 137 / 107 | 55606 | 1.83 |
| 3 | 955 / 615 | 78362 | 98 / 84 | 55709 | 3.20 |
| **4** | **854 / 576** | **78833** | **91 / 78** | **55745** | 4.66 |
| 5 | 815 / 555 | 79085 | 87 / 75 | 55759 | 6.46 |
| 6 | 789 / 536 | 79270 | 82 / 72 | 55807 | 7.12 |
| 8 | 761 / 522 | 79496 | 79 / 70 | 55848 | 8.07 |
| 12 | 741 / 507 | 79752 | 75 / 67 | 55917 | 12.80 |
| 16 | 728 / 498 | 79996 | 71 / 63 | 56026 | 18.77 |

Each further goto costs more lines the higher the budget, so the budget is
a readability trade, not a correctness one. The default is the largest
budget at which neither the consoles nor the whole set print more lines
than the fixed bound did (consoles 55746, total 79365): 4 -- consoles 133
-> 91 gotos at -1 line, total 868 -> 854 at -532 lines. Budget 6 removes
65 more gotos overall (consoles 9) for +437 lines (consoles +62).

### What is left, and what was not built (as of the SAILR round, superseded below)

`all`, consoles 91: into_loop 28, loop_exit 19, cross_arm 12,
exit_nested 11, into_arm 8, skip_after 6, backward 6, other 1 (76 with no
copyable tail). Not built:

- **Switch-lowering reversal** (compare chain -> `switch`): the lowered
  switches in the samples now print goto-free or nearly (gc 0x800a4578 0,
  gba 0x081b31b0 1, x360 0x8218cb60 1), so it would be cosmetic here. It
  also needs the conditions as expressions -- the IR carries them as
  PrintC emit fragments -- and a multi-way head the checker can verify.
- **Jump-threading reversal proper** (re-inserting the threaded test
  instead of duplicating code) and **loop re-rolling** need expression
  equality, which SAILR has on angr's AIL and this IR does not; they are
  what the remaining `loop_exit` (psv 0x8106a2a4) and dungeon `into_loop`
  gotos (unrolled copy loops) would take.
- **De-duplication of copied regions**: the passes copy only what removes
  a goto within the budget; recognizing code the *compiler* duplicated
  (loop-header copies) again needs expression equality.

Recommendation: make `ROMWRIGHT_RUST_STRUCTURING=all` (budget 4) the
default together with the Rust printer, superseding the recommendation
above: on the consoles it prints 71% fewer gotos than Ghidra (312 -> 91)
and 32% fewer than the fixed-bound `all` at the same size, with no
function regressing, no new compile diagnostic and m22/m15 unchanged.
Same prerequisites as above (Rust printer default, `native/build` with
printer IR version 2).

## Default cutover

2026-10-07: the recommendation above is applied. The Rust printer prints
every function and `ROMWRIGHT_RUST_STRUCTURING` defaults to `all` (budget
4); `ROMWRIGHT_RUST_PRINTER` is gone, `ghidra_opt` exports the printer IR
unconditionally and `native/build/ghidra_opt` was rebuilt. PrintC's markup
is kept only for the printer differential (`romwright-worker
--printer-diff` prints the IR without structuring, `printc::reference`).
`ROMWRIGHT_RUST_STRUCTURING=none` prints Ghidra's structure (ablation,
oracle parity: `tests/m4-003_language_parity.py` pins it).

Gate set (8 console samples + 200 libc, 1800 functions), printed gotos /
labels / non-blank lines. Before = PrintC default (pre-cutover build;
`structuring_baseline.py` there: consoles 312, total 1511 gotos, equal to
`baseline` below); after = the new default:

| | consoles | total | functions better / worse |
|---|---:|---:|---:|
| before (PrintC) | 312 / 231 / 55403 | 1511 / 934 / 77637 | |
| after (Rust printer, `all`) | 91 / 78 / 55745 | 854 / 576 / 78833 | 187 / 0 |

Whether the native `structure` IR pass (forced-goto cuts, kept only when
the printed function has fewer gotos -- now counted after the structuring
models) still earns its place, `all` with and without it:

| IR passes | consoles | total | m22 standalone |
|---|---:|---:|---:|
| default (`additive_inverse,canonical_helpers,structure`) | 91 / 78 / 55745 | 854 / 576 / 78833 | 64.143 (6/33 exact) |
| `additive_inverse,canonical_helpers` | 106 / 88 / 55765 | 919 / 597 / 78799 | 64.143 (6/33 exact) |

It still removes 15 console gotos (65 overall, 20 functions fewer, none
more) at +34 lines overall, with m22 unchanged, so it stays in the
defaults. Other checks on the cutover build: printer differential
1800/1800 identical; m22 standalone 64.142 (`none`) -> 64.143 (`all`); m15
0.8478 of stock (unchanged, it calls the structurer directly); the desktop
decompiler panel on the PS2 dungeon project prints 0x001284d8 with 0
gotos (PrintC: 3 gotos, 2 labels).

```
native/build_ghidra_opt.sh "$PWD/target/printercut/opt-after"   # absolute OUTDIR
CARGO_TARGET_DIR=target/printercut/after cargo build --release \
    -p romwright-cli -p romwright-worker -p romwright-api -p romwright-desktop
benchmarks/structuring_models.py --ghidra-opt target/printercut/opt-after/ghidra_opt \
    --target target/printercut/after --configs all \
    --report benchmarks/reports/structuring_cutover.json
benchmarks/structuring_models.py --ghidra-opt target/printercut/opt-after/ghidra_opt \
    --target target/printercut/after --configs all \
    --ir-passes additive_inverse,canonical_helpers \
    --report benchmarks/reports/structuring_cutover_no_structure.json
benchmarks/structuring_m22.py --ghidra-opt target/printercut/opt-after/ghidra_opt \
    --target target/printercut/after --configs baseline,all \
    --report benchmarks/reports/structuring_cutover_m22.json
benchmarks/structuring_m22.py --ghidra-opt target/printercut/opt-after/ghidra_opt \
    --target target/printercut/after --configs all \
    --ir-passes additive_inverse,canonical_helpers \
    --report benchmarks/reports/structuring_cutover_m22_no_structure.json
benchmarks/printer_diff.py --ghidra-opt target/printercut/opt-after/ghidra_opt \
    --target target/printercut/after --report benchmarks/reports/printer_diff.json
```

## Fake-match metric and the goto passes (round 2)

2026-10-08. A match that only holds through `goto` reproduces the bytes, not
the source's control flow, so printed gotos are judged against the real C.
Everything below was measured on the host (`ssh nih-vps-u`) with
`ghidra_opt` built *before* ProtoWork's Thumb-return hunks ("opt3": printer IR
v3 on the 04:02 patch), so before/after are the same decompiler apart from
this work; "current tree" repeats it with the rebuilt pair (patch of
2026-10-08 17:45). `benchmarks/reports/*goto_passes*`, `spurious_gotos*`.

### The metric (`benchmarks/spurious_gotos.py`, a supplement)

pokeemerald (`~/opt/pokeemerald-src`, GBA) and pokeheartgold
(`~/opt/pokeheartgold-src`, NDS arm9) have C source. The script maps every
decompiled function to its definition by symbol name (the images' unstripped
ELF; pokeemerald's local symbols through their `STT_FILE`), counts `goto`
tokens in the function body of the source (comments, strings and
preprocessor lines removed) and in our printed C, and reports per
configuration and image:

- **spurious functions**: scored functions printing >= 1 goto whose source
  has none;
- **spurious gotos**: sum over scored functions of max(0, printed - source).

Not scored: `asm`/`NAKED` definitions, names without a definition (macro
generated, asm-only, libraries) and names defined in several files that the
symbol table cannot tell apart. Sets: the 200-function samples of the
structuring gate set plus the 33 m22 functions (pokeemerald: 232 decompiled,
230 scored; pokeheartgold: 200, 194 scored), and the final research export's
samples (`--cache ~/.cache/romwright/research-final --sample-key
cdbbf0f7d1273898`: other functions, project with prototypes). The sources are
nearly goto-free (32 `goto` in pokeemerald's `src`, 1 in pokeheartgold's),
so *every* printed goto in a scored function is spurious.

| set / configuration | scored | printed gotos | spurious functions | spurious gotos |
|---|---:|---:|---:|---:|
| gate set, Ghidra's structure (`none`) | 424 | 67 | 31 | 67 |
| gate set, default before (`all`, budget 4) | 424 | 1 | 1 | 1 |
| **gate set, default after (`all`, budget 5)** | 424 | 0 | **0** | **0** |
| final export, `none` | 424 | 81 | 34 | 81 |
| final export, default before | 424 | 14 | 6 | 14 |
| **final export, default after** | 424 | 4 | **3** | **4** |

Per image (spurious functions / gotos, before -> after): gate set gba 1/1 ->
0/0, nds 0/0 -> 0/0; final export gba 6/14 -> 3/4, nds 0/0 -> 0/0 (the 9
Ghidra gotos in nds are gone in the default already). With the rebuilt pair
(current tree): gate set 0/0, final export 2/2.

Remaining spurious in the final export (opt3 pair): TaskFunc_UpdateWavePerFrame
(`default: goto L` over the statement after the switch: one statement
copied into seven cases, over the budget), HandleInput_InParty (2: a
`switch` default skipping a two-statement tail, and a flag threaded through
several assignments that do not all agree; with the rebuilt pair its
decompile has no goto) and Task_Hof_InitTeamSaveData (a loop exit threaded
past a test whose arm assigns differently on the two paths: the statements,
not just the test, must be proved equal).

### Printer IR version 3: expression trees

`native/romwright_printir.hh` exports, per statement candidate, an `Effect`
(opcode, calls/stores, written variable, CBRANCH polarity, inputs as `Expr`
trees: implied varnodes expanded, explicit ones leaves naming SSA value and
HighVariable with their storage class and aliasing). `printc/expr.rs` compares
(`same`), negates and propagates them (`Facts`: value sets of compared
expressions, `variable = constant` assignments, killed by writes, calls and
stores). Printer differential (`benchmarks/printer_diff.py`, 1800 functions,
current tree): **1800/1800 identical**; the fragments the printer reads are
unchanged. Details: [printer-ir.md](printer-ir.md#expression-trees-version-3).

### Passes

Each gated one by one on the gate set's goto counts and the spurious metric
(`structuring_models.py --config`, `spurious_gotos.py --config`), on `all` at
budget 4 unless stated; the 1800-function set is the 8 console samples plus
200 libc functions:

| change | consoles gotos | final-export gba spurious functions / gotos |
|---|---:|---:|
| before (`all`, budget 4) | 91 | 6 / 14 |
| + `sink_join` over a `switch` (cases that reach the end take M; `case n: goto L` becomes empty) and follow-ups run until the rewrite is affordable (16, was 8) | 88 | 5 / 7 |
| + `cond_merge` and `thread_test` | 86 | 3 / 5 |
| + budget 5 (**the new default**) | **84** | **3 / 4** (gate set 1 -> 0) |

Alone, on the unchanged `all` (earlier runs): `cond_merge` 91 -> 89 consoles
(x360), final export 14 -> 13 gotos (rfu_LMAN_CHILD_checkSendChildName);
`thread_test` 91 -> 91, final export 14 -> 13 (SpriteCB_PlayerOnBicycle).
The switch sink's gain is Cmd_jumpifstat 7 -> 0 (`case k: if (c) goto L;
break;` with `bVar2 = true; L:` after the switch) and x360's 8 -> 5.

Consoles 91 -> 84 gotos (labels 78 -> 72), libc 763 -> 727, whole set 854 ->
811; lines consoles 55745 -> 55780, whole set 78833 -> 79104; 189 functions
with fewer gotos, 0 with more. Per class (consoles):

| class | before | after |
|---|---:|---:|
| into_loop | 28 | 28 |
| loop_exit | 19 | 18 |
| cross_arm | 12 | 11 |
| exit_nested | 11 | 8 |
| into_arm | 8 | 7 |
| skip_after | 6 | 5 |
| backward | 6 | 6 |
| other | 1 | 1 |
| **total** | **91** | **84** |

Per image (before -> after): gba 1 -> 0, gc 21 -> 21, nds 0 -> 0, capcom 4 ->
3, dungeon 40 -> 40, psv 15 -> 15, psx 2 -> 2, x360 8 -> 3.

- **`thread_test`** is SAILR's jump-threading reversal on the structured
  tree (printc/structure/thread.rs). *Re-insert*: a `goto L` where `L` starts
  the arm of an `if (T)` and the conditions on every edge into `L` decide
  `T` drops the goto and runs `T` again (it falls out, `break`s or
  `continue`s into `T`). *Forward*: a goto (or `if (c) goto L;`) to a test
  the jump's own facts decide goes on to where the test leads; only the
  follow-ups remove the goto. The test must print nothing but itself and
  call nothing; facts die at calls/stores for aliased variables and loads, at
  writes to the variable, at labels other code jumps to and at loops. The
  checker accepts the changed edge through `Basic::threaded`, set on exactly
  the proved leaves, and never copies such a block. It rewrote
  gba 0x0816f9d4 to the shape the source has
  (`case 2: if (a || b) { x++; } break;`); on the console gate set it
  removes none: the threaded tests there decide on values that differ
  between the paths (statements, not tests, are equal), which needs the
  statement equality of the next item.
- **Not built, with the reason.** *Loop re-rolling / de-duplication of
  loop-header copies*: the 28 `into_loop` gotos are Duff-style remainder
  entries into unrolled bodies (dungeon 0x00112ab8, 0x00108dc0 and 15 in
  0x0010cc90 are zlib/stb copy loops unrolled four times with a one-, two-
  and three-iteration prologue). Re-rolling needs the unrolled copies proved
  equal modulo an induction variable, then rewritten as one loop and an
  entry test; the trees now give equality of tests, not of whole loop
  bodies, and nothing in the gate set that this would remove is in a function
  with source. *Switch-lowering reversal* (compare chain -> `switch`): the
  chain `p == 1 / p < 2 / p == 0` of gba 0x081b31b0 is decided by `Facts`,
  but as a `switch` its cases still need the shared struct copy M, so the
  goto goes only by the same copying (budget 5); no goto in the gate set
  disappears because a chain became a switch, so it was not built.
- **Budget.** 5 instead of 4: the smallest budget that removes the
  gate set's last spurious function (+35 console lines; compile and m22
  unchanged). Budget 8 removes 8 more console gotos than 5 for +89 lines
  (`structuring_goto_passes_variants.json`, measured before `cond_merge` and
  `thread_test` were default).

### Checks (all on the final build)

- **Compile** (`structuring_compile.py`, 1800 functions): 0 functions with a
  diagnostic the baseline lacks; 1519 error-free baseline functions stay
  error-free (190 rewritten). Every variant, same.
- **m22 standalone**: 64.14 (6/33 exact), baseline and `all`, unchanged.
- **Printer differential**: 1800/1800 identical (structuring off, printer IR
  v3).
- Tests: `cargo test --release -p romwright-worker --lib printc` (30 pass:
  expression facts, switch sink, `cond_merge`, both threadings, a write that
  blocks the threading).

```
native/build_ghidra_opt.sh "$PWD/target/opt3"          # absolute OUTDIR
CARGO_TARGET_DIR=target/q cargo build --release -p romwright-worker -p romwright-cli
benchmarks/spurious_gotos.py --ghidra-opt target/opt3/ghidra_opt --target target/q \
    --configs baseline,default --report benchmarks/reports/spurious_gotos.json
benchmarks/spurious_gotos.py --ghidra-opt target/opt3/ghidra_opt --target target/q \
    --cache ~/.cache/romwright/research-final --sample-key cdbbf0f7d1273898 \
    --configs baseline,default --report benchmarks/reports/spurious_gotos_final.json
benchmarks/structuring_models.py --ghidra-opt target/opt3/ghidra_opt --target target/q \
    --configs baseline,all --dump /tmp/gp-dump --report benchmarks/reports/structuring_goto_passes.json
benchmarks/structuring_compile.py --dump /tmp/gp-dump --report benchmarks/reports/structuring_goto_passes_compile.json
benchmarks/structuring_m22.py --ghidra-opt target/optm/ghidra_opt --target target/q \
    --configs baseline,all --report benchmarks/reports/structuring_goto_passes_m22.json
benchmarks/printer_diff.py --ghidra-opt target/optm/ghidra_opt --target target/q
```

What is left (`all`, consoles 84, table above): 28 `into_loop` (25 in
dungeon, unrolled loops with remainder entries), 18 `loop_exit` (interpreter
loops and search loops that exit through a flag assigned on both paths, e.g.
psv 0x8106a2a4, x360 0x82280cc8), 11 `cross_arm`, 8 `exit_nested`, 7
`into_arm`, 5 `skip_after`, 6 `backward`. Three things would take most of
them: loop re-rolling, exiting a loop through `break` plus a re-tested loop
condition (needs the condition proved to hold at the break), and proving
*statements* (not only tests) equal across two paths -- the expression trees
carry the statements' effects, so the last is the next step.

The `all` default is now all nine models at budget 5
(`ROMWRIGHT_RUST_STRUCTURING=thread_test` etc. still select single models).

## Arm order (P4.6, 2026-10-09)

`structure.rs` ends every restructure with `order_arms`: an `if`/`else` whose
`else` arm starts at a lower address than its `if` arm prints the arms in
address order, under the negated test. Ghidra writes the arm its own normal
form for the test selects (`if ((x & 1) == 0) A else B`); a compiler lays out
`if (x & 1) B else A` as the test, `B`, then `A`, so the printed order decides
which way the branch goes in a matching build. The address is the one the
leaf's `emitLabel` fragment names (block *indices* are Ghidra's flow order,
not addresses). Not reordered: a test that cannot be negated, and a pair of
arms that each only store a constant (a merged `return`: `FlagGet`'s
`t = 0` / `t = 1` scored 99.4 -> 74.2 when swapped, because the source had no
`if`/`else` there). `ROMWRIGHT_RUST_STRUCTURING=all,no_arm_order` turns it
off; `none` never runs it, so the printer differential is untouched.

Gates on the 1800-function set (`ghidra_opt` of the tree, `all` against
`all,no_arm_order`): printed gotos 813 / 813, functions better than Ghidra's
structure 184 / 184, worse 0 / 0, printed lines 80,955 / 80,836 (+119: a
reordered `else if` chain nests), functions rewritten 423 / 185, `gcc` new
diagnostics 0 / 0 (`structuring_compile.py`), spurious gotos 0 / 0
(`spurious_gotos.py`, 424 scored), printer differential 1800/1800 identical.
m22 context (ROM, 33 functions): 75.288 -> 75.734 (`CalcCRC16` 85.1 -> 87.3,
`ConvertIntToDecimalStringN` 62.2 -> 71.8, `GetMoveTarget` 66.1 -> 69.0).

```
benchmarks/structuring_models.py --ghidra-opt native/build/ghidra_opt --target target \
    --configs baseline,all --config noarm=all,no_arm_order --dump /tmp/arm-dump --report /tmp/arm.json
benchmarks/structuring_compile.py --dump /tmp/arm-dump --report /tmp/arm-compile.json
benchmarks/spurious_gotos.py --ghidra-opt native/build/ghidra_opt --target target \
    --configs baseline,default --config noarm=all,no_arm_order --report /tmp/arm-spurious.json
benchmarks/printer_diff.py --ghidra-opt native/build/ghidra_opt --target target
```

## Unstructured handoff (stage 1)

2026-10-11. `ghidra_opt` stops structuring: it exports the unstructured
control-flow graph (IR version 5) and the worker's `printc/collapse.rs`, a port
of `CollapseStructure`, builds the tree the printer prints
([printer-ir.md](printer-ir.md#unstructured-handoff-version-5-default)).
`ROMWRIGHT_NATIVE_STRUCTURE=1` is the stock path (Ghidra's tree, the Rust
models over it): this section's reference, and the baseline every number below
is measured against. The tree is exact where the port is: all 311 renders of
240 functions (30 per image, eight console images) of the tree built from the
stock pipeline's own graph equal Ghidra's, node for node
(`ROMWRIGHT_NATIVE_STRUCTURE=2 ROMWRIGHT_STRUCTURE=verify`, which also turns
`ActionPreferComplement` off so that only the base structurer is compared).

### Differential: Rust-structured against the stock path

`benchmarks/structure_handoff.py` decompiles each sampled function
(`export-c --address`, the ownership run's sample: 200 per image, seed
20261006, the console-research images) once on the stock path and once by
default, and compares the C text. `identical` is byte equality; `better`,
`neutral`, `worse` classify a changed function by printed gotos, then labels.
Both columns run the same Rust models (`ROMWRIGHT_RUST_STRUCTURING=all`), so
the gate is "no worse than the current default".

| image | functions | identical | better / neutral / worse | printed gotos stock -> Rust | labels | `else` | failed (stock / Rust) |
|---|---:|---:|---|---|---|---|---|
| gba-pokeemerald | 200 | 200 | 0 / 0 / 0 | 4 -> 4 | 8 -> 8 | 102 -> 102 | 0 / 0 |
| nds-pokeheartgold-arm9 | 200 | 200 | 0 / 0 / 0 | 0 -> 0 | 1 -> 1 | 77 -> 77 | 0 / 0 |
| ps2-capcom-fighting-evolution | 200 | 200 | 0 / 0 / 0 | 4 -> 4 | 7 -> 7 | 356 -> 356 | 0 / 0 |
| ps2-dungeon-game | 200 | 199 | 0 / 1 / 0 | 42 -> 42 | 23 -> 23 | 252 -> 252 | 0 / 0 |
| psx-darkstalkers-3 | 200 | 200 | 0 / 0 / 0 | 7 -> 7 | 6 -> 6 | 126 -> 126 | 0 / 0 |
| psv-need-for-speed-most-wanted | 200 | 200 | 0 / 0 / 0 | 52 -> 52 | 36 -> 36 | 135 -> 135 | 0 / 0 |
| x360-black-ops-2 | 200 | 200 | 0 / 0 / 0 | 6 -> 6 | 3 -> 3 | 203 -> 203 | 0 / 0 |
| gc-animal-crossing | 200 | 199 | 0 / 1 / 0 | 36 -> 36 | 19 -> 19 | 227 -> 227 | 0 / 0 |
| **all** | 1600 | 1598 | 0 / 2 / 0 | 151 -> 151 | 103 -> 103 | 1478 -> 1478 | 0 / 0 |

`benchmarks/reports/structure_handoff.json` (written by the script; ghidra_opt sha256 153960338f17ef9d...). The two psp images of the ownership sample have no project on the host and were skipped.

The two functions whose text differs print a `for` loop where the stock path
prints a `while` whose iterator statement is missing (`ps2-dungeon-game`
0x00107f18, `temp_v10 = temp_v10 + ...`; `gc-animal-crossing` 0x800774c4,
`temp_v7 = temp_v7 - 1` and the initializer): the stock text loops forever as
printed, the Rust tree prints the `for` the analysis found. Why the stock
printer left the statements out was not investigated.

### Where the two paths could differ, and what is exact

* **Condition polarity.** Ghidra's structurer negates a branch in the p-code,
  and `RuleCondNegate` and the boolean rules rewrite the flipped branch into the
  complemented comparison (`x <= 0x1e` is `x < 0x1f` by `replaceLessequal`). A
  version that left the graph as exported printed `0x1e >= x` where stock printed
  `x < 0x1f` (the first 30-function run: 6 of 60 PS2 functions differed). The
  worker now answers the negations (`printc/query.rs`) and `ghidra_opt` applies
  them, which is what made the paths equal.
* **`ActionPreferComplement`.** Its `flipInPlaceTest`/`Execute` run in C++ on the
  split points the worker's structure names; the worker swaps the arms of the
  `if`/`else` blocks whose test changed. The structure models'
  `order_arms` (arm order by layout address, "Arm order" below) runs after this,
  as before.
* **For loops.** `BlockWhileDo::finalTransform` runs for the `while` loops the
  worker's structure has (inner first), `finalizePrinting` after the variables
  merge; the loop's initializer and iterator stay exported as ordinary
  statements and the worker takes them out for a loop it prints as a `for`.
  Before the worker named the loops, a back-edge heuristic moved the iterator of
  loops that were not `while`s and changed variable types in one function.
* **`ActionReturnSplit`.** The worker names the in-edges of each multi-entry
  return block that its structure makes gotos, in Ghidra's order, including the
  "never split every edge" rule.

### Gates

Measured on `nih-vps-u`, the stock path (`ROMWRIGHT_NATIVE_STRUCTURE=1`) and the
default path of one build (`ghidra_opt` sha256
`153960338f17ef9d2b281028b26b20518a7779dd15d69c4193b3fdabd545aa7c`, the
release `romwright-cli`/`-worker` of the same tree), the same projects and
functions. The machine was loaded by other jobs throughout; no timing is
reported.

| gate | stock path | default (Rust structure) |
|---|---|---|
| m21-001 (7 images scored) | PASS | PASS |
| m22-002 MWCC seed 20261010, exact / mean % / compile failures | 55 / 76.976 / 3.5% | 55 / 76.976 / 3.5% (0 of 200 functions score differently) |
| m22-002 MWCC seed 20261011 | 57 / 78.321 / 3.0% | 57 / 78.321 / 3.0% (0 of 200) |
| m22-002 `--compiler eegcc` | 106 / 86.406 / 1.5% | 106 / 86.406 / 1.5% (0 of 200) |
| PS2 wave decompile success (`ps2_decompile_success.py`, 11 projects) | 10,337 / 10,342 | 10,337 / 10,342, the same five failures |
| `cargo test -p romwright-worker --lib` | | 96 passed, 10 ignored (the structurer's, the query's and the IR's tests among them) |

m22-002 against the figures this stage started from (55 exact / 76.624, 57 /
78.321, 106 / 86.406): not worse in exact or mean on any lane; the 76.624 ->
76.976 of seed 20261010 is in the stock column too, so it is another change of
the tree (the working tree carried other agents' PS2 work), not the handoff.

**The `if`/`else` arm-order class.** m22-002's open inexact class is the
`if`/`else` whose arms print in the other order from the source's: the compiler
emits the inverse branch and objdiff reports one branch replaced by its inverse
(`benchmarks/m22_branch_polarity.py` counts the functions with such a pair in a
run's work directory, `context` variant). Arm order is Rust's decision now:
Ghidra's `PreferComplement` choice (kept exact, above) and then the layout
rule of the models (`order_arms`: the arm laid out first prints first).

| lane | functions with an inverse-branch pair (pairs) | exact / mean % |
|---|---|---|
| seed 20261010, arms in Ghidra's order (`no_arm_order`) | 46 of 193 (63) | 51 / 74.355 |
| seed 20261010, stock path = default (layout order) | 32 of 193 (41) | 55 / 76.976 |
| seed 20261011, stock = default | 37 of 194 (44) | 57 / 78.321 |
| `--compiler eegcc`, stock = default | 4 of 197 (4) | 106 / 86.406 |

So the layout rule shrinks the class from 46 to 32 functions on seed
20261010 and the handoff keeps it there exactly; it does not shrink it
further. One variant was tried and not adopted: ordering the arms of an
`if`/`else` that each only store a constant too (`order_arms` excludes them,
because a merged `return`'s `t = 0`/`t = 1` has no source `if`; "Arm order"
above) moved seed 20261010 to 31 functions (40 pairs), exact 55, mean 76.976 ->
77.004: a gain of one function that the GBA result of the exclusion
(99.4 -> 74.2) does not justify without an agbcc run.


### Reproduce

```
native/build_ghidra_opt.sh --jobs 2          # ghidra_opt, default path
CARGO_TARGET_DIR=target cargo build --release -p romwright-cli -p romwright-worker
benchmarks/structure_handoff.py --target target --ghidra-opt native/build/ghidra_opt \
    --cache ~/runs/OwnershipMetric/cache --verify --jobs 3 --out /tmp/handoff.json
```
