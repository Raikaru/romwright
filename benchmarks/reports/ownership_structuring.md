# Ownership: Rust against the vendored Ghidra C++

Generated 2026-10-12T04:16:54+00:00 by `benchmarks/ownership.py`; definitions, stage attribution and reproduction in [docs/ownership.md](../../docs/ownership.md). Tree: `{"files": 346, "sha256": "13aecb49a6d18986", "vcs": "none: a working-tree snapshot, not a checkout"}`; tools fingerprint `ad8291070e1a047e`; n = 50 functions per image, seed 20261006.

## Headline

| measure | value |
|---|---|
| functions printed (all images) | 400 |
| printed text tokens emitted by Rust (block layer and expression printer) | 91.5% |
| printed text tokens replayed from PrintC's fragments (C++) | 8.5% |
| printed text tokens emitted by the Rust block layer | 13.4% |
| printed text tokens of expressions the Rust expression printer emitted | 78.1% |
| printed control-flow constructs created by the Rust structuring models | 100.0% |
| final p-code operations edited by a Rust transform | 0.7% |
| functions whose text changes with Rust structuring and IR passes off | 27.8% |
| functions changed by Rust structuring alone | 19.0% |
| functions changed by the Rust IR passes alone | 16.5% |
| functions whose text differs with the Rust expression printer off (PrintC's fragments instead) | 0.0% |
| executed code lines that are first-party Rust | 36.8% |
| executed code lines that are Rust (first-party + kuna-sleigh) | 44.1% |

## Stage attribution

Shares are of the stage's own unit; the rows do not add up to one number (docs/ownership.md explains why).

| stage | unit | basis | Rust (first-party) | Rust (kuna-sleigh) | C++ ours | C++ vendored | detail |
|---|---|---|---|---|---|---|---|
| load | bytes, symbols and types handed to the decompiler | code | 100.0% | n/a | n/a | n/a | provider.rs answers every query the C++ makes for bytes, symbols, types and flow facts; C++ loader lines executed: 2351 vendored (storage of what it is given) |
| discovery | stored analysis facts (xrefs, data definitions, flow overrides) by provenance | run | 100.0% | n/a | 0.0% | n/a | sampled functions by producer: {'call': 172, 'const': 4, 'pattern': 108, 'flow': 115, 'thunk': 1} (all Rust passes); constant-propagation facts are computed in process (native_runtime/propagation); facts owned by C++: 0 of 743641. Import time in C++-owned phases: 25.6% |
| flow (import walk) | flow queries during the discovery walk | code | n/a | 100.0% | n/a | n/a | discovery.rs walks with the in-process kuna-sleigh decoder (`SleighFlow`), and the constant propagation follows flow over the same decoder (native_runtime/propagation/graph.rs, FlowInfo); no C++ answers flow during import |
| flow (decompile) | instructions followed into the function body and its blocks | code + coverage | n/a | n/a | n/a | 100.0% | the decompiler's own FlowInfo (flow.cc) builds the function's p-code and block graph on every decompile; vendored flow lines executed 762 |
| pcode_lift | instructions lifted on the printed path | run + code | n/a | n/a | n/a | 100.0% | 20618 instructions in the sampled functions are lifted by the decompiler's own SLEIGH (ghidra_opt, ROMWRIGHT_SLA). Rust-lifted p-code (kuna-sleigh) feeds value-set analysis, SJA, the type solver and the prototype job, never the printed text |
| switch_recovery | dispatches in the stored import tables | run | 82.8% | n/a | n/a | 17.2% | 2107 of 2545 dispatches (84.0% of case edges) by Rust VSA; the rest by the decompiler path (a branch the decompiler-off import also stores is Rust's) |
| switch_recovery (printed) | switch tables the decompiler used when printing | run | 76.9% | n/a | n/a | 23.1% | 13 printed tables in 400 functions; the import's stored table was the authority for 13 (100.0%): 12 agreed with what jumptable.cc recovers again at decompile time, 1 replaced it; 0 had no stored table. Of the supplied tables 10 are Rust VSA's (the rest are the import's own decompiler pass, jumptable.cc at import time); jumptable.cc still derives the normalization, guards and case values. Of the sample's 9 Rust-recovered dispatches 9 also printed as a switch |
| simplification | final p-code operations | run | 0.7% | n/a | n/a | 99.3% | 290 Rust edits (290 additive_inverse, 0 canonical_helpers) over 40769 operations; 66 of 400 functions have an edit |
| type_inference (default) | printed type tokens | run | 0.0% | n/a | n/a | 100.0% | 2655 type tokens; the default import stores no persisted prototype, so every printed type is Ghidra's. The Rust type solver still runs per function as an evidence pass whose classes only steer export-c's temporary and global names |
| prototype (default) | printed function prototypes; call sites | run | 0.0% | n/a | n/a | 100.0% | 0 of 400 printed functions had a stored prototype; 0 of 1278 call sites name a callee with one (type-archive and SDK tables, Rust) |
| structuring | control-flow constructs in the printed tree | run | 100.0% | n/a | n/a | 0.0% | gotos 85 -> 24 and labels 68 -> 23 after the Rust models; 76 of 400 functions printed a Rust tree; created {'do_while': 124, 'if': 1350, 'leaf': 3749, 'condition': 222, 'goto_block': 19, 'while': 38, 'switch': 13, 'infinite_loop': 9, 'multigoto': 1}; IR `structure` cuts kept 0 of 63 |
| printing | visible text tokens | run | 91.5% | n/a | n/a | 8.5% | 120431 tokens: 10225 replayed from PrintC fragments (by kind {'comment': 898, 'function_name': 400, 'operator': 285, 'paren': 1194, 'punctuation': 2395, 'type': 2655, 'variable': 2255, 'label': 47, 'case_label': 96}), 16093 emitted by the Rust block layer and 94113 by the Rust expression printer (printc/render.rs, from the exported print trees; by kind {'function_name': 1298, 'operator': 28037, 'paren': 30686, 'type': 5890, 'variable': 27785, 'punctuation': 417}); 13569 expressions printed by Rust, 0 kept PrintC's fragment (by context.kind rust {'branch.branch': 532, 'branch.cbranch': 1730, 'negated.cbranch': 1730, 'statement.assign': 3545, 'statement.call': 1499, 'statement.cbranch': 1730, 'statement.return': 563, 'statement.store': 2196, 'branch.branchind': 13, 'statement.branchind': 13, 'loop-iterate.assign': 12, 'loop-init.assign': 6}, fragment {'branch.branch': 0, 'branch.cbranch': 0, 'negated.cbranch': 0, 'statement.assign': 0, 'statement.call': 0, 'statement.cbranch': 0, 'statement.return': 0, 'statement.store': 0, 'branch.branchind': 0, 'statement.branchind': 0, 'loop-iterate.assign': 0, 'loop-init.assign': 0}; why {}); 112034 spacing tokens laid out by printc/pretty.rs, a Rust port of EmitPrettyPrint (algorithm third-party, code first-party) |
| postprocess | identifiers in the export-c text | run | 19.6% | n/a | n/a | 80.4% | 11741 of 59941 identifier tokens are `temp_*`/`sp*` names emit_m2c gave decompiler locals; the rest keep the name the decompiler printed |

## Per image

| image | printed / sampled | tokens | Rust-emitted | constructs created by Rust | gotos Ghidra -> printed | edits / operations | printed differently without Rust: either (structuring alone / IR passes alone) | stored dispatches Rust-VSA |
|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | 50 / 50 | 6224 | 84.4% | 100.0% | 4 -> 1 | 5 / 1707 | 8/50 (7 / 2) | 598 of 617 |
| nds-pokeheartgold-arm9 | 50 / 50 | 4447 | 81.6% | 100.0% | 0 -> 0 | 1 / 1000 | 4/50 (3 / 1) | 384 of 408 |
| ps2-capcom-fighting-evolution | 50 / 50 | 17624 | 94.9% | 100.0% | 0 -> 0 | 14 / 5855 | 16/50 (12 / 8) | 184 of 515 |
| ps2-dungeon-game | 50 / 50 | 15532 | 92.8% | 100.0% | 46 -> 9 | 42 / 4354 | 16/50 (14 / 10) | 8 of 13 |
| psx-darkstalkers-3 | 50 / 50 | 7441 | 91.4% | 100.0% | 4 -> 1 | 35 / 2927 | 15/50 (6 / 11) | 20 of 21 |
| psv-need-for-speed-most-wanted | 50 / 50 | 27471 | 89.8% | 100.0% | 7 -> 5 | 3 / 9429 | 7/50 (6 / 3) | 553 of 601 |
| x360-black-ops-2 | 50 / 50 | 16070 | 92.0% | 100.0% | 7 -> 0 | 104 / 5680 | 23/50 (14 / 14) | 246 of 256 |
| gc-animal-crossing | 50 / 50 | 25622 | 93.4% | 100.0% | 17 -> 8 | 86 / 9817 | 22/50 (14 / 17) | 114 of 114 |
| psp-puzzle-bobble-pocket | error: import failed: thread 'main' (1319634) panicked at crates/romwright-core/src/native/discovery.rs:1170:58:
attempt to add with overflow
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace | | | | | | | |
| psp-puzzle-bobble-pocket-symtab | error: import failed: thread 'main' (1321179) panicked at crates/romwright-core/src/native/discovery.rs:1170:58:
attempt to add with overflow
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace | | | | | | | |

## Persisted-prototype profile

The same worker over the projects the research runs left after `infer_prototypes` (inferred-types merge on). `origin` names the project copied.

| image | origin tools | job seconds | printed | stored prototype | calls with stored prototype | parameter types upgraded by Rust | prototype sources |
|---|---|---|---|---|---|---|---|
| gba-pokeemerald | none usable | | | | | | |
| nds-pokeheartgold-arm9 | none usable | | | | | | |
| ps2-capcom-fighting-evolution | none usable | | | | | | |
| ps2-dungeon-game | none usable | | | | | | |
| psx-darkstalkers-3 | none usable | | | | | | |
| psv-need-for-speed-most-wanted | none usable | | | | | | |
| x360-black-ops-2 | none usable | | | | | | |
| gc-animal-crossing | none usable | | | | | | |
| psp-puzzle-bobble-pocket | none usable | | | | | | |
| psp-puzzle-bobble-pocket-symtab | none usable | | | | | | |

## Executed code lines by stage and owner

Lines with a nonzero count in the merged profiles of the default run (imports, the default decompile pass and the persisted-prototype pass; ablation passes are not merged). Each cell is executed/executable lines of the files the stage owns. Executable counts come from two different coverage mappings (clang for C++, rustc for Rust: lines with at least one mapped region), so compare executed lines, not percentages, across languages; a Rust line is a statement-sized unit, a C++ line often is too, but neither is a weighted work measure.

| stage | rust_first_party | rust_third_party | cpp_ours | cpp_vendored |
|---|---|---|---|---|
| load | 4494/12797 | 0/0 | 3/7 | 2351/4829 |
| discovery | 7719/10661 | 0/0 | 28/32 | 0/0 |
| flow | 337/356 | 0/0 | 29/32 | 762/1005 |
| pcode_lift | 772/1261 | 6702/20801 | 19/35 | 3904/10605 |
| switch_recovery | 2419/4881 | 0/0 | 153/191 | 1610/2058 |
| simplification | 792/1000 | 0/0 | 268/321 | 28924/38027 |
| type_inference | 155/2713 | 0/0 | 0/0 | 2942/6036 |
| prototype | 347/1539 | 0/0 | 17/18 | 2651/5773 |
| structuring | 4736/5846 | 0/0 | 451/477 | 1255/4641 |
| printing | 3362/4628 | 0/0 | 863/1148 | 1725/6616 |
| postprocess | 2412/3220 | 0/0 | 0/0 | 0/0 |
| host | 6269/28235 | 0/0 | 121/180 | 3366/10094 |
| **total** | 33814/77137 | 6702/20801 | 1952/2441 | 49490/89684 |

Other crates and std linked into the Rust binaries: 4330/95075 (not an owner).

Most-executed vendored C++ files (lines executed, stage):

- `ruleaction.cc`: 6469 (simplification)
- `coreaction.cc`: 3215 (simplification)
- `subflow.cc`: 2632 (simplification)
- `fspec.cc`: 2058 (prototype)
- `double.cc`: 1966 (simplification)
- `rangeutil.cc`: 1654 (simplification)
- `heritage.cc`: 1578 (simplification)
- `jumptable.cc`: 1542 (switch_recovery)
- `typeop.cc`: 1304 (type_inference)
- `database.cc`: 1285 (load)
- `type.cc`: 1135 (type_inference)
- `funcdata_varnode.cc`: 1122 (simplification)
- `printc.cc`: 1005 (printing)
- `block.cc`: 991 (structuring)
- `merge.cc`: 986 (simplification)

Most-executed first-party Rust files:

- `crates/romwright-core/src/native/discovery.rs`: 2119 (discovery)
- `crates/romwright-worker/src/printc/structure.rs`: 1477 (structuring)
- `crates/romwright-db/src/lib.rs`: 1468 (host)
- `crates/romwright-core/src/native/vsa.rs`: 1175 (switch_recovery)
- `crates/romwright-core/src/native/switch_tables.rs`: 1158 (switch_recovery)
- `crates/romwright-worker/src/printc/render.rs`: 1063 (printing)
- `crates/romwright-worker/src/provider.rs`: 988 (load)
- `crates/romwright-core/src/native.rs`: 977 (discovery)
- `crates/romwright-core/src/native_runtime/propagation.rs`: 919 (discovery)
- `crates/romwright-worker/src/printc/collapse/loops.rs`: 854 (structuring)
- `crates/romwright-core/src/native/gba/overlays.rs`: 838 (load)
- `crates/romwright-core/src/native_runtime/propagation/graph.rs`: 784 (discovery)
- `crates/romwright-core/src/native/store.rs`: 703 (host)
- `crates/romwright-worker/src/printc/ir.rs`: 661 (printing)
- `crates/romwright-worker/src/printc/pretty.rs`: 655 (printing)

Executed first-party Rust files no stage rule claims (counted under `host`): `crates/romwright-db/src/lib.rs` 1468, `crates/romwright-core/src/native/store.rs` 703, `crates/romwright-worker/src/worker.rs` 569, `crates/romwright-worker/src/wire.rs` 319, `crates/romwright-worker/src/doc.rs` 314, `crates/romwright-core/src/opinion.rs` 275, `crates/romwright-core/src/lib.rs` 244, `crates/romwright-core/src/session.rs` 235, `crates/romwright-cli/src/main.rs` 216, `crates/romwright-core/src/artifact.rs` 200, `crates/romwright-core/src/native_runtime.rs` 198, `crates/romwright-worker/src/main.rs` 168, `crates/romwright-core/src/exec.rs` 150, `crates/romwright-core/src/session/snapshot.rs` 105, `crates/romwright-worker/src/printc/ownership.rs` 97

## Lines of code

Unit: code lines: non-blank, non-comment; Rust test code excluded.

| owner | code lines | executable (coverage map) | executed in this run |
|---|---|---|---|
| rust_first_party | 115139 | 77137 | 33814 |
| rust_third_party | 17854 | 20801 | 6702 |
| cpp_ours | 2772 | 2441 | 1952 |
| cpp_vendored | 137961 | 89684 | 49490 |

First-party Rust by crate (code / test): romwright-api 862/165, romwright-cli 2486/0, romwright-core 65633/26420, romwright-db 5230/2003, romwright-debug 1659/763, romwright-desktop 13942/271, romwright-diff 1702/776, romwright-facts 1185/542, romwright-model 1914/60, romwright-sig 1018/468, romwright-worker 18199/3160, romwright-worker-client 1309/166

Ours C++: 662 patch-added code lines in 35 files, 2110 in native/romwright_*.hh. Vendored: counts every file of the pinned tree, including the SLEIGH compiler, the interactive console and the BFD loader, which `ghidra_opt` does not link; the coverage map's executable lines (`cpp_vendored`) are what the binary holds.

