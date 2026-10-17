# Ownership: Rust against the vendored Ghidra C++

Generated 2026-10-10T17:04:38+00:00 by `benchmarks/ownership.py`; definitions, stage attribution and reproduction in [docs/ownership.md](../../docs/ownership.md). Tree: `{"files": 322, "sha256": "04ff03f0b32b7537", "vcs": "none: a working-tree snapshot, not a checkout"}`; tools fingerprint `901c320a13fdf110`; n = 200 functions per image, seed 20261006.

## Headline

| measure | value |
|---|---|
| functions printed (all images) | 2000 |
| printed text tokens emitted by Rust (block layer and expression printer) | 90.9% |
| printed text tokens replayed from PrintC's fragments (C++) | 9.1% |
| printed text tokens emitted by the Rust block layer | 14.2% |
| printed text tokens of expressions the Rust expression printer emitted | 76.7% |
| printed control-flow constructs created by the Rust structuring models | 2.9% |
| final p-code operations edited by a Rust transform | 0.5% |
| functions whose text changes with Rust structuring and IR passes off | 33.2% |
| functions changed by Rust structuring alone | 23.1% |
| functions changed by the Rust IR passes alone | 18.6% |
| functions whose text differs with the Rust expression printer off (PrintC's fragments instead) | 0.0% |
| executed code lines that are first-party Rust | 32.5% |
| executed code lines that are Rust (first-party + kuna-sleigh) | 39.6% |

## Stage attribution

Shares are of the stage's own unit; the rows do not add up to one number (docs/ownership.md explains why).

| stage | unit | basis | Rust (first-party) | Rust (kuna-sleigh) | C++ ours | C++ vendored | detail |
|---|---|---|---|---|---|---|---|
| load | bytes, symbols and types handed to the decompiler | code | 100.0% | n/a | n/a | n/a | provider.rs answers every query the C++ makes for bytes, symbols, types and flow facts; C++ loader lines executed: 2392 vendored (storage of what it is given) |
| discovery | stored analysis facts (xrefs, data definitions, flow overrides) by provenance | run | 100.0% | n/a | 0.0% | n/a | sampled functions by producer: {'call': 849, 'flow': 329, 'pattern': 589, 'const': 27, 'thunk': 6, 'symbol': 200} (all Rust passes); constant-propagation facts are computed in process (native_runtime/propagation); facts owned by C++: 0 of 772258. Import time in C++-owned phases: 32.0% |
| flow (import walk) | flow queries during the discovery walk | code | n/a | 100.0% | n/a | n/a | discovery.rs walks with the in-process kuna-sleigh decoder (`SleighFlow`), and the constant propagation follows flow over the same decoder (native_runtime/propagation/graph.rs, FlowInfo); no C++ answers flow during import |
| flow (decompile) | instructions followed into the function body and its blocks | code + coverage | n/a | n/a | n/a | 100.0% | the decompiler's own FlowInfo (flow.cc) builds the function's p-code and block graph on every decompile; vendored flow lines executed 756 |
| pcode_lift | instructions lifted on the printed path | run + code | n/a | n/a | n/a | 100.0% | 114620 instructions in the sampled functions are lifted by the decompiler's own SLEIGH (ghidra_opt, ROMWRIGHT_SLA). Rust-lifted p-code (kuna-sleigh) feeds value-set analysis, SJA, the type solver and the prototype job, never the printed text |
| switch_recovery | dispatches in the stored import tables | run | 82.0% | n/a | n/a | 18.0% | 2060 of 2513 dispatches (83.6% of case edges) by Rust VSA; the rest by the decompiler path (a branch the decompiler-off import also stores is Rust's) |
| switch_recovery (printed) | switch tables the decompiler used when printing | run | 70.8% | n/a | n/a | 29.2% | 65 printed tables in 2000 functions; the import's stored table was the authority for 65 (100.0%): 65 agreed with what jumptable.cc recovers again at decompile time, 0 replaced it; 0 had no stored table. Of the supplied tables 46 are Rust VSA's (the rest are the import's own decompiler pass, jumptable.cc at import time); jumptable.cc still derives the normalization, guards and case values. Of the sample's 46 Rust-recovered dispatches 46 also printed as a switch |
| simplification | final p-code operations | run | 0.5% | n/a | n/a | 99.5% | 1318 Rust edits (1318 additive_inverse, 0 canonical_helpers) over 250591 operations; 365 of 2000 functions have an edit |
| type_inference (default) | printed type tokens | run | 0.0% | n/a | n/a | 100.0% | 14755 type tokens; the default import stores no persisted prototype, so every printed type is Ghidra's. The Rust type solver still runs per function as an evidence pass whose classes only steer export-c's temporary and global names |
| type_inference (persisted prototypes) | printed type tokens | run | 2.4% | n/a | n/a | 97.6% | 339 parameter types upgraded by the Rust merge (provenance `->` records) against 14342 printed type tokens in 1998 functions on 10 images; upper bound, one printed token per upgraded slot |
| prototype (default) | printed function prototypes; call sites | run | 2.1% | n/a | n/a | 97.9% | 43 of 2000 printed functions had a stored prototype; 300 of 7296 call sites name a callee with one (type-archive and SDK tables, Rust) |
| prototype (persisted prototypes) | printed function prototypes | run | 16.0% | n/a | n/a | 84.0% | 1988 of 1998 printed functions had a stored prototype and 6969 of 7103 call sites name a callee with one, all persisted by Rust. Share here is who decided the signature: a stored row whose provenance is `native-decompiler prototype recovery` alone is Ghidra's recovery stored by Rust; Rust decided the rows that also carry `inferred-types` (at least one slot changed). Source mix: {'native-decompiler prototype recovery': 1577, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 307, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 45, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()+native-prototype:inferred-types()': 8, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()': 3, 'native-decompiler prototype recovery+native-prototype:inferred-types()+native-prototype:forwarded-return': 5, 'native-import:symbol-library-prototype': 43} |
| structuring | control-flow constructs in the printed tree | run | 2.9% | n/a | n/a | 97.2% | gotos 844 -> 370 and labels 536 -> 216 after the Rust models; 461 of 2000 functions printed a Rust tree; created {'condition': 108, 'if': 227, 'leaf': 535, 'goto_block': 8, 'switch': 4}; IR `structure` cuts kept 104 of 867 |
| printing | visible text tokens | run | 90.9% | n/a | n/a | 9.1% | 624050 tokens: 56956 replayed from PrintC fragments (by kind {'function_name': 2000, 'paren': 5472, 'punctuation': 13581, 'type': 14755, 'comment': 5129, 'operator': 1935, 'variable': 12750, 'label': 648, 'case_label': 686}), 88650 emitted by the Rust block layer and 478444 by the Rust expression printer (printc/render.rs, from the exported print trees; by kind {'operator': 140459, 'variable': 151726, 'function_name': 7430, 'paren': 150792, 'type': 25828, 'punctuation': 2209}); 74378 expressions printed by Rust, 0 kept PrintC's fragment (by context.kind rust {'branch.branch': 3062, 'branch.branchind': 65, 'branch.cbranch': 9648, 'loop-init.assign': 99, 'loop-iterate.assign': 131, 'negated.cbranch': 9648, 'statement.assign': 20739, 'statement.branchind': 65, 'statement.call': 8029, 'statement.cbranch': 9648, 'statement.return': 3002, 'statement.store': 10241, 'loop-iterate.call': 1}, fragment {'branch.branch': 0, 'branch.branchind': 0, 'branch.cbranch': 0, 'loop-init.assign': 0, 'loop-iterate.assign': 0, 'negated.cbranch': 0, 'statement.assign': 0, 'statement.branchind': 0, 'statement.call': 0, 'statement.cbranch': 0, 'statement.return': 0, 'statement.store': 0, 'loop-iterate.call': 0}; why {}); 571056 spacing tokens laid out by printc/pretty.rs, a Rust port of EmitPrettyPrint (algorithm third-party, code first-party) |
| postprocess | identifiers in the export-c text | run | 20.7% | n/a | n/a | 79.3% | 65425 of 315535 identifier tokens are `temp_*`/`sp*` names emit_m2c gave decompiler locals; the rest keep the name the decompiler printed |

## Per image

| image | printed / sampled | tokens | Rust-emitted | constructs created by Rust | gotos Ghidra -> printed | edits / operations | printed differently without Rust: either (structuring alone / IR passes alone) | stored dispatches Rust-VSA |
|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | 200 / 200 | 31843 | 85.9% | 2.3% | 19 -> 3 | 15 / 10297 | 45/200 (35 / 11) | 598 of 617 |
| nds-pokeheartgold-arm9 | 200 / 200 | 28199 | 86.5% | 0.2% | 2 -> 0 | 18 / 10395 | 23/200 (12 / 12) | 384 of 408 |
| ps2-capcom-fighting-evolution | 200 / 200 | 72882 | 93.8% | 0.8% | 5 -> 1 | 122 / 26482 | 100/200 (79 / 53) | 138 of 454 |
| ps2-dungeon-game | 200 / 200 | 78351 | 92.3% | 4.1% | 100 -> 23 | 101 / 39681 | 54/200 (37 / 32) | 5 of 13 |
| psx-darkstalkers-3 | 200 / 200 | 43052 | 93.4% | 4.1% | 38 -> 4 | 167 / 17503 | 70/200 (34 / 52) | 19 of 21 |
| psv-need-for-speed-most-wanted | 200 / 200 | 97772 | 90.1% | 0.8% | 30 -> 20 | 95 / 41792 | 56/200 (40 / 26) | 551 of 601 |
| x360-black-ops-2 | 200 / 200 | 59505 | 89.4% | 2.5% | 55 -> 16 | 169 / 19365 | 82/200 (49 / 48) | 237 of 248 |
| gc-animal-crossing | 200 / 200 | 76663 | 92.1% | 2.1% | 81 -> 49 | 340 / 26758 | 72/200 (51 / 47) | 105 of 114 |
| psp-puzzle-bobble-pocket | 200 / 200 | 71644 | 90.6% | 4.5% | 255 -> 127 | 136 / 33247 | 78/200 (61 / 41) | 8 of 18 |
| psp-puzzle-bobble-pocket-symtab | 200 / 200 | 64139 | 90.0% | 4.8% | 259 -> 127 | 155 / 25071 | 84/200 (63 / 49) | 15 of 19 |

## Persisted-prototype profile

The same worker over the projects the research runs left after `infer_prototypes` (inferred-types merge on). `origin` names the project copied.

| image | origin tools | job seconds | printed | stored prototype | calls with stored prototype | parameter types upgraded by Rust | prototype sources |
|---|---|---|---|---|---|---|---|
| gba-pokeemerald | ea27c70333bb669d | 427.8 | 200 / 200 | 200 | 658 / 671 | 11 | {'native-decompiler prototype recovery': 185, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 11, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 4} |
| nds-pokeheartgold-arm9 | ea27c70333bb669d | 106.9 | 200 / 200 | 200 | 673 / 683 | 16 | {'native-decompiler prototype recovery': 181, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 3, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 14, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()+native-prototype:inferred-types()': 2} |
| ps2-capcom-fighting-evolution | ea27c70333bb669d | 532.6 | 200 / 200 | 200 | 865 / 865 | 60 | {'native-decompiler prototype recovery': 130, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 54, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 14, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()': 1, 'native-decompiler prototype recovery+native-prototype:inferred-types()+native-prototype:forwarded-return': 1} |
| ps2-dungeon-game | ea27c70333bb669d | 57.8 | 200 / 200 | 191 | 783 / 802 | 57 | {'native-decompiler prototype recovery': 126, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 52, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 12, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()+native-prototype:inferred-types()': 1} |
| psx-darkstalkers-3 | ea27c70333bb669d | 27.7 | 200 / 200 | 199 | 357 / 362 | 43 | {'native-decompiler prototype recovery': 156, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 43} |
| psv-need-for-speed-most-wanted | ea27c70333bb669d | 8388.8 | 198 / 200 | 198 | 429 / 508 | 59 | {'native-decompiler prototype recovery': 141, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 56, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 1} |
| x360-black-ops-2 | ea27c70333bb669d | 1827.1 | 200 / 200 | 200 | 870 / 878 | 28 | {'native-decompiler prototype recovery': 171, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()': 1, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 28} |
| gc-animal-crossing | ea27c70333bb669d | 54.4 | 200 / 200 | 200 | 789 / 789 | 15 | {'native-decompiler prototype recovery': 185, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 14, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 1} |
| psp-puzzle-bobble-pocket | ea27c70333bb669d | 31.4 | 200 / 200 | 200 | 816 / 816 | 22 | {'native-decompiler prototype recovery': 175, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 14, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 5, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()+native-prototype:inferred-types()': 3, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()': 1, 'native-decompiler prototype recovery+native-prototype:inferred-types()+native-prototype:forwarded-return': 2} |
| psp-puzzle-bobble-pocket-symtab | ea27c70333bb669d | 31.7 | 200 / 200 | 200 | 729 / 729 | 28 | {'native-decompiler prototype recovery': 127, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 21, 'native-import:symbol-library-prototype': 43, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 5, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()+native-prototype:inferred-types()': 2, 'native-decompiler prototype recovery+native-prototype:inferred-types()+native-prototype:forwarded-return': 2} |

## Executed code lines by stage and owner

Lines with a nonzero count in the merged profiles of the default run (imports, the default decompile pass and the persisted-prototype pass; ablation passes are not merged). Each cell is executed/executable lines of the files the stage owns. Executable counts come from two different coverage mappings (clang for C++, rustc for Rust: lines with at least one mapped region), so compare executed lines, not percentages, across languages; a Rust line is a statement-sized unit, a C++ line often is too, but neither is a weighted work measure.

| stage | rust_first_party | rust_third_party | cpp_ours | cpp_vendored |
|---|---|---|---|---|
| load | 4537/12749 | 0/0 | 3/7 | 2392/4829 |
| discovery | 7376/10296 | 0/0 | 28/32 | 0/0 |
| flow | 337/356 | 0/0 | 29/32 | 756/1005 |
| pcode_lift | 772/1261 | 6693/20801 | 20/35 | 3976/10604 |
| switch_recovery | 2277/4718 | 0/0 | 67/191 | 1437/2058 |
| simplification | 798/1000 | 0/0 | 264/306 | 30138/38032 |
| type_inference | 159/2713 | 0/0 | 0/0 | 3053/6036 |
| prototype | 456/1539 | 0/0 | 17/18 | 3002/5773 |
| structuring | 2676/3270 | 0/0 | 3/3 | 3586/4641 |
| printing | 3451/4486 | 0/0 | 856/1022 | 3893/6616 |
| postprocess | 1464/1931 | 0/0 | 0/0 | 0/0 |
| host | 6331/25514 | 0/0 | 136/161 | 3387/10087 |
| **total** | 30634/69833 | 6693/20801 | 1423/1807 | 55620/89681 |

Other crates and std linked into the Rust binaries: 4328/95075 (not an owner).

Most-executed vendored C++ files (lines executed, stage):

- `ruleaction.cc`: 6688 (simplification)
- `coreaction.cc`: 3467 (simplification)
- `subflow.cc`: 2692 (simplification)
- `double.cc`: 2316 (simplification)
- `fspec.cc`: 2287 (prototype)
- `block.cc`: 1804 (structuring)
- `heritage.cc`: 1721 (simplification)
- `rangeutil.cc`: 1717 (simplification)
- `printc.cc`: 1603 (printing)
- `blockaction.cc`: 1583 (structuring)
- `jumptable.cc`: 1374 (switch_recovery)
- `typeop.cc`: 1328 (type_inference)
- `database.cc`: 1315 (load)
- `type.cc`: 1188 (type_inference)
- `funcdata_varnode.cc`: 1135 (simplification)

Most-executed first-party Rust files:

- `crates/romwright-core/src/native/discovery.rs`: 1775 (discovery)
- `crates/romwright-worker/src/printc/structure.rs`: 1670 (structuring)
- `crates/romwright-db/src/lib.rs`: 1538 (host)
- `crates/romwright-core/src/native/vsa.rs`: 1105 (switch_recovery)
- `crates/romwright-worker/src/printc/render.rs`: 1100 (printing)
- `crates/romwright-core/src/native/switch_tables.rs`: 1086 (switch_recovery)
- `crates/romwright-worker/src/provider.rs`: 1024 (load)
- `crates/romwright-core/src/native.rs`: 976 (discovery)
- `crates/romwright-core/src/native_runtime/propagation.rs`: 920 (discovery)
- `crates/romwright-core/src/native/gba/overlays.rs`: 838 (load)
- `crates/romwright-core/src/native_runtime/propagation/graph.rs`: 785 (discovery)
- `crates/romwright-core/src/native/store.rs`: 723 (host)
- `crates/romwright-worker/src/printc/ir.rs`: 661 (printing)
- `crates/romwright-core/src/structuring.rs`: 660 (structuring)
- `crates/romwright-worker/src/printc/pretty.rs`: 656 (printing)

Executed first-party Rust files no stage rule claims (counted under `host`): `crates/romwright-db/src/lib.rs` 1538, `crates/romwright-core/src/native/store.rs` 723, `crates/romwright-worker/src/worker.rs` 654, `crates/romwright-worker/src/wire.rs` 323, `crates/romwright-worker/src/doc.rs` 314, `crates/romwright-core/src/opinion.rs` 275, `crates/romwright-core/src/lib.rs` 207, `crates/romwright-core/src/native_runtime.rs` 206, `crates/romwright-cli/src/main.rs` 203, `crates/romwright-core/src/artifact.rs` 197, `crates/romwright-core/src/session.rs` 173, `crates/romwright-worker/src/main.rs` 170, `crates/romwright-core/src/exec.rs` 150, `crates/romwright-core/src/session/snapshot.rs` 105, `crates/romwright-worker/src/printc/ownership.rs` 103

## Lines of code

Unit: code lines: non-blank, non-comment; Rust test code excluded.

| owner | code lines | executable (coverage map) | executed in this run |
|---|---|---|---|
| rust_first_party | 106346 | 69833 | 30634 |
| rust_third_party | 17854 | 20801 | 6693 |
| cpp_ours | 2047 | 1807 | 1423 |
| cpp_vendored | 137961 | 89681 | 55620 |

First-party Rust by crate (code / test): romwright-api 862/165, romwright-cli 2148/0, romwright-core 61320/24741, romwright-db 5230/2003, romwright-debug 1659/763, romwright-desktop 13942/271, romwright-diff 1702/776, romwright-facts 290/102, romwright-model 1914/60, romwright-sig 1018/468, romwright-worker 14952/2974, romwright-worker-client 1309/166

Ours C++: 634 patch-added code lines in 35 files, 1413 in native/romwright_*.hh. Vendored: counts every file of the pinned tree, including the SLEIGH compiler, the interactive console and the BFD loader, which `ghidra_opt` does not link; the coverage map's executable lines (`cpp_vendored`) are what the binary holds.

