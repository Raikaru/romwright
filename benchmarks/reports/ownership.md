# Ownership: Rust against the vendored Ghidra C++

Generated 2026-10-08T22:59:55+00:00 by `benchmarks/ownership.py`; definitions, stage attribution and reproduction in [docs/ownership.md](../../docs/ownership.md). Tree: `{"files": 292, "sha256": "fa7e3e2494034a33", "vcs": "none: a working-tree snapshot, not a checkout"}`; tools fingerprint `ab96daf837699f1a`; n = 200 functions per image, seed 20261006.

## Headline

| measure | value |
|---|---|
| functions printed (all images) | 1598 |
| printed text tokens emitted by the Rust block layer | 13.3% |
| printed text tokens replayed from PrintC's fragments (C++) | 86.7% |
| printed control-flow constructs created by the Rust structuring models | 2.0% |
| final p-code operations edited by a Rust transform | 0.5% |
| functions whose text changes with Rust structuring and IR passes off | 20.4% |
| functions changed by Rust structuring alone | 6.3% |
| functions changed by the Rust IR passes alone | 16.8% |
| executed code lines that are first-party Rust | 27.4% |
| executed code lines that are Rust (first-party + kuna-sleigh) | 33.7% |

## Stage attribution

Shares are of the stage's own unit; the rows do not add up to one number (docs/ownership.md explains why).

| stage | unit | basis | Rust (first-party) | Rust (kuna-sleigh) | C++ ours | C++ vendored | detail |
|---|---|---|---|---|---|---|---|
| load | bytes, symbols and types handed to the decompiler | code | 100.0% | n/a | n/a | n/a | provider.rs answers every query the C++ makes for bytes, symbols, types and flow facts; C++ loader lines executed: 1998 vendored (storage of what it is given) |
| discovery | stored analysis facts (xrefs, data definitions, flow overrides) by provenance | run | 57.8% | n/a | 42.2% | n/a | sampled functions by producer: {'pattern': 578, 'call': 712, 'flow': 291, 'const': 13, 'thunk': 6} (all Rust passes); constant-propagation facts (306509 of 726130) are computed by the console's propagation. Import time in console-owned phases: 49.8% |
| flow (import walk) | flow queries during the discovery walk | code | n/a | 100.0% | n/a | n/a | discovery.rs walks with the in-process kuna-sleigh decoder (`SleighFlow`); the console's own flow command only runs under ROMWRIGHT_FLOW_DIFFERENTIAL. The console nevertheless classifies instruction flow inside its reference propagation: native/romwright_flow.hh lines executed 96 of the C++ flow stage's ours |
| flow (decompile) | instructions followed into the function body and its blocks | code + coverage | n/a | n/a | n/a | 100.0% | the decompiler's own FlowInfo (flow.cc) builds the function's p-code and block graph on every decompile; vendored flow lines executed 770 |
| pcode_lift | instructions lifted on the printed path | run + code | n/a | n/a | n/a | 100.0% | 88816 instructions in the sampled functions are lifted by the decompiler's own SLEIGH (ghidra_opt, ROMWRIGHT_SLA). Rust-lifted p-code (kuna-sleigh) feeds value-set analysis, SJA, the type solver and the prototype job, never the printed text |
| switch_recovery | dispatches in the stored import tables | run | 70.9% | n/a | n/a | 29.1% | 1751 of 2470 dispatches (65.9% of case edges) by Rust VSA; the rest by the decompiler path (a branch the decompiler-off import also stores is Rust's) |
| switch_recovery (printed) | switch tables the decompiler used when printing | run | n/a | n/a | n/a | 100.0% | 73 printed tables in 1598 functions, all recovered again by jumptable.cc at decompile time; the stored import tables never reach the decompiler. Of the sample's 51 Rust-recovered dispatches 49 also printed as a switch |
| simplification | final p-code operations | run | 0.5% | n/a | n/a | 99.5% | 867 Rust edits (867 additive_inverse, 0 canonical_helpers) over 161418 operations; 266 of 1598 functions have an edit |
| type_inference (default) | printed type tokens | run | 0.0% | n/a | n/a | 100.0% | 29023 type tokens; the default import stores no persisted prototype, so every printed type is Ghidra's. The Rust type solver still runs per function as an evidence pass whose classes only steer export-c's temporary and global names |
| type_inference (persisted prototypes) | printed type tokens | run | 0.9% | n/a | n/a | 99.1% | 282 parameter types upgraded by the Rust merge (provenance `->` records) against 30561 printed type tokens in 1599 functions on 8 images; upper bound, one printed token per upgraded slot |
| prototype (default) | printed function prototypes; call sites | run | 0.0% | n/a | n/a | 100.0% | 0 of 1598 printed functions had a stored prototype; 0 of 5467 call sites name a callee with one (type-archive and SDK tables, Rust) |
| prototype (persisted prototypes) | printed function prototypes | run | 16.5% | n/a | n/a | 83.5% | 1597 of 1599 printed functions had a stored prototype and 5116 of 5188 call sites name a callee with one, all persisted by Rust. Share here is who decided the signature: a stored row whose provenance is `native-decompiler prototype recovery` alone is Ghidra's recovery stored by Rust; Rust decided the rows that also carry `inferred-types` (at least one slot changed). Source mix: {'native-decompiler prototype recovery': 1333, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 264} |
| structuring | control-flow constructs in the printed tree | run | 2.0% | n/a | n/a | 98.0% | gotos 371 -> 126 and labels 260 -> 92 after the Rust models; 100 of 1598 functions printed a Rust tree; created {'if': 116, 'leaf': 259, 'goto_block': 20, 'switch': 3, 'condition': 7}; IR `structure` cuts kept 30 of 328 |
| printing | visible text tokens | run | 13.3% | n/a | n/a | 86.7% | 452185 tokens: 392165 replayed from PrintC fragments (by kind {'comment': 6077, 'function_name': 7138, 'operator': 106576, 'paren': 114202, 'punctuation': 13678, 'type': 29023, 'variable': 114589, 'case_label': 664, 'label': 218}), 60020 emitted by the Rust block layer; 415659 spacing tokens laid out by printc/pretty.rs, a Rust port of EmitPrettyPrint (algorithm third-party, code first-party) |
| postprocess | identifiers in the export-c text | run | 19.2% | n/a | n/a | 80.8% | 44446 of 230865 identifier tokens are `temp_*`/`sp*` names emit_m2c gave decompiler locals; the rest keep the name the decompiler printed |

## Per image

| image | printed / sampled | tokens | Rust-emitted | constructs created by Rust | gotos Ghidra -> printed | edits / operations | printed differently without Rust: either (structuring alone / IR passes alone) | stored dispatches Rust-VSA |
|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | 200 / 200 | 34205 | 13.4% | 5.3% | 69 -> 14 | 21 / 10521 | 31/200 (23 / 17) | 528 of 617 |
| nds-pokeheartgold-arm9 | 200 / 200 | 27524 | 15.1% | 1.0% | 9 -> 0 | 37 / 9015 | 15/200 (3 / 13) | 343 of 408 |
| ps2-capcom-fighting-evolution | 199 / 200 | 71774 | 12.8% | 0.3% | 7 -> 2 | 114 / 25008 | 54/199 (4 / 52) | 126 of 454 |
| ps2-dungeon-game | 200 / 200 | 90777 | 12.5% | 4.1% | 111 -> 28 | 97 / 43030 | 39/200 (24 / 28) | 4 of 13 |
| psx-darkstalkers-3 | 200 / 200 | 21248 | 13.7% | 1.9% | 13 -> 2 | 61 / 5838 | 31/200 (4 / 28) | 19 of 19 |
| psv-need-for-speed-most-wanted | 200 / 200 | 95634 | 11.1% | 0.8% | 49 -> 38 | 64 / 30057 | 29/200 (9 / 24) | 433 of 597 |
| x360-black-ops-2 | 200 / 200 | 57539 | 15.2% | 2.1% | 45 -> 8 | 261 / 19076 | 73/200 (17 / 61) | 204 of 248 |
| gc-animal-crossing | 199 / 200 | 53484 | 15.7% | 1.6% | 68 -> 34 | 212 / 18873 | 54/199 (16 / 45) | 94 of 114 |

## Persisted-prototype profile

The same worker over the projects the research runs left after `infer_prototypes` (inferred-types merge on). `origin` names the project copied.

| image | origin tools | job seconds | printed | stored prototype | calls with stored prototype | parameter types upgraded by Rust | prototype sources |
|---|---|---|---|---|---|---|---|
| gba-pokeemerald | cdbbf0f7d1273898 | 320.1 | 200 / 200 | 200 | 645 / 645 | 13 | {'native-decompiler prototype recovery': 188, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 12} |
| nds-pokeheartgold-arm9 | cdbbf0f7d1273898 | 96.0 | 200 / 200 | 200 | 673 / 683 | 15 | {'native-decompiler prototype recovery': 185, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 15} |
| ps2-capcom-fighting-evolution | cdbbf0f7d1273898 | 299.3 | 200 / 200 | 199 | 606 / 606 | 49 | {'native-decompiler prototype recovery+native-prototype:inferred-types()': 44, 'native-decompiler prototype recovery': 155} |
| ps2-dungeon-game | cdbbf0f7d1273898 | 27.5 | 200 / 200 | 200 | 802 / 802 | 57 | {'native-decompiler prototype recovery': 147, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 53} |
| psx-darkstalkers-3 | cdbbf0f7d1273898 | 10.0 | 200 / 200 | 200 | 222 / 222 | 34 | {'native-decompiler prototype recovery': 166, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 34} |
| psv-need-for-speed-most-wanted | 08df1a6eff7987ed | 5201.7 | 200 / 200 | 199 | 671 / 725 | 68 | {'native-decompiler prototype recovery': 138, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 61} |
| x360-black-ops-2 | 08df1a6eff7987ed | 1559.9 | 200 / 200 | 200 | 870 / 878 | 28 | {'native-decompiler prototype recovery': 172, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 28} |
| gc-animal-crossing | cdbbf0f7d1273898 | 51.5 | 199 / 200 | 199 | 627 / 627 | 18 | {'native-decompiler prototype recovery+native-prototype:inferred-types()': 17, 'native-decompiler prototype recovery': 182} |

## Executed code lines by stage and owner

Lines with a nonzero count in the merged profiles of the default run (imports, the default decompile pass and the persisted-prototype pass; ablation passes are not merged). Each cell is executed/executable lines of the files the stage owns. Executable counts come from two different coverage mappings (clang for C++, rustc for Rust: lines with at least one mapped region), so compare executed lines, not percentages, across languages; a Rust line is a statement-sized unit, a C++ line often is too, but neither is a weighted work measure.

| stage | rust_first_party | rust_third_party | cpp_ours | cpp_vendored |
|---|---|---|---|---|
| load | 2979/10348 | 0/0 | 14/19 | 1998/3656 |
| discovery | 4179/6002 | 0/0 | 1800/2263 | 0/0 |
| flow | 225/237 | 0/0 | 96/120 | 770/1005 |
| pcode_lift | 707/1110 | 5105/20927 | 54/69 | 3544/9109 |
| switch_recovery | 2201/4632 | 0/0 | 0/0 | 1455/2060 |
| simplification | 786/1000 | 0/0 | 205/248 | 27406/34516 |
| type_inference | 159/2123 | 0/0 | 0/0 | 2752/5604 |
| prototype | 321/1120 | 0/0 | 0/0 | 3228/6127 |
| structuring | 2126/2594 | 0/0 | 0/0 | 3604/4642 |
| printing | 1662/1841 | 0/0 | 339/401 | 3865/6616 |
| postprocess | 1022/1401 | 0/0 | 0/0 | 0/0 |
| host | 5933/25007 | 0/0 | 149/288 | 2573/12119 |
| **total** | 22300/57415 | 5105/20927 | 2657/3408 | 51195/85454 |

Other crates and std linked into the Rust binaries: 4086/71022 (not an owner).

Most-executed vendored C++ files (lines executed, stage):

- `ruleaction.cc`: 6693 (simplification)
- `coreaction.cc`: 3493 (simplification)
- `subflow.cc`: 2706 (simplification)
- `fspec.cc`: 2443 (prototype)
- `double.cc`: 2237 (simplification)
- `block.cc`: 1822 (structuring)
- `heritage.cc`: 1734 (simplification)
- `blockaction.cc`: 1583 (structuring)
- `printc.cc`: 1582 (printing)
- `jumptable.cc`: 1392 (switch_recovery)
- `database.cc`: 1331 (load)
- `typeop.cc`: 1330 (type_inference)
- `type.cc`: 1223 (type_inference)
- `funcdata_varnode.cc`: 1168 (simplification)
- `merge.cc`: 995 (simplification)

Most-executed first-party Rust files:

- `crates/romwright-core/src/native/discovery.rs`: 1760 (discovery)
- `crates/romwright-db/src/lib.rs`: 1474 (host)
- `crates/romwright-worker/src/printc/structure.rs`: 1468 (structuring)
- `crates/romwright-core/src/native/vsa.rs`: 1104 (switch_recovery)
- `crates/romwright-core/src/native/switch_tables.rs`: 1011 (switch_recovery)
- `crates/romwright-worker/src/provider.rs`: 948 (load)
- `crates/romwright-core/src/native.rs`: 937 (discovery)
- `crates/romwright-core/src/structuring.rs`: 658 (structuring)
- `crates/romwright-worker/src/printc/pretty.rs`: 656 (printing)
- `crates/romwright-worker/src/worker.rs`: 627 (host)
- `crates/romwright-core/src/native_runtime.rs`: 622 (host)
- `crates/romwright-core/src/native/store.rs`: 593 (host)
- `crates/romwright-worker/src/printc/printer.rs`: 580 (printing)
- `crates/romwright-core/src/emit_m2c.rs`: 505 (postprocess)
- `crates/romwright-core/src/native_runtime/lift.rs`: 495 (pcode_lift)

Executed first-party Rust files no stage rule claims (counted under `host`): `crates/romwright-db/src/lib.rs` 1474, `crates/romwright-worker/src/worker.rs` 627, `crates/romwright-core/src/native_runtime.rs` 622, `crates/romwright-core/src/native/store.rs` 593, `crates/romwright-worker/src/wire.rs` 301, `crates/romwright-worker/src/doc.rs` 290, `crates/romwright-core/src/opinion.rs` 271, `crates/romwright-core/src/lib.rs` 231, `crates/romwright-core/src/session.rs` 218, `crates/romwright-cli/src/main.rs` 188, `crates/romwright-worker/src/main.rs` 161, `crates/romwright-core/src/exec.rs` 153, `crates/romwright-worker/src/printc/ownership.rs` 94, `crates/romwright-core/src/architecture.rs` 83, `crates/romwright-core/src/inputs.rs` 66

## Lines of code

Unit: code lines: non-blank, non-comment; Rust test code excluded.

| owner | code lines | executable (coverage map) | executed in this run |
|---|---|---|---|
| rust_first_party | 90137 | 57415 | 22300 |
| rust_third_party | 17540 | 20927 | 5105 |
| cpp_ours | 3848 | 3408 | 2657 |
| cpp_vendored | 137961 | 85454 | 51195 |

First-party Rust by crate (code / test): romwright-api 862/165, romwright-cli 2302/0, romwright-core 50128/19503, romwright-db 5221/2003, romwright-debug 1659/763, romwright-desktop 13942/271, romwright-diff 1702/776, romwright-facts 290/102, romwright-model 1894/60, romwright-sig 1018/468, romwright-worker 9951/1452, romwright-worker-client 1168/151

Ours C++: 481 patch-added code lines in 30 files, 3367 in native/romwright_*.hh. Vendored: includes the SLEIGH compiler and the interactive console sources, which the decompile and import paths never run.

