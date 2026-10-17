# Ownership: Rust against the vendored Ghidra C++

Generated 2026-10-09T20:02:04+00:00 by `benchmarks/ownership.py`; definitions, stage attribution and reproduction in [docs/ownership.md](../../docs/ownership.md). Tree: `{"files": 322, "sha256": "bf2e9bd8eb4c5996", "vcs": "none: a working-tree snapshot, not a checkout"}`; tools fingerprint `647485cad03ebd25`; n = 200 functions per image, seed 20261006.

## Headline

| measure | value |
|---|---|
| functions printed (all images) | 2000 |
| printed text tokens emitted by Rust (block layer and expression printer) | 90.7% |
| printed text tokens replayed from PrintC's fragments (C++) | 9.3% |
| printed text tokens emitted by the Rust block layer | 14.4% |
| printed text tokens of expressions the Rust expression printer emitted | 76.3% |
| printed control-flow constructs created by the Rust structuring models | 3.1% |
| final p-code operations edited by a Rust transform | 0.5% |
| functions whose text changes with Rust structuring and IR passes off | 32.1% |
| functions changed by Rust structuring alone | 22.3% |
| functions changed by the Rust IR passes alone | 18.3% |
| executed code lines that are first-party Rust | n/a |
| executed code lines that are Rust (first-party + kuna-sleigh) | n/a |

## Stage attribution

Shares are of the stage's own unit; the rows do not add up to one number (docs/ownership.md explains why).

| stage | unit | basis | Rust (first-party) | Rust (kuna-sleigh) | C++ ours | C++ vendored | detail |
|---|---|---|---|---|---|---|---|
| load | bytes, symbols and types handed to the decompiler | code | 100.0% | n/a | n/a | n/a | provider.rs answers every query the C++ makes for bytes, symbols, types and flow facts; C++ loader lines executed: None vendored (storage of what it is given) |
| discovery | stored analysis facts (xrefs, data definitions, flow overrides) by provenance | run | 100.0% | n/a | 0.0% | n/a | sampled functions by producer: {'const': 22, 'pattern': 569, 'flow': 337, 'call': 866, 'thunk': 6, 'symbol': 200} (all Rust passes); constant-propagation facts are computed in process (native_runtime/propagation); facts owned by the console: 0 of 688270. Import time in console-owned phases: 49.0% |
| flow (import walk) | flow queries during the discovery walk | code | n/a | 100.0% | n/a | n/a | discovery.rs walks with the in-process kuna-sleigh decoder (`SleighFlow`), and the constant propagation follows flow over the same decoder (native_runtime/propagation/graph.rs, FlowInfo); the console's own flow command only runs under ROMWRIGHT_FLOW_DIFFERENTIAL. native/romwright_flow.hh lines executed None of the C++ flow stage's ours |
| flow (decompile) | instructions followed into the function body and its blocks | code + coverage | n/a | n/a | n/a | 100.0% | the decompiler's own FlowInfo (flow.cc) builds the function's p-code and block graph on every decompile; vendored flow lines executed None |
| pcode_lift | instructions lifted on the printed path | run + code | n/a | n/a | n/a | 100.0% | 115832 instructions in the sampled functions are lifted by the decompiler's own SLEIGH (ghidra_opt, ROMWRIGHT_SLA). Rust-lifted p-code (kuna-sleigh) feeds value-set analysis, SJA, the type solver and the prototype job, never the printed text |
| switch_recovery | dispatches in the stored import tables | run | 81.4% | n/a | n/a | 18.6% | 2049 of 2517 dispatches (82.6% of case edges) by Rust VSA; the rest by the decompiler path (a branch the decompiler-off import also stores is Rust's) |
| switch_recovery (printed) | switch tables the decompiler used when printing | run | 76.6% | n/a | n/a | 23.4% | 77 printed tables in 2000 functions; the import's stored table was the authority for 77 (100.0%): 77 agreed with what jumptable.cc recovers again at decompile time, 0 replaced it; 0 had no stored table. Of the supplied tables 59 are Rust VSA's (the rest are the import's own decompiler pass, jumptable.cc at import time); jumptable.cc still derives the normalization, guards and case values. Of the sample's 59 Rust-recovered dispatches 59 also printed as a switch |
| simplification | final p-code operations | run | 0.5% | n/a | n/a | 99.5% | 1092 Rust edits (1092 additive_inverse, 0 canonical_helpers) over 233798 operations; 360 of 2000 functions have an edit |
| type_inference (default) | printed type tokens | run | 0.0% | n/a | n/a | 100.0% | 14254 type tokens; the default import stores no persisted prototype, so every printed type is Ghidra's. The Rust type solver still runs per function as an evidence pass whose classes only steer export-c's temporary and global names |
| type_inference (persisted prototypes) | printed type tokens | run | 2.4% | n/a | n/a | 97.6% | 282 parameter types upgraded by the Rust merge (provenance `->` records) against 11832 printed type tokens in 1599 functions on 8 images; upper bound, one printed token per upgraded slot |
| prototype (default) | printed function prototypes; call sites | run | 2.1% | n/a | n/a | 97.9% | 43 of 2000 printed functions had a stored prototype; 300 of 7179 call sites name a callee with one (type-archive and SDK tables, Rust) |
| prototype (persisted prototypes) | printed function prototypes | run | 16.5% | n/a | n/a | 83.5% | 1597 of 1599 printed functions had a stored prototype and 5256 of 5328 call sites name a callee with one, all persisted by Rust. Share here is who decided the signature: a stored row whose provenance is `native-decompiler prototype recovery` alone is Ghidra's recovery stored by Rust; Rust decided the rows that also carry `inferred-types` (at least one slot changed). Source mix: {'native-decompiler prototype recovery': 1333, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 264} |
| structuring | control-flow constructs in the printed tree | run | 3.1% | n/a | n/a | 96.9% | gotos 840 -> 327 and labels 524 -> 184 after the Rust models; 446 of 2000 functions printed a Rust tree; created {'if': 229, 'leaf': 580, 'condition': 103, 'goto_block': 16, 'switch': 5}; IR `structure` cuts kept 46 of 786 |
| printing | visible text tokens | run | 90.7% | n/a | n/a | 9.3% | 599899 tokens: 55728 replayed from PrintC fragments (by kind {'comment': 5187, 'function_name': 2000, 'paren': 5648, 'punctuation': 13279, 'type': 14254, 'operator': 1805, 'variable': 12254, 'case_label': 746, 'label': 555}), 86521 emitted by the Rust block layer and 457650 by the Rust expression printer (printc/render.rs, from the exported print trees; by kind {'function_name': 7328, 'operator': 134816, 'paren': 142130, 'variable': 147582, 'type': 23594, 'punctuation': 2200}); 72531 expressions printed by Rust, 0 kept PrintC's fragment (by context.kind rust {'branch.branch': 3106, 'branch.branchind': 77, 'branch.cbranch': 9357, 'loop-init.assign': 98, 'loop-iterate.assign': 138, 'negated.cbranch': 9357, 'statement.assign': 20098, 'statement.branchind': 77, 'statement.call': 8333, 'statement.cbranch': 9357, 'statement.return': 2977, 'statement.store': 9555, 'loop-iterate.call': 1}, fragment {'branch.branch': 0, 'branch.branchind': 0, 'branch.cbranch': 0, 'loop-init.assign': 0, 'loop-iterate.assign': 0, 'negated.cbranch': 0, 'statement.assign': 0, 'statement.branchind': 0, 'statement.call': 0, 'statement.cbranch': 0, 'statement.return': 0, 'statement.store': 0, 'loop-iterate.call': 0}; why {}); 546846 spacing tokens laid out by printc/pretty.rs, a Rust port of EmitPrettyPrint (algorithm third-party, code first-party) |
| postprocess | identifiers in the export-c text | run | 20.5% | n/a | n/a | 79.5% | 62475 of 304767 identifier tokens are `temp_*`/`sp*` names emit_m2c gave decompiler locals; the rest keep the name the decompiler printed |

## Per image

| image | printed / sampled | tokens | Rust-emitted | constructs created by Rust | gotos Ghidra -> printed | edits / operations | printed differently without Rust: either (structuring alone / IR passes alone) | stored dispatches Rust-VSA |
|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | 200 / 200 | 30496 | 86.0% | 3.5% | 38 -> 2 | 24 / 10104 | 46/200 (38 / 15) | 595 of 617 |
| nds-pokeheartgold-arm9 | 200 / 200 | 27540 | 85.9% | 1.0% | 9 -> 0 | 37 / 9015 | 20/200 (11 / 13) | 384 of 408 |
| ps2-capcom-fighting-evolution | 200 / 200 | 73363 | 93.8% | 0.9% | 4 -> 0 | 118 / 26685 | 94/200 (76 / 51) | 138 of 465 |
| ps2-dungeon-game | 200 / 200 | 83805 | 92.9% | 4.2% | 111 -> 26 | 97 / 40917 | 55/200 (43 / 28) | 5 of 13 |
| psx-darkstalkers-3 | 200 / 200 | 43052 | 93.4% | 4.1% | 38 -> 4 | 167 / 17503 | 70/200 (34 / 52) | 19 of 21 |
| psv-need-for-speed-most-wanted | 200 / 200 | 90528 | 89.9% | 2.6% | 39 -> 18 | 59 / 30895 | 47/200 (30 / 26) | 543 of 594 |
| x360-black-ops-2 | 200 / 200 | 59501 | 89.4% | 2.5% | 55 -> 16 | 169 / 19351 | 82/200 (49 / 48) | 237 of 248 |
| gc-animal-crossing | 200 / 200 | 55653 | 90.2% | 0.8% | 30 -> 8 | 124 / 21203 | 65/200 (41 / 40) | 105 of 114 |
| psp-puzzle-bobble-pocket | 200 / 200 | 71812 | 90.4% | 4.8% | 257 -> 126 | 142 / 33054 | 79/200 (61 / 44) | 8 of 18 |
| psp-puzzle-bobble-pocket-symtab | 200 / 200 | 64149 | 90.0% | 4.8% | 259 -> 127 | 155 / 25071 | 84/200 (63 / 49) | 15 of 19 |

## Persisted-prototype profile

The same worker over the projects the research runs left after `infer_prototypes` (inferred-types merge on). `origin` names the project copied.

| image | origin tools | job seconds | printed | stored prototype | calls with stored prototype | parameter types upgraded by Rust | prototype sources |
|---|---|---|---|---|---|---|---|
| gba-pokeemerald | cdbbf0f7d1273898 | 320.1 | 200 / 200 | 200 | 645 / 645 | 13 | {'native-decompiler prototype recovery': 188, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 12} |
| nds-pokeheartgold-arm9 | cdbbf0f7d1273898 | 96.0 | 200 / 200 | 200 | 673 / 683 | 15 | {'native-decompiler prototype recovery': 185, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 15} |
| ps2-capcom-fighting-evolution | cdbbf0f7d1273898 | 299.3 | 200 / 200 | 199 | 606 / 606 | 49 | {'native-decompiler prototype recovery+native-prototype:inferred-types()': 44, 'native-decompiler prototype recovery': 155} |
| ps2-dungeon-game | cdbbf0f7d1273898 | 27.5 | 200 / 200 | 200 | 802 / 802 | 57 | {'native-decompiler prototype recovery': 147, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 53} |
| psx-darkstalkers-3 | cdbbf0f7d1273898 | 10.0 | 200 / 200 | 200 | 362 / 362 | 34 | {'native-decompiler prototype recovery': 166, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 34} |
| psv-need-for-speed-most-wanted | 08df1a6eff7987ed | 5201.7 | 200 / 200 | 199 | 671 / 725 | 68 | {'native-decompiler prototype recovery': 138, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 61} |
| x360-black-ops-2 | 08df1a6eff7987ed | 1559.9 | 200 / 200 | 200 | 870 / 878 | 28 | {'native-decompiler prototype recovery': 172, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 28} |
| gc-animal-crossing | cdbbf0f7d1273898 | 51.5 | 199 / 200 | 199 | 627 / 627 | 18 | {'native-decompiler prototype recovery+native-prototype:inferred-types()': 17, 'native-decompiler prototype recovery': 182} |
| psp-puzzle-bobble-pocket | none usable | | | | | | |
| psp-puzzle-bobble-pocket-symtab | none usable | | | | | | |

## Lines of code

Unit: code lines: non-blank, non-comment; Rust test code excluded.

| owner | code lines | executable (coverage map) | executed in this run |
|---|---|---|---|
| rust_first_party | 104224 | n/a | n/a |
| rust_third_party | 17846 | n/a | n/a |
| cpp_ours | 4816 | n/a | n/a |
| cpp_vendored | 137961 | n/a | n/a |

First-party Rust by crate (code / test): romwright-api 862/165, romwright-cli 2125/0, romwright-core 59224/22592, romwright-db 5230/2003, romwright-debug 1659/763, romwright-desktop 13942/271, romwright-diff 1702/776, romwright-facts 290/102, romwright-model 1914/60, romwright-sig 1018/468, romwright-worker 14950/2974, romwright-worker-client 1308/166

Ours C++: 808 patch-added code lines in 39 files, 4008 in native/romwright_*.hh. Vendored: includes the SLEIGH compiler and the interactive console sources, which the decompile and import paths never run.

