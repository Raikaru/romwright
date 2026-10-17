# Ownership: Rust against the vendored Ghidra C++

Generated 2026-10-09T02:54:57+00:00 by `benchmarks/ownership.py`; definitions, stage attribution and reproduction in [docs/ownership.md](../../docs/ownership.md). Tree: `{"files": 305, "sha256": "5530d1ca0211244e", "git_head": "7e29f17c", "uncommitted_paths": 324}`; tools fingerprint `f30f26e1b0e4219a`; n = 200 functions per image, seed 20261006.

## Headline

| measure | value |
|---|---|
| functions printed (all images) | 2000 |
| printed text tokens emitted by the Rust block layer | 14.4% |
| printed text tokens replayed from PrintC's fragments (C++) | 85.5% |
| printed control-flow constructs created by the Rust structuring models | 2.9% |
| final p-code operations edited by a Rust transform | 0.5% |
| functions whose text changes with Rust structuring and IR passes off | 23.7% |
| functions changed by Rust structuring alone | 8.0% |
| functions changed by the Rust IR passes alone | 19.2% |
| executed code lines that are first-party Rust | n/a |
| executed code lines that are Rust (first-party + kuna-sleigh) | n/a |

## Stage attribution

Shares are of the stage's own unit; the rows do not add up to one number (docs/ownership.md explains why).

| stage | unit | basis | Rust (first-party) | Rust (kuna-sleigh) | C++ ours | C++ vendored | detail |
|---|---|---|---|---|---|---|---|
| load | bytes, symbols and types handed to the decompiler | code | 100.0% | n/a | n/a | n/a | provider.rs answers every query the C++ makes for bytes, symbols, types and flow facts; C++ loader lines executed: None vendored (storage of what it is given) |
| discovery | stored analysis facts (xrefs, data definitions, flow overrides) by provenance | run | 58.3% | n/a | 41.7% | n/a | sampled functions by producer: {'pattern': 584, 'call': 865, 'flow': 327, 'const': 18, 'thunk': 6, 'symbol': 200} (all Rust passes); constant-propagation facts (315613 of 757606) are computed by the console's propagation. Import time in console-owned phases: 64.0% |
| flow (import walk) | flow queries during the discovery walk | code | n/a | 100.0% | n/a | n/a | discovery.rs walks with the in-process kuna-sleigh decoder (`SleighFlow`); the console's own flow command only runs under ROMWRIGHT_FLOW_DIFFERENTIAL. The console nevertheless classifies instruction flow inside its reference propagation: native/romwright_flow.hh lines executed None of the C++ flow stage's ours |
| flow (decompile) | instructions followed into the function body and its blocks | code + coverage | n/a | n/a | n/a | 100.0% | the decompiler's own FlowInfo (flow.cc) builds the function's p-code and block graph on every decompile; vendored flow lines executed None |
| pcode_lift | instructions lifted on the printed path | run + code | n/a | n/a | n/a | 100.0% | 115758 instructions in the sampled functions are lifted by the decompiler's own SLEIGH (ghidra_opt, ROMWRIGHT_SLA). Rust-lifted p-code (kuna-sleigh) feeds value-set analysis, SJA, the type solver and the prototype job, never the printed text |
| switch_recovery | dispatches in the stored import tables | run | 69.9% | n/a | n/a | 30.1% | 1771 of 2533 dispatches (63.6% of case edges) by Rust VSA; the rest by the decompiler path (a branch the decompiler-off import also stores is Rust's) |
| switch_recovery (printed) | switch tables the decompiler used when printing | run | 57.8% | n/a | n/a | 42.2% | 64 printed tables in 2000 functions; the import's stored table was the authority for 64 (100.0%): 64 agreed with what jumptable.cc recovers again at decompile time, 0 replaced it; 0 had no stored table. Of the supplied tables 37 are Rust VSA's (the rest are the import's own decompiler pass, jumptable.cc at import time); jumptable.cc still derives the normalization, guards and case values. Of the sample's 35 Rust-recovered dispatches 35 also printed as a switch |
| simplification | final p-code operations | run | 0.5% | n/a | n/a | 99.5% | 1164 Rust edits (1164 additive_inverse, 0 canonical_helpers) over 236148 operations; 380 of 2000 functions have an edit |
| type_inference (default) | printed type tokens | run | 0.0% | n/a | n/a | 100.0% | 38296 type tokens; the default import stores no persisted prototype, so every printed type is Ghidra's. The Rust type solver still runs per function as an evidence pass whose classes only steer export-c's temporary and global names |
| type_inference (persisted prototypes) | printed type tokens | run | 0.9% | n/a | n/a | 99.1% | 282 parameter types upgraded by the Rust merge (provenance `->` records) against 32119 printed type tokens in 1599 functions on 8 images; upper bound, one printed token per upgraded slot |
| prototype (default) | printed function prototypes; call sites | run | 2.1% | n/a | n/a | 97.9% | 43 of 2000 printed functions had a stored prototype; 300 of 7118 call sites name a callee with one (type-archive and SDK tables, Rust) |
| prototype (persisted prototypes) | printed function prototypes | run | 16.5% | n/a | n/a | 83.5% | 1597 of 1599 printed functions had a stored prototype and 5256 of 5328 call sites name a callee with one, all persisted by Rust. Share here is who decided the signature: a stored row whose provenance is `native-decompiler prototype recovery` alone is Ghidra's recovery stored by Rust; Rust decided the rows that also carry `inferred-types` (at least one slot changed). Source mix: {'native-decompiler prototype recovery': 1333, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 264} |
| structuring | control-flow constructs in the printed tree | run | 2.9% | n/a | n/a | 97.2% | gotos 832 -> 318 and labels 521 -> 176 after the Rust models; 160 of 2000 functions printed a Rust tree; created {'if': 244, 'leaf': 592, 'condition': 15, 'goto_block': 18, 'switch': 4}; IR `structure` cuts kept 42 of 789 |
| printing | visible text tokens | run | 14.4% | n/a | n/a | 85.5% | 612286 tokens: 523795 replayed from PrintC fragments (by kind {'comment': 5161, 'function_name': 9261, 'operator': 140332, 'paren': 150038, 'punctuation': 17154, 'type': 38296, 'variable': 162410, 'case_label': 605, 'label': 538}), 88491 emitted by the Rust block layer; 558482 spacing tokens laid out by printc/pretty.rs, a Rust port of EmitPrettyPrint (algorithm third-party, code first-party) |
| postprocess | identifiers in the export-c text | run | 21.6% | n/a | n/a | 78.4% | 67359 of 312050 identifier tokens are `temp_*`/`sp*` names emit_m2c gave decompiler locals; the rest keep the name the decompiler printed |

## Per image

| image | printed / sampled | tokens | Rust-emitted | constructs created by Rust | gotos Ghidra -> printed | edits / operations | printed differently without Rust: either (structuring alone / IR passes alone) | stored dispatches Rust-VSA |
|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | 200 / 200 | 30741 | 14.7% | 3.4% | 39 -> 2 | 24 / 10039 | 27/200 (16 / 15) | 528 of 617 |
| nds-pokeheartgold-arm9 | 200 / 200 | 27524 | 15.1% | 1.0% | 9 -> 0 | 37 / 9015 | 15/200 (3 / 13) | 343 of 408 |
| ps2-capcom-fighting-evolution | 200 / 200 | 70471 | 13.6% | 0.3% | 9 -> 3 | 86 / 22775 | 56/200 (4 / 53) | 126 of 468 |
| ps2-dungeon-game | 200 / 200 | 90979 | 12.5% | 4.2% | 111 -> 26 | 97 / 43030 | 40/200 (25 / 28) | 4 of 13 |
| psx-darkstalkers-3 | 200 / 200 | 43048 | 12.6% | 3.9% | 38 -> 4 | 167 / 17503 | 58/200 (12 / 52) | 19 of 21 |
| psv-need-for-speed-most-wanted | 200 / 200 | 100268 | 11.5% | 1.1% | 35 -> 19 | 71 / 35344 | 35/200 (8 / 30) | 434 of 607 |
| x360-black-ops-2 | 200 / 200 | 57722 | 15.3% | 3.2% | 45 -> 3 | 261 / 19076 | 73/200 (17 / 61) | 204 of 248 |
| gc-animal-crossing | 200 / 200 | 55633 | 16.1% | 0.7% | 30 -> 8 | 124 / 21240 | 43/200 (8 / 40) | 94 of 114 |
| psp-puzzle-bobble-pocket | 200 / 200 | 71783 | 17.3% | 4.6% | 257 -> 126 | 142 / 33055 | 61/200 (33 / 44) | 7 of 18 |
| psp-puzzle-bobble-pocket-symtab | 200 / 200 | 64117 | 18.2% | 4.6% | 259 -> 127 | 155 / 25071 | 66/200 (34 / 49) | 12 of 19 |

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
| rust_first_party | 94900 | n/a | n/a |
| rust_third_party | 17540 | n/a | n/a |
| cpp_ours | 4154 | n/a | n/a |
| cpp_vendored | 137961 | n/a | n/a |

First-party Rust by crate (code / test): romwright-api 862/165, romwright-cli 2121/0, romwright-core 53474/21867, romwright-db 5230/2003, romwright-debug 1659/763, romwright-desktop 13942/271, romwright-diff 1702/776, romwright-facts 290/102, romwright-model 1914/60, romwright-sig 1018/468, romwright-worker 11514/2203, romwright-worker-client 1174/151

Ours C++: 712 patch-added code lines in 39 files, 3442 in native/romwright_*.hh. Vendored: includes the SLEIGH compiler and the interactive console sources, which the decompile and import paths never run.

