# Ownership: Rust against the vendored Ghidra C++

Generated 2026-10-09T09:53:21+00:00 by `benchmarks/ownership.py`; definitions, stage attribution and reproduction in [docs/ownership.md](../../docs/ownership.md). Tree: `{"files": 308, "sha256": "ed16933b88bdf0ff", "git_head": "7e29f17c", "uncommitted_paths": 341}`; tools fingerprint `ea27c70333bb669d`; n = 200 functions per image, seed 20261006.

## Headline

| measure | value |
|---|---|
| functions printed (all images) | 2000 |
| printed text tokens emitted by the Rust block layer | 14.5% |
| printed text tokens replayed from PrintC's fragments (C++) | 85.5% |
| printed control-flow constructs created by the Rust structuring models | 3.2% |
| final p-code operations edited by a Rust transform | 0.5% |
| functions whose text changes with Rust structuring and IR passes off | 33.6% |
| functions changed by Rust structuring alone | 23.1% |
| functions changed by the Rust IR passes alone | 19.2% |
| executed code lines that are first-party Rust | n/a |
| executed code lines that are Rust (first-party + kuna-sleigh) | n/a |

## Stage attribution

Shares are of the stage's own unit; the rows do not add up to one number (docs/ownership.md explains why).

| stage | unit | basis | Rust (first-party) | Rust (kuna-sleigh) | C++ ours | C++ vendored | detail |
|---|---|---|---|---|---|---|---|
| load | bytes, symbols and types handed to the decompiler | code | 100.0% | n/a | n/a | n/a | provider.rs answers every query the C++ makes for bytes, symbols, types and flow facts; C++ loader lines executed: None vendored (storage of what it is given) |
| discovery | stored analysis facts (xrefs, data definitions, flow overrides) by provenance | run | 58.3% | n/a | 41.7% | n/a | sampled functions by producer: {'pattern': 584, 'call': 865, 'flow': 327, 'const': 18, 'thunk': 6, 'symbol': 200} (all Rust passes); constant-propagation facts (315926 of 757917) are computed by the console's propagation. Import time in console-owned phases: 64.8% |
| flow (import walk) | flow queries during the discovery walk | code | n/a | 100.0% | n/a | n/a | discovery.rs walks with the in-process kuna-sleigh decoder (`SleighFlow`); the console's own flow command only runs under ROMWRIGHT_FLOW_DIFFERENTIAL. The console nevertheless classifies instruction flow inside its reference propagation: native/romwright_flow.hh lines executed None of the C++ flow stage's ours |
| flow (decompile) | instructions followed into the function body and its blocks | code + coverage | n/a | n/a | n/a | 100.0% | the decompiler's own FlowInfo (flow.cc) builds the function's p-code and block graph on every decompile; vendored flow lines executed None |
| pcode_lift | instructions lifted on the printed path | run + code | n/a | n/a | n/a | 100.0% | 115758 instructions in the sampled functions are lifted by the decompiler's own SLEIGH (ghidra_opt, ROMWRIGHT_SLA). Rust-lifted p-code (kuna-sleigh) feeds value-set analysis, SJA, the type solver and the prototype job, never the printed text |
| switch_recovery | dispatches in the stored import tables | run | 69.9% | n/a | n/a | 30.1% | 1771 of 2533 dispatches (63.6% of case edges) by Rust VSA; the rest by the decompiler path (a branch the decompiler-off import also stores is Rust's) |
| switch_recovery (printed) | switch tables the decompiler used when printing | run | 57.8% | n/a | n/a | 42.2% | 64 printed tables in 2000 functions; the import's stored table was the authority for 64 (100.0%): 64 agreed with what jumptable.cc recovers again at decompile time, 0 replaced it; 0 had no stored table. Of the supplied tables 37 are Rust VSA's (the rest are the import's own decompiler pass, jumptable.cc at import time); jumptable.cc still derives the normalization, guards and case values. Of the sample's 35 Rust-recovered dispatches 35 also printed as a switch |
| simplification | final p-code operations | run | 0.5% | n/a | n/a | 99.5% | 1164 Rust edits (1164 additive_inverse, 0 canonical_helpers) over 234245 operations; 380 of 2000 functions have an edit |
| type_inference (default) | printed type tokens | run | 0.0% | n/a | n/a | 100.0% | 38381 type tokens; the default import stores no persisted prototype, so every printed type is Ghidra's. The Rust type solver still runs per function as an evidence pass whose classes only steer export-c's temporary and global names |
| type_inference (persisted prototypes) | printed type tokens | run | 0.9% | n/a | n/a | 99.2% | 339 parameter types upgraded by the Rust merge (provenance `->` records) against 39729 printed type tokens in 1998 functions on 10 images; upper bound, one printed token per upgraded slot |
| prototype (default) | printed function prototypes; call sites | run | 2.1% | n/a | n/a | 97.9% | 43 of 2000 printed functions had a stored prototype; 300 of 7118 call sites name a callee with one (type-archive and SDK tables, Rust) |
| prototype (persisted prototypes) | printed function prototypes | run | 16.0% | n/a | n/a | 84.0% | 1988 of 1998 printed functions had a stored prototype and 6969 of 7103 call sites name a callee with one, all persisted by Rust. Share here is who decided the signature: a stored row whose provenance is `native-decompiler prototype recovery` alone is Ghidra's recovery stored by Rust; Rust decided the rows that also carry `inferred-types` (at least one slot changed). Source mix: {'native-decompiler prototype recovery': 1577, 'native-decompiler prototype recovery+native-prototype:inferred-types()': 307, 'native-decompiler prototype recovery+native-prototype:forwarded-return': 45, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()+native-prototype:inferred-types()': 8, 'native-decompiler prototype recovery+native-prototype:variadic-save-area()': 3, 'native-decompiler prototype recovery+native-prototype:inferred-types()+native-prototype:forwarded-return': 5, 'native-import:symbol-library-prototype': 43} |
| structuring | control-flow constructs in the printed tree | run | 3.2% | n/a | n/a | 96.8% | gotos 832 -> 318 and labels 521 -> 176 after the Rust models; 461 of 2000 functions printed a Rust tree; created {'if': 244, 'leaf': 592, 'condition': 123, 'goto_block': 18, 'switch': 4}; IR `structure` cuts kept 42 of 789 |
| printing | visible text tokens | run | 14.5% | n/a | n/a | 85.5% | 605355 tokens: 517414 replayed from PrintC fragments (by kind {'comment': 5119, 'function_name': 9261, 'operator': 137718, 'paren': 149136, 'punctuation': 15661, 'type': 38381, 'variable': 160995, 'case_label': 605, 'label': 538}), 87941 emitted by the Rust block layer; 552493 spacing tokens laid out by printc/pretty.rs, a Rust port of EmitPrettyPrint (algorithm third-party, code first-party) |
| postprocess | identifiers in the export-c text | run | 21.4% | n/a | n/a | 78.6% | 65791 of 307057 identifier tokens are `temp_*`/`sp*` names emit_m2c gave decompiler locals; the rest keep the name the decompiler printed |

## Per image

| image | printed / sampled | tokens | Rust-emitted | constructs created by Rust | gotos Ghidra -> printed | edits / operations | printed differently without Rust: either (structuring alone / IR passes alone) | stored dispatches Rust-VSA |
|---|---|---|---|---|---|---|---|---|
| gba-pokeemerald | 200 / 200 | 30756 | 14.7% | 3.7% | 39 -> 2 | 24 / 10039 | 47/200 (40 / 15) | 528 of 617 |
| nds-pokeheartgold-arm9 | 200 / 200 | 27540 | 15.1% | 1.0% | 9 -> 0 | 37 / 9015 | 20/200 (11 / 13) | 343 of 408 |
| ps2-capcom-fighting-evolution | 200 / 200 | 70544 | 13.7% | 1.2% | 9 -> 3 | 86 / 22985 | 103/200 (80 / 53) | 126 of 468 |
| ps2-dungeon-game | 200 / 200 | 83805 | 12.7% | 4.2% | 111 -> 26 | 97 / 40917 | 55/200 (43 / 28) | 4 of 13 |
| psx-darkstalkers-3 | 200 / 200 | 43052 | 12.6% | 4.1% | 38 -> 4 | 167 / 17503 | 70/200 (34 / 52) | 19 of 21 |
| psv-need-for-speed-most-wanted | 200 / 200 | 100279 | 11.5% | 2.0% | 35 -> 19 | 71 / 35344 | 54/200 (36 / 30) | 434 of 607 |
| x360-black-ops-2 | 200 / 200 | 57724 | 15.2% | 3.8% | 45 -> 3 | 261 / 19076 | 94/200 (52 / 61) | 204 of 248 |
| gc-animal-crossing | 200 / 200 | 55703 | 16.2% | 0.8% | 30 -> 8 | 124 / 21240 | 65/200 (41 / 40) | 94 of 114 |
| psp-puzzle-bobble-pocket | 200 / 200 | 71813 | 17.3% | 4.8% | 257 -> 126 | 142 / 33055 | 79/200 (61 / 44) | 7 of 18 |
| psp-puzzle-bobble-pocket-symtab | 200 / 200 | 64139 | 18.2% | 4.8% | 259 -> 127 | 155 / 25071 | 84/200 (63 / 49) | 12 of 19 |

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

## Lines of code

Unit: code lines: non-blank, non-comment; Rust test code excluded.

| owner | code lines | executable (coverage map) | executed in this run |
|---|---|---|---|
| rust_first_party | 95639 | n/a | n/a |
| rust_third_party | 17540 | n/a | n/a |
| cpp_ours | 4250 | n/a | n/a |
| cpp_vendored | 137961 | n/a | n/a |

First-party Rust by crate (code / test): romwright-api 862/165, romwright-cli 2125/0, romwright-core 54054/21937, romwright-db 5230/2003, romwright-debug 1659/763, romwright-desktop 13942/271, romwright-diff 1702/776, romwright-facts 290/102, romwright-model 1914/60, romwright-sig 1018/468, romwright-worker 11616/2276, romwright-worker-client 1227/151

Ours C++: 808 patch-added code lines in 39 files, 3442 in native/romwright_*.hh. Vendored: includes the SLEIGH compiler and the interactive console sources, which the decompile and import paths never run.

