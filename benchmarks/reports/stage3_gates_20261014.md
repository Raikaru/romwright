# Stage 3 (merge, explicit/implied, names, for-loop moves) gates, 20261014

`off` = `ROMWRIGHT_NATIVE_MERGE=1` (the decompiler's merge actions, `ActionMarkExplicit`/`ActionMarkImplied`, `ActionNameVars` and the for-loop moves in `romwright_structure.hh`: the previous default byte for byte). `def` = the default build (the worker decides). exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.

How the arms ran: one release build (`romwright-cli`, `romwright-worker`, the pinned `ghidra_opt`), each arm a wrapper binary that sets its switches and `ROMWRIGHT_ARM` (the m22-002 harness drops `ROMWRIGHT_*` from the environment), `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`. An m22-003 arm restores the lane's prepared work directory and repo from a pristine snapshot taken after its prepare stage (same path) and imports the retail image afresh; an m22-002 arm prepares its own work directory and repo copy.

| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled | gained exact | gained compiled |
|---|---|---|---|---|---|---|---|---|---|---|---|
| m22-002 MWCC seed 20261010 | off | 55 | 193 | 76.968 | | | | | | | |
| m22-002 MWCC seed 20261010 | def | 55 | 193 | 76.968 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-002 MWCC seed 20261011 | off | 57 | 194 | 78.316 | | | | | | | |
| m22-002 MWCC seed 20261011 | def | 57 | 194 | 78.316 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-002 ee-gcc | off | 106 | 197 | 86.403 | | | | | | | |
| m22-002 ee-gcc | def | 106 | 197 | 86.403 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 dds | off | 61 | 200 | 77.224 | | | | | | | |
| m22-003 dds | def | 61 | 200 | 77.224 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 rc | off | 26 | 200 | 68.158 | | | | | | | |
| m22-003 rc | def | 26 | 200 | 68.158 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 p4 | off | 60 | 193 | 79.4 | | | | | | | |
| m22-003 p4 | def | 60 | 193 | 79.4 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 gh (harness clone) | off | 78 | 199 | 82.119 | | | | | | | |
| m22-003 gh (harness clone) | def | 78 | 199 | 82.119 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 ff | off | 21 | 195 | 61.753 | | | | | | | |
| m22-003 ff | def | 21 | 195 | 61.753 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 dc | off | 38 | 186 | 69.844 | | | | | | | |
| m22-003 dc | def | 38 | 186 | 69.844 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 dk | off | 29 | 189 | 75.561 | | | | | | | |
| m22-003 dk | def | 29 | 189 | 75.561 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |

## Compile-failure classes per m22-003 lane, off against def (functions that did not compile, by the compiler's first diagnostic)

| lane | arm | classes |
|---|---|---|
| m22-003 dds | off | {} |
| m22-003 dds | def | {} |
| m22-003 rc | off | {} |
| m22-003 rc | def | {} |
| m22-003 p4 | off | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 p4 | def | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 gh (harness clone) | off | {} |
| m22-003 gh (harness clone) | def | {} |
| m22-003 ff | off | {"type mismatch (assignment, operand, return, cast)": 5} |
| m22-003 ff | def | {"type mismatch (assignment, operand, return, cast)": 5} |
| m22-003 dc | off | {"call does not match prototype": 2, "type mismatch (assignment, operand, return, cast)": 10, "undeclared identifier": 1, "unit post-processing rejected the candidate object": 1} |
| m22-003 dc | def | {"call does not match prototype": 2, "type mismatch (assignment, operand, return, cast)": 10, "undeclared identifier": 1, "unit post-processing rejected the candidate object": 1} |
| m22-003 dk | off | {"illegal or unknown type name": 1, "member access on a type the context lacks": 2, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |
| m22-003 dk | def | {"illegal or unknown type name": 1, "member access on a type the context lacks": 2, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |

All lanes together (m22-003, the first diagnostic of every function that did not compile):

| class | off | def |
|---|---|---|
| call does not match prototype | 3 | 3 |
| illegal or unknown type name | 1 | 1 |
| member access on a type the context lacks | 2 | 2 |
| type mismatch (assignment, operand, return, cast) | 26 | 26 |
| undeclared identifier | 4 | 4 |
| unit post-processing rejected the candidate object | 1 | 1 |
| **functions that do not compile** | 37 | 37 |

## Functions that lost an exact match or a compile (default build against `off`)

none

## merge_diff_f1

```json
{
 "benchmark": "merge_diff",
 "date": "2026-10-14",
 "ghidra_opt": "/home/raikaru/runs/Stage3/bin-f1/ghidra_opt",
 "decompiled": 1600,
 "identical": 1600,
 "images": [
  {
   "image": "gba-pokeemerald",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 201,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 4170,
    "speculative": 193,
    "explicit": 5078,
    "implied": 3342,
    "new_ops": 47,
    "entries": 13335
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 201,
   "verify_examples": []
  },
  {
   "image": "gc-animal-crossing",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 206,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 11751,
    "speculative": 601,
    "explicit": 13257,
    "implied": 7999,
    "new_ops": 394,
    "entries": 36456
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 206,
   "verify_examples": []
  },
  {
   "image": "nds-pokeheartgold-arm9",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 200,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 3282,
    "speculative": 150,
    "explicit": 4279,
    "implied": 2974,
    "new_ops": 87,
    "entries": 11558
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 200,
   "verify_examples": []
  },
  {
   "image": "ps2-capcom-fighting-evolution",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 202,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 2895,
    "speculative": 265,
    "explicit": 3962,
    "implied": 5164,
    "new_ops": 120,
    "entries": 13133
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 202,
   "verify_examples": []
  },
  {
   "image": "ps2-dungeon-game",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 207,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 41576,
    "speculative": 1120,
    "explicit": 43556,
    "implied": 9785,
    "new_ops": 463,
    "entries": 98950
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 207,
   "verify_examples": []
  },
  {
   "image": "psv-need-for-speed-most-wanted",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 220,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 29539,
    "speculative": 2281,
    "explicit": 33738,
    "implied": 12018,
    "new_ops": 758,
    "entries": 82277
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 220,
   "verify_examples": []
  },
  {
   "image": "psx-darkstalkers-3",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 204,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 8644,
    "speculative": 458,
    "explicit": 9794,
    "implied": 6288,
    "new_ops": 205,
    "entries": 26807
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 204,
   "verify_examples": []
  },
  {
   "image": "x360-black-ops-2",
   "sampled": 200,
   "decompiled": 200,
   "identical": 200,
   "different": 0,
   "worker_merge_functions": 207,
   "declined_functions": 0,
   "decline_reasons": {},
   "worker_did": {
    "merges": 7910,
    "speculative": 492,
    "explicit": 9881,
    "implied": 6871,
    "new_ops": 418,
    "entries": 28253
   },
   "one_arm_failed": [],
   "differences": [],
   "verify_mismatches": 0,
   "verify_verified": 207,
   "verify_examples": []
  }
 ]
}
```

## printer_diff_f1

```json
{
 "benchmark": "printer_diff",
 "date": "2026-10-14",
 "commit": "",
 "ghidra_opt": "/home/raikaru/runs/Stage3/bin-f1/ghidra_opt",
 "decompiled": 1800,
 "identical": 1800,
 "identical_rate": 1.0,
 "images": [
  {
   "image": "gba-pokeemerald",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/gba-pokeemerald-a9dec84dfe7f-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "gc-animal-crossing",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/gc-animal-crossing-e3166b15b810-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "nds-pokeheartgold-arm9",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/nds-pokeheartgold-arm9-65f02a56842b-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "ps2-capcom-fighting-evolution",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/ps2-capcom-fighting-evolution-84b53104d505-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "ps2-dungeon-game",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/ps2-dungeon-game-25faee2f9848-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "psv-need-for-speed-most-wanted",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/psv-need-for-speed-most-wanted-d15fc4d950ff-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "psx-darkstalkers-3",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/psx-darkstalkers-3-f933f98f1c35-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "x360-black-ops-2",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/runs/Stage3/cache/projects/x360-black-ops-2-bbf68c880351-4f53cda18c2b-23c94218619e781c",
   "differences": []
  },
  {
   "image": "x86-libc",
   "sampled": 200,
   "decompiled": 200,
   "decompile_errors": 0,
   "identical": 200,
   "identical_rate": 1.0,
   "categories": {},
   "examples": {},
   "project": "/home/raikaru/.cache/romwright/printer-diff/libc-01cccbe278d898ad",
   "differences": []
  }
 ]
}
```

## wave_text_diff_f1

```json
{
 "benchmark": "wave_text_diff",
 "date": "2026-10-14",
 "bin": "/home/raikaru/runs/Stage3/bin-f1",
 "a_env": {},
 "b_env": {
  "ROMWRIGHT_NATIVE_MERGE": "1"
 },
 "totals": {
  "compared": 7409,
  "identical": 7409,
  "different": 0,
  "missing": 91,
  "missing_a": 91,
  "missing_b": 91
 },
 "images": {
  "ps2-fatal-frame": {
   "compared": 942,
   "identical": 942,
   "different": 0,
   "missing": 0,
   "missing_a": 0,
   "missing_b": 0,
   "differences": []
  },
  "ps2-ratchet-clank-pal": {
   "compared": 858,
   "identical": 858,
   "different": 0,
   "missing": 1,
   "missing_a": 1,
   "missing_b": 1,
   "differences": []
  },
  "ps2-god-hand": {
   "compared": 980,
   "identical": 980,
   "different": 0,
   "missing": 0,
   "missing_a": 0,
   "missing_b": 0,
   "differences": []
  },
  "ps2-digital-devil-saga": {
   "compared": 977,
   "identical": 977,
   "different": 0,
   "missing": 0,
   "missing_a": 0,
   "missing_b": 0,
   "differences": []
  },
  "ps2-dark-chronicle": {
   "compared": 969,
   "identical": 969,
   "different": 0,
   "missing": 0,
   "missing_a": 0,
   "missing_b": 0,
   "differences": []
  },
  "ps2-ratchet-clank": {
   "compared": 860,
   "identical": 860,
   "different": 0,
   "missing": 1,
   "missing_a": 1,
   "missing_b": 1,
   "differences": []
  },
  "ps2-persona-4": {
   "compared": 935,
   "identical": 935,
   "different": 0,
   "missing": 40,
   "missing_a": 40,
   "missing_b": 40,
   "differences": []
  },
  "ps2-dark-cloud": {
   "compared": 888,
   "identical": 888,
   "different": 0,
   "missing": 49,
   "missing_a": 49,
   "missing_b": 49,
   "differences": []
  }
 }
}
```

## merge_verify_f1

```json
{
 "benchmark": "merge_verify",
 "date": "2026-10-14",
 "bin": "/home/raikaru/runs/Stage3/bin-f1",
 "totals": {
  "decided": 7619,
  "verified": 7619,
  "mismatch": 0,
  "declined": 0
 },
 "images": {
  "ps2-fatal-frame": {
   "decided": 988,
   "verified": 988,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [],
   "examples": []
  },
  "ps2-ratchet-clank-pal": {
   "decided": 893,
   "verified": 893,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [],
   "examples": []
  },
  "ps2-god-hand": {
   "decided": 1016,
   "verified": 1016,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [],
   "examples": []
  },
  "ps2-digital-devil-saga": {
   "decided": 991,
   "verified": 991,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [],
   "examples": []
  },
  "ps2-dark-chronicle": {
   "decided": 981,
   "verified": 981,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [],
   "examples": []
  },
  "ps2-ratchet-clank": {
   "decided": 902,
   "verified": 902,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [],
   "examples": []
  },
  "ps2-persona-4": {
   "decided": 951,
   "verified": 951,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [
    "error: decompiler timed out after 60s\n"
   ],
   "examples": []
  },
  "ps2-dark-cloud": {
   "decided": 897,
   "verified": 897,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {},
   "chunk_failures": [],
   "examples": []
  }
 }
}
```

## merge_port_measure_f1

```json
{
 "benchmark": "merge_port_measure",
 "date": "2026-10-14",
 "ghidra_opt": "/home/raikaru/runs/Stage3/bin-f1/ghidra_opt",
 "totals": {
  "functions": 1600,
  "worker": 1600,
  "decompiler": 0,
  "merges": 109767,
  "speculative": 5560,
  "explicit": 123545,
  "implied": 54441,
  "new_ops": 2492,
  "entries": 310769,
  "named": 9034
 },
 "images": [
  {
   "image": "gba-pokeemerald",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 201,
   "declined": {},
   "worker_did": {
    "merges": 4170,
    "speculative": 193,
    "explicit": 5078,
    "implied": 3342,
    "new_ops": 47,
    "entries": 13335
   },
   "variables_named_by_worker": 595,
   "worker_decide_microseconds": 24476,
   "decompile_wall_seconds": 8.9,
   "decide_share_of_wall": 0.0027
  },
  {
   "image": "gc-animal-crossing",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 206,
   "declined": {},
   "worker_did": {
    "merges": 11751,
    "speculative": 601,
    "explicit": 13257,
    "implied": 7999,
    "new_ops": 394,
    "entries": 36456
   },
   "variables_named_by_worker": 1004,
   "worker_decide_microseconds": 64019,
   "decompile_wall_seconds": 4.8,
   "decide_share_of_wall": 0.0134
  },
  {
   "image": "nds-pokeheartgold-arm9",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 200,
   "declined": {},
   "worker_did": {
    "merges": 3282,
    "speculative": 150,
    "explicit": 4279,
    "implied": 2974,
    "new_ops": 87,
    "entries": 11558
   },
   "variables_named_by_worker": 784,
   "worker_decide_microseconds": 22683,
   "decompile_wall_seconds": 7.1,
   "decide_share_of_wall": 0.0032
  },
  {
   "image": "ps2-capcom-fighting-evolution",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 202,
   "declined": {},
   "worker_did": {
    "merges": 2895,
    "speculative": 265,
    "explicit": 3962,
    "implied": 5164,
    "new_ops": 120,
    "entries": 13133
   },
   "variables_named_by_worker": 852,
   "worker_decide_microseconds": 23400,
   "decompile_wall_seconds": 4.2,
   "decide_share_of_wall": 0.0056
  },
  {
   "image": "ps2-dungeon-game",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 207,
   "declined": {},
   "worker_did": {
    "merges": 41576,
    "speculative": 1120,
    "explicit": 43556,
    "implied": 9785,
    "new_ops": 463,
    "entries": 98950
   },
   "variables_named_by_worker": 1586,
   "worker_decide_microseconds": 175071,
   "decompile_wall_seconds": 9.5,
   "decide_share_of_wall": 0.0185
  },
  {
   "image": "psv-need-for-speed-most-wanted",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 220,
   "declined": {},
   "worker_did": {
    "merges": 29539,
    "speculative": 2281,
    "explicit": 33738,
    "implied": 12018,
    "new_ops": 758,
    "entries": 82277
   },
   "variables_named_by_worker": 2170,
   "worker_decide_microseconds": 157692,
   "decompile_wall_seconds": 17.4,
   "decide_share_of_wall": 0.009
  },
  {
   "image": "psx-darkstalkers-3",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 204,
   "declined": {},
   "worker_did": {
    "merges": 8644,
    "speculative": 458,
    "explicit": 9794,
    "implied": 6288,
    "new_ops": 205,
    "entries": 26807
   },
   "variables_named_by_worker": 669,
   "worker_decide_microseconds": 42705,
   "decompile_wall_seconds": 2.8,
   "decide_share_of_wall": 0.0151
  },
  {
   "image": "x360-black-ops-2",
   "functions_logged": 200,
   "merge_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "decided_by_worker": 207,
   "declined": {},
   "worker_did": {
    "merges": 7910,
    "speculative": 492,
    "explicit": 9881,
    "implied": 6871,
    "new_ops": 418,
    "entries": 28253
   },
   "variables_named_by_worker": 1374,
   "worker_decide_microseconds": 52044,
   "decompile_wall_seconds": 15.3,
   "decide_share_of_wall": 0.0034
  }
 ]
}
```

## variant_smoke_stage3_20261014

```json
{
 "lane": "dds",
 "build": "bin-f1",
 "functions": [
  "btlCmdRememberUpperQueuedQuery",
  "btlHasIdleLinkedSlotKindTwo",
  "btlHasOtherGroup400DifferentUnitMode",
  "btlReleaseModelEntry",
  "btlUpdateActorModelColorAndLinks",
  "dds3AdminActivateRequestedMode",
  "effCreateStripNode",
  "effPcpGroupSetInitEntry",
  "effThunderReleaseSparkWork",
  "evtAdvanceSolarShortLayerTimer",
  "evtCommandSetMagatuhiSourcePoints",
  "evtPrintDeveloperConsoleMessage",
  "fldDestroySceneTasksAndBuffers",
  "fldGetCurrentSceneSelectionId",
  "fldSetSceneObjectAndGroupStates",
  "func_00129900",
  "func_001F9D48",
  "func_00243BF0",
  "func_00253778",
  "func_002649B0",
  "itfReleasePoolNode",
  "mnuShutdownContext",
  "ptyComputeMaxMp",
  "ptyMarkPresetSkillPool",
  "scrPushInteger",
  "sdfAppendFormattedDebugLogPair",
  "sdfBuildPrimaryAlphaAdditiveDmaPacket",
  "sdfGridReleaseAllCells",
  "sdfInitSecondaryAlphaSubtractiveRegisters",
  "sndAddSourceReferences"
 ],
 "variants": {
  "default": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 93.066,
   "spec": "default"
  },
  "adjacent-off": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 93.066,
   "spec": "adjacent=off"
  },
  "datatype-off": {
   "functions": 30,
   "exact": 1,
   "compiled": 30,
   "mean_percent": 93.223,
   "spec": "datatype=off"
  },
  "copy-off": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 93.066,
   "spec": "copy=off"
  },
  "adjoff-typeoff": {
   "functions": 30,
   "exact": 1,
   "compiled": 30,
   "mean_percent": 93.018,
   "spec": "adjacent=off,datatype=off"
  },
  "dominant-off": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 93.066,
   "spec": "dominant=off"
  },
  "hideshadow-off": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 93.066,
   "spec": "hideshadow=off"
  },
  "maxref1": {
   "functions": 30,
   "exact": 1,
   "compiled": 30,
   "mean_percent": 93.364,
   "spec": "maxref=1"
  },
  "maxref4": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 93.075,
   "spec": "maxref=4"
  },
  "maxdup1": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 92.992,
   "spec": "maxdup=1"
  },
  "maxdup4": {
   "functions": 30,
   "exact": 0,
   "compiled": 30,
   "mean_percent": 92.694,
   "spec": "maxdup=4"
  },
  "all-spec-off": {
   "functions": 30,
   "exact": 1,
   "compiled": 30,
   "mean_percent": 93.018,
   "spec": "adjacent=off,datatype=off,copy=off"
  }
 },
 "changed": {
  "dds3AdminActivateRequestedMode": {
   "address": "00102ae0",
   "by_variant": {
    "default": {
     "percent": 92.074,
     "exact": false,
     "compiled": true
    },
    "adjacent-off": {
     "percent": 92.074,
     "exact": false,
     "compiled": true
    },
    "datatype-off": {
     "percent": 92.34,
     "exact": false,
     "compiled": true
    },
    "copy-off": {
     "percent": 92.074,
     "exact": false,
     "compiled": true
    },
    "adjoff-typeoff": {
     "percent": 92.34,
     "exact": false,
     "compiled": true
    },
    "dominant-off": {
     "percent": 92.074,
     "exact": false,
     "compiled": true
    },
    "hideshadow-off": {
     "percent": 92.074,
     "exact": false,
     "compiled": true
    },
    "maxref1": {
     "percent": 89.83,
     "exact": false,
     "compiled": true
    },
    "maxref4": {
     "percent": 92.34,
     "exact": false,
     "compiled": true
    },
    "maxdup1": {
     "percent": 89.83,
     "exact": false,
     "compiled": true
    },
    "maxdup4": {
     "percent": 92.074,
     "exact": false,
     "compiled": true
    },
    "all-spec-off": {
     "percent": 92.34,
     "exact": false,
     "compiled": true
    }
   }
  },
  "ptyComputeMaxMp": {
   "address": "00118408",
   "by_variant": {
    "default": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "adjacent-off": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "datatype-off": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "copy-off": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "adjoff-typeoff": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "dominant-off": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "hideshadow-off": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "maxref1": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "maxref4": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "maxdup1": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    },
    "maxdup4": {
     "percent": 86.41,
     "exact": false,
     "compiled": true
    },
    "all-spec-off": {
     "percent": 90.769,
     "exact": false,
     "compiled": true
    }
   }
  },
  "effPcpGroupSetInitEntry": {
   "address": "00181708",
   "by_variant": {
    "default": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },
    "adjacent-off": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },
    "datatype-off": {
     "percent": 98.01,
     "exact": false,
     "compiled": true
    },
    "copy-off": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },
    "adjoff-typeoff": {
     "percent": 98.01,
     "exact": false,
     "compiled": true
    },
    "dominant-off": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },
    "hideshadow-off": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },
    "maxref1": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },
    "maxref4": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },
    "maxdup1": {
     "percent": 98.538,
     "exact": false,
     "compiled": true
    },

```

## variant_quality_stage3_20261014

```json
{
 "build": "bin-f1",
 "variants": [
  "default",
  "datatype-off",
  "adjoff-typeoff",
  "maxref1",
  "maxref4",
  "maxdup1"
 ],
 "lanes": {
  "ff": {
   "non_compiling_functions": {
    "sceVu0ViewClipMatrix": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "incompatible types in assignment"
    },
    "GetSmokePartAddr": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "incompatible types in assignment"
    },
    "printLMatC": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "incompatible types in assignment"
    },
    "SgSortGroupP": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "invalid operands to binary &"
    },
    "PSAchk3": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "invalid operands to binary |"
    }
   },
   "compiled_by_variant": {
    "default": 0,
    "datatype-off": 0,
    "adjoff-typeoff": 0,
    "maxref1": 0,
    "maxref4": 0,
    "maxdup1": 0
   }
  },
  "dk": {
   "non_compiling_functions": {
    "_LOAD_LIGHT__FP12RS_STACKDATAi": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "cannot convert"
    },
    "EdTalkModeInit__FP12CNPCharacteri": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "illegal operand"
    },
    "CheckBox2__9CMapPartsFP7CBoxVu0": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "cannot convert"
    },
    "FishingLoad__FP14CDataAlloc2_1_i": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "cannot convert"
    },
    "setShotVector__FPffff": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "cannot convert"
    },
    "Draw__15CItemBombEffectFP7CCamera": {
     "class": "undeclared identifier",
     "message": "undefined identifier 'int7'"
    },
    "Draw__13CWeaponEffectFv": {
     "class": "undeclared identifier",
     "message": "undefined identifier 'int7'"
    },
    "_CHK_USER_INNER_PRODUCT__FP12RS_STACKDATAi": {
     "class": "type mismatch (assignment, operand, return, cast)",
     "message": "cannot convert"
    },
    "MonsterNamePosSet__Fii": {
     "class": "illegal or unknown type name",
     "message": "illegal type"
    },
    "__sinit_mglib.cpp": {
     "class": "member access on a type the context lacks",
     "message": "illegal use of 'void'"
    },
    "__sinit_editloop3.cpp": {
     "class": "member access on a type the context lacks",
     "message": "illegal use of 'void'"
    }
   },
   "compiled_by_variant": {
    "default": 0,
    "datatype-off": 0,
    "adjoff-typeoff": 0,
    "maxref1": 0,
    "maxref4": 0,
    "maxdup1": 0
   }
  }
 },
 "conclusion": "no merge variant makes any of the 16 non-compiling functions compile; the failures are type mismatches / undeclared type names (type inference, stage 4)"
}
```

## ps2_decompile_success

```json
{
 "off": {
  "ps2-fatal-frame": {
   "sampled": 942,
   "decompiled": 942
  },
  "ps2-ratchet-clank-pal": {
   "sampled": 859,
   "decompiled": 858
  },
  "ps2-god-hand": {
   "sampled": 980,
   "decompiled": 980
  },
  "ps2-digital-devil-saga": {
   "sampled": 977,
   "decompiled": 977
  },
  "ps2-dark-chronicle": {
   "sampled": 969,
   "decompiled": 969
  },
  "ps2-ratchet-clank": {
   "sampled": 861,
   "decompiled": 860
  },
  "ps2-persona-4": {
   "sampled": 975,
   "decompiled": 974
  },
  "ps2-dark-cloud": {
   "sampled": 937,
   "decompiled": 888
  }
 },
 "def": {
  "ps2-fatal-frame": {
   "sampled": 942,
   "decompiled": 942
  },
  "ps2-ratchet-clank-pal": {
   "sampled": 859,
   "decompiled": 858
  },
  "ps2-god-hand": {
   "sampled": 980,
   "decompiled": 980
  },
  "ps2-digital-devil-saga": {
   "sampled": 977,
   "decompiled": 977
  },
  "ps2-dark-chronicle": {
   "sampled": 969,
   "decompiled": 969
  },
  "ps2-ratchet-clank": {
   "sampled": 861,
   "decompiled": 860
  },
  "ps2-persona-4": {
   "sampled": 975,
   "decompiled": 974
  },
  "ps2-dark-cloud": {
   "sampled": 937,
   "decompiled": 888
  }
 }
}
```

## ps2_decompile_success_total

```json
{
 "off [decompiled, sampled]": [
  7448,
  7500
 ],
 "def [decompiled, sampled]": [
  7448,
  7500
 ],
 "games that differ": []
}
```

## m21-001_off

```json
{
 "status": "pass",
 "failures": [],
 "rows": {
  "gba-pokeemerald": {
   "truth": 15856,
   "found": 15520,
   "recall": 0.9761,
   "precision": 0.9972,
   "size_exact": 15421
  },
  "nds-pokeheartgold-arm9": {
   "truth": 11078,
   "found": 10801,
   "recall": 0.9735,
   "precision": 0.9984,
   "size_exact": 9888
  },
  "ps2-capcom-fighting-evolution": {
   "truth": 8794,
   "found": 8598,
   "recall": 0.9724,
   "precision": 0.9945,
   "size_exact": 8534
  },
  "ps2-dungeon-game": {
   "truth": 783,
   "found": 786,
   "recall": 0.9872,
   "precision": 0.9835,
   "size_exact": 751
  },
  "psx-darkstalkers-3": {
   "truth": 818,
   "found": 2206,
   "recall": 0.9878,
   "precision": 0.3663,
   "size_exact": 0
  },
  "psv-need-for-speed-most-wanted": {
   "truth": 26495,
   "found": 26535,
   "recall": 0.9734,
   "precision": 0.9719,
   "size_exact": 16300
  },
  "x360-black-ops-2": {
   "truth": 27730,
   "found": 27364,
   "recall": 0.9833,
   "precision": 0.9964,
   "size_exact": 0
  }
 }
}
```

## m21-001_def

```json
{
 "status": "pass",
 "failures": [],
 "rows": {
  "gba-pokeemerald": {
   "truth": 15856,
   "found": 15520,
   "recall": 0.9761,
   "precision": 0.9972,
   "size_exact": 15421
  },
  "nds-pokeheartgold-arm9": {
   "truth": 11078,
   "found": 10801,
   "recall": 0.9735,
   "precision": 0.9984,
   "size_exact": 9888
  },
  "ps2-capcom-fighting-evolution": {
   "truth": 8794,
   "found": 8598,
   "recall": 0.9724,
   "precision": 0.9945,
   "size_exact": 8534
  },
  "ps2-dungeon-game": {
   "truth": 783,
   "found": 786,
   "recall": 0.9872,
   "precision": 0.9835,
   "size_exact": 751
  },
  "psx-darkstalkers-3": {
   "truth": 818,
   "found": 2206,
   "recall": 0.9878,
   "precision": 0.3663,
   "size_exact": 0
  },
  "psv-need-for-speed-most-wanted": {
   "truth": 26495,
   "found": 26535,
   "recall": 0.9734,
   "precision": 0.9719,
   "size_exact": 16300
  },
  "x360-black-ops-2": {
   "truth": 27730,
   "found": 27364,
   "recall": 0.9833,
   "precision": 0.9964,
   "size_exact": 0
  }
 }
}
```

## printer_differential

```json
{
 "decompiled": 1800,
 "identical": 1800,
 "identical_rate": 1.0
}
```

## merge_differential

```json
{
 "decompiled": 1600,
 "identical": 1600,
 "images": {
  "gba-pokeemerald": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 201,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 201
  },
  "gc-animal-crossing": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 206,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 206
  },
  "nds-pokeheartgold-arm9": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 200,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 200
  },
  "ps2-capcom-fighting-evolution": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 202,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 202
  },
  "ps2-dungeon-game": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 207,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 207
  },
  "psv-need-for-speed-most-wanted": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 220,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 220
  },
  "psx-darkstalkers-3": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 204,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 204
  },
  "x360-black-ops-2": {
   "decompiled": 200,
   "identical": 200,
   "worker_merge_functions": 207,
   "declined_functions": 0,
   "decline_reasons": {},
   "verify_mismatches": 0,
   "verify_verified": 207
  }
 }
}
```

## merge_verify_ps2_wave

```json
{
 "totals": {
  "decided": 7619,
  "verified": 7619,
  "mismatch": 0,
  "declined": 0
 },
 "images": {
  "ps2-fatal-frame": {
   "decided": 988,
   "verified": 988,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  },
  "ps2-ratchet-clank-pal": {
   "decided": 893,
   "verified": 893,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  },
  "ps2-god-hand": {
   "decided": 1016,
   "verified": 1016,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  },
  "ps2-digital-devil-saga": {
   "decided": 991,
   "verified": 991,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  },
  "ps2-dark-chronicle": {
   "decided": 981,
   "verified": 981,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  },
  "ps2-ratchet-clank": {
   "decided": 902,
   "verified": 902,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  },
  "ps2-persona-4": {
   "decided": 951,
   "verified": 951,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  },
  "ps2-dark-cloud": {
   "decided": 897,
   "verified": 897,
   "mismatch": 0,
   "declined": 0,
   "decline_reasons": {}
  }
 }
}
```
