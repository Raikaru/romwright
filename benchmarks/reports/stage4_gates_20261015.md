# Stage 4 (type decisions on the C output) gates, 20261015

`off` = `ROMWRIGHT_NATIVE_TYPES=1` (every stage 4 rule off: the previous default byte for byte). `def` = the default build. exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.

How the arms ran: one release build (`romwright-cli`, `romwright-worker`, the pinned `ghidra_opt`), each arm a wrapper binary that sets its switches and `ROMWRIGHT_ARM` (the m22-002 harness drops `ROMWRIGHT_*` from the environment), `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`. An m22-003 arm restores the lane's prepared work directory and repo from a pristine snapshot taken after its prepare stage (same path) and imports the retail image afresh; an m22-002 arm prepares its own work directory and repo copy.

| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled | gained exact | gained compiled |
|---|---|---|---|---|---|---|---|---|---|---|---|
| m22-002 MWCC seed 20261010 | off | 55 | 193 | 76.968 | | | | | | | |
| m22-002 MWCC seed 20261010 | def | 55 | 195 | 77.324 | 2 | 0 | 198 | 0 | 0 | 0 | 2 |
| m22-002 MWCC seed 20261011 | off | 57 | 194 | 78.316 | | | | | | | |
| m22-002 MWCC seed 20261011 | def | 57 | 194 | 78.316 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-002 ee-gcc | off | 106 | 197 | 86.403 | | | | | | | |
| m22-002 ee-gcc | def | 106 | 197 | 86.622 | 1 | 0 | 199 | 0 | 0 | 0 | 0 |
| m22-003 dds | off | 61 | 200 | 77.224 | | | | | | | |
| m22-003 dds | def | 61 | 200 | 77.224 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 rc | off | 26 | 200 | 68.158 | | | | | | | |
| m22-003 rc | def | 26 | 200 | 68.158 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 p4 | off | 60 | 193 | 79.4 | | | | | | | |
| m22-003 p4 | def | 60 | 198 | 80.732 | 5 | 0 | 195 | 0 | 0 | 0 | 5 |
| m22-003 gh (harness clone) | off | 78 | 199 | 82.119 | | | | | | | |
| m22-003 gh (harness clone) | def | 78 | 199 | 82.119 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 ff | off | 21 | 195 | 61.753 | | | | | | | |
| m22-003 ff | def | 21 | 199 | 62.913 | 4 | 1 | 195 | 0 | 0 | 0 | 4 |
| m22-003 dc | off | 38 | 186 | 69.844 | | | | | | | |
| m22-003 dc | def | 41 | 197 | 73.653 | 11 | 0 | 189 | 0 | 0 | 3 | 11 |
| m22-003 dk | off | 29 | 189 | 75.561 | | | | | | | |
| m22-003 dk | def | 29 | 197 | 78.277 | 8 | 0 | 192 | 0 | 0 | 0 | 8 |

## Compile-failure classes per m22-003 lane, off against def (functions that did not compile, by the compiler's first diagnostic)

| lane | arm | classes |
|---|---|---|
| m22-003 dds | off | {} |
| m22-003 dds | def | {} |
| m22-003 rc | off | {} |
| m22-003 rc | def | {} |
| m22-003 p4 | off | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 5, "undeclared identifier": 1} |
| m22-003 p4 | def | {"type mismatch (assignment, operand, return, cast)": 1, "undeclared identifier": 1} |
| m22-003 gh (harness clone) | off | {} |
| m22-003 gh (harness clone) | def | {} |
| m22-003 ff | off | {"type mismatch (assignment, operand, return, cast)": 5} |
| m22-003 ff | def | {"type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 dc | off | {"call does not match prototype": 2, "type mismatch (assignment, operand, return, cast)": 10, "undeclared identifier": 1, "unit post-processing rejected the candidate object": 1} |
| m22-003 dc | def | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 1, "unit post-processing rejected the candidate object": 1} |
| m22-003 dk | off | {"illegal or unknown type name": 1, "member access on a type the context lacks": 2, "type mismatch (assignment, operand, return, cast)": 6, "undeclared identifier": 2} |
| m22-003 dk | def | {"member access on a type the context lacks": 2, "type mismatch (assignment, operand, return, cast)": 1} |

All lanes together (m22-003, the first diagnostic of every function that did not compile):

| class | off | def |
|---|---|---|
| call does not match prototype | 3 | 1 |
| illegal or unknown type name | 1 | 0 |
| member access on a type the context lacks | 2 | 2 |
| type mismatch (assignment, operand, return, cast) | 26 | 4 |
| undeclared identifier | 4 | 1 |
| unit post-processing rejected the candidate object | 1 | 1 |
| **functions that do not compile** | 37 | 9 |

## Functions that lost an exact match or a compile (default build against `off`)

none

## types_port_measure_stage4

```json
{
 "benchmark": "types_port_measure",
 "date": "2026-10-15",
 "ghidra_opt": "/home/raikaru/runs/Stage4Types/bin-fin/ghidra_opt",
 "images": [
  {
   "image": "gba-pokeemerald",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "worker_cast_operators": {
    "bare_constants": 0,
    "casts": 983,
    "casts_replaced": 2,
    "constants_retyped": 0,
    "long_marked": 0,
    "ptrsubs": 0,
    "unsigned_marked": 10,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 0,
   "infer": {
    "functions": 201,
    "calls_total": 553,
    "calls_per_function_mean": 2.75,
    "calls_per_function_max": 9,
    "ops_per_call_mean": 68.0,
    "varnodes_per_call_mean": 119.2,
    "microseconds_total": 18928,
    "microseconds_per_function_mean": 94.2,
    "decompile_wall_seconds": 18.5,
    "infer_share_of_wall": 0.001
   }
  },
  {
   "image": "gc-animal-crossing",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "worker_cast_operators": {
    "bare_constants": 0,
    "casts": 1856,
    "casts_replaced": 1,
    "constants_retyped": 0,
    "long_marked": 0,
    "ptrsubs": 0,
    "unsigned_marked": 31,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 0,
   "infer": {
    "functions": 206,
    "calls_total": 485,
    "calls_per_function_mean": 2.35,
    "calls_per_function_max": 8,
    "ops_per_call_mean": 226.0,
    "varnodes_per_call_mean": 386.7,
    "microseconds_total": 68679,
    "microseconds_per_function_mean": 333.4,
    "decompile_wall_seconds": 12.0,
    "infer_share_of_wall": 0.0057
   }
  },
  {
   "image": "nds-pokeheartgold-arm9",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "worker_cast_operators": {
    "bare_constants": 0,
    "casts": 696,
    "casts_replaced": 0,
    "constants_retyped": 0,
    "long_marked": 0,
    "ptrsubs": 0,
    "unsigned_marked": 5,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 0,
   "infer": {
    "functions": 200,
    "calls_total": 369,
    "calls_per_function_mean": 1.84,
    "calls_per_function_max": 6,
    "ops_per_call_mean": 68.9,
    "varnodes_per_call_mean": 122.2,
    "microseconds_total": 16300,
    "microseconds_per_function_mean": 81.5,
    "decompile_wall_seconds": 14.0,
    "infer_share_of_wall": 0.0012
   }
  },
  {
   "image": "ps2-capcom-fighting-evolution",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "worker_cast_operators": {
    "bare_constants": 0,
    "casts": 1977,
    "casts_replaced": 8,
    "constants_retyped": 0,
    "long_marked": 38,
    "ptrsubs": 0,
    "unsigned_marked": 102,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 0,
   "infer": {
    "functions": 202,
    "calls_total": 369,
    "calls_per_function_mean": 1.83,
    "calls_per_function_max": 6,
    "ops_per_call_mean": 80.2,
    "varnodes_per_call_mean": 140.4,
    "microseconds_total": 19763,
    "microseconds_per_function_mean": 97.8,
    "decompile_wall_seconds": 10.1,
    "infer_share_of_wall": 0.002
   }
  },
  {
   "image": "ps2-dungeon-game",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 197,
    "decompiler": 3
   },
   "worker_cast_operators": {
    "bare_constants": 2,
    "casts": 1559,
    "casts_replaced": 0,
    "constants_retyped": 2,
    "long_marked": 23,
    "ptrsubs": 0,
    "unsigned_marked": 127,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 87,
   "infer": {
    "functions": 207,
    "calls_total": 606,
    "calls_per_function_mean": 2.93,
    "calls_per_function_max": 11,
    "ops_per_call_mean": 609.6,
    "varnodes_per_call_mean": 1134.9,
    "microseconds_total": 875664,
    "microseconds_per_function_mean": 4230.3,
    "decompile_wall_seconds": 24.3,
    "infer_share_of_wall": 0.036
   }
  },
  {
   "image": "psv-need-for-speed-most-wanted",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 190,
    "decompiler": 10
   },
   "worker_cast_operators": {
    "bare_constants": 34,
    "casts": 2431,
    "casts_replaced": 0,
    "constants_retyped": 5,
    "long_marked": 0,
    "ptrsubs": 0,
    "unsigned_marked": 20,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 510,
   "infer": {
    "functions": 205,
    "calls_total": 627,
    "calls_per_function_mean": 3.06,
    "calls_per_function_max": 12,
    "ops_per_call_mean": 278.7,
    "varnodes_per_call_mean": 514.5,
    "microseconds_total": 146923,
    "microseconds_per_function_mean": 716.7,
    "decompile_wall_seconds": 36.2,
    "infer_share_of_wall": 0.0041
   }
  },
  {
   "image": "psx-darkstalkers-3",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 200,
    "decompiler": 0
   },
   "worker_cast_operators": {
    "bare_constants": 0,
    "casts": 1696,
    "casts_replaced": 0,
    "constants_retyped": 0,
    "long_marked": 0,
    "ptrsubs": 0,
    "unsigned_marked": 191,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 0,
   "infer": {
    "functions": 204,
    "calls_total": 391,
    "calls_per_function_mean": 1.92,
    "calls_per_function_max": 9,
    "ops_per_call_mean": 174.1,
    "varnodes_per_call_mean": 299.5,
    "microseconds_total": 49049,
    "microseconds_per_function_mean": 240.4,
    "decompile_wall_seconds": 6.9,
    "infer_share_of_wall": 0.0071
   }
  },
  {
   "image": "x360-black-ops-2",
   "functions_logged": 200,
   "cast_functions": {
    "worker": 198,
    "decompiler": 2
   },
   "worker_cast_operators": {
    "bare_constants": 0,
    "casts": 1424,
    "casts_replaced": 2,
    "constants_retyped": 0,
    "long_marked": 0,
    "ptrsubs": 0,
    "unsigned_marked": 34,
    "warnings": 0
   },
   "decompiler_cast_ops_in_declined_functions": 10,
   "infer": {
    "functions": 205,
    "calls_total": 593,
    "calls_per_function_mean": 2.89,
    "calls_per
```

## ptrfields_dk

```json
{
 "addresses": 200,
 "env": [],
 "structs_printed": 9,
 "pointer_fields": {
  "fields": 71,
  "void *": 1,
  "non-pointer fields read through a pointer cast": 3
 },
 "functions_with_a_pointer_field": 1,
 "scalar_pointee_types": {}
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
   "found": 785,
   "recall": 0.9872,
   "precision": 0.9847,
   "size_exact": 752
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
   "found": 785,
   "recall": 0.9872,
   "precision": 0.9847,
   "size_exact": 752
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
