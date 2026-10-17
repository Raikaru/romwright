# Symbol layout gates, 20261015

`off` = `ROMWRIGHT_NATIVE_LAYOUT=1` (every layout rule off: Stage 4's default byte for byte). `def` = the default build. exact / compiled / mean %; paired = functions better / worse / same by match percent against `off`.

How the arms ran: one release build of the Stage 4 tree (the tree the baseline numbers came from) with this change added, and `ghidra_opt` built by `native/build_ghidra_opt.sh` from the regenerated patch (sha256 `4532792d...`); each arm a wrapper binary that sets its switches and `ROMWRIGHT_ARM` (the m22-002 harness drops `ROMWRIGHT_*` from the environment), `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`. An m22-003 arm restores the lane's prepared work directory and repo from a pristine snapshot taken after its prepare stage (same path) and imports the retail image afresh; an m22-002 arm prepares its own work directory and repo copy. The lane arms ran with the worker of the first build; the final worker differs from it in one decision (a function entry is never retyped as an array), which changes one function of the wave (`001ce9f0` of dark-cloud) and none of the 600 functions of the dc, dk and ff lanes.

| gate | arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled | gained exact | gained compiled |
|---|---|---|---|---|---|---|---|---|---|---|---|
| m22-002 MWCC seed 20261010 | off | 55 | 195 | 77.324 | | | | | | | |
| m22-002 MWCC seed 20261010 | def | 55 | 196 | 77.638 | 1 | 0 | 199 | 0 | 0 | 0 | 1 |
| m22-002 MWCC seed 20261011 | off | 57 | 194 | 78.316 | | | | | | | |
| m22-002 MWCC seed 20261011 | def | 57 | 195 | 78.712 | 1 | 0 | 199 | 0 | 0 | 0 | 1 |
| m22-002 ee-gcc | off | 106 | 197 | 86.622 | | | | | | | |
| m22-002 ee-gcc | def | 106 | 197 | 86.622 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 dds | off | 61 | 200 | 77.224 | | | | | | | |
| m22-003 dds | def | 61 | 200 | 77.402 | 4 | 0 | 196 | 0 | 0 | 0 | 0 |
| m22-003 rc | off | 26 | 200 | 68.158 | | | | | | | |
| m22-003 rc | def | 26 | 200 | 68.327 | 1 | 0 | 199 | 0 | 0 | 0 | 0 |
| m22-003 p4 | off | 60 | 198 | 80.732 | | | | | | | |
| m22-003 p4 | def | 60 | 199 | 80.85 | 1 | 0 | 199 | 0 | 0 | 0 | 1 |
| m22-003 gh (harness clone) | off | 78 | 199 | 82.119 | | | | | | | |
| m22-003 gh (harness clone) | def | 78 | 199 | 82.119 | 0 | 0 | 200 | 0 | 0 | 0 | 0 |
| m22-003 ff | off | 21 | 199 | 62.913 | | | | | | | |
| m22-003 ff | def | 22 | 199 | 63.148 | 7 | 3 | 190 | 0 | 0 | 1 | 0 |
| m22-003 dc | off | 41 | 197 | 73.653 | | | | | | | |
| m22-003 dc | def | 41 | 197 | 73.562 | 2 | 2 | 196 | 0 | 0 | 0 | 0 |
| m22-003 dk | off | 29 | 197 | 78.277 | | | | | | | |
| m22-003 dk | def | 29 | 197 | 78.194 | 0 | 2 | 198 | 0 | 0 | 0 | 0 |

## Compile-failure classes per m22-003 lane, off against def (functions that did not compile, by the compiler's first diagnostic)

| lane | arm | classes |
|---|---|---|
| m22-003 dds | off | {} |
| m22-003 dds | def | {} |
| m22-003 rc | off | {} |
| m22-003 rc | def | {} |
| m22-003 p4 | off | {"type mismatch (assignment, operand, return, cast)": 1, "undeclared identifier": 1} |
| m22-003 p4 | def | {"type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 gh (harness clone) | off | {} |
| m22-003 gh (harness clone) | def | {} |
| m22-003 ff | off | {"type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 ff | def | {"type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 dc | off | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 1, "unit post-processing rejected the candidate object": 1} |
| m22-003 dc | def | {"call does not match prototype": 1, "type mismatch (assignment, operand, return, cast)": 1, "unit post-processing rejected the candidate object": 1} |
| m22-003 dk | off | {"member access on a type the context lacks": 2, "type mismatch (assignment, operand, return, cast)": 1} |
| m22-003 dk | def | {"member access on a type the context lacks": 2, "type mismatch (assignment, operand, return, cast)": 1} |

All lanes together (m22-003, the first diagnostic of every function that did not compile):

| class | off | def |
|---|---|---|
| call does not match prototype | 1 | 1 |
| member access on a type the context lacks | 2 | 2 |
| type mismatch (assignment, operand, return, cast) | 4 | 4 |
| undeclared identifier | 1 | 0 |
| unit post-processing rejected the candidate object | 1 | 1 |
| **functions that do not compile** | 9 | 8 |

## Functions that lost an exact match or a compile (default build against `off`)

none

## Class counts over the PS2 wave (functions that print each symptom; every arm on the functions all arms decompiled)

| arm | functions | partial | stack0x | odd | mismatch | any |
|---|---|---|---|---|---|---|
| off | 7330 | 567 | 63 | 17 | 31 | 624 |
| default | 7330 | 496 | 1 | 20 | 21 | 503 |
| no-elements | 7330 | 554 | 1 | 20 | 21 | 559 |
| no-contain | 7330 | 495 | 1 | 20 | 21 | 502 |
| no-stack-align | 7330 | 496 | 1 | 20 | 21 | 503 |
| no-stack-fold | 7330 | 500 | 2 | 20 | 31 | 517 |
| no-stack-refs | 7330 | 496 | 50 | 20 | 21 | 547 |
| no-stack-fold-no-stack-align | 7330 | 525 | 14 | 17 | 31 | 540 |

Functions with a partial member, by what it is a member of (a function can be in several):

| arm | register | parameter | stack | global |
|---|---|---|---|---|
| off | 137 | 2 | 107 | 368 |
| default | 135 | 2 | 69 | 325 |
| no-elements | 135 | 2 | 69 | 383 |
| no-contain | 135 | 2 | 69 | 324 |
| no-stack-align | 135 | 2 | 69 | 325 |
| no-stack-fold | 135 | 2 | 71 | 326 |
| no-stack-refs | 135 | 2 | 69 | 325 |
| no-stack-fold-no-stack-align | 137 | 2 | 107 | 326 |

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
