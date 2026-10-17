# Stage 2 follow-up, 20261013

## m22-002 ee-gcc, three arms, each with a fresh import and work directory

off = `ROMWRIGHT_NATIVE_CASTS=1` with rule `mwcc-void-pointer-arithmetic` disabled; parity = the worker's casts with the rule disabled; default = the build as is. exact / compiled / mean %; paired against off.

| arm | exact | compiled | mean % | better | worse | same | lost exact | lost compiled |
|---|---|---|---|---|---|---|---|---|
| off | 106 | 197 | 86.403 | | | | | |
| parity | 106 | 197 | 86.403 | 0 | 0 | 200 | [] | [] |
| def | 106 | 197 | 86.403 | 0 | 0 | 200 | [] | [] |
Arms really differ in the process that decompiles: the m22-002 harness passes only `ROMWRIGHT_GHIDRA` and `ROMWRIGHT_STRUCTS` through, so the arms are wrapper binaries (`ghidra_opt_native` sets `ROMWRIGHT_NATIVE_CASTS=1`; `romwright-cli-novoid` sets `ROMWRIGHT_COMPILER_RULES_DISABLE=mwcc-void-pointer-arithmetic`; each report's `argv[0]` names the CLI that ran). Checked on the default arm's project: `export-c` with `ghidra_opt` writes a `cast_ok` line to `ROMWRIGHT_RUST_CASTS_LOG`, with `ghidra_opt_native` none (the decompiler cast); `romwright-cli-novoid compiler-rules` lists the rule `inactive`, `romwright-cli` `active`. On this lane all 200 functions are identical in the three arms.

## gh (`--layers romwright,m2c`, fresh import)

The 196 compiled of the stage 2 gates came from the lane run on the pristine repo copy `~/runs/Ps2Lanes/repos/gh`, whose own build matched 6,250 functions (4,866 in the size window); the harness cloning the repository itself matches 7,367 (5,544 in the window), which is what the 199-compiled baselines were measured on. A different matched set is a different 200-function sample, so the two are not comparable; the build under test is the same.

| run | matched | exact | compiled | mean % |
|---|---|---|---|---|
| default arm, pristine repo copy | 6,250 | 78 | 196 | 79.062 |
| default arm, harness clone | 7,367 | 78 | 199 | 82.119 |
| off arm (`ROMWRIGHT_NATIVE_CASTS=1`, rule disabled), harness clone | 7,367 | 78 | 199 | 82.057 |

Default against off on the harness clone: better 1, worse 0, same 199; lost exact [], lost compiled [].

## `ps2_decompile_success.py`, the wave's 11 projects, default build

10338 of 10342

| game | sampled | decompiled | failures |
|---|---|---|---|
| ps2-dark-chronicle | 969 | 969 | 0 |
| ps2-dark-chronicle-symtab | 962 | 962 | 0 |
| ps2-dark-cloud | 937 | 936 | 1 |
| ps2-dark-cloud-symtab | 940 | 940 | 0 |
| ps2-digital-devil-saga | 977 | 977 | 0 |
| ps2-fatal-frame | 942 | 942 | 0 |
| ps2-fatal-frame-symtab | 940 | 940 | 0 |
| ps2-god-hand | 980 | 980 | 0 |
| ps2-persona-4 | 975 | 974 | 1 |
| ps2-ratchet-clank | 861 | 860 | 1 |
| ps2-ratchet-clank-pal | 859 | 858 | 1 |

