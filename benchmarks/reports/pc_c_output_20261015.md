# PC C output (x86 PE): exact / compiled / mean objdiff percent, 200-function samples

Generated 2026-10-15 by `tests/m22-004_pc_c_output.py` (seed 20261015); fresh import per arm (`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`). `off` sets `ROMWRIGHT_PE_WINDOWS_SPEC=off ROMWRIGHT_PE_CONVENTIONS=off ROMWRIGHT_PE_IAT_REGIONS=off ROMWRIGHT_EXPORT_LONG_DOUBLE=off ROMWRIGHT_EXPORT_CALLEE_CONVENTIONS=off`; the other arms name the switch they turn off (or `on`: nothing off).

## pc-glquake-msvc42 (msvc4.2, `10.20.6166`)

Flags `/O2 /G5 /ML /DWIN32 /DNDEBUG /D_WINDOWS /DGLQUAKE`; sample 200 of 946 functions of 16-1024 bytes drawn from link map glquake.map.

| arm | functions | produced | compiled | exact | mean % | mean % (compiled) | >= 90% |
|---|---|---|---|---|---|---|---|
| off | 200 | 198 | 167 | 42 | 40.574 | 48.592 | 51 |
| on2 | 200 | 199 | 176 | 42 | 41.373 | 47.014 | 51 |
| on | 200 | 198 | 175 | 42 | 41.267 | 47.162 | 51 |

Paired, `on2` against `off` on percent: better 8, worse 3, same 189 (two-sided sign test p = 0.227).

Compile failures of the `on2` arm (first error, normalised): C2065 '_' : undeclared identifier x15; C2440 '_' : cannot convert from '_' to '_' (new behavior; please see help) x5; compiler failed x3; not produced x1

## pc-ioq3-ded-mingw32 (mingw-gcc, `i686-w64-mingw32-gcc (GCC) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)`)

Flags `-O2 -DNDEBUG -fno-lto -msse -mfpmath=387 -std=gnu99 -w -fpermissive -Wno-int-conversion -Wno-incompatible-pointer-types`; sample 200 of 1534 functions of 16-1024 bytes drawn from all truth functions (no link map and no readable PDB).

| arm | functions | produced | compiled | exact | mean % | mean % (compiled) | >= 90% |
|---|---|---|---|---|---|---|---|
| off | 200 | 152 | 124 | 20 | 21.793 | 35.151 | 23 |
| on2 | 200 | 152 | 137 | 20 | 22.704 | 33.145 | 23 |

Paired, `on2` against `off` on percent: better 13, worse 7, same 180 (two-sided sign test p = 0.263).

Compile failures of the `on2` arm (first error, normalised): not produced x48; error '_' undeclared (first use in this function) x6; error too many arguments to function '_'; expected N, have N x3; error conflicting types for '_'; have '_' x2; error cannot convert to a pointer type x1; error too few arguments to function '_'; expected N, have N x1; error request for member '_' in something not a structure or union x1; error expected identifier or '_' before '_' x1

## pc-quake2-msvc8 (msvc8.0, `14.00.50727.42`)

Flags `/O2 /MT /DWIN32 /DNDEBUG /D_WINDOWS`; sample 200 of 885 functions of 16-1024 bytes drawn from llvm-pdbutil on quake2.pdb.

| arm | functions | produced | compiled | exact | mean % | mean % (compiled) | >= 90% |
|---|---|---|---|---|---|---|---|
| no_EXPORT_CALLEE_CONVENTIONS | 200 | 173 | 165 | 19 | 25.091 | 30.413 | 25 |
| no_EXPORT_LONG_DOUBLE | 200 | 173 | 163 | 19 | 25.091 | 30.787 | 25 |
| no_PE_CONVENTIONS | 200 | 173 | 165 | 19 | 25.091 | 30.413 | 25 |
| no_PE_IAT_REGIONS | 200 | 173 | 165 | 19 | 25.401 | 30.789 | 25 |
| no_PE_WINDOWS_SPEC | 200 | 173 | 162 | 19 | 25.303 | 31.238 | 25 |
| off | 200 | 173 | 160 | 19 | 25.511 | 31.889 | 25 |
| on2 | 200 | 173 | 165 | 19 | 25.699 | 31.15 | 25 |
| on | 200 | 173 | 165 | 19 | 25.091 | 30.413 | 25 |

Paired, `on2` against `off` on percent: better 5, worse 4, same 191 (two-sided sign test p = 1).

Compile failures of the `on2` arm (first error, normalised): not produced x27; C2065 '_' : undeclared identifier x8

## pc-pcproject-mini (msvc6.0, `12.00.8168`)

Flags `/O2 /Gd`; sample 50 of 50 functions of 16-1024 bytes drawn from all truth functions (no link map and no readable PDB).

| arm | functions | produced | compiled | exact | mean % | mean % (compiled) | >= 90% |
|---|---|---|---|---|---|---|---|
| off | 50 | 48 | 45 | 17 | 68.547 | 76.163 | 22 |
| on2 | 50 | 48 | 48 | 19 | 74.721 | 77.835 | 25 |

Paired, `on2` against `off` on percent: better 6, worse 0, same 44 (two-sided sign test p = 0.0312).

Compile failures of the `on2` arm (first error, normalised): not produced x2

