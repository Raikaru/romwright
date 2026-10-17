# m22-004: C output on pc-ioq3-ded-mingw32 (x86 PE, mingw-gcc)

Generated 2026-10-15. Sample 200 functions (seed 20261015) of 1534 functions of 16-1024 bytes drawn from all truth functions (no link map and no readable PDB) (1884 in the truth). Fixture `ioq3ded.exe`; compiler `mingw-gcc` (`i686-w64-mingw32-gcc (GCC) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)`), flags `-O2 -DNDEBUG -fno-lto -msse -mfpmath=387 -std=gnu99 -w -fpermissive -Wno-int-conversion -Wno-incompatible-pointer-types`; tag `on3`; romwright environment `default`.

| functions | produced | compiled | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|
| 200 | 152 | 137 | 20 | 22.704 | 33.145 | 23 |

## By function size (bytes)

| size | n | compiled | exact | mean percent |
|---|---|---|---|---|
| 16-63 | 45 | 27 | 8 | 30.377 |
| 64-255 | 97 | 69 | 10 | 28.161 |
| 256-1024 | 58 | 41 | 2 | 7.626 |

## Compile failures (first error, normalised)

- not produced x48
- error '_' undeclared (first use in this function) x6
- error too many arguments to function '_'; expected N, have N x3
- error conflicting types for '_'; have '_' x2
- error cannot convert to a pointer type x1
- error too few arguments to function '_'; expected N, have N x1
- error request for member '_' in something not a structure or union x1
- error expected identifier or '_' before '_' x1

## Calling convention (the truth name's decoration -> the candidate's)

- cdecl -> cdecl: 135
- cdecl -> fastcall: 2

## Limits

- The candidate is romwright's `export-c` for one function with no context: callees are undeclared (implicit `int f()`), so a caller of a `__stdcall` function pays the `add esp` the callee's `ret N` would have removed, exactly as a reader who pastes the export into a project would.
- exact: the function's code bytes (the truth size) equal the retail bytes outside the object's relocation fields (`DIR32`, `REL32`), and anything after them in the candidate is a relocated jump-table word or padding. Percent is objdiff-cli 3.6.1 `match_percent` (`functionRelocDiffs=none`) between two one-function ELF i386 objects that carry the candidate's relocations on both sides.
- The comparator masks relocation fields; it does not check that a relocation's symbol is the operand the retail instruction uses.
- Functions romwright did not discover at the truth address have no export and score 0 (the importer's recall is part of the number).
- The sample is a seeded draw of truth functions the truth marks verified; functions are not independent (they share units).
