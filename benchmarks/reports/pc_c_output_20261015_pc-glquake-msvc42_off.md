# m22-004: C output on pc-glquake-msvc42 (x86 PE, msvc4.2)

Generated 2026-10-15. Sample 200 functions (seed 20261015) of 946 functions of 16-1024 bytes drawn from link map glquake.map (1331 in the truth). Fixture `glquake.exe`; compiler `msvc4.2` (`10.20.6166`), flags `/O2 /G5 /ML /DWIN32 /DNDEBUG /D_WINDOWS /DGLQUAKE`; tag `off`; romwright environment `{"ROMWRIGHT_PE_WINDOWS_SPEC": "off", "ROMWRIGHT_PE_CONVENTIONS": "off", "ROMWRIGHT_PE_IAT_REGIONS": "off", "ROMWRIGHT_EXPORT_LONG_DOUBLE": "off", "ROMWRIGHT_EXPORT_CALLEE_CONVENTIONS": "off"}`.

| functions | produced | compiled | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|
| 200 | 198 | 167 | 42 | 40.574 | 48.592 | 51 |

## By function size (bytes)

| size | n | compiled | exact | mean percent |
|---|---|---|---|---|
| 16-63 | 38 | 37 | 22 | 75.807 |
| 64-255 | 104 | 92 | 17 | 42.663 |
| 256-1024 | 58 | 38 | 3 | 13.746 |

## Compile failures (first error, normalised)

- C2065 '_' : undeclared identifier x21
- C2100 illegal indirection x4
- compiler failed x3
- C2440 '_' : cannot convert from '_' to '_' (new behavior; please see help) x3
- not produced x2

## Calling convention (the truth name's decoration -> the candidate's)

- cdecl -> cdecl: 167

## Limits

- The candidate is romwright's `export-c` for one function with no context: callees are undeclared (implicit `int f()`), so a caller of a `__stdcall` function pays the `add esp` the callee's `ret N` would have removed, exactly as a reader who pastes the export into a project would.
- exact: the function's code bytes (the truth size) equal the retail bytes outside the object's relocation fields (`DIR32`, `REL32`), and anything after them in the candidate is a relocated jump-table word or padding. Percent is objdiff-cli 3.6.1 `match_percent` (`functionRelocDiffs=none`) between two one-function ELF i386 objects that carry the candidate's relocations on both sides.
- The comparator masks relocation fields; it does not check that a relocation's symbol is the operand the retail instruction uses.
- Functions romwright did not discover at the truth address have no export and score 0 (the importer's recall is part of the number).
- The sample is a seeded draw of truth functions the truth marks verified; functions are not independent (they share units).
