# m22-004: C output on pc-pcproject-mini (x86 PE, msvc6.0)

Generated 2026-10-15. Sample 50 functions (seed 20261015) of 50 functions of 16-1024 bytes drawn from all truth functions (no link map and no readable PDB) (50 in the truth). Fixture `mini.exe`; compiler `msvc6.0` (`12.00.8168`), flags `/O2 /Gd`; tag `off`; romwright environment `{"ROMWRIGHT_PE_WINDOWS_SPEC": "off", "ROMWRIGHT_PE_CONVENTIONS": "off", "ROMWRIGHT_PE_IAT_REGIONS": "off", "ROMWRIGHT_EXPORT_LONG_DOUBLE": "off", "ROMWRIGHT_EXPORT_CALLEE_CONVENTIONS": "off"}`.

| functions | produced | compiled | exact | mean percent | mean percent (compiled) | percent >= 90 |
|---|---|---|---|---|---|---|
| 50 | 48 | 45 | 17 | 68.547 | 76.163 | 22 |

## By function size (bytes)

| size | n | compiled | exact | mean percent |
|---|---|---|---|---|
| 16-63 | 38 | 33 | 15 | 72.998 |
| 64-255 | 11 | 11 | 2 | 59.403 |
| 256-1024 | 1 | 1 | 0 | 0.0 |

## Compile failures (first error, normalised)

- C2100 illegal indirection x2
- not produced x2
- C2061 syntax error : identifier '_' x1

## Calling convention (the truth name's decoration -> the candidate's)

- cdecl -> cdecl: 42
- stdcall -> cdecl: 3

## Limits

- The candidate is romwright's `export-c` for one function with no context: callees are undeclared (implicit `int f()`), so a caller of a `__stdcall` function pays the `add esp` the callee's `ret N` would have removed, exactly as a reader who pastes the export into a project would.
- exact: the function's code bytes (the truth size) equal the retail bytes outside the object's relocation fields (`DIR32`, `REL32`), and anything after them in the candidate is a relocated jump-table word or padding. Percent is objdiff-cli 3.6.1 `match_percent` (`functionRelocDiffs=none`) between two one-function ELF i386 objects that carry the candidate's relocations on both sides.
- The comparator masks relocation fields; it does not check that a relocation's symbol is the operand the retail instruction uses.
- Functions romwright did not discover at the truth address have no export and score 0 (the importer's recall is part of the number).
- The sample is a seeded draw of truth functions the truth marks verified; functions are not independent (they share units).
