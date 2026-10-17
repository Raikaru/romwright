# Windows PE / x86: fixtures, the C-output lane, projects (finish item 5)

romwright imports a 32-bit Windows executable natively (`native/pe.rs`, `pe_roots.rs`; import numbers in
`docs/` "PE parity"). This page is the rest of the bar the consoles are held to: a *measured* C output, a `new-project`
repository and `match`, for PC games. Nothing here is fitted to a game's text; every rule is general x86/Windows and was
measured with fresh imports per arm.

## Truth fixtures

A fixture is a directory in the truth contract of [console-research.md](console-research.md#the-truth-contract): the image,
`truth/functions.tsv` (`start size name module verified`) and `truth/meta.json` (`compiler`, `flags`, `repo`, `commit`),
built from an open-source game with the vendor compiler and read back from its own PDB, COFF symbols or DWARF (never from the
importer). PcImport's fixtures live on `nih-vps-u:~/romwright-corpus/extracted/pc-*` and are listed with their compilers, flags
and source commits in `benchmarks/pc_fixtures/` (the build recipes); the ones this page measures:

| fixture | game | compiler | flags | truth |
|---|---|---|---|---|
| `pc-glquake-msvc42` | GLQuake (id Software/Quake @ `bf4ac42`) | Visual C++ 4.2 (`cl` 10.20.6166), pinned as `msvc4.2` | `/O2 /G5 /ML /Z7 ...` | 1,331 COFF function symbols |
| `pc-quake2-msvc8` | Quake 2 client+server (id-Software/Quake-2 @ `372afde`) | Visual C++ 2005 (`cl` 14.00.50727.42), pinned as `msvc8.0` | `/O2 /MT /Zi ...` (default `/GS`) | 2,094 PDB `S_GPROC32` |
| `pc-pcproject-mini` | 50 original functions written for this test | Visual C++ 6.0, pinned as `msvc6.0` | `/O2 /Gd` | the link map |
| `pc-ioq3-ded-mingw32` | ioquake3 dedicated server (ioquake/ioq3 @ `87a99d1`) | MinGW GCC 16.2.1 (Fedora RPMs, not pinned) | `-O2 -msse -mfpmath=387 -std=gnu99 -fno-strict-aliasing` (the cmake build's; `meta.json` omits the last) | DWARF + COFF symbols |
| `pc-doomgeneric-mingw32` | doomgeneric (ozkl/doomgeneric @ `e257a09`) | MinGW GCC 16.2.1 | `-O2 -DSNDSERV -D_DEFAULT_SOURCE` | DWARF + COFF symbols |
| `pc-quake2-game-msvc8`, `pc-quake2-refgl-msvc8` | Quake 2 game and OpenGL renderer DLLs | Visual C++ 2005 | `/O2 /MT` | PDB |

(`tests/pc/mini/` rebuilds the third; it is the fixture used while the lane was written and holds no third-party code.)

## The C-output lane (`tests/m22-004_pc_c_output.py`)

m22-003's method for a PE: for a fixture, a seeded sample (seed 20261015) of 200 truth functions of 16 to 1,024 bytes drawn
from the game's own code (the statically linked C runtime is excluded: the link map's `Lib:Object` column or, for a PDB,
`llvm-pdbutil`'s module list says which objects are the build's own), then for each:

1. `romwright-cli export-c --address` on a fresh import (`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`), no context;
2. the dialect prelude (Ghidra's type names as typedefs) and, for Visual C++, `long long` spelled `__int64`
   (`new_project/pe.rs` `msvc_dialect`) and a `__thiscall` definition written `__fastcall` with an unused `edx`;
3. the fixture's own compiler (`cl.exe` through the pinned wibo, the fixture's flags minus the debug options, `/c`);
4. the function's bytes and `DIR32`/`REL32` relocation fields out of the COFF object;
5. score against the retail bytes: **exact** (the code bytes of the truth size equal outside the relocation fields; after
   them only relocated jump-table words or padding; and every relocation the candidate names by an address, `FUN_<hex>` or
   `DAT_<hex>`, resolves to the operand the retail instruction has), **compiled** (the object defines the function) and the
   objdiff-cli 3.6.1 `match_percent` (`functionRelocDiffs=none`) of two one-function ELF i386 objects: the candidate with its
   own relocations, the retail function with the relocation fields read off its linked bytes (see "Upgrade round" for why).
   A function the importer did not discover at the truth address, or that does not compile, scores 0.

```
python3 tests/m22-004_pc_c_output.py --fixture ~/romwright-corpus/extracted/pc-glquake-msvc42 --tag arm \
    [--env ROMWRIGHT_PE_CONVENTIONS=off] [--report STEM] [--functions-out FILE] [--all-code] [--mingw-root DIR] \
    [--artifacts DIR] [--search N] [--flags "..."] [--target-relocs retail|candidate] [--no-strict-relocs]
python3 tests/m22-004/failure_classes.py REPORT.json DIR    # the classes of the non-exact functions (needs capstone)
```

Reports: `benchmarks/reports/pc_c_output_<date>.{json,md}` (the headline arms), per-arm files beside them.

## Results (2026-10-15, `nih-vps-u`, 200-function samples, fresh import per arm): the first wave

These numbers are the lane as first written: the objdiff target took the *candidate's* relocation fields, which understates every percent ("Upgrade round" below measures the same candidates at 41.6 -> 65.5 for GLQuake), and the ioq3 sample included the MinGW C runtime. The rules and their switches are still those below; the current numbers are in the upgrade round.

Cells are exact / compiled / mean objdiff percent. `off` is the build with every x86 rule of this wave switched off
(`ROMWRIGHT_PE_WINDOWS_SPEC=off ROMWRIGHT_PE_CONVENTIONS=off ROMWRIGHT_PE_IAT_REGIONS=off ROMWRIGHT_EXPORT_LONG_DOUBLE=off
ROMWRIGHT_EXPORT_CALLEE_CONVENTIONS=off`: the importer's gcc spec for an i386 image, IAT reads folded into constants,
`longdouble` as a bare identifier, no callee keywords); `on` is the default.

| fixture | compiler | sample | off | on | paired (percent), on better / worse / same |
|---|---|---|---|---|---|
| `pc-glquake-msvc42` | Visual C++ 4.2 | 200 of 946 game functions | 42 / 167 / 40.574 | 42 / 176 / 41.373 | 8 / 3 / 189 (p 0.23) |
| `pc-quake2-msvc8` | Visual C++ 2005 | 200 of 885 game functions | 19 / 160 / 25.511 | 19 / 165 / 25.699 | 5 / 4 / 191 (p 1) |
| `pc-ioq3-ded-mingw32` | MinGW GCC 16.2.1 (not pinned, see below) | 200 of 1,534 sized functions | 20 / 124 / 21.793 | 20 / 137 / 22.704 | 13 / 7 / 180 (p 0.26) |
| `pc-pcproject-mini` | Visual C++ 6.0 | 50 of 50 | 17 / 45 / 68.547 | 19 / 48 / 74.721 | 6 / 0 / 44 (p 0.031) |

The two real games are almost all `__cdecl` C, so the convention rules have little to do there: the win is compiled
functions (+9, +5, +13) and a mean percent up by 0.2 to 0.9 point, with no exact gain and no sign-test significance. Where
the code has `__stdcall` and `__fastcall` functions (the mini fixture has three `__stdcall` and one `__fastcall` function) the rules are worth 6 points of mean
percent and 3 compiled functions at p = 0.031. The importer's recall is inside the numbers: 27 of Quake 2's 200 sampled functions
(14%) and 48 of ioq3's (24%) have no function at the truth address and score 0 (PcImport's discovery work), 4% of Quake 2's
and 12% of GLQuake's candidates do not compile (below), and most of the rest differ in register allocation or instruction
order, which is the decompiler's, not x86's.

Leave-one-out on Quake 2 (each row is the default build with one switch off; `on` = 19 / 165 / 25.091 before the last rule below,
`on2` = 19 / 165 / 25.699 with it):

| switch off | exact / compiled / mean % |
|---|---|
| `ROMWRIGHT_PE_WINDOWS_SPEC` | 19 / 162 / 25.303 |
| `ROMWRIGHT_PE_CONVENTIONS` | 19 / 165 / 25.091 (no `ret N` function in the sample) |
| `ROMWRIGHT_PE_IAT_REGIONS` | 19 / 165 / 25.401 |
| `ROMWRIGHT_EXPORT_LONG_DOUBLE` | 19 / 163 / 25.091 |
| `ROMWRIGHT_EXPORT_CALLEE_CONVENTIONS` | 19 / 165 / 25.091 (no callee of the sample is `__stdcall` or `__fastcall`) |

`ROMWRIGHT_PE_IAT_REGIONS` costs 0.31 point of mean on this sample: three functions differ (+16.2, -59.8, -18.4); the carve
turns `(*(romwright_code *)(unsigned char *)0x719ce)(...)`, a call to an RVA that is no code, into a call through the named IAT
slot (`PTR_UnregisterHotKey_00461210`), 27 of the 200 sampled functions call an import that way, but the decompiler then
keeps one load of the slot in a variable and calls through it twice where Visual C++ loads it twice (the slot is not marked
volatile: the worker protocol has no such attribute).

### What was general about the failures, and the rules that came out of them

Every rule below is keyed to the image (an i386 PE) or the compiler id, not to a game, and has an `=off` switch (the lane's
`--env`). Files touched are listed in STATUS.

1. **The importer decompiled every i386 image, ELF and PE, with the gcc compiler spec** (`native/specs/x86-LE-32-default`:
   `__cdecl`, a `__thiscall` with stack-only inputs, `__regparm3`). A `__fastcall` function came out as `__regparm3`
   (a keyword Visual C++ rejects, C2061, with `eax` as a phantom first parameter) and the callee-pops functions as `__cdecl`.
   An i386 PE now gets Ghidra's `windows` compiler spec (`crates/romwright-worker/specs/x86win.cspec`, `worker/src/specs.rs`:
   `__stdcall`, `__fastcall`, `__thiscall`, the MSVC runtime call fixups `_SEH_prolog`/`_EH_prolog`/`__alloca_probe`), with one change
   documented in the file: `__cdecl` is the default model (the decompiler prints a model name only when it is not the default),
   so `__stdcall`/`__fastcall` are printed and Visual C++'s own default is not.
2. **Which convention.** The decompiler cannot tell `__stdcall` from `__cdecl` (its Java-side purge analysis is not part of the
   native importer): `native/pe/x86_conventions.rs` walks each function's p-code from its entry (lifting with the SLEIGH
   x86 language, following direct branches, never decoding the bytes after the last `ret`), records `__stdcall+N` where every
   reachable `ret` pops `N > 0` bytes and `ecx`/`edx` are not read first, and `__cdecl` where a `push ecx`/`push edx` only reserves
   stack (Visual C++'s four-byte frame, which the decompiler read as a `__fastcall` argument). The `+N` travels to the decompiler
   as the prototype's `extrapop`, which a call site needs (with two or more callee-pops calls the stack solver cannot settle
   the unknown purges: the callers' arguments came out wrong).
3. **Callee declarations carry the keyword** (`extern int __stdcall FUN_x(int, int);`), only for an i386 PE
   (`emit_m2c/dependencies.rs`: the MIPS spec's *default* model is also called `__stdcall`, and an earlier version of this rule printed it on
   every console callee; found by SymbolLayout's dc lane, fixed before the numbers above, gated on the program's compiler id).
4. **Imports.** A PE's import address table holds hint/name RVAs on disk and the loader overwrites it, so a decompiler that
   reads the slot as a constant folds `call [slot]` into a call to an RVA. The slots are carved out of their read-only section into
   their own writable regions (`native/pe.rs` `carve_import_slots`).
5. **`longdouble`.** The x87 value type was printed as a bare identifier; the C parser of the conform pass read
   `(longdouble)*p` as a product and cast the pointer to `unsigned int` (`*(unsigned int)p`, C2100). It is spelled `long double`
   (`emit_m2c/globals.rs`).
6. **Compiler era detection** (`compiler/detect.rs`): `msvc-10` .. `msvc-14` from the linker version in the optional header
   (`Rich` raises it to high), `mingw-gcc-<major>` from libgcc's string; Quake 2 reads `msvc-14` (high), GLQuake `msvc-10`.
7. **Visual C++ dialect** (harness and `new-project`, `new_project/pe.rs`): `__int64` and `i64`/`ui64` for `long long`, and a
   `__thiscall` definition as `__fastcall` with an unused `edx`.

Not done, with the reason (the `stack0x...` identifiers, 15 of GLQuake's 200 candidates and 8 of Quake 2's, were then the largest compile-failure class here; SymbolLayout's stack layout has since removed them, see the upgrade round): `x._1_3_`
partial members (KOTOR2) are the stack/global layout work SymbolLayout owns;
`SEH` (`__try`) prologues (2 of 200 Quake 2 functions): the `_SEH_prolog4` call fixup in the Windows spec only fires when the
helper has its name, which a stripped image does not; callers of `__thiscall` functions are not rewritten; Visual C++
5.0 and 2008+ are not pinned.

## Upgrade round (2026-10-15, PcUpgrade): classes, harness fixes, general x86 rules

The first wave left the real games at 42 / 176 / 41.4 (GLQuake), 19 / 165 / 25.7 (Quake 2) and 20 / 137 / 22.7 (ioq3) (exact /
compiled / mean %), far under the console bar (dds 61 / 200 / 77). This round classified every non-exact function of the three
samples (and of three further PcImport fixtures), fixed what the lane itself got wrong, then fixed the largest general classes in
the product, each with an `=off` switch, and measured off -> default with a fresh import per arm on the integrated tree (one
binary, one lane copy, one `ghidra_opt`; `off` is that binary with this round's switches off). The sample, the compilers and the
truth are unchanged (seed 20261015, 200 functions per fixture).

### The lane itself: what it got wrong

Found before any product work, in this order of effect:

1. **The objdiff target desynchronised on x86 (the largest artifact).** The target object was the retail bytes with the
   candidate's relocation fields copied in and the candidate's relocations attached. x86 instructions are variable length, so
   wherever the candidate and the retail function differ in length every later instruction of the target is decoded against
   fields at the wrong offsets and objdiff scores the rest of the function as inserted or removed: 33 of the 132 compiled,
   non-exact GLQuake functions scored 0.0 while differing from retail by one instruction (`FUN_00429fb0`: 48 against 49 bytes, one
   moved load). The target now carries the relocations read off the retail function's own linked bytes (`pcobj.retail_relocations`:
   an absolute displacement or immediate that is an image address is a `DIR32` field, a `call`/`jmp rel32` leaving the function a
   `REL32`). On the same 199 saved candidates the GLQuake mean goes from 41.58 to 65.46; exact and compiled cannot move.
   `--target-relocs candidate` keeps the first-wave rule. All first-wave percents above are on the old rule.
2. **`exact` was masked, not checked.** A function counted exact when its bytes were equal outside the candidate's relocation fields,
   whatever the relocations named. A relocation named by an address (`FUN_<hex>`, `DAT_<hex>`) is now resolved against the retail
   field (`pcobj.check_relocation_targets`): for the exact functions of the three samples, none had a wrong target (no false exact),
   and the rule is kept (`--no-strict-relocs` drops it). Relocations of other symbols (imports, string literals, the unit's float
   constants) stay masked and unchecked.
3. **The ioq3 sample included the MinGW C runtime.** A GCC fixture has no link map or PDB, so the sample was drawn from all truth
   functions: 117 of the 1,534 candidates were `__tmainCRTStartup`, `_pei386_runtime_relocator`, `__mingw_*`. The game's units are
   now read from the DWARF of the unstripped build (`llvm-dwarfdump`: compile units compiled under the repository's directory),
   1,417 eligible functions.
4. **ioq3 was compiled with other flags than the build's.** `meta.json` `flags` omits `-fno-strict-aliasing -fvisibility=hidden`
   that every game unit of the cmake build has (`build.ninja`); the candidates were compiled with strict aliasing. The arms pass
   `--flags` with the build's; PcImport was told to correct the fixture.
5. **GCC 16 is C23.** A GCC fixture whose flags name no `-std` (doomgeneric) failed 177 of 200 candidates on the prelude's
   `typedef unsigned char bool;` (a keyword in C23). The prelude now defines it only below C23.
6. **Classification input.** `--artifacts DIR` keeps every candidate's C, compile log and bytes; the export's own warnings are in the
   report; `tests/m22-004/failure_classes.py` sorts compile failures and byte differences (below).

Checked and not a problem: flags per unit (each fixture's build recipe compiles every game unit with one flag set), the C runtime
in the MSVC samples (the link map and the PDB exclude it), relocation masking creating false exacts (2 above).
Left, and documented: a function with a jump table inside its bytes can score about 0 in objdiff although it is a few bytes from
retail (4 GLQuake and 6 Quake 2 functions of the 200); `exact` and `compiled` are not affected.

### The general classes and the rules that came out of them

Every rule has an `=off` switch (`--env` in the lane; the leave-one-out tables in `benchmarks/reports/pc_upgrade_20261015.md` are the
default build with one switch off). The *declaration* rules apply to an i386 PE only: applied to every target they cost the Dark
Chronicle lane four exact functions (a callee declared from its call sites alone has integer parameter types for pointers, and the
casts `conform` then puts on the arguments change the MWCC code).

| rule (switch) | what it does | files |
|---|---|---|
| unknown-size return is `void` (`ROMWRIGHT_EXPORT_UNKNOWN_RETURN_VOID`) | a callee whose return the decompiler typed with no name and no size ("native datatype has no C declaration", at least 384 callee declarations refused in the GLQuake sample, in 149 of its 200 functions) is declared `void f(...)` instead of left to the reader: the `__stdcall` keyword, the parameter types and the float arguments reach the compiler | `emit_m2c/dependencies.rs` (`callee_declarator`), `globals.rs` |
| merge call-site signatures (`ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES`) | one callee seen with different parameter lists at its calls ("inconsistent recovered call-site signatures", 45 of GLQuake's 200 functions): same convention, integers of one width, a pointer and a pointer-sized integer, two pointers (`void *`); lists of other lengths merge to the common prefix and `...` for a caller-cleans convention | `dependencies.rs` (`merge_call_signatures`) |
| recursive callee (`ROMWRIGHT_EXPORT_RECURSIVE_CALLEE`) | a function is not declared as its own callee (the call-site signature conflicted with the definition's convention and parameters: `C2371`, `conflicting types`) | `dependencies.rs` |
| callee over code reference (`ROMWRIGHT_EXPORT_CALLEE_OVER_CODE_REF`) | a function used as a value *and* called had `extern int f();` and `extern void f(int);` (`C2371`); the callee's declaration stands | `emit_m2c.rs`, `dependencies.rs` |
| `__stdcall` import calls (`ROMWRIGHT_EXPORT_STDCALL_IMPORTS`) | `call [IAT slot]` of a Win32 import was a call through a cdecl function type, so Visual C++ added the `add esp, N` the API function's `ret N` already did; the slots of every library but the C runtime are `__stdcall` (the export reads the import directory again: the store drops the library name) | `emit_m2c/imports.rs`, `native/pe_roots.rs` (`stdcall_import_slots`), `lib.rs`, `core/src/native.rs` |
| `__ftol` (`ROMWRIGHT_PE_FTOL`) | Visual C++ converts a float to an integer with a call to a CRT helper that takes its argument in `ST0`; the decompiler saw a call with no argument and the converted expression vanished (`FUN_00406910(param_1, FUN_0043c750())`). The importer names the helper `__ftol` when its p-code reads the incoming `ST0`, truncates and calls nothing (`_ftol` of 4.x to 7.x, `_ftol2_sse` of 8.0), and `x86win.cspec` has a call fixup for it (`EAX = trunc(ST0)`, pops the x87 stack and the return address): the call prints `(int)(param_2 * 8.0f)` | `native/pe/x86_conventions.rs`, `native/store.rs`, `crates/romwright-worker/specs/x86win.cspec` |
| float stored through an integer pointer (`ROMWRIGHT_EXPORT_FLOAT_STORES`) | `p[1] = (float)x;` on an `unsigned int *` is a conversion to integer (`fistp`) to the compiler; the program stored the float's bits (`fstp dword`): the location is written as `*(float *)&p[1]` | `emit_m2c/conform.rs` |
| `-1 < x` (`ROMWRIGHT_EXPORT_COMPARE_ZERO`) | the decompiler's canonical `x >= 0`; Visual C++ compares with zero by `test`, with -1 by `cmp` | `conform.rs` |
| `rep movs`/`rep stos` loops (`ROMWRIGHT_EXPORT_STRING_OPS`) | the counted loops the decompiler prints for the string instructions (`n >> 2` dwords then `n & 3` bytes; a constant count) are `memcpy`/`memset`, which Visual C++ expands in line the same way | `conform.rs` |
| `fsqrt`, `fsin`, `fcos`, `fpatan` (`ROMWRIGHT_EXPORT_SQRT`, `ROMWRIGHT_EXPORT_X87_MATH`) | `FLOAT_SQRT` of the x87 stack's value (10 bytes) was an unsupported intrinsic, and the three transcendental instructions printed as calls of undeclared `fsin(...)`; they are `sqrt`, `sin`, `cos`, `atan2` | `dependencies.rs` |

### Results (`nih-vps-u`, integrated tree, fresh import per arm)

Cells are exact / compiled / mean objdiff percent. `off` is the final binary with this round's switches off, `default` the final binary;
the first three fixtures are the headline, the last three are further PcImport fixtures run the same way (the doomgeneric sample is
the DWARF game code of a `-O2` MinGW build, `gamex86.dll` and `ref_gl.dll` are Quake 2's game and renderer DLLs, whose C runtime
is excluded by their PDBs). The report with the classes, the tags and the leave-one-out rows of every fixture is
`benchmarks/reports/pc_upgrade_20261015.{json,md}` (per-arm reports in `pc_upgrade_20261015_arms/`).

| fixture | compiler | off | default | paired percent: better / worse / same (sign-test p) | exact gained |
|---|---|---|---|---|---|
| `pc-glquake-msvc42` (GLQuake) | Visual C++ 4.2 | 42 / 190 / 69.520 | **50 / 191 / 72.535** | 58 / 17 / 125 (p 2.2e-06) | +8 |
| `pc-quake2-msvc8` (Quake 2) | Visual C++ 2005 | 30 / 196 / 65.791 | **38 / 196 / 67.990** | 30 / 8 / 162 (p 0.0005) | +8 |
| `pc-ioq3-ded-mingw32` (ioq3 (dedicated, MinGW)) | MinGW GCC 16.2.1 | 21 / 181 / 41.633 | **22 / 181 / 41.968** | 14 / 7 / 179 (p 0.189) | +1 |
| `pc-doomgeneric-mingw32` (doomgeneric) | MinGW GCC 16.2.1 | 34 / 176 / 47.835 | **35 / 176 / 47.829** | 10 / 5 / 185 (p 0.302) | +1 |
| `pc-quake2-game-msvc8` (Quake 2 `gamex86.dll`) | Visual C++ 2005 | 32 / 195 / 63.037 | **35 / 195 / 63.132** | 16 / 9 / 175 (p 0.23) | +3 |
| `pc-quake2-refgl-msvc8` (Quake 2 `ref_gl.dll`) | Visual C++ 2005 | 92 / 196 / 73.009 | **94 / 197 / 73.786** | 14 / 1 / 185 (p 0.00098) | +2 |

Where the first-wave numbers stood on the same fixtures (GLQuake 42 / 176 / 41.373, Quake 2 19 / 165 / 25.699, ioq3 20 / 137 / 22.704) the
lane, the discovery (PcImport) and the stack layout (SymbolLayout) have all moved; the like-for-like reading of this round's own
work is the off -> default column. Under the first wave's objdiff rule GLQuake's off -> default is 43.1 -> 46.3 on 199 functions.

Leave one out, the default build with one switch off (exact / compiled / mean; the full rows with the paired tests are in the report):

| switch off | GLQuake | Quake 2 | ioq3 |
|---|---|---|---|
| `ROMWRIGHT_EXPORT_UNKNOWN_RETURN_VOID` | 48 / 191 / 72.084 | 34 / 196 / 67.089 | 21 / 181 / 41.670 |
| `ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES` | 50 / 191 / 72.557 | 38 / 196 / 68.088 | 22 / 181 / 41.889 |
| `ROMWRIGHT_EXPORT_STDCALL_IMPORTS` | 47 / 191 / 72.100 | 36 / 196 / 67.851 | - |
| `ROMWRIGHT_PE_FTOL` | 47 / 190 / 71.189 | 38 / 196 / 68.207 | - |
| `ROMWRIGHT_EXPORT_FLOAT_STORES` | 50 / 191 / 72.447 | 38 / 196 / 66.518 | 22 / 181 / 41.968 |
| `ROMWRIGHT_EXPORT_COMPARE_ZERO` | 50 / 191 / 72.529 | 36 / 196 / 67.635 | - |
| `ROMWRIGHT_EXPORT_STRING_OPS` | 50 / 191 / 72.340 | 38 / 196 / 67.971 | - |
| `ROMWRIGHT_EXPORT_SQRT` | 50 / 191 / 72.515 | 38 / 196 / 67.990 | - |
| `ROMWRIGHT_EXPORT_X87_MATH` | 50 / 191 / 71.798 | 38 / 196 / 67.990 | - |
| `ROMWRIGHT_EXPORT_RECURSIVE_CALLEE` | 50 / 191 / 72.535 | 38 / 195 / 67.623 | 22 / 181 / 41.590 |
| `ROMWRIGHT_EXPORT_CALLEE_OVER_CODE_REF` | 50 / 191 / 72.535 | 38 / 196 / 67.990 | 22 / 181 / 41.968 |

### The classes, before and after

Every non-exact function is one class (`tests/m22-004/failure_classes.py`: the compiler's first error, or the byte-difference class of
the candidate against the retail bytes, with tags for what the differing instructions involve: x87 code, switch tables, `rep`
string operations, `add esp` cleanup, the `__ftol` argument, the security cookie, strength reduction). Counts of the 200 sampled functions:

| fixture | arm | not produced | compile failure | length differs | few instructions differ in count | same length, other instructions | register allocation, single instruction, frame, order |
|---|---|---|---|---|---|---|---|
| `pc-glquake-msvc42` | off | 1 | 9 | 106 | 14 | 22 | 6 |
| `pc-glquake-msvc42` | default | 1 | 8 | 107 | 4 | 21 | 9 |
| `pc-quake2-msvc8` | off | 3 | 1 | 131 | 12 | 19 | 4 |
| `pc-quake2-msvc8` | default | 3 | 1 | 126 | 10 | 18 | 4 |
| `pc-ioq3-ded-mingw32` | off | 9 | 10 | 133 | 9 | 15 | 3 |
| `pc-ioq3-ded-mingw32` | default | 9 | 10 | 129 | 9 | 19 | 2 |

What the classes are made of, read from the functions themselves (the owner of each is in the report's class tables):

* **Not produced** (1 to 9): no function at the truth address, the importer's recall (PcImport).
* **Compile failures** (GLQuake 8, Quake 2 1, ioq3 10 of the 200): GLQuake's are a stack slot the decompiler uses as a pointer and as a
  float (`C2440`, 5), two compiler crashes (`cl` exits without a message) and one `romwright_storage_...` union view assigned a piece
  (`C2106`, SymbolLayout's); Quake 2's is a `switch` on a float. ioq3's are callees the decompiler named like library functions
  with the wrong number of arguments (`memcpy` with four, `strlen` with none: 6), recursive calls that lost their arguments (3) and one
  pointer cast. The `stack0x...` identifiers that were the first wave's largest failure class (15 + 6 + 11 functions) are gone with
  SymbolLayout's rules.
* **Length** (107 of GLQuake's 141 non-exact compiled functions, 126 of Quake 2's 158, 129 of ioq3's 159): the decompiler's C is another
  source of the same behaviour: which values share a variable, where a sub-expression is inlined, loop and `if` shape, float values the
  decompiler types as integers (`fld/fstp` of a float member printed as an integer `mov`), the 64-bit and string idioms. This is
  not x86-specific and is the class the printing-variant search addresses.
* **A few instructions, a different instruction at the same length, register allocation**: the compare's operand order, a constant, the
  allocator.
* Tags: x87 code is in 64 of GLQuake's, 74 of Quake 2's and 41 of ioq3's non-exact functions (ioq3 is `-mfpmath=387`), argument cleanup
  differs in 36, 58 and 46, and the `__ftol` argument lost 18 -> 2 in GLQuake after the rule.

### `match` as a lane layer on x86

`--search 12` runs the product's near-miss plan (`romwright-cli match --plan`: printing knobs for variable merging, inlining depth,
call prototypes, structuring) on every compiled, non-exact function: each variant exported, compiled with the fixture's compiler and
scored like the default print; the best print per function is the layer's candidate.

| fixture | default print | best of the plan's variants | functions improved / tried |
|---|---|---|---|
| `pc-glquake-msvc42` | 50 / 191 / 72.535 | 50 / 191 / 73.575 | 34 / 141 |
| `pc-quake2-msvc8` | 38 / 196 / 67.990 | 39 / 196 / 68.954 | 28 / 158 |
| `pc-ioq3-ded-mingw32` | 22 / 181 / 41.968 | 22 / 181 / 42.460 | 17 / 159 |

The search helps the mean by 0.5 to 1.0 point and the exact count by at most one on x86, against whole functions turning exact on the
consoles: the knobs were built for MIPS register allocation and instruction order, and what is left on x86 is mostly the x87 shape and
expression structure they do not reach. It is cheap (about 6 seconds a function) and is a lane flag, so it stays available.

### Console gates

| gate | off | default |
|---|---|---|
| m22-003 dds | 61 / 200 / 77.402 | 61 / 200 / 77.402 |
| m22-003 dc | 42 / 197 / 73.877 | 42 / 197 / 73.877 |
| m22-002 MWCC 20261010 | 56 / 196 / 78.031 | 56 / 196 / 78.031 |

Identical off and default in all three lanes (the declaration rules are i386-PE-only; the gating was added after the first integrated
arm showed dc losing four exact functions to the callee declarations).

### Limits of this round

The sample is one 200-function draw per fixture; the leave-one-out rows of rules the sample hardly meets (`FTOL`, `SQRT`, `X87_MATH`
on Quake 2, `STRING_OPS`, `COMPARE_ZERO`, `FLOAT_STORES` on GLQuake) are neutral there, not measured gains. `ROMWRIGHT_PE_FTOL` on
Quake 2 is neutral by exact and -0.22 point of mean (9 functions better, 5 worse: a conversion the decompiler stores in an
`unsigned short`, which Visual C++ 8.0 compiles in line); `ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES` is -0.02 and -0.09 point of mean
(it declares more callees; the declarations are the point). Measured and left: nesting a call's result into the next call compiles to
identical bytes; float loads through integer pointers (3 functions per fixture, indistinguishable from `fild` in the text); the
`repne scasb` idioms (`strlen`/`strcat`, 10 GLQuake functions); a compare's operand order (about 20 functions per fixture); a stack
slot used as a pointer and a float; SEH prologues and `/GS` cookies for arrays the layout does not recover. A function with a jump
table in its bytes scores about 0 in objdiff although it is a few bytes from retail (4 and 6 of 200). Details: the report's last section.

## `new-project` and `match` smoke runs

All on `nih-vps-u` with the final build, `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`, tools fetched by the generated
`configure.py` (sha256-checked) into the project.

| image | `new-project` | `python3 build.py` | `python3 build.py report` (objdiff) |
|---|---|---|---|
| GLQuake (`pc-glquake-msvc42`, compiler `msvc4.2` from the detector's `msvc-10`) | 1,284 functions imported, 1,283 decompiled (1 refused: `Cannot properly adjust input varnodes`), 1,283 target objects with 5,472 call and 12,227 data relocations, 1,275 prototypes in `include/protos.h`; import 10 s, decompile 414 s | 1,179 of 1,283 compile | **232 match exactly** (objdiff 100%), 98 at >= 90%, mean 64.501% |
| KOTOR2, the unpacked image (`~/Nihilus/.private/re/swkotor2_unpacked.exe`, read only; `msvc-13` -> `msvc7.0`) | 10,956 functions imported (80 decompiled, `--decompile first:80`), 80 target objects with 483 call and 795 data relocations | 68 of 80 compile (51 before `__thiscall` definitions were written as `__fastcall`) | 11 match exactly, 5 at >= 90%, mean 58.552% |
| KOTOR2, the retail Steam image (`KOTOR2_Clean_LegacyPC_2012/swkotor2.exe`, `msvc-13`) | **7 functions**: the image is Steam-DRM wrapped (entry in a `.bind` section, `.text` packed: its compression ratio is 0.9995), so the importer sees the loader stub only | 6 of 7 compile | `objdiff.json` loads in objdiff-cli (the report runs); 0 match, mean 7.7% |

The scaffold builds and `objdiff.json` loads for all three. Unpacking the Steam image is outside romwright (Steamless-style
tools); the unpacked image is the user's own research artifact and was used as data. KOTOR2 is C++ (`__thiscall`
everywhere), which is why its compile rate is the weakest; its 12 remaining compile failures are `stack0x...` identifiers (7) and `._1_3_` partial
members (5), the stack/global layout work SymbolLayout owns.

`match` inside the GLQuake project: six functions, budget 12, objdiff match 98.5 to 99.7% at the project's default flags and **one
byte-exact at the game's own flags** (docs/match.md, "Windows PE projects").

## Limits

* The three fixture numbers are one 200-function sample each (seed 20261015); functions share translation units, so the sign
  tests are indicative. The mini fixture is 50 functions written for the test.
* `pc-ioq3-ded-mingw32` compiles with PcImport's extracted Fedora MinGW GCC 16.2.1 (`--mingw-root`; its `gcc` binary's sha256 is
  in the report), **not** a pinned tool: GCC in the manifest would need an RPM unpacker in `download_tool.py`. The same applies to
  `new-project`/`match` on a MinGW PE (compile check with clang only).
* Wibo 1.2.0 runs every pinned `cl.exe` but not the `link.exe` of Visual C++ 7.x and 8.0 (missing `lstrcmpiA`/`lstrcmpiW`): the
  PC fixtures were linked elsewhere; nothing here needs a linker.
* The lane compiles each candidate with no context: a callee is implicitly `int f()` unless the decompiler printed a declaration.
  A caller of a `__thiscall` function is not rewritten.
* x86-64 PE is not handled (the importer reads PE32+; `new-project` refuses it).

