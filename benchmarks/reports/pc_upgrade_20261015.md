# PC upgrade: the m22-004 lane before and after (2026-10-15)

Cells are exact / compiled / mean objdiff percent over each fixture's 200-function sample (seed 20261015), fresh import per arm (`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`), the fixture's own compiler, the lane as fixed by this work (retail-relocation objdiff target, strict relocation targets, DWARF game-code sample, `-fno-strict-aliasing` for ioq3). `off` is the final build with every switch of this work off (the integrated tree without this work's product rules); `default` is the final build.

**What changed in the lane first** (`tests/m22-004_pc_c_output.py`, details in docs/pc-project.md "Upgrade round"): the objdiff target now carries
the retail function's own relocations (the first-wave target took the candidate's relocation fields, which desynchronised the x86
decode after the first difference in length: on the same 199 saved GLQuake candidates the mean goes 41.58 -> 65.46 and under that
first-wave rule this round's default is still +3.2 over off, 43.086 -> 46.318); `exact` also resolves the relocations the candidate names by an
address (no false exact found); the GCC fixtures draw their sample from the DWARF compile units of the game (ioq3: 117 of 1,534 sized
functions were the MinGW C runtime), ioq3 compiles with the build's `-fno-strict-aliasing`, and GCC 16's C23 `bool` keyword no longer
breaks the prelude (doomgeneric: 177 of 200 candidates did not compile for that reason alone).

**Reference points.** The first wave (first-wave lane, tree before SymbolLayout): GLQuake 42 / 176 / 41.373, Quake 2 19 / 165 / 25.699,
ioq3 20 / 137 / 22.704. The tree as found at the start of this work under the fixed lane (binary built from the then tree, `nih-vps-u`):
GLQuake 42 / 176 / 65.132, Quake 2 30 / 190 / 63.826 (PcImport's discovery work had already moved it), ioq3 21 / 176 / 40.305 (old flags,
sample with the C runtime). Every number below is on the integrated tree (SymbolLayout's `ghidra_opt` included: the `stack0x` compile
failures of the first wave are gone, GLQuake compiles 190 of 200 with this round's rules off): `off` = the final binary with this
round's switches off, `default` = the final binary.


## Per fixture

| fixture | compiler | off | default | default vs off (percent better / worse / same, sign-test p) | exact gained / lost |
|---|---|---|---|---|---|
| `pc-glquake-msvc42` | msvc4.2 | 42 / 190 / 69.520 | **50 / 191 / 72.535** | 58 / 17 / 125 (p 2.18e-06) | +8 / -0 |
| `pc-quake2-msvc8` | msvc8.0 | 30 / 196 / 65.791 | **38 / 196 / 67.990** | 30 / 8 / 162 (p 0.000472) | +8 / -0 |
| `pc-ioq3-ded-mingw32` | mingw-gcc | 21 / 181 / 41.633 | **22 / 181 / 41.968** | 14 / 7 / 179 (p 0.189) | +1 / -0 |
| `pc-doomgeneric-mingw32` | mingw-gcc | 34 / 176 / 47.835 | **35 / 176 / 47.829** | 10 / 5 / 185 (p 0.302) | +1 / -0 |
| `pc-quake2-game-msvc8` | msvc8.0 | 32 / 195 / 63.037 | **35 / 195 / 63.132** | 16 / 9 / 175 (p 0.23) | +3 / -0 |
| `pc-quake2-refgl-msvc8` | msvc8.0 | 92 / 196 / 73.009 | **94 / 197 / 73.786** | 14 / 1 / 185 (p 0.000977) | +2 / -0 |

### `pc-glquake-msvc42`

Failure classes (functions; first error or first byte-difference class; see tests/m22-004/failure_classes.py):

| class | off | default |
|---|---|---|
| bytes: length (candidate longer), mostly moves and arithmetic | 42 | 46 |
| bytes: length (candidate shorter), mostly moves and arithmetic | 23 | 25 |
| bytes: different instructions (same length) | 22 | 21 |
| bytes: length (candidate longer), mostly stack and arithmetic | 17 | 14 |
| bytes: length (candidate shorter), mostly x87 | 11 | 10 |
| bytes: few instructions differ in count | 14 | 4 |
| bytes: length (candidate shorter), mostly stack and arithmetic | 7 | 5 |
| compile: conflicting / incompatible types | 6 | 6 |
| bytes: length (candidate longer), mostly x87 | 4 | 6 |
| bytes: register allocation | 4 | 5 |
| compile: other | 3 | 2 |
| bytes: single instruction | 1 | 2 |
| bytes: length (candidate shorter), mostly control flow and calls | 2 | 1 |
| not produced | 1 | 1 |
| bytes: stack frame size | 1 | 1 |
| bytes: register allocation + immediates | 0 | 1 |

Tags (functions whose differing instructions involve it): argument cleanup (`add esp`) differs 43 -> 36, call count differs 23 -> 19, float-to-int helper (`__ftol`) argument lost 18 -> 2, mul/shift strength reduction 16 -> 16, rep string op 15 -> 12, security cookie 7 -> 8, switch table 6 -> 6, x87 67 -> 64

Leave one out (the default build with one switch off): exact / compiled / mean, and the default's paired percent against that arm:

| switch off | exact / compiled / mean | default better / worse / same (p) | exact gained |
|---|---|---|---|
| `ROMWRIGHT_EXPORT_UNKNOWN_RETURN_VOID` | 48 / 191 / 72.084 | 17 / 11 / 172 (p 0.345) | +2 / -0 |
| `ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES` | 50 / 191 / 72.557 | 1 / 5 / 194 (p 0.219) | +0 / -0 |
| `ROMWRIGHT_EXPORT_STDCALL_IMPORTS` | 47 / 191 / 72.100 | 16 / 2 / 182 (p 0.00131) | +3 / -0 |
| `ROMWRIGHT_PE_FTOL` | 47 / 190 / 71.189 | 21 / 6 / 173 (p 0.00592) | +3 / -0 |
| `ROMWRIGHT_EXPORT_FLOAT_STORES` | 50 / 191 / 72.447 | 4 / 0 / 196 (p 0.125) | +0 / -0 |
| `ROMWRIGHT_EXPORT_COMPARE_ZERO` | 50 / 191 / 72.529 | 1 / 0 / 199 (p 1) | +0 / -0 |
| `ROMWRIGHT_EXPORT_STRING_OPS` | 50 / 191 / 72.340 | 3 / 1 / 196 (p 0.625) | +0 / -0 |
| `ROMWRIGHT_EXPORT_SQRT` | 50 / 191 / 72.515 | 3 / 0 / 197 (p 0.25) | +0 / -0 |
| `ROMWRIGHT_EXPORT_X87_MATH` | 50 / 191 / 71.798 | 7 / 0 / 193 (p 0.0156) | +0 / -0 |
| `ROMWRIGHT_EXPORT_RECURSIVE_CALLEE` | 50 / 191 / 72.535 | 0 / 0 / 200 (p 1) | +0 / -0 |
| `ROMWRIGHT_EXPORT_CALLEE_OVER_CODE_REF` | 50 / 191 / 72.535 | 0 / 0 / 200 (p 1) | +0 / -0 |

Near-miss search (`--search`, docs/match.md), default print -> best of the plan's variants: 50 / 191 / 72.535 -> 50 / 191 / 73.575; the search found a better print for 34 of the 141 functions it tried.


### `pc-quake2-msvc8`

Failure classes (functions; first error or first byte-difference class; see tests/m22-004/failure_classes.py):

| class | off | default |
|---|---|---|
| bytes: length (candidate longer), mostly moves and arithmetic | 39 | 38 |
| bytes: length (candidate shorter), mostly moves and arithmetic | 36 | 35 |
| bytes: different instructions (same length) | 19 | 18 |
| bytes: length (candidate shorter), mostly x87 | 17 | 14 |
| bytes: length (candidate shorter), mostly stack and arithmetic | 12 | 11 |
| bytes: length (candidate longer), mostly x87 | 11 | 11 |
| bytes: few instructions differ in count | 12 | 10 |
| bytes: length (candidate longer), mostly stack and arithmetic | 8 | 9 |
| bytes: length (candidate shorter), mostly control flow and calls | 5 | 5 |
| not produced | 3 | 3 |
| bytes: length (candidate longer), mostly control flow and calls | 3 | 3 |
| bytes: register allocation | 2 | 2 |
| bytes: stack frame size | 1 | 1 |
| bytes: single instruction | 1 | 1 |
| compile: other | 1 | 1 |

Tags (functions whose differing instructions involve it): argument cleanup (`add esp`) differs 63 -> 58, call count differs 37 -> 38, float-to-int helper (`__ftol`) argument lost 14 -> 4, mul/shift strength reduction 15 -> 16, rep string op 6 -> 4, security cookie 15 -> 15, switch table 4 -> 4, x87 78 -> 74

Leave one out (the default build with one switch off): exact / compiled / mean, and the default's paired percent against that arm:

| switch off | exact / compiled / mean | default better / worse / same (p) | exact gained |
|---|---|---|---|
| `ROMWRIGHT_EXPORT_UNKNOWN_RETURN_VOID` | 34 / 196 / 67.089 | 9 / 3 / 188 (p 0.146) | +4 / -0 |
| `ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES` | 38 / 196 / 68.088 | 0 / 2 / 198 (p 0.5) | +0 / -0 |
| `ROMWRIGHT_EXPORT_STDCALL_IMPORTS` | 36 / 196 / 67.851 | 4 / 0 / 196 (p 0.125) | +2 / -0 |
| `ROMWRIGHT_PE_FTOL` | 38 / 196 / 68.207 | 9 / 5 / 186 (p 0.424) | +0 / -0 |
| `ROMWRIGHT_EXPORT_FLOAT_STORES` | 38 / 196 / 66.518 | 10 / 1 / 189 (p 0.0117) | +0 / -0 |
| `ROMWRIGHT_EXPORT_COMPARE_ZERO` | 36 / 196 / 67.635 | 2 / 0 / 198 (p 0.5) | +2 / -0 |
| `ROMWRIGHT_EXPORT_STRING_OPS` | 38 / 196 / 67.971 | 1 / 1 / 198 (p 1) | +0 / -0 |
| `ROMWRIGHT_EXPORT_SQRT` | 38 / 196 / 67.990 | 0 / 0 / 200 (p 1) | +0 / -0 |
| `ROMWRIGHT_EXPORT_X87_MATH` | 38 / 196 / 67.990 | 0 / 0 / 200 (p 1) | +0 / -0 |
| `ROMWRIGHT_EXPORT_RECURSIVE_CALLEE` | 38 / 195 / 67.623 | 1 / 1 / 198 (p 1) | +0 / -0 |
| `ROMWRIGHT_EXPORT_CALLEE_OVER_CODE_REF` | 38 / 196 / 67.990 | 0 / 0 / 200 (p 1) | +0 / -0 |

Near-miss search (`--search`, docs/match.md), default print -> best of the plan's variants: 38 / 196 / 67.990 -> 39 / 196 / 68.954; the search found a better print for 28 of the 158 functions it tried.


### `pc-ioq3-ded-mingw32`

Failure classes (functions; first error or first byte-difference class; see tests/m22-004/failure_classes.py):

| class | off | default |
|---|---|---|
| bytes: length (candidate longer), mostly moves and arithmetic | 62 | 58 |
| bytes: length (candidate shorter), mostly moves and arithmetic | 43 | 43 |
| bytes: different instructions (same length) | 15 | 19 |
| compile: syntax: type or keyword | 9 | 9 |
| bytes: few instructions differ in count | 9 | 9 |
| not produced | 9 | 9 |
| bytes: length (candidate shorter), mostly x87 | 8 | 8 |
| bytes: length (candidate longer), mostly control flow and calls | 7 | 8 |
| bytes: length (candidate longer), mostly x87 | 6 | 6 |
| bytes: length (candidate shorter), mostly control flow and calls | 5 | 4 |
| bytes: stack frame size | 1 | 1 |
| bytes: single instruction | 1 | 1 |
| bytes: length (candidate shorter), mostly stack and arithmetic | 1 | 1 |
| compile: other | 1 | 1 |
| bytes: length (candidate longer), mostly stack and arithmetic | 1 | 1 |
| bytes: scheduling / order | 1 | 0 |

Tags (functions whose differing instructions involve it): argument cleanup (`add esp`) differs 48 -> 46, call count differs 16 -> 14, mul/shift strength reduction 13 -> 14, security cookie 3 -> 2, switch table 3 -> 3, x87 41 -> 41

Leave one out (the default build with one switch off): exact / compiled / mean, and the default's paired percent against that arm:

| switch off | exact / compiled / mean | default better / worse / same (p) | exact gained |
|---|---|---|---|
| `ROMWRIGHT_EXPORT_UNKNOWN_RETURN_VOID` | 21 / 181 / 41.670 | 9 / 3 / 188 (p 0.146) | +1 / -0 |
| `ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES` | 22 / 181 / 41.889 | 3 / 1 / 196 (p 0.625) | +0 / -0 |
| `ROMWRIGHT_EXPORT_FLOAT_STORES` | 22 / 181 / 41.968 | 0 / 0 / 200 (p 1) | +0 / -0 |
| `ROMWRIGHT_EXPORT_RECURSIVE_CALLEE` | 22 / 181 / 41.590 | 2 / 0 / 198 (p 0.5) | +0 / -0 |
| `ROMWRIGHT_EXPORT_CALLEE_OVER_CODE_REF` | 22 / 181 / 41.968 | 0 / 0 / 200 (p 1) | +0 / -0 |

Near-miss search (`--search`, docs/match.md), default print -> best of the plan's variants: 22 / 181 / 41.968 -> 22 / 181 / 42.460; the search found a better print for 17 of the 159 functions it tried.


### `pc-doomgeneric-mingw32`

Failure classes (functions; first error or first byte-difference class; see tests/m22-004/failure_classes.py):

| class | off | default |
|---|---|---|
| bytes: length (candidate longer), mostly moves and arithmetic | 57 | 57 |
| bytes: length (candidate shorter), mostly moves and arithmetic | 42 | 42 |
| bytes: different instructions (same length) | 18 | 18 |
| compile: syntax: type or keyword | 15 | 15 |
| bytes: few instructions differ in count | 10 | 10 |
| not produced | 8 | 8 |
| bytes: scheduling / order | 5 | 5 |
| bytes: length (candidate longer), mostly control flow and calls | 3 | 3 |
| bytes: length (candidate shorter), mostly stack and arithmetic | 2 | 2 |
| bytes: register allocation | 2 | 1 |
| bytes: single instruction | 1 | 1 |
| compile: other | 1 | 1 |
| bytes: length (candidate shorter), mostly control flow and calls | 1 | 1 |
| bytes: length (candidate longer), mostly stack and arithmetic | 1 | 1 |

Tags (functions whose differing instructions involve it): argument cleanup (`add esp`) differs 29 -> 29, call count differs 14 -> 14, mul/shift strength reduction 26 -> 26, security cookie 5 -> 5, switch table 2 -> 2, x87 1 -> 1


### `pc-quake2-game-msvc8`

Failure classes (functions; first error or first byte-difference class; see tests/m22-004/failure_classes.py):

| class | off | default |
|---|---|---|
| bytes: length (candidate shorter), mostly x87 | 62 | 58 |
| bytes: length (candidate longer), mostly moves and arithmetic | 24 | 26 |
| bytes: different instructions (same length) | 21 | 21 |
| bytes: length (candidate longer), mostly x87 | 18 | 19 |
| bytes: length (candidate shorter), mostly moves and arithmetic | 16 | 15 |
| bytes: length (candidate shorter), mostly stack and arithmetic | 11 | 10 |
| bytes: few instructions differ in count | 4 | 4 |
| bytes: length (candidate longer), mostly control flow and calls | 4 | 4 |
| not produced | 2 | 2 |
| compile: conflicting / incompatible types | 2 | 2 |
| bytes: length (candidate longer), mostly stack and arithmetic | 2 | 2 |
| compile: other | 1 | 1 |
| bytes: length (candidate shorter), mostly control flow and calls | 1 | 1 |

Tags (functions whose differing instructions involve it): argument cleanup (`add esp`) differs 42 -> 43, call count differs 25 -> 29, float-to-int helper (`__ftol`) argument lost 16 -> 6, mul/shift strength reduction 7 -> 7, rep string op 12 -> 10, security cookie 17 -> 17, x87 143 -> 141


### `pc-quake2-refgl-msvc8`

Failure classes (functions; first error or first byte-difference class; see tests/m22-004/failure_classes.py):

| class | off | default |
|---|---|---|
| bytes: length (candidate longer), mostly stack and arithmetic | 21 | 20 |
| bytes: different instructions (same length) | 19 | 19 |
| bytes: length (candidate longer), mostly moves and arithmetic | 16 | 15 |
| bytes: length (candidate shorter), mostly moves and arithmetic | 13 | 12 |
| bytes: length (candidate shorter), mostly x87 | 12 | 12 |
| bytes: length (candidate longer), mostly x87 | 9 | 10 |
| bytes: length (candidate shorter), mostly stack and arithmetic | 6 | 6 |
| bytes: few instructions differ in count | 5 | 6 |
| not produced | 2 | 2 |
| bytes: single instruction | 2 | 2 |
| compile: syntax: type or keyword | 1 | 1 |
| bytes: length (candidate shorter), mostly control flow and calls | 1 | 1 |
| compile: conflicting / incompatible types | 1 | 0 |

Tags (functions whose differing instructions involve it): argument cleanup (`add esp`) differs 61 -> 56, call count differs 16 -> 16, float-to-int helper (`__ftol`) argument lost 9 -> 6, mul/shift strength reduction 6 -> 7, rep string op 4 -> 2, security cookie 8 -> 8, switch table 2 -> 2, x87 72 -> 72

## Console gates (no regression)

| gate | off | default |
|---|---|---|
| m22-003 dds | 61 / 200 / 77.402 | 61 / 200 / 77.402 |
| m22-003 dc | 42 / 197 / 73.877 | 42 / 197 / 73.877 |
| m22-002 MWCC 20261010 | 56 / 196 / 78.031 | 56 / 196 / 78.031 |

The gates compare the final build with the build one change earlier (only the PE-only `_ftol2_sse` detection differs, which no console lane reads) with this round's switches off (one `ghidra_opt`, `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`,
a fresh import and work directory per arm): identical in all three lanes, so no function of the console lanes changes. The reference values the
integrated tree was announced with (dds 61 / 200 / 77.402, dc 41 / 197 / 73.562, m22-002 55 / 196 / 77.638) are matched for dds; dc and m22-002 read
slightly higher on this host's copy of the tree (changes that landed after that measurement), off and default alike.

## Limits and what was not done

* One 200-function sample per fixture (seed 20261015); functions share units, the sign tests are indicative. The leave-one-out rows are the
  default build with one switch off on the same sample: a rule that moves nothing here (`FTOL`, `SQRT`, `X87_MATH` on Quake 2; `STRING_OPS`,
  `COMPARE_ZERO`, `FLOAT_STORES` on GLQuake) is general code that the sample hardly meets, not a measured gain.
* `ROMWRIGHT_PE_FTOL` on Quake 2 (`_ftol2_sse`, found by the same shape rule) is neutral by exact and -0.22 point of mean: of the 14 functions it
  changes, 9 get better and 5 worse; the worst (`0041a930`, 79 -> 33 percent) is a conversion the decompiler stores in an `unsigned short`
  variable, which Visual C++ 8.0 compiles in line (`fistp dword`) instead of calling the helper (the original has `(int)` then `& 0xffff`).
  The expression is no longer lost, which is why the rule stays; the narrower-type recovery is the decompiler's.
* `ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES` is neutral to slightly negative on the means (-0.02 GLQuake, -0.09 Quake 2, no exact change): it
  declares callees the export left to the reader (variadic ones included), and a declared return type can send the compiler to another
  compare form. Kept for the declarations; the paired p is 0.2 to 0.5.
* The declaration rules (`UNKNOWN_RETURN_VOID`, `MERGE_CALL_SIGNATURES`, `RECURSIVE_CALLEE`, `CALLEE_OVER_CODE_REF`) apply to an i386 PE only: on
  the consoles a callee declared from its call sites has integer parameter types for pointers and `conform`'s casts cost four exact
  functions of dc (found in the first integrated arm, 37 / 197 / 72.813 against 42 / 197 / 73.877 with the gating).
* Most of what is left is not x86: 107 of GLQuake's 141 and 126 of Quake 2's 158 non-exact compiled functions are a different *length* (the
  decompiler's C is another source of the same behaviour: variable merging, expression shape, loop form, `if` shape), the
  class the near-miss search is for; it adds +1.0 mean on GLQuake and Quake 2 and +0.5 on ioq3, and at most one exact function, much less than on
  the consoles (the search varies printing knobs that mostly matter to MIPS register allocation).
* Not done, measured and left: nesting a call's result into the next call (`g(f(x))` for `t = f(x); g(t)`) compiles to identical bytes in Visual C++ 4.2
  and 8.0 (15 functions changed, no byte moved: the retail's merged `add esp, 8` has another cause); float loads through integer pointers
  (`(float)p[8]`: `fild` for `fld`, 3 functions per fixture, indistinguishable from a real `fild` in the printed text); the `strlen`/`strcat`
  idioms of `repne scasb` (10 GLQuake functions; the loop shapes vary too much for a text rule); a compare's operand order (`cmp a, b; jl` for
  `cmp b, a; jg`, about 20 functions per fixture, not recoverable without the source's order); a stack slot used both as a pointer and
  as a float (`C2440`, 5 GLQuake functions); 64-bit helper calls (`__allmul`, `__aulldiv`) are not met in the three samples (doubles
  pushed as two dwords compile to the same `push` pair); SEH (`__try`) prologues and `/GS` cookies for arrays the layout does not recover (15 Quake 2
  functions carry the cookie tag).
* The jump-table artifact of the lane (a function with a table in its bytes scores about 0 in objdiff although it is a few bytes from
  retail: 4 GLQuake and 6 Quake 2 functions of 200; a cut at the table start was tried and did not move them) understates both arms alike.
* MinGW GCC is the fixture's own extracted compiler, not a pinned tool (sha256 in the reports); `new-project`/`match` on a MinGW PE are a
  clang compile check only.

