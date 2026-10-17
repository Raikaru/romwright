# Romwright game-decompilation program

Plan of record for making Romwright the best tool for console game
decompilation. Built from eight primary-source research scouts
(2026-09-12; transcripts `history://R1DecompWorkflow` … `R8GameTypes`)
on top of the console/format map already in `STATUS.md`. Every item
below carries an effort class (S <1 day, M days, L weeks+), its
dependencies, and a **superiority gate**: a number measured against a
named stock tool on a named fixture. Parity is never the bar.

## 1. Thesis

Decomp projects do not want a better Ghidra; they want a tool that
sits inside their loop: split the image, name everything the symbols
and maps already know, emit the files their toolchain reads
(splat/dtk/objdiff/decomp.me), decompile in the shape their compiler
emits so the diff score moves, and pull runtime truth from the
emulator when static analysis stalls. Romwright already has the
expensive parts (native SLEIGH/p-code/decompiler, no JVM, a fact store
with provenance, multi-program projects, a JSON API). What it lacks
is exactly the integration surface — and, per platform, three
load-bearing readers/loaders that nobody else has done right.

Three facts from the research shape the whole sequence:

1. **Romwright reads none of the debug/symbol formats decomp projects
   live on** (CodeWarrior MAP, psyq SYM, `.mdebug`, DWARF1, NIDs, DS
   overlay tables). Stock Ghidra reads only one (GameCubeLoader MAP).
   We already hold an 11 MB CodeWarrior MAP beside its ELF and ROM
   (HeartGold) — a free differential gate.
2. **No export path exists** from the store to splat/dtk/objdiff/
   decomp.me. Every schema is documented and permissively licensed;
   the emitters are S/M work.
3. **Two vector units have no open SLEIGH anywhere** (N64 RSP, PS2
   VU-micro) — the greenfield moat — while three (PSX GTE, Gekko
   paired-singles, VU0-macro) have in-install specs whose semantics
   are stubs. Semantics work is M; new languages are L.

## 2. State (2026-09-12)

- Native loaders: ELF32/64, PE, DOL, NDS (dual CPU + ARM9 unpack),
  NSO (single module), N64 z64, PSX EXE, GBA. #325 PPC SDA slice
  landed (`HadError` renders; r13 via `register_contexts`).
- Store: programs/functions/symbols/xrefs/memory_regions/
  decode_contexts/trace_events/type tables; m10 multi-image, m11 game
  sessions, m12 diff, m13 VSA, m15 structuring, m16 types.
- Red gates: m5-013 NDS (NitroMain one-byte seed; green 09-09, bisect
  in progress), m4-003 language parity (needs `service/` bridge).
- Fixtures held: `base.elf` (GC, MWCC C++), HeartGold ROM + ARM9/ARM7
  ELF + `pokeheartgold.map` (mwldarm), Perfect Dark `.z64`, 20-row
  Linux ELF corpus, synthetic PSX/N64/GBA/NDS/PPC-SDA fixtures.
- Installed stock extensions (baseline tools): GameCubeLoader
  (Apache-2.0 verified), gba-ghidra-loader (Apache-2.0),
  emotionengine-reloaded (Apache-2.0), PsxLoader / N64Loader /
  NdsLoader / SwitchLoader / GhidraSPU / XEXLoaderWV / Ghidra3DS
  (**no LICENSE file on disk** — measurement tools only, never copied).

## 3. Milestones

Legend: gate fixture tags — HELD (on disk), SYNTH (built from
`tests/fixtures-src`), BUILD (self-built from open SDK), OBTAIN
(legal source named, not yet on disk). Stock = the named tool run
headless through the P1 baseline harness.

### P0 — Stabilise the base

| ID | Item | Effort | Gate |
|---|---|---|---|
| P0.1 | m5-013 NDS regression: bisect 09-09→2ccbfdad^, fix root cause | S/M | `python3 tests/m5-013_nds.py` PASS, recall ≥ 0.61, NitroMain has a body (HELD) |
| P0.2 | Build `service/` bridge; run m4-003; re-record parity baseline with `missing-data-symbol` class count as evidence | M | class count shrinks vs `benchmarks/reports/parity-baseline.json` (HELD corpus) |

### P1 — Foundations (unblock everything; all S/M)

| ID | Item | Effort | Deps | Gate / stock |
|---|---|---|---|---|
| P1.1 | **Stock baseline harness** `benchmarks/stock_score.py`: `analyzeHeadless` + `ExportFunctionScoring` runner, `stock_key` caching, envelope `benchmarks/reports/<id>-stock.json` | M | — | `base-elf-stock.json`, `heartgold-nds-stock.json`, four synthetic `*-stock.json`, `corpus-stock.json`; every later gate cites one |
| P1.2 | **Modules data model**: `modules(module_id, program_id, name, kind, file_id, load_vaddr, size, file_off, resident)`; nullable `module_id` on functions/symbols/xrefs/memory_regions; `module_xrefs`; locate/follow module-aware | S/M | — | m10-001…004 green; synthetic 2-overlay project where `locate` names both modules |
| P1.3 | **Trace→facts consumer**: `trace_events` rows (breakpoint/branch/mem-*/snapshot, payload `{from,to,regs?}`) → computed-call targets + xrefs, provenance `emulator:<name>`, deduped vs static, hit-count confidence | M | — | synthetic trace log yields exactly the expected new facts, zero static duplicates (unit test) |
| P1.4 | **Gekko/Broadway language pack** vendored to `native/specs/PowerPC-BE-32-gekko/` (GameCubeLoader, Apache-2.0) + loader-pinned language selection (GC→gekko, PS2→r5900, GBA→apcs, NDS→v5t) | S | — | `base.elf` paired-single prologues decode `psq_l/psq_st` typed as pairs; zero `r13`-offset pseudo-vars; stock uses `e500`/`default` by opinion luck |
| P1.5 | **CodeWarrior MAP reader** (mwldeppc + mwldarm; dtk `map.rs` grammar, MIT/Apache) → functions/objects/TUs/visibility | M | cwdemangle (P1.7) | HeartGold: ≥99% MAP FUNC rows hit same-address ELF FUNC; ROM named-recall beats 0.61 floor; stock cannot ingest DS MAP (HELD) |
| P1.6 | **DS overlay tables** (OVT/FAT walk, per-overlay module rows, (overlay-id, addr) symbol binding) | S+M | P1.2 | HeartGold: overlay count/addrs equal OVT truth; precision ≥ NTRGhidra baseline (HELD) |
| P1.7 | **MWCC demangle** (vendor cwdemangle, CC0): `__vt__/__ct__/__dt__/__RTTI__/@off@/Method__ClassCFv` beside Itanium | S | — | class-scoped names on `base.elf` where stock leaves mangled; dtk demangle CLI as parity oracle (HELD) |
| P1.8 | **Qualified-name prototypes**: namespace/class on `Declaration`, `Class::method` in `declared_for`, calling_convention + this_type on the library path | S+M | P1.7 | applied-prototype count on HeartGold ELF with user-supplied NitroSDK headers beats stock with the same headers (HELD + user headers) |
| P1.9 | **splat + dtk symbol/config emit** (`symbol_addrs.txt` + minimal yaml; `config.yml`/`symbols.txt`/`splits.txt`) from the store | S+M | P1.2 for REL section-relative | splat consumes with zero parse errors, symbol set = analyzer entries (HeartGold, SYNTH); dtk consumes and `dtk dol diff` is empty on unmodified rebuild (`base.elf`) |

### P2 — The match loop (what makes projects adopt it)

| ID | Item | Effort | Deps | Gate / stock |
|---|---|---|---|---|
| P2.1 | objdiff `objdiff.json` + unit/object export; per-function match-% rollup with `report changes`-compatible deltas; frogress POST | M+S | P1.9 | `objdiff-cli report generate` equals control project JSON; deltas equal `report changes` |
| P2.2 | **Shared fact database** (replaces decomp.me integration — its API is Cloudflare-gated and agent-hostile): a hosted fact store keyed by `sha256(binary)` + per-function semantic signature. `push-facts` uploads names/prototypes/types/library matches with provenance; `pull-facts` applies them on import; signature match transfers facts across builds sharing library code. Server: `romwright-facts` + `romwright-api` endpoints; client: CLI + API methods | M+M | m13 signatures, m9 provenance | round-trip: push facts from an analysed program, wipe, pull on re-import → names restored; signature match transfers ≥90% of shared library functions' names between two builds of the same source (SYNTH pair) |
| P2.3 | MWCC prologue/epilogue: `_savegpr/_restgpr/_savefpr` expansion to per-register p-code; `r3+r4` 8-byte struct return; `fmadds` fused ops | M+S | P1.4 | `base.elf` `_savegpr_26+` functions: frame + callee-saved set = mwcc-rs oracle; fewer `/* unable */` frames than stock |
| P2.4 | IDO o32: f12/f13 hole rule, `(f12,f13)`→one f64, gp small-data range; `.late_rodata` switch shape (trailing-empty default, reorder tolerance) | M+M | — | sm64 `update_mario_state` float args token-equal to m2c `mips-ido-c`; oot `Actor_Update` switch case count ≥ stock and = m2c (OBTAIN: CC0 repos) |
| P2.5 | psyq o32-soft cspec (`mips32_psyq`: no FP arg regs, gp SDA) + ARM APCS/agbcc bundle (`ARM-LE-32-apcs`) + `swi`/`__aeabi_*`/`ldm-stm` memcpy folds | M+M | — | PSX SYNTH: zero `f12` args in soft-float prototypes; pokeemerald `Cmd_attackcanceler`: correct soft regs vs stock AAPCS |
| P2.6 | MWCC RTTI-less class recovery: `__vt__`-anchored extents, thunk deltas, `.ctors/.dtors` + `__ct__/__dt__` membership | M+M | P1.7 | vtable/class count on `base.elf` vs stock (expected 0); every row symbol-anchored (HELD) |
| P2.7 | psyq MND `.SYM` reader (psx_mnd_sym grammar, Unlicense) | M | — | names vs stock+PsxLoader on a SYM+EXE pair (OBTAIN: psx_mnd_sym test files or debug disc) |
| P2.8 | Containers, easy tier: GC GCM/ISO→DOL, PSX BIN/CUE+SYSTEM.CNF→EXE, PSP PBP→PRX/ELF, Switch NRO/PFS0 | S each | — | `import(container) == import(inner image)` byte-identical mappings+seeds (SYNTH via mkpsxiso; BUILD homebrew) |
| P2.9 | GDB-RSP client core + mGBA (access-log fast path), melonDS (dual-core attribution), Dolphin adapters | M+S+M+M | P1.3 | each: ≥5 new computed-call facts over static baseline on its SYNTH/HELD fixture; melonDS zero cross-core misattribution; mGBA log ≥10× faster than stepping |

### P3 — Modules and platforms

| ID | Item | Effort | Deps | Gate / stock |
|---|---|---|---|---|
| P3.1 | GC/Wii REL loader (header/imp/rel, 201–204 + PPC types 0–13, sequential placement, module rows, imp edges) | M | P1.2 | `dtk rel info` parity; cross-module xref count ≥ stock GameCubeLoader on a disc-supplied REL set (OBTAIN: user disc; pyelf2rel SYNTH for CI) |
| P3.2 | PSX overlay sets (multi-BIN sharing one VA window) | M | P1.2 | PSXOverlayExample exact placement (disc-free); open-spyro 37 overlays ≥ stock PsxLoader (OBTAIN) |
| P3.3 | N64 overlays (oot `ovl_*` block table + R_MIPS reloc application; sm64 segment path) | M+S | P1.2 | reloc parity vs fado/splat on oot ovl (OBTAIN: user ROM; CC0 repo truth) |
| P3.4 | Wii ISO/WBFS/RVZ + WAD via `nod` (MIT/Apache); encrypted → refuse with user-key recipe | M+S/M | P2.8 | equality vs DOL import on decrypted partition; `wit verify`-clean images |
| P3.5 | Vita/PS3/PSP NID readers + vendored vita-headers db (MIT); PSP/Vita/PS3 unencrypted SELF→ELF; PS3 PKG listing | S+M+S/M+M | P1.2 | 100% stub recovery on self-built PSL1GHT/pspsdk/vitasdk modules vs stock (BUILD) |
| P3.6 | Switch NCA/ExeFS/XCI chain (nx-archive or hac-rs after spike), multi-NSO rtld | M+S+L | P1.2 | ExeFS-extracted NSO equality; 2-NSO cross-module import resolves where single-module `nso.rs` dangles |
| P3.7 | Xbox 360 XEX (unencrypted, LZX via MIT XexTool-RE port) + OG XBE; 3DS NCSD/CIA (clean-room; Project_CTR unlicensed) | M/L+M+M/L | — | header/section equality vs `xex1tool -l` / Cxbx `Xbe.h` dump / `ctrtool -i` on homebrew (BUILD) |
| P3.8 | PS2 IRX (export/import magics, ordinal stub rewrite as module_xrefs) + EE fixed-VA window | L | P1.2 | edge counts match loadcore on synthetic IRX pair |
| P3.9 | ECOFF `.mdebug` core (N64 IDO + PS2 STABS layer; port ccc, MIT) + DWARF v1 (port ghidra-dwarf1, MIT) | L+M | — | synthetic round-trip; typed-function recovery vs stock (stock reads neither) on first legally held fixture (OBTAIN) |
| P3.10 | SDK type pipeline: struct/layout ingestion from open headers (vita-headers MIT, pspsdk BSD-3, ps2sdk AFL-2.0, libdragon Unlicense, libPorpoise MIT); user-overlay for proprietary SDKs, hashed, never committed | M+L | P1.8 | struct-access counts on HeartGold with user NitroSDK headers vs stock; clean tables alone beat stock-with-nothing |
| P3.11 | Remaining emulator adapters: DuckStation/PCSX-Redux, RPCS3 (GDB+PINE), PCSX2 (PINE-first, write-queued), PPSSPP (WebSocket log-only breakpoints), Vita3K, Ryujinx-fork; ares/Xenia deferred (no stub) | M each | P1.3, P2.9 | ≥5 new facts each on BUILD fixture; two-protocol agreement where two exist; PCSX2 100-cycle race test |
| P3.12 | Cross-module analysis policy: per-module namespaces, shared memory modeled once, rename isolation | M | P3.1–P3.8 | m10-004 sweep green; rename in overlay A invisible to B |

### P4 — Vector units and match-shaped emission (the moat)

Order is disassembly-first, in-install specs before greenfield.

| ID | Item | Effort | Deps | Gate / stock |
|---|---|---|---|---|
| P4.1 | PSX GTE: COP2 imm25 decode + psyq inline-macro lifter to `gte_RTPS`-style calls (clean-room from psx-spx; PsxLoader unlicensed) | M | — | synthetic COP2 stream decode parity; RTPS/RTPT/NCLIP/AVSZ3 sequences lift to single named calls where stock MIPS shows 8+ raw lines (SYNTH) |
| P4.2 | Gekko paired-singles: audit `ppc_gekko_broadway` decode, lane-wise p-code (two-f32, GQR quantize helpers, W-bit), render as `ps0/ps1` lane C | M+L | P1.4 | disasm parity vs `ppc-dis` on MWCC PS snippet; no `double` where source used pairs (`base.elf`, BUILD sample) |
| P4.3 | VU0-macro semantics: replace opaque `_v*` pcodeops in vendored `vuupper.sinc` with lane-wise float semantics; libvux-style helper rendering | M+M | — | ps2sdk math3d routine renders `vf[d] = vf[s] + vf[t]`-shaped C where stock emits `_vadd(...)` unknowns (BUILD) |
| P4.4 | **RSP SLEIGH** (new SU-minus + VU language, IMEM/DMEM, OSTask-at-0xFC0 loader) + GBI display-list annotator; audio-first C policy, gfx stays annotated asm | L+M+S | — | ≥99% mnemonic+operand parity vs ares (ISC) on f3dex2 CC0 F3DEX2 2.08; DL command boundaries ≥95% vs repo labels (CC0 corpus) |
| P4.5 | **VU-micro SLEIGH** (new 64-bit VLIW, lower pipeline, I/E/M/D/T bits) + VIF MPG/MSCAL code finder | L | P4.3 tables | ≥98% parity vs `ee-dvp-as -d` on ps2sdk VU samples; auto-found MPG blobs vs stock (blobs = data) (BUILD) |
| P4.6 | m2c-parity emission layer (clean-room): deterministic temporaries, `/* irregular */` honesty, stack-struct dump, globals emission; div/mod/`cntlzw` canonicalizers | L+L | P2.3–P2.5 | token-diff(Romwright, m2c) < token-diff(stock, m2c) AND objdiff(Romwright C) ≥ objdiff(m2c C) on ≥2/3 of {sm64 IDO fn, pokeemerald agbcc fn, `base.elf` MWCC fn} |

## 4. Sequencing rationale

- P1 is nine S/M items that every later milestone depends on; none
  depends on another except demangle→MAP→prototypes. Run P1.1
  (baselines) first: no gate after it is allowed to lack a stock
  number.
- P2 is chosen by adoption value: symbols in, files out, score up.
  P2.1–P2.2 give a project a reason to open Romwright; P2.3–P2.6 make
  the decompile worth exporting.
- P3 is breadth. REL and PSX overlays before N64/DS because their
  data-model demands are strictest; PS2 IRX and Switch rtld last
  (both L). Containers ride the "inner image equality" gate, so each
  is cheap once the reader exists.
- P4 is the moat and the risk. GTE first (in-install spec, S/M),
  Gekko PS second (fixture held), VU0 third, then the two greenfield
  languages. Lifting never precedes disassembly parity.

## 5. Legal register

- **Vendor/port (Apache-2.0 compatible):** dtk map parser + demangle
  (MIT/Apache), cwdemangle (CC0), mapfile_parser (MIT), psx_mnd_sym
  (Unlicense), ccc (MIT), ghidra-dwarf1 (MIT), vita-headers db (MIT),
  pspsdk (BSD-3), ps2sdk (AFL-2.0 + LICENSE text), libdragon
  (Unlicense), libPorpoise (MIT), nod (MIT/Apache), nx-archive (MIT),
  hac-rs (Apache/MIT), linkle, cytryna (BSD-4, advertising clause in
  NOTICES), pine (MIT), XexTool-RE (MIT), ares RSP tables (ISC),
  armips (MIT), mipsasm-rsp (Apache), f3dex2 corpus (CC0), PS2Tek
  (Unlicense), GameCubeLoader + gba-ghidra-loader +
  emotionengine-reloaded (Apache-2.0, verified on disk), objdiff
  (MIT/Apache), asm-differ (Unlicense), splat schemas (MIT).
- **Reference-only, never copy:** m2c (GPL-3.0 — out-of-process
  handoff only), agbcc/old-gcc/ido-static-recomp (GPL oracles),
  Dolphin/wit/RPCS3/PCSX2/PCSX-Redux/DuckStation/PPSSPP/mGBA/melonDS/
  ares/Cxbx (GPL protocol shapes only), prxtool (AFL — reference),
  binutils ECOFF headers (GPL spec), rspasm (LGPL), openvcl (AFL),
  PsxLoader/N64Loader/NdsLoader/SwitchLoader/GhidraSPU/XEXLoaderWV/
  Ghidra3DS (no license on disk), Project_CTR (unlicensed),
  re4sym/fado/mwcc-rs/ida-gekko-pseudocode (confirm before porting).
  2026-10-08: `native/languages/psx` had carried byte-identical copies of
  PsxLoader's `.sinc`/cspec/pspec/ldefs files (no licence file, no file
  headers). They were replaced by a clean-room language (stock Ghidra MIPS,
  Apache-2.0, plus GTE definitions from psx-spx); a hash check of every
  `~/opt/psxloader-src` file against the repo now finds no match.
- **Never ship or commit:** any console key or key derivation
  (Switch prod/dev keys, Wii common key/title keys, NPDRM
  RAP/RIF/klicensee, 3DS titlekeys, X360 session keys), proprietary
  SDK headers/libs (NitroSDK, Dolphin/Revolution SDK, libultra,
  PSY-Q, Sony official SDKs, MWCC binaries), retail images. Encrypted
  input is refused with a message naming the user's own key + the
  stock tool recipe. Proprietary headers: per-user derived tables
  only, hashed, gitignored.

## 6. Fixture register

| Fixture | Status | Feeds |
|---|---|---|
| `base.elf` (GC MWCC C++) | HELD, private | P1.4, P1.7, P2.3, P2.6, P4.2, baselines |
| HeartGold ROM + ELF + mwldarm MAP | HELD, hash-pinned | P1.5, P1.6, P1.8, P1.9, P3.10, baselines |
| Perfect Dark `.z64` | HELD | N64 baseline |
| Linux 20-row corpus | HELD | P0.2, corpus baseline |
| SYNTH PSX/N64/GBA/NDS/PPC-SDA | committed builders | P2.5, P2.8, P4.1, baselines |
| GC mwldeppc MAP, PSX SYM+EXE, PS2 `.mdebug` ELF, oot/tww/sms disc RELs+ovls | OBTAIN (user-owned) | P1.5 GC variant, P2.7, P3.9, P3.1–P3.3 |
| Homebrew PS3/Vita/PSP/Switch/XEX/3DS modules | BUILD from open SDKs (licenses: PSL1GHT/vitasdk/pspsdk/devkitA64/nxdk — confirm each) | P3.5–P3.7, P3.11 |
| f3dex2 CC0 binaries, ps2sdk VU samples | OBTAIN (public, free) | P4.4, P4.5 |

## 7. Decisions needed from the maintainer

1. Overlay model: shared program + `module_id` (recommended; keeps
   m10 API) vs one program per overlay.
2. Gekko PS emission: scalarized `{ps0,ps1}` lane C (portable) vs
   `__PS*` intrinsic spellings (needs MWCC headers users supply).
3. PS3 SPU: in scope (new SLEIGH; GhidraSPU unlicensed) or PPU-only
   with SPU as data for v1.
4. Which matched function per platform pins the P4.6 gate
   (repo+commit+function+compiler flags).
5. Switch crate: nx-archive vs hac-rs (spike on one homebrew NSP).
6. Corpus additions (each retail/user-owned image needs approval per
   `docs/third-party.md`).

### Decisions taken (2026-10-08, maintainer-approved)

1. Overlay model: shared program + `module_id` (already built; ratified).
   Refinement (P3.12, 2026-10-08): modules whose windows do not overlap (GC
   DOL + RELs, N64 segments) are rows of one program; modules that share a
   window (DS overlays, N64 overlay sets) are one program each with one `modules`
   row, because a program's facts are keyed by address. `locate` answers per
   (program, module) with the module id; resident memory is its own program.
2. Gekko PS emission: scalarized `{ps0,ps1}` lane C (already built; ratified).
3. PS3 SPU: out of scope; PPU only, SPU images stay data.
4. P4.6 pin: pokeemerald (agbcc) through the m22 harness; other platforms
   are added only when their fixtures are held.
5. Switch crate: neither for now (NCA/XCI chain deferred, see below).
6. Corpus: Capcom's DWARF 1 (`SLUS_209.50`) and PSP Puzzle Bobble's DWARF
   are approved as type-truth sources (stripped twins as analysis input).

### Revised order and deferrals (2026-10-08)

Grounded in the decomp.dev project census (GameCube 50, Wii 30, PS1 30,
PS2 29, N64 24, Windows 21, GBA 16, NDS 12, X360 7, Switch 6, Xbox 2,
PSP 1, 3DS 1). Goto removal is judged by fake matches avoided (a match
that only holds through `goto` does not reproduce the source's control
flow), not by the m22 score delta, which structuring moved by 0.001.

Order: (1) run every plan gate runnable on held fixtures; (2) P3.1 REL on
Animal Crossing (`foresta.rel.szs` holds the game code; the research `gc`
image is `main.dol` only); (3) P3.9 DWARF 1 + `.mdebug` types as truth and
facts; (4) ABI correctness P2.5, P2.4, P2.3; (5) P3.2/P3.3 PSX and N64
overlays, P1.6 certification, P3.12 rename isolation; (6) variable/stack
recovery against DWARF; (7) P4.6 with the m22 context fix; then P4.1/P4.3,
P1.3 with one adapter (PCSX2 PINE), a Rust-ownership metric. In parallel
with all of these: expression equality in the printer IR, then the
remaining goto passes (switch-lowering reversal, jump-threading reversal,
loop re-rolling, de-duplication of compiler-copied regions).

P4.6 status (2026-10-09, STATUS.md "P4.6 match-shaped emission"): the m22
context variant compiles (`context.h` no longer redeclares libc built-ins);
pokeemerald through m22 scores 75.7 mean / 9 exact in context (63.5 / 6
before), and the gate holds there: token distance to m2c 510 against stock's
516 on the five functions stock has output for, objdiff at or above m2c on
26 of 33 (33 of 33 standalone). The sm64 and `base.elf` rows have no fixture.

Deferred, with the reason:
- P2.2 hosted fact service: operating a service keyed to retail-binary
  hashes; file export (dtk/splat/objdiff) already covers sharing.
- P3.11 further emulator adapters: prove P1.3 end to end on one first.
- P4.4/P4.5 lifting microcode to C: projects keep RSP/VU microcode as asm;
  disassembly is the deliverable, decompile falls back to it.
- P3.6 NCA/XCI chain (per-user keys; projects extract NSOs already). The
  multi-NSO rtld link (main + subsdk) is kept.
- P3.7 XBE/3DS (2 and 1 projects); XEX is done.
- P3.8 PS2 IRX: IOP modules are mostly SDK code reached over SIF RPC, not
  the EE program projects decompile.
- Retypd and a general block/varnode export: no measured benefit at
  current truth density.
- P2.7 MND `.SYM`: no fixture held.

## 8. Verification discipline

- No milestone lands without its `tests/mX-NNN_*.py|.sh` gate, its
  `benchmarks/reports/<id>.json`, and the matching `<id>-stock.json`.
- Every gate uses `discovery_gate` scoring policy and `stock_key`
  caching so native and stock numbers stay comparable.
- Absent fixtures skip with reason, never pass silently.
- Standing regressions on every commit: `cargo test --workspace`,
  `tests/corpus.sh`, `tests/ppc_sda.sh`,
  `tests/generic_discovery_test.sh`, m10 sweep once P1.2 lands.

## 9. Status of the ABI rows (2026-10-08)

- **P2.3 (MWCC):** done on Animal Crossing. `_savegpr/_restgpr/_savefpr/_restfpr`
  entries are named from their bytes (`native/mwcc_runtime.rs`) and expanded by
  `r11`-based call fixups (`specs.rs`); the pinned spec's `r1`-based ones are
  replaced. On 200 functions calling `_savegpr_14..26`: arity 46% -> 95.5%
  (stock 46%), irregular inputs 283 -> 2. `fmadds` family and the `r3:r4`
  8-byte return were already right and now have tests. The plan's `base.elf`
  oracle gate stays open (not held); the ac-decomp truth stands in. See STATUS.md.
- **P2.4 (IDO o32):** the f12/f14 hole rule, the `sp+16` stack start and float
  typing of FP-register parameters are done (PD, 4086 truth functions derived
  from the ROM): float-subset signature agreement 43% -> 73% (stock 44%). The
  `gp` small-data range has no PD instance (`-G 0`); the sm64/oot gates named in
  the row are not held. Switch case counts equal stock on common functions; 18
  jump tables both tools lose remain.
- **P2.5 (soft-float):** PSX gets a soft-float convention (a declared `float` is
  `a0`, no FP register is callee-saved) and its crt0 `$gp`, so `$gp`-relative
  accesses name the `.sdata`/`.sbss` globals they address (243 `uGp...` tokens in
  71 functions -> 0). GBA: the ARM v4t convention was already agbcc-correct;
  arity agrees with the source on 97% of the 200-function sample, the misses
  being parameters the code never reads. See STATUS.md.

## 10. Status after the 2026-10-08 run

Each row's numbers and commands are in the STATUS.md section named after it.

| Item | State | Measured |
|---|---|---|
| P0.1 | done | m5-013 recall 0.9742 |
| P1.5 MAP | done | 0.9993 MAP FUNC rows hit same-address ELF FUNC |
| P1.6 DS overlays | done | 2772 -> 0 wrong-overlay names; precision ties NTRGhidra (0.99833), recall +0.109 |
| P1.7 MWCC demangle | done | 16,032/16,032 agree with `dtk demangle`; wired into import (display names, parameter prototypes) |
| P1.8 qualified prototypes | done | `declared_qualified_for` is the only library-prototype path |
| P1.9 / P2.1 export | done | dtk split clean, splat 0.39.1 rc 0 on PSX/PS2/PSP/N64, objdiff 707 units equal control; `dtk dol diff` residue is discovery |
| P2.3 / P2.4 / P2.5 ABI | done | section 9 |
| P2.8 containers | partial | PS2 ISO, GC CISO and PSX BIN/CUE pass (P3.4b); PBP, NRO not held |
| P3.4 Wii/GC disc containers | done | RVZ, WIA, WBFS and Wii ISO (encrypted partitions) import through `nod` lazily, GC CISO through `disc.rs`; project tables identical to the decompressed ISO on every disc checked (STATUS.md, RvzNkit) |
| P3.4b disc layers | done | RELs in RARC/U8 archives link like file-system RELs (TWW 415/415, TP 757/757, SS 636/636), same-id RELs are overlay programs (MP4 99/99), PS1 `.cue`/raw `.bin` import their boot PS-EXE (7 discs, function sets identical to the staged EXEs); STATUS.md, DiscLayer |
| P3.1 REL | done | Animal Crossing foresta recall 0.9993 vs GameCubeLoader 0.9414; relocations byte-equal to dtk |
| P3.3 N64 | done for 9 games | Perfect Dark through its catalog entry (145 -> 5485 functions, recall 0.9491 vs N64LoaderWV 0.0; its TLB-mapped layout is not discoverable generically, so the entry stays); generic layout discovery (`native/n64_discovery.rs`, 0 wrong vram) for the other eight: main recall OoT .045 -> .984, MM .104 -> .978, Banjo-Kazooie / SSB / Paper Mario 0 -> .95+, overlays .84-.99 (STATUS.md, N64Layouts) |
| P3.9 DWARF 1 | done | Capcom types: Rust and Python readers agree 5221/5221; `.mdebug` types not read (no held image has them) |
| P3.12 isolation | done | per-overlay programs; `tests/m10-005_overlay_isolation.py` |
| P4.1 GTE | done | clean-room language + psyq-style macro lifter (`printc/gte.rs`, default on): synthetic RTPT/NCLIP/AVSZ3 routine 14 MIPS instructions / 13 statements -> 6 calls, matrix setup 17 / 8 -> 2 (`tests/p4-1_gte_macros.py`); held PSX image (VS.EXE) has 3 functions with GTE moves (10 `ctc2`), 0 commands, 0 lifted, all 2206 functions print identically with the pass on and off |
| P4.3 VU0 | done | opaque VU calls in VU0 functions 883 -> 14 (Capcom), 984 -> 12 (dungeon) |
| P4.6 match-shaped emission | done on the pinned row | m22 ROM 64.14/6 exact -> 75.73/9; ours >= m2c on 26/33 (context) |
| PSP | added | stripped discovery recall 0.9453 vs stock 0.7990; symtab arity 0.8828 vs 0.7931 |
| Switch tables | done | stored tables supply 100% of printed switches (Rust-owned share 0% -> 61.8%) |
| Constant propagation in Rust | done | `native-analysis:constant-propagation` / `data-width` facts computed in process (`native_runtime/propagation*`), not by the console: project tables identical to the console-driven import on 5 of 10 images (dungeon, psx, gc, both PSP), every differing range on the other five classified as a jump table only one side follows (STATUS.md, ConstPropRust); m21 unchanged or up (GBA .9737 -> .9761); discovery-stage facts 100% Rust by provenance; imports 1.1-2.6x faster in paired runs (dungeon 8.3 -> 5.1 s, psx 10.2 -> 6.2 s, gc 14.5 -> 10.4 s, x360 152 -> 96 s) |
| SLEIGH console retired | done | every console caller (flow for nonreturn, ELF initializers, demand walks; the CLI/API/desktop `disasm` and listing; the m13 decode oracle) runs on the in-process kuna-sleigh lifter; `decomp_native`, `build_console.sh`, `ROMWRIGHT_FLOW_DIFFERENTIAL*` and 453 lines of first-party C++ are gone (net -422), `ghidra_opt` is the only native process and builds without `binutils-devel`; m21-001 identical on all 7 images, paired imports unchanged (gba 18.1 -> 18.0 s, gc 3.55 -> 3.53 s, x360 36.7 -> 36.7 s); `disasm` now lists the N instructions asked for instead of stopping at the console's flow-derived function end (STATUS.md, ConsoleRetire) |
| XEX LZX | done | compression-2 block chains walked; AMPED 3 imports 35,573 functions, other XEX images unchanged (STATUS.md, XexLzx) |
| GBA RAM overlays | done | `native/gba/overlays.rs` places code copied to RAM: NASCAR Heat 0 -> 353/456 copied functions, Golden Sun 96/96 scene overlays as `gba.ov<N>` programs; m21 gba .9761/.9972 (STATUS.md, GbaOverlays) |
| Import memory | done | mmap'd artifacts plus one parsed-image snapshot handed to workers: peak RSS Dark Cloud 16.0 -> 0.6 GB, Wii RVZ 16.9 -> 1.8 GB, Dark Chronicle OOM -> 0.95 GB; tables identical (STATUS.md, ImageMemory) |
| Switch determinism | done | a deterministic work budget (75M units) replaces the 60 s wall clock, lanes fixed at 4: 0 differing rows between idle and CPU-starved hosts on psv/AW/capcom; the 13 heaviest dispatchers are refused and named as partial; paired imports faster in all 8 pairs (psv 147 -> 91 s, nds 119 -> 68 s); ghidra_opt dbd7e74b (STATUS.md, SwitchDeterminism) |
| GC/Wii DOL discovery | done | sweep entries exempt from span-sharing retraction, DOLs seed data pointers: main recall Skyward Sword .594 -> .989, Galaxy .857 -> .997, NPC Pikmin 2 .701 -> .998, Rock Band 3 .866 -> .987, Strikers Charged .900 -> .997, GC Pikmin 2 .828 -> .9998, Melee/TW04 unchanged; precision 99.35-99.93%; m21 identical (STATUS.md, WiiDiscovery) |
| Per-program cost | done | worker snapshot reuses the importing process's image, SLEIGH decoders pooled, independent programs run side by side (rows identical at any job count): paired, Golden Sun 55.3 -> 12.0 s, Paper Mario 131.4 -> 21.1 s, Mario Party 4 51.1 -> 21.4 s, KH 358/2 Days 66.3 -> 16.6 s, single-program images flat (STATUS.md, ProgramOverhead) |
| Corpus wave (58 games, 9 platforms) | done | `console_research_wave_20261010` (tools 5d47c57f; n=500 x seeds 1,2; 55 headline games): discovery recall vs stock 51 wins / 0 losses / 2 ties (p < 1e-5), winning on every platform; precision vs stock 14/12 (p = 0.42), lost on PS2 (1/5) and PSP (1/3); vs baseline-off precision 20/0 and recall 8/0. Stock DNF on FE Sacred Stones (>4 h), stock crash on KH Chain of Memories; both are labelled rows and in no test (docs/console-research.md "Final run") |
| PS2 discovery | done | alignment fill is no function start, the boundary sweep and data-pointer seeding run for stripped MIPS ELF executables, a frame opener after a `nop` starts a function: recall (wave truth) Fatal Frame .937 -> .996, God Hand .971 -> .998, Persona 4 .986 -> .999, Dark Chronicle .984 -> .999, Dark Cloud .984 -> .999, Digital Devil Saga .985 -> .997, Ratchet & Clank .646 -> .688 (.861 -> .928 on the audited truth), PAL .854 -> .908; uncovered misses of 64+ bytes 167/109/52/43/40/38 -> 1/0/1/0/2/1; functions on fill words 24 -> 1; precision still below stock's (STATUS.md, Ps2Recall; docs/console-research.md "Supplement: PS2 discovery") |
