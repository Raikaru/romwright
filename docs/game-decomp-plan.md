# Ventris game-decompilation program

Plan of record for making Ventris the best tool for console game
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
emulator when static analysis stalls. Ventris already has the
expensive parts (native SLEIGH/p-code/decompiler, no JVM, a fact store
with provenance, multi-program projects, a JSON API). What it lacks
is exactly the integration surface — and, per platform, three
load-bearing readers/loaders that nobody else has done right.

Three facts from the research shape the whole sequence:

1. **Ventris reads none of the debug/symbol formats decomp projects
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
| P2.2 | decomp.me scratch export (target asm + ctx.c via `type_defs`) + compile-score import; permuter dir export; asm-differ `diff_settings.py` emit; m2c handoff out-of-process only (GPL) | M+S | P1.8 | export→compile round trip returns a score; re-import equals `GET /api/scratch/<slug>` (5 SYNTH fixtures) |
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
| P4.6 | m2c-parity emission layer (clean-room): deterministic temporaries, `/* irregular */` honesty, stack-struct dump, globals emission; div/mod/`cntlzw` canonicalizers | L+L | P2.3–P2.5 | token-diff(Ventris, m2c) < token-diff(stock, m2c) AND objdiff(Ventris C) ≥ objdiff(m2c C) on ≥2/3 of {sm64 IDO fn, pokeemerald agbcc fn, `base.elf` MWCC fn} |

## 4. Sequencing rationale

- P1 is nine S/M items that every later milestone depends on; none
  depends on another except demangle→MAP→prototypes. Run P1.1
  (baselines) first: no gate after it is allowed to lack a stock
  number.
- P2 is chosen by adoption value: symbols in, files out, score up.
  P2.1–P2.2 give a project a reason to open Ventris; P2.3–P2.6 make
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

## 8. Verification discipline

- No milestone lands without its `tests/mX-NNN_*.py|.sh` gate, its
  `benchmarks/reports/<id>.json`, and the matching `<id>-stock.json`.
- Every gate uses `discovery_gate` scoring policy and `stock_key`
  caching so native and stock numbers stay comparable.
- Absent fixtures skip with reason, never pass silently.
- Standing regressions on every commit: `cargo test --workspace`,
  `tests/corpus.sh`, `tests/ppc_sda.sh`,
  `tests/generic_discovery_test.sh`, m10 sweep once P1.2 lands.
