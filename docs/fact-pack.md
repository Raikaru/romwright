# Universal fact pack

A shipped, versioned, read-only SQLite file built from the corpus's decomp
repos. Every Romwright import can consult it. It names functions whose
relocation-masked body matches a function some decomp already named, gives their
exact size (boundary evidence), and attaches the donor's prototype.

Reference implementation: `crates/romwright-facts/src/{mask,pack}.rs` (format,
masking, lookup), `crates/romwright-core/src/fact_pack.rs` (apply and build),
`crates/romwright-cli/src/facts.rs` (`romwright-cli facts ...`).

## What the pack holds, and what it does not

The pack holds **no code bytes**. A body is stored as its length plus two
one-way digests of its masked bytes (below), next to a fact: a name, a
`verified` flag, and the donor game. Recovering a function's instructions from
a digest means breaking SHA-1 on a body already stripped of its address
operands; the pack file is not a copy of any donor's code. The build path
(`Pack::add_body`) takes the raw bytes, masks and hashes them in memory, and
never writes them anywhere; `the_pack_stores_digests_not_code` greps a built
pack file for the raw and masked bytes to keep it so.

## Format

`PRAGMA user_version` is the format version (`pack::FORMAT_VERSION`, now 2).
`Pack::open` refuses another version and a `mask_version` other than the build's
`MASK_VERSION`.

| table | columns |
|---|---|
| `meta` | `key PRIMARY KEY, value`: `format`, `mask_version`, `min_body` (32), `built_at` (unix seconds, refreshed by every `add-donor`), `tools`, `gate_short_body` (128), `gate_min_donors` (2) |
| `donors` | `id, game UNIQUE, platform, repo, commit, license, truth_kind, twin_group NULL, compiler NULL` |
| `bodies` | `family, prefix, length, digest, name NULL, donor, verified, program`, indexed on `(family, prefix)` |
| `prototypes` | `name, donor, decl` (primary key `(name, donor)`) |

* `family` is `mips-le`, `mips-be`, `ppc-be`, `arm` or `thumb`.
* `prefix` is the first 8 bytes (big-endian, as an `i64`) of the SHA-1 of the
  masked first 32 bytes. It finds candidates. `digest` is the SHA-1 of the whole
  masked body and confirms them. `length` is the donor body's exact size.
* `program` records which donor program (truth module) contributed a row, so a
  re-run of `add-donor` for the same program replaces its rows instead of
  duplicating them.
* A generic name (`func_XXXXXXXX`, `FUN_`, `sub_`, `fn_`, `lbl_`,
  address-suffixed; `pack::is_generic`) is stored as `name NULL`. The body still
  occupies its digest: it counts for ambiguity and stub detection, and names
  nothing.
* `prototypes.decl` is one C declaration per function name, `ret name(type a, ...)`.
  Apply spells the types in the decompiler's own names and drops a declaration
  that names a type the program's language parser does not know (see
  "Prototypes").
* `donors.compiler` is the donor's `compiler` string from its `truth/meta.json`,
  verbatim. It records which toolchain produced the bytes behind a fact, so a
  match can say which compiler it implies (`Candidate.compilers`,
  `FactPackReport.implied_compiler`).

## Masking (`MASK_VERSION` 1)

`mask::mask(family, bytes)` zeroes the operand bits that hold link-time
addresses and keeps everything else. Build and apply call this one function. It
depends only on its input: a rule that needs the body bounds uses `bytes.len()`,
and the prefix hash is computed over `mask(first 32 bytes)`, so a lookup never
needs the length it is looking for. Any rule change bumps `MASK_VERSION`, and a
pack built under another version is refused.

* **MIPS (LE/BE; the `MIPS`, `r5900`, `Allegrex` and `PSX` languages).** `j`/`jal` targets; `lui` immediates; the 16-bit immediate of
  `addi`, `daddi`, `addiu`, `daddiu`, `ori` and every load/store/cache opcode
  (`0x20..=0x3f`, plus `lq`/`sq`) whose base register is not `$zero` or `$sp`.
  That covers `%hi`/`%lo` halves and `$gp`-relative offsets, and also struct
  field offsets from other bases (a deliberate over-mask: the PS2 probe reached
  1678 agreeing names against 43 disagreeing ones with it). MIPS16/microMIPS has
  no rules and no family.
* **PowerPC (Gekko/Broadway included).** `bl`, `bla`, `ba` targets; a `b` or
  `bc` whose target leaves the body (one that stays inside is position
  independent and kept); the immediate of `addis`/`lis`; the immediate of an
  `addi`, `ori`, load or store whose base register an earlier `lis`/`addis` set
  and no low half has consumed yet (the `@l` half); the displacement of any
  `addi`, load or store based on `r2` or `r13` (small-data areas).
* **ARM.** `bl`/`blx` targets; a `b` that leaves the body; every
  `ldr rd, [pc, #imm]` literal-pool word inside the body whose value is an
  address in the GBA/NDS memory map (`0x01000000..0x04000000` and
  `0x08000000..0x0E000000`: RAM and ROM; I/O, VRAM and palette addresses are
  hardware constants and stay). A pool word is data, never decoded as an
  instruction.
* **Thumb.** Both halves of a `bl`/`blx` pair; a `b`/`b<cond>` that leaves the
  body; literal-pool words as for ARM.

Which instruction set a function is in: on **apply**, the program's stored
`LowBitCodeMode` context at the function's entry (the import's own mode
context); when none sits exactly there, the nearest context before it, and on
ARM both modes are tried. On **build**, the same contexts of the donor project
(truth addresses carry no Thumb bit). `add-donor` reports how many rows had an
exact context and how many were inferred.

## Consensus and abstention

Consensus is computed at query time (`Pack::lookup(family, window,
exclude_games)`), so one pack serves every leave-one-out run: the excluded games
and every donor in their twin group (`donors.twin_group`; Ratchet & Clank NTSC
and PAL, Pikmin 2 on GC and Wii) are removed first.

* Names are compared normalized: leading `_` stripped, case-insensitive. Equal
  normalized names agree; the reported spelling is the most common one, then the
  one with fewest leading underscores.
* More than one normalized non-generic name among the remaining donors is
  **ambiguous**: no name, `ambiguous = true`. (Mostly naming conventions, e.g.
  `FindSubstring` against `strstr`, or mangled against unmangled.)
* A body that occurs more than once inside one donor is a **stub** (return-0
  stubs, thunks) and names nothing for that donor.
* A donor body with only a generic name leaves the candidate unnamed.
* Lookup returns one candidate per matching length, so the exact length (the
  boundary) comes with the name.

### Rename gate

A short body is weak evidence: a candidate whose donor length is below
`gate_short_body` (default 128 bytes) renames only when at least
`gate_min_donors` (default 2) **independent** donors back the consensus name; a
twin group (`donors.twin_group`) counts once. Longer bodies keep the rule above.
The two parameters live in the pack's `meta` table, so a pack can tighten or
loosen its own gate; apply reads them and falls back to the defaults when absent
(`Pack::gate`). `facts add-donor` writes the defaults when it creates a pack, and
`romwright-cli facts set-meta --pack P gate_short_body|gate_min_donors VALUE`
changes one (no other `meta` key is settable). A gated candidate renames nothing,
writes no signature-match row and applies no prototype; the report lists it with
action `gated` (name, donors and `independent` still shown) and counts it in
`gated`, separately from `abstained`. A scan hit is unaffected (it writes
nothing). The gate also holds a would-be `kept_name` match, so weak evidence
leaves no row either. The study behind the defaults is
`benchmarks/reports/fact_pack_gating.md`.

Apply abstains in addition when several local functions hold the same donor
body (the target-side stub rule), and when a function entry matches several
lengths and none is its own size.

## Applying (`Core::apply_fact_pack`)

Probes every local function entry and, with `scan`, every aligned executable
offset no found function covers (4-byte, or 2-byte on ARM where both modes are
tried). Matches are reported as `{address, length, name, donors, ambiguous,
verified, found, our_size, family, compilers, action}`; `action` is one of
`renamed`, `kept_name`, `abstained`, `gated`, `scan_only`.

* **Only generated names change.** A `FUN_` function is renamed. A symbol-table
  or analyst name stays (`kept_name`), exactly as `Core::apply_signatures` and
  `fact_sync` do, and the match is still recorded.
* **Rows reuse the signature-match path.** Each named match is an inferred
  `signature_matches` row owned by source `fact-pack` (a `.vsig` row for the same
  function wins; a re-run replaces only this source's rows), bound to the
  imported input. `package` lists each donor's game, repo and commit; `license`
  lists the donors' licenses verbatim; `compared_bytes` is the donor length;
  confidence is 0.80 for one donor, 0.90 for two, 0.95 for three or more.
* **Scan writes nothing.** A scan hit has no function to name; it is evidence for
  discovery and measurement only.
* **Prototypes** (`fact-pack:prototype`, inferred): the consensus declaration for
  the name among non-excluded donors (majority by type signature, i.e. return
  type plus parameter types with parameter names ignored, `pack::type_key`; a
  tie abstains; the text returned is the most frequent spelling within the
  winning signature, ties by text order), applied through
  the existing library-prototype path (`library_types::signature`). It never
  replaces an assertion or a prototype from the image's own symbols or debug
  stream (`native-import:*`).

## Building (`romwright-cli facts add-donor`)

```
romwright-cli facts add-donor --pack PACK --project DIR --program NAME \
    --truth functions.tsv --donor donor.json [--prototypes protos.tsv] [--json]
```

* `--project`/`--program` is the donor's imported project and the program the
  truth rows belong to (a truth `module` maps to one program; filter the truth
  to it). The bytes of each row are read through that program's own mappings, so
  build and apply see identical bytes.
* `--truth` is `truth/functions.tsv` (`start size name module verified`).
* `--donor` is one JSON object, or a one-element list:
  `{game, platform, repo, commit, license, truth_kind, twin_group?, compiler?}`.
  A missing `twin_group` is filled for the known twin games.
* `--prototypes` is `name<TAB>declaration` lines, or `name = declaration`.
* Rows shorter than `min_body` (32 B) or not fully mapped are skipped; counts are
  reported by reason. Re-running a program replaces what it added. The pack is
  created on first use.

## Provenance and license policy

Every fact carries its donor: `donors` holds game, repo, commit, SPDX license
(`NONE` when the repo has no license file, `NOASSERTION` when GitHub could not
classify one) and truth kind, and every applied row copies the repo, commit and
license of the donors behind it.

**Policy: the shipped pack takes facts from all 48 decomp donors, whatever their
license** (25 permissive, 2 GPL-3.0, 6 NOASSERTION, 15 none), recorded verbatim in
`donors.license`; nothing is filtered by license. This is safe to ship because
the pack contains facts only: a function name, a size, a prototype
declaration, and one-way digests of address-masked bytes, never code, source or
assembly, and decomp repos are used as data, no code is copied from them. Every fact carries its donor's repo, commit and license, so
attribution is complete and a downstream user can see exactly what a name came
from. Dropping a donor is a rebuild without that donor (`--games` subsets the
build).

## Where a user's pack is

1. `--fact-pack PACK` (on `import`), else
2. `ROMWRIGHT_FACT_PACK`, else
3. `$XDG_DATA_HOME/romwright/fact-pack.sqlite` (`~/.local/share` when unset).

`import` applies the pack it finds, to every program of the image. An unreadable
implicit pack is reported on stderr and skipped; an unreadable explicit one is an
error. `ROMWRIGHT_NO_FACT_PACK=1` turns the implicit lookups off (an explicit
`--fact-pack` still applies). The import reuse key gains the pack's identity only
when a pack is in use, so an import with no pack keeps the key it always had.

Research and benchmark harnesses must never pick a pack up implicitly: the pack
is built from the very games they measure. `benchmarks/console_research.py`
(`Tools.env`), `tests/m21-001_real_images.py`, `tests/m22-001_c_output.py` and
`tests/m22-002_ps2_c_output.py` set `ROMWRIGHT_NO_FACT_PACK=1` in their
subprocess environments. The console-research cache key hashes only the
per-config extra environment, not `Tools.env`, so the variable does not change
any existing project directory name.
