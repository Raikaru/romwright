# Nintendo 64: segments, overlays and compression (P3.3)

A retail N64 ROM rarely holds its code where the CPU runs it. The header names
only the first stage (boot address at 0x08); the rest is the game's own
convention: segments packed in the ROM, unpacked into RDRAM by the boot code or
a loader, sometimes paged through the TLB, sometimes swapped in and out of the
same addresses as overlays. The stock Ghidra loader (N64LoaderWV) maps the ROM
linearly at the boot address and says so in its README; the compressed bytes are
then analysed as code.

## What the importer does

`native/n64.rs` recognises a ROM by its configuration word. If the header
(CRC1 at 0x10, CRC2 at 0x14, game code at 0x3b) matches a layout in
`native/n64_layouts.json`, `native/n64_segments.rs` applies it:

* each segment is one or more ROM parts, each stored raw or packed by a codec
  (`native/n64_codec.rs`), decoded and concatenated;
* a segment runs at a fixed address, at the header's boot address, or right
  after an earlier segment (`{"after": "lib", "plus": "0x10000000"}`);
* each decoded segment must have the size the layout declares, every ROM range
  must lie inside the ROM, no two segments may overlap in RDRAM. A layout that
  fails any of that is not applied in part: the ROM imports through the linear
  view and a `partial` diagnostic names the failed check;
* the import is **one program, one module row per segment** (the GameCube REL
  model: `modules` rows, so a call from `game` into `lib` is a
  `module_xrefs` row), plus the cartridge window and the console memory map.

`Layout::from_json` and `n64_overlays::import_with_layout` take a layout the
catalog does not know; `n64_overlays::import_set` places caller-supplied overlays
(`N64Overlay { rom_offset, codec, load_address, size }`) through the same codecs.

Layout JSON (numbers are hex strings or integers):

<!-- not gated: layout file format illustration for a user's own ROM, not a command -->
```json
{"id": "...", "title": "...",
 "detect": {"crc1": "0x41f2b98f", "crc2": "0xb458b466", "game_code": "NPDE"},
 "segments": [
   {"name": "lib", "flags": "rwx", "place": {"at": "0x70001050"}, "size": "0x58f90",
    "kind": "overlay",
    "parts": [{"rom": ["0x1050", "0x3050"], "codec": "raw"},
              {"rom": ["0x3050", "0x39850"], "codec": "rare-1173"}]}]}
```

Codecs: `raw`, `deflate`, `rare-1172`, `rare-1172-sized`, `rare-1173`,
`rare-1173-pages:<page>`, `mio0`, `yay0`, `yaz0`. `kind` defaults to `code`
(executable) or `data`.

## Layout discovery (no catalog entry)

A ROM the catalog does not list goes through `native/n64_discovery.rs`, which
finds the layout in the ROM's own bytes. Nothing in it is per game; every
placement is justified by evidence, and a segment the evidence does not settle
is left out (the ROM keeps the linear view for it).

**The evidence** (`Probe`): a blob linked for address `B` carries `B`. Its `jal`
targets that land inside it hit a function entry (an `addiu sp, sp, -N`
prologue, or the first instruction after a `jr ra` and its delay slot) for the
right `B` and are chance for any other, and its data words that start with `0x80`
are pointers, many of them to its own functions. A base is accepted when at
least three entries agree, most of the calls that land inside agree (a call
always names an entry; a pointer may point at data, so pointers only count
for), and the next-best base has at most half as many. A `jal` has no top
nibble, so `0x8` (cached RDRAM) is claimed only when a pointer, a `lui` constant
or a call from resident code carries it, or a ROM table gives the full address;
code whose only evidence is `jal` is refused (this is why Perfect Dark's TLB
segments at `0x70001050`/`0x7f000000` cannot be discovered).

**The candidates:**

| Source | What it finds | Games |
|---|---|---|
| boot code at ROM `0x1000` | the boot segment; entry point = header word, `-0x100000` or `-0x200000` (n64brew "CIC-NUS"), whichever the boot code's calls agree with; ends where the code stops, runs on over its data up to the next segment that starts within 256 KB, and is cut where another segment starts inside it | all |
| Yaz0 / MIO0 / Yay0 / Rare `0x1172`+length headers | packed files that decode to their declared length and hold code; placed by the evidence with resident code excluded | Zelda games, Star Fox 64, Banjo-Kazooie |
| a pair of ROM offsets next to a RDRAM address (table row `{rom start, rom end, ram}`, or the arguments a DMA call loads with `lui`/`addiu`) | raw ranges; the address is the hint to confirm | Paper Mario, Super Smash Bros., Super Mario 64's engine |
| a ROM offset the boot code loads, neither code nor a known stream | headerless raw DEFLATE | Dr. Mario 64 |

Overlays whose address ranges overlap cannot share an address space. They are
packed into as few programs as hold them (`n64.<first overlay>`, one `modules`
row per overlay), the main program is `n64.main`, and a ROM with no such
overlays is the single program `n64`. Overlay programs hold their own bytes and
no copy of the cartridge. Results, and what is not found and why: STATUS.md,
"N64 layout discovery".

`romwright-core`'s `native::n64_discovery::tests::layout_report` (ignored; set
`N64_ROM`) prints what discovery finds for one ROM; `benchmarks/n64_layout_score.py`
scores an import against a staged truth directory.

## Compression families

| Codec | Format | Documented games |
|---|---|---|
| MIO0 | 16-byte header, layout bitmap, 12-bit distance / 4-bit length (3..18) | Super Mario 64, Mario Kart 64, F-Zero X, Star Fox 64, Wave Race 64, Pilotwings 64, Beetle Adventure Racing, Body Harvest (Hack64 wiki's list) |
| Yay0 | MIO0 with lengths to 273 via a length byte | Paper Mario "and many other N64 games" (Hack64 wiki) |
| Yaz0 | code-byte groups, 12-bit distance, length to 273 | Ocarina of Time, Majora's Mask (nintendo-formats.com) |
| Rare `0x1172` | magic + raw DEFLATE | GoldenEye 007 (decomp `tools/rareunzip`) |
| Rare `0x1172` + length (`rare-1172-sized`) | magic + 4-byte big-endian inflated length + raw DEFLATE; the length is checked against what inflates | Banjo-Kazooie (measured on the ROM: each stream discovery places inflates to its declared length) |
| Rare `0x1173` | magic + 3-byte length + raw DEFLATE; the game segment is a table of offsets to 4 KiB chunk pages | Perfect Dark |

Tested on synthetic streams (`n64_codec` unit tests: encoders in the test
module round-trip; hand-assembled MIO0/Yaz0 streams; overlapping matches;
declared-length mismatch; truncated and out-of-range streams are errors). Not
covered: other publishers' own LZ variants, and Rare games other than the two
above (the same family is reported, not exercised here).

## Perfect Dark NTSC final (the one shipped layout)

Header CRCs `41f2b98f b458b466`, code `NPDE`, ROM md5 `e03b088b...` (the decomp's
ntsc-final). Source of the layout: `ld/pd.ld`, `tools/extract*` of
`n64decomp/perfect_dark` (MIT), every number re-measured on the ROM.

| Segment | ROM | RAM | Stored |
|---|---|---|---|
| preamble | 0x1000..0x1050 | 0x80001000 (boot address) | raw |
| lib-boot | 0x1050..0x3050 | 0x80001050 | raw; the preamble calls `vm_boot` here before the TLB maps the lib |
| lib | 0x1050..0x39850 | 0x70001050 | first 0x2000 raw, then Rare 0x1173 (0x58f90 bytes) |
| data | 0x39850..0x4e850 | 0x80059fe0 (after lib, KSEG0) | Rare 0x1173 (0x30e40 bytes) |
| inflate | 0x4e850..0x4fc40 | 0x70200000 | raw |
| game | 0x4fc40..0x194b20 | 0x7f000000 | paged Rare 0x1173 (0x1b99e0 bytes) |

Limits: the other five PD revisions have different `data`/`game` offsets (listed
in the decomp's `tools/extract`); they are not in the catalog because no ROM or
CRC for them was available to verify. `bss` is not in the ROM and is not mapped.
The game segment is demand-paged through the TLB at run time; it is mapped flat,
which is how the linker addresses it.

Perfect Dark's layout cannot come from discovery: its library and game run at
TLB-mapped addresses (`0x7...`), which no `jal` or data word of the ROM
carries, and the game segment is a table of 4 KiB pages. The catalog entry is
therefore not redundant. Other games' overlay tables are not mined; discovery
places an overlay when the overlay's own bytes (or a ROM row naming it with an
address) prove its address.

## Measurement

`benchmarks/n64_segments_score.py` scores an import against the PD truth
(`benchmarks/pd_ido_truth.py`) and stock Ghidra. `benchmarks/n64_layout_score.py`
scores an import of any staged N64 image against its `layout.json` /
`functions.tsv` truth (layout recovery, function recall and precision per module
class, wrong-vram placements), with a before/after table and paired wall times
from `benchmarks/n64_layout_run.py`. Results in STATUS.md and
`benchmarks/reports/n64_layout_discovery.json`.
