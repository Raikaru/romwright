# `.vsig` — relocation-masked signature database

Ventris' own container for library function signatures. A record is a byte
pattern, a per-byte compare mask that hides relocated operands, and the
provenance a clean-room project needs: the language the bytes decode in, the
function name, the exact package build the bytes came from, and that package's
license.

The container is deliberately small and fully validated. It carries no index
and no checksum: a matcher builds its own index after loading, and integrity of
a published database belongs to the release artifact manifest
(`packaging/update_manifest.py`).

Reference implementation and the only normative behaviour: `crates/lre-sig`.
Acceptance: `crates/lre-sig/tests/vsig_roundtrip.rs`.

## Layout

All integers are little-endian and unsigned. Offsets are byte offsets.

### Header (16 bytes)

|Offset|Size|Field|Value|
|---|---|---|---|
|0|4|`magic`|`VSIG`|
|4|2|`version`|`1`|
|6|2|`flags`|`0`; reserved, must be zero|
|8|4|`count`|number of records|
|12|4|`payload_len`|total byte length of the records that follow|

### Record (repeated `count` times, immediately after the header)

|Size|Field|Notes|
|---|---|---|
|2|`language_len`|bytes of `language`|
|2|`name_len`|bytes of `name`|
|2|`package_len`|bytes of `package`|
|2|`license_len`|bytes of `license`|
|4|`pattern_len`|bytes of `pattern`, and of `mask`|
|`language_len`|`language`|Ghidra language id, e.g. `x86:LE:64:default`|
|`name_len`|`name`|function name the pattern identifies|
|`package_len`|`package`|exact package build, e.g. `glibc-2.39-1`|
|`license_len`|`license`|SPDX expression for that package|
|`pattern_len`|`pattern`|pattern bytes; zero at masked positions|
|`pattern_len`|`mask`|`0xff` compares the byte, `0x00` ignores it|

A signature matches a byte window when the window is at least `pattern_len`
bytes long and every `0xff`-masked position is equal. Masked positions are
where a relocation, a linker-resolved displacement or an address constant
lands: they carry no identifying information, so the pattern stores zero there.

## Invariants

A file is either canonical or rejected; a decoder never repairs one.

- `magic` is `VSIG`, `version` is `1`, `flags` is zero.
- `language`, `name`, `package` and `license` are non-empty UTF-8 without
  control characters, each at most 65535 bytes.
- `pattern_len` is between 1 and 65536, and `mask` has the same length.
- Every mask byte is exactly `0x00` or `0xff`.
- Every masked pattern byte is `0x00`.
- At least one byte is compared: a fully masked record would match anything.
- Records are strictly ascending by `(language, name, package)`, so a repeated
  key — which would mean two conflicting patterns for one function in one
  package — cannot be encoded.
- `payload_len` equals the bytes the records actually span, and nothing follows
  the payload.

Because masked bytes are normalized and records are ordered,
`encode(decode(bytes)) == bytes` holds for every accepted file: a database
built from the same inputs is byte-identical, which is what continuous
integration compares.

Generators impose stricter policy on top of the format. The container accepts a
single compared byte; a signature that identifies a real function needs far
more, and `Signature::compared_bytes` reports what a record actually carries.

## Provenance rules

`package` and `license` are mandatory because signatures are derived from
someone else's compiled code. A record without an exact package build cannot be
audited, and a record without its license cannot be redistributed. Ventris'
generator records both from the package it opened, never from a guess, and
`docs/third-party.md` lists the packages a shipped database was built from.


## Matching

A record names a function when the byte window at the function's entry
satisfies every compared position of the pattern, in the program's own
language, and the record is at least as long as the function's proven body —
a shorter record would name a function after a fragment of itself. When two
records claim different names for one window the function keeps its own name:
a wrong name costs more than a missing one. `confidence` is the share of the
record that was compared, `compared_bytes / pattern_len`, and a match only
replaces a generated `FUN_*` name; symbol-table and analyst names stay.

Two library functions can have byte-identical bodies once relocated operands
are masked. A record is therefore dropped when another body in the same
package is indistinguishable from it, and every extracted body competes:
exported functions, bodies below the evidence threshold when they are the same
length, and `static` functions, whose names identify nothing but whose bodies
still occupy the image. Omitting that last class was the entire false-positive
population measured on the first run of `benchmarks/match_gate.py` — 7 of 915
matches, 0.77% — every one an exported wrapper naming its `static` twin.

### Measured false-positive rate

`benchmarks/match_gate.py` statically links a corpus source against a pinned
`libc.a`, strips it, imports it with the database built from that same archive,
and checks every match against the unstripped twin's symbols. A match is
correct when its name is one of the symbol names at that address.

|Architecture|Matches|Correct|False positives|Rate|
|---|---|---|---|---|
|AArch64|303|303|0|0.000|
|i386|297|297|0|0.000|
|PowerPC|270|270|0|0.000|
|Total|870|870|0|0.000|

Recorded in `benchmarks/reports/m2-012.json`; the databases are the ones
`benchmarks/reports/m2-011.json` describes. This rate is not an II.3 metric.