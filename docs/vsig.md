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
