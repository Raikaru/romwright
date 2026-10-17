//! Decompressors for the segment formats Nintendo 64 games store in their
//! cartridge: the games' code and data are packed in the ROM and the boot
//! code or a loader unpacks them into RDRAM.
//!
//! Formats and where they are documented (format facts only; no code of any
//! of these projects is used):
//!
//! * **MIO0** -- Hack64 wiki "MIO0 Compression" (`super_mario_64:mio0`): a
//!   16-byte header (`MIO0`, decompressed length, compressed-table offset,
//!   literal-table offset), a layout bitmap (MSB first, 1 = literal byte,
//!   0 = back reference), 16-bit back references (4-bit length + 3,
//!   12-bit distance + 1). Used by Super Mario 64, Mario Kart 64, F-Zero X,
//!   Star Fox 64, Wave Race 64, Pilotwings 64, Beetle Adventure Racing,
//!   Body Harvest, ... (the page's own list).
//! * **Yay0** -- Hack64 wiki "YAY0 Compression" (`paper_mario:yay0`):
//!   MIO0 with the match length extended to 273 by a length byte stored in
//!   the literal table when the 4-bit length is 0. Paper Mario and several
//!   other titles.
//! * **Yaz0** -- nintendo-formats.com "Yaz0" (`libs/sead/yaz0`): a 16-byte
//!   header (`Yaz0`, decompressed length, 8 reserved bytes), then groups of
//!   eight operations led by a code byte (MSB first, 1 = literal byte,
//!   0 = 2- or 3-byte back reference). Ocarina of Time and Majora's Mask
//!   store their code and assets this way.
//! * **Rare "zlib"** -- the n64decomp/perfect_dark tools (`tools/rareunzip`,
//!   `tools/extract-segment`; MIT) document it: a 16-bit magic, then raw
//!   DEFLATE (RFC 1951). `0x1172` (GoldenEye 007) has nothing between the
//!   magic and the stream; `0x1173` (Perfect Dark) carries a 3-byte
//!   big-endian inflated length first. Perfect Dark's game segment is a
//!   table of big-endian u32 offsets (each + 2 addresses a `0x1173` chunk)
//!   followed by 4 KiB pages, each its own chunk (the "paged" form, because
//!   the game demand-loads its code a page at a time through the TLB).
//!
//! Every decoder checks every index and reports the first inconsistency by
//! name: a segment that does not decode is an error to the caller, never a
//! silently short buffer.

use miniz_oxide::inflate::decompress_to_vec_with_limit;

/// How a ROM range is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// The bytes are the segment.
    Raw,
    /// Raw DEFLATE (RFC 1951), no header.
    Deflate,
    /// Rare `0x1172`: magic then raw DEFLATE (GoldenEye 007).
    Rare1172,
    /// Rare `0x1172` as Banjo-Kazooie stores it: magic, a 4-byte big-endian
    /// inflated length, raw DEFLATE. The length is checked like 0x1173's.
    Rare1172Sized,
    /// Rare `0x1173`: magic, 3-byte inflated length, raw DEFLATE (Perfect Dark).
    Rare1173,
    /// A table of u32 offsets to `0x1173` chunks that each inflate to one page.
    Rare1173Pages { page: usize },
    Mio0,
    Yay0,
    Yaz0,
}

impl Codec {
    pub fn name(self) -> &'static str {
        match self {
            Codec::Raw => "raw",
            Codec::Deflate => "deflate",
            Codec::Rare1172 => "rare-1172",
            Codec::Rare1172Sized => "rare-1172-sized",
            Codec::Rare1173 => "rare-1173",
            Codec::Rare1173Pages { .. } => "rare-1173-pages",
            Codec::Mio0 => "mio0",
            Codec::Yay0 => "yay0",
            Codec::Yaz0 => "yaz0",
        }
    }

    /// Unpacks `source`. `limit` bounds the output: a corrupt stream must not
    /// allocate without bound.
    pub fn decode(self, source: &[u8], limit: usize) -> Result<Vec<u8>, String> {
        match self {
            Codec::Raw => Ok(source.to_vec()),
            Codec::Deflate => inflate(source, limit),
            Codec::Rare1172Sized => rare_1172_sized(source, limit).map(|(out, _)| out),
            Codec::Rare1172 => {
                expect_magic(source, 0x1172)?;
                inflate(&source[2..], limit)
            }
            Codec::Rare1173 => rare_1173(source, limit),
            Codec::Rare1173Pages { page } => rare_1173_pages(source, page, limit),
            Codec::Mio0 => mio0(source, limit).map(|(out, _)| out),
            Codec::Yay0 => yay0(source, limit).map(|(out, _)| out),
            Codec::Yaz0 => yaz0(source, limit).map(|(out, _)| out),
        }
    }

    /// `decode`, and how many bytes of `source` the stream occupies: where
    /// a packed file ends when the ROM gives no length (a segment found by
    /// scanning). `Raw` and the paged form occupy all of `source`.
    pub fn decode_extent(self, source: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
        match self {
            Codec::Deflate => inflate_extent(source, limit),
            Codec::Rare1172 => {
                expect_magic(source, 0x1172)?;
                inflate_extent(&source[2..], limit).map(|(out, used)| (out, used + 2))
            }
            Codec::Rare1172Sized => rare_1172_sized(source, limit),
            Codec::Rare1173 => rare_1173(source, limit).map(|out| {
                let used = source.len();
                (out, used)
            }),
            Codec::Mio0 => mio0(source, limit),
            Codec::Yay0 => yay0(source, limit),
            Codec::Yaz0 => yaz0(source, limit),
            Codec::Raw | Codec::Rare1173Pages { .. } => self.decode(source, limit).map(|out| (out, source.len())),
        }
    }
}

fn inflate(source: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    decompress_to_vec_with_limit(source, limit).map_err(|error| format!("deflate: {error}"))
}

/// Inflates a stream whose end the ROM does not give, and reports how many
/// bytes of `source` it used. The output buffer doubles until the stream's
/// final block fits.
fn inflate_extent(source: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
    use miniz_oxide::inflate::TINFLStatus;
    let mut capacity = 0x1_0000usize.min(limit.max(1));
    loop {
        let mut state = DecompressorOxide::new();
        let mut out = vec![0u8; capacity];
        let (status, used, produced) =
            decompress(&mut state, source, &mut out, 0, inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
        match status {
            TINFLStatus::Done => {
                out.truncate(produced);
                return Ok((out, used));
            }
            TINFLStatus::HasMoreOutput if capacity < limit => capacity = (capacity * 2).min(limit),
            TINFLStatus::HasMoreOutput => return Err(format!("deflate: output over the {limit:#x} limit")),
            other => return Err(format!("deflate: {other:?}")),
        }
    }
}

/// Rare `0x1172` with a 4-byte length (Banjo-Kazooie). The declared length
/// must equal what inflates; the second value is the bytes the chunk uses.
fn rare_1172_sized(source: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    expect_magic(source, 0x1172)?;
    let declared = be32(source, 2)?;
    if declared > limit {
        return Err(format!("Rare 0x1172 chunk declares {declared:#x} bytes, over the {limit:#x} limit"));
    }
    let (out, used) = inflate_extent(&source[6..], declared.max(1))?;
    if out.len() != declared {
        return Err(format!("Rare 0x1172 chunk declares {declared:#x} bytes and inflates to {:#x}", out.len()));
    }
    Ok((out, used + 6))
}

fn expect_magic(source: &[u8], magic: u16) -> Result<(), String> {
    match source.get(..2) {
        Some(head) if u16::from_be_bytes([head[0], head[1]]) == magic => Ok(()),
        Some(head) => Err(format!(
            "expected Rare magic {magic:#06x}, found {:#06x}",
            u16::from_be_bytes([head[0], head[1]])
        )),
        None => Err("Rare chunk shorter than its magic".into()),
    }
}

fn be32(source: &[u8], at: usize) -> Result<usize, String> {
    source
        .get(at..at + 4)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
        .ok_or_else(|| format!("truncated: word at {at:#x} past {:#x}", source.len()))
}

/// One `0x1173` chunk. The declared length must equal what inflates: it is
/// the only integrity check the format has.
fn rare_1173(source: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    expect_magic(source, 0x1173)?;
    let head = source.get(2..5).ok_or("Rare 0x1173 chunk shorter than its header")?;
    let declared = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
    if declared > limit {
        return Err(format!("Rare 0x1173 chunk declares {declared:#x} bytes, over the {limit:#x} limit"));
    }
    let out = inflate(&source[5..], declared)?;
    if out.len() != declared {
        return Err(format!("Rare 0x1173 chunk declares {declared:#x} bytes and inflates to {:#x}", out.len()));
    }
    Ok(out)
}

/// A table of u32 offsets (relative to the start of `source`) whose entry
/// plus two addresses a `0x1173` chunk. Each chunk inflates to one page; a
/// page shorter than `page` is the last. The table ends where the first
/// chunk's offset says it does.
fn rare_1173_pages(source: &[u8], page: usize, limit: usize) -> Result<Vec<u8>, String> {
    let table_end = be32(source, 0)?;
    if table_end == 0 || table_end % 4 != 0 || table_end > source.len() {
        return Err(format!("page table ends at {table_end:#x}, outside its {:#x}-byte segment", source.len()));
    }
    let mut out = Vec::new();
    for index in 0..table_end / 4 {
        let start = be32(source, index * 4)? + 2;
        if start >= source.len() {
            break;
        }
        // A zero magic is the padding after the last page.
        if source.get(start..start + 2) == Some(&[0, 0]) {
            break;
        }
        // A chunk ends no later than the next entry, or the segment.
        let end = match be32(source, (index + 1) * 4) {
            Ok(next) if (index + 1) * 4 < table_end && next + 2 > start => (next + 2).min(source.len()),
            _ => source.len(),
        };
        let chunk = rare_1173(&source[start..end], page)
            .map_err(|error| format!("page {index} (at {start:#x}): {error}"))?;
        let last = chunk.len() != page;
        out.extend_from_slice(&chunk);
        if out.len() > limit {
            return Err(format!("pages exceed the {limit:#x}-byte limit"));
        }
        if last {
            break;
        }
    }
    if out.is_empty() {
        return Err("page table has no page".into());
    }
    Ok(out)
}

/// The three-table layout MIO0 and Yay0 share: a layout bitmap at 0x10, a
/// table of 16-bit back references, and a table of literal bytes.
struct Tables<'a> {
    source: &'a [u8],
    size: usize,
    links: usize,
    bytes: usize,
}

fn tables<'a>(source: &'a [u8], magic: &[u8; 4], limit: usize) -> Result<Tables<'a>, String> {
    if source.get(..4) != Some(magic) {
        return Err(format!("missing {} magic", String::from_utf8_lossy(magic)));
    }
    let size = be32(source, 4)?;
    let links = be32(source, 8)?;
    let bytes = be32(source, 12)?;
    if size > limit {
        return Err(format!("declares {size:#x} bytes, over the {limit:#x} limit"));
    }
    if links > source.len() || bytes > source.len() {
        return Err("table offset past the end of the data".into());
    }
    Ok(Tables { source, size, links, bytes })
}

/// Copies `count` bytes from `distance` back, one at a time: a match may
/// overlap its own output, which is how runs are encoded.
fn copy_back(out: &mut Vec<u8>, distance: usize, count: usize, size: usize) -> Result<(), String> {
    if distance > out.len() {
        return Err(format!("back reference reaches {distance:#x} bytes behind {:#x}", out.len()));
    }
    for _ in 0..count.min(size - out.len()) {
        out.push(out[out.len() - distance]);
    }
    Ok(())
}

fn mio0(source: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    let t = tables(source, b"MIO0", limit)?;
    let mut out = Vec::with_capacity(t.size);
    let (mut bit_at, mut link_at, mut byte_at) = (16usize, t.links, t.bytes);
    let mut bits = 0u32;
    let mut left = 0;
    while out.len() < t.size {
        if left == 0 {
            bits = be32(t.source, bit_at).map_err(|_| "layout bitmap runs past the data".to_string())? as u32;
            bit_at += 4;
            left = 32;
        }
        let literal = bits & 0x8000_0000 != 0;
        bits <<= 1;
        left -= 1;
        if literal {
            out.push(*t.source.get(byte_at).ok_or("literal table runs past the data")?);
            byte_at += 1;
        } else {
            let pair = t.source.get(link_at..link_at + 2).ok_or("back-reference table runs past the data")?;
            link_at += 2;
            let value = usize::from(pair[0]) << 8 | usize::from(pair[1]);
            copy_back(&mut out, (value & 0xfff) + 1, (value >> 12) + 3, t.size)?;
        }
    }
    Ok((out, byte_at))
}

fn yay0(source: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    let t = tables(source, b"Yay0", limit)?;
    let mut out = Vec::with_capacity(t.size);
    let (mut bit_at, mut link_at, mut byte_at) = (16usize, t.links, t.bytes);
    let mut bits = 0u32;
    let mut left = 0;
    while out.len() < t.size {
        if left == 0 {
            bits = be32(t.source, bit_at).map_err(|_| "layout bitmap runs past the data".to_string())? as u32;
            bit_at += 4;
            left = 32;
        }
        let literal = bits & 0x8000_0000 != 0;
        bits <<= 1;
        left -= 1;
        if literal {
            out.push(*t.source.get(byte_at).ok_or("literal table runs past the data")?);
            byte_at += 1;
        } else {
            let pair = t.source.get(link_at..link_at + 2).ok_or("back-reference table runs past the data")?;
            link_at += 2;
            let value = usize::from(pair[0]) << 8 | usize::from(pair[1]);
            let count = match value >> 12 {
                0 => {
                    let extra = *t.source.get(byte_at).ok_or("length byte runs past the data")?;
                    byte_at += 1;
                    usize::from(extra) + 0x12
                }
                short => short + 2,
            };
            copy_back(&mut out, (value & 0xfff) + 1, count, t.size)?;
        }
    }
    Ok((out, byte_at))
}

fn yaz0(source: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    if source.get(..4) != Some(b"Yaz0") {
        return Err("missing Yaz0 magic".into());
    }
    let size = be32(source, 4)?;
    if size > limit {
        return Err(format!("declares {size:#x} bytes, over the {limit:#x} limit"));
    }
    let mut out = Vec::with_capacity(size);
    let mut at = 16usize;
    let next = |at: &mut usize| -> Result<u8, String> {
        let byte = *source.get(*at).ok_or("Yaz0 stream ends before its declared length")?;
        *at += 1;
        Ok(byte)
    };
    while out.len() < size {
        let code = next(&mut at)?;
        for bit in (0..8).rev() {
            if out.len() >= size {
                break;
            }
            if code >> bit & 1 == 1 {
                out.push(next(&mut at)?);
            } else {
                let first = next(&mut at)?;
                let second = next(&mut at)?;
                let distance = (usize::from(first & 0xf) << 8 | usize::from(second)) + 1;
                let count = match first >> 4 {
                    0 => usize::from(next(&mut at)?) + 0x12,
                    short => usize::from(short) + 2,
                };
                copy_back(&mut out, distance, count, size)?;
            }
        }
    }
    Ok((out, at))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic mixed-entropy bytes: runs, a repeating phrase and
    /// pseudo-random filler, so every operation kind occurs.
    fn sample(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            match state >> 29 {
                0..=2 => out.extend((0..(state >> 8) % 40).map(|_| (state >> 16) as u8)),
                3..=4 => out.extend_from_slice(b"the quick brown fox "),
                _ => out.extend((0..(state >> 8) % 24).map(|i| (state >> (i % 24)) as u8)),
            }
        }
        out.truncate(len);
        out
    }

    /// Greedy matcher shared by the test encoders: the longest match within
    /// `window` bytes back, at most `max` long, at least 3.
    fn longest(data: &[u8], at: usize, window: usize, max: usize) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        for distance in 1..=window.min(at) {
            let mut n = 0;
            while n < max && at + n < data.len() && data[at + n - distance] == data[at + n] {
                n += 1;
            }
            if n >= 3 && best.is_none_or(|(_, length)| n > length) {
                best = Some((distance, n));
            }
        }
        best
    }

    fn encode_tables(data: &[u8], magic: &[u8; 4], yay: bool) -> Vec<u8> {
        let (mut bits, mut links, mut bytes) = (Vec::<bool>::new(), Vec::<u8>::new(), Vec::<u8>::new());
        let max = if yay { 273 } else { 18 };
        let mut at = 0;
        while at < data.len() {
            match longest(data, at, 4096, max) {
                Some((distance, length)) => {
                    bits.push(false);
                    let d = (distance - 1) as u16;
                    if yay && length > 17 {
                        links.extend_from_slice(&d.to_be_bytes());
                        bytes.push((length - 0x12) as u8);
                    } else {
                        let field = if yay { length - 2 } else { length - 3 } as u16;
                        links.extend_from_slice(&(field << 12 | d).to_be_bytes());
                    }
                    at += length;
                }
                None => {
                    bits.push(true);
                    bytes.push(data[at]);
                    at += 1;
                }
            }
        }
        let mut map = Vec::new();
        for word in bits.chunks(32) {
            let mut value = 0u32;
            for (i, &bit) in word.iter().enumerate() {
                value |= u32::from(bit) << (31 - i);
            }
            map.extend_from_slice(&value.to_be_bytes());
        }
        let links_at = 16 + map.len();
        let bytes_at = links_at + links.len();
        let mut out = magic.to_vec();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&(links_at as u32).to_be_bytes());
        out.extend_from_slice(&(bytes_at as u32).to_be_bytes());
        out.extend(map);
        out.extend(links);
        out.extend(bytes);
        out
    }

    fn encode_yaz0(data: &[u8]) -> Vec<u8> {
        let mut out = b"Yaz0".to_vec();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0; 8]);
        let mut at = 0;
        while at < data.len() {
            let head = out.len();
            out.push(0);
            for bit in (0..8).rev() {
                if at >= data.len() {
                    break;
                }
                match longest(data, at, 4096, 273) {
                    Some((distance, length)) => {
                        let d = (distance - 1) as u16;
                        if length > 17 {
                            out.extend_from_slice(&d.to_be_bytes());
                            out.push((length - 0x12) as u8);
                        } else {
                            out.extend_from_slice(&(((length - 2) as u16) << 12 | d).to_be_bytes());
                        }
                        at += length;
                    }
                    None => {
                        out[head] |= 1 << bit;
                        out.push(data[at]);
                        at += 1;
                    }
                }
            }
        }
        out
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec(data, 6)
    }

    fn rare(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x11, 0x73, (data.len() >> 16) as u8, (data.len() >> 8) as u8, data.len() as u8];
        out.extend(deflate(data));
        out
    }

    #[test]
    fn mio0_roundtrips_a_synthetic_stream() {
        let data = sample(20_000);
        let packed = encode_tables(&data, b"MIO0", false);
        assert!(packed.len() < data.len());
        assert_eq!(Codec::Mio0.decode(&packed, 1 << 20).unwrap(), data);
    }

    #[test]
    fn yay0_roundtrips_and_uses_the_extended_length() {
        let mut data = sample(20_000);
        data.extend(std::iter::repeat_n(7u8, 600)); // a 273-byte match, twice
        let packed = encode_tables(&data, b"Yay0", true);
        assert_eq!(Codec::Yay0.decode(&packed, 1 << 20).unwrap(), data);
    }

    #[test]
    fn yaz0_roundtrips_a_synthetic_stream() {
        let mut data = sample(20_000);
        data.extend(std::iter::repeat_n(0u8, 600));
        let packed = encode_yaz0(&data);
        assert_eq!(Codec::Yaz0.decode(&packed, 1 << 20).unwrap(), data);
    }

    #[test]
    fn mio0_known_stream() {
        // Hand-assembled: "ab" as two literals, then a 4-byte match at
        // distance 2 (length field 1 = 4 bytes) => "ababab".
        let mut packed = b"MIO0".to_vec();
        packed.extend_from_slice(&6u32.to_be_bytes());
        packed.extend_from_slice(&20u32.to_be_bytes()); // links
        packed.extend_from_slice(&22u32.to_be_bytes()); // bytes
        packed.extend_from_slice(&0xC000_0000u32.to_be_bytes()); // layout bits 1,1,0
        packed.extend_from_slice(&[0x10, 0x01]); // length 1+3, distance 1+1
        packed.extend_from_slice(b"ab");
        assert_eq!(Codec::Mio0.decode(&packed, 64).unwrap(), b"ababab");
    }

    #[test]
    fn a_match_may_overlap_its_own_output() {
        let mut packed = b"Yaz0".to_vec();
        packed.extend_from_slice(&9u32.to_be_bytes());
        packed.extend_from_slice(&[0; 8]);
        // literal 'x', then an 8-byte match one byte back.
        packed.extend_from_slice(&[0b1000_0000, b'x', 0x60, 0x00]);
        assert_eq!(Codec::Yaz0.decode(&packed, 64).unwrap(), b"xxxxxxxxx");
    }

    #[test]
    fn rare_1173_checks_its_declared_length() {
        let data = sample(5000);
        let chunk = rare(&data);
        assert_eq!(Codec::Rare1173.decode(&chunk, 1 << 20).unwrap(), data);
        let mut wrong = chunk.clone();
        wrong[4] ^= 1;
        assert!(Codec::Rare1173.decode(&wrong, 1 << 20).is_err());
        let mut magic = chunk;
        magic[1] = 0x72;
        assert!(Codec::Rare1173.decode(&magic, 1 << 20).unwrap_err().contains("magic"));
    }

    #[test]
    fn rare_1172_has_no_length_field() {
        let data = sample(3000);
        let mut chunk = vec![0x11, 0x72];
        chunk.extend(deflate(&data));
        assert_eq!(Codec::Rare1172.decode(&chunk, 1 << 20).unwrap(), data);
    }

    #[test]
    fn rare_1172_sized_checks_its_length_and_reports_where_it_ends() {
        let data = sample(5000);
        let mut chunk = vec![0x11, 0x72];
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunk.extend(deflate(&data));
        let mut padded = chunk.clone();
        padded.extend_from_slice(&[0xAA; 32]);
        let (out, used) = Codec::Rare1172Sized.decode_extent(&padded, 1 << 20).unwrap();
        assert_eq!((out, used), (data.clone(), chunk.len()));
        let mut wrong = chunk.clone();
        wrong[5] = wrong[5].wrapping_add(1);
        let error = Codec::Rare1172Sized.decode(&wrong, 1 << 20).unwrap_err();
        assert!(error.contains("declares"), "{error}");
    }

    #[test]
    fn packed_files_report_how_much_of_the_source_they_use() {
        let data = sample(6000);
        for (codec, packed) in [
            (Codec::Yaz0, encode_yaz0(&data)),
            (Codec::Mio0, encode_tables(&data, b"MIO0", false)),
            (Codec::Yay0, encode_tables(&data, b"Yay0", true)),
        ] {
            let mut padded = packed.clone();
            padded.extend_from_slice(&[0x55; 64]);
            let (out, used) = codec.decode_extent(&padded, 1 << 20).unwrap();
            assert_eq!(out, data, "{}", codec.name());
            // MIO0/Yay0 end at the literal table: within the last 16 bytes of the file.
            assert!(used <= packed.len() && packed.len() - used <= 16, "{} used {used} of {}", codec.name(), packed.len());
        }
        // Raw DEFLATE with trailing bytes reports its own length.
        let packed = deflate(&data);
        let mut padded = packed.clone();
        padded.extend_from_slice(&[0x55; 64]);
        assert_eq!(Codec::Deflate.decode_extent(&padded, 1 << 20).unwrap(), (data, packed.len()));
    }

    #[test]
    fn rare_pages_concatenate_and_stop_at_the_short_page() {
        let data = sample(0x1000 * 3 + 700);
        let pages: Vec<Vec<u8>> = data.chunks(0x1000).map(rare).collect();
        // Entry + 2 addresses a chunk, so the first entry is the table's own
        // length and two bytes of padding separate table and first chunk.
        let table_end = pages.len() * 4;
        let mut segment = vec![0u8; table_end];
        let mut payload = vec![0u8; 2];
        let mut cursor = table_end + 2;
        for (index, page) in pages.iter().enumerate() {
            segment[index * 4..index * 4 + 4].copy_from_slice(&((cursor - 2) as u32).to_be_bytes());
            payload.extend_from_slice(page);
            cursor += page.len();
        }
        segment.extend(payload);
        let out = Codec::Rare1173Pages { page: 0x1000 }.decode(&segment, 1 << 20).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn corrupt_streams_are_errors_not_short_buffers() {
        let data = sample(2000);
        let packed = encode_tables(&data, b"MIO0", false);
        assert!(Codec::Mio0.decode(&packed[..packed.len() - 40], 1 << 20).is_err());
        assert!(Codec::Mio0.decode(&packed, 100).is_err(), "over the limit");
        let yaz = encode_yaz0(&data);
        assert!(Codec::Yaz0.decode(&yaz[..yaz.len() / 2], 1 << 20).is_err());
        assert!(Codec::Yay0.decode(b"Yay0", 64).is_err());
        // A back reference before the start of the output.
        let mut packed = b"Yaz0".to_vec();
        packed.extend_from_slice(&4u32.to_be_bytes());
        packed.extend_from_slice(&[0; 8]);
        packed.extend_from_slice(&[0x00, 0x10, 0x05]);
        assert!(Codec::Yaz0.decode(&packed, 64).unwrap_err().contains("behind"));
    }
}
