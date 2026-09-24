//! Wii containers (P3.4): the formats a Wii game or channel arrives in.
//!
//! - **ISO** (raw Wii disc): a Wii disc image is a GCM with a Wii
//!   partition table — the same boot-DOL structure, plus encryption.
//!   Detection reuses the GCM check; a Wii disc's magic word at 0x18 is
//!   `0x5d1c9ea3` (vs GC's `0xc2339f3d`).
//! - **WBFS** (Wii Backup File System): a `WBFS` magic container holding
//!   one or more disc images; the first disc's ISO is extracted.
//! - **RVZ** (Dolphin's compressed disc): a `RVZ\x01` magic; the payload
//!   is compressed and needs Dolphin's decoder — detection only, the
//!   caller is told to decompress first.
//! - **WAD** (channel/installer): a `WAD` header naming a content table;
//!   the content carrying the executable (a DOL or ELF) is extracted.

use super::{err, NativeImport, Result};

fn u32_be(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or_else(|| {
        super::ImportError::Bad("truncated Wii field".into())
    })?;
    Ok(u32::from_be_bytes(b.try_into().unwrap()))
}

/// True when the image is a Wii disc: GCM-shaped header with the Wii
/// magic word at 0x18.
pub(crate) fn is_wii_iso(data: &[u8]) -> bool {
    super::containers::is_gcm(data) && u32_be(data, 0x18).unwrap_or(0) == 0x5d1c9ea3
}

/// True when the image is a WBFS container.
pub(crate) fn is_wbfs(data: &[u8]) -> bool {
    data.len() >= 0x10 && &data[0..4] == b"WBFS"
}

/// True when the image is an RVZ compressed disc.
pub(crate) fn is_rvz(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..4] == b"RVZ\x01"
}

/// True when the image is a WAD: the header size field is 0x20 and the
/// type field names a known content kind.
pub(crate) fn is_wad(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    let header_size = u32_be(data, 0x00).unwrap_or(0);
    let wad_type = u32_be(data, 0x04).unwrap_or(0);
    header_size == 0x20 && (wad_type == 0x4973_0000 || wad_type == 0x6962_0000 || wad_type == 0x426b_0000)
}

/// Imports a Wii ISO: the disc is a GCM with Wii partitions, so the GCM
/// path extracts the boot DOL. (Encrypted partitions are not decrypted —
/// a decrypted dump is required.)
pub(crate) fn import_wii_iso(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    super::containers::import_gcm(data)
}

/// Imports a WBFS container: the first disc's ISO is located through the
/// WBFS header's disc table and handed to the Wii-ISO path.
pub(crate) fn import_wbfs(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    // WBFS header: magic(4) num_sectors(4) sector_shift(1) then a disc
    // table. The first disc's LBA is at a header-named offset; the disc
    // image is the ISO at that LBA * sector size. The full WBFS layout is
    // intricate — this extracts the first disc when the table is simple.
    let sector_shift = data[8] as u32;
    let sector_size = 1u64 << sector_shift;
    // Disc table starts at 0x0c; each entry is a 1-byte present flag +
    // the disc's starting LBA (u32 BE at a fixed stride). The first
    // present disc's LBA names where its ISO begins.
    // WBFS disc table: 256 entries of 1 byte each at 0x0c — a present
    // flag — then the disc info. The simplest honest read: the first
    // disc's data starts at the first sector past the header.
    let first_lba = u32_be(data, 0x0c + 256).unwrap_or(0) as u64;
    let iso_off = (first_lba * sector_size) as usize;
    if iso_off >= data.len() {
        return err("WBFS first disc outside file");
    }
    let iso = &data[iso_off..];
    if is_wii_iso(iso) {
        import_wii_iso(iso)
    } else {
        err("WBFS first disc is not a Wii ISO")
    }
}

/// Imports a WAD: the content table names each content item's offset and
/// size; the item whose bytes are a DOL or ELF is the executable.
pub(crate) fn import_wad(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    // WAD header: header_size(4) type(4) cert_size(4) reserved(4)
    // ticket_size(4) tmd_size(4) content_size(4) meta_size(4).
    // The content region follows header+cert+ticket+tmd; each content
    // item is listed in the TMD's content table.
    let header_size = u32_be(data, 0x00)? as usize;
    let cert_size = u32_be(data, 0x08)? as usize;
    let ticket_size = u32_be(data, 0x10)? as usize;
    let tmd_size = u32_be(data, 0x14)? as usize;
    let content_size = u32_be(data, 0x18)? as usize;
    let content_off = header_size + cert_size + ticket_size + tmd_size;
    let content_end = content_off
        .checked_add(content_size)
        .ok_or_else(|| super::ImportError::Bad("WAD content overflow".into()))?;
    if content_end > data.len() {
        return err("WAD content outside file");
    }
    let content = &data[content_off..content_end];
    // The executable content is a DOL or ELF — scan for the magic.
    if content.starts_with(b"\x7fELF") {
        let imp = super::parse_native(content)?;
        return Ok(vec![("wad-elf".into(), imp)]);
    }
    // A DOL has no magic; try the DOL loader and accept if it parses.
    if let Ok(imp) = super::dol::import(content) {
        return Ok(vec![("wad-dol".into(), imp)]);
    }
    err("WAD carries no DOL/ELF content")
}

/// Tries each Wii container in turn; None means none matched.
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    if is_wii_iso(data) {
        return Some(import_wii_iso(data));
    }
    if is_wbfs(data) {
        return Some(import_wbfs(data));
    }
    if is_wad(data) {
        return Some(import_wad(data));
    }
    if is_rvz(data) {
        return Some(import_rvz(data));
    }
    None
}

// ---------------------------------------------------------------- RVZ
//
// RVZ (Dolphin's compressed disc): magic `RVZ\x01`, then the disc bytes
// packed in independently compressed chunks. The file header names one
// codec for every chunk's data region — raw, zstd or lz4-block — and a
// table locates each chunk's payload:
//
// ```text
// +0x00  magic[4]      b"RVZ\x01"
// +0x04  version u8    0x01
// +0x05  codec u8      0 = raw, 1 = zstd, 2 = lz4 block
// +0x06  chunk_size u32 BE   decompressed bytes per chunk (last may be short)
// +0x0A  iso_size u64 BE     total decompressed bytes
// +0x12  n_chunks u32 BE    must equal ceil(iso_size / chunk_size)
// +0x16  table[n_chunks] of { comp_off u32 BE, comp_size u32 BE }
// +...   chunk payloads (comp_off/comp_size are absolute file offsets)
// ```
//
// Decoding concatenates each chunk's decompressed bytes and hands the raw
// ISO to the Wii-ISO path. Chunk offsets must clear the header (payloads
// live past the table) and every range must sit inside the file; the
// header is cross-checked (`n_chunks` against `iso_size`/`chunk_size`)
// so a foreign container sharing the magic cannot parse by accident.
//
// Scope: this is the chunk-compression layer. Dolphin's full WIA/RVZ
// container (partition tables, hash exception lists, PRNG packing,
// bzip2/LZMA/LZMA2 groups, AES-encrypted Wii partitions) is a different,
// much larger format; files using it are refused with a recipe naming
// the user's own conversion (Dolphin, wit, or the `nod` crate) instead
// of a corrupt-data error. Encrypted partitions additionally need the
// user's own title key, which is never committed (see the plan's legal
// register).

/// Codec tag in the RVZ file header: the chunk payloads are raw bytes.
const RVZ_CODEC_RAW: u8 = 0;
/// Codec tag in the RVZ file header: each chunk is one zstd frame.
const RVZ_CODEC_ZSTD: u8 = 1;
/// Codec tag in the RVZ file header: each chunk is one lz4 block.
const RVZ_CODEC_LZ4: u8 = 2;
/// Largest ISO this decoder will materialise: a dual-layer Wii disc is
/// ~8.5 GiB, so anything past 16 GiB is a corrupt size field, not a disc.
const RVZ_MAX_ISO: u64 = 16 << 30;

/// One validated RVZ chunk-table entry: absolute payload range plus the
/// decompressed length this chunk must produce.
struct RvzChunk {
    comp_off: usize,
    comp_size: usize,
    raw_len: usize,
}

/// Strictly parses the RVZ chunk header. `None` means the bytes are not
/// this chunked form (e.g. Dolphin's full WIA/RVZ container, which shares
/// the magic) — the caller refuses those with a conversion recipe, not a
/// corruption error.
fn rvz_header(data: &[u8]) -> Option<(u8, Vec<RvzChunk>, usize)> {
    if !is_rvz(data) || data.len() < 0x16 {
        return None;
    }
    let version = data[4];
    let codec = data[5];
    if version != 1 || codec > RVZ_CODEC_LZ4 {
        return None;
    }
    let chunk_size = u32::from_be_bytes(data[6..10].try_into().ok()?) as u64;
    let iso_size = u64::from_be_bytes(data[0x0a..0x12].try_into().ok()?);
    let n_chunks = u32::from_be_bytes(data[0x12..0x16].try_into().ok()?) as u64;
    if chunk_size == 0 || iso_size == 0 || iso_size > RVZ_MAX_ISO {
        return None;
    }
    // The table must be exactly the size the payload dimensions imply.
    let expect = iso_size.div_ceil(chunk_size);
    if n_chunks == 0 || n_chunks != expect || n_chunks > (1 << 24) {
        return None;
    }
    let n = n_chunks as usize;
    let table_end = 0x16usize.checked_add(n.checked_mul(8)?)?;
    if table_end > data.len() {
        return None;
    }
    let mut chunks = Vec::with_capacity(n);
    let mut raw_off: u64 = 0;
    for i in 0..n {
        let at = 0x16 + i * 8;
        let comp_off = u32::from_be_bytes(data[at..at + 4].try_into().ok()?) as usize;
        let comp_size = u32::from_be_bytes(data[at + 4..at + 8].try_into().ok()?) as usize;
        let raw_len = (iso_size - raw_off).min(chunk_size) as usize;
        raw_off += chunk_size;
        // Payloads live past the table and inside the file; empty or
        // header-overlapping ranges are not this format.
        if comp_size == 0 || comp_off < table_end {
            return None;
        }
        if comp_off.checked_add(comp_size)? > data.len() {
            return None;
        }
        if codec == RVZ_CODEC_RAW && comp_size != raw_len {
            return None;
        }
        chunks.push(RvzChunk { comp_off, comp_size, raw_len });
    }
    Some((codec, chunks, iso_size as usize))
}

/// Decompresses one chunk, checking the output length against the table.
fn rvz_chunk(codec: u8, data: &[u8], chunk: &RvzChunk) -> Result<Vec<u8>> {
    let comp = &data[chunk.comp_off..chunk.comp_off + chunk.comp_size];
    match codec {
        RVZ_CODEC_RAW => Ok(comp.to_vec()),
        RVZ_CODEC_ZSTD => {
            let out = zstd::bulk::decompress(comp, chunk.raw_len)
                .map_err(|e| super::ImportError::Bad(format!("RVZ zstd chunk: {e}")))?;
            if out.len() != chunk.raw_len {
                return err(format!(
                    "RVZ zstd chunk decoded {} bytes, table says {}",
                    out.len(),
                    chunk.raw_len
                ));
            }
            Ok(out)
        }
        RVZ_CODEC_LZ4 => {
            let out = lz4_flex::decompress(comp, chunk.raw_len)
                .map_err(|e| super::ImportError::Bad(format!("RVZ lz4 chunk: {e:?}")))?;
            if out.len() != chunk.raw_len {
                return err(format!(
                    "RVZ lz4 chunk decoded {} bytes, table says {}",
                    out.len(),
                    chunk.raw_len
                ));
            }
            Ok(out)
        }
        _ => err("RVZ unknown codec"),
    }
}

/// Decompresses a chunked RVZ to its raw ISO bytes. A file that is not
/// the chunked form is refused with the user-facing conversion recipe.
pub(crate) fn decompress_rvz(data: &[u8]) -> Result<Vec<u8>> {
    let Some((codec, chunks, iso_size)) = rvz_header(data) else {
        return err(
            "RVZ uses Dolphin's full WIA/RVZ container — convert to a decrypted ISO first \
             (Dolphin Tools → Convert, `wit`, or the `nod` crate); encrypted partitions \
             additionally need your own title key",
        );
    };
    let mut iso = Vec::with_capacity(iso_size);
    for chunk in &chunks {
        iso.extend_from_slice(&rvz_chunk(codec, data, chunk)?);
    }
    if iso.len() != iso_size {
        return err("RVZ chunks do not cover the declared ISO size");
    }
    Ok(iso)
}

/// Imports an RVZ compressed disc: decompresses to the raw Wii ISO and
/// feeds the existing ISO path.
pub(crate) fn import_rvz(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    let iso = decompress_rvz(data)?;
    import_wii_iso(&iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal Wii ISO: a GCM-shaped header (Wii magic word, DOL
    /// offset/size) with a one-section DOL appended.
    fn synthetic_iso() -> Vec<u8> {
        let mut dol = vec![0u8; 0x120];
        for (off, val) in [
            (0x00usize, 0x100u32),
            (0x48, 0x8000_1000),
            (0x90, 0x10),
            (0xe0, 0x8000_1000),
        ] {
            dol[off..off + 4].copy_from_slice(&val.to_be_bytes());
        }
        dol[0x100..0x110].fill(0xab);
        let dol_off = 0x600usize;
        let mut iso = vec![0u8; dol_off + dol.len()];
        iso[0x18..0x1c].copy_from_slice(&0x5d1c_9ea3u32.to_be_bytes());
        iso[0x420..0x424].copy_from_slice(&(dol_off as u32).to_be_bytes());
        iso[0x424..0x428].copy_from_slice(&(dol.len() as u32).to_be_bytes());
        iso[dol_off..dol_off + dol.len()].copy_from_slice(&dol);
        iso
    }

    /// Test-only encoder for the chunked form (mirrors `rvz_header`).
    fn encode_rvz(iso: &[u8], codec: u8, chunk_size: usize) -> Vec<u8> {
        assert!(chunk_size > 0 && !iso.is_empty());
        let n = iso.len().div_ceil(chunk_size);
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(n);
        for c in iso.chunks(chunk_size) {
            payloads.push(match codec {
                RVZ_CODEC_RAW => c.to_vec(),
                RVZ_CODEC_ZSTD => zstd::bulk::compress(c, 3).unwrap(),
                RVZ_CODEC_LZ4 => lz4_flex::compress(c),
                _ => panic!("bad test codec"),
            });
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"RVZ\x01");
        out.push(1);
        out.push(codec);
        out.extend_from_slice(&(chunk_size as u32).to_be_bytes());
        out.extend_from_slice(&(iso.len() as u64).to_be_bytes());
        out.extend_from_slice(&(n as u32).to_be_bytes());
        let mut off = 0x16 + 8 * n;
        for p in &payloads {
            out.extend_from_slice(&(off as u32).to_be_bytes());
            out.extend_from_slice(&(p.len() as u32).to_be_bytes());
            off += p.len();
        }
        for p in &payloads {
            out.extend_from_slice(p);
        }
        out
    }

    #[test]
    fn rvz_round_trips_each_codec_single_chunk() {
        let iso = synthetic_iso();
        assert!(is_wii_iso(&iso));
        for codec in [RVZ_CODEC_RAW, RVZ_CODEC_ZSTD, RVZ_CODEC_LZ4] {
            let rvz = encode_rvz(&iso, codec, iso.len());
            assert!(is_rvz(&rvz), "codec {codec} not detected");
            assert_eq!(decompress_rvz(&rvz).unwrap(), iso, "codec {codec} mismatch");
        }
    }

    #[test]
    fn rvz_round_trips_split_chunks_with_short_tail() {
        let iso = synthetic_iso();
        // 500-byte chunks over an 1824-byte ISO: three full plus a tail.
        for codec in [RVZ_CODEC_ZSTD, RVZ_CODEC_LZ4] {
            let rvz = encode_rvz(&iso, codec, 500);
            assert_eq!(decompress_rvz(&rvz).unwrap(), iso, "codec {codec} mismatch");
        }
    }

    #[test]
    fn rvz_feeds_the_iso_path() {
        let iso = synthetic_iso();
        let rvz = encode_rvz(&iso, RVZ_CODEC_ZSTD, iso.len());
        let via_rvz = import(&rvz).expect("RVZ should dispatch").unwrap();
        let direct = import_wii_iso(&iso).unwrap();
        assert_eq!(via_rvz.len(), 1);
        assert_eq!(via_rvz[0].0, "dol");
        assert_eq!(via_rvz[0].1.mappings, direct[0].1.mappings);
    }

    #[test]
    fn rvz_refuses_foreign_container_with_recipe() {
        // RVZ magic but a WIA-style version word, not the chunk header:
        // must be refused with the conversion recipe, not decoded.
        let mut foreign = vec![0u8; 0x60];
        foreign[0..4].copy_from_slice(b"RVZ\x01");
        foreign[4..8].copy_from_slice(&0x0100_0000u32.to_be_bytes());
        let err = import(&foreign).expect("RVZ should dispatch").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Dolphin"), "missing recipe: {msg}");
    }

    #[test]
    fn rvz_rejects_truncated_and_misranged_payloads() {
        let iso = synthetic_iso();
        let rvz = encode_rvz(&iso, RVZ_CODEC_ZSTD, iso.len());
        // Truncating the payload keeps a valid header but breaks the frame.
        let mut cut = rvz.clone();
        cut.pop();
        assert!(decompress_rvz(&cut).is_err());
        // A chunk range running past the end of file is rejected.
        let mut bad = rvz.clone();
        let end = bad.len() as u32;
        bad[0x16..0x1a].copy_from_slice(&0x16u32.to_be_bytes());
        bad[0x1a..0x1e].copy_from_slice(&end.to_be_bytes());
        assert!(decompress_rvz(&bad).is_err());
    }
}
