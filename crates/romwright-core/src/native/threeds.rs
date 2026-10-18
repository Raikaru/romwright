//! Nintendo 3DS container family: NCCH executables, NCSD cartridges, CIA installers.
//!
//! Format facts are ported from public documentation; every line of code is
//! written fresh for this loader (clean-room):
//!
//! - 3dbrew "NCCH": NCCH header field offsets, the 8 `ncchflag` bytes
//!   (crypto-method slot select at [3], content platform at [4],
//!   form/type at [5], unit-size shift at [6], FixedCryptoKey/NoCrypto bits
//!   at [7]), the AES-128-CTR region counters (version 0/2: reversed
//!   partition id in CTR[0..8] plus the region type byte in CTR[8] with
//!   1 = exheader, 2 = ExeFS, 3 = RomFS; version 1: partition id in
//!   CTR[0..8] plus the region byte offset big-endian in CTR[12..16]), and
//!   the key groups (bootrom slot 0x2C primary key, ncchflag[3]-selected
//!   secondary slot, FixedCryptoKey fixed keys, NoCrypto plaintext).
//! - 3dbrew "CCI"/"NCSD": NCSD header offsets, the 8-entry partition table
//!   of (offset, size) media-unit pairs at 0x120, media-unit size from
//!   NCSD flags[6].
//! - 3dbrew "CIA" + "Title metadata": the little-endian CIA header chain
//!   (header 0x2020, cert chain, ticket, TMD, content, meta) with 64-byte
//!   section alignment, TMD signature-size table and content-chunk records,
//!   CBC content crypto keyed by the ticket title key.
//! - 3dbrew "ExeFS": the 0x200-byte ExeFS header (10 file headers of
//!   name/offset/size, offsets relative past the header, reversed SHA-256
//!   table), `.code` holding raw ARM11 code/data.
//! - gbatek "3DS Files - NCCH Format / Extended Header / ExeFS / LZ
//!   Decompression Functions" (Martin Korth / no$gba docs): the same header
//!   offsets, the exheader SCI code-set info (text/ro/data addresses and
//!   sizes, stack, BSS) with the `.code` compression flag at exheader+0x0D
//!   bit 0, and the backwards LZSS ("LZrev") footer algorithm used for
//!   compressed `.code`.
//! - ctrtool (3dshax/ctr, `ncch.c`/`exefs.c`/`lzss.c`/`ncsd.c`/`cia.c`/
//!   `tmd.c`): behavioural reference for the key-selection order
//!   (exheader-program-id match means an already-decrypted dump, then
//!   NoCrypto, then FixedCryptoKey with the zeros key for non-system
//!   titles, otherwise console-provisioned slot keys), the LZrev match
//!   form (`size = (segment >> 12) + 3`, `distance = (segment & 0xFFF) + 2`,
//!   control bits MSB-first), and the CIA 64-byte section walk with
//!   contents packed consecutively in chunk-record order.
//!
//! What this loader does not do, deliberately:
//!
//! - No RSA/SHA verification (signatures and superblock hashes are not
//!   needed to map code, and the hashes cover cleartext we may not have).
//! - No RomFS parsing (data-only filesystem; this loader maps code).
//! - No retail slot-key / common-key / title-key crypto: the bootrom
//!   keyslots (0x2C/0x25/0x18/0x1B), the CIA common key and ticket title
//!   keys are console-provisioned secrets, so content needing them is
//!   reported as such instead of decrypted with a wrong key. The only
//!   embedded key is the documented all-zeros FixedCryptoKey for
//!   non-system titles (3dbrew: the fixed key "for the rest"), plus the
//!   public counter/key-derivation structure.
//! - No hash verification of ExeFS entries.

use super::{crypto, err, Mapping, NativeFunction, NativeImport, Result};

/// ARM11 MPCore: the CXI `.code` instruction set.
const LANGUAGE: &str = "ARM:LE:32:v6";
/// Base media-unit size; scaled by the flags[6] shift (see `media_unit`).
const UNIT_BASE: u64 = 0x200;
/// Largest accepted decompressed `.code` (real codes are a few MiB).
const MAX_CODE: u64 = 64 << 20;

/// NCCH flag bits in `ncchflag[7]` (3dbrew "NCCH").
const FLAG_FIXEDKEY: u8 = 0x01;
const FLAG_NOCRYPTO: u8 = 0x04;

/// CTR region-type bytes for the version-0/2 counter (3dbrew "NCCH").
const CTR_EXHEADER: u8 = 1;
const CTR_EXEFS: u8 = 2;

/// The documented fixed key for non-system FixedCryptoKey titles: sixteen
/// zero bytes (3dbrew "NCCH": one fixed key for system titles, "and one for
/// the rest ('zeros' key)"). System-fixed and slot keys are not public and
/// are never embedded here.
const ZEROS_KEY: [u8; 16] = [0; 16];

fn u16le(data: &[u8], off: usize) -> Result<u16> {
    let b = data
        .get(off..off + 2)
        .ok_or_else(|| super::ImportError::Bad("truncated 3DS header".into()))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32le(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or_else(|| super::ImportError::Bad("truncated 3DS header".into()))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64le(data: &[u8], off: usize) -> Result<u64> {
    let b = data
        .get(off..off + 8)
        .ok_or_else(|| super::ImportError::Bad("truncated 3DS header".into()))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn u16be(data: &[u8], off: usize) -> Result<u16> {
    let b = data
        .get(off..off + 2)
        .ok_or_else(|| super::ImportError::Bad("truncated 3DS header".into()))?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn u32be(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or_else(|| super::ImportError::Bad("truncated 3DS header".into()))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64be(data: &[u8], off: usize) -> Result<u64> {
    let b = data
        .get(off..off + 8)
        .ok_or_else(|| super::ImportError::Bad("truncated 3DS header".into()))?;
    Ok(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// True when `data` starts with an NCCH image: `NCCH` magic at 0x100.
pub(crate) fn is_ncch(data: &[u8]) -> bool {
    data.len() >= 0x200 && data[0x100..0x104] == *b"NCCH"
}

/// True when `data` is an NCSD cartridge: `NCSD` magic at 0x100.
pub(crate) fn is_ncsd(data: &[u8]) -> bool {
    data.len() >= 0x104 && data[0x100..0x104] == *b"NCSD"
}

/// Files smaller than this are read whole: there is nothing worth leaving out.
const PROGRAM_VIEW_MIN: u64 = 64 << 20;

/// The program part of a large NCCH (`.cxi`) or NCSD (`.3ds`/`.cci`) file: what
/// the ARM11 program is loaded from, which is a few megabytes of a card whose
/// RomFS is gigabytes. An NCCH keeps its header, exheader and ExeFS at their
/// offsets and ends after the ExeFS, its header's content size cut to match and
/// its RomFS fields cleared. An NCSD keeps its header and, back to back, the
/// program view of every partition that has an ExeFS, with the partition table
/// rewritten to their new offsets (an NCCH's own offsets are relative to its
/// start, so its ExeFS counters are unchanged). The result is a container the
/// loaders read like the original. `None`: not one of these, a CIA, or small.
pub fn program_view(path: &std::path::Path) -> std::io::Result<Option<Vec<u8>>> {
    program_view_from(path, PROGRAM_VIEW_MIN)
}

fn program_view_from(path: &std::path::Path, min_length: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    if length < min_length {
        return Ok(None);
    }
    let mut header = [0u8; 0x200];
    if file.read_exact(&mut header).is_err() {
        return Ok(None);
    }
    // Every range is checked against the file before anything is allocated: a
    // header's offsets and sizes are untrusted.
    let mut read_at = |offset: u64, size: u64| -> std::io::Result<Vec<u8>> {
        if !offset.checked_add(size).is_some_and(|end| end <= length) {
            return Err(invalid_range("a range lies beyond the end of the file"));
        }
        let mut out = vec![0u8; usize::try_from(size).map_err(|_| invalid_range("a range is too large"))?];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut out)?;
        Ok(out)
    };
    let word = |data: &[u8], at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as u64;
    if is_ncch(&header) {
        return Ok(Some(ncch_view(&mut read_at, 0, length)?.unwrap_or_default()).filter(|view| !view.is_empty()));
    }
    if !is_ncsd(&header) {
        return Ok(None);
    }
    let unit = 0x200u64 << header[0x188 + 6].min(8);
    let first = (0..8).map(|i| word(&header, 0x120 + i * 8)).filter(|&o| o > 0).min().unwrap_or(0) * unit;
    if first == 0 || first > length {
        return Ok(None);
    }
    let mut out = read_at(0, first)?;
    for index in 0..8 {
        let (offset, size) = (word(&out, 0x120 + index * 8) * unit, word(&out, 0x124 + index * 8) * unit);
        // An NCCH may not reach past its own partition.
        let view = if size == 0 { None } else { ncch_view(&mut read_at, offset, offset.saturating_add(size))? };
        let (new_offset, new_size) = match view {
            Some(view) => {
                let at = out.len() as u64;
                out.extend_from_slice(&view);
                out.resize(out.len().next_multiple_of(unit as usize), 0);
                (at / unit, view.len() as u64 / unit)
            }
            None => (0, 0),
        };
        out[0x120 + index * 8..0x124 + index * 8].copy_from_slice(&(new_offset as u32).to_le_bytes());
        out[0x124 + index * 8..0x128 + index * 8].copy_from_slice(&(new_size as u32).to_le_bytes());
    }
    let total = out.len() as u64 / unit;
    out[0x104..0x108].copy_from_slice(&(total as u32).to_le_bytes());
    Ok(Some(out))
}

fn invalid_range(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("malformed 3DS image: {message}"))
}

/// The program view of the NCCH at `offset` (see [`program_view`]), `None`
/// when it is not an NCCH or has no ExeFS (a CFA: manual, update data).
/// `limit` is the end of the container it must fit in: its partition in an
/// NCSD, the file for a bare NCCH. A header that points outside it is an error.
fn ncch_view(
    read_at: &mut dyn FnMut(u64, u64) -> std::io::Result<Vec<u8>>,
    offset: u64,
    limit: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    if limit.saturating_sub(offset) < 0x200 {
        return Err(invalid_range("an NCCH is smaller than its header"));
    }
    let header = read_at(offset, 0x200)?;
    if !is_ncch(&header) {
        return Ok(None);
    }
    let parsed = parse_ncch_header(&header).map_err(|e| invalid_range(&e.to_string()))?;
    let unit = ncch_media_unit(&parsed).map_err(|e| invalid_range(&e.to_string()))?;
    let (exefs_offset, exefs_size) = (parsed.exefs_off_units as u64 * unit, parsed.exefs_size_units as u64 * unit);
    if exefs_size == 0 {
        return Ok(None);
    }
    let end = (exefs_offset + exefs_size).max(0x200 + parsed.exheader_size as u64).next_multiple_of(unit);
    if end > limit - offset {
        return Err(invalid_range("an NCCH's ExeFS lies beyond its partition"));
    }
    let mut view = read_at(offset, end)?;
    view[0x104..0x108].copy_from_slice(&((end / unit) as u32).to_le_bytes());
    // RomFS offset, size and hash-region size.
    view[0x1B0..0x1BC].fill(0);
    Ok(Some(view))
}

/// True when `data` is a CIA installer: archive header size 0x2020 with
/// type 0 / version 1 (the same two-field check `xbox_3ds::is_cia` uses).
pub(crate) fn is_cia(data: &[u8]) -> bool {
    data.len() >= 0x10
        && data[0..4] == [0x20, 0x20, 0x00, 0x00]
        && data[4..8] == [0x00, 0x00, 0x01, 0x00]
}

/// Tries each 3DS container in turn; None means none matched.
#[cfg(test)]
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    import_with(data, &super::keys::KeyStore::empty())
}

/// `import` with a user-supplied key store. A `slot0xNN`/`slotNN` key (the
/// bootrom keyslot the ncchflag selects) or `fixed_system` (the system fixed
/// key) from an `aes_keys.txt`/`boot9` dump reaches the NCCH decrypt; absent,
/// the console-provisioned key-gap error is unchanged.
pub(crate) fn import_with(
    data: &[u8],
    keys: &super::keys::KeyStore,
) -> Option<Result<Vec<(String, NativeImport)>>> {
    if is_cia(data) {
        return Some(import_cia(data, keys));
    }
    if is_ncsd(data) {
        return Some(import_ncsd_with(data, keys));
    }
    if is_ncch(data) {
        return Some(import_ncch_with(data, keys));
    }
    None
}

// --------------------------------------------------------------- NCCH

/// The NCCH header fields this loader reads (all little-endian file
/// offsets from the NCCH start; 3dbrew "NCCH" / gbatek NCCH format).
struct NcchHeader {
    content_units: u32,
    partition_id: [u8; 8],
    version: u16,
    program_id: [u8; 8],
    exheader_size: u32,
    flags: [u8; 8],
    exefs_off_units: u32,
    exefs_size_units: u32,
}

fn parse_ncch_header(ncch: &[u8]) -> Result<NcchHeader> {
    if ncch.len() < 0x200 || ncch[0x100..0x104] != *b"NCCH" {
        return err("not an NCCH image");
    }
    let mut partition_id = [0u8; 8];
    partition_id.copy_from_slice(&ncch[0x108..0x110]);
    let mut program_id = [0u8; 8];
    program_id.copy_from_slice(&ncch[0x118..0x120]);
    let mut flags = [0u8; 8];
    flags.copy_from_slice(&ncch[0x188..0x190]);
    Ok(NcchHeader {
        content_units: u32le(ncch, 0x104)?,
        partition_id,
        version: u16le(ncch, 0x112)?,
        program_id,
        exheader_size: u32le(ncch, 0x180)?,
        flags,
        exefs_off_units: u32le(ncch, 0x1A0)?,
        exefs_size_units: u32le(ncch, 0x1A4)?,
    })
}

/// Media-unit size in bytes: version 1 counts bytes, versions 0/2 scale
/// 0x200 by flags[6] (`0x200 * 2^flags[6]`, 3dbrew "NCCH").
fn ncch_media_unit(header: &NcchHeader) -> Result<u64> {
    if header.version == 1 {
        return Ok(1);
    }
    if header.version != 0 && header.version != 2 {
        return err(format!("unsupported NCCH version {}", header.version));
    }
    if header.flags[6] > 8 {
        return err("NCCH content-unit shift out of range");
    }
    UNIT_BASE
        .checked_mul(1u64 << header.flags[6])
        .ok_or_else(|| super::ImportError::Bad("NCCH media unit overflow".into()))
}

/// ctrtool `programid_is_system`: system titles carry the category bit in
/// the high program-id word.
fn program_id_is_system(program_id: &[u8; 8]) -> bool {
    let hi = u32::from_le_bytes([program_id[4], program_id[5], program_id[6], program_id[7]]);
    (hi >> 14) == 0x10 && (hi & 0x10) != 0
}
/// The AES-128-CTR initial counter for an NCCH region, per 3dbrew "NCCH"
/// (and ctrtool `ncch_get_counter`). Version 0/2 lays the reversed
/// partition id into CTR[0..8] and the region-type byte into CTR[8];
/// `crypto::ctr_counter` already builds `nonce ++ BE64(block)`, so with a
/// whole-region decrypt starting at block 0 patching CTR[8] to the region
/// type yields exactly the documented counter. Version 1 lays the
/// partition id into CTR[0..8] and the region byte offset big-endian into
/// CTR[12..16], which that helper cannot express, so it is built directly.
fn ncch_counter(
    version: u16,
    partition_id: &[u8; 8],
    region: u8,
    region_base: u64,
) -> Result<[u8; 16]> {
    if version == 1 {
        if region_base > u32::MAX as u64 {
            return err("NCCH v1 region offset out of range");
        }
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(partition_id);
        counter[12..].copy_from_slice(&(region_base as u32).to_be_bytes());
        return Ok(counter);
    }
    // The counter carries the partition id byte-reversed.
    let mut nonce = *partition_id;
    nonce.reverse();
    let mut counter = crypto::ctr_counter(&nonce, 0);
    counter[8] = region;
    Ok(counter)
}

fn ctr_decrypt(key: &[u8; 16], counter: &[u8; 16], bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    crypto::aes128_ctr(key, counter, &mut out);
    out
}

/// The backwards LZSS ("LZrev") covering compressed `.code`, after gbatek's
/// "LZ Decompression Functions" footer layout with ctrtool `lzss_decompress`
/// as the normative decoder (control bits MSB-first, match length
/// `(segment >> 12) + 3`, match distance `(segment & 0xFFF) + 2`, copying
/// from already-written bytes ahead while walking downward).
///
/// Layout: payload units (literals and 2-byte matches under flag bytes)
/// from `stop` upward, then a footer of `footer_len` bytes holding the
/// 24-bit payload-plus-footer length, the footer length, and the extra
/// (decompressed − compressed) length. Bytes below `stop` are an
/// uncompressed head copied verbatim, so a correct blob leaves the write
/// cursor exactly at `stop`.
fn lzrev_decompress(comp: &[u8]) -> Result<Vec<u8>> {
    if comp.len() < 9 {
        return err("LZrev .code too short for a footer");
    }
    let n = comp.len();
    let top = u32::from_le_bytes([comp[n - 8], comp[n - 7], comp[n - 6], comp[n - 5]]);
    let extra = u32::from_le_bytes([comp[n - 4], comp[n - 3], comp[n - 2], comp[n - 1]]) as u64;
    let dec_len = extra
        .checked_add(n as u64)
        .ok_or_else(|| super::ImportError::Bad("LZrev size overflow".into()))?;
    if dec_len > MAX_CODE {
        return err("LZrev .code decompresses past the size cap");
    }
    let footer_len = (top >> 24) as usize;
    let comp_len = (top & 0x00FF_FFFF) as usize;
    if footer_len < 8 || footer_len >= n {
        return err("LZrev footer length out of range");
    }
    // `comp_len` spans payload plus footer (stop == 0 packs the whole
    // blob); at least one payload byte must precede the footer.
    if comp_len <= footer_len || comp_len > n {
        return err("LZrev compressed length out of range");
    }
    let dec_len = dec_len as usize;
    let stop = n - comp_len;
    let mut out = vec![0u8; dec_len];
    out[..n].copy_from_slice(comp);
    let mut pos = dec_len;
    let mut index = n - footer_len;
    while index > stop {
        index -= 1;
        let mut control = comp[index];
        for _ in 0..8 {
            if index <= stop {
                break;
            }
            if pos == 0 {
                return err("LZrev .code overruns its declared size");
            }
            if control & 0x80 != 0 {
                if index < 2 {
                    return err("LZrev match runs past the payload start");
                }
                index -= 2;
                let segment = u16::from_le_bytes([comp[index], comp[index + 1]]);
                let seg_len = ((segment >> 12) & 0xF) as usize + 3;
                let seg_off = (segment & 0x0FFF) as usize + 2;
                for _ in 0..seg_len {
                    let src = pos
                        .checked_add(seg_off)
                        .ok_or_else(|| super::ImportError::Bad("LZrev offset overflow".into()))?;
                    if src >= dec_len {
                        return err("LZrev match reads past the output end");
                    }
                    if pos == 0 {
                        return err("LZrev .code overruns its declared size");
                    }
                    pos -= 1;
                    out[pos] = out[src];
                }
            } else {
                index -= 1;
                pos -= 1;
                out[pos] = comp[index];
            }
            control <<= 1;
        }
    }
    if pos != stop {
        return err("LZrev .code length does not match its footer");
    }
    Ok(out)
}

/// One ExeFS file entry: 8-byte name, offset and size past the 0x200-byte
/// header (3dbrew "ExeFS").
struct ExefsFile {
    name: [u8; 8],
    offset: u32,
    size: u32,
}

fn parse_exefs(exefs: &[u8]) -> Result<Vec<ExefsFile>> {
    if exefs.len() < 0x200 {
        return err("ExeFS smaller than its 0x200-byte header");
    }
    let mut files = Vec::new();
    for i in 0..10 {
        let at = i * 16;
        let mut name = [0u8; 8];
        name.copy_from_slice(&exefs[at..at + 8]);
        let offset = u32le(exefs, at + 8)?;
        let size = u32le(exefs, at + 12)?;
        files.push(ExefsFile { name, offset, size });
    }
    Ok(files)
}

/// Imports one NCCH slice. `base` is the NCCH start within the original
/// input, so mappings keep absolute file offsets. Returns `Ok(None)` for a
/// well-formed NCCH that carries no ARM11 `.code` (a CFA data archive):
/// container walkers skip those, while a lone CFA is reported by the
/// single-image wrapper.
fn import_ncch_slice(ncch: &[u8], base: u64, keys: &super::keys::KeyStore) -> Result<Option<NativeImport>> {
    let header = parse_ncch_header(ncch)?;
    let unit = ncch_media_unit(&header)?;
    let mul = |units: u32| -> Result<u64> {
        (units as u64)
            .checked_mul(unit)
            .ok_or_else(|| super::ImportError::Bad("NCCH region size overflow".into()))
    };
    let limit = if header.content_units == 0 {
        ncch.len() as u64
    } else {
        let total = mul(header.content_units)?;
        if total > ncch.len() as u64 {
            return err("NCCH content size overruns the input");
        }
        total
    };
    let within = |start: u64, len: u64| -> Result<bool> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| super::ImportError::Bad("NCCH region overflow".into()))?;
        Ok(end <= limit)
    };

    // Exheader region (decrypted below when needed). The SCI code-set info
    // needs the first 0x40 bytes of it.
    let exheader_raw: Option<&[u8]> = if header.exheader_size > 0 {
        let size = header.exheader_size as u64;
        if !within(0x200, size)? {
            return err("NCCH exheader runs past the content end");
        }
        if size < 0x40 {
            return err("NCCH exheader too small for code-set info");
        }
        Some(&ncch[0x200..0x200 + size as usize])
    } else {
        None
    };
    // Key selection mirrors ctrtool `ncch_determine_key`: an exheader whose
    // ARM11 program id already matches the header is an already-decrypted
    // dump, then NoCrypto, then the zeros fixed key for non-system titles.
    // Slot-key and system-fixed content resolve through `keys` when the user
    // supplied them.
    let raw_program_id_matches = exheader_raw.map_or(false, |raw| {
        ncch.len() >= 0x408 && raw.len() >= 0x208 && raw[0x200..0x208] == header.program_id
    });

    let key: Option<[u8; 16]> = if raw_program_id_matches || header.flags[7] & FLAG_NOCRYPTO != 0 {
        None
    } else if header.flags[7] & FLAG_FIXEDKEY != 0 {
        if program_id_is_system(&header.program_id) {
            // The system fixed key is console-provisioned; a user's
            // `fixed_system`/`slot0x..` dump supplies it when present.
            match keys.get_array::<16>("fixed_system")
                .or_else(|| keys.get_array::<16>("system_fixed_key"))
            {
                Some(k) => Some(k),
                None => return err(
                    "NCCH uses the system fixed key, which is console-provisioned; \
                     supply it via --keys (fixed_system = <hex>)",
                ),
            }
        } else {
            Some(ZEROS_KEY)
        }
    } else {
        // Secure slot crypto: the ncchflag[3] keyslot. A user's aes_keys.txt
        // names it `slot0xNN` (boot9 dump convention).
        let slot = header.flags[3];
        let named = keys.get_array::<16>(&format!("slot0x{slot:02x}"))
            .or_else(|| keys.get_array::<16>(&format!("slot{slot:02x}")))
            .or_else(|| keys.get_array::<16>(&format!("slot0x{slot:02X}")));
        match named {
            Some(k) => Some(k),
            None => return err(format!(
                "NCCH uses secure slot crypto (keyslot {slot:#04x}); \
                 supply the bootrom slot key via --keys (slot0x{slot:02x} = <hex>)",
            )),
        }
    };

    let exefs_start = mul(header.exefs_off_units)?;
    let exefs_len = mul(header.exefs_size_units)?;
    if header.exefs_size_units != 0 {
        if exefs_start < 0x200 {
            return err("NCCH ExeFS overlaps the NCCH header");
        }
        if !within(exefs_start, exefs_len)? {
            return err("NCCH ExeFS runs past the content end");
        }
    }
    let exheader_blob: Vec<u8> = match (key, exheader_raw) {
        (Some(k), Some(raw)) => {
            let counter = ncch_counter(header.version, &header.partition_id, CTR_EXHEADER, 0x200)?;
            ctr_decrypt(&k, &counter, raw)
        }
        (_, Some(raw)) => raw.to_vec(),
        (_, None) => Vec::new(),
    };
    let exefs_blob: Vec<u8> = if exefs_len == 0 {
        Vec::new()
    } else {
        let raw = &ncch[exefs_start as usize..(exefs_start + exefs_len) as usize];
        match key {
            Some(k) => {
                let counter =
                    ncch_counter(header.version, &header.partition_id, CTR_EXEFS, exefs_start)?;
                ctr_decrypt(&k, &counter, raw)
            }
            None => raw.to_vec(),
        }
    };
    if exefs_blob.is_empty() {
        // CFA without an ExeFS at all (manual-style archive).
        return Ok(None);
    }
    let files = parse_exefs(&exefs_blob)?;
    let code = files.iter().find(|f| f.name[..5] == *b".code");
    let Some(code) = code else {
        return Ok(None);
    };
    if exheader_raw.is_none() {
        return err("NCCH ExeFS holds .code but the NCCH has no exheader, so the ARM11 load address is unknown");
    }
    // SCI code-set info (gbatek exheader: text address at +0x10,
    // compression flag at +0x0D bit 0). The ARM11 kernel descriptors at
    // exheader+0x370 carry syscall/interrupt policy, not an entry point;
    // LOADER enters at the text base, which is the seed below.
    let text_addr = u32::from_le_bytes([
        exheader_blob[0x10],
        exheader_blob[0x11],
        exheader_blob[0x12],
        exheader_blob[0x13],
    ]);
    if text_addr == 0 {
        return err("NCCH exheader names a zero text address");
    }
    let compressed = exheader_blob[0x0D] & 1 != 0;
    let data_start = code
        .offset
        .checked_add(0x200)
        .ok_or_else(|| super::ImportError::Bad("ExeFS .code offset overflow".into()))?;
    let data_end = (data_start as u64)
        .checked_add(code.size as u64)
        .ok_or_else(|| super::ImportError::Bad("ExeFS .code size overflow".into()))?;
    if data_end > exefs_blob.len() as u64 {
        return err("ExeFS .code runs past the ExeFS end");
    }
    let stored = &exefs_blob[data_start as usize..data_end as usize];
    let code_bytes = if compressed {
        lzrev_decompress(stored)?
    } else {
        stored.to_vec()
    };
    let file_off = base
        .checked_add(exefs_start)
        .and_then(|v| v.checked_add(data_start as u64))
        .ok_or_else(|| super::ImportError::Bad("ExeFS .code file offset overflow".into()))?;
    let entry = text_addr as u64;
    let mut imp = NativeImport::default();
    let (mappings, names) = code_set_mappings(&exheader_blob, entry, file_off, code_bytes);
    imp.mappings = mappings;
    imp.mapping_names = names;
    imp.functions = vec![NativeFunction {
        entry,
        name: "entry".into(),
        size: 1,
    }];
    imp.format = "ncch".into();
    imp.language = LANGUAGE.into();
    Ok(Some(imp))
}

/// The ARM11 code set as the kernel maps it (gbatek/3dbrew exheader SCI
/// code-set info: text, ro and data at +0x10/+0x20/+0x30 as address, page
/// count, byte size, then the .bss size at +0x3C). The decompressed `.code`
/// holds the three segments back to back, each padded to its page count;
/// .bss follows .data in memory and has no bytes. Separate permissions are
/// what let analysis treat literal pools in .text and .rodata as constants.
/// A code set whose segments do not tile the blob that way is mapped as one
/// read/write/execute region, as before.
fn code_set_mappings(exheader: &[u8], entry: u64, file_off: u64, code: Vec<u8>) -> (Vec<Mapping>, Vec<String>) {
    let word = |at: usize| u32::from_le_bytes([exheader[at], exheader[at + 1], exheader[at + 2], exheader[at + 3]]) as u64;
    let segments = [(".text", 0x10, 6u64), (".rodata", 0x20, 2), (".data", 0x30, 3)];
    let mut layout = Vec::new();
    let mut offset = 0u64;
    let mut fits = true;
    for (name, at, flags) in segments {
        let (addr, pages, size) = (word(at), word(at + 4), word(at + 8));
        if size == 0 && pages == 0 {
            continue;
        }
        let span = pages * 0x1000;
        fits &= size <= span;
        layout.push((name, addr, offset, span, flags));
        offset += span;
    }
    let tiles = fits
        && layout.first().is_some_and(|first| first.1 == entry)
        && offset as usize == code.len()
        && layout.windows(2).all(|pair| pair[0].1 + pair[0].3 <= pair[1].1);
    if !tiles {
        let size = code.len() as u64;
        return (vec![Mapping { vaddr: entry, size, file_off, flags: 0x7, bytes: code }], vec![".code".into()]);
    }
    let mut mappings = Vec::new();
    let mut names = Vec::new();
    for (name, addr, start, span, flags) in &layout {
        let bytes = code[*start as usize..(*start + *span) as usize].to_vec();
        mappings.push(Mapping { vaddr: *addr, size: *span, file_off: file_off + start, flags: *flags, bytes });
        names.push(name.to_string());
    }
    let (data_addr, data_size, bss_size) = (word(0x30), word(0x38), word(0x3C));
    let mapped_end = layout.last().map_or(entry, |last| last.1 + last.3);
    let bss_end = data_addr + data_size + bss_size;
    if bss_size > 0 && bss_end > mapped_end {
        mappings.push(Mapping { vaddr: mapped_end, size: bss_end - mapped_end, file_off: 0, flags: 3, bytes: Vec::new() });
        names.push(".bss".into());
    }
    (mappings, names)
}

/// Imports a lone NCCH image.
fn import_ncch_with(data: &[u8], keys: &super::keys::KeyStore) -> Result<Vec<(String, NativeImport)>> {
    match import_ncch_slice(data, 0, keys)? {
        Some(imp) => Ok(vec![(".code".into(), imp)]),
        None => err("NCCH carries no ARM11 .code (CFA data archive?)"),
    }
}

// --------------------------------------------------------------- NCSD

/// NCSD media-unit size from NCSD flags[6] (ctrtool `ncsd_get_mediaunit_size`).
fn ncsd_media_unit(data: &[u8]) -> Result<u64> {
    let shift = data
        .get(0x188 + 6)
        .copied()
        .ok_or_else(|| super::ImportError::Bad("NCSD header too short".into()))?;
    if shift > 8 {
        return err("NCSD content-unit shift out of range");
    }
    Ok(1u64 << (9 + shift))
}

/// Imports an NCSD cartridge: each populated partition is an NCCH image
/// (3dbrew "CCI"). Empty slots and CFA/data partitions without `.code` are
/// skipped; a partition that is recognised but corrupt is remembered, and
/// only fails the import when nothing else yielded an image.
fn import_ncsd_with(data: &[u8], keys: &super::keys::KeyStore) -> Result<Vec<(String, NativeImport)>> {
    if data.len() < 0x160 || data[0x100..0x104] != *b"NCSD" {
        return err("not an NCSD image");
    }
    let unit = ncsd_media_unit(data)?;
    let mut out = Vec::new();
    let mut first_err: Option<super::ImportError> = None;
    for i in 0..8 {
        let off_units = u32le(data, 0x120 + i * 8)?;
        let size_units = u32le(data, 0x120 + i * 8 + 4)?;
        if size_units == 0 {
            continue;
        }
        let off = (off_units as u64)
            .checked_mul(unit)
            .ok_or_else(|| super::ImportError::Bad("NCSD partition offset overflow".into()))?;
        let size = (size_units as u64)
            .checked_mul(unit)
            .ok_or_else(|| super::ImportError::Bad("NCSD partition size overflow".into()))?;
        let end = off
            .checked_add(size)
            .ok_or_else(|| super::ImportError::Bad("NCSD partition overflow".into()))?;
        if end > data.len() as u64 {
            if first_err.is_none() {
                first_err = Some(super::ImportError::Bad(format!(
                    "NCSD partition {i} runs past the end of the file"
                )));
            }
            continue;
        }
        let slice = &data[off as usize..end as usize];
        if !is_ncch(slice) {
            continue;
        }
        match import_ncch_slice(slice, off, keys) {
            Ok(Some(imp)) => out.push((format!("partition{i}"), imp)),
            Ok(None) => {}
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    if out.is_empty() {
        return Err(first_err.unwrap_or(super::ImportError::Bad(
            "NCSD holds no executable NCCH partition".into(),
        )));
    }
    Ok(out)
}

// ---------------------------------------------------------------- CIA

fn align64(value: u64) -> Result<u64> {
    value
        .checked_add(63)
        .map(|v| v & !63)
        .ok_or_else(|| super::ImportError::Bad("CIA offset overflow".into()))
}

/// TMD signature-type table: (signature bytes, padding to 64) per 3dbrew
/// "Title metadata" (both SHA-256 and legacy SHA-1 ids accepted for the
/// size walk; the signature itself is never verified).
fn tmd_sig_len(sig_type: u32) -> Result<usize> {
    match sig_type {
        0x0100_00 | 0x0100_03 => Ok(0x200 + 0x3C),
        0x0100_01 | 0x0100_04 => Ok(0x100 + 0x3C),
        0x0100_02 | 0x0100_05 => Ok(0x3C + 0x40),
        _ => err(format!("CIA TMD has unknown signature type {sig_type:#010x}")),
    }
}

struct TmdContent {
    index: u16,
    ctype: u16,
    size: u64,
}

/// Parses the TMD content-chunk records (3dbrew "Title metadata").
fn parse_tmd(tmd: &[u8]) -> Result<Vec<TmdContent>> {
    if tmd.len() < 4 {
        return err("CIA TMD too short for a signature type");
    }
    let head = 4 + tmd_sig_len(u32be(tmd, 0)?)?;
    if tmd.len() < head + 0xC4 {
        return err("CIA TMD too short for its header");
    }
    let count = u16be(tmd, head + 0x9E)? as usize;
    if count == 0 {
        return err("CIA TMD carries no contents");
    }
    if count > 512 {
        return err("CIA TMD content count out of range");
    }
    let chunks = head
        .checked_add(0x9C4)
        .ok_or_else(|| super::ImportError::Bad("CIA TMD offset overflow".into()))?;
    let end = (count as u64)
        .checked_mul(0x30)
        .and_then(|v| (chunks as u64).checked_add(v))
        .ok_or_else(|| super::ImportError::Bad("CIA TMD offset overflow".into()))?;
    if end > tmd.len() as u64 {
        return err("CIA TMD content records run past the TMD end");
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = chunks + i * 0x30;
        out.push(TmdContent {
            index: u16be(tmd, at + 4)?,
            ctype: u16be(tmd, at + 6)?,
            size: u64be(tmd, at + 8)?,
        });
    }
    Ok(out)
}

/// Imports a CIA installer (3dbrew "CIA"): walks the 64-byte-aligned
/// header chain to the TMD, locates the main (index 0) content, and
/// recurses into the NCCH it holds. Titlekey-encrypted content needs the
/// ticket title key plus the console common key, so it is reported instead
/// of guessed at.
fn import_cia(data: &[u8], keys: &super::keys::KeyStore) -> Result<Vec<(String, NativeImport)>> {
    if data.len() < 0x20 {
        return err("CIA header too short");
    }
    let header_size = u32le(data, 0)? as u64;
    let cert_size = u32le(data, 8)? as u64;
    let ticket_size = u32le(data, 0x0C)? as u64;
    let tmd_size = u32le(data, 0x10)? as u64;
    let content_size = u64le(data, 0x18)?;
    let cert_off = align64(header_size)?;
    let ticket_off = align64(cert_off.checked_add(cert_size).ok_or_else(|| {
        super::ImportError::Bad("CIA certificate range overflow".into())
    })?)?;
    let tmd_off = align64(ticket_off.checked_add(ticket_size).ok_or_else(|| {
        super::ImportError::Bad("CIA ticket range overflow".into())
    })?)?;
    let content_off = align64(tmd_off.checked_add(tmd_size).ok_or_else(|| {
        super::ImportError::Bad("CIA TMD range overflow".into())
    })?)?;
    for (name, off, size) in [
        ("certificate chain", cert_off, cert_size),
        ("ticket", ticket_off, ticket_size),
        ("TMD", tmd_off, tmd_size),
    ] {
        let end = off
            .checked_add(size)
            .ok_or_else(|| super::ImportError::Bad("CIA offset overflow".into()))?;
        if end > data.len() as u64 {
            return err(format!("CIA {name} runs past the end of the file"));
        }
    }
    if tmd_size == 0 {
        return err("CIA has no TMD");
    }
    let contents = parse_tmd(&data[tmd_off as usize..(tmd_off + tmd_size) as usize])?;
    // Contents pack consecutively in chunk-record order (ctrtool `cia_save`
    // advances by each chunk size with no per-content padding).
    let mut cursor = content_off;
    let mut selected: Option<(u64, &TmdContent)> = None;
    let mut first: Option<(u64, &TmdContent)> = None;
    for chunk in &contents {
        if first.is_none() {
            first = Some((cursor, chunk));
        }
        if chunk.index == 0 && selected.is_none() {
            selected = Some((cursor, chunk));
        }
        cursor = cursor.checked_add(chunk.size).ok_or_else(|| {
            super::ImportError::Bad("CIA content range overflow".into())
        })?;
    }
    let (off, chunk) = selected.or(first).expect("TMD count checked nonzero");
    if chunk.size == 0 {
        return err("CIA main content is empty");
    }
    if chunk.size > content_size {
        return err("CIA content record overruns the declared content size");
    }
    let end = off
        .checked_add(chunk.size)
        .ok_or_else(|| super::ImportError::Bad("CIA content overflow".into()))?;
    if end > data.len() as u64 {
        return err("CIA content runs past the end of the file");
    }
    let blob = &data[off as usize..end as usize];
    if !is_ncch(blob) {
        if chunk.ctype & 1 != 0 {
            return err(
                "CIA content is titlekey-encrypted (AES-128-CBC): the ticket title key \
                 and console common key are not available to this loader",
            );
        }
        return err("CIA main content is not an NCCH image");
    }
    match import_ncch_slice(blob, off, keys)? {
        Some(imp) => Ok(vec![(".code".into(), imp)]),
        None => err("CIA content NCCH carries no ARM11 .code"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TEXT: u32 = 0x0010_0000;
    const TEST_PID: u64 = 0x0004_0000_0003_8c00;
    const NO_CRYPTO: u8 = FLAG_NOCRYPTO;
    const FIXED_KEY: u8 = FLAG_FIXEDKEY;

    fn put16(data: &mut [u8], off: usize, value: u16) {
        data[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(data: &mut [u8], off: usize, value: u32) {
        data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(data: &mut [u8], off: usize, value: u64) {
        data[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Plausible ARM11 code: sixteen `mov r0, r0` placeholders.
    fn test_code() -> Vec<u8> {
        let mut code = Vec::new();
        for _ in 0..16 {
            code.extend_from_slice(&0xE1A0_0000u32.to_le_bytes());
        }
        code
    }

    /// Greedy LZrev compressor producing blobs `lzrev_decompress` accepts.
    /// It is a test-only encoder (valid but not optimal): literals for
    /// novel bytes, longest matches (length 3..=18) otherwise, groups of
    /// eight under MSB-first flag bytes, then the footer. A match copies
    /// output byte `q` from `q + dist`; because the decoder reads ahead of
    /// its write cursor by one, the stored 12-bit distance is `dist - 3`
    /// (effective displacement 3..=0xFFF+3). Returns `None` when the data
    /// does not compress overall, which real `.code` blobs always do.
    fn lzrev_compress(raw: &[u8]) -> Option<Vec<u8>> {
        if raw.is_empty() {
            return None;
        }
        // Units in consumption order (highest output byte first).
        enum Unit {
            Literal(u8),
            Match { len: usize, dist: usize },
        }
        let mut units = Vec::new();
        let mut d = raw.len();
        while d > 0 {
            let mut best: Option<(usize, usize)> = None;
            let max_len = 18.min(d);
            // Format range is 3..=0xFFF+3; the search window is capped for
            // speed, which only costs optimality, never validity.
            let max_dist = (0xFFF + 3).min(raw.len().saturating_sub(1)).min(1024);
            if max_len >= 3 && max_dist >= 3 {
                'lens: for len in (3..=max_len).rev() {
                    for dist in 3..=max_dist {
                        let start = d - len;
                        // The decoder reads (pos + stored + 2) ahead of each
                        // write, so a match covering output top `d` reads up
                        // to `d + dist`: it must stay inside the output.
                        if d + dist >= raw.len() {
                            continue;
                        }
                        if raw[start..start + len] == raw[start + dist..start + dist + len] {
                            best = Some((len, dist));
                            break 'lens;
                        }
                    }
                }
            }
            match best {
                Some((len, dist)) => {
                    units.push(Unit::Match { len, dist });
                    d -= len;
                }
                None => {
                    d -= 1;
                    units.push(Unit::Literal(raw[d]));
                }
            }
        }
        // Lay out bottom-up: reverse the chunk order so consumption starts
        // at the top, and reverse each chunk's byte run so the first-
        // consumed unit sits just below its flag (consumption walks
        // addresses downward, MSB first). Reversing the whole run keeps
        // each match's high byte above its low byte.
        let mut payload = Vec::new();
        let mut chunks: Vec<&[Unit]> = units.chunks(8).collect();
        chunks.reverse();
        for chunk in chunks {
            let mut flag = 0u8;
            let mut bytes = Vec::new();
            for unit in chunk.iter() {
                flag <<= 1;
                match unit {
                    Unit::Literal(b) => bytes.push(*b),
                    Unit::Match { len, dist } => {
                        flag |= 1;
                        let seg = (((len - 3) << 12) | (dist - 3)) as u16;
                        bytes.push((seg >> 8) as u8);
                        bytes.push((seg & 0xFF) as u8);
                    }
                }
            }
            // A short final chunk covers the lowest bytes; its unused low
            // flag bits are never consumed (the cursor stops at `stop`).
            flag <<= 8 - chunk.len();
            bytes.reverse();
            payload.extend_from_slice(&bytes);
            payload.push(flag);
        }
        let pad = (4 - (payload.len() + 8) % 4) % 4;
        let footer_len = 8 + pad;
        let total = payload.len() + footer_len;
        if total >= raw.len() {
            return None;
        }
        let mut blob = payload;
        blob.extend(std::iter::repeat_n(0u8, pad));
        let comp_len = total as u32;
        let top = ((footer_len as u32) << 24) | (comp_len & 0x00FF_FFFF);
        blob.extend_from_slice(&top.to_le_bytes());
        blob.extend_from_slice(&((raw.len() - total) as u32).to_le_bytes());
        Some(blob)
    }

    /// Builds a minimal synthetic NCCH: header + 0x400-byte exheader +
    /// ExeFS holding one `.code` file. `code_stored` is the exact ExeFS
    /// payload (already compressed when `compress` is set).
    fn build_ncch(code_stored: &[u8], compress: bool, flags7: u8, program_id: u64) -> Vec<u8> {
        let exefs_off_units: u32 = 3; // header 0x200 + exheader 0x400
        let exefs_len = 0x200 + code_stored.len();
        let exefs_units = exefs_len.div_ceil(0x200) as u32;
        let total = exefs_off_units as usize * 0x200 + exefs_units as usize * 0x200;
        let mut ncch = vec![0u8; total];
        ncch[0x100..0x104].copy_from_slice(b"NCCH");
        put32(&mut ncch, 0x104, (total / 0x200) as u32);
        put64(&mut ncch, 0x108, program_id);
        put16(&mut ncch, 0x112, 2); // version
        put64(&mut ncch, 0x118, program_id);
        ncch[0x150..0x15A].copy_from_slice(b"CTR-P-TEST");
        put32(&mut ncch, 0x180, 0x400); // exheader size
        ncch[0x188..0x190].copy_from_slice(&[0, 0, 0, 0, 1, 3, 0, flags7]);
        put32(&mut ncch, 0x1A0, exefs_off_units);
        put32(&mut ncch, 0x1A4, exefs_units);
        put32(&mut ncch, 0x1A8, 1); // hash region
        // Exheader SCI.
        ncch[0x200..0x207].copy_from_slice(b"CtrTest");
        ncch[0x20D] = u8::from(compress);
        put32(&mut ncch, 0x210, TEST_TEXT);
        put32(&mut ncch, 0x214, 1);
        put32(&mut ncch, 0x218, 0x40);
        put32(&mut ncch, 0x21C, 0x1000);
        put64(&mut ncch, 0x400, program_id); // ACI program id
        // ExeFS with a single `.code` file.
        let eh = exefs_off_units as usize * 0x200;
        ncch[eh..eh + 5].copy_from_slice(b".code");
        put32(&mut ncch, eh + 8, 0);
        put32(&mut ncch, eh + 12, code_stored.len() as u32);
        ncch[eh + 0x200..eh + 0x200 + code_stored.len()].copy_from_slice(code_stored);
        ncch
    }

    /// Encrypts the exheader and ExeFS regions the way a real FixedCryptoKey
    /// NCCH stores them: whole-region AES-128-CTR under the zeros key with
    /// the documented per-region counters.
    fn encrypt_regions(ncch: &mut [u8]) {
        let mut pid = [0u8; 8];
        pid.copy_from_slice(&ncch[0x108..0x110]);
        let exheader = ncch_counter(2, &pid, CTR_EXHEADER, 0x200).expect("counter");
        let exefs = ncch_counter(2, &pid, CTR_EXEFS, 0x600).expect("counter");
        crypto::aes128_ctr(&ZEROS_KEY, &exheader, &mut ncch[0x200..0x600]);
        crypto::aes128_ctr(&ZEROS_KEY, &exefs, &mut ncch[0x600..]);
    }

    fn build_ncsd(partitions: &[Vec<u8>]) -> Vec<u8> {
        let mut off_units: u32 = 0x4000 / 0x200;
        let mut table = Vec::new();
        let mut total = 0x4000usize;
        for part in partitions {
            let units = part.len().div_ceil(0x200) as u32;
            table.push((off_units, units));
            off_units += units;
            total += units as usize * 0x200;
        }
        let mut ncsd = vec![0u8; total];
        ncsd[0x100..0x104].copy_from_slice(b"NCSD");
        put32(&mut ncsd, 0x104, (total / 0x200) as u32);
        put64(&mut ncsd, 0x108, TEST_PID);
        for (i, (off, size)) in table.iter().enumerate() {
            put32(&mut ncsd, 0x120 + i * 8, *off);
            put32(&mut ncsd, 0x120 + i * 8 + 4, *size);
        }
        for (i, part) in partitions.iter().enumerate() {
            let at = table[i].0 as usize * 0x200;
            ncsd[at..at + part.len()].copy_from_slice(part);
        }
        ncsd
    }

    /// `ncch` with `romfs` bytes of RomFS after its ExeFS, declared in the header.
    fn with_romfs(mut ncch: Vec<u8>, romfs: usize) -> Vec<u8> {
        let at = ncch.len();
        ncch.resize(at + romfs, 0xAB);
        let units = (ncch.len() / 0x200) as u32;
        put32(&mut ncch, 0x104, units);
        put32(&mut ncch, 0x1B0, (at / 0x200) as u32);
        put32(&mut ncch, 0x1B4, (romfs / 0x200) as u32);
        ncch
    }

    #[test]
    fn a_program_view_imports_like_the_whole_card_without_its_romfs() {
        let dir = std::env::temp_dir().join(format!("romwright-view-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ncch = build_ncch(&test_code(), false, NO_CRYPTO, TEST_PID);
        let exefs_end = ncch.len();
        let card = with_romfs(ncch, 0x10_0000);
        let mut cfa = build_ncch(&[], false, NO_CRYPTO, TEST_PID);
        cfa[0x600..0x605].copy_from_slice(b"icon\0");
        let manual = with_romfs(cfa, 0x8000);
        for (name, whole) in [("cxi", card.clone()), ("cci", build_ncsd(&[card.clone(), manual]))] {
            let path = dir.join(format!("game.{name}"));
            std::fs::write(&path, &whole).unwrap();
            let view = program_view_from(&path, 0).unwrap().expect("a program view");
            assert!(view.len() < whole.len() / 4, "{name}: the RomFS is left out");
            assert!(!view.windows(16).any(|w| w == [0xAB; 16]), "{name}: no RomFS byte is read");
            let mapped = |data: &[u8]| -> Vec<(u64, Vec<u8>)> {
                import(data).unwrap().unwrap().into_iter().flat_map(|(_, imp)| imp.mappings).map(|m| (m.vaddr, m.bytes)).collect()
            };
            assert_eq!(mapped(&view), mapped(&whole), "{name}: the same program");
            if name == "cxi" {
                assert_eq!(view.len(), exefs_end);
            }
        }
        // Small files are read whole.
        assert!(program_view(&dir.join("game.cxi")).unwrap().is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A 64 MiB file (the size `program_view` starts to trim at) with an NCCH header
    /// at 0: the given version and ncchflag[6], ExeFS offset and size, exheader size 0.
    fn big_ncch(name: &str, version: u16, shift: u8, exefs: (u32, u32)) -> std::path::PathBuf {
        use std::io::{Seek, SeekFrom, Write};
        let path = std::env::temp_dir().join(format!("romwright-{name}-{}.cxi", std::process::id()));
        let mut header = vec![0u8; 0x200];
        header[0x100..0x104].copy_from_slice(b"NCCH");
        put16(&mut header, 0x112, version);
        header[0x188 + 6] = shift;
        put32(&mut header, 0x1A0, exefs.0);
        put32(&mut header, 0x1A4, exefs.1);
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(PROGRAM_VIEW_MIN).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&header).unwrap();
        path
    }

    #[test]
    fn an_ncch_header_pointing_past_the_file_is_an_error_not_an_allocation() {
        // ExeFS offset and size 0xFFFFFFFF units of 0x200 << 8: about 2^49 bytes.
        let path = big_ncch("huge", 0, 8, (u32::MAX, u32::MAX));
        let error = program_view(&path).expect_err("a range that cannot fit the file");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("beyond"), "{error}");
    }

    #[test]
    fn an_ncch_whose_exefs_ends_past_the_file_is_an_error() {
        // Units of 0x200: the ExeFS ends 0x1E000 bytes past the 64 MiB file.
        let path = big_ncch("past-end", 0, 0, (0x1FFF0, 0x100));
        let error = program_view(&path).expect_err("an ExeFS past the end of the file");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_version_1_ncch_counts_its_offsets_in_bytes() {
        // ExeFS at byte 0x20000, 0x400 long: the view reads through 0x20400.
        let path = big_ncch("v1", 1, 0, (0x20000, 0x400));
        let view = program_view(&path).unwrap().expect("a program view");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(view.len(), 0x20400);
        assert_eq!(&view[0x104..0x108], &0x20400u32.to_le_bytes());
    }

    #[test]
    fn an_ncch_may_not_reach_past_its_ncsd_partition() {
        let dir = std::env::temp_dir().join(format!("romwright-part-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // One partition of 4 units at unit 0x20 (byte 0x4000), its NCCH a version-1
        // image whose ExeFS (0x1000 bytes at 0x1000) ends after the partition but
        // inside the file.
        let mut ncsd = vec![0u8; 0x4000 + 0x10000];
        ncsd[0x100..0x104].copy_from_slice(b"NCSD");
        put32(&mut ncsd, 0x120, 0x20);
        put32(&mut ncsd, 0x124, 4);
        ncsd[0x4100..0x4104].copy_from_slice(b"NCCH");
        put16(&mut ncsd, 0x4112, 1);
        put32(&mut ncsd, 0x41A0, 0x1000);
        put32(&mut ncsd, 0x41A4, 0x1000);
        let path = dir.join("part.cci");
        std::fs::write(&path, &ncsd).unwrap();
        let error = program_view_from(&path, 0).expect_err("an ExeFS outside its partition");
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("partition"), "{error}");
    }

    fn build_tmd(content_size: u64, ctype: u16) -> Vec<u8> {
        // RSA-2048/SHA-256 signature envelope, then the 0xC4 header.
        let mut tmd = vec![0u8; 0x140 + 0xC4 + 64 * 0x24 + 0x30];
        tmd[0..4].copy_from_slice(&0x0100_04u32.to_be_bytes());
        let head = 0x140;
        tmd[head + 0x9E..head + 0xA0].copy_from_slice(&1u16.to_be_bytes());
        let at = head + 0x9C4;
        tmd[at..at + 4].copy_from_slice(&0u32.to_be_bytes()); // content id
        tmd[at + 4..at + 6].copy_from_slice(&0u16.to_be_bytes()); // index 0
        tmd[at + 6..at + 8].copy_from_slice(&ctype.to_be_bytes());
        tmd[at + 8..at + 16].copy_from_slice(&content_size.to_be_bytes());
        tmd
    }

    fn build_cia(content: &[u8], ctype: u16) -> Vec<u8> {
        let tmd = build_tmd(content.len() as u64, ctype);
        let content_off = ((0x2040 + tmd.len() + 63) / 64) * 64;
        let mut cia = vec![0u8; content_off + content.len()];
        put32(&mut cia, 0, 0x2020);
        put16(&mut cia, 4, 0); // type
        put16(&mut cia, 6, 1); // version
        put32(&mut cia, 8, 0); // cert size
        put32(&mut cia, 0x0C, 0); // ticket size
        put32(&mut cia, 0x10, tmd.len() as u32);
        put32(&mut cia, 0x14, 0); // meta size
        cia[0x18..0x20].copy_from_slice(&(content.len() as u64).to_le_bytes());
        cia[0x2040..0x2040 + tmd.len()].copy_from_slice(&tmd);
        cia[content_off..content_off + content.len()].copy_from_slice(content);
        cia
    }

    #[test]
    fn decrypted_ncch_maps_code_at_text() {
        let code = test_code();
        let ncch = build_ncch(&code, false, NO_CRYPTO, TEST_PID);
        assert!(is_ncch(&ncch));
        assert!(!is_ncsd(&ncch));
        assert!(!is_cia(&ncch));
        let images = import(&ncch).expect("NCCH recognised").expect("NCCH imports");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, ".code");
        let imp = &images[0].1;
        assert_eq!(imp.language, "ARM:LE:32:v6");
        assert_eq!(imp.format, "ncch");
        assert!(!imp.mappings.is_empty());
        assert_eq!(imp.mappings[0].vaddr, TEST_TEXT as u64);
        assert_eq!(imp.mappings[0].bytes, code);
        assert_eq!(imp.functions.len(), 1);
        assert_eq!(imp.functions[0].entry, TEST_TEXT as u64);
    }

    #[test]
    fn detectors_reject_other_bytes() {
        let junk = vec![0x7Fu8; 0x300];
        assert!(!is_ncch(&junk));
        assert!(!is_ncsd(&junk));
        assert!(!is_cia(&junk));
        assert!(import(&junk).is_none());
        assert!(import(&[]).is_none());
        let mut cia_like = vec![0u8; 0x20];
        put32(&mut cia_like, 0, 0x2020);
        put16(&mut cia_like, 4, 0);
        put16(&mut cia_like, 6, 1);
        assert!(is_cia(&cia_like));
        assert!(!is_ncch(&cia_like));
    }

    #[test]
    fn ncsd_partition_recurses_with_absolute_offsets() {
        let code = test_code();
        let ncch = build_ncch(&code, false, NO_CRYPTO, TEST_PID);
        let ncsd = build_ncsd(&[ncch]);
        assert!(is_ncsd(&ncsd));
        let images = import(&ncsd).expect("NCSD recognised").expect("NCSD imports");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "partition0");
        let imp = &images[0].1;
        assert_eq!(imp.language, "ARM:LE:32:v6");
        assert!(!imp.mappings.is_empty());
        assert_eq!(imp.mappings[0].vaddr, TEST_TEXT as u64);
        assert_eq!(imp.mappings[0].bytes, code);
        // The mapping tracks the .code bytes inside the cartridge image:
        // partition base 0x4000 + ExeFS at media unit 3 + header 0x200.
        assert_eq!(imp.mappings[0].file_off, 0x4000 + 0x600 + 0x200);
        assert_eq!(imp.functions[0].entry, TEST_TEXT as u64);
    }

    #[test]
    fn ncsd_skips_data_partitions_but_keeps_code() {
        let code = test_code();
        let exec = build_ncch(&code, false, NO_CRYPTO, TEST_PID);
        // A CFA-style archive: valid NCCH header, no `.code` file.
        let mut cfa = build_ncch(&[], false, NO_CRYPTO, TEST_PID);
        cfa[0x600..0x605].copy_from_slice(b"icon\0");
        put32(&mut cfa, 0x600 + 8, 0);
        put32(&mut cfa, 0x600 + 12, 0x20);
        let ncsd = build_ncsd(&[exec, cfa]);
        let images = import(&ncsd).expect("NCSD recognised").expect("NCSD imports");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "partition0");
        assert_eq!(images[0].1.mappings[0].bytes, code);
    }

    #[test]
    fn compressed_code_decompresses_before_mapping() {
        // Repetitive code compresses; the tail literals exercise both paths.
        let mut code = Vec::new();
        for _ in 0..64 {
            code.extend_from_slice(&0xE1A0_0000u32.to_le_bytes());
        }
        code.extend_from_slice(b"unique-tail-bytes-0123456789abcdef");
        for _ in 0..64 {
            code.extend_from_slice(&0xE12FFF1Eu32.to_le_bytes());
        }
        let stored = lzrev_compress(&code).expect("fixture compresses");
        assert!(stored.len() < code.len());
        let ncch = build_ncch(&stored, true, NO_CRYPTO, TEST_PID);
        let images = import(&ncch).expect("NCCH recognised").expect("NCCH imports");
        assert_eq!(images[0].1.mappings[0].bytes, code);
        assert_eq!(images[0].1.mappings[0].size, code.len() as u64);
    }

    #[test]
    fn lzrev_roundtrip_covers_literals_and_matches() {
        let mut raw = b"literal-prefix-no-repeats-!@#$".to_vec();
        raw.extend(std::iter::repeat_n(0x41u8, 300));
        raw.extend(b"middle-seed-xyz".iter().copied());
        raw.extend(std::iter::repeat_n(0x42u8, 200));
        let blob = lzrev_compress(&raw).expect("fixture compresses");
        let back = lzrev_decompress(&blob).expect("round-trips");
        assert_eq!(back, raw);
    }

    #[test]
    fn lzrev_rejects_a_corrupt_footer() {
        assert!(lzrev_decompress(&[]).is_err());
        assert!(lzrev_decompress(&[0u8; 8]).is_err());
        let mut raw = std::iter::repeat_n(0x55u8, 512).collect::<Vec<_>>();
        raw.extend(b"seed-differing-tail-0123456789");
        let mut blob = lzrev_compress(&raw).expect("fixture compresses");
        blob.truncate(blob.len() / 2);
        assert!(lzrev_decompress(&blob).is_err());
    }

    #[test]
    fn fixed_key_encrypted_ncch_decrypts_with_zeros_key() {
        let code = test_code();
        let mut ncch = build_ncch(&code, false, FIXED_KEY, TEST_PID);
        encrypt_regions(&mut ncch);
        // The ExeFS header itself is ciphertext now.
        assert_ne!(&ncch[0x600..0x605], b".code");
        let images = import(&ncch).expect("NCCH recognised").expect("NCCH imports");
        assert_eq!(images[0].1.language, "ARM:LE:32:v6");
        assert_eq!(images[0].1.mappings[0].bytes, code);
        assert_eq!(images[0].1.functions[0].entry, TEST_TEXT as u64);
    }

    #[test]
    fn decrypted_dump_with_secure_flags_still_imports() {
        // A decrypted dump keeps its original secure flags; the matching
        // exheader program id marks it plaintext (ctrtool heuristic).
        let code = test_code();
        let ncch = build_ncch(&code, false, 0x00, TEST_PID);
        let images = import(&ncch).expect("NCCH recognised").expect("NCCH imports");
        assert_eq!(images[0].1.mappings[0].bytes, code);
    }

    #[test]
    fn secure_crypto_without_a_key_is_a_clear_error() {
        let code = test_code();
        // Secure flags with a mismatching exheader program id: neither a
        // decrypted dump nor fixed-key content.
        let mut ncch = build_ncch(&code, false, 0x00, 0x0004_0000_0000_0000);
        // Break the decrypted-dump heuristic: the ACI program id no longer
        // matches the header, so this reads as still-encrypted content.
        put64(&mut ncch, 0x400, TEST_PID);
        let result = import(&ncch).expect("NCCH recognised");
        let message = format!("{:?}", result.expect_err("needs slot keys"));
        assert!(message.contains("slot"), "unexpected error: {message}");
    }

    #[test]
    fn cia_chain_extracts_its_ncch() {
        let code = test_code();
        let ncch = build_ncch(&code, false, NO_CRYPTO, TEST_PID);
        let cia = build_cia(&ncch, 0);
        assert!(is_cia(&cia));
        assert!(!is_ncsd(&cia));
        let images = import(&cia).expect("CIA recognised").expect("CIA imports");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, ".code");
        let imp = &images[0].1;
        assert_eq!(imp.language, "ARM:LE:32:v6");
        assert_eq!(imp.mappings[0].bytes, code);
        assert_eq!(imp.functions[0].entry, TEST_TEXT as u64);
        // Absolute tracking into the CIA content region.
        let content_off = ((0x2040 + build_tmd(0, 0).len() + 63) / 64) * 64;
        assert_eq!(imp.mappings[0].file_off, content_off as u64 + 0x600 + 0x200);
    }

    #[test]
    fn cia_with_encrypted_content_reports_the_key_gap() {
        let filler = vec![0xABu8; 0x400];
        let cia = build_cia(&filler, 1); // type bit 0: Encrypted
        let result = import(&cia).expect("CIA recognised");
        let message = format!("{:?}", result.expect_err("titlekey unavailable"));
        assert!(message.contains("titlekey"), "unexpected error: {message}");
    }

    #[test]
    fn lone_cfa_without_code_is_a_clear_error() {
        let mut cfa = build_ncch(&[], false, NO_CRYPTO, TEST_PID);
        cfa[0x600..0x605].copy_from_slice(b"icon\0");
        let result = import(&cfa).expect("NCCH recognised");
        assert!(result.is_err());
    }

    #[test]
    fn code_set_info_splits_code_into_segments_with_permissions_and_bss() {
        let mut exheader = vec![0u8; 0x400];
        let mut set = |at: usize, values: [u32; 3]| {
            for (i, v) in values.iter().enumerate() {
                exheader[at + i * 4..at + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
        };
        // text 2 pages, ro 1 page, data 1 page (0x800 bytes used), then 0x1900 bytes of .bss.
        set(0x10, [0x10_0000, 2, 0x1F00]);
        set(0x20, [0x10_2000, 1, 0x100]);
        set(0x30, [0x10_3000, 1, 0x800]);
        exheader[0x3C..0x40].copy_from_slice(&0x1900u32.to_le_bytes());
        let code: Vec<u8> = (0..0x4000u32).map(|i| (i / 0x1000) as u8).collect();
        let (mappings, names) = code_set_mappings(&exheader, 0x10_0000, 0x1000, code.clone());
        assert_eq!(names, [".text", ".rodata", ".data", ".bss"]);
        let layout: Vec<(u64, u64, u64)> = mappings.iter().map(|m| (m.vaddr, m.size, m.flags)).collect();
        assert_eq!(layout, [(0x10_0000, 0x2000, 6), (0x10_2000, 0x1000, 2), (0x10_3000, 0x1000, 3), (0x10_4000, 0x1100, 3)]);
        assert_eq!(mappings[1].bytes, [2u8; 0x1000]);
        assert!(mappings[3].bytes.is_empty(), ".bss has no file bytes");
        // A blob the page counts do not tile stays one read/write/execute region.
        let (whole, names) = code_set_mappings(&exheader, 0x10_0000, 0x1000, code[..0x3000].to_vec());
        assert_eq!((whole.len(), whole[0].flags, names), (1, 7, vec![".code".to_string()]));
    }
}
