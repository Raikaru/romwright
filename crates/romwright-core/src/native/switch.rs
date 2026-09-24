//! Switch NCA content archives and XCI cartridges.
//!
//! The formats a Switch game arrives in, ported from public documentation
//! (never from leaked code):
//!
//! - **NCA** layout: switchbrew "NCA" wiki — `NCA3`/`NCA2` magic at 0x200,
//!   distribution type at 0x204 (0 download / 1 gamecard), content type at
//!   0x205 (0 program / 1 meta / 2 control / 3 manual / 4 data /
//!   5 public-data), old key generation at 0x206, key-area index at 0x207
//!   (0 application / 1 ocean / 2 system), content size (bytes) at 0x208,
//!   program id at 0x210, key generation at 0x220, rights id at 0x230, four
//!   16-byte `FsEntry` media-unit (`0x200`-byte block) ranges at 0x240, one
//!   SHA-256 over each section header at 0x280, the encrypted key area
//!   (four 16-byte section keys) at 0x300, and one `0x200`-byte `FsHeader`
//!   per section at file `0x400 + i * 0x200` (`u16` version at +0, fs type
//!   at +2 with 0 = RomFS / 1 = PartitionFS, hash type at +3, encryption
//!   type at +4 with 0 = Auto / 1 = None / 2 = AesXts / 3 = AesCtr /
//!   4 = AesCtrEx).
//! - **NCA crypto model**: SciresM `hactool` (`nca.h`/`nca.c`) — the first
//!   `0x400` header bytes plus each section `FsHeader` are AES-XTS under the
//!   header key in `0x200` sectors, the key area is unwrapped with the
//!   generation's key-area key into the per-section keys, and each section
//!   decrypts per its `FsHeader` encryption type with the section's media
//!   offset folded into the counter.
//! - **XCI/HFS0 layout**: switchbrew "XCI"/"Gamecard_Format" wiki plus
//!   hactool `xci.h` — `HEAD` magic in the CardHeader (at file `0x1000`,
//!   i.e. `HEAD` at `0x1100`), `PartitionFsHeaderAddress` at CardHeader
//!   `+0x130` naming the root HFS0 (which lives around file `0x10000`),
//!   `HFS0` magic + `u32` file count + `u32` string-table size, `0x40`-byte
//!   entries (`u64` offset, `u64` size, `u32` name offset, `u32` hashed
//!   size, `u64` reserved, 32-byte hash), partitions `update`/`normal`/
//!   `secure`/`logo`, with `secure` holding the game NCAs.
//! - **PFS0** (the ExeFS shape): switchbrew "NCA" — `PFS0` magic, `u32`
//!   file count, `u32` string-table size, `0x18`-byte entries (`u64`
//!   offset, `u64` size, `u32` name offset, `u32` reserved), then the
//!   string table and the packed file bytes. The ExeFS `main` is the
//!   AARCH64 image, mapped at `0x71_0000_0000` — the base the NSO loader
//!   (`native::nso`, after `SwitchLoader.load`) uses.
//!
//! Key honesty: retail Switch keys live in the console keyblobs / the
//! user's `prod.keys` (hactool reads them from disk) and are NOT embedded
//! here. `HEADER_KEY`/`KEY_AREA_KEY` below are test stand-ins: the
//! `#[cfg(test)]` fixtures encrypt with these same values so the decrypt
//! paths execute. A dump encrypted with retail keys needs its real keys
//! plumbed in where these stand-ins sit. Likewise the XTS tweak here is
//! the standard one from `native::crypto`; retail NCA uses a byte-reversed
//! tweak (switchbrew "NCA"), so retail headers would additionally need that
//! transform — noted, not silently claimed.

use super::crypto::{aes128_ctr, aes128_xts_decrypt, ctr_counter};
use super::{err, Mapping, NativeImport, Result};
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::Aes128;

fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or_else(|| {
        super::ImportError::Bad("truncated Switch field".into())
    })?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn u64_le(data: &[u8], off: usize) -> Result<u64> {
    let b = data.get(off..off + 8).ok_or_else(|| {
        super::ImportError::Bad("truncated Switch field".into())
    })?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}

/// One media unit: every NCA/HFS0 offset and size is a multiple of this.
const MEDIA_UNIT: usize = 0x200;
/// NCA magic offset; the `0x400`-byte main header precedes the FsHeaders.
const NCA_MAGIC_OFF: usize = 0x200;
/// NCA section-table offset: four 16-byte media-unit ranges.
const NCA_SECTAB_OFF: usize = 0x240;
/// NCA key-area offset: four ECB-wrapped 16-byte section keys.
const NCA_KEYAREA_OFF: usize = 0x300;
const NCA_KEYAREA_LEN: usize = 0x40;
/// First FsHeader offset; one `0x200`-byte header per section follows.
const NCA_FSHDR_OFF: usize = 0x400;
const NCA_FSHDR_LEN: usize = 0x200;
/// Bytes of NCA header covered by the XTS layer when encrypted.
const NCA_ENC_HDR_LEN: usize = 0x400;
/// Full header window (main header plus the four FsHeaders).
const NCA_HDR_LEN: usize = 0xC00;
/// Content-size field: total NCA size in bytes.
const NCA_SIZE_OFF: usize = 0x208;
/// FsHeader encryption types (switchbrew "NCA": FsHeader.EncryptionType).
const ENC_AUTO: u8 = 0;
const ENC_NONE: u8 = 1;
const ENC_XTS: u8 = 2;
const ENC_CTR: u8 = 3;
const ENC_CTREX: u8 = 4;
/// Ghidra language for the AARCH64 `main` image.
const AARCH64_LANG: &str = "AARCH64:LE:64:v8A";
/// Where a 64-bit Switch module is mapped (matches `native::nso`).
const MAIN_BASE: u64 = 0x71_0000_0000;

/// Stand-in header key (both XTS halves): fixtures encrypt with this, so
/// the header-decrypt path executes. Retail keys come from the console
/// keyblobs, never from this file.
const HEADER_KEY: [u8; 32] = *b"romwright-switch-hdr-test-key!!!";
/// Stand-in key-area key: fixtures wrap their section keys with this.
const KEY_AREA_KEY: [u8; 16] = *b"switch-keyarea-1";

/// True when the image is an XCI cartridge: `HEAD` magic at 0x100 (the
/// offset this loader historically detected) or at 0x1100 (CardHeader at
/// file 0x1000 per switchbrew "XCI", `HEAD` at +0x100).
pub(crate) fn is_xci(data: &[u8]) -> bool {
    (data.len() >= 0x104 && &data[0x100..0x104] == b"HEAD")
        || (data.len() >= 0x1104 && &data[0x1100..0x1104] == b"HEAD")
}

/// True when the image is an NCA archive: `NCA3`/`NCA2` magic at 0x200.
/// Only the plaintext form: an encrypted header needs the trial decrypt in
/// `import`, which a slice detector must not pay for.
pub(crate) fn is_nca(data: &[u8]) -> bool {
    data.len() >= 0x204 && (&data[0x200..0x204] == b"NCA3" || &data[0x200..0x204] == b"NCA2")
}

/// True when the image is an ExeFS: the header's file table names NSO
/// modules. ExeFS has no magic — the shape is a table of (name, offset,
/// size) entries whose names are the module files.
pub(crate) fn is_exefs(data: &[u8]) -> bool {
    if data.len() < 0x20 {
        return false;
    }
    // ExeFS header: up to 16 file entries of (name[8], offset u32, size
    // u32) at 0x00, then a hash region. A plausible ExeFS has at least
    // one entry whose name is a printable module name (main, rtld, sdk,
    // or a .nso) and whose offset+size land inside the file.
    for i in 0..16 {
        let entry = i * 16;
        let name_end = data[entry..entry + 8]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(8);
        let name = &data[entry..entry + name_end];
        if name.is_empty() {
            continue;
        }
        if !name.iter().all(|&b| b.is_ascii_graphic()) {
            return false;
        }
        let offset = u32_le(data, entry + 8).unwrap_or(0) as u64;
        let size = u32_le(data, entry + 12).unwrap_or(0) as u64;
        if size > 0 && offset + size <= data.len() as u64 {
            return true;
        }
    }
    false
}

/// Imports an ExeFS: each file entry is an NSO module handed to the NSO
/// loader, returned as sibling images named by the entry.
pub(crate) fn import_exefs(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    let mut out = Vec::new();
    for i in 0..16 {
        let entry = i * 16;
        let name_end = data[entry..entry + 8]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(8);
        let name = std::str::from_utf8(&data[entry..entry + name_end])
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let offset = u32_le(data, entry + 8)? as usize;
        let size = u32_le(data, entry + 12)? as usize;
        if size == 0 {
            continue;
        }
        let bytes = data
            .get(offset..offset + size)
            .ok_or_else(|| super::ImportError::Bad(format!(
                "ExeFS entry {name} outside file"
            )))?;
        if super::nso::is_module(bytes) {
            let imp = super::nso::import(bytes)?;
            out.push((name, imp));
        }
    }
    if out.is_empty() {
        return err("ExeFS carries no NSO modules");
    }
    Ok(out)
}

// ------------------------------------------------------------------ crypto

/// AES-XTS over `data` in `0x200` sectors numbered by file offset
/// (`sector = file_offset / 0x200`), with the standard tweak from
/// `native::crypto` (retail NCA reverses the tweak bytes — see above).
fn xts_data(key: &[u8; 32], base: usize, data: &mut [u8]) -> Result<()> {
    if data.len() % MEDIA_UNIT != 0 || base % MEDIA_UNIT != 0 {
        return err("XTS range is not sector-aligned");
    }
    let k1: [u8; 16] = key[..16]
        .try_into()
        .map_err(|_| super::ImportError::Bad("short XTS key".into()))?;
    let k2: [u8; 16] = key[16..]
        .try_into()
        .map_err(|_| super::ImportError::Bad("short XTS key".into()))?;
    for (i, chunk) in data.chunks_mut(MEDIA_UNIT).enumerate() {
        aes128_xts_decrypt(&k1, &k2, base as u64 / MEDIA_UNIT as u64 + i as u64, chunk)?;
    }
    Ok(())
}

/// Single-block AES-ECB decrypt: the key-area unwrap primitive (the same
/// `aes` crate the XEX loader uses directly).
fn ecb_decrypt(key: &[u8; 16], data: &mut [u8]) -> Result<()> {
    if data.len() % 16 != 0 {
        return err("ECB range is not a whole number of blocks");
    }
    let cipher = Aes128::new(key.into());
    for block in data.chunks_mut(16) {
        let mut arr = <&mut [u8; 16]>::try_from(&mut *block)
            .map_err(|_| super::ImportError::Bad("short ECB block".into()))?
            .to_owned();
        cipher.decrypt_block((&mut arr).into());
        block.copy_from_slice(&arr);
    }
    Ok(())
}

/// Simplified section counter: the section's byte offset folded the way
/// `crypto::ctr_counter` folds a stream offset (hactool `nca_section_ctr`
/// folds the media offset instead — same shape, indistinguishable without
/// retail keys; fixtures round-trip through this form).
fn section_ctr(offset: u64) -> [u8; 16] {
    ctr_counter(&[0u8; 8], offset)
}

// ------------------------------------------------------------------ NCA

fn header_magic(buf: &[u8]) -> bool {
    buf.len() >= NCA_MAGIC_OFF + 4
        && (&buf[NCA_MAGIC_OFF..NCA_MAGIC_OFF + 4] == b"NCA3"
            || &buf[NCA_MAGIC_OFF..NCA_MAGIC_OFF + 4] == b"NCA2")
}

/// First `0xC00` bytes of the NCA with the XTS layer removed when present:
/// plaintext magic passes through, otherwise the first `0x400` bytes are
/// trial-decrypted as XTS sectors 0-1 under the header key (hactool
/// `nca_decrypt_header`) plus each present FsHeader block as its own
/// sector. None when neither form carries the magic.
fn header_bytes(data: &[u8], header_key: &[u8; 32]) -> Option<Vec<u8>> {
    if data.len() < NCA_ENC_HDR_LEN {
        return None;
    }
    let end = data.len().min(NCA_HDR_LEN);
    let mut buf = data[..end].to_vec();
    if header_magic(&buf) {
        return Some(buf);
    }
    let mut head = buf[..NCA_ENC_HDR_LEN].to_vec();
    xts_data(header_key, 0, &mut head).ok()?;
    buf[..NCA_ENC_HDR_LEN].copy_from_slice(&head);
    for i in 0..4 {
        let off = NCA_FSHDR_OFF + i * NCA_FSHDR_LEN;
        if buf.len() >= off + NCA_FSHDR_LEN {
            xts_data(header_key, off, &mut buf[off..off + NCA_FSHDR_LEN]).ok()?;
        }
    }
    header_magic(&buf).then_some(buf)
}

fn read_header(data: &[u8], header_key: &[u8; 32]) -> Result<Vec<u8>> {
    header_bytes(data, header_key)
        .ok_or_else(|| super::ImportError::Bad("NCA header magic missing".into()))
}



/// One populated section-table entry: a byte range plus its FsHeader
/// encryption type.
struct Section {
    index: usize,
    off: usize,
    size: usize,
    enc: u8,
}

fn sections(hdr: &[u8]) -> Result<Vec<Section>> {
    let mut out = Vec::new();
    for i in 0..4 {
        let at = NCA_SECTAB_OFF + i * 16;
        let start = u64::from(u32_le(hdr, at)?) * MEDIA_UNIT as u64;
        let end = u64::from(u32_le(hdr, at + 4)?) * MEDIA_UNIT as u64;
        if end <= start {
            continue;
        }
        let fh = NCA_FSHDR_OFF + i * NCA_FSHDR_LEN;
        let enc = *hdr.get(fh + 4).ok_or_else(|| {
            super::ImportError::Bad("NCA section header outside file".into())
        })?;
        let off: usize = start
            .try_into()
            .map_err(|_| super::ImportError::Bad("NCA section offset overflows".into()))?;
        let size: usize = (end - start)
            .try_into()
            .map_err(|_| super::ImportError::Bad("NCA section size overflows".into()))?;
        out.push(Section {
            index: i,
            off,
            size,
            enc,
        });
    }
    Ok(out)
}

/// The four section keys: the key area unwrapped with the key-area key
/// (hactool `nca_decrypt_key_area`).
fn section_keys(hdr: &[u8], key_area_key: &[u8; 16]) -> Result<[[u8; 16]; 4]> {
    let area = hdr
        .get(NCA_KEYAREA_OFF..NCA_KEYAREA_OFF + NCA_KEYAREA_LEN)
        .ok_or_else(|| super::ImportError::Bad("NCA key area outside header".into()))?;
    let mut raw = area.to_vec();
    ecb_decrypt(key_area_key, &mut raw)?;
    let mut keys = [[0u8; 16]; 4];
    for (i, key) in keys.iter_mut().enumerate() {
        key.copy_from_slice(&raw[i * 16..(i + 1) * 16]);
    }
    Ok(keys)
}

/// Decrypted section bytes; None when the section's encryption type is
/// unknown (the section is skipped, not fatal — a sibling may hold `main`).
fn section_bytes(
    data: &[u8],
    sec: &Section,
    keys: &[[u8; 16]; 4],
) -> Result<Option<Vec<u8>>> {
    let mut bytes = data
        .get(sec.off..sec.off + sec.size)
        .ok_or_else(|| super::ImportError::Bad("NCA section outside file".into()))?
        .to_vec();
    match sec.enc {
        // Auto arrives resolved by whatever dumped the image; without the
        // key-generation tables there is nothing to resolve it with, so it
        // reads as-is like None.
        ENC_AUTO | ENC_NONE => {}
        ENC_CTR | ENC_CTREX => {
            aes128_ctr(&keys[sec.index], &section_ctr(sec.off as u64), &mut bytes);
        }
        ENC_XTS => {
            // Stand-in wiring: the 16-byte section key fills both XTS
            // halves (retail wiring needs retail keys to validate).
            let mut full = [0u8; 32];
            full[..16].copy_from_slice(&keys[sec.index]);
            full[16..].copy_from_slice(&keys[sec.index]);
            xts_data(&full, sec.off, &mut bytes)?;
        }
        _ => return Ok(None),
    }
    Ok(Some(bytes))
}

// ------------------------------------------------------------------ PFS0

/// One file inside a PFS0/ExeFS section, with its absolute section offset.
struct PfsFile {
    name: String,
    off: usize,
    size: usize,
}

/// Every `(offset, size)` fits under `base` inside `data_len`.
fn files_fit(data_len: usize, base: usize, files: &[(usize, usize)]) -> bool {
    files.iter().all(|(off, size)| {
        base.checked_add(*off)
            .and_then(|start| start.checked_add(*size))
            .is_some_and(|end| end <= data_len)
    })
}

/// Files of the PFS0 opening `data`; None when the section does not open
/// with PFS0 (e.g. a RomFS section), Err when it opens like PFS0 but
/// truncates. File bytes follow the string table packed; a media-aligned
/// variant is tolerated when packed does not fit.
fn parse_pfs0(data: &[u8]) -> Result<Option<Vec<PfsFile>>> {
    if data.len() < 0x10 || &data[0..4] != b"PFS0" {
        return Ok(None);
    }
    let count = u32_le(data, 4)? as usize;
    let strings = u32_le(data, 8)? as usize;
    if count > 256 {
        return err("PFS0 file count implausible");
    }
    let table = count
        .checked_mul(0x18)
        .and_then(|n| n.checked_add(0x10))
        .ok_or_else(|| super::ImportError::Bad("PFS0 table overflows".into()))?;
    let names = table
        .checked_add(strings)
        .ok_or_else(|| super::ImportError::Bad("PFS0 strings overflow".into()))?;
    if data.len() < names {
        return err("PFS0 header outside section");
    }
    let mut raw: Vec<(String, usize, usize)> = Vec::with_capacity(count);
    for i in 0..count {
        let at = 0x10 + i * 0x18;
        let off: usize = u64_le(data, at)?
            .try_into()
            .map_err(|_| super::ImportError::Bad("PFS0 offset overflows".into()))?;
        let size: usize = u64_le(data, at + 8)?
            .try_into()
            .map_err(|_| super::ImportError::Bad("PFS0 size overflows".into()))?;
        let name_at = u32_le(data, at + 0x10)? as usize;
        let tail = data
            .get(table + name_at..)
            .ok_or_else(|| super::ImportError::Bad("PFS0 name outside section".into()))?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| super::ImportError::Bad("PFS0 name unterminated".into()))?;
        if table + name_at + end > names {
            return err("PFS0 name outside string table");
        }
        let name = std::str::from_utf8(&tail[..end])
            .map_err(|_| super::ImportError::Bad("PFS0 name not UTF-8".into()))?
            .to_string();
        raw.push((name, off, size));
    }
    let extents: Vec<(usize, usize)> =
        raw.iter().map(|(_, off, size)| (*off, *size)).collect();
    for base in [names, names.next_multiple_of(0x20), names.next_multiple_of(MEDIA_UNIT)] {
        if files_fit(data.len(), base, &extents) {
            return Ok(Some(
                raw.into_iter()
                    .map(|(name, off, size)| PfsFile {
                        name,
                        off: base + off,
                        size,
                    })
                    .collect(),
            ));
        }
    }
    err("PFS0 files outside section")
}

/// Maps the ExeFS `main`: an NSO goes to the NSO loader, a raw blob maps
/// flat at the AARCH64 module base.
fn import_main(bytes: &[u8]) -> Result<NativeImport> {
    if super::nso::is_module(bytes) {
        return super::nso::import(bytes);
    }
    if bytes.is_empty() {
        return err("NCA main is empty");
    }
    let mut imp = NativeImport::default();
    imp.format = "nca".into();
    imp.language = AARCH64_LANG.into();
    imp.mappings.push(Mapping {
        vaddr: MAIN_BASE,
        size: bytes.len() as u64,
        file_off: 0,
        flags: 6,
        bytes: bytes.to_vec(),
    });
    imp.diagnose(romwright_model::DiagnosticSeverity::Info, "load", "raw main image carries no symbol table; entry unknown");
    Ok(imp)
}

pub(crate) fn import_nca(data: &[u8], header_key: &[u8; 32], key_area_key: &[u8; 16]) -> Result<Vec<(String, NativeImport)>> {
    let hdr = read_header(data, header_key)?;
    let keys = section_keys(&hdr, key_area_key)?;

    let mut out = Vec::new();
    for sec in sections(&hdr)? {
        let Some(raw) = section_bytes(data, &sec, &keys)? else {
            continue;
        };
        let Some(files) = parse_pfs0(&raw)? else {
            continue;
        };
        for file in files {
            if file.name != "main" {
                continue;
            }
            let bytes = raw
                .get(file.off..file.off + file.size)
                .ok_or_else(|| super::ImportError::Bad("NCA main outside section".into()))?;
            out.push(("main".to_string(), import_main(bytes)?));
        }
    }
    if out.is_empty() {
        return err("NCA carries no ExeFS main image");
    }
    Ok(out)
}

// ------------------------------------------------------------------ XCI

/// CardHeader base: `HEAD` at file 0x100 (historical) or at 0x1100
/// (CardHeader at 0x1000 per switchbrew "XCI", `HEAD` at +0x100).
fn card_base(data: &[u8]) -> Option<usize> {
    if data.len() >= 0x104 && &data[0x100..0x104] == b"HEAD" {
        Some(0x100)
    } else if data.len() >= 0x1104 && &data[0x1100..0x1104] == b"HEAD" {
        Some(0x1100)
    } else {
        None
    }
}

/// One file inside an HFS0 partition, with its absolute image offset.
struct HfsFile {
    name: String,
    off: usize,
    size: usize,
}

/// Files of the HFS0 rooted at `base` (switchbrew "XCI" PartitionFsHeader:
/// `HFS0` magic, `u32` count, `u32` string size, `0x40`-byte entries; the
/// hash fields are integrity only and ignored). Entry offsets are relative
/// to the data region after the string table, media-unit aligned, with a
/// packed fallback when aligned does not fit.
fn parse_hfs0(data: &[u8], base: usize) -> Result<Vec<HfsFile>> {
    let end = base
        .checked_add(0x10)
        .ok_or_else(|| super::ImportError::Bad("XCI HFS0 outside image".into()))?;
    let head = data
        .get(base..end)
        .ok_or_else(|| super::ImportError::Bad("XCI HFS0 outside image".into()))?;
    if head[0..4] != *b"HFS0" {
        return err("not an HFS0 partition");
    }
    if base >= data.len() {
        return err("XCI HFS0 outside image");
    }
    let count = u32_le(data, base + 4)? as usize;
    let strings = u32_le(data, base + 8)? as usize;
    if count > 1024 {
        return err("HFS0 file count implausible");
    }
    let table = count
        .checked_mul(0x40)
        .and_then(|n| n.checked_add(0x10))
        .and_then(|n| base.checked_add(n))
        .ok_or_else(|| super::ImportError::Bad("HFS0 table overflows".into()))?;
    let names = table
        .checked_add(strings)
        .ok_or_else(|| super::ImportError::Bad("HFS0 strings overflow".into()))?;
    if data.len() < names {
        return err("HFS0 header outside image");
    }
    let mut raw: Vec<(String, usize, usize)> = Vec::with_capacity(count);
    for i in 0..count {
        let at = base + 0x10 + i * 0x40;
        let off: usize = u64_le(data, at)?
            .try_into()
            .map_err(|_| super::ImportError::Bad("HFS0 offset overflows".into()))?;
        let size: usize = u64_le(data, at + 8)?
            .try_into()
            .map_err(|_| super::ImportError::Bad("HFS0 size overflows".into()))?;
        let name_at = u32_le(data, at + 0x10)? as usize;
        let tail = data
            .get(table + name_at..)
            .ok_or_else(|| super::ImportError::Bad("HFS0 name outside image".into()))?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| super::ImportError::Bad("HFS0 name unterminated".into()))?;
        if table + name_at + end > names {
            return err("HFS0 name outside string table");
        }
        let name = std::str::from_utf8(&tail[..end])
            .map_err(|_| super::ImportError::Bad("HFS0 name not UTF-8".into()))?
            .to_string();
        raw.push((name, off, size));
    }
    let extents: Vec<(usize, usize)> =
        raw.iter().map(|(_, off, size)| (*off, *size)).collect();
    for base in [names.next_multiple_of(MEDIA_UNIT), names] {
        if files_fit(data.len(), base, &extents) {
            return Ok(raw
                .into_iter()
                .map(|(name, off, size)| HfsFile {
                    name,
                    off: base + off,
                    size,
                })
                .collect());
        }
    }
    err("HFS0 files outside image")
}

/// Imports an XCI: the root HFS0 names the partitions; `secure` holds the
/// game NCAs (an HFS0 of NCAs, or a bare NCA chain stepped by content
pub(crate) fn import_xci(data: &[u8], header_key: &[u8; 32], key_area_key: &[u8; 16]) -> Result<Vec<(String, NativeImport)>> {

    let base = card_base(data)
        .ok_or_else(|| super::ImportError::Bad("XCI has no HEAD header".into()))?;
    // PartitionFsHeaderAddress: CardHeader+0x130, an absolute file offset.
    let hfs: usize = u64_le(data, base + 0x30)?
        .try_into()
        .map_err(|_| super::ImportError::Bad("XCI partition offset overflows".into()))?;
    let root = match parse_hfs0(data, hfs) {
        Ok(root) => root,
        // The field-first read misses dumps whose header disagrees with
        // the documented root location; retry there before giving up.
        Err(_) if hfs != 0x1_0000 => parse_hfs0(data, 0x1_0000)?,
        Err(other) => return Err(other),
    };
    let Some(secure) = root.iter().find(|f| f.name == "secure") else {
        return err("XCI carries no secure partition");
    };
    let finish = secure
        .off
        .checked_add(secure.size)
        .ok_or_else(|| super::ImportError::Bad("XCI secure partition overflows".into()))?;
    let sbytes = data
        .get(secure.off..finish)
        .ok_or_else(|| super::ImportError::Bad("XCI secure partition outside image".into()))?;
    let mut ncas: Vec<(String, usize, usize)> = Vec::new();
    if sbytes.len() >= 4 && &sbytes[0..4] == b"HFS0" {
        for file in parse_hfs0(sbytes, 0)? {
            let slice = sbytes.get(file.off..file.off + file.size).unwrap_or(&[]);
            if file.name.ends_with(".nca") || header_bytes(slice, header_key).is_some() {
                ncas.push((file.name, file.off, file.size));
            }
        }
    } else {
        // Bare NCA chain: step by the content-size field (NCA+0x208).
        let mut at = 0usize;
        for _ in 0..64 {
            let rest = sbytes.get(at..).unwrap_or(&[]);
            let Some(hdr) = header_bytes(rest, header_key) else {
                break;
            };
            let size: usize = u64_le(&hdr, NCA_SIZE_OFF)?
                .try_into()
                .map_err(|_| super::ImportError::Bad("NCA size overflows".into()))?;
            let step = if size >= NCA_HDR_LEN {
                size.next_multiple_of(MEDIA_UNIT).min(rest.len())
            } else {
                rest.len()
            };
            if step == 0 {
                break;
            }
            ncas.push((format!("image{}", ncas.len()), at, step));
            at += step;
            if at >= sbytes.len() {
                break;
            }
        }
    }
    if ncas.is_empty() {
        return err("XCI secure partition carries no NCA");
    }
    let mut out = Vec::new();
    for (name, off, size) in ncas {
        let bytes = sbytes
            .get(off..off + size)
            .ok_or_else(|| super::ImportError::Bad("XCI NCA outside secure partition".into()))?;
        for (suffix, imp) in import_nca(bytes, header_key, key_area_key)? {
            out.push((format!("{name}/{suffix}"), imp));
        }
    }
    Ok(out)
}

/// Tries each Switch container in turn; None means none matched. An
/// encrypted NCA hides its magic, so the NCA arm also pays for one header
/// trial-decrypt before declining.
#[cfg(test)]
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    import_with(data, &super::keys::KeyStore::empty())
}

/// `import` with a user-supplied key store. `header_key` (32-byte XTS) and
/// `key_area_key_application_00`/`key_area_key` (16-byte) come from the
/// user's `prod.keys`; absent, the test stand-ins are used so fixtures still
/// decrypt and a retail image reports its key gap rather than misdecrypt.
pub(crate) fn import_with(
    data: &[u8],
    keys: &super::keys::KeyStore,
) -> Option<Result<Vec<(String, NativeImport)>>> {
    let header_key: [u8; 32] = keys
        .get_array::<32>("header_key")
        .unwrap_or(HEADER_KEY);
    let key_area_key: [u8; 16] = keys
        .get_array::<16>("key_area_key_application_00")
        .or_else(|| keys.get_array::<16>("key_area_key"))
        .unwrap_or(KEY_AREA_KEY);
    if is_nca(data) || (data.len() >= NCA_ENC_HDR_LEN && header_bytes(data, &header_key).is_some()) {
        return Some(import_nca(data, &header_key, &key_area_key));
    }
    if is_xci(data) {
        return Some(import_xci(data, &header_key, &key_area_key));
    }
    if is_exefs(data) {
        return Some(import_exefs(data));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    use aes::Aes128;

    /// The GF(2^128) x-step of the XTS tweak schedule — the same field
    /// operation `native::crypto` applies, mirrored here so fixtures can be
    /// *encrypted* the way `import` decrypts them.
    fn tweak_mul_x(tweak: &mut [u8; 16]) {
        let mut carry = 0u8;
        for byte in tweak.iter_mut() {
            let next = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next;
        }
        if carry != 0 {
            tweak[0] ^= 0x87;
        }
    }

    /// XTS-encrypt one sector, mirroring `crypto::aes128_xts_decrypt`.
    fn xts_encrypt(key: &[u8; 32], sector: u64, data: &mut [u8]) {
        let k1: &[u8; 16] = &key[..16].try_into().unwrap();
        let k2: &[u8; 16] = &key[16..].try_into().unwrap();
        let enc = Aes128::new(k1.into());
        let tweak_enc = Aes128::new(k2.into());
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&sector.to_le_bytes());
        tweak_enc.encrypt_block((&mut tweak).into());
        for block in data.chunks_mut(16) {
            for (b, t) in block.iter_mut().zip(tweak.iter()) {
                *b ^= t;
            }
            let mut arr = <&mut [u8; 16]>::try_from(&mut *block).unwrap().to_owned();
            enc.encrypt_block((&mut arr).into());
            block.copy_from_slice(&arr);
            for (b, t) in block.iter_mut().zip(tweak.iter()) {
                *b ^= t;
            }
            tweak_mul_x(&mut tweak);
        }
    }

    fn xts_encrypt_sectors(key: &[u8; 32], base: usize, data: &mut [u8]) {
        for (i, chunk) in data.chunks_mut(MEDIA_UNIT).enumerate() {
            xts_encrypt(key, base as u64 / MEDIA_UNIT as u64 + i as u64, chunk);
        }
    }

    fn ecb_encrypt(key: &[u8; 16], data: &mut [u8]) {
        let enc = Aes128::new(key.into());
        for block in data.chunks_mut(16) {
            let mut arr = <&mut [u8; 16]>::try_from(&mut *block).unwrap().to_owned();
            enc.encrypt_block((&mut arr).into());
            block.copy_from_slice(&arr);
        }
    }

    fn section_key(i: u8) -> [u8; 16] {
        [0xA0 + i; 16]
    }

    /// Packed PFS0: header, entries, string table, then file bytes.
    fn build_pfs0(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut strings = Vec::new();
        let mut name_offs = Vec::new();
        for (name, _) in files {
            name_offs.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"PFS0");
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        let mut off = 0u64;
        for ((_, bytes), name_off) in files.iter().zip(name_offs) {
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&name_off.to_le_bytes());
            out.extend_from_slice(&[0u8; 4]);
            off += bytes.len() as u64;
        }
        out.extend_from_slice(&strings);
        for (_, bytes) in files {
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Minimal Program NCA: one PartitionFS section holding `section`,
    /// encrypted per `enc`; the header is XTS-wrapped when asked.
    fn build_nca(section: &[u8], enc: u8, encrypt_header: bool) -> Vec<u8> {
        build_nca_keyed(section, enc, encrypt_header, &HEADER_KEY, &KEY_AREA_KEY)
    }

    /// `build_nca` under caller-chosen header/key-area keys, so a test can
    /// encrypt with a "retail" key and prove the KeyStore supplies it.
    fn build_nca_keyed(
        section: &[u8],
        enc: u8,
        encrypt_header: bool,
        header_key: &[u8; 32],
        key_area_key: &[u8; 16],
    ) -> Vec<u8> {
        let mut body = section.to_vec();
        while body.len() % MEDIA_UNIT != 0 {
            body.push(0);
        }
        let keys = [section_key(0), section_key(1), section_key(2), section_key(3)];
        const SECT_OFF: usize = NCA_HDR_LEN;
        match enc {
            ENC_CTR | ENC_CTREX => {
                aes128_ctr(&keys[0], &section_ctr(SECT_OFF as u64), &mut body);
            }
            ENC_XTS => {
                let mut full = [0u8; 32];
                full[..16].copy_from_slice(&keys[0]);
                full[16..].copy_from_slice(&keys[0]);
                xts_encrypt_sectors(&full, SECT_OFF, &mut body);
            }
            _ => {}
        }
        let blocks = (body.len() / MEDIA_UNIT) as u32;
        let start = (NCA_HDR_LEN / MEDIA_UNIT) as u32;
        let mut hdr = vec![0u8; NCA_HDR_LEN];
        hdr[NCA_MAGIC_OFF..NCA_MAGIC_OFF + 4].copy_from_slice(b"NCA3");
        hdr[0x204] = 0; // download
        let total = (NCA_HDR_LEN + body.len()) as u64;
        hdr[NCA_SIZE_OFF..NCA_SIZE_OFF + 8].copy_from_slice(&total.to_le_bytes());
        hdr[0x210..0x218].copy_from_slice(&0x0100_0000_0000_0000u64.to_le_bytes());
        hdr[NCA_SECTAB_OFF..NCA_SECTAB_OFF + 4].copy_from_slice(&start.to_le_bytes());
        hdr[NCA_SECTAB_OFF + 4..NCA_SECTAB_OFF + 8]
            .copy_from_slice(&(start + blocks).to_le_bytes());
        let mut area = [0u8; NCA_KEYAREA_LEN];
        for (i, key) in keys.iter().enumerate() {
            area[i * 16..(i + 1) * 16].copy_from_slice(key);
        }
        ecb_encrypt(key_area_key, &mut area);
        hdr[NCA_KEYAREA_OFF..NCA_KEYAREA_OFF + NCA_KEYAREA_LEN].copy_from_slice(&area);
        hdr[NCA_FSHDR_OFF..NCA_FSHDR_OFF + 2].copy_from_slice(&2u16.to_le_bytes());
        hdr[NCA_FSHDR_OFF + 2] = 1; // PartitionFS
        hdr[NCA_FSHDR_OFF + 4] = enc;
        if encrypt_header {
            xts_encrypt_sectors(header_key, 0, &mut hdr[..NCA_ENC_HDR_LEN]);
            xts_encrypt_sectors(header_key, NCA_FSHDR_OFF, &mut hdr[NCA_FSHDR_OFF..NCA_HDR_LEN]);
        }
        hdr.extend_from_slice(&body);
        hdr
    }

    /// HFS0 with media-aligned file data, the on-cartridge shape.
    fn build_hfs0(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut strings = Vec::new();
        let mut name_offs = Vec::new();
        for (name, _) in files {
            name_offs.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"HFS0");
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        let mut off = 0u64;
        for ((_, bytes), name_off) in files.iter().zip(name_offs) {
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&name_off.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&[0u8; 32]);
            off += bytes.len() as u64;
        }
        out.extend_from_slice(&strings);
        while out.len() % MEDIA_UNIT != 0 {
            out.push(0);
        }
        for (_, bytes) in files {
            out.extend_from_slice(bytes);
        }
        out
    }

    /// XCI with the documented CardHeader placement: CardHeader at file
    /// 0x1000 (`HEAD` at 0x1100), root HFS0 at 0x10000, `secure` holding
    /// one HFS0 of NCAs.
    fn build_xci(ncas: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let refs: Vec<(&str, &[u8])> = ncas.iter().map(|(n, b)| (*n, b.as_slice())).collect();
        let inner = build_hfs0(&refs);
        let root = build_hfs0(&[("secure", inner.as_slice())]);
        const HFS_OFF: usize = 0x1_0000;
        let mut img = vec![0u8; HFS_OFF + root.len()];
        img[0x1100..0x1104].copy_from_slice(b"HEAD");
        img[0x1130..0x1138].copy_from_slice(&(HFS_OFF as u64).to_le_bytes());
        img[HFS_OFF..HFS_OFF + root.len()].copy_from_slice(&root);
        img
    }

    /// Minimal uncompressed NSO: one 16-byte text segment, no MOD0, so the
    /// NSO loader maps it with a discovery note.
    fn build_nso() -> Vec<u8> {
        let mut nso = vec![0u8; 0x6C + 0x10];
        nso[0..4].copy_from_slice(b"NSO0");
        nso[0x10..0x14].copy_from_slice(&0x6Cu32.to_le_bytes());
        nso[0x18..0x1C].copy_from_slice(&0x10u32.to_le_bytes());
        // Empty rodata/data parked past text so the assembled image covers it.
        nso[0x20..0x24].copy_from_slice(&0x7Cu32.to_le_bytes());
        nso[0x24..0x28].copy_from_slice(&0x10u32.to_le_bytes());
        nso[0x30..0x34].copy_from_slice(&0x7Cu32.to_le_bytes());
        nso[0x34..0x38].copy_from_slice(&0x10u32.to_le_bytes());
        nso[0x6C..0x6C + 0x10].copy_from_slice(&[0x1Fu8, 0x20, 0x03, 0xD5, 0, 0, 0, 0,
            0xC0, 0x03, 0x5F, 0xD6, 0, 0, 0, 0]);
        nso
    }
    #[test]
    fn detectors() {
        let mut nca = vec![0u8; 0x204];
        nca[0x200..0x204].copy_from_slice(b"NCA3");
        assert!(is_nca(&nca));
        nca[0x200..0x204].copy_from_slice(b"NCA2");
        assert!(is_nca(&nca));
        nca[0x200..0x204].copy_from_slice(b"XXXX");
        assert!(!is_nca(&nca));
        assert!(!is_nca(&[0u8; 0x100]));

        let mut xci = vec![0u8; 0x104];
        xci[0x100..0x104].copy_from_slice(b"HEAD");
        assert!(is_xci(&xci));
        let mut xci2 = vec![0u8; 0x1104];
        xci2[0x1100..0x1104].copy_from_slice(b"HEAD");
        assert!(is_xci(&xci2));
        assert!(!is_xci(&vec![0u8; 0x1200]));
    }

    #[test]
    fn unknown_is_none() {
        assert!(import(&vec![0u8; 0x2000]).is_none());
        assert!(import(b"definitely not a switch image".as_slice()).is_none());
    }

    #[test]
    fn nca_plain_main_blob() {
        let main = b"\x1f\x20\x03\xd5main-code-payload".to_vec();
        let pfs0 = build_pfs0(&[("main", &main), ("main.npdm", b"npdm")]);
        let nca = build_nca(&pfs0, ENC_NONE, false);
        assert!(is_nca(&nca));
        let Some(Ok(images)) = import(&nca) else {
            panic!("plaintext NCA was not imported");
        };
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "main");
        let imp = &images[0].1;
        assert_eq!(imp.language, "AARCH64:LE:64:v8A");
        assert_eq!(imp.mappings.len(), 1);
        assert_eq!(imp.mappings[0].vaddr, MAIN_BASE);
        assert_eq!(imp.mappings[0].bytes, main);
    }

    #[test]
    fn nca_encrypted_header_and_ctr_section() {
        let main = b"\x1f\x20\x03\xd5ctr-main-payload-1234".to_vec();
        let pfs0 = build_pfs0(&[("main", &main)]);
        let nca = build_nca(&pfs0, ENC_CTR, true);
        // The magic is hidden: the detector declines, the importer tries.
        assert!(!is_nca(&nca));
        let Some(Ok(images)) = import(&nca) else {
            panic!("encrypted NCA was not imported");
        };
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "main");
        assert_eq!(images[0].1.language, "AARCH64:LE:64:v8A");
        assert_eq!(images[0].1.mappings.len(), 1);
        assert_eq!(images[0].1.mappings[0].bytes, main);
    }

    #[test]
    fn nca_xts_section() {
        let main = b"\x1f\x20\x03\xd5xts-main-payload-6789".to_vec();
        let pfs0 = build_pfs0(&[("main", &main)]);
        let nca = build_nca(&pfs0, ENC_XTS, false);
        let Some(Ok(images)) = import(&nca) else {
            panic!("XTS NCA was not imported");
        };
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].1.language, "AARCH64:LE:64:v8A");
        assert_eq!(images[0].1.mappings[0].bytes, main);
    }

    #[test]
    fn nca_retail_keys_come_from_the_keystore() {
        // A "retail" NCA encrypted under keys that are NOT the compiled-in
        // stand-ins: without a KeyStore the import must fail (the stand-ins
        // don't decrypt it); with the user's prod.keys values it must yield
        // the main image. This is the whole point of the key channel.
        let retail_header: [u8; 32] = *b"retail-switch-header-key-000000!";
        let retail_area: [u8; 16] = *b"retail-keyarea-0";
        let main = b"\x1f\x20\x03\xd5retail-main-payload-xyz".to_vec();
        let pfs0 = build_pfs0(&[("main", &main)]);
        let nca = build_nca_keyed(&pfs0, ENC_CTR, true, &retail_header, &retail_area);

        // No keys supplied: the stand-ins cannot open it — the header magic
        // never decrypts, so the NCA is not even recognised (None), and it
        // must certainly not import.
        assert!(
            !matches!(import(&nca), Some(Ok(_))),
            "retail NCA must not import under the test stand-ins"
        );

        // The user supplies their dumped prod.keys.
        let mut store = crate::native::keys::KeyStore::empty();
        store.parse_text_for_test(
            "header_key = 72657461696c2d7377697463682d6865616465722d6b65792d30303030303021\n\
             key_area_key_application_00 = 72657461696c2d6b6579617265612d30\n",
        );
        let Some(Ok(images)) = import_with(&nca, &store) else {
            panic!("retail NCA with user keys was not imported");
        };
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].1.mappings[0].bytes, main);
    }

    #[test]
    fn nca_nso_main_uses_nso_loader() {
        let nso = build_nso();
        let pfs0 = build_pfs0(&[("main", &nso)]);
        let nca = build_nca(&pfs0, ENC_NONE, false);
        let Some(Ok(images)) = import(&nca) else {
            panic!("NSO NCA was not imported");
        };
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "main");
        assert_eq!(images[0].1.format, "nso");
        assert_eq!(images[0].1.language, "AARCH64:LE:64:v8A");
        assert!(!images[0].1.mappings.is_empty());
    }

    #[test]
    fn nca_without_main_errors() {
        let nca = build_nca(&vec![0u8; MEDIA_UNIT], ENC_NONE, false);
        assert!(matches!(import(&nca), Some(Err(_))));
        assert!(matches!(import_nca(&vec![0u8; NCA_HDR_LEN], &HEADER_KEY, &KEY_AREA_KEY), Err(_)));
    }

    #[test]
    fn xci_secure_nca_chain() {
        let main = b"\x1f\x20\x03\xd5xci-main-payload-abcdef".to_vec();
        let pfs0 = build_pfs0(&[("main", &main)]);
        let nca = build_nca(&pfs0, ENC_NONE, false);
        let xci = build_xci(&[("game.nca", nca)]);
        assert!(is_xci(&xci));
        let Some(Ok(images)) = import(&xci) else {
            panic!("XCI was not imported");
        };
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "game.nca/main");
        assert_eq!(images[0].1.language, "AARCH64:LE:64:v8A");
        assert_eq!(images[0].1.mappings[0].bytes, main);
    }

    #[test]
    fn xci_bare_nca_chain() {
        let main_a = b"\x1f\x20\x03\xd5bare-chain-a".to_vec();
        let main_b = b"\x1f\x20\x03\xd5bare-chain-b!!".to_vec();
        let nca_a = build_nca(&build_pfs0(&[("main", &main_a)]), ENC_NONE, false);
        let nca_b = build_nca(&build_pfs0(&[("main", &main_b)]), ENC_CTR, false);
        let chain: Vec<u8> = nca_a.into_iter().chain(nca_b).collect();
        let root = build_hfs0(&[("secure", chain.as_slice())]);
        const HFS_OFF: usize = 0x1_0000;
        let mut img = vec![0u8; HFS_OFF + root.len()];
        img[0x100..0x104].copy_from_slice(b"HEAD");
        img[0x130..0x138].copy_from_slice(&(HFS_OFF as u64).to_le_bytes());
        img[HFS_OFF..HFS_OFF + root.len()].copy_from_slice(&root);
        let Some(Ok(images)) = import(&img) else {
            panic!("bare-chain XCI was not imported");
        };
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].0, "image0/main");
        assert_eq!(images[1].0, "image1/main");
        assert_eq!(images[0].1.mappings[0].bytes, main_a);
        assert_eq!(images[1].1.mappings[0].bytes, main_b);
    }

    #[test]
    fn xci_without_secure_errors() {
        let root = build_hfs0(&[("normal", b"data".as_slice())]);
        let mut img = vec![0u8; 0x200 + root.len()];
        img[0x100..0x104].copy_from_slice(b"HEAD");
        img[0x130..0x138].copy_from_slice(&0x200u64.to_le_bytes());
        img[0x200..0x200 + root.len()].copy_from_slice(&root);
        assert!(matches!(import(&img), Some(Err(_))));
    }
}
