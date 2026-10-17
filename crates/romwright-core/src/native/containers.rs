//! Easy container formats (P2.8): the disc/homebrew wrappers that carry
//! one executable and need only header parsing to reach it.
//!
//! - **GCM** (GameCube disc): a raw image whose header at 0x0 names the
//!   boot DOL's file offset and size. The DOL is the executable.
//! - **BIN/CUE** (PSX CD): a `.cue` text sheet naming the `.bin` track;
//!   track 1 is the data track whose sectors carry the ISO9660 image the
//!   ISO reader already handles.
//! - **PBP** (PSP EBOOT): a `PBP\0` header whose section table names the
//!   embedded `PSP`/`ELF` payload offset.
//! - **NRO** (Switch homebrew): an `NRO0` header naming text/rodata/data
//!   segment file offsets and memory addresses.

use super::{err, Mapping, NativeImport, Result};

fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or_else(|| {
        super::ImportError::Bad("truncated container field".into())
    })?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn u32_be(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or_else(|| {
        super::ImportError::Bad("truncated container field".into())
    })?;
    Ok(u32::from_be_bytes(b.try_into().unwrap()))
}

// ---------------------------------------------------------------- GCM

/// True when the image is a GameCube disc: the GCM header carries a
/// valid DOL offset/size and the disc magic region is plausible.
pub(crate) fn is_gcm(data: &[u8]) -> bool {
    if data.len() >= 0x460 && u32_be(data, 0x1c).unwrap_or(0) == 0xc233_9f3d {
        return true;
    }
    if data.len() < 0x460 {
        return false;
    }
    // GCM header: 0x00 game code (4), 0x04 maker (2), 0x06 disc id,
    // 0x18 magic word 0xc2339f3d (GC) — but homebrew/early discs vary.
    // The reliable signal: a nonzero DOL offset+size at 0x420/0x424 that
    // lands inside the file.
    let dol_off = u32_be(data, 0x420).unwrap_or(0) as usize;
    let dol_size = u32_be(data, 0x424).unwrap_or(0) as usize;
    dol_off >= 0x460 && dol_size > 0 && dol_off + dol_size <= data.len()
}

/// Imports a GCM image. A GameCube disc with a readable FST imports as one
/// program holding the boot DOL and every REL on the disc (`disc`); an
/// image without that (a header-only fixture) reads the boot DOL from the
/// header's offset alone. Wii discs never get here: `wii::import_nod` reads
/// their decrypted partition.
pub(crate) fn import_gcm(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    if let Some(result) = super::disc::import_gc_raw(data) {
        return result;
    }
    let dol_off = u32_be(data, 0x420)? as usize;
    let dol_size = u32_be(data, 0x424)? as usize;
    let dol = data
        .get(dol_off..dol_off + dol_size)
        .ok_or_else(|| super::ImportError::Bad("GCM DOL outside file".into()))?;
    let imp = super::dol::import(dol)?;
    Ok(vec![("dol".into(), imp)])
}

// ---------------------------------------------------------------- PBP

/// True when the image is a PSP EBOOT.PBP: `PBP\0` magic + version.
pub(crate) fn is_pbp(data: &[u8]) -> bool {
    data.len() >= 0x28 && &data[0..4] == b"PBP\x00"
}

/// Extracts the embedded ELF/PSP payload from a PBP and imports it.
/// The PBP header at 0x08 holds a table of section offsets; the ELF
/// payload (`PSP`/`ELF` data) is the section named `DATA.PSP` — the
/// first data section after the header.
pub(crate) fn import_pbp(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    // PBP header: magic(4) version(4) then 8 section offsets (u32 LE).
    // Section 0 is the param.sfo; the ELF payload is the section whose
    // bytes start with the ELF magic — scan the table for it.
    let mut offsets = Vec::new();
    for i in 0..8 {
        offsets.push(u32_le(data, 0x08 + i * 4)? as usize);
    }
    for (i, &off) in offsets.iter().enumerate() {
        if off >= data.len() {
            continue;
        }
        let end = offsets
            .iter()
            .skip(i + 1)
            .copied()
            .filter(|&o| o > off && o <= data.len())
            .min()
            .unwrap_or(data.len());
        let section = &data[off..end];
        if section.len() >= 4 && &section[0..4] == b"\x7fELF" {
            let imp = super::parse_native(section)?;
            return Ok(vec![("psp".into(), imp)]);
        }
    }
    err("PBP carries no ELF payload")
}

// ---------------------------------------------------------------- NRO

/// True when the image is a Switch NRO: `NRO0` magic at 0x10.
pub(crate) fn is_nro(data: &[u8]) -> bool {
    data.len() >= 0x70 && &data[0x10..0x14] == b"NRO0"
}

/// Imports a Switch NRO: text/rodata/data segments at header-named
/// file offsets and memory addresses. NRO is a homebrew module format —
/// the segments map at the addresses the header declares.
pub(crate) fn import_nro(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    // NRO header (switchbrew): 0x10 "NRO0", then at 0x18+ the segment
    // table: text {file_off, size, vaddr}, rodata, data, each 12 bytes.
    let mut mappings = Vec::new();
    // Segment descriptors start at 0x20: three (file_off, size, vaddr)
    // triples for text/rodata/data, then bss size.
    let mut flags_for = [6u8, 3u8, 3u8].iter(); // text exec, rodata/data rw
    for i in 0..3 {
        let file_off = u32_le(data, 0x20 + i * 12)? as usize;
        let size = u32_le(data, 0x24 + i * 12)? as u64;
        let vaddr = u32_le(data, 0x28 + i * 12)? as u64;
        if size == 0 {
            continue;
        }
        let end = file_off
            .checked_add(size as usize)
            .ok_or_else(|| super::ImportError::Bad("NRO segment overflow".into()))?;
        if end > data.len() {
            return err("NRO segment outside file");
        }
        mappings.push(Mapping {
            vaddr,
            size,
            file_off: file_off as u64,
            flags: *flags_for.next().unwrap_or(&3) as u64,
            bytes: data[file_off..end].to_vec(),
        });
    }
    if mappings.is_empty() {
        return err("NRO carries no segments");
    }
    mappings.sort_unstable_by_key(|m| m.vaddr);
    let mut imp = NativeImport::default();
    imp.mappings = mappings;
    imp.format = "NRO".into();
    imp.language = "AARCH64:LE:64:v8A".into();
    Ok(vec![(String::new(), imp)])
}

// ---------------------------------------------------------------- dispatch

/// Tries each easy container in turn; None means none matched.
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    // RVZ/WIA/WBFS/Wii discs first: `is_gcm`'s offset heuristics can match
    // arbitrary compressed bytes.
    if let Some(result) = super::wii::import_disc_formats(data) {
        return Some(result);
    }
    if super::disc::is_ciso(data) {
        return Some(super::disc::import_ciso(data));
    }
    if is_gcm(data) {
        return Some(import_gcm(data));
    }
    if is_pbp(data) {
        return Some(import_pbp(data));
    }
    if is_nro(data) {
        return Some(import_nro(data));
    }
    // BIN/CUE is a two-file container: the .cue names the .bin, which the
    // caller resolves; detection alone is reported so the caller can pair.
    None
}
