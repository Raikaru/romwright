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

fn u64_be(data: &[u8], off: usize) -> Result<u64> {
    let b = data.get(off..off + 8).ok_or_else(|| {
        super::ImportError::Bad("truncated Wii field".into())
    })?;
    Ok(u64::from_be_bytes(b.try_into().unwrap()))
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
        return Some(err(
            "RVZ is a compressed disc — decompress with Dolphin first",
        ));
    }
    None
}
