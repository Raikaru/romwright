//! Wii and `nod`-read disc containers (P3.4): the formats a GameCube or Wii
//! game arrives in.
//!
//! - **Wii ISO** (raw disc): a disc header (`0x5d1c9ea3` at 0x18), a partition
//!   table, and AES-encrypted partitions. `nod` unwraps the data partition's
//!   encryption (the title key comes from the disc's own ticket) and the
//!   partition is then read like a GameCube disc (`disc.rs`).
//! - **WBFS** (Wii Backup File System): `nod` maps the container's sectors back
//!   to the disc and the same Wii path follows.
//! - **RVZ / WIA** (Dolphin's compressed disc, including Redump's `NKit RVZ
//!   [zstd-19-128k]`): `nod` decodes the chunk groups (zstd, bzip2, LZMA,
//!   LZMA2 or purge; Wii partitions stored decrypted and hash-less) on demand.
//!   Only the groups holding the header, FST, DOL and RELs are decompressed;
//!   the disc is never expanded to a whole ISO.
//! - **WAD** (channel/installer): a `WAD` header naming a content table;
//!   the content carrying the executable (a DOL or ELF) is extracted.
//!
//! GameCube CISO is read by `disc.rs` itself; a Wii-shaped CISO comes here.
//! `nod` is MIT OR Apache-2.0 (docs/third-party.md). It embeds the Wii common
//! keys it needs to unwrap a title key; this crate stores none.

use super::{disc, err, ImportError, NativeImport, Result};
use nod::common::PartitionKind;
use nod::read::{DiscOptions, DiscReader, PartitionOptions};

fn u32_be(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or_else(|| {
        super::ImportError::Bad("truncated Wii field".into())
    })?;
    Ok(u32::from_be_bytes(b.try_into().unwrap()))
}

/// True when the image is a raw Wii disc: the Wii magic word at 0x18. A real
/// Wii disc header carries nothing else a GCM check could use (the boot DOL
/// lives inside the encrypted partition).
pub(crate) fn is_wii_iso(data: &[u8]) -> bool {
    u32_be(data, 0x18).unwrap_or(0) == disc::WII_MAGIC
}

/// True when the image is a WBFS container.
pub(crate) fn is_wbfs(data: &[u8]) -> bool {
    data.len() >= 0x10 && &data[0..4] == b"WBFS"
}

/// True when the image is a Dolphin RVZ or WIA compressed disc.
pub(crate) fn is_rvz_or_wia(data: &[u8]) -> bool {
    data.len() >= 8 && (&data[0..4] == b"RVZ\x01" || &data[0..4] == b"WIA\x01")
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

/// A disc image held in memory, handed to `nod` without a copy.
///
/// `nod` wants a `'static` stream, but the image is the caller's borrowed
/// slice (a multi-gigabyte compressed disc that must not be duplicated).
/// `import_nod` is the only constructor and drops every reader built on it
/// before returning, so the pointer never outlives the borrow.
#[derive(Clone, Copy)]
struct BorrowedBytes {
    ptr: *const u8,
    len: usize,
}

// SAFETY: the bytes are immutable and outlive every holder (see above); the
// pointer is only ever read through a shared slice.
unsafe impl Send for BorrowedBytes {}

impl AsRef<[u8]> for BorrowedBytes {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `ptr`/`len` came from a live `&[u8]` that `import_nod` keeps
        // borrowed until every reader is dropped.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

fn nod_error(error: nod::Error) -> ImportError {
    ImportError::Bad(format!("disc image: {error}"))
}

/// Imports any disc `nod` reads (Wii ISO, WBFS, RVZ, WIA, a Wii CISO) through
/// its data partition: the boot DOL plus every REL, as one program, exactly as
/// the equivalent decrypted ISO imports.
pub(crate) fn import_nod(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    let stream = BorrowedBytes { ptr: data.as_ptr(), len: data.len() };
    // Preloader threads stay off (the default): no reader may outlive this call.
    let reader = DiscReader::new_stream(Box::new(stream), &DiscOptions::default()).map_err(nod_error)?;
    let partition = reader
        .open_partition_kind(PartitionKind::Data, &PartitionOptions::default())
        .map_err(nod_error)?;
    let images = disc::import_partition(partition);
    drop(reader);
    images
}

/// The boot DOL and RELs of a disc `nod` reads, as files.
fn extract_nod(data: &[u8]) -> Result<disc::DiscFiles> {
    let stream = BorrowedBytes { ptr: data.as_ptr(), len: data.len() };
    let reader = DiscReader::new_stream(Box::new(stream), &DiscOptions::default()).map_err(nod_error)?;
    let partition = reader
        .open_partition_kind(PartitionKind::Data, &PartitionOptions::default())
        .map_err(nod_error)?;
    let files = disc::extract_partition(partition);
    drop(reader);
    files
}

/// The boot DOL and RELs of a GameCube or Wii disc in any container this
/// crate imports (ISO, CISO, RVZ, WIA, WBFS, Wii ISO) as files; `None` when
/// `data` is no disc. The dispatch order is `containers::import`'s.
pub(crate) fn extract_disc(data: &[u8]) -> Option<Result<disc::DiscFiles>> {
    if is_rvz_or_wia(data) || is_wii_iso(data) || is_wbfs(data) {
        return Some(extract_nod(data));
    }
    if disc::is_ciso(data) && disc::ciso_is_wii(data) {
        return Some(extract_nod(data));
    }
    disc::extract_gc(data)
}

/// Imports a Wii ISO through its decrypted data partition.
pub(crate) fn import_wii_iso(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    import_nod(data)
}

/// Imports a WBFS container's first disc.
pub(crate) fn import_wbfs(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    import_nod(data)
}

/// Imports an RVZ or WIA compressed disc without expanding it.
pub(crate) fn import_rvz(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    import_nod(data)
}

/// The disc formats `nod` reads, tried before the GCM header heuristics (which
/// can match arbitrary compressed bytes); None means none matched.
pub(crate) fn import_disc_formats(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    if is_rvz_or_wia(data) {
        return Some(import_rvz(data));
    }
    if is_wii_iso(data) {
        return Some(import_wii_iso(data));
    }
    if is_wbfs(data) {
        return Some(import_wbfs(data));
    }
    None
}

/// Tries each Wii container in turn; None means none matched.
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    if let Some(result) = import_disc_formats(data) {
        return Some(result);
    }
    if is_wad(data) {
        return Some(import_wad(data));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disc_containers_are_recognised_by_magic_before_any_heuristic() {
        let mut rvz = vec![0u8; 0x500];
        rvz[0..4].copy_from_slice(b"RVZ\x01");
        let mut wia = rvz.clone();
        wia[0..4].copy_from_slice(b"WIA\x01");
        let mut wbfs = rvz.clone();
        wbfs[0..4].copy_from_slice(b"WBFS");
        let mut wii = vec![0u8; 0x500];
        wii[0x18..0x1c].copy_from_slice(&disc::WII_MAGIC.to_be_bytes());
        assert!(is_rvz_or_wia(&rvz) && is_rvz_or_wia(&wia) && !is_rvz_or_wia(&wbfs));
        assert!(is_wbfs(&wbfs) && is_wii_iso(&wii) && !is_wii_iso(&rvz));
        for image in [&rvz, &wia, &wbfs, &wii] {
            assert!(import_disc_formats(image).is_some());
        }
        assert!(import_disc_formats(&[0u8; 0x500]).is_none());
    }

    #[test]
    fn a_container_nod_cannot_open_is_refused_by_name_not_decoded() {
        // Right magic, nothing behind it: an error that names the disc image.
        let mut rvz = vec![0u8; 0x500];
        rvz[0..4].copy_from_slice(b"RVZ\x01");
        let error = import(&rvz).expect("RVZ dispatches").unwrap_err();
        assert!(error.to_string().contains("disc image"), "{error}");
        // A Wii magic with no partition table has no data partition to read.
        let mut wii = vec![0u8; 0x50000];
        wii[0x18..0x1c].copy_from_slice(&disc::WII_MAGIC.to_be_bytes());
        assert!(import(&wii).expect("Wii dispatches").is_err());
    }
}
