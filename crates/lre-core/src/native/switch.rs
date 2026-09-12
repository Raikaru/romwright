//! Switch containers (P3.6): the formats a Switch game arrives in.
//!
//! - **XCI** (cartridge image): a `HEAD` magic image whose partitions
//!   hold the game's NCAs. Encrypted — detection only.
//! - **NCA** (content archive): a `NCA3`/`NCA2` magic archive carrying
//!   the game's ExeFS/RomFS. Encrypted — detection only.
//! - **ExeFS** (executable filesystem): the unencrypted filesystem inside
//!   an NCA that carries the NSO modules. A `ExeFS`/`exefs` directory
//!   lists each module's offset+size; each is an NSO the existing loader
//!   imports.

use super::{err, NativeImport, Result};

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

/// True when the image is an XCI cartridge: `HEAD` magic at 0x100.
pub(crate) fn is_xci(data: &[u8]) -> bool {
    data.len() >= 0x200 && &data[0x100..0x104] == b"HEAD"
}

/// True when the image is an NCA archive: `NCA3`/`NCA2` magic at 0x200.
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

/// Tries each Switch container in turn; None means none matched.
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    if is_exefs(data) {
        return Some(import_exefs(data));
    }
    if is_nca(data) {
        return Some(err(
            "NCA is encrypted — decrypt with a Switch tool first",
        ));
    }
    if is_xci(data) {
        return Some(err(
            "XCI is an encrypted cartridge image — extract the NCA first",
        ));
    }
    None
}
