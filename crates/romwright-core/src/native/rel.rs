//! GameCube/Wii REL loader (P3.1): the relocatable module a disc carries
//! beside the boot DOL. A REL is a header plus a section table, a
//! relocation table, and an import table — the console's linker loads it
//! at runtime and patches its relocations against the main DOL.
//!
//! Format reference: the REL header layout documented by the GC/Wii
//! homebrew community (Dolphin's RelReader, decomp-toolkit). Independent
//! implementation; no upstream code copied.
//!
//! Header (big-endian):
//!   0x00  u32  module id
//!   0x04  u32  next/prev module links (runtime; 0 on disc)
//!   0x08  u32  num_sections
//!   0x0c  u32  section_table_offset
//!   0x10  u32  name_offset / name_size
//!   0x14  u32  name_size
//!   0x18  u32  version
//!   0x1c  u32  bss_size
//!   0x20  u32  relocation_offset
//!   0x24  u32  import_offset
//!   0x28  u32  import_size
//!   0x2c  u8   prolog section index
//!   0x2d  u8   epilog section index
//!   0x2e  u8   unresolved section index
//!   0x2f  u8   bss section index
//!   0x30  u32  prolog function offset
//!   0x34  u32  epilog function offset
//!   0x38  u32  unresolved function offset
//!   0x3c  u32  alignment (v2+)
//!   0x40  u32  bss_alignment (v2+)
//!
//! Section table entry (8 bytes): u32 offset (low bit = exec flag),
//! u32 size.

use super::{err, Mapping, NativeImport, Result};

fn u32_be(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or_else(|| {
        super::ImportError::Bad("truncated REL field".into())
    })?;
    Ok(u32::from_be_bytes(b.try_into().unwrap()))
}

/// True when the image is a REL: a plausible header whose section table
/// and relocation table land inside the file.
pub(crate) fn is_rel(data: &[u8]) -> bool {
    if data.len() < 0x48 {
        return false;
    }
    let num_sections = u32_be(data, 0x08).unwrap_or(0) as usize;
    let section_off = u32_be(data, 0x0c).unwrap_or(0) as usize;
    let reloc_off = u32_be(data, 0x20).unwrap_or(0) as usize;
    let import_off = u32_be(data, 0x24).unwrap_or(0) as usize;
    let import_size = u32_be(data, 0x28).unwrap_or(0) as usize;
    // A REL has at least one section, a section table inside the file,
    // and import/reloc tables that fit.
    num_sections >= 1
        && num_sections <= 64
        && section_off >= 0x48
        && section_off + num_sections * 8 <= data.len()
        && reloc_off < data.len()
        && import_off + import_size <= data.len()
}

/// Imports a REL: each section becomes a mapping at its declared file
/// offset; the section's exec bit (offset low bit) sets the mapping's
/// executable flag. Sections have no vaddr of their own — the console
/// linker places them — so we map them at a synthetic base plus the
/// section index, matching how a decomp project names them.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let num_sections = u32_be(data, 0x08)? as usize;
    let section_off = u32_be(data, 0x0c)? as usize;
    let mut mappings = Vec::with_capacity(num_sections);
    // REL sections are placed by the console linker; we map them at a
    // synthetic base so each section is a distinct, stable address.
    const SYNTHETIC_BASE: u64 = 0x8000_0000;
    for i in 0..num_sections {
        let entry = section_off + i * 8;
        let raw_offset = u32_be(data, entry)?;
        let size = u32_be(data, entry + 4)? as u64;
        if size == 0 {
            continue;
        }
        let exec = raw_offset & 1 != 0;
        let file_off = (raw_offset & !1) as usize;
        let end = file_off
            .checked_add(size as usize)
            .ok_or_else(|| super::ImportError::Bad("REL section overflow".into()))?;
        if end > data.len() {
            return err("REL section outside file");
        }
        mappings.push(Mapping {
            vaddr: SYNTHETIC_BASE + (i as u64) * 0x1000_0000,
            size,
            file_off: file_off as u64,
            flags: if exec { 6 } else { 3 },
            bytes: data[file_off..end].to_vec(),
        });
    }
    if mappings.is_empty() {
        return err("REL carries no sections");
    }
    let mut imp = NativeImport::default();
    imp.mappings = mappings;
    imp.format = "REL".into();
    imp.language = "PowerPC:BE:32:Gekko_Broadway".into();
    Ok(imp)
}
