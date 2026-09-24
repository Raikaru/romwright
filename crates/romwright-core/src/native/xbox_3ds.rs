//! Xbox 360 / Xbox / 3DS containers (P3.7): the formats those platforms'
//! executables arrive in.
//!
//! - **XEX** (Xbox 360 executable): a `XEX2`/`XEX0` magic header naming
//!   the PE image inside. The payload is a PE — the existing PE loader
//!   imports it once located.
//! - **XBE** (Xbox executable): a `XBEH` magic header naming sections;
//!   each section maps at its virtual address.
//! - **NCSD** (3DS cartridge): a `NCSD` magic image whose partition table
//!   names the ExeFS/carried NCCH. Encrypted — detection only.
//! - **CIA** (3DS installer): a `CIA` header naming the content chain.
//!   Encrypted — detection only.

use super::{err, Mapping, NativeImport, Result};

fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or_else(|| {
        super::ImportError::Bad("truncated field".into())
    })?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

// ---------------------------------------------------------------- XEX

/// True when the image is a XEX: `XEX2`/`XEX0`/`XEX1` magic.
pub(crate) fn is_xex(data: &[u8]) -> bool {
    data.len() >= 4 && (&data[0..4] == b"XEX2" || &data[0..4] == b"XEX0" || &data[0..4] == b"XEX1")
}

/// Imports a XEX: decrypts and decompresses the embedded PE image, then maps
/// its sections. The real container pipeline lives in `native::xex`; this
/// adapts it to the multi-image container shape.
pub(crate) fn import_xex(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    let imp = super::xex::import(data)?;
    Ok(vec![("xex".into(), imp)])
}

// ---------------------------------------------------------------- XBE

/// True when the image is an XBE: `XBEH` magic.
pub(crate) fn is_xbe(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"XBEH"
}

/// Imports an XBE: the header names the section table; each section maps
/// at its virtual address. XBE is a PE-derived format — the sections are
/// the executable's segments.
pub(crate) fn import_xbe(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    // XBE header: magic(4) then a digital signature, then the header
    // fields. The section table is at a header-named offset; each entry
    // is (flags, vaddr, vsize, file_off, file_size, ...). The layout is
    // intricate — this maps the sections the header names.
    // Section count at 0x11c, section table at 0x120 (relative to the
    // header base the certificate names). The honest minimal read: the
    // section headers are (u32 flags, u32 vaddr, u32 vsize, u32 file_off,
    // u32 file_size) at the table offset.
    let num_sections = u32_le(data, 0x11c)? as usize;
    let table_off = u32_le(data, 0x120)? as usize;
    if num_sections == 0 || num_sections > 64 {
        return err("XBE section count implausible");
    }
    let mut mappings = Vec::new();
    for i in 0..num_sections {
        let entry = table_off + i * 0x38; // XBE section header is 56 bytes
        let flags = u32_le(data, entry)?;
        let vaddr = u32_le(data, entry + 4)? as u64;
        let vsize = u32_le(data, entry + 8)? as u64;
        let file_off = u32_le(data, entry + 12)? as usize;
        let file_size = u32_le(data, entry + 16)? as u64;
        if file_size == 0 {
            continue;
        }
        let end = file_off
            .checked_add(file_size as usize)
            .ok_or_else(|| super::ImportError::Bad("XBE section overflow".into()))?;
        if end > data.len() {
            return err("XBE section outside file");
        }
        mappings.push(Mapping {
            vaddr,
            size: vsize.max(file_size),
            file_off: file_off as u64,
            flags: if flags & 0x04 != 0 { 6 } else { 3 },
            bytes: data[file_off..end].to_vec(),
        });
    }
    if mappings.is_empty() {
        return err("XBE carries no sections");
    }
    let mut imp = NativeImport::default();
    imp.mappings = mappings;
    imp.format = "XBE".into();
    imp.language = "x86:LE:32:default".into();
    Ok(vec![(String::new(), imp)])
}

// ---------------------------------------------------------------- 3DS

/// True when the image is an NCSD cartridge: `NCSD` magic at 0x100.
pub(crate) fn is_ncsd(data: &[u8]) -> bool {
    data.len() >= 0x104 && &data[0x100..0x104] == b"NCSD"
}

/// True when the image is a CIA installer: the header size field is
/// 0x2020 and the type field names a CIA.
pub(crate) fn is_cia(data: &[u8]) -> bool {
    if data.len() < 0x10 {
        return false;
    }
    let header_size = u32_le(data, 0x00).unwrap_or(0);
    let cia_type = u32_le(data, 0x04).unwrap_or(0);
    header_size == 0x2020 && cia_type == 0x0001_0000
}

/// Tries each container in turn; None means none matched.
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    if is_xex(data) {
        return Some(import_xex(data));
    }
    if is_xbe(data) {
        return Some(import_xbe(data));
    }
    if is_ncsd(data) {
        return Some(err(
            "NCSD is an encrypted 3DS cartridge — extract the NCCH first",
        ));
    }
    if is_cia(data) {
        return Some(err(
            "CIA is an encrypted 3DS installer — extract the content first",
        ));
    }
    None
}
