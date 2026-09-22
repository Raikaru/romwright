//! macOS Mach-O loader: fat binaries and 64-bit Intel slices.
//!
//! A fat binary (`0xCAFEBABE`, big-endian headers) carries one slice per
//! architecture; the loader takes the `x86_64` slice when present and
//! refuses anything else by name. A thin image must already be the
//! 64-bit `0xFEEDFACF` little-endian form; 32-bit and non-Intel
//! slices are recognised and refused rather than misread.
//!
//! Each `LC_SEGMENT_64` becomes a mapping at its declared virtual
//! address with the segment's initial protection; `LC_SYMTAB` names
//! the section symbols so discovery starts from real names. Format
//! reference: Apple's `loader.h` layout as implemented by every
//! open-source reader; independent implementation.

use super::{err, Mapping, NativeFunction, NativeImport, Result};

const FAT_MAGIC_BE: u32 = 0xCAFE_BABE;
const MH_MAGIC_64_LE: u32 = 0xFEED_FACF;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const N_STAB: u8 = 0xE0;
const N_SECT: u8 = 0x0E;
/// `VM_PROT_EXECUTE`: Mach-O protection bits are READ=1, WRITE=2,
/// EXECUTE=4 -- not the mapping-flag order.
const PROT_EXEC: u32 = 4;

fn u32_be(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| super::ImportError::Bad("Mach-O header outside file".into()))
}

fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| super::ImportError::Bad("Mach-O header outside file".into()))
}

fn u64_le(data: &[u8], off: usize) -> Result<u64> {
    data.get(off..off + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| super::ImportError::Bad("Mach-O header outside file".into()))
}

/// True for a fat binary or a thin Mach-O of any member: the family
/// check only, so an unsupported slice fails loudly in `import`
/// instead of falling through to the DOL fallback as garbage.
pub(crate) fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    if u32_be(data, 0).is_ok_and(|magic| magic == FAT_MAGIC_BE) {
        return true;
    }
    if let Ok(magic) = u32_le(data, 0) {
        // Thin headers: 64-bit and 32-bit little-endian, plus the
        // big-endian PowerPC form read byte-swapped.
        return matches!(magic, 0xFEED_FACF | 0xFEED_FACE | 0xCEFA_EDFE);
    }
    false
}

/// Selects the slice to load: the fat table's `x86_64` entry, or the
/// whole file for a thin image. Returns the slice byte range.
fn select_slice(data: &[u8]) -> Result<std::ops::Range<usize>> {
    if u32_be(data, 0).is_ok_and(|magic| magic == FAT_MAGIC_BE) {
        let narch = u32_be(data, 4)? as usize;
        if narch == 0 || narch > 32 {
            return err("Mach-O fat header names no architectures");
        }
        let mut first_intel = None;
        for index in 0..narch {
            let base = 8 + index * 20;
            let cpu = u32_be(data, base)?;
            let off = u32_be(data, base + 8)? as usize;
            let size = u32_be(data, base + 12)? as usize;
            if cpu == CPU_TYPE_X86_64 {
                let end = off
                    .checked_add(size)
                    .ok_or_else(|| super::ImportError::Bad("Mach-O slice overflow".into()))?;
                if end > data.len() {
                    return err("Mach-O slice outside file");
                }
                return Ok(off..end);
            }
            if first_intel.is_none() && (cpu & 0x00FF_FFFF) == 7 {
                first_intel = Some((off, size));
            }
        }
        if first_intel.is_some() {
            return err("Mach-O has no x86_64 slice (32-bit unsupported)");
        }
        return err("Mach-O has no Intel slice");
    }
    Ok(0..data.len())
}

/// Imports the selected slice: segments become mappings, section
/// symbols become named functions.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let slice = select_slice(data)?;
    let base = slice.start;
    let at = |off: usize| -> Result<usize> {
        base.checked_add(off)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| super::ImportError::Bad("Mach-O load command outside file".into()))
    };
    if u32_le(data, at(0)?)? != MH_MAGIC_64_LE {
        return err("Mach-O slice is not 64-bit Intel");
    }
    let cputype = u32_le(data, at(4)?)?;
    if cputype != CPU_TYPE_X86_64 {
        return err("Mach-O slice is not x86_64");
    }
    let ncmds = u32_le(data, at(16)?)? as usize;
    if ncmds > 256 {
        return err("Mach-O command count implausible");
    }
    let mut mappings = Vec::new();
    let mut symoff = None;
    let mut nsyms = 0u32;
    let mut stroff = 0usize;
    let mut strsize = 0usize;
    let mut cursor = 32usize;
    for _ in 0..ncmds {
        let cmd = u32_le(data, at(cursor)?)?;
        let size = u32_le(data, at(cursor + 4)?)? as usize;
        if size < 8 || cursor.checked_add(size).is_none() {
            return err("Mach-O command size invalid");
        }
        match cmd {
            LC_SEGMENT_64 => {
                let fileoff = u64_le(data, at(cursor + 40)?)?;
                let filesize = u64_le(data, at(cursor + 48)?)?;
                let vmaddr = u64_le(data, at(cursor + 24)?)?;
                let initprot = u32_le(data, at(cursor + 60)?)?;
                if filesize > 0 {
                    let start = fileoff as usize;
                    let end = start
                        .checked_add(filesize as usize)
                        .ok_or_else(|| super::ImportError::Bad("Mach-O segment overflow".into()))?;
                    if base + end > data.len() {
                        return err("Mach-O segment outside file");
                    }
                    mappings.push(Mapping {
                        vaddr: vmaddr,
                        size: filesize,
                        file_off: (base + start) as u64,
                        flags: if initprot & PROT_EXEC != 0 { 6 } else { 3 },
                        bytes: data[base + start..base + end].to_vec(),
                    });
                }
            }
            LC_SYMTAB => {
                if size < 24 {
                    return err("Mach-O symtab command truncated");
                }
                symoff = Some(u32_le(data, at(cursor + 8)?)? as usize);
                nsyms = u32_le(data, at(cursor + 12)?)?;
                stroff = u32_le(data, at(cursor + 16)?)? as usize;
                strsize = u32_le(data, at(cursor + 20)?)? as usize;
            }
            _ => {}
        }
        cursor += size;
    }
    if mappings.is_empty() {
        return err("Mach-O slice carries no segments");
    }
    let mut functions = Vec::new();
    if let Some(symoff) = symoff {
        if nsyms > 1_000_000 {
            return err("Mach-O symbol count implausible");
        }
        let str_start = base + stroff;
        let str_end = str_start
            .checked_add(strsize)
            .ok_or_else(|| super::ImportError::Bad("Mach-O strtab overflow".into()))?;
        if str_end > data.len() {
            return err("Mach-O strtab outside file");
        }
        for index in 0..nsyms as usize {
            let entry = base + symoff + index * 16;
            if entry + 16 > data.len() {
                return err("Mach-O symtab outside file");
            }
            let strx = u32_le(data, entry)? as usize;
            let n_type = data[entry + 4];
            let value = u64_le(data, entry + 8)?;
            if n_type & N_STAB != 0 || n_type & N_SECT != N_SECT || value == 0 {
                continue;
            }
            let name_off = str_start + strx;
            if name_off >= str_end {
                continue;
            }
            let name_end = data[name_off..str_end]
                .iter()
                .position(|&b| b == 0)
                .map(|len| name_off + len)
                .unwrap_or(str_end);
            let mut name = String::from_utf8_lossy(&data[name_off..name_end]).into_owned();
            // Mach-O C symbols carry a leading underscore the
            // toolchain adds; the decomp project names them bare.
            if let Some(bare) = name.strip_prefix('_') {
                if !bare.is_empty() {
                    name = bare.to_string();
                }
            }
            functions.push(NativeFunction { entry: value, name, size: 0 });
        }
    }
    let mut imp = NativeImport::default();
    imp.mappings = mappings;
    imp.functions = functions;
    imp.format = "Mach-O".into();
    imp.language = "x86:LE:64:default".into();
    Ok(imp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thin(cputype: u32) -> Vec<u8> {
        let mut image = vec![0u8; 64];
        image[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
        image[4..8].copy_from_slice(&cputype.to_le_bytes());
        image
    }

    fn fat(entries: &[(u32, usize, usize)]) -> Vec<u8> {
        let span = entries.iter().map(|(_, off, size)| off + size).max().unwrap_or(0);
        let mut image = vec![0u8; (8 + entries.len() * 20).max(span)];
        image[0..4].copy_from_slice(&FAT_MAGIC_BE.to_be_bytes());
        image[4..8].copy_from_slice(&(entries.len() as u32).to_be_bytes());
        for (index, (cpu, off, size)) in entries.iter().enumerate() {
            let base = 8 + index * 20;
            image[base..base + 4].copy_from_slice(&cpu.to_be_bytes());
            image[base + 8..base + 12].copy_from_slice(&(*off as u32).to_be_bytes());
            image[base + 12..base + 16].copy_from_slice(&(*size as u32).to_be_bytes());
        }
        image
    }

    #[test]
    fn family_check_covers_fat_and_thin() {
        assert!(is_macho(&fat(&[(CPU_TYPE_X86_64, 64, 64)])));
        assert!(is_macho(&thin(CPU_TYPE_X86_64)));
        assert!(is_macho(&thin(7)));
        assert!(!is_macho(b"\x7fELF...."));
        assert!(!is_macho(b"MZ...."));
        assert!(!is_macho(&[]));
    }

    #[test]
    fn fat_prefers_the_64_bit_slice() {
        let image = fat(&[(7, 128, 64), (CPU_TYPE_X86_64, 64, 64)]);
        assert_eq!(select_slice(&image).unwrap(), 64..128);
    }

    #[test]
    fn fat_without_intel_refuses_by_name() {
        let image = fat(&[(0x0100_000C, 64, 64)]);
        assert!(select_slice(&image).is_err());
        assert!(import(&image).is_err());
    }

    #[test]
    fn thin_32_refuses_as_unsupported() {
        let image = thin(7);
        assert!(is_macho(&image));
        assert!(import(&image).is_err());
    }
}
