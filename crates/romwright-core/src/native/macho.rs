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
const CPU_TYPE_I386: u32 = 7;
const MH_MAGIC_LE: u32 = 0xFEED_FACE;
const LC_SEGMENT: u32 = 0x1;
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
        // `0xCAFEBABE` is also a Java class file: require a sane
        // fat table (few arches, every entry inside the file) so a
        // class file falls through instead of misrouting here.
        let Ok(narch) = u32_be(data, 4) else {
            return false;
        };
        if narch == 0 || narch > 8 {
            return false;
        }
        for index in 0..narch as usize {
            let base = 8 + index * 20;
            let (Ok(off), Ok(size)) =
                (u32_be(data, base + 8), u32_be(data, base + 12))
            else {
                return false;
            };
            if (off as u64).checked_add(size as u64).is_none_or(|end| end > data.len() as u64) {
                return false;
            }
        }
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
        // No 64-bit slice: fall back to 32-bit Intel when present.
        if let Some((off, size)) = first_intel {
            let end = off
                .checked_add(size)
                .ok_or_else(|| super::ImportError::Bad("Mach-O slice overflow".into()))?;
            if end > data.len() {
                return err("Mach-O slice outside file");
            }
            return Ok(off..end);
        }
        return err("Mach-O has no Intel slice");
    }
    Ok(0..data.len())
}

/// Records one segment's file bytes as a mapping at its declared
/// virtual address.
fn push_segment(mappings: &mut Vec<Mapping>, data: &[u8], base: usize,
                fileoff: u64, filesize: u64, vmaddr: u64, initprot: u32) -> Result<()> {
    if filesize == 0 {
        return Ok(());
    }
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
    Ok(())
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
    let magic = u32_le(data, at(0)?)?;
    let is64 = match magic {
        MH_MAGIC_64_LE => true,
        MH_MAGIC_LE => false,
        _ => return err("Mach-O slice is not Intel"),
    };
    let cputype = u32_le(data, at(4)?)?;
    if is64 != (cputype == CPU_TYPE_X86_64) || (!is64 && cputype != CPU_TYPE_I386) {
        return err("Mach-O slice is not x86");
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
    let mut cursor = if is64 { 32 } else { 28 };
    for _ in 0..ncmds {
        let cmd = u32_le(data, at(cursor)?)?;
        let size = u32_le(data, at(cursor + 4)?)? as usize;
        if size < 8 || cursor.checked_add(size).is_none() {
            return err("Mach-O command size invalid");
        }
        match cmd {
            LC_SEGMENT_64 if is64 => {
                let fileoff = u64_le(data, at(cursor + 40)?)?;
                let filesize = u64_le(data, at(cursor + 48)?)?;
                let vmaddr = u64_le(data, at(cursor + 24)?)?;
                let initprot = u32_le(data, at(cursor + 60)?)?;
                push_segment(&mut mappings, data, base, fileoff, filesize,
                             vmaddr, initprot)?;
            }
            LC_SEGMENT if !is64 => {
                if size < 56 {
                    return err("Mach-O segment command truncated");
                }
                let fileoff = u64::from(u32_le(data, at(cursor + 32)?)?);
                let filesize = u64::from(u32_le(data, at(cursor + 36)?)?);
                let vmaddr = u64::from(u32_le(data, at(cursor + 24)?)?);
                let initprot = u32_le(data, at(cursor + 44)?)?;
                push_segment(&mut mappings, data, base, fileoff, filesize,
                             vmaddr, initprot)?;
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
        // 16-byte `nlist_64` or 12-byte `nlist`: the value field is
        // 8 or 4 bytes wide at the same layout otherwise.
        let step = if is64 { 16 } else { 12 };
        for index in 0..nsyms as usize {
            let entry = base + symoff + index * step;
            if entry + step > data.len() {
                return err("Mach-O symtab outside file");
            }
            let strx = u32_le(data, entry)? as usize;
            let n_type = data[entry + 4];
            let value = if is64 {
                u64_le(data, entry + 8)?
            } else {
                u64::from(u32_le(data, entry + 8)?)
            };
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
    imp.language = (if is64 { "x86:LE:64:default" } else { "x86:LE:32:default" }).into();
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
    fn thin_32_loads_segments_as_32_bit() {
        // Minimal thin i386 image: one `__TEXT` segment with a `ret`.
        let mut image = vec![0u8; 84 + 4];
        image[0..4].copy_from_slice(&MH_MAGIC_LE.to_le_bytes());
        image[4..8].copy_from_slice(&CPU_TYPE_I386.to_le_bytes());
        image[12..16].copy_from_slice(&2u32.to_le_bytes());
        image[16..20].copy_from_slice(&1u32.to_le_bytes());
        image[20..24].copy_from_slice(&56u32.to_le_bytes());
        image[28..32].copy_from_slice(&LC_SEGMENT.to_le_bytes());
        image[32..36].copy_from_slice(&56u32.to_le_bytes());
        image[36..42].copy_from_slice(b"__TEXT");
        image[52..56].copy_from_slice(&0x1000u32.to_le_bytes());
        image[56..60].copy_from_slice(&4u32.to_le_bytes());
        image[60..64].copy_from_slice(&84u32.to_le_bytes());
        image[64..68].copy_from_slice(&4u32.to_le_bytes());
        image[68..72].copy_from_slice(&5u32.to_le_bytes());
        image[72..76].copy_from_slice(&5u32.to_le_bytes());
        image[84] = 0xC3;
        assert!(is_macho(&image));
        let found = import(&image).unwrap();
        assert_eq!(found.language, "x86:LE:32:default");
        assert_eq!(found.mappings.len(), 1);
        assert_eq!(found.mappings[0].vaddr, 0x1000);
        assert_eq!(found.mappings[0].flags, 6);
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

    #[test]
    fn java_class_magic_is_not_macho() {
        // `0xCAFEBABE` with a class-file version pair is not a fat
        // table: few arches, entries inside the file, or no claim.
        let mut class = vec![0u8; 64];
        class[0..4].copy_from_slice(&FAT_MAGIC_BE.to_be_bytes());
        class[4..8].copy_from_slice(&52u32.to_be_bytes());
        assert!(!is_macho(&class));
        // Nor is a fat table whose entries leave the file.
        let mut wild = vec![0u8; 64];
        wild[0..4].copy_from_slice(&FAT_MAGIC_BE.to_be_bytes());
        wild[4..8].copy_from_slice(&1u32.to_be_bytes());
        wild[16..20].copy_from_slice(&0x0100_0000u32.to_be_bytes());
        wild[20..24].copy_from_slice(&0x0100_0000u32.to_be_bytes());
        assert!(!is_macho(&wild));
    }
}
