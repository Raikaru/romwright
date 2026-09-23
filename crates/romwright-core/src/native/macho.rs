//! macOS Mach-O loader: fat binaries and 64-bit Intel slices.
//!
//! A fat binary (`0xCAFEBABE`, big-endian headers) carries one slice per
//! architecture; the loader takes the `x86_64` slice when present and
//! refuses anything else by name. A thin image must already be the
//! 64-bit `0xFEEDFACF` little-endian form; 32-bit and non-Intel
//! slices are recognised and refused rather than misread.
//!
//! Each section becomes a mapping at its declared address: code sections
//! read+execute, everything else data, so `__TEXT,__cstring` and
//! `__TEXT,__const` read as data as an ELF `.rodata` does. A segment that
//! declares no sections is mapped whole, except `__LINKEDIT`. `LC_SYMTAB`
//! names the code-section symbols so discovery starts from real names,
//! and `LC_DYSYMTAB`'s indirect table names every import stub and pointer
//! slot. Format reference: Apple's `loader.h` layout as implemented by
//! every open-source reader; independent implementation.

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
/// virtual address. Only for a segment that declares no sections: a
/// sectioned segment is mapped section by section (`Section::mapping`).
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

/// `VM_PROT_WRITE`.
const PROT_WRITE: u32 = 2;
const LC_DYSYMTAB: u32 = 0xB;
/// Section attributes that mark code: `S_ATTR_PURE_INSTRUCTIONS` and
/// `S_ATTR_SOME_INSTRUCTIONS`.
const S_ATTR_INSTRUCTIONS: u32 = 0x8000_0000 | 0x0000_0400;
/// Section types without file bytes: `S_ZEROFILL`, `S_GB_ZEROFILL`,
/// `S_THREAD_LOCAL_ZEROFILL`.
const ZEROFILL_TYPES: [u32; 3] = [0x1, 0xC, 0x12];
/// Section types whose entries the indirect symbol table names:
/// non-lazy and lazy pointers, symbol stubs, lazy dylib pointers.
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_SYMBOL_STUBS: u32 = 0x8;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
/// Indirect-table entries that name no symbol.
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

/// One section header, in load-command order: the `n_sect` ordinal of a
/// symbol is its 1-based index into this list.
struct Section {
    addr: u64,
    size: u64,
    offset: u64,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    writable: bool,
}

impl Section {
    fn code(&self) -> bool {
        self.flags & S_ATTR_INSTRUCTIONS != 0
    }

    /// The section's bytes as a mapping. Code is read+execute; everything
    /// else is read (plus write when its segment is writable), so a
    /// `__TEXT,__cstring` or `__TEXT,__const` reads as data, exactly as an
    /// ELF `.rodata` inside a read-execute segment does.
    fn mapping(&self, data: &[u8], base: usize) -> Result<Option<Mapping>> {
        if self.size == 0 || self.offset == 0 || ZEROFILL_TYPES.contains(&(self.flags & 0xFF)) {
            return Ok(None);
        }
        // A section whose bytes leave the file is refused, like a segment
        // that does: mapping less than the header declares would misread.
        let bytes = usize::try_from(self.offset)
            .ok()
            .and_then(|offset| base.checked_add(offset))
            .and_then(|start| {
                let end = start.checked_add(usize::try_from(self.size).ok()?)?;
                Some((start, data.get(start..end)?))
            });
        let Some((start, bytes)) = bytes else {
            return err("Mach-O section outside file");
        };
        Ok(Some(Mapping {
            vaddr: self.addr,
            size: self.size,
            file_off: start as u64,
            flags: if self.code() {
                6
            } else if self.writable {
                3
            } else {
                2
            },
            bytes: bytes.to_vec(),
        }))
    }
}

/// Reads the section headers that follow a segment command.
fn sections(data: &[u8], at: &dyn Fn(usize) -> Result<usize>, cursor: usize, size: usize,
            is64: bool, initprot: u32) -> Result<Vec<Section>> {
    let (header, entry, count_at) = if is64 { (72, 80, 64) } else { (56, 68, 48) };
    let count = u32_le(data, at(cursor + count_at)?)? as usize;
    if header + count.saturating_mul(entry) > size {
        return err("Mach-O section headers overrun their segment command");
    }
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let s = cursor + header + index * entry;
        let (addr, size, rest) = if is64 {
            (u64_le(data, at(s + 32)?)?, u64_le(data, at(s + 40)?)?, s + 48)
        } else {
            (
                u64::from(u32_le(data, at(s + 32)?)?),
                u64::from(u32_le(data, at(s + 36)?)?),
                s + 40,
            )
        };
        out.push(Section {
            addr,
            size,
            offset: u64::from(u32_le(data, at(rest)?)?),
            flags: u32_le(data, at(rest + 16)?)?,
            reserved1: u32_le(data, at(rest + 20)?)?,
            reserved2: u32_le(data, at(rest + 24)?)?,
            writable: initprot & PROT_WRITE != 0,
        });
    }
    Ok(out)
}

/// Imports the selected slice: sections become mappings, code-section
/// symbols become named functions, and the indirect symbol table names
/// every import stub and pointer slot.
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
    let mut all_sections: Vec<Section> = Vec::new();
    let mut symoff = None;
    let mut nsyms = 0u32;
    let mut stroff = 0usize;
    let mut strsize = 0usize;
    let mut indirect: Option<(usize, usize)> = None;
    let mut cursor = if is64 { 32 } else { 28 };
    for _ in 0..ncmds {
        let cmd = u32_le(data, at(cursor)?)?;
        let size = u32_le(data, at(cursor + 4)?)? as usize;
        if size < 8 || cursor.checked_add(size).is_none() {
            return err("Mach-O command size invalid");
        }
        let segment = match cmd {
            LC_SEGMENT_64 if is64 => Some((
                u64_le(data, at(cursor + 40)?)?,
                u64_le(data, at(cursor + 48)?)?,
                u64_le(data, at(cursor + 24)?)?,
                u32_le(data, at(cursor + 60)?)?,
            )),
            LC_SEGMENT if !is64 => {
                if size < 56 {
                    return err("Mach-O segment command truncated");
                }
                Some((
                    u64::from(u32_le(data, at(cursor + 32)?)?),
                    u64::from(u32_le(data, at(cursor + 36)?)?),
                    u64::from(u32_le(data, at(cursor + 24)?)?),
                    u32_le(data, at(cursor + 44)?)?,
                ))
            }
            LC_SYMTAB => {
                if size < 24 {
                    return err("Mach-O symtab command truncated");
                }
                symoff = Some(u32_le(data, at(cursor + 8)?)? as usize);
                nsyms = u32_le(data, at(cursor + 12)?)?;
                stroff = u32_le(data, at(cursor + 16)?)? as usize;
                strsize = u32_le(data, at(cursor + 20)?)? as usize;
                None
            }
            LC_DYSYMTAB => {
                if size < 64 {
                    return err("Mach-O dysymtab command truncated");
                }
                indirect = Some((
                    u32_le(data, at(cursor + 56)?)? as usize,
                    u32_le(data, at(cursor + 60)?)? as usize,
                ));
                None
            }
            _ => None,
        };
        if let Some((fileoff, filesize, vmaddr, initprot)) = segment {
            let found = sections(data, &at, cursor, size, is64, initprot)?;
            if found.is_empty() {
                // The symbol and string tables live in `__LINKEDIT`: file
                // bytes the loader reads, not program memory, so they are
                // not mapped (their names would read as program strings).
                let name = &data[at(cursor + 8)?..at(cursor + 24)?];
                if !name.starts_with(b"__LINKEDIT") {
                    push_segment(&mut mappings, data, base, fileoff, filesize, vmaddr, initprot)?;
                }
            } else {
                for section in &found {
                    mappings.extend(section.mapping(data, base)?);
                }
                all_sections.extend(found);
            }
        }
        cursor += size;
    }
    if mappings.is_empty() {
        return err("Mach-O slice carries no segments");
    }

    // Symbol names by table index, for the indirect table below.
    let mut names: Vec<Option<String>> = Vec::new();
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
        names.reserve(nsyms as usize);
        for index in 0..nsyms as usize {
            let entry = base + symoff + index * step;
            if entry + step > data.len() {
                return err("Mach-O symtab outside file");
            }
            let strx = u32_le(data, entry)? as usize;
            let n_type = data[entry + 4];
            let n_sect = data[entry + 5] as usize;
            let value = if is64 {
                u64_le(data, entry + 8)?
            } else {
                u64::from(u32_le(data, entry + 8)?)
            };
            let name_off = str_start + strx;
            let name = (name_off < str_end).then(|| {
                let name_end = data[name_off..str_end]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|len| name_off + len)
                    .unwrap_or(str_end);
                let name = String::from_utf8_lossy(&data[name_off..name_end]).into_owned();
                // Mach-O C symbols carry a leading underscore the
                // toolchain adds; the decomp project names them bare.
                match name.strip_prefix('_') {
                    Some(bare) if !bare.is_empty() => bare.to_string(),
                    _ => name,
                }
            });
            names.push(name.clone().filter(|name| !name.is_empty()));
            if n_type & N_STAB != 0 || n_type & N_SECT != N_SECT || value == 0 {
                continue;
            }
            // A section symbol names a function only when its section holds
            // code: `__cstring`, `__const`, `__gcc_except_tab` and `__data`
            // labels are data, and decoding them as bodies would put strings
            // and tables among the program's functions. When the image
            // declares sections, an ordinal that names none of them is not
            // provably code either and is dropped; an image without section
            // headers keeps its symbols.
            if !all_sections.is_empty()
                && !(n_sect > 0 && all_sections.get(n_sect - 1).is_some_and(Section::code))
            {
                continue;
            }
            if let Some(name) = name {
                functions.push(NativeFunction { entry: value, name, size: 0 });
            }
        }
    }

    // Import names: each stub and pointer slot the indirect symbol table
    // covers is named after the undefined symbol it binds, the same
    // (address, name) pairs the ELF loader records for GOT slots.
    let mut externals = Vec::new();
    if let Some((offset, count)) = indirect {
        let pointer = if is64 { 8 } else { 4 };
        for section in &all_sections {
            let width = match section.flags & 0xFF {
                S_NON_LAZY_SYMBOL_POINTERS | S_LAZY_SYMBOL_POINTERS
                | S_LAZY_DYLIB_SYMBOL_POINTERS => pointer,
                S_SYMBOL_STUBS => u64::from(section.reserved2),
                _ => continue,
            };
            if width == 0 {
                continue;
            }
            for slot in 0..section.size / width {
                let index = section.reserved1 as usize + slot as usize;
                if index >= count {
                    break;
                }
                let Ok(symbol) = u32_le(data, base + offset + index * 4) else {
                    break;
                };
                if symbol & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                    continue;
                }
                if let Some(Some(name)) = names.get(symbol as usize) {
                    externals.push((section.addr + slot * width, name.clone()));
                }
            }
        }
    }

    let mut imp = NativeImport::default();
    imp.mappings = mappings;
    imp.functions = functions;
    imp.externals = externals;
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

    /// A thin i386 image with a sectioned `__TEXT` (`__text`, `__cstring`,
    /// `__symbol_stub`), a writable `__DATA,__la_symbol_ptr`, two defined
    /// symbols (one code, one string label) and one undefined import.
    fn sectioned_i386() -> Vec<u8> {
        fn put(image: &mut Vec<u8>, at: usize, value: u32) {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn name(image: &mut [u8], at: usize, text: &[u8]) {
            image[at..at + text.len()].copy_from_slice(text);
        }
        let mut image = vec![0u8; 0x400];
        put(&mut image, 0, MH_MAGIC_LE);
        put(&mut image, 4, CPU_TYPE_I386);
        put(&mut image, 12, 2);
        put(&mut image, 16, 4); // ncmds
        // __TEXT: three sections.
        let text = 28;
        put(&mut image, text, LC_SEGMENT);
        put(&mut image, text + 4, 56 + 3 * 68);
        name(&mut image, text + 8, b"__TEXT");
        put(&mut image, text + 24, 0x1000);
        put(&mut image, text + 28, 0x100);
        put(&mut image, text + 32, 0x200);
        put(&mut image, text + 36, 0x100);
        put(&mut image, text + 44, 5); // r-x
        put(&mut image, text + 48, 3);
        let sections = [
            (b"__text".as_slice(), 0x1000u32, 0x10u32, 0x200u32, 0x8000_0400u32, 0u32, 0u32),
            (b"__cstring", 0x1010, 0x10, 0x210, 0x2, 0, 0),
            (b"__symbol_stub", 0x1020, 0x6, 0x220, S_SYMBOL_STUBS | 0x8000_0400, 0, 6),
        ];
        for (index, (sect, addr, size, offset, flags, r1, r2)) in sections.iter().enumerate() {
            let s = text + 56 + index * 68;
            name(&mut image, s, sect);
            name(&mut image, s + 16, b"__TEXT");
            put(&mut image, s + 32, *addr);
            put(&mut image, s + 36, *size);
            put(&mut image, s + 40, *offset);
            put(&mut image, s + 56, *flags);
            put(&mut image, s + 60, *r1);
            put(&mut image, s + 64, *r2);
        }
        // __DATA: one lazy pointer, indirect index 1.
        let data = text + 56 + 3 * 68;
        put(&mut image, data, LC_SEGMENT);
        put(&mut image, data + 4, 56 + 68);
        name(&mut image, data + 8, b"__DATA");
        put(&mut image, data + 24, 0x2000);
        put(&mut image, data + 28, 0x4);
        put(&mut image, data + 32, 0x230);
        put(&mut image, data + 36, 0x4);
        put(&mut image, data + 44, 3); // rw-
        put(&mut image, data + 48, 1);
        let s = data + 56;
        name(&mut image, s, b"__la_symbol_ptr");
        name(&mut image, s + 16, b"__DATA");
        put(&mut image, s + 32, 0x2000);
        put(&mut image, s + 36, 0x4);
        put(&mut image, s + 40, 0x230);
        put(&mut image, s + 56, S_LAZY_SYMBOL_POINTERS);
        put(&mut image, s + 60, 1);
        // LC_SYMTAB: three nlist entries at 0x300, strings at 0x340.
        let symtab = data + 56 + 68;
        put(&mut image, symtab, LC_SYMTAB);
        put(&mut image, symtab + 4, 24);
        put(&mut image, symtab + 8, 0x300);
        put(&mut image, symtab + 12, 3);
        put(&mut image, symtab + 16, 0x340);
        put(&mut image, symtab + 20, 0x40);
        let symbols = [(1u32, 0x0Fu8, 1u8, 0x1000u32), (7, 0x0F, 2, 0x1010), (14, 0x01, 0, 0)];
        for (index, (strx, n_type, n_sect, value)) in symbols.iter().enumerate() {
            let e = 0x300 + index * 12;
            put(&mut image, e, *strx);
            image[e + 4] = *n_type;
            image[e + 5] = *n_sect;
            put(&mut image, e + 8, *value);
        }
        name(&mut image, 0x341, b"_main\0_label\0_puts\0");
        // LC_DYSYMTAB: indirect table at 0x3a0 = [2 (stub -> puts), 2 (pointer -> puts)].
        let dysym = symtab + 24;
        put(&mut image, dysym, LC_DYSYMTAB);
        put(&mut image, dysym + 4, 80);
        put(&mut image, dysym + 56, 0x3a0);
        put(&mut image, dysym + 60, 2);
        put(&mut image, 0x3a0, 2);
        put(&mut image, 0x3a4, 2);
        name(&mut image, 0x210, b"hello, world\0");
        image
    }

    #[test]
    fn sections_map_by_kind_and_name_their_imports() {
        let found = import(&sectioned_i386()).unwrap();
        let flags = |vaddr: u64| found.mappings.iter().find(|m| m.vaddr == vaddr).map(|m| m.flags);
        // Code executes; a string section inside the r-x segment is data,
        // so the string sweep (readable, not executable) reaches it.
        assert_eq!(flags(0x1000), Some(6));
        assert_eq!(flags(0x1010), Some(2));
        assert_eq!(flags(0x2000), Some(3));
        // The string label is not a function; the code symbol is.
        let names: Vec<_> = found.functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["main"]);
        // The stub and the lazy pointer are both named after their import.
        let mut externals = found.externals.clone();
        externals.sort();
        assert_eq!(externals, [(0x1020, "puts".to_string()), (0x2000, "puts".to_string())]);
    }

    #[test]
    fn a_section_outside_the_file_is_refused() {
        // Same image, cut inside `__cstring`'s bytes: the header still
        // declares the section, so importing must fail, not map less.
        let mut image = sectioned_i386();
        image.truncate(0x214);
        assert!(import(&image).is_err());
    }
}
