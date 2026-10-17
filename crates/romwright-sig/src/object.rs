//! Function patterns from ELF relocatable objects, with every relocated byte
//! masked out.
//!
//! Relocation field widths come from the public `elf.h` type numbers and each
//! architecture's ABI; an unknown type is never given a guessed width. The
//! function that carries it is skipped instead, so a pattern never compares
//! bytes a linker will rewrite.

/// A rejection of the object itself, before any function is considered.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObjectError {
    #[error("not an ELF object")]
    NotElf,
    #[error("unsupported ELF class {0}")]
    BadClass(u8),
    #[error("unsupported ELF data encoding {0}")]
    BadEncoding(u8),
    #[error("ELF type {0} is not a relocatable object")]
    NotRelocatable(u16),
    #[error("truncated ELF structure at {offset}")]
    Truncated { offset: usize },
    #[error("section {index} is out of range")]
    BadSection { index: usize },
    #[error("relocation entry size {0} is malformed")]
    BadRelocationSize(u64),
    #[error("symbol entry size {0} is malformed")]
    BadSymbolSize(u64),
}

type Result<T> = std::result::Result<T, ObjectError>;

/// Why a defined function produced no signature. Coverage, not corruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// A relocation type with no ABI width in this build's tables.
    UnknownRelocation(u64),
    /// A relocation field crosses the symbol's end: the size is untrustworthy.
    RelocationOutsideFunction,
    /// Longer than a signature container record may hold.
    TooLong,
    /// Section bytes for the symbol are missing or empty.
    NoBytes,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::UnknownRelocation(_) => "unknown-relocation",
            SkipReason::RelocationOutsideFunction => "relocation-outside-function",
            SkipReason::TooLong => "too-long",
            SkipReason::NoBytes => "no-bytes",
        }
    }
}

/// One extracted function: its bytes and which of them a linker may rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub name: String,
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: SkipReason,
}

/// Extracted functions of one relocatable object, plus its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub machine: u16,
    pub big_endian: bool,
    pub class64: bool,
    pub flags: u32,
    /// Exported (global or weak) functions: the records' names.
    pub functions: Vec<Extracted>,
    /// Local functions. Their names identify nothing outside their own
    /// translation unit, but their bodies still occupy the image and compete
    /// with exported records.
    pub locals: Vec<Extracted>,
    pub skipped: Vec<Skipped>,
}

/// Byte width a relocation of `kind` rewrites on `machine`, or `None` when
/// this build has no ABI evidence for that type.
pub fn relocation_width(machine: u16, kind: u64) -> Option<usize> {
    match machine {
        // x86-64: public elf.h R_X86_64_* numbering.
        0x3e => match kind {
            0 | 35 => Some(0), // NONE, TLSDESC_CALL: markers with no field
            1 | 6 | 7 | 8 | 16 | 17 | 18 | 24 | 25 | 37 => Some(8),
            2 | 3 | 4 | 9 | 10 | 11 | 19 | 20 | 21 | 22 | 23 | 26 | 34 | 41 | 42 | 43 => Some(4),
            12 | 13 => Some(2),
            14 | 15 => Some(1),
            36 => Some(16), // TLSDESC: two words
            _ => None,
        },
        // i386: public elf.h R_386_* numbering.
        0x03 => match kind {
            0 | 25 | 26 | 27 | 29 | 30 | 31 | 40 => Some(0),
            1..=11 | 14..=19 | 24 | 28 | 32..=39 | 41 | 42 | 43 => Some(4),
            20 | 21 => Some(2),
            22 | 23 => Some(1),
            _ => None,
        },
        // AArch64: 257..262 patch data words; every other static relocation
        // patches a field inside one 4-byte instruction.
        0xb7 => match kind {
            0 => Some(0),
            257 | 260 => Some(8),
            258 | 261 => Some(4),
            259 | 262 => Some(2),
            263..=600 => Some(4),
            _ => None,
        },
        // PowerPC 32-bit: elf.h R_PPC_* numbering. `word32` fields are 4
        // bytes, `half16` fields 2, and the `none` markers patch nothing.
        0x14 => match kind {
            0 | 67 | 95 | 96 => Some(0),
            1 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 26
            | 27 | 28 | 68 | 73 | 78 => Some(4),
            3 | 4 | 5 | 6 | 14 | 15 | 16 | 17 | 25 | 29 | 30 | 31 | 32 | 33 | 34 | 35 | 36
            | 69..=72 | 74..=77 | 79..=94 | 249..=252 => Some(2),
            _ => None,
        },
        // MIPS: elf.h R_MIPS_* numbering. Instruction fields (26-bit jump
        // targets, 16-bit HI/LO/GPREL/GOT/PC immediates, shift amounts) sit at
        // a byte offset that depends on endianness, which this table does not
        // see, so the whole 4-byte instruction is masked.
        0x08 => match kind {
            0 => Some(0),                                       // NONE
            1 => Some(2),                                       // 16
            2 | 3 | 12 => Some(4),                              // 32, REL32, GPREL32
            18 | 24 => Some(8),                                 // 64, SUB
            4..=11 | 16 | 17 | 19..=23 | 28..=31 | 37 => Some(4), // instruction fields
            _ => None,
        },
        _ => None,
    }
}

struct Elf<'a> {
    bytes: &'a [u8],
    big_endian: bool,
    class64: bool,
}

impl<'a> Elf<'a> {
    fn slice(&self, at: usize, len: usize) -> Result<&'a [u8]> {
        self.bytes
            .get(at..at.checked_add(len).ok_or(ObjectError::Truncated { offset: at })?)
            .ok_or(ObjectError::Truncated { offset: at })
    }

    fn word(&self, at: usize, size: usize) -> Result<u64> {
        let bytes = self.slice(at, size)?;
        Ok(bytes.iter().enumerate().fold(0u64, |value, (index, &byte)| {
            let shift = if self.big_endian { size - 1 - index } else { index };
            value | (byte as u64) << (8 * shift)
        }))
    }

    fn half(&self, at: usize) -> Result<u16> {
        Ok(self.word(at, 2)? as u16)
    }

    fn full(&self, at: usize) -> Result<u32> {
        Ok(self.word(at, 4)? as u32)
    }

    /// Address-sized field: 4 bytes on ELF32, 8 on ELF64.
    fn addr(&self, at: usize) -> Result<u64> {
        self.word(at, if self.class64 { 8 } else { 4 })
    }
}

#[derive(Clone, Copy)]
struct Section {
    typ: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    entry_size: u64,
}

/// Extracts every exported function of an ELF relocatable object.
///
/// Local symbols are left out on purpose: a static helper's name identifies
/// nothing outside its own translation unit, and several objects in one archive
/// reuse it.
pub fn relocatable(bytes: &[u8], max_pattern: usize) -> Result<Object> {
    if bytes.len() < 24 || !bytes.starts_with(b"\x7fELF") {
        return Err(ObjectError::NotElf);
    }
    let class64 = match bytes[4] {
        1 => false,
        2 => true,
        other => return Err(ObjectError::BadClass(other)),
    };
    let big_endian = match bytes[5] {
        1 => false,
        2 => true,
        other => return Err(ObjectError::BadEncoding(other)),
    };
    let elf = Elf {
        bytes,
        big_endian,
        class64,
    };
    let typ = elf.half(16)?;
    if typ != 1 {
        return Err(ObjectError::NotRelocatable(typ));
    }
    let machine = elf.half(18)?;
    let (flags_at, shoff_at, shentsize_at) = if class64 {
        (48, 40, 58)
    } else {
        (36, 32, 46)
    };
    let flags = elf.full(flags_at)?;
    let shoff = elf.addr(shoff_at)? as usize;
    let shentsize = elf.half(shentsize_at)? as usize;
    let shnum = elf.half(shentsize_at + 2)? as usize;
    let expected = if class64 { 64 } else { 40 };
    if shentsize != expected {
        return Err(ObjectError::BadSection { index: 0 });
    }
    let mut sections = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let at = shoff + index * shentsize;
        let (flags_off, offset_off, size_off, link_off, entry_off) = if class64 {
            (8, 24, 32, 40, 56)
        } else {
            (8, 16, 20, 24, 36)
        };
        sections.push(Section {
            typ: elf.full(at + 4)?,
            flags: elf.addr(at + flags_off)?,
            offset: elf.addr(at + offset_off)? as usize,
            size: elf.addr(at + size_off)? as usize,
            link: elf.full(at + link_off)?,
            info: elf.full(at + link_off + 4)?,
            entry_size: elf.addr(at + entry_off)?,
        });
    }
    let mut functions = Vec::new();
    let mut locals = Vec::new();
    let mut skipped = Vec::new();
    let symbol_size = if class64 { 24 } else { 16 };
    for symbols in sections.iter().filter(|section| section.typ == 2) {
        if symbols.entry_size != symbol_size as u64 {
            return Err(ObjectError::BadSymbolSize(symbols.entry_size));
        }
        let strings = sections
            .get(symbols.link as usize)
            .ok_or(ObjectError::BadSection {
                index: symbols.link as usize,
            })?;
        let table = elf.slice(strings.offset, strings.size)?;
        for index in 0..symbols.size / symbol_size {
            let at = symbols.offset + index * symbol_size;
            let name_offset = elf.full(at)? as usize;
            let (info, shndx, value, size) = if class64 {
                (
                    elf.slice(at + 4, 1)?[0],
                    elf.half(at + 6)?,
                    elf.addr(at + 8)?,
                    elf.addr(at + 16)?,
                )
            } else {
                (
                    elf.slice(at + 12, 1)?[0],
                    elf.half(at + 14)?,
                    elf.addr(at + 4)? & 0xffff_ffff,
                    elf.addr(at + 8)? & 0xffff_ffff,
                )
            };
            // STT_FUNC of any binding; the binding decides its role below.
            if info & 0xf != 2 || !matches!(info >> 4, 0 | 1 | 2) {
                continue;
            }
            let exported = info >> 4 != 0;
            let name = table
                .get(name_offset..)
                .and_then(|tail| tail.split(|&byte| byte == 0).next())
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default();
            if name.is_empty() || size == 0 {
                continue;
            }
            let owner = match sections.get(shndx as usize) {
                Some(section) if section.typ == 1 && section.flags & 4 != 0 => section,
                _ => continue,
            };
            let start = value as usize;
            let length = size as usize;
            if length > max_pattern {
                skipped.push(Skipped {
                    name,
                    reason: SkipReason::TooLong,
                });
                continue;
            }
            let Some(pattern) = owner
                .size
                .checked_sub(start)
                .filter(|remaining| *remaining >= length)
                .and_then(|_| elf.slice(owner.offset + start, length).ok())
            else {
                skipped.push(Skipped {
                    name,
                    reason: SkipReason::NoBytes,
                });
                continue;
            };
            let mut mask = vec![0xffu8; length];
            let mut reason = None;
            for relocations in sections
                .iter()
                .filter(|section| matches!(section.typ, 4 | 9) && section.info == shndx as u32)
            {
                let stride = if relocations.typ == 4 {
                    if class64 { 24 } else { 12 }
                } else if class64 {
                    16
                } else {
                    8
                };
                if relocations.entry_size != stride as u64 {
                    return Err(ObjectError::BadRelocationSize(relocations.entry_size));
                }
                for entry in 0..relocations.size / stride {
                    let at = relocations.offset + entry * stride;
                    let offset = elf.addr(at)? as usize;
                    let info = elf.addr(at + if class64 { 8 } else { 4 })?;
                    let kind = if class64 { info & 0xffff_ffff } else { info & 0xff };
                    if offset < start || offset >= start + length {
                        continue;
                    }
                    let Some(width) = relocation_width(machine, kind) else {
                        reason = Some(SkipReason::UnknownRelocation(kind));
                        break;
                    };
                    let field = offset - start;
                    if field + width > length {
                        reason = Some(SkipReason::RelocationOutsideFunction);
                        break;
                    }
                    mask[field..field + width].fill(0);
                }
                if reason.is_some() {
                    break;
                }
            }

            match reason {
                Some(reason) if exported => skipped.push(Skipped { name, reason }),
                Some(_) => {}
                None => (if exported { &mut functions } else { &mut locals }).push(Extracted {
                    name,
                    pattern: pattern
                        .iter()
                        .zip(&mask)
                        .map(|(&byte, &keep)| if keep == 0 { 0 } else { byte })
                        .collect(),
                    mask,
                }),
            }
        }
    }
    Ok(Object {
        machine,
        big_endian,
        class64,
        flags,
        functions,
        locals,
        skipped,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    struct Layout {
        class64: bool,
        big_endian: bool,
        machine: u16,
        rela: bool,
    }

    /// Minimal ET_REL object: one executable section, a symbol table and one
    /// relocation section for that code.
    fn object(
        layout: &Layout,
        code: &[u8],
        symbols: &[(&str, u8, u64, u64)],
        relocations: &[(u64, u64)],
    ) -> Vec<u8> {
        let word = |value: u64, size: usize| -> Vec<u8> {
            let mut bytes: Vec<u8> = (0..size).map(|index| (value >> (8 * index)) as u8).collect();
            if layout.big_endian {
                bytes.reverse();
            }
            bytes
        };
        let address = |value: u64| word(value, if layout.class64 { 8 } else { 4 });
        let symbol_size = if layout.class64 { 24 } else { 16 };
        let relocation_size = match (layout.rela, layout.class64) {
            (true, true) => 24,
            (true, false) => 12,
            (false, true) => 16,
            (false, false) => 8,
        };
        let mut strings = vec![0u8];
        let mut symbol_table = vec![0u8; symbol_size];
        for &(name, info, value, size) in symbols {
            let offset = strings.len() as u32;
            strings.extend(name.as_bytes());
            strings.push(0);
            let mut entry = Vec::new();
            if layout.class64 {
                entry.extend(word(offset as u64, 4));
                entry.push(info);
                entry.push(0);
                entry.extend(word(1, 2));
                entry.extend(address(value));
                entry.extend(address(size));
            } else {
                entry.extend(word(offset as u64, 4));
                entry.extend(address(value));
                entry.extend(address(size));
                entry.push(info);
                entry.push(0);
                entry.extend(word(1, 2));
            }
            assert_eq!(entry.len(), symbol_size);
            symbol_table.extend(entry);
        }
        let mut relocation_table = Vec::new();
        for &(offset, kind) in relocations {
            let mut entry = address(offset);
            entry.extend(address(kind << if layout.class64 { 32 } else { 8 } | kind));
            if layout.rela {
                entry.extend(address(0));
            }
            assert_eq!(entry.len(), relocation_size);
            relocation_table.extend(entry);
        }
        let header_len = if layout.class64 { 64 } else { 52 };
        let section_len = if layout.class64 { 64 } else { 40 };
        let shoff = header_len;
        let code_at = header_len + 5 * section_len;
        let symbols_at = code_at + code.len();
        let relocations_at = symbols_at + symbol_table.len();
        let strings_at = relocations_at + relocation_table.len();
        let mut bytes = b"\x7fELF".to_vec();
        bytes.push(if layout.class64 { 2 } else { 1 });
        bytes.push(if layout.big_endian { 2 } else { 1 });
        bytes.push(1);
        bytes.resize(16, 0);
        bytes.extend(word(1, 2)); // ET_REL
        bytes.extend(word(layout.machine as u64, 2));
        bytes.extend(word(1, 4));
        bytes.extend(address(0)); // e_entry
        bytes.extend(address(0)); // e_phoff
        bytes.extend(address(shoff as u64));
        bytes.extend(word(0, 4)); // e_flags
        bytes.extend(word(header_len as u64, 2));
        bytes.extend(word(0, 2));
        bytes.extend(word(0, 2));
        bytes.extend(word(section_len as u64, 2));
        bytes.extend(word(5, 2));
        bytes.extend(word(4, 2));
        assert_eq!(bytes.len(), header_len);
        // [0] null, [1] .text, [2] relocations, [3] .symtab, [4] .strtab
        for (typ, flags, offset, size, link, info, entry_size) in [
            (0u32, 0u64, 0usize, 0usize, 0u32, 0u32, 0u64),
            (1, 6, code_at, code.len(), 0, 0, 0),
            (
                if layout.rela { 4 } else { 9 },
                0,
                relocations_at,
                relocation_table.len(),
                3,
                1,
                relocation_size as u64,
            ),
            (2, 0, symbols_at, symbol_table.len(), 4, 0, symbol_size as u64),
            (3, 0, strings_at, strings.len(), 0, 0, 0),
        ] {
            bytes.extend(word(0, 4));
            bytes.extend(word(typ as u64, 4));
            bytes.extend(address(flags));
            bytes.extend(address(0));
            bytes.extend(address(offset as u64));
            bytes.extend(address(size as u64));
            bytes.extend(word(link as u64, 4));
            bytes.extend(word(info as u64, 4));
            bytes.extend(address(1));
            bytes.extend(address(entry_size));
        }
        assert_eq!(bytes.len(), code_at);
        bytes.extend(code);
        bytes.extend(symbol_table);
        bytes.extend(relocation_table);
        bytes.extend(strings);
        bytes
    }

    #[test]
    fn relocated_bytes_are_masked_and_local_symbols_ignored() {
        let layout = Layout {
            class64: true,
            big_endian: false,
            machine: 0x3e,
            rela: true,
        };
        let code = vec![
            0x55, 0xe8, 0x11, 0x22, 0x33, 0x44, 0x5d, 0xc3, // exported: call is relocated
            0x90, 0x90, 0x90, 0x90, // local helper
        ];
        let bytes = object(
            &layout,
            &code,
            &[
                ("exported", 0x12, 0, 8),
                ("helper", 0x02, 8, 4),
                ("weak_alias", 0x22, 0, 8),
            ],
            &[(2, 4)], // R_X86_64_PLT32 inside `exported`
        );
        let object = relocatable(&bytes, 4096).unwrap();
        assert_eq!((object.machine, object.class64, object.big_endian), (0x3e, true, false));
        assert!(object.skipped.is_empty(), "{:?}", object.skipped);
        let names: Vec<_> = object.functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["exported", "weak_alias"], "local symbols name nothing");
        let exported = &object.functions[0];
        assert_eq!(
            exported.mask,
            [0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff],
            "only the relocated displacement is ignored"
        );
        assert_eq!(exported.pattern, [0x55, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3]);
    }

    #[test]
    fn big_endian_rel_objects_and_unknown_relocations_are_handled() {
        let layout = Layout {
            class64: false,
            big_endian: true,
            machine: 0x14,
            rela: false,
        };
        let code = vec![
            0x48, 0x00, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20, // exported: REL24 branch
            0x38, 0x60, 0x00, 0x00, 0x4e, 0x80, 0x00, 0x20, // unknown relocation type
        ];
        let bytes = object(
            &layout,
            &code,
            &[("exported", 0x12, 0, 8), ("mystery", 0x12, 8, 8)],
            &[(0, 10), (9, 200)],
        );
        let object = relocatable(&bytes, 4096).unwrap();
        assert_eq!(object.functions.len(), 1);
        assert_eq!(object.functions[0].mask, [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            object.skipped,
            vec![Skipped {
                name: "mystery".into(),
                reason: SkipReason::UnknownRelocation(200),
            }],
            "a relocation with no ABI width must not be guessed"
        );
    }

    #[test]
    fn non_relocatable_and_malformed_inputs_are_rejected() {
        assert_eq!(relocatable(b"nope", 16).unwrap_err(), ObjectError::NotElf);
        let layout = Layout {
            class64: true,
            big_endian: false,
            machine: 0x3e,
            rela: true,
        };
        let mut bytes = object(&layout, &[0x90, 0xc3], &[("f", 0x12, 0, 2)], &[]);
        bytes[16] = 2; // ET_EXEC
        assert_eq!(
            relocatable(&bytes, 16).unwrap_err(),
            ObjectError::NotRelocatable(2)
        );
        bytes[16] = 1;
        bytes[4] = 7;
        assert_eq!(relocatable(&bytes, 16).unwrap_err(), ObjectError::BadClass(7));
        let long = object(&layout, &[0x90; 32], &[("f", 0x12, 0, 32)], &[]);
        let object = relocatable(&long, 8).unwrap();
        assert_eq!(object.skipped[0].reason, SkipReason::TooLong);
    }
}
