//! A small ELF32 little-endian reader: exactly what project bootstrapping
//! needs from a PlayStation 2 executable (program headers for the file
//! layout, section names and the symbol table as compiler evidence,
//! `.reginfo` for `_gp`). The importer's own loader answers what the program
//! *is*; this answers what the *file* looks like, byte for byte.

use std::ops::Range;

pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_MIPS_REGINFO: u32 = 0x7000_0006;
pub const PT_LOAD: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phdr {
    pub p_type: u32,
    pub offset: u32,
    pub vaddr: u32,
    pub filesz: u32,
    pub memsz: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shdr {
    pub name: String,
    pub sh_type: u32,
    pub flags: u32,
    pub addr: u32,
    pub offset: u32,
    pub size: u32,
    pub link: u32,
    pub entsize: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sym {
    pub name: String,
    pub value: u32,
    pub size: u32,
    /// `STT_*` (low nibble of `st_info`).
    pub kind: u8,
}

#[derive(Debug, Clone)]
pub struct Elf32<'a> {
    pub data: &'a [u8],
    pub entry: u32,
    pub phdrs: Vec<Phdr>,
    pub sections: Vec<Shdr>,
}

fn u16_at(data: &[u8], off: usize) -> Result<u16, String> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| format!("ELF truncated at {off:#x}"))
}

fn u32_at(data: &[u8], off: usize) -> Result<u32, String> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("ELF truncated at {off:#x}"))
}

fn c_string(data: &[u8], off: usize) -> String {
    let tail = data.get(off..).unwrap_or(&[]);
    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

impl<'a> Elf32<'a> {
    /// Parses an ELF32 little-endian executable. Section headers are
    /// optional (a stripped image has none); program headers are required.
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 52 || &data[..4] != b"\x7fELF" {
            return Err("not an ELF file".into());
        }
        if data[4] != 1 || data[5] != 1 {
            return Err("not a 32-bit little-endian ELF (PS2 executables are ELF32 LE)".into());
        }
        let entry = u32_at(data, 0x18)?;
        let phoff = u32_at(data, 0x1c)? as usize;
        let shoff = u32_at(data, 0x20)? as usize;
        let phentsize = u16_at(data, 0x2a)? as usize;
        let phnum = u16_at(data, 0x2c)? as usize;
        let shentsize = u16_at(data, 0x2e)? as usize;
        let shnum = u16_at(data, 0x30)? as usize;
        let shstrndx = u16_at(data, 0x32)? as usize;
        let mut phdrs = Vec::with_capacity(phnum);
        for index in 0..phnum {
            let at = phoff + index * phentsize;
            phdrs.push(Phdr {
                p_type: u32_at(data, at)?,
                offset: u32_at(data, at + 4)?,
                vaddr: u32_at(data, at + 8)?,
                filesz: u32_at(data, at + 16)?,
                memsz: u32_at(data, at + 20)?,
                flags: u32_at(data, at + 24)?,
            });
        }
        let mut raw = Vec::new();
        if shoff != 0 && shnum != 0 && shentsize >= 40 {
            for index in 0..shnum {
                let at = shoff + index * shentsize;
                raw.push((
                    u32_at(data, at)?,
                    u32_at(data, at + 4)?,
                    u32_at(data, at + 8)?,
                    u32_at(data, at + 12)?,
                    u32_at(data, at + 16)?,
                    u32_at(data, at + 20)?,
                    u32_at(data, at + 24)?,
                    u32_at(data, at + 36)?,
                ));
            }
        }
        let names_at = raw.get(shstrndx).map(|row| row.4 as usize);
        let sections = raw
            .iter()
            .map(|&(name, sh_type, flags, addr, offset, size, link, entsize)| Shdr {
                name: names_at.map(|base| c_string(data, base + name as usize)).unwrap_or_default(),
                sh_type,
                flags,
                addr,
                offset,
                size,
                link,
                entsize,
            })
            .collect();
        Ok(Self { data, entry, phdrs, sections })
    }

    /// File-backed `PT_LOAD` segments, in file order.
    pub fn loads(&self) -> Vec<&Phdr> {
        let mut loads: Vec<&Phdr> =
            self.phdrs.iter().filter(|p| p.p_type == PT_LOAD && p.filesz != 0).collect();
        loads.sort_by_key(|p| p.offset);
        loads
    }

    pub fn section(&self, name: &str) -> Option<&Shdr> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn bytes(&self, section: &Shdr) -> &'a [u8] {
        if section.sh_type == SHT_NOBITS {
            return &[];
        }
        let start = section.offset as usize;
        self.data.get(start..start + section.size as usize).unwrap_or(&[])
    }

    /// The `_gp` the linker recorded in `.reginfo` (`ri_gp_value`).
    pub fn gp_value(&self) -> Option<u32> {
        let reginfo = self.sections.iter().find(|s| s.sh_type == SHT_MIPS_REGINFO)?;
        let bytes = self.bytes(reginfo);
        (bytes.len() >= 24).then(|| u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]))
    }

    /// Every symbol of the first symbol table; empty for a stripped image.
    pub fn symbols(&self) -> Vec<Sym> {
        let Some(table) = self.sections.iter().find(|s| s.sh_type == SHT_SYMTAB) else {
            return Vec::new();
        };
        let Some(strings) = self.sections.get(table.link as usize) else {
            return Vec::new();
        };
        let (rows, names) = (self.bytes(table), self.bytes(strings));
        rows.as_chunks::<16>().0.iter()
            .map(|row| {
                let name = u32::from_le_bytes([row[0], row[1], row[2], row[3]]) as usize;
                Sym {
                    name: c_string(names, name),
                    value: u32::from_le_bytes([row[4], row[5], row[6], row[7]]),
                    size: u32::from_le_bytes([row[8], row[9], row[10], row[11]]),
                    kind: row[12] & 0xf,
                }
            })
            .collect()
    }

    /// Byte range of a program header in the file.
    pub fn file_range(phdr: &Phdr) -> Range<usize> {
        phdr.offset as usize..phdr.offset as usize + phdr.filesz as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Vec<u8> {
        let mut image = vec![0u8; 0x100];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 1;
        image[5] = 1;
        image[0x18..0x1c].copy_from_slice(&0x100008u32.to_le_bytes());
        image[0x1c..0x20].copy_from_slice(&0x34u32.to_le_bytes());
        image[0x2a..0x2c].copy_from_slice(&32u16.to_le_bytes());
        image[0x2c..0x2e].copy_from_slice(&1u16.to_le_bytes());
        let ph = 0x34;
        image[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        image[ph + 4..ph + 8].copy_from_slice(&0x80u32.to_le_bytes());
        image[ph + 8..ph + 12].copy_from_slice(&0x100000u32.to_le_bytes());
        image[ph + 16..ph + 20].copy_from_slice(&0x80u32.to_le_bytes());
        image
    }

    #[test]
    fn parses_program_headers_without_sections() {
        let image = tiny();
        let elf = Elf32::parse(&image).unwrap();
        assert_eq!(elf.entry, 0x100008);
        let loads = elf.loads();
        assert_eq!(loads.len(), 1);
        assert_eq!((loads[0].offset, loads[0].vaddr, loads[0].filesz), (0x80, 0x100000, 0x80));
        assert!(elf.sections.is_empty());
        assert!(elf.symbols().is_empty());
        assert_eq!(elf.gp_value(), None);
    }

    #[test]
    fn rejects_non_elf_and_big_endian() {
        assert!(Elf32::parse(b"MZ").is_err());
        let mut image = tiny();
        image[5] = 2;
        assert!(Elf32::parse(&image).is_err());
    }
}
