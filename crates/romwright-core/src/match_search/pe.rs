//! 32-bit Windows (PE, i386) support for the near-miss search: the COFF object Visual C++ (or clang for a Windows
//! target) writes for one unit, the retail bytes of a function out of the PE image, and the name decoration the compiler
//! adds (`_f`, `_f@12`, `@f@8`) that the project's target objects do not carry.
//!
//! The comparison is the same as `tests/m22-004_pc_c_output.py`'s: the bytes of the function with the four-byte
//! relocation fields (`DIR32`, `REL32`) masked, and objdiff-cli on one-function ELF objects that carry the compiled
//! function's relocations on both sides.

use super::object::{Function, Relocation};

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_REL_I386_DIR32: u16 = 0x0006;
const IMAGE_REL_I386_DIR32NB: u16 = 0x0007;
const IMAGE_REL_I386_REL32: u16 = 0x0014;
/// ELF i386 relocation types the objdiff objects use.
pub const R_386_32: u32 = 1;
pub const R_386_PC32: u32 = 2;

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| "object truncated".to_string())
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or_else(|| "object truncated".to_string())
}

/// A COFF object of the i386 machine (the magic is the machine field: there is no signature).
pub fn is_coff(data: &[u8]) -> bool {
    data.len() >= 20 && u16::from_le_bytes([data[0], data[1]]) == IMAGE_FILE_MACHINE_I386
}

/// `_f@12` -> `f`, `@f@8` -> `f`, `_f` -> `f`; a name with no decoration is returned as it is.
pub fn undecorate(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix('@') {
        return match rest.rsplit_once('@') {
            Some((base, args)) if !base.is_empty() && !args.is_empty() && args.bytes().all(|b| b.is_ascii_digit()) => base,
            _ => name,
        };
    }
    if let Some(rest) = name.strip_prefix('_') {
        return match rest.rsplit_once('@') {
            Some((base, args)) if !base.is_empty() && !args.is_empty() && args.bytes().all(|b| b.is_ascii_digit()) => base,
            _ => rest,
        };
    }
    name
}

struct Section {
    body: Vec<u8>,
    code: bool,
    /// (offset in the section, symbol index, COFF type)
    relocs: Vec<(usize, usize, u16)>,
}

struct Symbol {
    name: String,
    value: usize,
    section: i16,
    kind: u16,
    storage: u8,
    aux: bool,
}

pub struct CoffObject {
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
}

impl CoffObject {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if !is_coff(data) {
            return Err("not an i386 COFF object".into());
        }
        let sections_count = u16_at(data, 2)? as usize;
        let symbols_at = u32_at(data, 8)? as usize;
        let symbols_count = u32_at(data, 12)? as usize;
        let optional = u16_at(data, 16)? as usize;
        let strings_at = symbols_at + 18 * symbols_count;
        let string = |offset: usize| -> String {
            let tail = data.get(strings_at + offset..).unwrap_or(&[]);
            let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
            String::from_utf8_lossy(&tail[..end]).into_owned()
        };
        let mut symbols = Vec::with_capacity(symbols_count);
        let mut index = 0;
        while index < symbols_count {
            let at = symbols_at + 18 * index;
            let entry = data.get(at..at + 18).ok_or("symbol table truncated")?;
            let name = if entry[..4] == [0, 0, 0, 0] {
                string(u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]) as usize)
            } else {
                String::from_utf8_lossy(&entry[..8]).trim_end_matches('\0').to_string()
            };
            let aux = entry[17] as usize;
            symbols.push(Symbol {
                name,
                value: u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize,
                section: i16::from_le_bytes([entry[12], entry[13]]),
                kind: u16::from_le_bytes([entry[14], entry[15]]),
                storage: entry[16],
                aux: false,
            });
            for _ in 0..aux {
                symbols.push(Symbol { name: String::new(), value: 0, section: 0, kind: 0, storage: 0, aux: true });
            }
            index += 1 + aux;
        }
        let mut sections = Vec::with_capacity(sections_count);
        for i in 0..sections_count {
            let at = 20 + optional + 40 * i;
            let size = u32_at(data, at + 16)? as usize;
            let raw = u32_at(data, at + 20)? as usize;
            let relocs_at = u32_at(data, at + 24)? as usize;
            let relocs_count = u16_at(data, at + 32)? as usize;
            let characteristics = u32_at(data, at + 36)?;
            let body = if raw != 0 && characteristics & 0x80 == 0 { data.get(raw..raw + size).ok_or("section data truncated")?.to_vec() } else { Vec::new() };
            let mut relocs = Vec::with_capacity(relocs_count);
            for r in 0..relocs_count {
                let rat = relocs_at + 10 * r;
                relocs.push((u32_at(data, rat)? as usize, u32_at(data, rat + 4)? as usize, u16_at(data, rat + 8)?));
            }
            sections.push(Section { body, code: characteristics & 0x20 != 0, relocs });
        }
        Ok(CoffObject { sections, symbols })
    }

    /// The function the object defines under `name` (decoration ignored): its bytes up to the next function symbol of its
    /// section, without the compiler's trailing `nop`/`int3` alignment, and the relocations inside it.
    pub fn function(&self, name: &str) -> Result<Function, String> {
        let defined = |s: &Symbol| !s.aux && s.section > 0 && matches!(s.storage, 2 | 3) && s.kind & 0xF0 == 0x20 && self.sections.get(s.section as usize - 1).is_some_and(|sec| sec.code);
        let symbol = self
            .symbols
            .iter()
            .find(|s| defined(s) && (s.name == name || undecorate(&s.name) == name))
            .ok_or_else(|| format!("the object defines no function `{name}`"))?;
        let section = &self.sections[symbol.section as usize - 1];
        let end = self
            .symbols
            .iter()
            .filter(|s| defined(s) && s.section == symbol.section && s.value > symbol.value)
            .map(|s| s.value)
            .min()
            .unwrap_or(section.body.len());
        let mut body = section.body.get(symbol.value..end).ok_or("function outside its section")?.to_vec();
        while body.last().is_some_and(|b| matches!(b, 0x90 | 0xCC)) {
            body.pop();
        }
        let mut relocations = Vec::new();
        for &(offset, symbol_index, kind) in &section.relocs {
            if offset < symbol.value || offset >= symbol.value + body.len() {
                continue;
            }
            let r_type = match kind {
                IMAGE_REL_I386_DIR32 | IMAGE_REL_I386_DIR32NB => R_386_32,
                IMAGE_REL_I386_REL32 => R_386_PC32,
                _ => continue,
            };
            let target = self.symbols.get(symbol_index);
            relocations.push(Relocation {
                offset: offset - symbol.value,
                r_type,
                symbol: target.filter(|t| !t.name.is_empty()).map(|t| undecorate(&t.name).to_string()),
                field: Some(0xFFFF_FFFF),
            });
        }
        Ok(Function { name: name.to_string(), thumb: false, body, relocations })
    }
}

/// The bytes of `[address, address + size)` of a PE32 image, as the loader maps them (zero beyond a section's raw data).
pub fn retail_bytes(data: &[u8], address: u64, size: u64) -> Result<Vec<u8>, String> {
    if data.get(..2) != Some(b"MZ") {
        return Err("not a PE image".into());
    }
    let pe = u32_at(data, 0x3c)? as usize;
    if data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("no PE signature".into());
    }
    let sections = u16_at(data, pe + 6)? as usize;
    let optional = u16_at(data, pe + 20)? as usize;
    let base = u64::from(u32_at(data, pe + 24 + 28)?);
    for i in 0..sections {
        let at = pe + 24 + optional + 40 * i;
        let virtual_size = u64::from(u32_at(data, at + 8)?);
        let virtual_address = base + u64::from(u32_at(data, at + 12)?);
        let raw_size = u64::from(u32_at(data, at + 16)?);
        let raw = u64::from(u32_at(data, at + 20)?);
        let extent = virtual_size.max(raw_size);
        if address >= virtual_address && address + size <= virtual_address + extent {
            let offset = address - virtual_address;
            let have = raw_size.saturating_sub(offset).min(size) as usize;
            let start = (raw + offset) as usize;
            let mut bytes = data.get(start..start + have).ok_or("section data is past the end of the file")?.to_vec();
            bytes.resize(size as usize, 0);
            return Ok(bytes);
        }
    }
    Err(format!("{address:#x}+{size:#x} is not inside a section of the image"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoration_is_stripped_the_way_the_project_builds_strip_it() {
        for (raw, plain) in [("_f", "f"), ("_f@12", "f"), ("@f@8", "f"), ("f", "f"), ("_a@b", "a@b"), ("@x", "@x"), ("_FUN_00401000@4", "FUN_00401000")] {
            assert_eq!(undecorate(raw), plain, "{raw}");
        }
    }

    /// A COFF object with `_f@8` (`mov eax,[abs]; ret 8` + padding) and one DIR32 relocation, hand-assembled.
    fn object() -> Vec<u8> {
        let code = [0xA1u8, 0, 0, 0, 0, 0xC2, 0x08, 0x00, 0x90, 0x90];
        let symbols_at = 20 + 40 + code.len() + 10;
        let mut out = Vec::new();
        out.extend_from_slice(&0x14cu16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(symbols_at as u32).to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(b".text\0\0\0");
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&(code.len() as u32).to_le_bytes());
        out.extend_from_slice(&60u32.to_le_bytes());
        out.extend_from_slice(&((60 + code.len()) as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x6050_0020u32.to_le_bytes());
        out.extend_from_slice(&code);
        out.extend_from_slice(&1u32.to_le_bytes()); // relocation at offset 1 ...
        out.extend_from_slice(&1u32.to_le_bytes()); // ... against symbol 1
        out.extend_from_slice(&IMAGE_REL_I386_DIR32.to_le_bytes());
        for (name, value, section, kind) in [("_f@8", 0u32, 1i16, 0x20u16), ("_g_data", 0, 0, 0)] {
            let mut field = [0u8; 8];
            field[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&field);
            out.extend_from_slice(&value.to_le_bytes());
            out.extend_from_slice(&section.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&[2, 0]);
        }
        out.extend_from_slice(&4u32.to_le_bytes());
        out
    }

    #[test]
    fn a_function_is_found_by_its_plain_name_without_its_padding_and_with_its_relocations() {
        let coff = CoffObject::parse(&object()).unwrap();
        let function = coff.function("f").unwrap();
        assert_eq!(function.body, [0xA1, 0, 0, 0, 0, 0xC2, 0x08, 0x00]);
        assert_eq!(function.relocations.len(), 1);
        assert_eq!((function.relocations[0].offset, function.relocations[0].r_type), (1, R_386_32));
        assert_eq!(function.relocations[0].symbol.as_deref(), Some("g_data"));
        assert!(coff.function("g_data").is_err());
        assert!(coff.function("nope").is_err());
    }

    #[test]
    fn the_retail_bytes_come_out_of_the_section_that_maps_the_address() {
        let mut image = vec![0u8; 0x400];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c] = 0x80;
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // one section
        image[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // optional header size
        image[0x80 + 24 + 28..0x80 + 24 + 32].copy_from_slice(&0x400000u32.to_le_bytes());
        let section = 0x80 + 24 + 0xe0;
        image[section..section + 5].copy_from_slice(b".text");
        image[section + 8..section + 12].copy_from_slice(&0x10u32.to_le_bytes()); // virtual size
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&0x8u32.to_le_bytes()); // raw size
        image[section + 20..section + 24].copy_from_slice(&0x300u32.to_le_bytes());
        image[0x300..0x308].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(retail_bytes(&image, 0x401002, 4).unwrap(), [3, 4, 5, 6]);
        // beyond the raw data of the section: zeros, as mapped
        assert_eq!(retail_bytes(&image, 0x401006, 4).unwrap(), [7, 8, 0, 0]);
        assert!(retail_bytes(&image, 0x500000, 4).is_err());
    }
}
