//! 32-bit MIPS relocatable objects (little-endian, or big-endian for the N64) for the near-miss search: the
//! `.text` of one function with its relocations, the byte comparison that
//! ignores the fields a linker fills, and a one-function object `objdiff-cli`
//! can score. The comparison is the m22-003 lane harness's (tests/m22-003/elfobj.py),
//! so a project's `match` and a lane's numbers are the same measure.
//!
//! Written from the ELF and MIPS psABI specifications.

const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_NOBITS: u32 = 8;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHF_EXECINSTR: u32 = 4;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
pub const R_MIPS_26: u32 = 4;
pub const EM_PPC: u16 = 20;
pub const EM_ARM: u16 = 40;
pub const EM_386: u16 = 3;

/// The bits of the instruction or word a relocation of this type rewrites.
fn field_bits(r_type: u32) -> u32 {
    match r_type {
        2 | 3 | 12 => 0xFFFF_FFFF,
        4 => 0x03FF_FFFF,
        1 | 5 | 6 | 7 | 8 | 9 | 10 | 11 => 0x0000_FFFF,
        _ => 0xFFFF_FFFF,
    }
}

/// The bits of the instruction or word a PowerPC relocation rewrites (ELF PowerPC psABI,
/// plus the embedded `R_PPC_EMB_SDA21` Metrowerks and GNU use for small-data accesses).
fn ppc_field_bits(r_type: u32) -> u32 {
    match r_type {
        2 | 10 => 0x03FF_FFFC,
        3..=6 => 0x0000_FFFF,
        7 | 8 | 9 | 11 | 12 | 13 => 0x0000_FFFC,
        109 => 0x001F_FFFF,
        _ => 0xFFFF_FFFF,
    }
}

/// The bits of the instruction or word an ARM relocation rewrites (ELF for the Arm Architecture,
/// REL relocations: the field holds the addend). `R_ARM_THM_CALL` covers both halfwords of a `bl`.
fn arm_field_bits(r_type: u32) -> u32 {
    match r_type {
        1 | 28 | 29 | 5 => 0x00FF_FFFF, // PC24, CALL, JUMP24, (R_ARM_PREL31 is a word, below)
        10 | 30 => 0x07FF_07FF,         // THM_CALL, THM_JUMP24 (BL pair)
        11 => 0x0000_00FF,              // THM_PC8
        102 => 0x0000_07FF,             // THM_JUMP11
        103 => 0x0000_00FF,             // THM_JUMP8
        4 => 0x0080_0FFF,               // LDR_PC_G0
        _ => 0xFFFF_FFFF,               // ABS32, REL32, GOT*, ...
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// Offset inside the function.
    pub offset: usize,
    pub r_type: u32,
    /// The symbol the relocation names (`None` for the section symbol of a data reference).
    pub symbol: Option<String>,
    /// The bits the linker rewrites, when the object's architecture is not MIPS (`None`: the MIPS table).
    pub field: Option<u32>,
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    kind: u32,
    flags: u32,
    offset: usize,
    size: usize,
    link: usize,
    info: usize,
}

#[derive(Clone, Debug)]
struct Symbol {
    name: String,
    value: usize,
    size: usize,
    info: u8,
    shndx: usize,
}

pub struct Function {
    pub name: String,
    /// ARM objects: the function symbol has the Thumb bit.
    pub thumb: bool,
    pub body: Vec<u8>,
    pub relocations: Vec<Relocation>,
}

pub struct ElfObject<'a> {
    data: &'a [u8],
    pub e_flags: u32,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    /// (section index, offset, symbol index, type) of every relocation.
    relocs: Vec<(usize, usize, usize, u32)>,
    /// Big-endian object (N64, GameCube/Wii).
    big: bool,
    /// `e_machine`: 8 MIPS, 20 PowerPC.
    machine: u16,
}

fn u16_at(data: &[u8], at: usize, big: bool) -> Result<u16, String> {
    data.get(at..at + 2)
        .map(|b| if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })
        .ok_or_else(|| "object truncated".to_string())
}

fn u32_at(data: &[u8], at: usize, big: bool) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| if big { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) })
        .ok_or_else(|| "object truncated".to_string())
}

fn c_string(blob: &[u8], at: usize) -> String {
    let tail = blob.get(at..).unwrap_or(&[]);
    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

impl<'a> ElfObject<'a> {
    /// True for a big-endian object.
    pub fn is_big(&self) -> bool {
        self.big
    }

    /// True for an ARM object (`EM_ARM`).
    pub fn is_arm(&self) -> bool {
        self.machine == EM_ARM
    }

    /// True for a PowerPC object (`EM_PPC`).
    pub fn is_ppc(&self) -> bool {
        self.machine == EM_PPC
    }

    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 52 || &data[..4] != b"\x7fELF" || data[4] != 1 || !matches!(data[5], 1 | 2) {
            return Err("not an ELF32 file".into());
        }
        let big = data[5] == 2;
        let machine = u16_at(data, 18, big)?;
        let u16_at = |data: &[u8], at: usize| u16_at(data, at, big);
        let u32_at = |data: &[u8], at: usize| u32_at(data, at, big);
        let shoff = u32_at(data, 32)? as usize;
        let e_flags = u32_at(data, 36)?;
        let shentsize = u16_at(data, 46)? as usize;
        let shnum = u16_at(data, 48)? as usize;
        let shstrndx = u16_at(data, 50)? as usize;
        let mut sections = Vec::with_capacity(shnum);
        let mut name_offsets = Vec::with_capacity(shnum);
        for index in 0..shnum {
            let at = shoff + index * shentsize;
            name_offsets.push(u32_at(data, at)? as usize);
            sections.push(Section {
                name: String::new(),
                kind: u32_at(data, at + 4)?,
                flags: u32_at(data, at + 8)?,
                offset: u32_at(data, at + 16)? as usize,
                size: u32_at(data, at + 20)? as usize,
                link: u32_at(data, at + 24)? as usize,
                info: u32_at(data, at + 28)? as usize,
            });
        }
        if let Some(names) = sections.get(shstrndx).cloned() {
            let blob = data.get(names.offset..names.offset + names.size).unwrap_or(&[]);
            for (section, at) in sections.iter_mut().zip(name_offsets) {
                section.name = c_string(blob, at);
            }
        }
        let mut symbols = Vec::new();
        if let Some(table) = sections.iter().find(|s| s.kind == SHT_SYMTAB) {
            let strings = sections.get(table.link).ok_or("symbol table without strings")?;
            let blob = data.get(strings.offset..strings.offset + strings.size).unwrap_or(&[]);
            for index in 0..table.size / 16 {
                let at = table.offset + index * 16;
                symbols.push(Symbol {
                    name: c_string(blob, u32_at(data, at)? as usize),
                    value: u32_at(data, at + 4)? as usize,
                    size: u32_at(data, at + 8)? as usize,
                    info: *data.get(at + 12).ok_or("object truncated")?,
                    shndx: u16_at(data, at + 14)? as usize,
                });
            }
        }
        let mut relocs = Vec::new();
        for section in sections.iter().filter(|s| s.kind == SHT_REL || s.kind == SHT_RELA) {
            let step = if section.kind == SHT_RELA { 12 } else { 8 };
            for slot in 0..section.size / step {
                let at = section.offset + slot * step;
                let offset = u32_at(data, at)? as usize;
                let info = u32_at(data, at + 4)?;
                relocs.push((section.info, offset, (info >> 8) as usize, info & 0xFF));
            }
        }
        Ok(ElfObject { data, e_flags, sections, symbols, relocs, big, machine })
    }

    fn section_bytes(&self, index: usize) -> &'a [u8] {
        let section = &self.sections[index];
        if section.kind == SHT_NOBITS {
            return &[];
        }
        self.data.get(section.offset..section.offset + section.size).unwrap_or(&[])
    }

    /// Sized function symbols in executable sections: (name, section, offset, size).
    pub fn functions(&self) -> Vec<(String, usize, usize, usize)> {
        self.symbols
            .iter()
            .filter(|s| {
                s.info & 0xF == STT_FUNC
                    && s.size != 0
                    && s.shndx > 0
                    && s.shndx < self.sections.len()
                    && self.sections[s.shndx].flags & SHF_EXECINSTR != 0
            })
            .map(|s| (s.name.clone(), s.shndx, if self.machine == EM_ARM { s.value & !1 } else { s.value }, s.size))
            .collect()
    }

    fn function_at(&self, name: &str, shndx: usize, value: usize, size: usize) -> Function {
        let text = self.section_bytes(shndx);
        let body = text.get(value..value + size).unwrap_or(&[]).to_vec();
        let mut relocations = Vec::new();
        for &(section, offset, sym, r_type) in &self.relocs {
            if section != shndx || offset < value || offset >= value + size {
                continue;
            }
            let symbol = self.symbols.get(sym).filter(|_| sym != 0);
            // A call to another section's function is relocated against the section symbol: name the function that starts there.
            let mut symbol_name = symbol.map(|s| s.name.clone());
            if let Some(s) = symbol
                && s.info & 0xF == STT_SECTION
            {
                symbol_name = None;
                if r_type == R_MIPS_26 && self.machine != EM_PPC && self.machine != EM_ARM {
                    let word = u32_at(text, offset, self.big).unwrap_or(0);
                    let target = ((word & 0x03FF_FFFF) << 2) as usize;
                    symbol_name = self.functions().into_iter().find(|f| f.1 == s.shndx && f.2 == target).map(|f| f.0);
                }
            }
            let field = match self.machine {
                EM_PPC => Some(ppc_field_bits(r_type)),
                EM_ARM => Some(arm_field_bits(r_type)),
                _ => None,
            };
            relocations.push(Relocation { offset: offset - value, r_type, symbol: symbol_name, field });
        }
        let thumb = self.machine == EM_ARM && self.symbols.iter().any(|s| s.name == name && s.shndx == shndx && s.info & 0xF == STT_FUNC && s.value & 1 == 1);
        Function { name: name.to_string(), thumb, body, relocations }
    }

    /// The function called `name`; MWCC renames one its unit already knows (`f__2`), which is accepted when unique.
    /// With no name match, the object's only function.
    pub fn function(&self, name: &str) -> Result<Function, String> {
        let all = self.functions();
        if let Some((n, s, v, z)) = all.iter().find(|f| f.0 == name) {
            return Ok(self.function_at(n, *s, *v, *z));
        }
        let renamed: Vec<_> = all
            .iter()
            .filter(|f| f.0.strip_prefix(name).and_then(|r| r.strip_prefix("__")).is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())))
            .collect();
        if let [(n, s, v, z)] = renamed[..] {
            return Ok(self.function_at(n, *s, *v, *z));
        }
        if let [(n, s, v, z)] = &all[..] {
            return Ok(self.function_at(n, *s, *v, *z));
        }
        Err(format!("no function {name} in the object ({} functions: {})", all.len(), all.iter().map(|f| f.0.as_str()).take(6).collect::<Vec<_>>().join(", ")))
    }
}

/// 0xFF where a byte of the function is compared, 0 inside relocation fields.
pub fn field_mask(length: usize, relocations: &[Relocation], big: bool) -> Vec<u8> {
    let mut mask = vec![0xFFu8; length];
    for reloc in relocations {
        if reloc.offset + 4 > length {
            continue;
        }
        let field = reloc.field.unwrap_or_else(|| field_bits(reloc.r_type));
        for byte in 0..4 {
            let shift = if big { 8 * (3 - byte) } else { 8 * byte };
            mask[reloc.offset + byte] = !((field >> shift) as u8);
        }
    }
    mask
}

/// Number of differing bytes between `body` and the start of `retail`, outside relocation fields.
pub fn compare(body: &[u8], relocations: &[Relocation], retail: &[u8], big: bool) -> usize {
    let mask = field_mask(body.len(), relocations, big);
    (0..body.len())
        .filter(|&i| (body[i] ^ retail.get(i).copied().unwrap_or(0)) & mask[i] != 0)
        .count()
}

/// A relocatable MIPS object with one function `name` (`.text` = body, REL relocations kept) for objdiff-cli.
pub fn object_for_objdiff(body: &[u8], relocations: &[Relocation], name: &str, e_flags: u32, big: bool) -> Vec<u8> {
    object_for_machine(body, relocations, name, e_flags, big, 8, None)
}

/// A relocatable PowerPC object (big-endian, `.rela.text` with zero addends) with one function `name`.
pub fn object_for_objdiff_ppc(body: &[u8], relocations: &[Relocation], name: &str, e_flags: u32) -> Vec<u8> {
    object_for_machine(body, relocations, name, e_flags, true, EM_PPC, None)
}

/// A relocatable ARM object (little-endian, `.rel.text`) with one function `name`; a Thumb function
/// gets the low bit of its symbol value and a `$t` mapping symbol, an ARM one a `$a`, which is how
/// objdiff picks the instruction set.
pub fn object_for_objdiff_arm(body: &[u8], relocations: &[Relocation], name: &str, e_flags: u32, thumb: bool) -> Vec<u8> {
    object_for_machine(body, relocations, name, e_flags, false, EM_ARM, Some(thumb))
}

/// A relocatable i386 object (little-endian, `.rel.text`) with one function `name`, for a Windows PE project's objects.
pub fn object_for_objdiff_x86(body: &[u8], relocations: &[Relocation], name: &str) -> Vec<u8> {
    object_for_machine(body, relocations, name, 0, false, EM_386, None)
}

fn object_for_machine(body: &[u8], relocations: &[Relocation], name: &str, e_flags: u32, big: bool, machine: u16, arm_thumb: Option<bool>) -> Vec<u8> {
    let rela = machine == EM_PPC;
    let w32 = |v: u32| if big { v.to_be_bytes() } else { v.to_le_bytes() };
    let w16 = |v: u16| if big { v.to_be_bytes() } else { v.to_le_bytes() };
    let mut strtab = vec![0u8];
    // (name, value, size, info, other, shndx)
    let mut table: Vec<(u32, u32, u32, u8, u8, u16)> = vec![(0, 0, 0, 0, 0, 0), (0, 0, 0, STT_SECTION, 0, 1)];
    let add_string = |strtab: &mut Vec<u8>, text: &str| -> u32 {
        let at = strtab.len() as u32;
        strtab.extend_from_slice(text.as_bytes());
        strtab.push(0);
        at
    };
    if let Some(thumb) = arm_thumb {
        let at = add_string(&mut strtab, if thumb { "$t" } else { "$a" });
        table.push((at, 0, 0, 0, 0, 1));
    }
    let function = table.len();
    let name_at = add_string(&mut strtab, name);
    table.push((name_at, u32::from(arm_thumb == Some(true)), body.len() as u32, (1 << 4) | STT_FUNC, 0, 1));
    let first_global = function;
    let mut ids: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut rel = Vec::new();
    for reloc in relocations {
        let Some(symbol) = reloc.symbol.as_deref() else { continue };
        let id = match ids.get(symbol) {
            Some(id) => *id,
            None => {
                let at = add_string(&mut strtab, symbol);
                table.push((at, 0, 0, 1 << 4, 0, 0));
                ids.insert(symbol, table.len() - 1);
                table.len() - 1
            }
        };
        rel.extend_from_slice(&w32(reloc.offset as u32));
        rel.extend_from_slice(&w32(((id as u32) << 8) | reloc.r_type));
        if rela {
            rel.extend_from_slice(&w32(0));
        }
    }
    let mut symtab = Vec::new();
    for (n, v, s, info, other, shndx) in &table {
        symtab.extend_from_slice(&w32(*n));
        symtab.extend_from_slice(&w32(*v));
        symtab.extend_from_slice(&w32(*s));
        symtab.push(*info);
        symtab.push(*other);
        symtab.extend_from_slice(&w16(*shndx));
    }
    let mut shstr = vec![0u8];
    let mut names = std::collections::HashMap::new();
    for section in [".text", ".symtab", ".strtab", ".shstrtab", ".rel.text", ".rela.text"] {
        names.insert(section, shstr.len() as u32);
        shstr.extend_from_slice(section.as_bytes());
        shstr.push(0);
    }
    let blobs: [&[u8]; 6] = [&[], body, &symtab, &strtab, &shstr, &rel];
    let mut offset = 52usize;
    let mut offsets = Vec::new();
    for blob in blobs {
        offset = (offset + 3) & !3;
        offsets.push(offset);
        offset += blob.len();
    }
    let shoff = (offset + 3) & !3;
    let header = |name: u32, kind: u32, flags: u32, at: usize, size: usize, link: u32, info: u32, align: u32, entsize: u32| {
        let mut h = Vec::with_capacity(40);
        for v in [name, kind, flags, 0, at as u32, size as u32, link, info, align, entsize] {
            h.extend_from_slice(&w32(v));
        }
        h
    };
    let headers = [
        header(0, 0, 0, 0, 0, 0, 0, 0, 0),
        header(names[".text"], SHT_PROGBITS, 6, offsets[1], body.len(), 0, 0, 16, 0),
        header(names[".symtab"], SHT_SYMTAB, 0, offsets[2], symtab.len(), 3, first_global as u32, 4, 16),
        header(names[".strtab"], SHT_STRTAB, 0, offsets[3], strtab.len(), 0, 0, 1, 0),
        header(names[".shstrtab"], SHT_STRTAB, 0, offsets[4], shstr.len(), 0, 0, 1, 0),
        if rela {
            header(names[".rela.text"], SHT_RELA, 0x40, offsets[5], rel.len(), 2, 1, 4, 12)
        } else {
            header(names[".rel.text"], SHT_REL, 0x40, offsets[5], rel.len(), 2, 1, 4, 8)
        },
    ];
    let mut out = Vec::new();
    out.extend_from_slice(b"\x7fELF");
    out.extend_from_slice(&[1, if big { 2 } else { 1 }, 1, 0]);
    out.extend_from_slice(&[0u8; 8]);
    for (value, wide) in [(1u32, 2), (u32::from(machine), 2), (1, 4), (0, 4), (0, 4), (shoff as u32, 4), (e_flags, 4), (52, 2), (0, 2), (0, 2), (40, 2), (headers.len() as u32, 2), (4, 2)] {
        if wide == 2 {
            out.extend_from_slice(&w16(value as u16));
        } else {
            out.extend_from_slice(&w32(value));
        }
    }
    for (blob, start) in blobs.iter().zip(&offsets) {
        out.resize(*start, 0);
        out.extend_from_slice(blob);
    }
    out.resize(shoff, 0);
    for entry in &headers {
        out.extend_from_slice(entry);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_skips_relocation_fields_only() {
        let relocations = [
            Relocation { offset: 0, r_type: R_MIPS_26, symbol: Some("f".into()), field: None },
            Relocation { offset: 4, r_type: 5, symbol: None, field: None },
        ];
        let body = [0x01, 0x02, 0x03, 0x0c, 0xaa, 0xbb, 0x3c, 0x3c];
        let mask = field_mask(body.len(), &relocations, false);
        assert_eq!(mask, [0, 0, 0, 0xFC, 0, 0, 0xFF, 0xFF]);
        // A different call target and a different %hi are not differences; a different opcode byte is.
        let retail = [0x09, 0x08, 0x07, 0x0c, 0x11, 0x22, 0x3c, 0x3c];
        assert_eq!(compare(&body, &relocations, &retail, false), 0);
        let retail = [0x09, 0x08, 0x07, 0x0c, 0x11, 0x22, 0x3c, 0x3d];
        assert_eq!(compare(&body, &relocations, &retail, false), 1);
    }

    #[test]
    fn powerpc_objects_round_trip_with_their_relocation_fields() {
        // `bl callee` (REL24 = 10), `lwz r3, sym@sda21(r13)` (EMB_SDA21 = 109), `lis`/`addi` pair (HA = 6, LO = 4).
        let body: Vec<u8> = [0x4800_0001u32, 0x8062_0000, 0x3c60_0000, 0x3863_0000].iter().flat_map(|w| w.to_be_bytes()).collect();
        let relocations = vec![
            Relocation { offset: 0, r_type: 10, symbol: Some("callee".into()), field: Some(0x03FF_FFFC) },
            Relocation { offset: 4, r_type: 109, symbol: Some("sym".into()), field: Some(0x001F_FFFF) },
            Relocation { offset: 8, r_type: 6, symbol: Some("lbl".into()), field: Some(0xFFFF) },
            Relocation { offset: 12, r_type: 4, symbol: Some("lbl".into()), field: Some(0xFFFF) },
        ];
        let object = object_for_objdiff_ppc(&body, &relocations, "f", 0);
        let parsed = ElfObject::parse(&object).unwrap();
        assert!(parsed.is_ppc() && parsed.is_big());
        let function = parsed.function("f").unwrap();
        assert_eq!(function.body, body);
        assert_eq!(function.relocations, relocations);
        // The linker rewrites the branch displacement, the register+offset of an SDA21 access and the 16-bit halves.
        let mask = field_mask(16, &function.relocations, true);
        assert_eq!(mask, [0xFC, 0, 0, 0x03, 0xFF, 0xE0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0]);
    }

    #[test]
    fn objdiff_object_round_trips() {
        let relocations = vec![Relocation { offset: 4, r_type: R_MIPS_26, symbol: Some("callee".into()), field: None }];
        let body = vec![0u8; 16];
        let object = object_for_objdiff(&body, &relocations, "func", 0x2000_0000, false);
        let big = object_for_objdiff(&body, &relocations, "func", 0x1000_0000, true);
        let parsed_big = ElfObject::parse(&big).unwrap();
        assert_eq!(parsed_big.function("func").unwrap().relocations, relocations);
        assert_eq!(field_mask(8, &[Relocation { offset: 0, r_type: R_MIPS_26, symbol: None, field: None }], true)[..4], [0xFC, 0, 0, 0]);
        let parsed = ElfObject::parse(&object).unwrap();
        assert_eq!(parsed.e_flags, 0x2000_0000);
        let function = parsed.function("func").unwrap();
        assert_eq!(function.body, body);
        assert_eq!(function.relocations, relocations);
    }

    #[test]
    fn arm_objects_carry_the_thumb_bit_and_mask_a_bl_pair_whole() {
        // push {lr}; bl callee (a Thumb BL pair); pop {pc}
        let body = [0x00u8, 0xb5, 0x00, 0xf0, 0x00, 0xf8, 0x00, 0xbd];
        let relocations = vec![Relocation { offset: 2, r_type: 10, symbol: Some("callee".into()), field: Some(arm_field_bits(10)) }];
        let object = object_for_objdiff_arm(&body, &relocations, "func", 0x0500_0000, true);
        let parsed = ElfObject::parse(&object).unwrap();
        assert!(parsed.is_arm());
        let function = parsed.function("func").unwrap();
        assert!(function.thumb, "the symbol value has the Thumb bit");
        assert_eq!(function.body, body);
        assert_eq!(function.relocations[0].symbol.as_deref(), Some("callee"));
        // The 11-bit offsets of both halfwords are the linker's; the opcode bits are not.
        let mask = field_mask(body.len(), &function.relocations, false);
        assert_eq!(mask[2..6], [0, 0xf8, 0, 0xf8]);
        let retail = [0x00u8, 0xb5, 0x12, 0xf1, 0x34, 0xf9, 0x00, 0xbd];
        assert_eq!(compare(&body, &function.relocations, &retail, false), 0);
        let arm = object_for_objdiff_arm(&body, &[], "func", 0, false);
        assert!(!ElfObject::parse(&arm).unwrap().function("func").unwrap().thumb);
    }
}
