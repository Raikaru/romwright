//! Retail function bytes wrapped as relocatable ELF objects.
//!
//! objdiff compares two relocatable objects symbol by symbol. The retail side
//! of a non-matching scaffold is a linked image, so each function's bytes are
//! cut out and written as a one-section `.o` named after the function; the
//! project's own build of the decompiled C is the other side. A direct call in
//! the retail bytes encodes a displacement to wherever the callee sits in the
//! image, which no compiled object can reproduce, so every direct call and
//! branch to another known function is turned into the relocation a compiler
//! would have emitted (field zeroed the way an assembler writes it, symbol =
//! callee name). A displacement is only rewritten when the instruction decodes
//! to exactly the target the analysis recorded; anything else is left as
//! retail bytes. References to data (literal pools, RIP-relative loads) are not
//! rewritten, and objdiff reports their operands as differences.
//!
//! The ELF layout (section headers, `.symtab`, `REL`/`RELA` records, ARM
//! mapping symbols) follows the System V gABI and the processor supplements
//! (public specifications); nothing is taken from a tool's source.

use std::collections::HashMap;

/// The instruction sets the scaffold platforms use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arch {
    /// ARMv6K/ARMv7 A32 with Thumb (3DS, Vita).
    Arm32,
    Aarch64,
    X86_64,
    /// Xbox 360 Xenon: PowerPC, 32-bit addresses.
    Ppc32,
    /// PlayStation 3 PPU: PowerPC with 64-bit registers, ELF64.
    Ppc64,
}

impl Arch {
    fn class64(self) -> bool {
        matches!(self, Arch::Aarch64 | Arch::X86_64 | Arch::Ppc64)
    }

    fn big_endian(self) -> bool {
        matches!(self, Arch::Ppc32 | Arch::Ppc64)
    }

    fn machine(self) -> u16 {
        match self {
            Arch::Arm32 => 40,
            Arch::Aarch64 => 183,
            Arch::X86_64 => 62,
            Arch::Ppc32 => 20,
            Arch::Ppc64 => 21,
        }
    }

    fn flags(self) -> u32 {
        match self {
            // EF_ARM_EABI_VER5
            Arch::Arm32 => 0x0500_0000,
            _ => 0,
        }
    }

    fn text_align(self, thumb: bool) -> u64 {
        match self {
            Arch::Arm32 if thumb => 2,
            Arch::X86_64 => 16,
            _ => 4,
        }
    }

    /// `.rela` records (explicit addend) rather than `.rel`.
    fn rela(self) -> bool {
        !matches!(self, Arch::Arm32)
    }
}

/// One relocation in the function's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    /// Offset of the relocated field inside the function.
    pub offset: u64,
    pub symbol: String,
    /// ELF relocation type.
    pub kind: u32,
    pub addend: i64,
}

/// `(instruction address, target address, target name)` of a direct transfer.
#[derive(Debug, Clone)]
pub struct Transfer<'a> {
    pub from: u64,
    pub to: u64,
    pub name: &'a str,
}

fn read_u32(bytes: &[u8], at: usize, big: bool) -> Option<u32> {
    let word: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(if big { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) })
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32, big: bool) {
    let word = if big { value.to_be_bytes() } else { value.to_le_bytes() };
    bytes[at..at + 4].copy_from_slice(&word);
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

/// Rewrites the direct calls and branches of the function at `entry` that the
/// analysis recorded in `transfers`, returning the relocations and zeroing
/// the fields in `bytes` the way an assembler leaves them. `thumb` says the
/// function is Thumb code (ARM only).
pub fn relocate_transfers(arch: Arch, entry: u64, bytes: &mut [u8], thumb: bool, transfers: &[Transfer]) -> Vec<Reloc> {
    let big = arch.big_endian();
    let mut relocs: Vec<Reloc> = Vec::new();
    for t in transfers {
        if t.from < entry {
            continue;
        }
        let at = (t.from - entry) as usize;
        if at >= bytes.len() {
            continue;
        }
        let offset = at as u64;
        let reloc = match arch {
            Arch::Arm32 if !thumb => {
                let Some(word) = read_u32(bytes, at, big) else { continue };
                let (branch_link, blx) = (word >> 24 & 0x0F == 0x0B && word >> 28 != 0xF, word >> 25 == 0x7D);
                if !(branch_link || blx) {
                    continue;
                }
                let imm = sign_extend(word & 0x00FF_FFFF, 24) * 4 + if blx { ((word >> 24) & 1) as i64 * 2 } else { 0 };
                if (t.from as i64 + 8 + imm) as u64 & 0xFFFF_FFFF != t.to & 0xFFFF_FFFE {
                    continue;
                }
                let top = if blx { 0xFA00_0000 } else { word & 0xFF00_0000 };
                write_u32(bytes, at, top | 0x00FF_FFFE, big);
                Reloc { offset, symbol: t.name.to_string(), kind: 28, addend: 0 }
            }
            Arch::Arm32 => {
                // Thumb BL/BLX: two halfwords.
                let (Some(first), Some(second)) = (read_u16(bytes, at), read_u16(bytes, at + 2)) else { continue };
                if first & 0xF800 != 0xF000 || (second & 0xD000 != 0xD000 && second & 0xD001 != 0xC000) {
                    continue;
                }
                let blx = second & 0x1000 == 0;
                let s = (first >> 10 & 1) as u32;
                let (j1, j2) = ((second >> 13 & 1) as u32, (second >> 11 & 1) as u32);
                let (i1, i2) = (!(j1 ^ s) & 1, !(j2 ^ s) & 1);
                let imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((first as u32 & 0x3FF) << 12) | ((second as u32 & 0x7FF) << 1);
                let imm = sign_extend(imm, 25);
                let base = if blx { (t.from + 4) & !3 } else { t.from + 4 };
                if (base as i64 + imm) as u64 & 0xFFFF_FFFF != t.to & 0xFFFF_FFFE {
                    continue;
                }
                let patched: [u8; 4] = [0xFF, 0xF7, 0xFE, if blx { 0xEF } else { 0xFF }];
                bytes[at..at + 4].copy_from_slice(&patched);
                Reloc { offset, symbol: t.name.to_string(), kind: 10, addend: 0 }
            }
            Arch::Aarch64 => {
                let Some(word) = read_u32(bytes, at, big) else { continue };
                let (kind, opcode) = match word & 0xFC00_0000 {
                    0x9400_0000 => (283, 0x9400_0000),
                    0x1400_0000 => (282, 0x1400_0000),
                    _ => continue,
                };
                let target = t.from as i64 + sign_extend(word & 0x03FF_FFFF, 26) * 4;
                if target as u64 != t.to {
                    continue;
                }
                write_u32(bytes, at, opcode, big);
                Reloc { offset, symbol: t.name.to_string(), kind, addend: 0 }
            }
            Arch::X86_64 => {
                if !matches!(bytes[at], 0xE8 | 0xE9) {
                    continue;
                }
                let Some(field) = bytes.get(at + 1..at + 5) else { continue };
                let disp = i32::from_le_bytes(field.try_into().unwrap()) as i64;
                if (t.from as i64 + 5 + disp) as u64 != t.to {
                    continue;
                }
                bytes[at + 1..at + 5].fill(0);
                Reloc { offset: offset + 1, symbol: t.name.to_string(), kind: 4, addend: -4 }
            }
            Arch::Ppc32 | Arch::Ppc64 => {
                let Some(word) = read_u32(bytes, at, big) else { continue };
                // `b`/`bl` with AA = 0: opcode 18.
                if word >> 26 != 18 || word & 2 != 0 {
                    continue;
                }
                let target = t.from as i64 + sign_extend(word & 0x03FF_FFFC, 26);
                if (target as u64 & 0xFFFF_FFFF) != t.to & 0xFFFF_FFFF {
                    continue;
                }
                write_u32(bytes, at, word & 0xFC00_0003, big);
                Reloc { offset, symbol: t.name.to_string(), kind: 10, addend: 0 }
            }
        };
        relocs.push(reloc);
    }
    relocs.sort_by_key(|r| r.offset);
    relocs.dedup_by_key(|r| r.offset);
    relocs
}

struct StringTable {
    bytes: Vec<u8>,
    seen: HashMap<String, u32>,
}

impl StringTable {
    fn new() -> Self {
        Self { bytes: vec![0], seen: HashMap::new() }
    }

    fn add(&mut self, text: &str) -> u32 {
        if text.is_empty() {
            return 0;
        }
        if let Some(&at) = self.seen.get(text) {
            return at;
        }
        let at = self.bytes.len() as u32;
        self.bytes.extend_from_slice(text.as_bytes());
        self.bytes.push(0);
        self.seen.insert(text.to_string(), at);
        at
    }
}

struct Writer {
    big: bool,
    class64: bool,
    out: Vec<u8>,
}

impl Writer {
    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    /// An address-sized field.
    fn word(&mut self, v: u64) {
        if self.class64 {
            self.u64(v)
        } else {
            self.u32(v as u32)
        }
    }
    fn align(&mut self, to: usize) {
        while !self.out.len().is_multiple_of(to) {
            self.out.push(0);
        }
    }
}

struct Section {
    name: u32,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

/// A relocatable object holding `bytes` as the function `name`.
///
/// `relocs` come from [`relocate_transfers`]; `thumb` marks ARM Thumb code
/// (the symbol gets its low bit and a `$t` mapping symbol, otherwise `$a`).
pub fn build_object(arch: Arch, name: &str, bytes: &[u8], thumb: bool, relocs: &[Reloc]) -> Vec<u8> {
    let class64 = arch.class64();
    let mut strtab = StringTable::new();
    let mut shstr = StringTable::new();

    // Symbols: null, section, [mapping], function, undefined callees.
    struct Sym {
        name: u32,
        info: u8,
        shndx: u16,
        value: u64,
        size: u64,
    }
    let mut symbols = vec![Sym { name: 0, info: 0, shndx: 0, value: 0, size: 0 }];
    // STB_LOCAL << 4 | STT_SECTION
    symbols.push(Sym { name: 0, info: 3, shndx: 1, value: 0, size: 0 });
    if arch == Arch::Arm32 {
        let mapping = strtab.add(if thumb { "$t" } else { "$a" });
        symbols.push(Sym { name: mapping, info: 0, shndx: 1, value: 0, size: 0 });
    }
    let first_global = symbols.len() as u32;
    let function = strtab.add(name);
    // STB_GLOBAL << 4 | STT_FUNC
    symbols.push(Sym {
        name: function,
        info: 0x12,
        shndx: 1,
        value: if arch == Arch::Arm32 && thumb { 1 } else { 0 },
        size: bytes.len() as u64,
    });
    let mut index_of: HashMap<&str, u32> = HashMap::new();
    for reloc in relocs {
        if reloc.symbol == name || index_of.contains_key(reloc.symbol.as_str()) {
            continue;
        }
        index_of.insert(reloc.symbol.as_str(), symbols.len() as u32);
        let at = strtab.add(&reloc.symbol);
        symbols.push(Sym { name: at, info: 0x10, shndx: 0, value: 0, size: 0 });
    }

    let mut w = Writer { big: arch.big_endian(), class64, out: Vec::new() };
    let ehsize = if class64 { 64 } else { 52 };
    w.out.resize(ehsize, 0);

    let mut sections: Vec<Section> = vec![Section { name: 0, kind: 0, flags: 0, offset: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 }];
    // .text
    w.align(16);
    let text_offset = w.out.len() as u64;
    w.out.extend_from_slice(bytes);
    sections.push(Section {
        name: shstr.add(".text"),
        kind: 1,
        flags: 0x6,
        offset: text_offset,
        size: bytes.len() as u64,
        link: 0,
        info: 0,
        align: arch.text_align(thumb),
        entsize: 0,
    });
    let symtab_index = if relocs.is_empty() { 2 } else { 3 };
    // .rel(a).text
    if !relocs.is_empty() {
        w.align(8);
        let offset = w.out.len() as u64;
        for reloc in relocs {
            let symbol = if reloc.symbol == name { first_global } else { index_of[reloc.symbol.as_str()] } as u64;
            if class64 {
                w.u64(reloc.offset);
                w.u64(symbol << 32 | reloc.kind as u64);
                w.u64(reloc.addend as u64);
            } else {
                w.u32(reloc.offset as u32);
                w.u32((symbol as u32) << 8 | reloc.kind);
                if arch.rela() {
                    w.u32(reloc.addend as u32);
                }
            }
        }
        let entsize = match (class64, arch.rela()) {
            (true, _) => 24,
            (false, true) => 12,
            (false, false) => 8,
        };
        sections.push(Section {
            name: shstr.add(if arch.rela() { ".rela.text" } else { ".rel.text" }),
            kind: if arch.rela() { 4 } else { 9 },
            flags: 0x40,
            offset,
            size: w.out.len() as u64 - offset,
            link: symtab_index,
            info: 1,
            align: if class64 { 8 } else { 4 },
            entsize,
        });
    }
    // .symtab
    w.align(8);
    let symtab_offset = w.out.len() as u64;
    for sym in &symbols {
        if class64 {
            w.u32(sym.name);
            w.out.push(sym.info);
            w.out.push(0);
            w.u16(sym.shndx);
            w.u64(sym.value);
            w.u64(sym.size);
        } else {
            w.u32(sym.name);
            w.u32(sym.value as u32);
            w.u32(sym.size as u32);
            w.out.push(sym.info);
            w.out.push(0);
            w.u16(sym.shndx);
        }
    }
    sections.push(Section {
        name: shstr.add(".symtab"),
        kind: 2,
        flags: 0,
        offset: symtab_offset,
        size: w.out.len() as u64 - symtab_offset,
        link: symtab_index + 1,
        info: first_global,
        align: if class64 { 8 } else { 4 },
        entsize: if class64 { 24 } else { 16 },
    });
    // .strtab
    let strtab_offset = w.out.len() as u64;
    w.out.extend_from_slice(&strtab.bytes);
    sections.push(Section {
        name: shstr.add(".strtab"),
        kind: 3,
        flags: 0,
        offset: strtab_offset,
        size: strtab.bytes.len() as u64,
        link: 0,
        info: 0,
        align: 1,
        entsize: 0,
    });
    // .shstrtab
    let shstr_name = shstr.add(".shstrtab");
    let shstr_offset = w.out.len() as u64;
    w.out.extend_from_slice(&shstr.bytes);
    sections.push(Section {
        name: shstr_name,
        kind: 3,
        flags: 0,
        offset: shstr_offset,
        size: shstr.bytes.len() as u64,
        link: 0,
        info: 0,
        align: 1,
        entsize: 0,
    });
    // Section headers.
    w.align(8);
    let shoff = w.out.len() as u64;
    for s in &sections {
        w.u32(s.name);
        w.u32(s.kind);
        w.word(s.flags);
        w.word(0);
        w.word(s.offset);
        w.word(s.size);
        w.u32(s.link);
        w.u32(s.info);
        w.word(s.align);
        w.word(s.entsize);
    }
    let shnum = sections.len() as u16;
    // ELF header.
    let mut h = Writer { big: w.big, class64, out: Vec::new() };
    h.out.extend_from_slice(b"\x7fELF");
    h.out.push(if class64 { 2 } else { 1 });
    h.out.push(if w.big { 2 } else { 1 });
    h.out.push(1);
    h.out.extend_from_slice(&[0; 9]);
    h.u16(1); // ET_REL
    h.u16(arch.machine());
    h.u32(1);
    h.word(0);
    h.word(0);
    h.word(shoff);
    h.u32(arch.flags());
    h.u16(ehsize as u16);
    h.u16(0);
    h.u16(0);
    h.u16(if class64 { 64 } else { 40 });
    h.u16(shnum);
    h.u16(shnum - 1);
    w.out[..h.out.len()].copy_from_slice(&h.out);
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::{Object, ObjectSection, ObjectSymbol};

    fn parse(bytes: &[u8]) -> object::File<'_> {
        object::File::parse(bytes).expect("a valid ELF object")
    }

    #[test]
    fn x86_call_becomes_plt32_with_zeroed_field() {
        // call +0x10 (target 0x1000 + 5 + 0x10), ret
        let mut bytes = vec![0xE8, 0x10, 0, 0, 0, 0xC3];
        let transfers = [Transfer { from: 0x1000, to: 0x1015, name: "callee" }];
        let relocs = relocate_transfers(Arch::X86_64, 0x1000, &mut bytes, false, &transfers);
        assert_eq!(relocs, [Reloc { offset: 1, symbol: "callee".into(), kind: 4, addend: -4 }]);
        assert_eq!(bytes, [0xE8, 0, 0, 0, 0, 0xC3]);
        let elf = build_object(Arch::X86_64, "f", &bytes, false, &relocs);
        let file = parse(&elf);
        assert_eq!(file.architecture(), object::Architecture::X86_64);
        let text = file.section_by_name(".text").unwrap();
        assert_eq!(text.data().unwrap(), bytes);
        let reloc: Vec<_> = text.relocations().collect();
        assert_eq!(reloc.len(), 1);
        assert_eq!(reloc[0].0, 1);
        let f = file.symbols().find(|s| s.name() == Ok("f")).unwrap();
        assert!(f.is_global() && f.size() == 6);
        assert!(file.symbols().any(|s| s.name() == Ok("callee") && s.is_undefined()));
    }

    #[test]
    fn a_displacement_that_misses_the_recorded_target_is_left_alone() {
        let mut bytes = vec![0xE8, 0x10, 0, 0, 0, 0xC3];
        let transfers = [Transfer { from: 0x1000, to: 0x2000, name: "callee" }];
        assert!(relocate_transfers(Arch::X86_64, 0x1000, &mut bytes, false, &transfers).is_empty());
        assert_eq!(bytes[1], 0x10);
    }

    #[test]
    fn arm_bl_is_zeroed_like_an_assembler_and_thumb_symbols_carry_the_low_bit() {
        // bl 0x100c from 0x1000: imm24 = (0x100c - 0x1008) / 4 = 1
        let mut bytes = vec![0x01, 0x00, 0x00, 0xEB, 0x1E, 0xFF, 0x2F, 0xE1];
        let transfers = [Transfer { from: 0x1000, to: 0x100C, name: "callee" }];
        let relocs = relocate_transfers(Arch::Arm32, 0x1000, &mut bytes, false, &transfers);
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].kind, 28);
        assert_eq!(&bytes[..4], &[0xFE, 0xFF, 0xFF, 0xEB]);
        let elf = build_object(Arch::Arm32, "f", &bytes, true, &relocs);
        let file = parse(&elf);
        assert_eq!(file.architecture(), object::Architecture::Arm);
        let f = file.symbols().find(|s| s.name() == Ok("f")).unwrap();
        assert_eq!(f.address() & 1, 1);
        assert!(file.symbols().any(|s| s.name() == Ok("$t")));
    }

    #[test]
    fn thumb_bl_pair_round_trips_through_the_encoding() {
        // bl +0x20 from 0x2000: target = 0x2000 + 4 + 0x20
        // first = 0xF000 | imm10(hi), second = 0xF800 | imm11
        let offset = 0x20u32;
        let first = 0xF000u16 | ((offset >> 12) & 0x3FF) as u16;
        let second = 0xF800u16 | ((offset >> 1) & 0x7FF) as u16;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first.to_le_bytes());
        bytes.extend_from_slice(&second.to_le_bytes());
        let transfers = [Transfer { from: 0x2000, to: 0x2024, name: "t" }];
        let relocs = relocate_transfers(Arch::Arm32, 0x2000, &mut bytes, true, &transfers);
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].kind, 10);
        assert_eq!(bytes, [0xFF, 0xF7, 0xFE, 0xFF]);
    }

    #[test]
    fn aarch64_bl_and_tail_branch_are_relocated() {
        // bl +8 at 0x400000 (imm26 = 2), b -4 at 0x400004 to 0x400000 (a different function name).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x9400_0002u32.to_le_bytes());
        bytes.extend_from_slice(&0x17FF_FFFFu32.to_le_bytes());
        let transfers = [
            Transfer { from: 0x400000, to: 0x400008, name: "a" },
            Transfer { from: 0x400004, to: 0x400000, name: "b" },
        ];
        let relocs = relocate_transfers(Arch::Aarch64, 0x400000, &mut bytes, false, &transfers);
        assert_eq!(relocs.iter().map(|r| r.kind).collect::<Vec<_>>(), [283, 282]);
        assert_eq!(bytes, [0, 0, 0, 0x94, 0, 0, 0, 0x14]);
        let elf = build_object(Arch::Aarch64, "f", &bytes, false, &relocs);
        let file = parse(&elf);
        assert_eq!(file.architecture(), object::Architecture::Aarch64);
        assert_eq!(file.section_by_name(".text").unwrap().relocations().count(), 2);
    }

    #[test]
    fn powerpc_bl_is_big_endian_and_rela() {
        // bl +0x10 at 0x10000
        let mut bytes = (0x4800_0011u32).to_be_bytes().to_vec();
        let transfers = [Transfer { from: 0x10000, to: 0x10010, name: "x" }];
        let relocs = relocate_transfers(Arch::Ppc32, 0x10000, &mut bytes, false, &transfers);
        assert_eq!(relocs.len(), 1);
        assert_eq!(bytes, 0x4800_0001u32.to_be_bytes());
        let elf = build_object(Arch::Ppc32, "f", &bytes, false, &relocs);
        let file = parse(&elf);
        assert_eq!(file.architecture(), object::Architecture::PowerPc);
        assert!(!file.is_little_endian());
        let elf = build_object(Arch::Ppc64, "f", &bytes, false, &relocs);
        assert_eq!(parse(&elf).architecture(), object::Architecture::PowerPc64);
    }

    #[test]
    fn an_object_without_relocations_is_still_a_valid_elf() {
        let elf = build_object(Arch::Aarch64, "g", &[0xC0, 0x03, 0x5F, 0xD6], false, &[]);
        let file = parse(&elf);
        assert_eq!(file.section_by_name(".text").unwrap().size(), 4);
        assert_eq!(file.kind(), object::ObjectKind::Relocatable);
    }
}
