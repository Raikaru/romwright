//! The section layout of a GameCube/Wii DOL as decomp-toolkit's `Sections:`
//! block needs it: names, kinds and alignments in address order.
//!
//! A DOL stores 7 text and 11 data slots and one BSS range, nothing that says
//! what a slot is. Metrowerks' linker script does leave two tables in the
//! `.init` section, though: `_rom_copy_info` (one `rom, copy, size` triple per
//! initialised section, with the section's *unpadded* size) and `_bss_init_info`
//! (one `address, size` pair per BSS section). They give the exact section
//! boundaries (`.sbss2` ends where `.bss` begins even though both sit in one
//! BSS range of the header). The table search follows decomp-toolkit's
//! `process_dol` (MIT OR Apache-2.0; behaviour studied, code written here).
//!
//! Names are positional: the linker script orders sections `.init`, `extab`,
//! `extabindex`, `.text`, `.ctors`, `.dtors`, `.rodata`, `.data`, `.bss`,
//! `.sdata`, `.sbss`, `.sdata2`, `.sbss2` (Wii games move `.bss` to the end).
//! Eight initialised data slots are `extab` through `.sdata2`; six are the same
//! without `extab`/`extabindex`. A BSS section is `.sbss` after `.sdata`,
//! `.sbss2` after `.sdata2` and `.bss` otherwise. Alignments are the smallest
//! power of two (at least 4) that puts a section where it is after the previous
//! one: what the linker script must say for the link to reproduce the layout.

const TEXT_SLOTS: usize = 7;
const DATA_SLOTS: usize = 11;
const MAX_ROM_COPY_INFO: u32 = ((TEXT_SLOTS + DATA_SLOTS + 1) * 12) as u32;
const MAX_BSS_INIT_INFO: u32 = ((DATA_SLOTS + 1) * 8) as u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DolSection {
    pub name: String,
    /// `code`, `rodata`, `data` or `bss`: dtk's `type:`.
    pub kind: &'static str,
    pub align: u32,
    pub start: u32,
    /// Unpadded size (the `_rom_copy_info` size when the tables were found).
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DolLayout {
    pub entry: u32,
    pub sections: Vec<DolSection>,
    /// Section sizes and BSS boundaries came from the `.init` tables.
    pub from_tables: bool,
}

struct Slot {
    index: usize,
    address: u32,
    size: u32,
    offset: u32,
}

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn read_virtual(data: &[u8], slots: &[Slot], address: u32) -> Option<u32> {
    let slot = slots.iter().find(|s| {
        s.address <= address && address.checked_add(4).zip(s.address.checked_add(s.size)).is_some_and(|(end, limit)| end <= limit)
    })?;
    be32(data, (u64::from(slot.offset) + u64::from(address - slot.address)) as usize)
}

/// `(start, end)` address ranges.
type Ranges = Vec<(u32, u32)>;

/// The `_rom_copy_info` and `_bss_init_info` entries, when the `.init`
/// section carries them in the shape the Metrowerks linker script writes.
fn tables(data: &[u8], slots: &[Slot], bss: (u32, u32), entry: u32) -> Option<(Ranges, Ranges)> {
    let init = slots.iter().find(|s| s.address <= entry && entry < s.address.saturating_add(s.size))?;
    let first = slots.iter().min_by_key(|s| s.index)?.address;
    let end = init.address.saturating_add(init.size);
    if end > 0xffff_0000 {
        return None;
    }
    let mut at = end.checked_sub(MAX_ROM_COPY_INFO + MAX_BSS_INIT_INFO)?.max(init.address);
    loop {
        let value = read_virtual(data, slots, at)?;
        if value == first || value == entry {
            break;
        }
        at += 4;
        if at >= end {
            return None;
        }
    }
    let mut rom = Vec::new();
    loop {
        let (r, c, s) = (read_virtual(data, slots, at)?, read_virtual(data, slots, at + 4)?, read_virtual(data, slots, at + 8)?);
        at += 12;
        if s == 0 {
            break;
        }
        if r != c || at >= end {
            return None;
        }
        rom.push((r, s));
    }
    loop {
        let value = read_virtual(data, slots, at)?;
        if value >= bss.0 && value < bss.0.saturating_add(bss.1) {
            break;
        }
        at += 4;
        if at >= end {
            return None;
        }
    }
    let mut zero = Vec::new();
    loop {
        let (a, s) = (read_virtual(data, slots, at)?, read_virtual(data, slots, at + 4)?);
        at += 8;
        if s == 0 {
            break;
        }
        if at >= end {
            return None;
        }
        zero.push((a, s));
    }
    Some((rom, zero))
}

/// Parses `dol` and names its sections. `None` when it is not a DOL.
pub fn dol_layout(dol: &[u8]) -> Option<DolLayout> {
    if dol.len() < 0xe4 {
        return None;
    }
    let mut slots = Vec::new();
    for index in 0..TEXT_SLOTS + DATA_SLOTS {
        let size = be32(dol, 0x90 + index * 4)?;
        if size == 0 {
            continue;
        }
        slots.push(Slot { index, address: be32(dol, 0x48 + index * 4)?, size, offset: be32(dol, index * 4)? });
    }
    let (bss_address, bss_size, entry) = (be32(dol, 0xd8)?, be32(dol, 0xdc)?, be32(dol, 0xe0)?);
    let found = tables(dol, &slots, (bss_address, bss_size), entry);

    struct Raw {
        start: u32,
        size: u32,
        code: bool,
        init: bool,
        bss: bool,
    }
    let mut raw: Vec<Raw> = slots
        .iter()
        .map(|s| {
            let size = found
                .as_ref()
                .and_then(|(rom, _)| rom.iter().find(|(a, _)| *a == s.address).map(|(_, size)| *size))
                .unwrap_or(s.size);
            Raw {
                start: s.address,
                size,
                code: s.index < TEXT_SLOTS,
                init: s.address <= entry && entry < s.address.saturating_add(s.size),
                bss: false,
            }
        })
        .collect();
    match &found {
        Some((_, zero)) => raw.extend(zero.iter().map(|&(start, size)| Raw { start, size, code: false, init: false, bss: true })),
        None => {
            // No tables (another linker script): the BSS range minus what the
            // initialised sections cover.
            let mut cursor = bss_address;
            let end = bss_address.checked_add(bss_size)?;
            let mut covered: Vec<(u32, u32)> =
                slots.iter().filter(|s| s.index >= TEXT_SLOTS).map(|s| (s.address, s.address.saturating_add(s.size))).collect();
            covered.sort_unstable();
            for (lo, hi) in covered {
                if hi <= cursor || lo >= end {
                    continue;
                }
                if cursor < lo {
                    raw.push(Raw { start: cursor, size: lo - cursor, code: false, init: false, bss: true });
                }
                cursor = cursor.max(hi);
            }
            if cursor < end {
                raw.push(Raw { start: cursor, size: end - cursor, code: false, init: false, bss: true });
            }
        }
    }
    raw.sort_by_key(|r| r.start);

    let data_count = raw.iter().filter(|r| !r.code && !r.bss).count();
    const NAMES: [&str; 8] = ["extab", "extabindex", ".ctors", ".dtors", ".rodata", ".data", ".sdata", ".sdata2"];
    let named: Option<&[&str]> = match data_count {
        8 => Some(&NAMES),
        6 => Some(&NAMES[2..]),
        _ => None,
    };
    let mut sections: Vec<DolSection> = Vec::with_capacity(raw.len());
    let (mut data_index, mut text_index) = (0usize, 0usize);
    let mut previous_end: Option<u32> = None;
    for r in &raw {
        let name = if r.code {
            if r.init {
                ".init".to_string()
            } else {
                text_index += 1;
                if text_index == 1 { ".text".to_string() } else { format!(".text{}", text_index - 1) }
            }
        } else if r.bss {
            let preceding = sections.last().map(|s| s.name.as_str()).unwrap_or("");
            let base = match preceding {
                ".sdata" => ".sbss",
                ".sdata2" => ".sbss2",
                _ => ".bss",
            };
            if sections.iter().any(|s| s.name == base) { format!("{base}{}", sections.len()) } else { base.to_string() }
        } else {
            let name = named.map(|n| n[data_index].to_string()).unwrap_or_else(|| format!(".data{data_index}"));
            data_index += 1;
            name
        };
        let kind = if r.code {
            "code"
        } else if r.bss {
            "bss"
        } else if matches!(name.as_str(), ".data" | ".sdata") {
            "data"
        } else if named.is_some() {
            "rodata"
        } else {
            "data"
        };
        let align = match previous_end {
            None => 4,
            Some(end) => {
                let mut align = 4u64;
                while align <= 256 && u64::from(end).div_ceil(align) * align != u64::from(r.start) {
                    align *= 2;
                }
                if align <= 256 { align as u32 } else { 4 }
            }
        };
        previous_end = Some(r.start.saturating_add(r.size));
        sections.push(DolSection { name, kind, align, start: r.start, size: r.size });
    }
    Some(DolLayout { entry, sections, from_tables: found.is_some() })
}

impl DolLayout {
    /// The `Sections:` block of `splits.txt`.
    pub fn sections_block(&self) -> String {
        let mut text = String::from("Sections:\n");
        for section in &self.sections {
            text.push_str(&format!("\t{:<11} type:{} align:{}\n", section.name, section.kind, section.align));
        }
        text
    }

    /// `(name, address)` of the section holding `address`.
    pub fn section_of(&self, address: u64) -> Option<&DolSection> {
        self.sections.iter().find(|s| address >= u64::from(s.start) && address < u64::from(s.start) + u64::from(s.size.max(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// A DOL whose `.init` carries both tables the way the linker script writes them.
    fn dol_with_tables() -> Vec<u8> {
        let mut dol = vec![0u8; 0x1000];
        // text slot 0: .init at 0x80003100, 0x200 bytes at file 0x100.
        // text slot 1: .text at 0x80003300, 0x100 bytes at file 0x300.
        // data slots 7..: .ctors, .dtors, .rodata, .data, .sdata, .sdata2 (six: no extab).
        let sections: [(usize, u32, u32, u32); 8] = [
            (0, 0x100, 0x8000_3100, 0x200),
            (1, 0x300, 0x8000_3300, 0x100),
            (7, 0x400, 0x8000_3400, 0x20),
            (8, 0x420, 0x8000_3420, 0x20),
            (9, 0x440, 0x8000_3440, 0x40),
            (10, 0x480, 0x8000_3480, 0x40),
            (11, 0x4c0, 0x8000_34c0, 0x20),
            (12, 0x4e0, 0x8000_3600, 0x20),
        ];
        for (index, off, addr, size) in sections {
            put(&mut dol, index * 4, off);
            put(&mut dol, 0x48 + index * 4, addr);
            put(&mut dol, 0x90 + index * 4, size);
        }
        // BSS range 0x800034e0..0x80003620: .bss, then .sdata2 sits at 0x80003600
        put(&mut dol, 0xd8, 0x8000_34e0);
        put(&mut dol, 0xdc, 0x140);
        put(&mut dol, 0xe0, 0x8000_3100);
        // `_rom_copy_info` near the end of .init (file 0x100 + 0x200 - tables).
        let mut at = 0x100 + 0x200 - (MAX_ROM_COPY_INFO + MAX_BSS_INIT_INFO) as usize;
        for (addr, size) in [
            (0x8000_3100u32, 0x1f0u32),
            (0x8000_3300, 0xf0),
            (0x8000_3400, 0x20),
            (0x8000_3420, 0x10),
            (0x8000_3440, 0x40),
            (0x8000_3480, 0x40),
            (0x8000_34c0, 0x20),
            (0x8000_3600, 0x20),
        ] {
            put(&mut dol, at, addr);
            put(&mut dol, at + 4, addr);
            put(&mut dol, at + 8, size);
            at += 12;
        }
        at += 12; // terminator triple (all zero)
        for (addr, size) in [(0x8000_34e0u32, 0x100u32), (0x8000_3620, 0x0)] {
            put(&mut dol, at, addr);
            put(&mut dol, at + 4, size);
            at += 8;
        }
        dol
    }

    #[test]
    fn the_init_tables_give_unpadded_sizes_and_the_bss_sections() {
        let layout = dol_layout(&dol_with_tables()).unwrap();
        assert!(layout.from_tables);
        let names: Vec<_> = layout.sections.iter().map(|s| (s.name.as_str(), s.size)).collect();
        assert_eq!(
            names,
            [
                (".init", 0x1f0),
                (".text", 0xf0),
                (".ctors", 0x20),
                (".dtors", 0x10),
                (".rodata", 0x40),
                (".data", 0x40),
                (".sdata", 0x20),
                (".sbss", 0x100),
                (".sdata2", 0x20),
            ]
        );
    }

    #[test]
    fn alignment_is_the_smallest_that_places_the_section_after_the_previous_one() {
        let layout = dol_layout(&dol_with_tables()).unwrap();
        let align = |name: &str| layout.sections.iter().find(|s| s.name == name).unwrap().align;
        // .init ends at 0x800032f0 (16-aligned already), .text starts at 0x80003300: only 32 reaches it.
        assert_eq!(align(".text"), 32);
        // .ctors follows .text's end 0x800033f0 at 0x80003400: only 32 reaches it.
        assert_eq!(align(".ctors"), 32);
        // .dtors follows .ctors's end 0x80003420 exactly: the floor.
        assert_eq!(align(".dtors"), 4);
        assert!(layout.sections_block().starts_with("Sections:\n\t.init       type:code align:4\n"));
    }

    #[test]
    fn bss_without_tables_is_the_header_range_minus_initialised_data() {
        let mut dol = dol_with_tables();
        // Break the tables: nothing equals the entry or the first section any more.
        for byte in &mut dol[0x100 + 0x200 - 0x144..0x100 + 0x200] {
            *byte = 0xff;
        }
        let layout = dol_layout(&dol).unwrap();
        assert!(!layout.from_tables);
        let bss: Vec<_> = layout.sections.iter().filter(|s| s.kind == "bss").map(|s| (s.start, s.size)).collect();
        assert_eq!(bss, [(0x8000_34e0, 0x120)]);
    }

    #[test]
    fn a_short_file_is_no_dol() {
        assert!(dol_layout(&[0u8; 16]).is_none());
    }
}
