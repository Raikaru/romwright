//! GameCube DOL section-table loader. Format reference: Dolphin DolReader.h
//! (GPL-2.0-or-later); independent implementation, no upstream code copied.
use super::{err, u32_be_at, Mapping, NativeFunction, NativeImport, NativeRegisterContext, Result};

pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    const HEADER_SIZE: usize = 0xe4;
    if data.len() < HEADER_SIZE {
        return err("truncated DOL header");
    }
    let mut mappings: Vec<Mapping> = Vec::with_capacity(20);
    for index in 0..18 {
        let offset = u32_be_at(data, index * 4)? as usize;
        let address = u32_be_at(data, 0x48 + index * 4)? as u64;
        let size = u32_be_at(data, 0x90 + index * 4)? as u64;
        if size == 0 {
            continue;
        }
        let end = address + size;
        if end > 0x1_0000_0000 || (index < 7 && address % 4 != 0) {
            return err("invalid DOL section address range");
        }
        let file_end = offset.checked_add(size as usize)
            .ok_or_else(|| super::ImportError::Bad("DOL section file range overflow".into()))?;
        if offset < HEADER_SIZE || file_end > data.len() {
            return err("DOL section outside file");
        }
        if mappings.iter().any(|m| address < m.vaddr + m.size && m.vaddr < end) {
            return err("overlapping DOL initialized sections");
        }
        mappings.push(Mapping {
            vaddr: address,
            size,
            file_off: offset as u64,
            flags: if index < 7 { 6 } else { 3 },
            bytes: data[offset..file_end].to_vec(),
        });
    }
    let entry = u32_be_at(data, 0xe0)? as u64;
    if entry % 4 != 0 || !mappings.iter().any(|m| m.flags & 4 != 0 && entry >= m.vaddr && entry < m.vaddr + m.size) {
        return err("DOL entry is not inside a text section");
    }
    mappings.sort_unstable_by_key(|m| m.vaddr);
    let bss_start = u32_be_at(data, 0xd8)? as u64;
    let bss_end = bss_start + u32_be_at(data, 0xdc)? as u64;
    if bss_end > 0x1_0000_0000 {
        return err("DOL BSS address range overflow");
    }
    // DOL BSS bounds may encompass initialized small-data sections. Only
    // uncovered intervals are zero-filled; no allocation proportional to BSS.
    let mut zero_ranges = Vec::new();
    let mut cursor = bss_start;
    for m in &mappings {
        if cursor >= bss_end {
            break;
        }
        if m.vaddr + m.size <= cursor || m.vaddr >= bss_end {
            continue;
        }
        if cursor < m.vaddr {
            zero_ranges.push((cursor, m.vaddr));
        }
        cursor = cursor.max(m.vaddr + m.size);
    }
    if cursor < bss_end {
        zero_ranges.push((cursor, bss_end));
    }
    mappings.extend(zero_ranges.into_iter().map(|(start, end)| Mapping {
        vaddr: start, size: end - start, file_off: 0, flags: 3, bytes: Vec::new(),
    }));
    mappings.sort_unstable_by_key(|m| m.vaddr);
    let register_contexts = startup_register_contexts(&mappings, entry);
    Ok(NativeImport {
        mappings,
        functions: vec![NativeFunction { entry, name: "_entry".into(), size: 1 }],
        format: "dol".into(),
        language: "PowerPC:BE:32:Gekko_Broadway".into(),
        register_contexts,
        // A DOL carries no relocations: its vtables and callback tables hold
        // absolute code addresses, the only reference a virtual function has.
        unrelocated_data_pointers: true,
        ..Default::default()
    })
}

/// Recognize a side-effect-free EABI register initializer reached by the first
/// startup call. Values come from instructions, not guessed section offsets.
fn startup_registers(mappings: &[Mapping], entry: u64) -> Option<(u64, u64, [u32; 2], u32)> {
    let instruction = |address: u64| {
        let mapping = mappings.iter().find(|mapping| {
            mapping.flags & 4 != 0 && address >= mapping.vaddr
                && address.checked_add(4).is_some_and(|end| end <= mapping.vaddr + mapping.size)
        })?;
        let offset = usize::try_from(address - mapping.vaddr).ok()?;
        Some(u32::from_be_bytes(mapping.bytes.get(offset..offset + 4)?.try_into().ok()?))
    };
    let branch = instruction(entry)?;
    if branch >> 26 != 18 || branch & 1 == 0 {
        return None;
    }
    let displacement = (((branch & 0x03ff_fffc) as i32) << 6) >> 6;
    let initializer = if branch & 2 == 0 {
        (entry as u32).wrapping_add(displacement as u32)
    } else {
        displacement as u32
    } as u64;
    let mut registers: [Option<u32>; 32] = [None; 32];
    for index in 0..32u64 {
        let address = initializer.checked_add(index * 4)?;
        let word = instruction(address)?;
        if word == 0x4e80_0020 {
            // A complete stack + SDA setup distinguishes this ABI initializer
            // from an arbitrary helper that happens to write one register.
            let stack = registers[1]?;
            let bases = [registers[2]?, registers[13]?];
            if bases.iter().any(|base| *base == 0 || !mappings.iter().any(|mapping| {
                mapping.flags & 4 == 0 && mapping.size != 0
                    && mapping.vaddr < u64::from(*base) + 0x8000
                    && mapping.vaddr + mapping.size > u64::from(*base).saturating_sub(0x8000)
            })) {
                return None;
            }
            return Some((initializer, address + 4, bases, stack));
        }
        let destination;
        let value;
        match word >> 26 {
            14 | 15 => {
                destination = ((word >> 21) & 31) as usize;
                let source = ((word >> 16) & 31) as usize;
                let base = if source == 0 { 0 } else { registers[source]? };
                let immediate = word as i16 as i32 as u32;
                value = base.wrapping_add(if word >> 26 == 15 { immediate << 16 } else { immediate });
            }
            24 | 25 => {
                destination = ((word >> 16) & 31) as usize;
                let source = ((word >> 21) & 31) as usize;
                let immediate = word & 0xffff;
                value = registers[source]? | if word >> 26 == 25 { immediate << 16 } else { immediate };
            }
            _ => return None,
        }
        if !matches!(destination, 1 | 2 | 13) {
            return None;
        }
        registers[destination] = Some(value);
    }
    None
}

/// Where a REL set is placed: the first 32-byte boundary `0x2000` past the
/// arena start, which the Dolphin SDK linker script defines as
/// `__ArenaLo = align32(_stack_addr + 0x2000)` and the startup initializer's
/// `r1` is `_stack_addr`. decomp-toolkit's `rel merge` places its REL
/// sections at `align32(__ArenaLo + 0x2000)`, so this reproduces its layout
/// on any image built with that script. When the initializer is not
/// recognised the base falls back to the end of the DOL's own mappings.
pub(crate) fn rel_base(imp: &NativeImport) -> u64 {
    let end = imp.mappings.iter().map(|m| m.vaddr + m.size).max().unwrap_or(0);
    let arena_lo = imp
        .functions
        .first()
        .and_then(|entry| startup_registers(&imp.mappings, entry.entry))
        .map(|(_, _, _, stack)| (u64::from(stack) + 0x2000 + 31) & !31)
        .filter(|arena_lo| *arena_lo >= end)
        .unwrap_or((end + 31) & !31);
    (arena_lo + 0x2000 + 31) & !31
}

/// The `r2`/`r13` small-data bases the startup initializer establishes, as
/// `[r2, r13]`: REL code addresses its data through the same two.
pub(crate) fn sda_bases(imp: &NativeImport) -> Option<[u32; 2]> {
    let entry = imp.functions.first()?.entry;
    startup_registers(&imp.mappings, entry).map(|(_, _, bases, _)| bases)
}

fn startup_register_contexts(mappings: &[Mapping], entry: u64) -> Vec<NativeRegisterContext> {
    let Some((initializer, end, bases, _)) = startup_registers(mappings, entry) else {
        return Vec::new();
    };
    // Before this call returns the bases are not established. Do not assert
    // them at the startup entry or inside the initializer itself.
    let mut excluded = [(entry, entry + 4), (initializer, end)];
    excluded.sort_unstable();
    let mut ranges = Vec::new();
    for mapping in mappings.iter().filter(|mapping| mapping.flags & 4 != 0) {
        let end = mapping.vaddr + mapping.size;
        let mut cursor = mapping.vaddr;
        let mut add = |start, end| {
            if start < end {
                for (register, value) in [("r2", bases[0]), ("r13", bases[1])] {
                    ranges.push(NativeRegisterContext {
                        start, end, register: register.into(), value: u64::from(value),
                    });
                }
            }
        };
        for (first, last) in excluded {
            if last <= cursor || first >= end {
                continue;
            }
            add(cursor, first.min(end));
            cursor = cursor.max(last.min(end));
        }
        add(cursor, end);
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut data = vec![0; 0x120];
        for (offset, value) in [(0, 0x100_u32), (0x48, 0x80001000), (0x90, 0x10),
                                (0x1c, 0x110), (0x64, 0x80002010), (0xac, 0x10),
                                (0xd8, 0x80002000), (0xdc, 0x30), (0xe0, 0x80001000)] {
            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        data[0x110..0x120].fill(0xab);
        data
    }

    #[test]
    fn bss_preserves_initialized_small_data() {
        let parsed = import(&fixture()).unwrap();
        let data = parsed.mappings.iter().find(|m| m.vaddr == 0x80002010).unwrap();
        assert_eq!(data.bytes, vec![0xab; 16]);
        let zeros: Vec<_> = parsed.mappings.iter().filter(|m| m.bytes.is_empty())
            .map(|m| (m.vaddr, m.size)).collect();
        assert_eq!(zeros, [(0x80002000, 16), (0x80002020, 16)]);
    }

    #[test]
    fn startup_bases_reach_later_functions_but_not_the_initializer() {
        let mut data = fixture();
        data.resize(0x190, 0);
        data[0x90..0x94].copy_from_slice(&0x60u32.to_be_bytes());
        data[0x1c..0x20].copy_from_slice(&0x180u32.to_be_bytes());
        data[0x100..0x104].copy_from_slice(&0x4800_0021u32.to_be_bytes());
        // lis/ori stack and r2; lis/addi r13 with a signed low half.
        let initializer = [
            0x3c20_8001u32, 0x6021_a000, 0x3c40_8000, 0x6042_9ff0,
            0x3da0_8001, 0x39ad_a010, 0x4e80_0020,
        ];
        for (index, word) in initializer.into_iter().enumerate() {
            data[0x120 + index * 4..0x124 + index * 4].copy_from_slice(&word.to_be_bytes());
        }
        let mut parsed = import(&data).unwrap();
        parsed.functions.extend([0x80001020, 0x80001040].into_iter().map(|entry| {
            NativeFunction { entry, name: String::new(), size: 4 }
        }));
        assert_eq!(
            super::super::sda_decode_points(&parsed.register_contexts, &parsed.functions),
            [
                (0x80001040, "r13".into(), 0x8000a010),
                (0x80001040, "r2".into(), 0x80009ff0),
            ],
        );
        // A later unknown load destroys the constant proof. Do not retain the
        // earlier lis/addi pair while skipping an instruction we cannot model.
        data[0x138..0x13c].copy_from_slice(&0x81a3_0000u32.to_be_bytes());
        data[0x13c..0x140].copy_from_slice(&0x4e80_0020u32.to_be_bytes());
        assert!(import(&data).unwrap().register_contexts.is_empty());
    }

    #[test]
    fn malformed_ranges_and_entries_are_rejected() {
        for (offset, value) in [(0, 0x11f_u32), (0x48, 0xfffffff8),
                                (0x64, 0x80001000), (0xe0, 0x80002010),
                                (0xd8, 0xfffffff0)] {
            let mut data = fixture();
            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(import(&data).is_err(), "accepted malformed field {offset:#x}");
        }
        assert!(import(&[0; 0xe3]).is_err());
    }

    #[test]
    fn data_words_naming_code_seed_entries_in_a_dol() {
        // A DOL has no relocations: a vtable word is the only reference a
        // virtual function has. An aligned word naming code outside every body
        // counts; an unaligned one, a data address and the declared entry do not.
        let mut data = fixture();
        for (offset, word) in [(0x110, 0x8000_1008_u32), (0x114, 0x8000_1002),
                               (0x118, 0x8000_2010), (0x11c, 0x8000_1000)] {
            data[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
        }
        let parsed = import(&data).unwrap();
        assert!(parsed.unrelocated_data_pointers);
        assert_eq!(super::super::data_code_pointers(&parsed), [0x8000_1008]);
    }

    #[test]
    fn a_jump_table_run_is_not_seeded_but_a_vtable_run_is() {
        // 0x80001000..0x80001008 is a function body. A run of data words with
        // one inside it and no entry is a switch's table, whose case labels
        // are never entries; a run naming an entry is a vtable; a lone word
        // names its target either way.
        for (words, expected) in [
            ([0x8000_1004_u32, 0x8000_1008, 0, 0], &[][..]),
            ([0x8000_1000, 0x8000_1008, 0, 0], &[0x8000_1008][..]),
            ([0x8000_1008, 0, 0x8000_1004, 0], &[0x8000_1008][..]),
        ] {
            let mut data = fixture();
            for (index, word) in words.into_iter().enumerate() {
                data[0x110 + index * 4..0x114 + index * 4].copy_from_slice(&word.to_be_bytes());
            }
            let mut parsed = import(&data).unwrap();
            parsed.functions[0].size = 8;
            assert_eq!(super::super::data_code_pointers(&parsed), expected, "{words:x?}");
        }
    }
}
