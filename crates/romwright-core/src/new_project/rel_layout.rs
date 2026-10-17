//! The `Sections:` block of a REL module's `splits.txt`.
//!
//! A REL's section table (`header + 0x10`, `count` at `0xc`) names nothing: entry 0 is
//! null and the rest are (file offset | executable bit, size) pairs, an offset of
//! zero meaning bss. Metrowerks' linker script fills the slots the same way after the
//! text section: `.ctors`, `.dtors`, `.rodata`, `.data` in the four slots that follow
//! `.text` and `.bss` in the fifth (Twilight Princess, Wind Waker and Skyward Sword RELs
//! have `.text` in slot 1, Mario Party 4's in slot 2 with slot 1 empty); any other slot gets
//! a numbered name. dtk names a REL's sections by what its analysis sees the code do and
//! gives up (`Multiple sections with name .rodata`, `Only one of .ctors and .dtors has been
//! found?`) when two look alike, so the names are written down. Empty sections are not
//! listed (dtk does not list them either); alignments are the smallest power of two, at
//! least 4, that places a section where it is after the previous one in the file, which is
//! what dtk derives itself.

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

/// The module ids the REL imports relocations from (its import table at `0x28`, `0x2c` bytes of
/// `(module id, offset)` pairs), the DOL (0) and itself excluded.
pub fn imported_modules(data: &[u8]) -> Vec<u32> {
    let (Some(own), Some(table), Some(size)) = (be32(data, 0), be32(data, 0x28), be32(data, 0x2c)) else { return Vec::new() };
    let mut ids: Vec<u32> = (0..size as usize / 8)
        .filter_map(|i| be32(data, (table as usize).checked_add(i * 8)?))
        .filter(|id| *id != 0 && *id != own)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Whether the REL has a non-empty executable section. A module without one (Mario Party 4's
/// 144-byte stub DLLs hold only `.ctors`/`.dtors` words) cannot be linked by mwld: it dies with
/// `internal linker error: File: 'ELF_PPC_EABI.c' Line: 2687` on an object with no code.
pub fn has_code(data: &[u8]) -> bool {
    let (Some(count), Some(table)) = (be32(data, 0x0c), be32(data, 0x10)) else { return false };
    (1..count.min(256) as usize).any(|i| {
        let at = table as usize + i * 8;
        matches!((be32(data, at), be32(data, at + 4)), (Some(raw), Some(size)) if raw & 1 != 0 && size != 0)
    })
}

/// `Sections:` for the REL `data`; `None` when its header does not hold a section table.
pub fn rel_sections_block(data: &[u8]) -> Option<String> {
    let count = be32(data, 0x0c)? as usize;
    let table = be32(data, 0x10)? as usize;
    if count == 0 || count > 256 {
        return None;
    }
    let mut text = String::from("Sections:\n");
    let section = |index: usize| -> Option<(u32, u32)> { Some((be32(data, table + index * 8)?, be32(data, table + index * 8 + 4)?)) };
    // The slot of `.text`: the first non-empty executable section.
    let text_slot = (1..count).find(|&i| section(i).is_some_and(|(raw, size)| raw & 1 != 0 && size != 0));
    let mut previous_end: Option<u64> = None;
    for index in 1..count {
        let (raw, size) = section(index)?;
        if size == 0 {
            continue;
        }
        let exec = raw & 1 != 0;
        let offset = u64::from(raw & !1);
        let bss = offset == 0;
        let after_text = text_slot.and_then(|t| index.checked_sub(t));
        let (name, kind) = match after_text {
            Some(0) if exec => (".text".to_string(), "code"),
            Some(1) if !exec && !bss => (".ctors".to_string(), "rodata"),
            Some(2) if !exec && !bss => (".dtors".to_string(), "rodata"),
            Some(3) if !exec && !bss => (".rodata".to_string(), "rodata"),
            Some(4) if !exec && !bss => (".data".to_string(), "data"),
            Some(5) if bss => (".bss".to_string(), "bss"),
            _ if exec => (format!(".text{index}"), "code"),
            _ if bss => (format!(".bss{index}"), "bss"),
            _ => (format!(".data{index}"), "data"),
        };
        let align = if bss {
            // A bss section has no file offset; the linker aligns it to a cache line.
            32
        } else {
            let mut align = 4u64;
            if let Some(end) = previous_end {
                while align <= 256 && end.div_ceil(align) * align != offset {
                    align *= 2;
                }
                if align > 256 {
                    align = 4;
                }
            }
            align
        };
        if !bss {
            previous_end = Some(offset + u64::from(size));
        }
        text.push_str(&format!("\t{name:<11} type:{kind} align:{align}\n"));
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// Twilight Princess' `d_a_andsw2.rel` section table.
    #[test]
    fn slots_are_named_by_position_and_aligned_after_the_previous_section() {
        let mut rel = vec![0u8; 0x100];
        put(&mut rel, 0x0c, 7);
        put(&mut rel, 0x10, 0x40);
        for (index, offset, size) in [(1usize, 0xb5u32, 0xd40u32), (2, 0xdf4, 4), (3, 0xdf8, 4), (4, 0xe00, 0x84), (6, 0, 0x20)] {
            put(&mut rel, 0x40 + index * 8, offset);
            put(&mut rel, 0x40 + index * 8 + 4, size);
        }
        let block = rel_sections_block(&rel).unwrap();
        assert_eq!(
            block,
            "Sections:\n\t.text       type:code align:4\n\t.ctors      type:rodata align:4\n\t.dtors      type:rodata align:4\n\t.rodata     type:rodata align:8\n\t.bss        type:bss align:32\n"
        );
    }

    /// Mario Party 4's `safDll.rel`: slot 1 is an empty `.text`, the real one is slot 2.
    #[test]
    fn names_follow_the_text_slot_when_it_is_not_the_first() {
        let mut rel = vec![0u8; 0x100];
        put(&mut rel, 0x0c, 8);
        put(&mut rel, 0x10, 0x40);
        for (index, offset, size) in [
            (2usize, 0xc1u32, 0x3ac_u32),
            (3, 0x46c, 4),
            (4, 0x470, 4),
            (5, 0x478, 0x24),
            (6, 0x4a0, 0x39),
            (7, 0, 0x300),
        ] {
            put(&mut rel, 0x40 + index * 8, offset);
            put(&mut rel, 0x40 + index * 8 + 4, size);
        }
        let block = rel_sections_block(&rel).unwrap();
        let names: Vec<_> = block.lines().skip(1).map(|l| l.split_whitespace().next().unwrap()).collect();
        assert_eq!(names, [".text", ".ctors", ".dtors", ".rodata", ".data", ".bss"], "{block}");
    }

    #[test]
    fn imports_list_the_other_modules_a_rel_relocates_against() {
        let mut rel = vec![0u8; 0x100];
        put(&mut rel, 0, 7);
        put(&mut rel, 0x28, 0x60);
        put(&mut rel, 0x2c, 0x20);
        for (i, id) in [0u32, 7, 5, 5].into_iter().enumerate() {
            put(&mut rel, 0x60 + i * 8, id);
        }
        assert_eq!(imported_modules(&rel), [5]);
        assert!(imported_modules(&[0u8; 4]).is_empty());
    }

    #[test]
    fn a_module_without_an_executable_section_has_no_code() {
        let mut rel = vec![0u8; 0x100];
        put(&mut rel, 0x0c, 4);
        put(&mut rel, 0x10, 0x40);
        put(&mut rel, 0x40 + 2 * 8, 0x80); // data, not executable
        put(&mut rel, 0x40 + 2 * 8 + 4, 8);
        assert!(!has_code(&rel));
        put(&mut rel, 0x40 + 8, 0x91);
        put(&mut rel, 0x40 + 8 + 4, 0x10);
        assert!(has_code(&rel));
        assert!(!has_code(&[0u8; 4]));
    }

    #[test]
    fn a_file_without_a_section_table_has_no_block() {
        assert!(rel_sections_block(&[0u8; 8]).is_none());
        assert!(rel_sections_block(&[0u8; 0x40]).is_none());
    }
}
