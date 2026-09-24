//! Game Boy Advance cartridge images.
//!
//! A raw ROM has no section table, no symbol table and no entry field. What
//! it does have is documented: gbatek "Cartridge Header" fixes 0x96 at
//! offset 0xB2 and puts a branch at offset 0, and gbatek "Memory Map" fixes
//! where the cartridge and the console's RAM live. Everything else has to
//! come from flow.
//!
//! Nothing here guesses. An image is a cartridge only when the fixed byte is
//! in place *and* offset 0 is an unconditional ARM branch whose target lands
//! inside the image; otherwise the loader declines and the caller tries the
//! next format.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// gbatek "Memory Map": cartridge ROM, mirrored at three wait-state windows.
pub(crate) const ROM_BASE: u64 = 0x0800_0000;
/// The header a cartridge must carry, up to and including the fixed byte.
const HEADER_LEN: usize = 0xC0;
/// gbatek "Cartridge Header": offset 0xB2 is fixed, "required".
const FIXED_OFFSET: usize = 0xB2;
const FIXED_VALUE: u8 = 0x96;
/// ARM `B` with the condition field AL (ARM architecture reference A8.8.18).
const BRANCH_ALWAYS: u8 = 0xEA;

/// The console's own address map. A cartridge implies these regions without
/// containing them, so they are declared, never filled with invented bytes.
const REGIONS: [(&str, u64, u64, u64); 6] = [
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    ("ewram", 0x0200_0000, 256 * 1024, 0x7),
    ("iwram", 0x0300_0000, 32 * 1024, 0x7),
    ("io", 0x0400_0000, 0x400, 0x3),
    ("palette", 0x0500_0000, 1024, 0x3),
    ("vram", 0x0600_0000, 96 * 1024, 0x3),
    ("oam", 0x0700_0000, 1024, 0x3),
];

/// True when `data` carries the documented cartridge header.
pub(crate) fn is_cartridge(data: &[u8]) -> bool {
    entry_target(data).is_some()
}

/// The branch target at ROM offset 0, when the image is a cartridge.
/// `target = pc + 8 + (signed imm24 << 2)`, with pc the branch's address.
fn entry_target(data: &[u8]) -> Option<u64> {
    if data.len() < HEADER_LEN || data.get(FIXED_OFFSET) != Some(&FIXED_VALUE) {
        return None;
    }
    let word = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    if (word >> 24) as u8 != BRANCH_ALWAYS {
        return None;
    }
    let immediate = i32::from(((word & 0x00FF_FFFF) << 8) as i32 >> 8);
    let target = ROM_BASE
        .checked_add(8)?
        .checked_add_signed(i64::from(immediate) * 4)?;
    // A branch out of the image is not an entry point, and not evidence that
    // this file is a cartridge at all.
    let end = ROM_BASE.checked_add(data.len() as u64)?;
    (ROM_BASE..end).contains(&target).then_some(target)
}

/// Loads a cartridge image: ROM bytes at their mapped base, the entry branch
/// resolved as a seed, and the console's memory map declared.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let Some(entry) = entry_target(data) else {
        return super::err("not a Game Boy Advance cartridge");
    };
    let mut import = NativeImport {
        mappings: vec![Mapping {
            vaddr: ROM_BASE,
            size: data.len() as u64,
            file_off: 0,
            // Read + execute: the cartridge bus is not writable.
            flags: 0x6,
            bytes: data.to_vec(),
        }],
        mapping_names: vec!["rom".into()],
        format: "gba".into(),
        language: "ARM:LE:32:v4t".into(),
        // The cartridge holds code and data in one window.
        code_holds_data: true,
        ..Default::default()
    };
    // Two seeds, both from the header: the cartridge entry point the console
    // jumps to, and the function that branch reaches.
    import.functions.push(NativeFunction {
        entry: ROM_BASE,
        name: "_rom_entry".into(),
        size: 4,
    });
    if entry != ROM_BASE {
        import.functions.push(NativeFunction {
            entry,
            name: format!("entry_{entry:08x}"),
            size: 1,
        });
    }
    import.declared_regions = REGIONS
        .iter()
        .map(|&(name, vaddr, size, flags)| DeclaredRegion {
            name: name.into(),
            vaddr,
            size,
            flags,
        })
        .collect();
    Ok(import)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cartridge(branch: u32, len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len.max(HEADER_LEN)];
        data[..4].copy_from_slice(&branch.to_le_bytes());
        data[FIXED_OFFSET] = FIXED_VALUE;
        data
    }

    #[test]
    fn header_branch_resolves_the_entry_seed() {
        // b #0x150 from 0x08000000: 0x08000000 + 8 + 0x54 * 4.
        let image = cartridge(0xEA00_0054, 0x200);
        assert_eq!(entry_target(&image), Some(0x0800_0158));
        let import = import(&image).expect("cartridge");
        assert_eq!(import.language, "ARM:LE:32:v4t");
        assert_eq!(import.mappings[0].vaddr, ROM_BASE);
        assert_eq!(import.mappings[0].size, image.len() as u64);
        let seeds: Vec<u64> = import.functions.iter().map(|function| function.entry).collect();
        assert_eq!(seeds, vec![ROM_BASE, 0x0800_0158]);
    }

    #[test]
    fn the_fixed_byte_is_required() {
        let mut image = cartridge(0xEA00_0054, 0x200);
        image[FIXED_OFFSET] = 0;
        assert!(!is_cartridge(&image));
        assert!(import(&image).is_err());
    }

    #[test]
    fn offset_zero_must_be_an_unconditional_branch() {
        // A conditional branch, or any other instruction, is not the header
        // the console requires.
        assert!(!is_cartridge(&cartridge(0x1A00_0054, 0x200)));
    }

    #[test]
    fn a_branch_out_of_the_image_is_not_a_cartridge() {
        // Target 0x08001000 with a 0x200-byte image.
        assert!(!is_cartridge(&cartridge(0xEA00_03FE, 0x200)));
    }

    #[test]
    fn a_backward_branch_stays_inside_the_image() {
        // Negative displacement from the header lands before ROM base.
        assert!(!is_cartridge(&cartridge(0xEAFF_FF00, 0x200)));
    }

    #[test]
    fn declared_regions_are_the_console_map() {
        let import = import(&cartridge(0xEA00_0054, 0x200)).expect("cartridge");
        let declared: Vec<(&str, u64)> = import
            .declared_regions
            .iter()
            .map(|region| (region.name.as_str(), region.vaddr))
            .collect();
        assert_eq!(
            declared,
            vec![
                ("ewram", 0x0200_0000),
                ("iwram", 0x0300_0000),
                ("io", 0x0400_0000),
                ("palette", 0x0500_0000),
                ("vram", 0x0600_0000),
                ("oam", 0x0700_0000),
            ]
        );
    }
}
