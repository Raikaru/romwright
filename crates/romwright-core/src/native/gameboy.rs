//! Game Boy / Game Boy Color cartridge images (SM83 CPU, "GameBoy" SLEIGH).
//!
//! A `.gb`/`.gbc` ROM has no magic; its identity is the header at
//! `0x100..=0x14F`: entry point at `0x100`, the Nintendo logo bitmap at
//! `0x104..=0x133`, title and cartridge type through `0x14C`, and a header
//! checksum at `0x14D` computed as `x = x - byte - 1` over `0x134..=0x14C`
//! (gbdev Pan Docs, "The Cartridge Header"). A checksum that verifies is the
//! detection; nothing else about the layout is guessed.
//!
//! The SM83 sees the ROM at `0x0000`: bank 0 fixed across `0x0000..=0x3FFF`,
//! the first switchable bank across `0x4000..=0x7FFF`. Execution begins at
//! `0x100`, which is almost always a jump over the header into bank 0.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// The header lives at 0x100; the checksum covers 0x134..=0x14C.
const HEADER_END: usize = 0x150;
const CHECKSUM_AT: usize = 0x14D;
const CHECKSUM_FROM: usize = 0x134;
/// Bank 0 window and the switchable window.
const BANK0_END: u64 = 0x4000;
const BANK1_END: u64 = 0x8000;

/// The console's own address map, declared not filled.
const REGIONS: [(&str, u64, u64, u64); 7] = [
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    ("vram", 0x8000, 0x2000, 0x3),
    ("extram", 0xa000, 0x2000, 0x7),
    ("wram", 0xc000, 0x2000, 0x7),
    ("oam", 0xfe00, 0xa0, 0x3),
    ("io", 0xff00, 0x80, 0x3),
    ("hram", 0xff80, 0x7f, 0x7),
    ("ie", 0xffff, 0x1, 0x3),
];

/// The header checksum at 0x14D, verified over 0x134..=0x14C.
fn checksum_ok(data: &[u8]) -> bool {
    if data.len() < HEADER_END {
        return false;
    }
    let mut x: u8 = 0;
    for &b in &data[CHECKSUM_FROM..CHECKSUM_AT] {
        x = x.wrapping_sub(b).wrapping_sub(1);
    }
    x == data[CHECKSUM_AT]
}

/// True when `data` carries a verifiable Game Boy header.
pub(crate) fn is_rom(data: &[u8]) -> bool {
    checksum_ok(data)
}

/// Loads a Game Boy image: bank 0 at `0x0000`, the first switchable bank at
/// `0x4000`, the `0x100` entry seeded, and the console's map declared.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    if !checksum_ok(data) {
        return super::err("not a Game Boy cartridge");
    }
    let bank0 = data[..(BANK0_END as usize).min(data.len())].to_vec();
    let bank1 = if data.len() > BANK0_END as usize {
        data[BANK0_END as usize..(BANK1_END as usize).min(data.len())].to_vec()
    } else {
        Vec::new()
    };
    let mut mappings = vec![Mapping {
        vaddr: 0,
        size: bank0.len() as u64,
        file_off: 0,
        flags: 0x6,
        bytes: bank0,
    }];
    let mut names = vec!["rom0".to_string()];
    if !bank1.is_empty() {
        mappings.push(Mapping {
            vaddr: BANK0_END,
            size: bank1.len() as u64,
            file_off: BANK0_END,
            flags: 0x6,
            bytes: bank1,
        });
        names.push("rom1".to_string());
    }
    let mut import = NativeImport {
        mappings,
        mapping_names: names,
        format: "gb".into(),
        language: "GameBoy:LE:16:default".into(),
        process_entry: Some(0x100),
        ..Default::default()
    };
    import.functions.push(NativeFunction {
        entry: 0x100,
        name: "entry".into(),
        size: 4,
    });
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
