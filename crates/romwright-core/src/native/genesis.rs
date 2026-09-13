//! Sega Genesis / Mega Drive cartridge images (Motorola 68000).
//!
//! A raw ROM is the 68000's own vector table at offset 0: `0x000` is the
//! initial supervisor stack pointer and `0x004` the reset entry point, both
//! big-endian longs. The console header follows at `0x100` ("SEGA" in the
//! product field), but a homebrew or prototype image may not carry it, so the
//! loader keys on the vector table alone: a plausible SSP (RAM) and a reset
//! entry that lands inside the image.
//!
//! The 68000 reads the whole cartridge at `0x000000`; there is no banking in
//! the base format. Everything past the vectors is code and data the flow
//! pass separates.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// Cartridge base: the 68000's address 0.
const ROM_BASE: u64 = 0;
/// The vector table is the first 256 longs; the header follows at 0x100.
const HEADER_LEN: usize = 0x200;
/// Work RAM window the SSP must point into (0xFF0000..=0xFFFFFF, 64 KiB).
const RAM_LO: u64 = 0x00ff_0000;
const RAM_HI: u64 = 0x0100_0000;

/// The console's own address map, declared not filled.
const REGIONS: [(&str, u64, u64, u64); 4] = [
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    ("ram", 0x00ff_0000, 0x1_0000, 0x7),
    ("vdp", 0x00c0_0000, 0x20, 0x3),
    ("io", 0x00a1_0000, 0x40, 0x3),
    ("z80", 0x00a0_0000, 0x1_0000, 0x3),
];

fn be32(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 4)
        .map(|s| u64::from(u32::from_be_bytes(s.try_into().unwrap())))
}

/// The reset entry point, when the vector table is well-formed: a non-zero
/// SSP into work RAM and a non-zero entry inside the image.
fn entry_target(data: &[u8]) -> Option<u64> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let ssp = be32(data, 0)?;
    let entry = be32(data, 4)?;
    if !(RAM_LO..RAM_HI).contains(&ssp) {
        return None;
    }
    (entry != 0 && (entry as usize) < data.len()).then_some(entry)
}

/// True when `data` carries a plausible 68000 vector table.
pub(crate) fn is_rom(data: &[u8]) -> bool {
    entry_target(data).is_some()
}

/// Loads a Genesis image: ROM at `0x0`, the reset vector as the seed, and the
/// console's memory map declared.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let Some(entry) = entry_target(data) else {
        return super::err("not a Genesis cartridge");
    };
    let mut import = NativeImport {
        mappings: vec![Mapping {
            vaddr: ROM_BASE,
            size: data.len() as u64,
            file_off: 0,
            flags: 0x6, // read + execute
            bytes: data.to_vec(),
        }],
        mapping_names: vec!["rom".into()],
        format: "genesis".into(),
        language: "68000:BE:32:default".into(),
        process_entry: Some(entry),
        ..Default::default()
    };
    import.functions.push(NativeFunction {
        entry,
        name: "reset".into(),
        size: 1,
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
