//! N64 overlay sets (P3.3): an N64 game pages code in and out of RDRAM.
//! The ROM's overlay table — a run of entries the game itself reads —
//! names each overlay's ROM offset, load address, and size. An overlay
//! set is the boot image plus every overlay, each mapped at its declared
//! RDRAM address so cross-overlay calls resolve.
//!
//! The overlay table's location is game-specific (it lives in the game
//! code, not the header), so the caller supplies the parsed entries:
//! (name, rom_offset, load_address, size) rows. Each overlay's bytes are
//! sliced from the ROM and mapped at its load address.

use super::{Mapping, NativeImport, Result};

/// One N64 overlay: where it lives in the ROM and where it loads.
#[derive(Clone, Debug)]
pub struct N64Overlay {
    pub name: String,
    /// File offset of the overlay's bytes inside the ROM.
    pub rom_offset: u64,
    /// RDRAM address the overlay is loaded at.
    pub load_address: u64,
    /// Byte size of the overlay.
    pub size: u64,
}

/// Imports an N64 overlay set: the boot image (the whole ROM, parsed by
/// the N64 loader) plus each overlay mapped at its load address.
///
/// Returns the boot import first, then one import per overlay in table
/// order. Overlays sharing a load address are legal — the game swaps
/// them — so no overlap check runs across members.
pub fn import_set(
    rom: &[u8],
    overlays: &[N64Overlay],
) -> Result<Vec<(String, NativeImport)>> {
    let mut out = Vec::with_capacity(overlays.len() + 1);
    // The boot image: the whole ROM through the normal N64 loader.
    let boot = super::n64::import(rom)?;
    out.push(("boot".into(), boot));
    for overlay in overlays {
        let start = overlay.rom_offset as usize;
        let end = start
            .checked_add(overlay.size as usize)
            .ok_or_else(|| super::ImportError::Bad("N64 overlay range overflow".into()))?;
        let bytes = rom
            .get(start..end)
            .ok_or_else(|| super::ImportError::Bad(format!(
                "N64 overlay {} outside ROM", overlay.name
            )))?
            .to_vec();
        let mut imp = NativeImport::default();
        imp.mappings = vec![Mapping {
            vaddr: overlay.load_address,
            size: overlay.size,
            file_off: overlay.rom_offset,
            flags: 6, // overlays are code
            bytes,
        }];
        imp.format = "N64-overlay".into();
        imp.language = "MIPS:BE:64:64-32addr".into();
        out.push((overlay.name.clone(), imp));
    }
    Ok(out)
}
