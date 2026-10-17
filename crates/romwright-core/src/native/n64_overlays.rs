//! N64 overlay sets (P3.3): an N64 game pages code in and out of RDRAM.
//! The ROM's overlay table — a run of entries the game itself reads —
//! names each overlay's ROM offset, load address, and size. An overlay
//! set is the boot image plus every overlay, each mapped at its declared
//! RDRAM address so cross-overlay calls resolve.
//!
//! The overlay table's location is game-specific (it lives in the game
//! code, not the header), so the caller supplies the parsed entries:
//! (name, rom_offset, load_address, size) rows. Each overlay's bytes are
//! sliced from the ROM, unpacked with its codec (`n64_codec`: raw, Rare
//! zlib, MIO0, Yay0, Yaz0, deflate) and mapped at its load address.
//!
//! A game whose whole layout is known (every fixed segment, not only
//! overlays) is described once in `n64_layouts.json`; `import_with_layout`
//! applies a caller-supplied `n64_segments::Layout` to a ROM through the
//! same loader.

use super::n64_codec::Codec;
use super::n64_segments::Layout;
use super::{Mapping, NativeImport, Result};

/// One N64 overlay: where it lives in the ROM and where it loads.
#[derive(Clone, Debug)]
pub struct N64Overlay {
    pub name: String,
    /// File offset of the overlay's bytes inside the ROM.
    pub rom_offset: u64,
    /// How the bytes at `rom_offset` are stored; `size` is their stored length.
    pub codec: Codec,
    /// RDRAM address the overlay is loaded at.
    pub load_address: u64,
    /// Stored byte size of the overlay (the compressed length for a packed one).
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
        let stored = rom
            .get(start..end)
            .ok_or_else(|| super::ImportError::Bad(format!(
                "N64 overlay {} outside ROM", overlay.name
            )))?;
        let bytes = overlay
            .codec
            .decode(stored, 8 << 20)
            .map_err(|error| super::ImportError::Bad(format!(
                "N64 overlay {} ({}): {error}", overlay.name, overlay.codec.name()
            )))?;
        let imp = NativeImport {
            modules: vec![super::NativeModule {
                name: overlay.name.clone(),
                kind: "overlay".into(),
                file_id: format!("rom:{:#x}-{:#x}", overlay.rom_offset, end),
                load_vaddr: overlay.load_address,
                size: bytes.len() as u64,
                file_off: overlay.rom_offset,
            }],
            mappings: vec![Mapping {
                vaddr: overlay.load_address,
                size: bytes.len() as u64,
                file_off: overlay.rom_offset,
                flags: 6, // overlays are code
                bytes,
            }],
            format: "N64-overlay".into(),
            language: "MIPS:BE:64:64-32addr".into(),
            ..Default::default()
        };
        out.push((overlay.name.clone(), imp));
    }
    Ok(out)
}

/// Imports `rom` through a layout the caller supplies, for a game the
/// built-in catalog does not know.
pub fn import_with_layout(rom: &[u8], layout: &Layout) -> Result<NativeImport> {
    super::n64::import_layout(rom, Some(layout))
}
