//! SNES / Super Famicom cartridge images (WDC 65816, 24-bit `bus` space).
//!
//! A `.sfc`/`.smc` ROM carries a 64-byte internal header at `0x7FC0` (LoROM)
//! or `0xFFC0` (HiROM), optionally preceded by a 512-byte copier header. The
//! header's checksum and its complement must sum to `0xFFFF`, and the reset
//! vector (header `+0x3C`) must name a bus address at or above `0x8000` —
//! below that is RAM and I/O, never ROM (achan1989/ghidra-snes-loader,
//! `SnesHeader.looksValid`).
//!
//! The 65816 addresses a 24-bit bus as `bank:offset`. LoROM maps each 32 KiB
//! file chunk into the upper half of successive banks — chunk `i` at
//! `i:0x8000`, mirrored at `(i+0x80):0x8000` — so file offset `o` lands at
//! `(o/0x8000):0x8000+(o%0x8000)`. HiROM maps whole 64 KiB banks starting at
//! bank `0xC0`. Only LoROM is mapped here; HiROM is detected and refused with
//! a named error rather than mis-mapped.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// A copier (`.smc`) header is 512 bytes when present.
const SMC_LEN: usize = 512;
/// Internal header: reset vector at +0x3C, checksum pair at +0x1C/+0x1E.
const RESET_OFF: usize = 0x3C;
const COMPLEMENT_OFF: usize = 0x1C;
const CHECKSUM_OFF: usize = 0x1E;
/// LoROM header sits at file 0x7FC0; HiROM at 0xFFC0.
const LOROM_HEADER: usize = 0x7FC0;
const HIROM_HEADER: usize = 0xFFC0;
/// LoROM chunk size and the bank stride on the bus.
const CHUNK: u64 = 0x8000;
const BANK_STRIDE: u64 = 0x1_0000;

/// The console's own address map, declared not filled: work RAM lives in
/// banks 0x7E/0x7F, the PPU/APU registers in bank 0's low half.
const REGIONS: [(&str, u64, u64, u64); 3] = [
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    ("wram", 0x7e_0000, 0x2_0000, 0x7),
    ("io", 0x00_2000, 0x6000, 0x3),
    ("hw_vectors", 0x00_ffe0, 0x20, 0x2),
];

fn le16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Reads the header at `off` and reports whether it is a plausible SNES
/// header: checksum + complement == 0xFFFF and a reset vector >= 0x8000.
fn header_valid(data: &[u8], off: usize) -> Option<u16> {
    let checksum = le16(data, off + CHECKSUM_OFF)?;
    let complement = le16(data, off + COMPLEMENT_OFF)?;
    let reset = le16(data, off + RESET_OFF)?;
    if checksum.wrapping_add(complement) != 0xFFFF || reset < 0x8000 {
        return None;
    }
    Some(reset)
}

/// Finds the SNES header, allowing for a 512-byte copier prefix. Returns
/// (is_lorom, header_file_offset, reset_vector).
fn find_header(data: &[u8]) -> Option<(bool, usize, u16)> {
    for base in [0usize, SMC_LEN] {
        if let Some(reset) = header_valid(data, base + LOROM_HEADER) {
            return Some((true, base + LOROM_HEADER, reset));
        }
        if let Some(reset) = header_valid(data, base + HIROM_HEADER) {
            return Some((false, base + HIROM_HEADER, reset));
        }
    }
    None
}

/// True when `data` carries a verifiable SNES header.
pub(crate) fn is_rom(data: &[u8]) -> bool {
    find_header(data).is_some()
}

/// Loads a LoROM image: each 32 KiB chunk at `bank:0x8000` (and its 0x80
/// mirror), the reset vector seeded. HiROM is detected but refused — its
/// whole-bank mapping is a separate layout this loader does not yet emit.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let Some((lorom, header_off, reset)) = find_header(data) else {
        return super::err("not a SNES cartridge");
    };
    if !lorom {
        return super::err("HiROM SNES image detected but not yet mapped");
    }
    // Skip the copier header if present.
    let rom_start = if header_off == LOROM_HEADER { 0 } else { SMC_LEN };
    let rom = &data[rom_start..];
    let mut mappings = Vec::new();
    let mut names = Vec::new();
    let chunks = rom.len() / CHUNK as usize;
    for i in 0..chunks {
        let file_off = rom_start + i * CHUNK as usize;
        let bytes = rom[i * CHUNK as usize..(i + 1) * CHUNK as usize].to_vec();
        // Primary mapping at bank i, mirror at bank i+0x80.
        for (bank, tag) in [(i as u64, ""), (i as u64 + 0x80, "_m")] {
            mappings.push(Mapping {
                vaddr: bank * BANK_STRIDE + CHUNK,
                size: CHUNK,
                file_off: file_off as u64,
                flags: 0x6,
                bytes: bytes.clone(),
            });
            names.push(format!("rom_{:02x}{}", i, tag));
        }
    }
    // The reset vector is a 16-bit address in bank 0 (PB=0 at reset); for
    // LoROM that is bus 0x00:reset.
    let entry = u64::from(reset);
    let mut import = NativeImport {
        mappings,
        mapping_names: names,
        format: "sfc".into(),
        language: "65816:LE:16:default".into(),
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
