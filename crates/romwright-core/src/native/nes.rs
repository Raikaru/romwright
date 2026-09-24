//! NES / Famicom cartridge images (iNES and NES 2.0).
//!
//! An iNES image is a 16-byte header, then PRG ROM (code) and CHR ROM
//! (graphics). The header fixes the magic `NES\x1a`, the PRG size in 16 KiB
//! units, and a trainer flag that shifts the PRG offset by 512 bytes.
//! Everything else about the mapping is the console's own address map: the
//! 6502 sees PRG at `0x8000`, mirrored to fill `0x8000..=0xFFFF` when the
//! image carries only one 16 KiB bank.
//!
//! The CPU's three hardware vectors live in the last six bytes of the
//! *mapped* PRG — `0xFFFA` NMI, `0xFFFC` RESET, `0xFFFE` IRQ — and each names
//! a function the reset or interrupt path reaches. Those are the seeds; the
//! rest of the function set comes from flow.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// iNES magic: `N`, `E`, `S`, `0x1a`.
const MAGIC: &[u8; 4] = b"NES\x1a";
const HEADER_LEN: usize = 0x10;
/// A trainer present (header byte 6 bit 2) shifts PRG by 512 bytes.
const TRAINER_LEN: usize = 0x200;
/// CPU base the PRG bank maps at.
const PRG_BASE: u64 = 0x8000;
/// One mapped bank is 16 KiB; the CPU window is 32 KiB (`0x8000..=0xFFFF`).
const BANK: u64 = 0x4000;

/// The console's own address map, declared not filled: a cartridge implies
/// the 2 KiB work RAM, the PPU/APU registers and the mapper registers without
/// containing them.
const REGIONS: [(&str, u64, u64, u64); 4] = [
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    ("ram", 0x0000, 0x800, 0x7),
    ("ppu", 0x2000, 0x8, 0x3),
    ("apu_io", 0x4000, 0x20, 0x3),
    ("mapper", 0x4020, 0x1fe0, 0x3),
];

/// True when `data` carries the iNES magic and a non-empty PRG bank.
pub(crate) fn is_rom(data: &[u8]) -> bool {
    prg(data).is_some()
}

/// The PRG ROM's file offset and length, when the header is well-formed.
fn prg(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < HEADER_LEN || data.get(..4) != Some(MAGIC.as_slice()) {
        return None;
    }
    let banks = usize::from(*data.get(4)?);
    if banks == 0 {
        return None;
    }
    let trainer = if data.get(6)? & 0x04 != 0 { TRAINER_LEN } else { 0 };
    let off = HEADER_LEN.checked_add(trainer)?;
    let len = banks.checked_mul(BANK as usize)?;
    // A truncated image still parses: the loader maps what the file carries.
    (off < data.len()).then_some((off, len.min(data.len() - off)))
}

/// Loads an iNES image: PRG at `0x8000`, mirrored to fill the 32 KiB CPU
/// window when it is a single 16 KiB bank, and the three hardware vectors
/// seeded as functions.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let Some((off, len)) = prg(data) else {
        return super::err("not an iNES cartridge");
    };
    let prg = &data[off..off + len];
    // The 6502 window is 32 KiB at 0x8000. The *last* 16 KiB bank is fixed at
    // 0xC000 (the vectors live there); the first bank maps at 0x8000. A single
    // bank is mirrored into both halves, so it appears at 0x8000 and 0xC000.
    let bank = BANK as usize;
    let last = &prg[len.saturating_sub(bank)..];
    let mut mappings = Vec::new();
    let mut names = Vec::new();
    if len > bank {
        // Two or more banks: first at 0x8000, last at 0xC000.
        mappings.push(Mapping {
            vaddr: PRG_BASE,
            size: bank as u64,
            file_off: off as u64,
            flags: 0x6,
            bytes: prg[..bank].to_vec(),
        });
        names.push("prg0".into());
        mappings.push(Mapping {
            vaddr: PRG_BASE + BANK,
            size: last.len() as u64,
            file_off: (off + len - last.len()) as u64,
            flags: 0x6,
            bytes: last.to_vec(),
        });
        names.push("prg_last".into());
    } else {
        // One bank: mirrored at 0x8000 and 0xC000.
        for (vaddr, name) in [(PRG_BASE, "prg_lo"), (PRG_BASE + BANK, "prg_hi")] {
            mappings.push(Mapping {
                vaddr,
                size: last.len() as u64,
                file_off: (off + len - last.len()) as u64,
                flags: 0x6,
                bytes: last.to_vec(),
            });
            names.push(name.into());
        }
    }
    let mut import = NativeImport {
        mappings,
        mapping_names: names,
        format: "ines".into(),
        language: "6502:LE:16:default".into(),
        ..Default::default()
    };
    // The hardware vectors sit in the last six bytes of the *last* PRG bank —
    // the bank the CPU maps at the top of the window (0xFFFA..0xFFFF). For a
    // single 16 KiB bank that is the bank's own tail; for a larger image it is
    // the image's tail. Either way they are `prg[len-6 .. len]`.
    if len >= 6 {
        let vectors = &prg[len - 6..len];
        for (i, name) in [(0usize, "nmi"), (2, "reset"), (4, "irq")] {
            let target = u64::from(vectors[i]) | (u64::from(vectors[i + 1]) << 8);
            if target == 0 || target == 0xffff {
                continue;
            }
            import.functions.push(NativeFunction {
                entry: target,
                name: name.into(),
                size: 1,
            });
            if name == "reset" {
                import.process_entry = Some(target);
            }
        }
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
