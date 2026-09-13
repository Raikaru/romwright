//! Nintendo 64 cartridge ROMs.
//!
//! The first 0x1000 bytes are the header and the boot code; the game code
//! follows, and the boot code copies it to the address the header names
//! (n64brew "ROM header": the PI configuration word at 0x00 and the boot
//! address at 0x08, both big-endian). This loader maps the game code at that
//! address and seeds it; the boot code itself is Nintendo's and is not
//! interpreted.
//!
//! Only native byte order (`.z64`) is accepted. A byte-swapped dump (`.v64`,
//! `.n64`) would need its bytes reordered, and the JVM-free worker reads the
//! file directly, so it would decode the swapped bytes: refusing is honest
//! where silently mapping would be wrong. The refusal names the reason.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// n64brew "ROM header": the PI BSD domain 1 configuration word, identical
/// in every retail ROM, in each of the three dump byte orders.
const NATIVE: u32 = 0x8037_1240;
const BYTESWAPPED: u32 = 0x3780_4012;
const LITTLE_ENDIAN: u32 = 0x4012_3780;
/// Header plus boot code; the game code starts after it.
const CODE_OFFSET: u64 = 0x1000;
const BOOT_ADDRESS_OFFSET: usize = 0x08;

/// n64brew "Memory Map": RDRAM, 4 MB retail plus the 4 MB Expansion Pak,
/// seen cached at 0x80000000 and uncached at 0xa0000000.
const RDRAM_SIZE: u64 = 8 * 1024 * 1024;
const RDRAM_WINDOWS: [u64; 2] = [0x8000_0000, 0xA000_0000];

fn word(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

/// The window `address` sits in, when it is RDRAM at all.
fn rdram_window(address: u64, size: u64) -> Option<u64> {
    let end = address.checked_add(size)?;
    RDRAM_WINDOWS
        .iter()
        .copied()
        .find(|&base| address >= base && end <= base + RDRAM_SIZE)
}

/// The cartridge domain, where the whole ROM is visible to the CPU
/// (n64brew "Memory Map": PI domain 1, cached at 0x10000000 physical).
const CARTRIDGE_WINDOW: u64 = 0x1000_0000;

/// The boot address of a native-order ROM, when `data` is one.
///
/// A retail ROM is far larger than RDRAM -- Perfect Dark is 32 MB against a
/// console maximum of 8 -- because the boot code copies only its first
/// segment and the game pages in the rest. So the test is that the boot
/// address lands in RDRAM, not that the whole image fits there.
fn boot_address(data: &[u8]) -> Option<u64> {
    if (data.len() as u64) <= CODE_OFFSET {
        return None;
    }
    if word(data, 0)? != NATIVE {
        return None;
    }
    let boot = u64::from(word(data, BOOT_ADDRESS_OFFSET)?);
    rdram_window(boot, 1).map(|_| boot)
}

/// True when `data` is a native-order cartridge ROM.
pub(crate) fn is_rom(data: &[u8]) -> bool {
    boot_address(data).is_some()
}

/// True when `data` is a cartridge ROM in a byte order this loader refuses.
pub(crate) fn is_swapped_dump(data: &[u8]) -> bool {
    matches!(word(data, 0), Some(BYTESWAPPED) | Some(LITTLE_ENDIAN))
}

/// n64brew "Memory Map": windows the console has but the ROM does not carry.
fn regions(window: u64) -> Vec<DeclaredRegion> {
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    [
        ("rdram", window, RDRAM_SIZE, 0x7),
        ("sp-dmem", 0xA400_0000, 0x1000, 0x3),
        ("sp-imem", 0xA400_1000, 0x1000, 0x7),
        ("mmio", 0xA430_0000, 0x0020_0000, 0x3),
    ]
    .iter()
    .map(|&(name, vaddr, size, flags)| DeclaredRegion {
        name: name.into(),
        vaddr,
        size,
        flags,
    })
    .collect()
}

/// Loads a cartridge ROM: the boot segment at the header's boot address,
/// the whole ROM in the cartridge domain, that boot address as the seed, and
/// the console's memory map declared.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    if is_swapped_dump(data) {
        return super::err(
            "byte-swapped Nintendo 64 dump (.v64/.n64): convert to native order (.z64) first, \
             because the decompiler reads the file's own bytes",
        );
    }
    let Some(boot) = boot_address(data) else {
        return super::err("not a Nintendo 64 cartridge ROM");
    };
    let start = CODE_OFFSET as usize;
    let carried = data.len() as u64 - CODE_OFFSET;
    let window = rdram_window(boot, 1)
        .ok_or_else(|| super::ImportError::Bad("boot address is not RDRAM".into()))?;
    // The boot code copies as much as RDRAM holds; the rest of the ROM stays
    // in the cartridge domain until the game pages it in, so it is mapped
    // there rather than run off the end of memory.
    let resident = carried.min(window + RDRAM_SIZE - boot);
    let resident_end = start + resident as usize;
    let mut import = NativeImport {
        mappings: vec![
            Mapping {
                vaddr: boot,
                size: resident,
                file_off: CODE_OFFSET,
                // Copied into RDRAM by the boot code, so writable too.
                flags: 0x7,
                bytes: data[start..resident_end].to_vec(),
            },
            Mapping {
                vaddr: CARTRIDGE_WINDOW,
                size: data.len() as u64,
                file_off: 0,
                // The cartridge is read-only and is not executed in place.
                flags: 0x2,
                bytes: data.to_vec(),
            },
        ],
        mapping_names: vec!["code".into(), "cartridge".into()],
        declared_regions: regions(window),
        format: "n64".into(),
        // VR4300: 64-bit registers, 32-bit addresses.
        language: "MIPS:BE:64:64-32addr".into(),
        ..Default::default()
    };
    import.functions.push(NativeFunction {
        entry: boot,
        name: "n64_boot".into(),
        size: 1,
    });
    Ok(import)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rom(configuration: u32, boot: u32, len: usize) -> Vec<u8> {
        // Only the header fields are required; a caller asking for exactly
        // the header length gets a ROM with no game code.
        let mut data = vec![0u8; len.max(BOOT_ADDRESS_OFFSET + 4)];
        data[..4].copy_from_slice(&configuration.to_be_bytes());
        data[BOOT_ADDRESS_OFFSET..BOOT_ADDRESS_OFFSET + 4].copy_from_slice(&boot.to_be_bytes());
        data
    }

    #[test]
    fn the_header_boot_address_maps_the_game_code() {
        let image = rom(NATIVE, 0x8000_0400, 0x2000);
        let import = import(&image).expect("rom");
        assert_eq!(import.language, "MIPS:BE:64:64-32addr");
        assert_eq!(import.mappings[0].vaddr, 0x8000_0400);
        assert_eq!(import.mappings[0].file_off, CODE_OFFSET);
        assert_eq!(import.mappings[0].size, 0x1000);
        assert_eq!(import.functions[0].entry, 0x8000_0400);
    }

    #[test]
    fn a_rom_larger_than_rdram_loads_with_its_boot_segment_resident() {
        // Every retail cartridge is: Perfect Dark carries 32 MB against a
        // console maximum of 8, and requiring the image to fit in RDRAM made
        // the loader refuse it and the file fall through to another format's
        // parser.
        let length = (RDRAM_SIZE * 2) as usize;
        let image = rom(NATIVE, 0x8000_1000, length);
        assert!(is_rom(&image));
        let import = import(&image).expect("retail-sized rom");
        assert_eq!(import.mappings[0].vaddr, 0x8000_1000);
        assert_eq!(import.mappings[0].size, RDRAM_SIZE - 0x1000);
        assert_eq!(import.mappings[0].bytes.len() as u64, RDRAM_SIZE - 0x1000);
        // The rest of the cartridge is still readable where the CPU sees it.
        assert_eq!(import.mappings[1].vaddr, CARTRIDGE_WINDOW);
        assert_eq!(import.mappings[1].size, length as u64);
    }

    #[test]
    fn a_byte_swapped_dump_is_refused_with_its_reason() {
        let image = rom(BYTESWAPPED, 0x8000_0400, 0x2000);
        assert!(!is_rom(&image));
        assert!(is_swapped_dump(&image));
        let error = import(&image).expect_err("swapped dump");
        assert!(error.to_string().contains("native order"), "{error}");
    }

    #[test]
    fn a_little_endian_dump_is_refused() {
        assert!(is_swapped_dump(&rom(LITTLE_ENDIAN, 0x8000_0400, 0x2000)));
    }

    #[test]
    fn a_boot_address_outside_rdram_is_refused() {
        // The cartridge domain is not where the boot code copies game code.
        assert!(!is_rom(&rom(NATIVE, 0x1000_0000, 0x2000)));
    }

    #[test]
    fn a_rom_with_no_game_code_is_refused() {
        assert!(!is_rom(&rom(NATIVE, 0x8000_0400, CODE_OFFSET as usize)));
    }

    #[test]
    fn the_configuration_word_is_required() {
        assert!(!is_rom(&rom(0x1234_5678, 0x8000_0400, 0x2000)));
    }

    #[test]
    fn the_uncached_window_is_accepted() {
        let import = import(&rom(NATIVE, 0xA000_0400, 0x2000)).expect("rom");
        assert_eq!(import.declared_regions[0].vaddr, 0xA000_0000);
    }
}
