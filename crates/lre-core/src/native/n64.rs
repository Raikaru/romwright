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

/// The boot address of a native-order ROM, when `data` is one.
fn boot_address(data: &[u8]) -> Option<u64> {
    if (data.len() as u64) <= CODE_OFFSET {
        return None;
    }
    if word(data, 0)? != NATIVE {
        return None;
    }
    let boot = u64::from(word(data, BOOT_ADDRESS_OFFSET)?);
    let size = data.len() as u64 - CODE_OFFSET;
    rdram_window(boot, size).map(|_| boot)
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

/// Loads a cartridge ROM: the game code at the header's boot address, that
/// address as the seed, and the console's memory map declared.
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
    let size = data.len() as u64 - CODE_OFFSET;
    let window = rdram_window(boot, size)
        .ok_or_else(|| super::ImportError::Bad("boot address is not RDRAM".into()))?;
    let mut import = NativeImport {
        mappings: vec![Mapping {
            vaddr: boot,
            size,
            file_off: CODE_OFFSET,
            // Copied into RDRAM by the boot code, so writable too.
            flags: 0x7,
            bytes: data[start..].to_vec(),
        }],
        mapping_names: vec!["code".into()],
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
