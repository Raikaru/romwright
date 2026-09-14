//! Nintendo DS cartridge images.
//!
//! One container, two CPUs. gbatek "DS Cartridge Header" puts a descriptor
//! for each processor in the first 0x40 bytes: ROM offset, entry address,
//! RAM address and size at 0x20 for the ARM9 and 0x30 for the ARM7. The two
//! run different architectures (ARMv5TE and ARMv4T) from different memory,
//! so a cartridge yields two programs -- a program in the store has one
//! language, and collapsing the pair would decode one CPU's code with the
//! other's decoder.
//!
//! Detection is positive and arithmetic: every declared region must fit
//! inside the file, each entry must land inside its own loaded image, and
//! each RAM address must be where gbatek says that CPU's code runs. A file
//! that fails any of those is not a cartridge and the caller tries the next
//! format.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// gbatek "DS Cartridge Header": the header occupies 0x200 bytes, and the
/// two CPU descriptors sit inside its first 0x40.
const HEADER_LEN: u64 = 0x200;
const ARM9_DESCRIPTOR: usize = 0x20;
const ARM7_DESCRIPTOR: usize = 0x30;

/// gbatek "DS Memory Map": where each processor's code may be loaded.
/// ARM9 code runs from main RAM; ARM7 code runs from main RAM or its own
/// WRAM. Anything else is not a DS image.
const MAIN_RAM: (u64, u64) = (0x0200_0000, 0x0400_0000);
const ARM7_WRAM: (u64, u64) = (0x0380_0000, 0x0400_0000);
const ARM7_WRAM_BASE: u64 = 0x037F_8000;

/// One processor's image as the header describes it.
struct Descriptor {
    rom_offset: u64,
    entry: u64,
    ram: u64,
    size: u64,
}

fn descriptor(data: &[u8], at: usize) -> Option<Descriptor> {
    let word = |offset: usize| -> Option<u64> {
        let bytes = data.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64)
    };
    Some(Descriptor {
        rom_offset: word(at)?,
        entry: word(at + 4)?,
        ram: word(at + 8)?,
        size: word(at + 12)?,
    })
}

/// True when the descriptor's image fits the file and its entry lands in it.
fn plausible(descriptor: &Descriptor, len: u64, allowed: &[(u64, u64)]) -> bool {
    let Some(end) = descriptor.rom_offset.checked_add(descriptor.size) else {
        return false;
    };
    if descriptor.size == 0 || descriptor.rom_offset < HEADER_LEN || end > len {
        return false;
    }
    let Some(ram_end) = descriptor.ram.checked_add(descriptor.size) else {
        return false;
    };
    if !allowed
        .iter()
        .any(|&(start, limit)| descriptor.ram >= start && ram_end <= limit)
    {
        return false;
    }
    // The entry must be inside the image this descriptor loads: an entry
    // outside it is the strongest sign the fields are not a DS header.
    (descriptor.ram..ram_end).contains(&descriptor.entry)
}

/// True when `data` carries a DS cartridge header for both processors.
pub(crate) fn is_cartridge(data: &[u8]) -> bool {
    parse(data).is_some()
}

fn parse(data: &[u8]) -> Option<(Descriptor, Descriptor)> {
    let len = data.len() as u64;
    if len < HEADER_LEN {
        return None;
    }
    let arm9 = descriptor(data, ARM9_DESCRIPTOR)?;
    let arm7 = descriptor(data, ARM7_DESCRIPTOR)?;
    if !plausible(&arm9, len, &[MAIN_RAM]) {
        return None;
    }
    if !plausible(&arm7, len, &[MAIN_RAM, (ARM7_WRAM_BASE, ARM7_WRAM.1), ARM7_WRAM]) {
        return None;
    }
    // Two processors reading the same ROM bytes would not be a cartridge
    // layout; the images are distinct regions of the file.
    let arm9_end = arm9.rom_offset + arm9.size;
    let arm7_end = arm7.rom_offset + arm7.size;
    if arm9.rom_offset < arm7_end && arm7.rom_offset < arm9_end {
        return None;
    }
    Some((arm9, arm7))
}

/// gbatek "DS Memory Map": the windows each processor sees but the cartridge
/// does not contain. Declared for the store, never given invented bytes.
fn regions(cpu: &str) -> Vec<DeclaredRegion> {
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    let shared: [(&str, u64, u64, u64); 2] = [
        ("main-ram", MAIN_RAM.0, 4 * 1024 * 1024, 0x7),
        ("io", 0x0400_0000, 0x0010_0000, 0x3),
    ];
    let mut declared: Vec<DeclaredRegion> = shared
        .iter()
        .map(|&(name, vaddr, size, flags)| DeclaredRegion {
            name: name.into(),
            vaddr,
            size,
            flags,
        })
        .collect();
    match cpu {
        "arm9" => {
            declared.push(DeclaredRegion {
                name: "vram-a".into(),
                vaddr: 0x0680_0000,
                size: 128 * 1024,
                flags: 0x3,
            });
            declared.push(DeclaredRegion {
                name: "itcm".into(),
                vaddr: 0x0180_0000,
                size: 32 * 1024,
                flags: 0x7,
            });
        }
        _ => declared.push(DeclaredRegion {
            name: "arm7-wram".into(),
            vaddr: ARM7_WRAM_BASE,
            size: 64 * 1024,
            flags: 0x7,
        }),
    }
    declared
}

/// NitroSDK `crt0.c`: `_start_ModuleParams` is a table of nine words the
/// linker places in the uncompressed head of the ARM9 static module --
/// autoload list, autoload start, static bss start and end, then
/// `CompressedStaticEnd` at index 5, the SDK version, and two checker words
/// `SDK_NITROCODE_BE` (0xdec00621) and `SDK_NITROCODE_LE` (0x2106c0de) at
/// indices 7 and 8 (crt0.c:362-372). The pair is what identifies the table.
const NITROCODE_BE: u32 = 0xdec0_0621;
const NITROCODE_LE: u32 = 0x2106_c0de;
const COMPRESSED_STATIC_END: usize = 5;

/// Where the module's compressed data ends, in RAM, when the module is
/// compressed at all: `_start_ModuleParams[5]`, which crt0 hands to
/// `MIi_UncompressBackward` (crt0.c:277-279) and which is zero for an
/// uncompressed module.
fn compressed_static_end(module: &[u8]) -> Option<u64> {
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(module.get(at..at + 4)?.try_into().ok()?))
    };
    (0..module.len().saturating_sub(8))
        .step_by(4)
        .find(|&at| word(at) == Some(NITROCODE_BE) && word(at + 4) == Some(NITROCODE_LE))
        .and_then(|checker| {
            let base = checker.checked_sub(7 * 4)?;
            let end = word(base + COMPRESSED_STATIC_END * 4)?;
            (end != 0).then_some(u64::from(end))
        })
}

/// `MIi_UncompressBackward` (crt0.c:396-457), byte for byte. `bottom` is the
/// end of the packed archive; the footer just below it holds the offset back
/// to the top of the compressed data (24 bits), the offset back to the bottom
/// of the compressed data (8 bits) and the offset forward to the bottom of
/// the original data. Decompression runs downward from `bottom + original`,
/// copying literals or `(length nibble) + 3` bytes from `index + 2` ahead.
/// Returns the module with the decompressed tail, or `None` when the footer
/// does not describe the bytes it sits in.
fn uncompress_backward(module: &[u8], ram: u64, bottom: u64) -> Option<Vec<u8>> {
    let bottom = usize::try_from(bottom.checked_sub(ram)?).ok()?;
    if bottom < 8 || bottom > module.len() {
        return None;
    }
    let word = |at: usize| u32::from_le_bytes(module[at..at + 4].try_into().unwrap());
    let footer = word(bottom - 8);
    let original = word(bottom - 4) as usize;
    let mut inp = bottom.checked_sub((footer >> 24) as usize)?;
    let inp_top = bottom.checked_sub((footer & 0x00ff_ffff) as usize)?;
    if inp_top > inp || original == 0 || original > 0x0400_0000 {
        return None;
    }
    let mut out = module.to_vec();
    out.resize(bottom.checked_add(original)?, 0);
    let mut outp = out.len();
    while inp > inp_top {
        inp -= 1;
        let mut flag = out[inp];
        for _ in 0..8 {
            if inp <= inp_top {
                break;
            }
            if flag & 0x80 != 0 {
                if inp < 2 {
                    return None;
                }
                inp -= 1;
                let len = out[inp];
                inp -= 1;
                let index = ((usize::from(len & 0x0f) << 8) | usize::from(out[inp])) + 2;
                for _ in 0..(usize::from(len >> 4) + 3) {
                    let source = outp.checked_add(index)?;
                    if source >= out.len() || outp == 0 {
                        return None;
                    }
                    outp -= 1;
                    out[outp] = out[source];
                }
            } else {
                inp -= 1;
                if outp == 0 {
                    return None;
                }
                outp -= 1;
                out[outp] = out[inp];
            }
            flag <<= 1;
        }
    }
    // Everything the archive wrote lands above the compressed data's top;
    // the uncompressed head below it is untouched.
    (outp >= inp_top).then_some(out)
}

fn image(data: &[u8], cpu: &str, language: &str, descriptor: &Descriptor) -> NativeImport {
    let start = descriptor.rom_offset as usize;
    let end = start + descriptor.size as usize;
    let stored = &data[start..end];
    // The ARM9 static module is usually stored compressed and unpacked by
    // crt0 before anything else runs; the store must hold what runs.
    let bytes = compressed_static_end(stored)
        .and_then(|bottom| uncompress_backward(stored, descriptor.ram, bottom))
        .unwrap_or_else(|| stored.to_vec());
    let mut import = NativeImport {
        mappings: vec![Mapping {
            vaddr: descriptor.ram,
            size: bytes.len() as u64,
            file_off: descriptor.rom_offset,
            // Code loaded into RAM: readable, writable and executable, as
            // the console leaves it.
            flags: 0x7,
            bytes,
        }],
        mapping_names: vec![cpu.into()],
        declared_regions: regions(cpu),
        format: "nds".into(),
        language: language.into(),
        ..Default::default()
    };
    import.functions.push(NativeFunction {
        entry: descriptor.entry,
        name: format!("{cpu}_entry"),
        size: 1,
    });
    import
}

/// Loads both processors' images. The first is the ARM9, which the console
/// boots; each carries its own language, mapping and entry seed. ARM9
/// overlays (P1.6) join the ARM9 program as extra `ov<N>` mappings, so
/// `store_import` mints one `modules` row per overlay.
pub(crate) fn import(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    let Some((arm9, arm7)) = parse(data) else {
        return super::err("not a Nintendo DS cartridge");
    };
    let mut arm9_import = image(data, "arm9", "ARM:LE:32:v5t", &arm9);
    let overlays = super::nds_overlays::parse(data);
    super::nds_overlays::append_to_import(data, &overlays, &mut arm9_import);
    Ok(vec![
        ("arm9".into(), arm9_import),
        ("arm7".into(), image(data, "arm7", "ARM:LE:32:v4t", &arm7)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cartridge() -> Vec<u8> {
        let mut data = vec![0u8; 0x4400];
        // ARM9: 0x100 bytes at file 0x4000, RAM 0x02000000, entry +0x20.
        write(&mut data, ARM9_DESCRIPTOR, [0x4000, 0x0200_0020, 0x0200_0000, 0x100]);
        // ARM7: 0x100 bytes at file 0x4100, WRAM 0x037f8000, entry +0x10.
        write(&mut data, ARM7_DESCRIPTOR, [0x4100, 0x037F_8010, 0x037F_8000, 0x100]);
        data
    }

    fn write(data: &mut [u8], at: usize, fields: [u32; 4]) {
        for (index, value) in fields.iter().enumerate() {
            data[at + index * 4..at + index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    #[test]
    fn both_processors_become_their_own_program() {
        let images = import(&cartridge()).expect("cartridge");
        let described: Vec<(&str, &str, u64, u64)> = images
            .iter()
            .map(|(cpu, import)| {
                (
                    cpu.as_str(),
                    import.language.as_str(),
                    import.mappings[0].vaddr,
                    import.functions[0].entry,
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                ("arm9", "ARM:LE:32:v5t", 0x0200_0000, 0x0200_0020),
                ("arm7", "ARM:LE:32:v4t", 0x037F_8000, 0x037F_8010),
            ]
        );
    }

    #[test]
    fn each_program_maps_only_its_own_rom_bytes() {
        let mut data = cartridge();
        data[0x4000] = 0xA9;
        data[0x4100] = 0xA7;
        let images = import(&data).expect("cartridge");
        assert_eq!(images[0].1.mappings[0].bytes[0], 0xA9);
        assert_eq!(images[1].1.mappings[0].bytes[0], 0xA7);
        assert_eq!(images[0].1.mappings[0].file_off, 0x4000);
        assert_eq!(images[1].1.mappings[0].file_off, 0x4100);
    }

    #[test]
    fn a_size_past_the_end_of_the_file_is_refused() {
        let mut data = cartridge();
        write(&mut data, ARM9_DESCRIPTOR, [0x4000, 0x0200_0020, 0x0200_0000, 0x10_0000]);
        assert!(!is_cartridge(&data));
    }

    #[test]
    fn an_entry_outside_its_own_image_is_refused() {
        let mut data = cartridge();
        write(&mut data, ARM9_DESCRIPTOR, [0x4000, 0x0201_0000, 0x0200_0000, 0x100]);
        assert!(!is_cartridge(&data));
    }

    #[test]
    fn code_outside_the_documented_memory_map_is_refused() {
        let mut data = cartridge();
        // 0x08000000 is a GBA cartridge window, not DS code memory.
        write(&mut data, ARM9_DESCRIPTOR, [0x4000, 0x0800_0020, 0x0800_0000, 0x100]);
        assert!(!is_cartridge(&data));
    }

    #[test]
    fn overlapping_processor_images_are_refused() {
        let mut data = cartridge();
        write(&mut data, ARM7_DESCRIPTOR, [0x4080, 0x037F_8010, 0x037F_8000, 0x100]);
        assert!(!is_cartridge(&data));
    }

    #[test]
    fn a_header_inside_the_reserved_area_is_refused() {
        let mut data = cartridge();
        // An image starting inside the 0x200-byte header cannot be code.
        write(&mut data, ARM9_DESCRIPTOR, [0x40, 0x0200_0020, 0x0200_0000, 0x100]);
        assert!(!is_cartridge(&data));
    }
}
