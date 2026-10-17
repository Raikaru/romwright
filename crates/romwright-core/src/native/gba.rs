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
//!
//! The ROM is not the whole program. Games copy code into IWRAM/EWRAM, send
//! multiboot clients over the link cable, or keep code packed until a scene
//! starts, and that code's pointers are only right at its run address.
//! `overlays` finds those images from evidence in the ROM; this module places
//! each one as executable memory at its run address: beside the ROM in the
//! `gba` program (a `modules` row each, so a reference from ROM code into it
//! is a `module_xrefs` row) when nothing else runs at those addresses, and as
//! its own program `ov<N>` (the DS overlay model) when several share a window.

use super::{DeclaredRegion, Mapping, NativeContext, NativeFunction, NativeImport, NativeModule, Result};

mod overlays;

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

/// Loads a cartridge image as one program: the ROM, the RAM images that
/// nothing else shares an address window with, the entry branch resolved as a
/// seed, and the console's memory map declared.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    import_set(data).map(|(main, _)| main)
}

/// Every program a cartridge carries, each with the suffix that names it:
/// the `gba` program (empty suffix) and one `ov<N>` per RAM image that shares
/// its run window with another.
pub(crate) fn import_container(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    let (main, overlay_programs) = import_set(data)?;
    let mut images = vec![(String::new(), main)];
    images.extend(overlay_programs);
    Ok(images)
}

/// Seeds for an image's decoded entries and the instruction set each is in.
fn seed(import: &mut NativeImport, entries: &[(u32, bool)]) {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    for (entry, arm) in sorted {
        let address = u64::from(entry);
        import.contexts.push(NativeContext { name: "LowBitCodeMode".into(), address, value: u64::from(!arm) });
        import.functions.push(NativeFunction { entry: address, name: format!("FUN_{entry:08x}"), size: 1 });
    }
}

fn module_of(image: &overlays::Image, name: &str) -> NativeModule {
    NativeModule {
        name: name.into(),
        kind: "overlay".into(),
        file_id: format!("rom:{:#x}-{:#x}", image.rom_start, image.rom_start + image.rom_len),
        load_vaddr: u64::from(image.run),
        size: image.bytes.len() as u64,
        file_off: image.rom_start as u64,
    }
}

fn ram_mapping(image: &overlays::Image) -> Mapping {
    Mapping {
        vaddr: u64::from(image.run),
        size: image.bytes.len() as u64,
        file_off: image.rom_start as u64,
        // Code in RAM: readable, writable, executable.
        flags: 0x7,
        bytes: image.bytes.clone(),
    }
}

/// The ROM's mappings: executable except where a RAM image's load image lies,
/// which no code runs from (readable, not executable).
fn rom_mappings(data: &[u8], images: &[overlays::Image]) -> (Vec<Mapping>, Vec<String>) {
    let mut spans: Vec<(usize, usize)> = images
        .iter()
        .filter(|image| image.demote)
        .flat_map(|image| {
            std::iter::once((image.rom_start, image.rom_len)).chain(image.copies.iter().copied())
        })
        .map(|(start, len)| (start, start + len))
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut mappings = Vec::new();
    let mut names = Vec::new();
    let mut position = 0usize;
    let mut executable = 0usize;
    let push = |mappings: &mut Vec<Mapping>, names: &mut Vec<String>, start: usize, end: usize, flags: u64, name: String| {
        if end > start {
            mappings.push(Mapping {
                vaddr: ROM_BASE + start as u64,
                size: (end - start) as u64,
                file_off: start as u64,
                flags,
                bytes: data[start..end].to_vec(),
            });
            names.push(name);
        }
    };
    for (load_images, (start, end)) in merged.into_iter().enumerate() {
        let name = if executable == 0 { "rom".to_string() } else { format!("rom.{executable}") };
        if start > position {
            push(&mut mappings, &mut names, position, start, 0x6, name);
            executable += 1;
        }
        push(&mut mappings, &mut names, start, end, 0x2, format!("rom.load-image.{load_images}"));
        position = end;
    }
    let name = if executable == 0 { "rom".to_string() } else { format!("rom.{executable}") };
    push(&mut mappings, &mut names, position, data.len(), 0x6, name);
    (mappings, names)
}

fn import_set(data: &[u8]) -> Result<(NativeImport, Vec<(String, NativeImport)>)> {
    let Some(entry) = entry_target(data) else {
        return super::err("not a Game Boy Advance cartridge");
    };
    let images = overlays::find(data);
    let (mappings, mapping_names) = rom_mappings(data, &images);
    let mut import = NativeImport {
        mappings,
        mapping_names,
        format: "gba".into(),
        language: "ARM:LE:32:v4t".into(),
        // The cartridge holds code and data in one window.
        code_holds_data: true,
        // The function the header's branch reaches: the image declares it.
        process_entry: Some(entry),
        ..Default::default()
    };
    // One program, one module per RAM image that owns its window.
    if !images.is_empty() {
        import.modules.push(NativeModule {
            name: "gba:rom".into(),
            kind: "code".into(),
            file_id: String::new(),
            load_vaddr: ROM_BASE,
            size: data.len() as u64,
            file_off: 0,
        });
    }
    let mut overlay_programs = Vec::new();
    let mut overlay_index = 0u32;
    for image in &images {
        let note = format!(
            "RAM image at {:#010x} ({}): {}; {} words in the ROM point at its entries",
            image.run,
            image.kind.label(),
            image.evidence,
            image.callers
        );
        if image.overlay {
            let name = format!("ov{overlay_index}");
            let mut program = NativeImport {
                mappings: vec![ram_mapping(image)],
                mapping_names: vec![name.clone()],
                modules: vec![module_of(image, &format!("gba:{name}"))],
                format: "gba".into(),
                language: "ARM:LE:32:v4t".into(),
                code_holds_data: true,
                overlay_id: Some(overlay_index),
                ..Default::default()
            };
            seed(&mut program, &image.entries);
            program.diagnose(romwright_model::DiagnosticSeverity::Info, "loader", note);
            overlay_programs.push((name, program));
            overlay_index += 1;
        } else {
            import.mappings.push(ram_mapping(image));
            import.mapping_names.push(format!("ram.{:08x}", image.run));
            import.modules.push(module_of(image, &format!("gba:ram.{:08x}", image.run)));
            seed(&mut import, &image.entries);
            import.diagnose(romwright_model::DiagnosticSeverity::Info, "loader", note);
        }
    }
    // A mode context holds from its address to the next one. The RAM images'
    // Thumb contexts sit below the ROM, so without this one they would read
    // the whole cartridge, entry code included, as Thumb.
    if import.contexts.iter().any(|context| context.address < ROM_BASE) {
        import.contexts.push(NativeContext { name: "LowBitCodeMode".into(), address: ROM_BASE, value: 0 });
    }
    // The static image is discovered last, seeded by the calls the overlays
    // make into it.
    import.sibling_call_host = !overlay_programs.is_empty();
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
    Ok((import, overlay_programs))
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
        // The image declares that function the entry, so the call-only retraction trusts the calls it makes.
        assert_eq!(import.process_entry, Some(0x0800_0158));
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

    use super::overlays::fixture::{code_blob, resource_rom};

    /// A cartridge header over a synthetic ROM: the loader's own check passes.
    fn with_header(mut rom: Vec<u8>) -> Vec<u8> {
        rom[..4].copy_from_slice(&0xEA00_0054u32.to_le_bytes());
        rom[FIXED_OFFSET] = FIXED_VALUE;
        rom
    }

    #[test]
    fn ram_code_is_mapped_at_its_run_address_beside_the_rom() {
        let mut rom = vec![0u8; 0x4000];
        let blob = code_blob(0x0200_1000, 80);
        rom[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        let import = import(&with_header(rom)).expect("cartridge");
        let ram = import
            .mappings
            .iter()
            .position(|mapping| mapping.vaddr == 0x0200_1000)
            .expect("the module at its run address");
        assert_eq!(import.mappings[ram].flags, 0x7);
        assert_eq!(import.mappings[ram].file_off, 0x1000);
        assert_eq!(import.mapping_names[ram], "ram.02001000");
        // A reference from the ROM into it is a cross-module reference.
        let names: Vec<(&str, u64)> = import.modules.iter().map(|module| (module.name.as_str(), module.load_vaddr)).collect();
        assert_eq!(names, vec![("gba:rom", 0x0800_0000), ("gba:ram.02001000", 0x0200_1000)]);
        assert_eq!(import.modules[1].file_id, format!("rom:{:#x}-{:#x}", 0x1000, 0x1000 + import.mappings[ram].bytes.len()));
        // Its entries are seeds, each in its own instruction set.
        assert!(import.functions.iter().any(|function| function.entry == 0x0200_1000));
        assert!(import
            .contexts
            .iter()
            .any(|context| context.name == "LowBitCodeMode" && context.address == 0x0200_1000 && context.value == 1));
        assert!(!import.sibling_call_host, "one image per window needs no sibling programs");
    }

    #[test]
    fn the_load_image_is_data_and_the_rest_of_the_rom_stays_code() {
        let mut rom = vec![0u8; 0x4000];
        let blob = code_blob(0x0200_1000, 80);
        rom[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        let import = import(&with_header(rom)).expect("cartridge");
        let code = crate::native::code_ranges(&import);
        assert!(code.contains(&(ROM_BASE, ROM_BASE + 0x1000)));
        assert!(
            code.iter().all(|&(lo, hi)| !(lo <= ROM_BASE + 0x1100 && ROM_BASE + 0x1100 < hi)),
            "no code range covers the module's load image"
        );
        let load = import
            .mappings
            .iter()
            .find(|mapping| mapping.vaddr == ROM_BASE + 0x1000)
            .expect("the load image keeps its bytes");
        assert_eq!(load.flags, 0x2, "readable, not executable");
        // Every byte of the cartridge is still mapped exactly once.
        let rom_bytes: u64 = import.mappings.iter().filter(|mapping| mapping.vaddr >> 24 == 8).map(|mapping| mapping.size).sum();
        assert_eq!(rom_bytes, 0x4000);
    }

    #[test]
    fn images_sharing_a_window_become_overlay_programs() {
        let programs = import_container(&with_header(resource_rom(5))).expect("cartridge");
        let names: Vec<&str> = programs.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["", "ov0", "ov1", "ov2", "ov3", "ov4"]);
        assert!(programs[0].1.sibling_call_host, "overlays call the static image");
        assert!(programs[0].1.mappings.iter().all(|mapping| mapping.vaddr >> 24 == 8), "the static image holds no overlay");
        for (index, (name, program)) in programs.iter().enumerate().skip(1) {
            assert_eq!(program.overlay_id, Some(index as u32 - 1));
            assert_eq!(program.mappings.len(), 1);
            assert_eq!(program.mappings[0].vaddr, 0x0200_8000);
            assert_eq!(program.mappings[0].flags, 0x7);
            assert_eq!(program.modules.len(), 1);
            assert_eq!(program.modules[0].name, format!("gba:{name}"));
            assert_eq!(program.modules[0].kind, "overlay");
            assert_eq!(program.modules[0].file_off, program.mappings[0].file_off);
        }
        // The loader says what it found, as information.
        assert!(programs[1]
            .1
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("resource-table") && diagnostic.severity == romwright_model::DiagnosticSeverity::Info));
    }

    #[test]
    fn a_cartridge_with_no_ram_code_is_one_program_as_before() {
        let programs = import_container(&cartridge(0xEA00_0054, 0x200)).expect("cartridge");
        assert_eq!(programs.len(), 1);
        let import = &programs[0].1;
        assert_eq!(import.mappings.len(), 1);
        assert_eq!(import.mapping_names, vec!["rom".to_string()]);
        assert!(import.modules.is_empty());
        assert!(!import.sibling_call_host);
    }
}
