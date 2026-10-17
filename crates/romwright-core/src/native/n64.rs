//! Nintendo 64 cartridge ROMs.
//!
//! The first 0x1000 bytes are the header and the boot code; the game code
//! follows, and the boot code copies it to the address the header names
//! (n64brew "ROM header": the PI configuration word at 0x00 and the boot
//! address at 0x08, both big-endian). This loader maps the game code at that
//! address and seeds it; the boot code itself is Nintendo's and is not
//! interpreted.
//!
//! Most retail games pack their code in the ROM and unpack it at boot, so
//! the linear view maps compressed bytes as code. A ROM whose header the
//! segment catalog (`n64_segments`, `n64_layouts.json`) knows is loaded as
//! its real segments instead: each unpacked and mapped at its RDRAM
//! address, one module per segment. A ROM the catalog does not know is
//! laid out from its own bytes where they prove it (`n64_discovery`), and
//! keeps the linear view where they do not. The entry point is the header's
//! word corrected for the CIC variant (see `n64_discovery::entry_address`).
//!
//! Only native byte order (`.z64`) is accepted. A byte-swapped dump (`.v64`,
//! `.n64`) would need its bytes reordered, and the JVM-free worker reads the
//! file directly, so it would decode the swapped bytes: refusing is honest
//! where silently mapping would be wrong. The refusal names the reason.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, NativeModule, Result};

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

/// Loads a cartridge ROM as the one program a single-image caller wants:
/// the first of [`import_programs`].
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    import_programs(data)?
        .into_iter()
        .next()
        .map(|(_, import)| import)
        .ok_or_else(|| super::ImportError::Bad("empty Nintendo 64 import".into()))
}

/// Loads a cartridge ROM. The layout the catalog knows for its header wins
/// (every segment unpacked and placed where the game runs it, one module
/// each). Otherwise the layout the ROM's own bytes prove (`n64_discovery`):
/// the boot segment, packed and raw code segments and overlays, each at the
/// address the evidence pins; overlays that run at one address as a program
/// of their own each, the way DS overlays do. A ROM nothing is proven for
/// keeps the linear view: the boot segment at the entry point, the whole
/// ROM in the cartridge domain, that entry point as the seed, and the
/// console's memory map declared.
pub(crate) fn import_programs(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    if let Some(layout) = super::n64_segments::detect(data) {
        return import_layout(data, Some(layout)).map(|import| vec![(String::new(), import)]);
    }
    if !is_swapped_dump(data) && boot_address(data).is_some()
        && let Some(found) = super::n64_discovery::discover(data) {
            return Ok(from_discovery(data, &found));
        }
    import_layout(data, None).map(|import| vec![(String::new(), import)])
}

/// `import` with the layout chosen by the caller: `None` is the linear view.
/// A layout that does not apply to this ROM leaves the linear view in place
/// and says so, so the caller sees the loss rather than a silent downgrade.
pub(crate) fn import_layout(data: &[u8], layout: Option<&super::n64_segments::Layout>) -> Result<NativeImport> {
    if is_swapped_dump(data) {
        return super::err(
            "byte-swapped Nintendo 64 dump (.v64/.n64): convert to native order (.z64) first, \
             because the decompiler reads the file's own bytes",
        );
    }
    let Some(header) = boot_address(data) else {
        return super::err("not a Nintendo 64 cartridge ROM");
    };
    // A layout names its own addresses; the linear view needs the entry
    // point the boot code really starts at.
    let boot = if layout.is_some() { header } else { super::n64_discovery::entry_address(data, header) };
    let window = rdram_window(boot, 1)
        .ok_or_else(|| super::ImportError::Bad("boot address is not RDRAM".into()))?;
    let mut failure = None;
    if let Some(layout) = layout {
        match super::n64_segments::load(layout, data, boot) {
            Ok(placed) => return Ok(from_layout(data, boot, window, layout, placed)),
            Err(message) => failure = Some(format!("segment layout not applied, linear boot view used: {message}")),
        }
    }
    let start = CODE_OFFSET as usize;
    let carried = data.len() as u64 - CODE_OFFSET;
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
            cartridge(data),
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
    if let Some(message) = failure {
        import.diagnose(romwright_model::DiagnosticSeverity::Partial, "load", message);
    }
    Ok(import)
}

/// A ROM whose layout was discovered: the program of the boot segment and
/// every segment that has an address of its own, then one program per
/// overlay that shares its address range with another segment. An overlay
/// program holds only its bytes (not the cartridge window, which would copy
/// the ROM once per overlay), and the main program is seeded from their
/// calls into it.
fn from_discovery(data: &[u8], found: &super::n64_discovery::Discovered) -> Vec<(String, NativeImport)> {
    let window = rdram_window(found.boot, 1).unwrap_or(RDRAM_WINDOWS[0]);
    let clashes = found.clashes();
    let segment = |found: &super::n64_discovery::Found| {
        let kind = if found.resident { "code" } else { "overlay" };
        let module = NativeModule {
            name: found.name.clone(),
            kind: kind.into(),
            file_id: format!("rom:{:#x}-{:#x}", found.rom.0, found.rom.1),
            load_vaddr: u64::from(found.vram),
            size: found.size as u64,
            file_off: found.rom.0 as u64,
        };
        let mapping = Mapping {
            vaddr: u64::from(found.vram),
            size: found.size as u64,
            file_off: found.rom.0 as u64,
            flags: 0x7,
            bytes: found.bytes.clone(),
        };
        (mapping, module)
    };
    let (boot_start, boot_end) = found.boot_rom;
    let mut mappings = vec![Mapping {
        vaddr: found.boot,
        size: (boot_end - boot_start) as u64,
        file_off: boot_start as u64,
        flags: 0x7,
        bytes: data[boot_start..boot_end].to_vec(),
    }];
    let mut names = vec!["boot".to_string()];
    let mut modules = vec![NativeModule {
        name: "boot".into(),
        kind: "code".into(),
        file_id: format!("rom:{boot_start:#x}-{boot_end:#x}"),
        load_vaddr: found.boot,
        size: (boot_end - boot_start) as u64,
        file_off: boot_start as u64,
    }];
    // Overlays that share an address range with another segment cannot sit
    // in one address space. They go in as few programs as can hold them:
    // each takes the first program whose overlays it does not overlap.
    let span = |found: &super::n64_discovery::Found| (u64::from(found.vram), u64::from(found.vram) + found.size as u64);
    let mut slots: Vec<Vec<usize>> = Vec::new();
    for (index, segment_found) in found.segments.iter().enumerate() {
        if clashes[index + 1] {
            let (lo, hi) = span(segment_found);
            let free = slots.iter().position(|members| {
                members.iter().all(|&member| {
                    let (other_lo, other_hi) = span(&found.segments[member]);
                    hi <= other_lo || other_hi <= lo
                })
            });
            match free {
                Some(slot) => slots[slot].push(index),
                None => slots.push(vec![index]),
            }
        } else {
            let (mapping, module) = segment(segment_found);
            names.push(segment_found.name.clone());
            mappings.push(mapping);
            modules.push(module);
        }
    }
    let mut overlays: Vec<(String, NativeImport)> = Vec::new();
    for members in &slots {
        let mut import = NativeImport {
            declared_regions: regions(window),
            format: "n64".into(),
            language: "MIPS:BE:64:64-32addr".into(),
            ..Default::default()
        };
        for &index in members {
            let segment_found = &found.segments[index];
            let (mapping, module) = segment(segment_found);
            import.mapping_names.push(segment_found.name.clone());
            import.mappings.push(mapping);
            import.modules.push(module);
            import.functions.push(NativeFunction {
                entry: u64::from(segment_found.vram),
                name: segment_found.name.clone(),
                size: 1,
            });
            import.diagnose(
                romwright_model::DiagnosticSeverity::Info,
                "load",
                format!("{}: {}", segment_found.name, segment_found.evidence),
            );
        }
        overlays.push((found.segments[members[0]].name.clone(), import));
    }
    mappings.push(cartridge(data));
    names.push("cartridge".into());
    modules.push(NativeModule {
        name: "cartridge".into(),
        kind: "rom".into(),
        file_id: format!("rom:0x0-{:#x}", data.len()),
        load_vaddr: CARTRIDGE_WINDOW,
        size: data.len() as u64,
        file_off: 0,
    });
    let mut main = NativeImport {
        mappings,
        mapping_names: names,
        modules,
        declared_regions: regions(window),
        format: "n64".into(),
        language: "MIPS:BE:64:64-32addr".into(),
        sibling_call_host: !overlays.is_empty(),
        ..Default::default()
    };
    main.functions.push(NativeFunction { entry: found.boot, name: "n64_boot".into(), size: 1 });
    main.diagnose(
        romwright_model::DiagnosticSeverity::Info,
        "load",
        format!(
            "layout discovered from the ROM's bytes: boot segment, {} further segments ({} overlays share addresses and are in {} programs), {} candidates refused",
            found.segments.len(),
            slots.iter().map(Vec::len).sum::<usize>(),
            overlays.len(),
            found.refused.len()
        ),
    );
    // A container with several images selects each by its suffix, so the
    // main program needs one too; a lone program keeps the bare name.
    let suffix = if overlays.is_empty() { String::new() } else { "main".to_string() };
    let mut programs = vec![(suffix, main)];
    programs.extend(overlays);
    programs
}

/// The whole ROM where the CPU sees the cartridge: read-only, and not
/// executed in place.
fn cartridge(data: &[u8]) -> Mapping {
    Mapping {
        vaddr: CARTRIDGE_WINDOW,
        size: data.len() as u64,
        file_off: 0,
        flags: 0x2,
        bytes: data.to_vec(),
    }
}

/// A ROM whose layout is known: each unpacked segment at its RDRAM address,
/// as a module of one program, then the cartridge window.
fn from_layout(
    data: &[u8],
    boot: u64,
    window: u64,
    layout: &super::n64_segments::Layout,
    placed: super::n64_segments::Placed,
) -> NativeImport {
    let mut mappings = placed.mappings;
    let mut names = placed.names;
    let mut modules = placed.modules;
    mappings.push(cartridge(data));
    names.push("cartridge".into());
    modules.push(NativeModule {
        name: "cartridge".into(),
        kind: "rom".into(),
        file_id: format!("rom:0x0-{:#x}", data.len()),
        load_vaddr: CARTRIDGE_WINDOW,
        size: data.len() as u64,
        file_off: 0,
    });
    let mut import = NativeImport {
        mappings,
        mapping_names: names,
        modules,
        declared_regions: regions(window),
        format: "n64".into(),
        language: "MIPS:BE:64:64-32addr".into(),
        ..Default::default()
    };
    import.functions.push(NativeFunction { entry: boot, name: "n64_boot".into(), size: 1 });
    import.diagnose(
        romwright_model::DiagnosticSeverity::Info,
        "load",
        format!("{}: {} segments unpacked from the ROM", layout.title, layout.segments.len()),
    );
    import
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_discovered_layout_is_a_program_per_clashing_overlay_beside_the_main_one() {
        use super::super::n64_discovery::tests::{synthetic_rom, BOOT, OVERLAY, RAW};
        let rom = synthetic_rom(BOOT);
        let programs = import_programs(&rom).expect("programs");
        let names: Vec<&str> = programs.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["main", "ovl_10000", "ovl_14000"]);
        let main = &programs[0].1;
        assert!(main.sibling_call_host, "the overlays call into the main program");
        let modules: Vec<(&str, u64)> = main.modules.iter().map(|m| (m.name.as_str(), m.load_vaddr)).collect();
        assert_eq!(modules, [("boot", u64::from(BOOT)), ("ovl_4000", u64::from(RAW)), ("cartridge", CARTRIDGE_WINDOW)]);
        // The boot mapping is the boot segment, not the ROM.
        assert_eq!(main.mappings[0].size, 0x3000);
        // An overlay program holds its own bytes at its address and no copy of the ROM.
        for (_, overlay) in &programs[1..] {
            assert_eq!(overlay.mappings.len(), 1);
            assert_eq!(overlay.mappings[0].vaddr, u64::from(OVERLAY));
            assert_eq!(overlay.modules[0].kind, "overlay");
            assert_eq!(overlay.functions[0].entry, u64::from(OVERLAY));
        }
        // `import` is the first program; nothing proven keeps the linear view.
        assert_eq!(import(&rom).unwrap().modules.len(), 3);
        let bare = {
            let mut data = rom.clone();
            data[0x4000..].fill(0);
            data
        };
        let linear = import_programs(&bare).expect("linear");
        assert_eq!(linear.len(), 1);
        assert!(linear[0].0.is_empty() && linear[0].1.mapping_names == ["code", "cartridge"]);
    }

    #[test]
    fn overlays_that_do_not_overlap_each_other_share_a_program() {
        use super::super::n64_discovery::tests::{blob, put, synthetic_rom, yaz0, BOOT};
        // Two pairs of overlays: each pair runs at one address, the pairs at
        // two different ones. Four overlays, two programs of two.
        let mut rom = synthetic_rom(BOOT);
        put(&mut rom, 0x4000, &[0; 0x400]); // drop the raw range
        put(&mut rom, 0x14000, &yaz0(&blob(0x8030_0000, 8, true)));
        put(&mut rom, 0x18000, &yaz0(&blob(0x8038_0000, 9, true)));
        put(&mut rom, 0x1c000, &yaz0(&blob(0x8038_0000, 10, true)));
        let programs = import_programs(&rom).expect("programs");
        let layout: Vec<(&str, Vec<&str>)> = programs
            .iter()
            .map(|(name, import)| (name.as_str(), import.modules.iter().map(|m| m.name.as_str()).collect()))
            .collect();
        assert_eq!(
            layout,
            [
                ("main", vec!["boot", "cartridge"]),
                ("ovl_10000", vec!["ovl_10000", "ovl_18000"]),
                ("ovl_14000", vec!["ovl_14000", "ovl_1c000"]),
            ]
        );
    }

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

    const SYNTHETIC: &str = r#"{
        "id": "synthetic", "title": "Synthetic",
        "detect": {"crc1": "0x0", "crc2": "0x0", "game_code": "NTST"},
        "segments": [
          {"name": "boot", "flags": "rx", "place": "boot", "parts": [{"rom": ["0x1000", "0x1010"], "codec": "raw"}]},
          {"name": "main", "flags": "rwx", "place": {"at": "0x80200000"}, "parts": [{"rom": ["0x1010", "0x1020"], "codec": "raw"}]}
        ]
    }"#;

    #[test]
    fn a_layout_maps_its_segments_as_modules_beside_the_cartridge() {
        let mut image = rom(NATIVE, 0x8000_1000, 0x2000);
        image[0x1000..0x1020].copy_from_slice(&[7; 0x20]);
        let layout = &super::super::n64_segments::Layout::from_json(SYNTHETIC).unwrap()[0];
        let import = import_layout(&image, Some(layout)).expect("layout import");
        assert_eq!(import.mapping_names, ["boot", "main", "cartridge"]);
        assert_eq!(import.mappings[0].vaddr, 0x8000_1000);
        assert_eq!(import.mappings[1].vaddr, 0x8020_0000);
        assert_eq!(import.mappings[2].vaddr, CARTRIDGE_WINDOW);
        let modules: Vec<_> = import.modules.iter().map(|m| (m.name.as_str(), m.kind.as_str())).collect();
        assert_eq!(modules, [("boot", "code"), ("main", "code"), ("cartridge", "rom")]);
        assert_eq!(import.functions[0].entry, 0x8000_1000);
    }

    #[test]
    fn a_layout_that_does_not_apply_leaves_the_linear_view_and_says_so() {
        let image = rom(NATIVE, 0x8000_1000, 0x1800);
        // `main` reads ROM past its end.
        let layout = &super::super::n64_segments::Layout::from_json(&SYNTHETIC.replace("0x1020", "0x9000")).unwrap()[0];
        let import = import_layout(&image, Some(layout)).expect("falls back");
        assert_eq!(import.mapping_names, ["code", "cartridge"]);
        assert!(import.modules.is_empty());
        let note = import.diagnostics.iter().find(|d| d.stage == "load").expect("diagnostic");
        assert!(note.message.contains("outside"), "{}", note.message);
    }

    /// The retail ROM, when the corpus holds it. SHA-256 of each segment as
    /// inflated independently with Python's zlib (raw DEFLATE after the Rare
    /// header), not by this crate.
    #[test]
    fn perfect_dark_ntsc_final_loads_its_real_segments() {
        use sha2::{Digest, Sha256};
        let Some(path) = std::env::var_os("HOME")
            .map(|home| std::path::PathBuf::from(home).join("ventris-corpus/perfect_dark_ntsc_final.z64"))
            .filter(|path| path.is_file())
        else {
            eprintln!("SKIP: perfect_dark_ntsc_final.z64 not in the corpus");
            return;
        };
        let data = std::fs::read(path).unwrap();
        assert!(is_rom(&data));
        let import = import(&data).expect("perfect dark");
        let segment = |name: &str| {
            let index = import.mapping_names.iter().position(|n| n == name).unwrap();
            &import.mappings[index]
        };
        let digest = |m: &Mapping| format!("{:x}", Sha256::digest(&m.bytes));
        for (name, vaddr, size, sha) in [
            ("lib", 0x7000_1050, 0x58f90, "bd930d8c530be04b320d10f3a72594f106f0c54f0a580a93c747e2f9adb8cf5b"),
            ("data", 0x8005_9fe0, 0x30e40, "c789f6fe1eeebff0ca4a89006333147e8d53452a83db3e4409fe6e64f4d615f3"),
            ("game", 0x7f00_0000, 0x1b99e0, "0ee3c0a8bb3c7f006ec1e81d5400ac93d6d9d27c4062c934e03d7caa70e8d7d0"),
        ] {
            let m = segment(name);
            assert_eq!((m.vaddr, m.size), (vaddr, size), "{name}");
            assert_eq!(digest(m), sha, "{name}");
        }
        // The preamble calls vm_boot by its physical (KSEG0) address, before
        // the TLB maps the lib at 0x70001050: the raw head runs there too.
        assert_eq!(segment("lib-boot").vaddr, 0x8000_1050);
        assert_eq!(&segment("lib-boot").bytes[..], &segment("lib").bytes[..0x2000]);
        assert_eq!(segment("inflate").vaddr, 0x7020_0000);
        assert_eq!(segment("preamble").vaddr, 0x8000_1000);
        assert_eq!(import.modules.len(), 7);
        assert!(import.diagnostics.iter().all(|d| d.severity != romwright_model::DiagnosticSeverity::Partial));
    }

    #[test]
    fn the_uncached_window_is_accepted() {
        let import = import(&rom(NATIVE, 0xA000_0400, 0x2000)).expect("rom");
        assert_eq!(import.declared_regions[0].vaddr, 0xA000_0000);
    }
}
