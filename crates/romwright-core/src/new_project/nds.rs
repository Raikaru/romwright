//! The Nintendo DS plugin: a retail cartridge ROM in, a ds-decomp (`dsd`)
//! decompilation repository out.
//!
//! dsd extracts the ROM with ds-rom (ARM9 with its BLZ compression, the overlay
//! table and the overlays, the ARM7 program, banner, file system, header), analyses the
//! ARM9 program and its overlays into `config.yaml`, `delinks.txt` (the module's
//! sections), `relocs.txt` and `symbols.txt`, delinks them into relocatable objects,
//! writes a linker script for Metrowerks' `mwldarm`, and rebuilds the ROM from the
//! linked result. What romwright adds is its own function inventory: every ARM9
//! function, overlay function and symbol (with names from the importer's passes, a
//! fact pack or the image) written in dsd's `symbols.txt` grammar to
//! `config/romwright/<module>.symbols.txt`, and merged into dsd's by
//! `tools/merge_symbols.py` at configure time: names win over dsd's defaults, and
//! functions dsd's analysis did not find are added. The rest of the repository
//! (ninja, `swap`, the header CRC fix) is generated here.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use serde_json::json;

use super::arm::Mode;
use super::compiler::Confidence;
use super::manifest::Manifest;
use super::mips::{clean_prototype, fill, protos_header, template, types_header};
use super::GeneratedFile;
use crate::export::{sha1_hex, splat_symbol_rows, ExportFacts, SplatSymbol};

/// One store program of the imported ROM (ARM9 with its autoloads, an overlay, the ARM7).
pub struct NdsProgram<'a> {
    pub program: &'a str,
    pub facts: &'a ExportFacts,
    pub prototypes: &'a [(u64, String)],
}

pub struct NdsInputs<'a> {
    pub image: &'a [u8],
    pub image_name: &'a str,
    pub project_name: &'a str,
    /// The ARM9 program's name in the store (`match` opens it).
    pub program: &'a str,
    pub programs: &'a [NdsProgram<'a>],
    pub manifest: &'a Manifest,
    pub compiler_id: Option<&'a str>,
    pub cflags: Option<Vec<String>>,
    pub profile: Option<&'a str>,
    pub romwright_version: &'a str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NdsCompilerDetection {
    pub family: &'static str,
    pub version: String,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub suggested_tool: &'static str,
    /// `mwccarm/<this>/mwccarm.exe` in the pinned archive.
    pub mw_version: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NdsReport {
    pub image_sha1: String,
    pub detection: NdsCompilerDetection,
    pub compiler_tool: String,
    pub modules: usize,
    pub arm9_functions: usize,
    pub overlay_functions: usize,
    pub arm7_functions: usize,
    pub symbols: usize,
    pub prototypes_emitted: usize,
    pub prototypes_skipped: usize,
}

/// Header CRC-16 (ARM `GetCRC16`: polynomial 0xA001, initial value 0xFFFF).
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xa001 } else { crc >> 1 };
        }
    }
    crc
}

/// A cartridge ROM: the header's logo checksum (0x15C, the constant 0xCF56 of the logo bytes) and its
/// header CRC (0x15E) both hold.
pub fn looks_like_nds_rom(image: &[u8]) -> bool {
    image.len() >= 0x4000
        && u16::from_le_bytes([image[0x15c], image[0x15d]]) == 0xcf56
        && crc16(&image[0xc0..0x15c]) == 0xcf56
        && crc16(&image[..0x15e]) == u16::from_le_bytes([image[0x15e], image[0x15f]])
}

/// NitroSDK stamps every program that links one of its libraries with `[SDK+NINTENDO:<lib>]`, and the
/// SDK is built with CodeWarrior; nearly every title's own code is too. The importer's rule
/// (`compiler::detect`) is the same. The pinned archive holds several mwccarm builds; `2.0/sp2p3` is the
/// default for the evidence class, not a proven build (pokeheartgold builds its game code with 2.0/sp2p2
/// and the SDK with 2.0/sp2p3).
pub fn detect_nds_compiler(rom: &[u8]) -> NdsCompilerDetection {
    let mut banners: Vec<String> = Vec::new();
    let needle = b"[SDK+NINTENDO:";
    let mut from = 0usize;
    while let Some(at) = rom[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from) {
        let text: String = rom[at..].iter().take(64).take_while(|b| **b != b']' && b.is_ascii_graphic()).map(|b| *b as char).collect();
        if !banners.contains(&text) && banners.len() < 6 {
            banners.push(text);
        }
        from = at + needle.len();
        if banners.len() >= 6 {
            break;
        }
    }
    let (family, confidence, evidence) = if banners.is_empty() {
        ("mwcc-arm", Confidence::Low, vec!["no NitroSDK banner in the ROM; mwccarm is the default for Nintendo DS decompilation".to_string()])
    } else {
        ("mwcc-arm", Confidence::Medium, vec![format!("NitroSDK banners `{}]`: the SDK libraries are CodeWarrior builds", banners.join("]`, `"))])
    };
    NdsCompilerDetection { family, version: String::new(), confidence, evidence, suggested_tool: "mwccarm", mw_version: "2.0/sp2p3" }
}

/// `main`, `ov005` or `arm7`: the module a store program belongs to. The importer names the programs of
/// a ROM `<name>.arm9`, `<name>.arm7` and `<name>.ov<N>`.
fn module_of(program: &str) -> String {
    let suffix = program.rsplit('.').next().unwrap_or(program);
    if suffix == "arm9" {
        return "main".into();
    }
    if let Some(number) = suffix.strip_prefix("ov").and_then(|n| n.parse::<u32>().ok()) {
        return format!("ov{number:03}");
    }
    suffix.to_ascii_lowercase().replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_")
}

fn function_mode(contexts: &HashMap<u64, u64>, entry: u64) -> Mode {
    match contexts.get(&entry) {
        Some(1) => Mode::Thumb,
        Some(_) => Mode::Arm,
        None => {
            if entry.is_multiple_of(4) {
                Mode::Arm
            } else {
                Mode::Thumb
            }
        }
    }
}

/// dsd's `symbols.txt` rows of one program: functions (`kind:function(arm|thumb,size=0x..)`), then the
/// named non-function symbols (`kind:data(any)`).
fn symbol_rows(facts: &ExportFacts) -> (String, usize, usize, Vec<SplatSymbol>) {
    let rows = splat_symbol_rows(facts);
    let contexts: HashMap<u64, u64> =
        facts.contexts.iter().filter(|(_, name, _)| name == "LowBitCodeMode" || name == "TMode").map(|(a, _, v)| (*a, *v)).collect();
    let sizes: HashMap<u64, u64> = facts.functions.iter().map(|f| (f.entry.offset, f.size)).collect();
    let mut text = String::new();
    let (mut functions, mut data) = (0usize, 0usize);
    for row in &rows {
        if row.is_function {
            let mode = match function_mode(&contexts, row.address) {
                Mode::Thumb => "thumb",
                Mode::Arm => "arm",
            };
            let size = sizes.get(&row.address).copied().unwrap_or(0);
            if size == 0 {
                continue;
            }
            let _ = writeln!(text, "{} kind:function({mode},size={size:#x}) addr:{:#010x}", row.name, row.address);
            functions += 1;
        } else {
            let _ = writeln!(text, "{} kind:data(any) addr:{:#010x}", row.name, row.address);
            data += 1;
        }
    }
    (text, functions, data, rows)
}

pub fn plan(inputs: &NdsInputs) -> Result<(Vec<GeneratedFile>, NdsReport), String> {
    let image = inputs.image;
    if !looks_like_nds_rom(image) {
        return Err("this is not a Nintendo DS ROM (the header logo checksum or header CRC does not hold)".into());
    }
    let sha1 = sha1_hex(image);
    let detection = detect_nds_compiler(image);
    let compiler_id = inputs.compiler_id.unwrap_or(detection.suggested_tool).to_string();
    let compiler = inputs.manifest.tool(&compiler_id).ok_or_else(|| {
        format!("compiler `{compiler_id}` is not in the tool manifest; known: {}", inputs.manifest.compiler_ids().join(", "))
    })?;
    if compiler.role != "compiler" {
        return Err(format!("`{compiler_id}` is a {}, not a compiler", compiler.role));
    }
    let subset = inputs.manifest.subset(&["dsd", "dsrom", "wibo", &compiler_id, "objdiff-cli"])?;

    let mut files: Vec<GeneratedFile> = Vec::new();
    let mut modules: BTreeMap<String, (String, usize, usize)> = BTreeMap::new();
    let (mut arm9_functions, mut overlay_functions, mut arm7_functions, mut symbols) = (0usize, 0usize, 0usize, 0usize);
    let mut protos: BTreeMap<(String, u64), (String, String)> = BTreeMap::new();
    let mut skipped_protos = 0usize;
    for program in inputs.programs {
        let module = module_of(program.program);
        let (text, functions, data, rows) = symbol_rows(program.facts);
        match module.as_str() {
            "main" => arm9_functions += functions,
            "arm7" => arm7_functions += functions,
            _ => overlay_functions += functions,
        }
        symbols += functions + data;
        modules.insert(module.clone(), (program.program.to_string(), functions, data));
        files.push(template(&format!("config/romwright/{module}.symbols.txt"), &text, false));
        let by_address: HashMap<u64, &SplatSymbol> = rows.iter().filter(|r| r.is_function).map(|r| (r.address, r)).collect();
        for (address, declaration) in program.prototypes {
            let Some(symbol) = by_address.get(address) else { continue };
            match clean_prototype(declaration, &symbol.name) {
                Some(proto) => {
                    protos.insert((module.clone(), *address), (symbol.name.clone(), proto));
                }
                None => skipped_protos += 1,
            }
        }
    }
    let proto_entries: Vec<(String, String)> = protos.into_values().collect();

    let cflags = inputs.cflags.clone().unwrap_or_else(|| {
        ["-O4,p", "-enum", "int", "-char", "signed", "-str", "noreuse", "-proc", "arm946e", "-gccext,on", "-fp", "soft", "-inline", "noauto", "-lang", "c99", "-Cpp_exceptions", "off", "-interworking", "-w", "off", "-msgstyle", "gcc"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    });
    let header_json = json!({
        "game_title": String::from_utf8_lossy(&image[..12]).trim_end_matches('\0').to_string(),
        "game_code": String::from_utf8_lossy(&image[12..16]).to_string(),
        "maker_code": String::from_utf8_lossy(&image[16..18]).to_string(),
        // The CRC the retail header records over the *encrypted* secure area; ds-rom cannot recompute it from a
        // decrypted dump, so it is kept as it is. tools/romfix.py writes it back and recomputes the header CRC.
        "secure_area_crc": format!("{:02x}{:02x}", image[0x6c], image[0x6d]),
        "header_crc": format!("{:02x}{:02x}", image[0x15e], image[0x15f]),
    });
    let project = json!({
        "romwright": {"version": inputs.romwright_version, "schema": 1, "platform": "nds"},
        "name": inputs.project_name,
        "image": {"file": inputs.image_name, "orig": format!("orig/{}", inputs.image_name), "sha1": sha1, "size": image.len(), "program": inputs.program},
        "compiler": {
            "kind": "mwcc-arm",
            "tool": compiler_id,
            "runtime": compiler.runtime,
            "mw_version": detection.mw_version,
            "cflags": cflags,
            "detected": {
                "family": detection.family,
                "version": detection.version,
                "confidence": detection.confidence,
                "evidence": detection.evidence,
            },
        },
        "tools": {
            "dsd": "dsd",
            "rom": "dsrom",
            "compiler": compiler_id,
            "runtime": "wibo",
            "report": "objdiff-cli",
        },
        "modules": modules.iter().map(|(m, (program, f, d))| json!({"module": m, "program": program, "functions": f, "symbols": d})).collect::<Vec<_>>(),
        "dsd": {"config": "config/dsd/arm9/config.yaml", "build": "build/dsd", "extract": "extract"},
    });
    let mut evidence = String::new();
    for line in &detection.evidence {
        let _ = writeln!(evidence, "- {line}");
    }
    let readme = fill(
        include_str!("templates/nds/README.md.tmpl"),
        &[
            ("NAME", inputs.project_name.to_string()),
            ("IMAGE", inputs.image_name.to_string()),
            ("SHA1", sha1.clone()),
            ("DETECTED", format!("{} ({:?} confidence), default compiler `{compiler_id}` build `{}`", detection.family, detection.confidence, detection.mw_version)),
            ("EVIDENCE", evidence),
            ("COMPILER", compiler_id.clone()),
            ("MODULES", modules.len().to_string()),
            ("ARM9_FUNCTIONS", arm9_functions.to_string()),
            ("OVERLAY_FUNCTIONS", overlay_functions.to_string()),
            ("ROMWRIGHT", inputs.romwright_version.to_string()),
        ],
    );
    files.extend([
        template("configure.py", include_str!("templates/nds/configure.py"), true),
        template("tools/download_tool.py", include_str!("templates/ps2/tools/download_tool.py"), true),
        template("tools/merge_symbols.py", include_str!("templates/nds/tools/merge_symbols.py"), true),
        template("tools/romfix.py", include_str!("templates/nds/tools/romfix.py"), true),
        template("tools/cc.py", include_str!("templates/nds/tools/cc.py"), true),
        template("tools/verify.py", include_str!("templates/nds/tools/verify.py"), true),
        template("requirements.txt", "ninja\n", false),
        template(".gitignore", include_str!("templates/nds/gitignore"), false),
        template("README.md", &readme, false),
        template("include/romwright_types.h", &types_header("Nintendo DS (ARM946E-S, ILP32)"), false),
        template("include/romwright_protos.h", &protos_header(&proto_entries, skipped_protos), false),
        template("config/header.json", &(serde_json::to_string_pretty(&header_json).map_err(|e| e.to_string())? + "\n"), false),
        template("config/checksum.sha1", &format!("{sha1}  build/{}\n", inputs.image_name), false),
        template("config/project.json", &(serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n"), false),
        template("config/toolchain.json", &(serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())? + "\n"), false),
        template("config/swaps.json", "[]\n", false),
        template("src/.gitkeep", "", false),
    ]);
    if let Some(profile) = inputs.profile {
        files.push(template("config/toolchain.local.json", profile, false));
    }
    let report = NdsReport {
        image_sha1: sha1,
        detection,
        compiler_tool: compiler_id,
        modules: modules.len(),
        arm9_functions,
        overlay_functions,
        arm7_functions,
        symbols,
        prototypes_emitted: proto_entries.len(),
        prototypes_skipped: skipped_protos,
    };
    Ok((files, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rom() -> Vec<u8> {
        let mut rom = vec![0u8; 0x4000];
        rom[..12].copy_from_slice(b"TESTGAME\0\0\0\0");
        rom[12..16].copy_from_slice(b"ATSE");
        // The Nintendo logo is any 156 bytes whose CRC-16 is 0xCF56; build a header whose checks hold by
        // searching the last two logo bytes.
        let mut logo = vec![0x24u8; 156];
        'search: for a in 0..=255u8 {
            for b in 0..=255u8 {
                logo[154] = a;
                logo[155] = b;
                if crc16(&logo) == 0xcf56 {
                    break 'search;
                }
            }
        }
        assert_eq!(crc16(&logo), 0xcf56);
        rom[0xc0..0x15c].copy_from_slice(&logo);
        rom[0x15c..0x15e].copy_from_slice(&0xcf56u16.to_le_bytes());
        let crc = crc16(&rom[..0x15e]);
        rom[0x15e..0x160].copy_from_slice(&crc.to_le_bytes());
        rom
    }

    #[test]
    fn header_checks_identify_a_cartridge_rom() {
        let mut image = rom();
        assert!(looks_like_nds_rom(&image));
        image[0x20] ^= 1;
        assert!(!looks_like_nds_rom(&image), "a header edit breaks the header CRC");
        assert!(!looks_like_nds_rom(&vec![0u8; 0x4000]));
    }

    #[test]
    fn programs_map_to_dsd_modules() {
        assert_eq!(module_of("twewy.arm9"), "main");
        assert_eq!(module_of("twewy.ov5"), "ov005");
        assert_eq!(module_of("twewy.arm7"), "arm7");
    }

    #[test]
    fn symbols_are_written_in_the_dsd_grammar_with_the_mode_the_context_says() {
        let function = |name: &str, address: u64, size: u64| romwright_model::FunctionRow {
            entry: romwright_model::Address::ram(address),
            name: name.into(),
            size,
            signature: None,
            traced: false,
            calling_convention: None,
        };
        let facts = ExportFacts {
            program: "t".into(),
            functions: vec![function("main", 0x0200_0ca4, 0x1c8), function("Entry", 0x0200_0800, 0x154)],
            contexts: vec![(0x0200_0ca4, "LowBitCodeMode".into(), 1), (0x0200_0800, "LowBitCodeMode".into(), 0)],
            ..Default::default()
        };
        let (text, functions, data, _) = symbol_rows(&facts);
        assert_eq!((functions, data), (2, 0));
        assert!(text.contains("main kind:function(thumb,size=0x1c8) addr:0x02000ca4"), "{text}");
        assert!(text.contains("Entry kind:function(arm,size=0x154) addr:0x02000800"), "{text}");
    }

    /// `tools/merge_symbols.py` on a tiny dsd tree: a name replaces a default, a missed function is added,
    /// a mode conflict and an address inside a dsd function are left to dsd, ambiguous relocations are dropped.
    #[test]
    fn merging_names_adds_missed_functions_and_drops_ambiguous_relocations() {
        if std::process::Command::new("python3").arg("--version").output().is_err() {
            return;
        }
        let root = std::env::temp_dir().join(format!("romwright-nds-merge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["tools", "config/dsd/arm9", "config/romwright"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("tools/merge_symbols.py"), include_str!("templates/nds/tools/merge_symbols.py")).unwrap();
        let dsd = root.join("config/dsd/arm9");
        std::fs::write(dsd.join("delinks.txt"), "    .text       start:0x02000800 end:0x02000900 kind:code align:32\n    .data       start:0x02000900 end:0x02000a00 kind:data align:32\n").unwrap();
        std::fs::write(
            dsd.join("symbols.txt"),
            "func_02000800 kind:function(arm,size=0x20) addr:0x02000800\nfunc_02000820 kind:function(thumb,size=0x10) addr:0x02000820\ndata_02000900 kind:data(any) addr:0x02000900\n",
        )
        .unwrap();
        std::fs::write(dsd.join("relocs.txt"), "from:0x02000804 kind:arm_call to:0x02000820 module:main\nfrom:0x02000808 kind:load to:0x021e5901 module:overlays(1,2)\n").unwrap();
        std::fs::write(
            root.join("config/romwright/main.symbols.txt"),
            "Entry kind:function(arm,size=0x20) addr:0x02000800\ninner kind:function(arm,size=0x8) addr:0x02000808\nwrong kind:function(arm,size=0x10) addr:0x02000820\nthumb_helper kind:function(thumb,size=0x10) addr:0x02000840\ngGlobal kind:data(any) addr:0x02000900\nFUN_02000860 kind:function(thumb,size=0x6) addr:0x02000860\n",
        )
        .unwrap();
        let merge = |flags: &[&str]| {
            let output = std::process::Command::new("python3").arg(root.join("tools/merge_symbols.py")).args(flags).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
        };
        // `--no-add`: names only; the functions dsd missed are counted, not added.
        let report = merge(&["--no-add"]);
        assert_eq!(report["renamed_functions"], 1);
        assert_eq!(report["renamed_data"], 1);
        assert_eq!((report["added_functions"].as_i64(), report["candidates_not_added"].as_i64()), (Some(0), Some(2)), "{report}");
        assert_eq!(report["skipped_mode_conflict"], 1);
        assert_eq!(report["skipped_inside_dsd_function"], 1);
        assert_eq!(report["dropped_ambiguous_relocations"], 1);
        let symbols = std::fs::read_to_string(dsd.join("symbols.txt")).unwrap();
        assert!(symbols.contains("Entry kind:function(arm,size=0x20) addr:0x02000800"), "{symbols}");
        assert!(symbols.contains("gGlobal kind:data(any) addr:0x02000900"), "{symbols}");
        assert!(!symbols.contains("thumb_helper") && !symbols.contains("inner") && !symbols.contains("wrong"));
        let relocs = std::fs::read_to_string(dsd.join("relocs.txt")).unwrap();
        assert!(relocs.contains("arm_call") && !relocs.contains("overlays("));
        // The default adds them, starting from the saved originals (`*.dsd`).
        let report = merge(&[]);
        assert_eq!(report["added_functions"], 2, "thumb_helper and the default-named FUN_02000860: {report}");
        let symbols = std::fs::read_to_string(dsd.join("symbols.txt")).unwrap();
        assert!(symbols.contains("thumb_helper kind:function(thumb,size=0x10) addr:0x02000840"), "{symbols}");
        assert_eq!(report, merge(&[]), "running again starts from the originals");
        let _ = std::fs::remove_dir_all(&root);
    }
}
