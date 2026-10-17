//! The PlayStation 2 plugin: a retail boot ELF in, a splat + ninja
//! decompilation repository out.
//!
//! The layout contract is simple and checkable: the whole file is covered, in
//! file order, by splat segments. The ELF header and program headers are a
//! `databin` segment, each file-backed `PT_LOAD` is one `code` segment, and
//! whatever follows the last load (symbol table, section headers, debug) is a
//! `databin` trailer. Inside a load, every function romwright found is its own
//! `asm` subsegment (one `.s` file) and every byte range that is not a function
//! is a `textbin` (an `.incbin`). Linking those objects in order at the retail
//! addresses and flattening the result reproduces the retail file exactly, so
//! `sha1(build/<image>) == sha1(retail)` is the first test a project passes,
//! before any function has been decompiled.
//!
//! Per-function files are what make the C swap one yaml edit: a function
//! becomes a `c` subsegment and its source is compiled into the same slot.

use std::fmt::Write as _;

use serde_json::json;

use super::compiler::{detect_ps2_compiler, CompilerFamily, Ps2CompilerDetection};
use super::elf::{Elf32, Phdr};
use super::manifest::Manifest;
use super::mips::{count_units, fill, plan_layout, protos_header, symbol_files, template, types_header, write_segments, Layout, Load, Segment};
use super::GeneratedFile;
use crate::export::{sha1_hex, splat_symbol_rows, ExportFacts, SplatSymbol};

pub use super::mips::SPLAT_VERSION;

pub struct Ps2Inputs<'a> {
    pub image: &'a [u8],
    /// File name the retail image keeps (`SLUS_217.82`); also splat's basename.
    pub image_name: &'a str,
    pub project_name: &'a str,
    pub facts: &'a ExportFacts,
    /// `(function address, declaration)` pairs recovered by analysis or a fact pack.
    pub prototypes: &'a [(u64, String)],
    pub manifest: &'a Manifest,
    /// Manifest compiler id overriding the detector's suggestion.
    pub compiler_id: Option<&'a str>,
    pub cflags: Option<Vec<String>>,
    /// A user toolchain profile (JSON text) written as `config/toolchain.local.json`.
    pub profile: Option<&'a str>,
    pub romwright_version: &'a str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Ps2Report {
    pub image_sha1: String,
    pub detection: Ps2CompilerDetection,
    pub compiler_tool: String,
    pub segments: usize,
    pub asm_units: usize,
    pub bin_units: usize,
    pub symbols: usize,
    pub data_symbols: usize,
    pub functions_skipped: usize,
    pub prototypes_emitted: usize,
    pub prototypes_skipped: usize,
}

/// The planned layout of a PS2 ELF: the headers, one code segment per file-backed
/// `PT_LOAD`, and the tail.
pub(super) fn plan_ps2_layout(elf: &Elf32, rows: &[SplatSymbol], file_len: u64) -> Result<Layout, String> {
    let loads: Vec<Load> = elf
        .loads()
        .iter()
        .enumerate()
        .map(|(index, load)| Load {
            offset: load.offset as u64,
            vram: load.vaddr as u64,
            size: load.filesz as u64,
            name: if index == 0 { "main".to_string() } else { format!("main{}", index + 1) },
            rows: None,
        })
        .collect();
    let gap = |from: u64, _to: u64| {
        vec![Segment::databin(if from == 0 { "header".to_string() } else { format!("gap_{from:x}") }, from)]
    };
    plan_layout(elf.data, &loads, rows, file_len, &gap).map_err(|e| {
        e.replace("the image has no file-backed code range", "the ELF has no file-backed PT_LOAD segment").replace("code range", "PT_LOAD")
    })
}

fn render_yaml(inputs: &Ps2Inputs, elf: &Elf32, layout: &Layout, detection: &Ps2CompilerDetection, sha1: &str) -> String {
    let mut y = String::new();
    let image = inputs.image_name;
    let _ = writeln!(y, "sha1: {sha1}");
    let _ = writeln!(y, "options:");
    let _ = writeln!(y, "  basename: {image}");
    let _ = writeln!(y, "  target_path: orig/{image}");
    let _ = writeln!(y, "  base_path: ..");
    let _ = writeln!(y, "  platform: ps2");
    let _ = writeln!(y, "  compiler: {}", detection.splat_compiler);
    let _ = writeln!(y, "  asm_path: asm");
    let _ = writeln!(y, "  src_path: src");
    let _ = writeln!(y, "  build_path: build");
    let _ = writeln!(y, "  asset_path: assets");
    let _ = writeln!(y, "  symbol_addrs_path: config/symbol_addrs.txt");
    let _ = writeln!(y, "  ld_script_path: {image}.ld");
    let _ = writeln!(y, "  undefined_funcs_auto_path: undefined_funcs_auto.txt");
    let _ = writeln!(y, "  undefined_syms_auto_path: undefined_syms_auto.txt");
    let _ = writeln!(y, "  find_file_boundaries: False");
    let _ = writeln!(y, "  disasm_unknown: True");
    let _ = writeln!(y, "  subalign: 1");
    if let Some(gp) = elf.gp_value().filter(|gp| *gp != 0) {
        let _ = writeln!(y, "  gp_value: {gp:#x}");
    }
    write_segments(&mut y, layout, inputs.image.len());
    y
}

// ---------------------------------------------------------------------------
// README
// ---------------------------------------------------------------------------

const README: &str = include_str!("templates/ps2/README.md.tmpl");

fn render_readme(vars: &[(&str, String)]) -> String {
    fill(README, vars)
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

pub fn plan(inputs: &Ps2Inputs) -> Result<(Vec<GeneratedFile>, Ps2Report), String> {
    let elf = Elf32::parse(inputs.image)?;
    let machine = u16::from_le_bytes([inputs.image[18], inputs.image[19]]);
    if machine != 8 {
        return Err(format!("e_machine {machine} is not MIPS: this is not a PlayStation 2 executable"));
    }
    let sha1 = sha1_hex(inputs.image);
    let detection = detect_ps2_compiler(inputs.image);
    // Only addresses the image maps: DVP/VU overlay sections have address 0 and
    // bring their own function symbols, which no code segment can own.
    let memory: Vec<(u64, u64)> = elf
        .phdrs
        .iter()
        .filter(|p| p.p_type == super::elf::PT_LOAD && p.memsz != 0)
        .map(|p| (p.vaddr as u64, p.vaddr as u64 + p.memsz as u64))
        .collect();
    let mapped = |address: u64| memory.iter().any(|&(lo, hi)| address >= lo && address < hi);
    // Filtered before naming: an overlay symbol must not claim a name (and push
    // the real function to `name_<address>`).
    let image_facts = ExportFacts {
        program: inputs.facts.program.clone(),
        functions: inputs.facts.functions.iter().filter(|f| mapped(f.entry.offset)).cloned().collect(),
        symbols: inputs.facts.symbols.iter().filter(|s| mapped(s.address.offset)).cloned().collect(),
        ..Default::default()
    };
    let rows = splat_symbol_rows(&image_facts);
    let layout = plan_ps2_layout(&elf, &rows, inputs.image.len() as u64)?;

    // Tools: manifest compiler (the detector's default unless overridden).
    let compiler_id = inputs.compiler_id.unwrap_or(detection.suggested_tool).to_string();
    let compiler = inputs.manifest.tool(&compiler_id).ok_or_else(|| {
        format!("compiler `{compiler_id}` is not in the tool manifest; known: {}", inputs.manifest.compiler_ids().join(", "))
    })?;
    if compiler.role != "compiler" {
        return Err(format!("`{compiler_id}` is a {}, not a compiler", compiler.role));
    }
    let runtime_wibo = compiler.runtime.as_deref() == Some("wibo");
    let mut ids = vec!["binutils-mips-ps2-decompals"];
    if runtime_wibo {
        ids.push("wibo");
    }
    ids.push(&compiler_id);
    ids.push("objdiff-cli");
    let subset = inputs.manifest.subset(&ids)?;


    let symbols = symbol_files(&rows, &layout, inputs.prototypes);
    let (kept, symbol_addrs, undefined) = (&symbols.kept, &symbols.symbol_addrs, &symbols.undefined);
    let (data_symbols, proto_entries, skipped_protos) = (symbols.data_symbols, &symbols.protos, symbols.skipped_protos);

    let cflags = inputs.cflags.clone().unwrap_or_else(|| vec!["-O2".to_string()]);
    let layout_json: Vec<_> = elf
        .loads()
        .into_iter()
        .map(|p: &Phdr| json!({"offset": p.offset, "vaddr": p.vaddr, "size": p.filesz}))
        .collect();
    let project = json!({
        "romwright": {"version": inputs.romwright_version, "schema": 1, "platform": "ps2"},
        "name": inputs.project_name,
        "image": {"file": inputs.image_name, "orig": format!("orig/{}", inputs.image_name), "sha1": sha1, "size": inputs.image.len()},
        "splat": {"yaml": format!("config/{}.yaml", inputs.image_name), "version": SPLAT_VERSION},
        "compiler": {
            "kind": detection.profile_kind,
            "tool": compiler_id,
            "runtime": compiler.runtime,
            "cflags": cflags,
            "asflags": ["-EL", "-march=r5900", "-mabi=eabi"],
            "detected": {
                "family": detection.family.id(),
                "version": detection.version,
                "version_class": detection.version_class,
                "confidence": detection.confidence,
                "evidence": detection.evidence,
            },
        },
        "tools": {
            "binutils": "binutils-mips-ps2-decompals",
            "compiler": compiler_id,
            "runtime": if runtime_wibo { json!("wibo") } else { serde_json::Value::Null },
            "report": "objdiff-cli",
        },
        "layout": layout_json,
    });

    let (asm_units, bin_units) = count_units(&layout);


    let detected_line = format!(
        "{} ({:?} confidence) -> splat `{}`, default compiler `{}`",
        if detection.version.is_empty() { detection.family.id().to_string() } else { detection.version.clone() },
        detection.confidence,
        detection.splat_compiler,
        compiler_id
    );
    let mut evidence = String::new();
    for line in &detection.evidence {
        let _ = writeln!(evidence, "- {line}");
    }
    let readme = render_readme(&[
        ("NAME", inputs.project_name.to_string()),
        ("IMAGE", inputs.image_name.to_string()),
        ("SHA1", sha1.clone()),
        ("DETECTED", detected_line),
        ("EVIDENCE", evidence),
        ("COMPILER", compiler_id.clone()),
        ("KIND", detection.profile_kind.to_string()),
        ("ASM_UNITS", asm_units.to_string()),
        ("SPLAT", SPLAT_VERSION.to_string()),
        ("ROMWRIGHT", inputs.romwright_version.to_string()),
        ("FAMILY_NOTE", match detection.family {
            CompilerFamily::SnProdg => "SN ProDG is a gcc 2.95 derivative; the closest public compiler is an ee-gcc 2.95.x build, which is not byte-identical to ProDG output. Calibrate flags and expect some functions not to match.".to_string(),
            CompilerFamily::Unknown => "The compiler could not be identified; the default is a guess. Set `--compiler` and `--cflags` once you know.".to_string(),
            _ => "The version is the detector's default for that evidence class, not a proof of the exact build; if a function will not match at any flag set, try the neighbouring compiler versions in config/toolchain.json.".to_string(),
        }),
    ]);

    let mut files = vec![
        template("configure.py", include_str!("templates/ps2/configure.py"), true),
        template("tools/download_tool.py", include_str!("templates/ps2/tools/download_tool.py"), true),
        template("tools/asm.py", include_str!("templates/ps2/tools/asm.py"), true),
        template("tools/verify.py", include_str!("templates/ps2/tools/verify.py"), true),
        template("requirements.txt", include_str!("templates/ps2/requirements.txt"), false),
        template(".gitignore", include_str!("templates/ps2/gitignore"), false),
        template("README.md", &readme, false),
        template(&format!("config/{}.yaml", inputs.image_name), &render_yaml(inputs, &elf, &layout, &detection, &sha1), false),
        template("config/symbol_addrs.txt", symbol_addrs, false),
        template("config/undefined_syms.txt", undefined, false),
        template("config/checksum.sha1", &format!("{sha1}  build/{}\n", inputs.image_name), false),
        template("config/project.json", &(serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n"), false),
        template(
            "config/toolchain.json",
            &(serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())? + "\n"),
            false,
        ),
        template("include/romwright_types.h", &types_header("PlayStation 2 (EE, EABI64)"), false),
        template("include/romwright_protos.h", &protos_header(proto_entries, skipped_protos), false),
        template("src/.gitkeep", "", false),
    ];
    if let Some(profile) = inputs.profile {
        files.push(template("config/toolchain.local.json", profile, false));
    }
    let report = Ps2Report {
        image_sha1: sha1,
        detection,
        compiler_tool: compiler_id,
        segments: layout.segments.len(),
        asm_units,
        bin_units,
        symbols: kept.len(),
        data_symbols,
        functions_skipped: layout.skipped,
        prototypes_emitted: proto_entries.len(),
        prototypes_skipped: skipped_protos,
    };
    Ok((files, report))
}

#[cfg(test)]
mod tests {
    use super::super::mips::{clean_prototype, file_stem, lowercase_unique};
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn prototypes_keep_only_known_types_and_take_the_symbol_name() {
        assert_eq!(
            clean_prototype("int FUN_00100000(char *a, uint b)", "foo").as_deref(),
            Some("int foo(char *a, uint b);")
        );
        assert_eq!(clean_prototype("void bar(void)", "bar").as_deref(), Some("void bar(void);"));
        assert_eq!(clean_prototype("undefined4 baz(int, int)", "baz").as_deref(), Some("undefined4 baz(int, int);"));
        // Unknown struct and an unknown typedef are both refused.
        assert_eq!(clean_prototype("int f(struct Foo *x)", "f"), None);
        assert_eq!(clean_prototype("Vec3 f(int x)", "f"), None);
        assert_eq!(clean_prototype("int f(int x, ...)", "f").as_deref(), Some("int f(int x, ...);"));
    }

    #[test]
    fn file_stems_stay_short_and_unique_case_insensitively() {
        let long = "a".repeat(300);
        assert!(file_stem(&long, 0x100000).len() < 110);
        let mut taken = HashSet::new();
        assert_eq!(lowercase_unique(&mut taken, "main/0000/Foo".into(), 1), "main/0000/Foo");
        assert_eq!(lowercase_unique(&mut taken, "main/0000/foo".into(), 2), "main/0000/foo_00000002");
    }

    /// A one-load ELF: header 0x80, load 0x60 at vram 0x100000, trailer 0x10.
    fn synthetic_image() -> Vec<u8> {
        let mut image = vec![0u8; 0xf0];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 1;
        image[5] = 1;
        image[18..20].copy_from_slice(&8u16.to_le_bytes());
        image[0x18..0x1c].copy_from_slice(&0x100000u32.to_le_bytes());
        image[0x1c..0x20].copy_from_slice(&0x34u32.to_le_bytes());
        image[0x2a..0x2c].copy_from_slice(&32u16.to_le_bytes());
        image[0x2c..0x2e].copy_from_slice(&1u16.to_le_bytes());
        let ph = 0x34;
        for (at, value) in [(0, 1u32), (4, 0x80), (8, 0x100000), (12, 0x100000), (16, 0x60), (20, 0x100), (24, 5)] {
            image[ph + at..ph + at + 4].copy_from_slice(&value.to_le_bytes());
        }
        // f1 0x100000..10, pad, f2 0x100018..28, non-zero gap 0x100028..30, f3 0x100030..40, pad to 0x60.
        for range in [0x80..0x90, 0x98..0xa8, 0xa8..0xb0, 0xb0..0xc0] {
            for byte in &mut image[range] {
                *byte = 0x11;
            }
        }
        image
    }

    fn function(name: &str, address: u64, size: u64) -> romwright_model::FunctionRow {
        romwright_model::FunctionRow {
            entry: romwright_model::Address::ram(address),
            name: name.into(),
            size,
            signature: None,
            traced: false,
            calling_convention: None,
        }
    }

    fn symbol(name: &str, address: u64) -> romwright_model::SymbolRow {
        romwright_model::SymbolRow {
            name: name.into(),
            address: romwright_model::Address::ram(address),
            external: false,
            source: "IMPORTED".into(),
        }
    }

    #[test]
    fn plan_covers_the_file_with_function_pieces_and_keeps_padding_with_its_function() {
        let image = synthetic_image();
        let facts = ExportFacts {
            program: "t".into(),
            functions: vec![
                function("f1", 0x100000, 0x10),
                function("f2", 0x100018, 0x10),
                function("f3", 0x100030, 0x10),
                // An overlay function at address 8 is not part of the image.
                function("overlay", 8, 8),
            ],
            symbols: vec![
                symbol("inside_f2", 0x10001c),
                symbol("blob_start", 0x100028),
                symbol("blob_inner", 0x10002c),
                symbol("bss_var", 0x100070),
            ],
            ..Default::default()
        };
        let manifest = Manifest::builtin();
        let (files, report) = plan(&Ps2Inputs {
            image: &image,
            image_name: "SLUS_000.00",
            project_name: "t",
            facts: &facts,
            prototypes: &[(0x100000, "int f1(char *a)".into()), (0x100018, "Foo f2(void)".into())],
            manifest: &manifest,
            compiler_id: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let get = |path: &str| String::from_utf8(files.iter().find(|f| f.path == path).unwrap().bytes.clone()).unwrap();
        let yaml = get("config/SLUS_000.00.yaml");
        for line in [
            "  - name: header\n    type: databin\n    start: 0x0",
            "start: 0x80\n    vram: 0x100000",
            "- [0x80, asm, main/0000/f1]",
            "- [0x98, asm, main/0000/f2]",
            "- [0xa8, textbin, main/0001/data_00100028]",
            "- [0xb0, asm, main/0002/f3]",
            "  - name: trailer\n    type: databin\n    start: 0xe0",
            "  - [0xf0]",
        ] {
            assert!(yaml.contains(line), "{line}\n{yaml}");
        }
        assert_eq!((report.asm_units, report.segments, report.functions_skipped), (3, 3, 0));
        // Padding after f1 and f3 stayed with them: no data piece for it.
        assert!(!yaml.contains("data_00100010") && !yaml.contains("data_00100040"));
        let symbols = get("config/symbol_addrs.txt");
        assert!(symbols.contains("f2 = 0x100018; // type:func size:0x10"));
        assert!(!symbols.contains("overlay"));
        assert!(!symbols.contains("inside_f2"), "a name inside a function would cut it open");
        let undefined = get("config/undefined_syms.txt");
        assert!(undefined.contains("\"blob_inner\" = 0x10002c;") && undefined.contains("\"bss_var\" = 0x100070;"));
        assert!(!undefined.contains("blob_start"), "an object defines a name at a piece start");
        // Prototypes: the one made of known types is kept, the other counted.
        assert!(get("include/romwright_protos.h").contains("int f1(char *a);"));
        assert_eq!((report.prototypes_emitted, report.prototypes_skipped), (1, 1));
        assert_eq!(get("config/checksum.sha1"), format!("{}  build/SLUS_000.00\n", sha1_hex(&image)));
    }

    #[test]
    fn a_load_that_does_not_end_on_a_word_ends_with_a_databin_piece() {
        // GNU as rounds `.text` up to 4 bytes: a textbin holding the last
        // 0x5e - 0x5c bytes would grow the rebuilt file by 2.
        let mut image = synthetic_image();
        image[0x34 + 16..0x34 + 20].copy_from_slice(&0x5eu32.to_le_bytes());
        image[0xdc] = 0x22;
        let facts = ExportFacts {
            program: "t".into(),
            functions: vec![function("f1", 0x100000, 0x10), function("f3", 0x100030, 0x10)],
            ..Default::default()
        };
        let manifest = Manifest::builtin();
        let (files, _) = plan(&Ps2Inputs {
            image: &image,
            image_name: "SLUS_000.00",
            project_name: "t",
            facts: &facts,
            prototypes: &[],
            manifest: &manifest,
            compiler_id: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let yaml = String::from_utf8(files.iter().find(|f| f.path == "config/SLUS_000.00.yaml").unwrap().bytes.clone())
            .unwrap();
        assert!(yaml.contains("- [0xdc, databin, main/"), "{yaml}");
        assert!(!yaml.contains("data_00100040"), "the zero words before the tail stay with f3\n{yaml}");
        assert!(yaml.contains("  - name: trailer\n    type: databin\n    start: 0xde"), "{yaml}");
    }

    #[test]
    fn plan_refuses_non_mips_and_loadless_images() {
        let mut image = synthetic_image();
        let facts = ExportFacts::default();
        let manifest = Manifest::builtin();
        let inputs = |image: &[u8]| {
            plan(&Ps2Inputs {
                image,
                image_name: "x",
                project_name: "x",
                facts: &facts,
                prototypes: &[],
                manifest: &manifest,
                compiler_id: None,
                cflags: None,
                profile: None,
                romwright_version: "t",
            })
        };
        image[18] = 3;
        assert!(inputs(&image).unwrap_err().contains("not MIPS"));
        let mut loadless = synthetic_image();
        loadless[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());
        assert!(inputs(&loadless).unwrap_err().contains("PT_LOAD"));
    }
}
