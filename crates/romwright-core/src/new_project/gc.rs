//! The GameCube and Wii plugin: a retail DOL (and RELs) in, a decomp-toolkit
//! (dtk-template style) repository out.
//!
//! romwright writes what its analysis knows, in dtk's grammar: `config.yml`,
//! `splits.txt` (the `Sections:` block, named and aligned from the DOL's own
//! linker tables, see [`dol_layout`](super::dol_layout)) and `symbols.txt` (function
//! and data rows from the store). The generated `configure.py` then runs
//! `dtk dol split`, links the objects dtk writes with Metrowerks' `mwldeppc`
//! (through wibo) and flattens the ELF with `dtk elf2dol`; `dtk shasum` checks
//! the result against `build.sha1`. A fresh project therefore rebuilds the
//! retail DOL byte for byte from assembly-only units, before any function has
//! been decompiled. A function is decompiled by giving it a translation unit
//! (`configure.py swap`), compiled with the project's MWCC and compared to the
//! retail object by objdiff.
//!
//! dtk-template (CC0-1.0) was studied for its repository shape; the code here is
//! written for romwright.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use serde_json::json;

use super::dol_layout::{dol_layout, DolLayout};
use super::gc_compiler::{detect_gc_compiler, Console, GcCompilerDetection};
use super::manifest::Manifest;
use super::GeneratedFile;
use crate::export::{dtk_symbols_placed, sha1_hex, ExportFacts};

pub use crate::native::disc::{DiscFiles, DiscRelFile};

/// The dtk release the generated project pins (`config/toolchain.json`).
pub const DTK_VERSION: &str = "v1.8.4";
/// The `mw_comment_version` dtk writes into every object's `.comment` section for the linker
/// `mw_version`: dtk's own table (`util/comment.rs`) pairs 8 with CodeWarrior GC 1.0, 10 with 1.3.2,
/// 11/13 with 2.7 and 14/15 with 3.0 alpha. The newer `mwldeppc.exe` builds (`GC/3.0a*`, `Wii/*`)
/// segfault under wibo on a `.comment` older than their own (every object, any link, on two
/// kernels), and a mismatched older one loses the linker's force-active flags.
pub fn comment_version(mw_version: &str) -> u8 {
    let version = mw_version.split('/').nth(1).unwrap_or("");
    if mw_version.starts_with("Wii/") {
        15
    } else if version.starts_with("3.") {
        14
    } else if version.starts_with("2.") {
        11
    } else if version.starts_with("1.3") {
        10
    } else {
        8
    }
}

/// Manifest id of the compilers bundle, and its `<GC|Wii>/<version>/` layout.
pub const COMPILERS_ID: &str = "mwcc-gc-wii-20251118";

/// One REL of the project: its `modules:` entry and the rows romwright holds for it.
#[derive(Debug, Clone)]
pub struct GcModule {
    /// Module name (the REL's file stem, unique in the project).
    pub name: String,
    /// Project-relative path of the REL under `orig/`.
    pub rel_path: String,
    /// The module id in the REL's header.
    pub module_id: u32,
    /// Whether the build links this REL (a `modules:` entry). One that cannot be linked (no code:
    /// only `.ctors`/`.dtors` words, which mwld refuses) or that shares the id of a module other
    /// modules relocate against (dtk cannot tell which alternative they mean) is copied from the
    /// retail file instead.
    pub linked: bool,
    pub sha1: String,
    /// `symbols.txt` rows (section-relative); empty lets dtk's analysis name everything.
    pub symbols_txt: String,
    /// The module's `Sections:` block, when romwright knows it.
    pub splits_txt: Option<String>,
}

pub struct GcInputs<'a> {
    pub dol: &'a [u8],
    /// Directory name of this version under `config/`, `orig/`, `build/` (game id).
    pub version: &'a str,
    pub project_name: &'a str,
    pub title: &'a str,
    /// The DOL's program in the store.
    pub facts: &'a ExportFacts,
    pub prototypes: &'a [(u64, String)],
    pub modules: &'a [GcModule],
    pub manifest: &'a Manifest,
    /// Compiler directory (`GC/2.6`) overriding the detector's.
    pub mw_version: Option<&'a str>,
    pub cflags: Option<Vec<String>>,
    pub profile: Option<&'a str>,
    pub romwright_version: &'a str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GcReport {
    pub dol_sha1: String,
    pub detection: GcCompilerDetection,
    pub mw_version: String,
    pub sections: usize,
    pub sections_from_tables: bool,
    pub symbols: usize,
    pub functions: usize,
    pub functions_skipped: usize,
    pub modules: usize,
    pub prototypes_emitted: usize,
    pub prototypes_skipped: usize,
}

/// `gc` for anything that looks like a GameCube or Wii disc image or a DOL,
/// else `None`. The console is decided later, from the disc itself.
pub fn detect_platform(bytes: &[u8]) -> Option<&'static str> {
    let be = |at: usize| bytes.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let magic = bytes.get(..4);
    if matches!(magic, Some(b"RVZ\x01") | Some(b"WIA\x01") | Some(b"WBFS")) {
        return Some("gc");
    }
    if be(0x1c) == Some(0xc233_9f3d) || be(0x18) == Some(0x5d1c_9ea3) {
        return Some("gc");
    }
    if magic == Some(b"CISO") && bytes.len() > 0x8000 + 0x20 {
        return Some("gc");
    }
    // A DOL has no magic: text sections inside 0x80000000.., 4-aligned, a header the file covers.
    let layout = dol_layout(bytes)?;
    let in_ram = layout.sections.iter().all(|s| s.start >= 0x8000_0000);
    let covered = (0..18).all(|i| {
        let (off, size) = (be(i * 4).unwrap_or(0), be(0x90 + i * 4).unwrap_or(0));
        size == 0 || (off >= 0xe4 && u64::from(off) + u64::from(size) <= bytes.len() as u64)
    });
    (in_ram && covered && layout.entry >= 0x8000_0000 && layout.entry % 4 == 0 && layout.section_of(u64::from(layout.entry)).is_some())
        .then_some("gc")
}

/// The boot DOL and RELs of a disc image in any container, as files.
pub fn extract_disc(bytes: &[u8]) -> Option<Result<DiscFiles, String>> {
    crate::native::wii::extract_disc(bytes).map(|r| r.map_err(|e| e.to_string()))
}

/// The compiler verdict for a DOL or a disc image (its boot DOL), `None` when `bytes` is neither.
pub fn detect_image_compiler(bytes: &[u8]) -> Option<Result<GcCompilerDetection, String>> {
    detect_platform(bytes)?;
    let from_dol = |dol: &[u8]| {
        dol_layout(dol)
            .map(|layout| detect_gc_compiler(dol, layout.entry))
            .ok_or_else(|| "the boot executable is not a DOL".to_string())
    };
    Some(match extract_disc(bytes) {
        Some(Ok(files)) => from_dol(&files.dol),
        Some(Err(error)) => Err(error),
        None => from_dol(bytes),
    })
}

// ---------------------------------------------------------------------------
// Types and prototypes header
// ---------------------------------------------------------------------------

const TYPES_H: &str = "\
/* Generated by romwright new-project: base types for GameCube/Wii (Gekko/Broadway, EABI) code. */
#ifndef ROMWRIGHT_TYPES_H
#define ROMWRIGHT_TYPES_H

typedef signed char s8;
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef int s32;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long long u64;
typedef float f32;
typedef double f64;

/* The primitive names decompiler output uses. */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char byte;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef long long longlong;
typedef unsigned long long ulonglong;

#endif
";

const README: &str = include_str!("templates/gc/README.md.tmpl");

fn render(template: &str, vars: &[(&str, String)]) -> String {
    let mut text = template.to_string();
    for (key, value) in vars {
        text = text.replace(&format!("{{{{{key}}}}}"), value);
    }
    text
}

fn file(path: &str, text: &str, executable: bool) -> GeneratedFile {
    GeneratedFile { path: path.to_string(), bytes: text.as_bytes().to_vec(), executable }
}

/// Default MWCC flags (the dtk-template base set). Newer compilers take
/// `-enc SJIS`; the older ones `-multibyte`.
pub fn default_cflags(mw_version: &str) -> Vec<String> {
    let sjis = mw_version.starts_with("Wii/") || mw_version.starts_with("GC/3");
    let mut flags: Vec<String> = [
        "-nodefaults", "-proc gekko", "-align powerpc", "-enum int", "-fp hardware", "-Cpp_exceptions off", "-O4,p",
        "-inline auto", "-nosyspath", "-RTTI off", "-str reuse",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    flags.push(if sjis { "-enc SJIS".into() } else { "-multibyte".into() });
    flags.push("-i include".into());
    flags
}

/// The word at `address`, read from the DOL's file-backed sections.
fn word_at(dol: &[u8], address: u32) -> Option<u32> {
    let be = |at: usize| dol.get(at..at.checked_add(4)?).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    (0..18usize).find_map(|slot| {
        let (offset, start, size) = (be(slot * 4)?, be(0x48 + slot * 4)?, be(0x90 + slot * 4)?);
        let inside = size != 0 && address >= start && address.checked_add(4)? <= start.checked_add(size)?;
        inside.then(|| be(offset as usize + (address - start) as usize)).flatten()
    })
}

/// What `configure.py` needs to arrange Metrowerks' startup registrations, found from the DOL
/// alone. The linker script puts `__init_cpp_exceptions` first in `.ctors` and
/// `__destroy_global_chain`, `__fini_cpp_exceptions` first in `.dtors` (the `*_reference`
/// objects); each entry's target is a function in `.text`. dtk's own handling of them depends
/// on how the function boundaries romwright found agree with its signatures, and differs
/// between games, so `configure.py` tries the arrangements in turn and keeps the one that
/// rebuilds the retail DOL: nothing, a `.ctors$10` unit for the first `.ctors` entry, or the
/// three functions named after the linker script's symbols (the names dtk's analysis of a
/// REL uses for its calls into the DOL) with a unit for the three entries.
fn runtime_json(dol: &[u8], layout: &DolLayout) -> serde_json::Value {
    let in_text = |address: u32| address.is_multiple_of(4) && layout.section_of(u64::from(address)).is_some_and(|s| s.kind == "code");
    let first = |name: &str, index: u32| -> Option<(u32, u32)> {
        let section = layout.sections.iter().find(|s| s.name == name)?;
        let at = section.start.checked_add(4 * index)?;
        (section.size >= 4 * (index + 1)).then_some(())?;
        word_at(dol, at).filter(|w| in_text(*w)).map(|target| (at, target))
    };
    let ctors = first(".ctors", 0);
    let dtors = (first(".dtors", 0), first(".dtors", 1));
    json!({
        "ctors_start": ctors.map(|(at, _)| at),
        "ctors_target": ctors.map(|(_, target)| target),
        "dtors_start": dtors.0.map(|(at, _)| at),
        "destroy_target": dtors.0.map(|(_, target)| target),
        "fini_target": dtors.1.map(|(_, target)| target),
    })
}

pub fn plan(inputs: &GcInputs) -> Result<(Vec<GeneratedFile>, GcReport), String> {
    let (linked, copied): (Vec<&GcModule>, Vec<&GcModule>) = inputs.modules.iter().partition(|m| m.linked);
    let layout: DolLayout = dol_layout(inputs.dol).ok_or("this is not a DOL (header shorter than 0xe4 bytes)")?;
    let sha1 = sha1_hex(inputs.dol);
    let detection = detect_gc_compiler(inputs.dol, layout.entry);
    let wii = detection.console == Console::Wii;
    let mw_version = inputs.mw_version.unwrap_or(detection.mw_version).to_string();
    if !(mw_version.starts_with("GC/") || mw_version.starts_with("Wii/")) || mw_version.contains("..") {
        return Err(format!("compiler `{mw_version}` is not a directory of the compilers bundle (GC/<version> or Wii/<version>)"));
    }
    let version = inputs.version;

    // Tools.
    let mut ids = vec!["dtk", "wibo", COMPILERS_ID, "sjiswrap", "objdiff-cli"];
    ids.dedup();
    let subset = inputs.manifest.subset(&ids)?;

    // Symbols: functions and named data from the store, sections from the DOL's own layout.
    let place = |address: u64| layout.section_of(address).map(|s| (s.name.clone(), address));
    let symbols = dtk_symbols_placed(inputs.facts, &place, false);
    // A linker takes one definition per global name: a repeated name gets its address. Strings are
    // left out: dtk's own string detection finds them (as `lbl_` rows), and a literal romwright
    // names at an address dtk sized differently ("Unaligned symbol entry") only costs a split.
    let mut taken = std::collections::HashSet::new();
    let rows: Vec<String> = symbols
        .rows
        .iter()
        .filter(|row| !row.contains("data:string"))
        .map(|row| {
            let (name, rest) = row.split_once(" = ").unwrap_or((row.as_str(), ""));
            if taken.insert(name.to_string()) {
                return row.clone();
            }
            let address = rest.split(":0x").nth(1).and_then(|a| a.split(';').next()).unwrap_or("0");
            let renamed = format!("{name}_{}", address.trim_start_matches("0x"));
            taken.insert(renamed.clone());
            format!("{renamed} = {rest}")
        })
        .collect();
    let mut symbols_txt = String::new();
    // The loader names the DOL's entry `_entry`; Metrowerks' startup code is `__start`, which is also
    // the entry symbol mwld looks for when no `-m` is given.
    let entry_row = format!("_entry = {}:{:#x};", layout.section_of(u64::from(layout.entry)).map_or("", |s| s.name.as_str()), layout.entry);
    for row in &rows {
        match row.strip_prefix(&entry_row) {
            Some(rest) if !rows.iter().any(|r| r.starts_with("__start = ")) => {
                symbols_txt.push_str(&format!("__start = {}:{:#x};{rest}", layout.section_of(u64::from(layout.entry)).map_or("", |s| s.name.as_str()), layout.entry));
            }
            _ => symbols_txt.push_str(row),
        }
        symbols_txt.push('\n');
    }

    // Prototypes of the functions that made it into symbols.txt.
    let by_address: HashMap<u64, String> = inputs
        .facts
        .functions
        .iter()
        .filter(|f| !symbols.rejected.contains(&f.entry.offset))
        .map(|f| (f.entry.offset, f.name.clone()))
        .collect();
    let mut protos: BTreeMap<u64, (String, String)> = BTreeMap::new();
    let mut skipped_protos = 0usize;
    for (address, declaration) in inputs.prototypes {
        let Some(name) = by_address.get(address) else { continue };
        match super::mips::clean_prototype(declaration, name) {
            Some(text) => {
                protos.insert(*address, (name.clone(), text));
            }
            None => skipped_protos += 1,
        }
    }
    let mut protos_h = String::from(
        "/* Generated by romwright new-project: prototypes recovered by analysis (and the fact pack, when one was present).\n   Only declarations made of the base types of romwright_types.h are kept. */\n",
    );
    let _ = writeln!(protos_h, "/* {skipped_protos} declaration(s) were left out because they name types that header does not define. */");
    protos_h.push_str("#ifndef ROMWRIGHT_PROTOS_H\n#define ROMWRIGHT_PROTOS_H\n\n#include \"romwright_types.h\"\n\n");
    for (name, proto) in protos.values() {
        let _ = writeln!(protos_h, "/* {name} */ {proto}");
    }
    protos_h.push_str("\n#endif\n");

    let splits_txt = layout.sections_block();

    // config.yml
    let dol_path = format!("orig/{version}/sys/main.dol");
    let mut config = String::new();
    let _ = writeln!(config, "object: {dol_path}");
    let _ = writeln!(config, "hash: {sha1}");
    let _ = writeln!(config, "symbols: config/{version}/symbols.txt");
    let _ = writeln!(config, "splits: config/{version}/splits.txt");
    let _ = writeln!(config, "mw_comment_version: {}", comment_version(&mw_version));
    if !linked.is_empty() {
        let _ = writeln!(config, "modules:");
        // Modules that share an id are overlays (alternatives paged into one place, Mario Party 4's
        // DLLs, Skyward Sword's `d_s_bootNP` copies): dtk cannot link all of them to one another
        // ("Duplicate module ID"), so every module links to the modules with an id of its own
        // (and, through the DOL, to nothing else).
        let shared = |id: u32| linked.iter().filter(|m| m.module_id == id).count() > 1;
        let any_shared = linked.iter().any(|m| shared(m.module_id));
        for module in &linked {
            let _ = writeln!(config, "- object: {}", module.rel_path);
            let _ = writeln!(config, "  hash: {}", module.sha1);
            if any_shared {
                let links: Vec<&str> =
                    linked.iter().filter(|m| !shared(m.module_id) && m.name != module.name).map(|m| m.name.as_str()).collect();
                let _ = writeln!(config, "  links: [{}]", links.join(", "));
            }
            let _ = writeln!(config, "  symbols: config/{version}/modules/{}/symbols.txt", module.name);
            let _ = writeln!(config, "  splits: config/{version}/modules/{}/splits.txt", module.name);
        }
    }

    // build.sha1: the DOL, and the RELs that are copied rather than rebuilt. `rels.sha1`: every REL
    // as `dtk rel make` rebuilds it, checked by `ninja rels` (dtk's analysis alone does not
    // reproduce every REL's relocation table, so that check is a measure, not a gate).
    let mut build_sha1 = format!("{sha1}  build/{version}/main.dol\n");
    for module in &copied {
        let _ = writeln!(build_sha1, "{}  build/{version}/{}/{}.rel", module.sha1, module.name, module.name);
    }
    let mut rels_sha1 = String::new();
    for module in &linked {
        let _ = writeln!(rels_sha1, "{}  build/{version}/{}/{}.rel", module.sha1, module.name, module.name);
    }

    // The file-backed sections, for `match` (retail bytes by address).
    let header = |at: usize| u32::from_be_bytes(inputs.dol[at..at + 4].try_into().unwrap());
    let sections_json: Vec<_> = (0..18usize)
        .filter(|i| header(0x90 + i * 4) != 0)
        .map(|i| json!({"vaddr": header(0x48 + i * 4), "offset": header(i * 4), "size": header(0x90 + i * 4)}))
        .collect();
    let cflags = inputs.cflags.clone().unwrap_or_else(|| default_cflags(&mw_version));
    let project = json!({
        "romwright": {"version": inputs.romwright_version, "schema": 1, "platform": if wii { "wii" } else { "gc" }},
        "name": inputs.project_name,
        "title": inputs.title,
        "version": version,
        "image": {"file": "main.dol", "orig": dol_path, "sha1": sha1, "size": inputs.dol.len()},
        "dtk": {
            "config": format!("config/{version}/config.yml"),
            "symbols": format!("config/{version}/symbols.txt"),
            "splits": format!("config/{version}/splits.txt"),
            "objects": format!("config/{version}/objects.json"),
            "build_sha1": format!("config/{version}/build.sha1"),
            "rels_sha1": format!("config/{version}/rels.sha1"),
            "version": DTK_VERSION,
        },
        "compiler": {
            "kind": "mwcc-gc",
            "console": if wii { "wii" } else { "gc" },
            "mw_version": mw_version,
            "linker_version": mw_version,
            "cflags": cflags,
            "ldflags": ["-fp hardware", "-nodefaults"],
            "detected": {
                "family": detection.family,
                "version_class": detection.version_class,
                "default": detection.mw_version,
                "confidence": detection.confidence,
                "sdk_date": detection.sdk_date,
                "evidence": detection.evidence,
            },
        },
        "tools": {
            "dtk": "dtk",
            "compiler": COMPILERS_ID,
            "runtime": "wibo",
            "sjiswrap": "sjiswrap",
            "report": "objdiff-cli",
        },
        "layout": sections_json,
        "runtime": runtime_json(inputs.dol, &layout),
        "modules": linked.iter().map(|m| json!({"name": m.name, "path": m.rel_path, "sha1": m.sha1})).collect::<Vec<_>>(),
        "copied_modules": copied.iter().map(|m| json!({"name": m.name, "path": m.rel_path, "sha1": m.sha1})).collect::<Vec<_>>(),
    });

    let mut evidence = String::new();
    for line in &detection.evidence {
        let _ = writeln!(evidence, "- {line}");
    }
    let detected_line = format!(
        "{} ({:?} confidence): default compiler `{}`",
        detection.version_class, detection.confidence, mw_version
    );
    let readme = render(
        README,
        &[
            ("NAME", inputs.project_name.to_string()),
            ("TITLE", if inputs.title.is_empty() { inputs.project_name.to_string() } else { inputs.title.to_string() }),
            ("VERSION", version.to_string()),
            ("CONSOLE", if wii { "Wii" } else { "GameCube" }.to_string()),
            ("SHA1", sha1.clone()),
            ("DETECTED", detected_line),
            ("EVIDENCE", evidence),
            ("COMPILER", mw_version.clone()),
            ("MODULES", linked.len().to_string()),
            (
                "MODULES_NOTE",
                if inputs.modules.is_empty() {
                    String::new()
                } else {
                    format!(" and its {} RELs below `orig/{version}/`", inputs.modules.len())
                },
            ),
            ("ROMWRIGHT", inputs.romwright_version.to_string()),
            ("DTK", DTK_VERSION.to_string()),
        ],
    );

    let mut files = vec![
        file("configure.py", include_str!("templates/gc/configure.py"), true),
        file("tools/download_tool.py", include_str!("templates/ps2/tools/download_tool.py"), true),
        file("requirements.txt", "ninja\n", false),
        file(".gitignore", include_str!("templates/gc/gitignore"), false),
        file("README.md", &readme, false),
        file(&format!("config/{version}/config.yml"), &config, false),
        file(&format!("config/{version}/splits.txt"), &splits_txt, false),
        file(&format!("config/{version}/symbols.txt"), &symbols_txt, false),
        file(&format!("config/{version}/build.sha1"), &build_sha1, false),
        file(&format!("config/{version}/rels.sha1"), &rels_sha1, false),
        file(&format!("config/{version}/objects.json"), "{\n  \"objects\": {}\n}\n", false),
        file("config/project.json", &(serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n"), false),
        file("config/toolchain.json", &(serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())? + "\n"), false),
        file("include/romwright_types.h", TYPES_H, false),
        file("include/romwright_protos.h", &protos_h, false),
        file("src/.gitkeep", "", false),
    ];
    // A module file that is absent is written by dtk's own analysis on the first split.
    for module in &linked {
        if !module.symbols_txt.is_empty() {
            files.push(file(&format!("config/{version}/modules/{}/symbols.txt", module.name), &module.symbols_txt, false));
        }
        if let Some(splits) = module.splits_txt.as_deref().filter(|s| !s.is_empty()) {
            files.push(file(&format!("config/{version}/modules/{}/splits.txt", module.name), splits, false));
        }
    }
    if let Some(profile) = inputs.profile {
        files.push(file("config/toolchain.local.json", profile, false));
    }
    let report = GcReport {
        dol_sha1: sha1,
        detection,
        mw_version,
        sections: layout.sections.len(),
        sections_from_tables: layout.from_tables,
        symbols: rows.len(),
        functions: symbols.functions,
        functions_skipped: symbols.rejected.len(),
        modules: linked.len(),
        prototypes_emitted: protos.len(),
        prototypes_skipped: skipped_protos,
    };
    Ok((files, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{Address, FunctionRow};

    fn put(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// A DOL with `.init`, `.text` and six data sections, no tables.
    fn dol() -> Vec<u8> {
        let mut dol = vec![0u8; 0x800];
        let sections: [(usize, u32, u32, u32); 8] = [
            (0, 0x100, 0x8000_3100, 0x40),
            (1, 0x140, 0x8000_3140, 0x80),
            (7, 0x1c0, 0x8000_31c0, 0x20),
            (8, 0x1e0, 0x8000_31e0, 0x20),
            (9, 0x200, 0x8000_3200, 0x40),
            (10, 0x240, 0x8000_3240, 0x40),
            (11, 0x280, 0x8000_3280, 0x20),
            (12, 0x2a0, 0x8000_32a0, 0x20),
        ];
        for (index, off, addr, size) in sections {
            put(&mut dol, index * 4, off);
            put(&mut dol, 0x48 + index * 4, addr);
            put(&mut dol, 0x90 + index * 4, size);
        }
        put(&mut dol, 0xe0, 0x8000_3100);
        dol
    }

    fn function(name: &str, address: u64, size: u64) -> FunctionRow {
        FunctionRow {
            name: name.into(),
            entry: Address::ram(address),
            size,
            signature: None,
            traced: false,
            calling_convention: None,
        }
    }

    #[test]
    fn plan_writes_the_dtk_files_with_names_from_the_dol_layout() {
        let dol = dol();
        let facts = ExportFacts {
            program: "t".into(),
            language: "PowerPC:BE:32:Gekko_Broadway".into(),
            functions: vec![function("first", 0x8000_3140, 0x20), function("odd", 0x8000_3162, 0x10)],
            ..Default::default()
        };
        let manifest = Manifest::builtin();
        let (files, report) = plan(&GcInputs {
            dol: &dol,
            version: "GTST01",
            project_name: "t",
            title: "Test",
            facts: &facts,
            prototypes: &[],
            modules: &[],
            manifest: &manifest,
            mw_version: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let get = |path: &str| String::from_utf8(files.iter().find(|f| f.path == path).unwrap().bytes.clone()).unwrap();
        let splits = get("config/GTST01/splits.txt");
        assert!(splits.starts_with("Sections:\n\t.init       type:code align:4\n\t.text       type:code align:"), "{splits}");
        assert!(splits.contains(".ctors") && splits.contains(".sdata2"), "{splits}");
        let symbols = get("config/GTST01/symbols.txt");
        assert!(symbols.contains("first = .text:0x80003140; // type:function size:0x20"), "{symbols}");
        assert!(!symbols.contains("odd"), "an unaligned function is not representable: {symbols}");
        let config = get("config/GTST01/config.yml");
        assert!(config.contains("object: orig/GTST01/sys/main.dol") && config.contains(&format!("hash: {}", report.dol_sha1)));
        assert_eq!(get("config/GTST01/build.sha1"), format!("{}  build/GTST01/main.dol\n", report.dol_sha1));
        assert_eq!((report.functions, report.functions_skipped), (1, 1));
        assert!(files.iter().any(|f| f.path == "configure.py" && f.executable));
        let project: serde_json::Value = serde_json::from_str(&get("config/project.json")).unwrap();
        assert_eq!(project["layout"].as_array().unwrap().len(), 8);
        assert_eq!(project["tools"]["compiler"], COMPILERS_ID);
    }

    #[test]
    fn a_module_gets_its_modules_entry_symbols_and_checksum() {
        let dol = dol();
        let facts = ExportFacts { program: "t".into(), language: "PowerPC:BE:32:Gekko_Broadway".into(), ..Default::default() };
        let manifest = Manifest::builtin();
        let modules = [GcModule {
            name: "d_a_x".into(),
            rel_path: "orig/GTST01/files/rel/d_a_x.rel".into(),
            module_id: 7,
            linked: true,
            sha1: "ab".repeat(20),
            symbols_txt: "f = .text:0x0; // type:function size:0x4\n".into(),
            splits_txt: None,
        }];
        let (files, _) = plan(&GcInputs {
            dol: &dol,
            version: "GTST01",
            project_name: "t",
            title: "",
            facts: &facts,
            prototypes: &[],
            modules: &modules,
            manifest: &manifest,
            mw_version: Some("GC/2.6"),
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let get = |path: &str| String::from_utf8(files.iter().find(|f| f.path == path).unwrap().bytes.clone()).unwrap();
        let config = get("config/GTST01/config.yml");
        assert!(config.contains("modules:\n- object: orig/GTST01/files/rel/d_a_x.rel"), "{config}");
        assert!(config.contains("symbols: config/GTST01/modules/d_a_x/symbols.txt"));
        assert!(get("config/GTST01/rels.sha1").contains("build/GTST01/d_a_x/d_a_x.rel"));
        assert!(!get("config/GTST01/build.sha1").contains("d_a_x"));
        assert!(get("config/GTST01/modules/d_a_x/symbols.txt").contains("type:function"));
    }

    #[test]
    fn overlapping_functions_keep_the_one_that_starts_first() {
        let dol = dol();
        let facts = ExportFacts {
            program: "t".into(),
            language: "PowerPC:BE:32:Gekko_Broadway".into(),
            functions: vec![function("outer", 0x8000_3140, 0x40), function("inner", 0x8000_3160, 0x10), function("next", 0x8000_3180, 0x10)],
            ..Default::default()
        };
        let manifest = Manifest::builtin();
        let (files, report) = plan(&GcInputs {
            dol: &dol,
            version: "V",
            project_name: "t",
            title: "",
            facts: &facts,
            prototypes: &[],
            modules: &[],
            manifest: &manifest,
            mw_version: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let symbols = String::from_utf8(files.iter().find(|f| f.path == "config/V/symbols.txt").unwrap().bytes.clone()).unwrap();
        assert!(symbols.contains("outer =") && symbols.contains("next =") && !symbols.contains("inner"), "{symbols}");
        assert_eq!((report.functions, report.functions_skipped), (2, 1));
    }

    #[test]
    fn the_entry_function_is_named_start() {
        let dol = dol();
        let facts = ExportFacts {
            program: "t".into(),
            language: "PowerPC:BE:32:Gekko_Broadway".into(),
            functions: vec![function("_entry", 0x8000_3100, 0x20)],
            ..Default::default()
        };
        let manifest = Manifest::builtin();
        let (files, _) = plan(&GcInputs {
            dol: &dol,
            version: "V",
            project_name: "t",
            title: "",
            facts: &facts,
            prototypes: &[],
            modules: &[],
            manifest: &manifest,
            mw_version: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let symbols = String::from_utf8(files.iter().find(|f| f.path == "config/V/symbols.txt").unwrap().bytes.clone()).unwrap();
        assert!(symbols.starts_with("__start = .init:0x80003100; // type:function size:0x20"), "{symbols}");
    }

    #[test]
    fn a_compiler_outside_the_bundle_is_refused() {
        let dol = dol();
        let facts = ExportFacts::default();
        let manifest = Manifest::builtin();
        let error = plan(&GcInputs {
            dol: &dol,
            version: "V",
            project_name: "t",
            title: "",
            facts: &facts,
            prototypes: &[],
            modules: &[],
            manifest: &manifest,
            mw_version: Some("../evil"),
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap_err();
        assert!(error.contains("not a directory of the compilers bundle"));
    }

    #[test]
    fn dol_and_disc_magics_route_to_gc() {
        assert_eq!(detect_platform(&dol()), Some("gc"));
        assert_eq!(detect_platform(b"RVZ\x01rest"), Some("gc"));
        assert_eq!(detect_platform(&[0u8; 64]), None);
        let mut elf = vec![0u8; 0x400];
        elf[..4].copy_from_slice(b"\x7fELF");
        assert_eq!(detect_platform(&elf), None);
    }

    #[test]
    fn the_comment_version_follows_the_linker() {
        for (version, expected) in [("GC/1.2.5n", 8), ("GC/1.3.2", 10), ("GC/2.6", 11), ("GC/3.0a5.2", 14), ("Wii/1.5", 15)] {
            assert_eq!(comment_version(version), expected, "{version}");
        }
    }

    #[test]
    fn the_runtime_registration_entries_are_recorded_for_configure() {
        let mut patched = dol();
        // .ctors (0x800031c0): [init]; .dtors (0x800031e0): [destroy chain, fini]; all in .text.
        put(&mut patched, 0x1c0, 0x8000_3140);
        put(&mut patched, 0x1e0, 0x8000_3150);
        put(&mut patched, 0x1e4, 0x8000_3160);
        let layout = dol_layout(&patched).unwrap();
        let runtime = runtime_json(&patched, &layout);
        assert_eq!(runtime["ctors_start"], 0x8000_31c0u32);
        assert_eq!(runtime["ctors_target"], 0x8000_3140u32);
        assert_eq!(runtime["dtors_start"], 0x8000_31e0u32);
        assert_eq!((runtime["destroy_target"].clone(), runtime["fini_target"].clone()), (0x8000_3150u32.into(), 0x8000_3160u32.into()));
        // Empty tables record nothing.
        let empty = runtime_json(&dol(), &layout);
        assert!(empty["ctors_start"].is_null() && empty["dtors_start"].is_null());
    }

    #[test]
    fn default_flags_follow_the_compiler_generation() {
        assert!(default_cflags("GC/1.3.2").contains(&"-multibyte".to_string()));
        assert!(default_cflags("GC/3.0a5").contains(&"-enc SJIS".to_string()));
        assert!(default_cflags("Wii/1.5").contains(&"-enc SJIS".to_string()));
    }
}
