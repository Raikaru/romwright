//! The plumbing the splat-based MIPS plugins share (PlayStation 2, Nintendo 64,
//! PlayStation, PSP): the file-order layout planner, the symbol and prototype
//! files, the base types header and the template helpers.
//!
//! The contract is the one [`super::ps2`] documents: the yaml covers the whole
//! image in file order; inside a code load every function romwright found is
//! its own `asm` subsegment and every other byte range a `textbin`, so the
//! objects, linked in order at the retail addresses and flattened, reproduce
//! the retail file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use serde_json::json;

use super::detect::MipsDetection;
use super::manifest::Manifest;
use super::GeneratedFile;
use crate::export::{render_splat_symbols, sha1_hex, splat_symbol_rows, ExportFacts, SplatSymbol};

/// splat release the generated yaml and `requirements.txt` are written for.
pub const SPLAT_VERSION: &str = "0.39.1";
/// Functions per directory: the link rewrites each directory's run of
/// objects into one wildcard statement, which keeps GNU ld linear.
pub(super) const CHUNK: usize = 32;
/// Zero padding up to this many bytes after a function belongs to it.
pub(super) const PAD_LIMIT: u64 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Asm,
    TextBin,
    /// The last 1-3 bytes of a load whose size is not a whole word. GNU as
    /// rounds a MIPS `.text` section up to its 4-byte alignment, so these go
    /// in `.data` (alignment 1); being last, they still link in file order.
    DataBin,
}

#[derive(Debug, Clone)]
pub(super) struct Piece {
    /// File offset.
    pub offset: u64,
    pub kind: Kind,
    /// Path below the segment, without extension (`0003/memcmp`).
    pub file: String,
}

#[derive(Debug, Clone)]
pub(super) enum Segment {
    /// Raw bytes: splat `databin` (an `.incbin`), or `header` (splat's N64 header segment).
    Bin { name: String, start: u64, ty: &'static str },
    Code { name: String, start: u64, vram: u64, size: u64, pieces: Vec<Piece> },
}

impl Segment {
    pub(super) fn databin(name: impl Into<String>, start: u64) -> Segment {
        Segment::Bin { name: name.into(), start, ty: "databin" }
    }
}

/// One file-backed range that is code at `vram`.
pub(super) struct Load<'a> {
    pub offset: u64,
    pub vram: u64,
    pub size: u64,
    /// Segment name (`main`, `main2`, an overlay).
    pub name: String,
    /// The functions of this load; `None` takes the image-wide rows (a
    /// platform whose loads share addresses, N64 overlays, gives each its own).
    pub rows: Option<&'a [SplatSymbol]>,
}

/// The planned yaml segments and how many functions did not fit.
pub(super) struct Layout {
    pub segments: Vec<Segment>,
    pub skipped: usize,
    /// Start addresses (vram) of every piece, to keep the data symbol list honest.
    pub starts: HashSet<u64>,
    /// Function extents (vram), sorted, for interior checks.
    pub extents: Vec<(u64, u64)>,
}

pub(super) fn lowercase_unique(taken: &mut HashSet<String>, wanted: String, address: u64) -> String {
    if taken.insert(wanted.to_ascii_lowercase()) {
        return wanted;
    }
    let renamed = format!("{wanted}_{address:08x}");
    taken.insert(renamed.to_ascii_lowercase());
    renamed
}

/// A file stem for a function: its symbol name, shortened when a mangled C++
/// name would exceed what file systems accept.
pub(super) fn file_stem(name: &str, address: u64) -> String {
    if name.len() > 100 {
        format!("{}_{address:08x}", &name[..90])
    } else {
        name.to_string()
    }
}

/// Plans the segments of an image `data` that is `file_len` bytes long.
/// `loads` are the code ranges in file order; `gap` turns the bytes between
/// one load and the next (or the start of the file) into binary segments.
pub(super) fn plan_layout(
    data: &[u8],
    loads: &[Load],
    rows: &[SplatSymbol],
    file_len: u64,
    gap: &dyn Fn(u64, u64) -> Vec<Segment>,
) -> Result<Layout, String> {
    if loads.is_empty() {
        return Err("the image has no file-backed code range: nothing to split".into());
    }
    let mut segments = Vec::new();
    let mut starts = HashSet::new();
    let mut extents = Vec::new();
    let mut skipped = 0usize;
    let mut cursor = 0u64;
    let mut taken: HashSet<String> = HashSet::new();
    for load in loads {
        let (offset, vram, size) = (load.offset, load.vram, load.size);
        let rows = load.rows.unwrap_or(rows);
        let names: HashMap<u64, &SplatSymbol> = rows.iter().filter(|r| r.is_function).map(|r| (r.address, r)).collect();
        if offset < cursor {
            return Err(format!("code range at file offset {offset:#x} overlaps the previous one"));
        }
        if offset + size > file_len {
            return Err(format!("code range {offset:#x}+{size:#x} runs past the end of the file"));
        }
        if offset > cursor {
            segments.extend(gap(cursor, offset));
        }
        let seg_name = load.name.clone();
        let bytes = &data[offset as usize..(offset + size) as usize];
        let end = vram + size;

        // Function extents inside this load: entry aligned to a word, clipped
        // to the next entry and the load, whole words only.
        let mut entries: Vec<(u64, u64)> = rows
            .iter()
            .filter(|r| r.is_function && r.address >= vram && r.address < end)
            .map(|r| (r.address, r.size.unwrap_or(0)))
            .collect();
        entries.sort_unstable();
        entries.dedup_by_key(|e| e.0);
        let mut funcs: Vec<(u64, u64)> = Vec::new();
        for (i, &(entry, size)) in entries.iter().enumerate() {
            let next = entries.get(i + 1).map(|e| e.0).unwrap_or(end);
            let wanted = if size == 0 { next - entry } else { size };
            let stop = (entry + wanted).min(next).min(end);
            let stop = entry + ((stop - entry) & !3);
            if entry % 4 != 0 || stop <= entry {
                skipped += 1;
                continue;
            }
            funcs.push((entry, stop));
        }
        // Pieces: functions, with the gaps between them.
        let mut raw: Vec<(u64, Kind)> = Vec::new();
        let mut cur = vram;
        let mut prev_asm = false;
        let push_gap = |from: u64, to: u64, prev_asm: &mut bool, raw: &mut Vec<(u64, Kind)>| {
            if to <= from {
                return;
            }
            let span = &bytes[(from - vram) as usize..(to - vram) as usize];
            let padding = *prev_asm && to - from <= PAD_LIMIT && (to - from).is_multiple_of(4) && span.iter().all(|b| *b == 0);
            if !padding {
                raw.push((from, Kind::TextBin));
                *prev_asm = false;
            }
        };
        for &(entry, stop) in &funcs {
            push_gap(cur, entry, &mut prev_asm, &mut raw);
            raw.push((entry, Kind::Asm));
            prev_asm = true;
            cur = stop;
            extents.push((entry, stop));
        }
        // A load's size need not be a whole word (Digital Devil Saga's data
        // load is 0x992bd bytes); the tail is its own piece.
        let word_end = end - size % 4;
        push_gap(cur.min(word_end), word_end, &mut prev_asm, &mut raw);
        if word_end < end {
            raw.push((word_end, Kind::DataBin));
        }

        // Directories: `CHUNK` consecutive functions share one, and a binary
        // piece always sits alone in its own, so every directory is one
        // contiguous run in the link order.
        let mut pieces = Vec::with_capacity(raw.len());
        let (mut chunk, mut in_chunk) = (0usize, 0usize);
        for (addr, kind) in raw.iter() {
            let (stem, dir) = match kind {
                Kind::Asm => {
                    if in_chunk == CHUNK {
                        chunk += 1;
                        in_chunk = 0;
                    }
                    in_chunk += 1;
                    (file_stem(&names[addr].name, *addr), chunk)
                }
                Kind::TextBin | Kind::DataBin => {
                    if in_chunk > 0 {
                        chunk += 1;
                    }
                    let dir = chunk;
                    chunk += 1;
                    in_chunk = 0;
                    (format!("data_{addr:08x}"), dir)
                }
            };
            let dir = format!("{dir:04}");
            let stem = lowercase_unique(&mut taken, format!("{seg_name}/{dir}/{stem}"), *addr)
                .rsplit_once('/')
                .map(|(_, s)| s.to_string())
                .unwrap_or_default();
            starts.insert(*addr);
            pieces.push(Piece { offset: offset + (addr - vram), kind: *kind, file: format!("{dir}/{stem}") });
        }
        segments.push(Segment::Code { name: seg_name, start: offset, vram, size, pieces });
        cursor = offset + size;
    }
    if cursor < file_len {
        segments.push(Segment::databin("trailer", cursor));
    }
    extents.sort_unstable();
    Ok(Layout { segments, skipped, starts, extents })
}

/// The `segments:` block of the yaml (the closing `- [end]` entry included).
pub(super) fn write_segments(y: &mut String, layout: &Layout, image_len: usize) {
    let _ = writeln!(y, "segments:");
    for segment in &layout.segments {
        match segment {
            Segment::Bin { name, start, ty } => {
                if *ty == "databin" {
                    let _ = writeln!(y, "  - name: {name}\n    type: databin\n    start: {start:#x}\n    align: 1");
                } else {
                    let _ = writeln!(y, "  - name: {name}\n    type: {ty}\n    start: {start:#x}");
                }
            }
            Segment::Code { name, start, vram, pieces, .. } => {
                let _ = writeln!(
                    y,
                    "  - name: {name}\n    type: code\n    start: {start:#x}\n    vram: {vram:#x}\n    align: 1\n    subalign: 1\n    subsegments:"
                );
                for piece in pieces {
                    let kind = match piece.kind {
                        Kind::Asm => "asm",
                        Kind::TextBin => "textbin",
                        Kind::DataBin => "databin",
                    };
                    let _ = writeln!(y, "      - [{:#x}, {kind}, {name}/{}]", piece.offset, piece.file);
                }
            }
        }
    }
    let _ = writeln!(y, "  - [{:#x}]", image_len);
}

/// `(asm units, binary units)` of a layout.
pub(super) fn count_units(layout: &Layout) -> (usize, usize) {
    let (mut asm_units, mut bin_units) = (0usize, 0usize);
    for segment in &layout.segments {
        match segment {
            Segment::Bin { .. } => bin_units += 1,
            Segment::Code { pieces, .. } => {
                for piece in pieces {
                    match piece.kind {
                        Kind::Asm => asm_units += 1,
                        Kind::TextBin | Kind::DataBin => bin_units += 1,
                    }
                }
            }
        }
    }
    (asm_units, bin_units)
}

/// What a plugin writes from the symbols and prototypes it was given.
pub(super) struct SymbolFiles {
    pub kept: Vec<SplatSymbol>,
    pub symbol_addrs: String,
    pub undefined: String,
    pub data_symbols: usize,
    pub protos: Vec<(String, String)>,
    pub skipped_protos: usize,
}

/// Data symbols are kept when they do not point into the middle of a function,
/// where splat would cut it open; and defined absolutely for the link, since
/// a name inside a binary blob has no object that defines it. Prototypes are
/// kept for named functions when they are made of base types only.
pub(super) fn symbol_files(rows: &[SplatSymbol], layout: &Layout, prototypes: &[(u64, String)]) -> SymbolFiles {
    let in_function = |address: u64| {
        let at = layout.extents.partition_point(|e| e.0 <= address);
        at > 0 && address > layout.extents[at - 1].0 && address < layout.extents[at - 1].1
    };
    // splat refuses a symbol whose name cannot be a file name (255 bytes); a mangled C++ name
    // can be longer, so such a name is cut and keeps its address.
    let kept: Vec<SplatSymbol> = rows
        .iter()
        .filter(|r| r.is_function || !in_function(r.address))
        .cloned()
        .map(|mut row| {
            if row.name.len() > 240 {
                row.name = format!("{}_{:08x}", &row.name[..90], row.address);
            }
            row
        })
        .collect();
    let symbol_addrs = render_splat_symbols(&kept);
    let mut undefined = String::from("/* Names for addresses no object defines (data inside binary blobs, BSS). */\n");
    let mut data_symbols = 0usize;
    for row in kept.iter().filter(|r| !r.is_function && !layout.starts.contains(&r.address)) {
        // Quoted: some names are linker-script keywords (`VERSION`).
        let _ = writeln!(undefined, "\"{}\" = {:#x};", row.name, row.address);
        data_symbols += 1;
    }
    let by_address: HashMap<u64, &SplatSymbol> = kept.iter().filter(|r| r.is_function).map(|r| (r.address, r)).collect();
    let mut protos: BTreeMap<u64, (String, String)> = BTreeMap::new();
    let mut skipped_protos = 0usize;
    for (address, declaration) in prototypes {
        let Some(symbol) = by_address.get(address) else { continue };
        match clean_prototype(declaration, &symbol.name) {
            Some(text) => {
                protos.insert(*address, (symbol.name.clone(), text));
            }
            None => skipped_protos += 1,
        }
    }
    SymbolFiles { kept, symbol_addrs, undefined, data_symbols, protos: protos.into_values().collect(), skipped_protos }
}

/// `include/romwright_types.h` for a platform described by `subject`
/// (`PlayStation 2 (EE, EABI64)`).
pub(super) fn types_header(subject: &str) -> String {
    format!(
        "\
/* Generated by romwright new-project: base types for {subject} code. */
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
"
    )
}

pub(super) fn template(path: &str, text: &str, executable: bool) -> GeneratedFile {
    GeneratedFile { path: path.to_string(), bytes: text.as_bytes().to_vec(), executable }
}

pub(super) fn fill(template: &str, vars: &[(&str, String)]) -> String {
    let mut text = template.to_string();
    for (key, value) in vars {
        text = text.replace(&format!("{{{{{key}}}}}"), value);
    }
    text
}

const TYPE_WORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "const", "volatile", "s8", "u8",
    "s16", "u16", "s32", "u32", "s64", "u64", "f32", "f64", "undefined", "undefined1", "undefined2", "undefined4",
    "undefined8", "byte", "uchar", "ushort", "uint", "longlong", "ulonglong",
];

pub(super) fn is_ident(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !token.starts_with(|c: char| c.is_ascii_digit())
}

/// Splits `int *foo(char a, ...)` into tokens, keeping `*` and punctuation.
pub(super) fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            word.push(ch);
        } else {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            if !ch.is_whitespace() {
                out.push(ch.to_string());
            }
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// `["unsigned", "char", "*"]` -> `unsigned char *`.
pub(super) fn join_type(tokens: &[String]) -> String {
    let mut text = String::new();
    for t in tokens {
        if t == "*" {
            if !text.is_empty() && !text.ends_with('*') {
                text.push(' ');
            }
            text.push('*');
        } else {
            if !text.is_empty() && !text.ends_with('*') {
                text.push(' ');
            }
            text.push_str(t);
        }
    }
    text
}

/// Rewrites a recovered declaration into a prototype made only of types
/// `romwright_types.h` defines (parameter names kept), with the function named
/// `name`. `None` when it mentions anything else.
pub(super) fn clean_prototype(declaration: &str, name: &str) -> Option<String> {
    let declaration = declaration.trim().trim_end_matches(';').trim();
    let open = declaration.find('(')?;
    let close = declaration.rfind(')')?;
    if close < open || !declaration[close + 1..].trim().is_empty() {
        return None;
    }
    let head = tokens(&declaration[..open]);
    let (func, ret) = head.split_last()?;
    if !is_ident(func) || ret.is_empty() {
        return None;
    }
    let allowed = |t: &str| TYPE_WORDS.contains(&t) || t == "*";
    if !ret.iter().all(|t| allowed(t)) {
        return None;
    }
    let mut params = Vec::new();
    let args = declaration[open + 1..close].trim();
    if !args.is_empty() && args != "void" {
        for arg in args.split(',') {
            let toks = tokens(arg);
            if toks.is_empty() {
                return None;
            }
            if toks == ["."; 3] {
                params.push("...".to_string());
                continue;
            }
            let mut ty: &[String] = &toks;
            // A trailing identifier that is not a type word is the parameter name.
            let mut pname = None;
            if let Some(last) = toks.last()
                && is_ident(last) && !TYPE_WORDS.contains(&last.as_str()) && toks.len() >= 2 {
                    pname = Some(last.as_str());
                    ty = &toks[..toks.len() - 1];
                }
            if ty.is_empty() || !ty.iter().all(|t| allowed(t)) {
                return None;
            }
            let mut text = join_type(ty);
            if let Some(n) = pname {
                if !text.ends_with('*') {
                    text.push(' ');
                }
                text.push_str(n);
            }
            params.push(text);
        }
    }
    let mut ret_text = join_type(ret);
    if !ret_text.ends_with('*') {
        ret_text.push(' ');
    }
    let params = if params.is_empty() { "void".to_string() } else { params.join(", ") };
    Some(format!("{ret_text}{name}({params});"))
}

pub(super) fn protos_header(entries: &[(String, String)], skipped: usize) -> String {
    let mut h = String::from(
        "/* Generated by romwright new-project: prototypes recovered by analysis (and the fact pack,\n   when one was present). Only declarations made of the base types below are kept; */\n",
    );
    let _ = writeln!(h, "/* {} declaration(s) were left out because they name types this header does not define. */", skipped);
    h.push_str("#ifndef ROMWRIGHT_PROTOS_H\n#define ROMWRIGHT_PROTOS_H\n\n#include \"romwright_types.h\"\n\n");
    for (name, proto) in entries {
        let _ = writeln!(h, "/* {name} */ {proto}");
    }
    h.push_str("\n#endif\n");
    h
}

// ---------------------------------------------------------------------------
// The project a plugin without an ELF writes (N64, PlayStation, PSP)
// ---------------------------------------------------------------------------

/// The inputs every plugin takes (PS2 spells it `Ps2Inputs`).
pub struct Inputs<'a> {
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
pub struct MipsReport {
    pub platform: &'static str,
    pub image_sha1: String,
    pub detection: MipsDetection,
    pub compiler_tool: String,
    pub segments: usize,
    pub asm_units: usize,
    pub bin_units: usize,
    pub symbols: usize,
    pub data_symbols: usize,
    pub functions_skipped: usize,
    pub prototypes_emitted: usize,
    pub prototypes_skipped: usize,
    /// What the plugin could not carry (compressed segments, unknown CIC, ...).
    pub notes: Vec<String>,
}

/// What one platform is, for the parts of the project that do not depend on the image.
pub(super) struct Spec {
    pub id: &'static str,
    pub name: &'static str,
    /// `Nintendo 64 (VR4300, o32)`, for the types header.
    pub subject: &'static str,
    pub asflags: &'static [&'static str],
    /// `little` or `big`.
    pub endian: &'static str,
    /// GNU ld's `EL` / `EB`.
    pub link_flag: &'static str,
    /// A build step after the flat image (`n64crc`).
    pub post: Option<&'static str>,
    pub readme_limits: &'static str,
}

/// Everything about the image a plugin has worked out.
pub(super) struct Built {
    pub layout: Layout,
    pub yaml: String,
    pub detection: MipsDetection,
    pub rows: Vec<SplatSymbol>,
    /// Extra keys for `image` in project.json (`byte_order`, `source_sha1`, ...).
    pub image_json: serde_json::Value,
    /// `{offset, vaddr, size, name}` of every code load.
    pub layout_json: Vec<serde_json::Value>,
    pub extra_files: Vec<GeneratedFile>,
    /// `post` of project.json when the plugin decides (overrides the spec's).
    pub post: Option<&'static str>,
    pub notes: Vec<String>,
}

const README: &str = include_str!("templates/mips/README.md.tmpl");

/// Default `cflags` of a compiler family (a starting point, not a calibration).
fn default_cflags(family: &str) -> Vec<String> {
    let flags: &[&str] = match family {
        "ido" => &["-O2", "-G", "0", "-mips2", "-non_shared", "-Xcpluscomm", "-Wab,-r4300_mul", "-woff", "649,838"],
        "gcc-mips" => &["-O2", "-mips3", "-mgp32", "-mfp32", "-G", "0", "-mno-abicalls", "-fno-pic", "-fno-common"],
        "psyq" => &["-O2", "-G0"],
        "psp-gcc" => &["-O2", "-G0", "-mno-abicalls", "-fno-pic"],
        "mwcc-psp" => &["-O4,p", "-nodefaults", "-proc", "allegrex"],
        _ => &["-O2"],
    };
    flags.iter().map(|f| f.to_string()).collect()
}

/// Files and report from a planned layout: the tool subset, project.json,
/// symbol files, prototypes, README and the shared templates.
pub(super) fn assemble(spec: &Spec, inputs: &Inputs, built: Built) -> Result<(Vec<GeneratedFile>, MipsReport), String> {
    let Built { layout, yaml, detection, rows, image_json, layout_json, extra_files, post, notes } = built;
    let sha1 = sha1_hex(inputs.image);
    let compiler_id = inputs.compiler_id.unwrap_or(detection.suggested_tool).to_string();
    let compiler = inputs.manifest.tool(&compiler_id).ok_or_else(|| {
        format!("compiler `{compiler_id}` is not in the tool manifest; known: {}", inputs.manifest.compiler_ids().join(", "))
    })?;
    if compiler.role != "compiler" {
        return Err(format!("`{compiler_id}` is a {}, not a compiler", compiler.role));
    }
    if compiler.platform != spec.id {
        return Err(format!("`{compiler_id}` is a {} compiler, this is a {} image", compiler.platform, spec.id));
    }
    let family = compiler.family.clone().unwrap_or_default();
    let runtime_wibo = compiler.runtime.as_deref() == Some("wibo") || compiler.requires.iter().any(|r| r == "wibo");
    let mut ids: Vec<&str> = vec!["binutils-mips-ps2-decompals"];
    if runtime_wibo && !compiler.requires.iter().any(|r| r == "wibo") {
        ids.push("wibo");
    }
    ids.push(&compiler_id);
    ids.extend(compiler.requires.iter().map(String::as_str));
    ids.push("objdiff-cli");
    let subset = inputs.manifest.subset(&ids)?;
    let extra: Vec<&str> = compiler.requires.iter().map(String::as_str).collect();
    let compiler_dirs: Vec<&str> = std::iter::once(compiler_id.as_str())
        .chain(compiler.requires.iter().filter(|r| inputs.manifest.tool(r).is_some_and(|t| t.role == "support")).map(String::as_str))
        .collect();

    let mut symbols = symbol_files(&rows, &layout, inputs.prototypes);
    for target in undefined_call_targets(inputs.image, &layout, &rows, spec.endian == "big") {
        let _ = writeln!(symbols.undefined, "func_{target:08X} = {target:#x};");
    }
    let cflags = inputs.cflags.clone().unwrap_or_else(|| default_cflags(&family));
    let (asm_units, bin_units) = count_units(&layout);
    let mut project = json!({
        "romwright": {"version": inputs.romwright_version, "schema": 1, "platform": spec.id},
        "name": inputs.project_name,
        "platform": spec.id,
        "image": {"file": inputs.image_name, "orig": format!("orig/{}", inputs.image_name), "sha1": sha1, "size": inputs.image.len()},
        "splat": {"yaml": format!("config/{}.yaml", inputs.image_name), "version": SPLAT_VERSION},
        "compiler": {
            "kind": family,
            "tool": compiler_id,
            "runtime": compiler.runtime,
            "cflags": cflags,
            "asflags": spec.asflags,
            "endian": spec.endian,
            "detected": {
                "family": detection.family,
                "version": detection.version,
                "version_class": detection.version_class,
                "confidence": detection.confidence,
                "evidence": detection.evidence,
            },
        },
        "tools": {
            "binutils": "binutils-mips-ps2-decompals",
            "compiler": compiler_id,
            "extra": extra,
            "compiler_dirs": compiler_dirs,
            "runtime": if runtime_wibo { json!("wibo") } else { serde_json::Value::Null },
            "report": "objdiff-cli",
        },
        "link": {"endian": spec.link_flag},
        "layout": layout_json,
    });
    if let (Some(base), Some(add)) = (project["image"].as_object_mut(), image_json.as_object()) {
        for (key, value) in add {
            base.insert(key.clone(), value.clone());
        }
    }
    if let Some(post) = post.or(spec.post) {
        project["post"] = json!(post);
    }

    let detected_line = format!(
        "{} ({:?} confidence) -> splat `{}`, default compiler `{}`",
        if detection.version.is_empty() { detection.family.to_string() } else { detection.version.clone() },
        detection.confidence,
        detection.splat_compiler,
        compiler_id
    );
    let mut evidence = String::new();
    for line in &detection.evidence {
        let _ = writeln!(evidence, "- {line}");
    }
    let mut note_text = String::new();
    for line in &notes {
        let _ = writeln!(note_text, "- {line}");
    }
    let readme = fill(
        README,
        &[
            ("NAME", inputs.project_name.to_string()),
            ("PLATFORM", spec.name.to_string()),
            ("IMAGE", inputs.image_name.to_string()),
            ("SHA1", sha1.clone()),
            ("DETECTED", detected_line),
            ("EVIDENCE", evidence),
            ("COMPILER", compiler_id.clone()),
            ("KIND", family.clone()),
            ("ASM_UNITS", asm_units.to_string()),
            ("SPLAT", SPLAT_VERSION.to_string()),
            ("ROMWRIGHT", inputs.romwright_version.to_string()),
            ("NOTES", note_text),
            ("LIMITS", spec.readme_limits.to_string()),
        ],
    );

    let mut files = vec![
        template("configure.py", include_str!("templates/mips/configure.py"), true),
        template("tools/toolchain.py", include_str!("templates/mips/tools/toolchain.py"), false),
        template("tools/cc.py", include_str!("templates/mips/tools/cc.py"), true),
        template("tools/download_tool.py", include_str!("templates/ps2/tools/download_tool.py"), true),
        template("tools/asm.py", include_str!("templates/mips/tools/asm.py"), true),
        template("tools/verify.py", include_str!("templates/ps2/tools/verify.py"), true),
        template("requirements.txt", include_str!("templates/ps2/requirements.txt"), false),
        template(".gitignore", include_str!("templates/ps2/gitignore"), false),
        template("README.md", &readme, false),
        template(&format!("config/{}.yaml", inputs.image_name), &yaml, false),
        template("config/symbol_addrs.txt", &symbols.symbol_addrs, false),
        template("config/undefined_syms.txt", &symbols.undefined, false),
        template("config/checksum.sha1", &format!("{sha1}  build/{}\n", inputs.image_name), false),
        template("config/project.json", &(serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n"), false),
        template("config/toolchain.json", &(serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())? + "\n"), false),
        template("include/romwright_types.h", &types_header(spec.subject), false),
        template("include/romwright_protos.h", &protos_header(&symbols.protos, symbols.skipped_protos), false),
        template("src/.gitkeep", "", false),
    ];
    files.extend(extra_files);
    if let Some(profile) = inputs.profile {
        files.push(template("config/toolchain.local.json", profile, false));
    }
    let report = MipsReport {
        platform: spec.id,
        image_sha1: sha1,
        detection,
        compiler_tool: compiler_id,
        segments: layout.segments.len(),
        asm_units,
        bin_units,
        symbols: symbols.kept.len(),
        data_symbols: symbols.data_symbols,
        functions_skipped: layout.skipped,
        prototypes_emitted: symbols.protos.len(),
        prototypes_skipped: symbols.skipped_protos,
        notes,
    };
    Ok((files, report))
}

/// The image's functions as splat rows, keeping only addresses a code load maps.
pub(super) fn rows_in(facts: &ExportFacts, mapped: &dyn Fn(u64) -> bool) -> Vec<SplatSymbol> {
    let image_facts = ExportFacts {
        program: facts.program.clone(),
        functions: facts.functions.iter().filter(|f| mapped(f.entry.offset)).cloned().collect(),
        symbols: facts.symbols.iter().filter(|s| mapped(s.address.offset)).cloned().collect(),
        ..Default::default()
    };
    splat_symbol_rows(&image_facts)
}

/// The yaml `options:` block the MIPS plugins share; `extra` are further `  key: value` lines.
pub(super) fn yaml_options(image: &str, sha1: &str, platform: &str, compiler: &str, extra: &[String]) -> String {
    let mut y = String::new();
    let _ = writeln!(y, "sha1: {sha1}");
    let _ = writeln!(y, "options:");
    let _ = writeln!(y, "  basename: {image}");
    let _ = writeln!(y, "  target_path: orig/{image}");
    let _ = writeln!(y, "  base_path: ..");
    let _ = writeln!(y, "  platform: {platform}");
    let _ = writeln!(y, "  compiler: {compiler}");
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
    for line in extra {
        let _ = writeln!(y, "  {line}");
    }
    y
}

/// Call and tail-call targets in the function (`asm`) pieces that no function symbol names.
/// splat names such a target `func_XXXXXXXX` in the listing; when it falls inside a
/// binary piece or the middle of another function no object defines it and the link
/// stops on an undefined reference, so the plugin defines each one absolutely.
pub(super) fn undefined_call_targets(data: &[u8], layout: &Layout, rows: &[SplatSymbol], big: bool) -> Vec<u64> {
    let known: HashSet<u64> = rows.iter().filter(|r| r.is_function).map(|r| r.address).collect();
    let mut out = std::collections::BTreeSet::new();
    for segment in &layout.segments {
        let Segment::Code { start, vram, size, pieces, .. } = segment else { continue };
        let ranges: Vec<(u64, u64)> = pieces
            .iter()
            .enumerate()
            .filter(|(_, p)| p.kind == Kind::Asm)
            .map(|(i, p)| (p.offset, pieces.get(i + 1).map(|n| n.offset).unwrap_or(start + size)))
            .collect();
        for (from, to) in ranges {
            let Some(bytes) = data.get(from as usize..to as usize) else { continue };
            for (i, word) in bytes.as_chunks::<4>().0.iter().enumerate() {
                let w = if big { u32::from_be_bytes([word[0], word[1], word[2], word[3]]) } else { u32::from_le_bytes([word[0], word[1], word[2], word[3]]) };
                let op = w >> 26;
                if op != 2 && op != 3 {
                    continue;
                }
                let pc = vram + (from - start) + 4 * i as u64;
                let target = ((pc + 4) & 0xF000_0000) | (u64::from(w & 0x03FF_FFFF) << 2);
                let in_load = target >= *vram && target < vram + size;
                let piece = (*vram + (from - start), *vram + (to - start));
                // `jal` into this image: a function splat names and no object may define. A `j` that
                // leaves its own function is a tail call: into the image, or out of it (an overlay),
                // where splat lists only `jal` targets in its own undefined-functions file.
                let wanted = if op == 3 { in_load } else { target < piece.0 || target >= piece.1 };
                if wanted && !known.contains(&target) {
                    out.insert(target);
                }
            }
        }
    }
    out.into_iter().collect()
}
