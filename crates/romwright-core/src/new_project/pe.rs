//! `new-project` for 32-bit Windows executables (PE, i386): a reccmp-style repository of per-function units.
//!
//! A PC game's retail image is not rebuilt from its sources, so the repository has no whole-executable build and no
//! checksum to hit: the linker, the C runtime and the order of the object files are not part of what is recovered.
//! What does exist is the compiler era (the importer's `msvc-N` verdict, or `--compiler`), and that is enough to compare
//! one function at a time, the way reccmp projects do. The repository therefore holds
//!
//! * `src/<shard>/<function>.c`: romwright's decompiled C, one function per file, marked `NON_MATCHING` and annotated
//!   `// FUNCTION: <PROJECT> 0xADDRESS` (the marker reccmp reads),
//! * `orig/target/<shard>/<function>.obj`: the retail bytes of the function as an i386 COFF object (what Visual C++
//!   writes), with the relocations a compiler would have left: direct calls and jumps to other functions (`REL32`) and
//!   absolute operands that name a function or a data location (`DIR32`),
//! * `include/`: the types the decompiled C names (the Ghidra spellings, as MSVC can parse them) and the recovered
//!   prototypes with their calling conventions,
//! * `configure.py` (fetches the pinned compiler, `wibo`, `objdiff-cli`), `build.py` (compiles every unit with the pinned
//!   compiler and the era's flags, normalises the symbol names, writes `objdiff.json` units' base objects), and
//!   `build.py report` (objdiff's per-function match percentages, summarised as `build/progress.json`).
//!
//! The plugin is a pure function from facts to files, like the other plugins; the CLI gathers the facts and decompiles.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use serde_json::json;

use super::manifest::Manifest;
use super::scaffold::{self, ModuleInput, ScaffoldFacts, Unit};
use super::scaffold::{file_stem, is_ident, join_type, protos_header, render, template, tokens, Names, TYPE_WORDS};
use super::GeneratedFile;
use crate::{Core, Result};

/// The unpinned fallback for a PE no pinned MSVC era fits (MinGW, Borland): clang for the Windows target, which only
/// checks that the C compiles and cannot reproduce the original compiler's bytes.
pub const CLANG_ID: &str = scaffold::CLANG_ID;
const OBJDIFF_ID: &str = "objdiff-cli";
const WIBO_ID: &str = "wibo";
const MAX_FUNCTION_BYTES: u64 = 1 << 20;

/// What a PE compiles with.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeCompiler {
    /// A `toolchains.json` compiler id.
    pub tool: String,
    /// `msvc` (cl.exe through wibo) or `clang` (a native, non-matching compile check).
    pub family: &'static str,
    /// The flags every unit is compiled with, besides `/c`, the include path and the output name.
    pub flags: Vec<String>,
    /// Why this compiler: the detector's verdict and what the pin stands in for.
    pub why: String,
}

/// The pinned Visual C++ era for the importer's compiler id (`compiler::detect::pe_x86_image`): `msvc-10` is Visual C++
/// 4.x (cl 10.xx), `msvc-12` 6.0, `msvc-13` .NET 2002, `msvc-13.1` .NET 2003, `msvc-14` 2005. Visual C++ 5.0 (`msvc-11`)
/// and 2008 and later are not in the manifest: the nearest pinned era stands in and says so.
pub fn msvc_for(detected: &str) -> Option<(&'static str, &'static str)> {
    Some(match detected {
        "msvc-10" => ("msvc4.2", ""),
        "msvc-11" => ("msvc4.2", "Visual C++ 5.0 is not in the manifest; 4.2 is the nearest older era"),
        "msvc-12" => ("msvc6.0", ""),
        "msvc-13" => ("msvc7.0", ""),
        "msvc-13.1" => ("msvc7.1", ""),
        "msvc-14" => ("msvc8.0", ""),
        id if id.starts_with("msvc-") => ("msvc8.0", "later Visual C++ eras are not in the manifest; 2005 is the newest pinned"),
        _ => return None,
    })
}

/// The compiler of a project: `--compiler` (a manifest id), else the importer's verdict, else (a MinGW or unidentified
/// PE) the clang fallback.
pub fn compiler_for(detected: &str, requested: Option<&str>, flags: Option<Vec<String>>, manifest: &Manifest) -> std::result::Result<PeCompiler, String> {
    let (tool, why) = match requested {
        Some(id) => {
            if manifest.tool(id).is_none() {
                return Err(format!("--compiler {id}: not in the manifest (known compilers: {})", manifest.compiler_ids().join(", ")));
            }
            (id.to_string(), format!("--compiler {id}"))
        }
        None => match msvc_for(detected) {
            Some((tool, note)) => {
                let mut why = format!("the importer's verdict `{detected}`");
                if !note.is_empty() {
                    why.push_str(&format!("; {note}"));
                }
                (tool.to_string(), why)
            }
            None => (
                CLANG_ID.to_string(),
                format!("the importer's verdict is `{detected}`: no pinned Visual C++ era fits it, so units are only checked to compile (clang, `--target=i686-pc-windows-msvc`); pass --compiler msvc6.0 (or another era) to compare against Visual C++ output"),
            ),
        },
    };
    let entry = manifest.tool(&tool).ok_or_else(|| format!("{tool}: not in the manifest"))?;
    let family = if entry.family.as_deref() == Some("msvc") { "msvc" } else { "clang" };
    let flags = flags.unwrap_or_else(|| {
        if family == "msvc" {
            vec!["/O2".into(), "/Gd".into(), "/W0".into()]
        } else {
            ["-std=gnu17", "-O2", "-w", "-ffreestanding", "-fno-builtin", "-fno-pic", "-Wno-implicit-function-declaration", "-Wno-int-conversion", "-Wno-incompatible-pointer-types"]
                .iter()
                .map(|f| f.to_string())
                .collect()
        }
    });
    Ok(PeCompiler { tool, family, flags, why })
}

/// A PE the plugin can handle: PE32 with the i386 machine. `Err` names why a PE is refused; `None` is not a PE at all
/// (or an Xbox 360 executable, which is a PowerPC PE the scaffold handles).
pub fn detect_platform(data: &[u8]) -> Option<std::result::Result<&'static str, String>> {
    if data.get(..2) != Some(b"MZ") {
        return None;
    }
    let pe = data.get(0x3c..0x40).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)?;
    if data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return None;
    }
    let machine = u16::from_le_bytes(data.get(pe + 4..pe + 6)?.try_into().ok()?);
    let magic = u16::from_le_bytes(data.get(pe + 24..pe + 26)?.try_into().ok()?);
    match (machine, magic) {
        (0x014c, 0x10b) => Some(Ok("pe")),
        (0x8664, _) => Some(Err("this is a PE32+ (x86-64) executable: new-project writes i386 PE projects only (no pinned x64 compiler yet)".into())),
        _ => None,
    }
}

/// The importer's compiler detector on the image's own headers, without an import (`detect-compiler`).
pub fn detect_image_compiler(data: &[u8]) -> crate::compiler::Detection {
    let mut imp = crate::native::NativeImport { format: "PE".into(), language: "x86:LE:32:default".into(), ..Default::default() };
    let pe = data.get(0x3c..0x40).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize).unwrap_or(0);
    imp.image_facts.pe_linker = data.get(pe + 26..pe + 28).map(|v| (v[0], v[1]));
    imp.image_facts.pe_rich = crate::compiler::detect::find(&data[..pe.min(data.len())], b"Rich").is_some();
    imp.image_facts.pe_gcc_stamp = crate::compiler::detect::gcc_stamp_text(data);
    crate::compiler::detect::detect(&imp)
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

/// What the plugin reads from the store beyond the scaffold's facts.
#[derive(Debug, Clone, Default)]
pub struct PeFacts {
    pub scaffold: ScaffoldFacts,
    /// `(instruction address, address it names)` for every `READ`/`WRITE`/`DATA` reference the analysis resolved.
    pub data_refs: Vec<(u64, u64)>,
    /// The convention fact per function (`__stdcall+12`: the model and the bytes its `ret` pops).
    pub conventions: HashMap<u64, String>,
}

impl Core {
    pub fn pe_facts(&self, program: &str) -> Result<PeFacts> {
        let scaffold = self.scaffold_facts(program)?;
        let id = self.db.program_id(program)?;
        let data_refs = self
            .db
            .xrefs(id)?
            .into_iter()
            .filter(|x| matches!(x.kind.as_str(), "DATA" | "READ" | "WRITE"))
            .map(|x| (x.from.offset, x.to.offset))
            .collect();
        let conventions = self
            .db
            .calling_conventions(id)?
            .into_iter()
            .filter(|row| row.function.space == romwright_model::AddressSpace::Ram)
            .map(|row| (row.function.offset, row.convention))
            .collect();
        Ok(PeFacts { scaffold, data_refs, conventions })
    }
}

pub struct PeInputs<'a> {
    pub image_name: &'a str,
    pub project_name: &'a str,
    pub image_sha256: String,
    pub image_size: u64,
    pub program: String,
    pub facts: &'a PeFacts,
    /// Retail bytes at an address, from the program's own mapped image.
    pub code: &'a dyn Fn(u64, usize) -> Option<Vec<u8>>,
    /// sha256 of the mapped image.
    pub mapped_sha256: String,
    /// The importer's compiler id (`msvc-12`, `unknown`).
    pub detected: String,
    pub compiler: PeCompiler,
    pub manifest: &'a Manifest,
    pub profile: Option<&'a str>,
    pub romwright_version: &'a str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeReport {
    pub platform: String,
    pub image_sha256: String,
    pub compiler: String,
    pub compiler_family: &'static str,
    pub detected: String,
    pub functions: usize,
    pub sources: usize,
    pub target_objects: usize,
    pub call_relocations: usize,
    pub data_relocations: usize,
    pub objdiff_units: usize,
    pub symbols: usize,
    pub prototypes_emitted: usize,
    pub prototypes_skipped: usize,
}

/// Every function of the program as a unit: names, paths. One module, `main`.
pub fn layout(inputs: &PeInputs) -> Vec<Unit> {
    let mut functions: Vec<_> = inputs.facts.scaffold.facts.functions.iter().collect();
    functions.sort_by_key(|f| f.entry.offset);
    functions.dedup_by_key(|f| f.entry.offset);
    let mut names = Names::default();
    functions
        .into_iter()
        .map(|function| {
            let address = function.entry.offset;
            let cname = names.claim(scaffold::c_ident(&function.name, address), address);
            let stem = file_stem(&cname, address);
            Unit { module: 0, address, name: function.name.clone(), size: function.size, tu: format!("main/{:04x}/{stem}", address >> 16), cname }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Target objects: i386 COFF
// ---------------------------------------------------------------------------

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_REL_I386_DIR32: u16 = 0x0006;
const IMAGE_REL_I386_REL32: u16 = 0x0014;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// A 32-bit displacement from the end of the field (`call`, `jmp`, `jcc` near).
    Rel32,
    /// A 32-bit absolute address (`mov eax, [addr]`, `push offset addr`, `call [slot]`).
    Dir32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeReloc {
    pub offset: u32,
    pub kind: RelocKind,
    pub symbol: String,
}

/// An i386 COFF object with one function, `name`, in `.text`: the shape `cl.exe` writes (a `.text` section symbol with
/// its auxiliary record, the function as an external of type "function", one undefined external per relocation target).
pub fn coff_object(name: &str, bytes: &[u8], relocs: &[PeReloc]) -> Vec<u8> {
    let mut strings: Vec<u8> = Vec::new();
    let mut symbols: Vec<u8> = Vec::new();
    let mut count = 0u32;
    let push_symbol = |symbols: &mut Vec<u8>, strings: &mut Vec<u8>, name: &str, value: u32, section: i16, kind: u16, class: u8, aux: u8| {
        if name.len() <= 8 {
            let mut field = [0u8; 8];
            field[..name.len()].copy_from_slice(name.as_bytes());
            symbols.extend_from_slice(&field);
        } else {
            symbols.extend_from_slice(&[0, 0, 0, 0]);
            symbols.extend_from_slice(&(4 + strings.len() as u32).to_le_bytes());
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        symbols.extend_from_slice(&value.to_le_bytes());
        symbols.extend_from_slice(&section.to_le_bytes());
        symbols.extend_from_slice(&kind.to_le_bytes());
        symbols.push(class);
        symbols.push(aux);
    };
    // .text section symbol + auxiliary section record (length, relocation count, line numbers, checksum, number, selection)
    push_symbol(&mut symbols, &mut strings, ".text", 0, 1, 0, 3, 1);
    symbols.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    symbols.extend_from_slice(&(relocs.len() as u16).to_le_bytes());
    symbols.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    count += 2;
    let function = count;
    push_symbol(&mut symbols, &mut strings, name, 0, 1, 0x20, 2, 0);
    count += 1;
    let mut index: HashMap<&str, u32> = HashMap::new();
    for reloc in relocs {
        if !index.contains_key(reloc.symbol.as_str()) && reloc.symbol != name {
            index.insert(&reloc.symbol, count);
            push_symbol(&mut symbols, &mut strings, &reloc.symbol, 0, 0, 0x20, 2, 0);
            count += 1;
        }
    }
    let raw_at = 20 + 40;
    let relocs_at = raw_at + bytes.len();
    let symbols_at = relocs_at + relocs.len() * 10;
    let mut out = Vec::new();
    out.extend_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(symbols_at as u32).to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0x0100u16.to_le_bytes()); // IMAGE_FILE_32BIT_MACHINE
    out.extend_from_slice(b".text\0\0\0");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(raw_at as u32).to_le_bytes());
    out.extend_from_slice(&(if relocs.is_empty() { 0 } else { relocs_at as u32 }).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(relocs.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0x6050_0020u32.to_le_bytes()); // CNT_CODE | ALIGN_16BYTES | MEM_EXECUTE | MEM_READ
    out.extend_from_slice(bytes);
    for reloc in relocs {
        let symbol = if reloc.symbol == name { function } else { index[reloc.symbol.as_str()] };
        out.extend_from_slice(&reloc.offset.to_le_bytes());
        out.extend_from_slice(&symbol.to_le_bytes());
        out.extend_from_slice(&(if reloc.kind == RelocKind::Rel32 { IMAGE_REL_I386_REL32 } else { IMAGE_REL_I386_DIR32 }).to_le_bytes());
    }
    out.extend_from_slice(&symbols);
    out.extend_from_slice(&(4 + strings.len() as u32).to_le_bytes());
    out.extend_from_slice(&strings);
    out
}

/// The relocations of one function and the bytes with every relocated field zeroed (the addend a COFF `REL32`/`DIR32`
/// keeps in the field is zero when the symbol sits exactly at the address the instruction names).
///
/// A call or jump is relocated only when the instruction is `call`/`jmp rel32` or `jcc rel32` and the displacement lands
/// exactly on the transfer the analysis recorded; an absolute operand only when the four bytes of the address appear once
/// in the instruction's first ten bytes. Anything else stays as retail bytes.
pub fn relocate(
    entry: u64,
    bytes: &mut [u8],
    transfers: &[(u64, u64, bool)],
    data_refs: &[(u64, u64)],
    function_name: &dyn Fn(u64) -> Option<String>,
    data_name: &dyn Fn(u64) -> Option<String>,
) -> (Vec<PeReloc>, usize, usize) {
    let end = entry + bytes.len() as u64;
    let mut claimed: HashSet<usize> = HashSet::new();
    let mut relocs = Vec::new();
    let (mut calls, mut data) = (0usize, 0usize);
    let u32_at = |bytes: &[u8], at: usize| bytes.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let first = transfers.partition_point(|t| t.0 < entry);
    for &(from, to, is_call) in transfers[first..].iter().take_while(|t| t.0 < end) {
        // a jump inside the function is control flow, a branch back to the entry is a loop
        if (!is_call && to >= entry && to < end) || (to == entry && !is_call) {
            continue;
        }
        let at = (from - entry) as usize;
        let (field, length) = match (bytes.get(at), bytes.get(at + 1)) {
            (Some(0xE8 | 0xE9), _) => (at + 1, 5usize),
            (Some(0x0F), Some(0x80..=0x8F)) => (at + 2, 6usize),
            _ => continue,
        };
        let Some(displacement) = u32_at(bytes, field) else { continue };
        if from.wrapping_add(length as u64).wrapping_add(displacement as i32 as i64 as u64) & 0xffff_ffff != to & 0xffff_ffff {
            continue;
        }
        let Some(symbol) = function_name(to) else { continue };
        if !claimed.insert(field) {
            continue;
        }
        bytes[field..field + 4].fill(0);
        relocs.push(PeReloc { offset: field as u32, kind: RelocKind::Rel32, symbol });
        calls += 1;
    }
    let mut refs: Vec<(u64, u64)> = data_refs.iter().copied().filter(|r| r.0 >= entry && r.0 < end).collect();
    refs.sort_unstable();
    refs.dedup();
    for (from, to) in refs {
        let at = (from - entry) as usize;
        let window = &bytes[at..bytes.len().min(at + 10)];
        let hits: Vec<usize> = (1..window.len().saturating_sub(3))
            .filter(|&k| u32::from_le_bytes(window[k..k + 4].try_into().unwrap()) as u64 == to)
            .collect();
        let [k] = hits[..] else { continue };
        let field = at + k;
        if (field..field + 4).any(|b| claimed.contains(&b)) {
            continue;
        }
        let symbol = function_name(to).or_else(|| data_name(to)).unwrap_or_else(|| format!("DAT_{to:08x}"));
        for b in field..field + 4 {
            claimed.insert(b);
        }
        bytes[field..field + 4].fill(0);
        relocs.push(PeReloc { offset: field as u32, kind: RelocKind::Dir32, symbol });
        data += 1;
    }
    relocs.sort_by_key(|r| r.offset);
    (relocs, calls, data)
}

// ---------------------------------------------------------------------------
// Prototypes
// ---------------------------------------------------------------------------

const CONVENTIONS: &[&str] = &["__cdecl", "__stdcall", "__fastcall", "__thiscall"];

/// A recovered declaration as a prototype MSVC can parse: the base types of `romwright_types.h`, the function named
/// `name`, its convention keyword kept (`int __stdcall name(int a, int b);`). A `__thiscall` is dropped: Visual C's C mode
/// has no such keyword, and `__fastcall` would pass a second register argument the callee does not take.
pub fn clean_prototype(declaration: &str, name: &str, stored_convention: Option<&str>) -> Option<String> {
    let declaration = declaration.trim().trim_end_matches(';').trim();
    let open = declaration.find('(')?;
    let close = declaration.rfind(')')?;
    if close < open || !declaration[close + 1..].trim().is_empty() {
        return None;
    }
    let head = tokens(&declaration[..open]);
    let (func, ret) = head.split_last()?;
    if !is_ident(func) {
        return None;
    }
    let mut convention = stored_convention.map(|c| c.split('+').next().unwrap_or(c).to_string());
    let mut ret_tokens: Vec<String> = Vec::new();
    for token in ret {
        if CONVENTIONS.contains(&token.as_str()) {
            convention = Some(token.clone());
        } else {
            ret_tokens.push(token.clone());
        }
    }
    if ret_tokens.is_empty() {
        return None;
    }
    let allowed = |t: &str| TYPE_WORDS.contains(&t) || t == "*";
    if !ret_tokens.iter().all(|t| allowed(t)) {
        return None;
    }
    let convention = match convention.as_deref() {
        Some("__thiscall") => return None,
        Some("__stdcall") => "__stdcall ",
        Some("__fastcall") => "__fastcall ",
        _ => "",
    };
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
    let mut ret_text = join_type(&ret_tokens);
    if !ret_text.ends_with('*') {
        ret_text.push(' ');
    }
    let params = if params.is_empty() { "void".to_string() } else { params.join(", ") };
    Some(format!("{ret_text}{convention}{name}({params});"))
}

/// The prototype the decompiler recovered for a function, read off its definition in the exported C: the line that starts
/// the definition of `name` up to its closing parenthesis (`int __stdcall FUN_00401000(int param_1,int param_2)`). `None`
/// when the text defines no function of that name.
pub fn definition_head(text: &str, name: &str) -> Option<String> {
    let needle = format!("{name}(");
    let mut from = 0;
    while let Some(found) = text[from..].find(&needle) {
        let at = from + found;
        from = at + needle.len();
        let before = text[..at].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let open = at + name.len();
        let mut depth = 0usize;
        let mut close = None;
        for (i, b) in text.bytes().enumerate().skip(open) {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close?;
        // a definition is followed by its body; a call or a declaration is not
        if !text[close + 1..].trim_start().starts_with('{') {
            continue;
        }
        let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        let head = text[line_start..=close].split_whitespace().collect::<Vec<_>>().join(" ");
        return Some(head);
    }
    None
}

/// Types the decompiled C names: the Ghidra spellings, with the 64-bit integers spelled `__int64` (Visual C++ 6.0 and
/// earlier have no `long long`).
const TYPES_H: &str = "\
/* Generated by romwright new-project: the type names decompiled C uses (the decompiler's own spellings), as Visual C++ and
   clang parse them. `long` is 32 bits and pointers are 32 bits (i386). */
#ifndef ROMWRIGHT_TYPES_H
#define ROMWRIGHT_TYPES_H

#if defined(_MSC_VER)
typedef __int64 romwright_i64;
typedef unsigned __int64 romwright_u64;
#else
typedef long long romwright_i64;
typedef unsigned long long romwright_u64;
#define __int64 long long
#endif

typedef signed char s8;
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef int s32;
typedef unsigned int u32;
typedef romwright_i64 s64;
typedef romwright_u64 u64;
typedef float f32;
typedef double f64;

typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned char undefined3[3];
typedef unsigned int undefined4;
typedef unsigned char undefined5[5];
typedef unsigned char undefined6[6];
typedef unsigned char undefined7[7];
typedef romwright_u64 undefined8;
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef romwright_u64 qword;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef romwright_i64 longlong;
typedef romwright_u64 ulonglong;
/* the x87 stack holds 80-bit values; Visual C++ has no `long double` wider than `double` */
typedef double longdouble;
typedef void *pointer;
typedef int (*code)();
#ifndef __cplusplus
typedef unsigned char bool;
#endif

#endif
";

/// Visual C++'s C compiler has no `__thiscall` (error C4234). A member function takes `this` in `ecx` and pops its own stack
/// arguments, which is `__fastcall` with `edx` unused: the definition `T __thiscall f(A this, B b)` is written
/// `T __fastcall f(A this, int edx_unused, B b)`, which compiles to the same prologue and the same `ret N`. Only a
/// definition is rewritten (the text up to the first `{` after the closing parenthesis); callers are untouched.
pub fn thiscall_as_fastcall(text: &str) -> String {
    let Some(at) = text.find("__thiscall") else { return text.to_string() };
    let after = at + "__thiscall".len();
    let Some(open) = text[after..].find('(').map(|i| after + i) else { return text.to_string() };
    if !text[after..open].trim().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let (mut depth, mut close, mut comma) = (0usize, None, None);
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            b',' if depth == 1 && comma.is_none() => comma = Some(i),
            _ => {}
        }
    }
    let Some(close) = close else { return text.to_string() };
    if !text[close + 1..].trim_start().starts_with('{') {
        return text.to_string(); // a declaration, not the definition
    }
    let insert_at = comma.unwrap_or(close);
    format!("{}__fastcall{}, int edx_unused{}", &text[..at], &text[after..insert_at], &text[insert_at..]).replacen("(, int edx_unused", "(int edx_unused", 1)
}

/// The C of Visual C++ 4 to 7.0, which has no `long long` and no `LL`/`ULL` suffix: the 64-bit integer is `__int64` and a
/// literal of it ends `i64`/`ui64`. Strings, character constants and comments are left as they are.
pub fn msvc_dialect(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
                i += if bytes[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(bytes.len());
            out.push_str(&text[start..i]);
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let start = i;
            i = text[i + 2..].find("*/").map_or(bytes.len(), |end| i + 2 + end + 2);
            out.push_str(&text[start..i]);
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            let start = i;
            i = text[i..].find('\n').map_or(bytes.len(), |end| i + end);
            out.push_str(&text[start..i]);
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (is_word(bytes[i]) || bytes[i] == b'.') {
                i += 1;
            }
            let token = &text[start..i];
            let lower = token.to_ascii_lowercase();
            let hex = lower.starts_with("0x");
            let digits_end = |suffix: usize| token[..token.len() - suffix].bytes().all(|b| if hex { b.is_ascii_hexdigit() || b == b'x' || b == b'X' } else { b.is_ascii_digit() });
            if lower.ends_with("ull") && digits_end(3) {
                out.push_str(&token[..token.len() - 3]);
                out.push_str("ui64");
            } else if lower.ends_with("ll") && digits_end(2) {
                out.push_str(&token[..token.len() - 2]);
                out.push_str("i64");
            } else {
                out.push_str(token);
            }
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && is_word(bytes[i]) {
                i += 1;
            }
            let word = &text[start..i];
            if word == "long" {
                // `long long`: the second `long` after whitespace
                let mut j = i;
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                if j > i && text[j..].starts_with("long") && !bytes.get(j + 4).is_some_and(|b| is_word(*b)) {
                    out.push_str("__int64");
                    i = j + 4;
                    continue;
                }
            }
            out.push_str(word);
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn symbol_ident(name: &str, address: u64) -> String {
    scaffold::c_ident(name, address)
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

fn source_text(inputs: &PeInputs, unit: &Unit, body: &str) -> String {
    let mut body = body.to_string();
    if unit.cname != unit.name && !unit.name.is_empty() {
        body = body.replace(&unit.name, &unit.cname);
    }
    format!(
        "/* NON_MATCHING: romwright {} decompilation of `{}` ({:#x}, {:#x} bytes) from {}.\n * It reads the retail function; it does not reproduce its bytes until `python3 build.py report` says it does. */\n// FUNCTION: {} {:#010x}\n#include \"romwright_types.h\"\n\n{}\n",
        inputs.romwright_version,
        unit.cname,
        unit.address,
        unit.size,
        inputs.image_name,
        inputs.project_name.to_ascii_uppercase(),
        unit.address,
        if inputs.compiler.family == "msvc" { thiscall_as_fastcall(&msvc_dialect(body.trim_end())) } else { body.trim_end().to_string() }
    )
}

/// The files of the project. `sources` maps a unit's `tu` to the decompiled C text romwright wrote for it; units without
/// text get no file, no object and no objdiff row.
pub fn plan(inputs: &PeInputs, units: &[Unit], sources: &HashMap<String, String>) -> std::result::Result<(Vec<GeneratedFile>, PeReport), String> {
    let compiler = &inputs.compiler;
    let facts = inputs.facts;
    let mut ids = vec![WIBO_ID, OBJDIFF_ID, compiler.tool.as_str()];
    if compiler.family != "msvc" {
        ids.retain(|id| *id != WIBO_ID);
    }
    let subset = inputs.manifest.subset(&ids)?;
    let mut files: Vec<GeneratedFile> = Vec::new();

    // symbol file and prototypes
    let all_units: Vec<&Unit> = units.iter().collect();
    let module = ModuleInput {
        id: "main".into(),
        program: inputs.program.clone(),
        facts: &facts.scaffold,
        code: inputs.code,
        build_id: None,
        mapped_sha256: inputs.mapped_sha256.clone(),
    };
    let (symbols, symbol_count) = scaffold::symbols_text(&module, &all_units, false);
    files.push(template("config/symbols.txt", &symbols, false));
    let by_address: HashMap<u64, &Unit> = units.iter().map(|u| (u.address, u)).collect();
    let mut entries: BTreeMap<u64, (String, String)> = BTreeMap::new();
    let mut skipped = 0usize;
    // the importer stores none for a PE: the recovered prototype is the head of the decompiled definition
    let mut declarations: BTreeMap<u64, String> = facts.scaffold.prototypes.iter().cloned().collect();
    for unit in units {
        if let Some(head) = sources.get(&unit.tu).and_then(|text| definition_head(text, &unit.name)) {
            declarations.entry(unit.address).or_insert(head);
        }
    }
    for (address, declaration) in &declarations {
        let Some(unit) = by_address.get(address) else { continue };
        match clean_prototype(declaration, &unit.cname, facts.conventions.get(address).map(String::as_str)) {
            Some(text) => {
                entries.insert(*address, (unit.cname.clone(), text));
            }
            None => skipped += 1,
        }
    }
    let protos_ok = entries.len();
    let entries: Vec<_> = entries.into_values().collect();
    files.push(template("include/protos.h", &protos_header(&entries, skipped, "main"), false));
    files.push(template(
        "include/romwright_protos.h",
        "/* Generated by romwright new-project: the recovered prototypes. */\n#ifndef ROMWRIGHT_PROTOS_H\n#define ROMWRIGHT_PROTOS_H\n\n#include \"protos.h\"\n\n#endif\n",
        false,
    ));
    files.push(template("include/romwright_types.h", TYPES_H, false));

    // names the relocations use: functions by their unit's name, data by symbol or `DAT_<address>`
    let function_names: HashMap<u64, String> = units.iter().map(|u| (u.address, u.cname.clone())).collect();
    let mut data_names: HashMap<u64, String> = HashMap::new();
    for symbol in &facts.scaffold.facts.symbols {
        if symbol.source == crate::native::DEMANGLE_SOURCE || symbol.source == crate::qualified_prototypes::mangled::DISPLAY_SOURCE {
            continue;
        }
        data_names.entry(symbol.address.offset).or_insert_with(|| symbol_ident(&symbol.name, symbol.address.offset));
    }
    let function_name = |address: u64| function_names.get(&address).cloned();
    let data_name = |address: u64| data_names.get(&address).cloned();
    let mut transfers = facts.scaffold.transfers.clone();
    transfers.sort_unstable();
    let mut data_refs = facts.data_refs.clone();
    data_refs.sort_unstable();

    let mut unit_rows = Vec::new();
    let mut objdiff_rows = Vec::new();
    let mut tsv = String::from("address\tsize\tname\tcname\tconvention\tsource\ttarget\n");
    let (mut sources_written, mut targets_written, mut call_relocs, mut data_relocs) = (0usize, 0usize, 0usize, 0usize);
    for unit in units {
        let Some(body) = sources.get(&unit.tu) else { continue };
        files.push(template(&format!("src/{}.c", unit.tu), &source_text(inputs, unit, body), false));
        sources_written += 1;
        let convention = facts.conventions.get(&unit.address).cloned().unwrap_or_default();
        let mut row = json!({
            "function": unit.cname,
            "address": format!("{:#x}", unit.address),
            "size": unit.size,
            "convention": convention,
            "source": format!("src/{}.c", unit.tu),
            "object": format!("build/obj/{}.obj", unit.tu),
        });
        let mut target_path = String::new();
        if unit.size > 0 && unit.size <= MAX_FUNCTION_BYTES
            && let Some(mut bytes) = (inputs.code)(unit.address, unit.size as usize) {
                let (relocs, calls, data) = relocate(unit.address, &mut bytes, &transfers, &data_refs, &function_name, &data_name);
                call_relocs += calls;
                data_relocs += data;
                files.push(GeneratedFile { path: format!("orig/target/{}.obj", unit.tu), bytes: coff_object(&unit.cname, &bytes, &relocs), executable: false });
                targets_written += 1;
                target_path = format!("orig/target/{}.obj", unit.tu);
                row["target"] = json!(target_path);
                objdiff_rows.push(json!({
                    "name": format!("main/{:04x}/{}", unit.address >> 16, unit.cname),
                    "target_path": target_path,
                    "base_path": format!("build/obj/{}.obj", unit.tu),
                    "metadata": {
                        "complete": false,
                        "auto_generated": false,
                        "source_path": format!("src/{}.c", unit.tu),
                        "progress_categories": ["main"],
                        "functions": [{"name": unit.cname, "vram": format!("{:#x}", unit.address), "size": unit.size}],
                    },
                }));
            }
        let _ = writeln!(tsv, "{:#010x}\t{}\t{}\t{}\t{}\tsrc/{}.c\t{}", unit.address, unit.size, unit.name, unit.cname, convention, unit.tu, target_path);
        unit_rows.push(row);
    }
    let objdiff_units = objdiff_rows.len();
    if objdiff_units > 0 {
        let document = json!({
            "min_version": "2.0.0-beta.5",
            "custom_make": "python3",
            "custom_args": ["build.py"],
            "build_target": false,
            "build_base": true,
            "watch_patterns": ["src/**/*.c", "include/**/*.h"],
            "units": objdiff_rows,
            "progress_categories": [{"id": "main", "name": inputs.image_name}],
        });
        files.push(template("objdiff.json", &(serde_json::to_string_pretty(&document).map_err(|e| e.to_string())? + "\n"), false));
    }
    files.push(template("config/functions.tsv", &tsv, false));

    let project = json!({
        "romwright": {"version": inputs.romwright_version, "schema": 1, "platform": "pe", "kind": "pe-per-function"},
        "name": inputs.project_name,
        "image": {"file": inputs.image_name, "orig": format!("orig/{}", inputs.image_name), "sha256": inputs.image_sha256, "size": inputs.image_size, "mapped_sha256": inputs.mapped_sha256},
        "compiler": {
            "tool": compiler.tool,
            "family": compiler.family,
            "flags": compiler.flags,
            "detected": inputs.detected,
            "why": compiler.why,
        },
        "whole_image_rebuild": false,
        "units": unit_rows,
    });
    files.push(template("config/project.json", &(serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n"), false));
    files.push(template("config/toolchain.json", &(serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())? + "\n"), false));
    if let Some(profile) = inputs.profile {
        files.push(template("config/toolchain.local.json", profile, false));
    }

    let readme = render(
        include_str!("templates/pe/README.md.tmpl"),
        &[
            ("NAME", inputs.project_name.to_string()),
            ("IMAGE", inputs.image_name.to_string()),
            ("SHA256", inputs.image_sha256.clone()),
            ("ROMWRIGHT", inputs.romwright_version.to_string()),
            ("COMPILER", compiler.tool.clone()),
            ("COMPILER_WHY", compiler.why.clone()),
            ("FLAGS", compiler.flags.join(" ")),
            ("DETECTED", inputs.detected.clone()),
            ("UNITS", sources_written.to_string()),
            ("SYMBOLS", symbol_count.to_string()),
            ("CALL_RELOCS", call_relocs.to_string()),
            ("DATA_RELOCS", data_relocs.to_string()),
            ("PROJECT_UPPER", inputs.project_name.to_ascii_uppercase()),
        ],
    );
    files.push(template("README.md", &readme, false));
    files.push(template("configure.py", include_str!("templates/pe/configure.py"), true));
    files.push(template("build.py", include_str!("templates/pe/build.py"), true));
    files.push(template("tools/download_tool.py", include_str!("templates/ps2/tools/download_tool.py"), true));
    files.push(template(".gitignore", include_str!("templates/scaffold/gitignore"), false));
    if sources_written == 0 {
        files.push(template("src/.gitkeep", "", false));
    }
    let report = PeReport {
        platform: "pe".into(),
        image_sha256: inputs.image_sha256.clone(),
        compiler: compiler.tool.clone(),
        compiler_family: compiler.family,
        detected: inputs.detected.clone(),
        functions: units.len(),
        sources: sources_written,
        target_objects: targets_written,
        call_relocations: call_relocs,
        data_relocations: data_relocs,
        objdiff_units,
        symbols: symbol_count,
        prototypes_emitted: protos_ok,
        prototypes_skipped: skipped,
    };
    Ok((files, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_importers_msvc_ids_pick_a_pinned_era_and_other_ids_fall_back_to_clang() {
        let manifest = Manifest::builtin();
        for (detected, tool) in [("msvc-10", "msvc4.2"), ("msvc-12", "msvc6.0"), ("msvc-13", "msvc7.0"), ("msvc-13.1", "msvc7.1"), ("msvc-14", "msvc8.0"), ("msvc-16", "msvc8.0")] {
            let compiler = compiler_for(detected, None, None, &manifest).unwrap();
            assert_eq!((compiler.tool.as_str(), compiler.family), (tool, "msvc"), "{detected}");
            assert!(compiler.flags.contains(&"/O2".to_string()));
        }
        let mingw = compiler_for("mingw-gcc-16", None, None, &manifest).unwrap();
        assert_eq!((mingw.tool.as_str(), mingw.family), (CLANG_ID, "clang"));
        assert!(mingw.why.contains("mingw-gcc-16"));
        assert_eq!(compiler_for("unknown", Some("msvc6.0"), Some(vec!["/O1".into()]), &manifest).unwrap().flags, ["/O1"]);
        assert!(compiler_for("unknown", Some("nope"), None, &manifest).is_err());
    }

    #[test]
    fn a_pe32_is_the_i386_platform_and_a_pe32_plus_is_refused_with_a_reason() {
        let mut image = vec![0u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c] = 0x80;
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        assert_eq!(detect_platform(&image), Some(Ok("pe")));
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        assert!(detect_platform(&image).unwrap().unwrap_err().contains("x86-64"));
        image[0x84..0x86].copy_from_slice(&0x01f2u16.to_le_bytes());
        assert_eq!(detect_platform(&image), None);
        assert_eq!(detect_platform(b"\x7fELF"), None);
    }

    #[test]
    fn calls_and_absolute_operands_become_relocations_and_their_fields_are_zeroed() {
        // 0x401000: push ebx; mov eax,[0x402010]; call 0x401100; jmp 0x401200 (tail); ret
        let mut bytes: Vec<u8> = vec![0x53, 0xA1, 0x10, 0x20, 0x40, 0x00, 0xE8, 0xF6, 0x00, 0x00, 0x00, 0xE9, 0xF1, 0x01, 0x00, 0x00, 0xC3];
        let transfers = vec![(0x401006, 0x401101, true), (0x40100b, 0x401201, false)];
        // E8 at 0x401006: next = 0x40100b, + 0xf6 = 0x401101 ✓.; E9 at 0x40100b: next = 0x401010, + 0x1f1 = 0x401201 ✓.
        let data_refs = vec![(0x401001, 0x402010)];
        let functions: HashMap<u64, String> = [(0x401101, "callee".to_string()), (0x401201, "tail".to_string())].into_iter().collect();
        let (relocs, calls, data) = relocate(0x401000, &mut bytes, &transfers, &data_refs, &|a| functions.get(&a).cloned(), &|_| None);
        assert_eq!((calls, data), (2, 1));
        assert_eq!(
            relocs,
            vec![
                PeReloc { offset: 2, kind: RelocKind::Dir32, symbol: "DAT_00402010".into() },
                PeReloc { offset: 7, kind: RelocKind::Rel32, symbol: "callee".into() },
                PeReloc { offset: 12, kind: RelocKind::Rel32, symbol: "tail".into() },
            ]
        );
        assert_eq!(&bytes[2..6], [0, 0, 0, 0]);
        assert_eq!(&bytes[7..11], [0, 0, 0, 0]);
        assert_eq!(bytes[0], 0x53);
        // a call whose displacement does not land on the recorded target keeps its bytes
        let mut other = vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let (none, ..) = relocate(0x401000, &mut other, &[(0x401000, 0x402000, true)], &[], &|_| Some("x".into()), &|_| None);
        assert!(none.is_empty());
        assert_eq!(&other[1..5], [0, 0, 0, 0]);
    }

    #[test]
    fn the_coff_object_has_the_text_section_the_function_and_one_external_per_relocation() {
        let object = coff_object(
            "FUN_00401000",
            &[0xE8, 0, 0, 0, 0, 0xC3],
            &[PeReloc { offset: 1, kind: RelocKind::Rel32, symbol: "FUN_00401100".into() }],
        );
        assert_eq!(&object[0..2], [0x4c, 0x01]);
        let symbols_at = u32::from_le_bytes(object[8..12].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(object[12..16].try_into().unwrap());
        assert_eq!(count, 4); // .text + aux, the function, the callee
        // the relocation: offset 1, symbol index 3, REL32
        assert_eq!(&object[60 + 6..60 + 16], [1, 0, 0, 0, 3, 0, 0, 0, 0x14, 0]);
        // long names go through the string table
        assert_eq!(&object[symbols_at + 2 * 18..symbols_at + 2 * 18 + 4], [0, 0, 0, 0]);
        let strings_at = symbols_at + 18 * count as usize;
        assert!(object[strings_at + 4..].starts_with(b"FUN_00401000\0FUN_00401100\0"));
    }

    #[test]
    fn old_visual_c_gets_int64_for_long_long_and_i64_suffixes_outside_strings_and_comments() {
        assert_eq!(
            msvc_dialect("unsigned long long a = 0x10ULL + 5ll; long b; long  long c; /* long long */ char *s = \"long long 3LL\"; // 7ULL\nlonger x;"),
            "unsigned __int64 a = 0x10ui64 + 5i64; long b; __int64 c; /* long long */ char *s = \"long long 3LL\"; // 7ULL\nlonger x;"
        );
        assert_eq!(msvc_dialect("x = 0xFFFFFFFF;"), "x = 0xFFFFFFFF;");
    }

    #[test]
    fn the_recovered_prototype_is_the_head_of_the_definition_not_a_call_or_a_declaration() {
        let text = "extern int FUN_1(int);\nvoid g(void)\n{\n  FUN_1(2);\n}\nint __stdcall FUN_1(int param_1,\n  char *param_2)\n\n{\n  return 0;\n}\n";
        assert_eq!(definition_head(text, "FUN_1").as_deref(), Some("int __stdcall FUN_1(int param_1, char *param_2)"));
        assert_eq!(definition_head(text, "g").as_deref(), Some("void g(void)"));
        assert_eq!(definition_head(text, "nope"), None);
        assert_eq!(clean_prototype("int __stdcall FUN_1(int param_1, char *param_2)", "FUN_1", None).unwrap(), "int __stdcall FUN_1(int param_1, char *param_2);");
    }

    #[test]
    fn a_thiscall_definition_becomes_a_fastcall_with_an_unused_edx() {
        let text = "extern int g(int);\nint __thiscall FUN_1(int *this,int b)\n{\n  return b;\n}\n";
        assert_eq!(thiscall_as_fastcall(text), "extern int g(int);\nint __fastcall FUN_1(int *this, int edx_unused,int b)\n{\n  return b;\n}\n");
        let only_this = "void __thiscall FUN_2(int *this)\n{\n}\n";
        assert_eq!(thiscall_as_fastcall(only_this), "void __fastcall FUN_2(int *this, int edx_unused)\n{\n}\n");
        let declaration = "extern int __thiscall FUN_3(int *);\n";
        assert_eq!(thiscall_as_fastcall(declaration), declaration);
    }

    #[test]
    fn prototypes_keep_stdcall_and_fastcall_and_drop_thiscall_and_foreign_types() {
        assert_eq!(clean_prototype("int FUN_1(int param_1, char * param_2)", "f", Some("__stdcall+8")).unwrap(), "int __stdcall f(int param_1, char *param_2);");
        assert_eq!(clean_prototype("void __fastcall FUN_1(int a)", "f", None).unwrap(), "void __fastcall f(int a);");
        assert_eq!(clean_prototype("int __cdecl FUN_1(void)", "f", None).unwrap(), "int f(void);");
        assert!(clean_prototype("int __thiscall FUN_1(int a)", "f", None).is_none());
        assert!(clean_prototype("Foo * FUN_1(int a)", "f", None).is_none());
    }
}
