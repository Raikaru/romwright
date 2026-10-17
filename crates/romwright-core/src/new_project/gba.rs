//! The Game Boy Advance plugin: a retail cartridge ROM in, a GNU `as` + `ld`
//! + ninja decompilation repository out.
//!
//! splat has no ARM, so romwright writes the assembly itself (`arm.rs` is the
//! decoder). The layout contract is the PS2 one: the whole file is covered, in
//! order, by units. The cartridge header is one unit (`tools/header.py` writes
//! its assembly, computing the complement check byte), every function romwright
//! found (with the zero padding after it) is a unit of its own, and every other
//! byte range is a `.incbin` of the retail file. Linked in order at the retail
//! addresses and flattened with `objcopy -O binary`, the objects reproduce the
//! retail ROM, so `sha1(build/<rom>) == sha1(retail)` before any C exists.
//!
//! Inside a function unit the decoder follows the code from the entry; bytes it
//! does not reach are data: literal-pool words (with a label, when the load that
//! names them is in the unit) and switch tables, written as `.4byte`s that name a
//! function, label or symbol when the word is exactly that address.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

use serde_json::json;

use super::arm::{self, Flow, Insn, Mode};
use super::GeneratedFile;
use super::compiler::Confidence;
use super::manifest::Manifest;
use super::mips::{clean_prototype, file_stem, fill, lowercase_unique, protos_header, template, types_header};
use crate::export::{sha1_hex, splat_symbol_rows, ExportFacts, SplatSymbol};

/// The cartridge ROM is mapped here.
pub const ROM_BASE: u64 = 0x0800_0000;
/// Header size: through the complement check and the two reserved bytes.
const HEADER_LEN: u64 = 0xc0;
/// Units per object directory (one wildcard statement in the link script).
const CHUNK: usize = 64;
/// Zero padding up to this many bytes after a function belongs to it.
const PAD_LIMIT: u64 = 0x20;

pub struct GbaInputs<'a> {
    pub image: &'a [u8],
    pub image_name: &'a str,
    pub project_name: &'a str,
    /// Program name in the project store (`match` opens it).
    pub program: &'a str,
    pub facts: &'a ExportFacts,
    pub prototypes: &'a [(u64, String)],
    pub manifest: &'a Manifest,
    pub compiler_id: Option<&'a str>,
    pub cflags: Option<Vec<String>>,
    pub profile: Option<&'a str>,
    pub romwright_version: &'a str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GbaReport {
    pub image_sha1: String,
    pub detection: GbaCompilerDetection,
    pub compiler_tool: String,
    pub asm_units: usize,
    pub bin_units: usize,
    pub thumb_functions: usize,
    pub arm_functions: usize,
    pub symbols: usize,
    pub data_symbols: usize,
    pub functions_skipped: usize,
    pub prototypes_emitted: usize,
    pub prototypes_skipped: usize,
}

/// Which compiler family the ROM was built with, from what survives in it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GbaCompilerDetection {
    /// `agbcc` (GCC 2.95-derived, the AGB SDK's compiler) or `unknown`.
    pub family: &'static str,
    pub version: String,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub suggested_tool: &'static str,
}

// ---------------------------------------------------------------------------
// Compiler detection
// ---------------------------------------------------------------------------

/// How Thumb code returns decides the family, by the importer's own rule
/// (`compiler::detect`, measured there over the corpus): the share of
/// `pop {rX}; bx rX` among all Thumb returns is 0.106-0.562 for agbcc and the
/// GCC 2.9x snapshots it descends from, and 1.0 for GCC 4+ (the devkitARM
/// generation). Nintendo's AGB SDK library stamps (`SRAM_V113`, `EEPROM_V124`,
/// `FLASH512_V131`, ...) are listed as supporting evidence: the SDK's libraries
/// were built with the gcc 2.9x-derived compiler agbcc reproduces.
pub fn detect_gba_compiler(rom: &[u8]) -> GbaCompilerDetection {
    let (mut bx_pop, mut pop_pc) = (0u64, 0u64);
    let halves: Vec<u16> = rom.as_chunks::<2>().0.iter().map(|h| u16::from_le_bytes([h[0], h[1]])).collect();
    for pair in halves.windows(2) {
        let (h, next) = (pair[0], pair[1]);
        if h & 0xff00 == 0xbc00 && matches!(h & 0xff, 1 | 2 | 4 | 8) {
            let register = (h & 0xff).trailing_zeros() as u16;
            if next == 0x4700 | register << 3 {
                bx_pop += 1;
            }
        }
        if h & 0xff00 == 0xbd00 {
            pop_pc += 1;
        }
    }
    let share = bx_pop as f64 / (bx_pop + pop_pc).max(1) as f64;
    let mut evidence = vec![format!("{bx_pop} Thumb `pop {{rX}}; bx rX` returns against {pop_pc} `pop {{..,pc}}` (share {share:.3})")];
    let mut stamps: BTreeSet<String> = BTreeSet::new();
    for prefix in [&b"SRAM_V"[..], b"FLASH_V", b"FLASH512_V", b"FLASH1M_V", b"EEPROM_V", b"SIIRTC_V"] {
        let mut from = 0usize;
        while let Some(at) = find(rom, prefix, from) {
            let tail: String = rom[at..].iter().take(24).take_while(|b| b.is_ascii_alphanumeric() || **b == b'_').map(|b| *b as char).collect();
            if tail.len() >= prefix.len() + 3 {
                stamps.insert(tail);
            }
            from = at + prefix.len();
            if stamps.len() > 16 {
                break;
            }
        }
    }
    if !stamps.is_empty() {
        evidence.push(format!("AGB SDK library stamps: {}", stamps.iter().cloned().collect::<Vec<_>>().join(", ")));
    }
    let (family, confidence, version) = if bx_pop >= 200 && (0.05..=0.75).contains(&share) {
        ("agbcc", Confidence::Medium, "gcc 2.9x (agbcc lineage)".to_string())
    } else if bx_pop >= 200 && share >= 0.90 {
        ("devkitarm-gcc", Confidence::Low, String::new())
    } else {
        evidence.push("the return-shape rule is inconclusive here; agbcc is the default for GBA decompilation".to_string());
        ("agbcc", Confidence::Low, String::new())
    };
    GbaCompilerDetection { family, version, confidence, evidence, suggested_tool: "agbcc" }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= haystack.len() || needle.is_empty() {
        return None;
    }
    haystack[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Header,
    Func(Mode),
    Data,
}

#[derive(Debug, Clone)]
struct Unit {
    start: u64,
    end: u64,
    kind: Kind,
    /// Function symbol (functions only).
    name: String,
    /// Path below `asm/`, without extension (`main/0003/foo`).
    file: String,
}

struct Layout {
    units: Vec<Unit>,
    skipped: usize,
}

/// Mode of the function at `entry`: the decode context discovery stored there.
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

fn plan_layout(inputs: &GbaInputs, rows: &HashMap<u64, &SplatSymbol>, contexts: &HashMap<u64, u64>) -> Layout {
    let image = inputs.image;
    let rom_end = ROM_BASE + image.len() as u64;
    let mut entries: Vec<(u64, u64)> = inputs
        .facts
        .functions
        .iter()
        .filter(|f| f.entry.offset >= ROM_BASE + HEADER_LEN && f.entry.offset < rom_end)
        .map(|f| (f.entry.offset, f.size))
        .collect();
    entries.sort_unstable();
    entries.dedup_by_key(|e| e.0);
    let mut funcs: Vec<(u64, u64, Mode)> = Vec::new();
    let mut skipped = 0usize;
    for (i, &(entry, size)) in entries.iter().enumerate() {
        let next = entries.get(i + 1).map(|e| e.0).unwrap_or(rom_end);
        let mode = function_mode(contexts, entry);
        let align = if mode == Mode::Thumb { 2 } else { 4 };
        let wanted = if size == 0 { next - entry } else { size };
        let stop = (entry + wanted).min(next).min(rom_end);
        let stop = entry + ((stop - entry) / align * align);
        if entry % align != 0 || stop <= entry || !rows.contains_key(&entry) {
            skipped += 1;
            continue;
        }
        funcs.push((entry, stop, mode));
    }
    let bytes = |from: u64, to: u64| &image[(from - ROM_BASE) as usize..(to - ROM_BASE) as usize];
    let mut raw: Vec<(u64, u64, Kind)> = vec![(ROM_BASE, ROM_BASE + HEADER_LEN, Kind::Header)];
    let mut cursor = ROM_BASE + HEADER_LEN;
    let mut prev_func = false;
    for &(entry, stop, mode) in &funcs {
        if entry < cursor {
            skipped += 1;
            continue;
        }
        if entry > cursor {
            let span = bytes(cursor, entry);
            let padding = prev_func && entry - cursor <= PAD_LIMIT && span.iter().all(|b| *b == 0);
            if padding {
                let last = raw.last_mut().unwrap();
                last.1 = entry;
            } else {
                raw.push((cursor, entry, Kind::Data));
            }
        }
        raw.push((entry, stop, Kind::Func(mode)));
        cursor = stop;
        prev_func = true;
    }
    if cursor < rom_end {
        let span = bytes(cursor, rom_end);
        let padding = prev_func && rom_end - cursor <= PAD_LIMIT && span.iter().all(|b| *b == 0);
        if padding {
            raw.last_mut().unwrap().1 = rom_end;
        } else {
            raw.push((cursor, rom_end, Kind::Data));
        }
    }
    // Names and directories.
    let mut units = Vec::with_capacity(raw.len());
    let mut taken: HashSet<String> = HashSet::new();
    let (mut chunk, mut in_chunk) = (0usize, 0usize);
    for (start, end, kind) in raw {
        let (name, stem) = match kind {
            Kind::Header => (String::new(), "header".to_string()),
            Kind::Func(_) => {
                let name = rows[&start].name.clone();
                let stem = file_stem(&name, start);
                (name, stem)
            }
            Kind::Data => (String::new(), format!("data_{start:08x}")),
        };
        let dir = match kind {
            Kind::Header => "".to_string(),
            _ => {
                if in_chunk == CHUNK {
                    chunk += 1;
                    in_chunk = 0;
                }
                in_chunk += 1;
                format!("main/{chunk:04}")
            }
        };
        let file = if kind == Kind::Header {
            "header".to_string()
        } else {
            lowercase_unique(&mut taken, format!("{dir}/{stem}"), start)
        };
        units.push(Unit { start, end, kind, name, file });
    }
    Layout { units, skipped }
}

// ---------------------------------------------------------------------------
// Function assembly
// ---------------------------------------------------------------------------

/// Everything a unit's text needs to name other places.
struct Names<'a> {
    /// Function entry -> (symbol, Thumb).
    funcs: &'a HashMap<u64, (String, bool)>,
    /// Data symbol addresses (any region).
    data: &'a HashMap<u64, String>,
}

struct Emitted {
    text: String,
    words: usize,
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Assembly text of the function unit `[start, end)` read from `rom`.
fn emit_function(rom: &[u8], unit: &Unit, mode: Mode, names: &Names) -> Emitted {
    let (start, end) = (unit.start as u32, unit.end as u32);
    let base = unit.start as usize - ROM_BASE as usize;
    let code = &rom[base..base + (unit.end - unit.start) as usize];
    let at = |addr: u32| (addr - start) as usize;
    let step: u32 = if mode == Mode::Thumb { 2 } else { 4 };
    let in_unit = |addr: u32| addr >= start && addr < end;
    let aligned = |addr: u32| addr.is_multiple_of(step);

    let mut decoded: BTreeMap<u32, Insn> = BTreeMap::new();
    let mut covered: HashSet<u32> = HashSet::new();
    let mut roots: Vec<u32> = vec![start];
    let mut tables: BTreeSet<u32> = BTreeSet::new();
    loop {
        while let Some(root) = roots.pop() {
            let mut addr = root;
            while in_unit(addr) && aligned(addr) && !decoded.contains_key(&addr) {
                let off = at(addr);
                let Some(insn) = arm::decode(&code[off..], addr, mode) else { break };
                if off + insn.len as usize > code.len() {
                    break;
                }
                // An instruction may not start inside another.
                if (1..insn.len / step).any(|k| decoded.contains_key(&(addr + k * step))) || covered.contains(&addr) {
                    break;
                }
                let len = insn.len;
                for k in 1..len / step {
                    covered.insert(addr + k * step);
                }
                let flow = insn.flow;
                decoded.insert(addr, insn);
                match flow {
                    Flow::Next => {}
                    Flow::Stop => break,
                    Flow::Jump(target) => {
                        if in_unit(target) {
                            roots.push(target);
                        }
                        break;
                    }
                    Flow::CondJump(target) => {
                        if in_unit(target) {
                            roots.push(target);
                        }
                    }
                    Flow::Call(..) => {}
                }
                addr += len;
            }
        }
        // Switch tables: runs of >= 2 aligned words, none reached, each a code address of this unit
        // in this unit's instruction set.
        let reached = |addr: u32| decoded.contains_key(&addr) || covered.contains(&addr);
        let word_reached = |addr: u32| (0..4 / 2).any(|k| reached(addr + k * 2)) || (step == 4 && reached(addr));
        let mut found = Vec::new();
        let mut addr = (start + 3) & !3;
        while addr + 4 <= end {
            let mut run = Vec::new();
            let mut cur = addr;
            while cur + 4 <= end && !word_reached(cur) {
                let value = read_u32(code, at(cur));
                let (target, thumb_bit) = (value & !1, value & 1);
                if (mode == Mode::Thumb) != (thumb_bit == 1) || !in_unit(target) || !aligned(target) || word_reached(cur) {
                    break;
                }
                run.push((cur, target));
                cur += 4;
            }
            if run.len() >= 2 {
                for (_, target) in &run {
                    if !decoded.contains_key(target) && !tables.contains(target) {
                        found.push(*target);
                    }
                }
                for (word_at, target) in &run {
                    tables.insert(*target);
                    let _ = word_at;
                }
                addr = cur;
            } else {
                addr += 4;
            }
        }
        if found.is_empty() {
            break;
        }
        roots.extend(found);
    }

    // Pool words named by loads whose target lies in this unit and is not code.
    let mut pool_words: BTreeSet<u32> = BTreeSet::new();
    let label_ok = mode == Mode::Arm || start % 4 == 0;
    for insn in decoded.values() {
        if let Some(pool) = &insn.pool {
            let word = pool.address;
            if in_unit(word) && word + 4 <= end && !decoded.contains_key(&word) && !covered.contains(&word) && !decoded.contains_key(&(word + 2)) && label_ok && word % 4 == 0
            {
                pool_words.insert(word);
            }
        }
    }
    // Branch/label targets.
    let mut labels: BTreeSet<u32> = BTreeSet::new();
    for insn in decoded.values() {
        match insn.flow {
            Flow::Jump(t) | Flow::CondJump(t) | Flow::Call(t, _) if in_unit(t) && decoded.contains_key(&t) && t != start => {
                labels.insert(t);
            }
            _ => {}
        }
    }
    for t in &tables {
        if decoded.contains_key(t) && *t != start {
            labels.insert(*t);
        }
    }
    labels.extend(pool_words.iter().copied());

    let thumb = mode == Mode::Thumb;
    // A name for exactly this word: a function entry (with the Thumb bit it has), a data
    // symbol, a code label of this unit; else the number.
    let word_text = |value: u32| -> String {
        let (address, bit) = (value & !1, value & 1);
        if value >= 0x0200_0000 {
            if let Some((name, entry_thumb)) = names.funcs.get(&u64::from(address))
                && bit == u32::from(*entry_thumb) {
                    return name.clone();
                }
            if let Some(name) = names.data.get(&u64::from(value)) {
                return name.clone();
            }
        }
        if in_unit(address) && address != start && decoded.contains_key(&address) && (bit == 1) == thumb {
            return format!(".L{address:08x}{}", if thumb { " + 1" } else { "" });
        }
        format!("{value:#010x}")
    };

    let mut out = String::new();
    let (start_macro, mode_dir) = match mode {
        Mode::Thumb => ("thumb_func_start", ".thumb"),
        Mode::Arm => ("arm_func_start", ".arm"),
    };
    let _ = writeln!(out, ".include \"macro.inc\"\n.syntax unified\n.section .text, \"ax\"\n{mode_dir}\n");
    let _ = writeln!(out, "\t{start_macro} {}", unit.name);
    let mut words = 0usize;
    let mut pos = start;
    while pos < end {
        if pos != start && labels.contains(&pos) {
            let _ = writeln!(out, ".L{pos:08x}:");
        }
        if let Some(insn) = decoded.get(&pos) {
            let mut text = insn.text.clone();
            let mut raw_only = false;
            match insn.flow {
                Flow::Jump(t) | Flow::CondJump(t) | Flow::Call(t, _) => {
                    let label = if t == start {
                        Some(unit.name.clone())
                    } else if in_unit(t) && decoded.contains_key(&t) {
                        Some(format!(".L{t:08x}"))
                    } else if let Some((name, thumb)) = names.funcs.get(&u64::from(t)) {
                        let target_mode = insn.target_mode.unwrap_or(mode);
                        ((*thumb) == (target_mode == Mode::Thumb)).then(|| name.clone())
                    } else {
                        None
                    };
                    match label {
                        Some(label) => {
                            let _ = write!(text, " {label}");
                        }
                        None => raw_only = true,
                    }
                }
                _ => {}
            }
            if let Some(pool) = &insn.pool
                && pool_words.contains(&pool.address) {
                    text = format!("{}.L{:08x}", pool.prefix, pool.address);
                }
            let hex = if insn.len == 4 && mode == Mode::Thumb {
                format!("{:04x} {:04x}", insn.word >> 16, insn.word & 0xffff)
            } else if insn.len == 2 {
                format!("{:04x}", insn.word)
            } else {
                format!("{:08x}", insn.word)
            };
            if raw_only {
                text = raw_directive(insn, mode, &text);
            }
            let _ = writeln!(out, "\t{text}\t@ {pos:08x} {hex}");
            words += 1;
            pos += insn.len;
            continue;
        }
        // Data: up to the next decoded instruction or label.
        let mut next = pos + 1;
        while next < end && !decoded.contains_key(&next) && !covered.contains(&next) && !labels.contains(&next) {
            next += 1;
        }
        // Emit [pos, next) as words/halfwords/bytes.
        let mut cur = pos;
        while cur < next {
            let left = next - cur;
            let remaining_aligned = cur % 4 == 0 && left >= 4;
            if remaining_aligned {
                let value = read_u32(code, at(cur));
                let _ = writeln!(out, "\t.4byte {}\t@ {cur:08x}", word_text(value));
                cur += 4;
            } else if cur % 2 == 0 && left >= 2 {
                let value = read_u16(code, at(cur));
                let _ = writeln!(out, "\t.2byte {value:#06x}\t@ {cur:08x}");
                cur += 2;
            } else {
                let _ = writeln!(out, "\t.byte {:#04x}\t@ {cur:08x}", code[at(cur)]);
                cur += 1;
            }
            words += 1;
        }
        pos = next;
    }
    let _ = writeln!(out, "\t.size {0}, . - {0}", unit.name);
    Emitted { text: out, words }
}

/// An instruction the text cannot name (a branch to an unnamed place): its retail word, kept as an instruction.
fn raw_directive(insn: &Insn, mode: Mode, original: &str) -> String {
    match (mode, insn.len) {
        (Mode::Thumb, 2) => format!(".inst.n {:#06x} @ {original}", insn.word),
        (Mode::Thumb, _) => format!(".inst.w {:#010x} @ {original}", insn.word),
        (Mode::Arm, _) => format!(".inst {:#010x} @ {original}", insn.word),
    }
}

// ---------------------------------------------------------------------------
// Types and prototypes header (ARM, ILP32)
// ---------------------------------------------------------------------------

const MACRO_INC: &str = "\
@ Generated by romwright new-project. Each function unit opens with one of these.
.macro thumb_func_start name
	.global \\name
	.thumb_func
	.type \\name, %function
\\name:
.endm

.macro arm_func_start name
	.global \\name
	.type \\name, %function
\\name:
.endm
";

/// The header fields `tools/header.py` writes into `asm/header.s`.
fn header_json(rom: &[u8]) -> serde_json::Value {
    let hex = |range: std::ops::Range<usize>| rom[range].iter().map(|b| format!("{b:02x}")).collect::<String>();
    json!({
        "entry": hex(0..4),
        "title": hex(0xa0..0xac),
        "game_code": hex(0xac..0xb0),
        "maker_code": hex(0xb0..0xb2),
        "fixed": rom[0xb2],
        "main_unit": rom[0xb3],
        "device_type": rom[0xb4],
        "reserved_b5": hex(0xb5..0xbc),
        "version": rom[0xbc],
        "complement": rom[0xbd],
        "reserved_be": hex(0xbe..0xc0),
    })
}

/// The complement check the BIOS verifies: `-(sum(0xA0..0xBC) + 0x19)`.
pub fn header_complement(rom: &[u8]) -> u8 {
    let sum: u32 = rom[0xa0..0xbd].iter().map(|b| u32::from(*b)).sum();
    (0u32.wrapping_sub(sum + 0x19) & 0xff) as u8
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// True for a cartridge ROM: the fixed byte 0x96 at 0xB2 and a complement check that holds.
pub fn looks_like_gba_rom(image: &[u8]) -> bool {
    image.len() >= 0xc0 && image[0xb2] == 0x96 && header_complement(image) == image[0xbd] && image[3] == 0xea
}

pub fn plan(inputs: &GbaInputs) -> Result<(Vec<GeneratedFile>, GbaReport), String> {
    let image = inputs.image;
    if image.len() < 0xc0 || !image.len().is_multiple_of(4) {
        return Err("this is not a GBA ROM (shorter than the 0xC0-byte header, or not a whole number of words)".into());
    }
    let sha1 = sha1_hex(image);
    let detection = detect_gba_compiler(image);
    let rom_end = ROM_BASE + image.len() as u64;
    let in_rom = |address: u64| address >= ROM_BASE && address < rom_end;

    let image_facts = ExportFacts {
        program: inputs.facts.program.clone(),
        functions: inputs.facts.functions.iter().filter(|f| in_rom(f.entry.offset)).cloned().collect(),
        symbols: inputs.facts.symbols.clone(),
        ..Default::default()
    };
    let rows = splat_symbol_rows(&image_facts);
    let function_rows: HashMap<u64, &SplatSymbol> = rows.iter().filter(|r| r.is_function).map(|r| (r.address, r)).collect();
    let contexts: HashMap<u64, u64> =
        inputs.facts.contexts.iter().filter(|(_, name, _)| name == "LowBitCodeMode" || name == "TMode").map(|(a, _, v)| (*a, *v)).collect();
    let layout = plan_layout(inputs, &function_rows, &contexts);

    // Naming tables for the assembly.
    let mut funcs: HashMap<u64, (String, bool)> = HashMap::new();
    for unit in &layout.units {
        if let Kind::Func(mode) = unit.kind {
            funcs.insert(unit.start, (unit.name.clone(), mode == Mode::Thumb));
        }
    }
    let unit_of = |address: u64| {
        let at = layout.units.partition_point(|u| u.start <= address);
        (at > 0 && address < layout.units[at - 1].end).then(|| &layout.units[at - 1])
    };
    // Data symbols: every non-function row except ones inside function units.
    let mut data: HashMap<u64, String> = HashMap::new();
    let mut kept: Vec<SplatSymbol> = Vec::new();
    for row in &rows {
        if row.is_function {
            if funcs.contains_key(&row.address) {
                kept.push(row.clone());
            }
            continue;
        }
        if funcs.contains_key(&row.address) {
            continue;
        }
        if in_rom(row.address) {
            match unit_of(row.address) {
                Some(unit) if matches!(unit.kind, Kind::Func(_)) => continue,
                None => continue,
                _ => {}
            }
        }
        data.insert(row.address, row.name.clone());
        kept.push(row.clone());
    }

    // Compiler tool.
    let compiler_id = inputs.compiler_id.unwrap_or(detection.suggested_tool).to_string();
    let compiler = inputs.manifest.tool(&compiler_id).ok_or_else(|| {
        format!("compiler `{compiler_id}` is not in the tool manifest; known: {}", inputs.manifest.compiler_ids().join(", "))
    })?;
    if compiler.role != "compiler" {
        return Err(format!("`{compiler_id}` is a {}, not a compiler", compiler.role));
    }
    let subset = inputs.manifest.subset(&["binutils-arm-none-eabi", &compiler_id, "objdiff-cli"])?;

    // Per-unit assembly.
    let names = Names { funcs: &funcs, data: &data };
    let mut files: Vec<GeneratedFile> = Vec::new();
    let mut units_json = Vec::new();
    let (mut asm_units, mut bin_units) = (0usize, 0usize);
    let (mut thumb_functions, mut arm_functions) = (0usize, 0usize);
    let rom_name = inputs.image_name;
    for unit in &layout.units {
        let source = format!("asm/{}.s", unit.file);
        let (kind_name, mode_name) = match unit.kind {
            Kind::Header => ("header", ""),
            Kind::Func(Mode::Thumb) => ("asm", "thumb"),
            Kind::Func(Mode::Arm) => ("asm", "arm"),
            Kind::Data => ("data", ""),
        };
        match unit.kind {
            Kind::Header => {
                bin_units += 1;
            }
            Kind::Data => {
                bin_units += 1;
                let text = format!(
                    ".section .text, \"ax\"\n\t.incbin \"orig/{rom_name}\", {:#x}, {:#x}\n",
                    unit.start - ROM_BASE,
                    unit.end - unit.start
                );
                files.push(template(&source, &text, false));
            }
            Kind::Func(mode) => {
                asm_units += 1;
                if mode == Mode::Thumb {
                    thumb_functions += 1;
                } else {
                    arm_functions += 1;
                }
                let emitted = emit_function(image, unit, mode, &names);
                let _ = emitted.words;
                files.push(template(&source, &emitted.text, false));
            }
        }
        let mut row = json!({
            "name": if unit.name.is_empty() { unit.file.rsplit('/').next().unwrap_or("").to_string() } else { unit.name.clone() },
            "kind": kind_name,
            "start": unit.start,
            "end": unit.end,
            "source": source,
            "dir": unit.file.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default(),
        });
        if !mode_name.is_empty() {
            row["mode"] = json!(mode_name);
        }
        units_json.push(row);
    }

    // Symbols for the link and for people.
    let mut symbol_addrs = String::from("// name = address; type, size (functions)\n");
    let mut symbols_ld = String::from("/* Names for data no object defines: absolute, generated by romwright new-project. */\n");
    let mut data_symbols = 0usize;
    let size_of: HashMap<u64, u64> = layout.units.iter().filter(|u| matches!(u.kind, Kind::Func(_))).map(|u| (u.start, u.end - u.start)).collect();
    for row in &kept {
        if row.is_function {
            let thumb = funcs.get(&row.address).map(|f| f.1).unwrap_or(true);
            let _ = writeln!(symbol_addrs, "{} = {:#x}; // type:func{} size:{:#x}", row.name, row.address, if thumb { " thumb" } else { " arm" }, size_of.get(&row.address).copied().unwrap_or(0));
        } else {
            let _ = writeln!(symbol_addrs, "{} = {:#x};", row.name, row.address);
            let _ = writeln!(symbols_ld, "\"{}\" = {:#x};", row.name, row.address);
            data_symbols += 1;
        }
    }

    // Prototypes.
    let by_address: HashMap<u64, &SplatSymbol> = kept.iter().filter(|r| r.is_function).map(|r| (r.address, r)).collect();
    let mut protos: BTreeMap<u64, (String, String)> = BTreeMap::new();
    let mut skipped_protos = 0usize;
    for (address, declaration) in inputs.prototypes {
        let Some(symbol) = by_address.get(address) else { continue };
        match clean_prototype(declaration, &symbol.name) {
            Some(text) => {
                protos.insert(*address, (symbol.name.clone(), text));
            }
            None => skipped_protos += 1,
        }
    }
    let proto_entries: Vec<(String, String)> = protos.into_values().collect();

    let cflags = inputs.cflags.clone().unwrap_or_else(|| vec!["-O2".into(), "-mthumb-interwork".into(), "-fhex-asm".into()]);
    let project = json!({
        "romwright": {"version": inputs.romwright_version, "schema": 1, "platform": "gba"},
        "name": inputs.project_name,
        "image": {"file": rom_name, "orig": format!("orig/{rom_name}"), "sha1": sha1, "size": image.len(), "base": ROM_BASE, "program": inputs.program},
        "compiler": {
            "kind": "agbcc",
            "tool": compiler_id,
            "runtime": compiler.runtime,
            "cflags": cflags,
            "asflags": ["-mcpu=arm7tdmi"],
            "detected": {
                "family": detection.family,
                "version": detection.version,
                "confidence": detection.confidence,
                "evidence": detection.evidence,
            },
        },
        "tools": {
            "binutils": "binutils-arm-none-eabi",
            "compiler": compiler_id,
            "runtime": serde_json::Value::Null,
            "report": "objdiff-cli",
        },
        "units": "config/units.json",
        "layout": [{"offset": 0, "vaddr": ROM_BASE, "size": image.len()}],
    });

    let detected_line = format!(
        "{} ({:?} confidence), default compiler `{compiler_id}`",
        if detection.version.is_empty() { detection.family.to_string() } else { format!("{} {}", detection.family, detection.version) },
        detection.confidence
    );
    let mut evidence = String::new();
    for line in &detection.evidence {
        let _ = writeln!(evidence, "- {line}");
    }
    let readme = fill(
        include_str!("templates/gba/README.md.tmpl"),
        &[
            ("NAME", inputs.project_name.to_string()),
            ("IMAGE", rom_name.to_string()),
            ("SHA1", sha1.clone()),
            ("DETECTED", detected_line),
            ("EVIDENCE", evidence),
            ("COMPILER", compiler_id.clone()),
            ("ASM_UNITS", asm_units.to_string()),
            ("ROMWRIGHT", inputs.romwright_version.to_string()),
        ],
    );

    files.extend([
        template("configure.py", include_str!("templates/gba/configure.py"), true),
        template("tools/download_tool.py", include_str!("templates/ps2/tools/download_tool.py"), true),
        template("tools/asm.py", include_str!("templates/gba/tools/asm.py"), true),
        template("tools/cc.py", include_str!("templates/gba/tools/cc.py"), true),
        template("tools/autosyms.py", include_str!("templates/gba/tools/autosyms.py"), true),
        template("tools/header.py", include_str!("templates/gba/tools/header.py"), true),
        template("tools/verify.py", include_str!("templates/gba/tools/verify.py"), true),
        template("requirements.txt", "ninja\n", false),
        template(".gitignore", include_str!("templates/gba/gitignore"), false),
        template("README.md", &readme, false),
        template("include/macro.inc", MACRO_INC, false),
        template("include/romwright_types.h", &types_header("Game Boy Advance (ARM7TDMI, ILP32)"), false),
        template("include/romwright_protos.h", &protos_header(&proto_entries, skipped_protos), false),
        template("config/symbols.txt", &symbol_addrs, false),
        template("config/symbols.ld", &symbols_ld, false),
        template("config/header.json", &(serde_json::to_string_pretty(&header_json(image)).map_err(|e| e.to_string())? + "\n"), false),
        template("config/units.json", &(serde_json::to_string_pretty(&units_json).map_err(|e| e.to_string())? + "\n"), false),
        template("config/checksum.sha1", &format!("{sha1}  build/{rom_name}\n"), false),
        template("config/project.json", &(serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n"), false),
        template("config/toolchain.json", &(serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())? + "\n"), false),
        template("src/.gitkeep", "", false),
    ]);
    if let Some(profile) = inputs.profile {
        files.push(template("config/toolchain.local.json", profile, false));
    }
    let report = GbaReport {
        image_sha1: sha1,
        detection,
        compiler_tool: compiler_id,
        asm_units,
        bin_units,
        thumb_functions,
        arm_functions,
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
    use super::*;

    #[test]
    fn complement_check_matches_the_bios_rule() {
        let mut rom = vec![0u8; 0xc0];
        rom[0xa0..0xac].copy_from_slice(b"TESTROM\0\0\0\0\0");
        rom[0xac..0xb0].copy_from_slice(b"ATSE");
        rom[0xb2] = 0x96;
        rom[3] = 0xea;
        rom[0xbd] = header_complement(&rom);
        assert!(looks_like_gba_rom(&rom));
        rom[0xbd] ^= 1;
        assert!(!looks_like_gba_rom(&rom));
    }

    fn rom_with(code: &[u8]) -> Vec<u8> {
        let mut rom = vec![0u8; 0xc0];
        rom[3] = 0xea;
        rom[0xb2] = 0x96;
        rom[0xbd] = header_complement(&rom);
        rom.extend_from_slice(code);
        rom
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

    #[test]
    fn a_thumb_function_keeps_its_literal_pool_as_labelled_words() {
        // push {lr}; ldr r0, [pc, #4]; pop {pc}; pad; pool: 0x03007ffc
        let code: Vec<u8> = [
            0xb500u16, // push {lr}
            0x4801,    // ldr r0, [pc, #4]: ((0xc2 + 4) & !3) + 4 = 0xc8
            0xbd00,    // pop {pc}
            0x0000,    // alignment
        ]
        .iter()
        .flat_map(|h| h.to_le_bytes())
        .chain(0x0300_7ffcu32.to_le_bytes())
        .collect();
        let rom = rom_with(&code);
        let unit = Unit { start: ROM_BASE + 0xc0, end: ROM_BASE + 0xc0 + code.len() as u64, kind: Kind::Func(Mode::Thumb), name: "f".into(), file: "main/0000/f".into() };
        let funcs = HashMap::from([(unit.start, ("f".to_string(), true))]);
        let data = HashMap::new();
        let emitted = emit_function(&rom, &unit, Mode::Thumb, &Names { funcs: &funcs, data: &data });
        assert!(emitted.text.contains("thumb_func_start f"), "{}", emitted.text);
        assert!(emitted.text.contains("ldr r0, .L080000c8"), "{}", emitted.text);
        assert!(emitted.text.contains(".L080000c8:\n\t.4byte 0x03007ffc"), "{}", emitted.text);
    }

    #[test]
    fn the_plan_covers_the_rom_with_header_function_and_data_units() {
        let code: Vec<u8> = [0xb500u16, 0xbd00].iter().flat_map(|h| h.to_le_bytes()).chain([0xffu8; 8]).collect();
        let rom = rom_with(&code);
        let facts = ExportFacts {
            program: "t".into(),
            functions: vec![function("f", ROM_BASE + 0xc0, 4)],
            contexts: vec![(ROM_BASE + 0xc0, "LowBitCodeMode".into(), 1)],
            ..Default::default()
        };
        let manifest = Manifest::builtin();
        let (files, report) = plan(&GbaInputs {
            image: &rom,
            image_name: "t.gba",
            project_name: "t",
            program: "t",
            facts: &facts,
            prototypes: &[],
            manifest: &manifest,
            compiler_id: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let get = |path: &str| String::from_utf8(files.iter().find(|f| f.path == path).unwrap().bytes.clone()).unwrap();
        let units: serde_json::Value = serde_json::from_str(&get("config/units.json")).unwrap();
        let rows = units.as_array().unwrap();
        assert_eq!(rows.len(), 3, "{units}");
        assert_eq!((rows[0]["kind"].as_str(), rows[1]["kind"].as_str(), rows[2]["kind"].as_str()), (Some("header"), Some("asm"), Some("data")));
        assert_eq!((report.asm_units, report.thumb_functions), (1, 1));
        assert!(get("asm/main/0000/f.s").contains("pop {pc}"));
        assert!(get("asm/main/0000/data_080000c4.s").contains(".incbin \"orig/t.gba\", 0xc4, 0x8"));
    }
}
