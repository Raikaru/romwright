//! Project-file emitters for the decomp toolchain: decomp-toolkit (dtk)
//! `config.yml` / `splits.txt` / `symbols.txt` and splat `<name>.yaml` /
//! `symbol_addrs.txt`. Pure functions over store rows, so the byte format is
//! testable without a store or the tools.
//!
//! Format references (behaviour, not code): dtk's `docs/` and README
//! (MIT/Apache-2.0) for the `name = section:0xADDR; // attr:value` symbol
//! grammar and the `Sections:` block; splat's wiki and `splat/util/symbols.py`
//! option/attribute list (MIT) for `name = 0xADDR; // type:func size:0x..`.

use std::fmt::Write as _;

use romwright_model::{FunctionRow, MemoryRegion, StringRow, SymbolRow};

use crate::native::linkmap::{parse_splits, section_at, SplitExtent};
use crate::{Core, Result};

/// What an exporter reads from a program: rows the store already holds.
#[derive(Debug, Clone, Default)]
pub struct ExportFacts {
    pub program: String,
    /// Ghidra language id, e.g. `PowerPC:BE:32:Gekko_Broadway`.
    pub language: String,
    /// Toolchain the import recorded (`mwcc`, `gcc`, ...); empty when unknown.
    pub compiler: String,
    /// Path the program was imported from, when the store remembers it.
    pub source_path: Option<String>,
    pub functions: Vec<FunctionRow>,
    pub symbols: Vec<SymbolRow>,
    pub strings: Vec<StringRow>,
    /// Addresses some instruction was resolved to read or take the address
    /// of (`DATA`/`READ` xrefs): the evidence that a swept string is one.
    pub referenced: std::collections::HashSet<u64>,
    pub regions: Vec<MemoryRegion>,
    /// Decode contexts `(address, name, value)`: instruction-set mode at the points
    /// discovery settled (`LowBitCodeMode` 1 = Thumb on ARM, `ISA_MODE` on MIPS).
    pub contexts: Vec<(u64, String, u64)>,
}

impl Core {
    /// Everything the exporters read, in one consistent pass over the store.
    pub fn export_facts(&self, program: &str) -> Result<ExportFacts> {
        let id = self.db.program_id(program)?;
        let source_path = self.db.program_input(id).ok().map(|input| input.source_path);
        Ok(ExportFacts {
            program: program.to_string(),
            language: self.db.program_language(id)?,
            compiler: self.db.program_compiler(id)?,
            source_path,
            functions: self.db.functions(id)?,
            symbols: self.db.symbols(id)?,
            strings: self.db.strings(id)?,
            referenced: self
                .db
                .xrefs(id)?
                .into_iter()
                .filter(|xref| matches!(xref.kind.as_str(), "DATA" | "READ"))
                .map(|xref| xref.to.offset)
                .collect(),
            regions: self.db.memory_regions(id)?,
            contexts: self
                .db
                .decode_contexts(id)?
                .into_iter()
                .map(|(address, name, value)| (address.offset, name, value))
                .collect(),
        })
    }
}

/// Regions the loader mapped from the binary. Platform-declared regions
/// (`native-import:platform-map`: IO, scratchpad, main RAM) carry no image
/// bytes and are not sections of it.
fn image_regions(regions: &[MemoryRegion]) -> Vec<&MemoryRegion> {
    let mut image: Vec<&MemoryRegion> = regions
        .iter()
        .filter(|region| region.source == "native-import" && region.size != 0)
        .collect();
    image.sort_by_key(|region| region.start.offset);
    image
}

/// A name a symbol file can carry on one line. dtk splits `name = ...` on
/// whitespace and `=`/`:`; splat additionally refuses the characters an
/// output file name cannot hold (its `ILLEGAL_FILENAME_CHARS`). Anything else
/// is kept so MWCC `Foo__3BarFv` and `cmdTypeAndStatus$371` survive.
fn legal_name(name: &str, address: u64, reject: &[char]) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        let bad = !ch.is_ascii_graphic()
            || matches!(ch, '=' | ';' | ':' | '"' | '\\')
            || reject.contains(&ch);
        out.push(if bad { '_' } else { ch });
    }
    if out.is_empty() {
        return format!("sym_{address:08x}");
    }
    // `//` starts a comment in both grammars.
    while out.contains("//") {
        out = out.replace("//", "_/");
    }
    out
}

const SPLAT_ILLEGAL: [char; 6] = ['<', '>', '|', '?', '*', '/'];

/// A name GNU as accepts as a plain symbol: `[A-Za-z0-9_.$]`, not starting
/// with a digit, `$` (a register) or `.` (a local label: `.L` names vanish
/// from the object). splat writes symbol names straight into assembly, so
/// `CDataAlloc<1,1690000>::Alloc(int)` style names have to be flattened.
fn gas_symbol_name(name: &str, address: u64) -> String {
    let legal = legal_name(name, address, &SPLAT_ILLEGAL);
    let mut out: String = legal
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '$') { ch } else { '_' })
        .collect();
    if out.starts_with(|ch: char| ch.is_ascii_digit() || ch == '$' || ch == '.') {
        out.insert(0, '_');
    }
    out
}

/// Hands out each name once. A second claimant gets its address appended.
#[derive(Default)]
struct Names(std::collections::HashSet<String>);

impl Names {
    fn claim(&mut self, name: String, address: u64) -> String {
        if self.0.insert(name.clone()) {
            return name;
        }
        let renamed = format!("{name}_{address:08x}");
        self.0.insert(renamed.clone());
        renamed
    }
}

// ---------------------------------------------------------------------------
// dtk
// ---------------------------------------------------------------------------

/// One dtk section: the order of these rows is the order of the image's
/// sections, which is how dtk binds `Sections:` entries to a DOL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtkSection {
    pub name: String,
    pub kind: &'static str,
    pub align: u32,
    pub start: u64,
    pub end: u64,
}

fn region_kind(region: &MemoryRegion) -> &'static str {
    if region.permissions.contains('x') {
        "code"
    } else if region.permissions.contains('w') {
        "data"
    } else {
        "rodata"
    }
}

/// Section names and types for an image with no `splits.txt` of its own.
///
/// A MWCC-linked GameCube/Wii DOL is laid out `.init`, `extab`, `extabindex`,
/// `.text`, `.ctors`, `.dtors`, `.rodata`, `.data`, `.bss`, `.sdata`, `.sbss`,
/// `.sdata2` (what `dtk dol info` calls them, and what `elf2dol` of such a
/// link produces). That shape is recognised from the region order alone:
/// exactly two data regions between the first two code regions and exactly
/// eight after the last. Any other image gets `.text`/`.text<N>` for code and
/// `.data<N>` for everything else: valid section names, no claim about what
/// the bytes are.
pub fn dtk_sections(regions: &[MemoryRegion]) -> Vec<DtkSection> {
    let image = image_regions(regions);
    let executable: Vec<usize> = image
        .iter()
        .enumerate()
        .filter(|(_, region)| region.permissions.contains('x'))
        .map(|(index, _)| index)
        .collect();
    let canonical = (|| {
        let (&first, &second, &last) =
            (executable.first()?, executable.get(1)?, executable.last()?);
        let after = image.len() - 1 - last;
        (first == 0 && second == 3 && after == 8 && image[1..3].iter().all(|r| !r.permissions.contains('x')))
            .then_some(())
    })()
    .is_some();
    let mut sections = Vec::with_capacity(image.len());
    for (index, region) in image.iter().enumerate() {
        let (name, kind, align): (String, &'static str, u32) = if canonical {
            match index {
                0 => (".init".into(), "code", 4),
                1 => ("extab".into(), "rodata", 4),
                2 => ("extabindex".into(), "rodata", 4),
                3 => (".text".into(), "code", 4),
                4 => (".ctors".into(), "rodata", 4),
                5 => (".dtors".into(), "rodata", 4),
                6 => (".rodata".into(), "rodata", 8),
                7 => (".data".into(), "data", 32),
                8 => (".bss".into(), "bss", 32),
                9 => (".sdata".into(), "data", 8),
                10 => (".sbss".into(), "bss", 8),
                _ => (".sdata2".into(), "rodata", 8),
            }
        } else if region.permissions.contains('x') {
            let ordinal = executable.iter().position(|&i| i == index).unwrap_or(0);
            let name = if ordinal == 0 { ".text".to_string() } else { format!(".text{ordinal}") };
            (name, "code", 4)
        } else {
            (format!(".data{index}"), region_kind(region), 32)
        };
        sections.push(DtkSection {
            name,
            kind,
            align,
            start: region.start.offset,
            end: region.start.offset.saturating_add(region.size),
        });
    }
    sections
}

/// Resolves an address to the section name a symbol row carries.
struct SectionNamer<'a> {
    splits: &'a [SplitExtent],
    spans: Vec<(u64, u64, String)>,
}

impl<'a> SectionNamer<'a> {
    fn new(regions: &[MemoryRegion], splits: &'a [SplitExtent]) -> Self {
        let mut spans = Vec::new();
        for section in dtk_sections(regions) {
            // With the project's splits, a region takes the name of the
            // extent covering most of it; names the project did not use for
            // it are not ours to invent.
            let name = splits
                .iter()
                .filter(|extent| extent.start < section.end && extent.end > section.start)
                .max_by_key(|extent| {
                    extent.end.min(section.end).saturating_sub(extent.start.max(section.start))
                })
                .map(|extent| extent.name.clone())
                .unwrap_or(section.name);
            spans.push((section.start, section.end, name));
        }
        Self { splits, spans }
    }

    fn section(&self, address: u64) -> Option<&str> {
        section_at(self.splits, address).or_else(|| {
            self.spans
                .iter()
                .find(|(start, end, _)| address >= *start && address < *end)
                .map(|(_, _, name)| name.as_str())
        })
    }
}

/// dtk symbol rows plus what was left out and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DtkSymbols {
    pub rows: Vec<String>,
    pub functions: usize,
    pub objects: usize,
    /// Function entries dtk cannot represent: PowerPC instructions are
    /// whole words, so a `type:function` row at an unaligned address is an
    /// error in `dtk dol diff` and one whose size is not a multiple of four
    /// aborts `dtk dol split`.
    pub rejected: Vec<u64>,
    /// Rows whose address no image section covers.
    pub unmapped: usize,
}

/// `name = section:0xADDR; // type:function size:0x.. scope:global`.
///
/// Functions come from the function table; objects are the ASCII/UTF-8
/// string literals the sweep found (their size is the literal plus its NUL)
/// and the named non-external symbols. Names with characters the grammar
/// cannot hold are rewritten, never dropped.
///
/// `lossless` keeps every function row, including the ones dtk cannot
/// represent (that is what a round trip back into a store needs); without
/// it those are left out and listed in `rejected`.
pub fn dtk_symbols(facts: &ExportFacts, splits: &[SplitExtent], lossless: bool) -> DtkSymbols {
    let namer = SectionNamer::new(&facts.regions, splits);
    dtk_symbols_placed(facts, &|address| namer.section(address).map(|section| (section.to_string(), address)), lossless)
}

/// `dtk_symbols` with the section column supplied by the caller: `place`
/// maps an address to `(section name, the number the row prints)`. A DOL
/// prints the address itself; a REL module's rows are offsets into the
/// module's own section.
pub fn dtk_symbols_placed(
    facts: &ExportFacts,
    place: &dyn Fn(u64) -> Option<(String, u64)>,
    lossless: bool,
) -> DtkSymbols {
    let word_aligned = facts.language.starts_with("PowerPC") || facts.language.starts_with("ppc");
    let mut out = DtkSymbols::default();
    let mut taken: std::collections::HashSet<u64> = std::collections::HashSet::new();
    // dtk refuses overlapping functions ("Overlapping functions ... -> ..."): of two whose ranges
    // intersect the one that starts first stays, the entry inside it is not representable.
    let mut inside: std::collections::HashSet<u64> = std::collections::HashSet::new();
    if !lossless && word_aligned {
        let mut by_address: Vec<_> = facts.functions.iter().map(|f| (f.entry.offset, f.size)).collect();
        by_address.sort_unstable();
        let mut end = 0u64;
        for (address, size) in by_address {
            if address < end {
                inside.insert(address);
            } else {
                end = address.saturating_add(size);
            }
        }
    }
    for function in &facts.functions {
        let address = function.entry.offset;
        if !lossless && word_aligned && (address % 4 != 0 || function.size % 4 != 0 || inside.contains(&address)) {
            out.rejected.push(address);
            continue;
        }
        let Some((section, shown)) = place(address) else {
            out.unmapped += 1;
            continue;
        };
        let name = legal_name(&function.name, address, &[]);
        out.rows.push(format!(
            "{name} = {section}:{shown:#x}; // type:function size:{:#x} scope:global",
            function.size
        ));
        taken.insert(address);
        out.functions += 1;
    }
    for symbol in facts.symbols.iter().filter(|symbol| is_linkage_symbol(symbol)) {
        let address = symbol.address.offset;
        if symbol.external || taken.contains(&address) {
            continue;
        }
        let Some((section, shown)) = place(address) else {
            out.unmapped += 1;
            continue;
        };
        let name = legal_name(&symbol.name, address, &[]);
        out.rows.push(format!("{name} = {section}:{shown:#x}; // type:label scope:global"));
        taken.insert(address);
        out.objects += 1;
    }
    for string in &facts.strings {
        let address = string.address.offset;
        // A sweep also reads jump-table and pointer bytes as text; only a
        // plain-ASCII literal some code refers to is a string symbol, and
        // dtk rejects a symbol that lands inside a table it recognised.
        if string.kind != "ASCII"
            || !string.value.bytes().all(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\t'))
            || !facts.referenced.contains(&address)
            || taken.contains(&address)
        {
            continue;
        }
        let Some((section, shown)) = place(address) else {
            out.unmapped += 1;
            continue;
        };
        let name = format!("str_{address:08X}");
        out.rows.push(format!(
            "{name} = {section}:{shown:#x}; // type:object size:{:#x} scope:local data:string",
            string.value.len() + 1
        ));
        taken.insert(address);
        out.objects += 1;
    }
    out
}

/// Whether a stored symbol names something in the image. A name derived from
/// another (`typeinfo` from `_ZTIi`, `UberBond::__vtable` from
/// `__vt__8UberBond`) is what a reader sees, not what a linker resolves, and
/// exporting it in place of the mangled name would rename the symbol.
fn is_linkage_symbol(symbol: &SymbolRow) -> bool {
    symbol.source != crate::native::DEMANGLE_SOURCE
        && symbol.source != crate::qualified_prototypes::mangled::DISPLAY_SOURCE
}

/// The three files of a dtk project skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtkExport {
    pub config_yml: String,
    pub splits_txt: String,
    pub symbols_txt: String,
    pub symbols: DtkSymbols,
}

/// `config.yml`, `splits.txt` and `symbols.txt`. With the project's own
/// `splits.txt` the text passes through and names come from its extents;
/// without it `Sections:` lists the image's sections in order and no
/// translation unit is claimed (dtk makes its own units).
pub fn export_dtk(facts: &ExportFacts, splits_text: Option<&str>) -> DtkExport {
    let splits = splits_text.map(parse_splits).unwrap_or_default();
    let splits_txt = match splits_text {
        Some(text) => text.to_string(),
        None => {
            let mut text = String::from("Sections:\n");
            for section in dtk_sections(&facts.regions) {
                let _ = writeln!(
                    text,
                    "\t{:<11} type:{} align:{}",
                    section.name, section.kind, section.align
                );
            }
            text
        }
    };
    let symbols = dtk_symbols(facts, &splits, false);
    let mut symbols_txt = String::new();
    for row in &symbols.rows {
        symbols_txt.push_str(row);
        symbols_txt.push('\n');
    }
    let object = facts
        .source_path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("{}.dol", facts.program));
    let config_yml = format!(
        "name: {}\nobject: {object}\nsymbols: symbols.txt\nsplits: splits.txt\n",
        facts.program
    );
    DtkExport { config_yml, splits_txt, symbols_txt, symbols }
}

// ---------------------------------------------------------------------------
// splat
// ---------------------------------------------------------------------------

/// Platforms splat 0.39.1 ships a disassembler for.
const SPLAT_PLATFORMS: [&str; 4] = ["n64", "psx", "ps2", "psp"];

/// splat's `platform:` for a Ghidra language id. Platforms splat has no
/// disassembler for come back as `(name, false)`.
pub fn splat_platform(language: &str, regions: &[MemoryRegion]) -> (String, bool) {
    let arch = language.split(':').next().unwrap_or("").to_ascii_lowercase();
    let imported = |prefix: &str| regions.iter().any(|r| r.name.starts_with(prefix));
    let name = match arch.as_str() {
        "psx" => "psx",
        "r5900" => "ps2",
        "allegrex" => "psp",
        "mips" if language.contains(":BE:") => "n64",
        "powerpc" | "ppc" if imported("dol:") => "gc_wii",
        "arm" if imported("nds:") => "nds",
        _ => arch.as_str(),
    };
    (name.to_string(), SPLAT_PLATFORMS.contains(&name))
}

/// splat's compiler names (`splat/util/compiler.py`) a store compiler id can
/// stand for; otherwise the platform's usual one.
fn splat_compiler(platform: &str, recorded: &str) -> Option<&'static str> {
    const KNOWN: [&str; 8] = ["GCC", "SN64", "IDO", "KMC", "EGCS", "PSYQ", "MWCCPS2", "EEGCC"];
    if let Some(known) = KNOWN.iter().find(|name| name.eq_ignore_ascii_case(recorded)) {
        return Some(known);
    }
    match platform {
        "psx" | "psp" => Some("GCC"),
        "ps2" => Some("EEGCC"),
        _ => None,
    }
}

/// A byte range of the binary the loader mapped at `vaddr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backing {
    pub vaddr: u64,
    pub size: u64,
    pub file_off: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplatExport {
    pub yaml: String,
    pub symbol_addrs: String,
    pub platform: String,
    /// splat has a disassembler for the platform; when false the config
    /// declares `is_unsupported_platform` and uses only `bin` segments.
    pub supported: bool,
    pub segments: usize,
    pub symbols: usize,
}

/// One `symbol_addrs.txt` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplatSymbol {
    /// The name as written (gas-safe, unique).
    pub name: String,
    pub address: u64,
    /// `Some` for functions whose size is a whole number of words.
    pub size: Option<u64>,
    pub is_function: bool,
}

/// The rows of `symbol_addrs.txt`: functions first, then named non-external
/// symbols. splat refuses a repeated name or a second symbol at one
/// address, so both are resolved here; names are made safe to write into
/// assembly (`gas_symbol_name`).
pub fn splat_symbol_rows(facts: &ExportFacts) -> Vec<SplatSymbol> {
    let mut names = Names::default();
    let mut taken: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut rows = Vec::new();
    for function in &facts.functions {
        let address = function.entry.offset;
        if !taken.insert(address) {
            continue;
        }
        let name = names.claim(gas_symbol_name(&function.name, address), address);
        // splat's platforms are all fixed-width MIPS: a size that is not a
        // whole number of words only earns a warning, so it is left off.
        let size = (function.size % 4 == 0).then_some(function.size);
        rows.push(SplatSymbol { name, address, size, is_function: true });
    }
    for symbol in facts.symbols.iter().filter(|symbol| is_linkage_symbol(symbol)) {
        let address = symbol.address.offset;
        if symbol.external || !taken.insert(address) {
            continue;
        }
        let name = names.claim(gas_symbol_name(&symbol.name, address), address);
        rows.push(SplatSymbol { name, address, size: None, is_function: false });
    }
    rows
}

/// `name = 0xADDR; // type:func size:0x..` text for `rows`.
pub fn render_splat_symbols(rows: &[SplatSymbol]) -> String {
    let mut text = String::new();
    for row in rows {
        let (name, address) = (&row.name, row.address);
        match (row.is_function, row.size) {
            (true, Some(size)) => {
                let _ = writeln!(text, "{name} = {address:#x}; // type:func size:{size:#x}");
            }
            (true, None) => {
                let _ = writeln!(text, "{name} = {address:#x}; // type:func");
            }
            (false, _) => {
                let _ = writeln!(text, "{name} = {address:#x};");
            }
        }
    }
    text
}

/// `name = 0xADDR; // type:func size:0x..` rows and how many there are.
pub fn splat_symbol_addrs(facts: &ExportFacts) -> (String, usize) {
    let rows = splat_symbol_rows(facts);
    (render_splat_symbols(&rows), rows.len())
}

fn yaml_name(region: &str) -> String {
    region
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' { ch } else { '_' })
        .collect()
}

/// `<program>.yaml` and `symbol_addrs.txt`.
///
/// `sha1` is the target binary's SHA-1, which splat verifies; the store keeps
/// SHA-256 only, so the caller hashes the bytes it read (`sha1_hex`).
///
/// `backing` says where each mapped region sits in the file (splat's
/// `start` is a file offset, not an address). Regions with no file bytes (BSS) cannot be split and are left
/// out. Platforms splat cannot disassemble get `bin` segments only.
pub fn export_splat(
    facts: &ExportFacts,
    backing: &[Backing],
    target_path: &str,
    sha1: Option<&str>,
) -> Result<SplatExport, String> {
    let (platform, supported) = splat_platform(&facts.language, &facts.regions);
    let mut yaml = String::new();
    // splat checks the target binary against this when present.
    if let Some(sha1) = sha1 {
        let _ = writeln!(yaml, "sha1: {sha1}");
    }
    let _ = writeln!(yaml, "options:");
    let _ = writeln!(yaml, "  basename: {}", yaml_name(&facts.program));
    let _ = writeln!(yaml, "  target_path: {target_path}");
    let _ = writeln!(yaml, "  base_path: .");
    let _ = writeln!(yaml, "  platform: {platform}");
    if !supported {
        let _ = writeln!(yaml, "  is_unsupported_platform: true");
    }
    if let Some(compiler) = splat_compiler(&platform, &facts.compiler) {
        let _ = writeln!(yaml, "  compiler: {compiler}");
    }
    let _ = writeln!(yaml, "  asm_path: asm");
    let _ = writeln!(yaml, "  src_path: src");
    let _ = writeln!(yaml, "  build_path: build");
    let _ = writeln!(yaml, "  symbol_addrs_path: symbol_addrs.txt");
    let _ = writeln!(yaml, "segments:");

    // Mapped regions against the bytes backing them. One file range can be
    // mapped twice (an N64 ROM is both the cartridge window and the code
    // copied into RDRAM), so code claims its bytes first and every other
    // region keeps only what is left.
    struct Piece {
        name: String,
        code: bool,
        off: u64,
        size: u64,
        vram: u64,
    }
    let mut placed: Vec<(&MemoryRegion, Backing)> = image_regions(&facts.regions)
        .into_iter()
        .filter_map(|region| {
            backing
                .iter()
                .find(|b| b.vaddr == region.start.offset)
                .map(|b| (region, Backing { size: b.size.min(region.size), ..*b }))
        })
        .filter(|(_, b)| b.size != 0)
        .collect();
    placed.sort_by_key(|(region, b)| (!(supported && region.permissions.contains('x')), b.file_off));
    let mut claimed: Vec<(u64, u64)> = Vec::new();
    let mut pieces: Vec<Piece> = Vec::new();
    let mut used = std::collections::HashSet::new();
    for (region, b) in placed {
        let code = supported && region.permissions.contains('x');
        // The sub-ranges of [off, off+size) no earlier region claimed.
        let mut free = vec![(b.file_off, b.file_off + b.size)];
        for &(lo, hi) in &claimed {
            free = free
                .into_iter()
                .flat_map(|(start, end)| {
                    if hi <= start || lo >= end {
                        vec![(start, end)]
                    } else {
                        let mut keep = Vec::new();
                        if start < lo {
                            keep.push((start, lo));
                        }
                        if hi < end {
                            keep.push((hi, end));
                        }
                        keep
                    }
                })
                .collect();
        }
        let split = free.len() > 1;
        for (index, (start, end)) in free.into_iter().enumerate() {
            claimed.push((start, end));
            let mut name = yaml_name(&region.name);
            if split {
                name = format!("{name}_{index}");
            }
            if !used.insert(name.clone()) {
                name = format!("{name}_{start:x}");
                used.insert(name.clone());
            }
            pieces.push(Piece { name, code, off: start, size: end - start, vram: b.vaddr + (start - b.file_off) });
        }
    }
    pieces.sort_by_key(|piece| piece.off);
    let mut segments = 0;
    let mut cursor = 0u64;
    for piece in &pieces {
        // A segment runs to the next one's start: bytes between regions
        // are their own binary segment, not the tail of the previous one.
        if piece.off > cursor {
            let name = if cursor == 0 { "header".to_string() } else { format!("gap_{cursor:x}") };
            let _ = writeln!(yaml, "  - name: {name}\n    type: bin\n    start: {cursor:#x}");
            segments += 1;
        }
        if piece.code {
            let _ = writeln!(
                yaml,
                "  - name: {0}\n    type: code\n    start: {1:#x}\n    vram: {2:#x}\n    \
                 subsegments:\n      - [{1:#x}, asm, {0}]",
                piece.name, piece.off, piece.vram
            );
        } else {
            let _ = writeln!(
                yaml,
                "  - name: {}\n    type: bin\n    start: {:#x}\n    vram: {:#x}",
                piece.name, piece.off, piece.vram
            );
        }
        segments += 1;
        cursor = piece.off + piece.size;
    }
    if segments == 0 {
        return Err(format!(
            "{}: no mapped region is backed by file bytes, so there is nothing for splat to split",
            facts.program
        ));
    }
    // splat's final entry is the end offset of the last segment. It is the
    // end of the last mapped region, not of the file: what follows (symbol
    // tables, debug sections) is not part of the image and must not be
    // disassembled as the last code segment.
    let _ = writeln!(yaml, "  - [{cursor:#x}]");

    let (symbol_addrs, symbols) = splat_symbol_addrs(facts);
    Ok(SplatExport { yaml, symbol_addrs, platform, supported, segments, symbols })
}

// ---------------------------------------------------------------------------
// objdiff
// ---------------------------------------------------------------------------

/// Which units `objdiff.json` marks `complete` (linked into the verified
/// build). objdiff counts `complete_*` measures from this flag and, with it
/// set, pairs symbols differently, so it is a statement about the build the
/// store cannot make by itself: the caller says which units are complete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Complete {
    /// Every unit is written `complete: false`.
    #[default]
    None,
    All,
    /// Translation units, as named in `splits.txt` (`main.c`) or by their
    /// stem (`main`).
    Units(Vec<String>),
}

impl Complete {
    fn includes(&self, tu: &str, stem: &str) -> bool {
        match self {
            Complete::None => false,
            Complete::All => true,
            Complete::Units(list) => list.iter().any(|unit| unit == tu || unit == stem),
        }
    }
}

/// A unit dtk generated for a gap between translation units
/// (`auto_11_804E42A0_sdata2`). They exist only as target objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtkAutoUnit {
    pub name: String,
    /// File name of the object dtk wrote for it.
    pub object: String,
}

/// The `autogenerated` units of dtk's `build/<version>/config.json`.
pub fn dtk_auto_units(config_json: &str) -> std::result::Result<Vec<DtkAutoUnit>, String> {
    let config: serde_json::Value = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let units = config["units"].as_array().ok_or("dtk config.json has no units array")?;
    let mut out = Vec::new();
    for unit in units {
        if unit["autogenerated"].as_bool() != Some(true) {
            continue;
        }
        let name = unit["name"].as_str().ok_or("dtk unit without a name")?;
        let object = unit["object"].as_str().ok_or("dtk unit without an object")?;
        let file = std::path::Path::new(object)
            .file_name()
            .map(|file| file.to_string_lossy().into_owned())
            .ok_or("dtk unit object has no file name")?;
        out.push(DtkAutoUnit { name: name.to_string(), object: file });
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct ObjdiffOptions {
    /// Directory the splits' translation units live in, relative to the
    /// project (`src` for dtk-template); empty when `splits.txt` names are
    /// already project-relative.
    pub source_root: String,
    pub complete: Complete,
    pub auto_units: Vec<DtkAutoUnit>,
}

/// A unit's name is its translation unit without the source extension.
fn unit_stem(tu: &str) -> &str {
    tu.trim_end_matches(".c").trim_end_matches(".cpp")
}

/// objdiff units: one per `splits.txt` translation unit, then dtk's
/// gap-filling units when given. `paths` resolves a unit stem to its
/// `(target, base)` objects; `auto_target` a dtk object file name to its path.
pub fn objdiff_units(
    program: &str,
    functions: &[FunctionRow],
    splits: &[SplitExtent],
    options: &ObjdiffOptions,
    paths: &mut dyn FnMut(&str) -> Result<(String, String)>,
    auto_target: &dyn Fn(&str) -> String,
) -> Result<Vec<serde_json::Value>> {
    let mut units = std::collections::BTreeMap::<&str, Vec<&SplitExtent>>::new();
    for extent in splits {
        if !extent.tu.is_empty() {
            units.entry(&extent.tu).or_default().push(extent);
        }
    }
    let mut rows = Vec::with_capacity(units.len() + options.auto_units.len());
    for (tu, extents) in units {
        let stem = unit_stem(tu);
        let (target, base) = paths(stem)?;
        let names: Vec<_> = functions
            .iter()
            .filter(|function| {
                extents.iter().any(|extent| {
                    function.entry.offset >= extent.start && function.entry.offset < extent.end
                })
            })
            .map(|function| {
                serde_json::json!({
                    "name": function.name,
                    "vram": format!("{:#x}", function.entry.offset),
                    "size": function.size,
                })
            })
            .collect();
        let source_path = if options.source_root.is_empty() {
            tu.to_string()
        } else {
            format!("{}/{tu}", options.source_root.trim_end_matches('/'))
        };
        rows.push(serde_json::json!({
            "name": format!("{program}/{stem}"),
            "target_path": target,
            "base_path": base,
            "metadata": {
                "complete": options.complete.includes(tu, stem),
                "auto_generated": false,
                "source_path": source_path,
                "functions": names,
            },
        }));
    }
    for unit in &options.auto_units {
        rows.push(serde_json::json!({
            "name": format!("{program}/{}", unit_stem(&unit.name)),
            "target_path": auto_target(&unit.object),
            "metadata": {"auto_generated": true},
        }));
    }
    Ok(rows)
}

/// objdiff writes 64-bit counters as JSON strings (`"total_code": "124096"`);
/// an absent field is zero (the report is protobuf-shaped).
fn counter(value: &serde_json::Value, key: &str) -> u64 {
    match &value[key] {
        serde_json::Value::String(text) => text.parse().unwrap_or(0),
        other => other.as_u64().unwrap_or(0),
    }
}

fn percent(value: &serde_json::Value, key: &str) -> f64 {
    value[key].as_f64().unwrap_or(0.0)
}

/// The project measures an `objdiff-cli report generate` JSON implies, rolled
/// up from its units (objdiff's own `measures` is the cross-check): counters
/// are sums, the percentages are the ratios of those sums, and
/// `fuzzy_match_percent` is the unit values weighted by their code size.
/// Function rows are objdiff's `functions` arrays.
pub fn objdiff_rollup(report: &serde_json::Value) -> std::result::Result<serde_json::Value, String> {
    let units = report["units"].as_array().ok_or("report has no units array")?;
    const COUNTERS: [&str; 10] = [
        "total_code",
        "matched_code",
        "total_data",
        "matched_data",
        "total_functions",
        "matched_functions",
        "complete_code",
        "complete_data",
        "total_units",
        "complete_units",
    ];
    let mut sums = [0u64; 10];
    let mut weighted_fuzzy = 0.0f64;
    let mut rows = Vec::new();
    for unit in units {
        let measures = &unit["measures"];
        for (sum, key) in sums.iter_mut().zip(COUNTERS) {
            *sum += counter(measures, key);
        }
        weighted_fuzzy += percent(measures, "fuzzy_match_percent") * counter(measures, "total_code") as f64;
        let unit_name = unit["name"].as_str().unwrap_or("");
        for function in unit["functions"].as_array().into_iter().flatten() {
            let fuzzy = percent(function, "fuzzy_match_percent");
            let size = counter(function, "size");
            rows.push(serde_json::json!({
                "unit": unit_name,
                "function": function["name"].as_str().unwrap_or(""),
                "fuzzy_match_percent": fuzzy,
                "size": size,
                "virtual_address": function["metadata"]["virtual_address"],
            }));
        }
    }
    let ratio = |part: u64, whole: u64| if whole == 0 { 0.0 } else { part as f64 / whole as f64 * 100.0 };
    let [total_code, matched_code, total_data, matched_data, total_functions, matched_functions, complete_code, complete_data, total_units, complete_units] = sums;
    let fuzzy = if total_code == 0 { 0.0 } else { weighted_fuzzy / total_code as f64 };
    let rolled = serde_json::json!({
        "fuzzy_match_percent": fuzzy,
        "total_code": total_code,
        "matched_code": matched_code,
        "matched_code_percent": ratio(matched_code, total_code),
        "total_data": total_data,
        "matched_data": matched_data,
        "matched_data_percent": ratio(matched_data, total_data),
        "total_functions": total_functions,
        "matched_functions": matched_functions,
        "matched_functions_percent": ratio(matched_functions, total_functions),
        "complete_code": complete_code,
        "complete_code_percent": ratio(complete_code, total_code),
        "complete_data": complete_data,
        "complete_data_percent": ratio(complete_data, total_data),
        "total_units": total_units,
        "complete_units": complete_units,
    });
    let reported = &report["measures"];
    let agrees = reported.is_object()
        && COUNTERS.iter().zip(sums).all(|(key, sum)| counter(reported, key) == sum)
        && (percent(reported, "fuzzy_match_percent") - fuzzy).abs() < 1e-3;
    Ok(serde_json::json!({
        "functions": rows,
        "measures": rolled,
        "agrees_with_objdiff_measures": agrees,
    }))
}

/// `objdiff-cli report changes` for two reports: project measures before and
/// after, and every unit that was added, removed or changed with the
/// functions and sections that moved. Fields are copied from the reports, so
/// the protobuf zero-omission carries through unchanged.
pub fn objdiff_changes(previous: &serde_json::Value, current: &serde_json::Value) -> std::result::Result<serde_json::Value, String> {
    let index = |report: &serde_json::Value| -> std::result::Result<Vec<(String, serde_json::Value)>, String> {
        Ok(report["units"]
            .as_array()
            .ok_or("report has no units array")?
            .iter()
            .map(|unit| (unit["name"].as_str().unwrap_or("").to_string(), unit.clone()))
            .collect())
    };
    let (before, after) = (index(previous)?, index(current)?);
    let find = |list: &[(String, serde_json::Value)], name: &str| list.iter().find(|(n, _)| n == name).map(|(_, u)| u.clone());
    let named = |items: &serde_json::Value, key: &str| -> Vec<(String, serde_json::Value)> {
        items.as_array().into_iter().flatten().map(|item| (item[key].as_str().unwrap_or("").to_string(), item.clone())).collect()
    };
    // Changed rows of one array (`functions` or `sections`), keyed by name.
    let moves = |from: &serde_json::Value, to: &serde_json::Value| -> Vec<serde_json::Value> {
        let (old, new) = (named(from, "name"), named(to, "name"));
        let strip = |item: &serde_json::Value| {
            let mut copy = item.clone();
            if let Some(map) = copy.as_object_mut() {
                map.remove("name");
                map.remove("metadata");
                // objdiff's `changes` leaves the in-section offset out.
                map.remove("address");
            }
            copy
        };
        let mut out = Vec::new();
        for (name, was) in &old {
            let now = new.iter().find(|(n, _)| n == name).map(|(_, v)| v);
            if now.is_some_and(|now| strip(now) == strip(was)) {
                continue;
            }
            let mut row = serde_json::json!({"name": name, "from": strip(was)});
            if let Some(now) = now {
                row["to"] = strip(now);
            }
            row["metadata"] = was["metadata"].clone();
            out.push(row);
        }
        for (name, now) in &new {
            if old.iter().all(|(n, _)| n != name) {
                out.push(serde_json::json!({"name": name, "to": strip(now), "metadata": now["metadata"]}));
            }
        }
        out
    };
    let mut units = Vec::new();
    for (name, was) in &before {
        let now = find(&after, name);
        let mut row = serde_json::json!({"name": name, "from": was["measures"]});
        let empty = serde_json::json!([]);
        let (functions, sections) = match &now {
            Some(now) => {
                if now["measures"] == was["measures"]
                    && moves(&was["functions"], &now["functions"]).is_empty()
                    && moves(&was["sections"], &now["sections"]).is_empty()
                {
                    continue;
                }
                row["to"] = now["measures"].clone();
                (moves(&was["functions"], &now["functions"]), moves(&was["sections"], &now["sections"]))
            }
            None => (moves(&was["functions"], &empty), moves(&was["sections"], &empty)),
        };
        if !sections.is_empty() {
            row["sections"] = sections.into();
        }
        if !functions.is_empty() {
            row["functions"] = functions.into();
        }
        row["metadata"] = now.as_ref().unwrap_or(was)["metadata"].clone();
        units.push(row);
    }
    for (name, now) in &after {
        if find(&before, name).is_some() {
            continue;
        }
        let empty = serde_json::json!([]);
        let mut row = serde_json::json!({"name": name, "to": now["measures"]});
        let (functions, sections) = (moves(&empty, &now["functions"]), moves(&empty, &now["sections"]));
        if !sections.is_empty() {
            row["sections"] = sections.into();
        }
        if !functions.is_empty() {
            row["functions"] = functions.into();
        }
        row["metadata"] = now["metadata"].clone();
        units.push(row);
    }
    let mut changes = serde_json::json!({"from": previous["measures"], "to": current["measures"]});
    // Like objdiff's own output, an empty list is not written.
    if !units.is_empty() {
        changes["units"] = units.into();
    }
    Ok(changes)
}

/// The mappings whose bytes are the file's own bytes at `file_off`, as
/// `Backing`. A mapping the loader unpacked (an N64 game's compressed
/// segments) has no byte range in the file for splat to disassemble: its
/// `file_off` names where the packed form starts, so claiming it would make
/// splat read compressed bytes as code. Such a mapping is left out, and its
/// range stays a `bin` segment.
pub fn file_backing(mappings: &[crate::native::Mapping], file: &[u8]) -> Vec<Backing> {
    mappings
        .iter()
        .filter(|mapping| !mapping.bytes.is_empty())
        .filter(|mapping| {
            usize::try_from(mapping.file_off)
                .ok()
                .and_then(|start| file.get(start..start.checked_add(mapping.bytes.len())?))
                == Some(mapping.bytes.as_slice())
        })
        .map(|mapping| Backing { vaddr: mapping.vaddr, size: mapping.size, file_off: mapping.file_off })
        .collect()
}

/// SHA-1 as 40 lowercase hex digits: splat's `sha1:` option is its only
/// consumer, and it is an identity check, not a security property.
pub fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    use std::fmt::Write as _;
    Sha1::digest(data).iter().fold(String::with_capacity(40), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::Address;

    #[test]
    fn unpacked_mappings_are_not_file_backing() {
        use crate::native::Mapping;
        let file: Vec<u8> = (0..64u8).collect();
        let mapping = |vaddr, file_off, bytes: Vec<u8>| Mapping {
            vaddr,
            size: bytes.len() as u64,
            file_off,
            flags: 6,
            bytes,
        };
        let backing = file_backing(
            &[
                mapping(0x8000_0000, 16, file[16..32].to_vec()),
                // The packed form starts at 32, but these bytes are what it inflates to.
                mapping(0x7000_0000, 32, vec![0xEE; 16]),
                mapping(0x9000_0000, 60, file[60..64].to_vec()),
                mapping(0xA000_0000, 0, Vec::new()),
            ],
            &file,
        );
        assert_eq!(
            backing,
            vec![
                Backing { vaddr: 0x8000_0000, size: 16, file_off: 16 },
                Backing { vaddr: 0x9000_0000, size: 4, file_off: 60 },
            ]
        );
    }

    fn region(name: &str, start: u64, size: u64, permissions: &str) -> MemoryRegion {
        MemoryRegion {
            name: name.into(),
            start: Address::ram(start),
            size,
            permissions: permissions.into(),
            source: "native-import".into(),
        }
    }

    fn function(name: &str, entry: u64, size: u64) -> FunctionRow {
        FunctionRow {
            entry: Address::ram(entry),
            name: name.into(),
            size,
            signature: None,
            traced: false,
            calling_convention: None,
        }
    }

    /// bond.dol's region layout (12 sections, `dol:N` names).
    fn gc_regions() -> Vec<MemoryRegion> {
        let layout: [(u64, u64, &str); 12] = [
            (0x8000_7100, 0x22e0, "r-x"),
            (0x8000_93e0, 0x60, "rw-"),
            (0x8000_9440, 0x60, "rw-"),
            (0x8000_94a0, 0x21_f860, "r-x"),
            (0x8022_8d00, 0x200, "rw-"),
            (0x8022_8f00, 0x20, "rw-"),
            (0x8022_8f20, 0x1_4a60, "rw-"),
            (0x8023_d980, 0x5_3d40, "rw-"),
            (0x8029_16c0, 0x25_1980, "rw-"),
            (0x804e_3040, 0x440, "rw-"),
            (0x804e_3480, 0xe04, "rw-"),
            (0x804e_42a0, 0x2b20, "rw-"),
        ];
        layout
            .iter()
            .enumerate()
            .map(|(i, (start, size, perms))| region(&format!("dol:{i}"), *start, *size, perms))
            .collect()
    }

    fn gc_facts() -> ExportFacts {
        ExportFacts {
            program: "bond".into(),
            language: "PowerPC:BE:32:Gekko_Broadway".into(),
            compiler: "mwcc".into(),
            source_path: Some("/orig/GQFE78/bond.dol".into()),
            functions: vec![
                function("FUN_80007100", 0x8000_7100, 0x40),
                function("FUN_800073da", 0x8000_73da, 0x2d),
                function("FUN_800094a0", 0x8000_94a0, 0x10),
            ],
            symbols: vec![],
            strings: vec![
                StringRow { address: Address::ram(0x8022_8f26), value: "toggle".into(), kind: "ASCII".into() },
                StringRow { address: Address::ram(0x8000_9403), value: "x".into(), kind: "UTF-16BE".into() },
                // Swept but never referenced, and a UTF-8 table misread.
                StringRow { address: Address::ram(0x8022_8f31), value: "cvarlist".into(), kind: "ASCII".into() },
                StringRow { address: Address::ram(0x806a_4951), value: "iq\u{200}ir".into(), kind: "UTF-8".into() },
            ],
            referenced: [0x8022_8f26, 0x806a_4951].into_iter().collect(),
            regions: gc_regions(),
            contexts: vec![],
        }
    }

    /// A derived display name is what a reader sees, never what dtk links:
    /// the vtable keeps its `__vt__` spelling in the export whichever row the
    /// store lists first.
    #[test]
    fn derived_display_names_are_not_exported_in_place_of_the_mangled_name() {
        let symbol = |name: &str, source: &str| SymbolRow {
            name: name.into(),
            address: Address::ram(0x8022_8f20),
            external: false,
            source: source.into(),
        };
        let mut facts = gc_facts();
        facts.symbols = vec![
            symbol("UberBond::__vtable", crate::qualified_prototypes::mangled::DISPLAY_SOURCE),
            symbol("typeinfo", crate::native::DEMANGLE_SOURCE),
            symbol("__vt__8UberBond", "native-import:elf-object"),
        ];
        let dtk = export_dtk(&facts, None).symbols_txt;
        assert!(dtk.contains("__vt__8UberBond = "), "{dtk}");
        assert!(!dtk.contains("UberBond___vtable") && !dtk.contains("typeinfo"), "{dtk}");
        let (splat, _) = splat_symbol_addrs(&facts);
        assert!(splat.contains("__vt__8UberBond = 0x80228f20;"), "{splat}");
    }

    #[test]
    fn dtk_names_a_mwcc_dol_like_dtk_does() {
        let names: Vec<_> = dtk_sections(&gc_regions()).into_iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            [
                ".init", "extab", "extabindex", ".text", ".ctors", ".dtors", ".rodata", ".data",
                ".bss", ".sdata", ".sbss", ".sdata2"
            ]
        );
    }

    #[test]
    fn dtk_section_names_carry_no_colon() {
        // `dol:0` made dtk read `0` as a unit attribute.
        let mut regions = gc_regions();
        regions.truncate(5);
        let sections = dtk_sections(&regions);
        assert!(sections.iter().all(|s| !s.name.contains(':')), "{sections:?}");
        let facts = ExportFacts { regions, ..gc_facts() };
        let export = export_dtk(&facts, None);
        assert!(!export.splits_txt.contains("dol:"), "{}", export.splits_txt);
        assert!(!export.symbols_txt.contains("dol:"), "{}", export.symbols_txt);
    }

    #[test]
    fn dtk_skeleton_has_no_padded_extents_and_a_clean_sections_block() {
        let export = export_dtk(&gc_facts(), None);
        assert_eq!(
            export.splits_txt.lines().next(),
            Some("Sections:"),
            "{}",
            export.splits_txt
        );
        // No `start:`/`end:` row: the region sizes are DOL-padded and dtk
        // rejects an extent past its own (trimmed) section end.
        assert!(!export.splits_txt.contains("start:"), "{}", export.splits_txt);
        assert!(export.splits_txt.contains("\t.init       type:code align:4\n"));
        assert!(export.config_yml.contains("object: bond.dol\n"));
    }

    #[test]
    fn dtk_rows_use_real_section_names_and_data_symbols() {
        let export = export_dtk(&gc_facts(), None);
        let rows: Vec<&str> = export.symbols_txt.lines().collect();
        assert!(
            rows.contains(&"FUN_80007100 = .init:0x80007100; // type:function size:0x40 scope:global"),
            "{rows:?}"
        );
        assert!(
            rows.contains(&"FUN_800094a0 = .text:0x800094a0; // type:function size:0x10 scope:global"),
            "{rows:?}"
        );
        // The ASCII literal is an object sized with its NUL; UTF-16 is not
        // guessed at.
        assert!(
            rows.contains(&"str_80228F26 = .rodata:0x80228f26; // type:object size:0x7 scope:local data:string"),
            "{rows:?}"
        );
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!((export.symbols.functions, export.symbols.objects), (2, 1));
    }

    #[test]
    fn dtk_skips_powerpc_functions_that_are_not_whole_words() {
        let mut facts = gc_facts();
        // bond.dol's FUN_80682370-style tail: aligned entry, size 9.
        facts.functions.push(function("FUN_80007200", 0x8000_7200, 9));
        let export = export_dtk(&facts, None);
        assert_eq!(export.symbols.rejected, [0x8000_73da, 0x8000_7200]);
        assert!(!export.symbols_txt.contains("800073da"));
        assert!(!export.symbols_txt.contains("80007200"));
    }

    #[test]
    fn dtk_keeps_repeated_local_names_and_lossless_keeps_every_function() {
        let mut facts = gc_facts();
        facts.functions = vec![
            function("OnReset", 0x8000_7100, 0x10),
            function("OnReset", 0x8000_94a0, 0x10),
            function("__start", 0x8000_7200, 1),
        ];
        let strict = dtk_symbols(&facts, &[], false);
        assert!(strict.rows.contains(&"OnReset = .init:0x80007100; // type:function size:0x10 scope:global".to_string()));
        assert!(strict.rows.contains(&"OnReset = .text:0x800094a0; // type:function size:0x10 scope:global".to_string()));
        assert_eq!(strict.rejected, [0x8000_7200]);
        let lossless = dtk_symbols(&facts, &[], true);
        assert!(lossless.rejected.is_empty());
        assert!(lossless.rows.contains(&"__start = .init:0x80007200; // type:function size:0x1 scope:global".to_string()));
    }

    #[test]
    fn dtk_passes_projects_splits_through_and_names_from_them() {
        let splits = "Sections:\n\t.init type:code align:4\n\t.text type:code align:4\n\nmain.c:\n\t.text start:0x800094A0 end:0x80009EB8\n";
        let export = export_dtk(&gc_facts(), Some(splits));
        assert_eq!(export.splits_txt, splits);
        assert!(export.symbols_txt.contains("FUN_800094a0 = .text:0x800094a0;"));
    }

    #[test]
    fn dtk_rewrites_names_the_grammar_cannot_hold() {
        let mut facts = gc_facts();
        facts.functions = vec![function("operator new (unsigned long)", 0x8000_7100, 8)];
        let rows = export_dtk(&facts, None).symbols_txt;
        assert!(rows.starts_with("operator_new_(unsigned_long) = .init:0x80007100;"), "{rows}");
    }

    #[test]
    fn splat_symbol_addrs_use_the_name_equals_address_grammar() {
        let mut facts = gc_facts();
        facts.functions = vec![
            function("FUN_020001ba", 0x0200_01ba, 0x10),
            function("std::exception::~exception[base]()", 0x0200_0200, 0x20),
            function("FUN_020001ba", 0x0200_0300, 0x20),
            function("alias_of_first", 0x0200_01ba, 0x10),
            // 0xad is not a whole number of MIPS words.
            function("psx_entry", 0x0200_0400, 0xad),
        ];
        let (text, count) = splat_symbol_addrs(&facts);
        let rows: Vec<&str> = text.lines().collect();
        assert_eq!(rows[0], "FUN_020001ba = 0x20001ba; // type:func size:0x10");
        // Names are written into assembly: anything gas does not take in a
        // plain symbol (`:`, `<>*`, `~`, brackets, parentheses) becomes `_`.
        assert_eq!(rows[1], "std__exception___exception_base___ = 0x2000200; // type:func size:0x20");
        // A repeated name and a second symbol at one address are both errors
        // in splat's loader.
        assert_eq!(rows[2], "FUN_020001ba_02000300 = 0x2000300; // type:func size:0x20");
        assert_eq!(rows[3], "psx_entry = 0x2000400; // type:func");
        assert_eq!(count, 4, "{text}");
        for row in &rows {
            assert_eq!(row.matches(';').count(), 1, "{row}");
            assert!(row.contains(" = 0x"), "{row}");
        }
    }

    #[test]
    fn gas_symbol_names_are_plain_and_never_start_like_a_register_or_local_label() {
        assert_eq!(gas_symbol_name("Alloc__18CDataAlloc<1,6000>::Fv", 0x100000), "Alloc__18CDataAlloc_1_6000___Fv");
        assert_eq!(gas_symbol_name("cmdTypeAndStatus$371", 0x100000), "cmdTypeAndStatus$371");
        assert_eq!(gas_symbol_name("$LC0", 0x100000), "_$LC0");
        assert_eq!(gas_symbol_name(".L123", 0x100000), "_.L123");
        assert_eq!(gas_symbol_name("2fast", 0x100000), "_2fast");
        assert_eq!(gas_symbol_name("", 0x100000), "sym_00100000");
    }

    fn psx_facts() -> ExportFacts {
        let mut text = region("psx:text", 0x8013_2000, 0x6_4800, "rwx");
        text.source = "native-import".into();
        let mut ram = region("psx:main-ram", 0x8000_0000, 0x20_0000, "rwx");
        ram.source = "native-import:platform-map".into();
        ExportFacts {
            program: "ds3".into(),
            language: "PSX:LE:32:default".into(),
            functions: vec![function("FUN_80132000", 0x8013_2000, 0x20)],
            regions: vec![ram, text],
            ..Default::default()
        }
    }

    #[test]
    fn splat_yaml_for_psx_is_a_valid_platform_with_a_code_segment() {
        let facts = psx_facts();
        let backing = [Backing { vaddr: 0x8013_2000, size: 0x6_4800, file_off: 0x800 }];
        let export = export_splat(&facts, &backing, "VS.EXE", None).unwrap();
        assert_eq!((export.platform.as_str(), export.supported), ("psx", true));
        let yaml = &export.yaml;
        assert!(yaml.contains("  platform: psx\n"), "{yaml}");
        assert!(!yaml.contains("gc_wii") && !yaml.contains("GC/1.2.5"), "{yaml}");
        assert!(yaml.contains("  compiler: GCC\n"), "{yaml}");
        assert!(!yaml.contains("files: []"), "{yaml}");
        assert!(yaml.contains("    subsegments:\n      - [0x800, asm, psx_text]\n"), "{yaml}");
        // The segment starts at its file offset, not its address.
        assert!(yaml.contains("    start: 0x800\n    vram: 0x80132000\n"), "{yaml}");
        assert!(yaml.contains("  - name: header\n    type: bin\n    start: 0x0\n"), "{yaml}");
        assert!(yaml.trim_end().ends_with("  - [0x65000]"), "{yaml}");
        assert_eq!(export.symbol_addrs, "FUN_80132000 = 0x80132000; // type:func size:0x20\n");
    }

    #[test]
    fn splat_closes_at_the_last_mapped_region_not_the_file() {
        // SLUS_209.50: code at file 0x80, a BSS-only region, then 8 MB of
        // symbols and debug sections no segment may swallow.
        let facts = ExportFacts {
            program: "slus".into(),
            language: "r5900:LE:32:default".into(),
            regions: vec![
                region("irx:0", 0x10_0000, 0x22_a400, "rwx"),
                region("irx:1", 0x32_a400, 0xd_ea80, "rwx"),
            ],
            ..Default::default()
        };
        let backing = [Backing { vaddr: 0x10_0000, size: 0x22_a400, file_off: 0x80 }];
        let export = export_splat(&facts, &backing, "SLUS_209.50", None).unwrap();
        assert_eq!(export.platform, "ps2");
        assert!(export.yaml.contains("  compiler: EEGCC\n"), "{}", export.yaml);
        assert!(export.yaml.trim_end().ends_with("  - [0x22a480]"), "{}", export.yaml);
        assert!(!export.yaml.contains("irx_1"), "{}", export.yaml);
        assert_eq!(export.segments, 2);
    }

    #[test]
    fn splat_gives_overlapping_views_of_one_file_range_to_the_code() {
        // N64: the cartridge window maps the whole ROM; the boot code maps
        // the same bytes again at RDRAM. Code keeps its bytes, the cartridge
        // keeps the rest as two binary pieces.
        let facts = ExportFacts {
            program: "pd".into(),
            language: "MIPS:BE:64:64-32addr".into(),
            regions: vec![
                region("n64:code", 0x8000_1000, 0x7f_f000, "rwx"),
                region("n64:cartridge", 0x1000_0000, 0x200_0000, "r--"),
            ],
            ..Default::default()
        };
        let backing = [
            Backing { vaddr: 0x8000_1000, size: 0x7f_f000, file_off: 0x1000 },
            Backing { vaddr: 0x1000_0000, size: 0x200_0000, file_off: 0 },
        ];
        let export = export_splat(&facts, &backing, "pd.z64", None).unwrap();
        assert_eq!((export.platform.as_str(), export.segments), ("n64", 3));
        let yaml = &export.yaml;
        assert!(yaml.contains("  - name: n64_cartridge_0\n    type: bin\n    start: 0x0\n    vram: 0x10000000\n"), "{yaml}");
        assert!(yaml.contains("  - name: n64_code\n    type: code\n    start: 0x1000\n    vram: 0x80001000\n"), "{yaml}");
        assert!(yaml.contains("  - name: n64_cartridge_1\n    type: bin\n    start: 0x800000\n    vram: 0x10800000\n"), "{yaml}");
        assert!(yaml.trim_end().ends_with("  - [0x2000000]"), "{yaml}");
    }

    #[test]
    fn splat_fills_a_gap_between_regions_with_its_own_segment() {
        let facts = ExportFacts {
            program: "g".into(),
            language: "PSX:LE:32:default".into(),
            regions: vec![region("a", 0x8000_0000, 0x100, "rwx"), region("b", 0x8000_1000, 0x100, "rw-")],
            ..Default::default()
        };
        let backing = [
            Backing { vaddr: 0x8000_0000, size: 0x100, file_off: 0x800 },
            Backing { vaddr: 0x8000_1000, size: 0x100, file_off: 0xa00 },
        ];
        let yaml = export_splat(&facts, &backing, "g.exe", None).unwrap().yaml;
        assert!(yaml.contains("  - name: gap_900\n    type: bin\n    start: 0x900\n"), "{yaml}");
        assert!(yaml.trim_end().ends_with("  - [0xb00]"), "{yaml}");
    }

    #[test]
    fn splat_yaml_carries_the_binarys_sha1() {
        let backing = [Backing { vaddr: 0x8013_2000, size: 0x6_4800, file_off: 0x800 }];
        let sha1 = sha1_hex(b"abc");
        assert_eq!(sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        let yaml = export_splat(&psx_facts(), &backing, "VS.EXE", Some(&sha1)).unwrap().yaml;
        assert!(yaml.starts_with("sha1: a9993e364706816aba3e25717850c26c9cd0d89d\noptions:\n"), "{yaml}");
    }

    #[test]
    fn splat_declares_platforms_it_cannot_disassemble() {
        let (platform, supported) = splat_platform("PowerPC:BE:32:Gekko_Broadway", &gc_regions());
        assert_eq!((platform.as_str(), supported), ("gc_wii", false));
        let facts = gc_facts();
        let backing = [Backing { vaddr: 0x8000_7100, size: 0x22e0, file_off: 0x100 }];
        let export = export_splat(&facts, &backing, "bond.dol", None).unwrap();
        assert!(export.yaml.contains("  platform: gc_wii\n  is_unsupported_platform: true\n"), "{}", export.yaml);
        assert!(!export.yaml.contains("compiler:"), "{}", export.yaml);
        assert!(!export.yaml.contains("type: code"), "{}", export.yaml);
    }

    #[test]
    fn splat_refuses_an_image_with_no_file_backing() {
        let err = export_splat(&psx_facts(), &[], "VS.EXE", None).unwrap_err();
        assert!(err.contains("nothing for splat to split"), "{err}");
    }

    #[test]
    fn splat_maps_languages_to_platforms() {
        let none: [MemoryRegion; 0] = [];
        for (language, expect) in [
            ("PSX:LE:32:default", ("psx", true)),
            ("r5900:LE:32:default", ("ps2", true)),
            ("Allegrex:LE:32:default", ("psp", true)),
            ("MIPS:BE:64:64-32addr", ("n64", true)),
            ("ARM:LE:32:v5t", ("arm", false)),
        ] {
            let (name, supported) = splat_platform(language, &none);
            assert_eq!((name.as_str(), supported), expect, "{language}");
        }
    }

    #[test]
    fn objdiff_units_carry_complete_and_project_relative_source() {
        let extent = |tu: &str, start, end| SplitExtent {
            name: ".text".into(),
            start,
            end,
            kind: "code".into(),
            tu: tu.into(),
        };
        let splits = [extent("cvar.c", 0x800094a0, 0x80009eb8), extent("main.c", 0x8000b110, 0x8000d4a0)];
        let functions = [function("cvar_init", 0x800094a0, 0x20), function("main", 0x8000b110, 0x40)];
        let mut paths = |stem: &str| Ok((format!("obj/{stem}.o"), format!("src/{stem}.o")));
        let auto = |object: &str| format!("obj/{object}");
        let options = ObjdiffOptions {
            source_root: "src".into(),
            complete: Complete::Units(vec!["main".into()]),
            auto_units: vec![DtkAutoUnit {
                name: "auto_03_80009EB8_text".into(),
                object: "auto_03_80009EB8_text.o".into(),
            }, DtkAutoUnit {
                name: "__init_cpp_exceptions.cpp".into(),
                object: "__init_cpp_exceptions.cpp.o".into(),
            }],
        };
        let rows = objdiff_units("bond", &functions, &splits, &options, &mut paths, &auto).unwrap();
        assert_eq!(rows.len(), 4);
        // dtk names a split-out source unit with its extension; the objdiff
        // unit does not carry it.
        assert_eq!(rows[3]["name"], "bond/__init_cpp_exceptions");
        assert_eq!(rows[3]["target_path"], "obj/__init_cpp_exceptions.cpp.o");
        assert_eq!(rows[0]["name"], "bond/cvar");
        assert_eq!(rows[0]["metadata"]["source_path"], "src/cvar.c");
        assert_eq!(rows[0]["metadata"]["complete"], false);
        assert_eq!(rows[1]["metadata"]["complete"], true);
        assert_eq!(rows[1]["target_path"], "obj/main.o");
        assert_eq!(rows[1]["base_path"], "src/main.o");
        // Gap units are target-only and not complete-able.
        assert_eq!(rows[2]["name"], "bond/auto_03_80009EB8_text");
        assert_eq!(rows[2]["target_path"], "obj/auto_03_80009EB8_text.o");
        assert!(rows[2].get("base_path").is_none());
        assert_eq!(rows[2]["metadata"]["auto_generated"], true);
        assert!(rows[2]["metadata"].get("complete").is_none());
    }

    #[test]
    fn objdiff_complete_defaults_to_an_explicit_false() {
        let splits = [SplitExtent {
            name: ".text".into(),
            start: 0,
            end: 4,
            kind: "code".into(),
            tu: "a.c".into(),
        }];
        let mut paths = |stem: &str| Ok((format!("t/{stem}.o"), format!("b/{stem}.o")));
        let rows = objdiff_units("p", &[], &splits, &ObjdiffOptions::default(), &mut paths, &|o| o.into()).unwrap();
        assert_eq!(rows[0]["metadata"]["complete"], false);
        assert_eq!(rows[0]["metadata"]["source_path"], "a.c");
    }

    #[test]
    fn dtk_config_json_yields_only_the_autogenerated_units() {
        let json = r#"{"units":[
            {"object":"build/GQFE78/obj/cvar.o","name":"cvar.c","autogenerated":false},
            {"object":"build/GQFE78/obj/auto_11_804E42A0_sdata2.o","name":"auto_11_804E42A0_sdata2","autogenerated":true}]}"#;
        let units = dtk_auto_units(json).unwrap();
        assert_eq!(
            units,
            [DtkAutoUnit {
                name: "auto_11_804E42A0_sdata2".into(),
                object: "auto_11_804E42A0_sdata2.o".into()
            }]
        );
        assert!(dtk_auto_units("{}").is_err());
    }

    fn unit(name: &str, matched: u64, fuzzy: f64, functions: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "measures": {"fuzzy_match_percent": fuzzy, "total_code": "100", "matched_code": matched.to_string(),
                         "total_functions": 1, "matched_functions": u64::from(matched == 100), "total_units": 1},
            "functions": functions,
        })
    }

    #[test]
    fn objdiff_rollup_reads_the_functions_key_and_string_counters() {
        let report = serde_json::json!({
            "measures": {"fuzzy_match_percent": 75.0, "total_code": "200", "matched_code": "100",
                         "total_functions": 2, "matched_functions": 1, "total_units": 2},
            "units": [
                unit("p/a", 100, 100.0, serde_json::json!([{"name": "fa", "size": "100", "fuzzy_match_percent": 100.0, "metadata": {"virtual_address": "1"}}])),
                unit("p/b", 0, 50.0, serde_json::json!([{"name": "fb", "size": "100", "fuzzy_match_percent": 50.0}])),
            ],
        });
        let rolled = objdiff_rollup(&report).unwrap();
        assert_eq!(rolled["measures"]["total_code"], 200);
        assert_eq!(rolled["measures"]["matched_code"], 100);
        assert_eq!(rolled["measures"]["matched_functions"], 1);
        assert_eq!(rolled["measures"]["fuzzy_match_percent"], 75.0);
        assert_eq!(rolled["functions"].as_array().unwrap().len(), 2);
        assert_eq!(rolled["functions"][1]["function"], "fb");
        assert_eq!(rolled["agrees_with_objdiff_measures"], true);
    }

    #[test]
    fn objdiff_changes_list_added_removed_and_moved_units() {
        let f = |fuzzy: f64| serde_json::json!([{"name": "f", "size": "100", "fuzzy_match_percent": fuzzy}]);
        let old = serde_json::json!({"measures": {"total_code": "300"}, "units": [
            unit("p/same", 100, 100.0, f(100.0)),
            unit("p/moved", 100, 100.0, f(100.0)),
            unit("p/gone", 0, 0.0, f(0.0)),
        ]});
        let new = serde_json::json!({"measures": {"total_code": "300"}, "units": [
            unit("p/same", 100, 100.0, f(100.0)),
            unit("p/moved", 0, 40.0, f(40.0)),
            unit("p/new", 100, 100.0, f(100.0)),
        ]});
        let changes = objdiff_changes(&old, &new).unwrap();
        let names: Vec<_> = changes["units"].as_array().unwrap().iter().map(|u| u["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["p/moved", "p/gone", "p/new"]);
        let moved = &changes["units"][0];
        assert_eq!(moved["from"]["matched_code"], "100");
        assert_eq!(moved["to"]["matched_code"], "0");
        assert_eq!(moved["functions"][0]["from"]["fuzzy_match_percent"], 100.0);
        assert_eq!(moved["functions"][0]["to"]["fuzzy_match_percent"], 40.0);
        assert!(changes["units"][1].get("to").is_none());
        assert!(changes["units"][2].get("from").is_none());
        assert_eq!(changes["from"]["total_code"], "300");
        let same = objdiff_changes(&old, &old).unwrap();
        assert!(same.get("units").is_none(), "{same}");
    }
}
