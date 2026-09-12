//! Linker MAP readers: the image's own symbol table from the other side.
//!
//! One `--map` flag, five grammars, sniffed rather than named:
//!
//! * **mwldarm / mwldeppc** (CodeWarrior DS/GBA/GC/Wii): `N](name,type)
//!   found in local|global TU` link rows, `# .subsection` layout headers,
//!   `(lib.a member.o)` archive TUs, CRLF. dtk's `src/util/map.rs` models
//!   the same sections with `N] name (type,vis)` rows; both shapes parse.
//! * **PsyQ / SN** (PSX): `Start Stop Length Obj Group Section` extent
//!   table, then `Address  Names alphabetically` / `in address order`
//!   lists of bare `ADDR NAME` rows. No types: a name inside a `text`
//!   group's extent is code, anything else is data.
//! * **GNU ld** (agbcc GBA, homebrew): `file.o(input)` context lines,
//!   `ADDR NAME` symbol rows, `NAME = value` assignments (skipped: they
//!   are constants, not addresses), `*fill*` padding (skipped).
//! * **MSVC** (`Rva+Base` column): `seg:off name rva+base flag obj` rows;
//!   flag `f` is a function, anything else data.
//! * **flat** (`ADDR NAME` per line, e.g. 3DS `symbols.map`): everything
//!   code; the executable-mapping gate at apply time does the filtering.
//!
//! Kind precedence where a grammar types rows (mwldarm): link-map
//! `func`/`object` is the linker's own word and wins; `notype`/absent
//! falls through to the section heuristic, because the link map lists
//! globals only and a static function exists solely as a layout row.

use std::collections::HashMap;
use std::path::Path;

/// What a MAP row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Func,
    Object,
    /// A name with no type claim (PSX/PS2 .SYM rows): code when the
    /// address is executable, a bare name otherwise.
    Sym,
    NoType,
}

/// One MAP record: a name on an address, with the kind the grammar gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSymbol {
    /// Linked address (0 means unplaced).
    pub address: u64,
    /// Linker size; grammars without sizes carry 0.
    pub size: u64,
    /// Symbol name, as linked.
    pub name: String,
    pub kind: MapKind,
    /// Translation unit / object file, when the grammar records one.
    pub tu: String,
    /// Section the row appeared under, when recorded.
    pub section: String,
    /// `# .subsection` / group the row appeared under, for overlay scoping.
    pub subsection: String,
    /// Linker-defined row (command-file symbol, not linked code).
    pub linker_defined: bool,
}

/// A parsed MAP: records plus memory-map extents.
#[derive(Debug, Clone, Default)]
pub struct LinkerMap {
    pub symbols: Vec<MapSymbol>,
    /// `(name, vaddr, size)` memory-map rows where the grammar has them.
    pub memory: Vec<(String, u64, u64)>,
}

fn is_hex_word(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_data_section(section: &str) -> bool {
    matches!(
        section,
        ".rodata" | ".data" | ".bss" | ".sdata" | ".sdata2" | ".sbss" | ".sbss2"
    ) || section.ends_with(".bss")
        || section.ends_with("_data")
        || section.ends_with(".rodata")
        || section.ends_with(".data")
}

fn is_code_section(section: &str) -> bool {
    section == ".text"
        || section == ".init"
        || section == "text"
        || section.starts_with(".text.")
        || section.ends_with(".text")
}

// ---------------------------------------------------------------- mwldarm

/// mwldarm link-map entry: `(name, kind, TU)`, or `None` for generated /
/// duplicate / not-found lines. Accepts `N](name,type)` and dtk's
/// `N] name (type,vis)`.
fn parse_mw_link_row(line: &str) -> Option<(String, String, MapKind)> {
    let trimmed = line.trim();
    if trimmed.starts_with(">>>") || trimmed.contains("found as linker generated symbol") {
        return None;
    }
    let bracket = trimmed.find(']')?;
    if !trimmed[..bracket].trim().chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let rest = trimmed[bracket + 1..].trim_start();
    let found = rest.find(" found in ")?;
    let (left, after) = rest.split_at(found);
    let after = after.strip_prefix(" found in ")?;
    let mut words = after.split_whitespace();
    let visibility = words.next()?;
    if visibility != "local" && visibility != "global" {
        return None;
    }
    let tu = words.next()?.to_string();
    let left = left.trim_end();
    let (name, kind) = if let Some(inner) =
        left.strip_prefix('(').and_then(|s| s.strip_suffix(')'))
    {
        // mwldarm `(name,type)`.
        let (name, kind) = inner.split_once(',')?;
        (name.trim(), kind.trim())
    } else if let Some(paren) = left.rfind('(') {
        // dtk `name (type,visibility)`: the type leads.
        let name = left[..paren].trim_end();
        let inner = left[paren + 1..].strip_suffix(')')?;
        let (kind, _) = inner.split_once(',').unwrap_or((inner, ""));
        (name, kind.trim())
    } else {
        return None;
    };
    if name.is_empty() {
        return None;
    }
    let kind = match kind {
        "func" => MapKind::Func,
        "object" => MapKind::Object,
        _ => MapKind::NoType,
    };
    Some((name.to_string(), tu, kind))
}

/// mwldarm layout row: `(address, size, section, name, tu)`.
fn parse_mw_layout_row(line: &str) -> Option<(u64, u64, String, String, String)> {
    let body = line.strip_prefix("  ")?;
    if body.starts_with(' ') || body.starts_with('#') {
        return None;
    }
    let mut fields = body.split_whitespace();
    let addr_word = fields.next()?;
    let size_word = fields.next()?;
    if !is_hex_word(addr_word) || addr_word.len() != 8 || !is_hex_word(size_word) {
        return None;
    }
    let address = u64::from_str_radix(addr_word, 16).ok()?;
    let size = u64::from_str_radix(size_word, 16).ok()?;
    let rest = body[addr_word.len() + 1 + size_word.len() + 1..].trim_start();
    let (before_tu, tu) = match rest.rfind('(') {
        Some(open) if rest.ends_with(')') => {
            (rest[..open].trim_end(), rest[open + 1..rest.len() - 1].trim())
        }
        _ => return None,
    };
    let mut words = before_tu.split_whitespace();
    let first = words.next()?;
    // A section is a leading dotted word with a name behind it; anything
    // else is a section-less row (`Exception Table Index ()`).
    let (section, name) = if first.starts_with('.') && words.next().is_some() {
        (first.to_string(), before_tu[first.len()..].trim_start().to_string())
    } else {
        (String::new(), before_tu.to_string())
    };
    if name.is_empty() {
        return None;
    }
    Some((address, size, section, name, tu.to_string()))
}

/// `#>ADDR NAME (linker command file)` linker-defined row.
fn parse_mw_linker_defined(line: &str) -> Option<(u64, String)> {
    let body = line.strip_prefix("#>")?;
    let mut fields = body.split_whitespace();
    let addr_word = fields.next()?;
    if !is_hex_word(addr_word) {
        return None;
    }
    let address = u64::from_str_radix(addr_word, 16).ok()?;
    let name: Vec<&str> = fields.collect();
    let name = name.join(" ");
    let name = name.strip_suffix("(linker command file)").unwrap_or(&name).trim();
    if name.is_empty() {
        return None;
    }
    Some((address, name.to_string()))
}

fn parse_mwldarm(text: &str) -> LinkerMap {
    // Link-map types keyed by (name, TU), TU matched loosely at join time
    // (archive members read `(lib.a member.o)` in layout while the link
    // map names `lib.a`).
    let mut link: HashMap<(String, String), MapKind> = HashMap::new();
    for line in text.lines() {
        if let Some((name, tu, kind)) = parse_mw_link_row(line) {
            link.insert((name, tu), kind);
        }
    }
    let mut map = LinkerMap::default();
    let mut subsection = String::new();
    let mut in_memory = false;
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(header) = trimmed.strip_prefix("# ") {
            if header.starts_with("Link map of")
                || header.starts_with("Unreferenced symbols")
                || header.starts_with("Memory map")
                || header.starts_with("Linker generated symbols")
                || header.starts_with("Link start time")
                || header.starts_with("Link end time")
            {
                in_memory = header.starts_with("Memory map");
                continue;
            }
            subsection = header.to_string();
            in_memory = false;
            continue;
        }
        if in_memory {
            // mwldarm `v_addr p_addr size name`, dtk `section addr size off`.
            let words: Vec<&str> = trimmed.split_whitespace().collect();
            if let [a, b, c, d] = words.as_slice() {
                let hex = |w: &str| {
                    if is_hex_word(w) {
                        u64::from_str_radix(w, 16).ok()
                    } else {
                        None
                    }
                };
                if let (Some(addr), Some(size)) = (hex(a), hex(c)) {
                    map.memory.push((d.to_string(), addr, size));
                    continue;
                }
                if let (Some(addr), Some(size)) = (hex(b), hex(c)) {
                    map.memory.push((a.to_string(), addr, size));
                    continue;
                }
            }
            if trimmed.starts_with("v_addr") || trimmed.starts_with("Starting") {
                continue;
            }
            in_memory = false;
        }
        if let Some((address, name)) = parse_mw_linker_defined(line) {
            map.symbols.push(MapSymbol {
                address,
                size: 0,
                name,
                kind: MapKind::NoType,
                tu: String::new(),
                section: String::new(),
                subsection: subsection.clone(),
                linker_defined: true,
            });
            continue;
        }
        if trimmed == "Linker generated symbols:" {
            subsection = String::new();
            continue;
        }
        let Some((address, size, section, name, tu)) = parse_mw_layout_row(line) else {
            continue;
        };
        if name.starts_with('$') || name == section {
            // Mapping markers ride contexts, not symbols; section rows
            // name their section, not a symbol.
            if name == "$t" || name == "$a" {
                map.symbols.push(MapSymbol {
                    address,
                    size: 0,
                    name,
                    kind: MapKind::NoType,
                    tu,
                    section,
                    subsection: subsection.clone(),
                    linker_defined: false,
                });
            }
            continue;
        }
        let linked = link
            .get(&(name.clone(), tu.clone()))
            .copied()
            .or_else(|| {
                let first = tu.split_whitespace().next().unwrap_or("");
                let last = tu.split_whitespace().next_back().unwrap_or("");
                link.get(&(name.clone(), first.to_string()))
                    .or_else(|| link.get(&(name.clone(), last.to_string())))
                    .copied()
            });
        let kind = match linked {
            Some(MapKind::Func) => MapKind::Func,
            Some(MapKind::Object) => MapKind::Object,
            _ if is_data_section(&section) => MapKind::Object,
            _ if is_code_section(&section) => MapKind::Func,
            _ => linked.unwrap_or(MapKind::NoType),
        };
        map.symbols.push(MapSymbol {
            address,
            size,
            name,
            kind,
            tu,
            section,
            subsection: subsection.clone(),
            linker_defined: false,
        });
    }
    map
}

// ------------------------------------------------------------------- PsyQ

/// SN Systems / PsyQ map (PSX `VS.MAP`): an extent table
/// `Start Stop Length Obj Group Section`, then `ADDR NAME` lists under
/// `Names alphabetically` / `Names in address order`. No types: a name
/// inside a `text`-group extent is code, anything else is data. Overlay
/// groups reuse addresses; the executable-mapping gate at apply time
/// keeps only what the image actually maps.
fn parse_psyq(text: &str) -> LinkerMap {
    let mut map = LinkerMap::default();
    // Extent rows: ` 80132000 801395EF 000075F0 80132000 text .rdata`.
    let mut code_extents: Vec<(u64, u64)> = Vec::new();
    let mut in_names = false;
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("Address") && trimmed.contains("Names") {
            in_names = true;
            continue;
        }
        if trimmed.starts_with("Program entry point") || trimmed.starts_with("Start") {
            continue;
        }
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if !in_names {
            // Extent row: six+ fields, first four hex.
            if words.len() >= 6
                && words[..4].iter().all(|w| is_hex_word(w) && w.len() == 8)
            {
                let start = u64::from_str_radix(words[0], 16).unwrap_or(0);
                let stop = u64::from_str_radix(words[1], 16).unwrap_or(0);
                let section = words[5];
                // The group column says `text` for every loadable row;
                // the section name is what marks code.
                if section.ends_with(".text") {
                    code_extents.push((start, stop + 1));
                }
                map.memory.push((section.to_string(), start, stop.saturating_sub(start) + 1));
            }
            continue;
        }
        // Name row: ` 801847BC  ResetGraph`. Two fields, first hex.
        if words.len() == 2 && is_hex_word(words[0]) && words[0].len() == 8 {
            let address = u64::from_str_radix(words[0], 16).unwrap_or(0);
            let name = words[1];
            if name.starts_with('$') {
                continue;
            }
            let kind = if code_extents
                .iter()
                .any(|&(lo, hi)| address >= lo && address < hi)
            {
                MapKind::Func
            } else {
                MapKind::Object
            };
            map.symbols.push(MapSymbol {
                address,
                size: 0,
                name: name.to_string(),
                kind,
                tu: String::new(),
                section: String::new(),
                subsection: String::new(),
                linker_defined: false,
            });
        }
    }
    // The alphabetical and address-ordered lists repeat every name;
    // dedupe on (address, name).
    map.symbols.sort_by_key(|s| (s.address, s.name.clone()));
    map.symbols.dedup_by(|a, b| a.address == b.address && a.name == b.name);
    map
}

// ----------------------------------------------------------------- GNU ld

/// GNU ld map (agbcc GBA, homebrew): output-section headers
/// `name ADDR SIZE`, `file.o(input)` context lines, `ADDR NAME` symbol
/// rows. `NAME = value` assignments are constants, not addresses, and
/// `*fill*` is padding; both are skipped. The input section names the
/// kind: `.text`-family is code, data families are objects.
fn parse_gnuld(text: &str) -> LinkerMap {
    let mut map = LinkerMap::default();
    let mut input_section = String::new();
    let mut output_section = String::new();
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.trim().is_empty() {
            continue;
        }
        // ` file.o(input)` context: one leading space, ends `)`.
        if line.starts_with(' ')
            && !line.starts_with("  ")
            && line.trim_end().ends_with(')')
        {
            if let Some(open) = line.rfind('(') {
                input_section = line[open + 1..line.trim_end().len() - 1].to_string();
            }
            continue;
        }
        // Output-section header at column 0: `name ADDR SIZE`.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() >= 3
                && words[1].starts_with("0x")
                && is_hex_word(&words[1][2..])
            {
                output_section = words[0].to_string();
                if let (Ok(addr), Ok(size)) = (
                    u64::from_str_radix(&words[1][2..], 16),
                    u64::from_str_radix(words[2].trim_end_matches('x'), 16),
                ) {
                    map.memory.push((output_section.clone(), addr, size));
                }
            }
            continue;
        }
        // Indented rows: `ADDR NAME` symbols, `ADDR . = ...` assignments,
        // `*fill*` padding, input-section rows `name ADDR SIZE file`.
        let trimmed = line.trim();
        if trimmed.starts_with("*fill*") || trimmed.contains(" = ") {
            continue;
        }
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() == 2
            && words[0].starts_with("0x")
            && is_hex_word(&words[0][2..])
        {
            let address = u64::from_str_radix(&words[0][2..], 16).unwrap_or(0);
            let name = words[1];
            if name.starts_with('.') || name.starts_with('$') {
                continue;
            }
            let kind = if is_code_section(&input_section) {
                MapKind::Func
            } else if is_data_section(&input_section)
                || input_section.contains("rodata")
                || input_section.contains("consts")
            {
                MapKind::Object
            } else {
                MapKind::NoType
            };
            map.symbols.push(MapSymbol {
                address,
                size: 0,
                name: name.to_string(),
                kind,
                tu: String::new(),
                section: input_section.clone(),
                subsection: output_section.clone(),
                linker_defined: false,
            });
        }
    }
    map
}

// ------------------------------------------------------------------- MSVC

/// MSVC `/MAP` output: `seg:off name rva+base flag obj` rows under
/// `Publics by Value`. The flag `f` marks a function; anything else is
/// data. `Rva+Base` is the runtime address, so no segment arithmetic is
/// needed.
fn parse_msvc(text: &str) -> LinkerMap {
    let mut map = LinkerMap::default();
    let mut in_publics = false;
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.contains("Publics by Value") {
            in_publics = true;
            continue;
        }
        if !in_publics {
            continue;
        }
        if trimmed.starts_with("entry point") || trimmed.starts_with("Static symbols") {
            break;
        }
        // ` 0001:000506e0       ?name@@... 00000001400516e0 f   obj`
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() < 4 {
            continue;
        }
        let Some((seg, off)) = words[0].split_once(':') else {
            continue;
        };
        if !(is_hex_word(seg) && is_hex_word(off)) {
            continue;
        }
        let Some(rva_base) = words.get(2).and_then(|w| {
            if is_hex_word(w) {
                u64::from_str_radix(w, 16).ok()
            } else {
                None
            }
        }) else {
            continue;
        };
        let flag = words[3];
        let kind = if flag == "f" { MapKind::Func } else { MapKind::Object };
        map.symbols.push(MapSymbol {
            address: rva_base,
            size: 0,
            name: words[1].to_string(),
            kind,
            tu: words.get(4).copied().unwrap_or("").to_string(),
            section: String::new(),
            subsection: String::new(),
            linker_defined: false,
        });
    }
    map
}

// ------------------------------------------------------------------- flat

/// `ADDR NAME` per line (3DS `symbols.map` and similar dumps). No types:
/// everything is code, and the executable-mapping gate at apply time
/// drops whatever the image does not map.
fn parse_flat(text: &str) -> LinkerMap {
    let mut map = LinkerMap::default();
    for raw in text.lines() {
        let trimmed = raw.trim();
        let mut words = trimmed.split_whitespace();
        let (Some(addr), Some(name)) = (words.next(), words.next()) else {
            continue;
        };
        // Bare `ADDR NAME` (8-hex) and splat's `0xADDR NAME;` both land
        // here; the `0x` prefix and trailing `;` are decoration.
        let hex = addr.strip_prefix("0x").unwrap_or(addr);
        if !is_hex_word(hex) || hex.len() != 8 || name.starts_with('$') {
            continue;
        }
        let address = u64::from_str_radix(hex, 16).unwrap_or(0);
        let name = name.trim_end_matches(';');
        if name.is_empty() {
            continue;
        }
        map.symbols.push(MapSymbol {
            address,
            size: 0,
            name: name.to_string(),
            kind: MapKind::Func,
            tu: String::new(),
            section: String::new(),
            subsection: String::new(),
            linker_defined: false,
        });
    }
    map
}


// ---------------------------------------------------------------- psx .sym

/// PSX/PS2 `.SYM` (PsyQ/ProDG-era linker symbol dump): a flat array of
/// little-endian `(u32 address, u32 name_offset)` records followed by a
/// NUL-terminated string table. The first record's name offset is the
/// record count times eight; a `0xffffffff` address is a linker-defined
/// sentinel (`_end`, `_heap_size`). Rows carry no type — `Sym` lets the
/// executable-mapping check decide code vs name.
pub fn parse_sym(bytes: &[u8]) -> Option<LinkerMap> {
    if bytes.len() < 16 {
        return None;
    }
    let first_name_off =
        u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    if first_name_off == 0
        || first_name_off % 8 != 0
        || first_name_off >= bytes.len()
    {
        return None;
    }
    let count = first_name_off / 8;
    let mut map = LinkerMap::default();
    let mut prev = 0u64;
    let mut ordered = true;
    for index in 0..count {
        let base = index * 8;
        let address =
            u32::from_le_bytes(bytes[base..base + 4].try_into().ok()?) as u64;
        let name_off =
            u32::from_le_bytes(bytes[base + 4..base + 8].try_into().ok()?)
                as usize;
        if name_off >= bytes.len() {
            return None;
        }
        let end = bytes[name_off..]
            .iter()
            .position(|b| *b == 0)
            .map(|p| name_off + p)?;
        let name = std::str::from_utf8(&bytes[name_off..end]).ok()?;
        if name.is_empty()
            || !name.bytes().all(|b| (0x20..0x7f).contains(&b))
        {
            return None;
        }
        if address < prev {
            ordered = false;
        }
        prev = address;
        map.symbols.push(MapSymbol {
            address,
            size: 0,
            name: name.to_string(),
            kind: MapKind::Sym,
            tu: String::new(),
            section: String::new(),
            subsection: String::new(),
            linker_defined: address == u32::MAX as u64,
        });
    }
    // A real .SYM is address-ordered; random binary that survived the
    // structural checks still has to pass this one.
    if !ordered || map.symbols.len() < 2 {
        return None;
    }
    Some(map)
}
// -------------------------------------------------------------- dtk/splat

/// dtk `symbols.txt` / splat `symbol_addrs.txt`: the decomp project's own
/// symbol list, `name = section:0xADDR; // type:function size:0x40
/// scope:local` (dtk) or `name = 0xADDR;` / `0xADDR name` (splat). The
/// `//` comment carries `type:`/`size:`/`scope:`/`data:` attributes; a
/// `label`/`notype` row is a name, not an entry point.
fn parse_dtk_splat(text: &str) -> LinkerMap {
    let mut map = LinkerMap::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (body, comment) = match line.split_once("//") {
            Some((body, comment)) => (body.trim_end(), comment),
            None => (line, ""),
        };
        let body = body.trim_end_matches(';').trim();
        if body.is_empty() {
            continue;
        }
        // Attributes from the comment: `key:value` words.
        let mut kind = MapKind::NoType;
        let mut size = 0u64;
        let mut typed = false;
        for word in comment.split_whitespace() {
            if let Some((key, value)) = word.split_once(':') {
                match key {
                    "type" => {
                        typed = true;
                        kind = match value {
                            "function" | "func" => MapKind::Func,
                            "object" => MapKind::Object,
                            _ => MapKind::NoType,
                        };
                    }
                    "size" => {
                        size = u64::from_str_radix(
                            value.trim_start_matches("0x"),
                            16,
                        )
                        .unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }
        // Two shapes: `name = [section:]0xADDR` and splat's `0xADDR name`.
        let (name, address, section) = if let Some((left, right)) = body.split_once('=') {
            let name = left.trim().to_string();
            let right = right.trim();
            let (section, addr_word) = match right.split_once(':') {
                Some((section, addr)) => (section.to_string(), addr.trim()),
                None => (String::new(), right),
            };
            let Some(address) = addr_word
                .strip_prefix("0x")
                .or(Some(addr_word))
                .filter(|w| is_hex_word(w))
                .and_then(|w| u64::from_str_radix(w, 16).ok())
            else {
                continue;
            };
            (name, address, section)
        } else {
            let mut words = body.split_whitespace();
            let (Some(addr_word), Some(name)) = (words.next(), words.next()) else {
                continue;
            };
            let Some(address) = addr_word
                .strip_prefix("0x")
                .or(Some(addr_word))
                .filter(|w| is_hex_word(w))
                .and_then(|w| u64::from_str_radix(w, 16).ok())
            else {
                continue;
            };
            // Trailing `type:`/`size:` tokens on the bare shape.
            for word in words {
                if let Some((key, value)) = word.split_once(':') {
                    if key == "type" {
                        typed = true;
                        kind = match value {
                            "func" | "function" => MapKind::Func,
                            "object" | "data" => MapKind::Object,
                            _ => MapKind::NoType,
                        };
                    } else if key == "size" {
                        size = u64::from_str_radix(
                            value.trim_start_matches("0x"),
                            16,
                        )
                        .unwrap_or(0);
                    }
                }
            }
            (name.to_string(), address, String::new())
        };
        if name.is_empty() || name.starts_with('$') {
            continue;
        }
        if !typed {
            // Untyped rows take the section heuristic; no section means
            // the flat default, code.
            kind = if is_data_section(&section) {
                MapKind::Object
            } else {
                MapKind::Func
            };
        }
        map.symbols.push(MapSymbol {
            address,
            size,
            name,
            kind,
            tu: String::new(),
            section,
            subsection: String::new(),
            linker_defined: false,
        });
    }
    map
}


// ----------------------------------------------------------------- splits

/// One dtk `splits.txt` extent: a section name over `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitExtent {
    pub name: String,
    pub start: u64,
    pub end: u64,
    /// `code`/`rodata`/`data`/`bss` from the `Sections:` header, when the
    /// row's section declared one.
    pub kind: String,
}

/// dtk `splits.txt`: a `Sections:` block naming each section's type, then
/// per-TU blocks of `.section start:0x.. end:0x..` rows. The extents are
/// what a section name on a symbol means; without them an export can only
/// guess `.text`/`.data`, and `dtk dol diff` checks names against the
/// linked ELF's real sections.
pub fn parse_splits(text: &str) -> Vec<SplitExtent> {
    let mut extents = Vec::new();
    let mut section_kinds: HashMap<String, String> = HashMap::new();
    let mut in_sections = false;
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "Sections:" {
            in_sections = true;
            continue;
        }
        if in_sections {
            // `\t.init       type:code align:4` — tab-indented name + attrs.
            if line.starts_with('\t') || line.starts_with("    ") {
                let mut words = trimmed.split_whitespace();
                if let Some(name) = words.next() {
                    let kind = words
                        .find_map(|w| w.strip_prefix("type:").map(str::to_string))
                        .unwrap_or_default();
                    section_kinds.insert(name.to_string(), kind);
                }
                continue;
            }
            in_sections = false;
        }
        // `file.c:` opens a TU block; `\t.text start:0x.. end:0x..` rows
        // carry the extents.
        if trimmed.ends_with(':') && !trimmed.contains(' ') {
            continue;
        }
        let mut words = trimmed.split_whitespace();
        let Some(name) = words.next() else { continue };
        let mut start = None;
        let mut end = None;
        for word in words {
            if let Some(value) = word.strip_prefix("start:") {
                start = u64::from_str_radix(value.trim_start_matches("0x"), 16).ok();
            } else if let Some(value) = word.strip_prefix("end:") {
                end = u64::from_str_radix(value.trim_start_matches("0x"), 16).ok();
            }
        }
        if let (Some(start), Some(end)) = (start, end) {
            let kind = section_kinds.get(name).cloned().unwrap_or_default();
            extents.push(SplitExtent {
                name: name.to_string(),
                start,
                end,
                kind,
            });
        }
    }
    extents
}

/// The section name an address falls inside, when the splits name it.
pub fn section_at(extents: &[SplitExtent], address: u64) -> Option<&str> {
    extents
        .iter()
        .find(|extent| address >= extent.start && address < extent.end)
        .map(|extent| extent.name.as_str())
}

/// Parse a MAP file, sniffing the grammar from its own text. Never fails
/// on unknown lines: a linker upgrade must not break ingestion of the
/// parts that did not change.
pub fn parse(text: &str) -> LinkerMap {
    if text.contains("Publics by Value") && text.contains("Rva+Base") {
        return parse_msvc(text);
    }
    if text.contains("found in local") || text.contains("found in global") {
        return parse_mwldarm(text);
    }
    if text.contains("Names alphabetically") || text.contains("Names in address order") {
        return parse_psyq(text);
    }
    if text.contains("Archive member included to satisfy reference")
        || text.lines().any(|l| l.trim().starts_with("*fill*"))
    {
        return parse_gnuld(text);
    }
    // dtk's `name = section:0xADDR;` and splat's `name = 0xADDR;` both
    // carry `=` before `;`; a bare `0xADDR name` file is flat.
    if text.lines().any(|l| {
        let l = l.trim();
        l.contains(" = ") && l.trim_end_matches(';').contains("0x")
    }) {
        return parse_dtk_splat(text);
    }
    parse_flat(text)
}

/// Read and parse a MAP file.
pub fn parse_file(path: &Path) -> std::io::Result<LinkerMap> {
    std::fs::read_to_string(path).map(|text| parse(&text))
}

// ------------------------------------------------------------------ apply

/// Merge MAP records into an import before discovery, mirroring what the
/// ELF symtab paths establish: FUNC rows seed named functions (linker
/// ground truth outranks discovery coinage), OBJECT rows ride the
/// object size/name fields, `$t`/`$a` rows ride mode contexts. Only rows
/// inside an executable mapping are taken, which is what keeps overlay
/// records out of a static-module import until M-C gives them programs
/// of their own.
pub fn apply_to_import(imp: &mut super::NativeImport, map: &LinkerMap) {
    let in_code = |address: u64| {
        imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address - mapping.vaddr < mapping.size
        })
    };
    let mut entries: std::collections::HashSet<u64> =
        imp.functions.iter().map(|function| function.entry).collect();
    for symbol in &map.symbols {
        if symbol.address == 0 || symbol.linker_defined {
            continue;
        }
        if symbol.name == "$t" {
            if in_code(symbol.address) {
                imp.contexts.push(super::NativeContext {
                    name: "TMode".into(),
                    address: symbol.address,
                    value: 1,
                });
            }
            continue;
        }
        if symbol.name == "$a" {
            if in_code(symbol.address) {
                imp.contexts.push(super::NativeContext {
                    name: "TMode".into(),
                    address: symbol.address,
                    value: 0,
                });
            }
            continue;
        }
        match symbol.kind {
            MapKind::Func | MapKind::Sym if in_code(symbol.address) => {
                if let Some(function) = imp
                    .functions
                    .iter_mut()
                    .find(|function| function.entry == symbol.address)
                {
                    // Linker truth renames discovery coinage.
                    function.name = symbol.name.clone();
                } else if entries.insert(symbol.address) {
                    imp.functions.push(super::NativeFunction {
                        entry: symbol.address,
                        name: symbol.name.clone(),
                        size: symbol.size.max(1),
                    });
                }
                if !imp.symbol_named.contains(&symbol.address) {
                    imp.symbol_named.push(symbol.address);
                }
            }
            // A Sym outside code is a name, not an entry point.
            MapKind::Sym => {
                if !symbol.name.is_empty() {
                    imp.object_names.push((symbol.address, symbol.name.clone()));
                }
            }
            MapKind::Object => {
                if symbol.size > 0 {
                    imp.object_sizes.push((symbol.address, symbol.size));
                    if !symbol.name.is_empty() {
                        imp.object_names.push((symbol.address, symbol.name.clone()));
                    }
                }
            }
            MapKind::Func | MapKind::NoType => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn dtk_splat_rows_carry_type_and_size() {
        let text = concat!(
            "__start = .init:0x80007140; // type:function size:0x114 scope:weak\n",
            "Cvar_Set = .text:0x800097FC; // type:function size:0xB8 scope:global\n",
            "_bss_init_info = .init:0x800093B0; // type:object size:0x18 scope:global data:4byte\n",
            "gTRKInterruptVectorTable = .init:0x800073D8; // type:label scope:global\n",
            "0x80009D34 LoadGameflow\n",
            "plain = 0x8000B110;\n",
        );
        let map = parse(text);
        let by_name = |name: &str| map.symbols.iter().find(|s| s.name == name).unwrap().clone();
        let start = by_name("__start");
        assert_eq!((start.address, start.size, start.kind), (0x80007140, 0x114, MapKind::Func));
        assert_eq!(start.section, ".init");
        assert_eq!(by_name("Cvar_Set").kind, MapKind::Func);
        assert_eq!(by_name("_bss_init_info").kind, MapKind::Object);
        // A label is a name, not an entry point.
        assert_eq!(by_name("gTRKInterruptVectorTable").kind, MapKind::NoType);
        // Bare splat rows default to code.
        assert_eq!(by_name("LoadGameflow").kind, MapKind::Func);
        assert_eq!(by_name("plain").kind, MapKind::Func);
    }
    // mwldarm shape: `#` subsections, `N](name,type)` link rows without a
    // space after `]`, archive-member TUs, CRLF endings, `$t` markers.
    const MW_SAMPLE: &str = concat!(
        "# Unreferenced symbols:\r\n",
        "\t.bss\t(dead.o )\r\n",
        "\r\n",
        "# Link map of _start\r\n",
        "  8](_start,func) found in global main.o\r\n",
        "  9](NitroMain,func) found in global main.o\r\n",
        "  3](OSi_ThreadInfo,object) found in global os_thread.o\r\n",
        " 10](SVC_WaitByLoop,notype) found in global libsyscall.a\r\n",
        "  2](.text,section) found in local main.o\r\n",
        "  4] >>> UNREFERENCED DUPLICATE dup.o\r\n",
        "  5] >>> SYMBOL NOT FOUND: missing\r\n",
        "\r\n",
        "# .main\r\n",
        "#>02000000          SDK_STATIC_START (linker command file)\r\n",
        "#>00000000          SDK_OVERLAY_OVY_0_ID (linker command file)\r\n",
        "  02000CA4 00000000 .text   $t\t(main.o)\r\n",
        "  02000CA4 000001C8 .text   NitroMain\t(main.o)\r\n",
        "  02000800 00000024 .text   _start\t(main.o)\r\n",
        "  02000E00 00000004 .rodata version_tag\t(pm_version.o)\r\n",
        "  02000E04 00000000 .rodata $d\t(pm_version.o)\r\n",
        "  020001BA 00000004 .text   SVC_CpuSet\t(libsyscall.a _secure_ipke.o )\r\n",
        "  02200000 00000040 .bss    OSi_ThreadInfo\t(os_thread.o)\r\n",
        "  02000CA4 00000000 .text   $t\t(main.o)\r\n",
        "  020F509C 000005D0         Exception Table Index\t()\r\n",
        "\r\n",
        "# Memory map:\r\n",
        "  v_addr   p_addr   size     name\r\n",
        "  02000000 02000000 00111860 main\r\n",
        "\r\n",
        "# Link end time: Tue Sep 08 23:54:36 2026\r\n",
    );

    #[test]
    fn mw_link_rows_cover_both_shapes() {
        let (name, _, kind) = parse_mw_link_row("  9](NitroMain,func) found in global main.o").unwrap();
        assert_eq!((name.as_str(), kind), ("NitroMain", MapKind::Func));
        let (name, _, kind) =
            parse_mw_link_row("  9] NitroMain (func,global) found in global main.o").unwrap();
        assert_eq!((name.as_str(), kind), ("NitroMain", MapKind::Func));
        assert!(parse_mw_link_row("  4] >>> UNREFERENCED DUPLICATE dup.o").is_none());
        assert!(parse_mw_link_row("  5] >>> SYMBOL NOT FOUND: missing").is_none());
    }

    #[test]
    fn mw_layout_row_fields() {
        let (address, size, section, name, tu) =
            parse_mw_layout_row("  02000CA4 000001C8 .text   NitroMain\x09(main.o)").unwrap();
        assert_eq!((address, size), (0x02000ca4, 0x1c8));
        assert_eq!((section.as_str(), name.as_str(), tu.as_str()), (".text", "NitroMain", "main.o"));
        let (_, _, section, name, tu) =
            parse_mw_layout_row("  020F509C 000005D0         Exception Table Index\x09()").unwrap();
        assert_eq!((section.as_str(), name.as_str(), tu.as_str()), ("", "Exception Table Index", ""));
        assert!(parse_mw_layout_row("  UNUSED 00000004 .text dead (a.o)").is_none());
    }

    #[test]
    fn mw_join_prefers_link_type_over_section_heuristic() {
        let map = parse(MW_SAMPLE);
        let by_name = |name: &str| map.symbols.iter().find(|s| s.name == name).unwrap().clone();
        assert_eq!(by_name("NitroMain").kind, MapKind::Func);
        let thread_info = by_name("OSi_ThreadInfo");
        assert_eq!((thread_info.address, thread_info.kind), (0x02200000, MapKind::Object));
        // `notype` in a code section is still code: SVC stubs are real
        // functions the link map declines to type.
        assert_eq!(by_name("SVC_CpuSet").kind, MapKind::Func);
        assert_eq!(by_name("version_tag").kind, MapKind::Object);
        let markers: Vec<&MapSymbol> = map.symbols.iter().filter(|s| s.name == "$t").collect();
        assert_eq!(markers.len(), 2);
        let defined: Vec<&MapSymbol> = map.symbols.iter().filter(|s| s.linker_defined).collect();
        assert_eq!(defined.len(), 2);
        assert_eq!(map.memory, vec![("main".to_string(), 0x02000000, 0x111860)]);
    }

    #[test]
    fn psyq_names_typed_by_extent() {
        let text = concat!(
            "    Start     Stop   Length      Obj Group            Section name\r\n",
            " 80132000 801395EF 000075F0 80132000 text             .rdata\r\n",
            " 801395F0 8018ED2B 0005573C 801395F0 text             .text\r\n",
            " 8018ED2C 8019666F 00007944 8018ED2C text             .data\r\n",
            " 80196770 80196933 000001C4 80196770 bss              .sbss\r\n",
            "\r\n",
            "Program entry point : 00000000\r\n",
            "\r\n",
            "  Address  Names alphabetically\r\n",
            " 801890AC  AddPrim\r\n",
            " 801962F0  CD_cbread\r\n",
            " 80196770  gData\r\n",
            "\r\n",
            "  Address  Names in address order\r\n",
            " 801890AC  AddPrim\r\n",
            " 801962F0  CD_cbread\r\n",
            " 80196770  gData\r\n",
        );
        let map = parse(text);
        let by_name = |name: &str| map.symbols.iter().find(|s| s.name == name).unwrap().clone();
        // Inside the .text extent: code. In .data/.sbss extents: objects.
        assert_eq!(by_name("AddPrim").kind, MapKind::Func);
        assert_eq!(by_name("CD_cbread").kind, MapKind::Object);
        assert_eq!(by_name("gData").kind, MapKind::Object);
        // Both name lists dedupe to one record each.
        assert_eq!(map.symbols.len(), 3);
    }

    #[test]
    fn gnuld_rows_typed_by_input_section() {
        let text = concat!(
            "Archive member included to satisfy reference by file (symbol)\n",
            "\n",
            ".text           0x08000000   0x1db67c\n",
            " src/crt0.o(.text)\n",
            " .text          0x08000204      0x1a0 src/crt0.o\n",
            "                0x08000204                Init\n",
            "                0x08000248                IntrMain\n",
            " src/main.o(.text)\n",
            " .text          0x080003a4      0x5e4 src/main.o\n",
            "                0x080003a4                AgbMain\n",
            "                0x08b00000                        __gfx_load_address = 0x8c00000\n",
            " *fill*         0x08000988        0x4 \n",
            " src/malloc.o(ewram_data)\n",
            " ewram_data     0x02000000    0x1c000 src/malloc.o\n",
            "                0x02000000                gHeap\n",
        );
        let map = parse(text);
        let by_name = |name: &str| map.symbols.iter().find(|s| s.name == name).unwrap().clone();
        assert_eq!(by_name("Init").kind, MapKind::Func);
        assert_eq!(by_name("AgbMain").kind, MapKind::Func);
        assert_eq!(by_name("gHeap").kind, MapKind::Object);
        // Assignments and fills are not symbols.
        assert_eq!(map.symbols.len(), 4);
    }

    #[test]
    fn msvc_flag_types_the_row() {
        let text = concat!(
            " ffxv_s\n",
            "\n",
            " Timestamp is 5aa69591\n",
            "\n",
            " Preferred load address is 0000000140000000\n",
            "\n",
            "  Address         Publics by Value              Rva+Base               Lib:Object\n",
            "\n",
            " 0001:000506e0       ?Get@Thing@@EEBAPEBXXZ 00000001400516e0 f   Lobby.obj\n",
            " 0001:000506e0       ?gConfig@@3HA          00000001400516e0     Config.obj\n",
            "\n",
            " entry point at        0001:002f0000\n",
        );
        let map = parse(text);
        assert_eq!(map.symbols.len(), 2);
        assert_eq!(map.symbols[0].kind, MapKind::Func);
        assert_eq!(map.symbols[0].address, 0x1400516e0);
        assert_eq!(map.symbols[1].kind, MapKind::Object);
    }

    #[test]
    fn flat_rows_are_code() {
        let map = parse("00100048 .ARM.Collect$$libshutdown$$00000002\n001002ec __aeabi_vec_ctor\n");
        assert_eq!(map.symbols.len(), 2);
        assert_eq!(map.symbols[0].address, 0x100048);
        assert_eq!(map.symbols[0].kind, MapKind::Func);
    }

    #[test]
    fn apply_seeds_names_objects_and_modes() {
        use super::super::{Mapping, NativeFunction, NativeImport};
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x02000000,
                size: 0x111860,
                file_off: 0,
                flags: 6,
                bytes: vec![],
            }],
            functions: vec![NativeFunction {
                entry: 0x02000ca4,
                name: "FUN_02000ca4".into(),
                size: 1,
            }],
            ..Default::default()
        };
        // Overlay-range FUNC rows must not leak into a static import.
        let mut map = parse(MW_SAMPLE);
        map.symbols.push(MapSymbol {
            address: 0x021e5900,
            size: 0x100,
            name: "OverlayFn".into(),
            kind: MapKind::Func,
            tu: "ov.o".into(),
            section: ".text".into(),
            subsection: ".OVY_0".into(),
            linker_defined: false,
        });
        apply_to_import(&mut imp, &map);
        let renamed = imp.functions.iter().find(|f| f.entry == 0x02000ca4).unwrap();
        assert_eq!(renamed.name, "NitroMain");
        assert!(imp.symbol_named.contains(&0x02000ca4));
        assert!(imp.functions.iter().any(|f| f.entry == 0x02000800 && f.name == "_start"));
        assert!(!imp.functions.iter().any(|f| f.entry == 0x021e5900));
        assert!(!imp.symbol_named.contains(&0x021e5900));
        assert!(imp.object_sizes.contains(&(0x02000e00, 4)));
        assert!(imp.object_names.contains(&(0x02000e00, "version_tag".to_string())));
        assert!(imp
            .contexts
            .iter()
            .any(|c| c.name == "TMode" && c.address == 0x02000ca4 && c.value == 1));
    }
}
