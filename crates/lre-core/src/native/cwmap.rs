//! CodeWarrior linker MAP reader (`mwldeppc` GC/Wii, `mwldarm` DS).
//!
//! Grammar reference: dtk `src/util/map.rs` (MIT OR Apache-2.0) models the
//! same four sections, but `mwldarm` differs in row syntax, so this is a
//! focused reader rather than a port:
//!
//! * Link map: `  N](name,type) found in local|global TU` -- the symbol is
//!   *inside* the parens and no space follows `]` (dtk expects
//!   `N] name (type,vis)`). Both shapes are accepted.
//! * Layout: `# .section` subsection headers (`#` prefix, no `section
//!   layout` titles), rows `  ADDR SIZE SECTION NAME (TU)` with the TU in
//!   trailing parens (archive members read `(lib.a member.o)` while the
//!   link map names only `lib.a`). `UNUSED`/`........` addresses are
//!   dead-stripped.
//! * Memory map (mwldarm): `v_addr p_addr size name` columns, not dtk's
//!   `section addr size offset`.
//! * Files end lines with CRLF.
//!
//! A layout row's kind comes from the link map joined on (name, TU); rows
//! without a link entry are typed by section for data (`.rodata`, `.data`,
//! `.bss`, `.sdata*`) and left `NoType` otherwise -- `.text` rows without
//! a link entry are veneers the linker never named (`SVC_*`), and coining
//! them as functions would be wrong. `$t`/`$a` mapping rows ride contexts
//! the way ELF mapping symbols do.

use std::collections::HashMap;

/// What the link map says a row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CwKind {
    Func,
    Object,
    NoType,
}

/// One joined MAP record: a link-map type on a layout address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CwMapSymbol {
    /// Linked address (`#> ` rows carry it too; 0 means unplaced).
    pub address: u64,
    /// Linker size; mapping markers (`$t`) carry 0.
    pub size: u64,
    /// Symbol name, as linked.
    pub name: String,
    /// Link-map kind, or section-derived for data without an entry.
    pub kind: CwKind,
    /// Translation unit, parens stripped (`lib.a member.o` kept whole).
    pub tu: String,
    /// Layout section (`.text`, `.rodata`, ...), empty when the row has none.
    pub section: String,
    /// `# .subsection` header the row appeared under, for overlay scoping.
    pub subsection: String,
    /// `#> ` linker-defined row (command-file symbol, not linked code).
    pub linker_defined: bool,
}

/// A parsed MAP: joined records plus memory-map extents.
#[derive(Debug, Clone, Default)]
pub struct CwMap {
    pub symbols: Vec<CwMapSymbol>,
    /// `(name, vaddr, size)` memory-map rows, both column shapes.
    pub memory: Vec<(String, u64, u64)>,
}

fn is_hex_word(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Link-map entry: `(name, kind)` plus TU, or `None` for generated /
/// duplicate / not-found lines. Accepts the `mwldarm` `N](name,type)`
/// shape and dtk's `N] name (type,vis)` shape.
fn parse_link_row(line: &str) -> Option<(String, String, CwKind)> {
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
    // mwldarm: `(name,type)`; dtk: `name (type,vis)`.
    let (name, kind) = if let Some(inner) = left.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        let (name, kind) = inner.split_once(',')?;
        (name.trim(), kind.trim())
    } else if let Some(paren) = left.rfind('(') {
        let name = left[..paren].trim_end();
        let inner = left[paren + 1..].strip_suffix(')')?;
        // dtk shape `name (type,visibility)`: the type leads.
        let (kind, _) = inner.split_once(',').unwrap_or((inner, ""));
        (name, kind.trim())
    } else {
        return None;
    };
    if name.is_empty() {
        return None;
    }
    let kind = match kind {
        "func" => CwKind::Func,
        "object" => CwKind::Object,
        _ => CwKind::NoType,
    };
    Some((name.to_string(), tu, kind))
}

/// Layout row: `(address, size, section, name, tu)`. Returns `None` for
/// dead-stripped (`UNUSED`/`........`) or malformed rows. The TU is the
/// trailing `(...)` group and may be empty (`()`); the name is whatever
/// sits between the section and the TU.
fn parse_layout_row(line: &str) -> Option<(u64, u64, String, String, String)> {
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
    // Section, name, and TU out of the remainder: the TU is the trailing
    // paren group, the section is a leading dotted word when a name sits
    // behind it (section-less rows like `Exception Table Index ()` carry
    // only the name).
    let rest = body[addr_word.len() + 1 + size_word.len() + 1..].trim_start();
    let (before_tu, tu) = match rest.rfind('(') {
        Some(open) if rest.ends_with(')') => {
            (rest[..open].trim_end(), rest[open + 1..rest.len() - 1].trim())
        }
        _ => return None,
    };
    let mut words = before_tu.split_whitespace();
    let first = words.next()?;
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
fn parse_linker_defined(line: &str) -> Option<(u64, String)> {
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

fn is_code_section(section: &str) -> bool {
    section == ".text" || section == ".init" || section.starts_with(".text.")
}

fn is_data_section(section: &str) -> bool {
    matches!(section, ".rodata" | ".data" | ".bss" | ".sdata" | ".sdata2" | ".sbss" | ".sbss2")
        || section.ends_with(".bss")
}

/// Parse a whole MAP file. Never fails on unknown lines: sections the
/// reader does not model (unreferenced symbols, timestamps) are skipped,
/// because a linker upgrade must not break ingestion of the parts that
/// did not change.
pub fn parse(text: &str) -> CwMap {
    // First pass: link-map types keyed by (name, TU), TU matched loosely
    // at join time (archive members read `(lib.a member.o)` in layout
    // while the link map names `lib.a`).
    let mut link: HashMap<(String, String), CwKind> = HashMap::new();
    for line in text.lines() {
        if let Some((name, tu, kind)) = parse_link_row(line) {
            link.insert((name, tu), kind);
        }
    }
    let mut map = CwMap::default();
    let mut subsection = String::new();
    let mut in_memory = false;
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(header) = trimmed.strip_prefix("# ") {
            // Section keywords stay state, everything else opens a layout
            // subsection (`# .main`, `# Exception index`).

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
        if let Some((address, name)) = parse_linker_defined(line) {
            map.symbols.push(CwMapSymbol {
                address,
                size: 0,
                name,
                kind: CwKind::NoType,
                tu: String::new(),
                section: String::new(),
                subsection: subsection.clone(),
                linker_defined: true,
            });
            continue;
        }
        // `Linker generated symbols:` (no `#`, bare header) and its rows.
        if trimmed == "Linker generated symbols:" {
            subsection = String::new();
            continue;
        }
        let Some((address, size, section, name, tu)) = parse_layout_row(line) else {
            continue;
        };
        if name.starts_with('$') || name == section {
            // Mapping markers ride contexts, not symbols; section rows
            // name their section, not a symbol. Both are handled by
            // their own paths (`apply` for `$t`/`$a`).
            if name == "$t" || name == "$a" {
                map.symbols.push(CwMapSymbol {
                    address,
                    size: 0,
                    name,
                    kind: CwKind::NoType,
                    tu,
                    section,
                    subsection: subsection.clone(),
                    linker_defined: false,
                });
            }
            continue;
        }
        // Precedence: a link-map `func`/`object` is the linker's own word
        // and wins over any section heuristic. `notype` and absent fall
        // through to the section: the link map lists globals only, so a
        // static function in `.text` has no entry and is still code.
        let linked = link
            .get(&(name.clone(), tu.clone()))
            .copied()
            .or_else(|| {
                // Archive members: layout `(lib.a member.o)` against link
                // `lib.a` (or the reverse granularity).
                let first = tu.split_whitespace().next().unwrap_or("");
                let last = tu.split_whitespace().next_back().unwrap_or("");
                link.get(&(name.clone(), first.to_string()))
                    .or_else(|| link.get(&(name.clone(), last.to_string())))
                    .copied()
            });
        let kind = match linked {
            Some(CwKind::Func) => CwKind::Func,
            Some(CwKind::Object) => CwKind::Object,
            _ if is_data_section(&section) => CwKind::Object,
            _ if is_code_section(&section) => CwKind::Func,
            _ => linked.unwrap_or(CwKind::NoType),
        };
        map.symbols.push(CwMapSymbol {
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

/// Merge MAP records into an import before discovery, mirroring what the
/// ELF symtab paths establish: FUNC rows seed named functions (linker
/// ground truth outranks discovery coinage), OBJECT rows ride the
/// object size/name fields, `$t`/`$a` rows ride mode contexts. Only rows
/// inside an executable mapping are taken, which is what keeps overlay
/// records out of a static-module import until M-C gives them programs
/// of their own.
pub fn apply_to_import(imp: &mut super::NativeImport, map: &CwMap) {
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
            CwKind::Func => {
                if !in_code(symbol.address) {
                    continue;
                }
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
            CwKind::Object => {
                if symbol.size > 0 {
                    imp.object_sizes.push((symbol.address, symbol.size));
                    if !symbol.name.is_empty() {
                        imp.object_names.push((symbol.address, symbol.name.clone()));
                    }
                }
            }
            CwKind::NoType => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // mwldarm shape: `#` subsections, `N](name,type)` link rows without a
    // space after `]`, archive-member TUs, CRLF endings, `$t` markers.
    const SAMPLE: &str = concat!(
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
    fn link_rows_cover_both_shapes() {
        let (name, _, kind) = parse_link_row("  9](NitroMain,func) found in global main.o").unwrap();
        assert_eq!((name.as_str(), kind), ("NitroMain", CwKind::Func));
        let (name, _, kind) =
            parse_link_row("  9] NitroMain (func,global) found in global main.o").unwrap();
        assert_eq!((name.as_str(), kind), ("NitroMain", CwKind::Func));
        assert!(parse_link_row("  4] >>> UNREFERENCED DUPLICATE dup.o").is_none());
        assert!(parse_link_row("  5] >>> SYMBOL NOT FOUND: missing").is_none());
    }

    #[test]
    fn layout_row_fields() {
        let (address, size, section, name, tu) =
            parse_layout_row("  02000CA4 000001C8 .text   NitroMain\x09(main.o)").unwrap();
        assert_eq!((address, size), (0x02000ca4, 0x1c8));
        assert_eq!((section.as_str(), name.as_str(), tu.as_str()), (".text", "NitroMain", "main.o"));
        let (_, _, section, name, tu) =
            parse_layout_row("  020F509C 000005D0         Exception Table Index\x09()").unwrap();
        assert_eq!((section.as_str(), name.as_str(), tu.as_str()), ("", "Exception Table Index", ""));
        assert!(parse_layout_row("  UNUSED 00000004 .text dead (a.o)").is_none());
    }

    #[test]
    fn join_prefers_link_type_over_section_heuristic() {
        let map = parse(SAMPLE);
        let by_name = |name: &str| map.symbols.iter().find(|s| s.name == name).unwrap().clone();
        // Link-typed rows keep their kind even where the section agrees.
        assert_eq!(by_name("NitroMain").kind, CwKind::Func);
        let thread_info = by_name("OSi_ThreadInfo");
        assert_eq!((thread_info.address, thread_info.kind), (0x02200000, CwKind::Object));
        // `notype` in a code section is still code: SVC stubs are real
        // functions the link map declines to type.
        assert_eq!(by_name("SVC_CpuSet").kind, CwKind::Func);
        // Data sections type without a link entry.
        assert_eq!(by_name("version_tag").kind, CwKind::Object);
        // Mapping markers and linker-defined rows are kept with shape.
        let markers: Vec<&CwMapSymbol> =
            map.symbols.iter().filter(|s| s.name == "$t").collect();
        assert_eq!(markers.len(), 2);
        let defined: Vec<&CwMapSymbol> =
            map.symbols.iter().filter(|s| s.linker_defined).collect();
        assert_eq!(defined.len(), 2);
        assert_eq!(map.memory, vec![("main".to_string(), 0x02000000, 0x111860)]);
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
        let mut map = parse(SAMPLE);
        map.symbols.push(CwMapSymbol {
            address: 0x021e5900,
            size: 0x100,
            name: "OverlayFn".into(),
            kind: CwKind::Func,
            tu: "ov.o".into(),
            section: ".text".into(),
            subsection: ".OVY_0".into(),
            linker_defined: false,
        });
        apply_to_import(&mut imp, &map);
        // Linker truth renames the coined entry and marks it declared.
        let renamed = imp.functions.iter().find(|f| f.entry == 0x02000ca4).unwrap();
        assert_eq!(renamed.name, "NitroMain");
        assert!(imp.symbol_named.contains(&0x02000ca4));
        // New entries seed, overlay rows do not.
        assert!(imp.functions.iter().any(|f| f.entry == 0x02000800 && f.name == "_start"));
        assert!(!imp.functions.iter().any(|f| f.entry == 0x021e5900));
        assert!(!imp.symbol_named.contains(&0x021e5900));
        // Objects ride the sized fields; modes ride contexts.
        assert!(imp.object_sizes.contains(&(0x02000e00, 4)));
        assert!(imp.object_names.contains(&(0x02000e00, "version_tag".to_string())));
        assert!(imp.contexts.iter().any(|c| c.name == "TMode" && c.address == 0x02000ca4 && c.value == 1));
    }
}
