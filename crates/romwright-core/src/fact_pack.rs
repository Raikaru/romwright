//! The universal fact pack, applied and built.
//!
//! [`Core::apply_fact_pack`] probes a stored program against a pack
//! (`romwright-facts`): every local function entry, and with `scan` every
//! aligned executable offset no function covers. A hit is a name claim backed
//! by bytes: the relocation-masked body at that address digests like a body a
//! decomp already named, with the donor's exact size attached.
//!
//! Application reuses the signature-match machinery
//! ([`crate::signatures`], `replace_signature_matches`):
//!
//! * A claim is an inferred `signature_matches` row owned by [`SOURCE`], with
//!   the donor games, their repos and commits in `package` and their licenses
//!   in `license`. A `.vsig` row for the same function wins; this pass
//!   replaces only its own rows.
//! * Only generated names (`FUN_`) are overwritten. A symbol-table or analyst
//!   name stays; the match is still recorded.
//! * Donors that disagree after normalisation (`ambiguous`), donors that only
//!   hold generic names, and bodies several local functions share (stubs) name
//!   nothing.
//! * The consensus prototype is applied as an inference
//!   ([`PROTOTYPE_SOURCE`]); it never replaces an assertion or a prototype
//!   the image's own symbols or debug stream supplied, and a declaration
//!   naming a type the language's parser does not know is left out.
//!
//! [`Core::add_donor_to_pack`] is the build half: it reads each truth row's
//! bytes through the donor project's own mappings, the same bytes apply sees,
//! masks them, and stores digests and facts. No code bytes reach the pack.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use romwright_facts::mask::{Family, MASK_VERSION};
use romwright_facts::pack::{Candidate, Pack, PREFIX_BYTES};
pub use romwright_facts::pack::Donor;
use romwright_model::{Address, AddressSpace, FactKind, FactProvenance, PrototypeRow, SignatureMatchRow};
use serde::{Deserialize, Serialize};

use crate::native::{ImportError, Mapping};

/// Owner of every row this pass publishes.
pub const SOURCE: &str = "fact-pack";
/// Provenance of the prototypes this pass applies.
pub const PROTOTYPE_SOURCE: &str = "fact-pack:prototype";
/// Environment variable naming the pack to use.
pub const ENV_PACK: &str = "ROMWRIGHT_FACT_PACK";
/// Environment variable that turns implicit pack use off.
pub const ENV_DISABLE: &str = "ROMWRIGHT_NO_FACT_PACK";

/// Games that are one game under two builds: never used to evaluate each
/// other. Filled in by `add-donor` when the donor record names no group.
pub const TWIN_GROUPS: &[(&str, &str)] = &[
    ("ps2-ratchet-clank", "ratchet-clank"),
    ("ps2-ratchet-clank-pal", "ratchet-clank"),
    ("gc-pikmin-2", "pikmin-2"),
    ("wii-npc-pikmin-2", "pikmin-2"),
];

fn failure(message: impl Into<String>) -> crate::CoreError {
    ImportError::Bad(message.into()).into()
}

fn facts_error(error: romwright_facts::FactsError) -> crate::CoreError {
    failure(error.to_string())
}

/// Where a user's pack lives: `explicit` (`--fact-pack`), else
/// `ROMWRIGHT_FACT_PACK`, else `$XDG_DATA_HOME/romwright/fact-pack.sqlite`
/// (`~/.local/share` when unset). The second element is true when the path
/// was asked for by name. `ROMWRIGHT_NO_FACT_PACK` (any value but empty, `0`
/// or `false`) turns the implicit lookups off; an explicit path is still used.
pub fn resolve_pack(explicit: Option<&Path>) -> Option<(PathBuf, bool)> {
    if let Some(path) = explicit {
        return Some((path.to_path_buf(), true));
    }
    let set = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    if set(ENV_DISABLE).is_some_and(|value| value != "0" && value != "false") {
        return None;
    }
    if let Some(path) = set(ENV_PACK) {
        return Some((PathBuf::from(path), true));
    }
    let data = set("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| set("HOME").map(|home| PathBuf::from(home).join(".local/share")))?;
    let path = data.join("romwright").join("fact-pack.sqlite");
    path.is_file().then_some((path, false))
}

/// Opens a pack for writing its gate parameters (`facts set-meta`).
pub fn open_pack_rw(path: &Path) -> crate::Result<Pack> {
    Pack::open_rw(path).map_err(facts_error)
}

/// What to probe and what to leave out.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FactPackOptions {
    /// Games whose facts are ignored (and their twin groups): the
    /// leave-one-out switch.
    #[serde(default)]
    pub exclude_games: Vec<String>,
    /// Also probe every aligned executable offset no found function covers.
    #[serde(default)]
    pub scan: bool,
}

/// One probe that hit the pack.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FactPackMatch {
    pub address: u64,
    /// The donor body's exact size.
    pub length: u64,
    /// The consensus name; `None` when ambiguous or when no donor named it.
    pub name: Option<String>,
    pub donors: Vec<String>,
    pub ambiguous: bool,
    pub verified: bool,
    /// A local function starts at `address`.
    pub found: bool,
    /// That function's size.
    pub our_size: Option<u64>,
    pub family: String,
    /// `renamed` (a `FUN_` name replaced), `kept_name` (a non-generated name
    /// left alone), `abstained` (ambiguous, unnamed, stub, or several
    /// lengths), `gated` (a consensus name held back by the pack's rename
    /// gate: a short body without enough independent donors; nothing
    /// written), `scan_only` (no function here; nothing written).
    pub action: String,
    /// A donor prototype was applied.
    #[serde(default)]
    pub prototype: bool,
    /// Distinct compilers of the donors behind the claim.
    #[serde(default)]
    pub compilers: Vec<String>,
    /// Independent donors behind the name (a twin group counts once).
    #[serde(default)]
    pub independent: usize,
}

/// Counts and matches from one pass.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FactPackReport {
    pub program: String,
    pub language: String,
    pub pack: String,
    pub mask_version: u32,
    pub excluded: Vec<String>,
    pub probed_functions: usize,
    pub probed_scan: usize,
    /// Function entries with at least one pack hit.
    pub matched: usize,
    pub renamed: usize,
    pub kept_name: usize,
    pub abstained: usize,
    /// Consensus names held back by the rename gate (see `Gate`).
    #[serde(default)]
    pub gated: usize,
    /// The gate in force (the pack's `meta`, else the defaults).
    #[serde(default)]
    pub gate: Option<romwright_facts::pack::Gate>,
    pub scan_only: usize,
    pub prototypes: usize,
    /// Function entries whose bytes are not mapped.
    pub unmapped: usize,
    /// Why nothing was probed, when nothing was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub revision: u64,
    /// Named function-entry matches per donor compiler (a match counts once
    /// for each distinct compiler of its donors).
    #[serde(default)]
    pub compilers: std::collections::BTreeMap<String, usize>,
    /// The compiler with the most votes, when any donor records one.
    #[serde(default)]
    pub implied_compiler: Option<String>,
    pub matches: Vec<FactPackMatch>,
}

/// One truth row: a function a decomp names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TruthRow {
    pub start: u64,
    pub size: u64,
    pub name: String,
    pub verified: bool,
}

/// Parses `truth/functions.tsv`: a header naming at least `start`, `size`,
/// `name`; `verified` is optional.
pub fn parse_truth(text: &str) -> Result<Vec<TruthRow>, String> {
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().ok_or("empty truth file")?.split('\t').collect();
    let column = |name: &str| header.iter().position(|h| h.trim() == name);
    let (start, size, name) = (
        column("start").ok_or("truth has no `start` column")?,
        column("size").ok_or("truth has no `size` column")?,
        column("name").ok_or("truth has no `name` column")?,
    );
    let verified = column("verified");
    let mut rows = Vec::new();
    for (index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let cells: Vec<&str> = line.split('\t').collect();
        let cell = |i: usize| cells.get(i).map(|c| c.trim()).ok_or(format!("truth line {}: missing column", index + 2));
        let start_text = cell(start)?;
        let start_value = match start_text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => start_text.parse(),
        }
        .map_err(|e| format!("truth line {}: start: {e}", index + 2))?;
        rows.push(TruthRow {
            start: start_value,
            size: cell(size)?.parse().map_err(|e| format!("truth line {}: size: {e}", index + 2))?,
            name: cell(name)?.to_string(),
            verified: verified.and_then(|i| cells.get(i)).is_some_and(|v| v.trim() == "1"),
        });
    }
    Ok(rows)
}

/// Parses a prototype list: `name<TAB>declaration` lines, or the
/// `name = declaration` / `name: declaration` form
/// [`crate::sdk_types::parse_table`] reads. `#` comments and a leading
/// `name<TAB>decl` header are skipped.
pub fn parse_prototypes(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, decl)) = line.split_once('\t') {
            let (name, decl) = (name.trim(), decl.trim());
            if !name.is_empty() && !decl.is_empty() && !(name == "name" && decl == "decl") {
                out.push((name.to_string(), decl.to_string()));
            }
        } else {
            out.extend(crate::sdk_types::parse_table(line).prototypes);
        }
    }
    out
}

/// What the donor build did with a program's truth rows.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DonorBuildReport {
    pub game: String,
    pub program: String,
    pub language: String,
    pub rows: usize,
    pub added: usize,
    /// Added with a generic name: the body is known, no name is.
    pub generic_named: usize,
    pub skipped_short: usize,
    pub skipped_unmapped: usize,
    pub skipped_no_family: usize,
    /// Thumb/ARM decided by a context at the function's own address.
    pub mode_exact: usize,
    /// Decided by the nearest context before it (no context at the entry).
    pub mode_inferred: usize,
    /// Bodies a previous run of this program had added and this run replaced.
    pub replaced: usize,
    pub prototypes: usize,
    pub pack_bodies: usize,
}

/// Bytes and instruction-set modes of one stored program, read the way the
/// build and the apply pass both need them.
pub(crate) struct ProgramBytes {
    pub language: String,
    pub mappings: Vec<Mapping>,
    /// `(address, LowBitCodeMode)` sorted by address.
    pub modes: Vec<(u64, u64)>,
}

impl ProgramBytes {
    /// The bytes from `address` to the end of the mapping holding it.
    fn window(&self, address: u64) -> Option<&[u8]> {
        window(&self.mappings, address)
    }

    /// The code mode at `address` (true: Thumb) and whether a context sits
    /// exactly there rather than before it.
    fn mode_at(&self, address: u64) -> (bool, bool) {
        match self.modes.binary_search_by_key(&address, |m| m.0) {
            Ok(index) => (self.modes[index].1 & 1 == 1, true),
            Err(0) => (false, false),
            Err(index) => (self.modes[index - 1].1 & 1 == 1, false),
        }
    }

    /// The families to try at a function entry: the context's mode, and on
    /// ARM the other mode too when no context states it.
    fn entry_families(&self, address: u64) -> Vec<Family> {
        let (thumb, exact) = self.mode_at(address);
        let mut out = vec![Family::of(&self.language, thumb)];
        if Family::is_arm_language(&self.language) && !exact {
            out.push(Family::of(&self.language, !thumb));
        }
        out.into_iter()
            .flatten()
            .filter(|family| address.is_multiple_of(family.alignment() as u64))
            .collect()
    }

    /// The families a blind probe at `address` tries.
    fn scan_families(&self, address: u64) -> Vec<Family> {
        let modes: &[bool] = if Family::is_arm_language(&self.language) { &[false, true] } else { &[false] };
        modes
            .iter()
            .filter_map(|&thumb| Family::of(&self.language, thumb))
            .filter(|family| address.is_multiple_of(family.alignment() as u64))
            .collect()
    }
}

fn window(mappings: &[Mapping], address: u64) -> Option<&[u8]> {
    mappings.iter().find_map(|mapping| {
        let offset = address.checked_sub(mapping.vaddr)? as usize;
        mapping.bytes.get(offset..).filter(|bytes| !bytes.is_empty())
    })
}

/// Whether a language has masking rules at all.
fn has_rules(language: &str) -> bool {
    Family::of(language, false).is_some() || Family::of(language, true).is_some()
}

fn confidence(donors: usize) -> f64 {
    match donors {
        0 | 1 => 0.80,
        2 => 0.90,
        _ => 0.95,
    }
}

/// Package and license text for a claim: each donor's game, repo and commit,
/// and the distinct licenses, verbatim.
fn provenance_text(games: &[String], donors: &HashMap<String, Donor>) -> (String, String) {
    let mut package: Vec<String> = games
        .iter()
        .take(3)
        .map(|game| match donors.get(game) {
            Some(d) => format!("{game} {}@{}", d.repo, d.commit.chars().take(12).collect::<String>()),
            None => game.clone(),
        })
        .collect();
    if games.len() > 3 {
        package.push(format!("+{} more", games.len() - 3));
    }
    let mut licenses: Vec<&str> = games.iter().filter_map(|g| donors.get(g)).map(|d| d.license.as_str()).collect();
    licenses.sort_unstable();
    licenses.dedup();
    (package.join("; "), licenses.join(", "))
}

fn usable_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(char::is_whitespace) && !name.starts_with("FUN_")
}

/// Pick what a function entry's candidates say. A candidate whose length is
/// the local size wins; a lone candidate stands; several lengths and none the
/// local size is a conflict the entry abstains on.
fn choose(candidates: &[Candidate], size: u64) -> (Vec<&Candidate>, bool) {
    if let Some(exact) = candidates.iter().find(|c| c.length as u64 == size) {
        return (vec![exact], false);
    }
    match candidates {
        [only] => (vec![only], false),
        _ => (candidates.iter().collect(), true),
    }
}

/// C spellings the decompiler's own type names stand for.
fn normalize_type(text: &str) -> Option<String> {
    let stars = text.chars().filter(|c| *c == '*').count();
    let words: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || c == '*')
        .filter(|w| !w.is_empty() && !matches!(*w, "const" | "volatile" | "register" | "extern"))
        .collect();
    let base = match words.as_slice() {
        [] => return None,
        ["unsigned", "long", "long"] | ["unsigned", "long", "long", "int"] => "ulonglong".to_string(),
        ["long", "long"] | ["long", "long", "int"] | ["signed", "long", "long"] => "longlong".to_string(),
        ["unsigned", "long"] | ["unsigned", "long", "int"] => "ulong".to_string(),
        ["long", "int"] | ["signed", "long"] => "long".to_string(),
        ["unsigned", "int"] | ["unsigned"] => "uint".to_string(),
        ["unsigned", "short"] | ["unsigned", "short", "int"] => "ushort".to_string(),
        ["short", "int"] | ["signed", "short"] => "short".to_string(),
        ["unsigned", "char"] => "uchar".to_string(),
        ["signed", "char"] => "schar".to_string(),
        ["signed", "int"] | ["signed"] => "int".to_string(),
        other => other.join(" "),
    };
    Some(if stars == 0 { base } else { format!("{base} {}", "*".repeat(stars)) })
}

fn identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'_' | b'a'..=b'z' | b'A'..=b'Z')) && bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

/// Parses a C declaration `ret name(type a, type b, ...)` into the library
/// table's declaration shape, spelled in the decompiler's type names. `None`
/// when it is not a plain function declaration (function-pointer or array
/// parameters) or names a type `known` does not hold.
pub fn parse_declaration(
    decl: &str,
    known: &HashSet<String>,
) -> Option<crate::library_types::Declaration> {
    let decl = decl.trim().trim_end_matches(';').trim();
    let open = decl.find('(')?;
    let inner = decl[open + 1..].strip_suffix(')')?;
    if inner.contains(['(', ')', '[']) {
        return None;
    }
    let head = decl[..open].trim_end();
    let name_start = head.rfind(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))? + 1;
    if !identifier(&head[name_start..]) {
        return None;
    }
    let return_type = normalize_type(&head[..name_start])?;
    let mut declaration = crate::library_types::Declaration {
        return_type,
        varargs: false,
        parameters: Vec::new(),
        scope: None,
        calling_convention: None,
        this_type: None,
    };
    let inner = inner.trim();
    if !inner.is_empty() && inner != "void" {
        for (index, part) in inner.split(',').enumerate() {
            let part = part.trim();
            if part == "..." {
                declaration.varargs = true;
                continue;
            }
            if declaration.varargs {
                return None;
            }
            let split = part.rfind(|c: char| !(c == '_' || c.is_ascii_alphanumeric())).map_or(0, |i| i + 1);
            let (type_text, tail) = part.split_at(split);
            // A trailing word is the parameter's name unless it is a type word
            // (`unsigned int`, `char`) or nothing precedes it.
            let named = identifier(tail)
                && !type_text.trim().is_empty()
                && !matches!(tail, "int" | "char" | "short" | "long" | "unsigned" | "signed" | "float" | "double" | "void")
                && !known.contains(tail)
                && !type_text.trim_end().ends_with("struct")
                && !type_text.trim_end().ends_with("union")
                && !type_text.trim_end().ends_with("enum");
            let (type_text, tail) = if named { (type_text, tail) } else { (part, "") };
            let data_type = normalize_type(type_text)?;
            let name = if named && !known.contains(tail) { tail.to_string() } else { format!("param_{}", index + 1) };
            declaration.parameters.push(crate::library_types::Parameter { name, data_type });
        }
    }
    crate::library_types::representable(&declaration, known).then_some(declaration)
}

impl crate::Core {
    /// Image bytes, language and code modes of a stored program, as the
    /// project's own loader maps them.
    pub(crate) fn program_bytes(&self, program: &str) -> crate::Result<ProgramBytes> {
        let id = self.db.program_id(program)?;
        let language = self.db.program_language(id)?;
        let input = self.program_input(program)?;
        let (_, import) = crate::inputs::parse(self.db_path(), &input)?;
        let mut modes: Vec<(u64, u64)> = self
            .db
            .decode_contexts(id)?
            .into_iter()
            .filter(|(address, name, _)| address.space == AddressSpace::Ram && name == "LowBitCodeMode")
            .map(|(address, _, value)| (address.offset, value))
            .collect();
        modes.sort_unstable();
        Ok(ProgramBytes { language, mappings: import.mappings, modes })
    }

    /// The type names the program's language parser resolves; `None` when the
    /// language's specs are unavailable, and no prototype is applied.
    fn parser_types(&self, language: &str) -> Option<HashSet<String>> {
        let mut config = self.runtime_config().clone();
        config.adopt_language(language);
        let (_, specs, _, _) = crate::native_runtime::language_decompile_config(&config, language).ok()?;
        let mut known = crate::library_types::core_type_names(&specs)?;
        known.extend(crate::library_types::language_base_types(&specs).into_keys());
        Some(known)
    }

    /// Probes `program` against the pack at `pack` and publishes the claims
    /// (see the module docs).
    pub fn apply_fact_pack(
        &self,
        program: &str,
        pack: &Path,
        options: &FactPackOptions,
    ) -> crate::Result<FactPackReport> {
        let id = self.db.program_id(program)?;
        let language = self.db.program_language(id)?;
        let mut report = FactPackReport {
            program: program.into(),
            language: language.clone(),
            pack: pack.display().to_string(),
            mask_version: MASK_VERSION,
            excluded: options.exclude_games.clone(),
            ..Default::default()
        };
        let pack = Pack::open(pack).map_err(facts_error)?;
        if !has_rules(&language) {
            report.skipped = Some(format!("no masking rules for {language}"));
            report.revision = self.db.revision(id)?;
            return Ok(report);
        }
        let bytes = self.program_bytes(program)?;
        let input = Some(self.program_input(program)?);
        self.apply_fact_pack_to(program, &bytes, &pack, options, report, input)
    }

    pub(crate) fn apply_fact_pack_to(
        &self,
        program: &str,
        bytes: &ProgramBytes,
        pack: &Pack,
        options: &FactPackOptions,
        mut report: FactPackReport,
        input: Option<romwright_model::ProgramInput>,
    ) -> crate::Result<FactPackReport> {
        let id = self.db.program_id(program)?;
        let excluded: Vec<&str> = options.exclude_games.iter().map(String::as_str).collect();
        let gate = pack.gate().map_err(facts_error)?;
        report.gate = Some(gate);
        let donors: HashMap<String, Donor> =
            pack.donors().map_err(facts_error)?.into_iter().map(|d| (d.game.clone(), d)).collect();
        let functions: Vec<_> = self
            .db
            .functions(id)?
            .into_iter()
            .filter(|function| function.entry.space == AddressSpace::Ram)
            .collect();

        // Function entries.
        let mut matches: Vec<FactPackMatch> = Vec::new();
        let mut entry_of: Vec<usize> = Vec::new();
        for (index, function) in functions.iter().enumerate() {
            let entry = function.entry.offset;
            let Some(window) = bytes.window(entry) else {
                report.unmapped += 1;
                continue;
            };
            report.probed_functions += 1;
            for family in bytes.entry_families(entry) {
                let candidates = pack.lookup(family, window, &excluded).map_err(facts_error)?;
                if candidates.is_empty() {
                    continue;
                }
                let (chosen, conflict) = choose(&candidates, function.size);
                for candidate in chosen {
                    let named = candidate.name.as_deref().filter(|n| usable_name(n));
                    let action = if conflict || candidate.ambiguous || named.is_none() {
                        "abstained"
                    } else if gate.holds(candidate) {
                        "gated"
                    } else if function.name.starts_with("FUN_") {
                        "renamed"
                    } else {
                        "kept_name"
                    };
                    matches.push(FactPackMatch {
                        address: entry,
                        length: candidate.length as u64,
                        name: named.map(str::to_string),
                        donors: candidate.donors.clone(),
                        ambiguous: candidate.ambiguous,
                        verified: candidate.verified,
                        found: true,
                        our_size: Some(function.size),
                        family: family.as_str().into(),
                        action: action.into(),
                        compilers: candidate.compilers.clone(),
                        independent: candidate.independent,
                        prototype: false,
                    });
                    entry_of.push(index);
                }
                break;
            }
        }
        // Several local functions holding one donor body are stubs: the pass
        // names none of them.
        let mut shared: HashMap<(String, u64, String), usize> = HashMap::new();
        for found in matches.iter().filter(|m| m.action == "renamed" || m.action == "kept_name") {
            if let Some(name) = &found.name {
                *shared.entry((name.clone(), found.length, found.family.clone())).or_default() += 1;
            }
        }
        for found in matches.iter_mut().filter(|m| m.action == "renamed" || m.action == "kept_name") {
            let key = (found.name.clone().unwrap_or_default(), found.length, found.family.clone());
            if shared[&key] > 1 {
                found.action = "abstained".into();
            }
        }

        // Blind scan of what no function covers.
        if options.scan {
            let mut covered: Vec<(u64, u64)> = functions
                .iter()
                .map(|f| (f.entry.offset, f.entry.offset.saturating_add(f.size.max(1))))
                .collect();
            covered.sort_unstable();
            let inside = |address: u64| {
                let after = covered.partition_point(|(start, _)| *start <= address);
                after > 0 && covered[..after].iter().rev().take(64).any(|(_, end)| address < *end)
            };
            let stride = if Family::is_arm_language(&bytes.language) { 2 } else { 4 };
            let mut seen: HashSet<(u64, usize)> = HashSet::new();
            for mapping in bytes.mappings.iter().filter(|m| m.flags & 4 != 0) {
                for offset in (0..mapping.bytes.len()).step_by(stride) {
                    let address = mapping.vaddr + offset as u64;
                    if inside(address) {
                        continue;
                    }
                    let families = bytes.scan_families(address);
                    if families.is_empty() {
                        continue;
                    }
                    report.probed_scan += 1;
                    let window = &mapping.bytes[offset..];
                    for family in families {
                        for candidate in pack.lookup(family, window, &excluded).map_err(facts_error)? {
                            if !seen.insert((address, candidate.length)) {
                                continue;
                            }
                            matches.push(FactPackMatch {
                                address,
                                length: candidate.length as u64,
                                name: candidate.name.clone().filter(|n| usable_name(n) && !candidate.ambiguous),
                                donors: candidate.donors.clone(),
                                ambiguous: candidate.ambiguous,
                                verified: candidate.verified,
                                found: false,
                                our_size: None,
                                family: family.as_str().into(),
                                action: "scan_only".into(),
                                compilers: candidate.compilers.clone(),
                                independent: candidate.independent,
                                prototype: false,
                            });
                            entry_of.push(usize::MAX);
                        }
                    }
                }
            }
        }

        // Publish: rows for every named function-entry match, renames for the
        // generated names among them.
        // The claim is bound to the imported image it was read from.
        let mut rows = Vec::new();
        let mut renames = Vec::new();
        for (found, &index) in matches.iter().zip(&entry_of) {
            if !matches!(found.action.as_str(), "renamed" | "kept_name") {
                continue;
            }
            let (Some(name), Some(function)) = (&found.name, functions.get(index)) else { continue };
            let (package, license) = provenance_text(&found.donors, &donors);
            let level = confidence(found.donors.len());
            rows.push(SignatureMatchRow {
                function: function.entry.clone(),
                name: name.clone(),
                package,
                license,
                compared_bytes: found.length,
                confidence: level,
                input: input.clone(),
                provenance: FactProvenance {
                    kind: FactKind::Inferred,
                    source: SOURCE.into(),
                    confidence: Some(level),
                },
            });
            if found.action == "renamed" {
                renames.push((function.entry.clone(), name.clone()));
            }
        }
        let revision = self.db.revision(id)?;
        let (revision, renamed) = self.db.replace_signature_matches(id, revision, SOURCE, &rows, &renames)?;

        // Prototypes for the functions the pass named.
        let mut prototypes = 0;
        if !rows.is_empty()
            && let Some(known) = self.parser_types(&bytes.language) {
                let held: HashMap<Address, FactProvenance> = self
                    .db
                    .prototypes(id)?
                    .into_iter()
                    .map(|row| (row.function, row.provenance))
                    .collect();
                let mut applied: Vec<PrototypeRow> = Vec::new();
                let mut marked: Vec<usize> = Vec::new();
                for (position, (found, &index)) in matches.iter().zip(&entry_of).enumerate() {
                    let (Some(name), Some(function)) = (&found.name, functions.get(index)) else { continue };
                    if !matches!(found.action.as_str(), "renamed" | "kept_name") {
                        continue;
                    }
                    if held.get(&function.entry).is_some_and(|p| {
                        p.kind == FactKind::Asserted || p.source.starts_with("native-import")
                    }) {
                        continue;
                    }
                    let Some((decl, _)) = pack.prototype(name, &excluded).map_err(facts_error)? else { continue };
                    let Some(declaration) = parse_declaration(&decl, &known) else { continue };
                    let current = if found.action == "renamed" { name.as_str() } else { function.name.as_str() };
                    let current = if identifier(current) { current } else { name.as_str() };
                    applied.push(PrototypeRow {
                        function: function.entry.clone(),
                        signature: crate::library_types::signature(current, &declaration),
                        calling_convention: None,
                        return_type: Some(declaration.return_type.clone()),
                        provenance: FactProvenance {
                            kind: FactKind::Inferred,
                            source: PROTOTYPE_SOURCE.into(),
                            confidence: Some(confidence(found.donors.len())),
                        },
                    });
                    marked.push(position);
                }
                if !applied.is_empty() {
                    let current = self.db.revision(id)?;
                    let changed = self.db.merge_inferred_prototypes(id, current, &applied)?;
                    prototypes = changed.len();
                    let changed: HashSet<Address> = changed.into_iter().collect();
                    for (row, position) in applied.iter().zip(marked) {
                        matches[position].prototype = changed.contains(&row.function);
                    }
                }
            }

        report.revision = self.db.revision(id)?.max(revision);
        report.prototypes = prototypes;
        report.renamed = renamed;
        let mut votes: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for found in matches.iter().filter(|m| m.found && matches!(m.action.as_str(), "renamed" | "kept_name")) {
            for compiler in &found.compilers {
                *votes.entry(compiler.clone()).or_default() += 1;
            }
        }
        report.implied_compiler = votes
            .iter()
            .max_by_key(|(compiler, count)| (**count, std::cmp::Reverse((*compiler).clone())))
            .map(|(compiler, _)| compiler.clone());
        report.compilers = votes;
        report.matched = {
            let mut at: Vec<u64> = matches.iter().filter(|m| m.found).map(|m| m.address).collect();
            at.dedup();
            at.len()
        };
        report.kept_name = matches.iter().filter(|m| m.action == "kept_name").count();
        report.abstained = matches.iter().filter(|m| m.action == "abstained").count();
        report.gated = matches.iter().filter(|m| m.action == "gated").count();
        report.scan_only = matches.iter().filter(|m| m.action == "scan_only").count();
        report.matches = matches;
        Ok(report)
    }

    /// The build half: reads each truth row's bytes through `program`'s own
    /// mappings, masks them, and adds them to the pack at `pack_path`
    /// (created when absent) under `donor`. Re-running a program replaces what
    /// it added. `prototypes` are `(name, declaration)` pairs for the donor.
    pub fn add_donor_to_pack(
        &self,
        pack_path: &Path,
        program: &str,
        donor: &Donor,
        truth: &[TruthRow],
        prototypes: &[(String, String)],
    ) -> crate::Result<DonorBuildReport> {
        let bytes = self.program_bytes(program)?;
        let mut donor = donor.clone();
        if donor.twin_group.is_none() {
            donor.twin_group = TWIN_GROUPS
                .iter()
                .find(|(game, _)| *game == donor.game)
                .map(|(_, group)| group.to_string());
        }
        let pack = if pack_path.exists() {
            Pack::open_rw(pack_path)
        } else {
            Pack::create(
                pack_path,
                PREFIX_BYTES,
                concat!("romwright-core ", env!("CARGO_PKG_VERSION")),
            )
        }
        .map_err(facts_error)?;
        let mut report = DonorBuildReport {
            game: donor.game.clone(),
            program: program.into(),
            language: bytes.language.clone(),
            rows: truth.len(),
            ..Default::default()
        };
        pack.batch(|pack| {
            let id = pack.add_donor(&donor)?;
            report.replaced = pack.clear_program(id, program)?;
            for row in truth {
                if (row.size as usize) < pack.min_body() {
                    report.skipped_short += 1;
                    continue;
                }
                let Some(code) = bytes.window(row.start).and_then(|w| w.get(..row.size as usize)) else {
                    report.skipped_unmapped += 1;
                    continue;
                };
                let (thumb, exact) = bytes.mode_at(row.start);
                let Some(family) = Family::of(&bytes.language, thumb) else {
                    report.skipped_no_family += 1;
                    continue;
                };
                if Family::is_arm_language(&bytes.language) {
                    if exact { report.mode_exact += 1 } else { report.mode_inferred += 1 }
                }
                if pack.add_body(id, program, family, code, &row.name, row.verified)? {
                    report.added += 1;
                    if romwright_facts::pack::is_generic(&row.name) {
                        report.generic_named += 1;
                    }
                }
            }
            for (name, decl) in prototypes {
                pack.add_prototype(id, name, decl)?;
                report.prototypes += 1;
            }
            Ok(())
        })
        .map_err(facts_error)?;
        report.pack_bodies = pack.counts().map_err(facts_error)?.bodies;
        Ok(report)
    }

    /// The pack an import should apply, resolved from `explicit`, the
    /// environment and the user data directory; `None` when there is none or
    /// it cannot be read (an unreadable implicit pack is reported and skipped,
    /// an unreadable explicit one is an error).
    pub(crate) fn import_fact_pack(&self, explicit: Option<&Path>) -> crate::Result<Option<(PathBuf, String, bool)>> {
        let Some((path, named)) = resolve_pack(explicit) else { return Ok(None) };
        match Pack::open(&path).and_then(|pack| pack.identity()) {
            Ok(identity) => Ok(Some((path, identity, named))),
            Err(error) if named => Err(facts_error(error)),
            Err(error) => {
                eprintln!("warning: fact pack {}: {error}", path.display());
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{FunctionRow, Provenance};

    const MIPS: &str = "MIPS:LE:32:default";

    fn le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// 48 bytes of code whose compiler-chosen immediates depend on `seed` and
    /// whose call and address halves depend on the link.
    fn body(seed: u32, jal: u32, hi: u32) -> Vec<u8> {
        let mut words = vec![0x27BD_FFE0, 0xAFBF_0018];
        words.extend((0..7).map(|i| 0x2402_0000 | (seed + i)));
        words.extend([0x0C00_0000 | jal, 0x3C04_0000 | hi, 0x03E0_0008]);
        le(&words)
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "romwright-fact-pack-{}-{}-{tag}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn donor(game: &str, license: &str) -> Donor {
        Donor {
            game: game.into(),
            platform: "ps2".into(),
            repo: format!("example/{game}"),
            commit: "0123456789abcdef0123".into(),
            license: license.into(),
            truth_kind: "decomp-build".into(),
            twin_group: None,
            compiler: Some("test-cc 1.0".into()),
        }
    }

    /// A program of `names.len()` functions, each at 0x100 spacing holding
    /// `bodies[i]`, stored with the given names.
    fn project(scratch: &Scratch, names: &[&str], bodies: &[Vec<u8>]) -> (crate::Core, ProgramBytes) {
        let core = crate::Core::open(&scratch.0.join("project")).unwrap();
        let db = core.store_handle().unwrap();
        let provenance = Provenance { producer: "test".into(), upstream_version: "0".into() };
        let id = db.upsert_program("synth", MIPS, &provenance).unwrap();
        let mut image = vec![0u8; 0x100 * (names.len() + 1)];
        let mut rows = Vec::new();
        for (i, (name, code)) in names.iter().zip(bodies).enumerate() {
            let entry = 0x0010_0000 + 0x100 * i as u64;
            image[0x100 * i..0x100 * i + code.len()].copy_from_slice(code);
            rows.push(FunctionRow {
                entry: Address::ram(entry),
                name: (*name).into(),
                size: code.len() as u64,
                signature: None,
                traced: false,
                calling_convention: None,
            });
        }
        db.replace_functions(id, &rows).unwrap();
        let bytes = ProgramBytes {
            language: MIPS.into(),
            mappings: vec![Mapping { vaddr: 0x0010_0000, size: image.len() as u64, file_off: 0, flags: 7, bytes: image }],
            modes: Vec::new(),
        };
        (core, bytes)
    }

    fn build_pack(scratch: &Scratch, games: &[(&str, &str, &str, Vec<u8>)]) -> PathBuf {
        let path = scratch.0.join("pack.sqlite");
        let pack = Pack::create(&path, 32, "test").unwrap();
        // These tests exercise matching and provenance; the gate has its own tests.
        pack.set_meta(romwright_facts::pack::META_GATE_SHORT_BODY, "0").unwrap();
        for (game, license, name, code) in games {
            let id = pack.add_donor(&donor(game, license)).unwrap();
            pack.add_body(id, "main", Family::MipsLe, code, name, true).unwrap();
        }
        path
    }

    fn apply(core: &crate::Core, bytes: &ProgramBytes, pack: &Path, options: &FactPackOptions) -> FactPackReport {
        let report = FactPackReport { program: "synth".into(), language: MIPS.into(), ..Default::default() };
        core.apply_fact_pack_to("synth", bytes, &Pack::open(pack).unwrap(), options, report, None).unwrap()
    }

    #[test]
    fn renames_only_generated_names_and_records_donor_provenance() {
        let scratch = Scratch::new("rename");
        // One program, three functions; the pack knows all three bodies,
        // under different link addresses than the program's.
        let (a, b, c) = (body(10, 0x2000, 0x8002), body(30, 0x2000, 0x8002), body(50, 0x2000, 0x8002));
        let (core, bytes) = project(&scratch, &["FUN_00100000", "osReadSector", "FUN_00100200"], &[a, b, c]);
        let pack = build_pack(
            &scratch,
            &[
                ("game-a", "MIT", "ReadBlock", body(10, 0x1000, 0x8001)),
                ("game-b", "NONE", "OtherName", body(30, 0x1000, 0x8001)),
                ("game-c", "GPL-3.0-only", "FindThing", body(50, 0x1000, 0x8001)),
            ],
        );
        let report = apply(&core, &bytes, &pack, &FactPackOptions::default());
        assert_eq!((report.probed_functions, report.matched, report.renamed, report.kept_name), (3, 3, 2, 1));
        let by_address = |address: u64| report.matches.iter().find(|m| m.address == address).unwrap();
        assert_eq!(by_address(0x0010_0000).action, "renamed");
        assert_eq!(by_address(0x0010_0100).action, "kept_name");
        assert_eq!(by_address(0x0010_0000).length, 48);
        assert_eq!(by_address(0x0010_0000).our_size, Some(48));
        assert_eq!(by_address(0x0010_0000).compilers, ["test-cc 1.0"]);
        assert_eq!(report.implied_compiler.as_deref(), Some("test-cc 1.0"));
        assert_eq!(report.compilers["test-cc 1.0"], 3);
        let names: Vec<String> = core.functions("synth").unwrap().into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["ReadBlock", "osReadSector", "FindThing"]);
        // Provenance rows, including the one for the function that kept its name.
        let rows = core.signature_matches("synth").unwrap();
        assert_eq!(rows.len(), 3);
        let row = rows.iter().find(|r| r.name == "ReadBlock").unwrap();
        assert_eq!(row.provenance.source, SOURCE);
        assert_eq!(row.provenance.kind, FactKind::Inferred);
        assert_eq!(row.license, "MIT");
        assert!(row.package.contains("game-a example/game-a@0123456789ab"), "{}", row.package);
        assert_eq!(row.compared_bytes, 48);
        let kept = rows.iter().find(|r| r.name == "OtherName").unwrap();
        assert_eq!(kept.license, "NONE");
        assert_eq!(rows.iter().find(|r| r.name == "FindThing").unwrap().license, "GPL-3.0-only");
        // A second run changes nothing and leaves the names alone.
        let again = apply(&core, &bytes, &pack, &FactPackOptions::default());
        assert_eq!((again.renamed, again.kept_name), (0, 3));
        assert_eq!(core.signature_matches("synth").unwrap().len(), 3);
    }

    #[test]
    fn exclusions_ambiguity_and_stubs_abstain() {
        let scratch = Scratch::new("abstain");
        let shared = body(70, 0x2000, 0x8002);
        let (core, bytes) = project(
            &scratch,
            &["FUN_00100000", "FUN_00100100", "FUN_00100200", "FUN_00100300"],
            &[body(10, 0x2000, 0x8002), body(30, 0x2000, 0x8002), shared.clone(), shared],
        );
        let pack = build_pack(
            &scratch,
            &[
                ("game-a", "MIT", "ReadBlock", body(10, 0x1000, 0x8001)),
                // Two donors disagree on the second body.
                ("game-b", "MIT", "Alpha", body(30, 0x1000, 0x8001)),
                ("game-c", "MIT", "Beta", body(30, 0x1000, 0x8001)),
                // The third and fourth local functions share one donor body.
                ("game-d", "MIT", "Shared", body(70, 0x1000, 0x8001)),
            ],
        );
        let report = apply(&core, &bytes, &pack, &FactPackOptions::default());
        let action = |address: u64| report.matches.iter().find(|m| m.address == address).unwrap().action.clone();
        assert_eq!(action(0x0010_0000), "renamed");
        assert_eq!(action(0x0010_0100), "abstained");
        assert!(report.matches.iter().find(|m| m.address == 0x0010_0100).unwrap().ambiguous);
        assert_eq!(action(0x0010_0200), "abstained");
        assert_eq!(action(0x0010_0300), "abstained");
        assert_eq!(report.renamed, 1);
        let names: Vec<String> = core.functions("synth").unwrap().into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["ReadBlock", "FUN_00100100", "FUN_00100200", "FUN_00100300"]);
    }

    #[test]
    fn leave_one_out_removes_the_game_and_its_twin() {
        let scratch = Scratch::new("loo");
        let (core, bytes) = project(&scratch, &["FUN_00100000"], &[body(10, 0x2000, 0x8002)]);
        let path = scratch.0.join("pack.sqlite");
        {
            let pack = Pack::create(&path, 32, "test").unwrap();
            pack.set_meta(romwright_facts::pack::META_GATE_SHORT_BODY, "0").unwrap();
            for (game, twin) in [("ps2-ratchet-clank", Some("rc")), ("ps2-ratchet-clank-pal", Some("rc")), ("other", None)] {
                let mut d = donor(game, "MIT");
                d.twin_group = twin.map(String::from);
                let id = pack.add_donor(&d).unwrap();
                let name = if game == "other" { "OtherName" } else { "RcName" };
                pack.add_body(id, "main", Family::MipsLe, &body(10, 0x1000, 0x8001), name, false).unwrap();
            }
        }
        let report = apply(
            &core,
            &bytes,
            &path,
            &FactPackOptions { exclude_games: vec!["ps2-ratchet-clank-pal".into()], scan: false },
        );
        assert_eq!(report.matches[0].name.as_deref(), Some("OtherName"), "the excluded game's twin is gone too");
        assert_eq!(report.matches[0].donors, ["other"]);
    }

    /// 160 bytes: long enough to pass the default short-body gate.
    fn long_body(seed: u32, jal: u32, hi: u32) -> Vec<u8> {
        let mut words = vec![0x27BD_FFE0, 0xAFBF_0018];
        words.extend((0..35).map(|i| 0x2402_0000 | (seed + i)));
        words.extend([0x0C00_0000 | jal, 0x3C04_0000 | hi, 0x03E0_0008]);
        le(&words)
    }

    #[test]
    fn the_rename_gate_holds_short_bodies_without_independent_donors() {
        let scratch = Scratch::new("gate");
        let names = ["FUN_00100000", "FUN_00100100", "FUN_00100200", "FUN_00100300"];
        let (core, bytes) = project(
            &scratch,
            &names,
            &[
                body(10, 0x2000, 0x8002),      // short, one donor
                body(30, 0x2000, 0x8002),      // short, two donors of one twin group
                body(50, 0x2000, 0x8002),      // short, two independent donors
                long_body(70, 0x2000, 0x8002), // long, one donor
            ],
        );
        let path = scratch.0.join("pack.sqlite");
        {
            let pack = Pack::create(&path, 32, "test").unwrap();
            let add = |game: &str, twin: Option<&str>, name: &str, code: &[u8]| {
                let mut d = donor(game, "MIT");
                d.twin_group = twin.map(String::from);
                let id = pack.add_donor(&d).unwrap();
                pack.add_body(id, "main", Family::MipsLe, code, name, true).unwrap();
            };
            add("solo", None, "OneDonor", &body(10, 0x1000, 0x8001));
            add("rc", Some("rc"), "TwinName", &body(30, 0x1000, 0x8001));
            add("rc-pal", Some("rc"), "TwinName", &body(30, 0x1000, 0x8001));
            add("g1", None, "TwoDonors", &body(50, 0x1000, 0x8001));
            add("g2", None, "TwoDonors", &body(50, 0x1000, 0x8001));
            add("long", None, "LongOne", &long_body(70, 0x1000, 0x8001));
        }
        let report = apply(&core, &bytes, &path, &FactPackOptions::default());
        let action = |address: u64| report.matches.iter().find(|m| m.address == address).unwrap().action.clone();
        assert_eq!(action(0x0010_0000), "gated");
        assert_eq!(action(0x0010_0100), "gated");
        assert_eq!(action(0x0010_0200), "renamed");
        assert_eq!(action(0x0010_0300), "renamed");
        assert_eq!((report.renamed, report.gated, report.abstained), (2, 2, 0));
        assert_eq!(report.gate, Some(romwright_facts::pack::Gate { short_body: 128, min_donors: 2 }));
        let gated = report.matches.iter().find(|m| m.address == 0x0010_0100).unwrap();
        assert_eq!((gated.donors.len(), gated.independent), (2, 1));
        assert_eq!(gated.name.as_deref(), Some("TwinName"), "the report still shows the consensus");
        let stored: Vec<String> = core.functions("synth").unwrap().into_iter().map(|f| f.name).collect();
        assert_eq!(stored, ["FUN_00100000", "FUN_00100100", "TwoDonors", "LongOne"]);
        let rows = core.signature_matches("synth").unwrap();
        assert_eq!(rows.len(), 2, "gated candidates write no provenance rows");
        // The pack's meta moves the gate: with no short-body gate both are renamed.
        Pack::open_rw(&path).unwrap().set_meta(romwright_facts::pack::META_GATE_SHORT_BODY, "0").unwrap();
        let open = apply(&core, &bytes, &path, &FactPackOptions::default());
        assert_eq!((open.renamed, open.gated), (2, 0));
        // And raising min_donors gates the independent pair too (a fresh program state is not needed:
        // the already-renamed functions are kept_name, which the gate also holds).
        let pack = Pack::open_rw(&path).unwrap();
        pack.set_meta(romwright_facts::pack::META_GATE_SHORT_BODY, "128").unwrap();
        pack.set_meta(romwright_facts::pack::META_GATE_MIN_DONORS, "3").unwrap();
        drop(pack);
        let strict = apply(&core, &bytes, &path, &FactPackOptions::default());
        assert_eq!(strict.gate, Some(romwright_facts::pack::Gate { short_body: 128, min_donors: 3 }));
        assert_eq!(strict.gated, 4 - 1, "three short bodies are gated; the long one is not");
    }

    #[test]
    fn scan_reports_bodies_outside_functions_without_writing() {
        let scratch = Scratch::new("scan");
        let (core, mut bytes) = project(&scratch, &["FUN_00100000"], &[body(10, 0x2000, 0x8002)]);
        // An undiscovered body at 0x100080 (not a function entry).
        let hidden = body(90, 0x3000, 0x8003);
        bytes.mappings[0].bytes[0x80..0x80 + hidden.len()].copy_from_slice(&hidden);
        let pack = build_pack(
            &scratch,
            &[("game-a", "MIT", "Known", body(10, 0x1000, 0x8001)), ("game-b", "MIT", "Hidden", body(90, 0x1000, 0x8001))],
        );
        let without = apply(&core, &bytes, &pack, &FactPackOptions::default());
        assert_eq!(without.scan_only, 0);
        let report = apply(&core, &bytes, &pack, &FactPackOptions { exclude_games: vec![], scan: true });
        assert!(report.probed_scan > 0);
        let hit = report.matches.iter().find(|m| m.address == 0x0010_0080).expect("hidden body found");
        assert_eq!((hit.action.as_str(), hit.found, hit.length, hit.name.as_deref()), ("scan_only", false, 48, Some("Hidden")));
        // The covered function was not reported twice.
        assert_eq!(report.matches.iter().filter(|m| m.address == 0x0010_0000).count(), 1);
        let names: Vec<String> = core.functions("synth").unwrap().into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["Known"], "scan writes nothing");
        assert_eq!(core.signature_matches("synth").unwrap().len(), 1);
    }

    #[test]
    fn a_vsig_row_for_the_function_is_not_replaced() {
        let scratch = Scratch::new("vsig");
        let (core, bytes) = project(&scratch, &["FUN_00100000"], &[body(10, 0x2000, 0x8002)]);
        let db = core.store_handle().unwrap();
        let id = db.program_id("synth").unwrap();
        let revision = db.revision(id).unwrap();
        db.replace_signature_matches(
            id,
            revision,
            "signature-match",
            &[SignatureMatchRow {
                function: Address::ram(0x0010_0000),
                name: "FromVsig".into(),
                package: "sdk 1.0".into(),
                license: "MIT".into(),
                compared_bytes: 32,
                confidence: 0.9,
                input: None,
                provenance: FactProvenance { kind: FactKind::Inferred, source: "signature-match".into(), confidence: Some(0.9) },
            }],
            &[(Address::ram(0x0010_0000), "FromVsig".into())],
        )
        .unwrap();
        let pack = build_pack(&scratch, &[("game-a", "MIT", "ReadBlock", body(10, 0x1000, 0x8001))]);
        let report = apply(&core, &bytes, &pack, &FactPackOptions::default());
        assert_eq!(report.renamed, 0);
        assert_eq!(core.functions("synth").unwrap()[0].name, "FromVsig");
        let rows = core.signature_matches("synth").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].provenance.source, "signature-match");
    }

    #[test]
    fn build_reads_truth_through_the_mappings_and_reports_skips() {
        let scratch = Scratch::new("build");
        let (core, bytes) = project(&scratch, &["FUN_00100000"], &[body(10, 0x2000, 0x8002)]);
        // `add_donor_to_pack` reads the stored image; check the pieces it is built from.
        let truth = parse_truth(
            "start\tsize\tname\tmodule\tverified\n0x100000\t48\tReadBlock\tmain\t1\n0x100000\t16\tTiny\tmain\t0\n0x900000\t48\tNowhere\tmain\t0\n",
        )
        .unwrap();
        assert_eq!(truth.len(), 3);
        assert_eq!(truth[0], TruthRow { start: 0x100000, size: 48, name: "ReadBlock".into(), verified: true });
        assert!(bytes.window(truth[0].start).and_then(|w| w.get(..48)).is_some());
        assert!(bytes.window(truth[2].start).is_none());
        drop(core);
        assert_eq!(parse_prototypes("# c\nname\tdecl\nFoo\tint Foo(int a)\nBar = void Bar(void)\n").len(), 2);
    }

    #[test]
    fn declarations_become_library_declarations_in_the_languages_type_names() {
        let known: HashSet<String> =
            ["int", "uint", "char", "void", "uchar", "ushort", "float", "longlong"].iter().map(|s| s.to_string()).collect();
        let d = parse_declaration("const char *strstr(const char *haystack, const char *needle);", &known).unwrap();
        assert_eq!(crate::library_types::signature("strstr", &d), "char * strstr(char * haystack, char * needle)");
        let d = parse_declaration("unsigned int Hash(unsigned char *data, unsigned int len, ...)", &known).unwrap();
        assert_eq!(crate::library_types::signature("Hash", &d), "uint Hash(uchar * data, uint len, ...)");
        let d = parse_declaration("void Reset(void)", &known).unwrap();
        assert_eq!(crate::library_types::signature("Reset", &d), "void Reset(void)");
        let d = parse_declaration("int f(int, char)", &known).unwrap();
        assert_eq!(crate::library_types::signature("f", &d), "int f(int param_1, char param_2)");
        assert!(parse_declaration("s32 Foo(s32 a)", &known).is_none(), "unknown type names are left out");
        assert!(parse_declaration("struct Foo *Get(void)", &known).is_none());
        assert!(parse_declaration("int Call(void (*fn)(int))", &known).is_none());
        assert!(parse_declaration("not a declaration", &known).is_none());
    }

    #[test]
    fn pack_resolution_order() {
        // Explicit beats everything; the disable switch only turns off the implicit lookups.
        let explicit = Path::new("/tmp/explicit.sqlite");
        assert_eq!(resolve_pack(Some(explicit)), Some((explicit.to_path_buf(), true)));
    }
}
