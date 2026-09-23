//! Whole-program structural diff: matches the functions of one program onto
//! another and ports names across the match.
//!
//! The method is BinDiff's, not its code: match a few functions that can be
//! identified outright (an import thunk's name, a string only one function
//! reads, a feature profile only one function has), then propagate along the
//! call graph, because a function's neighbours in the call graph are the
//! strongest evidence about which function it is (Dullien & Rolles, "Graph-
//! based comparison of executable objects", SSTIC'05, §4: matching propagates
//! from a set of fixed points over the callgraph). None of it needs the
//! decompiler, so it runs in the JVM-free path over the facts the store
//! already holds: `functions` (entry, size, name), `xrefs` (calls, jumps,
//! data reads and writes), `strings`, `thunks`, `symbols`.
//!
//! What it is not: a library-identification pass. "Which known function is
//! this" is `romwright-sig`'s question, answered against a signature database of a
//! known build. This answers "which function in program B is this function of
//! program A", which is what porting names from a decompilation onto a retail
//! image, or diffing two builds, actually needs.

mod assign;
pub mod semantic;

use std::collections::{BTreeSet, HashMap, HashSet};

use romwright_db::ProjectDb;
use romwright_model::{Address, ThunkKind};

/// A failure reading either side of the diff.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("{0}")]
    Db(#[from] romwright_db::DbError),
    #[error("project has no program to diff")]
    NoProgram,
}

type Result<T> = std::result::Result<T, DiffError>;

/// Which matcher runs after the anchors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// Expand the anchor set over the call graph, taking the best local pair
    /// each round. This is the maximum-common-edge-subgraph strategy BinDiff
    /// and DeepBinDiff use (Dullien & Rolles, SSTIC'05, §4).
    Greedy,
    /// Solve the whole assignment at once as a network alignment problem:
    /// maximise `lambda * content similarity + (1 - lambda) * induced call
    /// edges` over one-to-one mappings (Mengin & Rossi, "Binary Diffing as a
    /// Network Alignment Problem via Belief Propagation", arXiv:2112.15337,
    /// §III). The quadratic objective is maximised by integer projected
    /// fixed point iteration: linearise at the current mapping, solve the
    /// resulting assignment exactly, repeat until it stops moving.
    Nap,
}

/// How the matcher is allowed to conclude.
#[derive(Clone, Debug)]
pub struct Options {
    /// Minimum similarity for a propagated match. Anchors bypass it: they
    /// are identified outright rather than scored.
    pub min_score: f64,
    /// Maximum propagation rounds. Each round matches at least one pair or
    /// the loop stops, so this only bounds pathological graphs.
    pub max_rounds: usize,
    /// Whether to run the final global pass over functions the call graph
    /// never reached. It matches only where a feature profile is unique on
    /// both sides, so it cannot pair two plausible candidates by accident.
    pub global_pass: bool,
    /// Which matcher runs after the anchors.
    pub matcher: Matcher,
    /// Content-versus-topology trade-off for `Matcher::Nap`. At 1.0 the
    /// call graph is ignored and the result is a maximum-weight matching on
    /// content alone; at 0.0 only induced call edges count.
    pub lambda: f64,
    /// How many candidate partners each function may have under
    /// `Matcher::Nap`. The quadratic problem is built over the candidate
    /// set, so this is what bounds its size (the paper's sparsity ratio).
    pub candidates: usize,
    /// Whether the BSim-style p-code evidence class contributes: the
    /// semantic term in content scoring and the mutual-best semantic pass.
    /// Off restores the purely structural matcher, which is what lets a
    /// gate measure the class with and without it.
    pub semantic: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // Measured on the corpus and on a zlib pair built at -O0 and
            // -O2 (benchmarks/reports/m12-001.json): at 0.85 the network
            // alignment beats the greedy strategy on precision, recall and
            // the share of ported names that are right, all three at once.
            min_score: 0.85,
            max_rounds: 64,
            global_pass: true,
            matcher: Matcher::Nap,
            lambda: 0.35,
            candidates: 12,
            semantic: true,
        }
    }
}

/// Why a pair was matched. Reported per row so a gate can score the classes
/// separately: an anchor and a propagated guess are not the same evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Evidence {
    /// Both sides carry the same non-generated name, unique on both sides.
    Name,
    /// Both are thunks to the same named import.
    Import,
    /// The same body bytes at the same address, unique on both sides.
    Body,
    /// The same masked bytes -- relocations and image addresses zeroed --
    /// unique on both sides: the same code, however loaded or relocated.
    /// Tier-0: reference lookups run before the structural match.
    Masked,
    /// The same decoded shape, unique on both sides: the same code, loaded
    /// or relocated differently.
    Shape,
    /// A string only this function reads, on both sides.
    String,
    /// A feature profile no other function on either side has.
    Profile,
    /// A callee or caller of an already-matched pair.
    CallGraph,
    /// Unique profile among what the call graph never reached.
    Global,
    /// Mutually-best p-code data-flow similarity at or above the semantic
    /// floor: the two bodies compute the same thing under different
    /// encodings. Unique on both sides by construction, like an anchor,
    /// but the evidence is similarity rather than identity.
    Semantic,
    /// The network alignment assigned it: content similarity and induced
    /// call edges weighed together.
    Alignment,
    /// Relevance decoding moved it there: the pairing as a whole preserves
    /// more call edges with the pair here than where the matchers put it.
    /// Raw similarity inverts among near-duplicate functions; context does
    /// not.
    Context,
}

/// One matched pair.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MatchRow {
    pub reference: Address,
    pub target: Address,
    pub reference_name: String,
    pub target_name: String,
    pub score: f64,
    pub evidence: Evidence,
}

/// A name the diff would port: `entry` in the target takes `name` from the
/// reference. Only functions whose target name is a generated one appear.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PortedName {
    pub entry: Address,
    pub name: String,
    pub score: f64,
    pub evidence: Evidence,
}

/// The whole answer: what matched, what would be renamed, and the sizes of
/// both sides so a caller can compute coverage without a second query.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DiffReport {
    pub reference_program: String,
    pub target_program: String,
    pub reference_functions: usize,
    pub target_functions: usize,
    pub anchors: usize,
    pub matches: Vec<MatchRow>,
    pub names: Vec<PortedName>,
}

/// True for a name analysis coined from an address rather than read from the
/// image. Ghidra's own prefixes (`SymbolUtilities.DEFAULT_*_PREFIX`) plus the
/// thunk form the store writes.
pub fn is_generated_name(name: &str) -> bool {
    const PREFIXES: [&str; 8] = [
        "FUN_", "LAB_", "SUB_", "DAT_", "UNK_", "EXT_", "OFF_", "PTR_",
    ];
    let bare = name.strip_prefix("thunk_").unwrap_or(name);
    PREFIXES.iter().any(|prefix| {
        bare.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

/// One function, reduced to the features a structural match can use.
#[derive(Clone, Debug, Default)]
struct Func {
    entry: u64,
    size: u64,
    name: String,
    /// Calls to functions of the same program, as indices.
    callees: Vec<usize>,
    callers: Vec<usize>,
    /// Names of imports and thunked targets this function calls.
    imports: BTreeSet<String>,
    /// String values read from the body.
    strings: BTreeSet<String>,
    /// Counts, not addresses: the addresses differ between builds.
    calls: u32,
    computed_jumps: u32,
    data_refs: u32,
    /// The named import this function is a thunk to, if it is one.
    thunk_to: Option<String>,
    /// Structural measurements, when the import recorded them.
    instructions: u32,
    blocks: u32,
    edges: u32,
    loops: u32,
    max_block: u32,
    /// Digest of the body bytes; equal digests are the same code at the same
    /// address. Empty when the body was never decoded.
    body_digest: String,
    /// Digest of the decoded shape; equal digests are the same code wherever
    /// it was loaded.
    shape_digest: String,
    /// Digest of the body bytes with relocations and image addresses
    /// masked; equal digests are the same instructions with the same
    /// constants, however loaded or relocated. The tier-0 anchor: looked
    /// up before the structural match runs.
    masked_digest: String,
    /// BSim-style data-flow signature, when the semantic index ran over
    /// this program. `None` is absence of evidence, never difference: the
    /// scorer drops the term rather than scoring it zero.
    semantic: Option<semantic::Signature>,
    /// Literal operands the indexing pass kept (`semantic::constants`);
    /// empty for an unindexed program, which drops the term.
    constants: BTreeSet<u64>,
}

/// One side of the diff.
pub struct Program {
    name: String,
    funcs: Vec<Func>,
}

impl Program {
    /// Reads one program's facts out of a project store.
    pub fn load(db: &ProjectDb, program: &str) -> Result<Self> {
        let id = db.program_id(program)?;
        let rows = db.functions(id)?;
        let mut funcs: Vec<Func> = rows
            .iter()
            .map(|row| Func {
                entry: row.entry.offset,
                size: row.size,
                name: row.name.clone(),
                ..Func::default()
            })
            .collect();
        funcs.sort_by_key(|f| f.entry);
        let entries: Vec<u64> = funcs.iter().map(|f| f.entry).collect();
        let by_entry: HashMap<u64, usize> = entries
            .iter()
            .enumerate()
            .map(|(index, &entry)| (entry, index))
            .collect();
        // A body ends at its proven size, or at the next entry when no size
        // was proven; two functions cannot overlap, so the next entry is the
        // hard bound either way.
        let ends: Vec<u64> = funcs
            .iter()
            .enumerate()
            .map(|(index, f)| {
                let next = entries.get(index + 1).copied().unwrap_or(u64::MAX);
                if f.size > 0 {
                    f.entry.saturating_add(f.size).min(next)
                } else {
                    next
                }
            })
            .collect();
        let owner = |address: u64| -> Option<usize> {
            let index = match entries.binary_search(&address) {
                Ok(index) => index,
                Err(0) => return None,
                Err(index) => index - 1,
            };
            (address < ends[index]).then_some(index)
        };

        let symbols: HashMap<u64, String> = db
            .symbols(id)?
            .into_iter()
            .map(|row| (row.address.offset, row.name))
            .collect();
        let strings: HashMap<u64, String> = db
            .strings(id)?
            .into_iter()
            .map(|row| (row.address.offset, row.value))
            .collect();
        // A thunk stands for the function it thunks: the name that matters is
        // the import's, at the slot or at the thunked entry.
        for row in db.thunks(id)? {
            let Some(index) = by_entry.get(&row.function.offset).copied() else {
                continue;
            };
            let named = symbols
                .get(&row.thunked.offset)
                .cloned()
                .or_else(|| match row.kind {
                    ThunkKind::Direct => by_entry
                        .get(&row.thunked.offset)
                        .map(|&target| funcs[target].name.clone())
                        .filter(|name| !is_generated_name(name)),
                    ThunkKind::Linkage => None,
                });
            funcs[index].thunk_to = named;
        }

        for row in db.function_features(id)? {
            if let Some(&index) = by_entry.get(&row.function.offset) {
                funcs[index].instructions = row.instructions;
                funcs[index].blocks = row.blocks;
                funcs[index].edges = row.edges;
                funcs[index].loops = row.loops;
                funcs[index].max_block = row.max_block;
                funcs[index].body_digest = row.body_digest;
                funcs[index].shape_digest = row.shape_digest;
                funcs[index].masked_digest = row.masked_digest;
            }
        }
        // Semantic signatures come from the explicit indexing pass, not
        // the import, so a program without them simply has none: every
        // term the scorer would build from one is dropped, and matching
        // falls back to the structural evidence alone.
        for row in db.semantic_signatures(id)? {
            if let Some(&index) = by_entry.get(&row.function.offset) {
                if row.ops > 0 {
                    funcs[index].semantic = semantic::Signature::parse_hex(&row.signature);
                }
                funcs[index].constants = row.constants.iter().copied().collect();
            }
        }

        for xref in db.xrefs(id)? {
            let Some(source) = owner(xref.from.offset) else {
                continue;
            };
            let destination = xref.to.offset;
            if xref.kind.contains("CALL") {
                funcs[source].calls += 1;
                match by_entry.get(&destination).copied() {
                    Some(target) => {
                        funcs[source].callees.push(target);
                        // A call to a thunk is a call to its import: record
                        // the name too, so both sides agree on it even when
                        // one build inlines the thunk away.
                        if let Some(import) = funcs[target].thunk_to.clone() {
                            funcs[source].imports.insert(import);
                        }
                    }
                    None => {
                        if let Some(name) = symbols.get(&destination) {
                            funcs[source].imports.insert(name.clone());
                        }
                    }
                }
                continue;
            }
            if xref.kind.contains("JUMP") && xref.kind.starts_with("COMPUTED") {
                funcs[source].computed_jumps += 1;
                continue;
            }
            if xref.kind.contains("READ") || xref.kind.contains("WRITE") || xref.kind == "DATA" {
                funcs[source].data_refs += 1;
                if let Some(value) = strings.get(&destination) {
                    funcs[source].strings.insert(value.clone());
                }
            }
        }

        for index in 0..funcs.len() {
            funcs[index].callees.sort_unstable();
            funcs[index].callees.dedup();
            let callees = funcs[index].callees.clone();
            for callee in callees {
                if callee != index {
                    funcs[callee].callers.push(index);
                }
            }
        }
        for func in &mut funcs {
            func.callers.sort_unstable();
            func.callers.dedup();
        }

        Ok(Self {
            name: program.to_string(),
            funcs,
        })
    }

    /// The program a project holds when the caller named none: a project with
    /// exactly one program needs no name, and naming the wrong one silently
    /// would diff two unrelated images.
    pub fn only_program(db: &ProjectDb) -> Result<String> {
        let mut programs = db.programs()?;
        match programs.len() {
            1 => Ok(programs.remove(0).program),
            _ => Err(DiffError::NoProgram),
        }
    }

    pub fn functions(&self) -> usize {
        self.funcs.len()
    }
}

/// Ratio similarity of two counts: 1.0 when equal, 0.0 when one is zero and
/// the other is not.
fn ratio(a: u64, b: u64) -> f64 {
    let (a, b) = (a as f64, b as f64);
    let high = a.max(b);
    if high == 0.0 {
        return 1.0;
    }
    a.min(b) / high
}

fn jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> Option<f64> {
    if a.is_empty() && b.is_empty() {
        return None;
    }
    let shared = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    Some(shared / union)
}

/// Matching state: the partner of each function on each side.
struct Pairing {
    reference: Vec<Option<usize>>,
    target: Vec<Option<usize>>,
}

impl Pairing {
    fn accept(&mut self, left: usize, right: usize) -> bool {
        if self.reference[left].is_some() || self.target[right].is_some() {
            return false;
        }
        self.reference[left] = Some(right);
        self.target[right] = Some(left);
        true
    }
}

/// Data-flow similarity of two functions, or `None` when either side has
/// no signature. Missing signatures drop the term rather than scoring it:
/// an unindexed program must match exactly as it did before indexing
/// existed.
fn semantic_similarity(a: &Func, b: &Func) -> Option<f64> {
    let (Some(left), Some(right)) = (a.semantic.as_ref(), b.semantic.as_ref()) else {
        return None;
    };
    left.similarity(right)
}

/// Similarity of two functions from their content alone -- everything that
/// does not depend on what else is matched. The network-alignment matcher
/// needs exactly this: its topology term is the induced-edge count, so a
/// content score that already folded neighbours in would count them twice.
fn content_score(a: &Func, b: &Func, options: &Options) -> f64 {
    // Weighted mean over the components that apply. A component with no
    // evidence on either side (neither reads a string, say) is dropped
    // rather than scored 1.0, which would reward having no features.
    let mut total = 0.0;
    let mut weight = 0.0;
    let mut add = |value: f64, w: f64| {
        total += value * w;
        weight += w;
    };
    add(ratio(a.size, b.size), 0.1);
    add(ratio(a.instructions.into(), b.instructions.into()), 0.15);
    add(ratio(a.blocks.into(), b.blocks.into()), 0.15);
    add(ratio(a.edges.into(), b.edges.into()), 0.1);
    // A loop count and the largest block survive a change of optimisation
    // level better than a byte count: the loops are in the source.
    add(ratio(a.loops.into(), b.loops.into()), 0.15);
    add(ratio(a.max_block.into(), b.max_block.into()), 0.1);
    // The same decoded shape is the same code: nothing else needs to agree.
    if !a.shape_digest.is_empty() && a.shape_digest == b.shape_digest {
        add(1.0, 1.0);
    }
    add(ratio(a.calls.into(), b.calls.into()), 0.1);
    add(ratio(a.callers.len() as u64, b.callers.len() as u64), 0.05);
    add(ratio(a.data_refs.into(), b.data_refs.into()), 0.05);
    add(
        ratio(a.computed_jumps.into(), b.computed_jumps.into()),
        0.05,
    );
    if let Some(value) = jaccard(&a.strings, &b.strings) {
        add(value, 0.3);
    }
    if let Some(value) = jaccard(&a.imports, &b.imports) {
        add(value, 0.2);
    }
    // Literal operands: magic values and masks are in the source, so they
    // survive a change of compiler that rewrites every count above.
    // Present whenever the program was indexed, independent of the
    // data-flow switch below; dropped when neither side kept one.
    if let Some(value) = jaccard(&a.constants, &b.constants) {
        add(value, semantic::CONSTANT_WEIGHT);
    }
    // Data-flow over p-code: what the body computes, not how it encodes
    // it. Dropped outright when the switch is off or either side has no
    // signature, so unindexed programs score exactly as before. And it
    // only ever raises: a low similarity is the expected state of two
    // builds the optimiser rewrote differently (measured median 0.56 for
    // true O0/O2 pairs on a 400-function corpus, where the true partner
    // routinely scores below a sibling that differs by one constant), so
    // blending it in would dilute a structural score that already clears
    // the floor. Only a similarity at or above the match floor joins the
    // mean; anything below leaves the structural score untouched.
    if options.semantic {
        if let Some(value) = semantic_similarity(a, b) {
            if value >= semantic::MATCH_FLOOR {
                add(value, semantic::SCORE_WEIGHT);
            }
        }
    }
    if weight == 0.0 { 0.0 } else { total / weight }
}

/// Similarity of two functions, given what is matched so far: content plus
/// the share of their matched neighbours that agree. This is the greedy
/// matcher's score; it is what makes propagation converge rather than drift.
fn score(reference: &Program, target: &Program, left: usize, right: usize, pairs: &Pairing, options: &Options) -> f64 {
    let a = &reference.funcs[left];
    let b = &target.funcs[right];
    let content = content_score(a, b, options);
    let mut total = content;
    let mut weight = 1.0;
    let mut add = |value: f64, w: f64| {
        total += value * w;
        weight += w;
    };
    let matched: Vec<usize> = a
        .callees
        .iter()
        .filter_map(|&callee| pairs.reference[callee])
        .collect();
    if !matched.is_empty() {
        let shared = matched
            .iter()
            .filter(|&&partner| b.callees.contains(&partner))
            .count() as f64;
        add(shared / matched.len() as f64, 0.5);
    }
    let matched_callers: Vec<usize> = a
        .callers
        .iter()
        .filter_map(|&caller| pairs.reference[caller])
        .collect();
    if !matched_callers.is_empty() {
        let shared = matched_callers
            .iter()
            .filter(|&&partner| b.callers.contains(&partner))
            .count() as f64;
        add(shared / matched_callers.len() as f64, 0.3);
    }
    total / weight
}

/// The key a function is identified by outright, when it has one.
fn profile(func: &Func) -> String {
    let mut key = String::with_capacity(64);
    key.push_str("p:");
    key.push_str(&func.shape_digest);
    key.push('/');
    key.push_str(&func.size.to_string());
    key.push('/');
    key.push_str(&func.instructions.to_string());
    key.push('/');
    key.push_str(&func.blocks.to_string());
    key.push('/');
    key.push_str(&func.edges.to_string());
    key.push('/');
    key.push_str(&func.loops.to_string());
    key.push('/');
    key.push_str(&func.calls.to_string());
    key.push('/');
    key.push_str(&func.computed_jumps.to_string());
    key.push('/');
    key.push_str(&func.data_refs.to_string());
    for import in &func.imports {
        key.push('|');
        key.push_str(import);
    }
    for value in &func.strings {
        key.push('\u{1}');
        key.push_str(value);
    }
    key
}

/// Indexes the values that occur exactly once, which is what makes a key
/// usable as an anchor: a key two functions share identifies neither.
fn unique_index<K: std::hash::Hash + Eq, F: Fn(&Func) -> Option<K>>(
    program: &Program,
    key: F,
) -> HashMap<K, usize> {
    let mut seen: HashMap<K, Option<usize>> = HashMap::new();
    for (index, func) in program.funcs.iter().enumerate() {
        if let Some(k) = key(func) {
            seen.entry(k)
                .and_modify(|slot| *slot = None)
                .or_insert(Some(index));
        }
    }
    seen.into_iter()
        .filter_map(|(k, slot)| slot.map(|index| (k, slot_value(index))))
        .collect()
}

fn slot_value(index: usize) -> usize {
    index
}

/// Shortest literal that may vote. Short text ("%s", "OK", "true") recurs
/// across unrelated functions in one build and is owned by exactly one
/// function in the other by accident. Twelve characters matches the SYM-0001
/// cross-compiler baseline's floor, which also required the literal to occur
/// once in the image; votes here require one owning function per side, a
/// weaker filter. Measured on that pair against its 286 names, with this
/// weaker filter: single-vote pairs 147/147 right, multi-vote 73/74 (the miss
/// matched the body of a function the target's import split in two).
const LITERAL_MIN_CHARS: usize = 12;

/// Pairs every literal-unique string votes for, keeping only pairs whose
/// votes are unanimous on both sides. Sorted, so acceptance order is
/// deterministic.
fn literal_votes(reference: &Program, target: &Program) -> Vec<(usize, usize)> {
    // The one function referencing each literal, or `None` once a second
    // function does.
    fn owners(program: &Program) -> HashMap<&str, Option<usize>> {
        let mut owner: HashMap<&str, Option<usize>> = HashMap::new();
        for (index, func) in program.funcs.iter().enumerate() {
            for value in &func.strings {
                if value.chars().count() < LITERAL_MIN_CHARS {
                    continue;
                }
                owner
                    .entry(value.as_str())
                    .and_modify(|slot| {
                        if *slot != Some(index) {
                            *slot = None;
                        }
                    })
                    .or_insert(Some(index));
            }
        }
        owner
    }
    let left_owner = owners(reference);
    let right_owner = owners(target);
    // Every function's votes, then unanimity from both ends.
    let mut left_votes: HashMap<usize, Option<usize>> = HashMap::new();
    let mut right_votes: HashMap<usize, Option<usize>> = HashMap::new();
    for (value, left) in &left_owner {
        let (Some(left), Some(Some(right))) = (*left, right_owner.get(value)) else {
            continue;
        };
        let right = *right;
        for (voter, choice, votes) in [(left, right, &mut left_votes), (right, left, &mut right_votes)] {
            votes
                .entry(voter)
                .and_modify(|slot| {
                    if *slot != Some(choice) {
                        *slot = None;
                    }
                })
                .or_insert(Some(choice));
        }
    }
    let mut pairs: Vec<(usize, usize)> = left_votes
        .iter()
        .filter_map(|(&left, &right)| {
            let right = right?;
            (right_votes.get(&right) == Some(&Some(left))).then_some((left, right))
        })
        .collect();
    pairs.sort_unstable();
    pairs
}

/// Matches `target` against `reference` and reports the names that would be
/// ported onto the target.
pub fn diff(reference: &Program, target: &Program, options: &Options) -> DiffReport {
    let mut pairs = Pairing {
        reference: vec![None; reference.funcs.len()],
        target: vec![None; target.funcs.len()],
    };
    let mut matches: Vec<MatchRow> = Vec::new();
    let mut anchors = 0usize;
    // 1. Anchors, strongest first. Each is a key that occurs once on each
    // side, so accepting it cannot be a choice between candidates.
    let anchor_keys: [(Evidence, fn(&Func) -> Option<String>); 7] = [
        (Evidence::Body, |func: &Func| {
            (!func.body_digest.is_empty()).then(|| format!("b:{}", func.body_digest))
        }),
        (Evidence::Masked, |func: &Func| {
            // Tier-0: an exact masked-bytes match is the same instructions
            // with the same constants, however loaded. A body shorter than
            // four instructions is a stub: too many functions share one
            // for it to identify anything, masked or not.
            (func.instructions >= 4 && !func.masked_digest.is_empty())
                .then(|| format!("m:{}", func.masked_digest))
        }),
        (Evidence::Shape, |func: &Func| {
            // A shape shorter than four instructions is a stub: too many
            // functions share one for it to identify anything.
            (func.instructions >= 4).then(|| format!("h:{}", func.shape_digest))
        }),
        (Evidence::Import, |func: &Func| {
            func.thunk_to.clone().map(|name| format!("t:{name}"))
        }),
        (Evidence::Name, |func: &Func| {
            (!is_generated_name(&func.name)).then(|| format!("n:{}", func.name))
        }),
        (Evidence::String, |func: &Func| {
            (func.strings.len() == 1).then(|| {
                let value = func.strings.iter().next().expect("one string");
                format!("s:{value}")
            })
        }),
        (Evidence::Profile, |func: &Func| {
            // A bare profile (straight-line code, no calls, no imports,
            // no strings) lives in a tiny key space: unrelated small
            // functions collide across programs and anchor wrong. The key
            // only identifies when it names something only the function
            // knows -- an import it calls or a string it references.
            (!func.imports.is_empty() || !func.strings.is_empty()).then(|| profile(func))
        }),
    ];
    for (evidence, key) in anchor_keys {
        let left_index = unique_index(reference, key);
        let right_index = unique_index(target, key);
        let mut hits: Vec<(usize, usize)> = left_index
            .iter()
            .filter_map(|(k, &left)| right_index.get(k).map(|&right| (left, right)))
            .collect();
        hits.sort_unstable();
        for (left, right) in hits {
            if pairs.accept(left, right) {
                anchors += 1;
                matches.push(row(reference, target, left, right, 1.0, evidence));
            }
        }
    }
    // 1a'. Literal votes. A string literal referenced by exactly one
    // function on each side votes for that pair; the pair anchors only
    // when every such vote from either function agrees, so a conflict
    // withholds the pair instead of choosing. This is the string evidence
    // one-string keys cannot use: most functions that print or look up
    // text reference several literals, and those survive a change of
    // compiler where sizes and shapes do not.
    for (left, right) in literal_votes(reference, target) {
        if pairs.accept(left, right) {
            anchors += 1;
            matches.push(row(reference, target, left, right, 1.0, Evidence::String));
        }
    }
    // 1b. Structural round one, from the anchors alone. Raw data-flow
    // similarity inverts among near-duplicate functions, so the semantic
    // seeds must not commit before the call graph has said its piece.
    if options.matcher == Matcher::Nap {
        align(reference, target, &mut pairs, options, &mut matches);
    } else {
        propagate(reference, target, &mut pairs, options, &mut matches);
    }

    // 1c. Semantic pairs: what is still unmatched but computes the same
    // thing on both sides. Each open function names its best partner by
    // data-flow similarity; a pair is taken only when both sides name
    // each other, uniquely, at or above the floor. Mutual-best is the
    // one-to-one condition for free: two functions cannot both be the
    // unique best partner of the same function. They join the anchors
    // and round one as seeds, so round two builds on all three.
    if options.semantic {
        semantic_pass(reference, target, &mut pairs, &mut matches);
    }

    // 1d. Structural round two: the neighbourhoods the semantic seeds
    // open were unreachable before, and the alignment's second run
    // measures its topology term against them.
    if options.matcher == Matcher::Nap {
        align(reference, target, &mut pairs, options, &mut matches);
    } else {
        propagate(reference, target, &mut pairs, options, &mut matches);
    }

/// 2. Propagation: only the neighbours of matched pairs are considered, so
/// the candidate set stays small and the evidence stays local. Runs to
/// fixpoint; calling it again after new seeds land extends the reached
/// neighbourhoods.
fn propagate(
    reference: &Program,
    target: &Program,
    pairs: &mut Pairing,
    options: &Options,
    matches: &mut Vec<MatchRow>,
) {
    if options.matcher != Matcher::Greedy {
        return;
    }
    for _ in 0..options.max_rounds {
        let mut candidates: HashSet<(usize, usize)> = HashSet::new();
        for left in 0..reference.funcs.len() {
            let Some(right) = pairs.reference[left] else {
                continue;
            };
            let a = &reference.funcs[left];
            let b = &target.funcs[right];
            for (left_side, right_side) in [(&a.callees, &b.callees), (&a.callers, &b.callers)] {
                for &l in left_side {
                    if pairs.reference[l].is_some() {
                        continue;
                    }
                    for &r in right_side {
                        if pairs.target[r].is_none() {
                            candidates.insert((l, r));
                        }
                    }
                }
            }
        }
        if candidates.is_empty() {
            break;
        }
        let mut scored: Vec<(f64, usize, usize)> = candidates
            .into_iter()
            .map(|(l, r)| (score(reference, target, l, r, &pairs, options), l, r))
            .filter(|&(value, _, _)| value >= options.min_score)
            .collect();
        // Best first; a stable order over equal scores keeps the result
        // deterministic, which the gates depend on.
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then((a.1, a.2).cmp(&(b.1, b.2)))
        });
        // An ambiguous best -- two candidates for the same function with the
        // same score -- is not evidence, so neither is taken.
        let mut ambiguous_left: HashMap<usize, f64> = HashMap::new();
        let mut ambiguous_right: HashMap<usize, f64> = HashMap::new();
        let mut ambiguous: HashSet<(usize, usize)> = HashSet::new();
        for &(value, l, r) in &scored {
            if let Some(&best) = ambiguous_left.get(&l) {
                if (best - value).abs() < f64::EPSILON {
                    ambiguous.insert((l, r));
                }
            } else {
                ambiguous_left.insert(l, value);
            }
            if let Some(&best) = ambiguous_right.get(&r) {
                if (best - value).abs() < f64::EPSILON {
                    ambiguous.insert((l, r));
                }
            } else {
                ambiguous_right.insert(r, value);
            }
        }
        let mut accepted = 0usize;
        for (value, l, r) in scored {
            if ambiguous.contains(&(l, r)) {
                continue;
            }
            if pairs.accept(l, r) {
                accepted += 1;
                matches.push(row(reference, target, l, r, value, Evidence::CallGraph));
            }
        }
        if accepted == 0 {
            break;
        }
    }
}

    // 3. What the call graph never reached: leaf functions nobody calls in
    // either build. Only a profile unique on both sides is taken.
    if options.global_pass {
        let left_index = unique_index(reference, |func| {
            Some(profile(func)).filter(|_| func.calls > 0 || !func.strings.is_empty())
        });
        let right_index = unique_index(target, |func| {
            Some(profile(func)).filter(|_| func.calls > 0 || !func.strings.is_empty())
        });
        let mut hits: Vec<(usize, usize)> = left_index
            .iter()
            .filter_map(|(k, &left)| right_index.get(k).map(|&right| (left, right)))
            .collect();
        hits.sort_unstable();
        for (left, right) in hits {
            if pairs.accept(left, right) {
                matches.push(row(reference, target, left, right, 1.0, Evidence::Global));
            }
        }
    }

    // 4. Relevance decoding over everything committed: raw similarity
    // inverts among near-duplicates, so each matcher-committed pair
    // reconsiders its target in call-graph context. Strict improvement
    // only, so this pass can only raise the alignment objective, never
    // scatter what the matchers found.
    decode(reference, target, &mut pairs, options, &mut matches);
    withdraw_unsupported(reference, target, &mut pairs, &mut matches);
    // 5. What the withdrawal left open next to what it kept: pairs the
    // call graph now vouches for.
    extend_supported(reference, target, &mut pairs, options, &mut matches);
    matches.sort_by_key(|row| (row.target.offset, row.reference.offset));
    let names = matches
        .iter()
        .filter(|row| {
            is_generated_name(&row.target_name) && !is_generated_name(&row.reference_name)
        })
        .map(|row| PortedName {
            entry: row.target.clone(),
            name: row.reference_name.clone(),
            score: row.score,
            evidence: row.evidence,
        })
        .collect();
    DiffReport {
        reference_program: reference.name.clone(),
        target_program: target.name.clone(),
        reference_functions: reference.funcs.len(),
        target_functions: target.funcs.len(),
        anchors,
        matches,
        names,
    }
}

/// A choice between candidates tied on preserved edges is only made on
/// content when the winner leads the runner-up by this much. Measured on
/// the game modules (boot/base/driving): no tie-break at all leaves recall
/// at 0.9299, breaking every tie takes 0.9386 but its added rows are 79%
/// right, and 0.2 lands 0.9784/0.9332 with the rows 87% right; on the
/// GCC-Mac/MSVC-Windows pair the added rows carry 0.2% Mac-only names at
/// 0.2 against 0.7% with every tie broken.
const EXTEND_MARGIN: f64 = 0.2;

/// Pairs open functions through the call edges they would preserve with
/// what is already matched: a pair gets one vote per matched neighbour
/// pair it sits under or over. A pair is taken when it is the most-voted
/// partner of both its functions -- ties at the top broken on content only
/// past `EXTEND_MARGIN` -- which is what makes each accepted pair
/// supported by construction. No content floor: the vote is the evidence
/// (on the modules, a floor of 0.425 lost more right pairs than wrong).
/// Repeats until nothing is accepted, since each round's pairs vote in
/// the next.
fn extend_supported(
    reference: &Program,
    target: &Program,
    pairs: &mut Pairing,
    options: &Options,
    matches: &mut Vec<MatchRow>,
) {
    // (votes, partner, content, runner-up content at the same votes)
    type Best = (u32, usize, f64, Option<f64>);
    loop {
        let mut votes: HashMap<(usize, usize), u32> = HashMap::new();
        for left in 0..reference.funcs.len() {
            let Some(right) = pairs.reference[left] else {
                continue;
            };
            let a = &reference.funcs[left];
            let b = &target.funcs[right];
            for (lefts, rights) in [(&a.callees, &b.callees), (&a.callers, &b.callers)] {
                for &l in lefts {
                    if pairs.reference[l].is_some() {
                        continue;
                    }
                    for &r in rights {
                        if pairs.target[r].is_none() {
                            *votes.entry((l, r)).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        let mut scored: Vec<((usize, usize), u32, f64)> = votes
            .into_iter()
            .map(|((l, r), n)| {
                let content = content_score(&reference.funcs[l], &target.funcs[r], options);
                ((l, r), n, content)
            })
            .collect();
        // Index order, so equal contents resolve the same way every run.
        scored.sort_unstable_by_key(|&(pair, _, _)| pair);
        let mut best_left: HashMap<usize, Best> = HashMap::new();
        let mut best_right: HashMap<usize, Best> = HashMap::new();
        for &((l, r), n, content) in &scored {
            for (best, key, partner) in [(&mut best_left, l, r), (&mut best_right, r, l)] {
                match best.get_mut(&key) {
                    Some(top) if n > top.0 => *top = (n, partner, content, None),
                    Some(top) if n == top.0 => {
                        if content > top.2 {
                            *top = (n, partner, content, Some(top.2));
                        } else {
                            top.3 = Some(top.3.map_or(content, |second| second.max(content)));
                        }
                    }
                    Some(_) => {}
                    None => {
                        best.insert(key, (n, partner, content, None));
                    }
                }
            }
        }
        let clear = |top: &Best| top.3.is_none_or(|second| top.2 - second >= EXTEND_MARGIN);
        let mut lefts: Vec<(usize, Best)> = best_left.into_iter().collect();
        lefts.sort_unstable_by_key(|&(l, _)| l);
        let mut accepted = 0usize;
        for (l, top) in lefts {
            let r = top.1;
            if clear(&top)
                && best_right.get(&r).is_some_and(|back| back.1 == l && clear(back))
                && pairs.accept(l, r)
            {
                matches.push(row(reference, target, l, r, top.2, Evidence::CallGraph));
                accepted += 1;
            }
        }
        if accepted == 0 {
            return;
        }
    }
}

/// Records one similarity observation for a function's best partner.
/// A strictly better value replaces; an equal one marks the tie, which
/// disqualifies the function from the mutual-best pass outright.
fn note_best(best: &mut Option<(usize, f64, bool)>, partner: usize, value: f64) {
    match best {
        Some((_, top, _)) if value > *top => *best = Some((partner, value, false)),
        Some((_, top, tied)) if (value - *top).abs() <= f64::EPSILON => *tied = true,
        None => *best = Some((partner, value, false)),
        _ => {}
    }
}

/// Mutual-best semantic matches over the pairs still unmatched. Each open
/// function with a signature names its highest-similarity partner; a pair
/// is a hit only when both sides name each other, the best is unique on
/// both sides, and the similarity reaches the semantic floor. The score a
/// row carries is the similarity itself, so a gate can threshold the class
/// further.
///
/// Hits commit strongest-first, and each must survive the call graph: a
/// hit that contradicts it -- paired neighbours on either side with none
/// preserved -- is deferred, because data-flow similarity inverts among
/// near-duplicate functions (measured on zlib, where false pairs score
/// 0.93-0.97 and steal targets from the true ones). A hit a preserved
/// call edge confirms, or one with no paired neighbours to judge it, is
/// taken. This is the relevance-decoding step: inter-function context
/// ranks candidates that raw similarity cannot separate.
fn semantic_pass(
    reference: &Program,
    target: &Program,
    pairs: &mut Pairing,
    matches: &mut Vec<MatchRow>,
) {
    // Best partner per side, in index order so ties resolve
    // deterministically: the first index keeps a tied best, and a tie is
    // recorded by the strict comparison below.
    let mut left_best: Vec<Option<(usize, f64, bool)>> = vec![None; reference.funcs.len()];
    let mut right_best: Vec<Option<(usize, f64, bool)>> = vec![None; target.funcs.len()];
    for left in 0..reference.funcs.len() {
        if pairs.reference[left].is_some() || reference.funcs[left].semantic.is_none() {
            continue;
        }
        for right in 0..target.funcs.len() {
            if pairs.target[right].is_some() || target.funcs[right].semantic.is_none() {
                continue;
            }
            let Some(value) = semantic_similarity(&reference.funcs[left], &target.funcs[right])
            else {
                continue;
            };
            note_best(&mut left_best[left], right, value);
            note_best(&mut right_best[right], left, value);
        }
    }
    let mut hits: Vec<(usize, usize, f64)> = Vec::new();
    for (left, best) in left_best.iter().enumerate() {
        let Some((right, value, tied)) = best else {
            continue;
        };
        if *tied || *value < semantic::MATCH_FLOOR {
            continue;
        }
        let mutual = matches!(right_best[*right], Some((partner, _, false)) if partner == left);
        if mutual {
            hits.push((left, *right, *value));
        }
    }
    // Strongest first, indices breaking ties: acceptance order is the
    // decoding order, so it must be deterministic, which the gates need.
    hits.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then((a.0, a.1).cmp(&(b.0, b.1)))
    });
    for (left, right, value) in hits {
        if pairs.reference[left].is_some() || pairs.target[right].is_some() {
            continue;
        }
        // Call-graph support among the pairs already taken: neighbours
        // matched on both sides, and how many of those pairings this hit
        // would preserve.
        let a = &reference.funcs[left];
        let b = &target.funcs[right];
        let mut judged = 0u32;
        let mut preserved = 0u32;
        for &callee in &a.callees {
            if let Some(mapped) = pairs.reference[callee] {
                judged += 1;
                if b.callees.contains(&mapped) {
                    preserved += 1;
                }
            }
        }
        for &caller in &a.callers {
            if let Some(mapped) = pairs.reference[caller] {
                judged += 1;
                if b.callers.contains(&mapped) {
                    preserved += 1;
                }
            }
        }
        if judged > 0 && preserved == 0 {
            continue;
        }
        if pairs.accept(left, right) {
            matches.push(row(reference, target, left, right, value, Evidence::Semantic));
        }
    }
}

/// One round of network alignment over the pairs still unmatched.
///
/// Maximises `lambda * content + (1 - lambda) * induced-call-edges` by
/// integer projected fixed point iteration (Leordeanu et al., NIPS'09) over
/// the candidate set: linearise the quadratic objective at the current
/// mapping -- the gradient of the topology term at a mapping is exactly the
/// number of call edges a pair would induce with it -- solve that assignment
/// exactly, and repeat until the mapping stops moving.
fn align(
    reference: &Program,
    target: &Program,
    pairs: &mut Pairing,
    options: &Options,
    matches: &mut Vec<MatchRow>,
) {
    let open_left: Vec<usize> = (0..reference.funcs.len())
        .filter(|&index| pairs.reference[index].is_none())
        .collect();
    let open_right: Vec<usize> = (0..target.funcs.len())
        .filter(|&index| pairs.target[index].is_none())
        .collect();
    if open_left.is_empty() || open_right.is_empty() {
        return;
    }
    let right_slot: HashMap<usize, u32> = open_right
        .iter()
        .enumerate()
        .map(|(slot, &index)| (index, slot as u32))
        .collect();

    // Candidates: each open function keeps its best few partners by content.
    // The quadratic problem lives on this set, so it is what bounds the cost
    // (the paper's sparsity ratio; here a fixed width per function, which
    // does not grow with the image).
    let mut candidates: Vec<(u32, u32, f64)> = Vec::new();
    let mut scratch: Vec<(f64, usize)> = Vec::with_capacity(open_right.len());
    for (slot, &left) in open_left.iter().enumerate() {
        scratch.clear();
        for &right in &open_right {
            let value = content_score(&reference.funcs[left], &target.funcs[right], options);
            if value > 0.0 {
                scratch.push((value, right));
            }
        }
        scratch.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.cmp(&b.1))
        });
        for &(value, right) in scratch.iter().take(options.candidates) {
            candidates.push((slot as u32, right_slot[&right], value));
        }
    }
    if candidates.is_empty() {
        return;
    }

    // The mapping the topology term is measured against: everything already
    // matched, plus whatever the last iteration proposed.
    let mut proposal: Vec<Option<usize>> = vec![None; reference.funcs.len()];
    let mut best: Vec<Option<u32>> = vec![None; open_left.len()];
    for round in 0..options.max_rounds.max(1) {
        let partner = |left: usize| -> Option<usize> {
            pairs.reference[left].or(proposal[left])
        };
        let edges: Vec<assign::Edge> = candidates
            .iter()
            .map(|&(left_slot, right_slot_index, content)| {
                let left = open_left[left_slot as usize];
                let right = open_right[right_slot_index as usize];
                let a = &reference.funcs[left];
                let b = &target.funcs[right];
                // Induced edges ("squares"): a call this pair would preserve
                // is one whose other end is already mapped onto a callee (or
                // caller) of the target function.
                let mut squares = 0u32;
                for &callee in &a.callees {
                    if let Some(mapped) = partner(callee) {
                        if b.callees.contains(&mapped) {
                            squares += 1;
                        }
                    }
                }
                for &caller in &a.callers {
                    if let Some(mapped) = partner(caller) {
                        if b.callers.contains(&mapped) {
                            squares += 1;
                        }
                    }
                }
                // Normalised by the degree either side offers, so a pair of
                // hubs cannot outvote every leaf in the program.
                let degree = (a.callees.len() + a.callers.len())
                    .max(b.callees.len() + b.callers.len())
                    .max(1) as f64;
                let topology = f64::from(squares) / degree;
                assign::Edge {
                    left: left_slot,
                    right: right_slot_index,
                    weight: options.lambda * content + (1.0 - options.lambda) * topology
                        - options.lambda * options.min_score,
                }
            })
            .collect();
        let assignment = assign::max_weight_matching(open_left.len(), open_right.len(), &edges);
        if assignment == best && round > 0 {
            break;
        }
        best = assignment;
        proposal.iter_mut().for_each(|slot| *slot = None);
        for (slot, matched) in best.iter().enumerate() {
            if let Some(right_slot_index) = matched {
                proposal[open_left[slot]] = Some(open_right[*right_slot_index as usize]);
            }
        }
    }

    // Commit: a pair whose content is below the floor is only taken when the
    // call graph vouches for it, which is the whole point of the alignment.
    for (slot, matched) in best.iter().enumerate() {
        let Some(right_slot_index) = matched else {
            continue;
        };
        let left = open_left[slot];
        let right = open_right[*right_slot_index as usize];
        let content = content_score(&reference.funcs[left], &target.funcs[right], options);
        // How much the call graph vouches for the pair: every call it would
        // preserve. One shared neighbour is weak evidence -- in a program
        // where everything calls the allocator, every function has it -- so
        // a pair below the content floor needs two.
        let squares = reference.funcs[left]
            .callees
            .iter()
            .filter_map(|&callee| pairs.reference[callee].or(proposal[callee]))
            .filter(|mapped| target.funcs[right].callees.contains(mapped))
            .count()
            + reference.funcs[left]
                .callers
                .iter()
                .filter_map(|&caller| pairs.reference[caller].or(proposal[caller]))
                .filter(|mapped| target.funcs[right].callers.contains(mapped))
                .count();
        if content < options.min_score && !(squares >= 2 && content >= options.min_score / 2.0) {
            continue;
        }
        if pairs.accept(left, right) {
            matches.push(row(
                reference,
                target,
                left,
                right,
                content,
                Evidence::Alignment,
            ));
        }
    }
}

/// Preserved call edges of the pair under the pairing: callees and
/// callers of the reference already mapped onto callees and callers of
/// the target, with the pair itself left out so a mutual recursion can
/// never vote for itself.
fn preserved(
    reference: &Program,
    target: &Program,
    left: usize,
    right: usize,
    pairs: &Pairing,
) -> u32 {
    let mut squares = 0u32;
    for &callee in &reference.funcs[left].callees {
        if callee != left
            && let Some(mapped) = pairs.reference[callee]
            && target.funcs[right].callees.contains(&mapped)
        {
            squares += 1;
        }
    }
    for &caller in &reference.funcs[left].callers {
        if caller != left
            && let Some(mapped) = pairs.reference[caller]
            && target.funcs[right].callers.contains(&mapped)
        {
            squares += 1;
        }
    }
    squares
}

/// The relevance-decoding objective of one committed pair: the
/// alignment's own blend of content similarity and degree-normalised
/// preserved edges.
fn pair_weight(
    reference: &Program,
    target: &Program,
    left: usize,
    right: usize,
    pairs: &Pairing,
    options: &Options,
) -> f64 {
    let a = &reference.funcs[left];
    let b = &target.funcs[right];
    let degree = (a.callees.len() + a.callers.len())
        .max(b.callees.len() + b.callers.len())
        .max(1) as f64;
    options.lambda * content_score(a, b, options)
        + (1.0 - options.lambda) * f64::from(preserved(reference, target, left, right, pairs))
            / degree
}

/// The change a move makes to the whole pairing's objective (the sum of
/// every committed pair's weight), computed exactly from the terms it can
/// touch. A pair's weight reads only its own partner and its call-graph
/// neighbours' partners, so moving the references in `moved` changes the
/// terms of those references and their neighbours and no others. Summing
/// only that neighbourhood before and after is the global difference
/// without the global sum, which at 10k+ committed pairs was the whole
/// cost of decoding.
fn affected(reference: &Program, moved: &[usize]) -> Vec<usize> {
    let mut set: Vec<usize> = moved.to_vec();
    for &left in moved {
        let func = &reference.funcs[left];
        set.extend(func.callees.iter().chain(&func.callers).copied());
    }
    set.sort_unstable();
    set.dedup();
    set
}

fn local_weight(
    reference: &Program,
    target: &Program,
    around: &[usize],
    pairs: &Pairing,
    options: &Options,
) -> f64 {
    around
        .iter()
        .filter_map(|&left| pairs.reference[left].map(|right| (left, right)))
        .map(|(left, right)| pair_weight(reference, target, left, right, pairs, options))
        .sum()
}

/// Relevance decoding over the committed pairing: coordinate ascent on
/// the alignment objective. Raw similarity inverts among near-duplicate
/// functions -- measured on zlib, where false pairs score up to 0.97 and
/// steal targets from the true ones -- so each committed reference
/// reconsiders its target in call-graph context: an open shortlist
/// candidate, or a swap with another committed pair. A move lands only
/// on a strict improvement of the whole pairing's objective, which is
/// what makes the iteration terminate; index order makes it
/// deterministic. Anchors and global leaves never move: a unique key is
/// not a choice between candidates.
fn decode(
    reference: &Program,
    target: &Program,
    pairs: &mut Pairing,
    options: &Options,
    matches: &mut Vec<MatchRow>,
) {
    const ROUNDS: usize = 8;
    // Rows a move must rewrite, by reference index: anchors and global
    // leaves are absent, so they can neither move nor be blamed.
    let movable = |evidence: Evidence| {
        matches!(
            evidence,
            Evidence::Alignment | Evidence::CallGraph | Evidence::Semantic
        )
    };
    let mut index_of: HashMap<u64, usize> = HashMap::with_capacity(reference.funcs.len());
    for (index, func) in reference.funcs.iter().enumerate() {
        index_of.entry(func.entry).or_insert(index);
    }
    let mut row_of: Vec<Option<usize>> = vec![None; reference.funcs.len()];
    for (index, row) in matches.iter().enumerate() {
        if !movable(row.evidence) {
            continue;
        }
        if let Some(&left) = index_of.get(&row.reference.offset) {
            row_of[left] = Some(index);
        }
    }
    // Content shortlist per movable reference, over every target: only
    // pairs that clear the commit floor are eligible destinations.
    // Context breaks ties between plausible pairs; it never installs a
    // pairing the content score would not take on its own (measured: an
    // unfloored pass moved a correct 0.87-content pair to a 0.62 one for
    // two shared neighbours). The current partner rides along even when
    // its content is low, since leaving is always an option the search
    // must price, not a destination it can choose.
    let mut shortlist: Vec<Vec<usize>> = vec![Vec::new(); reference.funcs.len()];
    // Every target a movable reference may be installed on (content at or
    // above the floor), sorted: a swap needs both installed pairs to clear
    // the floor, so only the holders of these targets can be swap partners.
    let mut eligible: Vec<Vec<u32>> = vec![Vec::new(); reference.funcs.len()];
    for left in 0..reference.funcs.len() {
        if row_of[left].is_none() {
            continue;
        }
        let mut scored: Vec<(f64, usize)> = (0..target.funcs.len())
            .map(|right| {
                (
                    content_score(&reference.funcs[left], &target.funcs[right], options),
                    right,
                )
            })
            .filter(|(value, _)| *value >= options.min_score)
            .collect();
        eligible[left] = scored.iter().map(|&(_, right)| right as u32).collect();
        eligible[left].sort_unstable();
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.cmp(&b.1))
        });
        shortlist[left] = scored
            .into_iter()
            .take(options.candidates)
            .map(|(_, right)| right)
            .collect();
        if let Some(held) = pairs.reference[left]
            && !shortlist[left].contains(&held)
        {
            shortlist[left].push(held);
        }
    }
    let retarget = |pairs: &mut Pairing, matches: &mut Vec<MatchRow>, left: usize, right: usize| {
        pairs.reference[left] = Some(right);
        pairs.target[right] = Some(left);
        if let Some(index) = row_of[left] {
            let content = content_score(&reference.funcs[left], &target.funcs[right], options);
            matches[index].target = Address::ram(target.funcs[right].entry);
            matches[index].target_name = target.funcs[right].name.clone();
            matches[index].score = content;
            matches[index].evidence = Evidence::Context;
        }
    };
    for _ in 0..ROUNDS {
        let mut moved = false;
        for left in 0..reference.funcs.len() {
            if row_of[left].is_none() {
                continue;
            }
            let mut best: Option<(usize, Option<usize>, f64)> = None;
            // Moves to an open target first (target index order), then
            // swaps with committed pairs (reference index order): a
            // free target never pays for a displacement it never caused.
            let around = affected(reference, &[left]);
            for &right in &shortlist[left] {
                if pairs.reference[left] == Some(right) {
                    continue;
                }
                if pairs.target[right].is_some() {
                    continue;
                }
                let held = pairs.reference[left].expect("movable is committed");
                let before = local_weight(reference, target, &around, pairs, options);
                pairs.reference[left] = Some(right);
                pairs.target[held] = None;
                pairs.target[right] = Some(left);
                let gain = local_weight(reference, target, &around, pairs, options) - before;
                pairs.reference[left] = Some(held);
                pairs.target[held] = Some(left);
                pairs.target[right] = None;
                if gain > 0.0 && best.is_none_or(|(_, _, top)| gain > top) {
                    best = Some((right, None, gain));
                }
            }
            let held = pairs.reference[left].expect("movable is committed");
            // Swap partners: movable holders of a target `left` may take
            // whose own content clears the floor on `held`.
            let mut others: Vec<usize> = eligible[left]
                .iter()
                .filter_map(|&right| pairs.target[right as usize])
                .filter(|&other| {
                    other != left
                        && row_of[other].is_some()
                        && eligible[other].binary_search(&(held as u32)).is_ok()
                })
                .collect();
            others.sort_unstable();
            for other in others {
                let other_held = pairs.reference[other].expect("movable is committed");
                if held == other_held {
                    continue;
                }
                let around = affected(reference, &[left, other]);
                let before = local_weight(reference, target, &around, pairs, options);
                pairs.reference[left] = Some(other_held);
                pairs.reference[other] = Some(held);
                pairs.target[held] = Some(other);
                pairs.target[other_held] = Some(left);
                let gain = local_weight(reference, target, &around, pairs, options) - before;
                pairs.reference[left] = Some(held);
                pairs.reference[other] = Some(other_held);
                pairs.target[held] = Some(left);
                pairs.target[other_held] = Some(other);
                if gain > 0.0 && best.is_none_or(|(_, _, top)| gain > top) {
                    best = Some((other_held, Some(other), gain));
                }
            }
            match best {
                Some((right, None, _)) => {
                    let held = pairs.reference[left].expect("movable is committed");
                    pairs.target[held] = None;
                    retarget(pairs, matches, left, right);
                    moved = true;
                }
                Some((right, Some(other), _)) => {
                    let held = pairs.reference[left].expect("movable is committed");
                    retarget(pairs, matches, other, held);
                    retarget(pairs, matches, left, right);
                    moved = true;
                }
                None => {}
            }
        }
        if !moved {
            break;
        }
    }
}

/// Withdraws every matcher-committed pair (alignment, context, call-graph)
/// that preserves no call edge of the final pairing. Content similarity
/// alone does not identify a function: measured on a GCC Mac / MSVC
/// Windows build of one game, unsupported pairs placed Mac-only names on
/// Windows code at the pool's own rate (9.5% vs 8.7%, so placement no
/// better than chance), with a median content score of 0.92, while pairs
/// preserving two or more edges placed 1 in 2,231. Anchors, global leaves
/// and semantic pairs are not choices between candidates and stay.
/// Withdrawing a pair can strip its neighbours of their only preserved
/// edge, so this runs to a fixed point.
fn withdraw_unsupported(
    reference: &Program,
    target: &Program,
    pairs: &mut Pairing,
    matches: &mut Vec<MatchRow>,
) -> usize {
    let mut index_of: HashMap<u64, usize> = HashMap::with_capacity(reference.funcs.len());
    for (index, func) in reference.funcs.iter().enumerate() {
        index_of.entry(func.entry).or_insert(index);
    }
    let mut withdrawn = 0usize;
    loop {
        let unsupported: Vec<(usize, usize)> = matches
            .iter()
            .filter(|row| {
                matches!(
                    row.evidence,
                    Evidence::Alignment | Evidence::Context | Evidence::CallGraph
                )
            })
            .filter_map(|row| {
                let left = index_of[&row.reference.offset];
                let right = pairs.reference[left].expect("a row is a committed pair");
                (preserved(reference, target, left, right, pairs) == 0).then_some((left, right))
            })
            .collect();
        if unsupported.is_empty() {
            return withdrawn;
        }
        for &(left, right) in &unsupported {
            pairs.reference[left] = None;
            pairs.target[right] = None;
        }
        matches.retain(|row| pairs.reference[index_of[&row.reference.offset]].is_some());
        withdrawn += unsupported.len();
    }
}

fn row(
    reference: &Program,
    target: &Program,
    left: usize,
    right: usize,
    score: f64,
    evidence: Evidence,
) -> MatchRow {
    MatchRow {
        reference: Address::ram(reference.funcs[left].entry),
        target: Address::ram(target.funcs[right].entry),
        reference_name: reference.funcs[left].name.clone(),
        target_name: target.funcs[right].name.clone(),
        score,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{FactProvenance, FunctionRow, StringRow, SymbolRow, ThunkRow, XrefRow};

    fn provenance() -> FactProvenance {
        FactProvenance {
            source: "native-import:thunk".into(),
            kind: romwright_model::FactKind::Inferred,
            confidence: None,
        }
    }

    struct Build {
        db: ProjectDb,
    }

    /// Builds a program with the shape:
    ///   entry -> helper -> puts(import)
    ///   entry reads "hello"
    /// at whatever base the caller names, so the two sides share structure
    /// and share no addresses.
    fn build(base: u64, sizes: [u64; 3], name: &str) -> Build {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db
            .upsert_program(name, "x86:LE:64:default", &prov_row())
            .unwrap();
        let entry = base;
        let helper = base + 0x100;
        let thunk = base + 0x200;
        let slot = base + 0x1000;
        let text = base + 0x2000;
        db.replace_functions(
            id,
            &[
                FunctionRow {
                    entry: Address::ram(entry),
                    name: format!("FUN_{entry:08x}"),
                    size: sizes[0],
                    signature: None,
                    traced: false,
            calling_convention: None,
                },
                FunctionRow {
                    entry: Address::ram(helper),
                    name: format!("FUN_{helper:08x}"),
                    size: sizes[1],
                    signature: None,
                    traced: false,
            calling_convention: None,
                },
                FunctionRow {
                    entry: Address::ram(thunk),
                    name: format!("FUN_{thunk:08x}"),
                    size: sizes[2],
                    signature: None,
                    traced: false,
            calling_convention: None,
                },
            ],
        )
        .unwrap();
        db.replace_symbols(
            id,
            &[SymbolRow {
                name: "puts".into(),
                address: Address::ram(slot),
                external: true,
                source: "IMPORTED".into(),
            }],
        )
        .unwrap();
        db.replace_strings(
            id,
            &[StringRow {
                address: Address::ram(text),
                value: "hello".into(),
                kind: "string".into(),
            }],
        )
        .unwrap();
        db.replace_inferred_thunks(
            id,
            "native-import:thunk",
            &[ThunkRow {
                function: Address::ram(thunk),
                thunked: Address::ram(slot),
                kind: ThunkKind::Linkage,
                provenance: provenance(),
            }],
        )
        .unwrap();
        db.replace_xrefs(
            id,
            &[
                XrefRow {
                    from: Address::ram(entry + 4),
                    to: Address::ram(helper),
                    kind: "UNCONDITIONAL_CALL".into(),
                    function: None,
                    provenance: provenance(),
                },
                XrefRow {
                    from: Address::ram(entry + 8),
                    to: Address::ram(text),
                    kind: "READ".into(),
                    function: None,
                    provenance: provenance(),
                },
                XrefRow {
                    from: Address::ram(helper + 4),
                    to: Address::ram(thunk),
                    kind: "UNCONDITIONAL_CALL".into(),
                    function: None,
                    provenance: provenance(),
                },
            ],
        )
        .unwrap();
        Build { db }
    }

    fn prov_row() -> romwright_model::Provenance {
        romwright_model::Provenance {
            producer: "test".into(),
            upstream_version: "0".into(),
        }
    }

    fn named(db: &ProjectDb, program: &str, entry: u64, name: &str) {
        let id = db.program_id(program).unwrap();
        db.rename_function(id, &Address::ram(entry), name).unwrap();
    }

    #[test]
    fn structure_matches_across_bases_and_ports_names() {
        let left = build(0x400000, [0x40, 0x30, 0x10], "ref");
        let right = build(0x800000, [0x40, 0x30, 0x10], "tgt");
        named(&left.db, "ref", 0x400000, "main");
        named(&left.db, "ref", 0x400100, "greet");
        let reference = Program::load(&left.db, "ref").unwrap();
        let target = Program::load(&right.db, "tgt").unwrap();
        let report = diff(&reference, &target, &Options::default());
        let ported: Vec<(u64, &str)> = report
            .names
            .iter()
            .map(|row| (row.entry.offset, row.name.as_str()))
            .collect();
        assert!(
            ported.contains(&(0x800000, "main")),
            "main not ported: {ported:?}"
        );
        assert!(
            ported.contains(&(0x800100, "greet")),
            "greet not ported: {ported:?}"
        );
    }

    #[test]
    fn a_size_change_still_matches_through_the_call_graph() {
        // The optimised build has different body sizes; the string, the
        // import and the graph still identify both functions.
        let left = build(0x400000, [0x40, 0x30, 0x10], "ref");
        let right = build(0x800000, [0x90, 0x18, 0x10], "tgt");
        named(&left.db, "ref", 0x400100, "greet");
        let reference = Program::load(&left.db, "ref").unwrap();
        let target = Program::load(&right.db, "tgt").unwrap();
        let report = diff(&reference, &target, &Options::default());
        assert_eq!(
            report
                .names
                .iter()
                .find(|row| row.entry.offset == 0x800100)
                .map(|row| row.name.as_str()),
            Some("greet"),
            "matches: {:?}",
            report.matches
        );
    }

    #[test]
    fn unrelated_programs_match_nothing_on_score() {
        let left = build(0x400000, [0x40, 0x30, 0x10], "ref");
        let right = ProjectDb::open_in_memory().unwrap();
        let id = right
            .upsert_program("tgt", "x86:LE:64:default", &prov_row())
            .unwrap();
        // One huge function, no calls, no strings, no imports: nothing about
        // it resembles the reference.
        right
            .replace_functions(
                id,
                &[FunctionRow {
                    entry: Address::ram(0x900000),
                    name: "FUN_00900000".into(),
                    size: 0x4000,
                    signature: None,
                    traced: false,
            calling_convention: None,
                }],
            )
            .unwrap();
        named(&left.db, "ref", 0x400000, "main");
        let reference = Program::load(&left.db, "ref").unwrap();
        let target = Program::load(&right, "tgt").unwrap();
        let report = diff(&reference, &target, &Options::default());
        assert!(report.names.is_empty(), "ported: {:?}", report.names);
    }

    /// A callee the other build rewrote past content recognition is still
    /// identified by where it sits: its caller is matched, and it is the
    /// caller's only open callee on each side.
    #[test]
    fn an_open_callee_is_paired_through_its_matched_caller() {
        let func = |entry: u64, name: &str, size: u64, instructions: u32, blocks: u32| Func {
            entry,
            size,
            name: name.into(),
            instructions,
            blocks,
            edges: blocks.saturating_sub(1),
            max_block: instructions / blocks.max(1),
            ..Func::default()
        };
        let program = |base: u64, callee: Func| {
            let mut funcs = vec![func(base, "main", 0x40, 12, 2), callee];
            funcs[0].calls = 1;
            funcs[0].callees = vec![1];
            funcs[1].callers = vec![0];
            Program {
                name: "p".into(),
                funcs,
            }
        };
        let reference = program(0x400000, func(0x400100, "FUN_00400100", 0x20, 6, 1));
        let target = program(0x800000, func(0x800100, "FUN_00800100", 0x400, 180, 14));
        let options = Options {
            semantic: false,
            ..Options::default()
        };
        let report = diff(&reference, &target, &options);
        let callee = report
            .matches
            .iter()
            .find(|row| row.reference.offset == 0x400100)
            .map(|row| row.target.offset);
        assert_eq!(callee, Some(0x800100), "{:?}", report.matches);
    }

    /// The cross-compiler failure: a function one build has and the other
    /// lacks resembles some unrelated function closely by counts alone.
    /// With no call edge between them, content is all that pairs them,
    /// and content is not identity: the pair must not be reported, while
    /// the pair the call graph vouches for stays.
    #[test]
    fn a_content_only_pair_with_no_preserved_call_is_withdrawn() {
        let func = |entry: u64, size: u64, instructions: u32| Func {
            entry,
            size,
            name: format!("FUN_{entry:08x}"),
            instructions,
            blocks: 1,
            edges: 0,
            max_block: instructions,
            ..Func::default()
        };
        // caller -> callee, plus one leaf nothing calls.
        let program = |base: u64, leaf_name: &str| {
            let mut funcs = vec![
                func(base, 0x40, 3),
                func(base + 0x100, 0x18, 2),
                func(base + 0x200, 0x90, 3),
            ];
            funcs[0].calls = 1;
            funcs[0].callees = vec![1];
            funcs[1].callers = vec![0];
            funcs[2].name = leaf_name.into();
            Program {
                name: "p".into(),
                funcs,
            }
        };
        let reference = program(0x400000, "mac_only");
        let mut target = program(0x800000, "FUN_00800200");
        // The target's leaf is some other function of the same shape.
        target.funcs[2].name = "FUN_00800200".into();
        let options = Options {
            semantic: false,
            ..Options::default()
        };
        let report = diff(&reference, &target, &options);
        let paired = |offset: u64| {
            report
                .matches
                .iter()
                .find(|row| row.reference.offset == offset)
                .map(|row| row.target.offset)
        };
        assert_eq!(paired(0x400100), Some(0x800100), "{:?}", report.matches);
        assert_eq!(paired(0x400200), None, "{:?}", report.matches);
    }

    /// Two programs, each with the same computation under different
    /// register allocation plus one unrelated function: the structural
    /// counts differ across builds (as -O0 and -O2 do), so only the
    /// data-flow signature identifies the pair.
    fn semantic_programs() -> (Program, Program) {
        use semantic::{SemOp, SemVar};
        // Same computation, two allocations: every register moved, widths
        // kept. Normalisation makes the two op streams identical.
        fn computation(base: u64) -> Vec<SemOp> {
            let reg = |index: u64| SemVar {
                space: "register".into(),
                offset: base + index,
                size: 8,
            };
            let tmp = |index: u64| SemVar {
                space: "unique".into(),
                offset: index,
                size: 8,
            };
            vec![
                SemOp {
                    opcode: "COPY".into(),
                    output: Some(tmp(1)),
                    inputs: vec![reg(0)],
                },
                SemOp {
                    opcode: "INT_ADD".into(),
                    output: Some(tmp(2)),
                    inputs: vec![
                        tmp(1),
                        SemVar {
                            space: "const".into(),
                            offset: 16,
                            size: 8,
                        },
                    ],
                },
                SemOp {
                    opcode: "INT_MULT".into(),
                    output: Some(tmp(3)),
                    inputs: vec![tmp(2), reg(1)],
                },
            ]
        }
        fn other() -> Vec<SemOp> {
            vec![
                SemOp::plain("INT_SLESS", &[("register", 4, 8), ("const", 0, 8)]),
                SemOp::plain("CBRANCH", &[("ram", 0x402000, 8), ("unique", 9, 1)]),
                SemOp::plain("RETURN", &[("unique", 10, 8)]),
            ]
        }
        // A third computation, sharing nothing with `other` but its
        // widths: different opcodes, different constants.
        fn other_build() -> Vec<SemOp> {
            vec![
                SemOp::plain("LOAD", &[("ram", 0x500000, 8), ("unique", 20, 8)]),
                SemOp::plain("INT_XOR", &[("unique", 20, 8), ("const", 7, 8)]),
                SemOp::plain("INT_ZEXT", &[("unique", 20, 2)]),
            ]
        }
        let reference = Program {
            name: "ref".into(),
            funcs: vec![
                Func {
                    entry: 0x400100,
                    size: 64,
                    name: "calc".into(),
                    instructions: 20,
                    blocks: 4,
                    edges: 5,
                    loops: 1,
                    max_block: 8,
                    calls: 1,
                    data_refs: 2,
                    semantic: Some(semantic::signature(&computation(0x10))),
                    ..Func::default()
                },
                Func {
                    entry: 0x400200,
                    size: 200,
                    name: "other".into(),
                    instructions: 80,
                    blocks: 9,
                    edges: 12,
                    loops: 0,
                    max_block: 30,
                    calls: 4,
                    data_refs: 9,
                    semantic: Some(semantic::signature(&other())),
                    ..Func::default()
                },
            ],
        };
        let target = Program {
            name: "tgt".into(),
            funcs: vec![
                Func {
                    entry: 0x800100,
                    size: 40,
                    name: "FUN_00800100".into(),
                    instructions: 12,
                    blocks: 3,
                    edges: 3,
                    loops: 1,
                    max_block: 6,
                    calls: 1,
                    data_refs: 2,
                    semantic: Some(semantic::signature(&computation(0x28))),
                    ..Func::default()
                },
                Func {
                    entry: 0x800200,
                    size: 30,
                    name: "FUN_00800200".into(),
                    instructions: 6,
                    blocks: 2,
                    edges: 1,
                    loops: 2,
                    max_block: 3,
                    calls: 0,
                    data_refs: 1,
                    semantic: Some(semantic::signature(&other_build())),
                    ..Func::default()
                },
            ],
        };
        (reference, target)
    }

    #[test]
    fn semantic_pass_matches_same_computation_across_builds() {
        let (reference, target) = semantic_programs();
        // Greedy: with no anchor seeds the propagation rounds take
        // nothing, so the pair can only match in the semantic pass.
        // Under the default network alignment the pair's content (with
        // its 1.0 data-flow term) already clears the floor and commits
        // as alignment evidence before the semantic pass runs.
        let options = Options {
            matcher: Matcher::Greedy,
            ..Options::default()
        };
        let report = diff(&reference, &target, &options);
        let calc = report
            .matches
            .iter()
            .find(|row| row.reference.offset == 0x400100)
            .expect("same computation must match");
        assert_eq!(calc.target.offset, 0x800100);
        assert_eq!(calc.evidence, Evidence::Semantic);
        assert!(
            (calc.score - 1.0).abs() < 1e-9,
            "identical data-flow must score 1.0, got {}",
            calc.score
        );
        // The unrelated pair shares no computation and differs
        // structurally: nothing may claim it.
        assert!(
            report
                .matches
                .iter()
                .all(|row| row.reference.offset != 0x400200),
            "unrelated function matched: {:?}",
            report.matches
        );
    }

    #[test]
    fn semantic_off_leaves_restructured_pair_unmatched() {
        let (reference, target) = semantic_programs();
        let options = Options {
            semantic: false,
            ..Options::default()
        };
        let report = diff(&reference, &target, &options);
        // Structural content alone sits below the floor (0.80 < 0.85)
        // with no call graph to vouch: the pair needs the data-flow
        // term, so switching the class off must lose it rather than
        // match it worse.
        assert!(
            report
                .matches
                .iter()
                .all(|row| row.reference.offset != 0x400100),
            "pair matched without its evidence: {:?}",
            report.matches
        );
        assert!(
            report
                .matches
                .iter()
                .all(|evidence| evidence.evidence != Evidence::Semantic),
            "semantic evidence with the class off: {:?}",
            report.matches
        );
    }

    #[test]
    fn low_similarity_leaves_the_structural_score_untouched() {
        // Same structure, unrelated data-flow: the similarity sits far
        // below the floor, so the semantic term must drop out and the
        // score must equal the semantic-off score exactly. This is the
        // regression test for the many.c `main` loss, where a 0.53
        // similarity diluted a 0.9052 structural score below the commit
        // floor and cost a correct alignment match.
        let (reference, target) = semantic_programs();
        let left = reference.funcs.iter().position(|f| f.entry == 0x400200).unwrap();
        let right = target.funcs.iter().position(|f| f.entry == 0x800100).unwrap();
        let on = Options::default();
        let off = Options { semantic: false, ..Options::default() };
        let similarity =
            semantic_similarity(&reference.funcs[left], &target.funcs[right]).unwrap();
        assert!(
            similarity < semantic::MATCH_FLOOR,
            "test needs a below-floor pair, got {similarity}"
        );
        assert_eq!(content_score(&reference.funcs[left], &target.funcs[right], &on), content_score(&reference.funcs[left], &target.funcs[right], &off));
    }

    #[test]
    fn generated_names_are_recognised() {
        assert!(is_generated_name("FUN_00400000"));
        assert!(is_generated_name("thunk_FUN_00400000"));
        assert!(is_generated_name("LAB_002106f4"));
        assert!(!is_generated_name("main"));
        assert!(!is_generated_name("FUN_helper"));
        assert!(!is_generated_name("_start"));
    }
}
