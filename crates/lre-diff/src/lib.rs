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
//! this" is `lre-sig`'s question, answered against a signature database of a
//! known build. This answers "which function in program B is this function of
//! program A", which is what porting names from a decompilation onto a retail
//! image, or diffing two builds, actually needs.

mod assign;

use std::collections::{BTreeSet, HashMap, HashSet};

use lre_db::ProjectDb;
use lre_model::{Address, ThunkKind};

/// A failure reading either side of the diff.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("{0}")]
    Db(#[from] lre_db::DbError),
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
    /// The network alignment assigned it: content similarity and induced
    /// call edges weighed together.
    Alignment,
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

fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> Option<f64> {
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

/// Similarity of two functions from their content alone -- everything that
/// does not depend on what else is matched. The network-alignment matcher
/// needs exactly this: its topology term is the induced-edge count, so a
/// content score that already folded neighbours in would count them twice.
fn content_score(a: &Func, b: &Func) -> f64 {
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
    if weight == 0.0 { 0.0 } else { total / weight }
}

/// Similarity of two functions, given what is matched so far: content plus
/// the share of their matched neighbours that agree. This is the greedy
/// matcher's score; it is what makes propagation converge rather than drift.
fn score(reference: &Program, target: &Program, left: usize, right: usize, pairs: &Pairing) -> f64 {
    let a = &reference.funcs[left];
    let b = &target.funcs[right];
    let content = content_score(a, b);
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
    let anchor_keys: [(Evidence, fn(&Func) -> Option<String>); 6] = [
        (Evidence::Body, |func: &Func| {
            (!func.body_digest.is_empty()).then(|| format!("b:{}", func.body_digest))
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
        (Evidence::Profile, |func: &Func| Some(profile(func))),
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

    if options.matcher == Matcher::Nap {
        align(reference, target, &mut pairs, options, &mut matches);
    }

    // 2. Propagation: only the neighbours of matched pairs are considered, so
    // the candidate set stays small and the evidence stays local.
    for _ in 0..options.max_rounds {
        if options.matcher != Matcher::Greedy {
            break;
        }
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
            .map(|(l, r)| (score(reference, target, l, r, &pairs), l, r))
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
            let value = content_score(&reference.funcs[left], &target.funcs[right]);
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
        let content = content_score(&reference.funcs[left], &target.funcs[right]);
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
    use lre_model::{FactProvenance, FunctionRow, StringRow, SymbolRow, ThunkRow, XrefRow};

    fn provenance() -> FactProvenance {
        FactProvenance {
            source: "native-import:thunk".into(),
            kind: lre_model::FactKind::Inferred,
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
                    calling_convention: None,
                },
                FunctionRow {
                    entry: Address::ram(helper),
                    name: format!("FUN_{helper:08x}"),
                    size: sizes[1],
                    signature: None,
                    calling_convention: None,
                },
                FunctionRow {
                    entry: Address::ram(thunk),
                    name: format!("FUN_{thunk:08x}"),
                    size: sizes[2],
                    signature: None,
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

    fn prov_row() -> lre_model::Provenance {
        lre_model::Provenance {
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
