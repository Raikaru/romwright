//! Jump tables from abstract interpretation, not from a pattern.
//!
//! The pass beside this one (`vsa`) emulates a dispatch's straight-line
//! window for a couple of index values and requires the shape it knows: a
//! load whose address moves with the index, bounded by a guard branch in
//! the immediately preceding block. Everything that shape misses is a
//! refusal, and on libc that is 59 dispatches with no load it recognised
//! and 126 where enumeration produced fewer than two targets.
//!
//! SJA (Nguyen, Priyadarshan & Sekar, "Scalable, Sound, and Accurate Jump
//! Table Analysis", ISSTA 2024, doi:10.1145/3650212.3680301) makes the same
//! recovery a *forward abstract interpretation* over the function's whole
//! control-flow graph with a relational value domain, so a table is found
//! because the analysis proves what the branch target can be, not because
//! the code looks like something. This is that, over our p-code:
//!
//! * the domain is `base + stride * [lo, hi]`, plus constants and a top --
//!   SJA's `B + S*I`, without the nested-dereference extension;
//! * a comparison a branch reads refines the index interval on the edge
//!   that assumes it, which is where the bound comes from: no guard has to
//!   sit in any particular block, and any comparison on any path can supply
//!   it;
//! * a load of a strided address is followed into the image, so the value
//!   read is itself strided when the table holds a stride;
//! * the fixpoint is over blocks in reverse post-order with a widening at
//!   loop headers, so an index the loop increments does not diverge.
//!
//! **The soundness this can claim is conditional, and the condition is
//! ours, not the paper's.** SJA is sound when the analysis runs on every
//! function; on a stripped image ours runs where discovery found a
//! function, so a table inside code nobody attributed to a function is
//! missed and no claim covers it. What is claimed here is narrower and
//! checkable: where the interval is bounded by a comparison and every
//! materialised target decodes inside the branching function, the answer is
//! reported as proven; everything else is reported as a refusal with the
//! reason.

use std::collections::BTreeMap;

use crate::native_runtime::{PcodeInstruction, PcodeVarnode};

use super::vsa::{Image, SwitchTable};

/// The largest table this pass will materialise. Ghidra's own jump-table
/// model caps at 1024 (`JumpTable::maxaddsub`-adjacent limits in
/// `jumptable.cc`); a bigger "table" is a sign the bound is wrong.
const MAX_TABLE: i64 = 1024;

/// A value, in the relational domain.
/// A bounded set of concrete values, kept in the order they were read.
pub type SetValue = std::rc::Rc<Vec<u64>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Nothing is known.
    Top,
    Const(u64),
    /// An explicit, bounded set of values in index order. A jump table
    /// holds whatever addresses the compiler put in it, so the domain has
    /// to be able to say "one of these" -- a progression is the rare case,
    /// not the general one.
    Set(SetValue),
    /// `base + stride * index`, with the index in `[lo, hi]`. `guarded`
    /// marks a bound a comparison stated; a bound that is only a width
    /// (a zero-extension's `0..=2^w-1`) is not a guard, and a table read
    /// from it would read past the table.
    Strided {
        base: u64,
        stride: u64,
        lo: i64,
        hi: i64,
        guarded: bool,
    },
}

impl Value {
    fn join(self, other: Value) -> Value {
        use Value::*;
        match (self, other) {
            (left, right) if left == right => left,
            (Const(left), Const(right)) => {
                // Two constants are a two-element set; the domain keeps the
                // range they span with a stride that reaches both, which is
                // exact when they differ by one step.
                let (low, high) = (left.min(right), left.max(right));
                Strided { base: low, stride: high - low, lo: 0, hi: 1, guarded: true }
            }
            (
                Strided { base: left_base, stride: left_stride, lo: left_lo, hi: left_hi, guarded: left_guarded },
                Strided { base: right_base, stride: right_stride, lo: right_lo, hi: right_hi, guarded: right_guarded },
            ) if left_base == right_base && left_stride == right_stride => Strided {
                base: left_base,
                stride: left_stride,
                lo: left_lo.min(right_lo),
                hi: left_hi.max(right_hi),
                // The union interval is still true; it just cannot drive a
                // table read unless both sides were guarded.
                guarded: left_guarded && right_guarded,
            },
            (Set(left), Set(right)) => {
                let mut all = (*left).clone();
                all.extend(right.iter().copied());
                if all.len() as i64 > MAX_TABLE {
                    Top
                } else {
                    Set(std::rc::Rc::new(all))
                }
            }
            (Set(values), Const(value)) | (Const(value), Set(values)) => {
                let mut all = (*values).clone();
                all.push(value);
                if all.len() as i64 > MAX_TABLE {
                    Top
                } else {
                    Set(std::rc::Rc::new(all))
                }
            }
            // A constant that continues the progression extends it. This is
            // what reading a table entry at a time produces, and without it
            // the third entry of every table collapsed the value to top.
            (
                Strided { base, stride, lo, hi, guarded },
                Const(value),
            )
            | (
                Const(value),
                Strided { base, stride, lo, hi, guarded },
            ) if stride != 0 => {
                let offset = value.wrapping_sub(base) as i64;
                let step = stride as i64;
                if step != 0 && offset % step == 0 {
                    let index = offset / step;
                    Strided {
                        base,
                        stride,
                        lo: lo.min(index),
                        hi: hi.max(index),
                        guarded,
                    }
                } else {
                    Top
                }
            }
            _ => Top,
        }
    }

    /// The concrete values this stands for, when there are few enough to
    /// enumerate.
    fn concrete(&self) -> Option<Vec<u64>> {
        match self {
            Value::Set(values) => Some((**values).clone()),
            Value::Const(value) => Some(vec![*value]),
            Value::Strided { base, stride, lo, hi, guarded } => {
                if hi < lo || hi - lo + 1 > MAX_TABLE {
                    return None;
                }
                Some(
                    (*lo..=*hi)
                        .map(|index| base.wrapping_add(stride.wrapping_mul(index as u64)))
                        .collect(),
                )
            }
            Value::Top => None,
        }
    }

    fn bounded(&self) -> bool {
        matches!(self, Value::Set(_))
            || matches!(self, Value::Const(_))
            || matches!(self, Value::Strided { lo, hi, .. } if *hi >= *lo && *hi - *lo + 1 <= MAX_TABLE)
    }
}

/// A varnode, as a key: space and offset identify storage, and a read at a
/// narrower width is the same storage.
type Slot = (String, u64);

/// A remembered comparison: compared slot, constant, `<=`, constant-left,
/// operand width, in-place shift stamp, whether it came straight from
/// a comparison (see the `State` field docs), and whether the comparison
/// was signed (`INT_SLESS`): a signed bound constrains below zero, so
/// the unsigned origin-nonnegativity floor does not apply to it.
type Predicate = (Slot, u64, bool, bool, u32, Option<i64>, bool, bool);

fn slot(varnode: &PcodeVarnode) -> Slot {
    (varnode.space.clone(), varnode.offset)
}

/// The abstract state of one program point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    values: BTreeMap<Slot, Value>,
    /// Booleans whose meaning is "these slots are at most these constants".
    /// They travel with the state because a comparison and the branch that
    /// reads it are often in different blocks -- a flag set before a call
    /// and tested after it is ordinary code. One boolean can carry several
    /// bounds: a range check `lo <= x && x < hi` is two comparisons ANDed,
    /// and keeping only the first loses the bound the dispatch needs. The
    /// trailing `u32` of each bound is the compared operand's width: a bound
    /// on `al` is a bound on one byte, whatever wider slot it was copied from.
    /// The trailing `bool` records whether the bound came straight from a
    /// comparison (polarity known: it holds on exactly one edge) or through
    /// a flag combination (polarity unknown: both-edges defense).
    /// Each bound also snapshots the affine translation its operand
    /// carried when the comparison ran: `p = (x < 64)` before `x -= 64`
    /// translates through `(x, -64)`; `q = (x < 4)` after translates
    /// through nothing. A slot-wide origin would mistranslate `q` to
    /// `[-64, -61]`.
    predicates: BTreeMap<Slot, Vec<Predicate>>,
    /// Set on an OR-taken edge: the disjunction establishes no child
    /// bound, so the forward values keep no guard provenance and the
    /// Top-only backward slice must not resurrect a pre-OR guard there.
    /// Monotone (join and widen OR it): uncertainty, once established,
    /// is not talked away. A later direct guard still refines values
    /// normally; the bit only gates the slice fallback.
    slice_blocked: bool,
    /// Affine provenance: `slot = origin + off`, narrowed by the smallest
    /// width crossed, plus the origin's own width. A copy in one block and
    /// the compare in the next are ordinary code, so the links travel with
    /// the state the way predicates do.
    origins: BTreeMap<Slot, (Slot, i64, Option<u32>, u32)>,
}
impl State {
    fn get(&self, varnode: &PcodeVarnode) -> Value {
        if varnode.space == "const" {
            return Value::Const(varnode.offset);
        }
        self.values.get(&slot(varnode)).cloned().unwrap_or(Value::Top)
    }

    fn set(&mut self, varnode: &PcodeVarnode, value: Value) {
        if varnode.space == "const" {
            return;
        }
        match value {
            Value::Top => {
                self.values.remove(&slot(varnode));
            }
            value => {
                self.values.insert(slot(varnode), value);
            }
        }
    }

    fn join(&self, other: &State) -> State {
        let mut merged = State::default();
        merged.slice_blocked = self.slice_blocked || other.slice_blocked;
        for (key, left) in &self.predicates {
            if other.predicates.get(key) == Some(left) {
                merged.predicates.insert(key.clone(), left.clone());
            }
        }
        for (key, left) in &self.origins {
            if other.origins.get(key) == Some(left) {
                merged.origins.insert(key.clone(), left.clone());
            }
        }
        for (key, left) in &self.values {
            if let Some(right) = other.values.get(key) {
                let joined = left.clone().join(right.clone());
                if joined != Value::Top {
                    merged.values.insert(key.clone(), joined);
                }
            }
        }
        merged
    }
}

/// A block of the function, as this pass consumes it.
#[derive(Debug, Clone)]
pub struct Block {
    /// Instructions in address order.
    pub instructions: Vec<PcodeInstruction>,
    /// Successor block indices, in the order the block branches.
    pub successors: Vec<usize>,
}

/// Why a dispatch was not answered.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Refusals {
    /// The branch target's value never became anything but top.
    pub unknown_target: usize,
    /// The target is strided but nothing bounded the index.
    pub unbounded: usize,
    /// The bound is wider than a table this pass will materialise.
    pub too_wide: usize,
    /// The materialised targets did not decode inside the function.
    pub outside_function: usize,
    /// Fewer than two distinct targets: not a switch.
    pub too_few_targets: usize,
}

impl Refusals {
    /// Records why one branch was refused, from a whole-function answer.
    pub fn merge_for(&mut self, branch: u64, analysis: &Analysis) {
        if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
            eprintln!(
                "SJA refused {branch:#x}: {:?}",
                analysis.reasons.get(&branch)
            );
        }
        match analysis.reasons.get(&branch) {
            Some(RefusalKind::Unknown) => self.unknown_target += 1,
            Some(RefusalKind::Unbounded) => self.unbounded += 1,
            Some(RefusalKind::TooWide) => self.too_wide += 1,
            Some(RefusalKind::Outside) => self.outside_function += 1,
            Some(RefusalKind::TooFew) => self.too_few_targets += 1,
            None => self.unknown_target += 1,
        }
    }
}

/// Why one dispatch was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    Unknown,
    Unbounded,
    TooWide,
    Outside,
    TooFew,
}

/// What the analysis proved about one function's indirect branches.
#[derive(Debug, Default, Clone)]
pub struct Analysis {
    pub tables: Vec<SwitchTable>,
    pub refusals: Refusals,
    /// Why each unanswered dispatch was unanswered.
    pub reasons: BTreeMap<u64, RefusalKind>,
    /// Blocks the fixpoint visited, for cost accounting.
    pub visits: u64,
}

/// Runs the analysis over one function.
///
/// `extent` is the function's own range: a materialised target outside it
/// is not this function's case, which is the check that keeps a wrong bound
/// from inventing a table out of whatever follows in memory.
/// Widening after eight non-converged updates: a value that is
/// *still* moving goes to top, and one that has settled is kept.
/// Bound metadata (predicates, origins) follows the same rule as the
/// join: entries both sides agree on are still true, so an unchanged
/// guard survives the loop that carries it instead of being dropped
/// with the noise.
fn widen_state(existing: &State, merged: &State) -> State {
    let mut widened = State::default();
    widened.slice_blocked = merged.slice_blocked;
    for (key, value) in &merged.values {
        if existing.values.get(key) == Some(value) {
            widened.values.insert(key.clone(), value.clone());
        }
    }
    for (key, bound) in &merged.predicates {
        if existing.predicates.get(key) == Some(bound) {
            widened.predicates.insert(key.clone(), bound.clone());
        }
    }
    for (key, link) in &merged.origins {
        if existing.origins.get(key) == Some(link) {
            widened.origins.insert(key.clone(), link.clone());
        }
    }
    widened
}

pub fn analyse<I: Image>(
    image: &I,
    blocks: &[Block],
    extent: (u64, u64),
) -> Analysis {
    let mut analysis = Analysis::default();
    if blocks.is_empty() {
        return analysis;
    }
    let order = reverse_post_order(blocks);
    let mut entry_state: Vec<Option<State>> = vec![None; blocks.len()];
    // Seed every component the entry cannot reach, not just the entry: a
    // dispatch downstream of an earlier unresolved `jmp *` sits in a
    // component the entry cannot reach, and leaving it unvisited answers
    // nothing about it. Reachability, not in-degree, decides: a loop header
    // has a back-edge into itself and still needs a seed, and so does the
    // first block when the loop is the whole function. A rootless block
    // starting at Top is the same assumption the function entry already
    // makes; the guard's bound still lands on the edge into the dispatch.
    let mut reached = vec![false; blocks.len()];
    // External entry seeds for the reaching-definitions index below: the
    // same roots this loop seeds from outside (block 0, plus every
    // component the entry cannot reach). Kept alongside so the index and
    // the forward pass agree on the outside boundary.
    let mut seeds: Vec<usize> = Vec::new();
    for index in 0..blocks.len() {
        if reached[index] {
            continue;
        }
        entry_state[index] = Some(State::default());
        seeds.push(index);
        reached[index] = true;
        let mut stack = vec![index];
        while let Some(node) = stack.pop() {
            for &successor in &blocks[node].successors {
                if successor < blocks.len() && !reached[successor] {
                    reached[successor] = true;
                    stack.push(successor);
                }
            }
        }
    }
    if let Some(at) = std::env::var("ROMWRIGHT_TRACE_SJA_CFG")
        .ok()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
    {
        for (index, block) in blocks.iter().enumerate() {
            let start = block.instructions.first().map(|i| i.address).unwrap_or(0);
            let end = block.instructions.last().map(|i| i.address).unwrap_or(0);
            if start <= at && at <= end + 0x200 {
                let succ: Vec<u64> = block
                    .successors
                    .iter()
                    .map(|&s| {
                        blocks
                            .get(s)
                            .and_then(|b| b.instructions.first())
                            .map(|i| i.address)
                            .unwrap_or(0)
                    })
                    .collect();
                eprintln!(
                    "CFG block {index} @{start:#x}..{end:#x} succ={succ:x?}"
                );
            }
        }
    }
    // grows, and a block that keeps growing is widened to top rather than
    // iterated forever.
    let mut rounds: Vec<u32> = vec![0; blocks.len()];
    let mut worklist: Vec<usize> = order.clone();
    let mut dispatches: BTreeMap<u64, (Value, Value)> = BTreeMap::new();
    let mut blocked_dispatch: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    while let Some(index) = worklist.pop() {
        let Some(state) = entry_state[index].clone() else {
            continue;
        };
        analysis.visits += 1;
        let (exit, edges, blocked) = run_block(image, &blocks[index], state, &mut dispatches, &mut blocked_dispatch);
        for (position, successor) in blocks[index].successors.iter().copied().enumerate() {
            if successor >= blocks.len() {
                continue;
            }
            // The edge's own refinement: a comparison the block ends on
            // tells each side something different about the index.
            let mut next = exit.clone();
            if let Some(refinements) = edges.get(&position) {
                for (key, value) in refinements {
                    next.values.insert(key.clone(), value.clone());
                }
            }
            if blocked.contains(&position) {
                next.slice_blocked = true;
            }
            if std::env::var("ROMWRIGHT_TRACE_SJA_EDGE")
                .ok()
                .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
                .is_some_and(|at| {
                    blocks[successor]
                        .instructions
                        .iter()
                        .any(|i| i.address == at)
                })
            {
                eprintln!(
                    "EDGE -> block@{:#x} (succ {}) r15={:?} prior={:?}",
                    blocks[successor].instructions.first().map(|i| i.address).unwrap_or(0),
                    position,
                    next.values.get(&("register".to_string(), 0xb8)),
                    entry_state[successor]
                        .as_ref()
                        .and_then(|s| s.values.get(&("register".to_string(), 0xb8))),
                );
            }
            let merged = match &entry_state[successor] {
                Some(existing) => {
                    let merged = existing.join(&next);
                    if merged == *existing {
                        continue;
                    }
                    merged
                }
                None => next,
            };
            rounds[successor] += 1;
            let merged = if rounds[successor] > 8 {
                match &entry_state[successor] {
                    Some(existing) => widen_state(existing, &merged),
                    None => merged,
                }
            } else {
                merged
            };
            if entry_state[successor].as_ref() != Some(&merged) {
                entry_state[successor] = Some(merged);
                worklist.push(successor);
            }
        }
    }
    // The reaching-definitions index is built only when a dispatch the
    // forward pass could not answer needs it -- the slice is the
    // `findDeterminingVarnodes` fallback for a target that stayed `Top`.
    let mut defs: Option<DefIndex> = None;
    for (branch, (target, index)) in dispatches {
        let mut result = materialise(image, target.clone(), index, extent);
        if matches!(result, Err(Reason::Unknown)) && matches!(target, Value::Top) && !blocked_dispatch.contains(&branch) {
            // The forward domain lost the bound entirely. Slice the
            // branch's address input back through the reaching
            // definitions to its table and bound the index there.
            let defs = defs.get_or_insert_with(|| DefIndex::build_with_entries(blocks, &seeds));
            let sliced = slice_dispatch(image, defs, blocks, branch, extent, &seeds);
            if std::env::var_os("ROMWRIGHT_TRACE_SLICE").is_some() {
                eprintln!("SJA-SLICE {branch:#x}: {sliced:?}");
            }
            if let Some(sliced) = sliced {
                result = sliced;
            }
        }
        match result {
            Ok(table) => analysis.tables.push(SwitchTable {
                branch,
                span: table.len() as u64,
                targets: table,
            }),
            Err(reason) => {
                let kind = match reason {
                    Reason::Unknown => RefusalKind::Unknown,
                    Reason::Unbounded => RefusalKind::Unbounded,
                    Reason::TooWide => RefusalKind::TooWide,
                    Reason::Outside => RefusalKind::Outside,
                    Reason::TooFew => RefusalKind::TooFew,
                };
                analysis.reasons.insert(branch, kind);
                match kind {
                    RefusalKind::Unknown => analysis.refusals.unknown_target += 1,
                    RefusalKind::Unbounded => analysis.refusals.unbounded += 1,
                    RefusalKind::TooWide => analysis.refusals.too_wide += 1,
                    RefusalKind::Outside => analysis.refusals.outside_function += 1,
                    RefusalKind::TooFew => analysis.refusals.too_few_targets += 1,
                }
            }
        }
    }
    analysis.tables.sort_by_key(|table| table.branch);
    analysis
}

#[derive(Debug)]
enum Reason {
    Unknown,
    Unbounded,
    TooWide,
    Outside,
    TooFew,
}

/// Turns the abstract target into the addresses it stands for.
fn materialise<I: Image>(
    image: &I,
    target: Value,
    _index: Value,
    extent: (u64, u64),
) -> std::result::Result<Vec<u64>, Reason> {
    match target {
        Value::Top => Err(Reason::Unknown),
        Value::Const(_) => Err(Reason::TooFew),
        Value::Set(ref values) => {
            let mut targets = Vec::with_capacity(values.len());
            for address in values.iter().copied() {
                // Every case must decode inside the branching function:
                // that check is what stops a bound one entry too long from
                // turning the next thing in memory into a case. A case in
                // space no other function has claimed is still reachable --
                // a shared tail past the symbol's stated end is exactly
                // that -- so the same owner check the strided arm uses
                // applies here.
                if !image.executable(address) {
                    return Err(Reason::Outside);
                }
                if address < extent.0 || address >= extent.1 {
                    match image.owner(address) {
                        Some(owner) if owner != extent => return Err(Reason::Outside),
                        _ => {}
                    }
                }
                targets.push(address);
            }
            let mut distinct = targets.clone();
            distinct.sort_unstable();
            distinct.dedup();
            if distinct.len() < 2 {
                return Err(Reason::TooFew);
            }
            Ok(targets)
        }
        Value::Strided { .. } if !target.bounded() => {
            // A strided target with no usable interval is either unbounded
            // or wider than a table: the two are different failures.
            match target {
                Value::Strided { lo, hi, .. } if hi >= lo => Err(Reason::TooWide),
                _ => Err(Reason::Unbounded),
            }
        }
        // A strided target is a table read's answer: it needs the bound a
        // comparison stated, not a width a zero-extension implies.
        Value::Strided { guarded: false, .. } => Err(Reason::Unbounded),
        Value::Strided { .. } => {
            let Some(addresses) = target.concrete() else {
                return Err(Reason::TooWide);
            };
            let mut targets = Vec::with_capacity(addresses.len());
            for address in addresses {
                if !image.executable(address) {
                    return Err(Reason::Outside);
                }
                // Inside this function, or in space no other function has
                // claimed: a computed goto's case blocks are reachable only
                // through the dispatch, so they are unclaimed until it is
                // answered. A target inside a *different* function is a
                // wrong bound reaching into a neighbour, and is refused.
                if address < extent.0 || address >= extent.1 {
                    match image.owner(address) {
                        Some(owner) if owner != extent => return Err(Reason::Outside),
                        Some(_) => {}
                        None => {}
                    }
                }
                targets.push(address);
            }
            let mut distinct = targets.clone();
            distinct.sort_unstable();
            distinct.dedup();
            if distinct.len() < 2 {
                return Err(Reason::TooFew);
            }
            Ok(targets)
        }
    }
}

/// Interprets one block, returning its exit state, the refinements each
/// outgoing edge adds, and recording any indirect branch it ends on.
/// The affine link a copy/shift of `source` inherits: the source's
/// recorded link, except a self-loop (`x -> (x, k)` from an in-place
/// rewrite) never propagates. The self-loop names the source's
/// pre-write value; the copy holds its current one, so inheriting it
/// would translate bounds the copy's own compares state through a
/// rewrite the copy never underwent. A post-rewrite copy is a plain
/// alias: `(source, 0)`.
fn inherit_link(
    origins: &BTreeMap<Slot, (Slot, i64, Option<u32>, u32)>,
    source: &PcodeVarnode,
) -> (Slot, i64, Option<u32>, u32) {
    match origins.get(&slot(source)) {
        Some((origin, _, _, _)) if *origin == slot(source) => {
            (slot(source), 0, None, source.size)
        }
        Some(link) => link.clone(),
        None => (slot(source), 0, None, source.size),
    }
}

fn run_block<I: Image>(
    image: &I,
    block: &Block,
    mut state: State,
    dispatches: &mut BTreeMap<u64, (Value, Value)>,
    blocked_dispatch: &mut std::collections::BTreeSet<u64>,
) -> (State, BTreeMap<usize, Vec<(Slot, Value)>>, std::collections::BTreeSet<usize>) {
    use crate::ir::Opcode as O;
    let mut edges: BTreeMap<usize, Vec<(Slot, Value)>> = BTreeMap::new();
    // Successors whose entry is downstream of an uncertain OR edge
    // (taken always, fallthrough when heuristics were dropped): the
    // Top-only backward slice must not resurrect a pre-OR guard there.
    let mut blocked: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    // The comparison that produced each boolean, so a branch reading it can
    // refine the operand.
    // Boolean -> [(the compared slot, the constant, inclusive, which side
    // the constant sat on, the operand's width, and the affine link the
    // operand carried when the comparison ran)]. The side decides which
    // *edge* learns the bound: `cmp idx, n; jbe body` bounds the taken
    // edge, and the far more common `cmp idx, n; ja default` bounds the
    // fallthrough. A boolean built from several comparisons -- a range
    // check `lo <= x && x < hi` -- carries every bound, not just the first.
    let mut comparisons: BTreeMap<Slot, Vec<Predicate>> =
        state.predicates.clone();
    // Booleans holding sign/overflow-class flags (`INT_SCARRY` and
    // `INT_SLESS` outputs): `JL` materialises as `INT_NOTEQUAL` of two
    // such flags, and only that idiom keeps a known taken-edge polarity
    // through a flag combination (see the `Bool` arm). Block-local: flags
    // set in an earlier block arrive as plain booleans, which keep the
    // both-edges defense.
    let mut flag_src: std::collections::HashSet<Slot> = std::collections::HashSet::new();
    // The subset holding signed-carry/borrow outputs: the `JL` polarity
    // gate needs the carry side specifically (see the `Bool` arm).
    let mut carry_src: std::collections::HashSet<Slot> = std::collections::HashSet::new();
    // `BOOL_OR` outputs and their input slots, block-local: an OR taken
    // is a disjunction (both-edges, as carried), but an OR fallthrough
    // means every input is false, so each input's negation holds there.
    // Only same-block combinations are tracked (flag idioms set and test
    // flags in one block); a cross-block combination keeps both-edges.
    let mut or_combos: std::collections::HashMap<Slot, Vec<Slot>> = std::collections::HashMap::new();
    // Where each temporary came from, as (origin slot, affine offset,
    // narrowest width crossed, origin width): a machine compares a *copy*
    // of the switch variable and then dispatches on the original, and the
    // copy is often `x - k` rather than `x`, so a bound on the temp is a
    // bound on the origin shifted by the offset. A bound applied only to
    // the compared temporary is discarded the moment the temporary dies --
    // which is why the first measurement of this pass bounded nothing on
    // libc. A SUBPIECE narrows the value: a bound on the piece says nothing
    // about the origin's upper bytes unless the origin already fits the
    // width, so the width rides along and the compare checks it. A `unique`
    // temporary is intra-instruction and dead by the next block, so it is
    // never an origin -- the output is its own origin instead. The links
    // live in the state: a copy in one block and the compare in the next
    // are ordinary code.
    let mut origins = state.origins.clone();
    let trace_at: Option<u64> = std::env::var("ROMWRIGHT_TRACE_SJA_OPS")
        .ok()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok());
    for instruction in &block.instructions {
        for op in &instruction.ops {
            let opcode = op.opcode.parse::<crate::ir::Opcode>().unwrap_or(crate::ir::Opcode::Other);
            let inputs: Vec<Value> = op.inputs.iter().map(|input| state.get(input)).collect();
            if trace_at == Some(instruction.address) {
                eprintln!(
                    "SJA-OP {:#x}: {} out={:?} in={:?}",
                    instruction.address, opcode.name(), op.output, op.inputs
                );
                for (key, known) in &state.values {
                    eprintln!("    {}:{:x} = {known:?}", key.0, key.1);
                }
            }
            if std::env::var("ROMWRIGHT_TRACE_SJA_STATE")
                .ok()
                .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
                .is_some_and(|at| instruction.address == at)
            {
                eprintln!("SJA-STATE {:#x}:", instruction.address);
                for (key, known) in &state.values {
                    eprintln!("    {}:{:x} = {known:?}", key.0, key.1);
                }
            }
            // A write that is not affine leaves the slot's old origin and
            // comparison behind: `eax = r15 - 0x20` followed by
            // `mov (%rsi),%eax` would otherwise push a bound on r15 from a
            // value that has nothing to do with it, and a stale `cmp`
            // result would bound an unrelated test. The affine arms
            // re-insert what they mean; `prior` keeps the entry an
            // in-place op (`sub $0x20,%eax`) still reads.
            //
            // An in-place `add`/`sub` by a constant is the exception to
            // the deletion below: the predicate names the slot's
            // pre-write value, and stamping it with the shift translates
            // it at edge time (`CF = old_r8 < 64` before `r8 -= 64`
            // refines the edge to `new_r8 in [-64, -1]`). Deleting it
            // loses the only bound the dispatch chain has: the value arm
            // computes `add(Top, -k) = Top`, so nothing else carries it.
            // A non-constant add/sub (`add %rbx,%rax`), or any write to a
            // *different* slot than the predicate names, still deletes:
            // no translation exists for those, and the stale-operand test
            // below pins that. A second in-place rewrite composes onto
            // an existing stamp; a predicate recorded after the rewrite
            // stays unstamped and applies to the current value.
            let in_place_shift = match opcode {
                crate::ir::Opcode::IntAdd | crate::ir::Opcode::IntSub => {
                    op.output.as_ref().and_then(|out| {
                        if out.is_const() {
                            return None;
                        }
                        let source = op.inputs.first()?;
                        let konst = op.inputs.get(1)?;
                        if slot(source) != slot(out) || !konst.is_const() {
                            return None;
                        }
                        let delta = sign_extend(konst.offset, konst.size) as i64;
                        Some(if matches!(opcode, crate::ir::Opcode::IntSub) {
                            -delta
                        } else {
                            delta
                        })
                    })
                }
                _ => None,
            };
            let prior = op.output.as_ref().and_then(|out| {
                let key = slot(out);
                comparisons.remove(&key);
                // A comparison whose *operand* is overwritten is stale too:
                // `cmp $4,%eax; mov (%rsi),%eax; jbe` bounds the new eax.
                // A value-preserving same-slot widening is the exception:
                // `cmp $0x5a,%al; movzbl %al,%eax; ja` keeps the bound.
                // An in-place add/sub by a constant stamps instead of
                // deleting (see above).
                let preserves = (matches!(opcode, crate::ir::Opcode::Copy | crate::ir::Opcode::IntZExt | crate::ir::Opcode::IntSExt)
                    && op.inputs.first().is_some_and(|src| slot(src) == key))
                    || in_place_shift.is_some();
                if !preserves {
                    comparisons.retain(|_, bounds| {
                        bounds.retain(|(operand, ..)| *operand != key);
                        !bounds.is_empty()
                    });
                } else if let Some(shift) = in_place_shift {
                    for bounds in comparisons.values_mut() {
                        for bound in bounds.iter_mut() {
                            if bound.0 == key {
                                bound.5 = Some(bound.5.unwrap_or(0) + shift);
                            }
                        }
                    }
                }
                origins.remove(&key)
            });
            match opcode {
                O::Copy | O::IntZExt | O::IntSExt | O::Subpiece => {
                    if let (Some(output), Some(value)) = (&op.output, inputs.first()) {
                        // A widening is arithmetic on the value, not a
                        // relabelling: a PIC jump table holds 32-bit signed
                        // offsets, and passing them through unchanged made
                        // every such table unrecoverable.
                        let width = op.inputs.first().map_or(output.size, |input| input.size);
                        let converted = match opcode {
                            O::IntSExt => map_values(value, |raw| sign_extend(raw, width)),
                            // A zero-extension of a value that already fits
                            // the *input* width is a no-op: the bound
                            // carries through, flag and all, rather than
                            // laundering into a set.
                            O::IntZExt if matches!(value, Value::Strided { base: 0, stride: 1, lo, hi, .. } if *lo >= 0 && *hi >= *lo && (width >= 8 || (*hi as u64) < (1u64 << (width * 8)))) => value.clone(),
                            // A zero-extension of an unknown w-byte input is
                            // provably 0..=2^(8w)-1 -- the bound the domain
                            // can state without knowing the value. Only a
                            // byte or a word is worth stating: a 4-byte
                            // bound turns every unknown 32-bit register into
                            // a live Strided entry the join loop carries.
                            O::IntZExt if matches!(value, Value::Top) && width <= 2 => {
                                let high = (1i64 << (width * 8)) - 1;
                                // A width, not a guard: `movzbl` says the
                                // index is a byte, not that the table is
                                // 256 entries.
                                Value::Strided { base: 0, stride: 1, lo: 0, hi: high , guarded: false }
                            }
                            O::IntZExt => map_values(value, |raw| truncate(raw, width)),
                            _ => value.clone(),
                        };
                        state.set(output, converted);
                    }
                    if let (Some(output), Some(source)) = (&op.output, op.inputs.first())
                        && source.space != "const"
                    {
                        // An in-place op reads the entry the top-of-loop
                        // clear just removed.
                        let (origin, off, narrow, _origin_size) = if slot(source) == slot(output) {
                            prior.clone().unwrap_or((slot(source), 0, None, source.size))
                        } else {
                            inherit_link(&origins, source)
                        };
                        // An in-place op reads the entry the top-of-loop
                        // clear just removed -- including a self-loop
                        // (`r8 -> (r8, -k)`), which the edge translation
                        // needs. Only `unique` temporaries (dead by the
                        // next block) have no parent at all. A same-slot
                        // copy keeps the prior link rather than dropping
                        // it.
                        if origin.0 != "unique" && (origin != slot(output) || prior.is_some()) {
                            // A bound on a piece says nothing about the
                            // whole: record the narrowest width crossed so
                            // the compare can check the origin already fits.
                            let narrow = if opcode == O::Subpiece {
                                Some(narrow.map_or(output.size, |w| w.min(output.size)))
                            } else {
                                narrow
                            };
                            origins.insert(slot(output), (origin, off, narrow, source.size));
                        }
                    }
                }
                O::IntAdd => {
                    if let (Some(output), Some(left), Some(right)) =
                        (&op.output, inputs.first(), inputs.get(1))
                    {
                        // A narrow immediate is signed: `add $-0x20,%eax`
                        // arrives as `0xffffffe0:4`, and the value path must
                        // shift by -0x20 the way the origin arm does.
                        let right = match (right, op.inputs.get(1)) {
                            (Value::Const(_), Some(konst)) if konst.space == "const" =>
                                Value::Const(sign_extend(konst.offset, konst.size)),
                            _ => right.clone(),
                        };
                        state.set(output, add(left.clone(), right));
                    }
                    // `out = x + k`: the output is the input's origin shifted
                    // by k, so a bound on the output is a bound on the
                    // origin shifted back.
                    if let (Some(output), Some(source), Some(konst)) =
                        (&op.output, op.inputs.first(), op.inputs.get(1))
                        && source.space != "const" && konst.space == "const"
                    {
                        let (origin, off, narrow, _origin_size) = if slot(source) == slot(output) {
                            prior.clone().unwrap_or((slot(source), 0, None, source.size))
                        } else {
                            inherit_link(&origins, source)
                        };
                        // A `unique` temporary is dead by the next block:
                        // the output has no affine parent.
                        // A self-loop (`r8 -> (r8, +k)` from an in-place
                        // `r8 += k`) is recorded, not skipped: the
                        // predicate on the pre-write value translates
                        // through it at edge time. The old skip (meant
                        // for `unique` temporaries, already excluded
                        // above) is what dropped every in-place re-bias.
                        if origin.0 != "unique" {
                            origins.insert(slot(output),
                                (origin, off + sign_extend(konst.offset, konst.size) as i64, narrow, source.size));
                        }
                    }
                }
                O::IntSub => {
                    if let (Some(output), Some(left), Some(right)) =
                        (&op.output, inputs.first(), inputs.get(1))
                    {
                        // The immediate is signed at its own width:
                        // `sub $-0x20,%eax` is `eax + 0x20`, not a shift by
                        // 0xffffffe0.
                        let negated = match (right, op.inputs.get(1)) {
                            (Value::Const(_), Some(konst)) if konst.space == "const" =>
                                Value::Const(sign_extend(konst.offset, konst.size).wrapping_neg()),
                            (value, _) => negate_interval(value.clone()),
                        };
                        state.set(output, add(left.clone(), negated));
                    }
                    // `out = x - k`: the output is the input's origin shifted
                    // by -k.
                    if let (Some(output), Some(source), Some(konst)) =
                        (&op.output, op.inputs.first(), op.inputs.get(1))
                        && source.space != "const" && konst.space == "const"
                    {
                        let (origin, off, narrow, _origin_size) = if slot(source) == slot(output) {
                            prior.clone().unwrap_or((slot(source), 0, None, source.size))
                        } else {
                            inherit_link(&origins, source)
                        };
                        // Self-loops recorded, as in the add arm: the edge
                        // translation needs `r8 -> (r8, -k)`.
                        if origin.0 != "unique" {
                            origins.insert(slot(output),
                                (origin, off - sign_extend(konst.offset, konst.size) as i64, narrow, source.size));
                        }
                    }
                }
                O::IntMult => {
                    if let (Some(output), Some(left), Some(right)) =
                        (&op.output, inputs.first(), inputs.get(1))
                    {
                        state.set(output, multiply(left.clone(), right.clone()));
                    }
                }
                O::IntLeft => {
                    if let Some(output) = &op.output {
                        match (inputs.first(), inputs.get(1)) {
                            (Some(left), Some(Value::Const(shift))) => {
                                let factor = 1u64.checked_shl(*shift as u32).unwrap_or(0);
                                state.set(output, multiply(left.clone(), Value::Const(factor)));
                            }
                            // A non-constant shift is still a write: the
                            // output is unknown, not its previous value.
                            _ => state.set(output, Value::Top),
                        }
                    }
                }
                // A mask *is* a bound, and needs no guard to state it:
                // `and $0xf, %ecx` says the index is 0..15 outright. Only a
                // low-bit mask (`m + 1` a power of two) admits exactly
                // `0..=m`; any other constant -- an alignment such as
                // `and $0xfffffffffffffff0` -- clears bits without bounding
                // the value, and stays unknown. This is the whole of the
                // computed-goto class: `and; shl; add table; jmp *reg`
                // materialises an arithmetic progression of code addresses
                // with no table in memory to read.
                O::IntAnd if op.output.as_ref().is_some_and(|output| output.size > 1) => {
                    if let Some(output) = &op.output {
                        let masked = match (inputs.first(), inputs.get(1)) {
                            (Some(Value::Const(left)), Some(Value::Const(right))) => {
                                Value::Const(left & right)
                            }
                            (Some(value), Some(Value::Const(mask)))
                            | (Some(Value::Const(mask)), Some(value)) => {
                                bound_by_mask(value.clone(), *mask)
                            }
                            _ => Value::Top,
                        };
                        state.set(output, masked);
                    }
                }
                O::Load => {
                    if let (Some(output), Some(address)) = (&op.output, inputs.get(1)) {
                        state.set(output, load(image, address.clone(), output.size));
                    }
                }
                // A machine does not branch on a comparison, it branches on
                // a combination of flags: `cmp $10, %edx; ja` is
                // `BOOL_AND(EQ(CF,0), EQ(ZF,0))` over `CF = edx < 10` and
                // `ZF = edx == 10`. Every boolean that depends on exactly
                // one compared slot carries that slot's bound forward, so
                // the branch can find it however the flags were combined.
                O::BoolAnd | O::BoolOr | O::IntAnd | O::IntOr | O::IntEqual
                | O::IntNotEqual | O::BoolNegate
                    if op.output.as_ref().is_some_and(|output| output.size == 1) =>
                {
                    // Record OR combinations for the branch that reads
                    // them: taken is a disjunction, but fallthrough means
                    // every input is false (see the `CBranch` arm).
                    if opcode == O::BoolOr
                        && let Some(output) = &op.output
                    {
                        or_combos.insert(slot(output), op.inputs.iter().map(slot).collect());
                    }
                    // The `JL` idiom is `INT_NOTEQUAL` of the signed-carry
                    // and sign flags of one comparison, and its taken edge
                    // means less-than only when the carry side proves `OF =
                    // 0`: `SF != OF` with `OF = 1` means `!SF`, and
                    // forwarding SF's bound to the taken edge then selects
                    // exactly the wrong entries. A wrong-edge upper that
                    // decodes in-function is accepted -- no backstop refuses
                    // it -- so the gate below, not a check downstream, is
                    // what keeps that case out. Every other combination
                    // keeps the both-edges defense: `ja` is an `AND` whose
                    // bound holds on the fallthrough, so polarity through
                    // arbitrary combinations would put bounds on exactly
                    // the wrong edge. The idiom needs both inputs to be
                    // sign/overflow-class flags (a `ZF`-derived `jne`
                    // carries no flags at all) and exactly one side to
                    // carry a bound (the carry side is silent).
                    let carrying = op.inputs.iter()
                        .filter(|input| comparisons.contains_key(&slot(input)))
                        .count();
                    let jl_idiom = opcode == O::IntNotEqual
                        && op.inputs.len() == 2
                        && carrying == 1
                        && op.inputs.iter().all(|input| flag_src.contains(&slot(input)));
                    // The overflow gate: the silent side must be the carry
                    // flag specifically, and its value must be constant-false
                    // (`x + 0` folds there; two constants fold; anything
                    // else stays unknown). A constant-true carry or an
                    // unknown one keeps the both-edges defense: the polarity
                    // is unproven, and forwarding it would be the OF=1
                    // misread.
                    let proven_no_overflow = jl_idiom && op.inputs.iter()
                        .find(|input| !comparisons.contains_key(&slot(input)))
                        .is_some_and(|silent| carry_src.contains(&slot(silent)) && state.get(silent) == Value::Const(0));
                    let mut carried: Vec<Predicate> = Vec::new();
                    for input in &op.inputs {
                        if let Some(found) = comparisons.get(&slot(input)) {
                            for bound in found {
                                // Two bounds on one slot: the looser one is
                                // what the combination admits -- but only
                                // when both sides agree on the stamp and the
                                // signedness. A stamp conflict (`p = (x < 4)`
                                // before `x += 16`, `q = (x < 4)` after,
                                // combined as `p || q`) admits a disjunction
                                // the upper-bound tuple cannot name (`[0,3]`
                                // or `[16,19]`); a signedness conflict (`x
                                // <_u 10 && x <_s 0`) mixes two readings of
                                // the bits no one interval names. Keeping
                                // the looser bound untranslated would present
                                // half the truth as the bound, so the whole
                                // bound is discarded and the dispatch refuses.
                                match carried
                                    .iter()
                                    .position(|existing: &Predicate| existing.0 == bound.0)
                                {
                                    Some(index) => {
                                        if carried[index].5 == bound.5 && carried[index].7 == bound.7 {
                                            carried[index].1 = carried[index].1.max(bound.1);
                                            carried[index].2 = carried[index].2 || bound.2;
                                            carried[index].6 = false;
                                        } else {
                                            carried.remove(index);
                                        }
                                    }
                                    None => {
                                        let mut combined = bound.clone();
                                        if opcode == O::BoolNegate && combined.6 {
                                            // A single negation has exact
                                            // polarity: taken means the
                                            // input is false, so the negated
                                            // bound (flipped inclusivity
                                            // and side, same stamp and
                                            // signedness) holds there.
                                            // Deeper combinations keep the
                                            // defense below.
                                            combined.2 = !combined.2;
                                            combined.3 = !combined.3;
                                        } else {
                                            // The `JL` idiom's bound holds on
                                            // the taken edge only with proven
                                            // no-overflow; everything else
                                            // through a combination keeps the
                                            // both-edges defense.
                                            combined.6 = proven_no_overflow;
                                        }
                                        carried.push(combined);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(output) = &op.output {
                        if !carried.is_empty() {
                            comparisons.insert(slot(output), carried);
                        }
                        state.set(output, Value::Top);
                    }
                }
                O::IntSCarry => {
                    // A signed-carry flag: with its `INT_SLESS` sibling it
                    // forms the `JL` idiom (`INT_NOTEQUAL(sc, sf)`), whose
                    // taken edge keeps a known polarity only when the
                    // carry side proves `OF = 0` (see the `Bool` arm).
                    // `INT_CARRY` is left out: unsigned combinations (`ja`)
                    // hold on the fallthrough, not the taken edge. The
                    // value is evaluated where provable (`x + 0` never
                    // overflows; two constants fold) so the gate below has
                    // something to read; otherwise it stays unknown and the
                    // idiom keeps the both-edges defense.
                    if let Some(output) = &op.output {
                        if output.size == 1 {
                            flag_src.insert(slot(output));
                            carry_src.insert(slot(output));
                        }
                        let carried = match (inputs.first(), inputs.get(1)) {
                            (Some(left), Some(right)) => scarry_value(left, right, op.inputs.first().map_or(8, |input| input.size)),
                            _ => Value::Top,
                        };
                        state.set(output, carried);
                    }
                }
                O::IntSBorrow => {
                    // The signed borrow of a subtraction: the `JL`-after-`SUB`
                    // idiom's carry side, gated exactly like `INT_SCARRY`.
                    if let Some(output) = &op.output {
                        if output.size == 1 {
                            flag_src.insert(slot(output));
                            carry_src.insert(slot(output));
                        }
                        let carried = match (inputs.first(), inputs.get(1)) {
                            (Some(left), Some(right)) => sborrow_value(left, right, op.inputs.first().map_or(8, |input| input.size)),
                            _ => Value::Top,
                        };
                        state.set(output, carried);
                    }
                 }
                O::IntLess | O::IntSLess | O::IntLessEqual | O::IntSLessEqual => {
                    // Remember what this boolean says, for the branch that
                    // reads it: `index < n` bounds the index above. The
                    // stamp is empty: this comparison observes the
                    // slot's current value, so no rewrite stands between
                    // the bound and the value it names.
                    let signed = matches!(opcode, O::IntSLess | O::IntSLessEqual);
                    // The sign half of the `JL` idiom (see `IntSCarry`).
                    if signed
                        && let Some(output) = &op.output
                        && output.size == 1
                    {
                        flag_src.insert(slot(output));
                    }
                    if let (Some(output), Some(left), Some(right)) =
                        (&op.output, op.inputs.first(), op.inputs.get(1))
                    {
                        let inclusive = matches!(opcode, O::IntLessEqual | O::IntSLessEqual);
                        match (state.get(left), state.get(right)) {
                            // `index < n`: the taken edge is in range.
                            (_, Value::Const(limit)) if right.space == "const" => {
                                comparisons
                                    .insert(slot(output), vec![(slot(left), limit, inclusive, false, left.size, None, true, signed)]);
                            }
                            // `n < index`: the *fallthrough* is in range.
                            (Value::Const(limit), _) if left.space == "const" => {
                                comparisons
                                    .insert(slot(output), vec![(slot(right), limit, inclusive, true, right.size, None, true, signed)]);
                            }
                            _ => {}
                        }
                    }
                }
                O::CBranch => {
                    // Successor 0 is the taken edge, successor 1 the
                    // fallthrough: block construction pushes the taken
                    // target first, and pruning preserves the order.
                    // A boolean built from several comparisons carries every
                    // bound; each refines the edge it holds on.
                    if let Some(condition) = op.inputs.get(1)
                        && let Some(bounds) = comparisons.get(&slot(condition)).cloned()
                    {
                        // An OR is one-sided and slot-local. Taken is a
                        // disjunction: no child bound holds there, so
                        // compared slots keep their exit intervals
                        // de-blessed (sets collapse; constants stay exact)
                        // and nothing else is pushed. Fallthrough means
                        // every input is false: each exact (direct)
                        // input's negation holds there, and each skipped
                        // heuristic child's operand is de-blessed the same
                        // way. Only slice-block marks travel (taken always,
                        // fallthrough when heuristics were dropped) so the
                        // Top-only backward slice cannot resurrect a
                        // pre-OR guard there; later direct guards re-guard
                        // normally, and forward reads proceed.
                        let or_inputs = or_combos.get(&slot(condition)).cloned().unwrap_or_default();
                        if or_inputs.is_empty() {
                            for bound in bounds {
                                apply_guard_bound(
                                    &state.values,
                                    &origins,
                                    &mut edges,
                                    instruction.address,
                                    bound,
                                    block.successors.len(),
                                    None,
                                );
                            }
                        } else {
                            // Successor 0 (taken) is uncertain: block the
                            // Top-only backward slice from resurrecting a
                            // pre-OR guard downstream of it.
                            blocked.insert(0);
                            let mut skipped = false;
                            for input in &or_inputs {
                                if let Some(found) = comparisons.get(input).cloned() {
                                    for bound in &found {
                                        match state.values.get(&bound.0).cloned() {
                                            Some(Value::Strided { base, stride, lo, hi, guarded: true }) => {
                                                edges.entry(0).or_default().push((bound.0.clone(),
                                                    Value::Strided { base, stride, lo, hi, guarded: false }));
                                            }
                                            Some(Value::Set(_)) => {
                                                edges.entry(0).or_default().push((bound.0.clone(), Value::Top));
                                            }
                                            _ => {}
                                        }
                                    }
                                    for (operand, limit, inclusive, constant_left, operand_size, stamp, direct, signed) in found {
                                        if !direct {
                                            skipped = true;
                                            match state.values.get(&operand).cloned() {
                                                Some(Value::Strided { base, stride, lo, hi, guarded: true }) => {
                                                    edges.entry(1).or_default().push((operand.clone(),
                                                        Value::Strided { base, stride, lo, hi, guarded: false }));
                                                }
                                                Some(Value::Set(_)) => {
                                                    edges.entry(1).or_default().push((operand.clone(), Value::Top));
                                                }
                                                _ => {}
                                            }
                                            continue;
                                        }
                                        let negated = (operand, limit, !inclusive, !constant_left, operand_size, stamp, false, signed);
                                        apply_guard_bound(
                                            &state.values,
                                            &origins,
                                            &mut edges,
                                            instruction.address,
                                            negated,
                                            block.successors.len(),
                                            Some(0),
                                        );
                                    }
                                }
                            }
                            // A fallthrough that dropped heuristic children
                            // is under-refined: block the slice there too.
                            if skipped {
                                blocked.insert(1);
                            }
                        }
                    }
                }
                O::BranchInd => {
                    if let Some(target) = op.inputs.first() {
                        let value = state.get(target);
                        if std::env::var("ROMWRIGHT_TRACE_SJA_AT")
                            .ok()
                            .and_then(|raw| {
                                u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok()
                            })
                            == Some(instruction.address)
                        {
                            eprintln!(
                                "SJA {:#x}: target {}:{:x} = {value:?}",
                                instruction.address, target.space, target.offset
                            );
                            for (key, known) in &state.values {
                                eprintln!("    {}:{:x} = {known:?}", key.0, key.1);
                            }
                        }
                        if state.slice_blocked {
                            blocked_dispatch.insert(instruction.address);
                        }
                        dispatches.insert(instruction.address, (value, Value::Top));
                    }
                }
                _ => {
                    if let Some(output) = &op.output {
                        state.set(output, Value::Top);
                    }
                }
            }
        }
    }
    state.predicates = comparisons;
    state.origins = origins;
    (state, edges, blocked)
}

/// Applies a function to every value a term stands for, where that is a
/// bounded set; anything else stays as it is.
fn map_values(value: &Value, transform: impl Fn(u64) -> u64) -> Value {
    match value {
        Value::Const(raw) => Value::Const(transform(*raw)),
        Value::Set(values) => Value::Set(std::rc::Rc::new(
            values.iter().copied().map(transform).collect(),
        )),
        // A transform on a width-only bound produces a set that no longer
        // carries the flag, so it would read past the table it indexes.
        // Refusing keeps the unsound read from happening.
        Value::Strided { guarded: false, .. } => Value::Top,
        Value::Strided { .. } => value
            .concrete()
            .map(|all| {
                Value::Set(std::rc::Rc::new(all.into_iter().map(&transform).collect()))
            })
            .unwrap_or(Value::Top),
        Value::Top => Value::Top,
    }
}

fn sign_extend(value: u64, width: u32) -> u64 {
    if width == 0 || width >= 8 {
        return value;
    }
    let bits = width * 8;
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

fn truncate(value: u64, width: u32) -> u64 {
    if width == 0 || width >= 8 {
        return value;
    }
    value & ((1u64 << (width * 8)) - 1)
}

/// What `INT_SCARRY(a, b)` -- the signed overflow of `a + b` -- is worth,
/// where provable. `x + 0` never overflows, whatever `x` is; two
/// constants fold by sign-extending to the operand width and adding
/// checked. Anything else stays unknown, and the `JL` polarity gate
/// keeps the both-edges defense there.
fn scarry_value(left: &Value, right: &Value, size: u32) -> Value {
    match (left, right) {
        (_, Value::Const(0)) | (Value::Const(0), _) => Value::Const(0),
        (Value::Const(a), Value::Const(b)) if size >= 1 && size <= 8 => {
            const_overflow(*a, *b, size, true)
        }
        (Value::Strided { base: 0, stride: 1, lo, hi, .. }, Value::Const(c))
        | (Value::Const(c), Value::Strided { base: 0, stride: 1, lo, hi, .. })
            if size == 8 && lo <= hi =>
        {
            scarry_interval(*lo, *hi, *c as i64, true)
        }
        _ => Value::Top,
    }
}
/// Overflow status of two constants at an operand width: sign-extend both
/// to the width, add or subtract exactly, and compare against the width's
/// signed bounds. Checking the extended sum for 64-bit overflow instead
/// would clear real 8-bit overflow (`127 + 1` fits an i64) and make a
/// wrong edge authoritative.
fn const_overflow(a: u64, b: u64, size: u32, is_add: bool) -> Value {
    let bits = size * 8;
    let extend = |v: u64| (((v << (64 - bits)) as i64) >> (64 - bits)) as i128;
    let sum = if is_add {
        extend(a) + extend(b)
    } else {
        extend(a) - extend(b)
    };
    let min = -(1i128 << (bits - 1));
    let max = (1i128 << (bits - 1)) - 1;
    Value::Const(u64::from(sum < min || sum > max))
}
/// Overflow status of an interval plus a constant: `add` when `is_add`,
/// `sub` otherwise. Opposite signs (add) or same signs (sub) never
/// overflow; otherwise the endpoints decide, since overflow is monotone
/// in each operand; a single wrapping value proves overflow.
fn scarry_interval(lo: i64, hi: i64, constant: i64, is_add: bool) -> Value {
    let combine = if is_add {
        i64::checked_add
    } else {
        i64::checked_sub
    };
    if is_add {
        if (hi <= 0 && constant >= 0) || (lo >= 0 && constant <= 0) {
            return Value::Const(0);
        }
    } else if (lo >= 0 && constant >= 0) || (hi <= 0 && constant <= 0) {
        return Value::Const(0);
    }
    if combine(lo, constant).is_some() && combine(hi, constant).is_some() {
        return Value::Const(0);
    }
    if lo == hi {
        return Value::Const(1);
    }
    Value::Top
}
/// What `INT_SBORROW(a, b)` -- the signed overflow of `a - b` -- is worth,
/// where provable. `x - 0` never overflows; two constants fold against
/// the width's signed bounds; a bounded interval minus a constant proves
/// itself like the carry case with the signs flipped. Else unknown.
fn sborrow_value(left: &Value, right: &Value, size: u32) -> Value {
    match (left, right) {
        (_, Value::Const(0)) => Value::Const(0),
        (Value::Const(a), Value::Const(b)) if size >= 1 && size <= 8 => {
            const_overflow(*a, *b, size, false)
        }
        (Value::Strided { base: 0, stride: 1, lo, hi, .. }, Value::Const(c))
            if size == 8 && lo <= hi =>
        {
            scarry_interval(*lo, *hi, *c as i64, false)
        }
        _ => Value::Top,
    }
}
fn add(left: Value, right: Value) -> Value {
    use Value::*;
    match (&left, &right) {
        (Set(_), Const(value)) => {
            let value = *value;
            return map_values(&left, |raw| raw.wrapping_add(value));
        }
        (Const(value), Set(_)) => {
            let value = *value;
            return map_values(&right, |raw| raw.wrapping_add(value));
        }
        _ => {}
    }
    match (left, right) {
        (Const(left), Const(right)) => Const(left.wrapping_add(right)),
        // An index-space value (`i` for `i` in `lo..=hi`, base 0, stride 1)
        // plus a constant is the same set with the interval shifted:
        // folding `k` into `lo`/`hi` keeps `base` at 0 so a later compare
        // can still refine it. `eax - 0x20` on `[0,255]` is `[-0x20, 0xdf]`,
        // not a value with a wrapped base. A non-zero base is an address,
        // not an index: `table + i` folds into `base` as before.
        (
            Strided { base: 0, stride: 1, lo, hi, guarded },
            Const(value),
        )
        | (
            Const(value),
            Strided { base: 0, stride: 1, lo, hi, guarded },
        ) => {
            let shift = value as i64;
            let lo = lo.wrapping_add(shift);
            let hi = hi.wrapping_add(shift);
            // A guarded interval whose minimum went negative was never
            // really stated: no compiler indexes a table negatively, so
            // the floor the compare assumed (`lo: -off` = 0) was wrong.
            // The read must refuse rather than reach into the table that
            // precedes this one.
            let guarded = guarded && lo >= 0;
            Strided { base: 0, stride: 1, lo, hi, guarded }
        }
        (
            Strided { base, stride, lo, hi, guarded },
            Const(value),
        )
        | (
            Const(value),
            Strided { base, stride, lo, hi, guarded },
        ) => Strided {
            base: base.wrapping_add(value),
            stride,
            lo,
            hi,
            guarded,
        },
        // Two index-space intervals add pointwise: `[la,ha] + [lb,hb]` is
        // `[la+lb, ha+hb]`, and stays guarded only when both sides were.
        // This is the half of `a - b` the negation arm feeds: a PIC index
        // computed as `x - y` over two masked values lands here.
        (
            Strided { base: 0, stride: 1, lo: left_lo, hi: left_hi, guarded: left_guarded },
            Strided { base: 0, stride: 1, lo: right_lo, hi: right_hi, guarded: right_guarded },
        ) => Strided {
            base: 0,
            stride: 1,
            lo: left_lo.wrapping_add(right_lo),
            hi: left_hi.wrapping_add(right_hi),
            guarded: left_guarded && right_guarded,
        },
        _ => Top,
    }
}

/// `0 - value` over the domain: a constant negates, and an index-space
/// interval `[lo, hi]` negates to `[-hi, -lo]`. Anything else is unknown.
/// This is what `a - b` needs when `b` is a bounded index rather than a
/// constant: a PIC table index computed as `x - y` over two masked values
/// stays an interval instead of collapsing to top.
fn negate_interval(value: Value) -> Value {
    match value {
        Value::Const(raw) => Value::Const(raw.wrapping_neg()),
        Value::Strided { base: 0, stride: 1, lo, hi, guarded } => Value::Strided {
            base: 0,
            stride: 1,
            lo: -hi,
            hi: -lo,
            guarded,
        },
        _ => Value::Top,
    }
}

/// What `value & mask` is worth, when the mask states a range.
///
/// `m + 1` a power of two means the mask keeps the low `k` bits and the
/// result is exactly `0..=m`, whatever came in. Any other constant clears
/// scattered bits, which bounds nothing this domain can name, so it is
/// unknown rather than guessed. A value already known to fit inside the
/// mask passes through: masking cannot widen it.
fn bound_by_mask(value: Value, mask: u64) -> Value {
    if !mask.checked_add(1).is_some_and(u64::is_power_of_two) {
        return Value::Top;
    }
    if let Value::Const(known) = value {
        return Value::Const(known & mask);
    }
    // The interval is signed, so a mask wider than `i64::MAX` states no
    // bound this domain can hold.
    let Ok(high) = i64::try_from(mask) else {
        return Value::Top;
    };
    if let Value::Strided {
        base: 0,
        stride: 1,
        lo: 0,
        hi,
        ..
    } = value
        && hi <= high
    {
        return value;
    }
    Value::Strided { base: 0, stride: 1, lo: 0, hi: high, guarded: true }
}

fn multiply(left: Value, right: Value) -> Value {
    use Value::*;
    match (&left, &right) {
        (Set(_), Const(value)) => {
            let value = *value;
            return map_values(&left, |raw| raw.wrapping_mul(value));
        }
        (Const(value), Set(_)) => {
            let value = *value;
            return map_values(&right, |raw| raw.wrapping_mul(value));
        }
        _ => {}
    }
    match (left, right) {
        (Const(left), Const(right)) => Const(left.wrapping_mul(right)),
        (
            Strided { base, stride, lo, hi, guarded },
            Const(value),
        )
        | (
            Const(value),
            Strided { base, stride, lo, hi, guarded },
        ) => Strided {
            base: base.wrapping_mul(value),
            stride: stride.wrapping_mul(value),
            lo,
            hi,
            guarded,
        },
        _ => Top,
    }
}

/// Reads what a strided address points at. A table of addresses read at a
/// fixed stride is itself a strided value only when its entries are; the
/// honest general answer is the set of entries, so the read produces a
/// strided value when the entries happen to form one and top otherwise --
/// and the caller materialises through `table_targets` instead.
fn load<I: Image>(image: &I, address: Value, size: u32) -> Value {
    match address {
        Value::Const(address) => image.read(address, size).map_or(Value::Top, Value::Const),
        // A table read needs a bound a comparison stated, not a width a
        // zero-extension implies: `movzbl` says the index is a byte, not
        // that the table is 256 entries, and reading on that bound alone
        // reads past the table into whatever follows it.
        Value::Strided { base, stride, lo, hi, guarded: true }
            if hi >= lo && hi - lo + 1 <= MAX_TABLE =>
        {
            // Read every entry the interval covers and keep them as a set:
            // a jump table holds whatever addresses the compiler emitted,
            // and requiring them to form a progression would refuse almost
            // every real one.
            let mut entries = Vec::with_capacity((hi - lo + 1) as usize);
            for index in lo..=hi {
                let at = base.wrapping_add(stride.wrapping_mul(index as u64));
                let Some(entry) = image.read(at, size) else {
                    return Value::Top;
                };
                entries.push(entry);
            }
            Value::Set(std::rc::Rc::new(entries))
        }
        // A two-level dispatch reads the second table at an address the
        // first table's entries produced: `LOAD(step + LOAD8(jt + i) * 8)`.
        // The address is a set of table entries, so the read is the set of
        // what each points at, kept in the order they were read -- the same
        // contract the Strided arm keeps, since the caller materialises
        // case->target positionally. Any member that does not read is a
        // wrong bound reaching outside the table, and the whole read is
        // unknown.
        Value::Set(ref addresses) if addresses.len() <= MAX_TABLE as usize => {
            let mut entries = Vec::with_capacity(addresses.len());
            for at in addresses.iter().copied() {
                let Some(entry) = image.read(at, size) else {
                    return Value::Top;
                };
                entries.push(entry);
            }
            Value::Set(std::rc::Rc::new(entries))
        }
        _ => Value::Top,
    }
}

/// Applies one comparison bound to both edges of a conditional branch.
///
/// `bound` is `(operand, limit, inclusive, constant_left, operand_size,
/// stamp, direct, signed)`: the compared slot, the constant it was
/// compared against, whether the compare was `<=`, which side the
/// constant sat on, the operand's width, the composed in-place shift
/// between the comparison and the branch (`Some(k)` when the slot was
/// rewritten `slot += k` after the comparison ran), whether the bound
/// holds on exactly one edge, and whether the comparison was signed.
/// `values` is the abstract state at the branch, `origins` the live
/// affine provenance map, `edges` the per-successor refinements this
/// block produces, and `branch` the branch's own address for tracing.
/// The stamp -- not the live map -- translates pre-write predicates, so
/// `p = (x < 64)` before `x -= 64` refines `new_x in [-64, -1]` while
/// `q = (x < 4)` recorded after applies to the current value
/// untranslated.
/// Intersect one bound shape with a slot's current value: the upper
/// (`high`) and lower (`low`) bounds apply independently, shifted by
/// the slot's origin offset. Returns `None` when the bound states
/// nothing usable (unknown value with a lower-only shape, unknown
/// value with a signed bound, infeasible intersect, non-index value):
/// the edge keeps its prior refinement.
fn intersect_bound(
    values: &BTreeMap<Slot, Value>,
    target: &Slot,
    off: i64,
    high: i64,
    low: i64,
    constant_left: bool,
    signed: bool,
) -> Option<Value> {
    // Intersect, not overwrite: a bound on
    // `t = origin + off` narrows the origin.
    // Only a plain index-space value
    // (base 0, stride 1) shifts this way.
    // The refined floor can still go
    // negative: `lea 0x10(%rax),%rdx;
    // cmp $0x20,%rdx` bounds eax to
    // [-0x10, 3-0x10]. No compiler indexes
    // a table negatively, so the guard was
    // never stated.
    // A signed upper bound constrains below zero (`R8 <_s 0` admits
    // `[-2^63, high]`), so the unsigned origin-nonnegativity floor
    // (`-off`) does not apply: the value's own floor is the only
    // floor. An unsigned bound keeps it, and a constant-left shape
    // keeps its lower shape.
    let floor = if signed && !constant_left {
        i64::MIN
    } else if constant_left {
        low.saturating_sub(off)
    } else {
        -off
    };
    match values.get(target).cloned() {
        Some(Value::Strided { base: 0, stride: 1, lo, hi: old_hi, .. }) => {
            // An unsigned lower bound names a complement the single
            // interval cannot always hold: negative-signed members are
            // unsigned-large and may satisfy `x >=_u n` too. Proceed
            // exactly when the negative piece is empty: their olds span
            // `[lo+off, off-1]`, so `lo+off >= 0` keeps them
            // unsigned-small and `off-1 < low` keeps them below the
            // limit; then the floor is exact. Otherwise refuse -- the
            // negative piece is real but unnameable. Signed lowers are
            // single intervals either way.
            let neg_piece_empty = lo.checked_add(off).is_some_and(|shifted| shifted >= 0)
                && off.checked_sub(1).is_some_and(|prev| prev < low);
            if constant_left && !signed && !neg_piece_empty {
                return None;
            }
            let floor = lo.max(floor);
            let hi = if constant_left {
                old_hi
            } else {
                old_hi.min(high - off)
            };
            if hi < floor {
                return None;
            }
            Some(Value::Strided { base: 0, stride: 1, lo: floor, hi, guarded: floor >= 0 })
        }
        // A fresh bound on an unknown value. A lower-bound shape
        // alone states no ceiling, so it refines nothing here
        // rather than inventing one -- and a signed bound on an
        // unknown value has no nameable floor (the unsigned `-off`
        // floor would exclude the negative half the bound admits),
        // so it refines nothing either.
        Some(Value::Top) | None => {
            if constant_left || signed {
                return None;
            }
            let (lo, hi) = (-off, high - off);
            if hi < lo {
                return None;
            }
            Some(Value::Strided { base: 0, stride: 1, lo, hi, guarded: lo >= 0 })
        }
        // A set filters to the members the
        // bound admits: sound, and keeps the
        // precision the set already had. The members are compared
        // signed: a signed upper bound keeps the negative-view
        // members an unsigned floor would drop.
        Some(Value::Set(values)) => {
            let kept: Vec<u64> = values.iter().copied()
                .filter(|v| (*v as i64) >= floor && (constant_left || (*v as i64) <= high - off))
                .collect();
            if kept.is_empty() {
                return None;
            }
            Some(Value::Set(std::rc::Rc::new(kept)))
        }
        // A constant outside the bound means
        // this edge is infeasible; a Strided
        // with a different base or stride is a
        // different value set entirely. Both
        // are left alone rather than refined
        // into an index-space bound.
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_guard_bound(
    values: &BTreeMap<Slot, Value>,
    origins: &BTreeMap<Slot, (Slot, i64, Option<u32>, u32)>,
    edges: &mut BTreeMap<usize, Vec<(Slot, Value)>>,
    branch: u64,
    bound: Predicate,
    successors: usize,
    skip_dest: Option<usize>,
) {
    let (operand, limit, inclusive, constant_left, operand_size, stamp, direct, signed) = bound;
    // `index < n` taken means index <= n-1; `n < index`
    // *not* taken means index <= n. `high` may go negative: a signed
    // bound (`JL` on `x <_s 0`) is a real upper bound, not an empty
    // one, and the per-arm intersect below decides feasibility --
    // the old blanket `high < 0` return dropped every negative
    // bound before it could refine anything. `low` is the lower
    // bound for the constant-left shape (`n < index` holds
    // `index >= n+1`, `n <= index` holds `index >= n`); the taken
    // edge of `cmp $10,%edx; ja` never states one.
    let high = if constant_left {
        if inclusive { limit as i64 - 1 } else { limit as i64 }
    } else if inclusive {
        limit as i64
    } else {
        limit as i64 - 1
    };
    let low = if constant_left {
        if inclusive { limit as i64 } else { limit.saturating_add(1) as i64 }
    } else {
        i64::MIN
    };
    let edge = usize::from(constant_left);
    // The bound belongs to the value, wherever it
    // lives: the compared slot and whatever it was
    // copied from. A temp `t = origin + off` bounded
    // to [0, high] bounds the origin to
    // [-off, high - off].
    // A stamped bound names the slot's pre-write value: the entry is
    // `-shift` (`old in [0, high]` with `new = old + shift` is `new
    // in [shift, high + shift]`). For `r8 -= 64` under `old_r8 < 64`
    // the entry is `(r8, +64)`, refining `new_r8 in [-64, -1]` --
    // not `[64, 127]`. The stamped entry stands alone: no
    // untranslated `(operand, 0)` (it would apply the pre-write
    // bound to the post-write slot), and no fixpoint propagation
    // to aliases (a post-write copy `y = x` holds the post-write
    // value, which the pre-write bound constrains only through the
    // stamp on `x` itself -- flattening it onto `y` mistargets).
    // Unstamped bounds keep the init entry and walk the live map.
    let mut targets = if let Some(shift) = stamp {
        vec![(operand.clone(), -shift)]
    } else {
        vec![(operand.clone(), 0i64)]
    };
    // Follow the origin chain transitively -- but only for unstamped
    // bounds. A stamp means an in-place rewrite stands between the
    // comparison and the branch, and every rewrite removes the
    // operand's link before recording a new one: any live link on
    // the operand now post-dates the comparison and describes the
    // post-write value, so walking it re-targets the pre-write
    // bound (`y = x; p = (y < 4); y -= 16` walks `y -> (x, -16)`
    // and bounds `x` to `[16, 19]` instead of `[0, 3]`). The stamp
    // entry above is the complete translation; aliases are already
    // excluded with it.
    if stamp.is_none() {
    // `dl` came from `edx`, which came from `r15`, so a
    // bound on the compared temp is a bound on each
    // link, shifted by the accumulated offset.
    {
        let mut current = operand.clone();
        let mut accumulated = 0i64;
        // The narrowest width crossed *so far*: a
        // bound on `al` that came through `eax` is
        // still a byte bound when it reaches `rax`,
        // so the running minimum, not this hop's
        // `narrow`, is what the origin must fit.
        let mut narrowest = operand_size;
        let mut seen: std::collections::HashSet<Slot> =
            [current.clone()].into_iter().collect();
        while let Some((origin, off, narrow, origin_size)) =
            origins.get(&current)
        {
            narrowest = narrow.map_or(narrowest, |w| w.min(narrowest));
            let effective = narrowest;
            // The origin's own width, not its current
            // value, decides: `mov %ebx,%r11d` copies
            // all of ebx, so a bound on the copy is a
            // bound on ebx whatever ebx holds.
            // a self-loop (`r8 -> (r8, -k)`) names the slot's pre-write
            // value, but an unstamped predicate was recorded after the
            // rewrite and constrains the current value. Stamped
            // (pre-write) predicates translate through the stamp above.
            if *origin == current {
                break;
            }
            let usable = if effective >= 8 || *origin_size <= effective {
                true
            } else {
                let mask = (1u64 << (effective * 8)) - 1;
                match values.get(origin) {
                    Some(Value::Top) | None => false,
                    Some(Value::Const(c)) => *c <= mask,
                    Some(Value::Strided { base: 0, stride: 1, lo, hi, .. }) =>
                        *lo >= 0 && *hi >= *lo && (*hi as u64) <= mask,
                    _ => false,
                }
            };
            let next_off = accumulated + off;
            // The shifted bound must fit the narrow
            // width too: `lea -0xf0(%r15),%eax; cmp
            // $0x5a,%al` wraps inside the byte, and
            // the interval would drop the wrapped
            // half.
            let fits = effective >= 8
                || (high - next_off) as u64
                    <= (1u64 << (effective * 8)) - 1;
            if usable && fits {
                targets.push((origin.clone(), next_off));
            }
            accumulated = next_off;
            current = origin.clone();
            if !seen.insert(current.clone()) {
                break;
            }
        }
    }
    }
    // And the other direction: `mov %ebx,%r11d`
    // before the compare means r11's origin is the
    // bounded slot, so the bound belongs to r11
    // too. Walk the links to a fixpoint: a slot
    // whose origin is already targeted gets the
    // bound shifted by its own offset. Only exact
    // copies and shifts propagate -- a subpiece
    // (narrow set) truncates, and a bound on the
    // whole says nothing about the piece. Stamped
    // (pre-write) bounds skip this: their entry names the
    // pre-write value, and no post-write alias may inherit it.
    let mut reached: Vec<(Slot, i64)> = targets.clone();
    if stamp.is_none() {
    loop {
        let mut grew = false;
        for (slot, (origin, off, narrow, _)) in origins {
            if reached.iter().any(|(s, _)| s == slot) {
                continue;
            }
            // Never flatten a copy through a pre-write self-link:
            // `y = x` after `x -= 64` links `y -> (x, 0)`, but `x`'s
            // bound here is the *pre-write* value (stamped) while `y`
            // holds the post-write one. Propagating the stamped entry
            // to `y` would claim `y in [-64, -61]` when `x == y`
            // post-write. The unstamped `(x, 0)` entry propagates
            // normally; stamped entries stay on their own slot.
            if *origin == *slot {
                continue;
            }
            if let Some((_, bound)) = reached.iter().find(|(s, _)| s == origin) {
                // The entry is an offset: `(s, o)`
                // means `s <= high - o`. `slot =
                // origin + off` and `origin <=
                // high - o` bound the slot to
                // `high - (o - off)`, so the slot's
                // entry is `o - off`.
                let shifted = bound - off;
                // origin still admits the bound when
                // the bound on it fits the truncated
                // width: `rax = zext(eax)` is a
                // 4-byte piece of `r14 - 0x20`, and
                // `eax <= 0x5a` bounds `rax` to
                // `0x5a` because `0x5a` fits the
                // piece. A bound that does not fit
                // wraps inside the piece and states
                // nothing.
                if let Some(width) = narrow {
                    let hi = high - shifted;
                    if *width < 8
                        && (hi < 0
                            || (hi as u64) > (1u64 << (*width * 8)) - 1)
                    {
                        continue;
                    }
                }
                reached.push((slot.clone(), shifted));
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    }
    if stamp.is_some() {
        reached = targets.clone();
    }
    targets = reached;
    // The taken edge is the one the comparison holds
    // on; our block successors list the taken target
    // first (`Block::successors`). Which side of the
    // branch the bound belongs to depends on how the
    // flags were combined and negated, and getting
    // that wrong silently is worse than trying both:
    // a bound applied to the wrong edge produces
    // targets that do not decode inside the function,
    // and `materialise` refuses those. So both edges
    // get the candidate and the check decides.
    let trace_cbranch = std::env::var("ROMWRIGHT_TRACE_SJA_CBRANCH")
        .ok()
        .and_then(|raw| {
            u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok()
        })
        == Some(branch);
    if trace_cbranch {
        eprintln!(
            "CBRANCH {:#x}: operand={:?} high={} targets={:?}",
            branch, operand, high, targets
        );
    }
    // The negation (flipped inclusivity and side) bounds the edge
    // the comparison does not hold on: `!(x < n)` is `x >= n`. Both
    // shapes refine both edges; overwrite order plus the
    // infeasibility skip heals polarity. On an edge a shape
    // contradicts, its intersect is infeasible and the other
    // shape's refinement stands; where both are feasible the last
    // one wins, and the materialise check refuses what decodes
    // outside the function.
    let neg_inclusive = !inclusive;
    let neg_left = !constant_left;
    let neg_high = if neg_left {
        if neg_inclusive { limit as i64 - 1 } else { limit as i64 }
    } else if neg_inclusive {
        limit as i64
    } else {
        limit as i64 - 1
    };
    let neg_low = if neg_left {
        if neg_inclusive { limit as i64 } else { limit.saturating_add(1) as i64 }
    } else {
        i64::MIN
    };
    // Destinations: a direct bound is the branch condition's truth, and
    // truth holds on the taken edge (successor 0) whatever side the
    // constant sat on: `index < n` taken means the upper bound, `n <
    // index` taken means the lower bound. The old const-left-maps-to-1
    // rule put lower bounds on the fallthrough, exactly backwards: a
    // direct `n < index` read holds taken, not fallthrough. The negation
    // holds on the other edge. Combination-derived bounds carry no
    // polarity, so they keep the both-edges defense with the stated
    // shape only. A degenerate single-target branch has no distinct
    // false edge, so it keeps the legacy upper-only defense.
    let mut work: Vec<(i64, i64, bool, usize, bool)> = Vec::new();
    if direct && successors >= 2 {
        // Taken edge is successor 0 (block construction pushes the
        // taken target first; pruning preserves order). The `JL`-idiom
        // and single-negation bounds arrive direct the same way: the
        // pushed tuple already names the taken truth, so it refines
        // successor 0 and its negation refines successor 1.
        work.push((high, low, constant_left, 0, signed));
        work.push((neg_high, neg_low, neg_left, 1, signed));
    } else {
        work.push((high, low, constant_left, edge, signed));
        work.push((high, low, constant_left, 1 - edge, signed));
    }
    for (target, off) in targets {
        for (high, low, constant_left, dest, signed) in work.iter().copied() {
            // An OR fallthrough takes negations, not stated shapes (and
            // vice versa for the taken edge): skip the edge this shape
            // does not hold on.
            if skip_dest == Some(dest) {
                continue;
            }
            let Some(bounded) = intersect_bound(values, &target, off, high, low, constant_left, signed)
            else {
                continue;
            };
            if trace_cbranch {
                eprintln!(
                    "  -> {:?} off={} bounded={:?}",
                    target, off, bounded
                );
            }
            edges.entry(dest).or_default().push((target.clone(), bounded));
        }
    }
}
// ---- Backward slice: findDeterminingVarnodes ----
//
// Ghidra's `JumpBasic::findDeterminingVarnodes` (jumptable.cc:554) walks a
// branch's address input back through the SSA def-use graph, descending
// `curvn->getDef()` while a varnode has one reaching definition and
// pruning where it does not -- a live-in, a merge of reaching defs, or a
// call/marker result (`isprune`, :424). A pruned varnode that is not a
// constant or a read-only is a candidate switch variable (`ispoint`,
// :436), and the ops common to every path form the address model
// (`pathMeld`). Our `PcodeVarnode` carries no def link and the p-code is
// not in SSA, so the reaching definitions are computed over the block
// graph first; the slice then descends a varnode with one reaching def
// and stops at one with none or several.

/// A position in the block graph: (block, instruction, op).
type DefPos = (usize, usize, usize);

/// What reaches a slot at a program point: one defining op, several
/// merged definitions, a live-in value no in-function op defines, or
/// bottom -- an edge whose transfer has not run yet and contributes
/// nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reach {
    /// The producing transfer has not run yet: no information. Bottom
    /// merges as identity and never materialises in the index.
    Bottom,
    /// No in-function definition reaches: the value is live-in.
    LiveIn,
    /// Exactly one op's output reaches.
    One(DefPos),
    /// Distinct definitions reach on different paths: a merge.
    Many,
}

impl Reach {
    /// Merges two incoming reaching definitions: bottom is identity, same
    /// source stays, any difference -- including one path live-in and one
    /// defined -- is a merge the slice cannot descend through.
    fn merge(self, other: Reach) -> Reach {
        if self == Reach::Bottom {
            return other;
        }
        if other == Reach::Bottom {
            return self;
        }
        if self == other {
            self
        } else {
            Reach::Many
        }
    }
}

/// Reaching definitions over the block graph: the `getDef()` the slice
/// needs, computed once per function.
struct DefIndex {
    /// Reaching definitions at each block's entry.
    reach_in: Vec<BTreeMap<Slot, Reach>>,
}

impl DefIndex {
    fn build(blocks: &[Block]) -> DefIndex {
        Self::build_with_entries(blocks, &[0])
    }

    /// Reaching definitions with explicit external entry seeds: the indices
    /// `analyse` seeds from outside (always block 0, plus every component
    /// the entry cannot reach). Graph structure alone cannot replace this
    /// boundary: a cycle with an incoming edge from another component
    /// still reads outside input on entry, and only the caller knows which
    /// blocks those are. Every seed merges the function-wide slot universe
    /// as `LiveIn` every pass alongside the other edges.
    fn build_with_entries(blocks: &[Block], entries: &[usize]) -> DefIndex {
        let n = blocks.len();
        let mut preds = vec![Vec::new(); n];
        for (index, block) in blocks.iter().enumerate() {
            for &successor in &block.successors {
                if successor < n {
                    preds[successor].push(index);
                }
            }
        }
        // Intern slots to dense ids for the fixpoint below. This is a pure
        // representation change: the lattice, the seeds, the merge order
        // effects (merge is commutative), and the stored facts are
        // identical. What changes is cost: the hot function holds
        // hundreds of blocks over a function-wide universe, and keying
        // every map by `(String, u64)` pays string compare/clone on every
        // edge every pass. Dense `Vec<Reach>` rows pay integer indexing.
        let mut id_of: BTreeMap<Slot, usize> = BTreeMap::new();
        let mut slots: Vec<Slot> = Vec::new();
        let mut intern = |slot: Slot| {
            if let Some(&id) = id_of.get(&slot) {
                return id;
            }
            let id = slots.len();
            slots.push(slot.clone());
            id_of.insert(slot, id);
            id
        };
        // Pre-intern in a fixed order so ids are deterministic.
        for block in blocks.iter() {
            for instruction in &block.instructions {
                for op in &instruction.ops {
                    for input in op.inputs.iter().filter(|v| !v.is_const()) {
                        intern(slot(input));
                    }
                    if let Some(out) = &op.output {
                        if !out.is_const() {
                            intern(slot(out));
                        }
                    }
                }
            }
        }
        let u = slots.len();
        // The last write each block makes to each slot, as its DefPos: a
        // later write kills the incoming definition.
        let mut last: Vec<Vec<Option<DefPos>>> = vec![vec![None; u]; n];
        for (index, block) in blocks.iter().enumerate() {
            for (insn, instruction) in block.instructions.iter().enumerate() {
                for (op_idx, op) in instruction.ops.iter().enumerate() {
                    if let Some(out) = &op.output {
                        if !out.is_const() {
                            let id = id_of[&slot(out)];
                            last[index][id] = Some((index, insn, op_idx));
                        }
                    }
                }
            }
        }
        let mut reach_in: Vec<Vec<Reach>> = vec![vec![Reach::Bottom; u]; n];
        let mut reach_out: Vec<Vec<Reach>> = vec![vec![Reach::Bottom; u]; n];
        // Forward fixpoint over a per-slot lattice with bottom. Every edge
        // starts at `Bottom` (its transfer has not run: neither a
        // definition nor a live-in source) and merges normally once
        // computed -- self-edges included, whose previous-pass OUT carries
        // loop-carried redefinitions. Missing is bottom on *every* edge
        // uniformly, so no circular absence ever becomes an implicit
        // `LiveIn`. `LiveIn` is seeded explicitly from entry roots: the
        // function-wide slot universe (every non-constant slot any block
        // names) is live at each root, where a root is a block with no
        // non-self predecessors -- including an entry that spans a cycle
        // whose members have no outside incoming edge. Seeding the
        // universe rather than per-block names keeps `entry -> left(def),
        // right(unnamed) -> join` at `Many`: the right arm contributes
        // the universe's live-in for the slot the left defines.
        let mut computed = vec![false; n];
        let mut prev_out: Vec<Vec<Reach>> = vec![vec![Reach::Bottom; u]; n];
        // External seeds as a set for the merge below: the caller names
        // the blocks it seeds from outside, and graph structure never
        // adds or removes one. A cycle with an incoming edge from another
        // component still reads outside input on entry, and only the
        // caller knows that boundary.
        let seeds: std::collections::BTreeSet<usize> =
            entries.iter().copied().filter(|&e| e < n).collect();
        for _ in 0..=n {
            let mut changed = false;
            for index in 0..n {
                computed[index] = true;
                // Iterating the full universe is a superset of the old
                // predecessor-key union: slots with no information
                // everywhere stay `Bottom` and are dropped from the
                // stored maps below, so the result is identical.
                let entry = seeds.contains(&index);
                for sid in 0..u {
                    let mut reach = Reach::Bottom;
                    for &pred in &preds[index] {
                        // Missing is bottom -- except through a block that
                        // is itself live for the slot: a computed
                        // predecessor whose entry already holds `LiveIn`
                        // passes it through unchanged. That is how the
                        // right arm of a diamond carries the entry's
                        // live-in to the join without defining anything.
                        let incoming = if pred == index {
                            prev_out[pred][sid]
                        } else if computed[pred] {
                            let out = reach_out[pred][sid];
                            if out != Reach::Bottom {
                                out
                            } else if reach_in[pred][sid] == Reach::LiveIn {
                                Reach::LiveIn
                            } else {
                                Reach::Bottom
                            }
                        } else {
                            Reach::Bottom
                        };
                        reach = reach.merge(incoming);
                    }
                    if entry {
                        reach = reach.merge(Reach::LiveIn);
                    }
                    if reach != reach_in[index][sid] {
                        reach_in[index][sid] = reach;
                        changed = true;
                    }
                }
                for sid in 0..u {
                    let mut out = reach_in[index][sid];
                    if let Some(def) = last[index][sid] {
                        out = Reach::One(def);
                    }
                    if out != reach_out[index][sid] {
                        reach_out[index][sid] = out;
                        changed = true;
                    }
                }
            }
            prev_out.clone_from(&reach_out);
            if !changed {
                break;
            }
        }
        let mut stored: Vec<BTreeMap<Slot, Reach>> = vec![BTreeMap::new(); n];
        for (index, row) in reach_in.iter().enumerate() {
            for (sid, &reach) in row.iter().enumerate() {
                if reach != Reach::Bottom {
                    stored[index].insert(slots[sid].clone(), reach);
                }
            }
        }
        DefIndex { reach_in: stored }
    }

    /// The reaching definition of `key` read at `upto` (instruction, op)
    /// in `block`: the last in-block write before the point, else the
    /// merged reaching definition at the block's entry.
    fn reaching_def(
        &self,
        blocks: &[Block],
        block: usize,
        key: &Slot,
        upto: (usize, usize),
    ) -> Reach {
        let mut found: Option<DefPos> = None;
        'outer: for (insn, instruction) in blocks[block].instructions.iter().enumerate() {
            for (op_idx, op) in instruction.ops.iter().enumerate() {
                if (insn, op_idx) >= upto {
                    break 'outer;
                }
                if let Some(out) = &op.output {
                    if !out.is_const() && slot(out) == *key {
                        found = Some((block, insn, op_idx));
                    }
                }
            }
        }
        if let Some(def) = found {
            return Reach::One(def);
        }
        self.reach_in[block]
            .get(key)
            .copied()
            .unwrap_or(Reach::LiveIn)
    }
}

/// The expression a backward slice recovers, in the shape `pathMeld`
/// keeps: the ops common to every path to the address. A `Point` is a
/// pruned varnode -- one with no single reaching definition -- which is
/// where a switch variable lives.
#[derive(Clone, Debug)]
enum Sliced {
    /// A constant.
    Const(u64),
    /// A pruned varnode: live-in, merged, or call/marker-defined. A
    /// candidate switch variable.
    Point(Slot),
    /// A varnode the slice could not descend into but that is not a
    /// switch-variable candidate (a unique temporary, a read-only).
    Opaque,
    /// `load(addr)` of `size` bytes.
    Load(Box<Sliced>, u32),
    /// `a + b`.
    Add(Box<Sliced>, Box<Sliced>),
    /// `a - b`.
    Sub(Box<Sliced>, Box<Sliced>),
    /// `a * b`.
    Mult(Box<Sliced>, Box<Sliced>),
    /// `a & b`.
    And(Box<Sliced>, Box<Sliced>),
    /// `a | b`.
    Or(Box<Sliced>, Box<Sliced>),
    /// `a << b`.
    Left(Box<Sliced>, Box<Sliced>),
    /// Sign-extend `a` from `width` bytes.
    SExt(Box<Sliced>, u32),
    /// Zero-extend `a` from `width` bytes.
    ZExt(Box<Sliced>, u32),
}

/// The slice depth bound: a switch address is a short chain, and a bound
/// stops a malformed or cyclic def graph from recursing forever.
const SLICE_DEPTH: u32 = 24;

/// Resolves `varnode` read at `upto` in `block` into its sliced
/// expression, descending through single reaching definitions and
/// stopping at pruned varnodes.
fn slice_expr(
    defs: &DefIndex,
    blocks: &[Block],
    block: usize,
    varnode: &PcodeVarnode,
    upto: (usize, usize),
    depth: u32,
) -> Sliced {
    if varnode.is_const() {
        return Sliced::Const(varnode.offset);
    }
    if depth == 0 {
        return Sliced::Opaque;
    }
    let key = slot(varnode);
    match defs.reaching_def(blocks, block, &key, upto) {
        Reach::One((b, insn, op_idx)) => {
            let op = &blocks[b].instructions[insn].ops[op_idx];
            slice_op(defs, blocks, b, op, (insn, op_idx), depth - 1)
        }
        // A merge, a live-in, or bottom (no computed definition reaches):
        // a pruned varnode. A persistent one is a switch-variable
        // candidate; a unique temporary is not.
        Reach::Many | Reach::LiveIn | Reach::Bottom => {
            if varnode.is_persistent() {
                Sliced::Point(key)
            } else {
                Sliced::Opaque
            }
        }
    }
}

/// Slices one defining op's output into its expression, recursing on its
/// inputs. `upto` is the op's own position, so its inputs are read just
/// before it.
fn slice_op(
    defs: &DefIndex,
    blocks: &[Block],
    block: usize,
    op: &crate::native_runtime::PcodeOp,
    upto: (usize, usize),
    depth: u32,
) -> Sliced {
    use crate::ir::Opcode as O;
    let opcode = op.opcode.parse::<O>().unwrap_or(O::Other);
    // `isprune`: a call, a marker, or an input-free op ends the descent and
    // its output is a point, not an expression.
    let prunes = matches!(
        opcode,
        O::Call | O::CallInd | O::CallOther | O::Branch | O::CBranch | O::BranchInd | O::Return
    ) || op.inputs.is_empty();
    if prunes {
        return match &op.output {
            Some(out) if out.is_persistent() => Sliced::Point(slot(out)),
            _ => Sliced::Opaque,
        };
    }
    let input = |index: usize| -> Sliced {
        op.inputs
            .get(index)
            .map(|v| slice_expr(defs, blocks, block, v, upto, depth - 1))
            .unwrap_or(Sliced::Opaque)
    };
    match opcode {
        O::Copy | O::Cast => input(0),
        O::Load => Sliced::Load(Box::new(input(1)), op.output.as_ref().map_or(8, |o| o.size)),
        O::IntAdd => Sliced::Add(Box::new(input(0)), Box::new(input(1))),
        O::IntSub => Sliced::Sub(Box::new(input(0)), Box::new(input(1))),
        O::IntMult => Sliced::Mult(Box::new(input(0)), Box::new(input(1))),
        O::IntAnd => Sliced::And(Box::new(input(0)), Box::new(input(1))),
        O::IntOr => Sliced::Or(Box::new(input(0)), Box::new(input(1))),
        O::IntLeft => Sliced::Left(Box::new(input(0)), Box::new(input(1))),
        O::IntSExt => Sliced::SExt(
            Box::new(input(0)),
            op.inputs.first().map_or(8, |v| v.size),
        ),
        O::IntZExt => Sliced::ZExt(
            Box::new(input(0)),
            op.inputs.first().map_or(8, |v| v.size),
        ),
        // A low-piece extraction is a quasi-copy: `subpiece(x, 0)` keeps
        // x's low bits, so the slice follows it.
        O::Subpiece
            if matches!(op.inputs.get(1), Some(k) if k.is_const() && k.offset == 0) =>
        {
            input(0)
        }
        _ => Sliced::Opaque,
    }
}

/// The table a dispatch reads: where entry 0 sits, how wide each entry
/// is, the index expression, and whether entries are absolute targets or
/// signed offsets from a base.
struct TableSlice {
    /// Address of entry 0.
    table_base: u64,
    /// Bytes per entry.
    entry_size: u32,
    /// Address step per index: `table_base + index * stride`.
    stride: u64,
    /// The index expression, for bound evaluation.
    index: Sliced,
    /// For a PIC table, the base the signed offset is added to; `None`
    /// for an absolute-target table.
    offset_base: Option<u64>,
}

/// Finds the table read inside a sliced dispatch target and pulls out its
/// descriptor. Returns `None` when the target is not a table read.
fn match_table(expr: &Sliced) -> Option<TableSlice> {
    // Peel the additive constants and no-op wrappers around the load,
    // accumulating the PIC offset base. `Add(Const, rest)` and
    // `Mult(x, 1)` are transparent; a non-constant addend means the target
    // is not purely the loaded value.
    let mut offset_base = 0u64;
    let mut current = expr;
    let load = loop {
        match current {
            Sliced::Load(_, _) => break current,
            Sliced::Add(a, b) => {
                if let Sliced::Const(k) = **a {
                    offset_base = offset_base.wrapping_add(k);
                    current = b;
                } else if let Sliced::Const(k) = **b {
                    offset_base = offset_base.wrapping_add(k);
                    current = a;
                } else {
                    return None;
                }
            }
            Sliced::Mult(a, b) => {
                if matches!(**a, Sliced::Const(1)) {
                    current = b;
                } else if matches!(**b, Sliced::Const(1)) {
                    current = a;
                } else {
                    return None;
                }
            }
            Sliced::SExt(inner, _) | Sliced::ZExt(inner, _) => current = inner,
            _ => return None,
        }
    };
    let Sliced::Load(addr, entry_size) = load else {
        unreachable!()
    };
    let (table_base, index, stride) = split_affine(addr)?;
    if table_base == 0 {
        return None;
    }
    Some(TableSlice {
        table_base,
        entry_size: *entry_size,
        stride,
        index,
        offset_base: (offset_base != 0).then_some(offset_base),
    })
}

/// Splits `base + index * stride` into `(base, index, stride)`, folding
/// nested additive constants into the base. Returns `None` when the sum
/// has more than one non-constant term.
fn split_affine(expr: &Sliced) -> Option<(u64, Sliced, u64)> {
    fn walk<'a>(
        expr: &'a Sliced,
        konst: &mut u64,
        index: &mut Option<&'a Sliced>,
    ) -> bool {
        match expr {
            Sliced::Const(k) => {
                *konst = konst.wrapping_add(*k);
                true
            }
            Sliced::Add(a, b) => walk(a, konst, index) && walk(b, konst, index),
            other => {
                if index.is_some() {
                    return false;
                }
                *index = Some(other);
                true
            }
        }
    }
    let mut konst = 0u64;
    let mut index = None;
    if !walk(expr, &mut konst, &mut index) {
        return None;
    }
    let index = index?;
    // `index * stride`: a multiply by a constant is the stride; anything
    // else is the index itself at stride 1.
    let (index, stride) = match index {
        Sliced::Mult(a, b) => {
            if let Sliced::Const(s) = **a {
                ((**b).clone(), s)
            } else if let Sliced::Const(s) = **b {
                ((**a).clone(), s)
            } else {
                (index.clone(), 1)
            }
        }
        other => (other.clone(), 1),
    };
    Some((konst, index, stride))
}

/// Evaluates a sliced expression into the abstract `Value` domain, so a
/// mask or width bound on the index resolves to its interval. `bound`
/// substitutes a guard's upper bound for one point leaf: the switch
/// variable the guard compared, so the expression's own arithmetic (a
/// shift, a mask) applies to the bounded value, not to `Top`.
fn eval_sliced<I: Image>(image: &I, expr: &Sliced, bound: Option<(&Slot, u64)>) -> Value {
    match expr {
        Sliced::Const(k) => Value::Const(*k),
        Sliced::Point(key) => match bound {
            Some((slot, high)) if slot == key => Value::Strided {
                base: 0,
                stride: 1,
                lo: 0,
                hi: high as i64,
                guarded: true,
            },
            _ => Value::Top,
        },
        Sliced::Opaque => Value::Top,
        Sliced::Load(addr, size) => load(image, eval_sliced(image, addr, bound), *size),
        Sliced::Add(a, b) => add(
            eval_sliced(image, a, bound),
            eval_sliced(image, b, bound),
        ),
        Sliced::Sub(a, b) => {
            let right = eval_sliced(image, b, bound);
            add(eval_sliced(image, a, bound), negate_interval(right))
        }
        Sliced::Mult(a, b) => multiply(
            eval_sliced(image, a, bound),
            eval_sliced(image, b, bound),
        ),
        Sliced::And(a, b) => match (
            eval_sliced(image, a, bound),
            eval_sliced(image, b, bound),
        ) {
            (Value::Const(l), Value::Const(r)) => Value::Const(l & r),
            (value, Value::Const(mask)) | (Value::Const(mask), value) => {
                bound_by_mask(value, mask)
            }
            _ => Value::Top,
        },
        Sliced::Or(a, b) => match (
            eval_sliced(image, a, bound),
            eval_sliced(image, b, bound),
        ) {
            (Value::Const(l), Value::Const(r)) => Value::Const(l | r),
            _ => Value::Top,
        },
        Sliced::Left(a, b) => match (
            eval_sliced(image, a, bound),
            eval_sliced(image, b, bound),
        ) {
            (value, Value::Const(shift)) => {
                let factor = 1u64.checked_shl(shift as u32).unwrap_or(0);
                multiply(value, Value::Const(factor))
            }
            _ => Value::Top,
        },
        Sliced::SExt(inner, width) => map_values(
            &eval_sliced(image, inner, bound),
            |raw| sign_extend(raw, *width),
        ),
        Sliced::ZExt(inner, width) => map_values(
            &eval_sliced(image, inner, bound),
            |raw| truncate(raw, *width),
        ),
    }
}
/// The earliest slot a varnode is quasi-copied from: through copies,
/// extensions, low-piece extractions, and mask/or operations that keep its
/// low bits. This is `GuardRecord::quasiCopy` (jumptable.cc:719): a guard
/// compares a *copy* of the switch variable, and matching the base slot is
/// what connects them.
fn quasi_copy(
    defs: &DefIndex,
    blocks: &[Block],
    block: usize,
    varnode: &PcodeVarnode,
    upto: (usize, usize),
) -> Slot {
    let mut current = slot(varnode);
    let mut at = upto;
    let mut in_block = block;
    for _ in 0..SLICE_DEPTH {
        let Reach::One((b, insn, op_idx)) =
            defs.reaching_def(blocks, in_block, &current, at)
        else {
            break;
        };
        let op = &blocks[b].instructions[insn].ops[op_idx];
        use crate::ir::Opcode as O;
        let opcode = op.opcode.parse::<O>().unwrap_or(O::Other);
        let next = match opcode {
            O::Copy | O::Cast | O::IntSExt | O::IntZExt => op.inputs.first(),
            O::Subpiece
                if matches!(op.inputs.get(1), Some(k) if k.is_const() && k.offset == 0) =>
            {
                op.inputs.first()
            }
            _ => None,
        };
        let Some(source) = next else { break };
        if source.is_const() {
            break;
        }
        current = slot(source);
        in_block = b;
        at = (insn, op_idx);
    }
    current
}

/// The bound a CBRANCH states: the compared varnode, the block and op
/// position of the comparison (for quasi-copy resolution), the limit, and
/// whether the compare was `<=`. Only `index < limit` (constant on the
/// right) yields an upper bound a table can use; `limit < index` is a
/// lower bound and bounds nothing here.
fn cbranch_bound(
    defs: &DefIndex,
    blocks: &[Block],
    block: usize,
    insn: usize,
    op_idx: usize,
) -> Option<(PcodeVarnode, usize, (usize, usize), u64, bool)> {
    use crate::ir::Opcode as O;
    let op = &blocks[block].instructions[insn].ops[op_idx];
    if op.opcode.parse::<O>().unwrap_or(O::Other) != O::CBranch {
        return None;
    }
    let condition = op.inputs.get(1)?;
    // The condition's reaching def is the comparison op.
    let Reach::One((b, ci, co)) =
        defs.reaching_def(blocks, block, &slot(condition), (insn, op_idx))
    else {
        return None;
    };
    let cmp = &blocks[b].instructions[ci].ops[co];
    let cmp_op = cmp.opcode.parse::<O>().unwrap_or(O::Other);
    let inclusive = matches!(cmp_op, O::IntLessEqual | O::IntSLessEqual);
    if !matches!(
        cmp_op,
        O::IntLess | O::IntSLess | O::IntLessEqual | O::IntSLessEqual
    ) {
        return None;
    }
    let left = cmp.inputs.first()?;
    let right = cmp.inputs.get(1)?;
    // `index < limit`: the index is the non-constant left operand.
    if right.is_const() && !left.is_const() {
        Some((left.clone(), b, (ci, co), right.offset, inclusive))
    } else {
        None
    }
}

/// Reads a recovered table into its targets. A bounded index reads at
/// `table_base + index * stride`; a guard-less one scans the table
/// linearly by entry position -- Ghidra's memory-scan bound
/// (`JumpBasic::sanityCheck`, jumptable.cc:1592), which stops at the
/// first entry that does not read, does not decode as code, or lands in
/// another function. For a PIC table the next table's offsets resolve
/// against *this* base, so an over-read produces a wrong address and
/// stops the scan on its own; for an absolute table the in-extent and
/// owner checks are what keep a wrong bound from inventing cases.
fn read_table<I: Image>(
    image: &I,
    table: &TableSlice,
    index: &Value,
    extent: (u64, u64),
) -> Result<Vec<u64>, Reason> {
    // The addresses to probe. A `Strided` whose lowest value is negative
    // was shifted below zero by the index's own arithmetic -- that reads
    // the preceding table, not a dispatch.
    let addresses: Vec<u64> = match index {
        Value::Const(k) => {
            vec![table.table_base.wrapping_add(k.wrapping_mul(table.stride))]
        }
        Value::Set(values) => values
            .iter()
            .map(|i| table.table_base.wrapping_add(i.wrapping_mul(table.stride)))
            .collect(),
        Value::Strided {
            base,
            stride,
            lo,
            hi,
            ..
        } => {
            if hi < lo || hi - lo >= MAX_TABLE {
                return Err(Reason::TooWide);
            }
            let first = base.wrapping_add(stride.wrapping_mul(*lo as u64));
            if (first as i64) < 0 {
                return Err(Reason::Unknown);
            }
            (*lo..=*hi)
                .map(|i| {
                    let idx = base.wrapping_add(stride.wrapping_mul(i as u64));
                    table.table_base.wrapping_add(idx.wrapping_mul(table.stride))
                })
                .collect()
        }
        // Guard-less: scan the table linearly by entry position until an
        // invalid entry -- Ghidra's memory-scan bound
        // (`JumpBasic::sanityCheck`, jumptable.cc:1592). Only sound when
        // the index is dense: the entry step equals the entry size, or
        // the index is already scaled (stride 1 means the expression
        // carries the `<<3` itself).
        Value::Top => {
            if table.stride != table.entry_size as u64 && table.stride != 1 {
                return Err(Reason::Unknown);
            }
            (0..MAX_TABLE as u64)
                .map(|k| table.table_base.wrapping_add(k.wrapping_mul(table.entry_size as u64)))
                .collect()
        }
    };
    let mut targets = Vec::new();
    for at in addresses {
        let Some(entry) = image.read(at, table.entry_size) else {
            break;
        };
        let target = match table.offset_base {
            Some(base) => base.wrapping_add(sign_extend(entry, table.entry_size)),
            None => entry,
        };
        if !image.executable(target) {
            break;
        }
        if target < extent.0 || target >= extent.1 {
            match image.owner(target) {
                Some(owner) if owner != extent => break,
                _ => {}
            }
        }
        targets.push(target);
    }
    let mut distinct = targets.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 2 {
        return Err(Reason::TooFew);
    }
    Ok(targets)
}

/// Recovers a dispatch the forward pass left unknown, by slicing the
/// branch's address input back to its table and bounding the index -- the
/// `findDeterminingVarnodes` path. Returns the table's targets when the
/// slice finds a readable table and a bound for its index.
fn slice_dispatch<I: Image>(
    image: &I,
    defs: &DefIndex,
    blocks: &[Block],
    branch: u64,
    extent: (u64, u64),
    seeds: &[usize],
) -> Option<Result<Vec<u64>, Reason>> {
    use crate::ir::Opcode as O;
    // Locate the BRANCHIND op and its block.
    let (block, insn, op_idx) = blocks.iter().enumerate().find_map(|(b, block)| {
        block.instructions.iter().enumerate().find_map(|(i, instruction)| {
            if instruction.address != branch {
                return None;
            }
            instruction.ops.iter().enumerate().find_map(|(o, op)| {
                (op.opcode.parse::<O>().unwrap_or(O::Other) == O::BranchInd)
                    .then_some((b, i, o))
            })
        })
    })?;
    let op = &blocks[block].instructions[insn].ops[op_idx];
    let target = op.inputs.first()?;
    let expr = slice_expr(defs, blocks, block, target, (insn, op_idx), SLICE_DEPTH);
    // expression's own; the goto's target is the whole expression.
    match match_table(&expr) {
        Some(table) => {
            // Bound the index. First the expression's own structure: a
            // mask or a width already bounds it (the PIC masked-difference
            // class).
            let index_value = eval_sliced(image, &table.index, None);
            let index_value = if index_value.bounded() {
                index_value
            } else {
                match guard_bound(defs, blocks, &table.index, block, seeds) {
                    GuardSearch::Bound(point, high) => {
                        // The guard the forward pass could not connect bounds a
                        // point leaf of the index. Substituting it back into the
                        // expression applies the index's own arithmetic to the
                        // bounded value: `r8 - 0x10` under `r8 < 0x20` is
                        // `[-0x10, 0xf]`, and the negative low end refuses it.
                        eval_sliced(image, &table.index, Some((&point, high)))
                    }
                    GuardSearch::NoMatchingGuard
                        if table.offset_base.is_some()
                            && matches!(table.index, Sliced::Point(_)) =>
                    {
                        // No comparison, mask, or width bounds the index: scan a
                        // PIC table linearly until an invalid entry -- Ghidra's
                        // memory-scan bound (`JumpBasic::sanityCheck`). Sound only
                        // for PIC with a dense point index: the next table's
                        // offsets resolve against *this* base, so an over-read
                        // produces a wrong address and stops the scan -- and a
                        // point enumerates entries densely, which an opaque or
                        // arithmetic index (a hash, a masked value) does not.
                        // An absolute table's neighbours are valid code, so
                        // the scan would over-read into them -- refused, as is
                        // any non-dense index.
                        Value::Top
                    }
                    // No guard at all on an absolute table, a guard-like
                    // comparison that decides nothing, or a non-dense index:
                    // scanning would read whatever decodes next.
                    _ => return None,
                }
            };
            Some(read_table(image, &table, &index_value, extent))
        }
        None => {
            // A computed goto: the sliced expression is the target. Bound
            // a point leaf through the guard and materialise the result.
            let target_value = eval_sliced(image, &expr, None);
            let target_value = if target_value.bounded() {
                target_value
            } else {
                match guard_bound(defs, blocks, &expr, block, seeds) {
                    GuardSearch::Bound(point, high) => eval_sliced(image, &expr, Some((&point, high))),
                    GuardSearch::NoMatchingGuard | GuardSearch::RejectedMatchingGuard => return None,
                }
            };
            Some(materialise(image, target_value, Value::Top, extent))
        }
    }
}


/// Whether `to` is reachable from `from` through block successors.
fn reaches(blocks: &[Block], from: usize, to: usize) -> bool {
    if from == to {
        return true;
    }
    if from >= blocks.len() {
        return false;
    }
    let mut seen = vec![false; blocks.len()];
    let mut stack = vec![from];
    seen[from] = true;
    while let Some(node) = stack.pop() {
        for &successor in &blocks[node].successors {
            if successor == to {
                return true;
            }
            if successor < blocks.len() && !seen[successor] {
                seen[successor] = true;
                stack.push(successor);
            }
        }
    }
    false
}
/// Whether every path from `entry` to `target` passes through `node`.
/// Implemented by removal: `target` reachable with `node` skipped means
/// some path avoids it.
fn dominates(blocks: &[Block], entry: usize, node: usize, target: usize) -> bool {
    // A zero-length path passes through nothing: when the dispatch is
    // itself the component root, only itself dominates it.
    if entry == target {
        return node == target;
    }
    if !reaches(blocks, entry, target) {
        return false;
    }
    if node == entry || node == target {
        return true;
    }
    let mut seen = vec![false; blocks.len()];
    let mut stack = vec![entry];
    seen[entry] = true;
    while let Some(current) = stack.pop() {
        if current == node {
            continue;
        }
        for &successor in &blocks[current].successors {
            if successor == target {
                return false;
            }
            if successor < blocks.len() && !seen[successor] {
                seen[successor] = true;
                stack.push(successor);
            }
        }
    }
    true
}
/// Whether the CBRANCH in `branch_block` decides the dispatch in `disp`:
/// the branch block dominates the dispatch from every component root
/// reaching it (so the bound is on every arrival path), and the branch's
/// false edge cannot reach the dispatch (so no arrival refutes it).
/// Successor 0 is the taken edge; fewer than two distinct successors is
/// not a decision (degenerate control flow states nothing here).
fn guard_decides(blocks: &[Block], seeds: &[usize], branch_block: usize, disp: usize) -> bool {
    let mut rooted = false;
    for &seed in seeds {
        if !reaches(blocks, seed, disp) {
            continue;
        }
        rooted = true;
        if !dominates(blocks, seed, branch_block, disp) {
            return false;
        }
    }
    if !rooted {
        return false;
    }
    let successors = &blocks[branch_block].successors;
    if successors.len() < 2 || successors[0] == successors[1] {
        return false;
    }
    !reaches(blocks, successors[1], disp)
}
/// What the guard search found: a deciding bound, no quasi-copy
/// comparison at all, or a quasi-copy comparison reaching the dispatch
/// that decides nothing. Only the first may bound the index; only the
/// second may fall back to the guardless linear scan. A reaching but
/// undeciding guard is evidence the index is wild where it matters --
/// scanning past it over-reads into whatever decodes next.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GuardSearch {
    Bound(Slot, u64),
    NoMatchingGuard,
    RejectedMatchingGuard,
}
/// Finds a CBRANCH whose compared varnode is a quasi-copy of a point leaf
/// of `expr` -- the guard the forward pass could not connect. Returns the
/// deciding bound, or whether the search found nothing (`NoMatchingGuard`)
/// or only reaching-but-undeciding comparisons (`RejectedMatchingGuard`).
/// `index < limit` bounds the index to `0..=limit-1` (`<=` to `0..=limit`).
fn guard_bound(defs: &DefIndex, blocks: &[Block], expr: &Sliced, disp: usize, seeds: &[usize]) -> GuardSearch {
    let mut points: Vec<Slot> = Vec::new();
    collect_points(expr, &mut points);
    let mut best: std::collections::BTreeMap<Slot, u64> = std::collections::BTreeMap::new();
    let mut rejected = false;
    for (b, blk) in blocks.iter().enumerate() {
        for (i, instruction) in blk.instructions.iter().enumerate() {
            for (o, _) in instruction.ops.iter().enumerate() {
                let Some((compared, cmp_block, cmp_at, limit, inclusive)) =
                    cbranch_bound(defs, blocks, b, i, o)
                else {
                    continue;
                };
                // The guard applies when the compared varnode is a
                // quasi-copy of a switch-variable point: same base slot,
                // or the compared varnode itself is a point. The point
                // must enter the index expression *unshifted*: a bound
                // stated for `r8` says nothing about `r8 + 48`, whose
                // loop-carried value the comparison never observed. A
                // shifted occurrence would evaluate the guard's interval
                // through arithmetic the guard did not state, reading a
                // different table region (observed: entries 48.. of the
                // neighbour table instead of 0..15 of the true one,
                // materialising a foreign function's blocks).
                let base = quasi_copy(defs, blocks, cmp_block, &compared, cmp_at);
                let Some(point) = points
                    .iter()
                    .find(|point| {
                        (**point == base || **point == slot(&compared))
                            && index_uses_point_unshifted(expr, point)
                    })
                else {
                    continue;
                };
                if !guard_decides(blocks, seeds, b, disp) {
                    // A quasi-copy comparison reaching the dispatch that
                    // decides nothing: the index is wild where it
                    // matters. Remember, but keep searching -- a deciding
                    // guard elsewhere still wins.
                    if reaches(blocks, b, disp) {
                        rejected = true;
                    }
                    continue;
                }
                let high = if inclusive {
                    limit
                } else {
                    limit.saturating_sub(1)
                };
                best.entry(point.clone())
                    .and_modify(|kept| *kept = (*kept).min(high))
                    .or_insert(high);
            }
        }
    }
    match best.into_iter().min_by_key(|(_, high)| *high) {
        Some((point, high)) => GuardSearch::Bound(point, high),
        None if rejected => GuardSearch::RejectedMatchingGuard,
        None => GuardSearch::NoMatchingGuard,
    }
}
fn collect_points(expr: &Sliced, out: &mut Vec<Slot>) {
    match expr {
        Sliced::Point(key) => {
            if !out.contains(key) {
                out.push(key.clone());
            }
        }
        Sliced::Load(addr, _) => collect_points(addr, out),
        Sliced::Add(a, b)
        | Sliced::Sub(a, b)
        | Sliced::Mult(a, b)
        | Sliced::And(a, b)
        | Sliced::Or(a, b)
        | Sliced::Left(a, b) => {
            collect_points(a, out);
            collect_points(b, out);
        }
        Sliced::SExt(inner, _) | Sliced::ZExt(inner, _) => collect_points(inner, out),
        _ => {}
    }
}
/// Whether `point` occurs in the index expression under only transparent
/// wrappers: bare, through copies/extensions/scale-by-1, or beside a zero
/// constant. Any nonzero constant shift, non-unit multiply, shift, or
/// mask means the guard's interval would be transformed before indexing,
/// and the bound does not apply. (An earlier version allowed a shifted
/// occurrence when the other side did not mention the point; that is
/// backwards -- `Add(Point, Const(48))` shifts every value of the point
/// regardless of what the other side mentions.)
fn index_uses_point_unshifted(expr: &Sliced, point: &Slot) -> bool {
    match expr {
        Sliced::Point(key) => key == point,
        Sliced::Load(addr, _) => index_uses_point_unshifted(addr, point),
        Sliced::Add(a, b) | Sliced::Sub(a, b) => match (&**a, &**b) {
            (Sliced::Const(0), other) | (other, Sliced::Const(0)) => {
                index_uses_point_unshifted(other, point)
            }
            _ => false,
        },
        Sliced::Mult(a, b) => match (&**a, &**b) {
            (Sliced::Const(1), other) | (other, Sliced::Const(1)) => {
                index_uses_point_unshifted(other, point)
            }
            _ => false,
        },
        Sliced::SExt(inner, _) | Sliced::ZExt(inner, _) => {
            index_uses_point_unshifted(inner, point)
        }
        _ => false,
    }
}
fn reverse_post_order(blocks: &[Block]) -> Vec<usize> {
    let mut seen = vec![false; blocks.len()];
    let mut order = Vec::with_capacity(blocks.len());
    let mut stack = vec![(0usize, 0usize)];
    seen[0] = true;
    while let Some((node, position)) = stack.pop() {
        if position < blocks[node].successors.len() {
            stack.push((node, position + 1));
            let next = blocks[node].successors[position];
            if next < blocks.len() && !seen[next] {
                seen[next] = true;
                stack.push((next, 0));
            }
        } else {
            order.push(node);
        }
    }
    order.reverse();
    let missing: Vec<usize> = (0..blocks.len()).filter(|index| !seen[*index]).collect();
    let mut all = order;
    all.extend(missing);
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_runtime::PcodeOp;
    use std::collections::HashMap;

    struct Fixture {
        memory: HashMap<u64, u64>,
        code: (u64, u64),
    }

    impl Image for Fixture {
        fn read(&self, address: u64, _size: u32) -> Option<u64> {
            self.memory.get(&address).copied()
        }
        fn executable(&self, address: u64) -> bool {
            (self.code.0..self.code.1).contains(&address)
        }
        fn big_endian(&self) -> bool {
            false
        }
    }

    fn varnode(space: &str, offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.to_string(),
            offset,
            size,
        }
    }

    fn op(opcode: &str, output: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOp {
        PcodeOp {
            opcode: opcode.to_string(),
            output,
            inputs,
        }
    }

    fn instruction(address: u64, ops: Vec<PcodeOp>) -> PcodeInstruction {
        PcodeInstruction {
            address,
            length: 4,
            ops,
            error: None,
        }
    }

    /// `and $0xf, %ecx; shl $6, %ecx; add %r9, %rcx; jmp *%rcx` -- the
    /// computed goto libc's `__memcpy_ssse3` dispatches with. There is no
    /// table in memory: the cases are 16 blocks of 64 bytes and the mask is
    /// the only thing that says so.
    fn masked_goto(mask: u64) -> Vec<Block> {
        vec![Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_AND",
                        Some(varnode("register", 0x8, 8)),
                        vec![varnode("register", 0x8, 8), varnode("const", mask, 8)],
                    ),
                    op(
                        "INT_LEFT",
                        Some(varnode("register", 0x8, 8)),
                        vec![varnode("register", 0x8, 8), varnode("const", 6, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("register", 0x8, 8)),
                        vec![varnode("register", 0x8, 8), varnode("const", 0x1400, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("register", 0x8, 8)]),
                ],
            )],
            successors: Vec::new(),
        }]
    }

    #[test]
    fn a_mask_bounds_a_computed_goto_with_no_table_to_read() {
        let image = Fixture {
            memory: HashMap::new(),
            code: (0x1000, 0x2000),
        };
        let analysis = analyse(&image, &masked_goto(0xf), (0x1000, 0x2000));
        let table = analysis.tables.first().expect("a table");
        assert_eq!(table.branch, 0x1000);
        assert_eq!(table.targets.len(), 16);
        assert_eq!(table.targets.first(), Some(&0x1400));
        assert_eq!(table.targets.last(), Some(&(0x1400 + 15 * 64)));
    }

    #[test]
    fn a_goto_into_another_function_is_refused() {
        // The same dispatch, but a neighbour owns the case blocks: a bound
        // that reaches into another function is wrong, whatever it says.
        struct Owned(Fixture);
        impl Image for Owned {
            fn read(&self, address: u64, size: u32) -> Option<u64> {
                self.0.read(address, size)
            }
            fn executable(&self, address: u64) -> bool {
                self.0.executable(address)
            }
            fn big_endian(&self) -> bool {
                false
            }
            fn owner(&self, address: u64) -> Option<(u64, u64)> {
                (address >= 0x1400).then_some((0x1400, 0x2000))
            }
        }
        let image = Owned(Fixture {
            memory: HashMap::new(),
            code: (0x1000, 0x2000),
        });
        let analysis = analyse(&image, &masked_goto(0xf), (0x1000, 0x1400));
        assert!(analysis.tables.is_empty());
        assert_eq!(analysis.reasons.get(&0x1000), Some(&RefusalKind::Outside));
    }

    #[test]
    fn an_alignment_mask_states_no_bound() {
        // `and $0xfffffffffffffff0` clears low bits instead of keeping
        // them: it says nothing about how large the value is, and reading
        // it as a bound would invent a table of everything.
        let image = Fixture {
            memory: HashMap::new(),
            code: (0x1000, 0x2000),
        };
        let analysis = analyse(&image, &masked_goto(!0xf), (0x1000, 0x2000));
        assert!(analysis.tables.is_empty());
        assert_eq!(analysis.reasons.get(&0x1000), Some(&RefusalKind::Unknown));
    }

    /// A guard block that bounds the index, then a dispatch block that
    /// loads the table and branches: the ordinary switch.
    fn switch_blocks() -> Vec<Block> {
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        vec![guard, dispatch]
    }

    fn table(entries: &[u64]) -> Fixture {
        let mut memory = HashMap::new();
        for (index, target) in entries.iter().enumerate() {
            memory.insert(0x9000 + index as u64 * 8, *target);
        }
        Fixture {
            memory,
            code: (0x1000, 0x2000),
        }
    }

    #[test]
    fn a_bounded_dispatch_is_recovered_from_the_graph() {
        // Four entries at a stride of 8, bounded by `index < 4`: the
        // targets are an arithmetic progression, which the domain keeps.
        let image = table(&[0x1100, 0x1108, 0x1110, 0x1118]);
        let found = analyse(&image, &switch_blocks(), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].branch, 0x1010);
        assert_eq!(found.tables[0].targets, vec![0x1100, 0x1108, 0x1110, 0x1118]);
    }
    /// `cmp $48,%r8` records `old_r8 < 48` on the carry flag; the next
    /// op rewrites the slot in place (`add $16,%r8`). The predicate
    /// names the pre-write value, and the origin self-loop carries it
    /// to the edge as `new_r8 in [16, 63]`: deleting it (as a stale
    /// operand) leaves `Top`, and the dispatch refuses. This is the
    /// value-identity half of the `00190be9` defect: `CF = old_r8 <
    /// 64` before `r8 -= 64` must survive as `new_r8 in [-64, -1]`.
    /// Pre-fix this test refuses (`unknown_target`); post-fix it
    /// recovers entries 16..63.
    #[test]
    fn a_bound_survives_an_in_place_shift() {
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 48, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 16, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 2],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1020, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let found = analyse(&image, &[guard, dispatch, default], (0x1000, 0x2000));
        let expected: Vec<u64> = (0..48u64).map(|i| 0x1100 + (16 + i) * 8).collect();
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].targets, expected);
    }
    /// Widening past eight updates drops a still-moving value but
    /// keeps an unchanged guard predicate and origin link: the join
    /// rule, not a blank slate. Without this, a dispatch after a
    /// long loop loses the bound established before it.
    #[test]
    fn widening_keeps_stable_bound_metadata() {
        let slot = |space: &str, offset: u64| (space.to_string(), offset);
        let mut existing = State::default();
        existing.values.insert(slot("register", 0x0), Value::Const(7));
        existing.predicates.insert(
            slot("unique", 0x10),
            vec![(slot("register", 0x38), 4, false, false, 8, None, true, false)],
        );
        existing.origins.insert(
            slot("register", 0x40),
            (slot("register", 0x38), 0, None, 8),
        );
        let mut merged = existing.clone();
        merged
            .values
            .insert(slot("register", 0x0), Value::Const(8));
        let widened = widen_state(&existing, &merged);
        assert_eq!(widened.values.get(&slot("register", 0x0)), None);
        assert_eq!(
            widened.predicates.get(&slot("unique", 0x10)),
            existing.predicates.get(&slot("unique", 0x10))
        );
        assert_eq!(
            widened.origins.get(&slot("register", 0x40)),
            existing.origins.get(&slot("register", 0x40))
        );
    }
    /// `INT_SCARRY` over a bounded 64-bit interval plus a constant proves
    /// its own overflow status. Production shapes first: JL1's
    /// `SCARRY(R8, 32)` with `R8 in [-144,-52]` and JL2's `SCARRY(R8, 16)`
    /// with `R8 in [-112,-20]` cannot wrap (negative plus non-negative).
    #[test]
    fn scarry_interval_proofs() {
        let strided = |lo: i64, hi: i64| Value::Strided { base: 0, stride: 1, lo, hi, guarded: false };
        assert_eq!(scarry_value(&strided(-144, -52), &Value::Const(32), 8), Value::Const(0));
        assert_eq!(scarry_value(&strided(-112, -20), &Value::Const(16), 8), Value::Const(0));
        assert_eq!(scarry_value(&strided(-32, 31), &Value::Const(32), 8), Value::Const(0));
        assert_eq!(scarry_value(&strided(i64::MAX - 10, i64::MAX), &Value::Const(32), 8), Value::Top);
        assert_eq!(scarry_value(&strided(i64::MAX, i64::MAX), &Value::Const(1), 8), Value::Const(1));
        assert_eq!(scarry_value(&strided(-4, 4), &Value::Const(1), 8), Value::Const(0));
        // Narrow widths compare against the width's bounds, not i64
        // overflow: 8-bit 127 + 1 wraps, 100 + 27 fits, and a wide 127 + 1
        // fits.
        assert_eq!(scarry_value(&Value::Const(127), &Value::Const(1), 1), Value::Const(1));
        assert_eq!(scarry_value(&Value::Const(100), &Value::Const(27), 1), Value::Const(0));
        assert_eq!(scarry_value(&Value::Const(127), &Value::Const(1), 8), Value::Const(0));
        assert_eq!(scarry_value(&strided(-4, 4), &Value::Const(1), 1), Value::Top);
        assert_eq!(
            scarry_value(&Value::Strided { base: 8, stride: 8, lo: 0, hi: 4, guarded: true }, &Value::Const(1), 8),
            Value::Top
        );
    }
    /// `INT_SBORROW` mirrors with subtraction semantics: `x - 0` never
    /// overflows, same-signed operands never overflow, else the endpoints
    /// decide, and a single wrapping value proves overflow.
    #[test]
    fn sborrow_interval_proofs() {
        let strided = |lo: i64, hi: i64| Value::Strided { base: 0, stride: 1, lo, hi, guarded: false };
        assert_eq!(sborrow_value(&Value::Const(5), &Value::Const(0), 8), Value::Const(0));
        assert_eq!(sborrow_value(&Value::Const(0), &Value::Const(1), 8), Value::Const(0));
        assert_eq!(sborrow_value(&Value::Const(1u64 << 63), &Value::Const(1), 8), Value::Const(1));
        assert_eq!(sborrow_value(&strided(10, 20), &Value::Const(5), 8), Value::Const(0));
        assert_eq!(sborrow_value(&strided(-20, -10), &Value::Const((-5i64) as u64), 8), Value::Const(0));
        assert_eq!(sborrow_value(&strided(-32, 31), &Value::Const((-40i64) as u64), 8), Value::Const(0));
        assert_eq!(sborrow_value(&strided(i64::MIN, i64::MIN + 10), &Value::Const(20), 8), Value::Top);
        assert_eq!(sborrow_value(&strided(i64::MIN, i64::MIN), &Value::Const(1), 8), Value::Const(1));
        // Narrow widths compare against the width's bounds: 8-bit -128 - 1
        // wraps, 0 - 1 fits, 127 - -1 wraps.
        assert_eq!(sborrow_value(&Value::Const(0x80), &Value::Const(1), 1), Value::Const(1));
        assert_eq!(sborrow_value(&Value::Const(0), &Value::Const(1), 1), Value::Const(0));
        assert_eq!(sborrow_value(&Value::Const(127), &Value::Const(0xff), 1), Value::Const(1));
        assert_eq!(sborrow_value(&strided(-4, 4), &Value::Const(1), 1), Value::Top);
    }
    /// A signed upper bound on a strided value keeps the negative half:
    /// `R in [-32, 31]` with `R <_s 0` refines to `[-32, -1]`. The
    /// unsigned floor (`-off`) made every negative upper bound
    /// infeasible-skipped, so the transfer returned `None` and a `JL`
    /// refined nothing. The unsigned reading of the same shape still
    /// refuses: `[0, -1]` is empty.
    #[test]
    fn a_signed_upper_bound_keeps_the_negative_half() {
        let target = ("register".to_string(), 0x80u64);
        let values: std::collections::BTreeMap<Slot, Value> =
            std::collections::BTreeMap::from([(
                target.clone(),
                Value::Strided { base: 0, stride: 1, lo: -32, hi: 31, guarded: false },
            )]);
        assert_eq!(
            intersect_bound(&values, &target, 0, -1, i64::MIN, false, true),
            Some(Value::Strided { base: 0, stride: 1, lo: -32, hi: -1, guarded: false })
        );
        assert_eq!(
            intersect_bound(&values, &target, 0, -1, i64::MIN, false, false),
            None
        );
    }
    /// `JL` keeps its polarity through the flag combination when the
    /// carry side proves `OF = 0`: `sub $32` then `jl` on `R in [-32, 31]`
    /// refines the taken edge to `[-32, -1]` and the fallthrough to
    /// `[0, 31]` (via the negation). The old both-edges defense could not
    /// state a negative upper bound at all, leaving the fallthrough
    /// dispatch at the full `[-32, 31]` (64 targets instead of entries
    /// 32..63). The taken leg biases back (`+32`) and re-guards unsigned
    /// before its dispatch, the production shape: only a
    /// comparison-blessed bound drives a read.
    fn jl_blocks(proven_overflow: bool) -> Vec<Block> {
        // Proven overflow (`0x7fff... + 1` signed-overflows) makes the `JL`
        // taken edge mean `!SF`: the control case for the polarity gate.
        // The plain case adds zero, which never overflows.
        let (scarry_left, scarry_right) = if proven_overflow {
            (varnode("const", 0x7fffffffffffffff, 8), varnode("const", 1, 8))
        } else {
            (varnode("register", 0x38, 8), varnode("const", 0, 8))
        };
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 6],
        };
        let compare = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 32, 8)],
                    ),
                    op(
                        "INT_SCARRY",
                        Some(varnode("unique", 0x5000, 1)),
                        vec![scarry_left, scarry_right],
                    ),
                    op(
                        "INT_SLESS",
                        Some(varnode("unique", 0x5008, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 0, 8)],
                    ),
                    op(
                        "INT_NOTEQUAL",
                        Some(varnode("unique", 0x5010, 1)),
                        vec![varnode("unique", 0x5000, 1), varnode("unique", 0x5008, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1020, 8), varnode("unique", 0x5010, 1)],
                    ),
                ],
            )],
            successors: vec![2, 4],
        };
        // Both legs bias back (`+32`) and re-guard unsigned before
        // dispatching: only a comparison-blessed bound drives a read.
        // Arithmetic never blesses (a width laundered through arithmetic
        // must not drive a read), so the re-guard is the production
        // shape, not test scaffolding: real switches bound-check after
        // biasing.
        let rebless_at = |address: u64, target: u64, then0: usize| Block {
            instructions: vec![instruction(
                address,
                vec![
                    op(
                        "INT_ADD",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 32, 8)],
                    ),
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x18, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 32, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", target, 8), varnode("unique", 0x18, 1)],
                    ),
                ],
            )],
            successors: vec![then0, 6],
        };
        let dispatch = |address: u64| Block {
            instructions: vec![instruction(
                address,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1060, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        vec![
            guard,
            compare,
            rebless_at(0x1020, 0x1030, 3),
            dispatch(0x1030),
            rebless_at(0x1040, 0x1050, 5),
            dispatch(0x1050),
            default,
        ]
    }
    #[test]
    fn a_jl_combination_keeps_its_taken_edge_polarity() {
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &jl_blocks(false), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 2, "{found:?}");
        let taken = found.tables.iter().find(|t| t.branch == 0x1030).expect("taken dispatch");
        let fall = found.tables.iter().find(|t| t.branch == 0x1050).expect("fallthrough dispatch");
        let expected_taken: Vec<u64> = (0..32u64).map(|i| 0x1100 + i * 8).collect();
        let expected_fall: Vec<u64> = (32..64u64).map(|i| 0x1100 + i * 8).collect();
        assert_eq!(taken.targets, expected_taken);
        assert_eq!(fall.targets, expected_fall);
    }
    /// `JL` with proven overflow keeps the both-edges defense:
    /// `SCARRY(0x7fff...fff, 1)` is constant-true, so `SF != OF` means
    /// `!SF` and forwarding SF's bound to the taken edge would put
    /// entries 32..63 on the fallthrough. Gated, the fallthrough keeps
    /// the upper shape (`[-32, -1]`), biases back, re-guards, and reads
    /// entries 0..31 (exact -- truth there is `R < 0`). The taken leg
    /// reads the same entries 0..31, which is the defense's heuristic,
    /// NOT the truth (`R >= 0`, entries 32..63): a wrong-edge upper that
    /// decodes in-function is accepted, and no backstop refuses it.
    /// Pinned as the known OF=1 limitation, not as exactness.
    #[test]
    fn a_jl_with_proven_overflow_keeps_both_edges() {
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &jl_blocks(true), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 2, "{found:?}");
        let taken = found.tables.iter().find(|t| t.branch == 0x1030).expect("taken dispatch");
        let fall = found.tables.iter().find(|t| t.branch == 0x1050).expect("fallthrough dispatch");
        let expected: Vec<u64> = (0..32u64).map(|i| 0x1100 + i * 8).collect();
        assert_eq!(fall.targets, expected);
        assert_eq!(taken.targets, expected);
    }
    /// An unsigned loop-back through a single negation: `x -= 64` then
    /// `jnc` (taken means no borrow, `x >= 64` pre-write) refines the
    /// taken edge to `[0, 191]` from a `[0, 255]` entry, and the dispatch
    /// reads 192 entries. The both-edges defense puts the upper shape on
    /// the taken edge instead (`[-64, -1]`, unblessed), and the dispatch
    /// refuses. Production mirror of the `0x190b93/0x190b97` loop-back.
    /// Verifies in two stages: single-negate polarity (ii) without the
    /// holds fix (iii) still fails (taken gets the upper); both pass.
    fn negate_blocks() -> Vec<Block> {
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 256, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 3],
        };
        let main = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "BOOL_NEGATE",
                        Some(varnode("unique", 0x12, 1)),
                        vec![varnode("unique", 0x11, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1020, 8), varnode("unique", 0x12, 1)],
                    ),
                ],
            )],
            successors: vec![2, 3],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1020,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1030, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        vec![guard, main, dispatch, default]
    }
    #[test]
    fn a_negated_borrow_bounds_the_loop_back_edge() {
        let mut memory = HashMap::new();
        for index in 0..192u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &negate_blocks(), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].branch, 0x1020);
        let expected: Vec<u64> = (0..192u64).map(|i| 0x1100 + i * 8).collect();
        assert_eq!(found.tables[0].targets, expected);
    }
    /// An unsigned `jbe` shape through an OR combination: `x < 101`
    /// guards entry to `[0, 100]`, then `(x < 50) || (x == 0)` branches
    /// with the dispatch on the fallthrough. Fallthrough means both
    /// disjuncts are false, so the negated bound `[50, 100]` holds and
    /// the dispatch reads entries 50..100. The both-edges defense puts
    /// the upper shape on the fallthrough instead (`[0, 49]`).
    /// Production mirror of `0x190b57/0x190b5b`.
    fn or_blocks() -> Vec<Block> {
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 101, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 3],
        };
        let main = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 50, 8)],
                    ),
                    op(
                        "INT_EQUAL",
                        Some(varnode("unique", 0x12, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 0, 8)],
                    ),
                    op(
                        "BOOL_OR",
                        Some(varnode("unique", 0x13, 1)),
                        vec![varnode("unique", 0x11, 1), varnode("unique", 0x12, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1030, 8), varnode("unique", 0x13, 1)],
                    ),
                ],
            )],
            successors: vec![3, 2],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1020,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1030, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        vec![guard, main, dispatch, default]
    }
    #[test]
    fn an_or_fallthrough_bounds_both_disjuncts_false() {
        let mut memory = HashMap::new();
        for index in 0..101u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &or_blocks(), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].branch, 0x1020);
        let expected: Vec<u64> = (50..101u64).map(|i| 0x1100 + i * 8).collect();
        assert_eq!(found.tables[0].targets, expected);
    }
    /// OR-taken applies no child bound: a disjunction implies none, so
    /// the taken edge keeps the exit (here `Top`, which refuses) instead
    /// of the wrong-side upper the both-edges defense fabricates (here a
    /// 10-entry table of entries 0..9 that decodes and would be
    /// accepted). Fails pre-fix with that table present.
    #[test]
    fn or_taken_applies_no_child_bound() {
        let startup = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 10, 8)],
                    ),
                    op(
                        "INT_EQUAL",
                        Some(varnode("unique", 0x12, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 0, 8)],
                    ),
                    op(
                        "BOOL_OR",
                        Some(varnode("unique", 0x13, 1)),
                        vec![varnode("unique", 0x11, 1), varnode("unique", 0x12, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x13, 1)],
                    ),
                ],
            )],
            successors: vec![1, 2],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1020, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &[startup, dispatch, default], (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
        assert_eq!(found.reasons.get(&0x1010), Some(&RefusalKind::Unknown));
    }
    /// OR-fallthrough that drops a heuristic child refuses: an AND-merged
    /// `(R < 20)` (non-direct) has unknown polarity, so the fallthrough
    /// is under-refined by construction and a dispatch downstream of it
    /// is refused outright rather than materialised wide. Fails pre-fix
    /// with entries 20..100.
    #[test]
    fn or_fallthrough_ignores_nondirect_children() {
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 101, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 3],
        };
        let main = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 10, 8)],
                    ),
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x12, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 20, 8)],
                    ),
                    op(
                        "BOOL_AND",
                        Some(varnode("unique", 0x14, 1)),
                        vec![varnode("unique", 0x11, 1), varnode("unique", 0x12, 1)],
                    ),
                    op(
                        "INT_EQUAL",
                        Some(varnode("unique", 0x15, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 0, 8)],
                    ),
                    op(
                        "BOOL_OR",
                        Some(varnode("unique", 0x13, 1)),
                        vec![varnode("unique", 0x14, 1), varnode("unique", 0x15, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1030, 8), varnode("unique", 0x13, 1)],
                    ),
                ],
            )],
            successors: vec![3, 2],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1020,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1030, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let mut memory = HashMap::new();
        for index in 0..101u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &[guard, main, dispatch, default], (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
        assert_eq!(found.reasons.get(&0x1020), Some(&RefusalKind::Unknown));
    }
    /// OR-taken with a pre-guarded value refuses: the taken edge keeps
    /// the exit interval de-blessed (same interval, no guard provenance),
    /// so the forward read yields `Top`, and the Top-only backward slice
    /// is blocked on the uncertain edge rather than resurrecting the
    /// pre-OR guard. Fails pre-fix with a 16-entry table of entries
    /// 0..15 -- the wrong-side upper, blessed and accepted as exact.
    #[test]
    fn or_taken_with_preguarded_value_refuses() {
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "COPY",
                        Some(varnode("register", 0x39, 8)),
                        vec![varnode("register", 0x38, 8)],
                    ),
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x39, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 3],
        };
        let main = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 16, 8)],
                    ),
                    op(
                        "INT_EQUAL",
                        Some(varnode("unique", 0x12, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 0, 8)],
                    ),
                    op(
                        "BOOL_OR",
                        Some(varnode("unique", 0x13, 1)),
                        vec![varnode("unique", 0x11, 1), varnode("unique", 0x12, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1020, 8), varnode("unique", 0x13, 1)],
                    ),
                ],
            )],
            successors: vec![2, 3],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1020,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1030, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &[guard, main, dispatch, default], (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
        assert_eq!(found.reasons.get(&0x1020), Some(&RefusalKind::Unknown));
    }
    /// An unsigned lower bound states a complement the single interval
    /// cannot name when values straddle zero: negative-signed members
    /// are unsigned-large and satisfy `x >=_u n` too. Refuse there;
    /// refine where values are already non-negative.
    #[test]
    fn unsigned_lower_refuses_when_values_straddle_zero() {
        let target = ("register".to_string(), 0x80u64);
        let values: std::collections::BTreeMap<Slot, Value> =
            std::collections::BTreeMap::from([(
                target.clone(),
                Value::Strided { base: 0, stride: 1, lo: -10, hi: 100, guarded: false },
            )]);
        assert_eq!(intersect_bound(&values, &target, 0, i64::MIN, 50, true, false), None);
        let values: std::collections::BTreeMap<Slot, Value> =
            std::collections::BTreeMap::from([(
                target.clone(),
                Value::Strided { base: 0, stride: 1, lo: 10, hi: 100, guarded: true },
            )]);
        assert_eq!(
            intersect_bound(&values, &target, 0, i64::MIN, 50, true, false),
            Some(Value::Strided { base: 0, stride: 1, lo: 50, hi: 100, guarded: true })
        );
    }

    /// A `JL`-shaped fallthrough: the first bound takes `r8` into
    /// `[0, 31]` on the taken edge; an in-place shift moves it to
    /// `[-16, 15]`; a signed `< 0` test's *fallthrough* (the value is
    /// `>= 0`) recovers `[0, 15]`. Without lower-bound application
    /// the dispatch reads `[-16, 15]`, whose negative low end misses
    /// the table base and refuses. The image holds 17 valid entries
    /// so the scan cannot mask the difference.
    #[test]
    fn a_fallthrough_lower_bound_recovers_the_dispatch() {
        let mut memory = HashMap::new();
        for index in 0..17u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let bound = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 32, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 3],
        };
        let shift = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 16, 8)],
                    ),
                    op(
                        "INT_SLESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 0, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1030, 8), varnode("unique", 0x11, 1)],
                    ),
                ],
            )],
            successors: vec![3, 2],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1020,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1030, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let found = analyse(&image, &[bound, shift, dispatch, default], (0x1000, 0x2000));
        let expected: Vec<u64> = (0..16u64).map(|i| 0x1100 + i * 8).collect();
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].targets, expected);
    }

    /// `p = (x < 64)` is recorded, `x -= 64` stamps it, then `q = (x
    /// < 4)` is recorded on the rewritten value. Branching on `q`
    /// must use `q` untranslated (`[0, 3]`): a slot-wide origin
    /// would translate `q` through the loop too, mistargeting
    /// `[-64, -61]`. Branching on `p` must still translate
    /// (`[-64, -1]`). Per-predicate stamps keep the two apart.
    #[test]
    fn a_post_write_bound_ignores_an_earlier_rewrite() {
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        // Guard block records p, rewrites, records q, branches on q.
        let guard_q = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x11, 1)],
                    ),
                ],
            )],
            successors: vec![1, 2],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1020, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let found = analyse(&image, &[guard_q, dispatch, default], (0x1000, 0x2000));
        // q's `[0, 3]` on the current value: entries 0..3. A shared
        // self-loop would read `[-64, -61]` and refuse.
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(
            found.tables[0].targets,
            vec![0x1100, 0x1108, 0x1110, 0x1118]
        );
    }

    /// `y = x` after `x -= 64` copies the post-write value, but the
    /// origin link is `y -> (x, 0)` while `x`'s recorded bound is the
    /// stamped pre-write one. Flattening the copy through the stamp
    /// claims `y in [-64, -61]` when `x == y` post-write; the
    /// dispatch through `y` must read `q`'s `[0, 3]`. Stamped
    /// entries stay on their own slot and never propagate to
    /// aliases.
    #[test]
    fn a_copy_after_a_rewrite_uses_the_current_bound() {
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 64, 8)],
                    ),
                    op(
                        "COPY",
                        Some(varnode("register", 0x40, 8)),
                        vec![varnode("register", 0x38, 8)],
                    ),
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x11, 1)],
                    ),
                ],
            )],
            successors: vec![1, 2],
        };
        // Dispatch reads through the copy `y` (register 0x40).
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x40, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1020, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let found = analyse(&image, &[guard, dispatch, default], (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(
            found.tables[0].targets,
            vec![0x1100, 0x1108, 0x1110, 0x1118]
        );
    }
    /// `p = (x < 4)` is recorded, `x += 16` stamps it, then `q = (x
    /// < 4)` is recorded on the rewritten value. Branching on `p ||
    /// q` admits a disjunction the upper-bound tuple cannot name
    /// (`[0,3]` or `[16,19]`): merging to the looser unstamped bound
    /// would present half the truth as the bound and recover only
    /// entries 0..3. The whole bound is discarded instead, and the
    /// dispatch refuses.
    #[test]
    fn a_stamp_conflict_in_a_combination_refuses() {
        let mut memory = HashMap::new();
        for index in [0u64, 1, 2, 3, 16, 17, 18, 19] {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("register", 0x38, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 16, 8)],
                    ),
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x11, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "BOOL_OR",
                        Some(varnode("unique", 0x12, 1)),
                        vec![varnode("unique", 0x10, 1), varnode("unique", 0x11, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x12, 1)],
                    ),
                ],
            )],
            successors: vec![1, 2],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1020, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let found = analyse(&image, &[guard, dispatch, default], (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
        assert_eq!(found.refusals.unknown_target, 1);
    }
    /// Alias before rewrite: `y = x` copies the current value, `p =
    /// (y < 4)` is recorded, then `y -= 16` stamps `p`. Branching on
    /// `p` with the dispatch reading `table[x]` must use `[0, 3]`:
    /// `x` still holds the value `p` constrained, and the live link
    /// `y -> (x, 0)` must not re-target `x` through the stamp
    /// (`(x, -16)` would read entries 16..19).
    #[test]
    fn an_alias_before_a_rewrite_keeps_the_compared_bound() {
        let mut memory = HashMap::new();
        for index in 0..64u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "COPY",
                        Some(varnode("register", 0x40, 8)),
                        vec![varnode("register", 0x38, 8)],
                    ),
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x40, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x40, 8)),
                        vec![varnode("register", 0x40, 8), varnode("const", 16, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![1, 2],
        };
        // Dispatch reads through `x` (register 0x38), which the
        // rewrite never touched.
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        let default = Block {
            instructions: vec![instruction(0x1020, vec![op("BRANCH", None, vec![])])],
            successors: vec![],
        };
        let found = analyse(&image, &[guard, dispatch, default], (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(
            found.tables[0].targets,
            vec![0x1100, 0x1108, 0x1110, 0x1118]
        );
    }



    /// (No shifted-guard unit regression: the two synthetic attempts were
    /// void -- the first never reached the filter, the second's image made
    /// refusal semantically correct. The filter's evidence is the
    /// import-level negative control on real libc p-code, recorded in
    /// STATUS: filter disabled reproduces the exact 18 foreign targets.)

    /// Preheader defines the index; header and latch shuttle it back and
    /// forth without redefining it. The latch's missing slot is bottom
    /// until its transfer runs -- not live-in -- so the dominating
    /// definition stays `One` however the blocks are ordered.
    #[test]
    fn a_latch_without_a_definition_keeps_the_dominator() {
        for order in [false, true] {
            let index = varnode("register", 0x38, 8);
            let preheader = Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![op(
                        "COPY",
                        Some(index.clone()),
                        vec![varnode("register", 0x40, 8)],
                    )],
                )],
                successors: vec![1],
            };
            let header = Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![index.clone(), varnode("const", 4, 8)],
                    )],
                )],
                successors: vec![2, 1],
            };
            let latch = Block {
                instructions: vec![instruction(
                    0x1020,
                    vec![op(
                        "COPY",
                        Some(varnode("unique", 0x20, 1)),
                        vec![varnode("const", 1, 1)],
                    )],
                )],
                successors: vec![1],
            };
            // Swapped order puts the latch first: its missing slot must
            // still read bottom, not live-in, or the dominator merges to
            // `Many` before the preheader is ever processed.
            // Swapped order puts the latch first, but the external entry
            // is still the preheader (now index 2): it is passed
            // explicitly, so position cannot move the outside boundary.
            // The latch's missing slot reads bottom until its transfer
            // runs, not live-in, or the dominator merges to `Many` before
            // the preheader is ever processed.
            let (blocks, header_at, pre_at, entries) = if order {
                // Latch first, header second, preheader third: the latch
                // still flows into the header (0->1), the header into the
                // latch and itself (1->0, 1->1), and the preheader into
                // the header (2->1). The latch bypasses nothing: the
                // header's inputs are the latch, itself, and the
                // preheader, so the dominator must survive.
                let mut blocks = vec![latch, header, preheader];
                blocks[0].successors = vec![1];
                blocks[1].successors = vec![0, 1];
                blocks[2].successors = vec![1];
                (blocks, 1, 2, vec![2])
            } else {
                (vec![preheader, header, latch], 1, 0, vec![0])
            };
            let defs = DefIndex::build_with_entries(&blocks, &entries);
            let reached = defs.reaching_def(&blocks, header_at, &slot(&index), (0, 0));
            assert!(
                matches!(reached, Reach::One(pos) if pos.0 == pre_at),
                "order {order}: dominated def went {reached:?}"
            );
        }
    }






    /// One entry block reads the index, writes it, then loops to itself.
    /// At its own entry the reaching def is `Many` -- the live-in read
    /// plus the loop-carried write -- not `One` of the later write.
    #[test]
    fn an_entry_self_loop_reading_and_writing_goes_many() {
        let index = varnode("register", 0x38, 8);
        let block = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![index.clone(), varnode("const", 4, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(index.clone()),
                        vec![index.clone(), varnode("const", 1, 8)],
                    ),
                ],
            )],
            successors: vec![0],
        };
        let blocks = vec![block];
        let defs = DefIndex::build(&blocks);
        let reached = defs.reaching_def(&blocks, 0, &slot(&index), (0, 0));
        assert!(
            matches!(reached, Reach::Many),
            "entry self-loop went {reached:?}"
        );
    }

    /// B0 defines the index; B1 reads it, redefines it, and loops to
    /// itself. At B1's entry the reaching def must be `Many` -- B0's
    /// definition plus B1's own previous-iteration definition. A merge
    /// that drops the computed self-edge would keep `One(B0)` and let the
    /// slice substitute the wrong value.
    #[test]
    fn a_self_loop_redefinition_merges_to_many() {
        let index = varnode("register", 0x38, 8);
        let entry = Block {
            instructions: vec![instruction(
                0x1000,
                vec![op(
                    "COPY",
                    Some(index.clone()),
                    vec![varnode("register", 0x40, 8)],
                )],
            )],
            successors: vec![1],
        };
        let header = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![index.clone(), varnode("const", 4, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(index.clone()),
                        vec![index.clone(), varnode("const", 1, 8)],
                    ),
                ],
            )],
            successors: vec![1],
        };
        let blocks = vec![entry, header];
        let defs = DefIndex::build(&blocks);
        let reached = defs.reaching_def(&blocks, 1, &slot(&index), (0, 0));
        assert!(
            matches!(reached, Reach::Many),
            "redefined loop went {reached:?}"
        );
    }
    /// Entry splits to two arms that join before the dispatch: the left
    /// arm defines the index, the right arm never names it. At the join
    /// the reaching def must be `Many` -- the left definition plus the
    /// right's live-in -- both before the fix (original code) and after:
    /// seeding only entry-named slots would keep `One(left)` and lose the
    /// live-in path.
    #[test]
    fn a_diamond_with_an_unnamed_arm_merges_to_many() {
        let index = varnode("register", 0x38, 8);
        let entry = Block {
            instructions: vec![instruction(
                0x1000,
                vec![op(
                    "CBRANCH",
                    None,
                    vec![varnode("ram", 0x1010, 8), varnode("const", 1, 1)],
                )],
            )],
            successors: vec![1, 2],
        };
        let left = Block {
            instructions: vec![instruction(
                0x1010,
                vec![op(
                    "COPY",
                    Some(index.clone()),
                    vec![varnode("register", 0x40, 8)],
                )],
            )],
            successors: vec![3],
        };
        let right = Block {
            instructions: vec![instruction(
                0x1020,
                vec![op(
                    "COPY",
                    Some(varnode("unique", 0x20, 1)),
                    vec![varnode("const", 1, 1)],
                )],
            )],
            successors: vec![3],
        };
        let join = Block {
            instructions: vec![instruction(
                0x1030,
                vec![op(
                    "INT_LESS",
                    Some(varnode("unique", 0x10, 1)),
                    vec![index.clone(), varnode("const", 4, 8)],
                )],
            )],
            successors: vec![],
        };
        let blocks = vec![entry, left, right, join];
        let defs = DefIndex::build(&blocks);
        let reached = defs.reaching_def(&blocks, 3, &slot(&index), (0, 0));
        assert!(
            matches!(reached, Reach::Many),
            "diamond went {reached:?}"
        );
    }

    /// Entry spans a two-block cycle without defining the index: both
    /// blocks loop to each other and neither writes it. The join reads
    /// live-in on every path -- not bottom, and not a definition that
    /// does not exist. `preds.all(pred == index)`-style entry checks
    /// miss the external source on cyclic entries; the universe seed
    /// covers it.
    #[test]
    fn a_cyclic_entry_without_a_definition_stays_live_in() {
        let index = varnode("register", 0x38, 8);
        let first = Block {
            instructions: vec![instruction(
                0x1000,
                vec![op(
                    "INT_LESS",
                    Some(varnode("unique", 0x10, 1)),
                    vec![index.clone(), varnode("const", 4, 8)],
                )],
            )],
            successors: vec![1],
        };
        let second = Block {
            instructions: vec![instruction(
                0x1010,
                vec![op(
                    "CBRANCH",
                    None,
                    vec![varnode("ram", 0x1020, 8), varnode("unique", 0x10, 1)],
                )],
            )],
            successors: vec![0],
        };
        let blocks = vec![first, second];
        let defs = DefIndex::build(&blocks);
        let reached = defs.reaching_def(&blocks, 0, &slot(&index), (0, 0));
        assert!(
            matches!(reached, Reach::LiveIn),
            "cyclic entry went {reached:?}"
        );
    }
    /// B0 reads the index, B1 writes it and loops back: B0's entry must
    /// be `Many` -- the external input plus B1's loop-carried definition.
    /// Seeding by predecessor count finds no root in the cycle and would
    /// merge `One(B1)` alone, letting the slice substitute the wrong
    /// value for the external input's path.
    #[test]
    fn a_cyclic_entry_read_then_written_goes_many() {
        let index = varnode("register", 0x38, 8);
        let first = Block {
            instructions: vec![instruction(
                0x1000,
                vec![op(
                    "INT_LESS",
                    Some(varnode("unique", 0x10, 1)),
                    vec![index.clone(), varnode("const", 4, 8)],
                )],
            )],
            successors: vec![1],
        };
        let second = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1020, 8), varnode("unique", 0x10, 1)],
                    ),
                    op(
                        "COPY",
                        Some(index.clone()),
                        vec![varnode("register", 0x40, 8)],
                    ),
                ],
            )],
            successors: vec![0],
        };
        let blocks = vec![first, second];
        let defs = DefIndex::build_with_entries(&blocks, &[0]);
        let reached = defs.reaching_def(&blocks, 0, &slot(&index), (0, 0));
        assert!(
            matches!(reached, Reach::Many),
            "cyclic read-write went {reached:?}"
        );
    }
    /// B0 reads the index and cannot reach B1; B1 writes it, then jumps
    /// to B0. With explicit seeds `[0,1]` B0's entry must be `Many` --
    /// the external input plus B1's definition. With seeds narrowed to
    /// `[1]` it must be `One(B1)`, reproducing the rejected SCC boundary
    /// that seeds graph components instead of the caller's outside
    /// knowledge. The cyclic B0<->B1 test cannot distinguish the two:
    /// this acyclic form can, because only the seed set places live-in
    /// at B0.
    #[test]
    fn an_acyclic_backedge_needs_explicit_seeds() {
        let index = varnode("register", 0x38, 8);
        let first = Block {
            instructions: vec![instruction(
                0x1000,
                vec![op(
                    "INT_LESS",
                    Some(varnode("unique", 0x10, 1)),
                    vec![index.clone(), varnode("const", 4, 8)],
                )],
            )],
            successors: vec![],
        };
        let second = Block {
            instructions: vec![instruction(
                0x1010,
                vec![op(
                    "COPY",
                    Some(index.clone()),
                    vec![varnode("register", 0x40, 8)],
                )],
            )],
            successors: vec![0],
        };
        let blocks = vec![first, second];
        let defs = DefIndex::build_with_entries(&blocks, &[0, 1]);
        let reached = defs.reaching_def(&blocks, 0, &slot(&index), (0, 0));
        assert!(
            matches!(reached, Reach::Many),
            "seeded acyclic entry went {reached:?}"
        );
        let defs = DefIndex::build_with_entries(&blocks, &[1]);
        let reached = defs.reaching_def(&blocks, 0, &slot(&index), (0, 0));
        assert!(
            matches!(reached, Reach::One((1, _, _))),
            "narrowed seeds went {reached:?}"
        );
    }





    /// `cmp $8,%r8; cmp $4,%rcx` combined into one flag by BOOL_AND, then
    /// `ja default` -- a bound on a different variable ANDed with the index
    /// bound. The dispatch reads the index; a guard that kept only the first
    /// comparison's bound dropped the one the dispatch needs.
    fn and_guard_blocks() -> Vec<Block> {
        let guard = Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    // A bound on a different variable, combined into the flag.
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x40, 8), varnode("const", 8, 8)],
                    ),
                    // The index bound the dispatch needs.
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x18, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "BOOL_AND",
                        Some(varnode("unique", 0x20, 1)),
                        vec![varnode("unique", 0x10, 1), varnode("unique", 0x18, 1)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x20, 1)],
                    ),
                ],
            )],
            successors: vec![1],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        vec![guard, dispatch]
    }

    #[test]
    fn a_dispatch_no_comparison_bounds_is_refused() {
        let image = table(&[0x1100, 0x1108, 0x1110, 0x1118]);
        let mut blocks = switch_blocks();
        // Remove the guard's comparison: nothing states the range, and an
        // absolute table's neighbours are valid code, so no scan can bound
        // it soundly.
        blocks[0].instructions[0].ops.remove(0);
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert!(found.tables.is_empty());
        assert_eq!(found.refusals.unknown_target, 1);
    }


    #[test]
    fn a_target_outside_the_function_is_refused() {
        // The bound says four cases but the table runs into other data.
        let image = table(&[0x1100, 0x1108, 0x1110, 0x9999]);
        let found = analyse(&image, &switch_blocks(), (0x1000, 0x2000));
        assert!(found.tables.is_empty());
        assert_eq!(found.refusals.outside_function, 1);
    }

    #[test]
    fn one_repeated_target_is_not_a_table() {
        let image = table(&[0x1100, 0x1100, 0x1100, 0x1100]);
        let found = analyse(&image, &switch_blocks(), (0x1000, 0x2000));
        assert!(found.tables.is_empty());
        assert_eq!(found.refusals.too_few_targets, 1);
    }

    /// `movzbl %cl, %ecx; cmp $4, %ecx; jae default; jmp *table(,%rcx,8)` --
    /// the index is a zero-extended byte. The compare is what bounds it;
    /// the byte's width alone only says `0..=255`, which is not a guard.
    fn zext_switch_blocks(with_guard: bool) -> Vec<Block> {
        let mut guard_ops = vec![op(
            "INT_ZEXT",
            Some(varnode("register", 0x38, 8)),
            vec![varnode("unique", 0x40, 1)],
        )];
        if with_guard {
            guard_ops.push(op(
                "INT_LESS",
                Some(varnode("unique", 0x10, 1)),
                vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
            ));
            guard_ops.push(op(
                "CBRANCH",
                None,
                vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
            ));
        }
        let guard = Block {
            instructions: vec![instruction(0x1000, guard_ops)],
            successors: vec![1],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        vec![guard, dispatch]
    }

    #[test]
    fn a_zero_extended_index_without_a_guard_is_refused() {
        // `movzbl` says the index is a byte, not that the table is 256
        // entries. The table here *has* 256 readable entries, so a read on
        // the width bound alone would recover a bogus 256-target table --
        // the refusal is what proves the bound was not treated as a guard.
        let entries: Vec<u64> = (0..256u64).map(|i| 0x1100 + i * 8).collect();
        let image = table(&entries);
        let found = analyse(&image, &zext_switch_blocks(false), (0x1000, 0x2000));
        assert!(found.tables.is_empty());
        assert_eq!(found.refusals.unknown_target, 1);
    }

    #[test]
    fn a_zero_extended_index_with_a_guard_is_recovered() {
        // The compare narrows the byte's width bound into a stated range,
        // which is a guard the table read can stand on.
        let image = table(&[0x1100, 0x1108, 0x1110, 0x1118]);
        let found = analyse(&image, &zext_switch_blocks(true), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].targets, vec![0x1100, 0x1108, 0x1110, 0x1118]);
    }

    /// `movzbl 0x1(%r12),%r15d; lea -0x20(%r15),%eax; cmp $0x5a,%al; jbe
    /// dispatch` then `movzbl %r15b,%eax; sub $0x20; movzbl jt(,%rax),%eax;
    /// movslq step(,%rax,4),%rdx; add base,%rdx; jmp *%rdx` -- vfprintf's
    /// two-level dispatch. The bound is on `%al`, three p-code ops and a
    /// `unique` temporary away from `r15`, and the dispatch re-derives the
    /// index from `r15b` in a different block.
    fn vfprintf_blocks() -> Vec<Block> {
        let guard = Block {
            instructions: vec![
                // r15d = zext(load) -- the byte is unknown, so r15 is the
                // width bound [0,255] unguarded.
                instruction(
                    0x1000,
                    vec![
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x100, 1)),
                            vec![varnode("const", 0x1b1, 4), varnode("const", 0xdead, 8)],
                        ),
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0xb8, 4)),
                            vec![varnode("unique", 0x100, 1)],
                        ),
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0xb8, 8)),
                            vec![varnode("register", 0xb8, 4)],
                        ),
                    ],
                ),
                // eax = subpiece(r15 - 0x20, 4); al < 4; jbe dispatch.
                instruction(
                    0x1010,
                    vec![
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x200, 8)),
                            vec![varnode("register", 0xb8, 8), varnode("const", 0xffffffffffffffe0, 8)],
                        ),
                        op(
                            "SUBPIECE",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("unique", 0x200, 8), varnode("const", 0, 4)],
                        ),
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x0, 1), varnode("const", 4, 1)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1020, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                ),
            ],
            successors: vec![1],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1020,
                vec![
                    // eax = zext(r15b); eax = eax - 0x20.
                    op(
                        "INT_ZEXT",
                        Some(varnode("register", 0x0, 4)),
                        vec![varnode("register", 0xb8, 1)],
                    ),
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x0, 4)),
                        vec![varnode("register", 0x0, 4), varnode("const", 0x20, 4)],
                    ),
                    // eax = zext(jt[eax]) -- the class byte.
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x300, 8)),
                        vec![varnode("const", 0x9000, 8), varnode("register", 0x0, 4)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x310, 1)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x300, 8)],
                    ),
                    op(
                        "INT_ZEXT",
                        Some(varnode("register", 0x0, 4)),
                        vec![varnode("unique", 0x310, 1)],
                    ),
                    // rdx = sext(step[eax*4]); rdx += base; jmp *rdx.
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x400, 8)),
                        vec![varnode("register", 0x0, 4), varnode("const", 4, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x408, 8)),
                        vec![varnode("const", 0x9100, 8), varnode("unique", 0x400, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x410, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x408, 8)],
                    ),
                    op(
                        "INT_SEXT",
                        Some(varnode("register", 0x10, 8)),
                        vec![varnode("unique", 0x410, 4)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("register", 0x10, 8)),
                        vec![varnode("register", 0x10, 8), varnode("const", 0x1400, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("register", 0x10, 8)]),
                ],
            )],
            successors: vec![],
        };
        vec![guard, dispatch]
    }

    #[test]
    fn a_bound_reaches_the_origin_through_a_unique_temporary() {
        // The class bytes 0,1,2,3 index a four-entry offset table; the
        // bound on %al has to reach r15 through the lea's unique temporary
        // and the subpiece, or the first table read is unguarded.
        let mut memory = HashMap::new();
        for (index, class) in [0u64, 1, 2, 3].iter().enumerate() {
            memory.insert(0x9000 + index as u64, *class);
        }
        for (index, offset) in [0x100u64, 0x108, 0x110, 0x118].iter().enumerate() {
            memory.insert(0x9100 + index as u64 * 4, *offset);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &vfprintf_blocks(), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(
            found.tables[0].targets,
            vec![0x1500, 0x1508, 0x1510, 0x1518]
        );
    }

    #[test]
    fn an_overwritten_slot_drops_its_origin() {
        // `eax = r15 - 0x20` links eax to r15; `mov (%rsi),%eax` then
        // overwrites eax with a value that has nothing to do with r15. A
        // compare on %al must not push a bound onto r15 through the stale
        // link -- if it does, the dispatch below resolves a bogus table.
        let mut memory = HashMap::new();
        for index in 0..4u64 {
            memory.insert(0x9000 + (0x20 + index) * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let blocks = vec![
            Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![
                        // r15 = zext(load): [0,255] unguarded, so the
                        // usable check accepts it as an origin target.
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x100, 1)),
                            vec![varnode("const", 0x1b1, 4), varnode("const", 0xbeef, 8)],
                        ),
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0xb8, 4)),
                            vec![varnode("unique", 0x100, 1)],
                        ),
                        // eax = r15 - 0x20: origins[eax] = (r15, -0x20).
                        op(
                            "INT_SUB",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("register", 0xb8, 4), varnode("const", 0x20, 4)],
                        ),
                        // eax = load(...): the stale link must die here.
                        op(
                            "LOAD",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("const", 0x1b1, 4), varnode("const", 0xdead, 8)],
                        ),
                        // al < 4; jbe dispatch.
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x0, 1), varnode("const", 4, 1)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                )],
                successors: vec![1],
            },
            Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![
                        // jmp *(0x9000 + r15*8): resolves only if the stale
                        // bound reached r15.
                        op(
                            "INT_MULT",
                            Some(varnode("unique", 0x20, 8)),
                            vec![varnode("register", 0xb8, 8), varnode("const", 8, 8)],
                        ),
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x28, 8)),
                            vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                        ),
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x30, 8)),
                            vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                        ),
                        op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                    ],
                )],
                successors: vec![],
            },
        ];
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
        assert_eq!(found.refusals.unknown_target, 1);
    }

    #[test]
    fn an_in_place_op_with_no_prior_origin_is_not_its_own_origin() {
        // `movzbl (%rdi),%eax; sub $0x20,%eax; cmp $3,%eax` -- the zext
        // leaves eax with no origin, so the in-place sub must not record
        // `eax = eax - 0x20`: a bound on the compared eax is a bound on
        // eax, not on eax shifted back. With the self-link the compare
        // pushes [0x20,0x23] and the table reads 0x20 entries too deep;
        // without it the bound stays on eax and the dispatch resolves the
        // four real entries.
        let mut memory = HashMap::new();
        for index in 0..4u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        // The wrong bound reads here: entries the self-link would claim.
        for index in 0..4u64 {
            memory.insert(0x9000 + (0x20 + index) * 8, 0x1200 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let blocks = vec![
            Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![
                        // eax = zext(load): [0,255] unguarded, no origin.
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x100, 1)),
                            vec![varnode("const", 0x1b1, 4), varnode("const", 0xbeef, 8)],
                        ),
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("unique", 0x100, 1)],
                        ),
                        // eax = eax - 0x20, in place: no origin must be
                        // recorded.
                        op(
                            "INT_SUB",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("register", 0x0, 4), varnode("const", 0x20, 4)],
                        ),
                        // eax < 4; jbe dispatch.
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x0, 4), varnode("const", 4, 4)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                )],
                successors: vec![1],
            },
            Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![
                        // jmp *(0x9000 + eax*8): the bound on eax is [0,3],
                        // so the four entries at 0x9000 are the table. A
                        // self-link would read the 0x9100-range entries
                        // instead.
                        op(
                            "INT_MULT",
                            Some(varnode("unique", 0x20, 8)),
                            vec![varnode("register", 0x0, 8), varnode("const", 8, 8)],
                        ),
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x28, 8)),
                            vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                        ),
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x30, 8)),
                            vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                        ),
                        op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                    ],
                )],
                successors: vec![],
            },
        ];
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        // The bound on eax is [0,3]: the four entries at 0x9000 are the
        // table, and a self-link would read the 0x9100-range entries.
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(
            found.tables[0].targets,
            vec![0x1100, 0x1108, 0x1110, 0x1118]
        );
    }

    #[test]
    fn a_guarded_bound_shifted_below_zero_is_refused() {
        // `cmp $0x20,%r8; jbe` states only `hi`; the `lo: 0` floor is the
        // fresh-bound assumption. `sub $0x10,%r8` then shifts it to
        // [-0x10, 0xf] -- and at 0x190114 that read the tail of the
        // preceding table as this one's head, one target landing
        // mid-instruction. A guarded index-space value shifted below zero
        // drops its guard: no compiler indexes a table negatively.
        let mut memory = HashMap::new();
        // The over-read the old code claimed: entries at 0x8fc0..0x907c.
        for index in -0x10i64..0x10 {
            memory.insert(
                (0x9000i64 + index * 4) as u64,
                (0x1100 + index * 8) as u64,
            );
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let blocks = vec![
            Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![
                        // r8 < 0x20; jbe dispatch.
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x40, 8), varnode("const", 0x20, 8)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                )],
                successors: vec![1],
            },
            Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![
                        // r8 -= 0x10 in place: [0,0x1f] -> [-0x10,0xf].
                        op(
                            "INT_SUB",
                            Some(varnode("register", 0x40, 8)),
                            vec![varnode("register", 0x40, 8), varnode("const", 0x10, 8)],
                        ),
                        // jmp *(0x9000 + r8*4).
                        op(
                            "INT_MULT",
                            Some(varnode("unique", 0x20, 8)),
                            vec![varnode("register", 0x40, 8), varnode("const", 4, 8)],
                        ),
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x28, 8)),
                            vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                        ),
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x30, 8)),
                            vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                        ),
                        op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                    ],
                )],
                successors: vec![],
            },
        ];
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
        assert_eq!(found.refusals.unknown_target, 1);
    }

    #[test]
    fn a_narrow_negative_immediate_shifts_the_bound_down() {
        // `add $-0x20,%eax` arrives as `0xffffffe0:4`; the value path must
        // shift by -0x20 the way the origin arm does, not by +4294967264.
        // Same shape as the in-place test, through INT_ADD.
        let mut memory = HashMap::new();
        for index in 0..4u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let blocks = vec![
            Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![
                        // eax = zext(load): [0,255] unguarded, no origin.
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x100, 1)),
                            vec![varnode("const", 0x1b1, 4), varnode("const", 0xbeef, 8)],
                        ),
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("unique", 0x100, 1)],
                        ),
                        // eax = eax + 0xffffffe0 (i.e. -0x20), in place.
                        op(
                            "INT_ADD",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("register", 0x0, 4), varnode("const", 0xffffffe0, 4)],
                        ),
                        // eax < 4; jbe dispatch.
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x0, 4), varnode("const", 4, 4)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                )],
                successors: vec![1],
            },
            Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![
                        op(
                            "INT_MULT",
                            Some(varnode("unique", 0x20, 8)),
                            vec![varnode("register", 0x0, 8), varnode("const", 8, 8)],
                        ),
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x28, 8)),
                            vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                        ),
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x30, 8)),
                            vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                        ),
                        op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                    ],
                )],
                successors: vec![],
            },
        ];
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(
            found.tables[0].targets,
            vec![0x1100, 0x1108, 0x1110, 0x1118]
        );
    }

    #[test]
    fn an_overwritten_flag_drops_its_comparison() {
        // `cmp $4,%al` records a bound keyed to the flag slot; `add
        // %rbx,%rax` rewrites that slot without clearing it, so the `jbe`
        // below would otherwise apply `al < 4` to an unrelated test and
        // invent a guarded bound.
        let mut memory = HashMap::new();
        for index in 0..4u64 {
            memory.insert(0x9000 + index * 8, 0x1100 + index * 8);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let blocks = vec![
            Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![
                        // al < 4: comparisons[flag] = (rax, 4, ...).
                        op(
                            "INT_LESS",
                            Some(varnode("register", 0x500, 1)),
                            vec![varnode("register", 0x0, 1), varnode("const", 4, 1)],
                        ),
                        // add %rbx,%rax rewrites the flag slot: the stale
                        // comparison must die here.
                        op(
                            "INT_ADD",
                            Some(varnode("register", 0x500, 1)),
                            vec![varnode("register", 0x0, 8), varnode("register", 0x18, 8)],
                        ),
                        // jbe dispatch reads the flag slot.
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1010, 8), varnode("register", 0x500, 1)],
                        ),
                    ],
                )],
                successors: vec![1],
            },
            Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![
                        // jmp *(0x9000 + rax*8): resolves only if the stale
                        // bound reached rax.
                        op(
                            "INT_MULT",
                            Some(varnode("unique", 0x20, 8)),
                            vec![varnode("register", 0x0, 8), varnode("const", 8, 8)],
                        ),
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x28, 8)),
                            vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                        ),
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x30, 8)),
                            vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                        ),
                        op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                    ],
                )],
                successors: vec![],
            },
        ];
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
        assert_eq!(found.refusals.unknown_target, 1);
    }

    #[test]
    fn a_function_with_no_indirect_branch_answers_nothing() {
        let image = table(&[]);
        let blocks = vec![Block {
            instructions: vec![instruction(0x1000, vec![op("COPY", None, vec![])])],
            successors: vec![],
        }];
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert!(found.tables.is_empty());
        assert_eq!(found.refusals, Refusals::default());
    }
    /// `r15 = zext(load); eax = subpiece(r15 - 0x20); r11 = zext(eax); cmp
    /// $0x5a,%al; jbe dispatch` then `jmp *(0x9000 + r11*8)` -- the compared
    /// slot is `al`, and `r11` is a truncation of the same origin (`r15 -
    /// 0x20`). The bound on `al` reaches `r11` only if the origin walk
    /// applies it to a slot whose link crossed a narrowing.
    fn narrow_reached_blocks() -> Vec<Block> {
        let guard = Block {
            instructions: vec![
                instruction(
                    0x1000,
                    vec![
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x100, 1)),
                            vec![varnode("const", 0x1b1, 4), varnode("const", 0xdead, 8)],
                        ),
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0xb8, 4)),
                            vec![varnode("unique", 0x100, 1)],
                        ),
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0xb8, 8)),
                            vec![varnode("register", 0xb8, 4)],
                        ),
                    ],
                ),
                instruction(
                    0x1010,
                    vec![
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x200, 8)),
                            vec![varnode("register", 0xb8, 8), varnode("const", 0xffffffffffffffe0, 8)],
                        ),
                        op(
                            "SUBPIECE",
                            Some(varnode("register", 0x0, 4)),
                            vec![varnode("unique", 0x200, 8), varnode("const", 0, 4)],
                        ),
                        // r11 = zext(eax): a truncation of the same origin.
                        op(
                            "INT_ZEXT",
                            Some(varnode("register", 0x58, 8)),
                            vec![varnode("register", 0x0, 4)],
                        ),
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x0, 1), varnode("const", 0x5b, 1)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1020, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                ),
            ],
            successors: vec![1],
        };
        let dispatch = Block {
            instructions: vec![instruction(
                0x1020,
                vec![
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x58, 8), varnode("const", 8, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 8)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                ],
            )],
            successors: vec![],
        };
        vec![guard, dispatch]
    }

    #[test]
    fn a_bound_reaches_a_truncated_slot_on_the_same_origin() {
        // The bound on `al` is [0,0x5a]; `r11 = zext(eax)` is a 4-byte piece
        // of `r15 - 0x20`, and `0x5a` fits the piece, so `r11` is bounded
        // [0,0x5a] and the dispatch resolves the table.
        let entries: Vec<u64> = (0..0x5bu64).map(|i| 0x1100 + i * 8).collect();
        let image = table(&entries);
        let found = analyse(&image, &narrow_reached_blocks(), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].targets.len(), 0x5b);
    }

    #[test]
    fn a_set_target_in_unclaimed_space_is_accepted() {
        // The Set arm of `materialise` must accept a case that is outside
        // the branching function's extent but in space no other function
        // has claimed -- a shared tail past the symbol's stated end.
        let image = Fixture {
            memory: HashMap::new(),
            code: (0x1000, 0x3000),
        };
        let analysis = analyse(&image, &masked_goto(0xf), (0x1000, 0x1400));
        assert_eq!(analysis.tables.len(), 1, "{analysis:?}");
        assert_eq!(analysis.tables[0].targets.len(), 16);
    }
    #[test]
    fn a_loop_header_entry_is_still_seeded() {
        // Block 0 is a loop header: its body jumps back to it, so it has a
        // predecessor (itself) and in-degree seeding would leave it
        // unvisited. Reachability seeding must still seed it.
        let image = table(&[0x1100, 0x1108, 0x1110, 0x1118]);
        let blocks = vec![
            // Loop header: index < 4; jbe dispatch; else loop back.
            Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                )],
                successors: vec![1, 0],
            },
            Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![
                        op(
                            "INT_MULT",
                            Some(varnode("unique", 0x20, 8)),
                            vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                        ),
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x28, 8)),
                            vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                        ),
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x30, 8)),
                            vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                        ),
                        op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                    ],
                )],
                successors: vec![],
            },
        ];
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
    }

    /// The PIC dispatch libc's SIMD string functions use: the index is a
    /// *difference of two masked values* (`(a & 0xf) + 0xf - (b & 0xf)`),
    /// and the table holds 32-bit signed offsets added back to the table
    /// base. There is no comparison guard -- the mask is the bound -- so
    /// the index only resolves if the domain can subtract one bounded
    /// interval from another.
    fn pic_table_blocks() -> Vec<Block> {
        vec![Block {
            instructions: vec![instruction(
                0x1000,
                vec![
                    // ecx = rcx & 0xf  -> [0,15]
                    op(
                        "INT_AND",
                        Some(varnode("register", 0x8, 8)),
                        vec![varnode("register", 0x8, 8), varnode("const", 0xf, 8)],
                    ),
                    // eax = rax & 0xf  -> [0,15]
                    op(
                        "INT_AND",
                        Some(varnode("register", 0x10, 8)),
                        vec![varnode("register", 0x10, 8), varnode("const", 0xf, 8)],
                    ),
                    // r9 = rax + 0xf   -> [15,30]
                    op(
                        "INT_ADD",
                        Some(varnode("register", 0x48, 8)),
                        vec![varnode("register", 0x10, 8), varnode("const", 0xf, 8)],
                    ),
                    // r9 = r9 - rcx    -> [15,30] - [0,15] = [0,30]
                    op(
                        "INT_SUB",
                        Some(varnode("register", 0x48, 8)),
                        vec![varnode("register", 0x48, 8), varnode("register", 0x8, 8)],
                    ),
                    // r10 = table base
                    op(
                        "COPY",
                        Some(varnode("register", 0x50, 8)),
                        vec![varnode("const", 0x9000, 8)],
                    ),
                    // r9 = sext(load4(r10 + r9*4))  -- the PIC offset
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x48, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("register", 0x50, 8), varnode("unique", 0x20, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op(
                        "INT_SEXT",
                        Some(varnode("register", 0x48, 8)),
                        vec![varnode("unique", 0x30, 4)],
                    ),
                    // r10 = r10 + r9  -> table_base + offset = target
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x38, 8)),
                        vec![varnode("register", 0x48, 8), varnode("const", 1, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x40, 8)),
                        vec![varnode("register", 0x50, 8), varnode("unique", 0x38, 8)],
                    ),
                    op(
                        "COPY",
                        Some(varnode("register", 0x50, 8)),
                        vec![varnode("unique", 0x40, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("register", 0x50, 8)]),
                ],
            )],
            successors: vec![],
        }]
    }

    #[test]
    fn a_pic_table_indexed_by_a_masked_difference_is_recovered() {
        // 31 entries (the [0,30] interval), each a signed 32-bit offset
        // from the table base 0x9000 to a distinct in-extent target.
        let mut memory = HashMap::new();
        let mut expected = Vec::new();
        for index in 0..31u64 {
            let target = 0x1400 + index * 4;
            let offset = (target as i64 - 0x9000) as i32 as u32 as u64;
            memory.insert(0x9000 + index * 4, offset);
            expected.push(target);
        }
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &pic_table_blocks(), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].branch, 0x1000);
        assert_eq!(found.tables[0].targets, expected);
    }

    /// `jmp [table + r38*4]` where r38 is live-in and *no* guard bounds it:
    /// the index is `Top`, so the only bound is the memory scan -- read
    /// entries until one resolves outside code.
    fn pic_guardless_blocks() -> Vec<Block> {
        vec![Block {
            instructions: vec![instruction(
                0x1010,
                vec![
                    // r10 = table base
                    op(
                        "COPY",
                        Some(varnode("register", 0x50, 8)),
                        vec![varnode("const", 0x9000, 8)],
                    ),
                    // r9 = sext(load4(r10 + r38*4))  -- the PIC offset
                    op(
                        "INT_MULT",
                        Some(varnode("unique", 0x20, 8)),
                        vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                    ),
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x28, 8)),
                        vec![varnode("register", 0x50, 8), varnode("unique", 0x20, 8)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("unique", 0x30, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                    ),
                    op(
                        "INT_SEXT",
                        Some(varnode("register", 0x48, 8)),
                        vec![varnode("unique", 0x30, 4)],
                    ),
                    // r10 = r10 + r9  -> table_base + offset = target
                    op(
                        "INT_ADD",
                        Some(varnode("register", 0x50, 8)),
                        vec![varnode("register", 0x50, 8), varnode("register", 0x48, 8)],
                    ),
                    op("BRANCHIND", None, vec![varnode("register", 0x50, 8)]),
                ],
            )],
            successors: vec![],
        }]
    }

    #[test]
    fn a_guardless_pic_table_is_scanned_to_its_first_invalid_entry() {
        // Four valid signed offsets from base 0x9000, then an entry whose
        // target lands outside code -- the scan stops there and recovers
        // the four, where no comparison ever stated the count.
        let mut memory = HashMap::new();
        let mut expected = Vec::new();
        for index in 0..4u64 {
            let target = 0x1400 + index * 8;
            let offset = (target as i64 - 0x9000) as i32 as u32 as u64;
            memory.insert(0x9000 + index * 4, offset);
            expected.push(target);
        }
        // Terminator: an offset that resolves to a non-executable address.
        memory.insert(0x9010, (0xdead0000u64 - 0x9000) as i32 as u32 as u64);
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &pic_guardless_blocks(), (0x1000, 0x2000));
        assert_eq!(found.tables.len(), 1, "{found:?}");
        assert_eq!(found.tables[0].targets, expected);
    }
    #[test]
    fn an_opaque_pic_index_is_not_scanned() {
        // Same table as the guardless scan, but the index is hashed
        // through an XOR the slicer cannot descend: the index expression
        // is opaque, not a dense point, so the linear scan -- which would
        // read whatever decodes next -- is refused. Fails pre-fix with
        // the four scanned entries.
        let mut blocks = pic_guardless_blocks();
        let mut ops = vec![blocks[0].instructions[0].ops[0].clone()];
        ops.push(op(
            "INT_XOR",
            Some(varnode("unique", 0x22, 8)),
            vec![varnode("register", 0x38, 8), varnode("const", 0x1234, 8)],
        ));
        ops.push(op(
            "INT_MULT",
            Some(varnode("unique", 0x20, 8)),
            vec![varnode("unique", 0x22, 8), varnode("const", 4, 8)],
        ));
        ops.extend(blocks[0].instructions[0].ops[2..].to_vec());
        blocks[0].instructions[0].ops = ops;
        let mut memory = HashMap::new();
        for index in 0..4u64 {
            let target = 0x1400 + index * 8;
            let offset = (target as i64 - 0x9000) as i32 as u32 as u64;
            memory.insert(0x9000 + index * 4, offset);
        }
        memory.insert(0x9010, (0xdead0000u64 - 0x9000) as i32 as u32 as u64);
        let image = Fixture {
            memory,
            code: (0x1000, 0x2000),
        };
        let found = analyse(&image, &blocks, (0x1000, 0x2000));
        assert!(found.tables.is_empty(), "{found:?}");
    }

    #[test]
    fn a_live_in_index_is_bounded_by_a_guard_through_the_slice() {
        // `jmp [table + r38*8]` where r38 is live-in (a Point the forward
        // pass sees as Top), and a predecessor guards `r38 < 4`. The slice
        // finds the table and the guard's bound.
        let image = table(&[0x1100, 0x1108, 0x1110, 0x1118]);
        let blocks = vec![
            Block {
                instructions: vec![instruction(
                    0x1000,
                    vec![
                        op(
                            "INT_LESS",
                            Some(varnode("unique", 0x10, 1)),
                            vec![varnode("register", 0x38, 8), varnode("const", 4, 8)],
                        ),
                        op(
                            "CBRANCH",
                            None,
                            vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                        ),
                    ],
                )],
                successors: vec![1, 2],
            },
            Block {
                instructions: vec![instruction(
                    0x1010,
                    vec![
                        op(
                            "INT_MULT",
                            Some(varnode("unique", 0x20, 8)),
                            vec![varnode("register", 0x38, 8), varnode("const", 8, 8)],
                        ),
                        op(
                            "INT_ADD",
                            Some(varnode("unique", 0x28, 8)),
                            vec![varnode("unique", 0x20, 8), varnode("const", 0x9000, 8)],
                        ),
                        op(
                            "LOAD",
                            Some(varnode("unique", 0x30, 8)),
                            vec![varnode("const", 0x1b1, 4), varnode("unique", 0x28, 8)],
                        ),
                        op("BRANCHIND", None, vec![varnode("unique", 0x30, 8)]),
                    ],
                )],
                successors: vec![],
            },
            Block {
                instructions: vec![instruction(0x1020, vec![op("BRANCH", None, vec![])])],
                successors: vec![],
            },
        ];
        let defs = DefIndex::build(&blocks);
        let result = slice_dispatch(&image, &defs, &blocks, 0x1010, (0x1000, 0x2000), &[0]);
        let targets = result
            .expect("the slice found a table")
            .expect("the table read");
        assert_eq!(targets, vec![0x1100, 0x1108, 0x1110, 0x1118]);
    }
    /// The slice takes the guard that decides the dispatch, not the
    /// first quasi-copy in function order: a side-branch `(R < 100)`
    /// that rejoins, and an outer `(R < 200)` whose false edge reaches
    /// too, are both skipped for the dominating `(R < 16)`.
    #[test]
    fn guard_search_requires_a_deciding_guard() {
        let guard_at = |address: u64, limit: u64, taken: u64, yes: usize, no: usize| Block {
            instructions: vec![instruction(
                address,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", limit, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", taken, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![yes, no],
        };
        let jump = |address: u64, to: usize| Block {
            instructions: vec![instruction(address, vec![op("BRANCH", None, vec![])])],
            successors: vec![to],
        };
        let blocks = vec![
            guard_at(0x1000, 200, 0x1010, 1, 2),
            guard_at(0x1010, 100, 0x1030, 3, 3),
            jump(0x1020, 3),
            jump(0x1030, 4),
            guard_at(0x1038, 312, 0x1040, 5, 7),
            guard_at(0x1040, 16, 0x1050, 6, 7),
            Block {
                instructions: vec![instruction(0x1050, vec![op("BRANCH", None, vec![])])],
                successors: vec![],
            },
            Block {
                instructions: vec![instruction(0x1060, vec![op("BRANCH", None, vec![])])],
                successors: vec![],
            },
        ];
        let defs = DefIndex::build_with_entries(&blocks, &[0]);
        let expr = Sliced::Point(("register".to_string(), 0x38));
        // The side guard (100) never dominates, the outer guard (200)
        // fails the false-edge rule, and the nested outer (312) loses to
        // the inner (15) by minimum -- first-match would answer 311.
        assert_eq!(
            guard_bound(&defs, &blocks, &expr, 6, &[0]),
            GuardSearch::Bound(("register".to_string(), 0x38), 15)
        );
    }
    /// A side guard alone rejects: it reaches the dispatch and constrains
    /// the point, but decides nothing there. The search must report the
    /// rejection (blocking the guardless scan), not `NoMatchingGuard`.
    #[test]
    fn guard_search_rejects_side_only_guards() {
        let branch = |address: u64, yes: usize, no: usize| Block {
            instructions: vec![instruction(
                address,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x39, 8), varnode("const", 7, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1010, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![yes, no],
        };
        let guard_at = |address: u64, limit: u64, taken: u64, yes: usize, no: usize| Block {
            instructions: vec![instruction(
                address,
                vec![
                    op(
                        "INT_LESS",
                        Some(varnode("unique", 0x10, 1)),
                        vec![varnode("register", 0x38, 8), varnode("const", limit, 8)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", taken, 8), varnode("unique", 0x10, 1)],
                    ),
                ],
            )],
            successors: vec![yes, no],
        };
        let jump = |address: u64, to: usize| Block {
            instructions: vec![instruction(address, vec![op("BRANCH", None, vec![])])],
            successors: vec![to],
        };
        let blocks = vec![
            branch(0x1000, 1, 2),
            guard_at(0x1010, 100, 0x1030, 3, 3),
            jump(0x1020, 3),
            Block {
                instructions: vec![instruction(0x1030, vec![op("BRANCH", None, vec![])])],
                successors: vec![],
            },
        ];
        let defs = DefIndex::build_with_entries(&blocks, &[0]);
        let expr = Sliced::Point(("register".to_string(), 0x38));
        assert_eq!(
            guard_bound(&defs, &blocks, &expr, 3, &[0]),
            GuardSearch::RejectedMatchingGuard
        );
    }
}
