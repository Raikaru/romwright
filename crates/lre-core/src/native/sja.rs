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

fn slot(varnode: &PcodeVarnode) -> Slot {
    (varnode.space.clone(), varnode.offset)
}

/// The abstract state of one program point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    values: BTreeMap<Slot, Value>,
    /// Booleans whose meaning is "this slot is at most this constant".
    /// They travel with the state because a comparison and the branch that
    /// reads it are often in different blocks -- a flag set before a call
    /// and tested after it is ordinary code. The trailing `u32` is the
    /// compared operand's width: a bound on `al` is a bound on one byte,
    /// whatever wider slot it was copied from.
    predicates: BTreeMap<Slot, (Slot, u64, bool, bool, u32)>,
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
        if std::env::var_os("VENTRIS_TRACE_VSA").is_some() {
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
    for index in 0..blocks.len() {
        if reached[index] {
            continue;
        }
        entry_state[index] = Some(State::default());
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
    if let Some(at) = std::env::var("VENTRIS_TRACE_SJA_CFG")
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
    while let Some(index) = worklist.pop() {
        let Some(state) = entry_state[index].clone() else {
            continue;
        };
        analysis.visits += 1;
        let (exit, edges) = run_block(image, &blocks[index], state, &mut dispatches);
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
            if std::env::var("VENTRIS_TRACE_SJA_EDGE")
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
            // Widening, after a few rounds: a value that is *still* moving
            // goes to top, and one that has settled is kept. Discarding the
            // whole state instead (the first version of this) threw away
            // every bound a guard had established, so a dispatch inside a
            // loop resolved to nothing.
            let merged = if rounds[successor] > 8 {
                match &entry_state[successor] {
                    Some(existing) => {
                        let mut widened = State::default();
                        for (key, value) in &merged.values {
                            if existing.values.get(key) == Some(value) {
                                widened.values.insert(key.clone(), value.clone());
                            }
                        }
                        widened
                    }
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
    for (branch, (target, index)) in dispatches {
        match materialise(image, target, index, extent) {
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
fn run_block<I: Image>(
    image: &I,
    block: &Block,
    mut state: State,
    dispatches: &mut BTreeMap<u64, (Value, Value)>,
) -> (State, BTreeMap<usize, Vec<(Slot, Value)>>) {
    use crate::ir::Opcode as O;
    let mut edges: BTreeMap<usize, Vec<(Slot, Value)>> = BTreeMap::new();
    // The comparison that produced each boolean, so a branch reading it can
    // refine the operand.
    // Boolean -> (the compared slot, the constant, inclusive, which side
    // the constant sat on, and the operand's width). The side decides which
    // *edge* learns the bound: `cmp idx, n; jbe body` bounds the taken
    // edge, and the far more common `cmp idx, n; ja default` bounds the
    // fallthrough.
    let mut comparisons: BTreeMap<Slot, (Slot, u64, bool, bool, u32)> = state.predicates.clone();
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
    let trace_at: Option<u64> = std::env::var("VENTRIS_TRACE_SJA_OPS")
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
            if std::env::var("VENTRIS_TRACE_SJA_STATE")
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
            let prior = op.output.as_ref().and_then(|out| {
                let key = slot(out);
                comparisons.remove(&key);
                // A comparison whose *operand* is overwritten is stale too:
                // `cmp $4,%eax; mov (%rsi),%eax; jbe` bounds the new eax.
                // A value-preserving same-slot widening is the exception:
                // `cmp $0x5a,%al; movzbl %al,%eax; ja` keeps the bound.
                let preserves = matches!(opcode, crate::ir::Opcode::Copy | crate::ir::Opcode::IntZExt | crate::ir::Opcode::IntSExt)
                    && op.inputs.first().is_some_and(|src| slot(src) == key);
                if !preserves {
                    comparisons.retain(|_, (operand, ..)| *operand != key);
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
                            origins.get(&slot(source)).cloned()
                                .unwrap_or((slot(source), 0, None, source.size))
                        };
                        // A `unique` temporary is intra-instruction and dead
                        // by the next block, so it is never an origin: the
                        // output has no affine parent at all.
                        if origin.0 != "unique" && origin != slot(output) {
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
                            origins.get(&slot(source)).cloned()
                                .unwrap_or((slot(source), 0, None, source.size))
                        };
                        // A `unique` temporary is dead by the next block:
                        // the output has no affine parent, and recording
                        // `out = out + k` would push a wrongly shifted bound
                        // onto it at the next compare.
                        if origin.0 != "unique" && origin != slot(output) {
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
                            (Value::Const(value), _) => Value::Const(value.wrapping_neg()),
                            _ => Value::Top,
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
                            origins.get(&slot(source)).cloned()
                                .unwrap_or((slot(source), 0, None, source.size))
                        };
                        if origin.0 != "unique" && origin != slot(output) {
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
                    let mut carried: Option<(Slot, u64, bool, bool, u32)> = None;
                    for input in &op.inputs {
                        if let Some(found) = comparisons.get(&slot(input)).cloned() {
                            carried = Some(match carried {
                                // Two bounds on one slot: the looser one is
                                // what the combination admits.
                                Some((existing, limit, inclusive, left, width))
                                    if existing == found.0 =>
                                {
                                    (existing, limit.max(found.1), inclusive || found.2, left, width)
                                }
                                Some(existing) => existing,
                                None => found,
                            });
                        }
                    }
                    if let (Some(output), Some(found)) = (&op.output, carried) {
                        comparisons.insert(slot(output), found);
                    }
                    if let Some(output) = &op.output {
                        state.set(output, Value::Top);
                    }
                }
                O::IntLess | O::IntSLess | O::IntLessEqual | O::IntSLessEqual => {
                    // Remember what this boolean says, for the branch that
                    // reads it: `index < n` bounds the index above.
                    if let (Some(output), Some(left), Some(right)) =
                        (&op.output, op.inputs.first(), op.inputs.get(1))
                    {
                        let inclusive = matches!(opcode, O::IntLessEqual | O::IntSLessEqual);
                        match (state.get(left), state.get(right)) {
                            // `index < n`: the taken edge is in range.
                            (_, Value::Const(limit)) if right.space == "const" => {
                                comparisons
                                    .insert(slot(output), (slot(left), limit, inclusive, false, left.size));
                            }
                            // `n < index`: the *fallthrough* is in range.
                            (Value::Const(limit), _) if left.space == "const" => {
                                comparisons
                                    .insert(slot(output), (slot(right), limit, inclusive, true, right.size));
                            }
                            _ => {}
                        }
                    }
                }
                O::CBranch => {
                    // Slot 0 of a block's successors is the fallthrough in
                    // our own construction, slot 1 the taken edge, so the
                    // refinement is applied to whichever assumes the test.
                    if let Some(condition) = op.inputs.get(1)
                        && let Some((operand, limit, inclusive, constant_left, operand_size)) =
                            comparisons.get(&slot(condition)).cloned()
                    {
                        // `index < n` taken means index <= n-1; `n < index`
                        // *not* taken means index <= n.
                        let high = if constant_left {
                            if inclusive { limit as i64 - 1 } else { limit as i64 }
                        } else if inclusive {
                            limit as i64
                        } else {
                            limit as i64 - 1
                        };
                        let edge = usize::from(constant_left);
                        if high >= 0 {
                            // The bound belongs to the value, wherever it
                            // lives: the compared slot and whatever it was
                            // copied from. A temp `t = origin + off` bounded
                            // to [0, high] bounds the origin to
                            // [-off, high - off].
                            let mut targets = vec![(operand.clone(), 0i64)];
                            // Follow the origin chain transitively: `dl`
                            // came from `edx`, which came from `r15`, so a
                            // bound on the compared temp is a bound on each
                            // link, shifted by the accumulated offset. One
                            // hop (the first version) stopped at `edx`, and
                            // the `movzbl %r15b,%edx` that overwrote it
                            // carried the bound nowhere. A hop that fails
                            // `usable` is skipped, not terminal: the bound
                            // still reaches the wider origin past it.
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
                                    let usable = if effective >= 8 || *origin_size <= effective {
                                        true
                                    } else {
                                        let mask = (1u64 << (effective * 8)) - 1;
                                        match state.values.get(origin) {
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
                            // And the other direction: `mov %ebx,%r11d`
                            // before the compare means r11's origin is the
                            // bounded slot, so the bound belongs to r11
                            // too. Walk the links to a fixpoint: a slot
                            // whose origin is already targeted gets the
                            // bound shifted by its own offset. Only exact
                            // copies and shifts propagate -- a subpiece
                            // (narrow set) truncates, and a bound on the
                            // whole says nothing about the piece.
                            let mut reached: Vec<(Slot, i64)> = targets.clone();
                            loop {
                                let mut grew = false;
                                for (slot, (origin, off, narrow, _)) in &origins {
                                    if reached.iter().any(|(s, _)| s == slot) {
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
                                        // A slot that is a truncation of its
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
                            let trace_cbranch = std::env::var("VENTRIS_TRACE_SJA_CBRANCH")
                                .ok()
                                .and_then(|raw| {
                                    u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok()
                                })
                                == Some(instruction.address);
                            if trace_cbranch {
                                eprintln!(
                                    "CBRANCH {:#x}: operand={:?} high={} targets={:?}",
                                    instruction.address, operand, high, targets
                                );
                            }
                            for (target, off) in targets {
                                let bounded = match state.values.get(&target).cloned() {
                                    // Intersect, not overwrite: a bound on
                                    // `t = origin + off` narrows the origin
                                    // to [lo.max(-off), hi.min(high-off)].
                                    // Only a plain index-space value
                                    // (base 0, stride 1) shifts this way.
                                    // The refined floor can still go
                                    // negative: `lea 0x10(%rax),%rdx;
                                    // cmp $0x20,%rdx` bounds eax to
                                    // [-0x10, 3-0x10]. No compiler indexes
                                    // a table negatively, so the guard was
                                    // never stated.
                                    Some(Value::Strided { base: 0, stride: 1, lo, hi: old_hi, .. }) => {
                                        let floor = lo.max(-off);
                                        Value::Strided { base: 0, stride: 1, lo: floor, hi: old_hi.min(high - off), guarded: floor >= 0 }
                                    }
                                    // A fresh bound on an unknown value.
                                    // `lea 0x10(%r8),%rax; cmp $0x20,%rax`
                                    // bounds r8 to [-0x10, 0xf]: the floor
                                    // went negative, so no guard was ever
                                    // stated and the read must refuse.
                                    Some(Value::Top) | None =>
                                        Value::Strided { base: 0, stride: 1, lo: -off, hi: high - off, guarded: -off >= 0 },
                                    // A set filters to the members the
                                    // bound admits: sound, and keeps the
                                    // precision the set already had.
                                    Some(Value::Set(values)) => {
                                        let kept: Vec<u64> = values.iter().copied()
                                            .filter(|v| (*v as i64) >= -off && (*v as i64) <= high - off)
                                            .collect();
                                        if kept.is_empty() {
                                            continue;
                                        }
                                        Value::Set(std::rc::Rc::new(kept))
                                    }
                                    // A constant outside the bound means
                                    // this edge is infeasible; a Strided
                                    // with a different base or stride is a
                                    // different value set entirely. Both
                                    // are left alone rather than refined
                                    // into an index-space bound.
                                    _ => continue,
                                };
                                if trace_cbranch {
                                    eprintln!(
                                        "  -> {:?} off={} bounded={:?}",
                                        target, off, bounded
                                    );
                                }
                                edges
                                    .entry(edge)
                                    .or_default()
                                    .push((target.clone(), bounded.clone()));
                                edges
                                    .entry(1 - edge)
                                    .or_default()
                                    .push((target, bounded));
                            }
                        }
                    }
                }
                O::BranchInd => {
                    if let Some(target) = op.inputs.first() {
                        let value = state.get(target);
                        if std::env::var("VENTRIS_TRACE_SJA_AT")
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
    (state, edges)
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
        _ => Top,
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

    #[test]
    fn a_dispatch_no_comparison_bounds_is_refused() {
        let image = table(&[0x1100, 0x1108, 0x1110, 0x1118]);
        let mut blocks = switch_blocks();
        // Remove the guard's comparison: nothing states the range.
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
}
