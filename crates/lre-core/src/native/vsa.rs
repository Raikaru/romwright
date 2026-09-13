//! Jump-table recovery by value-set analysis over raw p-code.
//!
//! Why this exists: switch recovery was the last pass in a native import
//! that still needed the decompiler. It cost the most of any phase -- 130 of
//! 137 seconds on a statically linked AArch64 image -- and two bodies there
//! hit the per-function decompiler deadline outright. The decompiler answers
//! by building its whole IR for a function; the question is narrower than
//! that.
//!
//! The method is Ghidra's own, moved off the IR and onto SLEIGH's p-code.
//! `JumpBasic::buildAddresses` (jumptable.cc:1451-1478) emulates the path
//! that feeds an indirect branch once per value of the switch variable, and
//! reads the target out of the emulator each time; `JumpValuesRange` supplies
//! the values, and the guard analysis (`JumpBasic::analyzeGuards`:1061)
//! supplies the range. This module does the same three things:
//!
//! 1. take the straight-line window of instructions that ends at the
//!    indirect branch (its basic block, optionally with the block before it);
//! 2. find the switch variable -- a value the window reads but never writes,
//!    which the branch target depends on -- and the bound a guard puts on it;
//! 3. emulate the window once per index value, reading the image for every
//!    load, and collect the targets.
//!
//! Nothing here is speculative: a target is kept only when it lands in
//! executable memory that the image actually maps, and a table is reported
//! only when at least two distinct targets are found. Where the emulator
//! meets an operation it does not model, the value becomes unknown and the
//! candidate is abandoned rather than guessed.

use std::collections::HashMap;

use crate::native_runtime::{PcodeInstruction, PcodeOp, PcodeVarnode};

/// Why a dispatch was not answered. Counted per import so the gap between
/// this pass and the decompiler is attributable rather than guessed at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refusals {
    /// Nothing the window read was a value it did not also write.
    pub no_live_in: usize,
    /// No load moved with the index, so nothing here reads a table.
    pub no_strided_load: usize,
    /// A table was found but had fewer than two distinct case targets.
    pub too_few_targets: usize,
    /// Every candidate hit an operation the emulator does not model.
    pub unmodelled: usize,
}

/// A recovered table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchTable {
    /// The indirect branch the table belongs to.
    pub branch: u64,
    /// Case targets, in index order, duplicates kept: a switch with two
    /// labels on one case really does repeat a target, and the count is the
    /// number of cases.
    pub targets: Vec<u64>,
    /// Which value the switch variable ran over, exclusive.
    pub span: u64,
}

/// What the emulator knows about one location.
type Known = Option<u64>;

fn mask(size: u32) -> u64 {
    match size {
        0 => 0,
        s if s >= 8 => u64::MAX,
        s => (1u64 << (s * 8)) - 1,
    }
}

fn sign_extend(value: u64, size: u32) -> u64 {
    if size == 0 || size >= 8 {
        return value;
    }
    let bits = size * 8;
    let sign = 1u64 << (bits - 1);
    if value & sign != 0 {
        value | !mask(size)
    } else {
        value & mask(size)
    }
}

/// The image the emulator reads loads from.
pub trait Image {
    /// Bytes at `address`, when the image maps them.
    fn read(&self, address: u64, size: u32) -> Option<u64>;
    /// True when `address` is inside a mapping that can be executed.
    fn executable(&self, address: u64) -> bool;
    /// True when the image is big-endian.
    fn big_endian(&self) -> bool;
    /// The extent of the function that already owns `address`, when one
    /// does.
    ///
    /// A dispatch's own case blocks are frequently reachable *only* through
    /// the dispatch, so at the moment it is analysed they belong to no
    /// function yet -- refusing a target for being outside the extent
    /// recovered so far would refuse exactly the dispatches that discover
    /// new code. What must not happen is a table reaching into a
    /// *different* function, which is what this answers.
    fn owner(&self, _address: u64) -> Option<(u64, u64)> {
        None
    }
}

/// A memory location named by structure, not by address: base slot plus a
/// constant displacement. The index of a PIC table lives in memory behind
/// a pointer no emulation can concretise, but the guard compares, and the
/// dispatch loads, the same expression -- forcing the expression to a
/// concrete index per run lets the existing machinery bound and read the
/// table with no other change.
type MemKey = ((String, u64), u64);

/// How one straight-line slice defines a varnode, as far as memory
/// expressions care: an add of a constant displacement to a slot, a copy
/// of another slot, or anything else.
enum Def {
    AddConst { base: (String, u64), disp: u64 },
    Copy { from: (String, u64) },
    Const { value: u64 },
}

/// The seed a run installs: a register value, or a memory expression
/// forced to a value wherever the slice loads it.
enum Seed<'a> {
    Reg((&'a str, u64, u32)),
    Mem(MemKey),
}
type DefMap = HashMap<(String, u64), Def>;

/// Definitions a straight-line slice makes, keeping only slots defined
/// exactly once: a redefined slot has no single meaning, and dropping it
/// misses tables rather than misreading them.
fn defs_for(slice: &[PcodeInstruction]) -> DefMap {
    defs_for_slices(&[slice], false)
}

/// Names the memory a varnode's defining chain addresses, or nothing when
/// the chain leaves the shapes an add-of-constant and copies describe.
fn resolve_key(
    defs: &DefMap,
    varnode: &PcodeVarnode,
) -> Option<MemKey> {
    if varnode.is_const() {
        return None;
    }
    let mut current = (varnode.space.clone(), varnode.offset);
    for _ in 0..8 {
        match defs.get(&current) {
            Some(Def::AddConst { base, disp }) => {
                return Some(((base.0.clone(), base.1), *disp));
            }
            Some(Def::Copy { from }) => {
                current = from.clone();
            }
            Some(Def::Const { .. }) | None => return None,
        }
    }
    None
}

/// Definitions over several straight-line slices, keeping only slots
/// defined exactly once across all of them: a redefined slot has no
/// single meaning, and dropping it misses tables rather than misreading
/// them. Guard blocks dominate the dispatch by predecessor construction,
/// so their single definitions hold wherever the dispatch runs.
fn defs_for_slices(slices: &[&[PcodeInstruction]], persistent_only: bool) -> DefMap {
    // Persistent slots only for cross-slice unions: `unique` offsets are
    // reused at every instruction, so unioning them marks every temporary
    // redefined and drops exactly the address expressions memory forcing
    // resolves. Cross-block values flow through registers and ram, never
    // uniques, so nothing real is lost.
    let keep = |space: &str| !persistent_only || space != "unique";
    let mut counts: HashMap<(String, u64), usize> = HashMap::new();
    for slice in slices {
        for instruction in slice.iter() {
            for op in &instruction.ops {
                if let Some(out) = op.output.as_ref() {
                    if !out.is_const() && keep(&out.space) {
                        *counts.entry((out.space.clone(), out.offset)).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    let mut defs = HashMap::new();
    for slice in slices {
        for instruction in slice.iter() {
            for op in &instruction.ops {
                let Some(out) = op.output.as_ref() else {
                    continue;
                };
                if out.is_const()
                    || !keep(&out.space)
                    || counts.get(&(out.space.clone(), out.offset)) != Some(&1)
                {
                    continue;
                }
                let slot = |v: &PcodeVarnode| (v.space.clone(), v.offset);
                match op.opcode.parse::<crate::ir::Opcode>().unwrap_or(crate::ir::Opcode::Other) {
                    crate::ir::Opcode::IntAdd if op.inputs.len() >= 2 => {
                        let (a, b) = (&op.inputs[0], &op.inputs[1]);
                        if a.is_const() && b.is_const() {
                            defs.insert(
                                slot(out),
                                Def::Const {
                                    value: a.offset.wrapping_add(b.offset),
                                },
                            );
                        } else if a.is_const() && !b.is_const() {
                            defs.insert(slot(out), Def::AddConst { base: slot(b), disp: a.offset });
                        } else if b.is_const() && !a.is_const() {
                            defs.insert(slot(out), Def::AddConst { base: slot(a), disp: b.offset });
                        }
                    }
                    crate::ir::Opcode::Copy | crate::ir::Opcode::Cast if op.inputs.len() == 1 => {
                        if op.inputs[0].is_const() {
                            defs.insert(
                                slot(out),
                                Def::Const {
                                    value: op.inputs[0].offset,
                                },
                            );
                        } else {
                            defs.insert(slot(out), Def::Copy { from: slot(&op.inputs[0]) });
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    defs
}

/// Follows a chain that reads nothing: copies and adds of constants. The
/// value holds on every path by construction, so seeding it is not a guess
/// but what the code computes. Anything else is none.
fn resolve_const(defs: &DefMap, varnode: &PcodeVarnode) -> Option<u64> {
    let value = if varnode.is_const() {
        varnode.offset
    } else {
        resolve_slot(defs, &(varnode.space.clone(), varnode.offset), 8)?
    };
    Some(value & mask(varnode.size))
}

fn resolve_slot(defs: &DefMap, slot: &(String, u64), depth: u8) -> Option<u64> {
    if depth == 0 {
        return None;
    }
    match defs.get(slot) {
        Some(Def::AddConst { base, disp }) => {
            resolve_slot(defs, base, depth - 1).map(|b| b.wrapping_add(*disp))
        }
        Some(Def::Const { value }) => Some(*value),
        Some(Def::Copy { from }) => resolve_slot(defs, from, depth - 1),
        None => None,
    }
}
/// A straight-line p-code emulator: enough of the integer operations to
/// follow a switch dispatch, and honest about everything else.

struct Machine<'a, I: Image> {
    image: &'a I,
    /// Machine state, keyed by space and offset, carrying the width it was
    /// written at: a narrower read of the same location takes its low bytes,
    /// a wider one is unknown rather than invented.
    state: HashMap<(&'a str, u64), (u64, u32)>,
    /// Values stored to memory during the window, so an index spilled to the
    /// stack and reloaded still follows.
    stored: HashMap<u64, (u64, u32)>,
    /// Persistent locations the window read before ever writing them: the
    /// candidates for the switch variable.
    live_in: Vec<(&'a str, u64, u32)>,
    /// Every conditional branch executed, in order: `(destination, whether
    /// it was taken)`. The guard that bounds a switch is one of these -- the
    /// range is where it starts sending the index to the default case, which
    /// is what `JumpBasic::analyzeGuards` establishes on the SSA path and
    /// what this establishes by running it.
    branches: Vec<(Option<u64>, Known)>,
    /// Every address loaded during the run, in order. A jump table is read
    /// by one of these, and which one is told apart from the rest by moving
    /// with the index.
    loads: Vec<u64>,
    /// The location the index was seeded at. A call clears every other
    /// register -- this emulator models no ABI -- but not this one: the
    /// value being tracked reaches the dispatch by construction, so the
    /// machine itself preserves it across whatever lies between.
    preserve: Option<(&'a str, u64)>,
    /// True once a call was reached, which is why the state was cleared.
    gave_up: bool,
    /// Ignore writes to the preserved location. A guard block often
    /// recomputes the index -- `mov 0x4(%rbx),%edx; sub $0x3,%edx` -- from
    /// values this emulator cannot know, and then compares it. The value it
    /// compares is by definition the one that reaches the dispatch, so
    /// holding the seeded value through the block makes the comparison read
    /// exactly what the dispatch will use. Without this the guard reads
    /// unknown and no table is ever bounded.
    pinned: bool,
    /// Definitions visible to this slice, output slot to defining shape:
    /// resolving a load's address through them names the memory the slice
    /// reads by structure instead of by an address it cannot know.
    defs: HashMap<(String, u64), Def>,
    /// A memory expression forced to one index value for this run.
    forced: Option<(MemKey, u64)>,
    /// Resolved address keys already asked about, so each load resolves
    /// its address expression once per run.
    memo: HashMap<(String, u64), Option<MemKey>>,
}

impl<'a, I: Image> Machine<'a, I> {
    fn new(image: &'a I) -> Self {
        Self {
            image,
            state: HashMap::new(),
            stored: HashMap::new(),
            live_in: Vec::new(),
            branches: Vec::new(),
            loads: Vec::new(),
            preserve: None,
            gave_up: false,
            pinned: false,
            defs: HashMap::new(),
            forced: None,
            memo: HashMap::new(),
        }
    }

    fn read(&mut self, varnode: &'a PcodeVarnode) -> Known {
        if varnode.is_const() {
            return Some(varnode.offset & mask(varnode.size));
        }
        match self.state.get(&(varnode.space.as_str(), varnode.offset)) {
            Some(&(value, size)) if varnode.size <= size => Some(value & mask(varnode.size)),
            Some(_) => None,
            None => {
                if varnode.is_persistent()
                    && !self
                        .live_in
                        .iter()
                        .any(|&(space, offset, _)| space == varnode.space && offset == varnode.offset)
                {
                    self.live_in
                        .push((varnode.space.as_str(), varnode.offset, varnode.size));
                }
                None
            }
        }
    }
    fn key_of(&mut self, varnode: &PcodeVarnode) -> Option<MemKey> {
        if varnode.is_const() {
            return None;
        }
        let slot = (varnode.space.clone(), varnode.offset);
        if let Some(hit) = self.memo.get(&slot) {
            return hit.clone();
        }
        let resolved = resolve_key(&self.defs, varnode);
        self.memo.insert(slot, resolved.clone());
        resolved
    }

    fn write(&mut self, varnode: &'a PcodeVarnode, value: Known) {
        if self.pinned
            && self.preserve == Some((varnode.space.as_str(), varnode.offset))
        {
            return;
        }
        match value {
            Some(value) => {
                self.state.insert(
                    (varnode.space.as_str(), varnode.offset),
                    (value & mask(varnode.size), varnode.size),
                );
            }
            None => {
                self.state.remove(&(varnode.space.as_str(), varnode.offset));
            }
        }
    }

    fn load(&self, address: u64, size: u32) -> Known {
        if let Some(&(value, stored_size)) = self.stored.get(&address) {
            if size <= stored_size {
                return Some(value & mask(size));
            }
            return None;
        }
        let raw = self.image.read(address, size)?;
        Some(raw & mask(size))
    }

    /// Runs one operation. Returns the branch destination when the operation
    /// is the window's indirect branch.
    fn step(&mut self, op: &'a PcodeOp) -> Option<u64> {
        use crate::ir::Opcode as O;
        // Lift the raw opcode string into the typed IR opcode; the varnodes
        // stay borrowed from `op` so `read`/`write` keep the `'a` lifetime.
        let opcode = op.opcode.parse::<O>().unwrap_or(O::Other);
        let inputs: Vec<Known> = op.inputs.iter().map(|input| {
            if input.is_const() {
                Some(input.offset & mask(input.size))
            } else {
                self.read(input)
            }
        }).collect();
        let size = op.output.as_ref().map_or(8, |out| out.size);
        let a = inputs.first().copied().flatten();
        let b = inputs.get(1).copied().flatten();
        if opcode == O::CBranch {
            // input 0 is the destination, input 1 the condition.
            let destination = op.inputs.first().map(|input| input.offset);
            let condition = inputs.get(1).copied().flatten();
            self.branches.push((destination, condition));
        }
        let value: Known = match opcode {
            O::Copy | O::Cast => a,
            O::Load => {
                // input 0 names the space, input 1 is the offset.
                let forced = op
                    .inputs
                    .get(1)
                    .and_then(|input| self.key_of(input))
                    .and_then(|key| match self.forced {
                        Some((ref forced_key, value)) if *forced_key == key => Some(value),
                        _ => None,
                    });
                if forced.is_some() {
                    // The seeded memory expression: answer the index and
                    // mark the read, so stride detection treats it as
                    // index-independent in every run alike.
                    self.loads.push(u64::MAX);
                }
                match forced {
                    Some(value) => Some(value),
                    None => {
                        let address = inputs.get(1).copied().flatten();
                        if let Some(address) = address {
                            self.loads.push(address);
                        }
                        address.and_then(|address| self.load(address, size))
                    }
                }
            }
            O::Store => {
                let address = inputs.get(1).copied().flatten();
                let stored = inputs.get(2).copied().flatten();
                let width = op.inputs.get(2).map_or(8, |input| input.size);
                match (address, stored) {
                    (Some(address), Some(stored)) => {
                        self.stored.insert(address, (stored, width));
                    }
                    (Some(address), None) => {
                        self.stored.remove(&address);
                    }
                    _ => {}
                }
                return None;
            }
            O::IntAdd => match (a, b) {
                (Some(a), Some(b)) => Some(a.wrapping_add(b)),
                _ => None,
            },
            O::IntSub => match (a, b) {
                (Some(a), Some(b)) => Some(a.wrapping_sub(b)),
                _ => None,
            },
            O::IntMult => match (a, b) {
                (Some(a), Some(b)) => Some(a.wrapping_mul(b)),
                _ => None,
            },
            O::IntDiv => match (a, b) {
                (Some(a), Some(b)) if b != 0 => Some(a / b),
                _ => None,
            },
            O::IntRem => match (a, b) {
                (Some(a), Some(b)) if b != 0 => Some(a % b),
                _ => None,
            },
            O::IntAnd => match (a, b) {
                (Some(a), Some(b)) => Some(a & b),
                _ => None,
            },
            O::IntOr => match (a, b) {
                (Some(a), Some(b)) => Some(a | b),
                _ => None,
            },
            O::IntXor => match (a, b) {
                (Some(a), Some(b)) => Some(a ^ b),
                _ => None,
            },
            O::IntLeft => match (a, b) {
                (Some(a), Some(b)) if b < 64 => Some(a << b),
                (Some(_), Some(_)) => Some(0),
                _ => None,
            },
            O::IntRight => match (a, b) {
                (Some(a), Some(b)) if b < 64 => Some(a >> b),
                (Some(_), Some(_)) => Some(0),
                _ => None,
            },
            O::IntSRight => match (a, b) {
                (Some(a), Some(b)) if b < 64 => {
                    let width = op.inputs.first().map_or(8, |input| input.size);
                    Some(((sign_extend(a, width) as i64) >> b) as u64)
                }
                _ => None,
            },
            O::IntNegate => a.map(|a| !a),
            O::Int2Comp => a.map(|a| a.wrapping_neg()),
            O::IntZExt => a,
            O::IntSExt => {
                let width = op.inputs.first().map_or(8, |input| input.size);
                a.map(|a| sign_extend(a, width))
            }
            O::Subpiece => match (a, b) {
                (Some(a), Some(shift)) => {
                    let bits = shift.saturating_mul(8);
                    if bits >= 64 { Some(0) } else { Some(a >> bits) }
                }
                _ => None,
            },
            O::Piece => match (a, b) {
                (Some(high), Some(low)) => {
                    let low_width = op.inputs.get(1).map_or(0, |input| input.size);
                    Some((high << (low_width * 8)) | low)
                }
                _ => None,
            },
            O::IntEqual => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a == b)),
                _ => None,
            },
            O::IntNotEqual => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a != b)),
                _ => None,
            },
            O::IntLess => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a < b)),
                _ => None,
            },
            O::IntLessEqual => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a <= b)),
                _ => None,
            },
            O::IntSLess | O::IntSLessEqual => match (a, b) {
                (Some(a), Some(b)) => {
                    let width = op.inputs.first().map_or(8, |input| input.size);
                    let (a, b) = (sign_extend(a, width) as i64, sign_extend(b, width) as i64);
                    Some(u64::from(if opcode == O::IntSLess {
                        a < b
                    } else {
                        a <= b
                    }))
                }
                _ => None,
            },
            O::BoolAnd => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a != 0 && b != 0)),
                _ => None,
            },
            O::BoolOr => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a != 0 || b != 0)),
                _ => None,
            },
            O::BoolXor => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from((a != 0) ^ (b != 0))),
                _ => None,
            },
            O::BoolNegate => a.map(|a| u64::from(a == 0)),
            O::PopCount => a.map(|a| u64::from(a.count_ones())),
            // Recorded above; a conditional branch inside the window is the
            // guard, not a reason to abandon the path.
            O::CBranch => None,
            O::BranchInd | O::CallInd | O::Return => {
                // The window's whole purpose: the destination this indirect
                // transfer computed.
                return a;
            }
            // A call returns knowing nothing about the caller-saved
            // registers, and this emulator does not model an ABI, so after
            // one nothing is known at all. Clearing is the conservative
            // reading; keeping the old values would let a stale register
            // produce a target that the machine never computes.
            O::Call | O::CallOther => {
                let kept = self
                    .preserve
                    .and_then(|key| self.state.get(&key).map(|value| (key, *value)));
                self.state.clear();
                if let Some((key, value)) = kept {
                    self.state.insert(key, value);
                }
                self.gave_up = true;
                None
            }
            // An unconditional branch is how a guard block reaches the
            // dispatch: the region is a straight line by construction, so
            // there is nothing to do here.
            O::Branch => None,
            // Anything else -- a flag computation, a floating-point
            // operation, an instruction with no integer model here -- makes
            // its output unknown and nothing else. Abandoning the whole run
            // instead cost the guard: on libc the guard region hit one of
            // these before its comparison every time, so no table was ever
            // bounded and 109 dispatches ended with too few targets.
            _ => None
        };
        if let Some(out) = op.output.as_ref() {
            self.write(out, value);
        }
        None
    }
}

/// Emulates `window` once, with `seed` installed as the switch variable, and
/// returns the destination the indirect branch computed.
struct Run {
    destination: Option<u64>,
    live_in: Vec<(String, u64, u32)>,
    loads: Vec<u64>,
    branches: Vec<(Option<u64>, Known)>,
    gave_up: bool,
}

fn run<I: Image>(
    image: &I,
    window: &[PcodeInstruction],
    seed: Option<((&str, u64, u32), u64)>,
    mem: Option<(MemKey, u64)>,
    concrete: &[((String, u64), u64)],
) -> Run {
    run_with(image, window, seed, mem, concrete, false)
}

fn run_with<I: Image>(
    image: &I,
    window: &[PcodeInstruction],
    seed: Option<((&str, u64, u32), u64)>,
    mem: Option<(MemKey, u64)>,
    concrete: &[((String, u64), u64)],
    pinned: bool,
) -> Run {
    let mut machine = Machine::new(image);
    machine.defs = defs_for(window);
    machine.forced = mem;
    for ((space, offset), value) in concrete {
        machine
            .state
            .insert((space.as_str(), *offset), (*value, 8));
    }
    if let Some(((space, offset, size), value)) = seed {
        machine
            .state
            .insert((space, offset), (value & mask(size), size));
        machine.preserve = Some((space, offset));
        machine.pinned = pinned;
    }
    let mut destination = None;
    for instruction in window {
        for op in &instruction.ops {
            if let Some(address) = machine.step(op) {
                destination = Some(address);
            }
        }
    }
    let live_in = machine
        .live_in
        .iter()
        .map(|&(space, offset, size)| (space.to_string(), offset, size))
        .collect();
    Run {
        destination,
        live_in,
        loads: machine.loads,
        branches: machine.branches,
        gave_up: machine.gave_up,
    }
}

/// How many index values a candidate may be tried at before the recovery
/// gives up on it. Ghidra bounds its own tables the same way, by a maximum
/// table size rather than by trusting the guard alone
/// (`JumpBasic::findNormalized`, `maxtablesize`).
const MAX_TABLE: u64 = 4096;

/// Recovers the table an indirect branch reads, or nothing.
///
/// `window` is the straight-line p-code ending at the branch; `bounds` are
/// the constants nearby guards compare against, largest first.
pub fn recover<I: Image>(
    image: &I,
    branch: u64,
    guard: &[Vec<PcodeInstruction>],
    window: &[PcodeInstruction],
    refusals: &mut Refusals,
) -> Option<SwitchTable> {
    if window.is_empty() {
        return None;
    }

    // One dry run: what does the window read that it never wrote? Those are
    // the only places a switch variable can come from.
    let dry = run(image, window, None, None, &[]);
    if dry.live_in.is_empty() {
        if dry.gave_up {
            refusals.unmodelled += 1;
        } else {
            refusals.no_live_in += 1;
        }
        return None;
    }
    let mut saw_stride = false;
    let mut saw_candidate = false;
    let trace = std::env::var("VENTRIS_TRACE_VSA_AT")
        .ok()
        .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        == Some(branch);
    if trace {
        eprintln!("VSA {branch:#x} live-in {:x?}", dry.live_in);
        for instruction in guard.iter().flatten().chain(window.iter()) {
            for op in &instruction.ops {
                let ins: Vec<String> = op
                    .inputs
                    .iter()
                    .map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size))
                    .collect();
                let out = op
                    .output
                    .as_ref()
                    .map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size))
                    .unwrap_or_else(|| "-".to_string());
                eprintln!("  {:x}: {} {} -> {}", instruction.address, op.opcode, ins.join(","), out);
            }
        }
    }
    // A guard states the range, and a guarded answer is the better one --
    // but it is not the only sound one. Deleting the unguarded fallback
    // outright cost 49 of 142 dispatches on libc, measured by `m13-001`,
    // because the code-bounded walk answers dispatches no guard analysis
    // reaches. Both tiers are kept, the guarded answer wins where there is
    // one, and every target either produces still has to decode and lie
    // inside the branching function before it becomes a fact.
    let mut guarded: Option<SwitchTable> = None;
    let mut unguarded: Option<SwitchTable> = None;
    // Values the code computes without reading anything, across the
    // window and its guard blocks: seeding them states facts, and they
    // stop being trial candidates (sweeping a known constant only ever
    // misread the table through it).
    let mut joint: Vec<&[PcodeInstruction]> = vec![window];
    joint.extend(guard.iter().map(Vec::as_slice));
    let joint_defs = defs_for_slices(&joint, true);
    // Address temporaries resolve per slice: uniques are per-instruction
    // scratch, so only the window's own map sees their definitions.
    let window_defs = defs_for(window);
    let concrete: Vec<((String, u64), u64)> = dry
        .live_in
        .iter()
        .filter_map(|(space, offset, size)| {
            let varnode = PcodeVarnode {
                space: space.clone(),
                offset: *offset,
                size: *size,
            };
            resolve_const(&joint_defs, &varnode).map(|value| ((space.clone(), *offset), value))
        })
        .collect();
    let inside: std::collections::HashSet<u64> = guard
        .iter()
        .flatten()
        .chain(window.iter())
        .map(|instruction| instruction.address)
        .collect();
    // Memory the window loads through an add of a constant: the index of
    // a PIC table lives behind a pointer no register seed moves, so those
    // expressions seed runs of their own. Capped: each costs two stride
    // runs before it is refused.
    let mut memkeys: Vec<MemKey> = Vec::new();
    for instruction in window {
        for op in &instruction.ops {
            if op.opcode.parse::<crate::ir::Opcode>() == Ok(crate::ir::Opcode::Load) {
                if let Some(input) = op.inputs.get(1) {
                    if let Some(key) = resolve_key(&window_defs, input) {
                        if !memkeys.contains(&key) {
                            memkeys.push(key);
                        }
                    }
                }
            }
        }
    }
    memkeys.truncate(8);
    let mut worker = |seed: Seed<'_>, label: String| {
        // A switch reads its targets out of a table, so the run must contain
        // a load whose address moves with the index by a fixed stride. That
        // single requirement is what separates a table from a register
        // sweep: without it, feeding indices to any live register produces
        // "targets" wherever the arithmetic happens to land in code, which
        // measured 0.42 edge precision against stock Ghidra on libc.
        let run_seed = |index: u64| match &seed {
            Seed::Reg(candidate) => {
                run(image, window, Some((*candidate, index)), None, &concrete)
            }
            Seed::Mem(key) => run(image, window, None, Some((key.clone(), index)), &concrete),
        };
        let run_guard = |block: &[PcodeInstruction], index: u64| match &seed {
            Seed::Reg(candidate) => {
                run_with(image, block, Some((*candidate, index)), None, &concrete, true)
            }
            Seed::Mem(key) => {
                run_with(image, block, None, Some((key.clone(), index)), &concrete, true)
            }
        };
        let first = run_seed(0);
        let second = run_seed(1);
        if first.gave_up || second.gave_up {
            return;
        }
        saw_candidate = true;
        if trace {
            eprintln!(
                "  candidate {label} loads0 {:x?} loads1 {:x?} dest0 {:x?} dest1 {:x?}",
                first.loads, second.loads, first.destination, second.destination
            );
        }
        if first.loads.len() != second.loads.len() {
            return;
        }
        let Some(slot) = first
            .loads
            .iter()
            .zip(&second.loads)
            .position(|(a, b)| a != b)
        else {
            return;
        };
        // Everything before the table read must be index-independent, and
        // the read itself must advance by one element.
        if first.loads[..slot] != second.loads[..slot] {
            return;
        }
        let stride = second.loads[slot].wrapping_sub(first.loads[slot]);
        if !matches!(stride, 1 | 2 | 4 | 8 | 16) {
            return;
        }
        let table_base = first.loads[slot];
        saw_stride = true;

        // Guard analysis is separate from path emulation, as it is in
        // Ghidra (`analyzeGuards` against `buildAddresses`): the dispatch
        // block computes the target, and the blocks before it decide which
        // indices ever reach the dispatch at all. Emulating both as one
        // window instead measured recall 0.05 against stock on libc, because
        // the guard's own inputs are unknown that early and it escapes at
        // once.
        let mut targets = Vec::new();
        let mut guarded_by_branch = false;
        for index in 0..MAX_TABLE {
            let attempt = run_seed(index);
            if attempt.gave_up || attempt.loads.len() <= slot {
                break;
            }
            // The table is contiguous: an entry read from anywhere else is
            // not this table's, and the walk has left it.
            if attempt.loads[slot] != table_base.wrapping_add(stride.wrapping_mul(index)) {
                break;
            }
            // The guard: a branch taken out of the region means this index
            // never reaches the dispatch at all.
            // Each predecessor is run on its own, with the index seeded at
            // its start: concatenating them means one block's call clears
            // the seed before the next block's comparison reads it.
            let guard_runs: Vec<Run> = guard
                .iter()
                .filter(|block| !block.is_empty())
                .map(|block| run_guard(block, index))
                .collect();
            let escaped = attempt
                .branches
                .iter()
                .chain(guard_runs.iter().flat_map(|run| run.branches.iter()))
                .any(|&(destination, condition)| {
                    condition == Some(1)
                        && destination.is_some_and(|destination| !inside.contains(&destination))
                });
            if escaped {
                guarded_by_branch = true;
                break;
            }
            if trace {
                eprintln!(
                    "    index {index} load {:x?} dest {:x?} exec {:?} guard_gave_up {:?} guard_branches {:x?}",
                    attempt.loads.get(slot),
                    attempt.destination,
                    attempt.destination.map(|a| image.executable(a)),
                    guard_runs.iter().map(|run| run.gave_up).collect::<Vec<_>>(),
                    guard_runs.iter().flat_map(|run| run.branches.clone()).collect::<Vec<_>>(),
                );
            }
            match attempt.destination {
                Some(address) if image.executable(address) => targets.push(address),
                // The first index whose target is not code is one past the
                // end of the table.
                _ => break,
            }
        }
        if targets.len() < 2 {
            return;
        }
        let mut distinct = targets.clone();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() < 2 {
            return;
        }
        let table = SwitchTable {
            branch,
            span: targets.len() as u64,
            targets,
        };
        let slot = if guarded_by_branch {
            &mut guarded
        } else {
            &mut unguarded
        };
        // The longest run wins within a class: a shorter one is the same
        // table cut off by something that was not this dispatch's bound.
        if slot
            .as_ref()
            .is_none_or(|current| current.targets.len() < table.targets.len())
        {
            *slot = Some(table);
        }
    };
    for (space, offset, size) in &dry.live_in {
        if concrete
            .iter()
            .any(|((known_space, known_offset), _)| known_space == space && *known_offset == *offset)
        {
            continue;
        }
        worker(
            Seed::Reg((space.as_str(), *offset, *size)),
            format!("{space}:{offset:x}:{size}"),
        );
    }
    for key in memkeys {
        let label = format!("mem({}:{:x}+{:x})", key.0.0, key.0.1, key.1);
        worker(Seed::Mem(key), label);
    }
    if guarded.is_none() && unguarded.is_none() {
        if !saw_candidate {
            refusals.unmodelled += 1;
        } else if !saw_stride {
            refusals.no_strided_load += 1;
        } else {
            refusals.too_few_targets += 1;
        }
    }
    // The unguarded answer is *recorded* but not returned: measured on
    // libc against truth it scores 0.73 soundness where the guarded answer
    // scores 0.999, and the decompiler path covers those dispatches at
    // 0.98. Keeping it would trade a sound answer for a wrong one.
    let _ = unguarded;
    guarded
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        /// address -> little-endian bytes
        memory: HashMap<u64, Vec<u8>>,
        code: (u64, u64),
    }

    impl Image for Fixture {
        fn read(&self, address: u64, size: u32) -> Option<u64> {
            let bytes = self.memory.get(&address)?;
            if bytes.len() < size as usize {
                return None;
            }
            let mut value = 0u64;
            for (index, byte) in bytes.iter().take(size as usize).enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
            Some(value)
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

    fn op(opcode: &str, out: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOp {
        PcodeOp {
            opcode: opcode.to_string(),
            output: out,
            inputs,
        }
    }

    /// The canonical dispatch: `target = *(table + index * 8)`, then branch.
    fn dispatch() -> Vec<PcodeInstruction> {
        vec![PcodeInstruction {
            address: 0x1000,
            length: 7,
            error: None,
            ops: vec![
                // unique:0x100 = register:0x0 (the index) * 8
                op(
                    "INT_MULT",
                    Some(varnode("unique", 0x100, 8)),
                    vec![varnode("register", 0x0, 8), varnode("const", 8, 8)],
                ),
                // unique:0x108 = unique:0x100 + 0x2000 (the table base)
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x108, 8)),
                    vec![varnode("unique", 0x100, 8), varnode("const", 0x2000, 8)],
                ),
                // unique:0x110 = *unique:0x108
                op(
                    "LOAD",
                    Some(varnode("unique", 0x110, 8)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x108, 8)],
                ),
                op("BRANCHIND", None, vec![varnode("unique", 0x110, 8)]),
            ],
        }]
    }

    fn fixture(entries: &[u64]) -> Fixture {
        let mut memory = HashMap::new();
        for (index, &target) in entries.iter().enumerate() {
            memory.insert(0x2000 + index as u64 * 8, target.to_le_bytes().to_vec());
        }
        Fixture {
            memory,
            code: (0x1000, 0x1800),
        }
    }

    /// The same dispatch with a guard in front of it: `index < bound`, then
    /// a conditional branch away. `compare_index` false bounds an unrelated
    /// register instead, which is the case that must not size this table.
    fn guarded(bound: u64, compare_index: bool) -> Vec<PcodeInstruction> {
        let mut window = dispatch();
        let operand = if compare_index {
            varnode("register", 0x0, 8)
        } else {
            varnode("register", 0x40, 8)
        };
        window[0].ops.splice(
            0..0,
            [
                op(
                    "INT_LESS",
                    Some(varnode("unique", 0x200, 1)),
                    vec![varnode("const", bound, 8), operand],
                ),
                op(
                    "CBRANCH",
                    None,
                    vec![varnode("ram", 0x1700, 8), varnode("unique", 0x200, 1)],
                ),
            ],
        );
        window
    }

    #[test]
    fn a_dispatch_with_no_guard_is_not_answered() {
        // Four code targets and then a word that is not code look like a
        // table ending where its targets stop being code, but nothing
        // states that end. Measured against truth on libc the unguarded
        // answer scores 0.73 soundness where the guarded one scores 0.999,
        // so this is a refusal and the decompiler path (0.98) covers it.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x9999]);
        let mut refusals = Refusals::default();
        assert_eq!(
            recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &dispatch(), &mut refusals),
            None
        );
    }

    #[test]
    fn the_guard_branch_ends_the_table() {
        // The memory after the table holds code addresses too; what says the
        // switch has three cases is that at index 3 the guard branches away.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x1500]);
        let table = recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &guarded(2, true), &mut Refusals::default()).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn a_guard_on_something_else_does_not_size_this_table() {
        // Taking any nearby constant as a bound measured 0.61 edge
        // precision against stock Ghidra on libc: a guard that bounds
        // something other than this index states nothing about this table.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x9999]);
        assert_eq!(
            recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &guarded(2, false), &mut Refusals::default()),
            None
        );
    }

    #[test]
    fn a_repeated_target_is_kept_as_its_own_case() {
        // Two cases that go to the same place are still two cases: the table
        // has an entry each, and a consumer counting edges must see both.
        let image = fixture(&[0x1100, 0x1100, 0x1200, 0x9999]);
        let table = recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &guarded(2, true), &mut Refusals::default()).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1100, 0x1200]);
    }

    #[test]
    fn a_single_target_is_not_a_table() {
        // One case is a computed call or a tail jump, not a switch.
        let image = fixture(&[0x1100, 0x9999]);
        assert_eq!(recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &dispatch(), &mut Refusals::default()), None);
        // The same run of targets repeated is also not a switch: nothing
        // distinguishes the cases.
        let image = fixture(&[0x1100, 0x1100, 0x9999]);
        assert_eq!(recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &dispatch(), &mut Refusals::default()), None);
    }

    #[test]
    fn an_unmodelled_operation_abandons_the_candidate() {
        let mut window = dispatch();
        window[0].ops.insert(
            0,
            op(
                "CALL",
                None,
                vec![varnode("ram", 0x1500, 8)],
            ),
        );
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x9999]);
        assert_eq!(recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &window, &mut Refusals::default()), None);
    }
    /// A PIC jump table: the guard bounds an index that lives in memory,
    /// the table holds 32-bit offsets, and the dispatch adds the base back
    /// (`movsxd; add; jmp`, the shape libc repeats). No register seed can
    /// move the index load; forcing the memory expression can.
    fn pic_dispatch() -> Vec<PcodeInstruction> {
        vec![PcodeInstruction {
            address: 0x1000,
            length: 7,
            error: None,
            ops: vec![
                // unique:0x80 = register:0x10 + 8 (the index address).
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x80, 8)),
                    vec![varnode("register", 0x10, 8), varnode("const", 8, 8)],
                ),
                op(
                    "LOAD",
                    Some(varnode("unique", 0x81, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x80, 8)],
                ),
                op(
                    "COPY",
                    Some(varnode("register", 0, 4)),
                    vec![varnode("unique", 0x81, 4)],
                ),
                op(
                    "INT_ZEXT",
                    Some(varnode("register", 0, 8)),
                    vec![varnode("register", 0, 4)],
                ),
                op(
                    "COPY",
                    Some(varnode("register", 8, 8)),
                    vec![varnode("const", 0x2000, 8)],
                ),
                op(
                    "INT_MULT",
                    Some(varnode("unique", 0x82, 8)),
                    vec![varnode("register", 0, 8), varnode("const", 4, 8)],
                ),
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x83, 8)),
                    vec![varnode("register", 8, 8), varnode("unique", 0x82, 8)],
                ),
                op(
                    "LOAD",
                    Some(varnode("unique", 0x84, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x83, 8)],
                ),
                op(
                    "INT_SEXT",
                    Some(varnode("register", 0, 8)),
                    vec![varnode("unique", 0x84, 4)],
                ),
                op(
                    "INT_ADD",
                    Some(varnode("register", 0, 8)),
                    vec![varnode("register", 0, 8), varnode("register", 8, 8)],
                ),
                op("BRANCHIND", None, vec![varnode("register", 0, 8)]),
            ],
        }]
    }

    fn pic_guard(bound: u64) -> Vec<PcodeInstruction> {
        vec![PcodeInstruction {
            address: 0x900,
            length: 7,
            error: None,
            ops: vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x70, 8)),
                    vec![varnode("register", 0x10, 8), varnode("const", 8, 8)],
                ),
                op(
                    "LOAD",
                    Some(varnode("unique", 0x71, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x70, 8)],
                ),
                op(
                    "INT_LESS",
                    Some(varnode("unique", 0x72, 1)),
                    vec![varnode("const", bound, 8), varnode("unique", 0x71, 4)],
                ),
                op(
                    "CBRANCH",
                    None,
                    vec![varnode("ram", 0x1700, 8), varnode("unique", 0x72, 1)],
                ),
            ],
        }]
    }

    /// Table entries are base-relative signed offsets, below the base here
    /// so the sign extension is load-bearing, not incidental.
    fn pic_fixture(targets: &[u64]) -> Fixture {
        let mut memory = HashMap::new();
        for (index, &target) in targets.iter().enumerate() {
            let offset = target.wrapping_sub(0x2000) as u32;
            memory.insert(0x2000 + index as u64 * 4, offset.to_le_bytes().to_vec());
        }
        Fixture {
            memory,
            code: (0x1000, 0x1800),
        }
    }

    #[test]
    fn a_pic_offset_table_answers_through_the_guard() {
        let image = pic_fixture(&[0x1100, 0x1200, 0x1300, 0x1400]);
        let table = recover(&image, 0x1000, &[pic_guard(2)], &pic_dispatch(), &mut Refusals::default())
            .expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn a_pic_offset_table_without_a_guard_is_not_answered() {
        // The offsets read past the table without a bound, and an unguarded
        // answer is what the 0.73-soundness fallback refuses.
        let image = pic_fixture(&[0x1100, 0x1200, 0x1300, 0x1400]);
        assert_eq!(
            recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &pic_dispatch(), &mut Refusals::default()),
            None
        );
    }

    #[test]
    fn an_index_spilled_to_memory_and_reloaded_still_follows() {
        // The index goes to the stack and comes back before the load, which
        // is what an unoptimised build does. The guard still bounds it.
        let mut window = guarded(2, true);
        let ops = &mut window[0].ops;
        ops.insert(
            0,
            op(
                "STORE",
                None,
                vec![
                    varnode("const", 0x1b1, 4),
                    varnode("const", 0x8000, 8),
                    varnode("register", 0x0, 8),
                ],
            ),
        );
        ops.insert(
            1,
            op(
                "LOAD",
                Some(varnode("register", 0x0, 8)),
                vec![varnode("const", 0x1b1, 4), varnode("const", 0x8000, 8)],
            ),
        );
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x9999]);
        let table = recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &window, &mut Refusals::default()).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }
}
