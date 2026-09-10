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
        if op.opcode == "CBRANCH" {
            // input 0 is the destination, input 1 the condition.
            let destination = op.inputs.first().map(|input| input.offset);
            let condition = inputs.get(1).copied().flatten();
            self.branches.push((destination, condition));
        }
        let value: Known = match op.opcode.as_str() {
            "COPY" | "CAST" => a,
            "LOAD" => {
                // input 0 names the space, input 1 is the offset.
                let address = inputs.get(1).copied().flatten();
                if let Some(address) = address {
                    self.loads.push(address);
                }
                address.and_then(|address| self.load(address, size))
            }
            "STORE" => {
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
            "INT_ADD" => match (a, b) {
                (Some(a), Some(b)) => Some(a.wrapping_add(b)),
                _ => None,
            },
            "INT_SUB" => match (a, b) {
                (Some(a), Some(b)) => Some(a.wrapping_sub(b)),
                _ => None,
            },
            "INT_MULT" => match (a, b) {
                (Some(a), Some(b)) => Some(a.wrapping_mul(b)),
                _ => None,
            },
            "INT_DIV" => match (a, b) {
                (Some(a), Some(b)) if b != 0 => Some(a / b),
                _ => None,
            },
            "INT_REM" => match (a, b) {
                (Some(a), Some(b)) if b != 0 => Some(a % b),
                _ => None,
            },
            "INT_AND" => match (a, b) {
                (Some(a), Some(b)) => Some(a & b),
                _ => None,
            },
            "INT_OR" => match (a, b) {
                (Some(a), Some(b)) => Some(a | b),
                _ => None,
            },
            "INT_XOR" => match (a, b) {
                (Some(a), Some(b)) => Some(a ^ b),
                _ => None,
            },
            "INT_LEFT" => match (a, b) {
                (Some(a), Some(b)) if b < 64 => Some(a << b),
                (Some(_), Some(_)) => Some(0),
                _ => None,
            },
            "INT_RIGHT" => match (a, b) {
                (Some(a), Some(b)) if b < 64 => Some(a >> b),
                (Some(_), Some(_)) => Some(0),
                _ => None,
            },
            "INT_SRIGHT" => match (a, b) {
                (Some(a), Some(b)) if b < 64 => {
                    let width = op.inputs.first().map_or(8, |input| input.size);
                    Some(((sign_extend(a, width) as i64) >> b) as u64)
                }
                _ => None,
            },
            "INT_NEGATE" => a.map(|a| !a),
            "INT_2COMP" => a.map(|a| a.wrapping_neg()),
            "INT_ZEXT" => a,
            "INT_SEXT" => {
                let width = op.inputs.first().map_or(8, |input| input.size);
                a.map(|a| sign_extend(a, width))
            }
            "SUBPIECE" => match (a, b) {
                (Some(a), Some(shift)) => Some(a >> (shift * 8)),
                _ => None,
            },
            "PIECE" => match (a, b) {
                (Some(high), Some(low)) => {
                    let low_width = op.inputs.get(1).map_or(0, |input| input.size);
                    Some((high << (low_width * 8)) | low)
                }
                _ => None,
            },
            "INT_EQUAL" => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a == b)),
                _ => None,
            },
            "INT_NOTEQUAL" => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a != b)),
                _ => None,
            },
            "INT_LESS" => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a < b)),
                _ => None,
            },
            "INT_LESSEQUAL" => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a <= b)),
                _ => None,
            },
            "INT_SLESS" | "INT_SLESSEQUAL" => match (a, b) {
                (Some(a), Some(b)) => {
                    let width = op.inputs.first().map_or(8, |input| input.size);
                    let (a, b) = (sign_extend(a, width) as i64, sign_extend(b, width) as i64);
                    Some(u64::from(if op.opcode == "INT_SLESS" {
                        a < b
                    } else {
                        a <= b
                    }))
                }
                _ => None,
            },
            "BOOL_AND" => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a != 0 && b != 0)),
                _ => None,
            },
            "BOOL_OR" => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from(a != 0 || b != 0)),
                _ => None,
            },
            "BOOL_XOR" => match (a, b) {
                (Some(a), Some(b)) => Some(u64::from((a != 0) ^ (b != 0))),
                _ => None,
            },
            "BOOL_NEGATE" => a.map(|a| u64::from(a == 0)),
            "POPCOUNT" => a.map(|a| u64::from(a.count_ones())),
            // Recorded above; a conditional branch inside the window is the
            // guard, not a reason to abandon the path.
            "CBRANCH" => None,
            "BRANCHIND" | "CALLIND" | "RETURN" => {
                // The window's whole purpose: the destination this indirect
                // transfer computed.
                return a;
            }
            // A call returns knowing nothing about the caller-saved
            // registers, and this emulator does not model an ABI, so after
            // one nothing is known at all. Clearing is the conservative
            // reading; keeping the old values would let a stale register
            // produce a target that the machine never computes.
            "CALL" | "CALLIND" | "CALLOTHER" => {
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
            "BRANCH" => None,
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
) -> Run {
    run_with(image, window, seed, false)
}

fn run_with<I: Image>(
    image: &I,
    window: &[PcodeInstruction],
    seed: Option<((&str, u64, u32), u64)>,
    pinned: bool,
) -> Run {
    let mut machine = Machine::new(image);
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
    let dry = run(image, window, None);
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
    for (space, offset, size) in &dry.live_in {
        let candidate = (space.as_str(), *offset, *size);
        // A switch reads its targets out of a table, so the run must contain
        // a load whose address moves with the index by a fixed stride. That
        // single requirement is what separates a table from a register
        // sweep: without it, feeding indices to any live register produces
        // "targets" wherever the arithmetic happens to land in code, which
        // measured 0.42 edge precision against stock Ghidra on libc.
        let first = run(image, window, Some((candidate, 0)));
        let second = run(image, window, Some((candidate, 1)));
        if first.gave_up || second.gave_up {
            continue;
        }
        saw_candidate = true;
        if trace {
            eprintln!(
                "  candidate {}:{:x}:{} loads0 {:x?} loads1 {:x?} dest0 {:x?} dest1 {:x?}",
                space, offset, size, first.loads, second.loads, first.destination, second.destination
            );
        }
        if first.loads.len() != second.loads.len() {
            continue;
        }
        let Some(slot) = first
            .loads
            .iter()
            .zip(&second.loads)
            .position(|(a, b)| a != b)
        else {
            continue;
        };
        // Everything before the table read must be index-independent, and
        // the read itself must advance by one element.
        if first.loads[..slot] != second.loads[..slot] {
            continue;
        }
        let stride = second.loads[slot].wrapping_sub(first.loads[slot]);
        if !matches!(stride, 1 | 2 | 4 | 8 | 16) {
            continue;
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
        let inside: std::collections::HashSet<u64> = guard
            .iter()
            .flatten()
            .chain(window.iter())
            .map(|instruction| instruction.address)
            .collect();
        let mut targets = Vec::new();
        let mut guarded_by_branch = false;
        for index in 0..MAX_TABLE {
            let attempt = run(image, window, Some((candidate, index)));
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
                .map(|block| run_with(image, block, Some((candidate, index)), true))
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
            continue;
        }
        let mut distinct = targets.clone();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() < 2 {
            continue;
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
