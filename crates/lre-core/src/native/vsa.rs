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
    /// True once an operation the emulator does not model was reached, which
    /// invalidates the run rather than the whole recovery.
    gave_up: bool,
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
            gave_up: false,
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
            // Flags and carries are computed and never read by a dispatch;
            // modelling them wrongly would be worse than not at all.
            "INT_CARRY" | "INT_SCARRY" | "INT_SBORROW" => None,
            // A call, a branch, or anything else in the window means this is
            // not a straight-line dispatch path.
            _ => {
                self.gave_up = true;
                None
            }
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
    let mut machine = Machine::new(image);
    if let Some(((space, offset, size), value)) = seed {
        machine
            .state
            .insert((space, offset), (value & mask(size), size));
    }
    let mut destination = None;
    for instruction in window {
        for op in &instruction.ops {
            if let Some(address) = machine.step(op) {
                destination = Some(address);
            }
            if machine.gave_up {
                break;
            }
        }
        if machine.gave_up {
            break;
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
    guard: &[PcodeInstruction],
    window: &[PcodeInstruction],
    unguarded: bool,
) -> Option<SwitchTable> {
    if window.is_empty() {
        return None;
    }
    // One dry run: what does the window read that it never wrote? Those are
    // the only places a switch variable can come from.
    let dry = run(image, window, None);
    if dry.live_in.is_empty() {
        return None;
    }
    // A guard states the range; the code-bounded walk is only what to do
    // when no guard was found. Ghidra keeps these apart the same way: the
    // range comes from `analyzeGuards`, and `maxtablesize` is a cap on it,
    // never a competitor.
    let unguarded_allowed = unguarded;
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
        if first.gave_up || second.gave_up || first.loads.len() != second.loads.len() {
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

        // Guard analysis is separate from path emulation, as it is in
        // Ghidra (`analyzeGuards` against `buildAddresses`): the dispatch
        // block computes the target, and the blocks before it decide which
        // indices ever reach the dispatch at all. Emulating both as one
        // window instead measured recall 0.05 against stock on libc, because
        // the guard's own inputs are unknown that early and it escapes at
        // once.
        let inside: std::collections::HashSet<u64> = guard
            .iter()
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
            let guard_run = (!guard.is_empty()).then(|| run(image, guard, Some((candidate, index))));
            let escaped = attempt
                .branches
                .iter()
                .chain(guard_run.iter().flat_map(|run| run.branches.iter()))
                .any(|&(destination, condition)| {
                    condition == Some(1)
                        && destination.is_some_and(|destination| !inside.contains(&destination))
                });
            if escaped {
                guarded_by_branch = true;
                break;
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
    // Without a guard the table's end is not stated anywhere: the entries
    // that follow it are other data, and a relative entry read out of them
    // still lands in code often enough to look like a case. Measured against
    // stock Ghidra on libc, keeping those cost more precision than the extra
    // branches were worth, so they are opt-in and the decompiler path gets
    // them by default.
    guarded.or(if unguarded_allowed { unguarded } else { None })
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

    #[test]
    fn it_recovers_a_table_bounded_by_its_own_targets() {
        // Four code targets, then a word that is not code: the table ends
        // where the targets stop being code, with no guard at all.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x9999]);
        let table = recover(&image, 0x1000, &[], &dispatch(), true).expect("table");
        assert_eq!(table.branch, 0x1000);
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300, 0x1400]);
        assert_eq!(table.span, 4);
    }

    /// `dispatch` with the guard a compiler emits in front of it:
    /// `cmp $n,%reg; ja default`, which in p-code is a comparison feeding a
    /// CBRANCH out of the dispatch block.
    fn guarded(bound: u64, compare_index: bool) -> Vec<PcodeInstruction> {
        let mut window = dispatch();
        let operand = if compare_index {
            varnode("register", 0x0, 8)
        } else {
            // Some other value entirely: this guard bounds something that is
            // not the switch variable.
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
    fn the_guard_branch_ends_the_table() {
        // The memory after the table holds code addresses too; what says the
        // switch has three cases is that at index 3 the guard branches away.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x1500]);
        let table = recover(&image, 0x1000, &[], &guarded(2, true), true).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn a_guard_on_something_else_does_not_size_this_table() {
        // Taking any nearby constant as a bound measured 0.61 edge precision
        // against stock Ghidra on libc; the guard has to be the one that
        // moves with this index.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x9999]);
        let table = recover(&image, 0x1000, &[], &guarded(2, false), true).expect("table");
        assert_eq!(
            table.targets,
            vec![0x1100, 0x1200, 0x1300, 0x1400],
            "the table ends where its targets stop being code"
        );
        // With no unguarded fallback allowed, nothing is claimed at all.
        assert_eq!(recover(&image, 0x1000, &[], &guarded(2, false), false), None);
    }

    #[test]
    fn a_repeated_target_is_kept_as_its_own_case() {
        let image = fixture(&[0x1100, 0x1100, 0x1200, 0x9999]);
        let table = recover(&image, 0x1000, &[], &dispatch(), true).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1100, 0x1200]);
    }

    #[test]
    fn a_single_target_is_not_a_table() {
        // One case is a computed call or a tail jump, not a switch.
        let image = fixture(&[0x1100, 0x9999]);
        assert_eq!(recover(&image, 0x1000, &[], &dispatch(), true), None);
        // The same run of targets repeated is also not a switch: nothing
        // distinguishes the cases.
        let image = fixture(&[0x1100, 0x1100, 0x9999]);
        assert_eq!(recover(&image, 0x1000, &[], &dispatch(), true), None);
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
        assert_eq!(recover(&image, 0x1000, &[], &window, true), None);
    }

    #[test]
    fn an_index_spilled_to_memory_and_reloaded_still_follows() {
        // The index goes to the stack and comes back before the load, which
        // is what an unoptimised build does.
        let mut window = dispatch();
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
        let table = recover(&image, 0x1000, &[], &window, true).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }
}
