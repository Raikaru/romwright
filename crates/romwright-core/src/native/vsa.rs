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
//! 1. take a straight line of instructions that ends at the indirect branch:
//!    its basic block with each predecessor block run on its own, then each
//!    predecessor (or single-predecessor chain of up to two guards) and the
//!    block as one line, then shorter suffixes of the block;
//! 2. find the switch variable -- a value the line reads but never writes,
//!    a memory expression it loads, or (for a suffix) a value it computes --
//!    and the guard that sends it away from the dispatch;
//! 3. emulate the line once per index value, reading the image for every
//!    load, and collect the targets in index order, below zero too where
//!    the guards admit it.
//!
//! What moves with the index is either a table read (a load whose address
//! advances by one element) or, where nothing is read, the destination
//! itself (`addls pc,pc,r0,lsl #2` over a run of `b case`). The answer is
//! the decompiler's to the entry: the guard's target follows the cases
//! wherever Ghidra folds it in (`JumpBasic::foldInOneGuard`), and a table
//! whose folded default depends on code not decoded yet is left to the
//! decompiler. Measured against the decompiler's tables for the same
//! branches on the eight console images (STATUS.md, 2026-10-07).
//!
//! Nothing here is speculative: a target is kept only when it lands in
//! executable memory that the image actually maps, a table is reported
//! only when a guard ends it and it has at least two distinct targets.
//! Where the emulator meets an operation it does not model, the value
//! becomes unknown and the candidate is abandoned rather than guessed.

use std::collections::HashMap;


use crate::native_runtime::{PcodeInstruction, PcodeOp, PcodeVarnode};

/// Why a dispatch was not answered. Counted per import so the gap between
/// this pass and the decompiler is attributable rather than guessed at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refusals {
    /// Nothing the window read was a value it did not also write.
    pub no_live_in: usize,
    /// Nothing before the branch tests anything, so no guard bounds it.
    pub no_guard: usize,
    /// No load moved with the index, so nothing here reads a table.
    pub no_strided_load: usize,
    /// A table was found but had fewer than two distinct case targets.
    pub too_few_targets: usize,
    /// A table was found, but no guard ended it.
    pub unguarded: usize,
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
    /// How many cases the switch variable ran over.
    pub span: u64,
}

/// What the emulator knows about one location.
type Known = Option<u64>;

/// One conditional branch a run executed.
#[derive(Clone, Copy, Debug)]
struct Exit {
    /// Where it goes when taken; none for a skip within its instruction.
    destination: Option<u64>,
    /// Whether it was taken, when known.
    condition: Known,
    /// Where it goes when not taken: the next instruction, or its own
    /// address when more of its p-code follows (a conditional return).
    fallthrough: Option<u64>,
}

/// What emulating one index value found.
enum Probe {
    /// The dispatch went to this case target.
    Case(u64),
    /// A guard sent the index away.
    Escape,
    /// The table ended: the read left it, or the target is not code.
    End,
}

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
    /// `address` as the address space holds it. A 64-bit PowerPC with
    /// 32-bit addressing (`PowerPC:BE:64:Xenon-32addr`) builds addresses
    /// in 64-bit registers -- `lis` sign-extends -- and its loads and
    /// branches use the low 32 bits, as Ghidra's `AddrSpace::wrapOffset`
    /// does.
    fn wrap(&self, address: u64) -> u64 {
        address
    }
    /// The target is big-endian: a narrower piece of a register is its
    /// high-order end at the same offset.
    fn big_endian(&self) -> bool {
        false
    }
    /// The instruction at `address` is a direct call. A guard that falls
    /// into one (`bls dispatch; bl default`, agbcc's long branch) bounds
    /// nothing: the call returns into the dispatch with the index register
    /// clobbered or not, so every index still reaches the table.
    fn is_call(&self, _address: u64) -> bool {
        false
    }
    /// The registers a call leaves as it found them, as register-space
    /// `(offset, size)` (`SleighLifter::unaffected`: the compiler spec's
    /// `<unaffected>` list). Empty when the image does not say, which makes
    /// every call forget every register.
    fn unaffected(&self) -> &[(u64, u32)] {
        &[]
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
type DefMap = Fast<(String, u64), Def>;

/// The emulator's maps are hashed per p-code op of every run; SipHash's
/// cost showed in profiles of a console import. Keys are addresses and
/// space names the image itself supplies, so collision resistance buys
/// nothing here.
type Fast<K, V> = HashMap<K, V, std::hash::BuildHasherDefault<Fx>>;

/// FxHash's mixing step (rotate, xor, multiply).
#[derive(Default, Clone, Copy)]
struct Fx(u64);

impl std::hash::Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_u64(u64::from(byte));
        }
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

/// How `op` defines its output, as far as memory expressions care.
fn def_of(op: &PcodeOp) -> Option<Def> {
    let slot = |v: &PcodeVarnode| (v.space.clone(), v.offset);
    match op.opcode.parse::<crate::ir::Opcode>().unwrap_or(crate::ir::Opcode::Other) {
        crate::ir::Opcode::IntAdd if op.inputs.len() >= 2 => {
            let (a, b) = (&op.inputs[0], &op.inputs[1]);
            match (a.is_const(), b.is_const()) {
                (true, true) => Some(Def::Const { value: a.offset.wrapping_add(b.offset) }),
                (true, false) => Some(Def::AddConst { base: slot(b), disp: a.offset }),
                (false, true) => Some(Def::AddConst { base: slot(a), disp: b.offset }),
                (false, false) => None,
            }
        }
        crate::ir::Opcode::Copy | crate::ir::Opcode::Cast if op.inputs.len() == 1 => {
            if op.inputs[0].is_const() {
                Some(Def::Const { value: op.inputs[0].offset })
            } else {
                Some(Def::Copy { from: slot(&op.inputs[0]) })
            }
        }
        _ => None,
    }
}

/// Records `op`'s definition in a map that follows a straight line in
/// order, so each use resolves through the definition that reaches it:
/// `unique` temporaries are reused by every instruction, and a register a
/// guard block recomputes before the dispatch has more than one meaning
/// along the line but exactly one at each point of it.
fn define(defs: &mut DefMap, op: &PcodeOp) {
    let Some(out) = op.output.as_ref().filter(|out| !out.is_const()) else {
        return;
    };
    let slot = (out.space.clone(), out.offset);
    match def_of(op) {
        Some(def) => {
            defs.insert(slot, def);
        }
        None => {
            defs.remove(&slot);
        }
    }
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
    let mut defs = DefMap::default();
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
                if let Some(def) = def_of(op) {
                    defs.insert((out.space.clone(), out.offset), def);
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
    state: Fast<(&'a str, u64), (u64, u32)>,
    /// Locations only some of whose bits are known, as `(value, known
    /// mask, width)`: a PowerPC compare packs its result into a CR field
    /// beside the summary-overflow bit nothing here knows, and the branch
    /// then extracts one known bit (`cmplwi; bgtlr`). Only the bitwise
    /// operations and shifts produce or consume these; a fully known
    /// result moves to `state`.
    partial: Fast<(&'a str, u64), (u64, u64, u32)>,
    /// Values stored to memory during the window, so an index spilled to the
    /// stack and reloaded still follows.
    stored: Fast<u64, (u64, u32)>,
    /// Persistent locations the window read before ever writing them: the
    /// candidates for the switch variable.
    live_in: Vec<(&'a str, u64, u32)>,
    /// Every conditional branch executed, in order. The guard that bounds a
    /// switch is one of these -- the range is where it starts sending the
    /// index to the default case, which is what `JumpBasic::analyzeGuards`
    /// establishes on the SSA path and what this establishes by running it.
    branches: Vec<Exit>,
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
    /// False while a pinned seed waits for its definition: the index is not
    /// there yet, so a call before that point changes nothing it holds.
    seed_installed: bool,
    /// The definitions reaching the current op, output slot to defining
    /// shape, kept in order as the run steps (`define`): resolving a
    /// load's address through them names the memory the slice reads by
    /// structure instead of by an address it cannot know.
    defs: DefMap,
    /// A memory expression forced to one index value for this run.
    forced: Option<(MemKey, u64)>,
    /// Registers a call leaves as it found them (`SleighLifter::unaffected`),
    /// as register-space `(offset, size)`. Empty unless a run asks for the
    /// ABI: `entry_facts`.
    kept: &'a [(u64, u32)],
}

impl<'a, I: Image> Machine<'a, I> {
    fn new(image: &'a I) -> Self {
        Self {
            image,
            state: Fast::default(),
            partial: Fast::default(),
            stored: Fast::default(),
            live_in: Vec::new(),
            branches: Vec::new(),
            loads: Vec::new(),
            preserve: None,
            gave_up: false,
            pinned: false,
            seed_installed: true,
            defs: DefMap::default(),
            forced: None,
            kept: image.unaffected(),
        }
    }

    fn read(&mut self, varnode: &'a PcodeVarnode) -> Known {
        if varnode.is_const() {
            return Some(varnode.offset & mask(varnode.size));
        }
        let key = (varnode.space.as_str(), varnode.offset);
        if !self.state.contains_key(&key) && !self.partial.contains_key(&key)
            && let Some(value) = self.enclosing(varnode) {
                return Some(value);
            }
        match self.state.get(&key) {
            Some(&(value, size)) if varnode.size <= size => {
                // A narrower read takes the low-order bytes on a
                // little-endian target and the high-order ones on a
                // big-endian one.
                let shift = if self.image.big_endian() { (size - varnode.size) * 8 } else { 0 };
                Some((value >> shift.min(63)) & mask(varnode.size))
            }
            Some(_) => None,
            // Written, but only partly known: not a live-in, and known
            // when the bits read are.
            None if self.partial.contains_key(&(varnode.space.as_str(), varnode.offset)) => {
                let (value, known) = self.bits(varnode);
                (known == mask(varnode.size)).then_some(value)
            }
            // A direct read of code memory is a literal pool (`ldr r1,[pc,
            // #8]` lifts to a COPY from `ram`): its value is the image's.
            // Other memory a direct read names is a variable, unknown here.
            None if varnode.space == "ram" && self.image.executable(varnode.offset) => self
                .image
                .read(varnode.offset, varnode.size)
                .map(|value| value & mask(varnode.size)),
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
    fn key_of(&self, varnode: &PcodeVarnode) -> Option<MemKey> {
        resolve_key(&self.defs, varnode)
    }

    /// A narrower register read out of a wider value written whole: the
    /// low word of a 64-bit PowerPC register is `register:5c:4` inside
    /// `register:58:8`, which is where `cmplwi` reads what `lbz` wrote.
    fn enclosing(&self, varnode: &PcodeVarnode) -> Option<u64> {
        if varnode.space != "register" {
            return None;
        }
        let (start, end) = (varnode.offset, varnode.offset + u64::from(varnode.size));
        self.state.iter().find_map(|(&(space, offset), &(value, size))| {
            let outer = offset + u64::from(size);
            if space != "register" || offset > start || outer < end || (offset, outer) == (start, end) {
                return None;
            }
            let shift = if self.image.big_endian() { outer - end } else { start - offset };
            Some((value >> (shift * 8).min(63)) & mask(varnode.size))
        })
    }

    /// Writes `value` with the bits in `known` known. A fully known value
    /// goes to `state`; a partly known one to `partial`; nothing known
    /// clears both.
    fn write_bits(&mut self, varnode: &'a PcodeVarnode, value: u64, known: u64) {
        if self.pinned
            && self.preserve == Some((varnode.space.as_str(), varnode.offset))
        {
            return;
        }
        let key = (varnode.space.as_str(), varnode.offset);
        let width = mask(varnode.size);
        let known = known & width;
        // A register write ends whatever overlapping location was known.
        if varnode.space == "register" {
            let (start, end) = (varnode.offset, varnode.offset + u64::from(varnode.size));
            let held = if self.pinned { self.preserve } else { None };
            let keep = move |(space, offset): (&str, u64), size: u32| {
                space != "register"
                    || offset == start
                    || offset + u64::from(size) <= start
                    || offset >= end
                    || held == Some((space, offset))
            };
            self.state.retain(|&key, &mut (_, size)| keep(key, size));
            self.partial.retain(|&key, &mut (_, _, size)| keep(key, size));
        }
        self.partial.remove(&key);
        if known == width {
            self.state.insert(key, (value & width, varnode.size));
        } else {
            self.state.remove(&key);
            if known != 0 {
                self.partial.insert(key, (value & known, known, varnode.size));
            }
        }
    }

    fn write(&mut self, varnode: &'a PcodeVarnode, value: Known) {
        match value {
            Some(value) => self.write_bits(varnode, value, u64::MAX),
            None => self.write_bits(varnode, 0, 0),
        }
    }

    /// What is known of `varnode`'s bits, as `(value, known mask)`; the
    /// value's unknown bits are zero.
    fn bits(&self, varnode: &'a PcodeVarnode) -> (u64, u64) {
        let width = mask(varnode.size);
        if varnode.is_const() {
            return (varnode.offset & width, width);
        }
        let key = (varnode.space.as_str(), varnode.offset);
        match self.state.get(&key) {
            Some(&(value, size)) if varnode.size <= size => return (value & width, width),
            Some(_) => return (0, 0),
            None => {}
        }
        match self.partial.get(&key) {
            Some(&(value, known, size)) if varnode.size <= size => (value & width, known & width),
            _ => (0, 0),
        }
    }

    /// The known bits of a bitwise operation or shift whose inputs are
    /// only partly known; nothing for any other operation.
    fn partial_result(&self, opcode: crate::ir::Opcode, op: &'a PcodeOp) -> Option<(u64, u64)> {
        use crate::ir::Opcode as O;
        let out = op.output.as_ref()?;
        let width = mask(out.size);
        let first = op.inputs.first()?;
        let (a, known_a) = self.bits(first);
        let shift = || {
            let amount = op.inputs.get(1)?;
            let (value, known) = self.bits(amount);
            (known == mask(amount.size)).then_some(value)
        };
        let (value, known) = match opcode {
            O::Copy | O::IntZExt => (a, known_a | (width & !mask(first.size))),
            O::IntAnd | O::IntOr => {
                let (b, known_b) = self.bits(op.inputs.get(1)?);
                if opcode == O::IntAnd {
                    // A bit is known where both are, or where either is a
                    // known zero.
                    let known = (known_a & known_b) | (known_a & !a) | (known_b & !b);
                    (a & b, known)
                } else {
                    // ... or where either is a known one.
                    let known = (known_a & known_b) | (known_a & a) | (known_b & b);
                    (a | b, known)
                }
            }
            // A sum's or difference's low bits are known up to the lowest
            // bit either input leaves unknown: a carry or borrow only moves
            // upwards (`sub sb,r8,#4` of an `r8` aligned to 8).
            O::IntAdd | O::IntSub => {
                let (b, known_b) = self.bits(op.inputs.get(1)?);
                let low = (known_a & known_b).trailing_ones();
                let known = if low >= 64 { u64::MAX } else { (1u64 << low) - 1 };
                let value = if opcode == O::IntAdd { a.wrapping_add(b) } else { a.wrapping_sub(b) };
                (value, known)
            }
            O::IntLeft => match shift()? {
                s if s >= 64 => (0, u64::MAX),
                s => (a << s, (known_a << s) | ((1u64 << s) - 1)),
            },
            O::IntRight => match shift()? {
                s if s >= 64 => (0, u64::MAX),
                s => {
                    let input = mask(first.size);
                    (a >> s, (known_a >> s) | (input & !(input >> s)) | !input)
                }
            },
            O::Subpiece => match shift()?.saturating_mul(8) {
                s if s >= 64 => (0, u64::MAX),
                s => (a >> s, known_a >> s),
            },
            _ => return None,
        };
        let known = known & width;
        Some((value & known, known))
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
            // input 0 is the destination, input 1 the condition. A
            // constant-space destination is a p-code-relative skip within
            // the instruction, not an address.
            let destination = op
                .inputs
                .first()
                .filter(|input| !input.is_const())
                .map(|input| input.offset);
            let condition = inputs.get(1).copied().flatten();
            self.branches.push(Exit { destination, condition, fallthrough: None });
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
                        let address =
                            inputs.get(1).copied().flatten().map(|address| self.image.wrap(address));
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
            // Flag computations a compare or an add leaves for the guard.
            O::IntCarry | O::IntSCarry | O::IntSBorrow => match (a, b) {
                (Some(a), Some(b)) => {
                    let width = op.inputs.first().map_or(8, |input| input.size);
                    let bits = width * 8;
                    Some(u64::from(match opcode {
                        O::IntCarry => a.checked_add(b).is_none_or(|sum| sum & !mask(width) != 0),
                        _ => {
                            let (a, b) = (
                                (sign_extend(a, width) as i64) << (64 - bits),
                                (sign_extend(b, width) as i64) << (64 - bits),
                            );
                            if opcode == O::IntSCarry {
                                a.checked_add(b).is_none()
                            } else {
                                a.checked_sub(b).is_none()
                            }
                        }
                    }))
                }
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
                return a.map(|address| self.image.wrap(address));
            }
            // A call returns knowing nothing about the caller-saved
            // registers, and this emulator does not model an ABI, so after
            // one nothing is known at all. Clearing is the conservative
            // reading; keeping the old values would let a stale register
            // produce a target that the machine never computes.
            // A user-defined operation (`CALLOTHER`) is not a call: SLEIGH
            // gives it no way to write anything but its own output, which
            // the catch-all below leaves unknown. Thumb-2 `tbh` sets the
            // Thumb bit through one in the middle of its dispatch.
            O::Call => {
                let preserved = self.preserve;
                let unaffected = self.kept;
                let survives = move |space: &str, offset: u64, size: u32| {
                    space == "register"
                        && unaffected.iter().any(|&(start, width)| {
                            offset >= start && offset + u64::from(size) <= start + u64::from(width)
                        })
                };
                self.state.retain(|&(space, offset), &mut (_, size)| {
                    preserved == Some((space, offset)) || survives(space, offset, size)
                });
                self.partial
                    .retain(|&(space, offset), &mut (_, _, size)| survives(space, offset, size));
                // A run seeded in a register the ABI leaves unaffected (`s0`
                // on MIPS, `r4`-`r11` on ARM) still holds its index after the
                // call, and what the call did clear reads as unknown from
                // here, which no target comes out of. Any other run is
                // abandoned: a seed the call may have changed means nothing
                // past it (God Hand 0x2ad018: `sra s0,a3,24; jal; sltiu
                // v0,s0,7; ...; jr a0`, the way in from the function entry).
                let seed_safe = preserved.is_some_and(|(space, offset)| {
                    !self.seed_installed || survives(space, offset, 1)
                });
                if !seed_safe {
                    self.gave_up = true;
                }
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
            match value {
                Some(value) => self.write(out, Some(value)),
                None => match self.partial_result(opcode, op) {
                    Some((value, known)) => self.write_bits(out, value, known),
                    None => self.write(out, None),
                },
            }
        }
        define(&mut self.defs, op);
        None
    }
}

/// Emulates `window` once, with `seed` installed as the switch variable, and
/// returns the destination the indirect branch computed.
struct Run {
    destination: Option<u64>,
    live_in: Vec<(String, u64, u32)>,
    loads: Vec<u64>,
    branches: Vec<Exit>,
    gave_up: bool,
}

fn run<I: Image>(
    image: &I,
    window: &[PcodeInstruction],
    seed: Option<((&str, u64, u32), u64)>,
    mem: Option<(MemKey, u64)>,
    concrete: &[((String, u64), u64)],
) -> Run {
    run_with(image, window, seed, mem, concrete, None)
}

fn run_with<I: Image>(
    image: &I,
    window: &[PcodeInstruction],
    seed: Option<((&str, u64, u32), u64)>,
    mem: Option<(MemKey, u64)>,
    concrete: &[((String, u64), u64)],
    pinned: Option<usize>,
) -> Run {
    let mut machine = Machine::new(image);
    machine.forced = mem;
    for ((space, offset), value) in concrete {
        machine
            .state
            .insert((space.as_str(), *offset), (*value, 8));
    }
    // A guard block seeds the index where the block last defines it: a
    // chain of guard blocks can test the same register before an earlier
    // block redefines it (`cmp r3,#5; ...; subs r3,r2,#1; cmp r3,#11;
    // bhi`), and only the last definition is the value the dispatch reads.
    // Holding the seed through that definition is what lets a block that
    // recomputes the index (`mov 0x4(%rbx),%edx; sub $0x3,%edx; cmp`)
    // compare the seeded value.
    let mut install_after: Option<(usize, usize)> = None;
    if let Some(((space, offset, size), value)) = seed {
        if let Some(pinned_length) = pinned {
            let end = offset + u64::from(size);
            for (position, instruction) in window.iter().enumerate().take(pinned_length) {
                for (index, op) in instruction.ops.iter().enumerate() {
                    if op.output.as_ref().is_some_and(|out| {
                        out.space == space && out.offset < end && out.offset + u64::from(out.size) > offset
                    }) {
                        install_after = Some((position, index));
                    }
                }
            }
        }
        if install_after.is_none() {
            machine
                .state
                .insert((space, offset), (value & mask(size), size));
        }
        machine.preserve = Some((space, offset));
        machine.pinned = pinned.is_some();
        machine.seed_installed = install_after.is_none();
    }
    // The destination is the last instruction's: a composed path carries
    // its guard block's own exits (a conditional return's RETURN), and the
    // value one of those computes is not where the dispatch goes.
    let mut destination = None;
    let last = window.len().saturating_sub(1);
    for (position, instruction) in window.iter().enumerate() {
        // Only the line's leading part (a composed line's guard) holds the
        // index where its last definition left it; the dispatch block after
        // it computes with the value as it goes.
        if pinned == Some(position) {
            machine.pinned = false;
        }
        // A p-code-relative branch whose condition is known skips the ops
        // it jumps over (ARM conditional execution: `popeq {..,pc}` on a
        // non-zero index leaves r6 and pc alone). One whose condition is
        // not known runs the body, and afterwards each register keeps only
        // what it shares with the state before the body.
        let mut skip_to: Option<usize> = None;
        let mut unsure: Option<Facts> = None;
        for (index, op) in instruction.ops.iter().enumerate() {
            if skip_to.is_some_and(|to| index < to) {
                continue;
            }
            let exits = machine.branches.len();
            if let Some(address) = machine.step(op)
                && position == last {
                    destination = Some(address);
                }
            if install_after == Some((position, index)) {
                machine.seed_installed = true;
                if let Some(((space, offset, size), value)) = seed {
                    let value = value & mask(size);
                    machine.state.insert((space, offset), (value, size));
                    // The definition widens the slot (`INT_SEXT r:4 -> r:8`, a
                    // MIPS64 register after a 32-bit result): the wider view
                    // is the same index, extended as the definition extends.
                    if let Some(out) = op.output.as_ref().filter(|out| {
                        out.space == space && out.offset == offset && out.size > size && out.size <= 8
                    }) {
                        match op.opcode.parse::<crate::ir::Opcode>() {
                            Ok(crate::ir::Opcode::IntSExt) => {
                                machine.state.insert((space, offset), (sign_extend(value, size) & mask(out.size), out.size));
                            }
                            Ok(crate::ir::Opcode::IntZExt) => {
                                machine.state.insert((space, offset), (value, out.size));
                            }
                            _ => {}
                        }
                    }
                }
            }
            if machine.branches.len() > exits {
                let next = instruction.address.wrapping_add(u64::from(instruction.length));
                // A p-code-relative skip past the instruction's last op is
                // a branch to the next instruction (ARM conditional
                // execution: `ldrls pc,[...]` skips itself when not LS);
                // one that lands inside the instruction leaves nothing.
                let skip_out = op.inputs.first().filter(|input| input.is_const()).map(|input| {
                    let delta = sign_extend(input.offset, input.size) as i64;
                    (index as i64).saturating_add(delta) >= instruction.ops.len() as i64
                });
                // A conditional branch that ends its instruction falls
                // through to the next one. One followed by more control
                // flow in the same instruction falls into that instead: a
                // MIPS branch-likely (`beql`: CBRANCH over the delay slot
                // and a BRANCH) goes where that BRANCH goes; a conditional
                // return (`bgtlr`: CBRANCH over a RETURN) to a block Ghidra
                // starts at the instruction's own address.
                let flow_after = instruction.ops[index + 1..].iter().find(|op| {
                    matches!(
                        op.opcode.parse::<crate::ir::Opcode>(),
                        Ok(crate::ir::Opcode::Branch
                            | crate::ir::Opcode::BranchInd
                            | crate::ir::Opcode::CBranch
                            | crate::ir::Opcode::Return
                            | crate::ir::Opcode::Call
                            | crate::ir::Opcode::CallInd)
                    )
                });
                let fallthrough = match flow_after {
                    None => next,
                    Some(after) => match after.inputs.first() {
                        Some(target)
                            if after.opcode.parse::<crate::ir::Opcode>()
                                == Ok(crate::ir::Opcode::Branch)
                                && !target.is_const() =>
                        {
                            target.offset
                        }
                        _ => instruction.address,
                    },
                };
                if let Some(exit) = machine.branches.last_mut() {
                    if skip_out == Some(true) {
                        exit.destination = Some(next);
                    }
                    exit.fallthrough = Some(fallthrough);
                    // ARM SLEIGH skips a conditional body with a CBRANCH to
                    // the next instruction; a p-code-relative one skips
                    // within the instruction.
                    if exit.condition == Some(1) {
                        match op.inputs.first() {
                            Some(input) if input.is_const() => {
                                let delta = sign_extend(input.offset, input.size) as i64;
                                let to = (index as i64).saturating_add(delta);
                                if to > index as i64 {
                                    skip_to = Some(usize::try_from(to).unwrap_or(usize::MAX));
                                }
                            }
                            Some(input) if input.offset == next => skip_to = Some(usize::MAX),
                            _ => {}
                        }
                    }
                }
                if unsure.is_none()
                    && skips_body(op, instruction)
                    && machine.branches.last().is_some_and(|exit| exit.condition.is_none())
                {
                    unsure = Some(machine.facts());
                }
            }
        }
        if let Some(before) = unsure {
            machine.meet_registers(&before);
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

/// Whether `instructions` write the register slot `(space, offset, size)`
/// before they read any of it.
fn defines_before_reading(instructions: &[PcodeInstruction], slot: (&str, u64, u32)) -> bool {
    let (space, offset, size) = slot;
    let end = offset + u64::from(size);
    let overlaps = |varnode: &PcodeVarnode| {
        varnode.space == space && varnode.offset < end && varnode.offset + u64::from(varnode.size) > offset
    };
    for op in instructions.iter().flat_map(|instruction| &instruction.ops) {
        if op.inputs.iter().any(overlaps) {
            return false;
        }
        if op.output.as_ref().is_some_and(overlaps) {
            return true;
        }
    }
    false
}

/// How many instructions before a line's last conditional branch a suffix
/// may start at: the test that guards a dispatch sits right before it.
const MAX_SUFFIX: usize = 6;

/// How many index values a candidate may be tried at before the recovery
/// gives up on it. Ghidra bounds its own tables the same way, by a maximum
/// table size rather than by trusting the guard alone
/// (`JumpBasic::recoverModel`, `maxtablesize`), 1024 by default
/// (`Architecture::max_jumptable_size`, architecture.cc:1432).
const MAX_TABLE: u64 = 1024;

/// How many leading index values a composed path may send away before the
/// table starts. A guard on a normalised index (`addiu v0,a0,-5; sltiu
/// at,v0,N`) rejects the low values of the raw one it is seeded at, and the
/// cases start where it first lets one through, as Ghidra's range does
/// (`JumpValuesRange`, starting at the guard's lower bound).
const MAX_LEADING: u64 = 256;

/// Below this, leading index values are tried one by one; above it, by
/// doubling.
const LINEAR_LEADING: u64 = 32;

/// How many indices past an escaping one the walk looks for a case before
/// it takes the escape as the end of the range rather than a hole.
const HOLE_LOOKAHEAD: u64 = 8;

/// One straight line the recovery emulates.
struct Path<'p> {
    /// The p-code, ending at the indirect branch.
    instructions: &'p [PcodeInstruction],
    /// Predecessor blocks run on their own, with the index pinned, for the
    /// guard they state.
    guards: &'p [Vec<PcodeInstruction>],
    /// A composed path: the guard block runs first, so the index it is
    /// seeded at may be a raw one whose low values the guard rejects.
    resume: Option<u64>,
    /// The dispatch block's first address. A conditional branch *to* it
    /// leaves the dispatch's way in when not taken (`bls dispatch; b
    /// default`, `bgtlr`), the reverse of a branch away.
    dispatch: u64,
    /// What runs right before `instructions` on the way in, as far as it is
    /// known: the bits it fixes in the switch variable rule out indices
    /// (`known_bits`).
    prefix: &'p [PcodeInstruction],
    /// What holds on every way into the dispatch block, when the function's
    /// flow was analysed (`entry_facts`); `prefix` then starts there.
    facts: Option<&'p Facts>,
}

/// Register bits that hold at a block's start on every way into it, as
/// `entry_facts` finds them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    /// `(register offset, size, value, known mask)`, sorted; the value's
    /// unknown bits are zero.
    bits: Vec<(u64, u32, u64, u64)>,
    /// `Machine::kept`, for running on from here.
    kept: Vec<(u64, u32)>,
}

impl Facts {
    pub(crate) fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// What holds on both ways: a bit both know with the same value.
    fn meet(&self, other: &Facts) -> Facts {
        let bits = self
            .bits
            .iter()
            .filter_map(|&(offset, size, value, known)| {
                let &(_, _, other_value, other_known) = other
                    .bits
                    .iter()
                    .find(|&&(o, s, _, _)| o == offset && s == size)?;
                let known = known & other_known & !(value ^ other_value);
                (known != 0).then_some((offset, size, value & known, known))
            })
            .collect();
        Facts { bits, kept: self.kept.clone() }
    }
}

impl<'a, I: Image> Machine<'a, I> {
    fn seed(&mut self, facts: &'a Facts) {
        self.kept = &facts.kept;
        for &(offset, size, value, known) in &facts.bits {
            if known == mask(size) {
                self.state.insert(("register", offset), (value, size));
            } else {
                self.partial.insert(("register", offset), (value, known, size));
            }
        }
    }

    /// The register bits known now, as `Facts`.
    fn facts(&self) -> Facts {
        let mut bits: Vec<(u64, u32, u64, u64)> = self
            .state
            .iter()
            .filter(|((space, _), _)| *space == "register")
            .map(|(&(_, offset), &(value, size))| (offset, size, value, mask(size)))
            .chain(
                self.partial
                    .iter()
                    .filter(|((space, _), _)| *space == "register")
                    .map(|(&(_, offset), &(value, known, size))| (offset, size, value, known)),
            )
            .collect();
        bits.sort_unstable();
        Facts { bits, kept: self.kept.to_vec() }
    }

    /// Runs one instruction. One whose body only runs when a condition
    /// holds (`movlo r4,#2`: a branch over the body, to the next
    /// instruction or p-code-relative) leaves each register as the meet of
    /// before and after: emulating the body unconditionally would claim
    /// `r4` is 2 on the way that skips it.
    fn step_instruction(&mut self, instruction: &'a PcodeInstruction) {
        let before = conditional_body(instruction).then(|| self.facts());
        for op in &instruction.ops {
            self.step(op);
        }
        if let Some(before) = before {
            self.meet_registers(&before);
        }
    }

    /// Keeps of every register only what it shares with `before`.
    fn meet_registers(&mut self, before: &Facts) {
        let merged = self.facts().meet(before);
        self.state.retain(|&(space, _), _| space != "register");
        self.partial.retain(|&(space, _), _| space != "register");
        for (offset, size, value, known) in merged.bits {
            if known == mask(size) {
                self.state.insert(("register", offset), (value, size));
            } else {
                self.partial.insert(("register", offset), (value, known, size));
            }
        }
    }
}

/// Whether `op` is a conditional skip over the rest of its instruction: a
/// CBRANCH p-code-relative or to the next instruction (how ARM SLEIGH
/// makes `movlo r4,#2` conditional).
fn skips_body(op: &PcodeOp, instruction: &PcodeInstruction) -> bool {
    let next = instruction.address.wrapping_add(u64::from(instruction.length));
    op.opcode == "CBRANCH" && op.inputs.first().is_some_and(|target| target.is_const() || target.offset == next)
}

/// Whether part of `instruction` only runs when a condition holds.
fn conditional_body(instruction: &PcodeInstruction) -> bool {
    instruction.ops.iter().any(|op| skips_body(op, instruction))
}

/// Most passes `entry_facts` makes over a block before it gives up and
/// knows nothing: a meet only ever forgets, so this bounds a loop whose
/// facts keep shrinking one bit at a time.
const FACT_PASSES: usize = 64;

/// The register bits that hold at the start of block `target` however
/// flow arrives there: a forward known-bits analysis over `blocks`
/// (p-code, successor indices), meeting at every join. `open` blocks are
/// entered from somewhere the edges do not show -- the function's entry, a
/// block nothing branches to, a jump table's case -- and start knowing
/// nothing. Calls keep `kept` (the ABI's unaffected registers) and forget
/// the rest.
///
/// This is what Ghidra's value ranges see and a straight line does not:
/// `and r8,r2,#0x3ffffff8` six blocks and a call before `sub sb,r8,#4; lsr
/// sb,#2; sub sb,#1; tbh` leaves only even indices (Vita 0x814a6668, 4 of
/// 8 cases).
pub(crate) fn entry_facts<I: Image>(
    image: &I,
    blocks: &[(Vec<PcodeInstruction>, Vec<usize>)],
    open: &[bool],
    target: usize,
    kept: &[(u64, u32)],
) -> Facts {
    let nothing = Facts { bits: Vec::new(), kept: kept.to_vec() };
    let mut input: Vec<Option<Facts>> = vec![None; blocks.len()];
    let mut work: Vec<usize> = Vec::new();
    for (index, &is_open) in open.iter().enumerate() {
        if is_open {
            input[index] = Some(nothing.clone());
            work.push(index);
        }
    }
    let mut passes = vec![0usize; blocks.len()];
    while let Some(index) = work.pop() {
        passes[index] += 1;
        if passes[index] > FACT_PASSES {
            return nothing;
        }
        let Some(start) = input[index].clone() else {
            continue;
        };
        let out = {
            let mut machine = Machine::new(image);
            machine.seed(&start);
            for instruction in &blocks[index].0 {
                machine.step_instruction(instruction);
            }
            machine.facts()
        };
        for &successor in &blocks[index].1 {
            let merged = match &input[successor] {
                None => out.clone(),
                Some(old) => old.meet(&out),
            };
            if input[successor].as_ref() != Some(&merged) {
                input[successor] = Some(merged);
                if !work.contains(&successor) {
                    work.push(successor);
                }
            }
        }
    }
    input.get(target).cloned().flatten().unwrap_or(nothing)
}

/// The bits of `slot` that hold after `prefix`, run from `facts` when the
/// flow was analysed and from nothing otherwise, as `(value, known mask)`.
/// A mask or a narrow field extracted before the dispatch (`rlwinm
/// r0,r28,0,0x1c,0x1d`; `lsl r0,#0x17; lsr r0,#0x1e`) leaves the switch
/// variable with bits that are always zero, and an index with any of them
/// set is never taken: Ghidra's value range excludes it, and so must the
/// table (gc 0x800331ec, 4 of 13 slots; NDS 0x2098bd0, 4 of 5).
fn known_bits<I: Image>(
    image: &I,
    facts: Option<&Facts>,
    prefix: &[PcodeInstruction],
    slot: (&str, u64, u32),
) -> (u64, u64) {
    if prefix.is_empty() && facts.is_none_or(Facts::is_empty) {
        return (0, 0);
    }
    let varnode = PcodeVarnode { space: slot.0.to_string(), offset: slot.1, size: slot.2 };
    let mut machine = Machine::new(image);
    if let Some(facts) = facts {
        machine.seed(facts);
    }
    for instruction in prefix {
        machine.step_instruction(instruction);
    }
    // A call forgets everything it could change, so what is known afterwards
    // holds afterwards; `bits` reports an unwritten location as nothing
    // known.
    machine.bits(&varnode)
}

/// What walking one path found.
#[derive(Default)]
struct Walk {
    /// The dry run read nothing it had not written; true when that was
    /// because a call cleared the state.
    dry_empty: Option<bool>,
    saw_candidate: bool,
    saw_stride: bool,
    guarded: Option<SwitchTable>,
    unguarded: bool,
}

/// The table of a dispatch whose guard each way into it states for itself:
/// every way, run as the single line that leads to the dispatch, bounds the
/// index and reads a table, and the cases are the union. A way that answers
/// nothing -- or a list that is not known to be every way (`switch_lines`
/// leaves it empty then) -- answers nothing: the paths the list does not
/// hold would reach the dispatch untested.
fn recover_through_ways<I: Image>(
    image: &I,
    branch: u64,
    ways: &[Vec<PcodeInstruction>],
    window: &[PcodeInstruction],
    facts: Option<&Facts>,
) -> Option<SwitchTable> {
    if ways.len() < 2 || ways.iter().any(Vec::is_empty) {
        return None;
    }
    let mut targets: Vec<u64> = Vec::new();
    for way in ways {
        let table = recover_table(image, branch, std::slice::from_ref(way), window, facts, &mut Refusals::default())?;
        targets.extend(table.targets);
    }
    targets.sort_unstable();
    targets.dedup();
    (targets.len() >= 2).then_some(SwitchTable { branch, span: targets.len() as u64, targets })
}

/// Recovers the table an indirect branch reads, or nothing: the addresses
/// the indirect branch itself can go to. A guard's default is not one of
/// them -- the guard's own branch goes there -- so it is never listed.
///
/// `guard` holds the dispatch block's predecessor blocks (at most four). The
/// table is found by `recover_table`; where every predecessor fixes the
/// destination outright -- the index is a constant on each way in -- only
/// the destinations those ways reach are kept (`constant_destinations`).
/// `facts`, when the function's flow was analysed (`entry_facts`), are the
/// register bits that hold on entry to the dispatch block: indices they
/// rule out are not cases.
pub fn recover<I: Image>(
    image: &I,
    branch: u64,
    guard: &[Vec<PcodeInstruction>],
    ways: &[Vec<PcodeInstruction>],
    window: &[PcodeInstruction],
    facts: Option<&Facts>,
    refusals: &mut Refusals,
) -> Option<SwitchTable> {
    let before = *refusals;
    let Some(mut table) = recover_table(image, branch, guard, window, facts, refusals) else {
        // The guard is not one block's to state: two or three blocks reach
        // the test, and each sets what it compares (GCC schedules the
        // `sltiu` into the delay slot of the branch before). Each way in is
        // then run on its own, as the one guard line, and the dispatch
        // takes the union of what they bound.
        let found = recover_through_ways(image, branch, ways, window, facts)?;
        *refusals = before;
        return Some(found);
    };
    if let Some(reached) = constant_destinations(image, ways, window) {
        // Every constant way in has to land on the table; anything else
        // means the table and the paths disagree, and the table stands.
        if !reached.is_empty() && reached.iter().all(|target| table.targets.contains(target)) {
            let mut distinct = reached;
            distinct.sort_unstable();
            distinct.dedup();
            table.span = distinct.len() as u64;
            table.targets = distinct;
        }
    }
    Some(table)
}

/// The destinations the dispatch reaches when each way in is run into it
/// with nothing seeded, or nothing when any way leaves the destination
/// unknown. `ways` holds, per block that enters the guard chain (or the
/// dispatch), the instructions from that block to the dispatch block
/// (`switch_lines`); an empty list means the ways in are not all known. A
/// way whose run leaves the line -- a known-taken branch off it, or out of
/// range so a guard escapes -- reaches nothing.
///
/// Vita 0x8149f65c: three ways in set r0 to 1, 1 and 0 before `subs r0,#1;
/// cmp r0,#8; bhi; tbb` -- only case 0 is ever taken, which the
/// decompiler's value ranges find too, where the guard alone admits 9.
fn constant_destinations<I: Image>(
    image: &I,
    ways: &[Vec<PcodeInstruction>],
    window: &[PcodeInstruction],
) -> Option<Vec<u64>> {
    if ways.is_empty() || ways.iter().any(Vec::is_empty) {
        return None;
    }
    let mut reached = Vec::new();
    for way in ways {
        let line: Vec<PcodeInstruction> = way.iter().chain(window).cloned().collect();
        let on_line: std::collections::HashSet<u64> =
            line.iter().map(|instruction| instruction.address).collect();
        let ran = run(image, &line, None, None, &[]);
        if ran.gave_up {
            return None;
        }
        let mut leaves = false;
        for exit in &ran.branches {
            match exit.condition {
                None => return None,
                Some(1) => leaves |= exit.destination.is_some_and(|to| !on_line.contains(&to)),
                _ => leaves |= exit.fallthrough.is_some_and(|next| !on_line.contains(&next)),
            }
        }
        if leaves {
            continue;
        }
        match ran.destination {
            Some(address) if image.executable(address) => reached.push(address),
            _ => return None,
        }
    }
    Some(reached)
}

/// `recover` before any way-in refinement.
fn recover_table<I: Image>(
    image: &I,
    branch: u64,
    guard: &[Vec<PcodeInstruction>],
    window: &[PcodeInstruction],
    facts: Option<&Facts>,
    refusals: &mut Refusals,
) -> Option<SwitchTable> {
    if window.is_empty() {
        return None;
    }
    let trace = std::env::var("ROMWRIGHT_TRACE_VSA_AT")
        .ok()
        .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        == Some(branch);
    if trace {
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
    // Only a guarded table is answered, so a line with no conditional
    // branch anywhere has nothing to find: most indirect jumps on a console
    // image (`bx r3`, a computed call through a jump) end here.
    let is_cbranch =
        |op: &PcodeOp| op.opcode.parse::<crate::ir::Opcode>() == Ok(crate::ir::Opcode::CBranch);
    if !guard.iter().flatten().chain(window).flat_map(|instruction| &instruction.ops).any(is_cbranch) {
        refusals.no_guard += 1;
        return None;
    }
    let inside: std::collections::HashSet<u64> = guard
        .iter()
        .flatten()
        .chain(window.iter())
        .map(|instruction| instruction.address)
        .collect();
    let dispatch = window[0].address;
    // A guard in a predecessor bounds the index only when it is the
    // dispatch's one way in: with two, the other path reaches the dispatch
    // untested. Ghidra stops its guard search at a block with more than one
    // predecessor (`JumpBasic::analyzeGuards`, `sizeIn() != 1`), and so do
    // these; a guard inside the dispatch block (`addls pc,..`) still counts.
    // Counting any predecessor's guard read NDS 0x20a5c20 as 4 cases where
    // the dispatch's own `cmp r0,#9` admits 10.
    let guard: &[Vec<PcodeInstruction>] = if guard.len() == 1 { guard } else { &[] };
    // The single way in, when there is one: what runs right before the
    // dispatch block. Facts from the function's flow already hold at the
    // dispatch block's start, so nothing runs before it then.
    let before: &[PcodeInstruction] = match facts {
        Some(_) => &[],
        None => guard.first().map_or(&[], Vec::as_slice),
    };
    let direct = walk(
        image,
        branch,
        &Path { instructions: window, guards: guard, resume: None, dispatch, prefix: before, facts },
        &inside,
        trace,
    );
    // The guard block and the dispatch as one line: the guard's index is
    // then the value the dispatch reads by construction.
    let mut unguarded = direct.unguarded;
    let composed = match guard {
        [block] if !block.is_empty() => {
            let instructions: Vec<PcodeInstruction> = block.iter().chain(window).cloned().collect();
            let found = walk(
                image,
                branch,
                &Path {
                    instructions: &instructions,
                    guards: &[],
                    resume: Some(window[0].address),
                    dispatch,
                    prefix: &[],
                    facts: None,
                },
                &inside,
                trace,
            );
            unguarded |= found.unguarded;
            found.guarded
        }
        _ => None,
    };
    // Both lines answered: the composed one sees every test on the way in
    // with the switch variable as its own value, so where its cases are a
    // strict subset of the direct answer's, the others are never taken. GC
    // 0x8008618c reloads its index after `cmplwi r0,0; beq` and the direct
    // line, seeded after the reload, kept slot 0 (the default); the
    // composed line, forcing both loads, does not.
    match (direct.guarded, composed) {
        (Some(direct), Some(composed))
            if composed.targets.iter().all(|target| direct.targets.contains(target))
                && direct.targets.iter().any(|target| !composed.targets.contains(target)) =>
        {
            return Some(composed);
        }
        (Some(direct), _) => return Some(direct),
        (None, Some(composed)) => return Some(composed),
        (None, None) => {}
    }
    // The index can also be computed inside the dispatch block itself -- a
    // block that loads and shifts it and then tests it (`ldrh; asr r3,r3,#8;
    // cmp r3,#3; addls pc,pc,r3,lsl #2`) reads nothing the switch variable
    // is a seed for at its start. The switch variable is then a value the
    // block computes, so it is seeded where a suffix of the block starts,
    // shortest suffix first: the first one that a guard bounds starts at
    // or after the guard's own test, as Ghidra's normalised variable does.
    // A suffix has to keep the guard, so it starts at or before the last
    // instruction with a conditional branch. Suffixes of a guard block
    // composed with the dispatch answered a few more tables (capcom 24, NDS
    // 8, psx/dungeon 2 each), which the decompiler answers instead, and
    // cost 6.8 of GBA's 9.8 s of analysis.
    if let Some(last) = window.iter().rposition(|instruction| instruction.ops.iter().any(is_cbranch)) {
        let first = last.saturating_sub(MAX_SUFFIX).max(1);
        for start in (first..=last).rev() {
            let prefix: Vec<PcodeInstruction> = before.iter().chain(&window[..start]).cloned().collect();
            let found = walk(
                image,
                branch,
                &Path {
                    instructions: &window[start..],
                    guards: &[],
                    resume: None,
                    dispatch,
                    prefix: &prefix,
                    facts,
                },
                &inside,
                trace,
            );
            unguarded |= found.unguarded;
            if found.guarded.is_some() {
                return found.guarded;
            }
        }
    }
    match direct.dry_empty {
        Some(true) => refusals.unmodelled += 1,
        Some(false) => refusals.no_live_in += 1,
        None if !direct.saw_candidate => refusals.unmodelled += 1,
        None if !direct.saw_stride => refusals.no_strided_load += 1,
        // The unguarded answer is *recorded* but not returned: measured on
        // libc against truth it scores 0.73 soundness where the guarded
        // answer scores 0.999, and the decompiler path covers those
        // dispatches at 0.98. Keeping it would trade a sound answer for a
        // wrong one.
        None if unguarded => refusals.unguarded += 1,
        None => refusals.too_few_targets += 1,
    }
    None
}

/// Walks one path: finds the switch variable among what it reads, the
/// table that moves with it, and the guard that ends it.
fn walk<I: Image>(
    image: &I,
    branch: u64,
    path: &Path<'_>,
    inside: &std::collections::HashSet<u64>,
    trace: bool,
) -> Walk {
    let mut out = Walk::default();
    let window = path.instructions;
    let guard = path.guards;
    // One dry run: what does the path read that it never wrote? Those are
    // the only places a switch variable can come from.
    let dry = run(image, window, None, None, &[]);
    if dry.live_in.is_empty() {
        out.dry_empty = Some(dry.gave_up);
        return out;
    }
    if trace {
        eprintln!("VSA {branch:#x} resume {:x?} live-in {:x?}", path.resume, dry.live_in);
    }
    // A guard states the range, and a guarded answer is the better one --
    // but it is not the only sound one. Deleting the unguarded fallback
    // outright cost 49 of 142 dispatches on libc, measured by `m13-001`,
    // because the code-bounded walk answers dispatches no guard analysis
    // reaches. Both tiers are kept, the guarded answer wins where there is
    // one, and every target either produces still has to decode and lie
    // inside the branching function before it becomes a fact.
    let mut guarded: Option<SwitchTable> = None;
    // Values the guard blocks compute without reading anything: seeding
    // them states facts, and they stop being trial candidates (sweeping a
    // known constant only ever misread the table through it). The line's
    // own definitions say nothing about its live-ins, which it reads before
    // it writes them: NDS 0x20dc0f4's chain reads r1 and the dispatch
    // block later sets `mov r1,#0`, which made r1 a constant 0 and left the
    // composed line no seed.
    let joint: Vec<&[PcodeInstruction]> = guard.iter().map(Vec::as_slice).collect();
    let joint_defs = defs_for_slices(&joint, true);
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
    // Memory the window loads through an add of a constant: the index of
    // a PIC table lives behind a pointer no register seed moves, so those
    // expressions seed runs of their own. Capped: each costs two stride
    // runs before it is refused.
    // A key whose base is rewritten between two loads through it names two
    // places (`adds r0,#0xb8; ldrb r0,[r0]` ... `adds r0,#0xbc; ldrb
    // r0,[r0]`, NDS 0x225dda0): forcing both reads the guard's byte as the
    // index. Such a key is no seed.
    let mut memkeys: Vec<MemKey> = Vec::new();
    let mut generation: HashMap<MemKey, usize> = HashMap::new();
    let mut ambiguous: Vec<MemKey> = Vec::new();
    let mut writes: HashMap<(String, u64), usize> = HashMap::new();
    let mut reaching = DefMap::default();
    for op in window.iter().flat_map(|instruction| &instruction.ops) {
        if op.opcode.parse::<crate::ir::Opcode>() == Ok(crate::ir::Opcode::Load)
            && let Some(key) = op.inputs.get(1).and_then(|input| resolve_key(&reaching, input)) {
                let current = writes.get(&key.0).copied().unwrap_or(0);
                match generation.get(&key) {
                    Some(&seen) if seen != current => ambiguous.push(key.clone()),
                    Some(_) => {}
                    None => {
                        generation.insert(key.clone(), current);
                        memkeys.push(key);
                    }
                }
            }
        if let Some(out) = op.output.as_ref().filter(|out| out.space != "unique") {
            *writes.entry((out.space.clone(), out.offset)).or_insert(0) += 1;
        }
        define(&mut reaching, op);
    }
    memkeys.retain(|key| !ambiguous.contains(key));
    memkeys.truncate(8);
    // A branch out of the path means the index never reaches the dispatch:
    // a taken branch away from it, or an untaken one whose taken edge is
    // the dispatch -- unless what it falls into is a call, which returns
    // into the dispatch (`is_call`).
    let escape = |exit: &Exit| -> bool {
        match (exit.destination, exit.condition) {
            (Some(destination), Some(0)) if destination == path.dispatch => {
                !exit.fallthrough.is_some_and(|next| image.is_call(next))
            }
            (Some(destination), Some(1)) => {
                destination != path.dispatch && !inside.contains(&destination)
            }
            _ => false,
        }
    };
    let mut worker = |seed: Seed<'_>, label: String| {
        // A switch reads its targets out of a table, so the run must contain
        // a load whose address moves with the index by a fixed stride. That
        // single requirement is what separates a table from a register
        // sweep: without it, feeding indices to any live register produces
        // "targets" wherever the arithmetic happens to land in code, which
        // measured 0.42 edge precision against stock Ghidra on libc.
        // A composed line leads with the way in, which may define the
        // variable itself (`sra s0,a3,24` before the call and the guard):
        // the index is what the dispatch block reads, so it holds where that
        // part last defines it (`run_with`).
        let guard_length = path.resume.and_then(|resume| window.iter().position(|instruction| instruction.address == resume));
        // Only where the way in defines the variable before anything reads
        // it: a block that reads the incoming value first (`movs r6,r0;
        // moveq r0,#0; popeq`) is tested with the seed as it came in.
        let run_seed = |index: u64| match &seed {
            Seed::Reg(candidate) => {
                let pinned = guard_length.filter(|&length| defines_before_reading(&window[..length], *candidate));
                run_with(image, window, Some((*candidate, index)), None, &concrete, pinned)
            }
            Seed::Mem(key) => run(image, window, None, Some((key.clone(), index)), &concrete),
        };
        let run_guard = |block: &[PcodeInstruction], index: u64| match &seed {
            Seed::Reg(candidate) => {
                run_with(image, block, Some((*candidate, index)), None, &concrete, Some(usize::MAX))
            }
            Seed::Mem(key) => {
                run_with(image, block, None, Some((key.clone(), index)), &concrete, Some(usize::MAX))
            }
        };
        // A composed line's guard can send index 0 away before the table
        // is read (`movs r6,r0; popeq {..,pc}`); the stride is then read
        // from indices 1 and 2.
        let zero = run_seed(0);
        let low = u64::from(path.resume.is_some() && zero.destination.is_none() && zero.loads.is_empty());
        let first = if low == 0 { zero } else { run_seed(low) };
        let second = run_seed(low + 1);
        if first.gave_up || second.gave_up {
            return;
        }
        out.saw_candidate = true;
        if trace {
            eprintln!(
                "  candidate {label} loads0 {:x?} loads1 {:x?} dest0 {:x?} dest1 {:x?}",
                first.loads, second.loads, first.destination, second.destination
            );
        }
        if first.loads.len() != second.loads.len() {
            return;
        }
        // What moves with the index: a table read, or -- where nothing is
        // read -- the destination itself. The second is a branch table
        // (`addls pc,pc,r0,lsl #2` and a run of `b case`), whose cases
        // are the slots the arithmetic lands on; it is still held to a
        // guard, which is what kept register sweeps out.
        let moving = match first.loads.iter().zip(&second.loads).position(|(a, b)| a != b) {
            Some(slot) => {
                // Everything before the table read must be
                // index-independent, and the read itself must advance by
                // one element.
                if first.loads[..slot] != second.loads[..slot] {
                    return;
                }
                let stride = second.loads[slot].wrapping_sub(first.loads[slot]);
                if !matches!(stride, 1 | 2 | 4 | 8 | 16) {
                    return;
                }
                (Some(slot), first.loads[slot].wrapping_sub(stride.wrapping_mul(low)), stride)
            }
            None => match (first.destination, second.destination) {
                (Some(at_low), Some(next)) if matches!(next.wrapping_sub(at_low), 2 | 4 | 8) => {
                    let stride = next.wrapping_sub(at_low);
                    (None, at_low.wrapping_sub(stride.wrapping_mul(low)), stride)
                }
                _ => return,
            },
        };
        let (slot, base, stride) = moving;
        out.saw_stride = true;
        // Bits the way in fixes in a register switch variable: an index
        // with any of them different is never taken, and past the largest
        // index they allow the table has ended (`known_bits`).
        let (fixed, fixed_mask) = match &seed {
            Seed::Reg(candidate) => known_bits(image, path.facts, path.prefix, *candidate),
            Seed::Mem(_) => (0, 0),
        };
        let width = match &seed {
            Seed::Reg((_, _, size)) => mask(*size),
            Seed::Mem(_) => u64::MAX,
        };
        let possible = |index: u64| index & fixed_mask == fixed;
        let largest = fixed | (!fixed_mask & width);
        // Only a guard ends an answer, and a guard ends it by deciding on
        // the index. Where no conditional branch on the line or in a guard
        // block has a known outcome at either of two indices, none will at
        // any: the walk would run to the table limit for nothing, which on
        // the Vita image (inline `tbh` tables followed by code that reads
        // as more entries) was most of the analysis.
        let decides = |run: &Run| run.branches.iter().any(|exit| exit.condition.is_some());
        let guarded_somewhere = [0, 1].iter().any(|&index| {
            guard.iter().filter(|block| !block.is_empty()).any(|block| decides(&run_guard(block, index)))
        });
        if !decides(&first) && !decides(&second) && !guarded_somewhere {
            out.unguarded = true;
            return;
        }

        // Guard analysis is separate from path emulation, as it is in
        // Ghidra (`analyzeGuards` against `buildAddresses`): the dispatch
        // block computes the target, and the blocks before it decide which
        // indices ever reach the dispatch at all. Emulating both as one
        // window instead measured recall 0.05 against stock on libc, because
        // the guard's own inputs are unknown that early and it escapes at
        // once.
        // One index: a case and its target, an escape and the guard's
        // target, or the end of the table.
        let probe = |index: u64| -> Probe {
            let attempt = run_seed(index);
            if attempt.gave_up {
                return Probe::End;
            }
            // The guard: a branch taken out of the region means this index
            // never reaches the dispatch at all, wherever the read it skips
            // would have gone (a zero-extended index below zero reads far
            // past the table, and the guard is what says it never does).
            // Each predecessor is run on its own, with the index seeded at
            // its start: concatenating them means one block's call clears
            // the seed before the next block's comparison reads it.
            let guard_runs: Vec<Run> = guard
                .iter()
                .filter(|block| !block.is_empty())
                .map(|block| run_guard(block, index))
                .collect();
            if attempt
                .branches
                .iter()
                .chain(guard_runs.iter().flat_map(|run| run.branches.iter()))
                .any(escape)
            {
                return Probe::Escape;
            }
            // The table is contiguous: an entry read from anywhere else is
            // not this table's, and the walk has left it.
            let expected = base.wrapping_add(stride.wrapping_mul(index));
            let on_table = match slot {
                Some(slot) => attempt.loads.get(slot) == Some(&expected),
                None => attempt.destination == Some(expected),
            };
            if !on_table {
                return Probe::End;
            }
            if trace {
                eprintln!(
                    "    index {index:#x} dest {:x?} exec {:?} guard_branches {:x?}",
                    attempt.destination,
                    attempt.destination.map(|a| image.executable(a)),
                    guard_runs.iter().flat_map(|run| run.branches.iter().copied()).collect::<Vec<_>>(),
                );
            }
            match attempt.destination {
                Some(address) if image.executable(address) => Probe::Case(address),
                // The first index whose target is not code is one past the
                // end of the table.
                _ => Probe::End,
            }
        };
        // A guard that bounds the table sends far indices away: one past a
        // byte's signed range and one at the table limit cover a byte index
        // and a wide one. Where neither escapes, the walk could only end
        // where the targets stop being code, which is never an answer, so
        // it is not taken -- on GBA lines with no such guard it was most of
        // the analysis.
        if ![0x7f, MAX_TABLE - 1].iter().any(|&far| matches!(probe(far), Probe::Escape)) {
            out.unguarded = true;
            return;
        }
        let mut targets = Vec::new();
        let mut guarded_by_branch = false;
        let mut start = None;
        // A composed path's guard can reject the low values of a raw index;
        // the cases start at the lowest it admits. Low starts are tried one
        // by one; past them a guard's single interval is found by doubling
        // and stepping back, not by trying every value below it.
        let mut first = 0;
        if path.resume.is_some() && matches!(probe(0), Probe::Escape) {
            let mut admitted = None;
            let mut rejected = 0;
            let mut step = 1;
            while step < MAX_LEADING {
                match probe(step) {
                    Probe::Escape => {
                        rejected = step;
                        step = if step < LINEAR_LEADING { step + 1 } else { step * 2 };
                    }
                    Probe::Case(_) => {
                        admitted = Some(step);
                        break;
                    }
                    Probe::End => break,
                }
            }
            let Some(mut low) = admitted else {
                return;
            };
            while low > rejected + 1 && matches!(probe(low - 1), Probe::Case(_)) {
                low -= 1;
            }
            first = low;
        }
        for index in first..MAX_TABLE {
            if fixed_mask != 0 && index > largest {
                guarded_by_branch = true;
                break;
            }
            if !possible(index) {
                continue;
            }
            match probe(index) {
                Probe::Escape => {
                    guarded_by_branch = true;
                    // An equality test on the way in (`cmp r1,#5; beq`)
                    // sends one value elsewhere and lets the next through:
                    // a hole, not the end of the range. Past a range test
                    // every later index escapes as well.
                    let mut resumes = false;
                    if start.is_some() {
                        for next in index + 1..index + 1 + HOLE_LOOKAHEAD {
                            if (fixed_mask != 0 && next > largest) || !possible(next) {
                                continue;
                            }
                            if matches!(probe(next), Probe::Case(_)) {
                                resumes = true;
                                break;
                            }
                        }
                    }
                    if resumes {
                        continue;
                    }
                    break;
                }
                Probe::Case(address) => {
                    start.get_or_insert(index);
                    targets.push(address);
                }
                Probe::End => break,
            }
        }
        // A range can also start below zero: a signed byte the code adds
        // one to (`lb v1,..; addiu v1,v1,1; sltiu at,v1,7`) admits -1, and
        // Ghidra's cases run from the range's lower bound. Indices below
        // the first are walked down, and the table stands only when a guard
        // ends it there too: a signed guard with no lower bound in sight
        // (`cmp lr,#0x75; bgt default; sub r1,lr,#0x5c; tbh`, the bound in
        // another block) admits values that read before the table, and
        // the decompiler, which sees that other block, answers instead.
        if guarded_by_branch && start == Some(0) {
            let mut below = Vec::new();
            let mut bounded = false;
            for back in 1..MAX_LEADING {
                let index = 0u64.wrapping_sub(back);
                // A value the way in cannot produce bounds the range as
                // well as a guard does.
                if fixed_mask != 0 && !possible(index & width) {
                    bounded = true;
                    break;
                }
                match probe(index) {
                    Probe::Case(address) => below.push(address),
                    Probe::Escape => {
                        bounded = true;
                        break;
                    }
                    Probe::End => break,
                }
            }
            if !bounded {
                out.unguarded = true;
                return;
            }
            below.reverse();
            below.append(&mut targets);
            targets = below;
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
        if !guarded_by_branch {
            out.unguarded = true;
            return;
        }
        let span = targets.len() as u64;
        // The longest run wins: a shorter one is the same table cut off by
        // something that was not this dispatch's bound.
        if guarded.as_ref().is_none_or(|current| current.span < span) {
            guarded = Some(SwitchTable { branch, span, targets });
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
    out.guarded = guarded;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        /// address -> little-endian bytes
        memory: HashMap<u64, Vec<u8>>,
        code: (u64, u64),
        /// What a call leaves unchanged (`Image::unaffected`).
        kept: Vec<(u64, u32)>,
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
        fn unaffected(&self) -> &[(u64, u32)] {
            &self.kept
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
            kept: Vec::new(),
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

    /// One way into a dispatch: the index is defined from an argument
    /// (`sra s0,a3,24`, sign-extended to the 64-bit register), a call runs,
    /// and then the guard block loads the table's base into a register
    /// (`lui` in the delay slot) and tests the index (`sltiu`, `bnez`).
    fn way_in_with_a_call(start: u64, bound: u64) -> Vec<PcodeInstruction> {
        vec![
            PcodeInstruction {
                address: start,
                length: 4,
                error: None,
                ops: vec![
                    op("INT_SRIGHT", Some(varnode("register", 0, 4)), vec![varnode("register", 0x70, 4), varnode("const", 24, 4)]),
                    op("INT_SEXT", Some(varnode("register", 0, 8)), vec![varnode("register", 0, 4)]),
                ],
            },
            PcodeInstruction {
                address: start + 4,
                length: 4,
                error: None,
                ops: vec![op("CALL", None, vec![varnode("ram", 0x1500, 8)])],
            },
            PcodeInstruction {
                address: start + 8,
                length: 4,
                error: None,
                ops: vec![
                    op("INT_LESS", Some(varnode("unique", 0x200, 1)), vec![varnode("const", bound, 8), varnode("register", 0, 8)]),
                    // The table's base, read from a variable (a constant would be
                    // known to a run of the dispatch block alone).
                    op("LOAD", Some(varnode("register", 0x20, 8)), vec![varnode("const", 0x1b1, 4), varnode("const", 0x1ff0, 8)]),
                    op("CBRANCH", None, vec![varnode("ram", 0x1700, 8), varnode("unique", 0x200, 1)]),
                ],
            },
        ]
    }

    /// The dispatch of `dispatch()`, reading the low word of the index and
    /// a table base the way in left in a register.
    fn word_dispatch() -> Vec<PcodeInstruction> {
        let mut window = dispatch();
        window[0].ops[0] = op(
            "INT_MULT",
            Some(varnode("unique", 0x100, 8)),
            vec![varnode("register", 0, 4), varnode("const", 8, 8)],
        );
        window[0].ops[1] = op(
            "INT_ADD",
            Some(varnode("unique", 0x108, 8)),
            vec![varnode("unique", 0x100, 8), varnode("register", 0x20, 8)],
        );
        window
    }

    #[test]
    fn a_way_in_that_calls_after_defining_the_index_still_bounds_it() {
        // God Hand 0x2ad018: two ways into the guard, and the one from the
        // function entry defines the index in a callee-saved register
        // before a call. The ABI leaves that register alone, so the guard
        // after the call still tests the index the dispatch reads, and the
        // table base the guard block sets up is what the dispatch adds.
        let mut image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x1500]);
        image.memory.insert(0x1ff0, 0x2000u64.to_le_bytes().to_vec());
        image.kept = vec![(0, 8)];
        let ways = [way_in_with_a_call(0xf00, 2), way_in_with_a_call(0xe00, 2)];
        // Two guard blocks reach the dispatch, so neither states its bound alone.
        let guard = [ways[0].clone(), ways[1].clone()];
        let table = recover(&image, 0x1000, &guard, &ways, &word_dispatch(), None, &mut Refusals::default())
            .expect("a table through the ways in");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn a_call_that_may_change_the_index_register_gives_no_table() {
        // The same ways with nothing known about what the call leaves alone:
        // the index after it is not the one defined before, so the guard
        // bounds nothing the dispatch reads.
        let mut image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x1500]);
        image.memory.insert(0x1ff0, 0x2000u64.to_le_bytes().to_vec());
        let ways = [way_in_with_a_call(0xf00, 2), way_in_with_a_call(0xe00, 2)];
        let guard = [ways[0].clone(), ways[1].clone()];
        assert_eq!(
            recover(&image, 0x1000, &guard, &ways, &word_dispatch(), None, &mut Refusals::default()),
            None
        );
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
            recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &dispatch(), None, &mut refusals),
            None
        );
    }

    #[test]
    fn the_guard_branch_ends_the_table() {
        // The memory after the table holds code addresses too; what says the
        // switch has three cases is that at index 3 the guard branches away.
        // The guard's own target is where out-of-range indices go; the
        // indirect branch never does, so it is not listed.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x1500]);
        let table = recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &guarded(2, true), None, &mut Refusals::default()).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
        assert_eq!(table.span, 3);
    }

    #[test]
    fn a_guard_on_something_else_does_not_size_this_table() {
        // Taking any nearby constant as a bound measured 0.61 edge
        // precision against stock Ghidra on libc: a guard that bounds
        // something other than this index states nothing about this table.
        let image = fixture(&[0x1100, 0x1200, 0x1300, 0x1400, 0x9999]);
        assert_eq!(
            recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &guarded(2, false), None, &mut Refusals::default()),
            None
        );
    }

    #[test]
    fn a_repeated_target_is_kept_as_its_own_case() {
        // Two cases that go to the same place are still two cases: the table
        // has an entry each, and a consumer counting edges must see both.
        let image = fixture(&[0x1100, 0x1100, 0x1200, 0x9999]);
        let table = recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &guarded(2, true), None, &mut Refusals::default()).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1100, 0x1200]);
    }

    #[test]
    fn a_single_target_is_not_a_table() {
        // One case is a computed call or a tail jump, not a switch.
        let image = fixture(&[0x1100, 0x9999]);
        assert_eq!(recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &dispatch(), None, &mut Refusals::default()), None);
        // The same run of targets repeated is also not a switch: nothing
        // distinguishes the cases.
        let image = fixture(&[0x1100, 0x1100, 0x9999]);
        assert_eq!(recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &dispatch(), None, &mut Refusals::default()), None);
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
        assert_eq!(recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &window, None, &mut Refusals::default()), None);
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
            kept: Vec::new(),
        }
    }

    #[test]
    fn a_pic_offset_table_answers_through_the_guard() {
        let image = pic_fixture(&[0x1100, 0x1200, 0x1300, 0x1400]);
        let table = recover(&image, 0x1000, &[pic_guard(2)], &[], &pic_dispatch(), None, &mut Refusals::default())
            .expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn a_pic_offset_table_without_a_guard_is_not_answered() {
        // The offsets read past the table without a bound, and an unguarded
        // answer is what the 0.73-soundness fallback refuses.
        let image = pic_fixture(&[0x1100, 0x1200, 0x1300, 0x1400]);
        assert_eq!(
            recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &pic_dispatch(), None, &mut Refusals::default()),
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
        let table = recover(&image, 0x1000, &[] as &[Vec<PcodeInstruction>], &[], &window, None, &mut Refusals::default()).expect("table");
        assert_eq!(table.targets, vec![0x1100, 0x1200, 0x1300]);
    }

    /// Dispatches taken byte for byte from the console corpus, lifted by
    /// SLEIGH, each checked against the table the decompiler fallback
    /// recovered for the same branch in the same import (the comparison
    /// recorded in STATUS.md, 2026-10-07): cases in index order, then the
    /// guard target Ghidra folds in (`JumpBasic::foldInOneGuard`).
    mod real {
        use super::super::*;
        use crate::native::{Mapping, NativeContext, NativeImport};
        use crate::native_runtime::SleighLifter;
        use crate::session::RuntimeConfig;

        struct Real {
            chunks: Vec<(u64, Vec<u8>)>,
            big_endian: bool,
            code: (u64, u64),
        }

        impl Image for Real {
            fn read(&self, address: u64, size: u32) -> Option<u64> {
                let (base, bytes) = self.chunks.iter().find(|(base, bytes)| {
                    address >= *base && address + u64::from(size) <= base + bytes.len() as u64
                })?;
                let at = (address - base) as usize;
                let bytes = &bytes[at..at + size as usize];
                Some(if self.big_endian {
                    bytes.iter().fold(0, |value, &byte| (value << 8) | u64::from(byte))
                } else {
                    bytes.iter().rev().fold(0, |value, &byte| (value << 8) | u64::from(byte))
                })
            }
            fn executable(&self, address: u64) -> bool {
                (self.code.0..self.code.1).contains(&address)
            }
            fn big_endian(&self) -> bool {
                self.big_endian
            }
            /// Every corpus image here addresses 32 bits.
            fn wrap(&self, address: u64) -> u64 {
                address & 0xffff_ffff
            }
        }

        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect()
        }

        /// One corpus dispatch.
        struct Case<'a> {
            language: &'a str,
            big_endian: bool,
            thumb: bool,
            /// Code bytes, then table bytes, by address.
            chunks: &'a [(u64, &'a str)],
            /// Where case targets may lie.
            code: (u64, u64),
            /// Instruction addresses: each predecessor block, the dispatch
            /// block (ending at the branch).
            guard: &'a [&'a [u64]],
            window: &'a [u64],
            /// Each way into the guard chain or dispatch: instruction
            /// addresses up to the dispatch block (`switch_lines`).
            ways: &'a [&'a [u64]],
            /// The function's blocks up to and including the dispatch
            /// block, which comes last: instruction addresses and successor
            /// indices; block 0 is entered from outside. Empty: no flow
            /// analysis (`entry_facts`).
            flow: &'a [(&'a [u64], &'a [usize])],
        }

        /// The table VSA recovers, or `None` without the case's language installed.
        fn recover_case(case: &Case<'_>) -> Option<Option<SwitchTable>> {
            let mut cfg = RuntimeConfig::from_env();
            if !crate::architecture::language_installed(&cfg.ghidra_install, case.language) {
                return None;
            }
            cfg.adopt_language(case.language);
            let chunks: Vec<(u64, Vec<u8>)> =
                case.chunks.iter().map(|&(base, text)| (base, hex(text))).collect();
            let (code_base, _) = chunks[0];
            let import = NativeImport {
                language: case.language.into(),
                mappings: chunks
                    .iter()
                    .map(|(base, bytes)| Mapping {
                        vaddr: *base,
                        size: bytes.len() as u64,
                        file_off: 0,
                        flags: 6,
                        bytes: bytes.clone(),
                    })
                    .collect(),
                contexts: if case.thumb {
                    vec![NativeContext { name: "TMode".into(), address: code_base, value: 1 }]
                } else {
                    Vec::new()
                },
                ..Default::default()
            };
            let mut lifter = SleighLifter::mapped(&cfg, &import).unwrap();
            let guard: Vec<Vec<PcodeInstruction>> =
                case.guard.iter().map(|block| lifter.lift(block)).collect();
            let window = lifter.lift(case.window);
            assert!(guard.iter().flatten().chain(&window).all(|i| i.error.is_none()));
            let image = Real {
                chunks,
                big_endian: case.big_endian,
                code: case.code,
            };
            let branch = *case.window.last().unwrap();
            let ways: Vec<Vec<PcodeInstruction>> = case.ways.iter().map(|line| lifter.lift(line)).collect();
            let facts = (!case.flow.is_empty()).then(|| {
                let blocks: Vec<(Vec<PcodeInstruction>, Vec<usize>)> = case
                    .flow
                    .iter()
                    .map(|&(addresses, successors)| (lifter.lift(addresses), successors.to_vec()))
                    .collect();
                let mut open = vec![false; blocks.len()];
                open[0] = true;
                entry_facts(&image, &blocks, &open, blocks.len() - 1, lifter.unaffected())
            });
            Some(recover(&image, branch, &guard, &ways, &window, facts.as_ref(), &mut Refusals::default()))
        }

        /// Vita 0x8149f65c: `subs r0,#1; cmp r0,#8; bhi; tbb` admits nine
        /// cases, but the three ways in set r0 to 1, 1 and 0 -- index 0, 0
        /// and -1 -- so the only place the branch goes is case 0. The
        /// decompiler's answer (case 0, default dropped) is the true one.
        #[test]
        fn constant_ways_in_keep_only_the_cases_they_reach() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v8",
                big_endian: false,
                thumb: true,
                chunks: &[(
                    0x8149f638,
                    "01200ce049f65871c8f27711381c0422dcf130ee002801d1012000e00020013808281ed8dfe800f005080b0e11141d171a00",
                )],
                code: (0x81000000, 0x81800000),
                guard: &[&[0x8149f656, 0x8149f658, 0x8149f65a]],
                window: &[0x8149f65c],
                ways: &[
                    &[0x8149f638, 0x8149f63a, 0x8149f656, 0x8149f658, 0x8149f65a],
                    &[0x8149f650, 0x8149f652, 0x8149f656, 0x8149f658, 0x8149f65a],
                    &[0x8149f654, 0x8149f656, 0x8149f658, 0x8149f65a],
                ],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets, [0x8149f66a]);
        }

        /// NDS 0x20a7514, `cmp r4,#3; addls pc,pc,r4,lsl #2`: r4 is set to
        /// 0, 1, 2 and 3 elsewhere in the loop, so all four slots are taken.
        /// The decompiler listed two; the guard's four are the true ones.
        #[test]
        fn every_slot_the_guard_admits_is_listed() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v5t",
                big_endian: false,
                thumb: false,
                chunks: &[(0x20a7510, "030054e304f18f90310000ea020000ea120000ea1a0000ea2d0000ea")],
                code: (0x2000000, 0x2100000),
                guard: &[],
                window: &[0x20a7510, 0x20a7514],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets, [0x20a751c, 0x20a7520, 0x20a7524, 0x20a7528]);
        }

        /// GameCube 0x800331ec: `rlwinm r0,r28,0,0x1c,0x1d` leaves only
        /// bits 2-3 of the index, so of the 13 slots `cmplwi r0,12` admits
        /// only 0, 4, 8 and 12 are taken; the other nine hold the default
        /// as filler. The decompiler's four cases are the true ones.
        #[test]
        fn a_masked_index_takes_only_the_slots_its_bits_allow() {
            let Some(table) = recover_case(&Case {
                language: "PowerPC:BE:32:Gekko_Broadway",
                big_endian: true,
                thumb: false,
                chunks: &[
                    (0x800331c4, "5780073a7c7f1b782800000c579c063e418100683c60800d5400103a38635c887c03002e7c0903a64e800420"),
                    (0x800d5c88, "800331f08003323c8003323c8003323c8003320c8003323c8003323c8003323c8003321c8003323c8003323c8003323c80033230"),
                ],
                code: (0x80003100, 0x800c0000),
                guard: &[&[0x800331c4, 0x800331c8, 0x800331cc, 0x800331d0, 0x800331d4]],
                window: &[0x800331d8, 0x800331dc, 0x800331e0, 0x800331e4, 0x800331e8, 0x800331ec],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets, [0x800331f0, 0x8003320c, 0x8003321c, 0x80033230]);
        }

        /// NDS 0x2098bd0: `lsl r0,#0x17; lsr r0,#0x1e` leaves a two-bit
        /// field, so of the five slots `cmp r0,#4; addls pc` admits, the
        /// fifth is never taken.
        #[test]
        fn a_narrow_field_index_ends_the_table_at_its_width() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v5t",
                big_endian: false,
                thumb: false,
                chunks: &[(0x2098bbc, "140095e5b000d0e1800ba0e1200fa0e1040050e300f18f900d0000ea030000ea040000ea050000ea060000ea070000ea")],
                code: (0x2000000, 0x2100000),
                guard: &[],
                window: &[0x2098bbc, 0x2098bc0, 0x2098bc4, 0x2098bc8, 0x2098bcc, 0x2098bd0],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets, [0x2098bd8, 0x2098bdc, 0x2098be0, 0x2098be4]);
        }

        /// NDS `RtcCommonCallback` 0x20dc0f4: the one way in is `cmp r2,#0;
        /// bne dispatch`, so `cmp r2,#4; addls pc` never sees 0 and slot 0
        /// is not a case. The guard block composed with the dispatch knows
        /// that; the dispatch alone does not.
        #[test]
        fn a_way_in_that_excludes_zero_drops_slot_zero() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v5t",
                big_endian: false,
                thumb: false,
                chunks: &[
                    (0x20dbc90, "7f0c01e22004a0e1ff0000e2300050e3ff2001e20500001ac4049fe5280090e5000050e33880bd0830ff2fe13880bde8000052e30601001a"),
                    (0x20dc0e4, "88009fe50010a0e3241080e5040052e302f18f900a0000ea090000ea020000ea030000ea040000ea050000ea"),
                ],
                code: (0x2000000, 0x2100000),
                // The chain `switch_lines` builds: two conditional branches.
                guard: &[&[0x20dbc90, 0x20dbc94, 0x20dbc98, 0x20dbc9c, 0x20dbca0, 0x20dbca4, 0x20dbcc0, 0x20dbcc4]],
                window: &[0x20dc0e4, 0x20dc0e8, 0x20dc0ec, 0x20dc0f0, 0x20dc0f4],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets, [0x20dc100, 0x20dc104, 0x20dc108, 0x20dc10c]);
        }

        /// NDS overlay 0 0x21ee8c8: `movs r6,r0; moveq r0,#0; popeq
        /// {..,pc}` returns on 0 before `cmp r6,#4; addls pc`, so slot 0 is
        /// not a case.
        #[test]
        fn a_conditional_return_on_zero_drops_slot_zero() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v5t",
                big_endian: false,
                thumb: false,
                chunks: &[(0x21ee8b4, "70402de90060b0e10000a0037080bd08040056e306f18f900f0000ea0e0000ea020000ea040000ea060000ea080000ea")],
                code: (0x2000000, 0x2300000),
                guard: &[&[0x21ee8b4, 0x21ee8b8, 0x21ee8bc, 0x21ee8c0]],
                window: &[0x21ee8c4, 0x21ee8c8],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets, [0x21ee8d4, 0x21ee8d8, 0x21ee8dc, 0x21ee8e0]);
        }

        /// NDS overlay 49 0x225dda0: `ldrb r0,[r4+r5+0xb8]; cmp r0,#0;
        /// beq` tests a *different* byte than the index (`ldrb
        /// r0,[r4+r5+0xbc]; cmp r0,#6; bhi`), so index 0 stays a case.
        #[test]
        fn a_test_of_a_neighbouring_byte_keeps_slot_zero() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v5t",
                big_endian: false,
                thumb: true,
                chunks: &[(0x225dd82, "6019b8300078002830d06019bc30007806282bd800187844c0880004001487440c00280058016e008a00ce002401")],
                code: (0x2200000, 0x2300000),
                guard: &[&[0x225dd82, 0x225dd84, 0x225dd86, 0x225dd88, 0x225dd8a, 0x225dd8c, 0x225dd8e, 0x225dd90, 0x225dd92, 0x225dd94]],
                window: &[0x225dd96, 0x225dd98, 0x225dd9a, 0x225dd9c, 0x225dd9e, 0x225dda0],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets.first(), Some(&0x225ddb0));
        }

        /// GameCube 0x8008618c: `lwz r0,-0x7160(r13); cmplwi r0,0; beq`,
        /// then the dispatch reloads the same word. Slot 0 (the default
        /// target) is only reached if the word changes between the loads.
        #[test]
        fn a_reloaded_index_keeps_the_way_ins_test() {
            let Some(table) = recover_case(&Case {
                language: "PowerPC:BE:32:Gekko_Broadway",
                big_endian: true,
                thumb: false,
                chunks: &[
                    (0x80086154, "808d8e7880040008900d8e94800d8ea02800000041820174800d8ea0280000074181015c3c60800e38630fe45400103a7c03002e7c0903a64e800420"),
                    (0x800e0fe4, "800862d080086190800861a8800861c0800861f0800862b480086208800861d8"),
                ],
                code: (0x80003100, 0x800c0000),
                guard: &[&[0x80086154, 0x80086158, 0x8008615c, 0x80086160, 0x80086164, 0x80086168]],
                window: &[0x8008616c, 0x80086170, 0x80086174, 0x80086178, 0x8008617c, 0x80086180, 0x80086184, 0x80086188, 0x8008618c],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(
                table.expect("table").targets,
                [0x80086190, 0x800861a8, 0x800861c0, 0x800861f0, 0x800862b4, 0x80086208, 0x800861d8]
            );
        }

        /// GameCube 0x8002b7bc: `rlwinm r3,r31,0,0x18,0x1c` (a multiple of
        /// 8) three ways before `addi r0,r3,-0x70; cmplwi r0,0x28; bgt`, so
        /// only every eighth of the 41 slots is taken; the others hold the
        /// default as filler.
        #[test]
        fn bits_fixed_on_every_way_in_rule_out_slots() {
            let Some(table) = recover_case(&Case {
                language: "PowerPC:BE:32:Gekko_Broadway",
                big_endian: true,
                thumb: false,
                chunks: &[
                    (0x8002b780, "57e3063857f6077e2c0300704182001028160004418000083ac000003803ff90280000284181f5803c60800d5400103a3863384c7c03002e7c0903a64e800420"),
                    (0x800d384c, "8002b8a48002ad248002ad248002ad248002ad248002ad248002ad248002ad248002b8b88002ad248002ad248002ad248002ad248002ad248002ad248002ad248002b7c08002ad248002ad248002ad248002ad248002ad248002ad248002ad248002b7f08002ad248002ad248002ad248002ad248002ad248002ad248002ad248002b82c8002ad248002ad248002ad248002ad248002ad248002ad248002ad248002b83c"),
                ],
                code: (0x80003100, 0x800c0000),
                guard: &[&[0x8002b79c, 0x8002b7a0, 0x8002b7a4]],
                window: &[0x8002b7a8, 0x8002b7ac, 0x8002b7b0, 0x8002b7b4, 0x8002b7b8, 0x8002b7bc],
                ways: &[],
                flow: &[
                    (&[0x8002b780, 0x8002b784, 0x8002b788, 0x8002b78c], &[3, 1]),
                    (&[0x8002b790, 0x8002b794], &[3, 2]),
                    (&[0x8002b798], &[3]),
                    (&[0x8002b79c, 0x8002b7a0, 0x8002b7a4], &[4]),
                    (&[0x8002b7a8, 0x8002b7ac, 0x8002b7b0, 0x8002b7b4, 0x8002b7b8, 0x8002b7bc], &[]),
                ],
            }) else {
                return;
            };
            assert_eq!(
                table.expect("table").targets,
                [0x8002b8a4, 0x8002b8b8, 0x8002b7c0, 0x8002b7f0, 0x8002b82c, 0x8002b83c]
            );
        }

        /// GameCube 0x80033588: `r26` is `x & 0xc` or 16 on every way in,
        /// across calls (`r26` is one the ABI leaves unaffected), so of the
        /// 17 slots `cmplwi r26,0x10` admits only 0, 4, 8, 12 and 16 are
        /// taken.
        #[test]
        fn bits_kept_across_calls_rule_out_slots() {
            let Some(table) = recover_case(&Case {
                language: "PowerPC:BE:32:Gekko_Broadway",
                big_endian: true,
                thumb: false,
                chunks: &[
                    (0x800334d4, "5480073e7c7f1b782c00000b549a073a549907be4082000c3b4000003b20000b2c00000a408200207fe3fb784bfff9c17c641b785463e73e3b20000a549a073a3b0300045480073e2c000009408200207fe3fb784bfff999547a073a54790636281a0008408200083b4000107fe3fb784bfff97d2819000a7c7d1b784082001c7fe3fb784bfff9697c641b787fe3fb78480005fd7c7b1b78281a0010418100703c60800d5740103a38635cbc7c03002e7c0903a64e800420"),
                    (0x800d5cbc, "8003358c800335e0800335e0800335e0800335a8800335e0800335e0800335e0800335b8800335e0800335e0800335e0800335cc800335e0800335e0800335e0800335dc"),
                ],
                code: (0x80003100, 0x800c0000),
                guard: &[&[0x8003356c, 0x80033570]],
                window: &[0x80033574, 0x80033578, 0x8003357c, 0x80033580, 0x80033584, 0x80033588],
                ways: &[],
                flow: &[
                    (&[0x800334d4, 0x800334d8, 0x800334dc, 0x800334e0, 0x800334e4, 0x800334e8], &[2, 1]),
                    (&[0x800334ec, 0x800334f0], &[2]),
                    (&[0x800334f4, 0x800334f8], &[4, 3]),
                    (&[0x800334fc, 0x80033500, 0x80033504, 0x80033508, 0x8003350c, 0x80033510, 0x80033514], &[4]),
                    (&[0x80033518, 0x8003351c, 0x80033520], &[7, 5]),
                    (&[0x80033524, 0x80033528, 0x8003352c, 0x80033530, 0x80033534, 0x80033538], &[7, 6]),
                    (&[0x8003353c], &[7]),
                    (&[0x80033540, 0x80033544, 0x80033548, 0x8003354c, 0x80033550], &[9, 8]),
                    (&[0x80033554, 0x80033558, 0x8003355c, 0x80033560, 0x80033564, 0x80033568], &[9]),
                    (&[0x8003356c, 0x80033570], &[10]),
                    (&[0x80033574, 0x80033578, 0x8003357c, 0x80033580, 0x80033584, 0x80033588], &[]),
                ],
            }) else {
                return;
            };
            assert_eq!(table.expect("table").targets, [0x8003358c, 0x800335a8, 0x800335b8, 0x800335cc, 0x800335dc]);
        }

        /// Vita 0x81007cd4: `cmp r2,#6; beq.w elsewhere; subs r1,#1; cmp
        /// r1,#0xb; bhi; tbb` -- 6 goes elsewhere, 7 and 8 still reach
        /// their slots. The equality test is a hole in the range, not its
        /// end.
        #[test]
        fn an_equality_test_is_a_hole_not_the_end() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v8",
                big_endian: false,
                thumb: true,
                chunks: &[(0x81007cc2, "0ab2062a00f0dc800139d0ed060a0b293dd8dfe801f006332a2a3c3c211606333c06")],
                code: (0x81000000, 0x81800000),
                guard: &[&[0x81007cc2, 0x81007cc4, 0x81007cc6, 0x81007cca, 0x81007ccc, 0x81007cd0, 0x81007cd2]],
                window: &[0x81007cd4],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let targets = table.expect("table").targets;
            assert!(targets.contains(&0x81007d1a) && targets.contains(&0x81007d04), "{targets:x?}");
        }

        /// PS2 (r5900) GCC: `sltiu v1,a1,6; beqz v1,default` with the table
        /// index scaled in the branch's delay slot (`sll a3,a1,2`), so the
        /// dispatch block reads the index already scaled. Walking the guard
        /// block and the dispatch block as one line seeds the guard's own
        /// value. `dungeon_game.elf` 0x11b2e0.
        #[test]
        fn mips_guard_scales_the_index_in_its_delay_slot() {
            let Some(table) = recover_case(&Case {
                language: "r5900:LE:32:default",
                big_endian: false,
                thumb: false,
                chunks: &[
                    (0x11b2bc, "0600a32c040084c438006010022006461400083c80380500704202252120e2000000858c0800a00000000000"),
                    (0x144270, "e8b2110030b3110068b3110078b3110088b3110098b31100"),
                ],
                code: (0x100000, 0x140000),
                guard: &[&[0x11b2bc, 0x11b2c0, 0x11b2c4]],
                window: &[0x11b2cc, 0x11b2d0, 0x11b2d4, 0x11b2d8, 0x11b2dc, 0x11b2e0],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(
                table.targets,
                [0x11b2e8, 0x11b330, 0x11b368, 0x11b378, 0x11b388, 0x11b398]
            );
            assert_eq!(table.span, 6);
        }

        /// PS2 (r5900) GCC on a signed byte plus one: `lb v1,0x1dd(s1);
        /// addiu v1,v1,1; sltiu at,v1,7` admits -1..5, and the cases run
        /// from -1. The index lives in memory, so the load is what is
        /// seeded. `SLUS_209.50` 0x18521c.
        #[test]
        fn mips_range_starting_below_zero() {
            let Some(table) = recover_case(&Case {
                language: "r5900:LE:32:default",
                big_endian: false,
                thumb: false,
                chunks: &[
                    (0x1851f8, "dd012382010063240700612cf40020103100043c8018030030678424211864000000638c0800600000000000"),
                    (0x316730, "d85518002852180080521800105318009853180050541800d8541800"),
                ],
                code: (0x100000, 0x300000),
                guard: &[&[0x1851f8, 0x1851fc, 0x185200, 0x185204]],
                window: &[0x18520c, 0x185210, 0x185214, 0x185218, 0x18521c],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(
                table.targets,
                [0x1855d8, 0x185228, 0x185280, 0x185310, 0x185398, 0x185450, 0x1854d8]
            );
        }

        /// PS2 (r5900) GCC schedules the `sltiu` that `beqz v0,default` reads
        /// into the delay slot of the branch before it, so the test has two
        /// ways in and each states its own: `bne s0,v0,L; sltiu v0,s0,7` and,
        /// falling through, `lb s0,..; sltiu v0,s0,7`. No way is the single
        /// block the guard line is built from, and the dispatch block alone
        /// tests nothing; each way run as the guard bounds the index at 7
        /// cases. God Hand `cIDManager_getLocalFileName` 0x2ad018, whose 7
        /// case blocks stayed functions.
        #[test]
        fn mips_each_way_in_states_its_own_guard() {
            let Some(table) = recover_case(&Case {
                language: "r5900:LE:32:default",
                big_endian: false,
                thumb: false,
                chunks: &[
                    (0x2acfe8, "ffff0224040002160700022e7400023c0c7a50800700022e270040104500023c8018100020b04224211862000000648c0800800000000000"),
                    (0x44b020, "20d02a0030d02a0040d02a0050d02a0060d02a0070d02a008cd02a00"),
                ],
                code: (0x100000, 0x400000),
                guard: &[&[0x2ad000]],
                window: &[0x2ad008, 0x2ad00c, 0x2ad010, 0x2ad014, 0x2ad018],
                ways: &[&[0x2acfe8, 0x2acfec, 0x2ad000], &[0x2acff4, 0x2acff8, 0x2acffc, 0x2ad000]],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(table.targets, [0x2ad020, 0x2ad030, 0x2ad040, 0x2ad050, 0x2ad060, 0x2ad070, 0x2ad08c]);
        }

        /// The same dispatch with the way that loads its index stripped of the
        /// test: one way in is unguarded, so the others do not make a guard.
        #[test]
        fn mips_a_way_that_tests_nothing_leaves_the_dispatch_unanswered() {
            let Some(table) = recover_case(&Case {
                language: "r5900:LE:32:default",
                big_endian: false,
                thumb: false,
                chunks: &[
                    // `sltiu v0,s0,7` at 0x2acffc is a `nop`.
                    (0x2acfe8, "ffff0224040002160700022e7400023c0c7a508000000000270040104500023c8018100020b04224211862000000648c0800800000000000"),
                    (0x44b020, "20d02a0030d02a0040d02a0050d02a0060d02a0070d02a008cd02a00"),
                ],
                code: (0x100000, 0x400000),
                guard: &[&[0x2ad000]],
                window: &[0x2ad008, 0x2ad00c, 0x2ad010, 0x2ad014, 0x2ad018],
                ways: &[&[0x2acfe8, 0x2acfec, 0x2ad000], &[0x2acff4, 0x2acff8, 0x2acffc, 0x2ad000]],
                flow: &[],
            }) else {
                return;
            };
            assert_eq!(table, None);
        }

        /// GameCube (Metrowerks PowerPC): `cmplwi r4,15; ...; bgtlr` -- the
        /// guard is a conditional return, its compare packed into CR0 beside
        /// the summary-overflow bit nothing knows, and the dispatch is
        /// `lis; slwi; addi; lwzx; mtctr; bctr`. Ghidra folds the return
        /// path in at the `bgtlr` itself. `main.dol` 0x80059cb0.
        #[test]
        fn powerpc_conditional_return_guard() {
            let Some(table) = recover_case(&Case {
                language: "PowerPC:BE:32:Gekko_Broadway",
                big_endian: true,
                thumb: false,
                chunks: &[
                    (0x80059c8c, "2804000f3ca0800e38c5aaa04d8100203ca0800e5480103a3885b24c7c04002e7c0903a64e800420"),
                    (0x800db24c, "80059cb480059cbc80059cc480059ccc80059cd480059cdc80059ce480059cec80059cf480059cfc80059d0480059d0c80059d1480059d1c80059d2480059d2c"),
                ],
                code: (0x80003100, 0x800c0000),
                guard: &[&[0x80059c8c, 0x80059c90, 0x80059c94, 0x80059c98]],
                window: &[0x80059c9c, 0x80059ca0, 0x80059ca4, 0x80059ca8, 0x80059cac, 0x80059cb0],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            let expected: Vec<u64> = (0..16).map(|case| 0x80059cb4 + case * 8).collect();
            assert_eq!(table.targets, expected);
        }

        /// NDS (Thumb, agbcc/mwcc style): `cmp r1,#3; bls dispatch; b
        /// default`, then `adds r1,r1,r1; add r1,pc; ldrh r1,[r1,#6]; lsls;
        /// asrs; add pc,r1` over an inline table of halfword offsets. The
        /// guard branches *into* the dispatch; the default Ghidra folds in
        /// is where the `b` goes. `pokeheartgold` arm9 0x2028980.
        #[test]
        fn thumb_branch_into_dispatch_over_halfword_offsets() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v5t",
                big_endian: false,
                thumb: true,
                chunks: &[(0x2028970, "032900d992e049187944c988090409148f4406009c00c400ea00")],
                code: (0x2000000, 0x2100000),
                guard: &[&[0x2028970, 0x2028972]],
                window: &[0x2028976, 0x2028978, 0x202897a, 0x202897c, 0x202897e, 0x2028980],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(table.targets, [0x202898a, 0x2028a20, 0x2028a48, 0x2028a6e]);
        }

        /// GBA (agbcc Thumb): `ldrb r0,[r6,#0x1c]; cmp r0,#6; bls dispatch;
        /// b default`, then `lsls r0,r0,#2; ldr r1,=table; adds r0,r0,r1;
        /// ldr r0,[r0]; mov pc,r0`. The table base comes out of the literal
        /// pool, which lifts to a direct read of code memory. `pokeemerald`
        /// 0x80057cc.
        #[test]
        fn agbcc_thumb_word_table_through_a_literal_pool() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v4t",
                big_endian: false,
                thumb: true,
                chunks: &[
                    (0x80057bc, "307f062800d9d3e2800002494018006887460000d4570008"),
                    (0x80057d4, "f0570008785c00088c5c0008b85c0008f05c0008485d00085a5d0008"),
                ],
                code: (0x8000000, 0x8100000),
                guard: &[&[0x80057bc, 0x80057be, 0x80057c0]],
                window: &[0x80057c4, 0x80057c6, 0x80057c8, 0x80057ca, 0x80057cc],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(
                table.targets,
                [0x80057f0, 0x8005c78, 0x8005c8c, 0x8005cb8, 0x8005cf0, 0x8005d48, 0x8005d5a]
            );
        }

        /// NDS (mwcc ARM): `cmp r0,#3; addls pc,pc,r0,lsl #2; b default` and
        /// a run of `b case`. Nothing is loaded: the destination itself moves
        /// with the index, and the dispatch's own condition is the guard.
        /// `pokeheartgold` arm9 0x20cded8.
        #[test]
        fn arm_conditional_add_to_pc_over_a_branch_table() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v5t",
                big_endian: false,
                thumb: false,
                chunks: &[(0x20cded0, "290000aa030050e300f18f90360000ea350000ea160000ea190000ea110000ea")],
                code: (0x2000000, 0x2100000),
                guard: &[],
                window: &[0x20cded4, 0x20cded8],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(table.targets, [0x20cdee0, 0x20cdee4, 0x20cdee8, 0x20cdeec]);
        }

        /// Vita (ARMv7 Thumb-2, SN/clang): `cmp r0,#0; ble default; cmp
        /// r0,#7; bgt default; subs r0,#1; tbh [pc,r0,lsl #1]` -- two guards
        /// in two blocks bound the index from both sides, and `tbh` sets the
        /// Thumb bit through a user-defined p-code operation mid-dispatch.
        /// `eboot.elf` 0x8104f108.
        #[test]
        fn thumb2_tbh_bounded_by_two_guard_blocks() {
            let Some(table) = recover_case(&Case {
                language: "ARM:LE:32:v8",
                big_endian: false,
                thumb: true,
                chunks: &[(0x8104f0fe, "002813dd072811dc0138dfe810f00700e302e302d902e302d902d002")],
                code: (0x81000000, 0x81800000),
                guard: &[&[0x8104f0fe, 0x8104f100, 0x8104f102, 0x8104f104]],
                window: &[0x8104f106, 0x8104f108],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(
                table.targets,
                [0x8104f11a, 0x8104f6d2, 0x8104f6d2, 0x8104f6be, 0x8104f6d2, 0x8104f6be, 0x8104f6ac]
            );
        }

        /// Xbox 360 (MSVC PowerPC64, 32-bit addressing): `lbz r11,3(r9);
        /// cmplwi cr6,r11,18; bgt cr6,default; lis r12,..; rlwinm; addi;
        /// lwzx; mtctr; bctr`. `lbz` writes all of r11 and `cmplwi` reads
        /// its low word, and `lis` sign-extends the table address past 32
        /// bits. The default is case 3 too, so nothing is folded.
        /// `default_mp_script.exe` 0x821ab6ec.
        #[test]
        fn powerpc64_32addr_low_word_compare() {
            let Some(table) = recover_case(&Case {
                language: "PowerPC:BE:64:Xenon-32addr",
                big_endian: true,
                thumb: false,
                chunks: &[(
                    0x821ab6c4,
                    "896400037c9f23783bc000002b0b0012419900b03d80821b5560103a398cb6f07c0c002e7c0903a64e800420821ab774821ab744821ab784821ab784821ab784821ab784821ab784821ab784821ab74c821ab74c821ab784821ab73c821ab764821ab784821ab764821ab784821ab76c821ab784821ab76c",
                )],
                code: (0x82000000, 0x83000000),
                guard: &[&[0x821ab6c4, 0x821ab6d0, 0x821ab6d4]],
                window: &[0x821ab6d8, 0x821ab6dc, 0x821ab6e0, 0x821ab6e4, 0x821ab6e8, 0x821ab6ec],
                ways: &[],
                flow: &[],
            }) else {
                return;
            };
            let table = table.expect("table");
            assert_eq!(table.span, 19);
            assert_eq!(table.targets.len(), 19);
            assert_eq!(&table.targets[..3], [0x821ab774, 0x821ab744, 0x821ab784]);
            assert_eq!(table.targets[18], 0x821ab76c);
        }
    }
}
