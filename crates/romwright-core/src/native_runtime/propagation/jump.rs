//! The table of an indirect jump, recovered inside the reference flow.
//!
//! The decompiler's flow recovers a jump's table while it follows flow
//! (`FlowInfo::recoverJumpTables`, `jumptable.cc`; Ghidra 12.1.3, Apache-2.0)
//! and goes on tracing the cases it finds. The reference flow of `graph.rs`
//! used to treat a jump with no stored table as a return or a call, so the
//! case bodies of such a jump (an ARM `addls pc,pc,r0,lsl #2` over a run of
//! `b case`, a `ldr pc,[pc,r0,lsl #2]` table read) never joined the flow.
//!
//! The answer here is the value-set pass the import already runs for the
//! walk's jumps (`native::vsa`, itself `JumpBasic::buildAddresses` and
//! `analyzeGuards` over p-code): the dispatch block of the branch and the
//! blocks that reach it are lines of instructions, the guard that bounds the
//! index is read off them, and the branch is emulated once per index value.
//! What it needs from the flow is the same three things the walk gave it: the
//! shape of each instruction (`FlowShape`), the p-code of the lines
//! (`PcodeInstruction`), and the image bytes a table read touches. Here the
//! shapes and the p-code come from the ops the flow already holds, so no
//! second decoder is built.
//!
//! A table is kept only when a guard bounds the index (`vsa` answers nothing
//! else), every case lies in the range being traced, and the pass ends in at
//! least two distinct targets. Anything else is a refusal with a reason, and
//! the jump stays a call, as before.
use super::graph::Environment;
use super::lang::Lang;
use crate::native::vsa::{self, Image, Refusals};
use crate::native::FlowShape;
use crate::native_runtime::PcodeInstruction;

/// Why the flow has no table for an indirect jump it asked about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Refusal {
    /// The flow does not hold the block around the branch.
    NoWindow,
    /// An instruction of the lines is not held whole (a call fixup replaced
    /// part of it, or the flow cut it short).
    Undecodable,
    /// Nothing before the branch tests anything.
    NoGuard,
    /// Nothing the block read was a value it did not also write.
    NoLiveIn,
    /// No load moved with the index: nothing here reads a table.
    NoStridedLoad,
    /// A table was found with fewer than two distinct targets.
    TooFewTargets,
    /// A table was found, but no guard ended it.
    Unguarded,
    /// Every candidate hit an operation the emulator does not model.
    Unmodelled,
    /// A case lies outside the range being traced.
    Outside,
    /// The answer did not hold once the flow it opened was traced.
    Unstable,
}

/// The image as value-set analysis reads it, over what the flow's
/// environment answers.
struct View<'a, E: Environment> {
    env: &'a E,
    big_endian: bool,
    /// The code space's width as a mask (`vsa::Image::wrap`).
    mask: u64,
    /// The shapes of the instructions the flow traced, sorted by address.
    shapes: &'a [FlowShape],
}

impl<E: Environment> Image for View<'_, E> {
    fn read(&self, address: u64, size: u32) -> Option<u64> {
        self.env.read_image(address, size)
    }

    fn executable(&self, address: u64) -> bool {
        self.env.executable(address)
    }

    fn wrap(&self, address: u64) -> u64 {
        address & self.mask
    }

    fn big_endian(&self) -> bool {
        self.big_endian
    }

    fn is_call(&self, address: u64) -> bool {
        self.shapes
            .binary_search_by_key(&address, |shape| shape.address)
            .is_ok_and(|index| matches!(self.shapes[index].kind, crate::native_runtime::FlowKind::Call) && !self.shapes[index].conditional)
    }
}

/// The distinct targets, sorted, of the dispatch at `branch`, a `BRANCHIND`
/// of the range `[entry, end)` the flow traced. `shapes` are the traced
/// instructions sorted by address; `pcode` answers the p-code of one traced
/// instruction as the flow holds it, `None` when it holds no whole copy.
pub(super) fn recover<E: Environment>(
    env: &E,
    lang: &Lang,
    shapes: &[FlowShape],
    pcode: &dyn Fn(u64) -> Option<PcodeInstruction>,
    branch: u64,
    entry: u64,
    end: u64,
) -> Result<Vec<u64>, Refusal> {
    let by_reference: Vec<&FlowShape> = shapes.iter().collect();
    let (window, guard, ways) = crate::native::switch_tables::switch_lines(&by_reference, branch, entry, end);
    if window.is_empty() {
        return Err(Refusal::NoWindow);
    }
    let fetch = |addresses: &[u64]| -> Option<Vec<PcodeInstruction>> { addresses.iter().map(|&address| pcode(address)).collect() };
    let window = fetch(&window).ok_or(Refusal::Undecodable)?;
    let guard: Vec<Vec<PcodeInstruction>> = guard.iter().map(|block| fetch(block)).collect::<Option<_>>().ok_or(Refusal::Undecodable)?;
    // A way in that is not held whole leaves the list incomplete, which
    // `vsa::recover` then does not trust.
    let ways: Vec<Vec<PcodeInstruction>> = ways.iter().map(|line| fetch(line)).collect::<Option<_>>().unwrap_or_default();
    let view = View {
        env,
        big_endian: lang.big_endian,
        mask: lang.space(lang.code_space).highest,
        shapes,
    };
    let mut refusals = Refusals::default();
    let Some(table) = vsa::recover(&view, branch, &guard, &ways, &window, None, &mut refusals) else {
        return Err(if refusals.no_guard > 0 {
            Refusal::NoGuard
        } else if refusals.no_live_in > 0 {
            Refusal::NoLiveIn
        } else if refusals.no_strided_load > 0 {
            Refusal::NoStridedLoad
        } else if refusals.too_few_targets > 0 {
            Refusal::TooFewTargets
        } else if refusals.unguarded > 0 {
            Refusal::Unguarded
        } else {
            Refusal::Unmodelled
        });
    };
    let mut targets = table.targets;
    targets.sort_unstable();
    targets.dedup();
    // The decompiler places a case outside the dispatching function itself
    // (`switch_tables`: such a table is left to it); the flow of this range
    // cannot follow one.
    if targets.len() < 2 {
        return Err(Refusal::TooFewTargets);
    }
    if targets.iter().any(|&target| target < entry || target >= end) {
        return Err(Refusal::Outside);
    }
    Ok(targets)
}
