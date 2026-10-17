//! What a function's direct callers do with it: which argument registers they
//! set, and whether they read its result.
//!
//! A function can read a register that most of its callers never write: a
//! trailing argument the source leaves out of a call (a K&R declaration, a
//! `GetMonData(mon, field)` against a three-parameter definition). The
//! decompiler recovers the callee's third parameter, and once that prototype
//! is locked every caller that did not set the register inherits it as a
//! parameter of its own, which then propagates up the call graph.
//!
//! The evidence that a trailing parameter is optional is in the callers: at
//! each direct call, a register the caller wrote since its previous call
//! (or its entry) is an argument it passed; one it did not is, at best, a
//! pass-through of its own register. A trailing slot that almost no call
//! site sets is not part of the arity the callers use. Such a slot is kept
//! as `...`, which keeps what the callee reads and leaves each call site to
//! work out for itself whether it passed one.
//!
//! The same scan says whether a caller reads the register a call returns in
//! (`uses_result`). A function that only forwards a callee's result is
//! indistinguishable, in the binary, between returning a value and dropping
//! one; unless some caller reads the result, its return is not evidence of a
//! value.
use std::collections::BTreeSet;

use crate::native_runtime::PcodeInstruction;

/// One direct call, as its caller makes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSite {
    pub callee: u64,
    /// Per integer argument slot, whether the caller wrote that register
    /// since its entry or its previous call (bit `k` for slot `k`).
    pub set: u64,
    /// Whether the caller reads a result register after the call, before
    /// writing it again or calling again: it uses what the callee returns.
    pub uses_result: bool,
}

/// The direct calls in `instructions`, in program order. `returns` are the
/// registers a callee's result arrives in: they hold a value the caller did
/// not write itself but may well pass on (`f(g())`), so they count as set
/// after a call.
pub fn call_sites(instructions: &[PcodeInstruction], slots: &[u64], returns: &[u64]) -> Vec<CallSite> {
    let mut sites: Vec<CallSite> = Vec::new();
    let mut written: BTreeSet<u64> = BTreeSet::new();
    // The call whose result registers are still unread and unwritten.
    let mut awaiting: Option<usize> = None;
    let mut watched: BTreeSet<u64> = BTreeSet::new();
    let mask = |written: &BTreeSet<u64>| -> u64 {
        slots
            .iter()
            .take(64)
            .enumerate()
            .filter(|(_, offset)| written.contains(offset))
            .fold(0u64, |mask, (slot, _)| mask | 1 << slot)
    };
    let overlaps = |offset: u64, size: u32, register: u64| offset <= register && register < offset + u64::from(size);
    for instruction in instructions {
        for op in &instruction.ops {
            if op.opcode == "CALL" || op.opcode == "CALLIND" {
                awaiting = None;
                if op.opcode == "CALL"
                    && let Some(target) = op.inputs.first()
                    && target.space != "const"
                {
                    sites.push(CallSite { callee: target.offset, set: mask(&written), uses_result: false });
                    awaiting = Some(sites.len() - 1);
                    watched = returns.iter().copied().collect();
                }
                written.clear();
                written.extend(returns.iter().copied());
                continue;
            }
            if let Some(site) = awaiting {
                let read = op.inputs.iter().any(|input| {
                    input.space == "register"
                        && watched.iter().any(|register| overlaps(input.offset, input.size, *register))
                });
                if read {
                    sites[site].uses_result = true;
                    awaiting = None;
                }
            }
            if let Some(output) = &op.output
                && output.space == "register"
            {
                for offset in slots {
                    if overlaps(output.offset, output.size, *offset) {
                        written.insert(*offset);
                    }
                }
                watched.retain(|register| !overlaps(output.offset, output.size, *register));
                if watched.is_empty() {
                    awaiting = None;
                }
            }
        }
    }
    sites
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_runtime::{PcodeOp, PcodeVarnode};

    fn reg(offset: u64) -> PcodeVarnode {
        PcodeVarnode { space: "register".into(), offset, size: 4 }
    }
    fn instruction(ops: Vec<PcodeOp>) -> PcodeInstruction {
        PcodeInstruction { address: 0, length: 4, ops, error: None }
    }
    fn set(offset: u64) -> PcodeInstruction {
        instruction(vec![PcodeOp {
            opcode: "COPY".into(),
            output: Some(reg(offset)),
            inputs: vec![PcodeVarnode { space: "const".into(), offset: 1, size: 4 }],
        }])
    }
    fn call(target: u64) -> PcodeInstruction {
        instruction(vec![PcodeOp {
            opcode: "CALL".into(),
            output: None,
            inputs: vec![PcodeVarnode { space: "ram".into(), offset: target, size: 4 }],
        }])
    }

    #[test]
    fn a_call_records_the_registers_written_since_the_previous_call() {
        let slots = [0x20, 0x24, 0x28];
        let program = [set(0x20), set(0x24), call(0x100), set(0x28), call(0x200), call(0x300)];
        // Calling convention returns in the first slot's register.
        let sites: Vec<(u64, u64)> =
            call_sites(&program, &slots, &[0x20]).iter().map(|s| (s.callee, s.set)).collect();
        assert_eq!(sites, vec![(0x100, 0b011), (0x200, 0b101), (0x300, 0b001)]);
    }

    fn read(offset: u64) -> PcodeInstruction {
        instruction(vec![PcodeOp {
            opcode: "COPY".into(),
            output: Some(reg(0x80)),
            inputs: vec![reg(offset)],
        }])
    }

    #[test]
    fn a_result_is_used_when_read_before_it_is_overwritten() {
        let slots = [0x20, 0x24];
        let uses = |program: &[PcodeInstruction]| -> Vec<bool> {
            call_sites(program, &slots, &[0x20]).iter().map(|s| s.uses_result).collect()
        };
        assert_eq!(uses(&[call(0x100), read(0x20)]), vec![true]);
        assert_eq!(uses(&[call(0x100), set(0x20), read(0x20)]), vec![false]);
        assert_eq!(uses(&[call(0x100), call(0x200), read(0x20)]), vec![false, true]);
        assert_eq!(uses(&[call(0x100), read(0x24)]), vec![false]);
    }
}
