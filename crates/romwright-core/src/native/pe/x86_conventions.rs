//! The calling convention an i386 PE function was compiled with, read from its own code.
//!
//! Ghidra's `windows` compiler spec names `__stdcall`, `__fastcall` and `__thiscall`, but its Java analysis (which
//! sets each function's convention from the stack purge of its `ret`) is not part of the native importer, so the
//! decompiler would print every function with the default model and the callee-pops variants would come out as
//! `__cdecl`. The rule here is the one the compilers follow, applied to the p-code SLEIGH lifts for the function:
//!
//! * every reachable `ret` pops the same non-zero byte count (`ret N`) and neither `ecx` nor `edx` is read before it is
//!   written: `__stdcall` (what Visual C++ and MinGW emit for the Win32 API and for `__stdcall` game code);
//! * a plain `ret`, neither register read first, and a `push ecx`/`push edx` reserving stack: `__cdecl`, recorded so the
//!   decompiler does not take the reservation for a `__fastcall` argument;
//! * everything else is left to the decompiler, whose `__cdecl/__fastcall/__thiscall` resolution reads the inputs
//!   itself (a function that reads `ecx` and `edx` first is `__fastcall`, one that reads only `ecx` `__thiscall`).
//!
//! A `push ecx`/`push edx` is a four-byte stack reservation in Visual C++ code, not a read of the register, and `xor r,r`
//! / `sub r,r` write; a call clobbers both registers. The walk follows direct branches inside the function and
//! stops at indirect ones (a jump table), so bytes after the last `ret` are never decoded as code.

use std::collections::HashSet;

use crate::native::NativeImport;
use crate::native_runtime::{PcodeInstruction, PcodeOp, PcodeVarnode};

/// `ecx` and `edx` in the x86 register space (`registers.txt`: ECX at 4, EDX at 8, four bytes each).
const ECX: std::ops::Range<u64> = 4..8;
const EDX: std::ops::Range<u64> = 8..12;
/// `ST0`, the top of the x87 stack (`registers.txt`: ST0 at 4352, ten bytes).
const ST0: std::ops::Range<u64> = 4352..4362;
/// Instruction budget for one function.
const BUDGET: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Observed {
    /// The single stack purge every reachable `ret` agrees on, `None` when they differ or none was reached.
    pub purge: Option<u16>,
    pub ecx_read_first: bool,
    pub edx_read_first: bool,
    /// A `push ecx`/`push edx` of a register nothing had written: Visual C++'s four-byte stack reservation (the decompiler
    /// reads it as the register's incoming value, an argument of the convention it resolves).
    pub reserved_by_push: bool,
    /// The body reads the x87 stack's top before anything wrote it: it takes an argument in `ST0`.
    pub reads_incoming_st0: bool,
    /// A float-to-integer conversion (`fistp`, `cvttsd2si`: `TRUNC`) somewhere in the body.
    pub truncates: bool,
    /// The walk met a call.
    pub calls: bool,
    /// Instructions walked.
    pub steps: usize,
}

impl Observed {
    /// The runtime helper that converts the x87 stack's top to an integer and returns it in `eax` (Visual C++ before 8.0 calls it
    /// `_ftol` for every `(int)` of a float, Visual C++ 8.0 `_ftol2_sse`, which tests for SSE2 first and has both conversions in its
    /// body): a few dozen instructions, no call, the argument in `ST0`.
    pub fn is_float_to_int_helper(self) -> bool {
        self.reads_incoming_st0 && self.truncates && !self.calls && self.steps <= 64
    }

    /// The convention to record, or `None` to leave the choice to the decompiler: `__stdcall+N`, the model and the
    /// bytes its `ret` pops (the decompiler's call sites need the purge: it is `extrapop = 4 + N`).
    pub fn model(self) -> Option<String> {
        if self.ecx_read_first || self.edx_read_first {
            return None;
        }
        match self.purge? {
            0 => self.reserved_by_push.then(|| "__cdecl".to_string()),
            purge => Some(format!("__stdcall+{purge}")),
        }
    }
}

fn overlaps(vn: &PcodeVarnode, range: &std::ops::Range<u64>) -> bool {
    vn.space == "register" && vn.offset < range.end && vn.offset + u64::from(vn.size) > range.start
}

/// `written` bit 1: ecx, bit 2: edx, bit 4: st0.
fn written_bits(vn: &PcodeVarnode) -> u8 {
    u8::from(overlaps(vn, &ECX)) | (u8::from(overlaps(vn, &EDX)) << 1) | (u8::from(overlaps(vn, &ST0)) << 2)
}

fn is_self_idiom(op: &PcodeOp) -> bool {
    matches!(op.opcode.as_str(), "INT_XOR" | "INT_SUB") && op.inputs.len() == 2 && op.inputs[0] == op.inputs[1]
}

/// Walks the function from `entry` over the instructions `lift` decodes (inside `[entry, end)` when `end` is known),
/// and `byte_at` reads the opcode byte of an instruction (`ret imm16` is `0xC2`).
pub fn observe(
    entry: u64,
    end: Option<u64>,
    mut lift: impl FnMut(u64) -> PcodeInstruction,
    byte_at: impl Fn(u64) -> Option<u8>,
    word_at: impl Fn(u64) -> Option<u16>,
) -> Observed {
    let mut seen: HashSet<(u64, u8)> = HashSet::new();
    let mut work = vec![(entry, 0u8)];
    let mut purges: HashSet<u16> = HashSet::new();
    let mut observed = Observed::default();
    let mut budget = BUDGET;
    while let Some((mut address, mut written)) = work.pop() {
        loop {
            if budget == 0 || end.is_some_and(|end| address >= end) || !seen.insert((address, written)) {
                break;
            }
            budget -= 1;
            observed.steps = BUDGET - budget;
            let instruction = lift(address);
            if instruction.error.is_some() {
                break;
            }
            let first = byte_at(address);
            let dummy_push = matches!(first, Some(0x51 | 0x52));
            if dummy_push && written & if first == Some(0x51) { 1 } else { 2 } == 0 {
                observed.reserved_by_push = true;
            }
            let mut next = Some(address + u64::from(instruction.length));
            let mut returned = false;
            for op in &instruction.ops {
                if matches!(op.opcode.as_str(), "TRUNC" | "FLOAT_TRUNC") {
                    observed.truncates = true;
                }
                // a `COPY` of the top of the stack is the shift every push and pop makes, not a use of its value
                if op.opcode != "COPY" && written & 4 == 0 && op.inputs.iter().any(|input| overlaps(input, &ST0)) {
                    observed.reads_incoming_st0 = true;
                }
                if !dummy_push && !is_self_idiom(op) {
                    for input in &op.inputs {
                        if overlaps(input, &ECX) && written & 1 == 0 {
                            observed.ecx_read_first = true;
                        }
                        if overlaps(input, &EDX) && written & 2 == 0 {
                            observed.edx_read_first = true;
                        }
                    }
                }
                if let Some(output) = &op.output {
                    written |= written_bits(output);
                }
                match op.opcode.as_str() {
                    "CALL" | "CALLIND" => {
                        written |= 3;
                        observed.calls = true;
                    }
                    "RETURN" => {
                        let purge = if first == Some(0xC2) { word_at(address + 1).unwrap_or(0) } else { 0 };
                        purges.insert(purge);
                        returned = true;
                    }
                    // a destination in the `ram` space is an address; one in `const` is a branch inside the
                    // instruction's own p-code, which continues to the next instruction
                    "BRANCH" | "CBRANCH" => {
                        if let Some(target) = op.inputs.first().filter(|vn| vn.space == "ram") {
                            work.push((target.offset, written));
                            if op.opcode == "BRANCH" {
                                next = None;
                            }
                        }
                    }
                    "BRANCHIND" => next = None,
                    _ => {}
                }
            }
            if returned {
                next = None;
            }
            match next {
                Some(following) => address = following,
                None => break,
            }
        }
    }
    if purges.len() == 1 {
        observed.purge = purges.into_iter().next();
    }
    observed
}

/// What the code of an i386 PE's functions proves: the model of each function for which it proves one (see the module comment)
/// and the entries of the runtime's float-to-integer helpers.
#[derive(Debug, Default)]
pub(in crate::native) struct Analysis {
    pub conventions: Vec<(u64, String)>,
    pub float_to_int: Vec<u64>,
}

/// Empty for any other image, and when the SLEIGH language cannot be loaded (the decompiler then falls back to its own
/// resolution). `ROMWRIGHT_PE_CONVENTIONS=off` records no model and `ROMWRIGHT_PE_FTOL=off` finds no helper.
pub(in crate::native) fn analyse(imp: &NativeImport) -> Analysis {
    let conventions_on = !std::env::var("ROMWRIGHT_PE_CONVENTIONS").is_ok_and(|v| v == "off");
    let ftol_on = !std::env::var("ROMWRIGHT_PE_FTOL").is_ok_and(|v| v == "off");
    if imp.format != "PE" || imp.language != "x86:LE:32:default" || !(conventions_on || ftol_on) {
        return Analysis::default();
    }
    let Ok(mut lifter) = crate::native_runtime::SleighLifter::mapped(&imp.cfg, imp) else {
        return Analysis::default();
    };
    let byte_at = |address: u64| {
        imp.mappings.iter().find_map(|mapping| {
            let offset = usize::try_from(address.checked_sub(mapping.vaddr)?).ok()?;
            mapping.bytes.get(offset).copied()
        })
    };
    let word_at = |address: u64| Some(u16::from_le_bytes([byte_at(address)?, byte_at(address + 1)?]));
    let mut found = Analysis::default();
    for function in &imp.functions {
        let end = (function.size > 0).then(|| function.entry + function.size);
        let lift = |address: u64| {
            lifter.lift(&[address]).into_iter().next().unwrap_or(PcodeInstruction {
                address,
                length: 1,
                ops: Vec::new(),
                error: Some("BAD".into()),
            })
        };
        let observed = observe(function.entry, end, lift, byte_at, word_at);
        if conventions_on
            && let Some(model) = observed.model() {
                found.conventions.push((function.entry, model));
            }
        if ftol_on && observed.is_float_to_int_helper() {
            found.float_to_int.push(function.entry);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode { space: "register".into(), offset, size }
    }

    fn op(opcode: &str, output: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOp {
        PcodeOp { opcode: opcode.into(), output, inputs }
    }

    fn instruction(address: u64, length: u8, ops: Vec<PcodeOp>) -> PcodeInstruction {
        PcodeInstruction { address, length, ops, error: None }
    }

    /// A code image of `(address, length, ops)` rows and the bytes the walk reads.
    fn run(rows: Vec<(u64, u8, Vec<PcodeOp>)>, bytes: Vec<(u64, u8)>, word: u16) -> Observed {
        let lift = |address: u64| match rows.iter().find(|row| row.0 == address) {
            Some((a, l, ops)) => instruction(*a, *l, ops.clone()),
            None => PcodeInstruction { address, length: 1, ops: vec![], error: Some("BAD".into()) },
        };
        let byte_at = |address: u64| bytes.iter().find(|row| row.0 == address).map(|row| row.1);
        observe(0x1000, None, lift, byte_at, |_| Some(word))
    }

    fn ret() -> Vec<PcodeOp> {
        vec![op("RETURN", None, vec![reg(16, 4)])]
    }

    #[test]
    fn a_ret_with_a_count_is_stdcall_unless_ecx_or_edx_is_read_first() {
        // mov eax,[esp+4]; ret 8
        let mine = run(
            vec![(0x1000, 4, vec![op("COPY", Some(reg(0, 4)), vec![reg(16, 4)])]), (0x1004, 3, ret())],
            vec![(0x1000, 0x8B), (0x1004, 0xC2)],
            8,
        );
        assert_eq!(mine.purge, Some(8));
        assert_eq!(mine.model().as_deref(), Some("__stdcall+8"));
        // mov eax,ecx; ret 4: __thiscall/__fastcall territory, left to the decompiler
        let reads_ecx = run(
            vec![(0x1000, 2, vec![op("COPY", Some(reg(0, 4)), vec![reg(4, 4)])]), (0x1002, 3, ret())],
            vec![(0x1000, 0x8B), (0x1002, 0xC2)],
            4,
        );
        assert!(reads_ecx.ecx_read_first);
        assert_eq!(reads_ecx.model(), None);
        // a plain ret is cdecl: nothing recorded ...
        let plain = run(vec![(0x1000, 1, ret())], vec![(0x1000, 0xC3)], 0);
        assert_eq!(plain.purge, Some(0));
        assert_eq!(plain.model(), None);
        // ... unless a `push ecx` reserved stack: recorded, so the decompiler does not read it as an argument
        let ecx = reg(4, 4);
        let reserved = run(
            vec![(0x1000, 1, vec![op("STORE", None, vec![ecx.clone()])]), (0x1001, 1, ret())],
            vec![(0x1000, 0x51), (0x1001, 0xC3)],
            0,
        );
        assert_eq!(reserved.model().as_deref(), Some("__cdecl"));
    }

    #[test]
    fn push_ecx_xor_self_and_a_call_are_not_reads_of_the_incoming_register() {
        let ecx = reg(4, 4);
        let rows = vec![
            (0x1000, 1, vec![op("INT_SUB", Some(reg(16, 4)), vec![reg(16, 4), PcodeVarnode { space: "const".into(), offset: 4, size: 4 }]),
                             op("STORE", None, vec![ecx.clone()])]),
            (0x1001, 2, vec![op("INT_XOR", Some(ecx.clone()), vec![ecx.clone(), ecx.clone()])]),
            (0x1003, 2, vec![op("COPY", Some(reg(0, 4)), vec![ecx.clone()])]),
            (0x1005, 3, ret()),
        ];
        let seen = run(rows, vec![(0x1000, 0x51), (0x1001, 0x33), (0x1003, 0x8B), (0x1005, 0xC2)], 12);
        assert!(!seen.ecx_read_first);
        assert_eq!(seen.model().as_deref(), Some("__stdcall+12"));
        // after a call both registers are clobbered, so a later read is of the call's result
        let rows = vec![
            (0x1000, 5, vec![op("CALL", None, vec![PcodeVarnode { space: "ram".into(), offset: 0x2000, size: 4 }])]),
            (0x1005, 2, vec![op("COPY", Some(reg(0, 4)), vec![ecx.clone()])]),
            (0x1007, 3, ret()),
        ];
        assert!(!run(rows, vec![(0x1000, 0xE8), (0x1005, 0x8B), (0x1007, 0xC2)], 4).ecx_read_first);
    }

    #[test]
    fn the_walk_follows_branches_and_does_not_decode_the_bytes_after_the_last_ret() {
        let target = |offset: u64| PcodeVarnode { space: "ram".into(), offset, size: 4 };
        let rows = vec![
            (0x1000, 2, vec![op("CBRANCH", None, vec![target(0x1008), reg(0, 1)])]),
            (0x1002, 1, ret()),
            // a jump table after the ret would decode as nonsense; the walk never reaches it
            (0x1008, 3, ret()),
        ];
        let seen = run(rows, vec![(0x1002, 0xC3), (0x1008, 0xC2)], 8);
        // one ret pops nothing, the other 8: they disagree, so no model
        assert_eq!(seen.purge, None);
        assert_eq!(seen.model(), None);
    }

    #[test]
    fn a_small_call_free_body_that_truncates_the_incoming_x87_top_is_the_float_to_int_helper() {
        let st0 = reg(4352, 10);
        let truncate = |input: PcodeVarnode| vec![op("ROUND", Some(reg(0, 10)), vec![input]), op("TRUNC", Some(reg(0, 8)), vec![reg(0, 10)])];
        // fistp qword [ebp-12]; mov eax,[ebp-12]; ret
        let helper = run(vec![(0x1000, 3, truncate(st0.clone())), (0x1003, 3, ret())], vec![(0x1003, 0xC3)], 0);
        assert!(helper.is_float_to_int_helper());
        // the same instruction after the body wrote the top of the stack (`fld [esp+4]` first) is a function of its own
        let own = run(
            vec![(0x1000, 4, vec![op("FLOAT_FLOAT2FLOAT", Some(st0.clone()), vec![reg(16, 4)])]), (0x1004, 3, truncate(st0.clone())), (0x1007, 1, ret())],
            vec![(0x1007, 0xC3)],
            0,
        );
        assert!(!own.reads_incoming_st0 && !own.is_float_to_int_helper());
        // a call makes it something else
        let calls = run(
            vec![(0x1000, 5, vec![op("CALL", None, vec![PcodeVarnode { space: "ram".into(), offset: 0x2000, size: 4 }])]), (0x1005, 3, truncate(st0)), (0x1008, 1, ret())],
            vec![(0x1008, 0xC3)],
            0,
        );
        assert!(!calls.is_float_to_int_helper());
    }
}
