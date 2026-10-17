//! Variadic register-save areas, read from p-code.
//!
//! A C function with `...` has to hand `va_arg` the arguments that arrived
//! in registers, so its prologue writes the tail of the argument register
//! list into the frame: `stmdb sp!,{r1-r3}`, MIPS `sd a1,0x18(sp)` ..
//! `sd t3,0x48(sp)`, PowerPC `stw r4,8(r1)` .. `stw r10,0x24(r1)`, x86-64
//! `mov [rsp+0x28],rsi` .. `mov [rsp+0x48],r9`. The decompiler sees every one
//! of those registers read and commits all of them as parameters, so the
//! function claims `(fmt, a2, a3, a4, a5, a6, a7, a8)` instead of
//! `(fmt, ...)`. Persisted, that prototype is read at every call site as
//! eight arguments, and each caller that set only two of them inherits the
//! other six as parameters of its own, which propagates up the call graph
//! one round at a time.
//!
//! The evidence that a trailing run of argument registers is a save area and
//! not parameters is all in the function's entry block:
//!
//! * every read of each register's entry value is the store of it (or of a
//!   narrowed copy of it) into the frame, at increasing consecutive
//!   addresses in register order;
//! * no direct load ever reads those slots back (an unoptimised function
//!   spills its real parameters and then reloads them from the same slot);
//! * the run reaches the last argument register, which is what `va_start`
//!   needs and what a function that merely stores two of its own parameters
//!   does not do;
//! * a named parameter precedes the run (C requires one), so a run that
//!   begins at the first register is a by-value aggregate, not `...`;
//! * the stores come before the function's first control transfer.
//!
//! Anything weaker is left alone: a function that also *uses* one of the
//! registers, spills it elsewhere, or stores only part of the tail keeps the
//! decompiler's answer.
use std::collections::{BTreeMap, BTreeSet};

use super::Machine;
use crate::native_runtime::{PcodeInstruction, PcodeVarnode};

type Key<'a> = (&'a str, u64);

fn key(varnode: &PcodeVarnode) -> Key<'_> {
    (varnode.space.as_str(), varnode.offset)
}

/// A constant operand as the signed number of its width (`0xffffffe0` in four
/// bytes is -32, which is how `addiu sp,sp,-32` arrives).
fn signed(constant: &PcodeVarnode) -> i64 {
    match constant.size {
        1 => i64::from(constant.offset as u8 as i8),
        2 => i64::from(constant.offset as u16 as i16),
        4 => i64::from(constant.offset as u32 as i32),
        _ => constant.offset as i64,
    }
}

/// Where one argument register's entry value went.
#[derive(Debug, Default, Clone, Copy)]
struct Slot {
    /// Frame displacement (from the stack pointer at entry), stored width
    /// and operation index of the first spill.
    spill: Option<(i64, u32, usize)>,
    /// Read by anything other than the spill: a real parameter.
    used: bool,
}

/// The number of leading integer argument slots that are named parameters,
/// when the function's remaining argument registers are only a variadic
/// register-save area. `slots` are the register offsets of the default
/// prototype model's integer parameter registers, in order.
pub fn named_slots(
    instructions: &[PcodeInstruction],
    slots: &[u64],
    machine: &Machine,
) -> Option<usize> {
    let stack_pointer = machine.stack_pointer?;
    if slots.len() < 3 {
        return None;
    }
    let slot_of: BTreeMap<u64, usize> =
        slots.iter().enumerate().map(|(index, offset)| (*offset, index)).collect();
    let mut state = vec![Slot::default(); slots.len()];
    let mut defined: BTreeSet<u64> = BTreeSet::new();
    // A varnode holding a frame address, as a displacement from the stack
    // pointer at entry. The stack pointer is such a varnode from the start.
    let mut frame: BTreeMap<Key<'_>, i64> = BTreeMap::new();
    frame.insert(("register", stack_pointer), 0);
    // A temporary holding (a narrowed copy of) an argument register's entry
    // value.
    let mut carried: BTreeMap<Key<'_>, usize> = BTreeMap::new();
    let mut loads: Vec<(i64, u32)> = Vec::new();
    let mut first_control: Option<usize> = None;
    let mut index = 0usize;
    for instruction in instructions {
        for op in &instruction.ops {
            index += 1;
            let opcode = op.opcode.as_str();
            if first_control.is_none()
                && matches!(
                    opcode,
                    "BRANCH" | "CBRANCH" | "BRANCHIND" | "CALL" | "CALLIND" | "RETURN"
                )
            {
                first_control = Some(index);
            }
            // Which argument register's entry value each data input carries.
            let origin = |input: &PcodeVarnode| -> Option<usize> {
                if input.space == "register" && !defined.contains(&input.offset) {
                    slot_of.get(&input.offset).copied()
                } else {
                    carried.get(&key(input)).copied()
                }
            };
            let mut carries: Option<usize> = None;
            match opcode {
                "STORE" => {
                    let address = op.inputs.get(1).and_then(|a| frame.get(&key(a)).copied());
                    for (position, input) in op.inputs.iter().enumerate().skip(1) {
                        let Some(slot) = origin(input) else { continue };
                        match (position, address) {
                            (2, Some(displacement)) => {
                                let state = &mut state[slot];
                                if state.spill.is_none() {
                                    state.spill = Some((displacement, input.size, index));
                                }
                            }
                            _ => state[slot].used = true,
                        }
                    }
                }
                "COPY" | "SUBPIECE" | "INT_ZEXT" | "INT_SEXT" => {
                    let input = op.inputs.first();
                    let slot = input.and_then(&origin);
                    match (slot, &op.output) {
                        (Some(slot), Some(output)) if output.space == "unique" => {
                            carries = Some(slot);
                        }
                        (Some(slot), _) => state[slot].used = true,
                        _ => {}
                    }
                }
                "LOAD" => {
                    if let (Some(address), Some(output)) = (op.inputs.get(1), &op.output)
                        && let Some(displacement) = frame.get(&key(address))
                    {
                        loads.push((*displacement, output.size));
                    }
                    for input in op.inputs.iter().skip(1) {
                        if let Some(slot) = origin(input) {
                            state[slot].used = true;
                        }
                    }
                }
                _ => {
                    for input in &op.inputs {
                        if let Some(slot) = origin(input) {
                            state[slot].used = true;
                        }
                    }
                }
            }
            // Frame address arithmetic: `base +- constant`, a plain copy, or a
            // re-extension of the stack pointer (MIPS64 writes `sp` at 4 bytes
            // and sign-extends it to 8).
            let mut resolved: Option<i64> = None;
            if let Some(base) = op.inputs.first().and_then(|b| frame.get(&key(b)).copied()) {
                resolved = match (opcode, op.inputs.get(1)) {
                    ("COPY" | "INT_SEXT" | "INT_ZEXT", _) => Some(base),
                    ("SUBPIECE", Some(c)) if c.space == "const" && c.offset == 0 => Some(base),
                    ("INT_ADD", Some(c)) if c.space == "const" => Some(base + signed(c)),
                    ("INT_SUB", Some(c)) if c.space == "const" => Some(base - signed(c)),
                    _ => None,
                };
            }
            if let Some(output) = &op.output {
                let output_key = key(output);
                frame.remove(&output_key);
                carried.remove(&output_key);
                if let Some(displacement) = resolved {
                    frame.insert(output_key, displacement);
                }
                if let Some(slot) = carries {
                    carried.insert(output_key, slot);
                }
                if output.space == "register" {
                    defined.insert(output.offset);
                }
            }
        }
    }
    let spilled = |slot: usize| -> Option<(i64, u32, usize)> {
        let slot = &state[slot];
        let (displacement, width, at) = slot.spill?;
        let reloaded = loads.iter().any(|(at_load, size)| {
            *at_load < displacement + i64::from(width) && displacement < *at_load + i64::from(*size)
        });
        (!slot.used && !reloaded).then_some((displacement, width, at))
    };
    // The longest run of save-area slots that ends at the last register:
    // spilled before the first control transfer, packed at one stride.
    let mut first = slots.len();
    let mut stride: Option<i64> = None;
    let mut later: Option<i64> = None;
    for slot in (0..slots.len()).rev() {
        let Some((displacement, width, at)) = spilled(slot) else { break };
        if first_control.is_some_and(|control| at >= control) {
            break;
        }
        if let Some(later) = later {
            let step = later - displacement;
            if step != i64::from(width) || stride.is_some_and(|stride| stride != step) {
                break;
            }
            stride = Some(step);
        }
        later = Some(displacement);
        first = slot;
    }
    // A named parameter precedes the run, and the run is more than one
    // store: a lone trailing spill is one parameter written to a local.
    (first >= 1 && slots.len() - first >= 2).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_runtime::PcodeOp;

    fn reg(offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode { space: "register".into(), offset, size }
    }
    fn unique(offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode { space: "unique".into(), offset, size }
    }
    fn constant(value: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode { space: "const".into(), offset: value, size }
    }
    fn op(opcode: &str, output: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOp {
        PcodeOp { opcode: opcode.into(), output, inputs }
    }
    fn instruction(address: u64, ops: Vec<PcodeOp>) -> PcodeInstruction {
        PcodeInstruction { address, length: 4, ops, error: None }
    }

    const SP: u64 = 0x100;
    const A0: u64 = 0x10;
    const MACHINE: Machine = Machine { pointer_size: 4, stack_pointer: Some(SP) };
    fn slots() -> Vec<u64> {
        (0..4).map(|index| A0 + index * 8).collect()
    }

    /// `sw argN, disp(sp)` the way the MIPS language lifts it: the address
    /// is a temporary and the 4-byte store takes a narrowed copy.
    fn spill(address: u64, register: u64, displacement: u64) -> PcodeInstruction {
        instruction(
            address,
            vec![
                op("INT_ADD", Some(unique(0x1000, 4)), vec![reg(SP, 4), constant(displacement, 4)]),
                op("SUBPIECE", Some(unique(0x1010, 4)), vec![reg(register, 8), constant(0, 4)]),
                op("STORE", None, vec![constant(1, 4), unique(0x1000, 4), unique(0x1010, 4)]),
            ],
        )
    }

    fn use_of(address: u64, register: u64) -> PcodeInstruction {
        instruction(
            address,
            vec![op("INT_ADD", Some(reg(0x500, 4)), vec![reg(register, 4), constant(1, 4)])],
        )
    }

    #[test]
    fn a_trailing_save_area_leaves_the_named_parameters() {
        let program = vec![
            spill(0, A0 + 8, 0x24),
            spill(4, A0 + 16, 0x28),
            spill(8, A0 + 24, 0x2c),
            use_of(12, A0),
            use_of(16, A0 + 8),
        ];
        // a1 is read too, so it is named: the save area is a2, a3.
        assert_eq!(named_slots(&program, &slots(), &MACHINE), Some(2));
    }

    #[test]
    fn the_save_area_starts_after_the_last_named_parameter() {
        let program = vec![
            spill(0, A0 + 8, 0x24),
            spill(4, A0 + 16, 0x28),
            spill(8, A0 + 24, 0x2c),
            use_of(12, A0),
        ];
        assert_eq!(named_slots(&program, &slots(), &MACHINE), Some(1));
    }

    #[test]
    fn a_sign_extended_stack_pointer_is_still_the_frame() {
        // `addiu sp,sp,-64` on a 64-bit MIPS: a 4-byte add, then the result
        // sign-extended back into the 8-byte register.
        let adjust = instruction(
            0,
            vec![
                op("INT_ADD", Some(reg(SP, 4)), vec![reg(SP, 4), constant(0xffff_ffc0, 4)]),
                op("INT_SEXT", Some(reg(SP, 8)), vec![reg(SP, 4)]),
            ],
        );
        let program = vec![
            adjust,
            spill(4, A0 + 8, 0x24),
            spill(8, A0 + 16, 0x28),
            spill(12, A0 + 24, 0x2c),
            use_of(16, A0),
        ];
        assert_eq!(named_slots(&program, &slots(), &MACHINE), Some(1));
    }

    #[test]
    fn a_register_run_from_the_first_register_is_not_variadic() {
        let program = vec![
            spill(0, A0, 0x20),
            spill(4, A0 + 8, 0x24),
            spill(8, A0 + 16, 0x28),
            spill(12, A0 + 24, 0x2c),
        ];
        assert_eq!(named_slots(&program, &slots(), &MACHINE), None);
    }

    #[test]
    fn a_spill_that_is_reloaded_is_a_parameter() {
        let mut program = vec![
            spill(0, A0 + 8, 0x24),
            spill(4, A0 + 16, 0x28),
            spill(8, A0 + 24, 0x2c),
            use_of(12, A0),
        ];
        program.push(instruction(
            16,
            vec![
                op("INT_ADD", Some(unique(0x2000, 4)), vec![reg(SP, 4), constant(0x28, 4)]),
                op("LOAD", Some(reg(0x500, 4)), vec![constant(1, 4), unique(0x2000, 4)]),
            ],
        ));
        // a2's slot is read back, so only a3 remains: one store is no run.
        assert_eq!(named_slots(&program, &slots(), &MACHINE), None);
    }

    #[test]
    fn stores_after_a_branch_are_not_a_prologue() {
        let program = vec![
            use_of(0, A0),
            instruction(4, vec![op("BRANCH", None, vec![constant(0x40, 4)])]),
            spill(8, A0 + 8, 0x24),
            spill(12, A0 + 16, 0x28),
            spill(16, A0 + 24, 0x2c),
        ];
        assert_eq!(named_slots(&program, &slots(), &MACHINE), None);
    }

    #[test]
    fn a_gap_in_the_run_ends_it() {
        let program = vec![
            use_of(0, A0),
            spill(4, A0 + 8, 0x20),
            spill(8, A0 + 16, 0x30),
            spill(12, A0 + 24, 0x34),
        ];
        // a2 and a3 are contiguous; a1 is not adjacent to them.
        assert_eq!(named_slots(&program, &slots(), &MACHINE), Some(2));
    }
}
