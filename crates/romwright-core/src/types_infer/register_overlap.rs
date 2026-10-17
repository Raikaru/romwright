//! Float parameter registers the body also touches at another width.
//!
//! ARM VFP names one register file three ways: `s0`, `d0` (= `s0`, `s1`) and
//! `q0` (= `s0`..`s3`). A function that reads or writes `q0` or `d0` whole, as
//! a vector op does, and `s0` alone, has varnodes at overlapping addresses.
//! The decompiler's own recovery copes: it splits the wide access into
//! pieces. Applied as a locked prototype, though, `float param_1` pins `s0`
//! as a four-byte input of its own, heritage then asks for the whole `q0` as
//! an input beside the `s1`..`s3` remainder, and the decompiler stops with
//! `Low-level Error: Overlapping input varnodes` (new `q0` 16 bytes against
//! old `s1`-`s3` 12 bytes, on every function that fails this way on Vita).
//! Persisting such a prototype breaks every later decompile of the function,
//! so the job leaves it out and the decompiler keeps recovering the function
//! freshly.
use std::collections::BTreeSet;

use romwright_model::function_ir::FunctionIr;

use crate::native_runtime::PcodeInstruction;

fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.0 + b.1 && b.0 < a.0 + a.1
}

/// Indices into `slots` (register offset and size, in parameter order) whose
/// register the body touches, anywhere, as part of a varnode of a different
/// offset or width: read whole as `d0` or `q0`, or written whole by a vector
/// load. Heritage merges those wide accesses with the pieces around them, and
/// a locked four-byte input in the middle no longer fits.
pub fn overlapped(instructions: &[PcodeInstruction], slots: &[(u64, u32)]) -> BTreeSet<usize> {
    let mut touched: BTreeSet<(u64, u32)> = BTreeSet::new();
    for op in instructions.iter().flat_map(|instruction| &instruction.ops) {
        for varnode in op.inputs.iter().chain(op.output.as_ref()) {
            if varnode.space == "register" {
                touched.insert((varnode.offset, varnode.size));
            }
        }
    }
    slots
        .iter()
        .enumerate()
        .filter(|(_, (offset, size))| {
            touched.iter().any(|(at, width)| {
                (*at, *width) != (*offset, *size)
                    && overlaps((*at, u64::from(*width)), (*offset, u64::from(*size)))
            })
        })
        .map(|(index, _)| index)
        .collect()
}

/// The floating-point parameter registers of the default prototype model, and
/// the registers the model names (stack pointer, parameter and result
/// registers), whose values identify the register space in a `FunctionIr`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FloatLayout {
    pub known: Vec<(u64, u32)>,
    pub registers: Vec<(u64, u32)>,
}

/// `overlapped`, read from the decompiler's own recovery instead of the lifted
/// p-code. The lifted body can stop short (a jump table's targets are not
/// walked), so an access that the decompiler sees may be missing from it: the
/// recovered `FunctionIr` holds a value for every register varnode the
/// decompiler built. The register space is the one holding most of the
/// layout's known registers at exactly their offset and size.
pub fn overlapped_ir(ir: &FunctionIr, layout: &FloatLayout) -> BTreeSet<usize> {
    let known: BTreeSet<(u64, u32)> = layout.known.iter().copied().collect();
    let mut votes: Vec<(romwright_model::function_ir::IrSpace, BTreeSet<(u64, u32)>)> = Vec::new();
    for value in ir.values.values() {
        let (Some(offset), Some(size)) = (value.offset, value.size) else { continue };
        if !known.contains(&(offset, size)) {
            continue;
        }
        match votes.iter_mut().find(|(space, _)| *space == value.space) {
            Some((_, seen)) => {
                seen.insert((offset, size));
            }
            None => votes.push((value.space.clone(), BTreeSet::from([(offset, size)]))),
        }
    }
    let Some(space) = votes.into_iter().max_by_key(|(_, seen)| seen.len()).map(|(space, _)| space) else {
        return BTreeSet::new();
    };
    let touched: BTreeSet<(u64, u32)> = ir
        .values
        .values()
        .filter(|value| value.space == space)
        .filter_map(|value| Some((value.offset?, value.size?)))
        .collect();
    layout
        .registers
        .iter()
        .enumerate()
        .filter(|(_, (offset, size))| {
            touched.iter().any(|(at, width)| {
                (*at, *width) != (*offset, *size)
                    && overlaps((*at, u64::from(*width)), (*offset, u64::from(*size)))
            })
        })
        .map(|(index, _)| index)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_runtime::{PcodeOp, PcodeVarnode};

    fn reg(offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode { space: "register".into(), offset, size }
    }
    fn read(offset: u64, size: u32) -> PcodeInstruction {
        PcodeInstruction {
            address: 0,
            length: 4,
            ops: vec![PcodeOp { opcode: "COPY".into(), output: Some(reg(0x900, 4)), inputs: vec![reg(offset, size)] }],
            error: None,
        }
    }
    fn write(offset: u64, size: u32) -> PcodeInstruction {
        PcodeInstruction {
            address: 0,
            length: 4,
            ops: vec![PcodeOp {
                opcode: "COPY".into(),
                output: Some(reg(offset, size)),
                inputs: vec![PcodeVarnode { space: "const".into(), offset: 0, size }],
            }],
            error: None,
        }
    }

    const S: [(u64, u32); 2] = [(0x300, 4), (0x304, 4)];

    #[test]
    fn a_read_of_the_exact_register_overlaps_nothing() {
        assert!(overlapped(&[read(0x300, 4), read(0x304, 4)], &S).is_empty());
    }

    #[test]
    fn a_wide_read_over_a_parameter_register_is_an_overlap() {
        // d0 = s0:s1 read whole; s1 alone is read too.
        let found = overlapped(&[read(0x300, 8), read(0x304, 4)], &S);
        assert_eq!(found, BTreeSet::from([0, 1]));
        // q1 does not cover s0 or s1.
        assert!(overlapped(&[read(0x310, 16)], &S).is_empty());
    }

    #[test]
    fn a_wide_write_over_a_parameter_register_is_an_overlap_too() {
        // q0 written whole after s0 was read alone.
        let found = overlapped(&[read(0x300, 4), write(0x300, 16)], &S);
        assert_eq!(found, BTreeSet::from([0, 1]));
    }

    fn ir_value(id: u64, space: u64, offset: u64, size: u32) -> romwright_model::function_ir::IrValue {
        use romwright_model::function_ir::{IrSpace, IrValue, ValueId};
        IrValue {
            id: ValueId(id),
            space: IrSpace::Index(space),
            offset: Some(offset),
            size: Some(size),
            pieces: Vec::new(),
            input: true,
            persistent: false,
            address_tied: false,
            unaffected: false,
            volatile: false,
        }
    }

    fn ir(values: Vec<romwright_model::function_ir::IrValue>) -> FunctionIr {
        FunctionIr {
            values: values.into_iter().map(|value| (value.id, value)).collect(),
            blocks: Vec::new(),
            high_variables: Vec::new(),
            type_evidence: Default::default(),
            control_flow_cuts: Vec::new(),
            passes: Vec::new(),
            diagnostics: Vec::new(),
            cast_types: Vec::new(),
        }
    }

    #[test]
    fn the_recovery_shows_a_wide_value_in_the_register_space_only() {
        let layout = FloatLayout { known: vec![(0x54, 4), (0x300, 4), (0x304, 4)], registers: S.to_vec() };
        // Space 4 holds the stack pointer; a 16-byte value at 0x300 is in it.
        // A tiny function with only s0 in it still names its space.
        let wide = ir(vec![ir_value(1, 4, 0x54, 4), ir_value(2, 4, 0x300, 16), ir_value(3, 4, 0x300, 4)]);
        assert_eq!(overlapped_ir(&wide, &layout), BTreeSet::from([0, 1]));
        // The same offsets in another space (unique temporaries) are not registers.
        let other = ir(vec![ir_value(1, 4, 0x54, 4), ir_value(2, 1, 0x300, 16)]);
        assert!(overlapped_ir(&other, &layout).is_empty());
        // Exact four-byte values overlap nothing; no stack pointer, no register space.
        let exact = ir(vec![ir_value(1, 4, 0x54, 4), ir_value(2, 4, 0x300, 4), ir_value(3, 4, 0x304, 4)]);
        assert!(overlapped_ir(&exact, &layout).is_empty());
        assert!(overlapped_ir(&wide, &FloatLayout { known: Vec::new(), registers: S.to_vec() }).is_empty());
    }
}
