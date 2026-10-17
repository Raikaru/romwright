//! Eight-byte parameters passed in an aligned pair of 4-byte registers.
//!
//! On a 32-bit register ABI (PSP/o32-style EABI, ARM AAPCS, PowerPC EABI) a
//! `double` or `long long` argument occupies two consecutive argument
//! registers, the first at an even slot (`a0:a1`, `a2:a3`, `t0:t1`). The
//! decompiler's own recovery only ever finds single-register parameters, so a
//! function taking `double x` recovers as `(undefined4, undefined4)` and its
//! callers print the value split in two.
//!
//! The evidence is read off the decompiler's SSA, not guessed from a body's
//! shape. When a call's argument is a joined 8-byte value (`PIECE`, through
//! `CAST`/`COPY`) whose two halves are *the function's own entry values* of an
//! aligned register pair, the function receives one value in that pair and
//! hands it whole to a callee whose prototype declares an 8-byte parameter
//! there (a documented library or run-time helper, debug information, or a
//! prototype this pass already joined in an earlier round, so the evidence
//! travels up the call graph). Nothing else counts: a single reader of the
//! high word (`and a1, 0x7fffffff`), two spills to adjacent slots, a pair of
//! loads, or a hole in the argument registers are all things two separate
//! `int` parameters do too.
//!
//! What the pass changes is the parameter list only: the two single-register
//! parameters at the pair's slots become one parameter of the callee's
//! declared type. The binary is the same either way (the ABI puts an 8-byte
//! value in exactly those registers); the join is what makes the printed
//! signature and the callers' call sites say one value.
use std::collections::{BTreeMap, BTreeSet};

use romwright_model::function_ir::{FunctionIr, IrSpace, IrValue, Opcode, OperationId, Operand, ValueId};
use romwright_model::{DecompType, FuncParam, FuncProto};

use super::prototypes::Target;

/// The integer argument registers of the default prototype model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairLayout {
    /// Register-space offsets of the integer argument registers, in order.
    pub slots: Vec<u64>,
    /// Bytes in each of them.
    pub sizes: Vec<u32>,
    /// Whether the most significant word of an 8-byte value is in the
    /// lower-numbered register (big-endian EABIs) or the higher one.
    pub high_in_lower_slot: bool,
}

/// One 8-byte argument built from two of the function's entry registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// First slot of the pair (even), as an index into `PairLayout::slots`.
    pub slot: usize,
    /// The declared type of the callee's parameter the pair was passed as.
    pub data_type: DecompType,
    /// Whether the register just below the pair (the odd slot an 8-byte value
    /// skips to reach an even one) is never read by the body: the alignment
    /// hole of `f(int a, double b)`, not a parameter.
    pub hole_unread: bool,
}

impl crate::Core {
    /// The integer argument registers of the program's default prototype
    /// model, and which end of an 8-byte value sits in the lower register.
    pub fn pair_layout(&self, req: &crate::exec::ExecutionRequest) -> crate::Result<PairLayout> {
        let (_, specs, _, _) =
            crate::native_runtime::language_decompile_config(&req.config, &req.language)?;
        let cspec = std::fs::read_to_string(specs.join("cspec.xml"))?;
        let table = std::fs::read_to_string(specs.join("registers.txt"))?;
        let conventions = crate::register_params::Conventions::parse(&cspec, &table);
        let mut layout = PairLayout {
            slots: Vec::new(),
            sizes: Vec::new(),
            high_in_lower_slot: req.language.contains(":BE:"),
        };
        if let Some(model) = conventions.default() {
            for name in &model.registers {
                if let Some((offset, size)) = conventions.registers.get(name) {
                    layout.slots.push(*offset);
                    layout.sizes.push(u32::try_from(*size).unwrap_or(u32::MAX));
                }
            }
        }
        Ok(layout)
    }
}

fn definitions(ir: &FunctionIr) -> BTreeMap<ValueId, &romwright_model::function_ir::IrOperation> {
    ir.blocks
        .iter()
        .flat_map(|block| &block.operations)
        .filter_map(|operation| operation.output.map(|output| (output, operation)))
        .collect()
}

/// The register space of an IR: the one holding the most argument registers at
/// exactly their offset and size (the same vote `register_overlap` takes).
fn register_space(ir: &FunctionIr, layout: &PairLayout) -> Option<IrSpace> {
    let known: BTreeSet<(u64, u32)> =
        layout.slots.iter().copied().zip(layout.sizes.iter().copied()).collect();
    let mut votes: Vec<(IrSpace, BTreeSet<(u64, u32)>)> = Vec::new();
    for value in ir.values.values().filter(|value| value.input) {
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
    votes.into_iter().max_by_key(|(_, seen)| seen.len()).map(|(space, _)| space)
}

/// Every call argument of `ir` that is one 8-byte value assembled from an
/// aligned pair of this function's entry registers, with the type the callee
/// declares for it. `calls` is the recovery's per-call prototype table.
pub fn sightings(
    ir: &FunctionIr,
    calls: &BTreeMap<OperationId, FuncProto>,
    layout: &PairLayout,
) -> Vec<Sighting> {
    let Some(registers) = register_space(ir, layout) else { return Vec::new() };
    let defining = definitions(ir);
    let slot_of = |value: &IrValue| -> Option<usize> {
        if !value.input || value.space != registers {
            return None;
        }
        let (offset, size) = (value.offset?, value.size?);
        let slot = layout.slots.iter().position(|at| *at == offset)?;
        (layout.sizes[slot] == size).then_some(slot)
    };
    // Argument registers whose entry value anything reads.
    let mut read: BTreeSet<usize> = BTreeSet::new();
    for operation in ir.blocks.iter().flat_map(|block| &block.operations) {
        for input in &operation.inputs {
            if let Operand::Value(id) = input
                && let Some(slot) = ir.values.get(id).and_then(&slot_of)
            {
                read.insert(slot);
            }
        }
    }
    let mut found = Vec::new();
    for operation in ir.blocks.iter().flat_map(|block| &block.operations) {
        if !matches!(operation.opcode, Opcode::CALL | Opcode::CALLIND) {
            continue;
        }
        let Some(callee) = calls.get(&operation.id) else { continue };
        for (index, argument) in operation.inputs.iter().skip(1).enumerate() {
            let Some(parameter) = callee.parameters.get(index) else { break };
            let Operand::Value(mut value) = *argument else { continue };
            // The argument may have been cast to the callee's declared type.
            let mut piece = None;
            for _ in 0..4 {
                let Some(definition) = defining.get(&value) else { break };
                match definition.opcode {
                    Opcode::CAST | Opcode::COPY => match definition.inputs.first() {
                        Some(Operand::Value(next)) => value = *next,
                        _ => break,
                    },
                    Opcode::PIECE => {
                        piece = Some(*definition);
                        break;
                    }
                    _ => break,
                }
            }
            let Some(piece) = piece else { continue };
            // One 8-byte value, whether the decompiler wrote it as the call's
            // joined argument storage or as a temporary it later cast to the
            // declared type. That the callee's parameter really is 8 bytes is
            // checked against its declared type when the prototype is joined.
            let Some(joined) = piece.output.and_then(|output| ir.values.get(&output)) else { continue };
            if joined.size != Some(2 * layout.sizes[0]) {
                continue;
            }
            let [Operand::Value(high), Operand::Value(low)] = piece.inputs.as_slice() else { continue };
            let (Some(high), Some(low)) = (ir.values.get(high), ir.values.get(low)) else { continue };
            let (Some(high), Some(low)) = (slot_of(high), slot_of(low)) else { continue };
            let first = high.min(low);
            let aligned = first % 2 == 0 && high.abs_diff(low) == 1;
            // The most significant word sits where the ABI puts it.
            let oriented = (high > low) == !layout.high_in_lower_slot;
            if aligned && oriented {
                found.push(Sighting {
                    slot: first,
                    data_type: parameter.data_type.clone(),
                    hole_unread: first >= 2 && !read.contains(&(first - 1)),
                });
            }
        }
    }
    found
}

/// Folds a later round's sightings of one function into the earlier ones.
///
/// What an earlier round proved stays proved: a callee prototype persisted
/// since can make the recovery read the slot below a pair (the hole of
/// `f(int, double)` becomes a parameter of the callee, so its callers pass the
/// register through), which says nothing about the body. A round that saw the
/// slot unread saw the body, so `hole_unread` is sticky; and a round that
/// sees no pair at all (the recovery took a changed callee into account) does
/// not take back a pair an earlier round saw.
pub fn carry_forward(earlier: Option<&[Sighting]>, mut found: Vec<Sighting>) -> Vec<Sighting> {
    let Some(earlier) = earlier else { return found };
    for sighting in &mut found {
        sighting.hole_unread |=
            earlier.iter().any(|before| before.slot == sighting.slot && before.hole_unread);
    }
    if found.is_empty() { earlier.to_vec() } else { found }
}

/// The provenance suffix of a prototype whose register pairs were joined.
pub const SOURCE: &str = "native-prototype:joined-pairs";

/// Joins the single-register parameters at each sighted pair into one
/// parameter of the declared type; returns how many pairs were joined.
///
/// Parameters map onto integer slots in order. A single-precision float uses
/// the float registers and no integer slot; any other parameter that is not
/// one 4-byte integer-like register ends the mapping, since every later slot
/// would be a guess. A pair is joined only when both of its slots hold an
/// unknown/int/uint parameter (not a pointer or a float: those are evidence
/// the two words are separate values) and every sighting of it names the same
/// declared 8-byte type.
pub fn join(
    prototype: &mut FuncProto,
    sightings: &[Sighting],
    layout: &PairLayout,
    target: &Target,
) -> usize {
    if sightings.is_empty()
        || prototype.variadic
        || (!matches!(prototype.calling_convention.as_str(), "" | "unknown" | "default")
            && prototype.calling_convention != target.model)
    {
        return 0;
    }
    // One declared type per pair; a pair seen as two different types is not
    // one this pass can name.
    let mut declared: BTreeMap<usize, Option<&DecompType>> = BTreeMap::new();
    for sighting in sightings {
        match declared.get(&sighting.slot) {
            None => {
                declared.insert(sighting.slot, Some(&sighting.data_type));
            }
            Some(Some(seen)) if same_type(seen, &sighting.data_type) => {}
            Some(_) => {
                declared.insert(sighting.slot, None);
            }
        }
    }
    // Where each parameter lives: index -> slot, until the mapping breaks.
    let mut placed: Vec<(usize, usize)> = Vec::new(); // (parameter index, slot)
    let mut slot = 0usize;
    for (index, parameter) in prototype.parameters.iter().enumerate() {
        let Some((metatype, size)) = target.shape(&parameter.data_type) else { break };
        if metatype == "float" && size <= 4 {
            continue;
        }
        let Some(&register) = layout.sizes.get(slot) else { break };
        let integral = matches!(metatype, "unknown" | "int" | "uint" | "bool" | "ptr");
        if !integral || size == 0 || size > register {
            break;
        }
        placed.push((index, slot));
        slot += 1;
    }
    // Whether every sighting of a pair says the slot below it is never read.
    let mut hole: BTreeMap<usize, bool> = BTreeMap::new();
    for sighting in sightings {
        let entry = hole.entry(sighting.slot).or_insert(true);
        *entry &= sighting.hole_unread;
    }
    let mut joins: Vec<(usize, DecompType, bool)> = Vec::new(); // (first parameter index, type, drop the hole)
    for (&first, data_type) in &declared {
        let Some(data_type) = data_type else { continue };
        let Some((metatype, size)) = target.shape(data_type) else { continue };
        // Two registers hold it exactly: on a machine whose registers are
        // 8 bytes wide the same value is one register, never a pair.
        let register = |slot: usize| layout.sizes.get(slot).copied().unwrap_or(0);
        if size != 2 * register(first)
            || register(first) != register(first + 1)
            || !matches!(metatype, "float" | "int" | "uint")
        {
            continue;
        }
        let at = |wanted: usize| {
            placed.iter().find(|(_, slot)| *slot == wanted).map(|(index, _)| *index)
        };
        let (Some(low), Some(high)) = (at(first), at(first + 1)) else { continue };
        if high != low + 1 {
            continue;
        }
        let plain = |index: usize| {
            target
                .shape(&prototype.parameters[index].data_type)
                .is_some_and(|(metatype, size)| matches!(metatype, "unknown" | "int" | "uint") && size == 4)
        };
        if plain(low) && plain(high) {
            // The odd slot below an even-slot pair, when nothing reads it, is
            // the hole the ABI leaves to align the pair: the recovery had to
            // invent a parameter for it. A parameter that really is unused
            // looks the same in the registers, but an odd count of 4-byte
            // parameters before an 8-byte one is how such functions are
            // written (`f(int a, double b)`); an unused one is the exception.
            let hole_index = (first >= 2 && hole.get(&first) == Some(&true)).then(|| at(first - 1)).flatten();
            let droppable = hole_index.is_some_and(|below| below + 1 == low && plain(below));
            joins.push((low, (*data_type).clone(), droppable));
        }
    }
    if joins.is_empty() {
        return 0;
    }
    let mut notes = Vec::new();
    // Back to front, so earlier indices stay valid.
    joins.sort_by_key(|(index, _, _)| std::cmp::Reverse(*index));
    for (index, data_type, drop_hole) in &joins {
        let name = data_type.name.clone().unwrap_or_else(|| "8 bytes".into());
        let dropped = if *drop_hole { format!("hole {};", prototype.parameters[*index - 1].name) } else { String::new() };
        notes.push(format!("{dropped}{}+{}->{name}", prototype.parameters[*index].name, prototype.parameters[*index + 1].name));
        prototype.parameters[*index] = FuncParam {
            ordinal: prototype.parameters[*index].ordinal,
            name: prototype.parameters[*index].name.clone(),
            data_type: data_type.clone(),
        };
        prototype.parameters.remove(*index + 1);
        if *drop_hole {
            prototype.parameters.remove(*index - 1);
        }
    }
    notes.reverse();
    for (ordinal, parameter) in prototype.parameters.iter_mut().enumerate() {
        parameter.ordinal = ordinal as u32;
        parameter.name = format!("param_{}", ordinal + 1);
    }
    let base = prototype
        .parameter_source
        .take()
        .unwrap_or_else(|| "native-decompiler prototype recovery".to_string());
    prototype.parameter_source = Some(format!("{base}+{SOURCE}({})", notes.join(",")));
    joins.len()
}

fn same_type(left: &DecompType, right: &DecompType) -> bool {
    left.name == right.name && left.id == right.id
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::function_ir::{BlockId, IrBlock, IrOperation};
    use romwright_model::Address;

    const REGISTERS: [u64; 4] = [0x10, 0x14, 0x18, 0x1c];
    fn layout(high_in_lower_slot: bool) -> PairLayout {
        PairLayout { slots: REGISTERS.to_vec(), sizes: vec![4; 4], high_in_lower_slot }
    }

    fn ty(name: &str) -> DecompType {
        DecompType { name: Some(name.into()), id: Some(1), size: None, metatype: None, element_count: None, target: None, prototype: None }
    }
    fn param(ordinal: u32, name: &str) -> FuncParam {
        FuncParam { ordinal, name: format!("param_{}", ordinal + 1), data_type: ty(name) }
    }
    fn proto(parameters: Vec<FuncParam>) -> FuncProto {
        FuncProto {
            calling_convention: "__stdcall".into(),
            return_type: ty("void"),
            parameters,
            variadic: false,
            no_return: false,
            parameter_source: None,
        }
    }
    fn target() -> Target {
        Target {
            model: "__stdcall".into(),
            pointer_size: 4,
            slot_sizes: vec![4; 4],
            types: [
                ("undefined4", ("unknown", 4)),
                ("int", ("int", 4)),
                ("uint", ("uint", 4)),
                ("float", ("float", 4)),
                ("double", ("float", 8)),
                ("longlong", ("int", 8)),
                ("ptr", ("ptr", 4)),
            ]
            .into_iter()
            .map(|(name, (metatype, size))| (name.to_string(), (metatype.to_string(), size)))
            .collect(),
        }
    }
    fn value(id: u64, space: u64, offset: u64, size: u32, input: bool, pieces: Vec<(u64, u32)>) -> (ValueId, IrValue) {
        let joined = !pieces.is_empty();
        (
            ValueId(id),
            IrValue {
                id: ValueId(id),
                space: if joined { IrSpace::Special(1) } else { IrSpace::Index(space) },
                offset: (!joined).then_some(offset),
                size: Some(size),
                pieces: pieces
                    .into_iter()
                    .map(|(offset, size)| romwright_model::function_ir::StoragePiece { space: "register".into(), offset, size })
                    .collect(),
                input,
                persistent: false,
                address_tied: false,
                unaffected: false,
                volatile: false,
            },
        )
    }
    fn op(id: u64, opcode: Opcode, output: Option<u64>, inputs: &[u64]) -> IrOperation {
        IrOperation {
            id: OperationId(id),
            address: Address::ram(0x1000),
            opcode,
            output: output.map(ValueId),
            inputs: inputs.iter().map(|input| Operand::Value(ValueId(*input))).collect(),
        }
    }

    /// `f(in_a1:a0)` calls `g(double)` with `CAST(PIECE(in_a1, in_a0))`; `g` is
    /// operation 7 with a declared `double` parameter.
    fn call_of(high: u64, low: u64, joined_pieces: Vec<(u64, u32)>) -> (FunctionIr, BTreeMap<OperationId, FuncProto>) {
        let mut values = BTreeMap::new();
        for (id, offset) in [(1u64, high), (2, low)] {
            values.extend([value(id, 4, offset, 4, true, vec![])]);
        }
        values.extend([
            value(3, 1, 0, 8, false, joined_pieces),
            value(4, 2, 0x100, 8, false, vec![]),
            value(5, 3, 0x2000, 4, false, vec![]),
        ]);
        let operations = vec![
            op(5, Opcode::PIECE, Some(3), &[1, 2]),
            op(6, Opcode::CAST, Some(4), &[3]),
            op(7, Opcode::CALL, None, &[5, 4]),
        ];
        let ir = FunctionIr {
            values,
            blocks: vec![IrBlock { id: BlockId(0), operations, predecessors: vec![], successors: vec![] }],
            high_variables: vec![],
            type_evidence: BTreeMap::new(),
            control_flow_cuts: vec![],
            passes: vec![],
            diagnostics: vec![],
            cast_types: vec![],
        };
        let calls = BTreeMap::from([(OperationId(7), proto(vec![param(0, "double")]))]);
        (ir, calls)
    }

    #[test]
    fn an_entry_pair_passed_whole_to_a_declared_double_is_a_sighting() {
        let (ir, calls) = call_of(0x14, 0x10, vec![(0x14, 4), (0x10, 4)]);
        let found = sightings(&ir, &calls, &layout(false));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].slot, found[0].data_type.name.as_deref()), (0, Some("double")));
        // The second pair: slots 2 and 3.
        let (ir, calls) = call_of(0x1c, 0x18, vec![(0x1c, 4), (0x18, 4)]);
        assert_eq!(sightings(&ir, &calls, &layout(false))[0].slot, 2);
    }

    #[test]
    fn a_pair_that_is_misaligned_swapped_or_not_joined_is_not_a_sighting() {
        // a1:a2 is not an aligned pair
        let (ir, calls) = call_of(0x18, 0x14, vec![(0x18, 4), (0x14, 4)]);
        assert!(sightings(&ir, &calls, &layout(false)).is_empty());
        // the halves are in the wrong order for a little-endian ABI
        let (ir, calls) = call_of(0x10, 0x14, vec![(0x10, 4), (0x14, 4)]);
        assert!(sightings(&ir, &calls, &layout(false)).is_empty());
        // ... and right for a big-endian one
        assert_eq!(sightings(&ir, &calls, &layout(true)).len(), 1);
        // the same pair cast to the declared type from a temporary, not the
        // call's joined storage, is the same evidence
        let (ir, calls) = call_of(0x14, 0x10, vec![]);
        assert_eq!(sightings(&ir, &calls, &layout(false)).len(), 1);
        // halves that are not the function's entry values are nothing
        let (mut ir, calls) = call_of(0x14, 0x10, vec![(0x14, 4), (0x10, 4)]);
        for id in [1u64, 2] {
            ir.values.get_mut(&ValueId(id)).unwrap().input = false;
        }
        assert!(sightings(&ir, &calls, &layout(false)).is_empty());
        // a call with no prototype says nothing
        let (ir, _) = call_of(0x14, 0x10, vec![(0x14, 4), (0x10, 4)]);
        assert!(sightings(&ir, &BTreeMap::new(), &layout(false)).is_empty());
    }

    fn sighted(slot: usize, name: &str) -> Sighting {
        Sighting { slot, data_type: ty(name), hole_unread: false }
    }

    fn sighted_after_a_hole(slot: usize, name: &str) -> Sighting {
        Sighting { slot, data_type: ty(name), hole_unread: true }
    }

    #[test]
    fn the_two_single_register_parameters_become_one_declared_double() {
        let mut prototype = proto(vec![param(0, "undefined4"), param(1, "uint"), param(2, "undefined4"), param(3, "uint")]);
        assert_eq!(join(&mut prototype, &[sighted(0, "double")], &layout(false), &target()), 1);
        let names: Vec<_> = prototype.parameters.iter().map(|p| (p.name.as_str(), p.data_type.name.as_deref().unwrap())).collect();
        assert_eq!(names, [("param_1", "double"), ("param_2", "undefined4"), ("param_3", "uint")]);
        assert!(prototype.parameters.iter().enumerate().all(|(index, p)| p.ordinal == index as u32));
        assert!(prototype.parameter_source.as_deref().unwrap().contains("joined-pairs(param_1+param_2->double)"));
        // The second pair of a four-word prototype, with a pointer in front.
        let mut prototype = proto(vec![param(0, "ptr"), param(1, "int"), param(2, "undefined4"), param(3, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted(2, "longlong")], &layout(false), &target()), 1);
        assert_eq!(prototype.parameters.len(), 3);
        assert_eq!(prototype.parameters[2].data_type.name.as_deref(), Some("longlong"));
    }

    #[test]
    fn an_unread_slot_below_the_pair_is_the_alignment_hole_and_goes() {
        // f(int a, double b): a0 = a, a1 is the hole, a2:a3 = b
        let mut prototype = proto(vec![param(0, "int"), param(1, "undefined4"), param(2, "undefined4"), param(3, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted_after_a_hole(2, "double")], &layout(false), &target()), 1);
        let names: Vec<_> = prototype.parameters.iter().map(|p| (p.name.as_str(), p.data_type.name.as_deref().unwrap())).collect();
        assert_eq!(names, [("param_1", "int"), ("param_2", "double")]);
        assert!(prototype.parameter_source.as_deref().unwrap().contains("hole param_2;param_3+param_4->double"));
        // the slot below is read: it is a parameter
        let mut prototype = proto(vec![param(0, "int"), param(1, "undefined4"), param(2, "undefined4"), param(3, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted(2, "double")], &layout(false), &target()), 1);
        assert_eq!(prototype.parameters.len(), 3);
        // one of two sightings of the pair reads it: a parameter
        let mut prototype = proto(vec![param(0, "int"), param(1, "undefined4"), param(2, "undefined4"), param(3, "undefined4")]);
        let mixed = [sighted_after_a_hole(2, "double"), sighted(2, "double")];
        assert_eq!(join(&mut prototype, &mixed, &layout(false), &target()), 1);
        assert_eq!(prototype.parameters.len(), 3);
        // a pointer in the slot below is never a hole
        let mut prototype = proto(vec![param(0, "int"), param(1, "ptr"), param(2, "undefined4"), param(3, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted_after_a_hole(2, "double")], &layout(false), &target()), 1);
        assert_eq!(prototype.parameters.len(), 3);
        // the first pair has nothing below it
        let mut prototype = proto(vec![param(0, "undefined4"), param(1, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted_after_a_hole(0, "double")], &layout(false), &target()), 1);
        assert_eq!(prototype.parameters.len(), 1);
    }

    /// `cvt(data, [hole], value, ...)`: a pointer, the unread slot, the pair,
    /// then more register and stack parameters.
    #[test]
    fn a_later_round_keeps_what_an_earlier_one_proved() {
        let earlier = [sighted_after_a_hole(2, "double")];
        // the slot is read in the later round (an inherited callee parameter)
        let later = carry_forward(Some(&earlier), vec![sighted(2, "double")]);
        assert_eq!(later, [sighted_after_a_hole(2, "double")]);
        // a pair the earlier round did not see is not given a hole
        let other = carry_forward(Some(&earlier), vec![sighted(0, "double")]);
        assert_eq!(other, [sighted(0, "double")]);
        // no sighting later keeps the earlier ones; none at all stays none
        assert_eq!(carry_forward(Some(&earlier), vec![]), earlier);
        assert!(carry_forward(None, vec![]).is_empty());
        assert_eq!(carry_forward(None, vec![sighted(0, "double")]), [sighted(0, "double")]);
    }

    #[test]
    fn the_hole_goes_from_a_longer_prototype_too() {
        let mut prototype = proto(vec![
            param(0, "ptr"), param(1, "undefined4"), param(2, "undefined4"), param(3, "int"), param(4, "int"),
            param(5, "uint"), param(6, "ptr"), param(7, "ptr"), param(8, "int"), param(9, "ptr"),
        ]);
        assert_eq!(join(&mut prototype, &[sighted_after_a_hole(2, "double")], &layout(false), &target()), 1);
        let names: Vec<_> = prototype.parameters.iter().map(|p| p.data_type.name.as_deref().unwrap()).collect();
        assert_eq!(names, ["ptr", "double", "int", "uint", "ptr", "ptr", "int", "ptr"]);
    }

    #[test]
    fn a_float_before_the_pair_takes_no_integer_slot() {
        let mut prototype = proto(vec![param(0, "float"), param(1, "undefined4"), param(2, "undefined4"), param(3, "ptr")]);
        assert_eq!(join(&mut prototype, &[sighted(0, "double")], &layout(false), &target()), 1);
        let names: Vec<_> = prototype.parameters.iter().map(|p| p.data_type.name.as_deref().unwrap()).collect();
        assert_eq!(names, ["float", "double", "ptr"]);
    }

    #[test]
    fn nothing_is_joined_when_the_words_are_separately_typed_or_the_sightings_disagree() {
        // a pointer or a float in the pair is evidence of two values
        let mut prototype = proto(vec![param(0, "ptr"), param(1, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted(0, "double")], &layout(false), &target()), 0);
        // two declared types for one pair
        let mut prototype = proto(vec![param(0, "undefined4"), param(1, "undefined4")]);
        let both = [sighted(0, "double"), sighted(0, "longlong")];
        assert_eq!(join(&mut prototype, &both, &layout(false), &target()), 0);
        // the same type twice is fine
        let twice = [sighted(0, "double"), sighted(0, "double")];
        assert_eq!(join(&mut prototype, &twice, &layout(false), &target()), 1);
        // the declared type is not 8 bytes
        let mut prototype = proto(vec![param(0, "undefined4"), param(1, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted(0, "int")], &layout(false), &target()), 0);
        // the prototype is shorter than the pair
        let mut prototype = proto(vec![param(0, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted(0, "double")], &layout(false), &target()), 0);
        // an odd start is not a pair this ABI can place
        let mut prototype = proto(vec![param(0, "undefined4"), param(1, "undefined4"), param(2, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted(1, "double")], &layout(false), &target()), 1, "slot 1 is addressed as given");
    }

    /// 32-bit-register prototypes only: a 64-bit machine has no register pair.
    #[test]
    fn a_target_with_wide_registers_has_no_pairs() {
        let wide = PairLayout { slots: REGISTERS.to_vec(), sizes: vec![8; 4], high_in_lower_slot: false };
        let mut prototype = proto(vec![param(0, "undefined4"), param(1, "undefined4")]);
        assert_eq!(join(&mut prototype, &[sighted(0, "double")], &wide, &target()), 0);
    }
}
