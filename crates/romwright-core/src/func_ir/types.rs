//! Constraint propagation over SSA IDs. Physical-register reuse cannot join
//! unrelated values; copies and phi inputs propagate only at equal widths.
use romwright_model::function_ir::{FunctionIr, Opcode, Operand, ValueId};
use romwright_model::type_evidence::Class;
use std::collections::{BTreeMap, VecDeque};

pub fn infer(
    ir: &FunctionIr,
    context: &super::TransformContext,
) -> Result<BTreeMap<ValueId, Class>, String> {
    context.checkpoint()?;
    let mut facts = BTreeMap::new();
    for (id, value) in &ir.values {
        context.checkpoint()?;
        facts.insert(
            *id,
            value
                .size
                .and_then(|size| size.checked_mul(8))
                .map(Class::Opaque)
                .unwrap_or_default(),
        );
    }
    let mut aliases: BTreeMap<ValueId, Vec<ValueId>> = BTreeMap::new();
    let width = |id: ValueId| {
        ir.values
            .get(&id)
            .and_then(|value| value.size)
            .and_then(|size| size.checked_mul(8))
    };
    let constrain = |facts: &mut BTreeMap<ValueId, Class>, id: ValueId, class: Class| {
        let entry = facts.entry(id).or_default();
        *entry = entry.join(class);
    };
    let alias = |aliases: &mut BTreeMap<ValueId, Vec<ValueId>>, a: ValueId, b: ValueId| {
        if a != b && width(a).is_some() && width(a) == width(b) {
            aliases.entry(a).or_default().push(b);
            aliases.entry(b).or_default().push(a);
        }
    };
    for high in &ir.high_variables {
        for member in &high.members {
            context.checkpoint()?;
            alias(&mut aliases, high.representative, *member);
            // A recovered default C spelling is not signedness evidence.
            if high.type_locked {
                if let Some(bits) =
                    width(*member).filter(|bits| high.data_type.size == Some(u64::from(*bits / 8)))
                {
                    let class = match high.data_type.metatype.as_deref() {
                        Some("int") => Class::Int(bits),
                        Some("uint") | Some("bool") => Class::Uint(bits),
                        Some("float") => Class::Float(bits),
                        Some("ptr") => Class::Ptr,
                        Some("code") => Class::Code,
                        _ => Class::Unknown,
                    };
                    constrain(&mut facts, *member, class);
                }
            }
        }
    }
    for op in ir.blocks.iter().flat_map(|block| &block.operations) {
        context.checkpoint()?;
        let input = |slot: usize| match op.inputs.get(slot) {
            Some(Operand::Value(id)) => Some(*id),
            _ => None,
        };
        if matches!(op.opcode, Opcode::COPY | Opcode::MULTIEQUAL) {
            if let Some(output) = op.output {
                for operand in &op.inputs {
                    if let Operand::Value(source) = operand {
                        alias(&mut aliases, output, *source);
                    }
                }
            }
        }
        for (slot, operand) in op.inputs.iter().enumerate() {
            let Operand::Value(id) = operand else {
                continue;
            };
            let Some(bits) = width(*id) else { continue };
            use Opcode::*;
            let class = match op.opcode {
                LOAD | STORE if slot == 1 => Class::Ptr,
                CALLIND if slot == 0 => Class::Code,
                PTRADD | PTRSUB if slot == 0 => Class::Ptr,
                PTRADD | PTRSUB => Class::Num(bits),
                INT_SLESS | INT_SLESSEQUAL | INT_SCARRY | INT_SBORROW | INT_SDIV | INT_SREM
                | INT_SEXT | FLOAT_INT2FLOAT => Class::Int(bits),
                INT_SRIGHT if slot == 0 => Class::Int(bits),
                INT_LESS | INT_LESSEQUAL | INT_CARRY | INT_DIV | INT_REM => Class::Uint(bits),
                INT_RIGHT if slot == 0 => Class::Uint(bits),
                INT_RIGHT | INT_SRIGHT | INT_LEFT if slot == 1 => Class::Uint(bits),
                FLOAT_EQUAL | FLOAT_NOTEQUAL | FLOAT_LESS | FLOAT_LESSEQUAL | FLOAT_NAN
                | FLOAT_ADD | FLOAT_DIV | FLOAT_MULT | FLOAT_SUB | FLOAT_NEG | FLOAT_ABS
                | FLOAT_SQRT | FLOAT_FLOAT2FLOAT | FLOAT_TRUNC | FLOAT_CEIL | FLOAT_FLOOR
                | FLOAT_ROUND => Class::Float(bits),
                INT_ADD | INT_SUB | INT_MULT | INT_2COMP | INT_NEGATE | INT_XOR | INT_AND
                | INT_OR | INT_LEFT | INT_ZEXT | POPCOUNT | LZCOUNT => Class::Num(bits),
                BOOL_NEGATE | BOOL_XOR | BOOL_AND | BOOL_OR => Class::Uint(bits),
                _ => Class::Unknown,
            };
            constrain(&mut facts, *id, class);
        }
        if let Some(output) = op.output {
            if let Some(bits) = width(output) {
                use Opcode::*;
                let class = match op.opcode {
                    FLOAT_ADD | FLOAT_DIV | FLOAT_MULT | FLOAT_SUB | FLOAT_NEG | FLOAT_ABS
                    | FLOAT_SQRT | FLOAT_INT2FLOAT | FLOAT_FLOAT2FLOAT | FLOAT_CEIL
                    | FLOAT_FLOOR | FLOAT_ROUND => Class::Float(bits),
                    FLOAT_TRUNC | INT_SEXT | INT_SDIV | INT_SREM | INT_SRIGHT | SPULL => {
                        Class::Int(bits)
                    }
                    INT_ZEXT | INT_DIV | INT_REM | INT_RIGHT | POPCOUNT | LZCOUNT | ZPULL => {
                        Class::Uint(bits)
                    }
                    INT_EQUAL | INT_NOTEQUAL | INT_SLESS | INT_SLESSEQUAL | INT_LESS
                    | INT_LESSEQUAL | INT_CARRY | INT_SCARRY | INT_SBORROW | BOOL_NEGATE
                    | BOOL_XOR | BOOL_AND | BOOL_OR | FLOAT_EQUAL | FLOAT_NOTEQUAL | FLOAT_LESS
                    | FLOAT_LESSEQUAL | FLOAT_NAN => Class::Uint(bits),
                    PTRADD | PTRSUB => Class::Ptr,
                    INT_ADD | INT_SUB | INT_MULT | INT_2COMP | INT_NEGATE | INT_XOR | INT_AND
                    | INT_OR | INT_LEFT => Class::Num(bits),
                    _ => Class::Unknown,
                };
                constrain(&mut facts, output, class);
            }
        }
        // An indirect-effect marker still copies input zero; its operation
        // reference is not a value and cannot contribute a type.
        if op.opcode == Opcode::INDIRECT {
            if let (Some(output), Some(source)) = (op.output, input(0)) {
                alias(&mut aliases, output, source);
            }
        }
    }
    let mut queue: VecDeque<_> = facts.keys().copied().collect();
    while let Some(source) = queue.pop_front() {
        context.checkpoint()?;
        let class = facts[&source];
        if let Some(neighbors) = aliases.get(&source) {
            for target in neighbors {
                let old = facts[target];
                let joined = old.join(class);
                if joined != old {
                    facts.insert(*target, joined);
                    queue.push_back(*target);
                }
            }
        }
    }
    Ok(facts)
}
