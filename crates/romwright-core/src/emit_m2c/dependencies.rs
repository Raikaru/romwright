//! C dependencies are selected by native operation identity, never helper spelling.
use super::{DeclaredPrototypes, globals, is_c_ident};
use romwright_model::function_ir::{Effect, FunctionIr, IrOperation, Opcode, Operand, OperationId};
use romwright_model::{DecompDoc, TokenKind};
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Default)]
pub(super) struct Dependencies {
    pub names: BTreeMap<OperationId, String>,
    pub text: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Intrinsic {
    Piece(u32, u32),
    Carry(u32),
    /// `INT_ZEXT` / `INT_SEXT`: a width change, which is a cast in C.
    Extend { from: u32, to: u32, signed: bool },
    /// `SUBPIECE(value, k)`: the `to`-byte field `k` bytes up from the bottom.
    Subpiece { from: u32, to: u32, offset: u32 },
    /// `FLOAT_ABS` / `FLOAT_NEG` / `FLOAT_SQRT` on a 4- or 8-byte float.
    FloatUnary { op: FloatUnary, size: u32 },
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FloatUnary {
    Abs,
    Negate,
}

fn signed_type(size: u32) -> Result<&'static str, String> {
    match size {
        1 => Ok("signed char"),
        2 => Ok("short"),
        4 => Ok("int"),
        8 => Ok("long long"),
        16 => Ok(INT128),
        _ => Err(format!("no supported C integer for {size}-byte intrinsic operand")),
    }
}

fn float_type(size: u32) -> Result<&'static str, String> {
    match size {
        4 => Ok("float"),
        8 => Ok("double"),
        _ => Err(format!("no supported C float for {size}-byte intrinsic operand")),
    }
}

/// A 128-bit integer is a real C type on every target that has one: GCC and
/// Clang both spell it `__attribute__((mode(TI)))`, and PS2 decompilation
/// projects already use exactly that under their own name (`u_long128`).
/// Rejecting 16-byte operands left quadword extracts and extensions - the
/// ordinary C behind `lq`/`sq` and the COP2 transfers - unrenderable for no
/// reason, so they get the same treatment as every other width.
const UINT128: &str = "romwright_uint128";
const INT128: &str = "romwright_int128";
const INT128_TYPEDEFS: &str = concat!(
    "#ifndef ROMWRIGHT_INT128_DEFINED\n#define ROMWRIGHT_INT128_DEFINED\n",
    "typedef unsigned int romwright_uint128 __attribute__((mode(TI)));\n",
    "typedef int romwright_int128 __attribute__((mode(TI)));\n#endif\n",
);

fn unsigned(size: u32) -> Result<&'static str, String> {
    match size {
        1 => Ok("unsigned char"),
        2 => Ok("unsigned short"),
        4 => Ok("unsigned int"),
        8 => Ok("unsigned long long"),
        16 => Ok(UINT128),
        _ => Err(format!("no supported C integer for {size}-byte intrinsic operand")),
    }
}

impl Intrinsic {
    fn recover(ir: &FunctionIr, operation: &IrOperation) -> Result<Self, String> {
        let is_float = |index: usize| {
            matches!(operation.inputs.get(index), Some(Operand::Value(id))
                if matches!(ir.type_evidence.get(id),
                            Some(romwright_model::type_evidence::Class::Float(_))))
        };
        let width = |index: usize| {
            let Some(Operand::Value(id)) = operation.inputs.get(index) else {
                return Err("intrinsic has no scalar input".to_string());
            };
            ir.values.get(id).and_then(|value| value.size)
                .ok_or_else(|| "intrinsic input has no native width".to_string())
        };
        let input = |index: usize| {
            if is_float(index) {
                return Err("intrinsic requires a floating-point bit reinterpretation".into());
            }
            width(index)
        };
        // A constant operand lives in native space zero, and its offset is
        // the value: that is how SUBPIECE carries its byte offset.
        let constant = |index: usize| {
            let Some(Operand::Value(id)) = operation.inputs.get(index) else { return None };
            let value = ir.values.get(id)?;
            (value.space == romwright_model::function_ir::IrSpace::Index(0))
                .then_some(value.offset)
                .flatten()
        };
        let output = operation.output.and_then(|id| ir.values.get(&id))
            .and_then(|value| value.size)
            .ok_or("intrinsic output has no native width")?;

        // Width changes and float sign operations take one operand, so they
        // are recovered before the two-operand integer forms.
        match operation.opcode {
            Opcode::INT_ZEXT | Opcode::INT_SEXT => {
                // Ghidra widens a constant through whatever odd source width
                // the instruction implied (a 7-byte shift amount, say). A
                // constant needs no truncation step, so the extension is just
                // a cast to the output type.
                let from = if constant(0).is_some() { output } else { input(0)? };
                let signed = operation.opcode == Opcode::INT_SEXT;
                if signed { signed_type(from)?; } else { unsigned(from)?; }
                unsigned(output)?;
                return Ok(Self::Extend { from, to: output, signed });
            }
            Opcode::SUBPIECE => {
                let from = input(0)?;
                let offset = constant(1)
                    .ok_or("SUBPIECE needs a constant byte offset")?;
                let offset = u32::try_from(offset)
                    .map_err(|_| "SUBPIECE byte offset does not fit".to_string())?;
                unsigned(from)?;
                unsigned(output)?;
                if offset + output > from {
                    return Err("SUBPIECE field lies outside its operand".into());
                }
                return Ok(Self::Subpiece { from, to: output, offset });
            }
            Opcode::FLOAT_ABS | Opcode::FLOAT_NEG => {
                let size = width(0)?;
                float_type(size)?;
                if size != output {
                    return Err("float sign operation changes width".into());
                }
                let op = if operation.opcode == Opcode::FLOAT_ABS {
                    FloatUnary::Abs
                } else {
                    FloatUnary::Negate
                };
                return Ok(Self::FloatUnary { op, size });
            }
            _ => {}
        }

        if operation.inputs.len() != 2 {
            return Err("integer intrinsic needs two native operands".into());
        }
        let upper = input(0)?;
        let lower = input(1)?;
        unsigned(upper)?;
        unsigned(lower)?;
        match operation.opcode {
            Opcode::PIECE if upper.checked_add(lower) == Some(output) => {
                unsigned(output)?;
                Ok(Self::Piece(upper, lower))
            }
            Opcode::INT_CARRY if upper == lower && output == 1 => Ok(Self::Carry(upper)),
            _ => Err(format!("unsupported C intrinsic {:?} ({upper}, {lower}) -> {output}", operation.opcode)),
        }
    }

    fn stem(self) -> String {
        match self {
            Self::Piece(upper, lower) => format!("romwright_piece_{upper}_{lower}"),
            Self::Carry(size) => format!("romwright_carry_{size}"),
            Self::Extend { from, to, signed } => {
                let kind = if signed { "sext" } else { "zext" };
                format!("romwright_{kind}_{from}_{to}")
            }
            Self::Subpiece { from, to, offset } => {
                format!("romwright_subpiece_{from}_{to}_{offset}")
            }
            Self::FloatUnary { op, size } => {
                let kind = match op {
                    FloatUnary::Abs => "fabs",
                    FloatUnary::Negate => "fneg",
                };
                format!("romwright_{kind}_{size}")
            }
        }
    }

    fn definition(self, name: &str) -> Result<String, String> {
        let guard = format!("{}_DEFINED", name.to_ascii_uppercase());
        let body = match self {
            Self::Piece(upper, lower) => {
                let result = unsigned(upper + lower)?;
                let upper_type = unsigned(upper)?;
                let lower_type = unsigned(lower)?;
                let shift = lower * 8;
                // Each argument occurs once. Cast before shifting, including
                // the 32+32 case, and truncate both source pieces first.
                format!("#define {name}(upper, lower) (({result})((({result})({upper_type})(upper) << {shift}) | ({lower_type})(lower)))\n")
            }
            Self::Carry(size) if size < 8 => {
                let input = unsigned(size)?;
                let wide = unsigned(size * 2)?;
                let maximum = (1u64 << (size * 8)) - 1;
                format!("#define {name}(left, right) ((unsigned char)(({wide})({input})(left) + ({wide})({input})(right) > {maximum:#x}ULL))\n")
            }
            Self::Carry(_) => {
                // No wider portable integer is assumed. Function parameters
                // evaluate each operand once; addition is unsigned modulo 2^64.
                format!("static unsigned char {name}(unsigned long long left, unsigned long long right)\n{{\n    return (unsigned char)((left + right) < left);\n}}\n")
            }
            Self::Extend { from, to, signed } => {
                // A width change is a cast. Truncate to the source width
                // first so the macro is correct when handed a wider value,
                // and go through the signed type for INT_SEXT so the
                // conversion sign-extends.
                let result = unsigned(to)?;
                let source = if signed { signed_type(from)? } else { unsigned(from)? };
                format!("#define {name}(value) (({result})({source})(value))\n")
            }
            Self::Subpiece { from, to, offset } => {
                let result = unsigned(to)?;
                let source = unsigned(from)?;
                let shift = offset * 8;
                if shift == 0 {
                    format!("#define {name}(value) (({result})({source})(value))\n")
                } else {
                    format!("#define {name}(value) (({result})((({source})(value)) >> {shift}))\n")
                }
            }
            Self::FloatUnary { op, size } => {
                let ty = float_type(size)?;
                match op {
                    // The argument appears twice, so this has to be a
                    // function: a macro would evaluate a call operand twice.
                    FloatUnary::Abs => format!(
                        "static {ty} {name}({ty} value)\n{{\n    return value < ({ty})0 ? -value : value;\n}}\n"
                    ),
                    FloatUnary::Negate => format!("#define {name}(value) (-({ty})(value))\n"),
                }
            }
        };
        let prelude = if body.contains(UINT128) || body.contains(INT128) {
            INT128_TYPEDEFS
        } else {
            ""
        };
        Ok(format!("{prelude}#ifndef {guard}\n#define {guard}\n{body}#endif\n"))
    }
}

pub(super) fn from_doc(
    doc: &DecompDoc,
    keep: &[String],
    emit_callees: bool,
    asserted_prototypes: Option<&DeclaredPrototypes>,
) -> Result<Dependencies, String> {
    let ir = doc.function_ir.as_ref().ok_or("C dependencies require a semantic graph")?;
    let requested: BTreeMap<_, _> = doc.tokens.iter()
        .filter(|token| matches!(token.kind, TokenKind::FuncName | TokenKind::Op) && is_c_ident(&token.text))
        .filter_map(|token| token.operation.map(|operation| (operation, token.text.as_str())))
        .collect();
    let mut result = Dependencies::default();
    let mut helpers: BTreeMap<Intrinsic, String> = BTreeMap::new();
    let mut callees: BTreeMap<&str, Result<String, String>> = BTreeMap::new();
    let mut unsupported: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for operation in ir.blocks.iter().flat_map(|block| &block.operations) {
        let Some(&name) = requested.get(&operation.id) else { continue };
        match operation.opcode {
            Opcode::CALL if emit_callees => {
                if !is_c_ident(name) {
                    return Err(format!("callee {name:?} needs a C identifier"));
                }
                let asserted = match (asserted_prototypes, doc.call_targets.get(&operation.id)) {
                    (Some(prototypes), Some(address)) => prototypes.callee(address, name)?,
                    _ => None,
                };
                let declaration = asserted.map(Ok).unwrap_or_else(|| {
                    doc.call_prototypes.get(&operation.id)
                        .ok_or_else(|| "native call-site signature unavailable".to_string())
                        .and_then(|prototype| globals::function_declarator(prototype, name, 0))
                });
                match callees.entry(name) {
                    std::collections::btree_map::Entry::Vacant(entry) => { entry.insert(declaration); }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        if entry.get() != &declaration {
                            *entry.get_mut() = Err("inconsistent recovered call-site signatures".into());
                        }
                    }
                }
            }
            Opcode::CALL | Opcode::CALLIND => {}
            _ if operation.effect() == Effect::Control => {}
            _ => {
                // An operation with no C spelling -- a VU0 macro-mode
                // instruction or an MMI op arriving as CALLOTHER, say -- used
                // to abort the whole export, which loses a 600-instruction
                // body over one opcode. Flag it and carry on instead: the
                // reader gets the control flow, the types and every other
                // statement, with that one operation marked the same way an
                // untyped callee is. m2c's `M2C_ERROR` serves the same purpose.
                //
                // The decompiler's own rendering of the operation is already
                // the userop's name (`_lqc2`, `_pextlb`), so it is kept as
                // written rather than replaced by a generic stem: which VU
                // instruction it was is exactly what the reader needs.
                let Ok(intrinsic) = Intrinsic::recover(ir, operation) else {
                    let label = if is_c_ident(name) {
                        name.to_string()
                    } else {
                        format!("romwright_unsupported_{}", stem_for(operation))
                    };
                    if unsupported.insert(label.clone()) {
                        let _ = writeln!(
                            result.text,
                            "/* Unsupported intrinsic, declaration required: {label} ({:?}). */",
                            operation.opcode
                        );
                        result.warnings.push(format!(
                            "operation {name} uses intrinsic {:?}, which this emitter cannot \
                             render in C; the body is emitted with a placeholder",
                            operation.opcode
                        ));
                    }
                    result.names.insert(operation.id, label);
                    continue;
                };
                let helper = match helpers.entry(intrinsic) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let mut helper = intrinsic.stem();
                        while keep.contains(&helper) || doc.tokens.iter().any(|token| token.text == helper) {
                            helper.push('_');
                        }
                        result.text.push_str(&intrinsic.definition(&helper)?);
                        entry.insert(helper)
                    }
                };
                result.names.insert(operation.id, helper.clone());
            }
        }
    }
    for (name, declaration) in callees {
        match declaration {
            Ok(declaration) => { let _ = writeln!(result.text, "extern {declaration};"); }
            Err(error) => {
                let _ = writeln!(result.text, "/* Supplied declaration required: {name}. */");
                result.warnings.push(format!("callee {name} requires supplied context: {error}"));
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::Intrinsic;

    #[test]
    #[ignore = "requires cc with undefined-behavior instrumentation"]
    fn integer_helpers_preserve_boundaries_and_single_evaluation() {
        let root = std::env::temp_dir().join(format!(
            "romwright-c-intrinsics-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let mut definitions = String::new();
        for intrinsic in [
            Intrinsic::Piece(1, 1), Intrinsic::Piece(2, 2), Intrinsic::Piece(4, 4),
            Intrinsic::Carry(1), Intrinsic::Carry(2), Intrinsic::Carry(4), Intrinsic::Carry(8),
        ] {
            definitions.push_str(&intrinsic.definition(&intrinsic.stem()).unwrap());
        }
        // Combined translation units may include the same support block twice.
        let mut source = format!("{definitions}\n{definitions}\nint main(void) {{\nunsigned int a,b,left=0,right=0;\n");
        source.push_str("for(a=0;a<256;++a) for(b=0;b<256;++b) {\n\
            if(romwright_piece_1_1(a,b)!=((a<<8)|b)) return 1;\n\
            if(romwright_carry_1(a,b)!=(a>255-b)) return 2;\n}\n");
        for size in [2, 4, 8] {
            let maximum = (1u128 << (size * 8)) - 1;
            for left in [0, 1, maximum - 1, maximum] {
                for right in [0, 1, maximum - 1, maximum] {
                    let expected = u8::from(left + right > maximum);
                    source.push_str(&format!(
                        "if(romwright_carry_{size}({left:#x}ULL,{right:#x}ULL)!={expected}) return 3;\n"
                    ));
                    if size < 8 {
                        let expected = (left << (size * 8)) | right;
                        source.push_str(&format!(
                            "if(romwright_piece_{size}_{size}({left:#x}ULL,{right:#x}ULL)!={expected:#x}ULL) return 4;\n"
                        ));
                    }
                }
            }
        }
        source.push_str("if(romwright_piece_4_4(left++,right++)!=0 || left!=1 || right!=1) return 5;\n\
            left=right=0;\n\
            if(romwright_carry_4(left++,right++)!=0 || left!=1 || right!=1) return 6;\n\
            left=right=0;\n\
            if(romwright_carry_8(left++,right++)!=0 || left!=1 || right!=1) return 7;\n\
            return 0;\n}\n");
        let file = root.join("intrinsics.c");
        let executable = root.join("intrinsics");
        std::fs::write(&file, source).unwrap();
        let compiled = std::process::Command::new("cc")
            .args(["-std=c89", "-O2", "-fsanitize=undefined", "-fsanitize-undefined-trap-on-error"])
            .arg(&file).arg("-o").arg(&executable).output().unwrap();
        assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
        let ran = std::process::Command::new(&executable).output().unwrap();
        assert!(ran.status.success(), "exit {:?}: {}", ran.status.code(), String::from_utf8_lossy(&ran.stderr));
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// A C identifier stem for an operation this emitter cannot render, taken from
/// the opcode's own debug name so two different unsupported opcodes never
/// collapse into one placeholder.
fn stem_for(operation: &IrOperation) -> String {
    let debug = format!("{:?}", operation.opcode);
    let mut stem: String = debug
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect();
    while stem.contains("__") {
        stem = stem.replace("__", "_");
    }
    stem.trim_matches('_').to_string()
}
