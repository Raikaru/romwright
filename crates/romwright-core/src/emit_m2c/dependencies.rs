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
}

fn unsigned(size: u32) -> Result<&'static str, String> {
    match size {
        1 => Ok("unsigned char"),
        2 => Ok("unsigned short"),
        4 => Ok("unsigned int"),
        8 => Ok("unsigned long long"),
        _ => Err(format!("no supported C integer for {size}-byte intrinsic operand")),
    }
}

impl Intrinsic {
    fn recover(ir: &FunctionIr, operation: &IrOperation) -> Result<Self, String> {
        let input = |index| {
            let Some(Operand::Value(id)) = operation.inputs.get(index) else {
                return Err("intrinsic has no scalar input".to_string());
            };
            if matches!(ir.type_evidence.get(id), Some(romwright_model::type_evidence::Class::Float(_))) {
                return Err("intrinsic requires a floating-point bit reinterpretation".into());
            }
            ir.values.get(id).and_then(|value| value.size)
                .ok_or_else(|| "intrinsic input has no native width".to_string())
        };
        let output = operation.output.and_then(|id| ir.values.get(&id))
            .and_then(|value| value.size)
            .ok_or("intrinsic output has no native width")?;
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
        };
        Ok(format!("#ifndef {guard}\n#define {guard}\n{body}#endif\n"))
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
                let intrinsic = Intrinsic::recover(ir, operation)
                    .map_err(|error| format!("cannot emit intrinsic {name}: {error}"))?;
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
