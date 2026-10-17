//! C dependencies are selected by native operation identity, never helper spelling.
use super::{DeclaredPrototypes, globals, is_c_ident};
use romwright_model::function_ir::{Effect, FunctionIr, IrOperation, Opcode, Operand, OperationId};
use romwright_model::{DecompDoc, TokenKind};
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Default)]
pub(super) struct Dependencies {
    /// The callees `text` declares.
    pub declared: std::collections::BTreeSet<String>,
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
    Sqrt,
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
        // the x87 stack's value (`sqrt` of `ST0`)
        10 | 12 | 16 if super::locals::enabled("ROMWRIGHT_EXPORT_LONG_DOUBLE") => Ok("long double"),
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

/// [`unsigned`], and the integer a 3-, 5-, 6- or 7-byte value (Ghidra's `int7`, the 7-byte half of `CONCAT71`) lives in.
fn unsigned_wide(size: u32) -> Result<&'static str, String> {
    match size {
        3 => Ok("unsigned int"),
        5..=7 => Ok("unsigned long long"),
        other => unsigned(other),
    }
}

/// Pieces of odd widths are rendered (`ROMWRIGHT_EXPORT_ODD_PIECES=off`, or `ROMWRIGHT_NATIVE_TYPES=1`, leaves them
/// unsupported intrinsics).
fn odd_pieces() -> bool {
    !std::env::var("ROMWRIGHT_NATIVE_TYPES").is_ok_and(|mode| mode == "1") && super::locals::enabled("ROMWRIGHT_EXPORT_ODD_PIECES")
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
            // `fsqrt`: the C library's `sqrt` (`ROMWRIGHT_EXPORT_SQRT=off` leaves it an unsupported intrinsic)
            Opcode::FLOAT_SQRT if super::locals::enabled("ROMWRIGHT_EXPORT_SQRT") => {
                let size = width(0)?;
                float_type(size)?;
                if size != output {
                    return Err("sqrt changes width".into());
                }
                return Ok(Self::FloatUnary { op: FloatUnary::Sqrt, size });
            }
            _ => {}
        }

        if operation.inputs.len() != 2 {
            return Err("integer intrinsic needs two native operands".into());
        }
        let upper = input(0)?;
        let lower = input(1)?;
        if !(operation.opcode == Opcode::PIECE && odd_pieces()) {
            unsigned(upper)?;
            unsigned(lower)?;
        }
        match operation.opcode {
            Opcode::PIECE if upper.checked_add(lower) == Some(output) => {
                if odd_pieces() {
                    unsigned_wide(upper)?;
                    unsigned_wide(lower)?;
                    unsigned_wide(output)?;
                } else {
                    unsigned(output)?;
                }
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
                    FloatUnary::Sqrt => "sqrt",
                };
                format!("romwright_{kind}_{size}")
            }
        }
    }

    fn definition(self, name: &str) -> Result<String, String> {
        let guard = format!("{}_DEFINED", name.to_ascii_uppercase());
        let body = match self {
            Self::Piece(upper, lower) => {
                let result = unsigned_wide(upper + lower)?;
                let upper_type = unsigned_wide(upper)?;
                let lower_type = unsigned_wide(lower)?;
                let shift = lower * 8;
                // A 3-, 5-, 6- or 7-byte piece (`CONCAT71`) lives in the next wider integer; the lower piece's bytes
                // above its width are not part of it.
                let lower_value = if matches!(lower, 3 | 5 | 6 | 7) {
                    format!("(({lower_type})(lower) & {:#x}ULL)", (1u64 << (lower * 8)) - 1)
                } else {
                    format!("({lower_type})(lower)")
                };
                // Each argument occurs once. Cast before shifting, including
                // the 32+32 case, and truncate both source pieces first.
                format!("#define {name}(upper, lower) (({result})((({result})({upper_type})(upper) << {shift}) | {lower_value}))\n")
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
                // The printer writes the piece as `SUB84(value, 4)`: the byte offset is a second argument,
                // which a one-parameter macro rejects ("macro passed 2 arguments, but takes just 1").
                let parameters = if super::locals::enabled("ROMWRIGHT_EXPORT_SUBPIECE_ARITY") { "value, offset" } else { "value" };
                if shift == 0 {
                    format!("#define {name}({parameters}) (({result})({source})(value))\n")
                } else {
                    format!("#define {name}({parameters}) (({result})((({source})(value)) >> {shift}))\n")
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
                    // the library function the compiler expands in line (`/Oi`, `-O`)
                    FloatUnary::Sqrt => format!("double sqrt(double);\nstatic {ty} {name}({ty} value)\n{{\n    return ({ty})sqrt((double)value);\n}}\n"),
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

/// Merges the signatures two call sites of one callee were recovered with (`ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES=off` keeps
/// "inconsistent recovered call-site signatures" and leaves the callee to the reader). The decompiler recovers one prototype
/// per call from what that call pushes, so a variadic callee shows a different parameter list at each call and one callee's
/// `int` argument shows as `unsigned int` at another. Two signatures merge when they have the same calling convention and,
/// parameter by parameter, are the same type or two integers of one width, a pointer and a pointer-sized integer (the
/// pointer), or two pointers (`void *`). Lists of different lengths merge only for a caller-cleans convention, into the
/// common prefix and `...`. A float against anything else, or a stdcall/fastcall list of another length, does not merge.
fn merge_call_signatures(a: &romwright_model::FuncProto, b: &romwright_model::FuncProto) -> Option<romwright_model::FuncProto> {
    if a.calling_convention != b.calling_convention {
        return None;
    }
    let mut merged = a.clone();
    merged.return_type = merge_types(&a.return_type, &b.return_type, true)?;
    merged.no_return = a.no_return && b.no_return;
    let count = a.parameters.len().min(b.parameters.len());
    let callee_cleans = matches!(a.calling_convention.as_str(), "__stdcall" | "__fastcall" | "__thiscall");
    if a.parameters.len() != b.parameters.len() {
        if callee_cleans || count == 0 {
            return None;
        }
        merged.variadic = true;
    }
    merged.variadic |= b.variadic;
    merged.parameters.truncate(count);
    for (index, parameter) in merged.parameters.iter_mut().enumerate() {
        parameter.data_type = merge_types(&a.parameters[index].data_type, &b.parameters[index].data_type, false)?;
    }
    Some(merged)
}

fn merge_types(a: &romwright_model::DecompType, b: &romwright_model::DecompType, is_return: bool) -> Option<romwright_model::DecompType> {
    let text_a = globals::declarator(a, "", false, 0).ok();
    let text_b = globals::declarator(b, "", false, 0).ok();
    // a return of no size and no type (rendered `void`, see globals.rs) yields to a real return type
    let is_void = |ty: &romwright_model::DecompType, text: &Option<String>| {
        text.is_none() && ty.metatype.as_deref() == Some("unknown") && ty.size == Some(0) && ty.name.is_none()
    };
    if is_return {
        if is_void(a, &text_a) && is_void(b, &text_b) {
            return Some(a.clone());
        }
        if is_void(a, &text_a) && text_b.is_some() {
            return Some(b.clone());
        }
        if is_void(b, &text_b) && text_a.is_some() {
            return Some(a.clone());
        }
    }
    let (text_a, text_b) = (text_a?, text_b?);
    if text_a == text_b {
        return Some(a.clone());
    }
    enum Kind {
        Pointer,
        Float,
        Integer(u32),
        Other,
    }
    let kind = |text: &str| {
        let text = text.trim();
        if text.contains('*') {
            Kind::Pointer
        } else {
            match text {
                "float" | "double" | "long double" => Kind::Float,
                "signed char" | "unsigned char" => Kind::Integer(1),
                "short" | "unsigned short" => Kind::Integer(2),
                "int" | "unsigned int" => Kind::Integer(4),
                "long long" | "unsigned long long" => Kind::Integer(8),
                _ => Kind::Other,
            }
        }
    };
    match (kind(&text_a), kind(&text_b)) {
        (Kind::Integer(x), Kind::Integer(y)) if x == y => Some(a.clone()),
        (Kind::Pointer, Kind::Integer(4)) => Some(a.clone()),
        (Kind::Integer(4), Kind::Pointer) => Some(b.clone()),
        (Kind::Pointer, Kind::Pointer) => Some(romwright_model::DecompType {
            name: None,
            id: None,
            size: Some(4),
            metatype: Some("ptr".into()),
            element_count: None,
            target: Some(Box::new(romwright_model::DecompType {
                name: Some("void".into()),
                id: None,
                size: None,
                metatype: None,
                element_count: None,
                target: None,
                prototype: None,
            })),
            prototype: None,
        }),
        _ => None,
    }
}

/// The C library function an x87 instruction the decompiler prints as a user operation computes: `fsin`, `fcos` and `fpatan`
/// (`atan2` of its two stack values, `ST1` first). The result of the instruction is the C function's.
fn x87_userop(name: &str) -> Option<&'static str> {
    match name {
        "fsin" => Some("double sin(double);\n#define fsin(x) sin(x)\n"),
        "fcos" => Some("double cos(double);\n#define fcos(x) cos(x)\n"),
        "fpatan" => Some("double atan2(double, double);\n#define fpatan(y, x) atan2(y, x)\n"),
        _ => None,
    }
}

const MERGE_CALL_SIGNATURES: &str = "ROMWRIGHT_EXPORT_MERGE_CALL_SIGNATURES";

/// The declaration of a callee from a call-site prototype. On an i386 PE (`x86_pe`) a return of no size and no type is `void`
/// (`ROMWRIGHT_EXPORT_UNKNOWN_RETURN_VOID=off` leaves the declaration refused, "native datatype has no C declaration", and the callee to
/// the reader): the decompiler recovered the arguments of a Win32 caller well enough to declare them, which is what makes a
/// `__stdcall` callee's cleanup and a float argument right. On the consoles a callee declared from its call site alone has integer
/// parameter types for pointers, and the casts `conform` then adds to the arguments cost more than the declaration gains.
fn callee_declarator(prototype: &romwright_model::FuncProto, name: &str, x86_pe: bool) -> Result<String, String> {
    if x86_pe && globals::has_unknown_return(prototype) && super::locals::enabled(UNKNOWN_RETURN_VOID) {
        let mut typed = prototype.clone();
        typed.return_type = romwright_model::DecompType {
            name: Some("void".into()),
            id: None,
            size: None,
            metatype: Some("void".into()),
            element_count: None,
            target: None,
            prototype: None,
        };
        return globals::function_declarator(&typed, name, 0);
    }
    globals::function_declarator(prototype, name, 0)
}

const UNKNOWN_RETURN_VOID: &str = "ROMWRIGHT_EXPORT_UNKNOWN_RETURN_VOID";

/// A callee the decompiler modelled `__stdcall` or `__fastcall` is declared with the keyword (the models exist only in the
/// Windows x86 spec; callers compiled without it would pop the arguments the callee already popped). Only where
/// `enabled`: the caller says the program is an i386 PE, because on other languages the *default* model carries the
/// name `__stdcall` (MIPS) and a keyword the compiler has never heard of must not be printed.
fn with_convention(text: String, prototype: &romwright_model::FuncProto, name: &str, enabled: bool) -> String {
    let keyword = match prototype.calling_convention.as_str() {
        keyword @ ("__stdcall" | "__fastcall") if enabled && super::locals::enabled("ROMWRIGHT_EXPORT_CALLEE_CONVENTIONS") => keyword,
        _ => return text,
    };
    let needle = format!("{name}(");
    match text.find(&needle) {
        Some(at) => format!("{}{keyword} {}", &text[..at], &text[at..]),
        None => text,
    }
}

pub(super) fn from_doc(
    doc: &DecompDoc,
    keep: &[String],
    emit_callees: bool,
    asserted_prototypes: Option<&DeclaredPrototypes>,
    convention_keywords: bool,
) -> Result<Dependencies, String> {
    let ir = doc.function_ir.as_ref().ok_or("C dependencies require a semantic graph")?;
    let requested: BTreeMap<_, _> = doc.tokens.iter()
        .filter(|token| matches!(token.kind, TokenKind::FuncName | TokenKind::Op) && is_c_ident(&token.text))
        .filter_map(|token| token.operation.map(|operation| (operation, token.text.as_str())))
        .collect();
    let mut result = Dependencies::default();
    let mut helpers: BTreeMap<Intrinsic, String> = BTreeMap::new();
    let mut callees: BTreeMap<&str, Result<String, String>> = BTreeMap::new();
    let mut merged: BTreeMap<&str, Option<romwright_model::FuncProto>> = BTreeMap::new();
    let mut unsupported: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for operation in ir.blocks.iter().flat_map(|block| &block.operations) {
        let Some(&name) = requested.get(&operation.id) else { continue };
        match operation.opcode {
            Opcode::CALL if emit_callees => {
                if !is_c_ident(name) {
                    return Err(format!("callee {name:?} needs a C identifier"));
                }
                // a recursive call: the definition is its declaration (a declaration of the call-site's signature before it
                // conflicts with the definition's own convention and parameter list)
                if convention_keywords && doc.call_targets.get(&operation.id) == Some(&doc.address) && super::locals::enabled("ROMWRIGHT_EXPORT_RECURSIVE_CALLEE") {
                    continue;
                }
                let asserted = match (asserted_prototypes, doc.call_targets.get(&operation.id)) {
                    (Some(prototypes), Some(address)) => prototypes.callee(address, name)?,
                    _ => None,
                };
                let site_asserted = asserted.is_some();
                let declaration = asserted.map(Ok).unwrap_or_else(|| {
                    doc.call_prototypes.get(&operation.id)
                        .ok_or_else(|| "native call-site signature unavailable".to_string())
                        .and_then(|prototype| {
                            callee_declarator(prototype, name, convention_keywords).map(|text| with_convention(text, prototype, name, convention_keywords))
                        })
                });
                let site = if site_asserted { None } else { doc.call_prototypes.get(&operation.id) };
                match callees.entry(name) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(declaration);
                        merged.insert(name, site.cloned());
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        if entry.get() != &declaration {
                            // one callee seen with different parameter lists or integer/pointer spellings (a variadic function,
                            // `int` and `unsigned int` of one argument): the one signature every call is a use of
                            let both = merged.get(name).cloned().flatten().zip(site);
                            let unified = both.and_then(|(a, b)| merge_call_signatures(&a, b)).filter(|_| convention_keywords && super::locals::enabled(MERGE_CALL_SIGNATURES));
                            match unified {
                                Some(proto) => {
                                    *entry.get_mut() = callee_declarator(&proto, name, convention_keywords)
                                        .map(|text| with_convention(text, &proto, name, convention_keywords));
                                    merged.insert(name, Some(proto));
                                }
                                None => {
                                    *entry.get_mut() = Err("inconsistent recovered call-site signatures".into());
                                    merged.insert(name, None);
                                }
                            }
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
                    // x87 transcendental instructions are the C library's functions
                    if let Some(definition) = x87_userop(&label).filter(|_| super::locals::enabled("ROMWRIGHT_EXPORT_X87_MATH")) {
                        if unsupported.insert(label.clone()) {
                            result.text.push_str(definition);
                        }
                        result.names.insert(operation.id, label);
                        continue;
                    }
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
        // A C library function is declared by the library's own header, which
        // the project already includes. Redeclaring it with the types the
        // decompiler recovered conflicts with the compiler's built-in
        // prototype (`size_t` is `unsigned long` there), which is an error
        // under `-Werror`. The call stays implicit, as it is in C89 source.
        if is_library_builtin(name) {
            continue;
        }
        // A compiler's runtime helper has one ABI: `int __divsi3(int, int)`.
        // Without a recovered call-site signature it is that, not "supplied".
        let declaration = match (declaration, crate::func_ir::helper_semantics(name)) {
            (Err(_), Some((_, width, kind))) => {
                let ty = match (kind, width) {
                    ("int", 4) => "int",
                    ("uint", 4) => "unsigned int",
                    ("int", 8) => "long long",
                    _ => "unsigned long long",
                };
                Ok(format!("{ty} {name}({ty}, {ty})"))
            }
            (declaration, _) => declaration,
        };
        match declaration {
            Ok(declaration) => {
                let _ = writeln!(result.text, "extern {declaration};");
                result.declared.insert(name.to_string());
            }
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
    use super::{merge_call_signatures, Intrinsic};
    use romwright_model::{DecompType, FuncParam, FuncProto};

    fn named(name: &str) -> DecompType {
        DecompType { name: Some(name.into()), id: None, size: None, metatype: None, element_count: None, target: None, prototype: None }
    }

    fn pointer(to: &str) -> DecompType {
        DecompType { name: None, id: None, size: Some(4), metatype: Some("ptr".into()), element_count: None, target: Some(Box::new(named(to))), prototype: None }
    }

    fn proto(convention: &str, parameters: Vec<DecompType>) -> FuncProto {
        FuncProto {
            calling_convention: convention.into(),
            return_type: named("int"),
            parameters: parameters.into_iter().enumerate()
                .map(|(index, data_type)| FuncParam { ordinal: index as u32, name: String::new(), data_type })
                .collect(),
            variadic: false,
            no_return: false,
            parameter_source: None,
        }
    }

    #[test]
    fn call_sites_of_one_callee_merge_when_they_are_uses_of_one_signature() {
        // a variadic callee: the shorter list and `...`
        let one = proto("__cdecl", vec![pointer("char")]);
        let two = proto("__cdecl", vec![pointer("char"), named("int")]);
        let merged = merge_call_signatures(&one, &two).expect("variadic");
        assert!(merged.variadic && merged.parameters.len() == 1);
        // `int` and `unsigned int` of one argument; a pointer where another site passes a pointer-sized integer
        let a = proto("__cdecl", vec![named("int"), pointer("char")]);
        let b = proto("__cdecl", vec![named("uint"), named("undefined4")]);
        let merged = merge_call_signatures(&a, &b).expect("integers and a pointer");
        assert_eq!(merged.parameters.len(), 2);
        assert!(merged.parameters[1].data_type.metatype.as_deref() == Some("ptr"));
        // callee-pops lists of other lengths, and a float against an integer, do not merge
        assert!(merge_call_signatures(&proto("__stdcall", vec![named("int")]), &proto("__stdcall", vec![named("int"), named("int")])).is_none());
        assert!(merge_call_signatures(&proto("__cdecl", vec![named("float")]), &proto("__cdecl", vec![named("int")])).is_none());
        assert!(merge_call_signatures(&proto("__cdecl", vec![named("int")]), &proto("__stdcall", vec![named("int")])).is_none());
    }

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

/// ISO C `<string.h>`/`<stdlib.h>` functions compilers know as built-ins.
fn is_library_builtin(name: &str) -> bool {
    matches!(
        name,
        "memcpy" | "memmove" | "memset" | "memcmp" | "memchr" | "strlen" | "strcpy" | "strncpy"
            | "strcmp" | "strncmp" | "strcat" | "strncat" | "strchr" | "strrchr" | "strstr"
            | "abs" | "labs"
    )
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
