//! Global declarations use native symbol types and whole-value SSA evidence.
//! A field's scalar evidence must never replace its containing aggregate.
use super::is_c_ident;
use romwright_model::type_evidence::Class;
use romwright_model::{DecompDoc, DecompType, FuncProto, TokenKind};
use std::collections::BTreeMap;

pub(super) struct GlobalRef {
    pub name: String,
    pub declaration: String,
    pub address: Option<u64>,
    pub definition: String,
}

#[derive(Default)]
pub(super) struct Globals {
    pub refs: Vec<GlobalRef>,
    pub replacements: BTreeMap<usize, String>,
    pub warnings: Vec<String>,
}

pub(super) fn from_doc(
    doc: &DecompDoc,
    layouts: &super::UnitLayouts,
    little_endian: Option<bool>,
    declared: &std::collections::BTreeSet<String>,
) -> Result<Globals, String> {
    let ir = doc
        .function_ir
        .as_ref()
        .ok_or("global emission requires a semantic graph")?;
    let owners: BTreeMap<_, _> = ir
        .high_variables
        .iter()
        .flat_map(|high| high.members.iter().map(move |member| (*member, high)))
        .collect();
    let mut globals: BTreeMap<String, (&DecompType, bool, Option<u64>, Class)> = BTreeMap::new();
    let operations: BTreeMap<_, _> = ir.blocks.iter().flat_map(|block| &block.operations)
        .filter(|op| op.opcode == romwright_model::function_ir::Opcode::PTRSUB).map(|op| (op.id, op)).collect();
    let mut result = Globals::default();
    let mut code: BTreeMap<String, Option<u64>> = BTreeMap::new();
    for (index, token) in doc.tokens.iter().enumerate() {
        if token.kind != TokenKind::Variable {
            continue;
        }
        let address_only = token.varnode.is_none();
        let id = match token.varnode {
            Some(id) => id,
            None => {
                let Some(op) = token.operation.and_then(|id| operations.get(&id)) else { continue };
                let Some(romwright_model::function_ir::Operand::Value(id)) = op.inputs.get(1) else { continue };
                *id
            }
        };
        let Some(high) = owners.get(&id) else {
            continue;
        };
        if !high
            .symbol
            .as_ref()
            .map_or(high.class == "global", |symbol| symbol.global)
        {
            continue;
        }
        let value = &ir.values[&id];
        let (name, data_type, volatile) = match &high.symbol {
            Some(symbol) => (symbol.name.as_str(), &symbol.data_type, symbol.volatile),
            None if !address_only => (token.text.trim(), &high.data_type, value.volatile),
            None => continue,
        };
        if !is_c_ident(name) {
            return Err(format!("global {name:?} needs a C identifier"));
        }
        let offset = high.symbol_offset.unwrap_or(0);
        let address = match &high.symbol {
            Some(symbol) => symbol.address.as_ref().map(|address| address.offset),
            None => value.offset.and_then(|address| {
                u64::try_from(offset)
                    .ok()
                    .and_then(|offset| address.checked_sub(offset))
            }),
        };
        // A global the project's header declares is read through that declaration: the printed accesses
        // address the object's bytes, not a union the project never saw.
        let against_header = declared.contains(name) && super::locals::enabled(super::storage::DECLARED_VIEWS);
        let spelled = if super::locals::enabled(super::locals::MISMATCH_NAMES) { symbol_name(high, token) } else { None };
        if let Some(view) = layouts.get(name) {
            view.substitutions(
                doc, index, high, (!address_only).then_some(id), &mut result.replacements, little_endian,
                against_header, spelled,
            )?;
        }
        if data_type.metatype.as_deref() == Some("code") && data_type.prototype.is_none() {
            let warning = format!("symbol {name} needs a supplied function prototype");
            if !result.warnings.contains(&warning) { result.warnings.push(warning); }
            // Used as a value, the function still has to be declared: unspecified parameters (K&R),
            // for the project's own declaration to replace.
            code.entry(name.to_string()).or_insert(address);
            continue;
        }
        let whole = !address_only && offset == 0 && value.size.map(u64::from) == data_type.size;
        let class = if whole && !high.type_locked {
            ir.type_evidence.get(&id).copied().unwrap_or_default()
        } else {
            Class::Unknown
        };
        match globals.entry(name.into()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((data_type, volatile, address, class));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let (previous_type, previous_volatile, previous_address, previous_class) =
                    entry.get_mut();
                if *previous_type != data_type || *previous_address != address {
                    return Err(format!("conflicting global declaration for {name}"));
                }
                *previous_volatile |= volatile;
                *previous_class = previous_class.join(class);
            }
        }
    }
    result.refs.extend(code.into_iter().map(|(name, address)| GlobalRef {
        declaration: format!("int {name}()"),
        name,
        address,
        definition: String::new(),
    }));
    result.refs.extend(globals
        .into_iter()
        .map(|(name, (data_type, volatile, address, class))| {
            let scalar = super::scalar_name(class);
            let view = layouts.get(&name).filter(|_| !(declared.contains(&name) && super::locals::enabled(super::storage::DECLARED_VIEWS)));
            let (declaration, definition) = if let Some(view) = view {
                view.declaration(&name, volatile)?
            } else { (match scalar {
                Some(scalar) => {
                    format!("{}{scalar} {name}", if volatile { "volatile " } else { "" })
                }
                None => declarator(data_type, &name, volatile, 0)?,
            }, String::new()) };
            Ok(GlobalRef {
                name,
                declaration,
                address,
                definition,
            })
        })
        .collect::<Result<Vec<GlobalRef>, String>>()?);
    Ok(result)
}

/// The symbol's own name where the printer wrote it with a leading underscore: a use whose width is not
/// the symbol's (`PrintC::pushMismatchSymbol`), which names an object nothing declares.
fn symbol_name<'a>(high: &'a romwright_model::function_ir::HighVariable, token: &romwright_model::DecompToken) -> Option<&'a str> {
    let symbol = high.symbol.as_ref()?;
    (token.text.trim().strip_prefix('_') == Some(symbol.name.as_str())).then_some(symbol.name.as_str())
}

pub(super) fn render(globals: &[GlobalRef]) -> String {
    let mut sorted: Vec<_> = globals.iter().collect();
    sorted.sort_by(|a, b| {
        (a.address.is_none(), a.address, &a.name).cmp(&(b.address.is_none(), b.address, &b.name))
    });
    let mut text = String::new();
    for global in sorted {
        use std::fmt::Write;
        text.push_str(&global.definition);
        let _ = write!(text, "extern {};", global.declaration);
        if let Some(address) = global.address {
            let _ = write!(text, " /* {address:#x} */");
        }
        text.push('\n');
    }
    text
}

pub(super) fn declarator(
    data_type: &DecompType,
    name: &str,
    volatile: bool,
    depth: usize,
) -> Result<String, String> {
    if depth > 32 {
        return Err("global datatype nesting exceeds 32".into());
    }
    let qualifier = if volatile { "volatile " } else { "" };
    match data_type.metatype.as_deref() {
        Some("ptr") => {
            let target = data_type
                .target
                .as_ref()
                .ok_or("pointer has no target type")?;
            let pointer = format!("*{qualifier}{name}");
            let pointer = if matches!(target.metatype.as_deref(), Some("array" | "code")) {
                format!("({pointer})")
            } else {
                pointer
            };
            return declarator(target, &pointer, false, depth + 1);
        }
        Some("array") => {
            let count = data_type
                .element_count
                .ok_or("array has no element count")?;
            return declarator(
                data_type
                    .target
                    .as_ref()
                    .ok_or("array has no element type")?,
                &format!("{name}[{count}]"),
                volatile,
                depth + 1,
            );
        }
        Some("code") if data_type.prototype.is_some() => {
            return function_declarator(data_type.prototype.as_ref().unwrap(), name, depth + 1);
        }
        _ => {}
    }
    // A placeholder of a width no C type has (`undefined6`) is that many bytes.
    if let Some(size) = data_type.name.as_deref().and_then(super::locals::odd_undefined)
        .filter(|_| primitive(data_type).is_none() && super::locals::enabled(super::locals::ODD_WIDTHS))
    {
        return Ok(format!("{qualifier}unsigned char {name}[{size}]"));
    }
    let base = primitive(data_type).or_else(|| data_type.name.as_deref().filter(|name| is_c_ident(name)))
        .ok_or("native datatype has no C declaration")?;
    Ok(format!("{qualifier}{base} {name}").trim_end().to_string())
}

pub(super) fn function_declarator(
    prototype: &FuncProto,
    name: &str,
    depth: usize,
) -> Result<String, String> {
    let mut parameters: Vec<_> = prototype
        .parameters
        .iter()
        .map(|parameter| declarator(&parameter.data_type, "", false, depth + 1))
        .collect::<Result<_, _>>()?;
    if prototype.variadic {
        if parameters.is_empty() {
            return Err("variadic C prototype has no fixed parameter".into());
        }
        parameters.push("...".into());
    } else if parameters.is_empty() {
        parameters.push("void".into());
    }
    declarator(&prototype.return_type, &format!("{name}({})", parameters.join(", ")), false, depth + 1)
}

/// A return of no size and no type (the decompiler's `undefined` of width zero: nothing reads the result) is `void`.
pub(super) fn has_unknown_return(prototype: &FuncProto) -> bool {
    let ty = &prototype.return_type;
    ty.metatype.as_deref() == Some("unknown") && ty.size == Some(0) && ty.name.is_none()
}

pub(super) fn primitive(data_type: &DecompType) -> Option<&'static str> {
    match (data_type.metatype.as_deref(), data_type.size) {
        (Some("int"), Some(1)) => Some("signed char"),
        (Some("int"), Some(2)) => Some("short"),
        (Some("int"), Some(4)) => Some("int"),
        (Some("int"), Some(8)) => Some("long long"),
        (Some("uint" | "unknown" | "bool"), Some(1)) => Some("unsigned char"),
        (Some("uint" | "unknown"), Some(2)) => Some("unsigned short"),
        (Some("uint" | "unknown"), Some(4)) => Some("unsigned int"),
        (Some("uint" | "unknown"), Some(8)) => Some("unsigned long long"),
        (Some("float"), Some(4)) => Some("float"),
        (Some("float"), Some(8)) => Some("double"),
        // the x87 stack's value (`longdouble`, 10 bytes, padded to 12 or 16): C's own spelling parses as a type in a cast,
        // where the bare `longdouble` is an identifier to a parser that has not seen the typedef (`(longdouble)*p` is a product)
        (Some("float"), Some(10 | 12 | 16)) if super::locals::enabled("ROMWRIGHT_EXPORT_LONG_DOUBLE") => Some("long double"),
        (Some("void"), _) => Some("void"),
        (None | Some("int" | "uint" | "unknown"), _) => primitive_name(data_type.name.as_deref()?),
        _ => None,
    }
}

pub(super) fn primitive_name(name: &str) -> Option<&'static str> {
    match name {
        "undefined" | "undefined1" | "byte" | "uchar" | "bool" => Some("unsigned char"),
        "undefined2" | "ushort" | "word" => Some("unsigned short"),
        "undefined4" | "uint" | "dword" => Some("unsigned int"),
        "undefined8" | "ulonglong" | "qword" => Some("unsigned long long"),
        "longlong" => Some("long long"),
        "longdouble" if super::locals::enabled("ROMWRIGHT_EXPORT_LONG_DOUBLE") => Some("long double"),
        "ulong" => Some("unsigned long"),
        _ => None,
    }
}
