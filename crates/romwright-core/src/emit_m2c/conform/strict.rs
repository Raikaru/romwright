//! What armcc's C front end rejects in the decompiler's text, spelled so that it compiles and computes what the machine
//! code does.
//!
//! The decompiler types a register by how the function uses it, and one register is a pointer here and an integer or a
//! float there; Ghidra prints those uses as implicit conversions, and as pieces of a variable C has no spelling for.
//! clang accepts most of them (a pointer compared with an integer, arithmetic on a function pointer); armcc does not.
//! Each rule changes only what the compiler is told, never what the instructions do:
//!
//! - **A pointer against an integer, or two unrelated pointers, in a comparison**: the pointer is read as the unsigned
//!   integer it is (`(unsigned int)p < n`), or the right operand takes the left's pointer type.
//! - **Arithmetic and indexing on a pointer to a function or to `void`**: Ghidra counts those in bytes, so the pointer is
//!   a byte pointer (`(unsigned char *)p + 8`).
//! - **A dereference of an integer**: the integer is the address (`*(unsigned int *)n`), with the width of the value
//!   stored where the statement says one.
//! - **A pointer where an integer is switched on**, and a function type or an array type cast to: the unsigned integer
//!   of the same width (a three-, five-, six- or seven-byte value is the next wider integer, masked).
//! - **A float and a pointer converted into each other**: a register moved between the two files, so the bits move
//!   (`romwright_f2u`, `romwright_u2f`), not the value.
//! - **A piece of a variable that no C type has the width of** (`x._1_3_`): the shift and mask of the integer it is part
//!   of, as a value and as an assignment's target.
//! - **The stack pointer read as a register** (`register0x00000054`): `__current_sp()`.
//!
//! Only armcc projects run these (`Decls::strict`).
use super::*;

/// Ghidra's names for the integer types the output uses, as the C types they are: with the names unknown to a parser,
/// `(uint)*p` is a product and `(uint *)p` another, and no later rule can tell.
fn primitive_spelling(name: &str) -> Option<&'static str> {
    Some(match name {
        "uint" | "ulong" | "dword" | "undefined4" | "BADSPACEBASE" => "unsigned int",
        "ushort" | "word" | "undefined2" => "unsigned short",
        "uchar" | "byte" | "undefined" | "undefined1" => "unsigned char",
        "sbyte" => "signed char",
        "sword" => "short",
        "sdword" => "int",
        "longlong" | "sqword" => "long long",
        "ulonglong" | "qword" | "undefined8" => "unsigned long long",
        _ => return None,
    })
}

/// The text with Ghidra's primitive type names spelled as C types.
pub(in super::super) fn normalize_primitives(text: &str) -> String {
    let terminated = terminate_labels(text);
    let text = terminated.as_str();
    let Some(tree) = parse(text) else { return terminated };
    let mut edits = Vec::new();
    visit(tree.root_node(), &mut |node| {
        if !matches!(node.kind(), "identifier" | "type_identifier") {
            return;
        }
        let name = text_of(node, text);
        if let Some(spelling) = primitive_spelling(name) {
            replace(&mut edits, node.start_byte(), node.end_byte(), spelling.into());
        } else if let Some(size) = name.strip_prefix("undefined").and_then(|n| n.parse::<u64>().ok()).filter(|n| matches!(n, 3 | 5 | 6 | 7))
            && node.parent().is_some_and(|parent| parent.kind() == "parenthesized_expression")
        {
            // `(undefined3)(x)` reads as a call until the name is known to be a type: a cast to the byte array
            replace(&mut edits, node.start_byte(), node.end_byte(), format!("unsigned char [{size}]"));
        }
    });
    apply_edits(text, edits).unwrap_or_else(|| text.to_string())
}

/// A label before the closing brace (`LAB_0036b5b0:\n  }`) names no statement, which C does not allow.
pub(in super::super) fn terminate_labels(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = String::with_capacity(text.len() + 8);
    for (index, line) in lines.iter().enumerate() {
        out.push_str(line);
        let label = {
            let trimmed = line.trim();
            trimmed.ends_with(':')
                && trimmed[..trimmed.len() - 1].chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !trimmed.starts_with("default")
                && lines[index + 1..].iter().map(|l| l.trim()).find(|l| !l.is_empty()).is_some_and(|next| next.starts_with('}'))
        };
        if label {
            out.push(';');
        }
        if index + 1 < lines.len() {
            out.push('\n');
        }
    }
    out
}

const BITS_HELPERS: &str = "\
#ifndef ROMWRIGHT_FLOAT_BITS_DEFINED\n\
#define ROMWRIGHT_FLOAT_BITS_DEFINED\n\
static unsigned int romwright_f2u(float value)\n{\n    union { float f; unsigned int u; } bits;\n    bits.f = value;\n    return bits.u;\n}\n\
static float romwright_u2f(unsigned int value)\n{\n    union { float f; unsigned int u; } bits;\n    bits.u = value;\n    return bits.f;\n}\n\
#endif\n";

const ISNAN_HELPERS: &str = "\
#ifndef ROMWRIGHT_ISNAN_DEFINED\n\
#define ROMWRIGHT_ISNAN_DEFINED\n\
static int romwright_isnanf(float value)\n{\n    return value != value;\n}\n\
static int romwright_isnan(double value)\n{\n    return value != value;\n}\n\
#endif\n";

/// The definitions of the helpers the conformed text calls.
pub(in super::super) fn helper_definitions(body: &str) -> String {
    let mut text = String::new();
    if body.contains("romwright_f2u(") || body.contains("romwright_u2f(") {
        text.push_str(BITS_HELPERS);
    }
    if body.contains("romwright_set_sp(") {
        text.push_str("/* Unsupported intrinsic, declaration required: romwright_set_sp (a write of the stack pointer). */\n");
    }
    if body.contains("romwright_isnan(") || body.contains("romwright_isnanf(") {
        text.push_str(ISNAN_HELPERS);
    }
    text
}

fn byte_pointer() -> Ty {
    Ty::Ptr(Box::new(Ty::Int(Int::UChar)))
}

/// `((T)x)`: `x` read as a `T`, as the operand of a subscript, which binds tighter than a cast.
fn parenthesized_cast(edits: &mut Vec<Edit>, node: Node<'_>, to: &Ty) {
    let Some(text) = spell(to) else { return };
    insert_before(edits, node.start_byte(), format!("(({text})"));
    insert_after(edits, node.end_byte(), ")".into());
}

/// A pointer to a function or to `void`: ISO C has no arithmetic on it, and the decompiler counts it in bytes.
fn byte_counted(ty: &Ty) -> bool {
    matches!(ty, Ty::Ptr(target) if matches!(resolve(target), Ty::Func(..) | Ty::Void))
}

fn value_type(typer: &Typer<'_>, node: Node<'_>) -> Option<Ty> {
    typer.of(node).map(|ty| decayed(&ty))
}

fn scalar_of_width(width: u64) -> Option<(&'static str, u64)> {
    Some(match width {
        1 => ("unsigned char", 1),
        2 => ("unsigned short", 2),
        3 | 4 => ("unsigned int", 4),
        5..=8 => ("unsigned long long", 8),
        _ => return None,
    })
}

fn binary(node: Node<'_>, typer: &Typer<'_>, source: &str, edits: &mut Vec<Edit>) {
    let Some(op) = operator(node, source) else { return };
    let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else { return };
    match op {
        "<" | ">" | "<=" | ">=" | "==" | "!=" => {
            let equality = matches!(op, "==" | "!=");
            let (lt, rt) = (value_type(typer, left), value_type(typer, right));
            match (&lt, &rt) {
                (Some(Ty::Ptr(a)), Some(Ty::Ptr(b))) => {
                    let void = matches!(resolve(a), Ty::Void) || matches!(resolve(b), Ty::Void);
                    if !void && same(a, b) == Some(false) && let Some(lt) = &lt {
                        cast_to(edits, right, lt);
                    }
                }
                (Some(Ty::Ptr(_)), Some(Ty::Int(_))) if !(equality && is_zero(right, source)) => {
                    cast_to(edits, left, &Ty::Int(Int::UInt));
                }
                (Some(Ty::Int(_)), Some(Ty::Ptr(_))) if !(equality && is_zero(left, source)) => {
                    cast_to(edits, right, &Ty::Int(Int::UInt));
                }
                _ => {}
            }
        }
        "+" | "-" => {
            for operand in [left, right] {
                if value_type(typer, operand).is_some_and(|ty| byte_counted(&ty)) {
                    cast_to(edits, operand, &byte_pointer());
                }
            }
        }
        _ => {}
    }
}

/// The type a dereferenced integer is read as: the width of what the statement stores through it.
fn dereferenced_element(node: Node<'_>, typer: &Typer<'_>, source: &str) -> Ty {
    if let Some(parent) = node.parent()
        && parent.kind() == "assignment_expression"
        && operator(parent, source) == Some("=")
        && let (Some(left), Some(right)) = (parent.child_by_field_name("left"), parent.child_by_field_name("right"))
        && left.id() == node.id()
    {
        match typer.of(right).map(|ty| decayed(&ty)) {
            Some(Ty::Int(int)) => return Ty::Int(int),
            Some(float @ Ty::Float(_)) => return float,
            _ => {}
        }
    }
    Ty::Int(Int::UInt)
}

/// `value` converted by the bits of a register moved between the integer and the float file.
fn bits_around(edits: &mut Vec<Edit>, value: Node<'_>, open: &str) {
    insert_before(edits, value.start_byte(), open.to_string());
    insert_after(edits, value.end_byte(), "))".to_string());
}

/// A float where a pointer is wanted, a pointer where a float is: `to` gets `from`'s bits. `cast`: the pointer type
/// is not already spelled by a cast around `value`.
fn bit_conversion(edits: &mut Vec<Edit>, to: &Ty, from: &Ty, value: Node<'_>, cast: bool) {
    match (resolve(to), resolve(&decayed(from))) {
        (Ty::Ptr(_), Ty::Float(_)) => {
            let Some(spelling) = spell(to) else { return };
            let prefix = if cast { format!("({spelling})") } else { String::new() };
            bits_around(edits, value, &format!("{prefix}romwright_f2u((float)("));
        }
        (Ty::Float(width), Ty::Ptr(_)) => {
            let double = if *width == 8 { "(double)" } else { "" };
            bits_around(edits, value, &format!("{double}romwright_u2f((unsigned int)("));
        }
        _ => {}
    }
}

fn cast(node: Node<'_>, typer: &Typer<'_>, edits: &mut Vec<Edit>) {
    let (Some(descriptor), Some(value)) = (node.child_by_field_name("type"), node.child_by_field_name("value")) else { return };
    let to = typer.type_descriptor(descriptor);
    match resolve(&to) {
        Ty::Ptr(_) => {
            if let Some(from) = typer.of(value) && matches!(resolve(&from), Ty::Float(_)) {
                bit_conversion(edits, &to, &from, value, false);
            }
        }
        Ty::Float(_) => {
            let Some(from) = typer.of(value) else { return };
            if matches!(resolve(&from), Ty::Array(..)) {
                if strip_parens(value).kind() == "identifier" {
                    replace(edits, node.start_byte(), value.start_byte(), "(*(float *)".into());
                    insert_after(edits, value.end_byte(), ")".into());
                }
            } else if matches!(decayed(&from), Ty::Ptr(_)) {
                // the cast is replaced by the helper: `(float)p` is `romwright_u2f((unsigned int)(p))`
                let double = if matches!(resolve(&to), Ty::Float(8)) { "(double)" } else { "" };
                replace(edits, node.start_byte(), value.start_byte(), format!("{double}romwright_u2f((unsigned int)("));
                insert_after(edits, value.end_byte(), "))".into());
            }
        }
        _ => {}
    }
}

/// `strict` rules over the statements of one function.
pub(in super::super) fn strict_expressions(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if !decls.strict {
        return;
    }
    let Some(body) = function.node.child_by_field_name("body") else { return };
    let typer = Typer { decls, scope: &function.scope, source, own: Some((&function.name, &function.ty)) };
    let mut undeclared: Vec<String> = Vec::new();
    visit(body, &mut |node| match node.kind() {
        "binary_expression" => binary(node, &typer, source, edits),
        "subscript_expression" => {
            let Some(argument) = node.child_by_field_name("argument") else { return };
            match value_type(&typer, argument) {
                Some(ty) if byte_counted(&ty) => parenthesized_cast(edits, argument, &byte_pointer()),
                Some(Ty::Int(_)) => {
                    let element = dereferenced_element(node, &typer, source);
                    parenthesized_cast(edits, argument, &Ty::Ptr(Box::new(element)));
                }
                _ => {}
            }
        }
        // `case (int *)0x0:` of a switch on the pointer read as an integer
        "case_statement" => {
            let Some(value) = node.child_by_field_name("value") else { return };
            let value = strip_parens(value);
            if value.kind() == "cast_expression" && matches!(typer.of(value).as_ref().map(resolve), Some(Ty::Ptr(_))) {
                cast_to(edits, value, &Ty::Int(Int::UInt));
            } else if value.kind() == "number_literal"
                && let text = text_of(value, source).trim_end_matches(['f', 'F'])
                && text.contains(['.', 'e', 'E'])
                && !text.starts_with("0x")
                && let Ok(float) = text.parse::<f32>()
            {
                replace(edits, value.start_byte(), value.end_byte(), format!("{:#x}", float.to_bits()));
            }
        }
        // the decompiler's `NAN(x)` is the test for a NaN: `x != x`
        "call_expression" => {
            let (Some(callee), Some(arguments)) = (node.child_by_field_name("function"), node.child_by_field_name("arguments")) else { return };
            // `(*field)(...)` of an integer: the integer is the address of the function
            if callee.kind() == "parenthesized_expression"
                && let [target] = named_children(callee).as_slice()
                && target.kind() == "pointer_expression"
                && operator(*target, source) == Some("*")
                && let Some(address) = target.child_by_field_name("argument")
                && matches!(value_type(&typer, address), Some(Ty::Int(_)))
            {
                if is_prefix_safe(address) {
                    replace(edits, callee.start_byte(), address.start_byte(), "((int (*)())".into());
                } else {
                    replace(edits, callee.start_byte(), address.start_byte(), "((int (*)())(".into());
                    insert_after(edits, address.end_byte(), ")".into());
                }
                return;
            }
            let arguments = named_children(arguments);
            let [argument] = arguments.as_slice() else { return };
            if callee.kind() != "identifier" || text_of(callee, source) != "NAN" {
                return;
            }
            let text = text_of(*argument, source);
            let replacement = if argument.kind() == "identifier" {
                format!("({text} != {text})")
            } else {
                let float = matches!(typer.of(*argument).as_ref().map(resolve), Some(Ty::Float(4)));
                format!("romwright_isnan{}({text})", if float { "f" } else { "" })
            };
            replace(edits, node.start_byte(), node.end_byte(), replacement);
        }
        "pointer_expression" if operator(node, source) == Some("*") => {
            let Some(argument) = node.child_by_field_name("argument") else { return };
            match value_type(&typer, argument) {
                Some(Ty::Int(_)) if !is_callee(node) => {
                    let element = dereferenced_element(node, &typer, source);
                    cast_to(edits, argument, &Ty::Ptr(Box::new(element)));
                }
                // `*(code *)p` read as a value is the byte `code` is, not the function itself
                Some(ty) if matches!(&ty, Ty::Ptr(target) if matches!(resolve(target), Ty::Func(..))) && !is_callee(node) => {
                    cast_to(edits, argument, &byte_pointer());
                }
                _ => {}
            }
        }
        "switch_statement" => {
            let Some(condition) = node.child_by_field_name("condition") else { return };
            let Some(inner) = named_children(condition).into_iter().next() else { return };
            match value_type(&typer, inner) {
                Some(Ty::Ptr(_)) => cast_to(edits, inner, &Ty::Int(Int::UInt)),
                // a float switched on is the register's bits, and its case values are those bits printed as floats
                Some(Ty::Float(_)) => bits_around(edits, inner, "(int)romwright_f2u((float)("),
                _ => {}
            }
        }
        "cast_expression" => cast(node, &typer, edits),
        // `FUN_00427bec.whole`: the storage view of a code address the decompiler read as data is the address
        "field_expression" => {
            let (Some(argument), Some(field)) = (node.child_by_field_name("argument"), node.child_by_field_name("field")) else { return };
            if text_of(field, source) != "whole" || argument.kind() != "identifier" || source[argument.end_byte()..field.start_byte()].trim() != "." {
                return;
            }
            let name = text_of(argument, source);
            let known = typer.of(argument);
            let is_function = matches!(known.as_ref().map(resolve), Some(Ty::Func(..)))
                || (known.is_none() && !function.scope.contains_key(name) && !decls.objects.contains_key(name) && name.starts_with("FUN_"));
            if is_function {
                replace(edits, node.start_byte(), node.end_byte(), name.to_string());
            } else if let Some(address) = name.strip_prefix("ram0x").filter(|hex| hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                && known.is_none()
            {
                // storage at an address no symbol covers (inside a larger object's bytes): what is at that address,
                // as wide as the statement that reads it
                let element = node
                    .parent()
                    .filter(|parent| parent.kind() == "assignment_expression" && parent.child_by_field_name("right").is_some_and(|r| r.id() == node.id()))
                    .and_then(|parent| parent.child_by_field_name("left"))
                    .and_then(|left| typer.of(left))
                    .filter(|ty| matches!(resolve(ty), Ty::Int(_) | Ty::Float(_)))
                    .and_then(|ty| spell(&ty))
                    .unwrap_or_else(|| "unsigned int".to_string());
                replace(edits, node.start_byte(), node.end_byte(), format!("(*({element} *)0x{address})"));
            }
        }
        "assignment_expression" if operator(node, source) == Some("=") => {
            let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else { return };
            // the stack pointer written: C has no way to say so, so it is the call of an intrinsic (declaration required)
            if text_of(left, source) == "register0x00000054" && node.parent().is_some_and(|parent| parent.kind() == "expression_statement") {
                replace(edits, left.start_byte(), right.start_byte(), "romwright_set_sp((unsigned int)(".into());
                insert_after(edits, right.end_byte(), "))".into());
                return;
            }
            if let (Some(to), Some(from)) = (typer.of(left), typer.of(right)) {
                bit_conversion(edits, &to, &from, right, true);
            }
        }
        "init_declarator" => {
            let (Some(left), Some(right)) = (node.child_by_field_name("declarator"), node.child_by_field_name("value")) else { return };
            if let (Some(to), Some(from)) = (typer.of(left), typer.of(right)) {
                bit_conversion(edits, &to, &from, right, true);
            }
        }
        "identifier" => {
            let name = text_of(node, source);
            if name == "register0x00000054" {
                let assigned = node.parent().is_some_and(|parent| {
                    parent.kind() == "assignment_expression"
                        && parent.child_by_field_name("left").is_some_and(|left| left.id() == node.id())
                });
                if !assigned {
                    replace(edits, node.start_byte(), node.end_byte(), "((unsigned int)__current_sp())".into());
                }
            } else if name.starts_with("unique0x") && !function.scope.contains_key(name) && !undeclared.iter().any(|n| n == name) {
                undeclared.push(name.to_string());
            }
        }
        _ => {}
    });
    // a temporary the decompiler named and never declared: a variable of its own
    for name in undeclared {
        insert_after(edits, body.start_byte() + 1, format!("\n  unsigned int {name};"));
    }
}

/// `_<offset>_<size>_`, the printer's name for the piece of a variable no field covers.
fn piece(text: &str) -> Option<(u64, u64)> {
    let inner = text.strip_prefix('_')?.strip_suffix('_')?;
    let (offset, size) = inner.split_once('_')?;
    Some((offset.parse().ok()?, size.parse().ok()?))
}

/// `x._1_3_`: the bytes of the integer `x` at that offset, little-endian, as a shift and a mask.
pub(in super::super) fn partial_members(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if !decls.strict {
        return;
    }
    let Some(body) = function.node.child_by_field_name("body") else { return };
    let typer = Typer { decls, scope: &function.scope, source, own: Some((&function.name, &function.ty)) };
    visit(body, &mut |node| {
        if node.kind() != "field_expression" {
            return;
        }
        let (Some(argument), Some(field)) = (node.child_by_field_name("argument"), node.child_by_field_name("field")) else { return };
        let Some((offset, size)) = piece(text_of(field, source)) else { return };
        if source[argument.end_byte()..field.start_byte()].contains("->") {
            return;
        }
        let owner = text_of(argument, source);
        if owner.contains('(') {
            return;
        }
        let Some(ty) = typer.of(argument) else { return };
        if !matches!(resolve(&ty), Ty::Int(_) | Ty::Ptr(_)) {
            return;
        }
        let Some(width) = size_of(&ty).filter(|width| matches!(width, 1 | 2 | 4 | 8)) else { return };
        if size == 0 || offset + size > width {
            return;
        }
        // the whole of the variable: the variable
        if offset == 0 && size == width {
            replace(edits, node.start_byte(), node.end_byte(), owner.to_string());
            return;
        }
        let (unsigned, suffix) = if width == 8 { ("unsigned long long", "ULL") } else { ("unsigned int", "U") };
        let full = if width == 8 { u64::MAX } else { 0xffff_ffff };
        let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
        let shift = offset * 8;
        if let Some(parent) = node.parent()
            && parent.kind() == "assignment_expression"
            && operator(parent, source) == Some("=")
            && parent.child_by_field_name("left").is_some_and(|left| left.id() == node.id())
        {
            let Some(right) = parent.child_by_field_name("right") else { return };
            let keep = full & !(mask << shift);
            // a pointer is rebuilt from the integer
            let (open, close) = match resolve(&ty) {
                Ty::Ptr(_) => (format!("({})(", spell(&ty).unwrap_or_default()), ")"),
                _ => (String::new(), ""),
            };
            if open == "()(" {
                return;
            }
            replace(
                edits,
                parent.start_byte(),
                parent.end_byte(),
                format!(
                    "{owner} = {open}((({unsigned})({owner}) & {keep:#x}{suffix}) | ((({unsigned})({}) & {mask:#x}{suffix}) << {shift})){close}",
                    text_of(right, source)
                ),
            );
        } else {
            replace(
                edits,
                node.start_byte(),
                node.end_byte(),
                format!("((({unsigned})({owner}) >> {shift}) & {mask:#x}{suffix})"),
            );
        }
    });
}

/// `unsigned char x [3];` of a value only ever used whole (assigned, cast, passed to a piece macro): the integer that
/// holds it. C has no assignment to an array, and no three-byte integer.
pub(in super::super) fn odd_array_locals(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if !decls.strict {
        return;
    }
    let Some(body) = function.node.child_by_field_name("body") else { return };
    for item in named_children(body) {
        if item.kind() != "declaration" {
            continue;
        }
        let mut cursor = item.walk();
        let declarators: Vec<_> = item.children_by_field_name("declarator", &mut cursor).collect();
        let [declarator] = declarators.as_slice() else { continue };
        if declarator.kind() != "array_declarator" {
            continue;
        }
        let Some(name_node) = declarator.child_by_field_name("declarator").filter(|n| n.kind() == "identifier") else { continue };
        let name = text_of(name_node, source);
        let Some(count) = decls.array_len(*declarator, source) else { continue };
        let element = item.child_by_field_name("type").map_or(Ty::Unknown, |ty| decls.base_type(ty, source));
        if !matches!(resolve(&element), Ty::Int(Int::UChar)) || !matches!(count, 3 | 5 | 6 | 7) {
            continue;
        }
        let mut whole = true;
        visit(body, &mut |node| {
            if node.kind() != "identifier" || text_of(node, source) != name || node.id() == name_node.id() {
                return;
            }
            let Some(parent) = node.parent() else { return };
            let allowed = match parent.kind() {
                "assignment_expression" | "cast_expression" | "parenthesized_expression" | "binary_expression" => true,
                "argument_list" => parent
                    .parent()
                    .and_then(|call| callee_name(call, source))
                    .is_some_and(|callee| callee.starts_with("romwright_piece_")),
                _ => false,
            };
            whole &= allowed;
        });
        if whole && let Some((scalar, _)) = scalar_of_width(count) {
            replace(edits, item.start_byte(), item.end_byte(), format!("{scalar} {name};"));
        }
    }
}

/// A cast to a type C has no value of: Ghidra's `code` (a function: one byte there) and a byte array (a value of that
/// many bytes: the unsigned integer of the width, masked where the width is no integer's).
pub(in super::super) fn odd_casts(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if !decls.strict {
        return;
    }
    let Some(body) = function.node.child_by_field_name("body") else { return };
    let typer = Typer { decls, scope: &function.scope, source, own: Some((&function.name, &function.ty)) };
    visit(body, &mut |node| {
        if node.kind() != "cast_expression" {
            return;
        }
        let Some(descriptor) = node.child_by_field_name("type") else { return };
        match resolve(&typer.type_descriptor(descriptor)) {
            Ty::Func(..) => replace(edits, descriptor.start_byte(), descriptor.end_byte(), "unsigned char".into()),
            Ty::Array(element, Some(count)) => {
                let Some(width) = size_of(element).map(|size| size * count) else { return };
                let Some((scalar, scalar_width)) = scalar_of_width(width) else { return };
                replace(edits, descriptor.start_byte(), descriptor.end_byte(), scalar.into());
                if width != scalar_width {
                    insert_before(edits, node.start_byte(), "(".into());
                    insert_after(
                        edits,
                        node.end_byte(),
                        format!(" & {:#x}{})", (1u64 << (width * 8)) - 1, if scalar_width == 8 { "ULL" } else { "U" }),
                    );
                }
            }
            _ => {}
        }
    });
}

/// A parameter or local of Ghidra's `code` type itself (not a pointer to it): `code` is one byte there, but a function
/// type declared as a parameter is a pointer to the function. The byte it is.
pub(in super::super) fn code_values(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if !decls.strict {
        return;
    }
    visit(function.node, &mut |node| {
        if !matches!(node.kind(), "parameter_declaration" | "declaration") {
            return;
        }
        let Some(spec) = node.child_by_field_name("type") else { return };
        if spec.kind() != "type_identifier" || text_of(spec, source) != CODE_TYPE {
            return;
        }
        let mut cursor = node.walk();
        let plain = node.children_by_field_name("declarator", &mut cursor).all(|declarator| declarator.kind() == "identifier");
        if plain {
            replace(edits, spec.start_byte(), spec.end_byte(), "unsigned char".into());
        }
    });
}

/// The name of the function the text defines.
pub(in super::super) fn function_name(text: &str) -> Option<String> {
    let tree = parse(text)?;
    let node = named_children(tree.root_node()).into_iter().find(|n| n.kind() == "function_definition")?;
    Decls::new().header(node, text).map(|(name, _, _)| name)
}

/// `declarations` without the lines that declare `name`: a function defined here is declared by its definition, and an
/// `extern` of the prototype one call recovered (a recursion that passes fewer arguments) conflicts with it.
pub(in super::super) fn without_declarations_of(declarations: &str, name: &str) -> String {
    let declares = |line: &str| {
        line.starts_with("extern ")
            && line.match_indices(&format!("{name}(")).any(|(at, _)| {
                !line[..at].chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            })
    };
    declarations.split_inclusive('\n').filter(|line| !declares(line)).collect()
}

/// Whether `node` (through parentheses and further dereferences) is what a call calls.
fn is_callee(mut node: Node<'_>) -> bool {
    loop {
        let Some(parent) = node.parent() else { return false };
        match parent.kind() {
            "parenthesized_expression" | "pointer_expression" => node = parent,
            "call_expression" => return parent.child_by_field_name("function").is_some_and(|callee| callee.id() == node.id()),
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict(header: &str) -> Decls {
        let mut decls = Decls::new();
        decls.enable_strict();
        decls.add_source(header);
        decls
    }

    fn run(source: &str, header: &str) -> String {
        let (text, _) = super::super::spelled(&normalize_primitives(source));
        super::super::apply(&text, &strict(header))
    }

    #[test]
    fn ghidra_type_names_are_c_types_before_a_parser_reads_a_cast_as_a_product() {
        let out = normalize_primitives("void f(uint *p)\n{\n  p = (byte *)(uint)*(byte *)(q + 0x3b);\n  r = (undefined3)(x >> 8);\n}\n");
        assert!(out.contains("(unsigned char *)(unsigned int)*(unsigned char *)(q + 0x3b)"), "{out}");
        assert!(out.contains("(unsigned char [3])(x >> 8)"), "{out}");
        assert!(out.contains("unsigned int *p"), "{out}");
    }

    #[test]
    fn a_label_before_a_closing_brace_names_a_statement() {
        let out = terminate_labels("void f(void)\n{\n  do {\n    g();\nLAB_1:\n  } while (y);\n  if (x) {\nLAB_2:\n  }\n}\n");
        assert!(out.contains("LAB_1:;\n  } while") && out.contains("LAB_2:;\n  }"), "{out}");
        assert_eq!(terminate_labels("void f(void)\n{\nLAB_3:\n  g();\n}\n"), "void f(void)\n{\nLAB_3:\n  g();\n}\n");
    }

    #[test]
    fn a_pointer_compared_with_an_integer_is_the_unsigned_integer() {
        let out = run(
            "int f(unsigned int *p, unsigned int n, unsigned char *a, int *b)\n{\n  if (p < n) {\n    return 1;\n  }\n  if (n >= p) {\n    return 2;\n  }\n  if (p != 0) {\n    return 3;\n  }\n  return a < b;\n}\n",
            "",
        );
        assert!(out.contains("(unsigned int)p < n"), "{out}");
        assert!(out.contains("n >= (unsigned int)p"), "{out}");
        assert!(out.contains("p != 0"), "a comparison with the null constant is C: {out}");
        assert!(out.contains("a < (unsigned char *)b"), "{out}");
    }

    #[test]
    fn arithmetic_and_indexing_on_a_function_or_void_pointer_count_bytes() {
        let out = run(
            "void f(code *p, void *q)\n{\n  g(p + 0x38, q + 4);\n  p[0x6c] = (code)0;\n  *(int *)(p + 8) = 1;\n}\n",
            "",
        );
        assert!(out.contains("(unsigned char *)p + 0x38"), "{out}");
        assert!(out.contains("(unsigned char *)q + 4"), "{out}");
        assert!(out.contains("((unsigned char *)p)[0x6c] = (unsigned char)0;"), "{out}");
        assert!(out.contains("*(int *)((unsigned char *)p + 8)"), "{out}");
    }

    #[test]
    fn an_integer_dereferenced_is_the_address_of_what_is_stored() {
        let out = run("void f(unsigned int a, unsigned int b)\n{\n  *a = (unsigned char)b;\n  b = a[2] + *b;\n}\n", "");
        assert!(out.contains("*(unsigned char *)a = (unsigned char)b;"), "{out}");
        assert!(out.contains("((unsigned int *)a)[2] + *(unsigned int *)b"), "{out}");
    }

    #[test]
    fn a_pointer_switched_on_is_the_integer_its_cases_name() {
        let out = run(
            "void f(int *p)\n{\n  switch (p) {\n  case (int *)0x0:\n    g();\n    break;\n  case (int *)0x4:\n    break;\n  }\n}\n",
            "",
        );
        assert!(out.contains("switch((unsigned int)p)") || out.contains("switch ((unsigned int)p)"), "{out}");
        assert!(out.contains("case (unsigned int)0x0:") && out.contains("case (unsigned int)0x4:"), "{out}");
    }

    #[test]
    fn a_float_and_a_pointer_trade_bits_not_values() {
        let out = run(
            "void f(float *fp, unsigned int *p, float x)\n{\n  p = (unsigned int *)fp[0x8a];\n  x = (float)p;\n  p = x * 2.0f;\n  switch (x) {\n  case 1.4013e-45:\n    break;\n  }\n}\n",
            "",
        );
        assert!(out.contains("(unsigned int *)romwright_f2u((float)(fp[0x8a]))"), "{out}");
        assert!(out.contains("x = romwright_u2f((unsigned int)(p))"), "{out}");
        assert!(out.contains("p = (unsigned int *)romwright_f2u((float)(x * 2.0f))"), "{out}");
        assert!(out.contains("(int)romwright_f2u((float)(x))") && out.contains("case 0x1:"), "{out}");
        assert!(helper_definitions(&out).contains("static float romwright_u2f"));
        assert!(helper_definitions("int g(void) { return 0; }").is_empty());
    }

    #[test]
    fn the_bytes_of_an_integer_that_no_type_has_the_width_of_are_a_shift_and_a_mask() {
        let out = run(
            "void f(unsigned int x, unsigned int *y)\n{\n  unsigned int a;\n  a = romwright_piece_3_1(x._1_3_, 1);\n  x._1_3_ = (undefined3)(a >> 8);\n  y[0]._0_3_ = 5;\n  a = x._3_1_;\n}\n",
            "",
        );
        assert!(out.contains("romwright_piece_3_1((((unsigned int)(x) >> 8) & 0xffffffU), 1)"), "{out}");
        assert!(
            out.contains("x = (((unsigned int)(x) & 0xffU) | (((unsigned int)(((unsigned int)(a >> 8) & 0xffffffU)) & 0xffffffU) << 8));"),
            "{out}"
        );
        assert!(out.contains("y[0] = (((unsigned int)(y[0]) & 0xff000000U) | (((unsigned int)(5) & 0xffffffU) << 0));"), "{out}");
        assert!(out.contains("a = (((unsigned int)(x) >> 24) & 0xffU)"), "{out}");
    }

    #[test]
    fn a_three_byte_local_used_whole_is_the_integer_that_holds_it() {
        let out = run(
            "void f(unsigned int in)\n{\n  unsigned char temp_v6 [3];\n  unsigned int temp_v7;\n  temp_v6 = (undefined3)(in >> 8);\n  temp_v7 = romwright_piece_3_1(temp_v6, 200);\n}\n",
            "",
        );
        assert!(out.contains("unsigned int temp_v6;"), "{out}");
        assert!(out.contains("temp_v6 = ((unsigned int)(in >> 8) & 0xffffffU);"), "{out}");
        let kept = run("void g(void)\n{\n  unsigned char temp_v6 [3];\n  h(&temp_v6);\n}\n", "");
        assert!(kept.contains("unsigned char temp_v6 [3];"), "{kept}");
    }

    #[test]
    fn a_member_the_decompiler_typed_as_an_integer_takes_a_pointer_by_a_cast() {
        let header = "typedef unsigned int undefined4;\ntypedef struct fn_arg0 fn_arg0;\nstruct fn_arg0 {\n  unsigned char pad_0x0[0x4];\n  undefined4 field_0x8;\n  undefined4 field_0xc;\n};\n";
        let out = run(
            "void f(fn_arg0 *param_1, unsigned int *p)\n{\n  param_1->field_0x8 = p;\n  (*param_1->field_0xc)(p, 0);\n}\n",
            header,
        );
        assert!(out.contains("param_1->field_0x8 = (undefined4)p;"), "{out}");
        assert!(out.contains("((int (*)())param_1->field_0xc)(p, 0)"), "{out}");
    }

    #[test]
    fn a_recursive_call_is_made_to_agree_with_the_definition() {
        let out = run("int f(int a, unsigned char *b, int c)\n{\n  f(a, b);\n  f(a, a, c);\n  return 0;\n}\n", "extern int f(int *);\n");
        assert!(out.contains("f(a, b, /* unrecovered */ 0);"), "{out}");
        assert!(out.contains("f(a, (unsigned char *)a, c);"), "{out}");
        assert_eq!(without_declarations_of("extern int f(int *);\nextern int g(int);\nextern int of(int);\n", "f"), "extern int g(int);\nextern int of(int);\n");
    }

    #[test]
    fn the_decompilers_nan_test_is_a_self_comparison_and_register_54_is_sp() {
        let out = run(
            "int f(float a, float b, unsigned int c)\n{\n  unsigned int sp;\n  sp = (unsigned int)register0x00000054;\n  register0x00000054 = (BADSPACEBASE *)c;\n  return NAN(a) || NAN(b * 2.0f);\n}\n",
            "",
        );
        assert!(out.contains("(a != a)"), "{out}");
        assert!(out.contains("romwright_isnanf(b * 2.0f)"), "{out}");
        assert!(out.contains("(unsigned int)((unsigned int)__current_sp())"), "{out}");
        assert!(out.contains("romwright_set_sp((unsigned int)((unsigned int *)c))"), "{out}");
        assert!(helper_definitions(&out).contains("romwright_set_sp"));
    }

    #[test]
    fn a_parameter_of_ghidras_code_type_is_a_byte() {
        let out = run("void f(code a, code *b)\n{\n  code c;\n  c = a;\n}\n", "");
        assert!(out.contains("unsigned char a") && out.contains("unsigned char c;"), "{out}");
        assert!(out.contains("romwright_code *b"), "{out}");
    }

    #[test]
    fn nothing_is_conformed_for_a_compiler_that_is_not_strict() {
        let out = super::super::apply("int f(unsigned int *p, unsigned int n)\n{\n  return p < n;\n}\n", &Decls::new());
        assert!(out.contains("p < n") && !out.contains("(unsigned int)p"), "{out}");
    }
}
