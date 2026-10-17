//! Address constants: an integer the code builds with `lui` + `addiu` is a
//! relocated symbol address, not a number.
//!
//! The decompiler folds the pair into one constant (`0x5f05e8`) and prints
//! it as a number. A source file wrote a symbol there (`&D_005F05E8`), and a
//! compiler that is given a number builds it differently: MWCC and ee-gcc
//! materialise an integer constant with `lui` + `ori`, an address with
//! `lui` + `addiu`, whose low half the linker fills in. So the pair itself is
//! the evidence: a constant of the printed function that its own machine code
//! builds as `lui rt, hi` / `addiu rd, rt, lo` and that lies in the image is
//! an address, and it is printed as one (`(char *)&name`, or `&name` for a
//! function passed as an argument) wherever it occurs. The cast is to a
//! pointer, not `int`: MWCC schedules the instructions of a call argument or
//! of a base address differently when the source converts it to an integer.
//! A number the code builds with `ori` (a colour, a count, a mask) is never
//! touched.
//!
//! The name is the project's symbol at that exact address, else
//! `DAT_<address>` (declared here as an array of unknown size). Only the
//! `r5900` code is read: other MIPS targets are not measured.
use super::globals::GlobalRef;
use super::is_c_ident;
use std::collections::{BTreeMap, BTreeSet};

/// A project symbol at an address: a function's name, or a data symbol's.
#[derive(Clone, Debug)]
pub struct Named {
    pub name: String,
    pub function: bool,
}

/// The project's names for addresses; functions win over other symbols at the
/// same address, and a name that is not a C identifier is not used.
pub fn address_names<'a>(
    functions: impl IntoIterator<Item = (u64, &'a str)>,
    symbols: impl IntoIterator<Item = (u64, &'a str)>,
) -> BTreeMap<u64, Named> {
    let mut names = BTreeMap::new();
    for (address, name) in symbols {
        if is_c_ident(name) {
            names.entry(address).or_insert(Named { name: name.to_string(), function: false });
        }
    }
    for (address, name) in functions {
        if is_c_ident(name) {
            names.insert(address, Named { name: name.to_string(), function: true });
        }
    }
    names
}

fn hex_literal(text: &str, at: usize) -> Option<(usize, u64)> {
    let rest = &text[at..];
    let digits = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X"))?;
    let length = digits.bytes().take_while(u8::is_ascii_hexdigit).count();
    if length == 0 || length > 8 {
        return None;
    }
    let value = u64::from_str_radix(&digits[..length], 16).ok()?;
    let mut end = at + 2 + length;
    while text[end..].starts_with(['u', 'U', 'l', 'L']) {
        end += 1;
    }
    Some((end, value))
}

/// The printed function with every address constant spelled as a symbol, the
/// declarations of the symbols it introduced, and the extern lines of the
/// functions among them. `declared` says whether a name already has a
/// declaration in the printed text.
pub(super) fn rewrite(
    body: &str,
    constants: &BTreeSet<u64>,
    names: &BTreeMap<u64, Named>,
    declared: &dyn Fn(&str) -> bool,
) -> (String, Vec<GlobalRef>, String) {
    if constants.is_empty() {
        return (body.to_string(), Vec::new(), String::new());
    }
    let mut out = String::with_capacity(body.len());
    let mut added: BTreeMap<String, (u64, bool)> = BTreeMap::new();
    let bytes = body.as_bytes();
    let mut at = 0;
    let mut previous_word = false;
    while at < bytes.len() {
        let rest = &body[at..];
        if rest.starts_with("/*") {
            let end = rest.find("*/").map_or(body.len(), |end| at + end + 2);
            out.push_str(&body[at..end]);
            at = end;
            previous_word = false;
        } else if rest.starts_with("//") {
            let end = rest.find('\n').map_or(body.len(), |end| at + end);
            out.push_str(&body[at..end]);
            at = end;
            previous_word = false;
        } else if bytes[at] == b'"' || bytes[at] == b'\'' {
            let quote = bytes[at];
            let mut end = at + 1;
            while end < bytes.len() && bytes[end] != quote {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            let end = (end + 1).min(bytes.len());
            out.push_str(&body[at..end]);
            at = end;
            previous_word = false;
        } else if !previous_word && rest.starts_with("0x") {
            match hex_literal(body, at).filter(|(_, value)| constants.contains(value)) {
                Some((end, value)) => {
                    let (name, function) = match names.get(&value) {
                        Some(named) => (named.name.clone(), named.function),
                        None => (format!("DAT_{value:08x}"), false),
                    };
                    // A pointer, not an integer: MWCC schedules the code of a call argument or
                    // a base address differently when the source converts it to `int` first.
                    let previous = out.trim_end().chars().last();
                    let next = body[end..].trim_start().chars().next();
                    let argument = matches!(previous, Some('(' | ',')) && matches!(next, Some(')' | ','));
                    if function && argument {
                        out.push_str(&format!("&{name}"));
                    } else {
                        out.push_str(&format!("(char *)&{name}"));
                    }
                    added.entry(name).or_insert((value, function));
                    at = end;
                }
                None => {
                    let end = at + 2 + rest[2..].bytes().take_while(u8::is_ascii_alphanumeric).count();
                    out.push_str(&body[at..end]);
                    at = end;
                }
            }
            previous_word = true;
        } else {
            let c = rest.chars().next().unwrap();
            previous_word = c.is_ascii_alphanumeric() || c == '_' || c == '.';
            out.push(c);
            at += c.len_utf8();
        }
    }
    let mut globals = Vec::new();
    let mut functions = String::new();
    for (name, (address, function)) in added {
        if declared(&name) {
            continue;
        }
        if function {
            functions.push_str(&format!("extern int {name}();\n"));
        } else {
            globals.push(GlobalRef {
                declaration: format!("unsigned char {name}[]"),
                name,
                address: Some(address),
                definition: String::new(),
            });
        }
    }
    (out, globals, functions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_become_symbols_and_numbers_stay() {
        let constants = BTreeSet::from([0x5f05e8, 0x1db8d0]);
        let names = address_names([(0x1db8d0, "func_001DB8D0")], []);
        let body = "x = f(0x5f05e8, 0x1db8d0, 0x3131, a.0x5f05e8, \"0x5f05e8\"); /* 0x5f05e8 */";
        let (text, globals, functions) = rewrite(body, &constants, &names, &|_| false);
        assert_eq!(
            text,
            "x = f((char *)&DAT_005f05e8, &func_001DB8D0, 0x3131, a.0x5f05e8, \"0x5f05e8\"); /* 0x5f05e8 */"
        );
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0].declaration, "unsigned char DAT_005f05e8[]");
        assert_eq!(globals[0].address, Some(0x5f05e8));
        assert_eq!(functions, "extern int func_001DB8D0();\n");
    }

    #[test]
    fn a_declared_name_is_not_declared_again() {
        let constants = BTreeSet::from([0x5f05e8]);
        let names = address_names([], [(0x5f05e8, "D_005F05E8")]);
        let (text, globals, _) = rewrite("f(0x5f05e8U);", &constants, &names, &|name| name == "D_005F05E8");
        assert_eq!(text, "f((char *)&D_005F05E8);");
        assert!(globals.is_empty());
    }
}
