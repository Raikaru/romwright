//! Declarations the pinned C library type archive holds, applied to imports.
//!
//! The archive itself is a Ghidra packed database; a parser for it in the
//! JVM-free path would be a lot of format for one table of names, so the table
//! is exported once by `scripts/gen_library_prototypes.py` and committed with
//! the archive's hash. This module reads that table and types the imports the
//! image names, and nothing else.
use std::collections::HashMap;
use std::path::Path;

/// The provenance every fact this pass writes carries.
pub const SOURCE: &str = "native-import:type-archive";

/// Base type names the decompiler always has, from its own core type table
/// (`native/specs/coretypes.xml`). A declaration naming anything else is left
/// alone: the C parser the worker feeds would reject it, and a rejected
/// signature fails the decompile rather than improving it.
const CORE: &[&str] = &[
    "void", "bool", "char", "uchar", "sbyte", "byte", "short", "ushort", "int", "uint",
    "long", "ulong", "longlong", "ulonglong", "float", "double", "longdouble",
    "wchar_t", "wchar16", "wchar32", "undefined", "undefined1", "undefined2",
    "undefined4", "undefined8", "code",
];

/// One declaration: what it returns, what it takes, whether it is variadic.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Declaration {
    pub return_type: String,
    #[serde(default)]
    pub varargs: bool,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Table {
    pub archive: String,
    pub archive_sha256: String,
    pub functions: HashMap<String, Declaration>,
}

/// Reads the committed table. A missing table is not an error: the pass simply
/// has nothing to say, exactly as it does for a name the archive omits.
pub fn load(path: &Path) -> Option<Table> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Whether every type in a declaration is one the decompiler already has, in
/// a shape its C parser accepts: a core base type with at most one pointer.
/// A deeper declarator (`char * *`) is refused rather than risking a parse
/// error, which fails the whole decompile instead of merely leaving it untyped.
fn representable(declaration: &Declaration) -> bool {
    let known = |text: &str| {
        let base = text.trim_end_matches(['*', ' ']).trim();
        CORE.contains(&base) && text.matches('*').count() <= 1
    };
    known(&declaration.return_type)
        && declaration
            .parameters
            .iter()
            .all(|parameter| known(&parameter.data_type))
}

/// The C declaration to hand the decompiler, e.g. `int printf(char * p1, ...)`.
pub fn signature(name: &str, declaration: &Declaration) -> String {
    let mut text = format!("{} {name}(", declaration.return_type);
    let mut parts: Vec<String> = declaration
        .parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| {
            // A declared parameter name may be a reserved word or empty; the
            // position is what the prototype needs.
            let identifier = if parameter.name.is_empty() {
                format!("param_{}", index + 1)
            } else {
                parameter.name.replace(|c: char| !c.is_alphanumeric() && c != '_', "_")
            };
            format!("{} {identifier}", parameter.data_type)
        })
        .collect();
    if declaration.varargs {
        parts.push("...".into());
    }
    if parts.is_empty() {
        text.push_str("void");
    } else {
        text.push_str(&parts.join(", "));
    }
    text.push(')');
    text
}

/// The declarations that apply to the names an image imports.
///
/// A name is typed only when the archive declares it and every type in that
/// declaration is one the decompiler has. Nothing else is invented: a name the
/// archive omits stays untyped.
pub fn declared_for<'a>(
    table: &'a Table,
    names: impl IntoIterator<Item = (u64, &'a str)>,
) -> Vec<(u64, String, &'a Declaration)> {
    let mut applied = Vec::new();
    for (address, name) in names {
        let Some(declaration) = table.functions.get(name) else {
            continue;
        };
        if !representable(declaration) {
            continue;
        }
        applied.push((address, signature(name, declaration), declaration));
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printf() -> Declaration {
        Declaration {
            return_type: "int".into(),
            varargs: true,
            parameters: vec![Parameter {
                name: "__format".into(),
                data_type: "char *".into(),
            }],
        }
    }

    #[test]
    fn a_variadic_declaration_composes_the_c_the_parser_needs() {
        assert_eq!(
            signature("printf", &printf()),
            "int printf(char * __format, ...)"
        );
    }

    #[test]
    fn a_declaration_with_no_parameters_is_void_not_empty() {
        let declaration = Declaration {
            return_type: "int".into(),
            varargs: false,
            parameters: Vec::new(),
        };
        assert_eq!(signature("getpid", &declaration), "int getpid(void)");
    }

    #[test]
    fn a_deeper_declarator_is_refused() {
        // `char * *` reaches the parser as a syntax error, which fails the
        // decompile of every function that calls it.
        let declaration = Declaration {
            return_type: "long".into(),
            varargs: false,
            parameters: vec![Parameter {
                name: "endptr".into(),
                data_type: "char * *".into(),
            }],
        };
        let table = Table {
            archive: "a".into(),
            archive_sha256: "b".into(),
            functions: HashMap::from([("strtol".into(), declaration)]),
        };
        assert!(declared_for(&table, [(0x30u64, "strtol")]).is_empty());
    }

    #[test]
    fn a_type_the_decompiler_does_not_have_is_left_alone() {
        // `FILE *` is a real declaration in the archive and a type the C
        // parser has never heard of: applying it would fail the decompile.
        let declaration = Declaration {
            return_type: "int".into(),
            varargs: false,
            parameters: vec![Parameter {
                name: "stream".into(),
                data_type: "FILE *".into(),
            }],
        };
        let table = Table {
            archive: "a".into(),
            archive_sha256: "b".into(),
            functions: HashMap::from([
                ("fclose".into(), declaration),
                ("printf".into(), printf()),
            ]),
        };
        let applied = declared_for(&table, [(0x10u64, "fclose"), (0x20u64, "printf")]);
        assert_eq!(
            applied
                .iter()
                .map(|(address, signature, _)| (*address, signature.clone()))
                .collect::<Vec<_>>(),
            vec![(0x20, "int printf(char * __format, ...)".to_string())]
        );
    }
}
