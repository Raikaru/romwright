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

/// The type names one language's own core-type document declares: exactly
/// what the decompiler's C parser can resolve. This is not a constant: a
/// 32-bit language's `coretypes.xml` names `longlong` and no `long`, so
/// applying `long strtol(...)` there fails the parse -- and one failed parse
/// fails the whole decompile, not just that prototype.
pub fn core_type_names(specs: &Path) -> Option<std::collections::HashSet<String>> {
    let text = std::fs::read_to_string(specs.join("coretypes.xml")).ok()?;
    let mut names = std::collections::HashSet::new();
    let mut rest = text.as_str();
    while let Some(position) = rest.find("<type ") {
        let tag = &rest[position..];
        rest = &tag[1..];
        let Some(end) = tag.find('>') else { break };
        let header = &tag[..end];
        let Some(start) = header.find("name=\"") else { continue };
        let value = &header[start + 6..];
        if let Some(close) = value.find('"') {
            names.insert(value[..close].to_string());
        }
    }
    (!names.is_empty()).then_some(names)
}

/// Whether every type in a declaration is one the decompiler already has, in
/// a shape its C parser accepts. Pointer depth is not a limit -- the parser's
/// `pointer` rule is recursive and stock applies `char **__endptr` -- but the
/// base type has to be one this language declares.
fn representable(declaration: &Declaration, known_types: &std::collections::HashSet<String>) -> bool {
    // Pointer depth is not a limit the decompiler has: its own C parser takes
    // `char * *` (`grammar.y`'s `pointer` rule is recursive), and stock applies
    // exactly that declaration to `strtol`. What has to be known is the base
    // type the pointers end at.
    let known = |text: &str| {
        let base = text.trim_end_matches(['*', ' ']).trim();
        known_types.contains(base)
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
    known_types: &std::collections::HashSet<String>,
) -> Vec<(u64, String, &'a Declaration)> {
    let mut applied = Vec::new();
    for (address, name) in names {
        let Some(declaration) = table.functions.get(name) else {
            continue;
        };
        if !representable(declaration, known_types) {
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

    fn types(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn a_declaration_is_applied_only_where_the_language_has_its_types() {
        // Pointer depth is not the question -- the parser's `pointer` rule is
        // recursive -- but the base type is: a 32-bit language's coretypes
        // name `longlong` and no `long`, and `long strtol(...)` there reaches
        // the parser as a syntax error that fails the whole decompile.
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
        let wide = types(&["long", "char", "int"]);
        let narrow = types(&["longlong", "char", "int"]);
        assert_eq!(
            declared_for(&table, [(0x30u64, "strtol")], &wide)
                .iter()
                .map(|(address, signature, _)| (*address, signature.clone()))
                .collect::<Vec<_>>(),
            vec![(0x30, "long strtol(char * * endptr)".to_string())]
        );
        assert!(declared_for(&table, [(0x30u64, "strtol")], &narrow).is_empty());
    }

    #[test]
    fn the_type_names_come_from_the_language_document() {
        let directory = std::env::temp_dir().join(format!(
            "lre-coretypes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("coretypes.xml"),
            "<coretypes><type name=\"int\" size=\"4\" metatype=\"int\"/>\
             <type name=\"longlong\" size=\"8\" metatype=\"int\"/></coretypes>",
        )
        .unwrap();
        let names = core_type_names(&directory).unwrap();
        assert!(names.contains("longlong") && names.contains("int"));
        assert!(!names.contains("long"));
        // A document with no types names nothing, and the caller applies
        // nothing rather than guessing.
        std::fs::write(directory.join("coretypes.xml"), "<coretypes/>").unwrap();
        assert!(core_type_names(&directory).is_none());
        std::fs::remove_dir_all(&directory).unwrap();
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
        let applied = declared_for(&table, [(0x10u64, "fclose"), (0x20u64, "printf")],
                                   &types(&["int", "char"]));
        assert_eq!(
            applied
                .iter()
                .map(|(address, signature, _)| (*address, signature.clone()))
                .collect::<Vec<_>>(),
            vec![(0x20, "int printf(char * __format, ...)".to_string())]
        );
    }
}
