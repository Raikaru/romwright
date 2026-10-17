//! Struct layouts as the store holds them, and the switch that decides which
//! of them the decompiler may see.
//!
//! A layout is a `type_defs` row of kind `struct` plus its `type_fields`
//! rows. The row's `provenance` names where the layout came from, and that
//! is what the mode gates on:
//!
//! * [`StructSource::Debug`]: the image's own debug stream (`native-import:
//!   debug-info`). Exact: the compiler wrote it.
//! * [`StructSource::Inferred`]: synthesized from the accesses a function's
//!   body makes (`native-inferred:struct-layout`). A partial view.
//! * [`StructSource::FactPack`] and [`StructSource::User`]: asserted by a
//!   donor pack or by the analyst. Authoritative; every mode but `off` uses
//!   them.
//!
//! A field's `type_ref` is a type name (a core type, another struct, or a
//! `pointer`/`array` row of the type manager) or a short C-style spelling of
//! one: `name`, `name *`, `name **`, `name[4]`, `name *[4]`, `name[2][3]`.

use crate::{TypeDefRow, TypeFieldRow};

/// The environment variable that selects the [`StructMode`].
pub const ENV: &str = "ROMWRIGHT_STRUCTS";

/// Provenance of layouts read from the image's debug stream. The prototypes
/// that stream states carry the same source.
pub const DEBUG_SOURCE: &str = "native-import:debug-info";

/// Provenance of layouts synthesized from function bodies.
pub const INFERRED_SOURCE: &str = "native-inferred:struct-layout";

/// Provenance of a prototype row whose parameters name inferred structs. The
/// row belongs to one function: it types that function's own decompile and is
/// never applied as a callee's signature.
pub const PROTOTYPE_SOURCE: &str = "native-prototype:inferred-struct";

/// Whether a prototype row's source says its parameters name inferred structs
/// (the source may carry earlier passes' names in front of it).
pub fn is_struct_prototype(source: &str) -> bool {
    source.contains(PROTOTYPE_SOURCE)
}

/// Which struct layouts reach the decompiler and the printed C.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StructMode {
    /// None: parameters are `void *` / integers, as before.
    Off,
    /// Layouts the debug stream states (plus asserted ones).
    Debug,
    /// Layouts inferred from function bodies (plus asserted ones).
    Inferred,
    /// Both.
    All,
}

/// Where a layout came from, read from its provenance.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StructSource {
    Debug,
    Inferred,
    FactPack,
    User,
}

impl StructMode {
    /// What an unset `ROMWRIGHT_STRUCTS` means.
    pub const DEFAULT: StructMode = StructMode::All;

    pub fn parse(text: &str) -> Option<StructMode> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "none" => Some(StructMode::Off),
            "debug" => Some(StructMode::Debug),
            "inferred" => Some(StructMode::Inferred),
            "all" | "1" | "on" => Some(StructMode::All),
            _ => None,
        }
    }

    /// The mode the environment asks for. An unrecognised value is reported
    /// and read as the default rather than silently turning structs off.
    pub fn from_env() -> StructMode {
        match std::env::var(ENV) {
            Ok(text) if !text.trim().is_empty() => StructMode::parse(&text).unwrap_or_else(|| {
                eprintln!(
                    "{ENV}={text}: not one of off|debug|inferred|all; using {}",
                    StructMode::DEFAULT.name()
                );
                StructMode::DEFAULT
            }),
            _ => StructMode::DEFAULT,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            StructMode::Off => "off",
            StructMode::Debug => "debug",
            StructMode::Inferred => "inferred",
            StructMode::All => "all",
        }
    }

    /// Whether a layout of this source may be shown to the decompiler.
    pub fn allows(self, source: StructSource) -> bool {
        match (self, source) {
            (StructMode::Off, _) => false,
            (_, StructSource::FactPack | StructSource::User) => true,
            (StructMode::Debug | StructMode::All, StructSource::Debug) => true,
            (StructMode::Inferred | StructMode::All, StructSource::Inferred) => true,
            _ => false,
        }
    }

    /// Whether this mode asks for the inference pass.
    pub fn infers(self) -> bool {
        matches!(self, StructMode::Inferred | StructMode::All)
    }
}

/// The source a layout's provenance names.
pub fn source_of(provenance: &str) -> StructSource {
    if provenance.starts_with(DEBUG_SOURCE) {
        StructSource::Debug
    } else if provenance.starts_with("native-inferred") {
        StructSource::Inferred
    } else if provenance.starts_with("fact-pack") {
        StructSource::FactPack
    } else {
        StructSource::User
    }
}

/// The name of the struct synthesized for a function's `index`th parameter.
pub fn inferred_name(entry: u64, index: usize) -> String {
    format!("fn_{entry:08x}_arg{index}")
}

/// The name of the struct a field of `parent` points at, synthesized from the
/// accesses made through the loaded pointer.
pub fn inferred_pointee_name(parent: &str, offset: i64) -> String {
    format!("{parent}_p{offset:x}")
}

/// Whether `name` is one [`inferred_name`] or [`inferred_pointee_name`] makes:
/// a name no source declares, so a signature that names it and finds no
/// layout is the inference's own and can be erased.
pub fn is_inferred_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("fn_") else { return false };
    let Some((entry, tail)) = rest.split_once("_arg") else { return false };
    entry.len() == 8
        && entry.bytes().all(|b| b.is_ascii_hexdigit())
        && tail.split("_p").enumerate().all(|(i, part)| {
            !part.is_empty() && part.bytes().all(|b| if i == 0 { b.is_ascii_digit() } else { b.is_ascii_hexdigit() })
        })
}

/// One member of a stored layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructField {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    /// See the module comment for the spelling.
    pub type_ref: String,
}

/// A struct as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructLayout {
    pub name: String,
    pub size: u64,
    pub provenance: String,
    /// In offset order.
    pub fields: Vec<StructField>,
}

impl StructLayout {
    pub fn source(&self) -> StructSource {
        source_of(&self.provenance)
    }

    /// The `type_defs` row and `type_fields` rows that store this layout.
    pub fn rows(&self) -> (TypeDefRow, Vec<TypeFieldRow>) {
        let def = TypeDefRow {
            name: self.name.clone(),
            kind: "struct".into(),
            definition: String::new(),
            size: Some(self.size),
            alignment: None,
            base_type: None,
            provenance: self.provenance.clone(),
            primitive: None,
            element_count: None,
        };
        let fields = self
            .fields
            .iter()
            .enumerate()
            .map(|(ordinal, field)| TypeFieldRow {
                type_name: self.name.clone(),
                ordinal: ordinal as u32,
                field_name: field.name.clone(),
                offset: field.offset,
                size: Some(field.size),
                type_ref: Some(field.type_ref.clone()),
            })
            .collect();
        (def, fields)
    }
}

/// The struct layouts among `defs`, with their fields from `fields` (any
/// order). A field with no `type_ref` or no size is skipped: nothing states
/// what it is.
pub fn layouts(defs: &[TypeDefRow], fields: &[TypeFieldRow]) -> Vec<StructLayout> {
    let mut by_type: std::collections::BTreeMap<&str, Vec<&TypeFieldRow>> = Default::default();
    for field in fields {
        by_type.entry(field.type_name.as_str()).or_default().push(field);
    }
    defs.iter()
        .filter(|def| def.kind == "struct")
        .map(|def| {
            let mut rows = by_type.remove(def.name.as_str()).unwrap_or_default();
            rows.sort_by_key(|row| (row.offset, row.ordinal));
            StructLayout {
                name: def.name.clone(),
                size: def.size.unwrap_or(0),
                provenance: def.provenance.clone(),
                fields: rows
                    .into_iter()
                    .filter_map(|row| {
                        Some(StructField {
                            name: row.field_name.clone(),
                            offset: row.offset,
                            size: row.size?,
                            type_ref: row.type_ref.clone()?,
                        })
                    })
                    .collect(),
            }
        })
        .collect()
}

/// A field type, parsed from its `type_ref` spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeSpelling {
    Name(String),
    Pointer(Box<TypeSpelling>),
    Array(Box<TypeSpelling>, u64),
}

impl TypeSpelling {
    /// Parses `name`, `name *`, `name **`, `name[4]`, `name *[4]`,
    /// `name[2][3]`. `None` for anything else.
    pub fn parse(text: &str) -> Option<TypeSpelling> {
        let text = text.trim();
        let name_end = text.find(['*', '[']).unwrap_or(text.len());
        let name = text[..name_end].trim();
        if name.is_empty() || name.contains(char::is_whitespace) && !name.starts_with("struct ") {
            return None;
        }
        let mut rest = text[name_end..].trim_start();
        let mut ty = TypeSpelling::Name(name.trim_start_matches("struct ").trim().to_string());
        while let Some(more) = rest.strip_prefix('*') {
            ty = TypeSpelling::Pointer(Box::new(ty));
            rest = more.trim_start();
        }
        let mut dims = Vec::new();
        while let Some(more) = rest.strip_prefix('[') {
            let end = more.find(']')?;
            dims.push(more[..end].trim().parse::<u64>().ok()?);
            rest = more[end + 1..].trim_start();
        }
        if !rest.is_empty() {
            return None;
        }
        for count in dims.into_iter().rev() {
            ty = TypeSpelling::Array(Box::new(ty), count);
        }
        Some(ty)
    }

    /// The spelling [`parse`](Self::parse) reads back.
    pub fn text(&self) -> String {
        match self {
            TypeSpelling::Name(name) => name.clone(),
            TypeSpelling::Pointer(inner) => {
                let inner = inner.text();
                if inner.ends_with('*') {
                    format!("{inner}*")
                } else {
                    format!("{inner} *")
                }
            }
            TypeSpelling::Array(..) => {
                // The outermost dimension is written first.
                let mut dimensions = String::new();
                let mut element = self;
                while let TypeSpelling::Array(inner, count) = element {
                    dimensions.push_str(&format!("[{count}]"));
                    element = inner;
                }
                format!("{}{dimensions}", element.text())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_gate_sources() {
        assert!(!StructMode::Off.allows(StructSource::User));
        assert!(StructMode::Debug.allows(StructSource::Debug));
        assert!(!StructMode::Debug.allows(StructSource::Inferred));
        assert!(StructMode::Inferred.allows(StructSource::Inferred));
        assert!(!StructMode::Inferred.allows(StructSource::Debug));
        assert!(StructMode::Inferred.allows(StructSource::User));
        assert!(StructMode::All.allows(StructSource::Debug) && StructMode::All.allows(StructSource::Inferred));
        assert_eq!(source_of(DEBUG_SOURCE), StructSource::Debug);
        assert_eq!(source_of(INFERRED_SOURCE), StructSource::Inferred);
        assert_eq!(source_of("fact-pack:donor"), StructSource::FactPack);
        assert_eq!(source_of("user"), StructSource::User);
    }

    #[test]
    fn spellings_round_trip() {
        for text in ["int", "Foo *", "Foo **", "byte[4]", "Foo *[4]", "short[2][3]"] {
            let parsed = TypeSpelling::parse(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(parsed.text(), text);
        }
        assert_eq!(
            TypeSpelling::parse("short[2][3]"),
            Some(TypeSpelling::Array(
                Box::new(TypeSpelling::Array(Box::new(TypeSpelling::Name("short".into())), 3)),
                2
            ))
        );
        assert_eq!(TypeSpelling::parse("int[x]"), None);
        assert_eq!(TypeSpelling::parse(""), None);
        assert_eq!(TypeSpelling::parse("*"), None);
    }
}
