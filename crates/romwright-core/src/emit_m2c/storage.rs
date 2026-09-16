//! Partial native storage is represented as a C union, not a guessed structure.
//! Aligned scalar views preserve target byte order and volatile access width.
use super::{globals, is_c_ident, scalar_name};
use romwright_model::function_ir::{HighVariable, ValueId};
use romwright_model::{DecompDoc, DecompType, TokenKind};
use std::collections::BTreeMap;
use std::fmt::Write;

const MEMBERS: &[(u32, &str, &str)] = &[
    (1, "u1", "unsigned char"), (1, "s1", "signed char"),
    (2, "u2", "unsigned short"), (2, "s2", "short"),
    (4, "u4", "unsigned int"), (4, "s4", "int"), (4, "f4", "float"),
    (8, "u8", "unsigned long long"), (8, "s8", "long long"), (8, "f8", "double"),
];

pub(super) struct StorageView {
    data_type: DecompType,
    address: u64,
    size: u64,
    alignment: u32,
}

/// The same object must have the same declaration in every function of a TU.
#[derive(Default)]
pub(crate) struct UnitLayouts {
    views: BTreeMap<String, StorageView>,
}

impl UnitLayouts {
    pub(crate) fn new<'a>(docs: impl IntoIterator<Item = &'a DecompDoc>) -> Result<Self, String> {
        let mut result = Self::default();
        for doc in docs {
            let ir = doc.function_ir.as_ref().ok_or("storage views require a semantic graph")?;
            for high in &ir.high_variables {
                let Some(symbol) = high.symbol.as_ref().filter(|symbol| symbol.global) else { continue };
                if high.class != "global" {
                    continue;
                }
                let Some(size) = symbol.data_type.size.filter(|size| *size != 0) else { continue };
                let partial = high.symbol_offset.unwrap_or(0) != 0
                    || high.members.iter().any(|id| ir.values.get(id)
                        .and_then(|value| value.size).is_some_and(|width| u64::from(width) != size));
                if !partial {
                    continue;
                }
                if !is_c_ident(&symbol.name) {
                    return Err(format!("global {:?} needs a C identifier", symbol.name));
                }
                let address = symbol.address.as_ref().ok_or("partial global has no fixed address")?.offset;
                match result.views.entry(symbol.name.clone()) {
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        if entry.get().data_type != symbol.data_type || entry.get().address != address {
                            return Err(format!("conflicting storage views for {}", symbol.name));
                        }
                    }
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let alignment = [8, 4, 2, 1].into_iter()
                            .find(|width| size % u64::from(*width) == 0 && address % u64::from(*width) == 0)
                            .unwrap();
                        entry.insert(StorageView { data_type: symbol.data_type.clone(), address, size, alignment });
                    }
                }
            }
        }
        Ok(result)
    }

    pub(super) fn get(&self, name: &str) -> Option<&StorageView> {
        self.views.get(name)
    }
}

impl StorageView {
    pub(super) fn declaration(&self, name: &str, volatile: bool) -> Result<(String, String), String> {
        let tag = format!("romwright_storage_{name}_{}_{}", self.size, self.alignment);
        let guard = format!("ROMWRIGHT_STORAGE_{name}_{}_{}_DEFINED", self.size, self.alignment);
        let mut definition = format!("#ifndef {guard}\n#define {guard}\n/* Storage views; not a recovered source structure. */\nunion {tag} {{\n    {};\n", globals::declarator(&self.data_type, "whole", false, 0)?);
        for &(width, member, data_type) in MEMBERS {
            if width <= self.alignment {
                let _ = writeln!(definition, "    {data_type} {member}[{}];", self.size / u64::from(width));
            }
        }
        let _ = writeln!(definition, "}};\ntypedef char {tag}_size_check[(sizeof(union {tag}) == {}) ? 1 : -1];", self.size);
        for &(width, member, _) in MEMBERS {
            if width <= self.alignment {
                let _ = writeln!(definition, "typedef char {tag}_{member}_width_check[(sizeof(((union {tag} *)0)->{member}[0]) == {width}) ? 1 : -1];");
            }
        }
        definition.push_str("#endif\n");
        Ok((format!("{}union {tag} {name}", if volatile { "volatile " } else { "" }), definition))
    }

    pub(super) fn substitutions(
        &self,
        doc: &DecompDoc,
        index: usize,
        high: &HighVariable,
        value: Option<ValueId>,
        replacements: &mut BTreeMap<usize, String>,
    ) -> Result<(), String> {
        let name = &doc.tokens[index].text;
        let next = |start| doc.tokens.iter().enumerate().skip(start)
            .find(|(_, token)| !token.text.is_empty());
        let field = next(index + 1).filter(|(_, token)| token.kind == TokenKind::Op && token.text == ".")
            .and_then(|(dot, _)| next(dot + 1));
        if let (Some(id), Some((field_index, field))) = (value, field) {
            let ir = doc.function_ir.as_ref().unwrap();
            let width = ir.values.get(&id).and_then(|value| value.size).ok_or("partial access has no width")?;
            let offset = high.symbol_offset.and_then(|offset| u64::try_from(offset).ok())
                .ok_or("partial access has no nonnegative symbol offset")?;
            // Native PrintC tags artificial fields as Syntax, real fields as
            // Field. The spelling is checked only after binding to SSA storage.
            if field.kind == TokenKind::Syntax && field.text == format!("_{offset}_{width}_") {
                if width > self.alignment || width == 0 || offset % u64::from(width) != 0
                    || offset.checked_add(u64::from(width)).is_none_or(|end| end > self.size)
                {
                    return Err(format!("unaligned or out-of-bounds partial access to {name} needs typed context"));
                }
                let refined = (!high.type_locked).then(|| ir.type_evidence.get(&id).copied())
                    .flatten().and_then(scalar_name);
                let scalar = refined.as_deref().or_else(|| globals::primitive(&high.data_type))
                    .ok_or_else(|| format!("partial access to {name} has no scalar C type"))?;
                let member = MEMBERS.iter().find(|(size, _, data_type)| *size == width && *data_type == scalar)
                    .map(|(_, member, _)| *member)
                    .ok_or_else(|| format!("unsupported {scalar} partial access to {name}"))?;
                replacements.insert(field_index, format!("{member}[{}]", offset / u64::from(width)));
                return Ok(());
            }
        }
        // Ordinary scalar, array, and genuine named-field uses retain their
        // original C type through the whole-object member of the same union.
        replacements.insert(index, format!("{name}.whole"));
        Ok(())
    }
}
