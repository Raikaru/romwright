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

/// `ROMWRIGHT_EXPORT_DECLARED_VIEWS=off`: a global the project's header declares keeps the union view of its
/// storage in the printed body, which the header's own declaration does not have the members of.
pub(super) const DECLARED_VIEWS: &str = "ROMWRIGHT_EXPORT_DECLARED_VIEWS";

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

    /// `against_header`: the project's header declares the object, so no union exists in the translation
    /// unit and every access is printed through the object's own address. `spelled` is the object's name where
    /// the printer prefixed an underscore to it (a use whose width is not the symbol's).
    // One call site per storage rewrite; the arguments are the rewrite's independent inputs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn substitutions(
        &self,
        doc: &DecompDoc,
        index: usize,
        high: &HighVariable,
        value: Option<ValueId>,
        replacements: &mut BTreeMap<usize, String>,
        little_endian: Option<bool>,
        against_header: bool,
        spelled: Option<&str>,
    ) -> Result<(), String> {
        let name: &str = spelled.unwrap_or(&doc.tokens[index].text);
        let next = |start| doc.tokens.iter().enumerate().skip(start)
            .find(|(_, token)| !token.text.is_empty());
        let dot = next(index + 1).filter(|(_, token)| token.kind == TokenKind::Op && token.text == ".")
            .map(|(dot, _)| dot);
        let field = dot.and_then(|dot| next(dot + 1));
        if let (Some(id), Some((field_index, field))) = (value, field) {
            let ir = doc.function_ir.as_ref().unwrap();
            let width = ir.values.get(&id).and_then(|value| value.size).ok_or("partial access has no width")?;
            let offset = high.symbol_offset.and_then(|offset| u64::try_from(offset).ok())
                .ok_or("partial access has no nonnegative symbol offset")?;
            // Native PrintC tags artificial fields as Syntax, real fields as
            // Field. The spelling is checked only after binding to SSA storage.
            if field.kind == TokenKind::Syntax && field.text == format!("_{offset}_{width}_") {
                let volatile = high.symbol.as_ref().is_some_and(|symbol| symbol.volatile);
                if !matches!(width, 1 | 2 | 4 | 8) {
                    // No C type has this width: a read is the bytes put together in the target's byte order.
                    let written = next(field_index + 1).is_some_and(|(_, t)| t.kind == TokenKind::Op && t.text == "=");
                    let Some(little_endian) = little_endian.filter(|_| !written && (3..=7).contains(&width)) else {
                        return Err(format!("{width}-byte partial {} {name} has no C type", if written { "write to" } else { "access to" }));
                    };
                    replacements.insert(index, Self::composed(name, offset, width, little_endian, volatile));
                    replacements.insert(dot.unwrap(), String::new());
                    replacements.insert(field_index, String::new());
                    return Ok(());
                }
                let refined = (!high.type_locked).then(|| ir.type_evidence.get(&id).copied())
                    .flatten().and_then(scalar_name);
                let scalar = refined.as_deref().or_else(|| globals::primitive(&high.data_type));
                if against_header {
                    let qualifier = if volatile { "volatile " } else { "" };
                    let cast = match scalar {
                        Some(scalar) => format!("{qualifier}{scalar} *"),
                        None => globals::declarator(&high.data_type, "*", volatile, 0).unwrap_or_else(|_| {
                            let base = MEMBERS.iter().find(|(size, member, _)| *size == width && member.starts_with('u'))
                                .map_or("unsigned char", |(_, _, data_type)| *data_type);
                            format!("{qualifier}{base} *")
                        }),
                    };
                    replacements.insert(index, format!("(*({cast})((unsigned char *)&{name} + {offset}))"));
                    replacements.insert(dot.unwrap(), String::new());
                    replacements.insert(field_index, String::new());
                    return Ok(());
                }
                let (prefix, member) = match scalar {
                    Some(scalar) => self.partial(name, offset, width, scalar, volatile)?,
                    None => self.typed(name, offset, width, &high.data_type, volatile)?,
                };
                if let Some(prefix) = prefix {
                    replacements.insert(index, prefix);
                }
                replacements.insert(field_index, member);
                return Ok(());
            }
        }
        // Ordinary scalar, array, and genuine named-field uses retain their
        // original C type through the whole-object member of the same union.
        if against_header {
            // The object as the decompiler typed it, at the object's address: what `.whole` was in the union.
            let array = self.data_type.metatype.as_deref() == Some("array")
                || self.data_type.name.as_deref().and_then(super::locals::odd_undefined).is_some();
            let cast = globals::declarator(&self.data_type, if array { "(*)" } else { "*" }, false, 0).ok();
            match cast {
                Some(cast) if self.data_type.metatype.as_deref() != Some("code") => {
                    replacements.insert(index, format!("(*({cast})&{name})"));
                }
                _ if spelled.is_some() => {
                    replacements.insert(index, name.to_string());
                }
                _ => {}
            }
            return Ok(());
        }
        replacements.insert(index, format!("{name}.whole"));
        Ok(())
    }

    /// A 3 to 7 byte read of the object at `offset`: its bytes put together as an
    /// unsigned integer in the target's byte order. No C type has this width,
    /// so there is no lvalue to print; a write is refused by the caller.
    fn composed(name: &str, offset: u64, width: u32, little_endian: bool, volatile: bool) -> String {
        let wide = if width > 4 { "unsigned long long" } else { "unsigned int" };
        let byte_type = if volatile { "volatile unsigned char" } else { "unsigned char" };
        let parts: Vec<String> = (0..width)
            .map(|i| {
                let shift = 8 * if little_endian { i } else { width - 1 - i };
                let byte = format!("(({wide})(({byte_type} *)&{name})[{}])", offset + u64::from(i));
                if shift == 0 { byte } else { format!("({byte} << {shift})") }
            })
            .collect();
        format!("({})", parts.join(" | "))
    }

    /// The C spelling of a `width`-byte access at `offset`: the replacement
    /// for the object's name token, if any, and for the artificial field.
    ///
    /// An access the union has a member for is an element of it. Any other
    /// access of a 1, 2, 4 or 8 byte value (one wider than the union's
    /// alignment — a word copy out of a 13-byte string, which no `u4[]`
    /// member can describe without changing the object's size — or one
    /// that is misaligned or lies past the object's end) reads the bytes at
    /// the same address as `cast`, a pointer type to the value's own type:
    /// `&name.u1[offset]` inside the object, `&name.u1[0] + offset` beyond
    /// it. The target performs exactly that load or store.
    fn view(
        &self,
        name: &str,
        offset: u64,
        width: u32,
        cast: &str,
        member: Option<&str>,
    ) -> Result<(Option<String>, String), String> {
        let wide = u64::from(width);
        if !matches!(width, 1 | 2 | 4 | 8) {
            return Err(format!("{width}-byte partial access to {name} has no C type"));
        }
        let inside = offset.checked_add(wide).is_some_and(|end| end <= self.size);
        if let Some(member) = member.filter(|_| inside && width <= self.alignment && offset.is_multiple_of(wide)) {
            return Ok((None, format!("{member}[{}]", offset / wide)));
        }
        if inside {
            Ok((Some(format!("(*({cast})&{name}")), format!("u1[{offset}])")))
        } else {
            Ok((Some(format!("(*({cast})((unsigned char *)&{name}")), format!("u1[0] + {offset}))")))
        }
    }

    /// A `width`-byte access whose value is the scalar `scalar`.
    fn partial(
        &self,
        name: &str,
        offset: u64,
        width: u32,
        scalar: &str,
        volatile: bool,
    ) -> Result<(Option<String>, String), String> {
        let member = MEMBERS.iter().find(|(size, _, data_type)| *size == width && *data_type == scalar)
            .map(|(_, member, _)| *member)
            .ok_or_else(|| format!("unsupported {scalar} partial access to {name}"))?;
        let qualifier = if volatile { "volatile " } else { "" };
        self.view(name, offset, width, &format!("{qualifier}{scalar} *"), Some(member))
    }

    /// A `width`-byte access whose value has no scalar C type here (a pointer
    /// stored in a word of an `undefined8`, a code pointer): the bytes at
    /// `offset` read as the value's own declared type through their address.
    fn typed(
        &self,
        name: &str,
        offset: u64,
        width: u32,
        data_type: &DecompType,
        volatile: bool,
    ) -> Result<(Option<String>, String), String> {
        let unsigned = MEMBERS.iter().find(|(size, member, _)| *size == width && member.starts_with('u'));
        let cast = globals::declarator(data_type, "*", volatile, 0).unwrap_or_else(|_| {
            let base = unsigned.map_or("unsigned char", |(_, _, data_type)| *data_type);
            format!("{}{base} *", if volatile { "volatile " } else { "" })
        });
        // a typed value is never a member of the union: the cast is what gives it its type
        self.view(name, offset, width, &cast, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(address: u64, size: u64, alignment: u32) -> StorageView {
        let data_type = DecompType {
            name: Some("undefined1".into()), id: None, size: Some(1), metatype: Some("unknown".into()),
            element_count: None, target: None, prototype: None,
        };
        StorageView { data_type, address, size, alignment }
    }

    #[test]
    fn member_access_indexes_the_matching_array() {
        let view = view(0x1000, 16, 8);
        assert_eq!(view.partial("g", 4, 4, "unsigned int", false), Ok((None, "u4[1]".into())));
        assert_eq!(view.partial("g", 8, 8, "double", false), Ok((None, "f8[1]".into())));
    }

    #[test]
    fn aligned_word_of_an_odd_sized_object_reads_through_the_byte_view() {
        // x360 0x8258d150: `s______829dc830._0_4_`, a word copy out of a
        // 13-byte string at a 16-aligned address. The union has only byte
        // members, so the word is read at the same address through them.
        let view = view(0x829d_c830, 13, 1);
        assert_eq!(
            view.partial("s", 0, 4, "unsigned int", false),
            Ok((Some("(*(unsigned int *)&s".into()), "u1[0])".into()))
        );
        assert_eq!(
            view.partial("s", 8, 4, "int", true),
            Ok((Some("(*(volatile int *)&s".into()), "u1[8])".into()))
        );
    }

    fn named(name: &str, size: Option<u64>) -> DecompType {
        DecompType {
            name: Some(name.into()), id: None, size, metatype: None,
            element_count: None, target: None, prototype: None,
        }
    }

    fn pointer_to(target: DecompType) -> DecompType {
        DecompType {
            name: None, id: None, size: Some(4), metatype: Some("ptr".into()),
            element_count: None, target: Some(Box::new(target)), prototype: None,
        }
    }

    #[test]
    fn a_pointer_in_a_word_of_an_undefined8_is_read_through_its_own_type() {
        // fatal-frame 0x100958: `DAT_00252750._4_4_`, a `short *` in the high
        // word of an 8-byte global that has no pointer member.
        let view = view(0x252750, 8, 8);
        let pointer = pointer_to(named("short", None));
        assert_eq!(
            view.typed("DAT_00252750", 4, 4, &pointer, false),
            Ok((Some("(*(short **)&DAT_00252750".into()), "u1[4])".into()))
        );
        assert_eq!(
            view.typed("DAT_00252750", 4, 4, &pointer, true),
            Ok((Some("(*(short *volatile *)&DAT_00252750".into()), "u1[4])".into()))
        );
    }

    #[test]
    fn a_typed_access_in_a_byte_aligned_object_reads_through_the_byte_view() {
        let view = view(0x829d_c830, 13, 1);
        let pointer = pointer_to(named("char", None));
        assert_eq!(
            view.typed("s", 8, 4, &pointer, false),
            Ok((Some("(*(char **)&s".into()), "u1[8])".into()))
        );
        assert_eq!(
            view.typed("s", 9, 4, &pointer, false),
            Ok((Some("(*(char **)&s".into()), "u1[9])".into()))
        );
        assert_eq!(
            view.typed("s", 12, 4, &pointer, false),
            Ok((Some("(*(char **)((unsigned char *)&s".into()), "u1[0] + 12))".into()))
        );
    }

    #[test]
    fn an_odd_width_read_is_its_bytes_in_the_targets_order() {
        // fatal-frame 0x104b40: `DAT_00357e30._1_3_`, three bytes of a word
        let low = "((unsigned int)((unsigned char *)&g)[1])";
        let mid = "((unsigned int)((unsigned char *)&g)[2])";
        let high = "((unsigned int)((unsigned char *)&g)[3])";
        assert_eq!(
            StorageView::composed("g", 1, 3, true, false),
            format!("({low} | ({mid} << 8) | ({high} << 16))")
        );
        assert_eq!(
            StorageView::composed("g", 1, 3, false, false),
            format!("(({low} << 16) | ({mid} << 8) | {high})")
        );
        assert!(StorageView::composed("g", 0, 6, true, true).contains("(volatile unsigned char *)&g)[5]"));
        assert!(StorageView::composed("g", 0, 6, true, true).starts_with("(((unsigned long long)"));
    }

    #[test]
    fn a_misaligned_or_out_of_bounds_access_is_printed_through_its_address() {
        // fatal-frame / dark-chronicle: a word past the end of an object, or
        // not aligned to its width, is the load the target performs at that
        // address; only a width with no C type and a scalar of another size
        // are refused.
        let view = view(0x829d_c830, 13, 1);
        assert_eq!(
            view.partial("s", 2, 4, "unsigned int", false),
            Ok((Some("(*(unsigned int *)&s".into()), "u1[2])".into()))
        );
        assert_eq!(
            view.partial("s", 12, 4, "unsigned int", false),
            Ok((Some("(*(unsigned int *)((unsigned char *)&s".into()), "u1[0] + 12))".into()))
        );
        assert!(view.partial("s", 0, 0, "unsigned int", false).is_err());
        assert!(view.partial("s", 0, 3, "unsigned int", false).is_err());
        assert!(view.partial("s", 0, 4, "char", false).is_err());
    }
}
