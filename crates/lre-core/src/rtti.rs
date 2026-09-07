//! Itanium C++ ABI class recovery.
//!
//! Evidence chain, all of it in the image: a loader-bound relocation names one
//! of the ABI's `__cxxabiv1` type_info vtables, so any data word holding that
//! vtable's address point is a `type_info`'s vptr. The word after it points at
//! the mangled type name, the `__si`/`__vmi` shapes carry the base list, and a
//! data word holding the type_info's own address is a vtable's type_info slot,
//! two pointers into the object. Nothing here guesses: a candidate that fails
//! any step produces no class.
//!
//! Layouts follow the Itanium C++ ABI sections 2.9.5 (RTTI) and 2.5.2 (vtable
//! layout); the ABI vtable names follow the same document's mangling rules and
//! are matched literally.
use crate::native::{self, ImportError, Mapping, NativeImport};
use lre_model::{Address, ClassBase, ClassKind, ClassRow, FactKind, FactProvenance};
use std::collections::BTreeMap;

pub const SOURCE: &str = "itanium-rtti";

const CLASS_TYPE_INFO: &str = "_ZTVN10__cxxabiv117__class_type_infoE";
const SI_CLASS_TYPE_INFO: &str = "_ZTVN10__cxxabiv120__si_class_type_infoE";
const VMI_CLASS_TYPE_INFO: &str = "_ZTVN10__cxxabiv121__vmi_class_type_infoE";

/// Counts from one recovery pass.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ClassReport {
    /// ABI type_info vtable address points the image binds.
    pub anchors: usize,
    pub typeinfo: usize,
    pub classes: usize,
    pub bases: usize,
    /// type_info objects with no vtable pointing at them: no class row.
    pub without_vtable: usize,
    pub revision: u64,
}

/// Reader over the loaded image: pointer width, byte order and mapped words.
struct Image<'a> {
    mappings: &'a [Mapping],
    width: usize,
    big_endian: bool,
}

impl<'a> Image<'a> {
    fn bytes(&self, address: u64, len: usize) -> Option<&'a [u8]> {
        self.mappings.iter().find_map(|mapping| {
            let offset = address.checked_sub(mapping.vaddr)? as usize;
            mapping.bytes.get(offset..offset.checked_add(len)?)
        })
    }

    fn word(&self, address: u64) -> Option<u64> {
        let bytes = self.bytes(address, self.width)?;
        Some(bytes.iter().enumerate().fold(0u64, |value, (index, &byte)| {
            let shift = if self.big_endian {
                self.width - 1 - index
            } else {
                index
            };
            value | (byte as u64) << (8 * shift)
        }))
    }

    /// True when `address` lies in an executable mapping: a function pointer.
    fn executable(&self, address: u64) -> bool {
        address != 0
            && self.mappings.iter().any(|mapping| {
                mapping.flags & 4 != 0
                    && address >= mapping.vaddr
                    && address - mapping.vaddr < mapping.size
            })
    }

    fn u32(&self, address: u64) -> Option<u32> {
        let bytes = self.bytes(address, 4)?;
        let bytes: [u8; 4] = bytes.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    /// Signed word, for the ABI's `ptrdiff_t` and `long` fields.
    fn signed(&self, address: u64) -> Option<i64> {
        let value = self.word(address)?;
        Some(if self.width == 8 {
            value as i64
        } else {
            value as u32 as i32 as i64
        })
    }

    /// A NUL-terminated Itanium type name: `<number><identifier>` or a nested
    /// `N...E` form. Anything else is not a type name and ends the candidate.
    fn type_name(&self, address: u64) -> Option<String> {
        let bytes = self.bytes(address, 1)?;
        if !bytes[0].is_ascii_digit() && bytes[0] != b'N' {
            return None;
        }
        let mut name = String::new();
        for step in 0..1024u64 {
            let byte = self.bytes(address + step, 1)?[0];
            if byte == 0 {
                return (!name.is_empty()).then_some(name);
            }
            if !byte.is_ascii_graphic() {
                return None;
            }
            name.push(byte as char);
        }
        None
    }
}

/// Itanium `<source-name>` and nested `N ... E` names only; anything else is
/// reported in its mangled form rather than guessed at.
pub fn demangle_type(mangled: &str) -> String {
    fn components(text: &str) -> Option<Vec<String>> {
        let mut rest = text;
        let mut parts = Vec::new();
        while !rest.is_empty() {
            let digits = rest.find(|c: char| !c.is_ascii_digit())?;
            if digits == 0 {
                return None;
            }
            let (length, tail) = rest.split_at(digits);
            let length: usize = length.parse().ok()?;
            if tail.len() < length {
                return None;
            }
            let (component, tail) = tail.split_at(length);
            parts.push(component.to_string());
            rest = tail;
        }
        (!parts.is_empty()).then_some(parts)
    }
    let inner = mangled
        .strip_prefix('N')
        .and_then(|rest| rest.strip_suffix('E'))
        .unwrap_or(mangled);
    match components(inner) {
        Some(parts) => parts.join("::"),
        None => mangled.to_string(),
    }
}

impl crate::Core {
    pub fn classes(&self, program: &str) -> crate::Result<Vec<ClassRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.classes(id)?)
    }

    /// Recovers Itanium classes from a byte snapshot and publishes them.
    pub fn recover_classes(
        &self,
        binary: &std::path::Path,
        program: &str,
    ) -> crate::Result<ClassReport> {
        let id = self.db.program_id(program)?;
        let import = native::parse_native(&std::fs::read(binary)?)?;
        if import.language != self.db.program_language(id)? {
            return Err(ImportError::Bad("class input and stored language differ".into()).into());
        }
        let (rows, mut report) = recover(&import);
        self.db.replace_inferred_classes(id, SOURCE, &rows)?;
        report.revision = self.db.revision(id)?;
        Ok(report)
    }
}

/// Recovers every class the image describes, with no store access.
pub fn recover(import: &NativeImport) -> (Vec<ClassRow>, ClassReport) {
    let width = if import.language.contains(":64:") { 8 } else { 4 };
    let image = Image {
        mappings: &import.mappings,
        width,
        big_endian: import.language.contains(":BE:") || import.language.contains(":LEBE:"),
    };
    let mut report = ClassReport::default();
    // Two evidence forms. A COPY relocation duplicates one of the ABI's
    // type_info vtables into this image, so a vptr *holds* its address point.
    // Every other named binding rewrites the vptr slot itself, so that slot
    // *is* a type_info's first word.
    let mut anchors: BTreeMap<u64, ClassKind> = BTreeMap::new();
    let mut bound: BTreeMap<u64, ClassKind> = BTreeMap::new();
    for relocation in &import.named_relocations {
        let kind = match relocation.symbol.as_str() {
            CLASS_TYPE_INFO => ClassKind::Plain,
            SI_CLASS_TYPE_INFO => ClassKind::SingleBase,
            VMI_CLASS_TYPE_INFO => ClassKind::MultipleBase,
            _ => continue,
        };
        if relocation.copies {
            // Objects hold the address point: two pointers into the vtable.
            if let Some(anchor) = relocation.address.checked_add(2 * width as u64) {
                anchors.insert(anchor, kind);
            }
        } else {
            bound.insert(relocation.address, kind);
        }
    }
    report.anchors = anchors.len() + bound.len();
    if report.anchors == 0 {
        // No image binds an ABI type_info vtable, so no Itanium class exists
        // here and nothing needs scanning.
        return (Vec::new(), report);
    }
    let named = |candidate: u64| {
        image
            .word(candidate + width as u64)
            .and_then(|pointer| image.type_name(pointer))
    };
    let mut typeinfo: BTreeMap<u64, (ClassKind, String)> = BTreeMap::new();
    for (&address, &kind) in &bound {
        if let Some(name) = named(address) {
            typeinfo.insert(address, (kind, name));
        }
    }
    // type_info objects: a data word holding an anchor, followed by a name.
    for mapping in import.mappings.iter().filter(|mapping| mapping.flags & 4 == 0) {
        let mut address = mapping.vaddr;
        let end = mapping.vaddr + mapping.bytes.len() as u64;
        while address + 2 * width as u64 <= end {
            let candidate = address;
            address += width as u64;
            let Some(vptr) = image.word(candidate) else {
                continue;
            };
            let Some(&kind) = anchors.get(&vptr) else {
                continue;
            };
            let Some(name) = named(candidate) else {
                continue;
            };
            typeinfo.insert(candidate, (kind, name));
        }
    }
    report.typeinfo = typeinfo.len();
    // Vtables: a data word holding a type_info address is the vtable's
    // type_info slot, one pointer past `offset_to_top`.
    let mut vtables: BTreeMap<u64, u64> = BTreeMap::new();
    for mapping in import.mappings.iter().filter(|mapping| mapping.flags & 4 == 0) {
        let mut address = mapping.vaddr;
        let end = mapping.vaddr + mapping.bytes.len() as u64;
        while address + width as u64 <= end {
            let slot = address;
            address += width as u64;
            let Some(value) = image.word(slot) else {
                continue;
            };
            if !typeinfo.contains_key(&value) || slot < mapping.vaddr + width as u64 {
                continue;
            }
            // The primary vtable is the one whose `offset_to_top` is zero.
            if image.signed(slot - width as u64) != Some(0) {
                continue;
            }
            vtables.entry(value).or_insert(slot - width as u64);
        }
    }
    let mut rows = Vec::new();
    for (&address, (kind, mangled)) in &typeinfo {
        let Some(&vtable) = vtables.get(&address) else {
            report.without_vtable += 1;
            continue;
        };
        let bases = bases(&image, address, *kind, &typeinfo);
        report.bases += bases.len();
        rows.push(ClassRow {
            typeinfo: Address::ram(address),
            vtable: Address::ram(vtable),
            name: demangle_type(mangled),
            mangled: mangled.clone(),
            kind: *kind,
            vtable_slots: slots(&image, vtable),
            bases,
            provenance: FactProvenance {
                kind: FactKind::Inferred,
                source: SOURCE.into(),
                confidence: None,
            },
        });
    }
    report.classes = rows.len();
    (rows, report)
}

/// Virtual function slots after the address point. A vtable slot holds a
/// function pointer, so the run ends at the first word that does not point
/// into executable memory — which is exactly where the next vtable, a pure
/// virtual entry or the padding begins.
fn slots(image: &Image<'_>, vtable: u64) -> u64 {
    let width = image.width as u64;
    let mut slot = vtable + 2 * width;
    let mut count = 0;
    while let Some(value) = image.word(slot) {
        if !image.executable(value) {
            break;
        }
        count += 1;
        slot += width;
    }
    count
}

/// Base list exactly as the ABI records it for this type_info shape.
fn bases(
    image: &Image<'_>,
    address: u64,
    kind: ClassKind,
    typeinfo: &BTreeMap<u64, (ClassKind, String)>,
) -> Vec<ClassBase> {
    let width = image.width as u64;
    let named = |target: u64| {
        typeinfo
            .get(&target)
            .map(|(_, mangled)| mangled.clone())
            .unwrap_or_default()
    };
    match kind {
        ClassKind::Plain => Vec::new(),
        ClassKind::SingleBase => match image.word(address + 2 * width) {
            Some(base) if base != 0 => vec![ClassBase {
                typeinfo: Address::ram(base),
                mangled: named(base),
                offset: 0,
                virtual_base: false,
                public_base: true,
            }],
            _ => Vec::new(),
        },
        ClassKind::MultipleBase => {
            // __vmi_class_type_info: flags, base count, then base_class_type_info
            // pairs of (type_info*, offset_flags).
            let Some(count) = image.u32(address + 2 * width + 4) else {
                return Vec::new();
            };
            let mut bases = Vec::new();
            for index in 0..count.min(1024) as u64 {
                let entry = address + 2 * width + 8 + index * 2 * width;
                let (Some(base), Some(flags)) =
                    (image.word(entry), image.signed(entry + width))
                else {
                    break;
                };
                if base == 0 {
                    break;
                }
                bases.push(ClassBase {
                    typeinfo: Address::ram(base),
                    mangled: named(base),
                    // Itanium ABI: the low byte holds the flags, the rest is a
                    // signed offset in bytes.
                    offset: flags >> 8,
                    virtual_base: flags & 1 != 0,
                    public_base: flags & 2 != 0,
                });
            }
            bases
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_grammar_this_build_parses_is_demangled() {
        assert_eq!(demangle_type("4Base"), "Base");
        assert_eq!(demangle_type("N3app6WidgetE"), "app::Widget");
        assert_eq!(demangle_type("6Middle"), "Middle");
        // Templates and pointers are left mangled rather than half-decoded.
        assert_eq!(demangle_type("1AIiE"), "1AIiE");
        assert_eq!(demangle_type("Pi"), "Pi");
        assert_eq!(demangle_type("9"), "9");
    }
}
