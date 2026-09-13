//! MSVC RTTI class recovery.
//!
//! Evidence chain, all of it structural. A `TypeDescriptor` is recognised by
//! its decorated name, which always starts with `.?A`, sitting two pointers
//! into the object after the `type_info` vftable pointer and a zero spare. A
//! `RTTICompleteObjectLocator` is then confirmed by its own fields: the
//! signature, a `pTypeDescriptor` that names a descriptor we already found, a
//! `pClassDescriptor` whose hierarchy descriptor signature is zero, and — on
//! 64-bit images — a self reference that fixes the image base without reading
//! any header. A data word holding the locator's address is the slot that
//! precedes a vftable's address point.
//!
//! Layouts follow LLVM's `clang/lib/CodeGen/MicrosoftCXXABI.cpp` and
//! `MicrosoftRTTI` emission (Apache-2.0 WITH LLVM-exception), which documents
//! `RTTICompleteObjectLocator`, `RTTIClassHierarchyDescriptor`,
//! `RTTIBaseClassDescriptor`, `TypeDescriptor` and the `PMD` displacement
//! triple. No Microsoft header, database or tool output is used.
use super::{ClassReport, Image, slots};
use romwright_model::{Address, ClassBase, ClassKind, ClassRow, FactKind, FactProvenance};
use std::collections::BTreeMap;

pub const SOURCE: &str = "msvc-rtti";

/// Decorated-name prefix every `TypeDescriptor` carries.
const NAME_PREFIX: &[u8] = b".?A";
/// `pTypeDescriptor` sits after signature, offset and cdOffset.
const LOCATOR_TYPE: u64 = 12;
const LOCATOR_HIERARCHY: u64 = 16;
const LOCATOR_SELF: u64 = 20;
/// A base is private or protected: not part of the public interface.
const BASE_PRIVATE: u32 = 4;

/// One confirmed complete object locator.
struct Locator {
    /// Byte offset of the vfptr this locator describes within the class.
    offset: u32,
    typeinfo: u64,
    hierarchy: u64,
    address: u64,
}

/// MSVC's decorated type name: `.?AV<reversed components>@@`. Anything the
/// documented grammar does not cover keeps its decorated form.
pub fn demangle_type(decorated: &str) -> String {
    let Some(rest) = decorated.strip_prefix(".?A") else {
        return decorated.to_string();
    };
    // Class, struct, union and enum tags; an enum tag carries one extra digit.
    let rest = match rest.as_bytes().first() {
        Some(b'V' | b'U' | b'T') => &rest[1..],
        Some(b'W') if rest.len() > 1 && rest.as_bytes()[1].is_ascii_digit() => &rest[2..],
        _ => return decorated.to_string(),
    };
    let parts: Vec<&str> = rest.split('@').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return decorated.to_string();
    }
    parts
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("::")
}

/// Recovers every class whose RTTI the image carries.
pub fn recover(image: &Image<'_>) -> (Vec<ClassRow>, ClassReport) {
    let width = image.width as u64;
    let mut report = ClassReport::default();
    // Type descriptors: the decorated name is the only self-describing part.
    let mut typeinfo: BTreeMap<u64, String> = BTreeMap::new();
    for mapping in image
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 4 == 0 && !mapping.bytes.is_empty())
    {
        for (offset, window) in mapping.bytes.windows(NAME_PREFIX.len()).enumerate() {
            if window != NAME_PREFIX {
                continue;
            }
            let name_at = mapping.vaddr + offset as u64;
            let Some(descriptor) = name_at.checked_sub(2 * width) else {
                continue;
            };
            // vftable pointer present, spare word clear, name terminated.
            if image.word(descriptor).unwrap_or(0) == 0
                || image.word(descriptor + width) != Some(0)
            {
                continue;
            }
            if let Some(name) = decorated_name(image, name_at) {
                typeinfo.insert(descriptor, name);
            }
        }
    }
    report.typeinfo = typeinfo.len();
    if typeinfo.is_empty() {
        return (Vec::new(), report);
    }
    // Complete object locators, each confirmed by its own fields.
    let mut locators: BTreeMap<u64, Vec<Locator>> = BTreeMap::new();
    for mapping in image
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 4 == 0 && !mapping.bytes.is_empty())
    {
        let end = mapping.vaddr + mapping.bytes.len() as u64;
        let mut candidate = mapping.vaddr;
        while candidate + LOCATOR_SELF + 4 <= end {
            let address = candidate;
            candidate += 4;
            let Some(locator) = confirm(image, address, &typeinfo) else {
                continue;
            };
            locators
                .entry(locator.typeinfo)
                .or_default()
                .push(locator);
        }
    }
    report.anchors = locators.values().map(Vec::len).sum();
    // The vftable's own slot: a data word holding the locator's address.
    let mut vtables: BTreeMap<u64, u64> = BTreeMap::new();
    for mapping in image
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 4 == 0 && !mapping.bytes.is_empty())
    {
        let end = mapping.vaddr + mapping.bytes.len() as u64;
        let mut slot = mapping.vaddr;
        while slot + width <= end {
            let address = slot;
            slot += width;
            let Some(value) = image.word(address) else {
                continue;
            };
            if locators
                .values()
                .flatten()
                .any(|locator| locator.address == value)
            {
                vtables.entry(value).or_insert(address);
            }
        }
    }
    let mut rows = Vec::new();
    for (&descriptor, name) in &typeinfo {
        let Some(found) = locators.get(&descriptor) else {
            continue;
        };
        // The primary vfptr is the one at the smallest offset in the class.
        let Some(primary) = found.iter().min_by_key(|locator| locator.offset) else {
            continue;
        };
        let Some(&vtable) = vtables.get(&primary.address) else {
            report.without_vtable += 1;
            continue;
        };
        let (bases, kind) = hierarchy(image, primary, descriptor, &typeinfo);
        report.bases += bases.len();
        rows.push(ClassRow {
            typeinfo: Address::ram(descriptor),
            vtable: Address::ram(vtable),
            name: demangle_type(name),
            mangled: name.clone(),
            kind,
            // The locator slot sits one pointer before the address point, so
            // the shared counter starts a pointer earlier than Itanium's.
            vtable_slots: slots(image, vtable.saturating_sub(width)),
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

/// Full decorated name at `address`, or `None` when it is not one.
fn decorated_name(image: &Image<'_>, address: u64) -> Option<String> {
    let mut name = String::new();
    for step in 0..1024u64 {
        let byte = image.bytes(address + step, 1)?[0];
        if byte == 0 {
            // `.?A` plus a tag plus at least one component.
            return (name.len() > 4 && name.ends_with('@')).then_some(name);
        }
        if !byte.is_ascii_graphic() {
            return None;
        }
        name.push(byte as char);
    }
    None
}

/// Confirms a complete object locator at `address` and resolves its fields.
///
/// A 64-bit locator stores image-relative offsets and a self reference, which
/// yields the image base; a 32-bit locator stores addresses directly.
fn confirm(
    image: &Image<'_>,
    address: u64,
    typeinfo: &BTreeMap<u64, String>,
) -> Option<Locator> {
    let signature = image.u32(address)?;
    let base = match signature {
        0 => 0,
        1 => {
            let self_reference = image.u32(address + LOCATOR_SELF)? as u64;
            let base = address.checked_sub(self_reference)?;
            // Images load on a page boundary, and nothing precedes the base.
            if base & 0xfff != 0 {
                return None;
            }
            base
        }
        _ => return None,
    };
    let descriptor = base.checked_add(image.u32(address + LOCATOR_TYPE)? as u64)?;
    if !typeinfo.contains_key(&descriptor) {
        return None;
    }
    let hierarchy = base.checked_add(image.u32(address + LOCATOR_HIERARCHY)? as u64)?;
    // RTTIClassHierarchyDescriptor: signature zero, at least the class itself.
    if image.u32(hierarchy)? != 0 || !(1..=4096).contains(&image.u32(hierarchy + 8)?) {
        return None;
    }
    Some(Locator {
        offset: image.u32(address + 4)?,
        typeinfo: descriptor,
        hierarchy,
        address,
    })
}

/// Bases from the class hierarchy descriptor's base class array, skipping the
/// entry that describes the class itself.
fn hierarchy(
    image: &Image<'_>,
    locator: &Locator,
    descriptor: u64,
    typeinfo: &BTreeMap<u64, String>,
) -> (Vec<ClassBase>, ClassKind) {
    // The same base the locator proved: zero for the 32-bit absolute form.
    let base = match image.u32(locator.address) {
        Some(1) => locator
            .address
            .checked_sub(image.u32(locator.address + LOCATOR_SELF).unwrap_or(0) as u64)
            .unwrap_or(0),
        _ => 0,
    };
    let resolve = |value: u32| base.checked_add(value as u64);
    let Some(count) = image.u32(locator.hierarchy + 8) else {
        return (Vec::new(), ClassKind::Plain);
    };
    let Some(array) = image.u32(locator.hierarchy + 12).and_then(resolve) else {
        return (Vec::new(), ClassKind::Plain);
    };
    let mut bases = Vec::new();
    for index in 0..count.min(4096) as u64 {
        let Some(entry) = image.u32(array + index * 4).and_then(resolve) else {
            break;
        };
        let (Some(base_descriptor), Some(displacement), Some(pointer), Some(attributes)) = (
            image.u32(entry).and_then(resolve),
            image.signed_u32(entry + 8),
            image.signed_u32(entry + 12),
            image.u32(entry + 20),
        ) else {
            break;
        };
        if base_descriptor == descriptor {
            continue; // Every hierarchy lists the class itself first.
        }
        bases.push(ClassBase {
            typeinfo: Address::ram(base_descriptor),
            mangled: typeinfo.get(&base_descriptor).cloned().unwrap_or_default(),
            offset: displacement as i64,
            // A virtual base reaches its subobject through the vbtable, so its
            // PMD carries a displacement instead of the `-1` sentinel.
            virtual_base: pointer != -1,
            public_base: attributes & BASE_PRIVATE == 0,
        });
    }
    let kind = match bases.len() {
        0 => ClassKind::Plain,
        1 if !bases[0].virtual_base => ClassKind::SingleBase,
        _ => ClassKind::MultipleBase,
    };
    (bases, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_documented_decoration_is_demangled() {
        assert_eq!(demangle_type(".?AVBase@@"), "Base");
        assert_eq!(demangle_type(".?AUMulti@@"), "Multi");
        assert_eq!(demangle_type(".?AVWidget@app@@"), "app::Widget");
        assert_eq!(demangle_type(".?AW4Color@@"), "Color");
        // Not a decorated type name, or a form this parser does not cover.
        assert_eq!(demangle_type(".?AX@@"), ".?AX@@");
        assert_eq!(demangle_type("Base"), "Base");
        assert_eq!(demangle_type(".?AV@@"), ".?AV@@");
    }
}
