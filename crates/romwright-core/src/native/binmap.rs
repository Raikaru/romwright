//! EBOOT.BINMAP: the binary symbol map EA's Vita build left beside the
//! SELF. It is the linker's own table in binary form — the same ground
//! truth the text MAP grammars carry, so it feeds the same apply step.
//!
//! Layout, reverse-engineered from the NFS Most Wanted dump (record count
//! and file size agree exactly: 16 + 39461 * 160 = 6313776):
//!
//! ```text
//! header:  u32 record_count, u32 header_size (=16), u32 0, u32 version (=1)
//! record:  char name[152] NUL-padded, u32 a, u32 b          (160 bytes)
//! ```
//!
//! Record kinds, by name prefix:
//!
//! * plain `name`: `a` is the linked vaddr (low bit = Thumb, as ELF
//!   `st_value`), `b` the size. Functions and data both appear; the
//!   executable-mapping gate plus a vtable/typeinfo name check sorts them.
//! * `_NID_<name>`: `a` is the imported function's NID, `b` a file offset
//!   into the *original* linked ELF — stale against a rebuilt eboot.elf,
//!   so only the nid→name pair is used.
//! * `_INID_<liblen>_<LibName>__<namelen>_<name>`: `a` is a NID — the
//!   library's own NID when the `__` tail is absent, else the imported
//!   symbol's. `_o<ord>_` ordinal markers appear in some tails.
//! * `_MNID_<modlen>_<Module>__<explen>_<export>_<namelen>_<name>`: `a` is
//!   the module export's NID; the final length-prefixed field is the
//!   symbol name (`__start`, `__sce_moduleinfo`, ...).

use std::collections::{HashMap, HashSet};

use super::{NativeContext, NativeFunction, NativeImport};

const HEADER_SIZE: usize = 16;
const RECORD_SIZE: usize = 160;
const NAME_SIZE: usize = 152;

/// A parsed BINMAP: address records plus the NID→name table.
#[derive(Debug, Default)]
pub struct Binmap {
    /// Plain records: `(vaddr, size, name)`, deduplicated by address.
    pub symbols: Vec<(u64, u64, String)>,
    /// NID → symbol name, from `_NID_` / `_INID_` / `_MNID_` records.
    pub nid_names: HashMap<u32, String>,
}

/// The name a length-prefixed `_INID_`/`_MNID_` tail encodes: the last
/// `_<digits>_` run whose digit count equals the remaining length.
fn encoded_tail(rest: &str) -> Option<&str> {
    let bytes = rest.as_bytes();
    let mut found = None;
    for i in 0..bytes.len() {
        if bytes[i] != b'_' {
            continue;
        }
        let digits_end = bytes[i + 1..]
            .iter()
            .position(|b| !b.is_ascii_digit())
            .map(|p| i + 1 + p)
            .unwrap_or(bytes.len());
        if digits_end == i + 1 || digits_end >= bytes.len() || bytes[digits_end] != b'_' {
            continue;
        }
        let Ok(len) = rest[i + 1..digits_end].parse::<usize>() else {
            continue;
        };
        if digits_end + 1 + len == bytes.len() {
            found = Some(&rest[digits_end + 1..]);
        }
    }
    found
}

/// The symbol name a `_INID_`/`_MNID_` record carries, after its first
/// length-prefixed field (library / module name).
fn tagged_name(name: &str, prefix: &str) -> Option<String> {
    let rest = name.strip_prefix(prefix)?;
    let digits = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || rest.len() <= digits + 1 {
        return None;
    }
    let lib_len: usize = rest[..digits].parse().ok()?;
    let after_lib = rest.get(digits + 1..)?;
    if after_lib.len() < lib_len {
        return None;
    }
    encoded_tail(&after_lib[lib_len..]).map(str::to_owned)
}

/// Parse a BINMAP blob. `None` when the bytes are not this format — the
/// caller falls back to the text MAP grammars.
pub fn parse(data: &[u8]) -> Option<Binmap> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    let count = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let header_size = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    if header_size != HEADER_SIZE || count == 0 {
        return None;
    }
    if HEADER_SIZE + count.checked_mul(RECORD_SIZE)? != data.len() {
        return None;
    }
    let mut map = Binmap::default();
    let mut seen: HashSet<u64> = HashSet::new();
    for i in 0..count {
        let record = HEADER_SIZE + i * RECORD_SIZE;
        let name = data[record..record + NAME_SIZE]
            .split(|byte| *byte == 0)
            .next()
            .map(|raw| String::from_utf8_lossy(raw).into_owned())
            .unwrap_or_default();
        let a = u32::from_le_bytes(data[record + 152..record + 156].try_into().ok()?);
        let b = u32::from_le_bytes(data[record + 156..record + 160].try_into().ok()?);
        if name.is_empty() {
            continue;
        }
        if let Some(nid_name) = name.strip_prefix("_NID_") {
            map.nid_names.insert(a, nid_name.to_owned());
        } else if let Some(nid_name) = tagged_name(&name, "_INID_") {
            map.nid_names.insert(a, nid_name);
        } else if let Some(nid_name) = tagged_name(&name, "_MNID_") {
            map.nid_names.insert(a, nid_name);
        } else if !name.starts_with('_') && a != 0 && seen.insert((a & !1) as u64) {
            map.symbols.push((a as u64, b as u64, name));
        }
    }
    if map.symbols.is_empty() && map.nid_names.is_empty() {
        return None;
    }
    Some(map)
}

/// Names that mark a record as data even inside an executable mapping:
/// C++ RTTI/vtable rows the linker placed in the text segment.
fn is_data_name(name: &str) -> bool {
    name.starts_with("vtable for ")
        || name.starts_with("typeinfo for ")
        || name.starts_with("VTT for ")
        || name.starts_with("guard variable for ")
        || name.starts_with("typeinfo name for ")
}

/// The NID a seeded SCE name encodes: `sce_import_*_<nid8>` /
/// `sce_export_<nid8>` carry it as the trailing hex field, and the fixed
/// module-export names map back through the same table `sce` seeds from.
fn seeded_nid(name: &str) -> Option<u32> {
    if name.starts_with("sce_import_") || name.starts_with("sce_export_") {
        let tail = name.rsplit('_').next()?;
        return u32::from_str_radix(tail, 16).ok().filter(|_| tail.len() == 8);
    }
    super::sce::MODULE_NIDS
        .iter()
        .find(|(_, standard)| *standard == name)
        .map(|(nid, _)| *nid)
}

/// Merge BINMAP records into an import, mirroring `linkmap::apply_to_import`:
/// address records seed or rename functions inside executable mappings and
/// name objects elsewhere, and the NID table renames the `sce_import_*` /
/// `sce_export_*` placeholders the SCE parser seeded.
pub fn apply_to_import(imp: &mut NativeImport, map: &Binmap) {
    let in_code = |address: u64| {
        imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address - mapping.vaddr < mapping.size
        })
    };
    let mut entries: HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    for (address, size, name) in &map.symbols {
        let entry = address & !1;
        if in_code(entry) && !is_data_name(name) {
            if let Some(function) = imp.functions.iter_mut().find(|f| f.entry == entry) {
                function.name = name.clone();
                if *size != 0 {
                    function.size = *size;
                }
            } else if entries.insert(entry) {
                imp.functions.push(NativeFunction {
                    entry,
                    name: name.clone(),
                    size: (*size).max(1),
                });
            }
            if address & 1 != 0 {
                imp.contexts.push(NativeContext {
                    name: "TMode".into(),
                    address: entry,
                    value: 1,
                });
            }
            if !imp.symbol_named.contains(&entry) {
                imp.symbol_named.push(entry);
            }
        } else {
            if *size > 0 {
                imp.object_sizes.push((entry, *size));
            }
            imp.object_names.push((entry, name.clone()));
        }
    }
    if map.nid_names.is_empty() {
        return;
    }
    for function in &mut imp.functions {
        if let Some(name) = seeded_nid(&function.name).and_then(|nid| map.nid_names.get(&nid)) {
            function.name = name.clone();
        }
    }
    for (_, name) in imp.externals.iter_mut().filter(|(slot, _)| *slot != 0) {
        if let Some(resolved) = seeded_nid(name).and_then(|nid| map.nid_names.get(&nid)) {
            *name = resolved.clone();
        }
    }
    // Object names seeded from export NIDs resolve the same way.
    for (_, name) in imp.object_names.iter_mut() {
        if let Some(resolved) = seeded_nid(name).and_then(|nid| map.nid_names.get(&nid)) {
            *name = resolved.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, a: u32, b: u32) -> Vec<u8> {
        let mut record = vec![0u8; RECORD_SIZE];
        record[..name.len()].copy_from_slice(name.as_bytes());
        record[152..156].copy_from_slice(&a.to_le_bytes());
        record[156..160].copy_from_slice(&b.to_le_bytes());
        record
    }

    fn binmap(records: &[Vec<u8>]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(records.len() as u32).to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        for r in records {
            data.extend_from_slice(r);
        }
        data
    }

    #[test]
    fn parses_records() {
        let data = binmap(&[
            record("_NID_ldexp", 0x56061b, 0),
            record("_INID_7_SceLibm__5_ldexp", 0x56061b, 0),
            record("_MNID_12_module_start_6__start", 0x935cd196, 0xd19c5),
            record("Game::Update", 0x8100b7af, 0x160),
        ]);
        let map = parse(&data).expect("binmap");
        assert_eq!(map.nid_names.get(&0x935cd196).map(String::as_str), Some("_start"));
        assert_eq!(map.symbols, vec![(0x8100b7af, 0x160, "Game::Update".to_owned())]);
    }

    #[test]
    fn rejects_text_and_short_blobs() {
        assert!(parse(b"not a binmap").is_none());
        assert!(parse(&[]).is_none());
        // Right header, wrong length.
        assert!(parse(&binmap(&[record("x", 1, 0)])[..20]).is_none());
    }

    #[test]
    fn apply_names_functions_objects_and_nids() {
        let data = binmap(&[
            record("_NID_sceKernelWaitSema", 0x12345678, 0),
            record("thumb_fn", 0x81001001, 0x40),
            record("vtable for Widget", 0x81002000, 0x18),
            record("gCounter", 0x81800000, 4),
        ]);
        let map = parse(&data).expect("binmap");
        let mut imp = NativeImport {
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x81000000,
                    size: 0x100000,
                    file_off: 0,
                    flags: 5,
                    bytes: Vec::new(),
                },
                crate::native::Mapping {
                    vaddr: 0x81800000,
                    size: 0x1000,
                    file_off: 0,
                    flags: 3,
                    bytes: Vec::new(),
                },
            ],
            functions: vec![NativeFunction {
                entry: 0x81005000,
                name: "sce_import_SceLibc_12345678".into(),
                size: 1,
            }],
            externals: vec![(0x81005000, "sce_import_SceLibc_12345678".into())],
            ..Default::default()
        };
        apply_to_import(&mut imp, &map);
        assert!(imp.functions.iter().any(|f| f.entry == 0x81001000 && f.name == "thumb_fn"));
        assert!(imp.functions.iter().any(|f| f.entry == 0x81005000 && f.name == "sceKernelWaitSema"));
        assert!(imp.externals.iter().any(|(_, n)| n == "sceKernelWaitSema"));
        assert!(imp.object_names.iter().any(|(a, n)| *a == 0x81002000 && n == "vtable for Widget"));
        assert!(imp.object_names.iter().any(|(a, n)| *a == 0x81800000 && n == "gCounter"));
        assert!(imp.contexts.iter().any(|c| c.address == 0x81001000 && c.value == 1));
    }
}
