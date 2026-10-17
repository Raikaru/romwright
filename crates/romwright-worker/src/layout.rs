//! Global symbol layout (docs/types-port.md, section 13): what a data object is made of, from the facts the importer stores.
//!
//! The importer stores two kinds of facts about data: the *objects* an ELF symbol declares (`native-import:elf-object`, a name
//! and a size) and the *widths* of the accesses the constant propagation resolved (`native-analysis:data-width`, one row per
//! accessed address). The decompiler asks for a symbol by address, and the provider answers from those rows. Read as they
//! stand they disagree about every array:
//!
//! * a `lw` at `key_now + 8` is a row of its own, so the decompiler asks for it, gets an address-named `undefined4` symbol
//!   that lies inside `key_now`, and prints two names for one object (`key_now._4_4_`, `DAT_00252750._4_4_`) according to
//!   which address it asked first (the symbol it already has wins);
//! * an object wider than a word is an array of `undefined1`, whatever the accesses to it say, so every word read prints as a
//!   member (`_8_4_`) of a byte array.
//!
//! One decision per object, from the accesses inside it (the rows at addresses after its start; the access at the start is
//! not stored): the element `W` that most of them are exactly one of, no wider than the narrowest access, and a divisor of the
//! object's size. An object that most accesses fit (an object of bytes included) becomes an array of `undefinedW` and its
//! interior access rows are evidence, not symbols; the accesses that are wider or unaligned print as pieces of the whole
//! array (`_8_8_`), which the export layer already spells. An object with no accesses in it, one that is a string or a function
//! (the symbol of a function entry is the function's: an object row there would give a second symbol the same name), one whose
//! address is taken (a pointer to it is typed by the elements it was read as, and the decompiler would have to cast it) and
//! one most accesses do not fit, and one of which fewer than half of the elements are touched (a table of structures read
//! at a few of its fields, which the code walks by an index the rows do not show), keeps what it was. Off with `ROMWRIGHT_NATIVE_LAYOUT=1` (every rule) or
//! `ROMWRIGHT_LAYOUT_<RULE>=off`:
//!
//! * `ELEMENTS`: the retyping (`undefined4[]` for `undefined1[]`, and an array of narrow elements for an `undefined8` object
//!   only ever accessed narrower);
//! * `CONTAIN`: the interior access rows of a retyped object are dropped (an address inside it is the object).
use std::collections::BTreeMap;

pub const OBJECT_SOURCE: &str = "native-import:elf-object";
pub const WIDTH_SOURCE: &str = "native-analysis:data-width";

pub const CONTAIN: &str = "ROMWRIGHT_LAYOUT_CONTAIN";
pub const ELEMENTS: &str = "ROMWRIGHT_LAYOUT_ELEMENTS";
/// `ROMWRIGHT_LAYOUT_DENSITY=N`: an object becomes an array only when at least 1/N of its elements are touched (default 2; 0 = no test).
pub const DENSITY: &str = "ROMWRIGHT_LAYOUT_DENSITY";

fn density() -> u64 {
    std::env::var(DENSITY).ok().and_then(|value| value.parse().ok()).unwrap_or(2)
}

/// Whether a layout rule is on: `ROMWRIGHT_NATIVE_LAYOUT=1` turns every rule off, `<switch>=off` the one.
pub fn enabled(switch: &str) -> bool {
    !std::env::var("ROMWRIGHT_NATIVE_LAYOUT").is_ok_and(|mode| mode == "1")
        && std::env::var(switch).map_or(true, |mode| mode != "off")
}

/// One stored data definition: `(address, type, width or object size, source)`.
pub type Definition = (u64, String, u64, String);

/// The element type name of an array definition (`undefined4[]` is 4), `undefined1[]` for the importer's own spelling.
pub fn element_width(kind: &str) -> Option<u64> {
    let width = kind.strip_prefix("undefined")?.strip_suffix("[]")?;
    width.parse().ok().filter(|width| matches!(width, 1 | 2 | 4 | 8))
}

/// The element width that leaves the fewest accesses to print as a piece of the array: the accesses that are not one
/// element at an element boundary. No element is wider than the narrowest access (an access inside an element prints as
/// a member of it, which C has no spelling for). Narrower elements win a tie: a wide access is the same bytes as several
/// narrow ones, not the reverse.
fn fit(size: u64, accesses: &[(u64, u64)]) -> (u64, usize) {
    let narrowest = accesses.iter().map(|(_, access)| *access).min().unwrap_or(1);
    let mut best = (1, accesses.iter().filter(|(_, access)| *access != 1).count());
    for width in [2, 4, 8] {
        if width <= narrowest && size.is_multiple_of(width) {
            let misfits = accesses.iter().filter(|(offset, access)| *access != width || offset % width != 0).count();
            if misfits < best.1 {
                best = (width, misfits);
            }
        }
    }
    best
}

/// The element an object's accesses make it, when they make it an array: `Some(W)` for an object of `size` bytes where
/// at least half of the accesses are one `W`-byte element, with `W` narrower than the object.
fn element(size: u64, accesses: &[(u64, u64)], density: u64) -> Option<u64> {
    if accesses.is_empty() {
        return None;
    }
    let (width, misfits) = fit(size, accesses);
    if width >= size || misfits * 2 > accesses.len() {
        return None;
    }
    // An object walked by an index the constant accesses do not show (a table of structures read at three of its fields) has
    // few of its elements touched; one that is only ever read at constant indexes has most. The first element counts as touched:
    // the object's own address is where the access that is not stored is.
    let mut touched: Vec<u64> = accesses.iter().map(|(offset, _)| offset / width).chain([0]).collect();
    touched.sort_unstable();
    touched.dedup();
    (density == 0 || touched.len() as u64 * density >= size / width).then_some(width)
}

/// The data definitions the provider answers from, given the importer's.
pub fn globals(
    mut rows: Vec<Definition>,
    not_data: impl Fn(u64) -> bool,
    address_taken: impl Fn(u64, u64) -> bool,
) -> BTreeMap<u64, (String, u64)> {
    let contain = enabled(CONTAIN);
    let elements = enabled(ELEMENTS);
    let density = density();
    if !contain && !elements {
        return rows.into_iter().map(|(address, kind, size, _)| (address, (kind, size))).collect();
    }
    rows.sort_by_key(|row| row.0);
    // The outermost ELF objects, by start: an object inside another is the other's business.
    let mut objects: Vec<(u64, u64)> = Vec::new(); // (start, end)
    for (address, kind, size, source) in &rows {
        let object = source == OBJECT_SOURCE
            && *size > 0
            && (kind == "undefined1[]" || kind == "undefined")
            && !not_data(*address)
            && !address_taken(*address, address + size);
        if object && objects.last().is_none_or(|(_, end)| address >= end) {
            objects.push((*address, address + size));
        }
    }
    let mut accesses: Vec<Vec<(u64, u64)>> = vec![Vec::new(); objects.len()];
    let inside = |address: u64| {
        let at = objects.partition_point(|(start, _)| *start <= address).checked_sub(1)?;
        (address > objects[at].0 && address < objects[at].1).then_some(at)
    };
    for (address, _, size, source) in &rows {
        if source == WIDTH_SOURCE
            && let Some(at) = inside(*address)
            && address + size <= objects[at].1
        {
            accesses[at].push((address - objects[at].0, *size));
        }
    }
    let arrays: Vec<Option<u64>> = objects
        .iter()
        .zip(&accesses)
        .map(|((start, end), accesses)| element(end - start, accesses, density))
        .collect();
    let mut kept: BTreeMap<u64, (String, u64)> = BTreeMap::new();
    for (address, kind, size, source) in rows {
        if source == WIDTH_SOURCE
            && let Some(at) = inside(address)
            && arrays[at].is_some()
            && address + size <= objects[at].1
            && contain
        {
            continue;
        }
        kept.insert(address, (kind, size));
    }
    if elements {
        for ((start, end), array) in objects.iter().zip(&arrays) {
            if let Some(width) = array {
                kept.insert(*start, (format!("undefined{width}[]"), end - start));
            }
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn globals_of(rows: Vec<Definition>) -> BTreeMap<u64, (String, u64)> {
        globals(rows, |_| false, |_, _| false)
    }

    fn object(address: u64, size: u64) -> Definition {
        let kind = if size > 8 { "undefined1[]" } else { "undefined" };
        (address, kind.into(), size, OBJECT_SOURCE.into())
    }

    fn width(address: u64, size: u64) -> Definition {
        (address, "undefined".into(), size, WIDTH_SOURCE.into())
    }

    #[test]
    fn element_width_reads_the_array_spelling() {
        assert_eq!(element_width("undefined1[]"), Some(1));
        assert_eq!(element_width("undefined4[]"), Some(4));
        assert_eq!(element_width("undefined"), None);
        assert_eq!(element_width("undefined3[]"), None);
    }

    #[test]
    fn an_object_takes_the_widest_element_its_accesses_fit() {
        let layout = globals_of(vec![object(0x100, 32), width(0x104, 4), width(0x108, 8), width(0x10c, 4), width(0x110, 8)]);
        assert_eq!(layout.get(&0x100), Some(&("undefined4[]".to_string(), 32)));
        assert_eq!(layout.len(), 1, "the accesses are evidence, not symbols");
    }

    #[test]
    fn an_object_of_bytes_stays_an_array_of_bytes_and_absorbs_its_accesses() {
        let layout = globals_of(vec![object(0x100, 8), width(0x101, 1), width(0x103, 1), width(0x105, 1), width(0x107, 1)]);
        assert_eq!(layout.get(&0x100), Some(&("undefined1[]".to_string(), 8)));
        assert_eq!(layout.len(), 1);
    }

    #[test]
    fn no_element_is_wider_than_the_narrowest_access() {
        // three words and three halfwords: elements of two bytes, the words are pieces of the array
        let rows = vec![object(0x100, 24), width(0x104, 4), width(0x108, 4), width(0x10c, 4), width(0x112, 2), width(0x114, 2), width(0x116, 2)];
        let layout = globals_of(rows);
        assert_eq!(layout.get(&0x100), Some(&("undefined2[]".to_string(), 24)));
        assert_eq!(layout.len(), 1);
        // mostly words and a halfword: the words are not pieces of an array of halfwords
        assert_eq!(element(64, &[(4, 4), (8, 4), (12, 4), (14, 4), (34, 2)], 0), None);
        assert_eq!(element(64, &[(4, 4), (8, 4), (12, 4)], 0), Some(4));
    }

    #[test]
    fn a_split_object_is_left_as_it_was() {
        let rows = vec![object(0x100, 32), width(0x104, 4), width(0x109, 1), width(0x10c, 8), width(0x112, 2)];
        let layout = globals_of(rows);
        assert_eq!(layout.len(), 5);
        assert_eq!(layout.get(&0x100), Some(&("undefined1[]".to_string(), 32)));
    }

    #[test]
    fn a_string_or_a_function_is_not_an_object_to_retype() {
        let rows = vec![object(0x100, 32), width(0x104, 4), width(0x108, 4)];
        assert_eq!(globals(rows, |address| address == 0x100, |_, _| false).len(), 3);
    }

    #[test]
    fn an_object_with_no_access_evidence_is_unchanged() {
        assert_eq!(globals_of(vec![object(0x100, 16)]).get(&0x100), Some(&("undefined1[]".to_string(), 16)));
    }

    #[test]
    fn a_small_object_with_only_narrow_accesses_is_an_array_of_them() {
        let layout = globals_of(vec![object(0x100, 8), width(0x101, 1), width(0x102, 1), width(0x103, 1)]);
        assert_eq!(layout.get(&0x100), Some(&("undefined1[]".to_string(), 8)));
        // an access as wide as the object makes no array
        let whole = globals_of(vec![object(0x100, 4), width(0x102, 2)]);
        assert_eq!(whole.get(&0x100), Some(&("undefined2[]".to_string(), 4)));
        let same = globals_of(vec![object(0x100, 4), width(0x100, 4)]);
        assert_eq!(same.get(&0x100), Some(&("undefined".to_string(), 4)));
    }

    #[test]
    fn the_element_needs_the_accesses_to_fit_it() {
        assert_eq!(element(32, &[(4, 4), (8, 8), (12, 4)], 2), Some(4));
        assert_eq!(element(32, &[(4, 4), (9, 1)], 0), Some(1)); // a tie: the narrower element
        assert_eq!(element(32, &[(4, 4), (9, 1), (10, 2), (14, 8)], 0), None);
        assert_eq!(element(32, &[(1, 1), (2, 1), (4, 4)], 0), Some(1));
        assert_eq!(element(8, &[(0, 8)], 2), None);
    }

    #[test]
    fn a_table_read_at_a_few_of_its_fields_is_not_an_array_of_them() {
        // 60 bytes, two words at 48 and 52: the code walks it by an index (five structures of 12 bytes)
        assert_eq!(element(60, &[(48, 4), (52, 4)], 2), None);
        assert_eq!(element(60, &[(48, 4), (52, 4)], 0), Some(4));
        // sixteen bytes read at three of four words, the first one at the object's address
        assert_eq!(element(16, &[(4, 4), (8, 4), (12, 4)], 2), Some(4));
        assert_eq!(globals_of(vec![object(0x100, 60), width(0x130, 4), width(0x134, 4)]).len(), 3);
    }
}
