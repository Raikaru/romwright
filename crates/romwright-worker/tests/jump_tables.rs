use romwright_model::{Address, AddressSpace};
use romwright_worker::doc::decode_document_with_ram_space;
use romwright_worker::wire::{
    ELEMENT_END, ELEMENT_START, attr_type, elem, encode_attribute, encode_header,
};

// Pinned funcdata.cc and jumptable.cc element tables; marshal.cc attributes.
const TABLES: u32 = 118;
const TABLE: u32 = 213;
const DEST: u32 = 212;

fn address(out: &mut Vec<u8>, element: u32, space: u64, offset: Option<u64>) {
    encode_header(out, ELEMENT_START, element);
    encode_attribute(out, 20, attr_type::SPACE, space);
    if let Some(offset) = offset {
        encode_attribute(out, 16, attr_type::UNSIGNED_INT, offset);
    }
    encode_header(out, ELEMENT_END, element);
}

fn document(targets: Option<&[(u64, Option<u64>)]>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header(&mut out, ELEMENT_START, elem::DOC);
    encode_header(&mut out, ELEMENT_START, elem::FUNCTION);
    address(&mut out, elem::ADDR, 3, Some(0x1_0000_0000));
    if let Some(targets) = targets {
        encode_header(&mut out, ELEMENT_START, TABLES);
        encode_header(&mut out, ELEMENT_START, TABLE);
        address(&mut out, elem::ADDR, 3, Some(0x1_0000_0010));
        for &(space, offset) in targets {
            address(&mut out, DEST, space, offset);
        }
        encode_header(&mut out, ELEMENT_END, TABLE);
        encode_header(&mut out, ELEMENT_END, TABLES);
    }
    encode_header(&mut out, ELEMENT_END, elem::FUNCTION);
    // C markup also uses FUNCTION. It must not replace the structural result.
    encode_header(&mut out, ELEMENT_START, elem::FUNCTION);
    encode_header(&mut out, ELEMENT_END, elem::FUNCTION);
    encode_header(&mut out, ELEMENT_END, elem::DOC);
    out
}

#[test]
fn switch_targets_preserve_order_duplicates_and_address_spaces() {
    let packed = document(Some(&[
        (3, Some(0x1_0000_0090)),
        (4, Some(0x40)),
        (3, Some(0x1_0000_0090)),
        (3, Some(0x1_0000_0020)),
    ]));
    let recovered = decode_document_with_ram_space(&packed, Some(3))
        .jump_tables
        .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].branch, Address::ram(0x1_0000_0010));
    assert_eq!(
        recovered[0].targets,
        vec![
            Address::ram(0x1_0000_0090),
            Address {
                space: AddressSpace::Other("space:4".into()),
                offset: 0x40
            },
            Address::ram(0x1_0000_0090),
            Address::ram(0x1_0000_0020),
        ]
    );
}

#[test]
fn absent_tables_are_distinct_from_unavailable_or_incomplete_metadata() {
    assert_eq!(
        decode_document_with_ram_space(&document(None), Some(3)).jump_tables,
        Some(vec![])
    );
    assert!(
        decode_document_with_ram_space(&[], Some(3))
            .jump_tables
            .is_none()
    );
    let packed = document(Some(&[(3, Some(0x1_0000_0090))]));
    for end in 0..packed.len() {
        assert!(
            decode_document_with_ram_space(&packed[..end], Some(3))
                .jump_tables
                .is_none(),
            "published partial metadata at byte {end}"
        );
    }
    let missing_offset = document(Some(&[(3, None)]));
    assert!(
        decode_document_with_ram_space(&missing_offset, Some(3))
            .jump_tables
            .is_none()
    );
}

/// One table whose destinations carry case labels (`None`: no label).
fn labelled_document(dests: &[(u64, Option<u64>)]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header(&mut out, ELEMENT_START, elem::DOC);
    encode_header(&mut out, ELEMENT_START, elem::FUNCTION);
    address(&mut out, elem::ADDR, 3, Some(0x1000));
    encode_header(&mut out, ELEMENT_START, TABLES);
    encode_header(&mut out, ELEMENT_START, TABLE);
    address(&mut out, elem::ADDR, 3, Some(0x1010));
    for &(offset, label) in dests {
        encode_header(&mut out, ELEMENT_START, DEST);
        encode_attribute(&mut out, 20, attr_type::SPACE, 3);
        encode_attribute(&mut out, 16, attr_type::UNSIGNED_INT, offset);
        if let Some(label) = label {
            encode_attribute(&mut out, 131, attr_type::UNSIGNED_INT, label);
        }
        encode_header(&mut out, ELEMENT_END, DEST);
    }
    encode_header(&mut out, ELEMENT_END, TABLE);
    encode_header(&mut out, ELEMENT_END, TABLES);
    encode_header(&mut out, ELEMENT_END, elem::FUNCTION);
    encode_header(&mut out, ELEMENT_END, elem::DOC);
    out
}

/// Ghidra appends a folded guard's target last, without a case label; the
/// indirect branch never goes there, so it is not a target.
#[test]
fn a_folded_default_is_not_a_switch_target() {
    let targets = |dests: &[(u64, Option<u64>)]| {
        decode_document_with_ram_space(&labelled_document(dests), Some(3)).jump_tables.unwrap()[0]
            .targets
            .iter()
            .map(|target| target.offset)
            .collect::<Vec<_>>()
    };
    assert_eq!(targets(&[(0x1100, Some(0)), (0x1200, Some(1)), (0x1700, None)]), vec![0x1100, 0x1200]);
    // A table recovered without labels keeps every entry.
    assert_eq!(targets(&[(0x1100, None), (0x1200, None)]), vec![0x1100, 0x1200]);
}

/// A printed table says how the import's stored table related to what
/// `jumptable.cc` recovered (`JumpTable::encode`'s `storedout`, `stocksize`,
/// `storedsize`, `commonsize`).
#[test]
fn switch_sources_report_the_stored_table_relation() {
    let table = |extra: Option<(u64, i64, u64, u64)>| {
        let mut out = Vec::new();
        encode_header(&mut out, ELEMENT_START, elem::DOC);
        encode_header(&mut out, ELEMENT_START, elem::FUNCTION);
        address(&mut out, elem::ADDR, 3, Some(0x1000));
        encode_header(&mut out, ELEMENT_START, TABLES);
        encode_header(&mut out, ELEMENT_START, TABLE);
        if let Some((state, stock, stored, common)) = extra {
            encode_attribute(&mut out, 401, attr_type::UNSIGNED_INT, state);
            if stock >= 0 {
                encode_attribute(&mut out, 402, attr_type::POSITIVE_INT, stock as u64);
            } else {
                // writeSignedInteger(-1): negative type, magnitude 1.
                encode_attribute(&mut out, 402, attr_type::NEGATIVE_INT, 1);
            }
            encode_attribute(&mut out, 403, attr_type::UNSIGNED_INT, stored);
            encode_attribute(&mut out, 404, attr_type::UNSIGNED_INT, common);
        }
        address(&mut out, elem::ADDR, 3, Some(0x1010));
        address(&mut out, DEST, 3, Some(0x1100));
        address(&mut out, DEST, 3, Some(0x1200));
        encode_header(&mut out, ELEMENT_END, TABLE);
        encode_header(&mut out, ELEMENT_END, TABLES);
        encode_header(&mut out, ELEMENT_END, elem::FUNCTION);
        encode_header(&mut out, ELEMENT_END, elem::DOC);
        decode_document_with_ram_space(&out, Some(3)).switch_sources
    };
    let none = table(None);
    assert_eq!((none[0].branch, none[0].state, none[0].stock), (0x1010, "none", None));
    let confirmed = table(Some((1, 2, 2, 2)));
    assert_eq!((confirmed[0].state, confirmed[0].stock, confirmed[0].common), ("confirmed", Some(2), 2));
    let applied = table(Some((2, 3, 2, 2)));
    assert_eq!((applied[0].state, applied[0].stock, applied[0].stored), ("applied", Some(3), 2));
    let failed = table(Some((2, -1, 2, 0)));
    assert_eq!((failed[0].state, failed[0].stock), ("applied", None));
    assert_eq!(table(Some((3, 1, 2, 1)))[0].state, "observed");
}
