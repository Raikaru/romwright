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
