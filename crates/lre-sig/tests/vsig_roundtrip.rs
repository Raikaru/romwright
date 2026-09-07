//! m2-010 acceptance: a `.vsig` database survives a byte-stable round trip and
//! rejects every non-canonical or ill-formed encoding.
use lre_sig::{Signature, SignatureDb, VsigError};

/// `printf` prologue with a relocated 4-byte displacement masked out.
fn masked() -> Signature {
    Signature::new(
        "x86:LE:64:default",
        "printf",
        "glibc-2.39-1",
        "LGPL-2.1-or-later",
        &[0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x8b, 0x05, 0xde, 0xad, 0xbe, 0xef, 0xc3],
        &[0xff; 12].iter().copied().enumerate()
            .map(|(index, byte)| if (7..11).contains(&index) { 0 } else { byte })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn plain(name: &str, language: &str) -> Signature {
    Signature::new(
        language,
        name,
        "musl-1.2.5",
        "MIT",
        &[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3],
        &[0xff; 8],
    )
    .unwrap()
}

fn db() -> SignatureDb {
    SignatureDb::from_signatures([
        plain("strlen", "x86:LE:64:default"),
        masked(),
        plain("strlen", "AARCH64:LE:64:v8A"),
    ])
    .unwrap()
}

/// Assemble a file from record payloads in the given order, using the header
/// layout `docs/vsig.md` documents. Only a canonical order may decode.
fn file(records: &[Signature]) -> Vec<u8> {
    let payload: Vec<u8> = records
        .iter()
        .flat_map(|record| {
            let single = SignatureDb::from_signatures([record.clone()]).unwrap().encode();
            single[16..].to_vec()
        })
        .collect();
    let mut bytes = b"VSIG".to_vec();
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend((records.len() as u32).to_le_bytes());
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend(payload);
    bytes
}

#[test]
fn database_round_trips_byte_for_byte_in_canonical_order() {
    let original = db();
    let encoded = original.encode();
    let decoded = SignatureDb::decode(&encoded).unwrap();
    assert_eq!(decoded.signatures(), original.signatures());
    assert_eq!(decoded.encode(), encoded, "canonical form must be stable");
    // Canonical order is (language, name, package), independent of input order.
    let names: Vec<_> = decoded
        .signatures()
        .iter()
        .map(|signature| (signature.language.as_str(), signature.name.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("AARCH64:LE:64:v8A", "strlen"),
            ("x86:LE:64:default", "printf"),
            ("x86:LE:64:default", "strlen"),
        ]
    );
    // Masked bytes carry no information: the pattern stores zero under them.
    let printf = decoded
        .signatures()
        .iter()
        .find(|signature| signature.name == "printf")
        .unwrap();
    assert_eq!(&printf.pattern[7..11], &[0, 0, 0, 0]);
    assert_eq!(printf.license, "LGPL-2.1-or-later");
    assert_eq!(printf.package, "glibc-2.39-1");
}

#[test]
fn masks_decide_which_bytes_are_compared() {
    let printf = masked();
    let mut bytes = vec![
        0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44, 0xc3, 0x90,
    ];
    assert!(printf.matches(&bytes), "a relocated displacement is ignored");
    bytes[4] = 0x49;
    assert!(!printf.matches(&bytes), "an unmasked byte must compare");
    assert!(!printf.matches(&bytes[..8]), "a short window cannot match");
}

#[test]
fn construction_rejects_unusable_signatures() {
    let cases: Vec<(&str, &str, &str, &str, Vec<u8>, Vec<u8>)> = vec![
        ("x86:LE:64:default", "", "p", "MIT", vec![0x90], vec![0xff]),
        ("", "n", "p", "MIT", vec![0x90], vec![0xff]),
        ("x86:LE:64:default", "n", "", "MIT", vec![0x90], vec![0xff]),
        ("x86:LE:64:default", "n", "p", "", vec![0x90], vec![0xff]),
        ("x86:LE:64:default", "n\0x", "p", "MIT", vec![0x90], vec![0xff]),
        ("x86:LE:64:default", "n", "p", "MIT", vec![], vec![]),
        ("x86:LE:64:default", "n", "p", "MIT", vec![0x90], vec![0xff, 0xff]),
        ("x86:LE:64:default", "n", "p", "MIT", vec![0x90], vec![0x0f]),
        ("x86:LE:64:default", "n", "p", "MIT", vec![0x90, 0x90], vec![0, 0]),
    ];
    for (language, name, package, license, pattern, mask) in cases {
        assert!(
            Signature::new(language, name, package, license, &pattern, &mask).is_err(),
            "accepted {language}/{name}/{package}/{license} {pattern:?} {mask:?}"
        );
    }
    assert!(matches!(
        SignatureDb::from_signatures([masked(), masked()]),
        Err(VsigError::Duplicate { .. })
    ));
}

#[test]
fn decoding_rejects_corrupt_and_non_canonical_files() {
    let encoded = db().encode();
    assert!(matches!(
        SignatureDb::decode(&encoded[..encoded.len() - 1]),
        Err(VsigError::Truncated { .. })
    ));
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        SignatureDb::decode(&trailing),
        Err(VsigError::TrailingBytes { .. })
    ));
    let mut magic = encoded.clone();
    magic[1] = b'X';
    assert!(matches!(
        SignatureDb::decode(&magic),
        Err(VsigError::BadMagic)
    ));
    let mut version = encoded.clone();
    version[4] = 2;
    assert!(matches!(
        SignatureDb::decode(&version),
        Err(VsigError::UnsupportedVersion(2))
    ));
    let mut flags = encoded.clone();
    flags[6] = 1;
    assert!(matches!(
        SignatureDb::decode(&flags),
        Err(VsigError::ReservedFlags(1))
    ));
    let mut count = encoded.clone();
    count[8] = 9;
    assert!(SignatureDb::decode(&count).is_err());
    let mut records = SignatureDb::decode(&encoded).unwrap().signatures().to_vec();
    assert_eq!(file(&records), encoded, "the documented header must be exact");
    records.reverse();
    assert!(
        matches!(
            SignatureDb::decode(&file(&records)),
            Err(VsigError::NotCanonical { .. })
        ),
        "a decoder must reject records that are not in canonical order"
    );
    assert!(SignatureDb::decode(&[]).is_err());
}
