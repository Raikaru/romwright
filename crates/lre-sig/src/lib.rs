//! Relocation-masked function signatures and their on-disk database.
//!
//! `.vsig` is Ventris' own container (see `docs/vsig.md`): a byte pattern, a
//! per-byte compare mask that hides relocated operands, and the provenance a
//! clean-room project needs — the language the bytes decode in, the function
//! name, the package the bytes came from, and that package's license.
//!
//! Files are canonical: records are sorted, duplicates rejected, and masked
//! pattern bytes stored as zero, so `encode(decode(bytes)) == bytes` holds for
//! every file this crate accepts. Integrity of a published database is the
//! outer artifact manifest's job; the container carries no checksum.
#![forbid(unsafe_code)]

pub mod archive;
pub mod build;
pub mod matcher;
pub mod object;

pub use archive::{ArchiveError, Member};
pub use build::{BuildError, BuildReport, from_archive};
pub use matcher::{MatchIndex, Outcome};
pub use object::{Extracted, Object, ObjectError, SkipReason, Skipped};

pub const MAGIC: &[u8; 4] = b"VSIG";
pub const VERSION: u16 = 1;
/// Header: magic, version, flags, record count, payload length.
pub const HEADER_LEN: usize = 16;
/// A record's four length fields plus its pattern length.
const RECORD_HEADER_LEN: usize = 12;
/// Per-record ceiling: a signature is a function prologue, not an image.
pub const MAX_PATTERN: usize = 64 * 1024;

/// Every rejection is a fact about the input, never a silent repair.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VsigError {
    #[error("{field} is empty")]
    EmptyField { field: &'static str },
    #[error("{field} contains a control character or NUL")]
    UnprintableField { field: &'static str },
    #[error("{field} is longer than {max} bytes")]
    FieldTooLong { field: &'static str, max: usize },
    #[error("pattern is empty")]
    EmptyPattern,
    #[error("pattern is {pattern} bytes but the mask is {mask}")]
    MaskLength { pattern: usize, mask: usize },
    #[error("mask byte {index} is {byte:#04x}; only 0x00 and 0xff exist")]
    MaskByte { index: usize, byte: u8 },
    #[error("pattern byte {index} is masked but not zero")]
    MaskedPatternByte { index: usize },
    #[error("pattern of {length} bytes compares nothing")]
    FullyMasked { length: usize },
    #[error("pattern is {length} bytes; the limit is {MAX_PATTERN}")]
    PatternTooLong { length: usize },
    #[error("duplicate signature {language} {name} from {package}")]
    Duplicate {
        language: String,
        name: String,
        package: String,
    },
    #[error("expected magic {MAGIC:?}")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("reserved header flags {0:#06x} must be zero")]
    ReservedFlags(u16),
    #[error("needed {needed} bytes at offset {offset}, found {found}")]
    Truncated {
        offset: usize,
        needed: usize,
        found: usize,
    },
    #[error("header declares {declared} payload bytes; {records} records span {actual}")]
    PayloadLength {
        declared: usize,
        actual: usize,
        records: usize,
    },
    #[error("{count} bytes follow the {records}-record payload")]
    TrailingBytes { count: usize, records: usize },
    #[error("record {index} is not after its predecessor")]
    NotCanonical { index: usize },
    #[error("{field} is not UTF-8")]
    NotUtf8 { field: &'static str },
}

type Result<T> = std::result::Result<T, VsigError>;

fn field(value: &str, name: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(VsigError::EmptyField { field: name });
    }
    if value.len() > u16::MAX as usize {
        return Err(VsigError::FieldTooLong {
            field: name,
            max: u16::MAX as usize,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(VsigError::UnprintableField { field: name });
    }
    Ok(())
}

/// One function's masked byte pattern with the provenance that licenses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Ghidra language id the pattern decodes in, e.g. `x86:LE:64:default`.
    pub language: String,
    pub name: String,
    /// Exact package build the bytes were extracted from.
    pub package: String,
    /// That package's license, as an SPDX expression.
    pub license: String,
    /// Pattern bytes; masked positions are stored as zero.
    pub pattern: Vec<u8>,
    /// `0xff` compares the pattern byte, `0x00` ignores it.
    pub mask: Vec<u8>,
}

impl Signature {
    /// Validates provenance and mask shape, then normalizes masked pattern
    /// bytes to zero so equal signatures encode identically.
    pub fn new(
        language: &str,
        name: &str,
        package: &str,
        license: &str,
        pattern: &[u8],
        mask: &[u8],
    ) -> Result<Self> {
        field(language, "language")?;
        field(name, "name")?;
        field(package, "package")?;
        field(license, "license")?;
        if pattern.is_empty() {
            return Err(VsigError::EmptyPattern);
        }
        if pattern.len() > MAX_PATTERN {
            return Err(VsigError::PatternTooLong {
                length: pattern.len(),
            });
        }
        if pattern.len() != mask.len() {
            return Err(VsigError::MaskLength {
                pattern: pattern.len(),
                mask: mask.len(),
            });
        }
        let mut compared = 0usize;
        for (index, &byte) in mask.iter().enumerate() {
            match byte {
                0xff => compared += 1,
                0x00 => {}
                byte => return Err(VsigError::MaskByte { index, byte }),
            }
        }
        if compared == 0 {
            return Err(VsigError::FullyMasked {
                length: pattern.len(),
            });
        }
        let pattern = pattern
            .iter()
            .zip(mask)
            .map(|(&byte, &keep)| if keep == 0 { 0 } else { byte })
            .collect();
        Ok(Self {
            language: language.to_string(),
            name: name.to_string(),
            package: package.to_string(),
            license: license.to_string(),
            pattern,
            mask: mask.to_vec(),
        })
    }

    /// True when `bytes` starts with this pattern at every compared position.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() >= self.pattern.len()
            && self
                .pattern
                .iter()
                .zip(&self.mask)
                .zip(bytes)
                .all(|((&byte, &keep), &actual)| keep == 0 || byte == actual)
    }

    /// Number of compared bytes: a generator's usable evidence.
    pub fn compared_bytes(&self) -> usize {
        self.mask.iter().filter(|&&keep| keep != 0).count()
    }

    fn key(&self) -> (&str, &str, &str) {
        (&self.language, &self.name, &self.package)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend((self.language.len() as u16).to_le_bytes());
        out.extend((self.name.len() as u16).to_le_bytes());
        out.extend((self.package.len() as u16).to_le_bytes());
        out.extend((self.license.len() as u16).to_le_bytes());
        out.extend((self.pattern.len() as u32).to_le_bytes());
        out.extend(self.language.as_bytes());
        out.extend(self.name.as_bytes());
        out.extend(self.package.as_bytes());
        out.extend(self.license.as_bytes());
        out.extend(&self.pattern);
        out.extend(&self.mask);
    }

    fn encoded_len(&self) -> usize {
        RECORD_HEADER_LEN
            + self.language.len()
            + self.name.len()
            + self.package.len()
            + self.license.len()
            + 2 * self.pattern.len()
    }
}

/// A canonical, duplicate-free signature set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignatureDb {
    signatures: Vec<Signature>,
}

impl SignatureDb {
    /// Orders records canonically and rejects a repeated
    /// (language, name, package) key, whose byte patterns would conflict.
    pub fn from_signatures(signatures: impl IntoIterator<Item = Signature>) -> Result<Self> {
        let mut signatures: Vec<_> = signatures.into_iter().collect();
        signatures.sort_by(|left, right| left.key().cmp(&right.key()));
        if let Some(pair) = signatures.windows(2).find(|pair| pair[0].key() == pair[1].key()) {
            return Err(VsigError::Duplicate {
                language: pair[0].language.clone(),
                name: pair[0].name.clone(),
                package: pair[0].package.clone(),
            });
        }
        Ok(Self { signatures })
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload: usize = self
            .signatures
            .iter()
            .map(|signature| signature.encoded_len())
            .sum();
        let mut out = Vec::with_capacity(HEADER_LEN + payload);
        out.extend(MAGIC);
        out.extend(VERSION.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend((self.signatures.len() as u32).to_le_bytes());
        out.extend((payload as u32).to_le_bytes());
        for signature in &self.signatures {
            signature.encode_into(&mut out);
        }
        out
    }

    /// Accepts only canonical files: correct header, exact payload length, no
    /// trailing bytes, ascending keys and normalized masks.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader {
            bytes,
            offset: 0,
        };
        if reader.take(4)? != MAGIC {
            return Err(VsigError::BadMagic);
        }
        let version = reader.u16()?;
        if version != VERSION {
            return Err(VsigError::UnsupportedVersion(version));
        }
        let flags = reader.u16()?;
        if flags != 0 {
            return Err(VsigError::ReservedFlags(flags));
        }
        let count = reader.u32()? as usize;
        let payload = reader.u32()? as usize;
        let mut signatures = Vec::with_capacity(count.min(1024));
        for index in 0..count {
            let language_len = reader.u16()? as usize;
            let name_len = reader.u16()? as usize;
            let package_len = reader.u16()? as usize;
            let license_len = reader.u16()? as usize;
            let pattern_len = reader.u32()? as usize;
            if pattern_len > MAX_PATTERN {
                return Err(VsigError::PatternTooLong {
                    length: pattern_len,
                });
            }
            let language = reader.text(language_len, "language")?;
            let name = reader.text(name_len, "name")?;
            let package = reader.text(package_len, "package")?;
            let license = reader.text(license_len, "license")?;
            let pattern = reader.take(pattern_len)?.to_vec();
            let mask = reader.take(pattern_len)?.to_vec();
            let signature =
                Signature::new(&language, &name, &package, &license, &pattern, &mask)?;
            // Normalization is part of the format, so a stored pattern that
            // needed repair was not canonical.
            if signature.pattern != pattern {
                let position = pattern
                    .iter()
                    .zip(&mask)
                    .position(|(&byte, &keep)| keep == 0 && byte != 0)
                    .unwrap_or(0);
                return Err(VsigError::MaskedPatternByte { index: position });
            }
            if signatures
                .last()
                .is_some_and(|previous: &Signature| previous.key() >= signature.key())
            {
                return Err(VsigError::NotCanonical { index });
            }
            signatures.push(signature);
        }
        if reader.offset != HEADER_LEN + payload {
            return Err(VsigError::PayloadLength {
                declared: payload,
                actual: reader.offset - HEADER_LEN,
                records: count,
            });
        }
        if reader.offset != bytes.len() {
            return Err(VsigError::TrailingBytes {
                count: bytes.len() - reader.offset,
                records: count,
            });
        }
        Ok(Self { signatures })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, needed: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(needed)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(VsigError::Truncated {
                offset: self.offset,
                needed,
                found: self.bytes.len().saturating_sub(self.offset),
            })?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("two bytes")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    fn text(&mut self, len: usize, name: &'static str) -> Result<String> {
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| VsigError::NotUtf8 { field: name })
    }
}
