//! `ar` static archive reader for the System V/GNU and BSD member layouts.
//!
//! Fields follow the public `ar(5)` layout: a `!<arch>\n` magic, then 60-byte
//! member headers whose numeric fields are ASCII. Thin archives keep member
//! bytes outside the file and are rejected rather than half-read.

/// Every rejection names the offset it was decided at.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArchiveError {
    #[error("not an ar archive")]
    BadMagic,
    #[error("thin archives hold no member bytes")]
    ThinArchive,
    #[error("member header at {offset} is truncated")]
    TruncatedHeader { offset: usize },
    #[error("member header at {offset} lacks the `\\n magic")]
    BadHeaderMagic { offset: usize },
    #[error("member at {offset} has a malformed {field}")]
    MalformedField { offset: usize, field: &'static str },
    #[error("member at {offset} claims {size} bytes, {available} remain")]
    TruncatedMember {
        offset: usize,
        size: usize,
        available: usize,
    },
    #[error("long-name reference {offset} is outside the name table")]
    BadLongName { offset: usize },
}

type Result<T> = std::result::Result<T, ArchiveError>;

const MAGIC: &[u8] = b"!<arch>\n";
const THIN_MAGIC: &[u8] = b"!<thin>\n";
const HEADER_LEN: usize = 60;

/// One archive member: an object file in almost every case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member<'a> {
    pub name: String,
    pub data: &'a [u8],
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end().to_string()
}

fn decimal(bytes: &[u8], offset: usize, field: &'static str) -> Result<usize> {
    let text = text(bytes);
    let text = text.trim();
    if text.is_empty() {
        return Err(ArchiveError::MalformedField { offset, field });
    }
    text.parse()
        .map_err(|_| ArchiveError::MalformedField { offset, field })
}

/// Reads every real member, dropping the symbol index and name table that
/// belong to the container rather than to the library.
pub fn members(bytes: &[u8]) -> Result<Vec<Member<'_>>> {
    if bytes.starts_with(THIN_MAGIC) {
        return Err(ArchiveError::ThinArchive);
    }
    if !bytes.starts_with(MAGIC) {
        return Err(ArchiveError::BadMagic);
    }
    let mut names: &[u8] = &[];
    let mut members = Vec::new();
    let mut offset = MAGIC.len();
    while offset < bytes.len() {
        if bytes.len() - offset < HEADER_LEN {
            return Err(ArchiveError::TruncatedHeader { offset });
        }
        let header = &bytes[offset..offset + HEADER_LEN];
        if &header[58..60] != b"`\n" {
            return Err(ArchiveError::BadHeaderMagic { offset });
        }
        let size = decimal(&header[48..58], offset, "size")?;
        let start = offset + HEADER_LEN;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or(ArchiveError::TruncatedMember {
                offset,
                size,
                available: bytes.len() - start.min(bytes.len()),
            })?;
        let raw = text(&header[0..16]);
        let mut data = &bytes[start..end];
        let name = if raw == "/" || raw == "/SYM64/" {
            String::new() // Symbol index: the container's own table.
        } else if raw == "//" {
            names = data;
            String::new()
        } else if let Some(reference) = raw.strip_prefix('/') {
            let at: usize = reference
                .parse()
                .map_err(|_| ArchiveError::MalformedField {
                    offset,
                    field: "long name",
                })?;
            let tail = names
                .get(at..)
                .ok_or(ArchiveError::BadLongName { offset: at })?;
            let stop = tail
                .iter()
                .position(|&byte| byte == b'/' || byte == b'\n' || byte == 0)
                .unwrap_or(tail.len());
            text(&tail[..stop])
        } else if let Some(length) = raw.strip_prefix("#1/") {
            // BSD long name: the first `length` data bytes hold it.
            let length: usize = length
                .parse()
                .map_err(|_| ArchiveError::MalformedField {
                    offset,
                    field: "bsd name length",
                })?;
            if length > data.len() {
                return Err(ArchiveError::MalformedField {
                    offset,
                    field: "bsd name length",
                });
            }
            let (name, rest) = data.split_at(length);
            data = rest;
            text(name).trim_end_matches('\0').to_string()
        } else {
            raw.trim_end_matches('/').to_string()
        };
        if !name.is_empty() {
            members.push(Member { name, data });
        }
        offset = end + (end % 2);
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut bytes = format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, 100644,
            data.len())
        .into_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        bytes.extend(data);
        if data.len() % 2 == 1 {
            bytes.push(b'\n');
        }
        bytes
    }

    #[test]
    fn reads_short_long_and_bsd_names_without_container_entries() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(member("/", b"symbol index"));
        bytes.extend(member("//", b"a_very_long_member_name.o/\n"));
        bytes.extend(member("short.o", b"odd"));
        bytes.extend(member("/0", b"long"));
        bytes.extend(member("#1/8", b"bsdname\0bsd"));
        let members = members(&bytes).unwrap();
        assert_eq!(
            members,
            vec![
                Member { name: "short.o".into(), data: b"odd" },
                Member { name: "a_very_long_member_name.o".into(), data: b"long" },
                Member { name: "bsdname".into(), data: b"bsd" },
            ]
        );
    }

    #[test]
    fn malformed_containers_are_rejected() {
        assert_eq!(members(b"not an archive").unwrap_err(), ArchiveError::BadMagic);
        assert_eq!(members(THIN_MAGIC).unwrap_err(), ArchiveError::ThinArchive);
        let mut short = MAGIC.to_vec();
        short.extend(b"tiny");
        assert!(matches!(
            members(&short).unwrap_err(),
            ArchiveError::TruncatedHeader { .. }
        ));
        let mut lying = MAGIC.to_vec();
        lying.extend(member("short.o", b"1234"));
        lying.truncate(lying.len() - 2);
        assert!(matches!(
            members(&lying).unwrap_err(),
            ArchiveError::TruncatedMember { .. }
        ));
        let mut bad_size = MAGIC.to_vec();
        bad_size.extend(member("short.o", b"12"));
        bad_size[MAGIC.len() + 48] = b'x';
        assert!(matches!(
            members(&bad_size).unwrap_err(),
            ArchiveError::MalformedField { field: "size", .. }
        ));
        let mut unnamed = MAGIC.to_vec();
        unnamed.extend(member("/9", b"12"));
        assert!(matches!(
            members(&unnamed).unwrap_err(),
            ArchiveError::BadLongName { .. }
        ));
    }
}
