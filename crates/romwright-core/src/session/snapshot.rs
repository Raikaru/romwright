//! A program's mapped image as one file its readers map instead of rebuilding.
//!
//! The importing process holds the input (a disc image is gigabytes) and has
//! already run the loader. A child worker that parsed the input again would
//! hold the input and its own copy of every mapped byte, once per worker. The
//! snapshot is exactly what a `ProgramImage` reads -- regions, relocated words,
//! override bytes -- written once, so every worker maps the same pages.
//!
//! Layout, little-endian, every field a `u64` unless noted:
//! `"RWIMGSN1"`, region count, relocation count, patch count; then regions
//! (`vaddr size file_off file_size flags`), relocations (`address width` and
//! eight bytes), patches (`vaddr start len`); then the bytes. `file_off` and
//! `start` are absolute offsets into the snapshot. A mapping's bytes are
//! stored once, and its region and (when the loader's bytes differ from the
//! input file) its patch both point at them, which reads exactly as the
//! region over the input file plus an owned patch does.
use super::{MemoryRegion, Patch, ProgramImage};
use crate::artifact::SharedBytes;
use crate::native::{MemoryRelocation, NativeImport};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

const MAGIC: &[u8; 8] = b"RWIMGSN1";
const HEADER: usize = 32;
const REGION: usize = 40;
const RELOCATION: usize = 24;
const PATCH: usize = 24;

fn invalid(message: &str) -> crate::CoreError {
    io::Error::new(io::ErrorKind::InvalidData, format!("image snapshot: {message}")).into()
}

impl ProgramImage {
    /// Writes the snapshot of `import` as `ProgramImage::from_import` would
    /// read it over `map`, the input file's bytes.
    pub(crate) fn write_snapshot(
        map: &[u8],
        import: &NativeImport,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let mut patches: BTreeMap<u64, usize> = BTreeMap::new();
        for (index, mapping) in import.mappings.iter().enumerate() {
            if Self::is_patch(map, mapping) {
                patches.insert(mapping.vaddr, index);
            }
        }
        let mut cursor = (HEADER
            + import.mappings.len() * REGION
            + import.relocations.len() * RELOCATION
            + patches.len() * PATCH) as u64;
        let starts: Vec<u64> = import
            .mappings
            .iter()
            .map(|mapping| {
                let start = cursor;
                cursor += mapping.bytes.len() as u64;
                start
            })
            .collect();
        out.write_all(MAGIC)?;
        for count in [import.mappings.len(), import.relocations.len(), patches.len()] {
            out.write_all(&(count as u64).to_le_bytes())?;
        }
        for (mapping, start) in import.mappings.iter().zip(&starts) {
            for field in [
                mapping.vaddr,
                mapping.size,
                *start,
                mapping.bytes.len() as u64,
                mapping.flags,
            ] {
                out.write_all(&field.to_le_bytes())?;
            }
        }
        for relocation in &import.relocations {
            out.write_all(&relocation.address.to_le_bytes())?;
            out.write_all(&(relocation.width as u64).to_le_bytes())?;
            out.write_all(&relocation.bytes)?;
        }
        for (vaddr, index) in &patches {
            for field in [
                *vaddr,
                starts[*index],
                import.mappings[*index].bytes.len() as u64,
            ] {
                out.write_all(&field.to_le_bytes())?;
            }
        }
        for mapping in &import.mappings {
            out.write_all(&mapping.bytes)?;
        }
        Ok(())
    }

    /// Reads a snapshot written by `write_snapshot`; `path` names it in diagnostics.
    pub(crate) fn from_snapshot(path: PathBuf, map: SharedBytes) -> crate::Result<Self> {
        let field = |at: usize| -> crate::Result<u64> {
            map.get(at..at + 8)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
                .ok_or_else(|| invalid("truncated header"))
        };
        if map.get(..8) != Some(MAGIC.as_slice()) {
            return Err(invalid("not an image snapshot"));
        }
        let count = |at: usize, size: usize| -> crate::Result<usize> {
            usize::try_from(field(at)?)
                .ok()
                .filter(|count| {
                    count
                        .checked_mul(size)
                        .is_some_and(|bytes| bytes <= map.len())
                })
                .ok_or_else(|| invalid("table larger than the file"))
        };
        let (regions_len, relocations_len, patches_len) =
            (count(8, REGION)?, count(16, RELOCATION)?, count(24, PATCH)?);
        let relocations_at = HEADER + regions_len * REGION;
        let patches_at = relocations_at + relocations_len * RELOCATION;
        let data_at = patches_at + patches_len * PATCH;
        if data_at > map.len() {
            return Err(invalid("tables larger than the file"));
        }
        let within = |start: u64, len: u64| -> crate::Result<(usize, usize)> {
            let start = usize::try_from(start).map_err(|_| invalid("offset out of range"))?;
            let len = usize::try_from(len).map_err(|_| invalid("length out of range"))?;
            if start < data_at || start.checked_add(len).is_none_or(|end| end > map.len()) {
                return Err(invalid("bytes outside the file"));
            }
            Ok((start, len))
        };
        let mut regions = Vec::with_capacity(regions_len);
        for index in 0..regions_len {
            let at = HEADER + index * REGION;
            let (file_off, file_size) = (field(at + 16)?, field(at + 24)?);
            within(file_off, file_size)?;
            regions.push(MemoryRegion {
                vaddr: field(at)?,
                size: field(at + 8)?,
                file_off,
                file_size,
                flags: field(at + 32)?,
            });
        }
        let mut relocations = Vec::with_capacity(relocations_len);
        for index in 0..relocations_len {
            let at = relocations_at + index * RELOCATION;
            let width = usize::try_from(field(at + 8)?)
                .ok()
                .filter(|width| *width <= 8)
                .ok_or_else(|| invalid("relocation wider than eight bytes"))?;
            relocations.push(MemoryRelocation {
                address: field(at)?,
                bytes: map[at + 16..at + 24].try_into().expect("eight bytes"),
                width,
            });
        }
        let mut patches = BTreeMap::new();
        for index in 0..patches_len {
            let at = patches_at + index * PATCH;
            let (start, len) = within(field(at + 8)?, field(at + 16)?)?;
            patches.insert(field(at)?, Patch::Backed { start, len });
        }
        Ok(Self {
            path,
            map,
            regions,
            relocations,
            patches,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::Mapping;

    /// Reads agree over every region, across the bytes a relocation word
    /// covers, an override and the zero-filled tail, and refusals agree.
    #[test]
    fn a_snapshot_reads_exactly_what_the_image_it_came_from_reads() {
        // The input file: 0x20 bytes of 0x11 then 0x20 of 0x22.
        let mut file = vec![0x11u8; 0x20];
        file.extend([0x22u8; 0x20]);
        let import = NativeImport {
            mappings: vec![
                // Equal to the file: no override.
                Mapping { vaddr: 0x1000, size: 0x30, file_off: 0, flags: 5, bytes: vec![0x11; 0x20] },
                // Loader bytes that are not the file's: an override.
                Mapping { vaddr: 0x2000, size: 0x28, file_off: 0x20, flags: 3, bytes: vec![0x77; 0x18] },
                // Past the end of the file entirely: an override.
                Mapping { vaddr: 0x3000, size: 0x10, file_off: 0x1000, flags: 3, bytes: vec![0x55; 4] },
                // Nothing in the file, nothing mapped.
                Mapping { vaddr: 0x4000, size: 0x10, file_off: 0, flags: 3, bytes: Vec::new() },
            ],
            relocations: vec![
                MemoryRelocation { address: 0x1004, bytes: [1, 2, 3, 4, 0, 0, 0, 0], width: 4 },
                MemoryRelocation { address: 0x2004, bytes: [9, 9, 9, 9, 9, 9, 9, 9], width: 8 },
                MemoryRelocation { address: 0x5000, bytes: [8; 8], width: 2 },
            ],
            ..Default::default()
        };
        let mut expected = ProgramImage::from_import("input".into(), file.clone().into(), {
            NativeImport {
                mappings: import.mappings.clone(),
                relocations: import.relocations.clone(),
                ..Default::default()
            }
        });
        let mut bytes = Vec::new();
        ProgramImage::write_snapshot(&file, &import, &mut bytes).unwrap();
        let mut held = ProgramImage::from_snapshot("snapshot".into(), bytes.clone().into()).unwrap();
        for image in [&mut expected, &mut held] {
            image.patch(0x1018, vec![0xee, 0xef]);
        }
        for region in expected.regions().to_vec() {
            for start in 0..region.size {
                for size in [1, 3, 8, region.size - start] {
                    let at = region.vaddr + start;
                    assert_eq!(held.read(at, size), expected.read(at, size), "{at:#x}+{size}");
                }
            }
        }
        for at in [0xfff, 0x4010, 0x5000, 0x9000] {
            assert_eq!(held.read(at, 1), expected.read(at, 1), "{at:#x}");
        }
        // The bytes are stored once, not once per region and once per override.
        assert!(bytes.len() < 32 + 4 * 40 + 3 * 24 + 2 * 24 + 0x20 + 0x18 + 4 + 8);
    }

    #[test]
    fn a_damaged_snapshot_is_refused() {
        let import = NativeImport {
            mappings: vec![Mapping { vaddr: 0x1000, size: 8, file_off: 0, flags: 5, bytes: vec![1; 8] }],
            ..Default::default()
        };
        let mut bytes = Vec::new();
        ProgramImage::write_snapshot(&[], &import, &mut bytes).unwrap();
        assert!(ProgramImage::from_snapshot("s".into(), bytes.clone().into()).is_ok());
        assert!(ProgramImage::from_snapshot("s".into(), bytes[..bytes.len() - 1].to_vec().into()).is_err());
        assert!(ProgramImage::from_snapshot("s".into(), bytes[..20].to_vec().into()).is_err());
        let mut wrong = bytes.clone();
        wrong[0] ^= 1;
        assert!(ProgramImage::from_snapshot("s".into(), wrong.into()).is_err());
        let mut huge = bytes;
        huge[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ProgramImage::from_snapshot("s".into(), huge.into()).is_err());
    }
}
