//! PlayStation executables (PS-EXE).
//!
//! A 2 KiB header followed by one flat image. psx-spx "Executables" fixes
//! the fields this reads: the `PS-X EXE` magic at 0x00, the initial PC at
//! 0x10, the destination address at 0x18 and the image size at 0x1C. The
//! file says nothing about functions, so discovery closes the rest from
//! flow.
//!
//! The magic alone is not accepted: the declared size must match the file,
//! the destination must be somewhere a program can be loaded (psx-spx
//! "Memory Map"), and the initial PC must land inside the image the header
//! describes. A file failing any of those is not a PS-EXE.

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

const MAGIC: &[u8; 8] = b"PS-X EXE";
/// psx-spx "Executables": the header occupies 0x800 bytes.
const HEADER_LEN: u64 = 0x800;
const PC_OFFSET: usize = 0x10;
const DESTINATION_OFFSET: usize = 0x18;
const SIZE_OFFSET: usize = 0x1C;

/// psx-spx "Memory Map": the 2 MB of main RAM, seen through the MIPS
/// segments. A program is loaded into one of these windows.
const RAM_SIZE: u64 = 2 * 1024 * 1024;
const RAM_WINDOWS: [u64; 3] = [0x0000_0000, 0x8000_0000, 0xA000_0000];

struct Header {
    entry: u64,
    destination: u64,
    size: u64,
}

fn word(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64)
}

/// The window `address` sits in, when it is main RAM at all.
fn ram_window(address: u64, size: u64) -> Option<u64> {
    let end = address.checked_add(size)?;
    RAM_WINDOWS
        .iter()
        .copied()
        .find(|&base| address >= base && end <= base + RAM_SIZE)
}

fn parse(data: &[u8]) -> Option<Header> {
    if !data.starts_with(MAGIC) {
        return None;
    }
    let header = Header {
        entry: word(data, PC_OFFSET)?,
        destination: word(data, DESTINATION_OFFSET)?,
        size: word(data, SIZE_OFFSET)?,
    };
    // The header states the image length; a file that does not carry it is
    // truncated or is not a PS-EXE.
    if header.size == 0 || HEADER_LEN.checked_add(header.size)? > data.len() as u64 {
        return None;
    }
    ram_window(header.destination, header.size)?;
    let end = header.destination.checked_add(header.size)?;
    // The console jumps to the initial PC after loading; a PC outside the
    // loaded image would execute bytes this file does not contain.
    (header.destination..end).contains(&header.entry).then_some(header)
}

/// True when `data` carries a PlayStation executable header.
pub(crate) fn is_executable(data: &[u8]) -> bool {
    parse(data).is_some()
}

/// psx-spx "Memory Map": windows a program sees but the file does not carry.
fn regions(window: u64) -> Vec<DeclaredRegion> {
    // name, base, size, permissions (1 = write, 2 = read, 4 = execute)
    [
        ("main-ram", window, RAM_SIZE, 0x7),
        ("scratchpad", 0x1F80_0000, 1024, 0x3),
        ("io", 0x1F80_1000, 0x2000, 0x3),
    ]
    .iter()
    .map(|&(name, vaddr, size, flags)| DeclaredRegion {
        name: name.into(),
        vaddr,
        size,
        flags,
    })
    .collect()
}

/// Loads a PS-EXE: the image at its destination, the initial PC as the seed,
/// and the console's memory map declared.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let Some(header) = parse(data) else {
        return super::err("not a PlayStation executable");
    };
    let start = HEADER_LEN as usize;
    let end = start + header.size as usize;
    let window = ram_window(header.destination, header.size)
        .ok_or_else(|| super::ImportError::Bad("PS-EXE destination is not main RAM".into()))?;
    let mut import = NativeImport {
        mappings: vec![Mapping {
            vaddr: header.destination,
            size: header.size,
            file_off: HEADER_LEN,
            // Loaded into RAM, so writable as well as executable.
            flags: 0x7,
            bytes: data[start..end].to_vec(),
        }],
        mapping_names: vec!["text".into()],
        declared_regions: regions(window),
        format: "psx".into(),
        language: "MIPS:LE:32:default".into(),
        ..Default::default()
    };
    import.functions.push(NativeFunction {
        entry: header.entry,
        name: "psx_entry".into(),
        size: 1,
    });
    Ok(import)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable(entry: u64, destination: u64, size: u64, file_len: usize) -> Vec<u8> {
        let mut data = vec![0u8; file_len.max(HEADER_LEN as usize)];
        data[..8].copy_from_slice(MAGIC);
        for (offset, value) in [
            (PC_OFFSET, entry),
            (DESTINATION_OFFSET, destination),
            (SIZE_OFFSET, size),
        ] {
            data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        data
    }

    #[test]
    fn the_header_names_the_mapping_and_the_seed() {
        let image = executable(0x8001_0040, 0x8001_0000, 0x200, 0xA00);
        let import = import(&image).expect("executable");
        assert_eq!(import.language, "MIPS:LE:32:default");
        assert_eq!(import.mappings[0].vaddr, 0x8001_0000);
        assert_eq!(import.mappings[0].size, 0x200);
        assert_eq!(import.mappings[0].file_off, HEADER_LEN);
        assert_eq!(import.functions[0].entry, 0x8001_0040);
    }

    #[test]
    fn a_size_the_file_does_not_carry_is_refused() {
        assert!(!is_executable(&executable(0x8001_0040, 0x8001_0000, 0x4000, 0xA00)));
    }

    #[test]
    fn an_entry_outside_the_loaded_image_is_refused() {
        assert!(!is_executable(&executable(0x8002_0000, 0x8001_0000, 0x200, 0xA00)));
    }

    #[test]
    fn a_destination_outside_main_ram_is_refused() {
        // The BIOS window is not somewhere an executable is loaded.
        assert!(!is_executable(&executable(0xBFC0_0040, 0xBFC0_0000, 0x200, 0xA00)));
    }

    #[test]
    fn the_uncached_mirror_is_accepted() {
        // psx-spx: the same RAM is visible at 0x00000000 and 0xa0000000.
        let import = import(&executable(0xA001_0000, 0xA001_0000, 0x100, 0x900))
            .expect("mirrored executable");
        assert_eq!(import.mappings[0].vaddr, 0xA001_0000);
        assert_eq!(import.declared_regions[0].vaddr, 0xA000_0000);
    }

    #[test]
    fn the_magic_is_required() {
        let mut image = executable(0x8001_0040, 0x8001_0000, 0x200, 0xA00);
        image[0] = b'X';
        assert!(!is_executable(&image));
    }

    #[test]
    fn a_zero_length_image_is_refused() {
        assert!(!is_executable(&executable(0x8001_0000, 0x8001_0000, 0, 0xA00)));
    }
}
