//! ISO9660 container reading: a PS2 (or any CD) disc image is a container
//! whose boot executable lives behind `SYSTEM.CNF`'s `BOOT2` line. The
//! reader walks the primary volume descriptor's root directory, resolves
//! the boot path, and hands the ELF to the normal importer. Other root
//! ELFs come along as sibling images so a disc's modules are all loaded.

use super::{ImportError, NativeImport};

const SECTOR: usize = 2048;

/// True when sector 16 carries the ISO9660 primary-volume magic.
pub(crate) fn is_iso(data: &[u8]) -> bool {
    data.get(16 * SECTOR + 1..16 * SECTOR + 6) == Some(b"CD001")
}

/// One directory record's decoded fields.
struct DirEntry {
    extent: usize,
    size: usize,
    is_dir: bool,
    name: String,
}

/// Walk a directory extent's records.
fn read_dir(data: &[u8], extent: usize, size: usize) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let base = extent * SECTOR;
    let end = (base + size).min(data.len());
    let mut cursor = base;
    while cursor < end {
        let length = data[cursor] as usize;
        if length == 0 {
            // Records never cross a sector boundary; skip the padding.
            cursor = (cursor / SECTOR + 1) * SECTOR;
            continue;
        }
        if cursor + length > data.len() || length < 34 {
            break;
        }
        let record = &data[cursor..cursor + length];
        let entry_extent =
            u32::from_le_bytes(record[2..6].try_into().unwrap()) as usize;
        let entry_size =
            u32::from_le_bytes(record[10..14].try_into().unwrap()) as usize;
        let flags = record[25];
        let name_len = record[32] as usize;
        let name = match name_len {
            0 => String::new(),
            1 if record[33] == 0 => ".".into(),
            1 if record[33] == 1 => "..".into(),
            _ => {
                let raw = &record[33..33 + name_len.min(length - 33)];
                let text = String::from_utf8_lossy(raw);
                // ISO9660 names carry a `;1` version suffix — cut at the
                // semicolon only, never trailing digits (`SLUS_205.79`).
                text.split(';').next().unwrap_or("").to_string()
            }
        };
        entries.push(DirEntry {
            extent: entry_extent,
            size: entry_size,
            is_dir: flags & 0x02 != 0,
            name,
        });
        cursor += length;
    }
    entries
}

/// Read a file's bytes from its extent.
fn read_file<'a>(data: &'a [u8], extent: usize, size: usize) -> Option<&'a [u8]> {
    let base = extent.checked_mul(SECTOR)?;
    data.get(base..base + size)
}

/// Resolve a `cdrom0:\PATH;1` boot path against the root directory to the
/// directory record it names.
fn resolve_path(data: &[u8], root: &DirEntry, path: &str) -> Option<DirEntry> {
    // `cdrom0:\DIR\FILE;1` — split off the device and version.
    let path = path
        .trim_start_matches("cdrom0:")
        .trim_start_matches(['\\', '/'])
        .split(';')
        .next()
        .unwrap_or("");
    let mut dir = DirEntry {
        extent: root.extent,
        size: root.size,
        is_dir: true,
        name: String::new(),
    };
    let mut components = path.split(['\\', '/']).filter(|c| !c.is_empty()).peekable();
    while let Some(component) = components.next() {
        let entries = read_dir(data, dir.extent, dir.size);
        let found = entries.iter().find(|e| {
            e.name.eq_ignore_ascii_case(component)
        })?;
        if components.peek().is_none() {
            return Some(DirEntry {
                extent: found.extent,
                size: found.size,
                is_dir: found.is_dir,
                name: found.name.clone(),
            });
        }
        if !found.is_dir {
            return None;
        }
        dir = DirEntry {
            extent: found.extent,
            size: found.size,
            is_dir: true,
            name: found.name.clone(),
        };
    }
    None
}

/// Parse `BOOT2 = cdrom0:\FILE;1` out of SYSTEM.CNF.
fn boot_path(cnf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(cnf).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once('=') {
            if key.trim().eq_ignore_ascii_case("BOOT2")
                || key.trim().eq_ignore_ascii_case("BOOT")
            {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Import a disc image: boot ELF from SYSTEM.CNF plus every other
/// root-level ELF as sibling images.
pub(crate) fn import(data: &[u8]) -> Result<Vec<(String, NativeImport)>, ImportError> {
    if !is_iso(data) {
        return Err(ImportError::Bad("not an ISO9660 image".into()));
    }
    // Primary volume descriptor: root directory record at offset 156.
    let pvd = &data[16 * SECTOR..17 * SECTOR];
    let root = DirEntry {
        extent: u32::from_le_bytes(pvd[158..162].try_into().unwrap()) as usize,
        size: u32::from_le_bytes(pvd[166..170].try_into().unwrap()) as usize,
        is_dir: true,
        name: String::new(),
    };
    let root_entries = read_dir(data, root.extent, root.size);

    // SYSTEM.CNF names the boot executable as a full `cdrom0:\DIR\FILE;1`
    // path, which may sit below the root; fall back to the first ELF.
    let cnf = root_entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case("SYSTEM.CNF"))
        .and_then(|e| read_file(data, e.extent, e.size));
    let boot = cnf
        .and_then(boot_path)
        .and_then(|path| resolve_path(data, &root, &path))
        .filter(|entry| !entry.is_dir);

    let mut images: Vec<(String, NativeImport)> = Vec::new();
    let mut elfs: Vec<&DirEntry> = root_entries
        .iter()
        .filter(|e| !e.is_dir && e.name.to_uppercase().ends_with(".ELF"))
        .collect();
    // The boot path may name a non-.ELF file (SLUS_205.79) or one outside
    // the root; include it.
    if let Some(entry) = &boot {
        if !elfs.iter().any(|e| e.extent == entry.extent) {
            elfs.insert(0, entry);
        }
    }
    for entry in elfs {
        let Some(bytes) = read_file(data, entry.extent, entry.size) else {
            continue;
        };
        if !bytes.starts_with(b"\x7fELF") {
            continue;
        }
        let imp = super::import_elf(bytes)?;
        let suffix = entry
            .name
            .trim_end_matches(".ELF")
            .trim_end_matches(".elf")
            .to_string();
        images.push((suffix, imp));
    }
    if images.is_empty() {
        return Err(ImportError::Bad(
            "ISO9660 image carries no ELF executable".into(),
        ));
    }
    // Boot image first when SYSTEM.CNF named one.
    if let Some(entry) = &boot {
        let name = entry.name.trim_end_matches(".ELF").trim_end_matches(".elf");
        if let Some(index) = images.iter().position(|(s, _)| s == name) {
            images.swap(0, index);
        }
    }
    Ok(images)
}
