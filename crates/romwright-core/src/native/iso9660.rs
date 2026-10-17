//! ISO9660 container reading: a PlayStation or PlayStation 2 disc image is a
//! container whose boot executable lives behind `SYSTEM.CNF`'s boot line
//! (`BOOT2` for a PS2 ELF, `BOOT` for a PS1 PS-EXE). The reader walks the
//! primary volume descriptor's root directory, resolves the boot path, and
//! hands the executable to the normal importer. Other root ELFs come along
//! as sibling images so a PS2 disc's modules are all loaded.
//!
//! Sector layouts, from ECMA-130 (CD-ROM sectors), ECMA-119 (ISO9660) and
//! psx-spx "CDROM Disk Images" / "CDROM File Formats": a data track is a
//! run of sectors whose 2048-byte user data holds the ISO9660 volume, read
//! at logical sector `n`. An ISO file stores those 2048 bytes alone. A raw
//! `.bin` track stores whole 2352-byte sectors -- 12 sync bytes
//! (`00 FF*10 00`), a 4-byte header whose last byte is the mode, then for
//! mode 1 the 2048 data bytes at offset 16, and for mode 2 (CD-ROM XA, every
//! PS1 game's data track) an 8-byte subheader and the 2048 bytes of a form-1
//! sector at offset 24. A 2336-byte image drops sync and header, leaving the
//! mode-2 subheader at 0. The volume is found by the same signature in every
//! layout: `CD001` one byte into logical sector 16.

use super::{ImportError, NativeImport};
use std::borrow::Cow;

/// ISO9660 logical sector: the user data of one CD sector.
const SECTOR: usize = 2048;
/// `(bytes per image sector, offset of the user data in it)`, in the order a
/// layout is tried: a cooked ISO, then raw mode 1, raw mode 2 form 1, and
/// 2336-byte mode 2 without sync.
const LAYOUTS: [(usize, usize); 4] = [(2048, 0), (2352, 16), (2352, 24), (2336, 8)];

/// An image read as logical 2048-byte sectors, whatever its stored layout.
struct Volume<'a> {
    data: &'a [u8],
    stride: usize,
    skip: usize,
}

impl<'a> Volume<'a> {
    /// The layout whose logical sector 16 carries the primary volume
    /// descriptor, `None` for a file that is no CD data track.
    fn detect(data: &'a [u8]) -> Option<Self> {
        LAYOUTS.iter().find_map(|&(stride, skip)| {
            let at = 16 * stride + skip;
            (data.get(at + 1..at + 6) == Some(b"CD001")).then_some(Self { data, stride, skip })
        })
    }

    /// `size` bytes from logical sector `extent`; borrowed when the image is
    /// cooked, gathered sector by sector when it is raw. `None` when the
    /// image ends first.
    fn read(&self, extent: usize, size: usize) -> Option<Cow<'a, [u8]>> {
        if self.stride == SECTOR {
            let base = extent.checked_mul(SECTOR)?;
            return self.data.get(base..base.checked_add(size)?).map(Cow::Borrowed);
        }
        let mut out = Vec::with_capacity(size);
        let mut sector = extent;
        while out.len() < size {
            let at = sector.checked_mul(self.stride)?.checked_add(self.skip)?;
            let take = (size - out.len()).min(SECTOR);
            out.extend_from_slice(self.data.get(at..at.checked_add(take)?)?);
            sector += 1;
        }
        Some(Cow::Owned(out))
    }
}

/// True when the file is a CD data track: an ISO image or a raw sector dump.
pub(crate) fn is_iso(data: &[u8]) -> bool {
    Volume::detect(data).is_some()
}

/// One directory record's decoded fields.
struct DirEntry {
    extent: usize,
    size: usize,
    is_dir: bool,
    name: String,
}

/// Walk a directory extent's records.
fn read_dir(volume: &Volume, extent: usize, size: usize) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    // A directory the image cuts short still yields what it holds.
    let Some(data) = volume.read(extent, size).or_else(|| {
        (1..=size.div_ceil(SECTOR)).rev().find_map(|sectors| volume.read(extent, sectors * SECTOR))
    }) else {
        return entries;
    };
    let end = data.len().min(size);
    let mut cursor = 0;
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
        let entry_extent = u32::from_le_bytes(record[2..6].try_into().unwrap()) as usize;
        let entry_size = u32::from_le_bytes(record[10..14].try_into().unwrap()) as usize;
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
fn read_file<'a>(volume: &Volume<'a>, entry: &DirEntry) -> Option<Cow<'a, [u8]>> {
    volume.read(entry.extent, entry.size)
}

/// The text after `prefix` when `path` begins with it, ignoring ASCII case.
fn strip_prefix_nocase<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let head = path.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &path[prefix.len()..])
}

/// Resolve a `cdrom0:\PATH;1` (PS2) or `cdrom:\PATH;1` (PS1) boot path
/// against the root directory to the directory record it names.
fn resolve_path(volume: &Volume, root: &DirEntry, path: &str) -> Option<DirEntry> {
    // `cdrom0:\DIR\FILE;1` — split off the device and version.
    let path = strip_prefix_nocase(path, "cdrom0:")
        .or_else(|| strip_prefix_nocase(path, "cdrom:"))
        .unwrap_or(path)
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
        let entries = read_dir(volume, dir.extent, dir.size);
        let found = entries.iter().find(|e| e.name.eq_ignore_ascii_case(component))?;
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

/// Parse `BOOT2 = cdrom0:\FILE;1` (PS2) or `BOOT = cdrom:\FILE;1` (PS1) out
/// of SYSTEM.CNF.
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

/// Import a disc image: the boot executable from SYSTEM.CNF -- a PS1 PS-EXE
/// as the one program, or a PS2 ELF with every other root-level ELF as
/// sibling images.
pub(crate) fn import(data: &[u8]) -> Result<Vec<(String, NativeImport)>, ImportError> {
    let volume = Volume::detect(data)
        .ok_or_else(|| ImportError::Bad("not an ISO9660 image".into()))?;
    // Primary volume descriptor: root directory record at offset 156.
    let pvd = volume
        .read(16, SECTOR)
        .ok_or_else(|| ImportError::Bad("ISO9660 volume descriptor is truncated".into()))?;
    let root = DirEntry {
        extent: u32::from_le_bytes(pvd[158..162].try_into().unwrap()) as usize,
        size: u32::from_le_bytes(pvd[166..170].try_into().unwrap()) as usize,
        is_dir: true,
        name: String::new(),
    };
    let root_entries = read_dir(&volume, root.extent, root.size);

    // SYSTEM.CNF names the boot executable as a full `cdrom0:\DIR\FILE;1`
    // path, which may sit below the root; fall back to the first ELF.
    let cnf = root_entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case("SYSTEM.CNF"))
        .and_then(|e| read_file(&volume, e));
    let boot = cnf
        .as_deref()
        .and_then(boot_path)
        .and_then(|path| resolve_path(&volume, &root, &path))
        .filter(|entry| !entry.is_dir);

    // A PlayStation disc boots a PS-EXE, whose header names where it loads.
    if let Some(entry) = &boot
        && let Some(bytes) = read_file(&volume, entry).filter(|bytes| super::psx::is_executable(bytes)) {
            return Ok(vec![(String::new(), super::psx::import(&bytes)?)]);
        }

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
        let Some(bytes) = read_file(&volume, entry) else {
            continue;
        };
        if !bytes.starts_with(b"\x7fELF") {
            continue;
        }
        let imp = super::import_elf(&bytes)?;
        let suffix = entry
            .name
            .trim_end_matches(".ELF")
            .trim_end_matches(".elf")
            .to_string();
        images.push((suffix, imp));
    }
    if images.is_empty() {
        return Err(ImportError::Bad(
            "ISO9660 image carries neither an ELF nor a PS-EXE boot executable".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A PS-EXE of `words` at `destination`, entering at its first word.
    fn ps_exe(destination: u32, words: &[u32]) -> Vec<u8> {
        let mut out = vec![0u8; 0x800 + words.len() * 4];
        out[..8].copy_from_slice(b"PS-X EXE");
        out[0x10..0x14].copy_from_slice(&destination.to_le_bytes());
        out[0x18..0x1c].copy_from_slice(&destination.to_le_bytes());
        out[0x1c..0x20].copy_from_slice(&((words.len() * 4) as u32).to_le_bytes());
        for (index, word) in words.iter().enumerate() {
            out[0x800 + index * 4..0x804 + index * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn record(name: &str, extent: usize, size: usize, directory: bool) -> Vec<u8> {
        let name = name.as_bytes();
        let mut out = vec![0u8; 33 + name.len() + (name.len() + 1) % 2];
        out[0] = out.len() as u8;
        out[2..6].copy_from_slice(&(extent as u32).to_le_bytes());
        out[10..14].copy_from_slice(&(size as u32).to_le_bytes());
        out[25] = if directory { 2 } else { 0 };
        out[32] = name.len() as u8;
        out[33..33 + name.len()].copy_from_slice(name);
        out
    }

    /// A cooked ISO9660 volume of root-level `files` (name, bytes): volume
    /// descriptor at sector 16, root directory at 18, files from 19.
    fn volume(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut sectors: Vec<Vec<u8>> = vec![vec![0u8; SECTOR]; 19];
        let mut root = Vec::new();
        root.extend(record("\0", 18, SECTOR, true));
        root.extend(record("\u{1}", 18, SECTOR, true));
        let mut at = 19;
        let mut data = Vec::new();
        for (name, bytes) in files {
            root.extend(record(&format!("{name};1"), at, bytes.len(), false));
            let count = bytes.len().div_ceil(SECTOR).max(1);
            let mut padded = bytes.to_vec();
            padded.resize(count * SECTOR, 0);
            data.extend(padded.chunks(SECTOR).map(<[u8]>::to_vec));
            at += count;
        }
        root.resize(SECTOR, 0);
        sectors[18] = root;
        let mut pvd = vec![0u8; SECTOR];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[6] = 1;
        let root_record = record("\0", 18, SECTOR, true);
        pvd[156..156 + root_record.len()].copy_from_slice(&root_record);
        sectors[16] = pvd;
        sectors.extend(data);
        sectors.concat()
    }

    /// The same volume as 2352-byte (`mode` 1 or 2) or 2336-byte sectors.
    fn raw(cooked: &[u8], stride: usize, mode: u8) -> Vec<u8> {
        let mut out = Vec::new();
        for (index, sector) in cooked.chunks(SECTOR).enumerate() {
            let mut cell = Vec::with_capacity(stride);
            if stride == 2352 {
                cell.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
                let frame = index + 150;
                let bcd = |n: usize| (((n / 10) << 4) | (n % 10)) as u8;
                cell.extend_from_slice(&[bcd(frame / 75 / 60), bcd(frame / 75 % 60), bcd(frame % 75), mode]);
            }
            if mode == 2 {
                cell.extend_from_slice(&[0, 0, 8, 0, 0, 0, 8, 0]);
            }
            cell.extend_from_slice(sector);
            cell.resize(stride, 0);
            out.extend(cell);
        }
        out
    }

    fn boot_disc(cnf: &str, exe: &[u8]) -> Vec<u8> {
        volume(&[("SYSTEM.CNF", cnf.as_bytes()), ("SLUS_010.32", exe)])
    }

    const CNF: &str = "BOOT = cdrom:\\SLUS_010.32;1\r\nTCB = 4\r\nEVENT = 10\r\nSTACK = 801FFFF0\r\n";

    #[test]
    fn a_ps1_disc_imports_its_boot_exe_from_every_sector_layout() {
        let exe = ps_exe(0x8009_0800, &[0x03e0_0008, 0, 0x03e0_0008, 0]);
        let cooked = boot_disc(CNF, &exe);
        let want = super::super::psx::import(&exe).unwrap();
        for (label, image) in [
            ("iso", cooked.clone()),
            ("mode 1 raw", raw(&cooked, 2352, 1)),
            ("mode 2 raw", raw(&cooked, 2352, 2)),
            ("mode 2 2336", raw(&cooked, 2336, 2)),
        ] {
            assert!(is_iso(&image), "{label}");
            // Through the container dispatch, so a raw track is never offered to the DOL loader.
            let programs = super::super::parse_container(&image).unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(programs.len(), 1, "{label}");
            let (suffix, got) = &programs[0];
            assert!(suffix.is_empty(), "{label}");
            assert_eq!(got.format, "psx", "{label}");
            assert_eq!(got.mappings, want.mappings, "{label}");
            assert_eq!(got.language, want.language, "{label}");
            assert_eq!(got.functions[0].entry, 0x8009_0800, "{label}");
        }
    }

    #[test]
    fn boot_lines_of_either_console_and_spelling_resolve() {
        let exe = ps_exe(0x8001_0000, &[0x03e0_0008, 0]);
        for cnf in [
            "BOOT=cdrom:SLUS_010.32;1",
            "boot = CDROM:\\slus_010.32;1\n",
            "BOOT = cdrom:\\\\SLUS_010.32;1\r\nTCB = 4",
        ] {
            let programs = import(&boot_disc(cnf, &exe)).unwrap_or_else(|error| panic!("{cnf:?}: {error}"));
            assert_eq!(programs[0].1.format, "psx", "{cnf:?}");
        }
        // No SYSTEM.CNF boot line, or one naming a file the disc lacks, is a refusal by name.
        for cnf in ["TCB = 4", "BOOT = cdrom:\\MISSING.EXE;1"] {
            let error = import(&boot_disc(cnf, &exe)).unwrap_err().to_string();
            assert!(error.contains("neither an ELF nor a PS-EXE"), "{cnf:?}: {error}");
        }
        // A boot file that is neither (a PS-EXE whose header lies about its size).
        let mut lying = exe.clone();
        lying[0x1c..0x20].copy_from_slice(&0x10_0000u32.to_le_bytes());
        assert!(import(&boot_disc(CNF, &lying)).is_err());
    }

    #[test]
    fn a_raw_track_cut_short_is_an_error_not_a_panic() {
        let cooked = boot_disc(CNF, &ps_exe(0x8001_0000, &[0x03e0_0008, 0]));
        let image = raw(&cooked, 2352, 2);
        // Cut inside the PS-EXE's sectors, inside the directory, and before the volume descriptor.
        for keep in [image.len() - 100, 18 * 2352 + 100, 16 * 2352 + 30, 5000, 0] {
            let _ = import(&image[..keep]);
        }
        assert!(import(&image[..image.len() - 2352 * 3]).is_err());
        assert!(!is_iso(&image[..16 * 2352 + 28]));
    }

    #[test]
    fn a_cue_sheet_imports_the_bin_beside_it_like_the_bin_itself() {
        let dir = std::env::temp_dir().join(format!("rw-ps1-cue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = ps_exe(0x8009_0800, &[0x03e0_0008, 0, 0x03e0_0008, 0]);
        std::fs::write(dir.join("Game (USA).bin"), raw(&boot_disc(CNF, &exe), 2352, 2)).unwrap();
        std::fs::write(
            dir.join("Game (USA).cue"),
            "FILE \"Game (USA).bin\" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n",
        )
        .unwrap();
        let core = crate::Core::open(&dir.join("project")).unwrap();
        let from_cue = core.load_program(&dir.join("Game (USA).cue"), "game").unwrap();
        assert_eq!((from_cue.len(), from_cue[0].program.as_str(), from_cue[0].language.as_str()), (1, "game", "PSX:LE:32:default"));
        // The program's captured input is the .bin the sheet names.
        let input = core.program_input("game").unwrap();
        assert!(input.source_path.ends_with("Game (USA).bin"), "{}", input.source_path);
        // The sheet identifies the program as well as the .bin does.
        for path in [dir.join("Game (USA).cue"), dir.join("Game (USA).bin")] {
            core.resolve_program_input(&path, "game").unwrap();
        }
        drop(core);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
