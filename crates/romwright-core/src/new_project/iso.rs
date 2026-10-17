//! Boot-executable extraction from a PS2 disc image.
//!
//! A retail PS2 disc holds many files; the one a project decompiles is the ELF
//! `SYSTEM.CNF` names on its `BOOT2 = cdrom0:\SLUS_xxx.xx;1` line. This reads
//! just enough ISO9660 (ECMA-119) to find and copy that file out, for the
//! layouts a ripped data track comes in: cooked 2048-byte sectors, raw mode 1
//! (2352), raw mode 2 form 1 (2352) and headerless mode 2 (2336).

const SECTOR: usize = 2048;
/// `(stride, user-data offset)` per layout.
const LAYOUTS: [(usize, usize); 4] = [(2048, 0), (2352, 16), (2352, 24), (2336, 8)];

struct Volume<'a> {
    data: &'a [u8],
    stride: usize,
    skip: usize,
}

impl<'a> Volume<'a> {
    fn detect(data: &'a [u8]) -> Option<Self> {
        LAYOUTS.iter().find_map(|&(stride, skip)| {
            let volume = Volume { data, stride, skip };
            let sector = volume.sector(16)?;
            (sector[0] == 1 && &sector[1..6] == b"CD001").then_some(volume)
        })
    }

    fn sector(&self, lba: usize) -> Option<&'a [u8]> {
        let start = lba.checked_mul(self.stride)? + self.skip;
        self.data.get(start..start + SECTOR)
    }

    fn read(&self, lba: usize, length: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(length);
        let mut at = lba;
        while out.len() < length {
            let sector = self.sector(at)?;
            out.extend_from_slice(&sector[..SECTOR.min(length - out.len())]);
            at += 1;
        }
        Some(out)
    }
}

fn le32(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize
}

/// `(name, extent, length, is_directory)` of each record of a directory.
fn records(volume: &Volume, extent: usize, length: usize) -> Vec<(String, usize, usize, bool)> {
    let Some(data) = volume.read(extent, length) else { return Vec::new() };
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let size = data[at] as usize;
        if size == 0 {
            // Records never straddle a sector: skip to the next one.
            at = (at / SECTOR + 1) * SECTOR;
            continue;
        }
        if at + size > data.len() || size < 34 {
            break;
        }
        let name_len = data[at + 32] as usize;
        if at + 33 + name_len <= data.len() {
            let raw = &data[at + 33..at + 33 + name_len];
            let name = String::from_utf8_lossy(raw).into_owned();
            out.push((name, le32(&data, at + 2), le32(&data, at + 10), data[at + 25] & 2 != 0));
        }
        at += size;
    }
    out
}

fn find(volume: &Volume, dir: (usize, usize), wanted: &str) -> Option<(usize, usize, bool)> {
    let wanted = wanted.trim_end_matches(";1").to_ascii_uppercase();
    records(volume, dir.0, dir.1).into_iter().find_map(|(name, extent, length, is_dir)| {
        (name.trim_end_matches(";1").to_ascii_uppercase() == wanted).then_some((extent, length, is_dir))
    })
}

/// `BOOT2 = cdrom0:\DIR\FILE;1` -> `["DIR", "FILE;1"]`.
fn boot_path(system_cnf: &str) -> Option<Vec<String>> {
    system_cnf.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("BOOT2") {
            return None;
        }
        let value = value.trim();
        let value = value.split_once(':').map(|(_, rest)| rest).unwrap_or(value);
        Some(value.split(['\\', '/']).filter(|p| !p.is_empty()).map(str::to_string).collect())
    })
}

/// The boot ELF of a PS2 disc image as `(file name, bytes)`; `Ok(None)` when
/// `data` is not an ISO9660 volume at all (then it is a plain executable).
pub fn boot_executable(data: &[u8]) -> Result<Option<(String, Vec<u8>)>, String> {
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return Ok(None);
    }
    let Some(volume) = Volume::detect(data) else { return Ok(None) };
    let pvd = volume.sector(16).ok_or("ISO9660: truncated volume descriptor")?;
    let root = (le32(pvd, 156 + 2), le32(pvd, 156 + 10));
    let (extent, length, _) = find(&volume, root, "SYSTEM.CNF")
        .ok_or("ISO9660 image has no SYSTEM.CNF: not a PlayStation disc")?;
    let cnf = volume.read(extent, length).ok_or("ISO9660: SYSTEM.CNF is truncated")?;
    let path = boot_path(&String::from_utf8_lossy(&cnf)).ok_or(
        "SYSTEM.CNF has no BOOT2 line: this is not a PlayStation 2 disc (a PlayStation disc names BOOT)",
    )?;
    let mut dir = root;
    let mut file = None;
    for (index, part) in path.iter().enumerate() {
        let (extent, length, is_dir) = find(&volume, dir, part)
            .ok_or_else(|| format!("ISO9660: `{part}` from SYSTEM.CNF's BOOT2 path is not on the disc"))?;
        if index + 1 == path.len() {
            file = Some((part.trim_end_matches(";1").to_string(), extent, length));
        } else if is_dir {
            dir = (extent, length);
        } else {
            return Err(format!("ISO9660: `{part}` is a file but the BOOT2 path continues past it"));
        }
    }
    let (name, extent, length) = file.ok_or("SYSTEM.CNF's BOOT2 path is empty")?;
    let bytes = volume.read(extent, length).ok_or("ISO9660: the boot executable runs past the end of the image")?;
    Ok(Some((name, bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn record(buf: &mut Vec<u8>, name: &str, extent: u32, length: u32, dir: bool) {
        let mut rec = vec![0u8; 33 + name.len()];
        rec[0] = rec.len() as u8;
        put32(&mut rec, 2, extent);
        put32(&mut rec, 10, length);
        rec[25] = if dir { 2 } else { 0 };
        rec[32] = name.len() as u8;
        rec[33..].copy_from_slice(name.as_bytes());
        buf.extend_from_slice(&rec);
    }

    /// A cooked image: PVD at 16, root at 17, SYSTEM.CNF at 18, ELF at 19.
    fn disc() -> Vec<u8> {
        let elf = b"\x7fELFpayload";
        let mut image = vec![0u8; 20 * SECTOR];
        image[16 * SECTOR] = 1;
        image[16 * SECTOR + 1..16 * SECTOR + 6].copy_from_slice(b"CD001");
        let root = 16 * SECTOR + 156;
        put32(&mut image, root + 2, 17);
        put32(&mut image, root + 10, SECTOR as u32);
        let mut dir = Vec::new();
        record(&mut dir, "SYSTEM.CNF;1", 18, 40, false);
        record(&mut dir, "SLUS_217.82;1", 19, elf.len() as u32, false);
        image[17 * SECTOR..17 * SECTOR + dir.len()].copy_from_slice(&dir);
        let cnf = b"BOOT2 = cdrom0:\\SLUS_217.82;1\nVER = 1.00\n";
        image[18 * SECTOR..18 * SECTOR + cnf.len()].copy_from_slice(cnf);
        image[19 * SECTOR..19 * SECTOR + elf.len()].copy_from_slice(elf);
        image
    }

    #[test]
    fn extracts_the_file_system_cnf_names() {
        let (name, bytes) = boot_executable(&disc()).unwrap().unwrap();
        assert_eq!(name, "SLUS_217.82");
        assert_eq!(bytes, b"\x7fELFpayload");
    }

    #[test]
    fn raw_mode2_sectors_and_plain_elf_and_ps1_discs() {
        let cooked = disc();
        let mut raw = vec![0u8; cooked.len() / SECTOR * 2352];
        for (lba, sector) in cooked.chunks(SECTOR).enumerate() {
            raw[lba * 2352 + 24..lba * 2352 + 24 + SECTOR].copy_from_slice(sector);
        }
        assert_eq!(boot_executable(&raw).unwrap().unwrap().0, "SLUS_217.82");
        assert_eq!(boot_executable(b"\x7fELF....").unwrap(), None);
        assert_eq!(boot_executable(b"not a disc").unwrap(), None);
        let mut ps1 = disc();
        let at = 18 * SECTOR;
        ps1[at..at + 5].copy_from_slice(b"BOOT ");
        assert!(boot_executable(&ps1).unwrap_err().contains("BOOT2"));
    }
}
