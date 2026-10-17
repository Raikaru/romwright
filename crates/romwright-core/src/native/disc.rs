//! GameCube disc access (P3.1): CISO wrapper, GCM boot header, file system
//! table (FST), and the program a disc holds -- the boot DOL plus the RELs
//! it carries, linked as one image (`rel::attach`). The RELs are the FST's
//! `.rel`/`.rel.szs` files and the RELs inside the disc's RARC and U8 archives
//! (`archive.rs`, plain or Yaz0): every archive file is probed by its directory
//! alone, and only one that lists a REL is unpacked. RELs sharing a module id
//! become overlay programs (`rel::attach`).
//!
//! Formats, from the GC/Wii homebrew community's documentation (YAGCD, the
//! `nod` and decomp-toolkit disc readers; the last two MIT OR Apache-2.0):
//!
//! * **Containers read through `nod`** (RVZ, WIA, WBFS, a Wii ISO's encrypted
//!   partitions): `wii::import_nod` opens the data partition as a decrypted
//!   byte stream and `Disc::Partition` reads boot header, FST, DOL and RELs
//!   from it on demand; nothing is inflated to a whole ISO.
//! * **Wii layout**: the data partition starts like a GameCube disc (`boot.bin`
//!   at 0) but carries `0x5d1c9ea3` at `0x18`, and the DOL offset, FST offset,
//!   FST size and every FST file offset are stored shifted right by two.
//!
//! * **CISO** ("compact ISO"): a `0x8000`-byte header -- `CISO`, the
//!   little-endian block size, then one byte per block, 1 when the block is
//!   stored and 0 when it reads as zeros -- followed by the stored blocks
//!   back to back. The image is never expanded: reads go block by block.
//! * **GCM** boot header: `0x1c` holds `0xc2339f3d` on a GameCube disc;
//!   `0x420` the boot DOL's offset, `0x424` the FST's offset, `0x428` its
//!   size. The DOL's size is not stored: it is the end of its furthest section.
//! * **FST**: 12-byte entries -- a flag byte (1 = directory), a 24-bit name
//!   offset into the string table that follows the entries, then for a file
//!   its disc offset and size, for a directory its parent index and the index
//!   one past its last child. Entry 0 is the root and its last field is the
//!   entry count.
//!
//! Independent implementation; no upstream code copied.

use super::rel::{self, DiscRel};
use super::{archive, yaz0};
use super::{err, ImportError, NativeImport, Result};
use nod::read::PartitionReader;
use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom};

const GC_MAGIC: u32 = 0xc233_9f3d;
pub(crate) const WII_MAGIC: u32 = 0x5d1c_9ea3;
const CISO_HEADER: usize = 0x8000;
/// Larger than any real FST (AC's is 0x5a00 bytes); guards an absurd claim.
const MAX_FST: u64 = 64 << 20;
/// Larger than any REL a GameCube can hold in its 24 MiB.
const MAX_REL: u64 = 64 << 20;

/// True when the file is a CISO: magic, a sane block size, and a block map
/// of 0s and 1s whose stored blocks fit in the file (the last may be short).
pub(crate) fn is_ciso(data: &[u8]) -> bool {
    Ciso::parse(data).is_ok()
}

pub(crate) struct Ciso<'a> {
    data: &'a [u8],
    block: u64,
    /// Stored-block index of each logical block, `None` when it is zeros.
    stored: Vec<Option<u32>>,
    /// Logical length: through the last stored block.
    length: u64,
}

impl<'a> Ciso<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < CISO_HEADER || &data[0..4] != b"CISO" {
            return err("not a CISO image");
        }
        let block = u64::from(u32::from_le_bytes(data[4..8].try_into().unwrap()));
        if !(0x8000..=(64 << 20)).contains(&block) || block % 0x8000 != 0 {
            return err("CISO block size is not a multiple of 0x8000 up to 64 MiB");
        }
        let mut stored = Vec::new();
        let mut count = 0u32;
        for &flag in &data[8..CISO_HEADER] {
            match flag {
                0 => stored.push(None),
                1 => {
                    stored.push(Some(count));
                    count += 1;
                }
                _ => return err("CISO block map holds a value other than 0 or 1"),
            }
        }
        let Some(last) = stored.iter().rposition(Option::is_some) else {
            return err("CISO stores no blocks");
        };
        stored.truncate(last + 1);
        // Every stored block but the last must be whole.
        let whole = CISO_HEADER as u64 + u64::from(count - 1) * block;
        if whole >= data.len() as u64 {
            return err("CISO stored blocks run past the end of the file");
        }
        Ok(Self { data, block, length: stored.len() as u64 * block, stored })
    }
}

/// A `nod` partition: the GameCube disc, or a Wii data partition already
/// decrypted, read as a seekable stream whose offset 0 is `boot.bin`.
pub(crate) struct Partition {
    reader: RefCell<Box<dyn PartitionReader>>,
    length: u64,
}

impl Partition {
    pub(crate) fn new(mut reader: Box<dyn PartitionReader>) -> Result<Self> {
        let length = reader
            .seek(SeekFrom::End(0))
            .map_err(|error| ImportError::Bad(format!("disc partition: {error}")))?;
        Ok(Self { reader: RefCell::new(reader), length })
    }
}

/// A disc image: raw bytes, a CISO read block by block, or a `nod` partition.
pub(crate) enum Disc<'a> {
    Raw(&'a [u8]),
    Ciso(Ciso<'a>),
    Partition(Partition),
}

impl Disc<'_> {
    fn len(&self) -> u64 {
        match self {
            Disc::Raw(data) => data.len() as u64,
            Disc::Ciso(ciso) => ciso.length,
            Disc::Partition(partition) => partition.length,
        }
    }

    /// `len` bytes at disc offset `off`; an absent CISO block reads as zeros.
    fn read(&self, off: u64, len: usize) -> Result<Vec<u8>> {
        let end = off
            .checked_add(len as u64)
            .filter(|end| *end <= self.len())
            .ok_or_else(|| ImportError::Bad("disc read outside the image".into()))?;
        match self {
            Disc::Raw(data) => Ok(data[off as usize..end as usize].to_vec()),
            Disc::Partition(partition) => {
                let mut reader = partition.reader.borrow_mut();
                let mut out = vec![0u8; len];
                reader
                    .seek(SeekFrom::Start(off))
                    .and_then(|_| reader.read_exact(&mut out))
                    .map_err(|error| ImportError::Bad(format!("disc read at {off:#x}: {error}")))?;
                Ok(out)
            }
            Disc::Ciso(ciso) => {
                let mut out = Vec::with_capacity(len);
                let mut at = off;
                while at < end {
                    let index = (at / ciso.block) as usize;
                    let inner = at % ciso.block;
                    let take = (ciso.block - inner).min(end - at) as usize;
                    match ciso.stored[index] {
                        None => out.resize(out.len() + take, 0),
                        Some(slot) => {
                            let start = CISO_HEADER as u64 + u64::from(slot) * ciso.block + inner;
                            let have = (ciso.data.len() as u64).saturating_sub(start).min(take as u64) as usize;
                            // Only the last stored block may be short; its
                            // missing tail was zeros in the source image.
                            if have < take && index + 1 != ciso.stored.len() {
                                return err("CISO stored block is truncated");
                            }
                            out.extend_from_slice(&ciso.data[start as usize..start as usize + have]);
                            out.resize(out.len() + take - have, 0);
                        }
                    }
                    at += take as u64;
                }
                Ok(out)
            }
        }
    }
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// One file of the disc's file system.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FstFile {
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

struct Boot {
    dol_offset: u64,
    fst_offset: u64,
    fst_size: u64,
    /// Wii partition: FST file offsets are stored shifted right by two.
    wii: bool,
}

fn boot(disc: &Disc) -> Result<Boot> {
    let header = disc.read(0, 0x440)?;
    let wii = be32(&header, 0x18) == WII_MAGIC;
    if !wii && be32(&header, 0x1c) != GC_MAGIC {
        return err("not a GameCube or Wii disc: magic word 0xc2339f3d missing at 0x1c");
    }
    let shift = if wii { 2 } else { 0 };
    Ok(Boot {
        dol_offset: u64::from(be32(&header, 0x420)) << shift,
        fst_offset: u64::from(be32(&header, 0x424)) << shift,
        fst_size: u64::from(be32(&header, 0x428)) << shift,
        wii,
    })
}

/// Every file in the FST, with its full path from the root.
fn files(disc: &Disc, boot: &Boot) -> Result<Vec<FstFile>> {
    if boot.fst_size < 12 || boot.fst_size > MAX_FST {
        return err("FST size is outside 12 bytes..64 MiB");
    }
    let fst = disc.read(boot.fst_offset, boot.fst_size as usize)?;
    if fst[0] != 1 {
        return err("FST root entry is not a directory");
    }
    let count = be32(&fst, 8) as usize;
    let table = count
        .checked_mul(12)
        .filter(|table| *table <= fst.len() && count >= 1)
        .ok_or_else(|| ImportError::Bad("FST entry count does not fit its size".into()))?;
    let name_at = |offset: usize| -> Result<&str> {
        let tail = fst
            .get(table + offset..)
            .ok_or_else(|| ImportError::Bad("FST name outside the string table".into()))?;
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        // Names are ASCII or Shift-JIS; a path is a label, not a key, so a
        // lossy view is enough.
        Ok(std::str::from_utf8(&tail[..end]).unwrap_or("?"))
    };
    let mut out = Vec::new();
    // (name, index one past the directory's last child)
    let mut dirs: Vec<(&str, usize)> = Vec::new();
    for index in 1..count {
        while dirs.last().is_some_and(|&(_, end)| index >= end) {
            dirs.pop();
        }
        let entry = &fst[index * 12..index * 12 + 12];
        let name = name_at(u32::from_be_bytes([0, entry[1], entry[2], entry[3]]) as usize)?;
        let (a, b) = (be32(entry, 4), be32(entry, 8));
        if entry[0] == 1 {
            if (b as usize) < index + 1 || b as usize > count {
                return err("FST directory range is malformed");
            }
            dirs.push((name, b as usize));
        } else {
            let mut path = String::new();
            for (dir, _) in &dirs {
                path.push_str(dir);
                path.push('/');
            }
            path.push_str(name);
            let offset = u64::from(a) << if boot.wii { 2 } else { 0 };
            out.push(FstFile { path, offset, size: u64::from(b) });
        }
    }
    Ok(out)
}

/// The byte length of a DOL whose header is `header`: its furthest section.
fn dol_length(header: &[u8]) -> Result<usize> {
    if header.len() < 0xe4 {
        return err("truncated DOL header");
    }
    let mut end = 0xe4u64;
    for index in 0..18 {
        let offset = u64::from(be32(header, index * 4));
        let size = u64::from(be32(header, 0x90 + index * 4));
        if size != 0 {
            end = end.max(offset + size);
        }
    }
    usize::try_from(end).map_err(|_| ImportError::Bad("DOL length overflow".into()))
}

fn is_rel_name(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".rel") || lower.ends_with(".rel.szs")
}

/// A file that may be an archive worth opening for the RELs inside: games
/// pack theirs as `RELS.arc` (Wind Waker, Twilight Princess) or `rels.arc`
/// (Skyward Sword), plain or Yaz0-wrapped (`.szs`). The magic decides.
fn is_archive_name(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".arc", ".szs", ".u8", ".rarc"].iter().any(|ext| lower.ends_with(ext))
}

/// `foresta` for `files/foresta.rel.szs`.
fn module_name(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let lower = file.to_ascii_lowercase();
    let stem = lower
        .strip_suffix(".szs")
        .unwrap_or(&lower)
        .strip_suffix(".rel")
        .unwrap_or(&lower);
    file[..stem.len()].to_string()
}

/// How much of an archive file a first look reads; its directory is
/// usually well inside it.
const PROBE: usize = 1 << 16;
/// Larger than any archive a console loads whole.
const MAX_ARCHIVE: u64 = 512 << 20;

/// The REL members of the archive `file`, read from its directory alone:
/// `None` when the file is no archive or lists no REL, so the hundreds of
/// model and sound archives of a disc cost one small read each instead of
/// being unpacked. A Yaz0-wrapped archive is decoded only as far as its
/// directory reaches.
fn rel_members(disc: &Disc, file: &FstFile) -> Option<Vec<archive::Member>> {
    let size = usize::try_from(file.size).ok()?;
    if size < 0x20 || file.size > MAX_ARCHIVE {
        return None;
    }
    let mut take = size.min(PROBE);
    loop {
        let head = disc.read(file.offset, take).ok()?;
        let more = take < size;
        let directory = if yaz0::is_yaz0(&head) {
            let (first, ready) = yaz0::decompress_prefix(&head, 0x20).ok()?;
            if !ready || first.len() < 0x20 {
                if more {
                    take = (take * 4).min(size);
                    continue;
                }
                return None;
            }
            let need = archive::directory_len(&first)?;
            let (directory, ready) = yaz0::decompress_prefix(&head, need).ok()?;
            if !ready && more {
                take = (take * 4).min(size);
                continue;
            }
            directory
        } else {
            let need = archive::directory_len(&head)?;
            if need > head.len() && more {
                take = need.max(take * 2).min(size);
                continue;
            }
            head[..need.min(head.len())].to_vec()
        };
        let members: Vec<archive::Member> = archive::members(&directory)
            .ok()?
            .into_iter()
            .filter(|member| is_rel_name(&member.path))
            .collect();
        return (!members.is_empty()).then_some(members);
    }
}

/// Reads the RELs `members` names out of the archive `file`.
fn archive_rels(
    disc: &Disc,
    file: &FstFile,
    members: &[archive::Member],
    rels: &mut Vec<DiscRel>,
    notes: &mut Vec<String>,
) -> usize {
    let before = rels.len();
    let stored = match disc.read(file.offset, file.size as usize) {
        Ok(stored) => stored,
        Err(error) => {
            notes.push(format!("{}: {error}", file.path));
            return 0;
        }
    };
    let packed = yaz0::is_yaz0(&stored);
    let whole = if packed {
        match yaz0::decompress(&stored) {
            Ok(whole) => whole,
            Err(error) => {
                notes.push(format!("{}: {error}", file.path));
                return 0;
            }
        }
    } else {
        stored
    };
    for member in members {
        let id = format!("{}:{}", file.path, member.path);
        let mut bytes = match archive::extract(&whole, member) {
            Ok(bytes) => bytes.to_vec(),
            Err(error) => {
                notes.push(format!("{id}: {error}"));
                continue;
            }
        };
        if yaz0::is_yaz0(&bytes) {
            match yaz0::decompress(&bytes) {
                Ok(unpacked) => bytes = unpacked,
                Err(error) => {
                    notes.push(format!("{id}: {error}"));
                    continue;
                }
            }
        }
        if !rel::is_rel(&bytes) {
            notes.push(format!("{id}: not a REL"));
            continue;
        }
        rels.push(DiscRel {
            name: module_name(&member.path),
            file_id: id,
            container: file.path.clone(),
            // A plain archive's member sits at a known place on the disc; a
            // Yaz0-wrapped one is only reachable through its stored file.
            file_off: if packed { file.offset } else { file.offset + member.offset as u64 },
            bytes,
        });
    }
    rels.len() - before
}

/// What a disc carries that a decompilation project needs as files.
pub(crate) struct Collected {
    pub dol_offset: u64,
    pub dol: Vec<u8>,
    pub rels: Vec<DiscRel>,
    pub notes: Vec<String>,
    /// Archives that held RELs, and how many RELs came out of them.
    pub archives: usize,
    pub in_archives: usize,
    /// `boot.bin`: game id (0x00..0x06), disc number, version, title (0x20..0x60).
    pub header: Vec<u8>,
    pub wii: bool,
}

/// The boot DOL and every REL of the disc, the file system's and those
/// packed in archives, in file-system order.
fn collect(disc: &Disc) -> Result<Collected> {
    let boot = boot(disc)?;
    let header = disc.read(0, 0x60)?;
    let head = disc.read(boot.dol_offset, 0xe4)?;
    let dol = disc.read(boot.dol_offset, dol_length(&head)?)?;
    let listing = files(disc, &boot)?;
    let mut rels = Vec::new();
    let mut notes = Vec::new();
    let (mut archives, mut in_archives) = (0usize, 0usize);
    for file in &listing {
        if !is_rel_name(&file.path) {
            if is_archive_name(&file.path)
                && let Some(members) = rel_members(disc, file) {
                    archives += 1;
                    in_archives += archive_rels(disc, file, &members, &mut rels, &mut notes);
                }
            continue;
        }
        if file.size > MAX_REL {
            notes.push(format!("{}: {} bytes is larger than a console can hold", file.path, file.size));
            continue;
        }
        let mut bytes = disc.read(file.offset, file.size as usize)?;
        if yaz0::is_yaz0(&bytes) {
            match yaz0::decompress(&bytes) {
                Ok(unpacked) => bytes = unpacked,
                Err(error) => {
                    notes.push(format!("{}: {error}", file.path));
                    continue;
                }
            }
        }
        if !rel::is_rel(&bytes) {
            notes.push(format!("{}: not a REL", file.path));
            continue;
        }
        rels.push(DiscRel {
            name: module_name(&file.path),
            file_id: file.path.clone(),
            container: file.path.rsplit_once('/').map_or("", |(dir, _)| dir).to_string(),
            file_off: file.offset,
            bytes,
        });
    }
    Ok(Collected { dol_offset: boot.dol_offset, dol, rels, notes, archives, in_archives, header, wii: boot.wii })
}

/// The DOL with the disc's RELs linked beside it: the RELs the file system
/// lists, and those packed in archives. RELs that share a module id are
/// programs of their own (`rel::attach`).
fn import_disc(disc: &Disc) -> Result<Vec<(String, NativeImport)>> {
    let found = collect(disc)?;
    let image = super::dol::import(&found.dol)?;
    let mut programs = rel::attach(image, "sys/main.dol", found.dol_offset, &found.rels)?;
    let main = &mut programs[0].1;
    if found.archives > 0 {
        main.diagnose(
            romwright_model::DiagnosticSeverity::Info,
            "disc",
            format!("{} REL file(s) read from {} archive(s) (U8/RARC, plain or Yaz0)", found.in_archives, found.archives),
        );
    }
    for note in found.notes {
        main.diagnose(romwright_model::DiagnosticSeverity::Partial, "disc", format!("REL file skipped: {note}"));
    }
    Ok(programs)
}

/// One REL taken off a disc, decompressed, with where it lived.
#[derive(Debug, Clone)]
pub struct DiscRelFile {
    /// Module name: the file's stem (`d_a_obj_test`).
    pub name: String,
    /// The disc file the bytes came from (`rel/Final/Release/x.rel.szs`) or
    /// `archive:member` for a REL packed in an archive.
    pub source: String,
    /// The directory or archive that holds it.
    pub container: String,
    pub bytes: Vec<u8>,
}

/// The boot DOL and RELs of a GameCube or Wii disc as files, plus the boot
/// header's identity fields: what `new-project` writes into `orig/`.
#[derive(Debug, Clone)]
pub struct DiscFiles {
    /// Six-character game id (`GPVE01`).
    pub game_id: String,
    pub title: String,
    pub disc_number: u8,
    pub disc_version: u8,
    pub wii: bool,
    pub dol: Vec<u8>,
    pub rels: Vec<DiscRelFile>,
    pub notes: Vec<String>,
}

fn disc_files(disc: &Disc) -> Result<DiscFiles> {
    let found = collect(disc)?;
    let text = |bytes: &[u8]| {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).trim().to_string()
    };
    Ok(DiscFiles {
        game_id: text(&found.header[..6]),
        title: text(&found.header[0x20..0x60]),
        disc_number: found.header[6],
        disc_version: found.header[7],
        wii: found.wii,
        dol: found.dol,
        rels: found
            .rels
            .into_iter()
            .map(|rel| DiscRelFile { name: rel.name, source: rel.file_id, container: rel.container, bytes: rel.bytes })
            .collect(),
        notes: found.notes,
    })
}

/// The boot DOL and RELs of a raw GameCube image or a GameCube CISO; `None`
/// when `data` is neither (a Wii-shaped disc goes through `wii::extract`).
pub(crate) fn extract_gc(data: &[u8]) -> Option<Result<DiscFiles>> {
    if is_ciso(data) {
        if ciso_is_wii(data) {
            return None;
        }
        return Some(Ciso::parse(data).and_then(|ciso| disc_files(&Disc::Ciso(ciso))));
    }
    let disc = Disc::Raw(data);
    let ready = boot(&disc).ok().is_some_and(|boot| boot.fst_offset >= 0x460 && files(&disc, &boot).is_ok());
    ready.then(|| disc_files(&disc))
}

/// The files of a disc read through `nod` (a Wii data partition, or any
/// GameCube disc `nod` opens).
pub(crate) fn extract_partition(reader: Box<dyn PartitionReader>) -> Result<DiscFiles> {
    disc_files(&Disc::Partition(Partition::new(reader)?))
}

/// Imports a CISO image: the boot DOL and its RELs as one program. A Wii
/// disc's CISO goes through `nod`, which decrypts its data partition.
pub(crate) fn import_ciso(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    if ciso_is_wii(data) {
        return super::wii::import_nod(data);
    }
    import_disc(&Disc::Ciso(Ciso::parse(data)?))
}

/// Imports a disc read through `nod`: the data partition (a Wii disc's
/// decrypted one, or the whole GameCube disc) holding the boot DOL and RELs.
pub(crate) fn import_partition(reader: Box<dyn PartitionReader>) -> Result<Vec<(String, NativeImport)>> {
    import_disc(&Disc::Partition(Partition::new(reader)?))
}

/// True when a CISO's logical disc is a Wii disc, which `nod` reads.
pub(crate) fn ciso_is_wii(data: &[u8]) -> bool {
    Ciso::parse(data)
        .and_then(|ciso| Disc::Ciso(ciso).read(0x18, 4))
        .is_ok_and(|word| be32(&word, 0) == WII_MAGIC)
}

/// Imports a raw GameCube image through its FST. `None` when the image has
/// no GameCube magic or no usable FST, so a caller can keep its older
/// header-only reading of such a file.
pub(crate) fn import_gc_raw(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    let disc = Disc::Raw(data);
    let ready = boot(&disc).ok().is_some_and(|boot| {
        boot.fst_offset >= 0x460 && files(&disc, &boot).is_ok()
    });
    ready.then(|| import_disc(&disc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(out: &mut [u8], at: usize, value: u32) {
        out[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// An FST over `(path, offset, size)`: directories are created in the
    /// order their first file appears, files grouped under them.
    fn fst(entries: &[(&str, u32, u32)]) -> Vec<u8> {
        // root -> "sys" and "files"; every path here is `<dir>/<name>`.
        let mut dirs: Vec<&str> = Vec::new();
        for (path, _, _) in entries {
            let dir = path.split('/').next().unwrap();
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        let mut names: Vec<u8> = Vec::new();
        let name_of = |name: &str, names: &mut Vec<u8>| {
            let at = names.len();
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            at as u32
        };
        let mut rows: Vec<[u32; 3]> = Vec::new();
        let total = 1 + dirs.len() + entries.len();
        rows.push([0x0100_0000, 0, total as u32]);
        for dir in &dirs {
            let at = rows.len();
            let dir_name = name_of(dir, &mut names);
            rows.push([0x0100_0000 | dir_name, 0, 0]);
            for (path, offset, size) in entries.iter().filter(|(p, _, _)| p.starts_with(&format!("{dir}/"))) {
                let file = name_of(path.split_once('/').unwrap().1, &mut names);
                rows.push([file, *offset, *size]);
            }
            rows[at][2] = rows.len() as u32;
        }
        let mut out = Vec::new();
        for row in &rows {
            for word in row {
                out.extend_from_slice(&word.to_be_bytes());
            }
        }
        out.extend_from_slice(&names);
        out
    }

    /// A DOL with one text section of `words` at 0x80003100.
    fn dol(words: &[u32]) -> Vec<u8> {
        let size = words.len() * 4;
        let mut out = vec![0u8; 0x100 + size];
        put32(&mut out, 0, 0x100);
        put32(&mut out, 0x48, 0x8000_3100);
        put32(&mut out, 0x90, size as u32);
        put32(&mut out, 0xe0, 0x8000_3100);
        for (index, word) in words.iter().enumerate() {
            put32(&mut out, 0x100 + index * 4, *word);
        }
        out
    }

    /// Yaz0 with every chunk a literal: valid, if not smaller.
    fn yaz0_literals(data: &[u8]) -> Vec<u8> {
        let mut out = b"Yaz0".to_vec();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0; 8]);
        for group in data.chunks(8) {
            out.push((0xffu16 << (8 - group.len())) as u8);
            out.extend_from_slice(group);
        }
        out
    }

    fn rel_bytes() -> Vec<u8> {
        // Module 1: text of `bl 0` and `blr`, a data word; the `bl` is
        // relocated to the DOL's 0x80003100.
        let mut out = Vec::new();
        let (text_at, data_at, rel_at) = (0x60usize, 0x68usize, 0x6cusize);
        for value in [1u32, 0, 0, 3, 0x48, 0, 0, 2, 0, rel_at as u32, (rel_at + 0x18) as u32, 8] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&[0, 0, 0, 0]);
        for value in [0u32, 0, 0, 4, 4] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        assert_eq!(out.len(), 0x48);
        for value in [0u32, 0, (text_at | 1) as u32, 8, data_at as u32, 4] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&0x4800_0001u32.to_be_bytes());
        out.extend_from_slice(&0x4e80_0020u32.to_be_bytes());
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(out.len(), rel_at);
        // section 1, REL24 at +0 -> module 0 0x80003100; END
        for (offset, kind, section, addend) in [(0u16, 202u8, 1u8, 0u32), (0, 10, 0, 0x8000_3100), (0, 203, 0, 0)] {
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&[kind, section]);
            out.extend_from_slice(&addend.to_be_bytes());
        }
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(rel_at as u32).to_be_bytes());
        out
    }

    /// A disc: boot header, DOL, FST, `files/mod.rel.szs`.
    fn disc_image() -> Vec<u8> {
        layout(false)
    }

    /// The same disc laid out as a Wii data partition's decrypted stream:
    /// Wii magic at 0x18, and the DOL offset, FST offset, FST size and file
    /// offsets stored shifted right by two.
    fn wii_partition_image() -> Vec<u8> {
        layout(true)
    }

    fn layout(wii: bool) -> Vec<u8> {
        let dol = dol(&[0x4e80_0020, 0x6000_0000, 0x4e80_0020]);
        let szs = yaz0_literals(&rel_bytes());
        let dol_at = 0x2000usize;
        let szs_at = dol_at + 0x200;
        let fst_at = (szs_at + szs.len() + 0x20 + 3) & !3;
        let shift = if wii { 2 } else { 0 };
        let mut table = fst(&[
            ("sys/main.dol", (dol_at >> shift) as u32, dol.len() as u32),
            ("files/mod.rel.szs", (szs_at >> shift) as u32, szs.len() as u32),
        ]);
        // A Wii FST size is stored in units of four bytes.
        table.resize(table.len().next_multiple_of(4), 0);
        let mut out = vec![0u8; fst_at + table.len()];
        put32(&mut out, if wii { 0x18 } else { 0x1c }, if wii { WII_MAGIC } else { GC_MAGIC });
        put32(&mut out, 0x420, (dol_at >> shift) as u32);
        put32(&mut out, 0x424, (fst_at >> shift) as u32);
        put32(&mut out, 0x428, (table.len() >> shift) as u32);
        out[dol_at..dol_at + dol.len()].copy_from_slice(&dol);
        out[szs_at..szs_at + szs.len()].copy_from_slice(&szs);
        out[fst_at..].copy_from_slice(&table);
        out
    }

    /// Packs `image` into a CISO with the given block size, dropping every
    /// all-zero block.
    fn ciso(image: &[u8], block: usize) -> Vec<u8> {
        let mut header = vec![0u8; CISO_HEADER];
        header[0..4].copy_from_slice(b"CISO");
        header[4..8].copy_from_slice(&(block as u32).to_le_bytes());
        let mut body = Vec::new();
        for (index, chunk) in image.chunks(block).enumerate() {
            if chunk.iter().any(|&b| b != 0) {
                header[8 + index] = 1;
                body.extend_from_slice(chunk);
            }
        }
        header.extend_from_slice(&body);
        header
    }

    /// `rel_bytes` with another module id.
    fn rel_with_id(id: u32) -> Vec<u8> {
        let mut out = rel_bytes();
        out[0..4].copy_from_slice(&id.to_be_bytes());
        out
    }

    /// `rel_with_id` whose data word differs, so same-id RELs are not copies.
    fn rel_variant(id: u32, data: u8) -> Vec<u8> {
        let mut out = rel_with_id(id);
        let at = out.windows(4).position(|w| w == [0xde, 0xad, 0xbe, 0xef]).unwrap();
        out[at] = data;
        out
    }

    /// A GameCube disc: boot header, a DOL, then `files` (path, bytes) in order.
    fn disc_of(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let dol = dol(&[0x4e80_0020, 0x6000_0000, 0x4e80_0020]);
        let dol_at = 0x2000usize;
        let mut at = dol_at + 0x200;
        let mut placed = Vec::new();
        for (path, bytes) in files {
            placed.push((*path, at, bytes.len()));
            at = (at + bytes.len() + 0x1f) & !0x1f;
        }
        let mut entries = vec![("sys/main.dol", dol_at as u32, dol.len() as u32)];
        entries.extend(placed.iter().map(|&(path, at, len)| (path, at as u32, len as u32)));
        let table = fst(&entries);
        let fst_at = at;
        let mut out = vec![0u8; fst_at + table.len()];
        put32(&mut out, 0x1c, GC_MAGIC);
        put32(&mut out, 0x420, dol_at as u32);
        put32(&mut out, 0x424, fst_at as u32);
        put32(&mut out, 0x428, table.len() as u32);
        out[dol_at..dol_at + dol.len()].copy_from_slice(&dol);
        for ((_, bytes), &(_, at, len)) in files.iter().zip(&placed) {
            out[at..at + len].copy_from_slice(bytes);
        }
        out[fst_at..].copy_from_slice(&table);
        out
    }

    fn module_rows(imp: &NativeImport) -> Vec<(String, String)> {
        imp.modules.iter().map(|m| (m.name.clone(), m.file_id.clone())).collect()
    }

    #[test]
    fn rels_in_rarc_and_u8_archives_link_like_file_system_rels() {
        use super::archive::tests::{build_rarc, build_u8};
        let packed = yaz0_literals(&rel_with_id(5));
        let rarc = build_rarc("rels", &[("mmem", "a.rel", &rel_with_id(2)), ("amem", "b.rel", &rel_with_id(3)), ("", "notes.txt", b"hi")]);
        let u8_arc = build_u8(&[("rels/c.rel", &rel_with_id(4)), ("rels/d.rel.szs", &packed), ("rels/x.bin", b"zz")]);
        // Yaz0 around the whole archive, as TP and TWW pack theirs.
        let wrapped = yaz0_literals(&build_rarc("rels", &[("m", "e.rel", &rel_with_id(6))]));
        let image = disc_of(&[
            ("files/mod.rel", rel_with_id(1)),
            ("files/RELS.arc", rarc.clone()),
            ("files/rels.arc", u8_arc),
            ("files/Stage.szs", wrapped),
            // Not an archive, though named like one.
            ("files/model.arc", vec![0x42; 0x80]),
        ]);
        let images = import_gc_raw(&image).unwrap().unwrap();
        assert_eq!(images.len(), 1);
        let imp = &images[0].1;
        let rows = module_rows(imp);
        assert_eq!(
            rows.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            ["main.dol", "mod", "a", "b", "c", "d", "e"],
            "{rows:?}"
        );
        assert_eq!(rows[2].1, "files/RELS.arc:rels/mmem/a.rel");
        assert_eq!(rows[3].1, "files/RELS.arc:rels/amem/b.rel");
        assert_eq!(rows[5].1, "files/rels.arc:rels/d.rel.szs");
        assert_eq!(rows[6].1, "files/Stage.szs:rels/m/e.rel");
        // A member of a plain archive is located on the disc; one of a
        // Yaz0-wrapped archive only through the stored file.
        let listing = files(&Disc::Raw(&image), &boot(&Disc::Raw(&image)).unwrap()).unwrap();
        let at = |path: &str| listing.iter().find(|f| f.path == path).unwrap().offset;
        let inner = archive::members(&rarc).unwrap();
        let a = inner.iter().find(|m| m.path.ends_with("a.rel")).unwrap();
        assert_eq!(imp.modules[2].file_off, at("files/RELS.arc") + a.offset as u64);
        assert_eq!(imp.modules[6].file_off, at("files/Stage.szs"));
        // Module-id order places them one after another from the base, and
        // their `bl` reaches the DOL as in a loose REL.
        let loads: Vec<u64> = imp.modules[1..].iter().map(|m| m.load_vaddr).collect();
        assert!(loads.windows(2).all(|pair| pair[0] < pair[1]), "{loads:x?}");
        let want = 0x4800_0001u32 | 0x8000_3100u32.wrapping_sub(0x8000_5120) & 0x03ff_fffc;
        assert_eq!(&imp.mappings[1].bytes[0..4], &want.to_be_bytes());
        assert!(imp.diagnostics.iter().any(|d| d.message.contains("5 REL file(s) read from 3 archive(s)")), "{:?}", imp.diagnostics);
        // The same disc with the archives unpacked as loose files is the same program.
        let loose = disc_of(&[
            ("files/mod.rel", rel_with_id(1)),
            ("files/a.rel", rel_with_id(2)),
            ("files/b.rel", rel_with_id(3)),
            ("files/c.rel", rel_with_id(4)),
            ("files/d.rel", rel_with_id(5)),
            ("files/e.rel", rel_with_id(6)),
        ]);
        let want = import_gc_raw(&loose).unwrap().unwrap();
        assert_eq!(imp.mappings, want[0].1.mappings);
    }

    #[test]
    fn an_archive_directory_longer_than_the_first_look_is_still_read() {
        use super::archive::tests::build_rarc;
        // 3,000 members with 30-byte names put the directory past 64 KiB,
        // in both a plain and a Yaz0-wrapped archive; the REL is the last.
        let names: Vec<String> = (0..3000).map(|n| format!("model_{n:04}_with_a_long_name.bti")).collect();
        let mut members: Vec<(&str, &str, &[u8])> = names.iter().map(|n| ("tex", n.as_str(), &b"."[..])).collect();
        let rel = rel_with_id(7);
        members.push(("tex", "late.rel", &rel));
        let plain = build_rarc("res", &members);
        assert!(archive::directory_len(&plain).unwrap() > PROBE);
        for stored in [plain.clone(), yaz0_literals(&plain)] {
            let image = disc_of(&[("files/big.arc", stored)]);
            let imp = &import_gc_raw(&image).unwrap().unwrap()[0].1;
            assert_eq!(module_rows(imp)[1].0, "late");
        }
    }

    #[test]
    fn rels_sharing_a_module_id_are_overlay_programs_not_a_merge() {
        let image = disc_of(&[
            ("files/boot.rel", rel_with_id(1)),
            ("files/stay.rel", rel_with_id(9)),
            ("files/game_a.rel", rel_variant(1, 0x11)),
            ("files/dir/game_b.rel.szs", yaz0_literals(&rel_variant(1, 0x22))),
            // The same file reached twice is one module, not an alternative.
            ("files/copy/stay.rel", rel_with_id(9)),
            // Two names holding the same bytes are two modules.
            ("files/twin_a.rel", rel_with_id(4)),
            ("files/twin_b.rel", rel_with_id(4)),
            ("files/other/game_a.rel", rel_variant(1, 0x33)),
        ]);
        let programs = import_gc_raw(&image).unwrap().unwrap();
        let suffixes: Vec<&str> = programs.iter().map(|(suffix, _)| suffix.as_str()).collect();
        assert_eq!(suffixes, ["main", "boot", "game_a", "game_b", "game_a_1", "twin_a", "twin_b"]);
        let main = &programs[0].1;
        assert!(main.sibling_call_host);
        assert_eq!(module_rows(main).iter().map(|row| row.0.as_str()).collect::<Vec<_>>(), ["main.dol", "stay"]);
        assert!(main.diagnostics.iter().any(|d| d.message.contains("REL copy not linked again: files/copy/stay.rel is identical to files/stay.rel")));
        assert!(main.diagnostics.iter().any(|d| d.message.contains("6 REL file(s) share a module id")));
        // Each alternative holds only itself, from the base the merged
        // modules start at, and sees the DOL through its relocations.
        let base = main.modules[1].load_vaddr;
        for (suffix, imp) in &programs[1..] {
            assert_eq!(imp.modules.len(), 1, "{suffix}");
            assert_eq!(imp.modules[0].load_vaddr, 0x8000_5120, "{suffix}");
            assert_eq!(base, 0x8000_5120);
            assert_eq!(imp.mappings[0].vaddr, 0x8000_5120);
            assert!(!imp.sibling_call_host);
            assert_eq!(imp.format, "dol");
            let want = 0x4800_0001u32 | 0x8000_3100u32.wrapping_sub(0x8000_5120) & 0x03ff_fffc;
            assert_eq!(&imp.mappings[0].bytes[0..4], &want.to_be_bytes(), "{suffix}");
        }
        // The data word that tells the variants apart is each program's own.
        let tag = |program: usize| programs[program].1.mappings[1].bytes[0];
        assert_eq!((tag(2), tag(3), tag(4)), (0x11, 0x22, 0x33));
        assert!(programs[1].1.diagnostics.iter().any(|d| d.message.contains("module id 1 is shared by 4 REL files")));
    }

    #[test]
    fn the_biggest_set_keeps_its_ids_and_a_stub_of_a_module_is_an_overlay() {
        use super::archive::tests::build_u8;
        // Skyward Sword's shape: `rels.arc` holds the game's modules; a loose
        // copy of one, and a tiny stub of another, sit elsewhere on the disc.
        let arc = build_u8(&[
            ("rels/p.rel", &rel_with_id(1)),
            ("rels/q.rel", &rel_with_id(2)),
            ("rels/r.rel", &rel_with_id(3)),
        ]);
        let image = disc_of(&[
            ("files/q.rel", rel_with_id(2)),
            ("files/stub/p.rel", rel_variant(1, 0x55)),
            ("files/rels.arc", arc),
        ]);
        let programs = import_gc_raw(&image).unwrap().unwrap();
        let suffixes: Vec<&str> = programs.iter().map(|(suffix, _)| suffix.as_str()).collect();
        // The stub keeps its file's name in its module row; its program's name
        // is not the resident module's.
        assert_eq!(suffixes, ["main", "p_1"]);
        let main = &programs[0].1;
        let rows = module_rows(main);
        assert_eq!(
            rows,
            [
                ("main.dol".to_string(), "sys/main.dol".to_string()),
                ("p".into(), "files/rels.arc:rels/p.rel".into()),
                ("q".into(), "files/rels.arc:rels/q.rel".into()),
                ("r".into(), "files/rels.arc:rels/r.rel".into()),
            ]
        );
        assert!(main.diagnostics.iter().any(|d| d.message.contains("files/q.rel is identical to files/rels.arc:rels/q.rel")), "{:?}", main.diagnostics);
        let stub = &programs[1].1;
        assert_eq!(module_rows(stub), [("p".to_string(), "files/stub/p.rel".to_string())]);
        assert_eq!(stub.mappings[1].bytes[0], 0x55);
    }

    #[test]
    fn an_overlay_reaches_a_resident_module_through_its_main_program_address() {
        use super::rel::tests as rel_tests;
        let image = disc_of(&[
            ("files/resident.rel", rel_tests::module_importing(2, &[])),
            ("files/a.rel", rel_tests::module_importing(5, &[(2, 0x10)])),
            ("files/b.rel", rel_tests::module_importing(5, &[(2, 0x20)])),
        ]);
        let programs = import_gc_raw(&image).unwrap().unwrap();
        assert_eq!(programs.len(), 3);
        let resident_text = programs[0].1.modules[1].load_vaddr;
        // Each overlay's data word names the resident module's text.
        let word = |imp: &NativeImport| u32::from_be_bytes(imp.mappings[1].bytes[4..8].try_into().unwrap());
        assert_eq!(u64::from(word(&programs[1].1)), resident_text + 0x10);
        assert_eq!(u64::from(word(&programs[2].1)), resident_text + 0x20);
    }

    #[test]
    fn ciso_reads_stored_absent_and_short_final_blocks() {
        let mut image = vec![0u8; 0x8000 * 3 + 100];
        image[5] = 7;
        image[0x8000 * 2 + 3] = 9;
        image[0x8000 * 3 + 99] = 5;
        let packed = ciso(&image, 0x8000);
        assert!(is_ciso(&packed));
        let disc = Disc::Ciso(Ciso::parse(&packed).unwrap());
        // Spans the stored block 0, the absent block 1, and stored block 2.
        assert_eq!(disc.read(0, 0x8000 * 3).unwrap(), image[..0x8000 * 3]);
        // The last block is stored short: its tail reads as zeros.
        assert_eq!(disc.read(0x8000 * 3, 100).unwrap(), image[0x8000 * 3..]);
        assert_eq!(disc.len(), 0x8000 * 4);
        assert!(disc.read(0x8000 * 4, 1).is_err());
        // Absent block in the middle of a read.
        assert_eq!(disc.read(0x7fff, 3).unwrap(), [0, 0, 0]);
    }

    #[test]
    fn ciso_refuses_a_bad_map_a_bad_block_size_and_truncation() {
        let good = ciso(&[1u8; 0x8000 * 2], 0x8000);
        assert!(is_ciso(&good));
        let mut bad = good.clone();
        bad[9] = 2;
        assert!(!is_ciso(&bad));
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&0x1234u32.to_le_bytes());
        assert!(!is_ciso(&bad));
        assert!(!is_ciso(&good[..CISO_HEADER + 0x7000]));
        assert!(!is_ciso(b"CISO"));
    }

    #[test]
    fn fst_lists_nested_files_with_paths() {
        let image = disc_image();
        let disc = Disc::Raw(&image);
        let boot = boot(&disc).unwrap();
        let listing = files(&disc, &boot).unwrap();
        let paths: Vec<&str> = listing.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["sys/main.dol", "files/mod.rel.szs"]);
        assert_eq!(listing[0].offset, 0x2000);
        assert_eq!(module_name("files/mod.rel.szs"), "mod");
        assert_eq!(module_name("Foresta.REL"), "Foresta");
        // A disc without the GameCube magic is not read as one.
        let mut wii = image.clone();
        put32(&mut wii, 0x1c, 0);
        assert!(boot_of(&wii).is_err());
    }

    fn boot_of(image: &[u8]) -> Result<Boot> {
        boot(&Disc::Raw(image))
    }

    #[test]
    fn a_disc_imports_as_one_program_with_dol_and_rel_modules() {
        for packed in [disc_image(), ciso(&disc_image(), 0x8000)] {
            let images = if is_ciso(&packed) {
                import_ciso(&packed).unwrap()
            } else {
                import_gc_raw(&packed).unwrap().unwrap()
            };
            assert_eq!(images.len(), 1);
            let (suffix, imp) = &images[0];
            assert!(suffix.is_empty());
            // The DOL text, then the REL's text and data (no bss section).
            let starts: Vec<u64> = imp.mappings.iter().map(|m| m.vaddr).collect();
            assert_eq!(starts[0], 0x8000_3100);
            // Fallback base: DOL end 0x8000_310c + 0x2000, 32-aligned.
            assert_eq!(starts[1..], [0x8000_5120, 0x8000_5140]);
            // `bl` relocated to the DOL's first word from 0x80005120.
            let rel_text = &imp.mappings[1].bytes;
            let want = 0x4800_0001u32 | 0x8000_3100u32.wrapping_sub(0x8000_5120) & 0x03ff_fffc;
            assert_eq!(&rel_text[0..4], &want.to_be_bytes());
            assert_eq!(imp.mappings[2].bytes, [0xde, 0xad, 0xbe, 0xef]);
            let modules: Vec<(&str, &str, u64)> =
                imp.modules.iter().map(|m| (m.name.as_str(), m.kind.as_str(), m.load_vaddr)).collect();
            assert_eq!(modules, [("main.dol", "dol", 0x8000_3100), ("mod", "rel", 0x8000_5120)]);
            assert_eq!(imp.modules[1].file_id, "files/mod.rel.szs");
            // Where the stored bytes begin in the disc: the DOL, and the
            // Yaz0-packed REL that follows it (`disc_image` lays them out).
            assert_eq!((imp.modules[0].file_off, imp.modules[1].file_off), (0x2000, 0x2200));
            assert_eq!(imp.format, "dol");
        }
    }

    #[test]
    fn rels_that_cannot_be_read_are_reported_not_fatal() {
        let mut image = disc_image();
        // Corrupt the Yaz0 stream's declared size past what it can hold.
        let at = 0x2200;
        assert_eq!(&image[at..at + 4], b"Yaz0");
        image[at + 4..at + 8].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        let images = import_gc_raw(&image).unwrap().unwrap();
        let imp = &images[0].1;
        assert_eq!(imp.mappings.len(), 1);
        assert!(imp.modules.is_empty());
        assert!(imp.diagnostics.iter().any(|d| d.message.contains("mod.rel.szs")));
    }

    #[test]
    fn dol_length_is_the_furthest_section_end() {
        let image = dol(&[0, 0, 0]);
        assert_eq!(dol_length(&image).unwrap(), 0x10c);
        assert!(dol_length(&image[..0xe0]).is_err());
    }

    #[test]
    fn a_wii_partition_imports_like_the_gamecube_disc_it_mirrors() {
        let wii = wii_partition_image();
        let disc = Disc::Raw(&wii);
        let boot = boot(&disc).unwrap();
        assert!(boot.wii);
        assert_eq!((boot.dol_offset, boot.fst_offset % 4), (0x2000, 0));
        let listing = files(&disc, &boot).unwrap();
        assert_eq!(listing[0].offset, 0x2000);
        assert_eq!(listing[1].offset, 0x2200);
        let via_wii = import_disc(&disc).unwrap();
        let via_gc = import_gc_raw(&disc_image()).unwrap().unwrap();
        assert_eq!(via_wii.len(), 1);
        let (wii_imp, gc_imp) = (&via_wii[0].1, &via_gc[0].1);
        assert_eq!(wii_imp.mappings, gc_imp.mappings);
        let identity = |imp: &NativeImport| -> Vec<_> {
            imp.modules
                .iter()
                .map(|m| (m.name.clone(), m.kind.clone(), m.load_vaddr, m.file_id.clone(), m.file_off))
                .collect()
        };
        assert_eq!(identity(wii_imp), identity(gc_imp));
    }

    /// Writes `image` out as `format` with `nod`'s own encoder.
    fn nod_pack(image: &[u8], format: nod::common::Format, compression: nod::common::Compression) -> Vec<u8> {
        use nod::read::{DiscOptions, DiscReader};
        use nod::write::{DiscWriter, FormatOptions, ProcessOptions};
        let reader = DiscReader::new_stream(Box::new(image.to_vec()), &DiscOptions::default()).unwrap();
        let options = FormatOptions { format, compression, block_size: format.default_block_size() };
        let writer = DiscWriter::new(reader, &options).unwrap();
        let mut out = Vec::new();
        let finalization = writer
            .process(
                |data, _, _| {
                    out.extend_from_slice(&data);
                    Ok(())
                },
                &ProcessOptions::default(),
            )
            .unwrap();
        out[..finalization.header.len()].copy_from_slice(&finalization.header);
        out
    }

    #[test]
    fn rvz_wia_and_wbfs_import_exactly_like_the_iso() {
        use nod::common::{Compression, Format};
        let image = disc_image();
        let want = import_gc_raw(&image).unwrap().unwrap();
        for (format, compression) in [
            (Format::Rvz, Compression::Zstandard(3)),
            (Format::Rvz, Compression::None),
            (Format::Rvz, Compression::Lzma(6)),
            (Format::Wia, Compression::Lzma(6)),
            (Format::Wia, Compression::Lzma2(6)),
            (Format::Wia, Compression::None),
            (Format::Wbfs, Compression::None),
        ] {
            let packed = nod_pack(&image, format, compression);
            assert_ne!(packed, image);
            let got = super::super::wii::import(&packed)
                .unwrap_or_else(|| panic!("{format:?} not dispatched"))
                .unwrap_or_else(|error| panic!("{format:?}/{compression:?}: {error}"));
            assert_eq!(got.len(), 1, "{format:?}");
            assert_eq!(got[0].1.mappings, want[0].1.mappings, "{format:?}/{compression:?}");
            assert_eq!(got[0].1.modules.len(), want[0].1.modules.len());
            for (a, b) in got[0].1.modules.iter().zip(&want[0].1.modules) {
                assert_eq!(
                    (&a.name, &a.kind, a.load_vaddr, &a.file_id, a.file_off),
                    (&b.name, &b.kind, b.load_vaddr, &b.file_id, b.file_off),
                    "{format:?}/{compression:?}"
                );
            }
        }
    }

    #[test]
    fn a_truncated_rvz_is_an_error_not_a_panic() {
        use nod::common::{Compression, Format};
        let packed = nod_pack(&disc_image(), Format::Rvz, Compression::Zstandard(3));
        // A cut header is an error; a cut that only drops unused tail bytes may
        // still read, but no cut may panic.
        for keep in [0x10, 0x60, 0x100] {
            let result = super::super::wii::import(&packed[..keep]).expect("RVZ magic dispatches");
            assert!(result.is_err(), "{keep}");
        }
        for keep in [packed.len() / 2, packed.len() - 1] {
            let _ = super::super::wii::import(&packed[..keep]);
        }
    }

    #[test]
    fn a_ciso_of_a_wii_disc_is_routed_to_nod() {
        // A header-only Wii disc inside a CISO: the logical magic decides.
        let mut image = vec![0u8; 0x8000];
        put32(&mut image, 0x18, WII_MAGIC);
        let packed = ciso(&image, 0x8000);
        assert!(is_ciso(&packed) && ciso_is_wii(&packed));
        assert!(!ciso_is_wii(&ciso(&disc_image(), 0x8000)));
    }
}
