//! GameCube/Wii archives (P3.4b): the two containers first-party games pack
//! their RELs, models and resources into, read far enough to list a member's
//! path and where its bytes sit. The disc importer (`disc.rs`) uses this to
//! reach RELs that are not files of the disc's own file system -- Wind
//! Waker's and Twilight Princess's `RELS.arc` (RARC), Skyward Sword's
//! `rels.arc` (U8).
//!
//! Formats, from the community documentation (the RARC page of the Custom
//! Mario Kart / Luigi's Mansion modding wikis, Wiibrew's "U8 archive"
//! page, YAGCD for the shared big-endian conventions); independent
//! implementation, no upstream code copied. Everything is big-endian.
//!
//! * **U8**: `55 AA 38 2D`, the offset of the node table (`0x20`), the byte
//!   size of node table plus string pool, the offset of the data, sixteen
//!   reserved bytes. A node is 12 bytes -- a type byte (0 file, 1
//!   directory), a 24-bit name offset into the string pool that follows the
//!   table, then for a file its data offset (from the start of the archive)
//!   and size, for a directory its parent index and the index one past its
//!   last descendant. Node 0 is the root; its last field is the node count.
//! * **RARC**: `RARC`, the file size, the header size (`0x20`), the offset of
//!   the file data *from `0x20`*, the data size, two memory sizes, padding;
//!   then, at `0x20`, an info block of directory-node count, offset, file-
//!   entry count, offset, string-table size, offset (offsets from `0x20`).
//!   A directory node is 16 bytes (type, name offset, name hash, entry
//!   count, first entry index); a file entry is 20 bytes (file id, name
//!   hash, a type byte whose bit 1 marks a sub-directory and a 24-bit name
//!   offset, then data offset *from the file data* -- or the directory-node
//!   index for a sub-directory -- the size, padding).
//!
//! Either may be wrapped in Yaz0 (`yaz0.rs`). Directories sit before the file
//! data, so [`directory_len`] says how much of the (decompressed) archive a
//! member listing needs, and a caller reads only that much of a large
//! archive to see whether it carries what it is looking for.

use super::{err, ImportError, Result};

const U8_MAGIC: [u8; 4] = [0x55, 0xaa, 0x38, 0x2d];
const RARC_MAGIC: &[u8; 4] = b"RARC";
/// Larger than any directory a console archive has (the biggest first-party
/// one is a few hundred KiB); guards an absurd claim.
const MAX_DIRECTORY: usize = 16 << 20;
/// How deep sub-directories may nest.
const MAX_DEPTH: usize = 32;

/// One file of an archive.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Member {
    /// `dir/sub/name`, from the archive's root (a RARC's root directory
    /// carries a name of its own, which leads the path).
    pub path: String,
    /// Where the member's bytes begin in the (decompressed) archive.
    pub offset: usize,
    pub size: usize,
}

fn be32(data: &[u8], at: usize) -> Result<usize> {
    at.checked_add(4)
        .and_then(|end| data.get(at..end))
        .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()) as usize)
        .ok_or_else(|| ImportError::Bad("archive field outside the file".into()))
}

fn be16(data: &[u8], at: usize) -> Result<usize> {
    at.checked_add(2)
        .and_then(|end| data.get(at..end))
        .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()) as usize)
        .ok_or_else(|| ImportError::Bad("archive field outside the file".into()))
}

/// How many bytes from the start of the decompressed archive a member
/// listing reads: the header and every table before the file data. `None`
/// when `head` (at least the first `0x20` bytes) is no archive or claims an
/// absurd directory.
pub(crate) fn directory_len(head: &[u8]) -> Option<usize> {
    let len = if head.starts_with(&U8_MAGIC) {
        be32(head, 4).ok()?.checked_add(be32(head, 8).ok()?)?
    } else if head.starts_with(RARC_MAGIC) {
        0x20usize.checked_add(be32(head, 0x0c).ok()?)?
    } else {
        return None;
    };
    (0x20..=MAX_DIRECTORY).contains(&len).then_some(len)
}

fn cstr(data: &[u8], at: usize) -> Result<String> {
    let tail = data
        .get(at..)
        .ok_or_else(|| ImportError::Bad("archive name outside the string table".into()))?;
    let end = tail.iter().position(|&byte| byte == 0).unwrap_or(tail.len());
    // Names are ASCII or Shift-JIS; a path is a label, not a key.
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// Every file of the archive, in table order. `data` holds the decompressed
/// archive from its start, at least [`directory_len`] bytes of it; a member's
/// range is not checked against `data`, because a caller listing from a
/// prefix has not read the data yet (`extract` checks).
pub(crate) fn members(data: &[u8]) -> Result<Vec<Member>> {
    if data.starts_with(&U8_MAGIC) {
        u8_members(data)
    } else if data.starts_with(RARC_MAGIC) {
        rarc_members(data)
    } else {
        err("not a U8 or RARC archive")
    }
}

/// The bytes of `member` out of the whole decompressed archive.
pub(crate) fn extract<'a>(data: &'a [u8], member: &Member) -> Result<&'a [u8]> {
    member
        .offset
        .checked_add(member.size)
        .and_then(|end| data.get(member.offset..end))
        .ok_or_else(|| ImportError::Bad(format!("archive member {} lies outside the archive", member.path)))
}

fn u8_members(data: &[u8]) -> Result<Vec<Member>> {
    let root = be32(data, 4)?;
    let total = be32(data, root + 8)?;
    if total == 0 || data.get(root).copied() != Some(1) {
        return err("U8 root node is not a directory");
    }
    let table = total
        .checked_mul(12)
        .and_then(|bytes| root.checked_add(bytes))
        .ok_or_else(|| ImportError::Bad("U8 node count overflows".into()))?;
    if table > MAX_DIRECTORY + root {
        return err("U8 node table is absurdly large");
    }
    let mut out = Vec::new();
    // (name, index one past the directory's last descendant)
    let mut dirs: Vec<(String, usize)> = Vec::new();
    for index in 1..total {
        while dirs.last().is_some_and(|(_, end)| index >= *end) {
            dirs.pop();
        }
        let node = root + index * 12;
        let word = be32(data, node)?;
        let (kind, name_at) = (word >> 24, word & 0x00ff_ffff);
        let name = cstr(data, table + name_at)?;
        let (a, b) = (be32(data, node + 4)?, be32(data, node + 8)?);
        if kind == 1 {
            if b <= index || b > total || dirs.len() >= MAX_DEPTH {
                return err("U8 directory range is malformed");
            }
            dirs.push((name, b));
        } else {
            let mut path = String::new();
            for (dir, _) in &dirs {
                path.push_str(dir);
                path.push('/');
            }
            path.push_str(&name);
            out.push(Member { path, offset: a, size: b });
        }
    }
    Ok(out)
}

fn rarc_members(data: &[u8]) -> Result<Vec<Member>> {
    let file_data = 0x20usize
        .checked_add(be32(data, 0x0c)?)
        .ok_or_else(|| ImportError::Bad("RARC data offset overflows".into()))?;
    let dir_count = be32(data, 0x20)?;
    let dir_at = 0x20 + be32(data, 0x24)?;
    let file_count = be32(data, 0x28)?;
    let file_at = 0x20 + be32(data, 0x2c)?;
    let names = 0x20 + be32(data, 0x34)?;
    if dir_count == 0 || dir_count > MAX_DIRECTORY / 16 || file_count > MAX_DIRECTORY / 20 {
        return err("RARC directory counts are outside what an archive holds");
    }
    let mut out = Vec::new();
    // (directory node, path prefix, next entry to read, last entry)
    let mut stack: Vec<(usize, String, usize, usize)> = Vec::new();
    let mut visited = vec![false; dir_count];
    let enter = |node: usize, prefix: &str, visited: &mut Vec<bool>| -> Result<(usize, String, usize, usize)> {
        if node >= dir_count || std::mem::replace(&mut visited[node], true) {
            return err("RARC directory is out of range or revisited");
        }
        let at = dir_at + node * 16;
        let name = cstr(data, names + be32(data, at + 4)?)?;
        let (count, first) = (be16(data, at + 10)?, be32(data, at + 12)?);
        if first.checked_add(count).is_none_or(|end| end > file_count) {
            return err("RARC directory entries lie outside the file table");
        }
        Ok((node, format!("{prefix}{name}/"), first, first + count))
    };
    stack.push(enter(0, "", &mut visited)?);
    while let Some((node, prefix, next, last)) = stack.pop() {
        if next >= last {
            continue;
        }
        stack.push((node, prefix.clone(), next + 1, last));
        let at = file_at + next * 20;
        let flags_name = be32(data, at + 4)?;
        let name = cstr(data, names + (flags_name & 0x00ff_ffff))?;
        let (a, b) = (be32(data, at + 8)?, be32(data, at + 12)?);
        if name == "." || name == ".." {
            continue;
        }
        if flags_name >> 24 & 0x02 != 0 {
            if stack.len() >= MAX_DEPTH {
                return err("RARC directories nest too deeply");
            }
            stack.push(enter(a, &prefix, &mut visited)?);
        } else {
            out.push(Member {
                path: format!("{prefix}{name}"),
                offset: file_data
                    .checked_add(a)
                    .ok_or_else(|| ImportError::Bad("RARC member offset overflows".into()))?,
                size: b,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn put(out: &mut Vec<u8>, at: usize, value: u32) {
        if out.len() < at + 4 {
            out.resize(at + 4, 0);
        }
        out[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// A U8 archive of `(path, bytes)`: directories are the path's leading
    /// components, files grouped by directory in first-seen order.
    pub(crate) fn build_u8(files: &[(&str, &[u8])]) -> Vec<u8> {
        // Nodes: root, then for each directory its files (one level, or
        // `a/b/name` as nested directories).
        let mut nodes: Vec<(u8, String, usize)> = vec![(1, String::new(), 0)]; // type, name, file index or end
        let mut stack: Vec<String> = Vec::new();
        let mut open: Vec<usize> = Vec::new();
        for (index, (path, _)) in files.iter().enumerate() {
            let parts: Vec<&str> = path.split('/').collect();
            let dirs = &parts[..parts.len() - 1];
            let common = stack.iter().zip(dirs).take_while(|(a, b)| a.as_str() == **b).count();
            while stack.len() > common {
                stack.pop();
                let at = open.pop().unwrap();
                nodes[at].2 = nodes.len();
            }
            for dir in &dirs[common..] {
                stack.push((*dir).to_string());
                open.push(nodes.len());
                nodes.push((1, (*dir).to_string(), 0));
            }
            nodes.push((0, parts[parts.len() - 1].to_string(), index));
        }
        while let Some(at) = open.pop() {
            nodes[at].2 = nodes.len();
        }
        nodes[0].2 = nodes.len();
        let mut names = vec![0u8];
        let mut name_offsets = Vec::new();
        for (_, name, _) in &nodes {
            if name.is_empty() {
                name_offsets.push(0);
                continue;
            }
            name_offsets.push(names.len());
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        let table = 12 * nodes.len();
        let header_size = table + names.len();
        let data_at = (0x20 + header_size + 0x1f) & !0x1f;
        let mut out = vec![0u8; data_at];
        out[0..4].copy_from_slice(&U8_MAGIC);
        put(&mut out, 4, 0x20);
        put(&mut out, 8, header_size as u32);
        put(&mut out, 12, data_at as u32);
        let mut placed: Vec<(usize, usize)> = vec![(0, 0); files.len()];
        for (index, (_, bytes)) in files.iter().enumerate() {
            while !out.len().is_multiple_of(0x20) {
                out.push(0);
            }
            placed[index] = (out.len(), bytes.len());
            out.extend_from_slice(bytes);
        }
        for (index, (kind, _, extra)) in nodes.iter().enumerate() {
            let at = 0x20 + index * 12;
            let word = (u32::from(*kind) << 24) | name_offsets[index] as u32;
            put(&mut out, at, word);
            if *kind == 1 {
                put(&mut out, at + 4, 0);
                put(&mut out, at + 8, *extra as u32);
            } else {
                put(&mut out, at + 4, placed[*extra].0 as u32);
                put(&mut out, at + 8, placed[*extra].1 as u32);
            }
        }
        out[0x20 + table..0x20 + table + names.len()].copy_from_slice(&names);
        out
    }

    /// A RARC of `(dir, name, bytes)` over one level of sub-directories
    /// under a root named `root`.
    pub(crate) fn build_rarc(root: &str, files: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let mut dirs: Vec<&str> = Vec::new();
        for (dir, _, _) in files {
            if !dir.is_empty() && !dirs.contains(dir) {
                dirs.push(dir);
            }
        }
        let mut names = Vec::new();
        let name_of = |text: &str, names: &mut Vec<u8>| {
            let at = names.len();
            names.extend_from_slice(text.as_bytes());
            names.push(0);
            at
        };
        let dot = name_of(".", &mut names);
        let dotdot = name_of("..", &mut names);
        let root_name = name_of(root, &mut names);
        // Directory nodes: 0 root, then one per sub-directory.
        let mut entries: Vec<[u32; 4]> = Vec::new(); // flags|name, a, b, id
        let mut nodes: Vec<(usize, usize, usize)> = Vec::new(); // name, count, first
        let mut data = Vec::new();
        let mut file_rows: Vec<(usize, u32, u32)> = Vec::new(); // name, offset, size
        for (_, name, bytes) in files {
            while data.len() % 0x20 != 0 {
                data.push(0);
            }
            file_rows.push((name_of(name, &mut names), data.len() as u32, bytes.len() as u32));
            data.extend_from_slice(bytes);
        }
        let sub_names: Vec<usize> = dirs.iter().map(|dir| name_of(dir, &mut names)).collect();
        // Root: its files (dir == ""), its sub-directory entries, `.`, `..`.
        let root_first = entries.len();
        for (index, (dir, _, _)) in files.iter().enumerate() {
            if dir.is_empty() {
                entries.push([0x1100_0000 | file_rows[index].0 as u32, file_rows[index].1, file_rows[index].2, 0]);
            }
        }
        for (index, _) in dirs.iter().enumerate() {
            entries.push([0x0200_0000 | sub_names[index] as u32, 1 + index as u32, 0x10, 0]);
        }
        entries.push([0x0200_0000 | dot as u32, 0, 0x10, 0]);
        entries.push([0x0200_0000 | dotdot as u32, 0xffff_ffff, 0x10, 0]);
        nodes.push((root_name, entries.len() - root_first, root_first));
        for (dir_index, dir) in dirs.iter().enumerate() {
            let first = entries.len();
            for (index, (member_dir, _, _)) in files.iter().enumerate() {
                if member_dir == dir {
                    entries.push([0x1100_0000 | file_rows[index].0 as u32, file_rows[index].1, file_rows[index].2, 0]);
                }
            }
            entries.push([0x0200_0000 | dot as u32, 1 + dir_index as u32, 0x10, 0]);
            entries.push([0x0200_0000 | dotdot as u32, 0, 0x10, 0]);
            nodes.push((sub_names[dir_index], entries.len() - first, first));
        }
        let info = 0x20usize;
        let dir_at = 0x20usize; // relative to `info`
        let file_at = dir_at + nodes.len() * 16;
        let names_at = (file_at + entries.len() * 20 + 0x1f) & !0x1f;
        let file_data_at = (info + names_at + names.len() + 0x1f) & !0x1f; // absolute
        let mut out = vec![0u8; file_data_at];
        out[0..4].copy_from_slice(RARC_MAGIC);
        put(&mut out, 8, 0x20);
        put(&mut out, 0x0c, (file_data_at - 0x20) as u32);
        put(&mut out, 0x10, data.len() as u32);
        put(&mut out, 0x20, nodes.len() as u32);
        put(&mut out, 0x24, dir_at as u32);
        put(&mut out, 0x28, entries.len() as u32);
        put(&mut out, 0x2c, file_at as u32);
        put(&mut out, 0x30, names.len() as u32);
        put(&mut out, 0x34, names_at as u32);
        for (index, (name, count, first)) in nodes.iter().enumerate() {
            let at = info + dir_at + index * 16;
            out[at..at + 4].copy_from_slice(if index == 0 { b"ROOT" } else { b"DIR\0" });
            put(&mut out, at + 4, *name as u32);
            out[at + 10..at + 12].copy_from_slice(&(*count as u16).to_be_bytes());
            put(&mut out, at + 12, *first as u32);
        }
        for (index, entry) in entries.iter().enumerate() {
            let at = info + file_at + index * 20;
            put(&mut out, at, index as u32);
            put(&mut out, at + 4, entry[0]);
            put(&mut out, at + 8, entry[1]);
            put(&mut out, at + 12, entry[2]);
        }
        out[info + names_at..info + names_at + names.len()].copy_from_slice(&names);
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn a_u8_lists_nested_files_with_paths_and_ranges() {
        let archive = build_u8(&[("rels/a.rel", b"AAAA"), ("rels/b.rel", b"BB"), ("top.txt", b"T"), ("x/y/z.bin", b"ZZZZZZ")]);
        assert!(directory_len(&archive).is_some());
        // Eight nodes (root, rels, two RELs, top.txt, x, y, z.bin) and the string pool.
        assert_eq!(directory_len(&archive), Some(0x20 + 12 * 8 + 1 + "rels\0a.rel\0b.rel\0top.txt\0x\0y\0z.bin\0".len()));
        let listing = members(&archive).unwrap();
        let paths: Vec<&str> = listing.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(paths, ["rels/a.rel", "rels/b.rel", "top.txt", "x/y/z.bin"]);
        let bytes: Vec<&[u8]> = listing.iter().map(|m| extract(&archive, m).unwrap()).collect();
        assert_eq!(bytes, [&b"AAAA"[..], b"BB", b"T", b"ZZZZZZ"]);
        // Listing needs only the directory prefix.
        let prefix = &archive[..directory_len(&archive).unwrap()];
        assert_eq!(members(prefix).unwrap(), listing);
        assert!(extract(prefix, &listing[3]).is_err());
    }

    #[test]
    fn a_rarc_lists_files_below_its_named_root_and_skips_dot_entries() {
        let archive = build_rarc("rels", &[("mmem", "a.rel", b"AAAA"), ("mmem", "b.rel", b"BB"), ("amem", "c.rel", b"CCC"), ("", "readme", b"R")]);
        assert!(directory_len(&archive).is_some());
        let listing = members(&archive).unwrap();
        let mut paths: Vec<&str> = listing.iter().map(|m| m.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(paths, ["rels/amem/c.rel", "rels/mmem/a.rel", "rels/mmem/b.rel", "rels/readme"]);
        for member in &listing {
            let want: &[u8] = match member.path.rsplit('/').next().unwrap() {
                "a.rel" => b"AAAA",
                "b.rel" => b"BB",
                "c.rel" => b"CCC",
                _ => b"R",
            };
            assert_eq!(extract(&archive, member).unwrap(), want, "{}", member.path);
        }
        let prefix = &archive[..directory_len(&archive).unwrap()];
        assert_eq!(members(prefix).unwrap().len(), 4);
    }

    #[test]
    fn malformed_archives_are_refused_not_followed() {
        assert!(directory_len(b"Yaz0\0\0\0\0\0\0\0\0\0\0\0\0").is_none());
        assert!(directory_len(b"RARC").is_none());
        assert!(members(b"not an archive").is_err());
        // A U8 directory whose range ends before it starts.
        let mut archive = build_u8(&[("d/a", b"A")]);
        put(&mut archive, 0x20 + 12 + 8, 1);
        assert!(members(&archive).is_err());
        // A RARC sub-directory that names the root again.
        let mut archive = build_rarc("r", &[("d", "a", b"A")]);
        let file_at = 0x20 + be32(&archive, 0x2c).unwrap();
        // The root's `d` entry is its first sub-directory entry (root has no files).
        put(&mut archive, file_at + 8, 0);
        assert!(members(&archive).is_err());
        // A claimed directory the size of the address space.
        let mut archive = build_rarc("r", &[("", "a", b"A")]);
        put(&mut archive, 0x0c, 0xffff_fff0);
        assert!(directory_len(&archive).is_none());
        // Truncated tables error instead of panicking.
        let archive = build_u8(&[("a", b"A"), ("b", b"B")]);
        for keep in 0..archive.len().min(0x60) {
            let _ = members(&archive[..keep]);
        }
        let archive = build_rarc("r", &[("d", "a", b"A")]);
        for keep in 0..archive.len().min(0xc0) {
            let _ = members(&archive[..keep]);
        }
    }
}
