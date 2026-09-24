//! PSP PRX modules (decrypted) and encrypted `~PSP` images.
//!
//! Documented format facts only, ported from public references (no code
//! copied from any implementation):
//!
//! - pspsdk `src/user/pspmoduleinfo.h` (pspdev/pspsdk): `SceModuleInfo`
//!   holds `modattribute`, `modversion[2]`, `modname[27]`, `terminal`,
//!   `gp_value`, `ent_top/end`, `stub_top/end`, and the `PSP_MODULE_INFO`
//!   macro emits it into `.rodata.sceModuleInfo`.
//! - pspsdk `src/startup/crt0.c`: the executable's default library entry
//!   is `{name: NULL, version, attribute 0x8000, entLen 4, varCount 1,
//!   funcCount 1, entrytable}`, whose entry table holds the NIDs first and
//!   the addresses after (`[D632ACDB, F01D73A7, &_start, &module_info]`).
//! - rust-psp `pspsdk` crate `src/sys/library.rs` (docs.rs): `repr(C)`
//!   `StubLibraryEntry` (name, version, flags, `len` of 6|7 words, var/func
//!   counts, NID / func-stub / var-stub tables) and `ResidentLibraryEntry`
//!   (`len` of 4|5 words, one entry table of NIDs-then-addresses, funcs
//!   before vars); a `VariableStub` is `{addr, nid}`.
//! - yapspd chap26 ("PSP Relocation eXecutable"): a PRX reports ELF type
//!   0xFFA0, not the usual 0x0002.
//! - psdevwiki "PRX File Format" and PPSSPP `Core/HLE/sceKernelModule.cpp`:
//!   shipped modules arrive wrapped in a `~PSP` header and KIRK-encrypted.
//!   The KIRK key vault, the CMD1 master key, and the tag tables are
//!   long-public constants (PSARDUMPER/JPCSP dumps), embedded in
//!   `super::kirk_tables`; `import_with` decrypts `~PSP` images through the
//!   KIRK algorithm (`super::kirk`) and imports the resulting PRX.
//! - The language is the one `opinion::elf_selection` keys a 0xFFA0 MIPS
//!   ELF to: `Allegrex:LE:32:default`.
//!
//! `EBOOT.PBP` already unwraps in `containers.rs`; the ELF it extracts is
//! what this parser consumes.

use std::collections::HashSet;

use super::{Mapping, NativeFunction, NativeImport, Result};

/// The language a decrypted PRX decodes with.
const LANGUAGE: &str = "Allegrex:LE:32:default";
/// yapspd chap26 "Unique ELF type": a PRX reports this, not 0x0002.
const ET_SCE_PSPRELEXEC: u16 = 0xFFA0;
/// psdevwiki "PRX File Format": magic of the encrypted wrapper.
const ENC_MAGIC: &[u8; 4] = b"~PSP";
/// Scrambled-PRX prefix: refused like `~PSP` (decrypt first).
const SCRAMBLED_MAGIC: &[u8; 4] = b"PSP\x00";
/// pspsdk `pspmoduleinfo.h`: 4 header bytes + 28 name bytes + 5 pointers.
const MODULE_INFO_LEN: usize = 52;
/// `SceModuleInfo` field offsets of the four table pointers.
const ENT_TOP_OFF: usize = 36;
const ENT_END_OFF: usize = 40;
const STUB_TOP_OFF: usize = 44;
const STUB_END_OFF: usize = 48;
/// Largest table range trusted before the walk is abandoned.
const MAX_TABLE_SPAN: u64 = 1 << 20;
/// Largest import/export list trusted in one table.
const MAX_ENTRIES: u64 = 0x1000;

fn u16le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// True for the encrypted form: `~PSP`-wrapped (KIRK) or scrambled.
fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 4 && (&data[..4] == ENC_MAGIC || &data[..4] == SCRAMBLED_MAGIC)
}

/// The `e_type` when `data` is an ELF32 little-endian MIPS header.
fn elf_type(data: &[u8]) -> Option<u16> {
    if data.len() < 52 || &data[..4] != b"\x7fELF" {
        return None;
    }
    if data[4] != 1 || data[5] != 1 {
        // ELFCLASS32, ELFDATA2LSB: a PRX is always 32-bit little-endian.
        return None;
    }
    if u16le(data, 18)? != 8 {
        // EM_MIPS (the Allegrex is a MIPS32r2 core).
        return None;
    }
    u16le(data, 16)
}

/// True when the ELF carries PSP module markers: the module-info or library
/// sections, or the `sceModuleInfo` symbol a stripped file may retain.
fn has_module_marker(data: &[u8]) -> bool {
    let Ok((sections, _)) = super::parse_elf32_sections(data, false) else {
        return false;
    };
    if sections.iter().any(|s| {
        matches!(
            s.name.as_str(),
            ".rodata.sceModuleInfo" | ".lib.ent" | ".lib.stub"
        )
    }) {
        return true;
    }
    for symtab in sections.iter().filter(|s| s.typ == 2 || s.typ == 11) {
        let Some(strtab) = sections.get(symtab.link as usize).and_then(|t| {
            data.get(t.off as usize..t.off as usize + t.size as usize)
        }) else {
            continue;
        };
        let count = symtab.size as usize / 16;
        for i in 0..count {
            let base = symtab.off as usize + i * 16;
            let Some(rec) = data.get(base..base + 16) else {
                break;
            };
            let name_off =
                u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            if name == "sceModuleInfo" {
                return true;
            }
        }
    }
    false
}

/// True when `data` is a PSP module: encrypted (`~PSP`/scrambled), a PRX by
/// ELF type, or a MIPS ELF carrying PSP module markers.
pub(crate) fn is_prx(data: &[u8]) -> bool {
    if is_encrypted(data) {
        return true;
    }
    match elf_type(data) {
        Some(ET_SCE_PSPRELEXEC) => true,
        Some(_) => has_module_marker(data),
        None => false,
    }
}

/// Loads the image. `None` means "not a PSP module"; encrypted images are
/// decrypted first and import as the PRX they carry.
#[cfg(test)]
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    import_with(data, &super::keys::KeyStore::empty())
}

/// `import` with a user-supplied key store. PSP encryption is KIRK driven
/// by embedded public tables (`super::kirk`), not by a file-supplied key,
/// so the keystore is accepted for interface uniformity and ignored: a
/// `~PSP`/scrambled image decrypts in-loader, then imports as a PRX. What
/// no decrypt type accepts still errors instead of importing garbage.
pub(crate) fn import_with(
    data: &[u8],
    _keys: &super::keys::KeyStore,
) -> Option<Result<Vec<(String, NativeImport)>>> {
    if is_encrypted(data) {
        let plain = match super::kirk::decrypt_prx(data) {
            Ok(plain) => plain,
            Err(e) => return Some(Err(e)),
        };
        return Some(import_prx(&plain).map(|imp| vec![(String::new(), imp)]));
    }
    if !is_prx(data) {
        return None;
    }
    Some(import_prx(data).map(|imp| vec![(String::new(), imp)]))
}

fn import_prx(data: &[u8]) -> Result<NativeImport> {
    let mut imp = super::import_elf32(data, false)?;
    imp.format = "PRX".into();
    imp.language = LANGUAGE.into();
    collect_module_info(data, &mut imp);
    seed_entry(data, &mut imp);
    imp.functions.sort_by_key(|f| f.entry);
    Ok(imp)
}

/// One word at a loaded address.
fn word_at(mappings: &[Mapping], vaddr: u64) -> Option<u32> {
    mappings.iter().find_map(|m| {
        let rel = vaddr.checked_sub(m.vaddr)?;
        let start = usize::try_from(rel).ok()?;
        m.bytes
            .get(start..start + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    })
}

/// `len` bytes at a loaded address.
fn block_at(mappings: &[Mapping], vaddr: u64, len: usize) -> Option<Vec<u8>> {
    mappings.iter().find_map(|m| {
        let rel = vaddr.checked_sub(m.vaddr)?;
        let start = usize::try_from(rel).ok()?;
        let end = start.checked_add(len)?;
        m.bytes.get(start..end).map(|b| b.to_vec())
    })
}

/// A NUL-terminated string at a loaded address (bounded).
fn cstr_at(mappings: &[Mapping], vaddr: u64) -> String {
    let mut out = Vec::new();
    for i in 0..256u64 {
        let Some(byte) = mappings.iter().find_map(|m| {
            let rel = vaddr.checked_add(i)?.checked_sub(m.vaddr)?;
            m.bytes.get(usize::try_from(rel).ok()?).copied()
        }) else {
            break;
        };
        if byte == 0 {
            break;
        }
        out.push(byte);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mapped(mappings: &[Mapping], addr: u64) -> bool {
    mappings.iter().any(|m| {
        m.size > 0 && addr >= m.vaddr && addr - m.vaddr < m.size
    })
}

fn seed(imp: &mut NativeImport, seeded: &mut HashSet<u64>, entry: u64, name: String) {
    if entry == 0 || seeded.contains(&entry) {
        return;
    }
    if !mapped(&imp.mappings, entry) {
        return;
    }
    seeded.insert(entry);
    imp.functions.push(NativeFunction {
        entry,
        name,
        size: 1,
    });
    if !imp.symbol_named.contains(&entry) {
        imp.symbol_named.push(entry);
    }
}

/// The library name a table entry points at, or empty for the NULL default
/// library (pspsdk `crt0.c` registers `_start`/`module_info` with no name).
fn lib_name(mappings: &[Mapping], vaddr: u32) -> String {
    if vaddr == 0 {
        return String::new();
    }
    let name = cstr_at(mappings, vaddr as u64);
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
    {
        return String::new();
    }
    name
}

fn export_name(lib: &str, nid: u32) -> String {
    if lib.is_empty() {
        format!("sce_export_{nid:08x}")
    } else {
        format!("{lib}_{nid:08x}")
    }
}

fn import_name(lib: &str, nid: u32) -> String {
    if lib.is_empty() {
        format!("sce_import_{nid:08x}")
    } else {
        format!("{lib}_{nid:08x}")
    }
}

fn import_var_name(lib: &str, nid: u32) -> String {
    if lib.is_empty() {
        format!("sce_import_var_{nid:08x}")
    } else {
        format!("{lib}_var_{nid:08x}")
    }
}

/// The `sceModuleInfo` value from the symbol table, for files whose section
/// was renamed but whose symbols survive.
fn module_info_symbol(data: &[u8], sections: &[super::ElfSection]) -> Option<u64> {
    for symtab in sections.iter().filter(|s| s.typ == 2 || s.typ == 11) {
        let strtab = sections
            .get(symtab.link as usize)
            .and_then(|t| data.get(t.off as usize..t.off as usize + t.size as usize))?;
        let count = symtab.size as usize / 16;
        for i in 0..count {
            let base = symtab.off as usize + i * 16;
            let rec = data.get(base..base + 16)?;
            let name_off = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            if name == "sceModuleInfo" {
                return Some(u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]) as u64);
            }
        }
    }
    None
}

/// Parses `SceModuleInfo` and its export/import tables into the import.
///
/// Lenient by design (like `sce::collect`): a malformed module block must
/// not sink an otherwise loadable ELF, so a bad table ends the walk rather
/// than the import.
fn collect_module_info(data: &[u8], imp: &mut NativeImport) {
    let sections = super::parse_elf32_sections(data, false)
        .map(|(s, _)| s)
        .unwrap_or_default();
    let mut info: Option<Vec<u8>> = None;
    for s in &sections {
        if s.name == ".rodata.sceModuleInfo" && s.size >= MODULE_INFO_LEN as u64 {
            if let Some(b) = data.get(s.off as usize..s.off as usize + MODULE_INFO_LEN) {
                info = Some(b.to_vec());
                break;
            }
        }
    }
    if info.is_none() {
        if let Some(value) = module_info_symbol(data, &sections) {
            info = block_at(&imp.mappings, value, MODULE_INFO_LEN);
        }
    }
    let Some(info) = info else {
        return;
    };
    let ptr = |off: usize| u32::from_le_bytes([info[off], info[off + 1], info[off + 2], info[off + 3]]) as u64;
    let ent_top = ptr(ENT_TOP_OFF);
    let ent_end = ptr(ENT_END_OFF);
    let stub_top = ptr(STUB_TOP_OFF);
    let stub_end = ptr(STUB_END_OFF);
    if ent_end < ent_top || stub_end < stub_top {
        return;
    }
    if ent_end - ent_top > MAX_TABLE_SPAN || stub_end - stub_top > MAX_TABLE_SPAN {
        return;
    }
    let mut seeded: HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    collect_exports(imp, &mut seeded, ent_top, ent_end);
    collect_stubs(imp, &mut seeded, stub_top, stub_end);
}

/// Walks the `.lib.ent` resident entries. Each entry's single table holds
/// the func NIDs, then the var NIDs, then the addresses in the same order
/// (pspsdk `crt0.c`, rust-psp `ResidentLibraryEntry`).
fn collect_exports(imp: &mut NativeImport, seeded: &mut HashSet<u64>, top: u64, end: u64) {
    let mut cursor = top;
    while cursor < end {
        let remain = end - cursor;
        if remain < 16 {
            break;
        }
        let Some(hdr) = block_at(&imp.mappings, cursor, 16) else {
            break;
        };
        let lib = lib_name(&imp.mappings, u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]));
        let len_words = hdr[8] as u64;
        let vars = hdr[9] as u64;
        let funcs = u16::from_le_bytes([hdr[10], hdr[11]]) as u64;
        let entry_len = len_words.checked_mul(4).unwrap_or(0);
        if len_words < 4 || entry_len > remain {
            break;
        }
        let table = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as u64;
        let total = funcs + vars;
        if total > MAX_ENTRIES {
            break;
        }
        if total > 0 {
            let nids = block_at(&imp.mappings, table, total as usize * 4);
            let addrs = table
                .checked_add(total * 4)
                .and_then(|a| block_at(&imp.mappings, a, total as usize * 4));
            if let (Some(nids), Some(addrs)) = (nids, addrs) {
                for i in 0..total as usize {
                    let nid = u32::from_le_bytes([
                        nids[i * 4],
                        nids[i * 4 + 1],
                        nids[i * 4 + 2],
                        nids[i * 4 + 3],
                    ]);
                    let addr = u32::from_le_bytes([
                        addrs[i * 4],
                        addrs[i * 4 + 1],
                        addrs[i * 4 + 2],
                        addrs[i * 4 + 3],
                    ]) as u64;
                    if addr == 0 {
                        continue;
                    }
                    let name = export_name(&lib, nid);
                    if (i as u64) < funcs {
                        seed(imp, seeded, addr, name);
                    } else {
                        imp.object_names.push((addr, name));
                    }
                }
            }
        }
        cursor += entry_len;
    }
}

/// Walks the `.lib.stub` entries. The NID array holds funcs then vars; each
/// func stub is 8 bytes of code in `.sceStub.text`, each var slot an 8-byte
/// `VariableStub {addr, nid}` (rust-psp `StubLibraryEntry`).
fn collect_stubs(imp: &mut NativeImport, seeded: &mut HashSet<u64>, top: u64, end: u64) {
    let mut cursor = top;
    while cursor < end {
        let remain = end - cursor;
        if remain < 24 {
            break;
        }
        let Some(hdr) = block_at(&imp.mappings, cursor, 24) else {
            break;
        };
        let lib = lib_name(&imp.mappings, u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]));
        let len_words = hdr[8] as u64;
        let vars = hdr[9] as u64;
        let funcs = u16::from_le_bytes([hdr[10], hdr[11]]) as u64;
        let entry_len = len_words.checked_mul(4).unwrap_or(0);
        if len_words < 6 || entry_len > remain {
            break;
        }
        let nids_at = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as u64;
        let funcs_at = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as u64;
        let vars_at = u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]) as u64;
        let total = funcs + vars;
        if total > MAX_ENTRIES {
            break;
        }
        let nids = if total == 0 {
            Some(Vec::new())
        } else {
            block_at(&imp.mappings, nids_at, total as usize * 4)
        };
        let Some(nids) = nids else {
            cursor += entry_len;
            continue;
        };
        let nid = |i: usize| {
            u32::from_le_bytes([nids[i * 4], nids[i * 4 + 1], nids[i * 4 + 2], nids[i * 4 + 3]])
        };
        for i in 0..funcs as usize {
            let Some(stub) = funcs_at.checked_add((i * 8) as u64) else {
                break;
            };
            let name = import_name(&lib, nid(i));
            seed(imp, seeded, stub, name.clone());
            imp.externals.push((stub, name));
        }
        for i in 0..vars as usize {
            let Some(slot) = vars_at.checked_add((i * 8) as u64) else {
                break;
            };
            let name = import_var_name(&lib, nid(funcs as usize + i));
            if let Some(addr) = word_at(&imp.mappings, slot).map(|a| a as u64) {
                if addr != 0 && mapped(&imp.mappings, addr) {
                    imp.object_names.push((addr, name.clone()));
                }
            }
            imp.externals.push((slot, name));
        }
        cursor += entry_len;
    }
}

/// Seeds `e_entry` (Ghidra's `entry`) and records the process entry when the
/// header names a loadable address.
fn seed_entry(data: &[u8], imp: &mut NativeImport) {
    let Some(entry) = u32le(data, 24).map(|e| e as u64) else {
        return;
    };
    if entry == 0 || !mapped(&imp.mappings, entry) {
        return;
    }
    if imp.process_entry.is_none() {
        imp.process_entry = Some(entry);
    }
    let mut seeded: HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    seed(imp, &mut seeded, entry, "entry".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0880_0000;

    /// Builds a minimal decrypted PRX: `.text` with two functions, module
    /// info, one resident export (1 func + 1 var) and one stub import
    /// (1 func + 1 var), plus symtab/strtab/shstrtab.
    fn build_elf(
        e_type: u16,
        modinfo_name: &str,
        ent_name: &str,
        stub_name: &str,
        with_module_symbol: bool,
    ) -> Vec<u8> {
        let text_v = BASE;
        let mod_v = BASE + 0x100;
        let ent_v = BASE + 0x140;
        let rod_v = BASE + 0x180;
        let stub_v = BASE + 0x1c0;
        let stext_v = BASE + 0x200;
        // `.rodata` contents: export entry table, exported var, lib name,
        // stub NIDs, imported var.
        let entrytab_v = rod_v;
        let expvar_v = rod_v + 16;
        let libstr_v = rod_v + 20;
        let stubnids_v = rod_v + 28;
        let impvar_v = rod_v + 36;
        let stubcode_v = stext_v;
        let varstub_v = stext_v + 8;

        let jr_ra_nop: [u8; 8] = [0x08, 0x00, 0xE0, 0x03, 0x00, 0x00, 0x00, 0x00];
        let mut text = Vec::new();
        text.extend_from_slice(&jr_ra_nop);
        text.extend_from_slice(&jr_ra_nop);

        let mut modinfo = Vec::new();
        modinfo.extend_from_slice(&0u16.to_le_bytes()); // modattribute
        modinfo.extend_from_slice(&[1, 0]); // modversion
        let mut name = [0u8; 28]; // modname[27] + terminal
        name[..7].copy_from_slice(b"testmod");
        modinfo.extend_from_slice(&name);
        modinfo.extend_from_slice(&0u32.to_le_bytes()); // gp_value
        modinfo.extend_from_slice(&(ent_v).to_le_bytes()); // ent_top
        modinfo.extend_from_slice(&(ent_v + 16).to_le_bytes()); // ent_end
        modinfo.extend_from_slice(&(stub_v).to_le_bytes()); // stub_top
        modinfo.extend_from_slice(&(stub_v + 24).to_le_bytes()); // stub_end
        assert_eq!(modinfo.len(), MODULE_INFO_LEN);

        let mut ent = Vec::new();
        ent.extend_from_slice(&libstr_v.to_le_bytes()); // libname
        ent.extend_from_slice(&0x0101u16.to_le_bytes()); // version
        ent.extend_from_slice(&0x8000u16.to_le_bytes()); // attribute
        ent.push(4); // ent_len (words)
        ent.push(1); // var_count
        ent.extend_from_slice(&1u16.to_le_bytes()); // func_count
        ent.extend_from_slice(&entrytab_v.to_le_bytes()); // entrytable
        assert_eq!(ent.len(), 16);

        let mut rodata = Vec::new();
        rodata.extend_from_slice(&0x12345678u32.to_le_bytes()); // func NID
        rodata.extend_from_slice(&0x9abcdef0u32.to_le_bytes()); // var NID
        rodata.extend_from_slice(&(text_v + 8).to_le_bytes()); // func addr
        rodata.extend_from_slice(&expvar_v.to_le_bytes()); // var addr
        rodata.extend_from_slice(&0u32.to_le_bytes()); // exported var
        rodata.extend_from_slice(b"TestLib\0"); // lib name
        rodata.extend_from_slice(&0x11111111u32.to_le_bytes()); // stub func NID
        rodata.extend_from_slice(&0x22222222u32.to_le_bytes()); // stub var NID
        rodata.extend_from_slice(&0u32.to_le_bytes()); // imported var
        assert_eq!(rodata.len(), 40);

        let mut stub = Vec::new();
        stub.extend_from_slice(&libstr_v.to_le_bytes()); // libname
        stub.extend_from_slice(&0x0101u16.to_le_bytes()); // version
        stub.extend_from_slice(&0u16.to_le_bytes()); // flags
        stub.push(6); // stub_len (words, old form)
        stub.push(1); // var_count
        stub.extend_from_slice(&1u16.to_le_bytes()); // func_count
        stub.extend_from_slice(&stubnids_v.to_le_bytes()); // nid_table
        stub.extend_from_slice(&stubcode_v.to_le_bytes()); // func_stub_table
        stub.extend_from_slice(&varstub_v.to_le_bytes()); // var_stub_table
        assert_eq!(stub.len(), 24);

        let mut stext = Vec::new();
        stext.extend_from_slice(&jr_ra_nop); // import stub code
        stext.extend_from_slice(&impvar_v.to_le_bytes()); // VariableStub.addr
        stext.extend_from_slice(&0x22222222u32.to_le_bytes()); // VariableStub.nid

        let mut strtab = vec![0u8];
        let sym_mod_off = strtab.len() as u32;
        strtab.extend_from_slice(b"sceModuleInfo\0");
        let sym_func_off = strtab.len() as u32;
        strtab.extend_from_slice(b"func_a\0");

        // 16-byte Elf32_Sym records.
        fn sym(name: u32, value: u32, size: u32, info: u8, shndx: u16) -> [u8; 16] {
            let mut r = [0u8; 16];
            r[..4].copy_from_slice(&name.to_le_bytes());
            r[4..8].copy_from_slice(&value.to_le_bytes());
            r[8..12].copy_from_slice(&size.to_le_bytes());
            r[12] = info;
            r[14..16].copy_from_slice(&shndx.to_le_bytes());
            r
        }
        let mut symtab = vec![0u8; 16];
        if with_module_symbol {
            symtab.extend_from_slice(&sym(
                sym_mod_off,
                mod_v,
                MODULE_INFO_LEN as u32,
                0x11,
                2,
            ));
        }
        symtab.extend_from_slice(&sym(sym_func_off, text_v, 8, 0x12, 1));

        let shstr_names = [
            "",
            ".text",
            modinfo_name,
            ent_name,
            ".rodata",
            stub_name,
            ".sceStub.text",
            ".symtab",
            ".strtab",
            ".shstrtab",
        ];
        let mut shstrtab = Vec::new();
        let mut shstr_offs = Vec::new();
        for n in shstr_names {
            shstr_offs.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(n.as_bytes());
            shstrtab.push(0);
        }

        // (name_idx, type, flags, vaddr, align, link, info, entsize, bytes)
        let sections: Vec<(usize, u32, u32, u32, u32, u32, u32, u32, Vec<u8>)> = vec![
            (1, 1, 6, text_v, 16, 0, 0, 0, text),
            (2, 1, 2, mod_v, 4, 0, 0, 0, modinfo),
            (3, 1, 2, ent_v, 4, 0, 0, 0, ent),
            (4, 1, 2, rod_v, 4, 0, 0, 0, rodata),
            (5, 1, 2, stub_v, 4, 0, 0, 0, stub),
            (6, 1, 6, stext_v, 4, 0, 0, 0, stext),
            (7, 2, 0, 0, 4, 8, 1, 16, symtab),
            (8, 3, 0, 0, 1, 0, 0, 0, strtab),
            (9, 3, 0, 0, 1, 0, 0, 0, shstrtab),
        ];

        // Loaded sections mirror their vaddrs: file_off = 0x100 + (vaddr - BASE).
        let mut file = vec![0u8; 0x100];
        let mut offs = Vec::new();
        for (_, _, _, vaddr, ..) in &sections {
            let off = if *vaddr == 0 {
                0usize // placed later
            } else {
                0x100 + (*vaddr - BASE) as usize
            };
            offs.push(off);
        }
        let mut end = 0x100 + 0x210;
        for (i, (_, _, _, vaddr, _, _, _, _, _)) in sections.iter().enumerate() {
            if *vaddr == 0 {
                offs[i] = end;
                end += sections[i].8.len();
            }
        }
        for (i, (_, _, _, _, _, _, _, _, bytes)) in sections.iter().enumerate() {
            let off = offs[i];
            if file.len() < off + bytes.len() {
                file.resize(off + bytes.len(), 0);
            }
            file[off..off + bytes.len()].copy_from_slice(bytes);
        }

        // One PT_LOAD over the linked image.
        let mut phdr = vec![0u8; 32];
        phdr[..4].copy_from_slice(&1u32.to_le_bytes());
        phdr[4..8].copy_from_slice(&0x100u32.to_le_bytes());
        phdr[8..12].copy_from_slice(&BASE.to_le_bytes());
        phdr[12..16].copy_from_slice(&BASE.to_le_bytes());
        phdr[16..20].copy_from_slice(&0x210u32.to_le_bytes());
        phdr[20..24].copy_from_slice(&0x210u32.to_le_bytes());
        phdr[24..28].copy_from_slice(&7u32.to_le_bytes());
        phdr[28..32].copy_from_slice(&0x10u32.to_le_bytes());
        file[52..52 + 32].copy_from_slice(&phdr);

        let shoff = file.len();
        // NULL section header first.
        file.extend_from_slice(&[0u8; 40]);
        for (i, (name_idx, typ, flags, vaddr, align, link, info, entsize, bytes)) in
            sections.iter().enumerate()
        {
            let mut sh = vec![0u8; 40];
            sh[..4].copy_from_slice(&shstr_offs[*name_idx].to_le_bytes());
            sh[4..8].copy_from_slice(&typ.to_le_bytes());
            sh[8..12].copy_from_slice(&flags.to_le_bytes());
            sh[12..16].copy_from_slice(&vaddr.to_le_bytes());
            sh[16..20].copy_from_slice(&(offs[i] as u32).to_le_bytes());
            sh[20..24].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            sh[24..28].copy_from_slice(&link.to_le_bytes());
            sh[28..32].copy_from_slice(&info.to_le_bytes());
            sh[32..36].copy_from_slice(&align.to_le_bytes());
            sh[36..40].copy_from_slice(&entsize.to_le_bytes());
            file.extend_from_slice(&sh);
        }

        let mut ehdr = vec![0u8; 52];
        ehdr[..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 1; // 32-bit
        ehdr[5] = 1; // little-endian
        ehdr[6] = 1; // version
        ehdr[16..18].copy_from_slice(&e_type.to_le_bytes());
        ehdr[18..20].copy_from_slice(&8u16.to_le_bytes()); // EM_MIPS
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        ehdr[24..28].copy_from_slice(&BASE.to_le_bytes()); // e_entry
        ehdr[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff
        ehdr[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
        ehdr[40..42].copy_from_slice(&52u16.to_le_bytes());
        ehdr[42..44].copy_from_slice(&32u16.to_le_bytes());
        ehdr[44..46].copy_from_slice(&1u16.to_le_bytes());
        ehdr[46..48].copy_from_slice(&40u16.to_le_bytes());
        ehdr[48..50].copy_from_slice(&10u16.to_le_bytes());
        ehdr[50..52].copy_from_slice(&9u16.to_le_bytes());
        file[..52].copy_from_slice(&ehdr);
        file
    }

    fn prx() -> Vec<u8> {
        build_elf(
            ET_SCE_PSPRELEXEC,
            ".rodata.sceModuleInfo",
            ".lib.ent",
            ".lib.stub",
            true,
        )
    }

    #[test]
    fn decrypted_prx_names_exports_and_imports() {
        let data = prx();
        assert!(is_prx(&data));
        let images = import(&data).expect("recognized").expect("valid PRX");
        assert_eq!(images.len(), 1);
        let imp = &images[0].1;
        assert_eq!(imp.format, "PRX");
        assert_eq!(imp.language, "Allegrex:LE:32:default");
        let names: std::collections::HashMap<u64, &str> = imp
            .functions
            .iter()
            .map(|f| (f.entry, f.name.as_str()))
            .collect();
        // symtab name survives at the entry; the export names its function.
        assert_eq!(names.get(&(BASE as u64)), Some(&"func_a"));
        assert_eq!(
            names.get(&((BASE + 8) as u64)),
            Some(&"TestLib_12345678")
        );
        // the import stub seeds a function and an external.
        assert_eq!(
            names.get(&((BASE + 0x200) as u64)),
            Some(&"TestLib_11111111")
        );
        assert!(
            imp.externals
                .iter()
                .any(|(a, n)| *a == (BASE + 0x200) as u64 && n == "TestLib_11111111")
        );
        // the exported variable names data, not code.
        assert!(
            imp.object_names
                .iter()
                .any(|(a, n)| *a == (BASE + 0x180 + 16) as u64 && n == "TestLib_9abcdef0")
        );
        assert_eq!(imp.process_entry, Some(BASE as u64));
    }

    #[test]
    fn module_info_is_found_via_symbol_when_renamed() {
        let data = build_elf(ET_SCE_PSPRELEXEC, ".myinfo", ".lib.ent", ".lib.stub", true);
        assert!(is_prx(&data));
        let images = import(&data).expect("recognized").expect("valid PRX");
        let imp = &images[0].1;
        assert!(
            imp.functions
                .iter()
                .any(|f| f.entry == (BASE + 8) as u64 && f.name == "TestLib_12345678")
        );
    }

    #[test]
    fn static_psp_elf_with_markers_is_prx() {
        // A static executable (ET_EXEC) is still a PSP module when it
        // carries the module structures.
        let data = build_elf(2, ".rodata.sceModuleInfo", ".lib.ent", ".lib.stub", true);
        assert!(is_prx(&data));
        let images = import(&data).expect("recognized").expect("valid");
        assert_eq!(images[0].1.language, "Allegrex:LE:32:default");
    }

    /// Encrypts `prx` into a `~PSP` image with the type-2 path run backwards
    /// (tag 0, the first `g_tagInfo2` entry): payload under a fixed AES key,
    /// keypair under the CMD1 master key, header SHA-1, then the kirk7
    /// layers. Asserts the loader's decrypt side by construction.
    fn encrypt_type2(prx: &[u8]) -> Vec<u8> {
        use super::super::crypto::{aes128_cbc_encrypt, sha1};
        use super::super::kirk::expand_seed;
        use super::super::kirk_tables::{KEYVAULT, KEY_21C0, KIRK1_KEY};

        const CODE: u8 = 0x42;
        let vault_key = &KEYVAULT[CODE as usize];
        let size = prx.len();
        let aligned = size.next_multiple_of(16);

        // Payload ciphertext under a fixed test AES key.
        let aes_key = [0x11u8; 16];
        let mut padded = vec![0u8; aligned];
        padded[..size].copy_from_slice(prx);
        aes128_cbc_encrypt(&aes_key, &mut padded).unwrap();

        // Keypair plaintext (AES key plus a CMAC key the loader never
        // checks), encrypted with the CMD1 master key.
        let mut pair = [0u8; 32];
        pair[..16].copy_from_slice(&aes_key);
        pair[16..32].copy_from_slice(&[0x22u8; 16]);
        aes128_cbc_encrypt(&KIRK1_KEY, &mut pair).unwrap();

        // Plaintext key header: encrypted pair, zero hash slots.
        let mut kh = [0u8; 0x40];
        kh[..32].copy_from_slice(&pair);

        // Outer-layer inverse of `decrypt_kirk_header`.
        let xor = expand_seed(&KEY_21C0, CODE, None).unwrap();
        let mut t = [0u8; 0x40];
        for i in 0..0x40 {
            t[i] = kh[i] ^ xor[0x50 + i];
        }
        aes128_cbc_encrypt(vault_key, &mut t).unwrap();
        let mut fp = [0u8; 0x40];
        for i in 0..0x40 {
            fp[i] = t[i] ^ xor[0x10 + i];
        }

        // Prefix copy and metadata (size + data offset 0x80).
        let mut prefix = [0u8; 0x80];
        prefix[..4].copy_from_slice(b"~PSP");
        let mut meta = [0u8; 0x10];
        meta[..4].copy_from_slice(&(size as u32).to_le_bytes());
        meta[4..8].copy_from_slice(&0x80u32.to_le_bytes());

        // Header hash over the rearranged-plaintext fields.
        let id = [0x33u8; 16];
        let digest = sha1(&[
            &[0u8; 4],
            &xor[..0x10],
            &[0u8; 0x58],
            &id,
            &fp,
            &meta,
            &prefix,
        ]);

        // id-run inverse: id ++ hash ++ key-head, CBC-encrypted.
        let mut b = [0u8; 0x60];
        b[..0x10].copy_from_slice(&id);
        b[0x10..0x24].copy_from_slice(&digest);
        b[0x24..0x60].copy_from_slice(&fp[..0x3C]);
        aes128_cbc_encrypt(vault_key, &mut b).unwrap();

        // Scatter into the file: prefix, key header, metadata, tag (zero),
        // hash slot, id slot, then the payload ciphertext.
        let mut file = vec![0u8; 0x150 + aligned];
        file[..0x80].copy_from_slice(&prefix);
        file[0x80..0xB0].copy_from_slice(&b[0x24..0x54]);
        file[0xB0..0xC0].copy_from_slice(&meta);
        file[0xC0..0xCC].copy_from_slice(&b[0x54..0x60]);
        file[0xCC..0xD0].copy_from_slice(&fp[0x3C..0x40]);
        file[0x12C..0x140].copy_from_slice(&b[0x10..0x24]);
        file[0x140..0x150].copy_from_slice(&b[..0x10]);
        file[0x150..].copy_from_slice(&padded);
        file
    }

    #[test]
    fn encrypted_psp_round_trip_decrypts_and_imports() {
        let plain = prx();
        let data = encrypt_type2(&plain);
        assert!(is_prx(&data));
        let images = import(&data).expect("recognized").expect("decryptable");
        assert_eq!(images.len(), 1);
        let imp = &images[0].1;
        assert_eq!(imp.format, "PRX");
        assert_eq!(imp.language, "Allegrex:LE:32:default");
        // The decrypted bytes are the original PRX: same entry, same names.
        let names: std::collections::HashMap<u64, &str> = imp
            .functions
            .iter()
            .map(|f| (f.entry, f.name.as_str()))
            .collect();
        assert_eq!(
            names.get(&((BASE + 8) as u64)),
            Some(&"TestLib_12345678")
        );
        assert_eq!(
            names.get(&((BASE + 0x200) as u64)),
            Some(&"TestLib_11111111")
        );
        assert_eq!(imp.process_entry, Some(BASE as u64));
    }

    #[test]
    fn undecryptable_psp_errors_cleanly() {
        // Zero-filled wrapper: known tag, failing header check.
        let mut zeroed = b"~PSP".to_vec();
        zeroed.resize(0x200, 0);
        assert!(is_prx(&zeroed));
        let err = import(&zeroed).expect("recognized").expect_err("no match");
        assert!(
            err.to_string().contains("decrypt"),
            "unexpected error: {err}"
        );
        // Unknown tag with junk behind it.
        let mut junk = vec![0xA5u8; 0x200];
        junk[..4].copy_from_slice(b"~PSP");
        junk[0xD0..0xD4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(import(&junk).expect("recognized").is_err());
        // Truncated below the header: an error, never a panic.
        let mut short = b"~PSP".to_vec();
        short.resize(0x40, 0);
        assert!(import(&short).expect("recognized").is_err());
        // Scrambled prefix without KIRK bytes behind it still refuses.
        let mut scrambled = b"PSP\x00".to_vec();
        scrambled.resize(0x100, 0);
        assert!(import(&scrambled).expect("recognized").is_err());
        // A non-module blob is not recognized at all.
        assert!(import(b"definitely not a module image").is_none());
    }

    #[test]
    fn generic_mips_elf_and_pbp_are_not_prx() {
        // Same shape but no PSP markers: plain ET_EXEC MIPS ELF.
        let data = build_elf(2, ".rodata", ".data", ".data2", false);
        assert!(!is_prx(&data));
        assert!(import(&data).is_none());
        // The scrambled-prefix check must not catch the PBP container.
        assert!(!is_prx(b"PBP\x00PSP Mistake"));
    }
}
