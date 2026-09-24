//! Nintendo DS ARM9 overlay tables (P1.6).
//!
//! A DS cartridge pages code in and out of main RAM through overlays.
//! The ROM header names two tables (gbatek "DS Cartridge Header",
//! public offsets, reimplemented here without upstream code):
//!
//! - FAT at header `0x48` (offset) / `0x4C` (size): a run of
//!   `{start u32 LE, end u32 LE}` file offsets indexed by file id.
//! - ARM9 OVT at header `0x50` (offset) / `0x54` (size): a run of
//!   32-byte entries, each
//!   `{overlay_id u32, ram_addr u32, ram_size u32, bss_size u32,
//!     static_init_start u32, static_init_end u32, file_id u32,
//!     flags u32}` (all LE); `flags` bit 24 marks the file as packed
//!   with the backward LZ the ARM9 static module uses, bits 0-23 its
//!   packed size.
//!
//! Each overlay's bytes live in the file at `FAT[file_id]`, and load
//! at `ram_addr` with resident size `ram_size + bss_size` (the `bss`
//! tail is zero-filled; it has no file bytes). Overlays share RAM --
//! the game swaps them -- so overlapping load addresses are legal and
//! no overlap check runs.
//!
//! Model: each overlay is its own program `ov<N>` (`N` = overlay id)
//! beside `arm9` and `arm7`, mapping only its own bytes at `ram_addr`,
//! so `store_import` mints one `modules` row for it. An
//! `(overlay-id, addr)` pair binds through [`bind`] / [`bind_offset`] to
//! its module, RAM address and file offset -- the hook a symbol reader
//! (e.g. an mwldarm MAP with overlay-relative symbols) resolves through.

use super::{Mapping, NativeImport};
use romwright_model::{Address, ModuleRow};

/// ROM header offsets (gbatek "DS Cartridge Header", LE u32 each).
pub const FAT_OFFSET_OFF: usize = 0x48;
/// ROM header offset of the FAT size word.
pub const FAT_SIZE_OFF: usize = 0x4C;
/// ROM header offset of the ARM9 OVT offset word.
pub const OVT_OFFSET_OFF: usize = 0x50;
/// ROM header offset of the ARM9 OVT size word.
pub const OVT_SIZE_OFF: usize = 0x54;
/// One OVT entry is eight LE words.
pub const OVT_ENTRY_SIZE: usize = 32;
/// One FAT entry is two LE words.
pub const FAT_ENTRY_SIZE: usize = 8;

/// One ARM9 overlay: where it lives in the file and where it loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsOverlay {
    /// Overlay id as the OVT states it; also names the module `ov<N>`.
    pub overlay_id: u32,
    /// RAM address the overlay loads at.
    pub ram_addr: u64,
    /// File-backed resident size in bytes.
    pub ram_size: u64,
    /// Zero-filled tail past `ram_size`, with no file bytes.
    pub bss_size: u64,
    /// RAM address of the static initializer start (from the OVT).
    pub static_init_start: u32,
    /// RAM address of the static initializer end (from the OVT).
    pub static_init_end: u32,
    /// FAT index whose `{offset, size}` holds this overlay's bytes.
    pub file_id: u32,
    /// File offset of the overlay's bytes (from the FAT).
    pub file_off: u64,
    /// File size of the overlay's bytes (from the FAT).
    pub file_size: u64,
    /// The file holds the overlay packed (OVT flags bit 24); its RAM
    /// image is what `MIi_UncompressBackward` makes of it.
    pub compressed: bool,
}

impl DsOverlay {
    /// Module name for this overlay: `ov<N>`.
    pub fn name(&self) -> String {
        format!("ov{}", self.overlay_id)
    }

    /// Resident size: file-backed bytes plus the zero-filled BSS tail.
    /// `file_size` wins over `ram_size` when the FAT holds more than
    /// the OVT declares (never truncated: the mapping keeps every
    /// file byte).
    pub fn total_size(&self) -> u64 {
        self.file_size.max(self.ram_size).saturating_add(self.bss_size)
    }

    /// True when `addr` lands in this overlay's resident range
    /// (`ram_addr..ram_addr + total_size`), BSS included.
    pub fn contains_ram(&self, addr: u64) -> bool {
        addr >= self.ram_addr && addr - self.ram_addr < self.total_size()
    }

    /// RAM address of `offset` bytes into the overlay, when the offset
    /// is file-backed (`offset < ram_size`).
    pub fn ram_addr_of(&self, offset: u64) -> Option<u64> {
        (offset < self.ram_size).then(|| self.ram_addr + offset)
    }

    /// File offset backing `addr`, when `addr` is in this overlay's
    /// file-backed part (BSS has no file bytes and returns `None`, and
    /// neither does a packed overlay, whose file bytes are not its RAM).
    pub fn file_off_of_ram(&self, addr: u64) -> Option<u64> {
        let off = addr.checked_sub(self.ram_addr)?;
        (!self.compressed && off < self.ram_size && off < self.file_size).then(|| self.file_off + off)
    }
}

/// One bound `(overlay-id, addr)` pair: which module it belongs to,
/// where it runs, and where its byte sits in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundAddr {
    /// Owning module name (`ov<N>`).
    pub module: String,
    /// RAM address (echoes the queried address).
    pub ram_addr: u64,
    /// File offset of the byte at `ram_addr`, when file-backed.
    /// `None` for an address in the overlay's BSS tail.
    pub file_off: Option<u64>,
}

fn u32_le(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

/// Walks the ARM9 OVT + FAT and returns one row per well-formed
/// overlay, in table order. Malformed entries are skipped; a missing
/// or truncated table yields an empty vec (a cartridge without
/// overlays is ordinary, not an error).
pub fn parse(data: &[u8]) -> Vec<DsOverlay> {
    let Some(header) = data.get(..OVT_SIZE_OFF + 4) else {
        return Vec::new();
    };
    let word = |off: usize| u32::from_le_bytes(header[off..off + 4].try_into().unwrap()) as u64;
    let fat_off = word(FAT_OFFSET_OFF);
    let fat_size = word(FAT_SIZE_OFF);
    let ovt_off = word(OVT_OFFSET_OFF);
    let ovt_size = word(OVT_SIZE_OFF);
    let len = data.len() as u64;
    // Both tables must sit inside the file; a zero OVT size means no
    // overlays, which is the common case for homebrew/small games.
    if ovt_size == 0 {
        return Vec::new();
    }
    let Some(ovt_end) = ovt_off.checked_add(ovt_size) else {
        return Vec::new();
    };
    let Some(fat_end) = fat_off.checked_add(fat_size) else {
        return Vec::new();
    };
    if ovt_end > len || fat_end > len {
        return Vec::new();
    }
    let fat_count = (fat_size / FAT_ENTRY_SIZE as u64) as usize;
    let mut out = Vec::new();
    let entries = ovt_size / OVT_ENTRY_SIZE as u64;
    for i in 0..entries {
        let base = (ovt_off + i * OVT_ENTRY_SIZE as u64) as usize;
        let entry = &data[base..base + OVT_ENTRY_SIZE];
        let w = |o: usize| u32::from_le_bytes(entry[o..o + 4].try_into().unwrap());
        let overlay = DsOverlay {
            overlay_id: w(0),
            ram_addr: w(4) as u64,
            ram_size: w(8) as u64,
            bss_size: w(12) as u64,
            static_init_start: w(16),
            static_init_end: w(20),
            file_id: w(24),
            file_off: 0,
            file_size: 0,
            compressed: w(28) & 0x0100_0000 != 0,
        };
        if overlay.ram_size == 0 {
            continue;
        }
        // FAT index must exist and its byte range must fit the file.
        let fat_at = (fat_off as usize) + (overlay.file_id as usize) * FAT_ENTRY_SIZE;
        if (overlay.file_id as usize) >= fat_count {
            continue;
        }
        let (Some(f_off), Some(f_end)) = (u32_le(data, fat_at), u32_le(data, fat_at + 4)) else {
            continue;
        };
        let (f_off, f_end) = (f_off as u64, f_end as u64);
        // A FAT entry is a start and an end offset. Read as a size, the
        // end mapped a megabyte of other files behind every overlay of
        // Pokemon HeartGold, and discovery walked each copy.
        if f_end <= f_off || f_end > len {
            continue;
        }
        let f_size = f_end - f_off;
        out.push(DsOverlay {
            file_off: f_off,
            file_size: f_size,
            ..overlay
        });
    }
    out
}

/// One `modules`-row per overlay: `module_id` 0 (the store assigns
/// one), `name` `ov<N>`, `kind` `"overlay"`, `file_id` the FAT index,
/// `load_vaddr` the RAM address, `size` the resident size
/// (`ram_size + bss_size`), `file_off` the FAT offset, resident.
pub fn modules(overlays: &[DsOverlay]) -> Vec<ModuleRow> {
    overlays
        .iter()
        .map(|ov| ModuleRow {
            module_id: 0,
            program: String::new(),
            name: ov.name(),
            kind: "overlay".into(),
            file_id: ov.file_id.to_string(),
            load_vaddr: Address::ram(ov.ram_addr),
            size: ov.total_size(),
            file_off: ov.file_off,
            resident: true,
        })
        .collect()
}

/// The RAM image each overlay contributes to an import: its FAT bytes
/// (unpacked when the OVT marks them packed), zero-padded to `ram_size`
/// when the file holds fewer, plus `bss_size` zero bytes. Returns
/// `(Mapping, name)` pairs in table order, and the names of packed
/// overlays whose bytes did not unpack to exactly `ram_size`.
pub fn mappings_for(data: &[u8], overlays: &[DsOverlay]) -> (Vec<(Mapping, String)>, Vec<String>) {
    let len = data.len() as u64;
    let mut out = Vec::with_capacity(overlays.len());
    let mut refused = Vec::new();
    for ov in overlays {
        let Some(f_end) = ov.file_off.checked_add(ov.file_size) else {
            continue;
        };
        if f_end > len {
            continue;
        }
        let stored = &data[ov.file_off as usize..f_end as usize];
        let mut bytes = if ov.compressed {
            // The packed file ends where its footer does, so the bottom
            // `MIi_UncompressBackward` starts from is the file's end.
            match super::nds::uncompress_backward(stored, ov.ram_addr, ov.ram_addr + ov.file_size) {
                Some(unpacked) if unpacked.len() as u64 == ov.ram_size => unpacked,
                _ => {
                    refused.push(ov.name());
                    continue;
                }
            }
        } else {
            stored.to_vec()
        };
        // A short file still loads a full `ram_size` window; the
        // missing tail reads as zeros, like BSS does.
        if (bytes.len() as u64) < ov.ram_size {
            bytes.resize(ov.ram_size as usize, 0);
        }
        bytes.extend(std::iter::repeat(0).take(ov.bss_size as usize));
        let size = bytes.len() as u64;
        out.push((
            Mapping {
                vaddr: ov.ram_addr,
                size,
                file_off: ov.file_off,
                // Code paged into RAM: readable, writable, executable,
                // as the console leaves it.
                flags: 0x7,
                bytes,
            },
            ov.name(),
        ));
    }
    (out, refused)
}

/// One program per overlay, named `ov<N>`, holding only that overlay's
/// mapping. Overlays share RAM, so they cannot sit in one address space:
/// Pokemon HeartGold loads 129 of them into a few windows, and one
/// program with every copy overlapping made address-keyed discovery and
/// its stores conflate unrelated code. Calls from an overlay into the
/// static ARM9 image leave its own program, like calls into a library.
/// The second list names the overlays [`mappings_for`] refused.
pub fn programs_for(
    data: &[u8],
    overlays: &[DsOverlay],
    language: &str,
) -> (Vec<(String, NativeImport)>, Vec<String>) {
    let (mappings, refused) = mappings_for(data, overlays);
    let programs = mappings
        .into_iter()
        .map(|(mapping, name)| {
            let import = NativeImport {
                mappings: vec![mapping],
                mapping_names: vec![name.clone()],
                format: "nds".into(),
                language: language.into(),
                ..Default::default()
            };
            (name, import)
        })
        .collect();
    (programs, refused)
}

/// Finds the overlay with `overlay_id` that contains absolute RAM
/// address `addr` (BSS included), binding the pair to its module and
/// file offset. `None` when no overlay with that id covers `addr`.
pub fn bind(overlays: &[DsOverlay], overlay_id: u32, addr: u64) -> Option<BoundAddr> {
    overlays
        .iter()
        .find(|ov| ov.overlay_id == overlay_id && ov.contains_ram(addr))
        .map(|ov| BoundAddr {
            module: ov.name(),
            ram_addr: addr,
            file_off: ov.file_off_of_ram(addr),
        })
}

/// Binds `offset` bytes into overlay `overlay_id` (offset origin =
/// the overlay's load address) to its RAM address and file offset.
/// `None` when the offset is past the overlay's file-backed size.
pub fn bind_offset(overlays: &[DsOverlay], overlay_id: u32, offset: u64) -> Option<BoundAddr> {
    let ov = overlays.iter().find(|ov| ov.overlay_id == overlay_id)?;
    let ram_addr = ov.ram_addr_of(offset)?;
    Some(BoundAddr {
        module: ov.name(),
        ram_addr,
        file_off: ov.file_off_of_ram(ram_addr),
    })
}

/// Which overlay covers absolute RAM address `addr`, if any. With
/// overlapping overlays several may cover it; the first in table
/// order wins (call [`bind`] with an id to disambiguate).
pub fn overlay_at(overlays: &[DsOverlay], addr: u64) -> Option<&DsOverlay> {
    overlays.iter().find(|ov| ov.contains_ram(addr))
}

/// The overlay with `overlay_id`, if the table holds one.
pub fn overlay_by_id(overlays: &[DsOverlay], overlay_id: u32) -> Option<&DsOverlay> {
    overlays.iter().find(|ov| ov.overlay_id == overlay_id)
}

/// Canonical symbol spelling for an address in an overlay:
/// `ov<N>_XXXXXXXX` (8 lowercase hex digits, the decomp-project
/// convention for overlay-relative names).
pub fn symbol_name(overlay_id: u32, ram_addr: u64) -> String {
    format!("ov{overlay_id}_{ram_addr:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARM9_DESC: usize = 0x20;
    const ARM7_DESC: usize = 0x30;

    fn write_words(data: &mut [u8], at: usize, words: &[u32]) {
        for (i, w) in words.iter().enumerate() {
            data[at + i * 4..at + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
    }

    /// Synthetic .nds: valid ARM9/ARM7 statics plus a 2-entry OVT, a
    /// 2-entry FAT and two overlay payloads.
    fn cartridge() -> Vec<u8> {
        let mut data = vec![0u8; 0x5000];
        // ARM9 static: 0x100 bytes at 0x4000, RAM 0x02000000.
        write_words(&mut data, ARM9_DESC, &[0x4000, 0x0200_0020, 0x0200_0000, 0x100]);
        // ARM7 static: 0x100 bytes at 0x4100, WRAM 0x037f8000.
        write_words(&mut data, ARM7_DESC, &[0x4100, 0x037F_8010, 0x037F_8000, 0x100]);
        // FAT: 2 entries at 0x4240; OVT: 2 entries at 0x4200.
        write_words(&mut data, FAT_OFFSET_OFF, &[0x4240, 16]);
        write_words(&mut data, OVT_OFFSET_OFF, &[0x4200, 64]);
        // OVT[0]: id 0, RAM 0x02100000, 0x40 bytes + 0x10 BSS, file 0.
        write_words(
            &mut data,
            0x4200,
            &[0, 0x0210_0000, 0x40, 0x10, 0, 0, 0, 0],
        );
        // OVT[1]: id 1, RAM 0x02110000, 0x80 bytes, file 1.
        write_words(
            &mut data,
            0x4220,
            &[1, 0x0211_0000, 0x80, 0, 0, 0, 1, 0],
        );
        // FAT entries are {start, end}: FAT[0] -> 0x4300..0x4340,
        // FAT[1] -> 0x4340..0x43C0.
        write_words(&mut data, 0x4240, &[0x4300, 0x4340]);
        write_words(&mut data, 0x4248, &[0x4340, 0x43C0]);
        data[0x4300..0x4340].fill(0xAA);
        data[0x4340..0x43C0].fill(0xBB);
        data
    }

    #[test]
    fn ovt_and_fat_walk_yields_one_row_per_overlay() {
        let ov = parse(&cartridge());
        assert_eq!(ov.len(), 2);
        assert_eq!(
            ov[0],
            DsOverlay {
                overlay_id: 0,
                ram_addr: 0x0210_0000,
                ram_size: 0x40,
                bss_size: 0x10,
                static_init_start: 0,
                static_init_end: 0,
                file_id: 0,
                file_off: 0x4300,
                file_size: 0x40,
                compressed: false,
            }
        );
        assert_eq!(ov[1].overlay_id, 1);
        assert_eq!(ov[1].ram_addr, 0x0211_0000);
        assert_eq!((ov[1].file_off, ov[1].file_size), (0x4340, 0x80));
    }

    #[test]
    fn module_rows_carry_name_vaddr_size_and_file_off() {
        let rows = modules(&parse(&cartridge()));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "ov0");
        assert_eq!(rows[0].load_vaddr, Address::ram(0x0210_0000));
        // 0x40 file bytes + 0x10 zero-filled BSS.
        assert_eq!(rows[0].size, 0x50);
        assert_eq!(rows[0].file_off, 0x4300);
        assert_eq!(rows[0].kind, "overlay");
        assert!(rows[0].resident);
        assert_eq!(rows[1].name, "ov1");
        assert_eq!(rows[1].load_vaddr, Address::ram(0x0211_0000));
        assert_eq!(rows[1].size, 0x80);
        assert_eq!(rows[1].file_off, 0x4340);
    }

    #[test]
    fn overlay_id_and_addr_bind_to_module_ram_and_file() {
        let ov = parse(&cartridge());
        let bound = bind(&ov, 0, 0x0210_0010).expect("ov0 covers its window");
        assert_eq!(bound.module, "ov0");
        assert_eq!(bound.ram_addr, 0x0210_0010);
        assert_eq!(bound.file_off, Some(0x4310));
        // BSS tail binds to the module but has no file byte.
        let bss = bind(&ov, 0, 0x0210_0045).expect("BSS is still resident");
        assert_eq!(bss.module, "ov0");
        assert_eq!(bss.file_off, None);
        // Wrong id does not cross-bind even at a covered address.
        assert!(bind(&ov, 1, 0x0210_0010).is_none());
        assert!(bind(&ov, 9, 0x0210_0010).is_none());
        // Offset form: 0x10 into ov1 == RAM 0x02110010, file 0x4350.
        let off = bind_offset(&ov, 1, 0x10).expect("offset in range");
        assert_eq!((off.ram_addr, off.file_off), (0x0211_0010, Some(0x4350)));
        assert!(bind_offset(&ov, 1, 0x80).is_none());
        // Coverage + lookup helpers agree.
        assert_eq!(overlay_at(&ov, 0x0211_0010).unwrap().overlay_id, 1);
        assert_eq!(overlay_by_id(&ov, 0).unwrap().ram_addr, 0x0210_0000);
        assert_eq!(symbol_name(3, 0x0210_0010), "ov3_02100010");
    }

    #[test]
    fn mappings_carry_overlay_bytes_with_zeroed_bss() {
        let data = cartridge();
        let ov = parse(&data);
        let (maps, refused) = mappings_for(&data, &ov);
        assert!(refused.is_empty());
        assert_eq!(maps.len(), 2);
        assert_eq!((maps[0].0.vaddr, maps[0].0.size), (0x0210_0000, 0x50));
        assert_eq!((maps[0].0.file_off, maps[0].1.as_str()), (0x4300, "ov0"));
        assert!(maps[0].0.bytes[..0x40].iter().all(|&b| b == 0xAA));
        assert!(maps[0].0.bytes[0x40..].iter().all(|&b| b == 0));
        assert!(maps[1].0.bytes.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn each_overlay_is_its_own_program_beside_the_static_images() {
        let data = cartridge();
        let images = super::super::nds::import(&data).expect("cartridge");
        let names: Vec<&str> = images.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["arm9", "arm7", "ov0", "ov1"]);
        // Overlays share RAM, so the static ARM9 program maps only itself.
        assert_eq!(images[0].1.mapping_names, vec!["arm9"]);
        let (_, ov0) = &images[2];
        assert_eq!(ov0.language, images[0].1.language);
        assert_eq!((ov0.mappings.len(), ov0.mappings[0].vaddr), (1, 0x0210_0000));
        assert_eq!((ov0.mappings[0].file_off, ov0.mappings[0].bytes[0]), (0x4300, 0xAA));
        assert_eq!(images[3].1.mappings[0].vaddr, 0x0211_0000);
    }

    /// A packed overlay is its unpacked RAM image or nothing: bytes that
    /// do not unpack to `ram_size` are refused and named, never mapped as
    /// code.
    #[test]
    fn a_packed_overlay_that_does_not_unpack_is_refused_by_name() {
        let mut data = cartridge();
        // OVT[1] flags: packed, 0x80 bytes; its file is 0xBB filler.
        write_words(&mut data, 0x4220 + 28, &[0x0100_0080]);
        let (programs, refused) = programs_for(&data, &parse(&data), "ARM:LE:32:v5t");
        assert_eq!(refused, ["ov1"]);
        assert_eq!(programs.len(), 1);
        let images = super::super::nds::import(&data).expect("cartridge");
        assert!(images[0].1.diagnostics.iter().any(|d| d.message.contains("ov1")));
    }

    #[test]
    fn missing_ovt_means_no_overlays_not_an_error() {
        let mut data = cartridge();
        write_words(&mut data, OVT_OFFSET_OFF, &[0, 0]);
        assert!(parse(&data).is_empty());
        let images = super::super::nds::import(&data).expect("still a cartridge");
        assert_eq!(images.len(), 2);
    }

    #[test]
    fn malformed_entries_are_skipped_not_fatal() {
        let mut data = cartridge();
        // OVT[1] points at FAT index 7, which does not exist.
        write_words(&mut data, 0x4220 + 24, &[7]);
        let ov = parse(&data);
        assert_eq!(ov.len(), 1);
        assert_eq!(ov[0].overlay_id, 0);
    }
}
