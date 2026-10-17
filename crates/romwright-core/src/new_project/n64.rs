//! The Nintendo 64 plugin: a cartridge ROM in, a splat + ninja repository out.
//!
//! The yaml covers the ROM in file order: the 0x40-byte header (splat's `header`
//! segment), the 0xFC0-byte IPL3 boot code (`databin`), then romwright's layout
//! (`native/n64_discovery.rs`, or a catalog entry): every executable range of
//! the main program that sits in the ROM as raw bytes is a `code` segment of
//! per-function `asm` units and `textbin` gaps; everything else (data, assets,
//! compressed segments and overlays, which have no raw MIPS to split) is a
//! `databin` of its own, so the rebuild reproduces the ROM byte for byte.
//!
//! Byte order: ROMs are normalised to big-endian `.z64` before anything else
//! (the importer and splat both read that order); `config/project.json`
//! records the order the dump had, and `tools/n64crc.py swap` converts a build
//! back. The header CRC1/CRC2 are recomputed after linking when the CIC is a
//! known one and the retail header is consistent with it (a no-op while the
//! image is still all assembly, REQUIRED once a C unit changes the code).

use serde_json::json;

use super::detect::detect_n64;
use super::mips::{assemble, plan_layout, rows_in, yaml_options, write_segments, Built, Inputs, Load, MipsReport, Segment, Spec};
use super::GeneratedFile;
use crate::export::{sha1_hex, Backing};

const SPEC: Spec = Spec {
    id: "n64",
    name: "Nintendo 64",
    subject: "Nintendo 64 (VR4300, o32)",
    asflags: &["-EB", "-march=vr4300", "-mabi=32"],
    endian: "big",
    link_flag: "EB",
    // `plan` sets it when the CIC is known and the retail header is consistent with it.
    post: None,
    readme_limits: "* Only segments that are raw MIPS in the ROM are split into functions. Compressed segments (Yaz0, MIO0, Yay0, Rare 0x1172/0x1173, DEFLATE) are carried as the compressed bytes: a decompressed segment cannot be re-compressed byte-identically in general, so those functions are not part of the build and `romwright-cli match` does not see them.\n* Data and rodata between functions are `textbin` pieces inside a code segment (no `.data/.rodata/.bss` split): literals and tables a C unit emits are not linked, the retail bytes stay.\n* `build/<image>` is big-endian (`.z64`); `python3 tools/n64crc.py swap build/<image> out.v64 v64` writes the other byte orders.",
};

/// Dump byte orders by the first word of the header (n64brew "ROM header").
pub fn byte_order(data: &[u8]) -> Option<&'static str> {
    match data.get(..4)? {
        [0x80, 0x37, 0x12, 0x40] => Some("z64"),
        [0x37, 0x80, 0x40, 0x12] => Some("v64"),
        [0x40, 0x12, 0x37, 0x80] => Some("n64"),
        _ => None,
    }
}

/// A ROM in any dump order, as big-endian `.z64` bytes.
pub fn to_z64(data: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    let order = byte_order(data)?;
    let mut out = data.to_vec();
    let n = out.len() - out.len() % 4;
    match order {
        "v64" => out[..n].as_chunks_mut::<2>().0.iter_mut().for_each(|pair| pair.swap(0, 1)),
        "n64" => out[..n].as_chunks_mut::<4>().0.iter_mut().for_each(|word| word.reverse()),
        _ => {}
    }
    Some((out, order))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// `(CIC name, CRC1, CRC2)` of a `.z64` ROM; `None` for an unknown boot code or a
/// ROM shorter than 1 MiB + 0x1000 (n64brew "CIC-NUS"; same algorithm as `tools/n64crc.py`).
pub fn header_crcs(rom: &[u8]) -> Option<(&'static str, u32, u32)> {
    if rom.len() < 0x10_1000 {
        return None;
    }
    let (name, seed) = match crc32(&rom[0x40..0x1000]) {
        0x6170_A4A1 => ("6101", 0xF8CA_4DDCu32),
        0x90BB_6CB5 => ("6102", 0xF8CA_4DDC),
        0x0B05_0EE0 => ("6103", 0xA388_6759),
        0x98BC_2C86 => ("6105", 0xDF26_F436),
        0xACC8_580A => ("6106", 0x1FEA_617A),
        _ => return None,
    };
    let word = |at: usize| u32::from_be_bytes([rom[at], rom[at + 1], rom[at + 2], rom[at + 3]]);
    let (mut t1, mut t2, mut t3, mut t4, mut t5, mut t6) = (seed, seed, seed, seed, seed, seed);
    for i in (0..0x10_0000usize).step_by(4) {
        let d = word(0x1000 + i);
        if t6.wrapping_add(d) < t6 {
            t4 = t4.wrapping_add(1);
        }
        t6 = t6.wrapping_add(d);
        t3 ^= d;
        let r = d.rotate_left(d & 31);
        t5 = t5.wrapping_add(r);
        t2 = if t2 > d { t2 ^ r } else { t2 ^ t6 ^ d };
        t1 = if name == "6105" { t1.wrapping_add(word(0x40 + 0x710 + (i & 0xFF)) ^ d) } else { t1.wrapping_add(t5 ^ d) };
    }
    let (c1, c2) = match name {
        "6103" => ((t6 ^ t4).wrapping_add(t3), (t5 ^ t2).wrapping_add(t1)),
        "6106" => (t6.wrapping_mul(t4).wrapping_add(t3), t5.wrapping_mul(t2).wrapping_add(t1)),
        _ => (t6 ^ t4 ^ t3, t5 ^ t2 ^ t1),
    };
    Some((name, c1, c2))
}

/// Everything about the dump `plan` cannot read from the `.z64` bytes.
pub struct N64Source<'a> {
    /// `z64`, `v64` or `n64`.
    pub order: &'a str,
    /// sha1 of the dump as the user supplied it.
    pub dump_sha1: &'a str,
    /// File-backed ranges of the main program (`export::file_backing` of its mappings).
    pub backing: &'a [Backing],
}

pub fn plan(inputs: &Inputs, source: &N64Source) -> Result<(Vec<GeneratedFile>, MipsReport), String> {
    if byte_order(inputs.image) != Some("z64") {
        return Err("the ROM must be in big-endian (.z64) order here; `new-project` normalises dumps first".into());
    }
    // Code ranges: executable regions of the program that are raw bytes of the ROM.
    let mut code: Vec<(u64, u64, u64, String)> = Vec::new(); // offset, size, vram, name
    for region in inputs.facts.regions.iter().filter(|r| r.source == "native-import" && r.size != 0 && r.permissions.contains('x')) {
        let Some(b) = source.backing.iter().find(|b| b.vaddr == region.start.offset) else { continue };
        let size = b.size.min(region.size);
        if size == 0 || b.file_off + size > inputs.image.len() as u64 {
            continue;
        }
        let name: String = region.name.trim_start_matches("n64:").chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
        code.push((b.file_off, size, b.vaddr, name));
    }
    code.sort();
    // The cartridge window and overlapping views of one range: the first claim keeps it.
    let mut kept: Vec<(u64, u64, u64, String)> = Vec::new();
    for range in code {
        if kept.last().is_some_and(|last| range.0 < last.0 + last.1) {
            continue;
        }
        kept.push(range);
    }
    let mut notes = Vec::new();
    if kept.is_empty() {
        return Err("romwright's layout found no raw executable range in this ROM (every code segment is compressed): nothing for splat to disassemble".into());
    }
    let detection = detect_n64(inputs.image, &kept.iter().map(|k| (k.0, k.1)).collect::<Vec<_>>());
    let mapped = |address: u64| kept.iter().any(|k| address >= k.2 && address < k.2 + k.1);
    let rows = rows_in(inputs.facts, &mapped);
    let loads: Vec<Load> = kept
        .iter()
        .enumerate()
        .map(|(i, k)| Load { offset: k.0, vram: k.2, size: k.1, name: if i == 0 { "main".to_string() } else { k.3.clone() }, rows: None })
        .collect();
    let gap = |from: u64, to: u64| -> Vec<Segment> {
        let mut out = Vec::new();
        let mut at = from;
        if at == 0 && to >= 0x40 {
            out.push(Segment::Bin { name: "header".into(), start: 0, ty: "header" });
            at = 0x40;
        }
        if at == 0x40 && to >= 0x1000 {
            out.push(Segment::databin("ipl3", 0x40));
            at = 0x1000;
        }
        if at < to {
            out.push(Segment::databin(format!("bin_{at:x}"), at));
        }
        out
    };
    let layout = plan_layout(inputs.image, &loads, &rows, inputs.image.len() as u64, &gap)?;
    let sha1 = sha1_hex(inputs.image);
    let header_crc = (u32::from_be_bytes(inputs.image[0x10..0x14].try_into().unwrap()), u32::from_be_bytes(inputs.image[0x14..0x18].try_into().unwrap()));
    let post = match header_crcs(inputs.image) {
        Some((cic, c1, c2)) if (c1, c2) == header_crc => {
            notes.push(format!("CIC-{cic}: the header CRC1/CRC2 ({:08x} {:08x}) reproduce from the ROM; `ninja` recomputes them after linking", header_crc.0, header_crc.1));
            Some("n64crc")
        }
        Some((cic, c1, c2)) => {
            notes.push(format!("CIC-{cic}: the retail header CRCs ({:08x} {:08x}) are not what the ROM computes ({c1:08x} {c2:08x}); they are not recomputed", header_crc.0, header_crc.1));
            None
        }
        None => {
            notes.push("the boot code is not a known CIC (or the ROM is shorter than 1 MiB + 0x1000): the header CRCs are not recomputed".to_string());
            None
        }
    };
    if source.order != "z64" {
        notes.push(format!("the dump was in {} byte order; it is normalised to big-endian `.z64` (checksum and `orig/` are the normalised bytes, dump sha1 {})", source.order, source.dump_sha1));
    }
    let compressed = inputs.facts.regions.iter().filter(|r| r.source == "native-import" && r.size != 0 && r.permissions.contains('x')).count().saturating_sub(kept.len());
    if compressed > 0 {
        notes.push(format!("{compressed} further executable region(s) of the import are not raw bytes of the ROM (compressed or overlaid) or duplicate a view; they stay `databin` pieces"));
    }
    let mut extra = vec!["header_encoding: word".to_string()];
    extra.push("ld_bss_is_noload: True".to_string());
    let mut yaml = yaml_options(inputs.image_name, &sha1, "n64", detection.splat_compiler, &extra);
    write_segments(&mut yaml, &layout, inputs.image.len());
    let layout_json: Vec<_> = kept.iter().map(|k| json!({"offset": k.0, "vaddr": k.2, "size": k.1, "name": k.3})).collect();
    let built = Built {
        layout,
        yaml,
        detection,
        rows,
        image_json: json!({
            "format": "n64 rom",
            "source_byte_order": source.order,
            "source_sha1": source.dump_sha1,
            "header_crc": [format!("{:08x}", header_crc.0), format!("{:08x}", header_crc.1)],
        }),
        layout_json,
        extra_files: vec![super::mips::template("tools/n64crc.py", include_str!("templates/mips/tools/n64crc.py"), true)],
        post,
        notes,
    };
    assemble(&SPEC, inputs, built)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_orders_round_trip_to_z64() {
        let z64 = [0x80, 0x37, 0x12, 0x40, 1, 2, 3, 4];
        let v64 = [0x37, 0x80, 0x40, 0x12, 2, 1, 4, 3];
        let n64 = [0x40, 0x12, 0x37, 0x80, 4, 3, 2, 1];
        assert_eq!(to_z64(&z64), Some((z64.to_vec(), "z64")));
        assert_eq!(to_z64(&v64), Some((z64.to_vec(), "v64")));
        assert_eq!(to_z64(&n64), Some((z64.to_vec(), "n64")));
        assert_eq!(to_z64(b"nope"), None);
    }

    #[test]
    fn plan_writes_header_ipl3_code_and_binary_segments() {
        // 0x1000 header+ipl3, code 0x1000..0x1040 at 0x80000400 (f1, f2), a 0x40 data tail.
        let mut rom = vec![0u8; 0x1080];
        rom[..4].copy_from_slice(&[0x80, 0x37, 0x12, 0x40]);
        for range in [0x1000..0x1010, 0x1020..0x1030] {
            rom[range].fill(0x11);
        }
        let function = |name: &str, address: u64| romwright_model::FunctionRow {
            entry: romwright_model::Address::ram(address),
            name: name.into(),
            size: 0x10,
            signature: None,
            traced: false,
            calling_convention: None,
        };
        let region = |name: &str, start: u64, size: u64, permissions: &str, source: &str| romwright_model::MemoryRegion {
            name: name.into(),
            start: romwright_model::Address::ram(start),
            size,
            permissions: permissions.into(),
            source: source.into(),
        };
        let facts = crate::export::ExportFacts {
            program: "t".into(),
            functions: vec![function("f1", 0x8000_0400), function("f2", 0x8000_0420)],
            regions: vec![
                region("n64:cartridge", 0x1000_0000, 0x1080, "r--", "native-import"),
                region("n64:boot", 0x8000_0400, 0x40, "rwx", "native-import"),
                region("n64:rdram", 0x8000_0000, 0x80_0000, "rwx", "native-import:platform-map"),
            ],
            ..Default::default()
        };
        let backing = [Backing { vaddr: 0x8000_0400, size: 0x40, file_off: 0x1000 }, Backing { vaddr: 0x1000_0000, size: 0x1080, file_off: 0 }];
        let manifest = super::super::manifest::Manifest::builtin();
        let inputs = Inputs {
            image: &rom,
            image_name: "g.z64",
            project_name: "g",
            facts: &facts,
            prototypes: &[],
            manifest: &manifest,
            compiler_id: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        };
        let (files, report) = plan(&inputs, &N64Source { order: "v64", dump_sha1: "abc", backing: &backing }).unwrap();
        let get = |path: &str| String::from_utf8(files.iter().find(|f| f.path == path).unwrap().bytes.clone()).unwrap();
        let yaml = get("config/g.z64.yaml");
        for line in [
            "  platform: n64",
            "  header_encoding: word",
            "  - name: header\n    type: header\n    start: 0x0\n  - name: ipl3\n    type: databin\n    start: 0x40",
            "start: 0x1000\n    vram: 0x80000400",
            "- [0x1000, asm, main/0000/f1]",
            "- [0x1020, asm, main/0000/f2]",
            "  - name: trailer\n    type: databin\n    start: 0x1040",
            "  - [0x1080]",
        ] {
            assert!(yaml.contains(line), "{line}\n{yaml}");
        }
        assert_eq!(report.asm_units, 2);
        assert!(report.notes.iter().any(|n| n.contains("v64 byte order")), "{:?}", report.notes);
        let project = get("config/project.json");
        assert!(project.contains("\"source_byte_order\": \"v64\"") && project.contains("\"endian\": \"big\""), "{project}");
        // A ROM this short has no CRC to reproduce, so the post step is off.
        assert!(!project.contains("n64crc"), "{project}");
        // And a ROM with no raw code range is refused, not silently emitted as binary.
        let none = crate::export::ExportFacts { regions: vec![], ..Default::default() };
        let refused = plan(&Inputs { facts: &none, ..inputs }, &N64Source { order: "z64", dump_sha1: "abc", backing: &backing });
        assert!(refused.unwrap_err().contains("no raw executable range"));
    }

    #[test]
    fn crc32_is_the_ieee_one() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
