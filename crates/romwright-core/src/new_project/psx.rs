//! The PlayStation plugin: a PS-X EXE in, a splat + ninja repository out.
//!
//! The file is the 0x800-byte header (`PS-X EXE`, `pc0`, `gp0`, `t_addr`,
//! `t_size`, ...) followed by one flat image of `t_size` bytes loaded at
//! `t_addr`. The yaml covers it in file order like the PS2 plugin: the header
//! is a `databin`, the image one `code` segment of per-function `asm` units
//! and `textbin` gaps, and anything after `t_size` a `databin` trailer.
//! Compiled units go through PSY-Q's `CC1PSX` and maspsx (`tools/toolchain.py`).

use serde_json::json;

use super::detect::detect_psx;
use super::mips::{assemble, plan_layout, rows_in, yaml_options, write_segments, Built, Inputs, Load, MipsReport, Segment, Spec};
use super::GeneratedFile;
use crate::export::sha1_hex;

const HEADER_LEN: u64 = 0x800;

const SPEC: Spec = Spec {
    id: "psx",
    name: "PlayStation",
    subject: "PlayStation (R3000, o32)",
    asflags: &["-EL", "-march=r3000", "-mabi=32"],
    endian: "little",
    link_flag: "EL",
    post: None,
    readme_limits: "* GTE instructions are written with the `gte_macros.inc` macros splat generates; the rebuild is checked word for word against the listing.\n* Overlays and modules loaded from the disc (`BODYPROG.BIN`, `MAP*.BIN`) are separate files and not part of this project.\n* `maspsx` emulates ASPSX per version; `compiler.aspsx` in `config/project.json` selects the one used for compiled units (the version `CC1PSX` prints in its own output wins).",
};

/// The fields of the PS-X EXE header this plugin reads.
#[derive(Debug)]
pub struct PsxHeader {
    pub pc0: u32,
    pub gp0: u32,
    pub t_addr: u32,
    pub t_size: u32,
}

fn word(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

pub fn looks_like_psx_exe(image: &[u8]) -> bool {
    image.len() >= HEADER_LEN as usize && &image[..8] == b"PS-X EXE"
}

pub fn parse_header(image: &[u8]) -> Result<PsxHeader, String> {
    if !looks_like_psx_exe(image) {
        return Err("not a PS-X EXE: no `PS-X EXE` magic in the first 0x800 bytes".into());
    }
    let header = PsxHeader { pc0: word(image, 0x10), gp0: word(image, 0x14), t_addr: word(image, 0x18), t_size: word(image, 0x1c) };
    if HEADER_LEN + u64::from(header.t_size) > image.len() as u64 {
        return Err(format!("the header's t_size {:#x} runs past the end of the file ({:#x} bytes)", header.t_size, image.len()));
    }
    Ok(header)
}

pub fn plan(inputs: &Inputs) -> Result<(Vec<GeneratedFile>, MipsReport), String> {
    let header = parse_header(inputs.image)?;
    let (t_addr, t_size) = (u64::from(header.t_addr), u64::from(header.t_size));
    let detection = detect_psx(inputs.image);
    let rows = rows_in(inputs.facts, &|address| address >= t_addr && address < t_addr + t_size);
    let loads = [Load { offset: HEADER_LEN, vram: t_addr, size: t_size, name: "main".into(), rows: None }];
    let gap = |from: u64, _to: u64| vec![Segment::databin(if from == 0 { "header".to_string() } else { format!("gap_{from:x}") }, from)];
    let layout = plan_layout(inputs.image, &loads, &rows, inputs.image.len() as u64, &gap)?;
    let sha1 = sha1_hex(inputs.image);
    let mut extra = Vec::new();
    if header.gp0 != 0 {
        extra.push(format!("gp_value: {:#x}", header.gp0));
    }
    let mut yaml = yaml_options(inputs.image_name, &sha1, "psx", detection.splat_compiler, &extra);
    write_segments(&mut yaml, &layout, inputs.image.len());
    let built = Built {
        layout,
        yaml,
        detection,
        rows,
        image_json: json!({"format": "ps-x exe", "pc0": header.pc0, "gp0": header.gp0, "t_addr": header.t_addr, "t_size": header.t_size}),
        layout_json: vec![json!({"offset": HEADER_LEN, "vaddr": t_addr, "size": t_size, "name": "main"})],
        extra_files: Vec::new(),
        post: None,
        notes: Vec::new(),
    };
    assemble(&SPEC, inputs, built)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_fields_and_size_check() {
        let mut image = vec![0u8; 0x800 + 0x40];
        image[..8].copy_from_slice(b"PS-X EXE");
        image[0x10..0x14].copy_from_slice(&0x8001_0000u32.to_le_bytes());
        image[0x18..0x1c].copy_from_slice(&0x8001_0000u32.to_le_bytes());
        image[0x1c..0x20].copy_from_slice(&0x40u32.to_le_bytes());
        let header = parse_header(&image).unwrap();
        assert_eq!((header.t_addr, header.t_size), (0x8001_0000, 0x40));
        image[0x1c..0x20].copy_from_slice(&0x41u32.to_le_bytes());
        assert!(parse_header(&image).unwrap_err().contains("past the end"));
        assert!(!looks_like_psx_exe(&image[..0x700]));
    }

    fn function(name: &str, address: u64, size: u64) -> romwright_model::FunctionRow {
        romwright_model::FunctionRow {
            entry: romwright_model::Address::ram(address),
            name: name.into(),
            size,
            signature: None,
            traced: false,
            calling_convention: None,
        }
    }

    #[test]
    fn plan_covers_header_image_and_trailer_in_file_order() {
        // header 0x800, image 0x30 at 0x80010000 (f1 0x10, zero pad, f2 0x20..0x30), 0x10 of trailer.
        let mut image = vec![0u8; 0x800 + 0x30 + 0x10];
        image[..8].copy_from_slice(b"PS-X EXE");
        image[0x10..0x14].copy_from_slice(&0x8001_0000u32.to_le_bytes());
        image[0x14..0x18].copy_from_slice(&0x8002_0000u32.to_le_bytes());
        image[0x18..0x1c].copy_from_slice(&0x8001_0000u32.to_le_bytes());
        image[0x1c..0x20].copy_from_slice(&0x30u32.to_le_bytes());
        for range in [0x800..0x810, 0x820..0x830] {
            image[range].fill(0x11);
        }
        // f1: `jal 0x80010018` (inside the image, no function there) and `j 0x800798a4` (a tail call out of it).
        image[0x800..0x804].copy_from_slice(&0x0C00_4006u32.to_le_bytes());
        image[0x804..0x808].copy_from_slice(&0x0801_E629u32.to_le_bytes());
        let facts = crate::export::ExportFacts {
            program: "t".into(),
            functions: vec![function("f1", 0x8001_0000, 0x10), function("f2", 0x8001_0020, 0x10), function("elsewhere", 0x8002_0000, 8)],
            ..Default::default()
        };
        let manifest = super::super::manifest::Manifest::builtin();
        let (files, report) = plan(&Inputs {
            image: &image,
            image_name: "SLUS_000.00",
            project_name: "t",
            facts: &facts,
            prototypes: &[],
            manifest: &manifest,
            compiler_id: None,
            cflags: None,
            profile: None,
            romwright_version: "test",
        })
        .unwrap();
        let get = |path: &str| String::from_utf8(files.iter().find(|f| f.path == path).unwrap().bytes.clone()).unwrap();
        let yaml = get("config/SLUS_000.00.yaml");
        for line in [
            "  platform: psx",
            "  gp_value: 0x80020000",
            "  - name: header\n    type: databin\n    start: 0x0",
            "start: 0x800\n    vram: 0x80010000",
            "- [0x800, asm, main/0000/f1]",
            "- [0x820, asm, main/0000/f2]",
            "  - name: trailer\n    type: databin\n    start: 0x830",
            "  - [0x840]",
        ] {
            assert!(yaml.contains(line), "{line}\n{yaml}");
        }
        assert!(!get("config/symbol_addrs.txt").contains("elsewhere"));
        // splat names those targets `func_XXXXXXXX` and no object defines them: the link needs them.
        let undefined = get("config/undefined_syms.txt");
        assert!(undefined.contains("func_80010018 = 0x80010018;") && undefined.contains("func_800798A4 = 0x800798a4;"), "{undefined}");
        assert_eq!((report.platform, report.asm_units, report.compiler_tool.as_str()), ("psx", 2, "psyq4.3"));
        let project = get("config/project.json");
        assert!(project.contains("\"kind\": \"psyq\"") && project.contains("\"endian\": \"little\"") && project.contains("\"maspsx\""), "{project}");
        // The compiler's own requirements are in the pinned subset.
        let tools = get("config/toolchain.json");
        for id in ["psyq4.3", "wibo", "maspsx", "binutils-mips-ps2-decompals"] {
            assert!(tools.contains(&format!("\"id\": \"{id}\"")), "{id}");
        }
    }
}
