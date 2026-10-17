//! The PSP plugin: a PSP ELF (a `~PSP`-decrypted EBOOT or PRX, or a fixed-address
//! `ET_EXEC`) in, a splat + ninja repository out.
//!
//! The layout is the PS2 plugin's: the ELF header and program headers, one
//! `code` segment per file-backed `PT_LOAD`, a `databin` tail (section headers,
//! symbols, and for a PRX the `.rel.*` relocation sections and the `PT_PSPREL`
//! table, all of which are file bytes outside every load). The rebuild
//! therefore carries the retail relocation tables verbatim: an all-assembly
//! image, and any C unit that compiles to the retail bytes at the retail
//! offsets, needs no relocation re-emission. A unit that moves code or
//! changes which words carry a relocation would invalidate the table;
//! re-emitting `.rel.*` is not implemented (see docs/new-project.md).

use serde_json::json;

use super::detect::detect_psp;
use super::elf::Elf32;
use super::mips::{assemble, rows_in, yaml_options, write_segments, Built, Inputs, MipsReport, Spec};
use super::ps2::plan_ps2_layout;
use super::GeneratedFile;
use crate::export::sha1_hex;

const SPEC: Spec = Spec {
    id: "psp",
    name: "PSP",
    subject: "PSP (Allegrex, o32)",
    asflags: &["-EL", "-march=mips32r2", "-mabi=32"],
    endian: "little",
    link_flag: "EL",
    post: None,
    readme_limits: "* Allegrex-only instructions (VFPU `lv.q`/`vadd`, `max`, `min`, `mfic`) are not known to GNU as for MIPS; a unit that has one is assembled as raw `.word`s (`tools/asm.py` prints a `note:` naming it). Such a unit is data to the assembler, not a decompilation target.\n* The PRX relocation tables (`.rel.*`, `PT_PSPREL`) are file bytes the rebuild carries verbatim. A C unit that is not byte-identical to the retail function can shift or add relocation sites; this project does not re-emit the tables, so `ninja`'s sha1 check is the judge.\n* `EBOOT.PBP` packing and `~PSP` encryption are not part of the build.",
};

/// e_flags `EF_MIPS_MACH` of the Allegrex (binutils `E_MIPS_MACH_ALLEGREX`).
const MACH_ALLEGREX: u32 = 0x00a2_0000;

/// A PSP image: ELF32 LE MIPS whose machine bits name the Allegrex.
pub fn looks_like_psp_elf(image: &[u8]) -> bool {
    image.len() > 40
        && &image[..4] == b"\x7fELF"
        && image[4] == 1
        && image[5] == 1
        && u16::from_le_bytes([image[18], image[19]]) == 8
        && u32::from_le_bytes([image[36], image[37], image[38], image[39]]) & 0x00ff_0000 == MACH_ALLEGREX
}

pub fn plan(inputs: &Inputs) -> Result<(Vec<GeneratedFile>, MipsReport), String> {
    let elf = Elf32::parse(inputs.image)?;
    if !looks_like_psp_elf(inputs.image) {
        return Err("the ELF is not an Allegrex (PSP) executable: e_flags names another MIPS machine".into());
    }
    let detection = detect_psp(inputs.image);
    // Only addresses the image maps.
    let memory: Vec<(u64, u64)> = elf
        .phdrs
        .iter()
        .filter(|p| p.p_type == super::elf::PT_LOAD && p.memsz != 0)
        .map(|p| (p.vaddr as u64, p.vaddr as u64 + p.memsz as u64))
        .collect();
    let rows = rows_in(inputs.facts, &|address| memory.iter().any(|&(lo, hi)| address >= lo && address < hi));
    let layout = plan_ps2_layout(&elf, &rows, inputs.image.len() as u64)?;
    let sha1 = sha1_hex(inputs.image);
    // The Allegrex is a 32-bit processor: splat's default `.set gp=64` would be refused by GNU as.
    let mut yaml = yaml_options(inputs.image_name, &sha1, "psp", detection.splat_compiler, &["add_set_gp_64: False".to_string()]);
    write_segments(&mut yaml, &layout, inputs.image.len());
    let e_type = u16::from_le_bytes([inputs.image[16], inputs.image[17]]);
    let layout_json: Vec<_> = elf
        .loads()
        .into_iter()
        .map(|p| json!({"offset": p.offset, "vaddr": p.vaddr, "size": p.filesz}))
        .collect();
    let mut notes = Vec::new();
    if e_type == 0xffa0 {
        notes.push("PRX (ET_PRX 0xffa0): linked at address 0; the retail `.rel.*` relocation tables are carried as bytes of the tail".to_string());
    }
    let built = Built {
        layout,
        yaml,
        detection,
        rows,
        image_json: json!({"format": if e_type == 0xffa0 { "psp prx" } else { "psp elf" }, "e_type": e_type}),
        layout_json,
        extra_files: Vec::new(),
        post: None,
        notes,
    };
    assemble(&SPEC, inputs, built)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_by_the_allegrex_machine_bits() {
        let mut image = vec![0u8; 64];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 1;
        image[5] = 1;
        image[18] = 8;
        image[36..40].copy_from_slice(&0x10a2_3001u32.to_le_bytes());
        assert!(looks_like_psp_elf(&image));
        image[36..40].copy_from_slice(&0x2092_4001u32.to_le_bytes());
        assert!(!looks_like_psp_elf(&image));
    }

    #[test]
    fn plan_splits_an_et_prx_load_and_carries_the_tail() {
        // ET_PRX, one load 0x40 at vaddr 0 (file offset 0x80): f1 0x0..0x10, f2 0x20..0x30; tail 0x10.
        let mut image = vec![0u8; 0xd0];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 1;
        image[5] = 1;
        image[16..18].copy_from_slice(&0xffa0u16.to_le_bytes());
        image[18..20].copy_from_slice(&8u16.to_le_bytes());
        image[36..40].copy_from_slice(&0x10a2_3001u32.to_le_bytes());
        image[0x1c..0x20].copy_from_slice(&0x34u32.to_le_bytes());
        image[0x2a..0x2c].copy_from_slice(&32u16.to_le_bytes());
        image[0x2c..0x2e].copy_from_slice(&1u16.to_le_bytes());
        for (at, value) in [(0usize, 1u32), (4, 0x80), (8, 0), (12, 0), (16, 0x40), (20, 0x40), (24, 5)] {
            image[0x34 + at..0x34 + at + 4].copy_from_slice(&value.to_le_bytes());
        }
        for range in [0x80..0x90, 0xa0..0xb0] {
            image[range].fill(0x11);
        }
        let function = |name: &str, address: u64| romwright_model::FunctionRow {
            entry: romwright_model::Address::ram(address),
            name: name.into(),
            size: 0x10,
            signature: None,
            traced: false,
            calling_convention: None,
        };
        let facts = crate::export::ExportFacts {
            program: "t".into(),
            functions: vec![function("f1", 0), function("f2", 0x20)],
            ..Default::default()
        };
        let manifest = super::super::manifest::Manifest::builtin();
        let (files, report) = plan(&Inputs {
            image: &image,
            image_name: "EBOOT.BIN",
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
        let yaml = get("config/EBOOT.BIN.yaml");
        for line in [
            "  platform: psp",
            "  add_set_gp_64: False",
            "  - name: header\n    type: databin\n    start: 0x0",
            "start: 0x80\n    vram: 0x0",
            "- [0x80, asm, main/0000/f1]",
            "- [0xa0, asm, main/0000/f2]",
            "  - name: trailer\n    type: databin\n    start: 0xc0",
        ] {
            assert!(yaml.contains(line), "{line}\n{yaml}");
        }
        assert_eq!((report.platform, report.asm_units), ("psp", 2));
        assert!(report.notes.iter().any(|n| n.contains("PRX")));
    }
}
