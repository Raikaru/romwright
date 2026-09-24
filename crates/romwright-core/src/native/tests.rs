use super::discovery::flow_discover_with_provider;
use super::*;
use super::references::stack_frame;
use super::switch_tables::{FlowShapeIndex, blocks_reaching, function_blocks, switch_window};

#[test]
fn a_slice_keeps_what_reaches_the_dispatch_and_drops_what_follows_it() {
    // 0 -> {1, 2}, 1 -> 3 (the dispatch), 2 -> 4 (a sibling path), and
    // 3 -> 5 (what the cases run). Only 0, 1 and 3 decide the index.
    let blocks = vec![
        (0x1000, vec![0x1000], vec![1, 2]),
        (0x1010, vec![0x1010], vec![3]),
        (0x1020, vec![0x1020], vec![4]),
        (0x1030, vec![0x1030, 0x1034], vec![5]),
        (0x1040, vec![0x1040], vec![]),
        (0x1050, vec![0x1050], vec![]),
    ];
    let sliced = blocks_reaching(&blocks, &[0x1034]);
    assert_eq!(
        sliced
            .iter()
            .map(|(start, _, _)| *start)
            .collect::<Vec<_>>(),
        vec![0x1000, 0x1010, 0x1030]
    );
    // The entry keeps index 0, its edge to the dropped sibling is gone,
    // and the dispatch block's successor renumbers or disappears.
    assert_eq!(sliced[0].2, vec![1]);
    assert_eq!(sliced[1].2, vec![2]);
    assert_eq!(sliced[2].2, Vec::<usize>::new());
}

#[test]
fn a_slice_keeps_a_loop_that_reaches_the_dispatch() {
    // A dispatch inside a loop: the back edge is part of what sets the
    // index, so both blocks stay and the back edge survives.
    let blocks = vec![
        (0x1000, vec![0x1000], vec![1]),
        (0x1010, vec![0x1010], vec![2, 0]),
        (0x1020, vec![0x1020], vec![]),
    ];
    let sliced = blocks_reaching(&blocks, &[0x1010]);
    assert_eq!(sliced.len(), 2);
    assert_eq!(sliced[1].2, vec![0]);
}

#[test]
fn a_slice_of_a_function_with_no_dispatch_is_empty() {
    let blocks = vec![(0x1000, vec![0x1000], vec![])];
    assert!(blocks_reaching(&blocks, &[0x2000]).is_empty());
}

#[test]
fn a_leader_with_no_shape_still_splits_the_block() {
    // `jmp` at 0x1000, dead bytes at 0x1005..0x1010 (padding, never
    // decoded), then a `ja` at 0x1010. The leader at 0x1005 has no
    // shape; without it the `ja` is absorbed into the `jmp`'s block and
    // the block holds two branches.
    use crate::native_runtime::FlowKind;
    let imp = NativeImport {
        flow_shapes: vec![
            FlowShape {
                address: 0x1000,
                length: 5,
                kind: FlowKind::Branch,
                conditional: false,
                target: Some(0x2000),
            },
            FlowShape {
                address: 0x1010,
                length: 2,
                kind: FlowKind::CBranch,
                conditional: true,
                target: Some(0x3000),
            },
            FlowShape {
                address: 0x1012,
                length: 4,
                kind: FlowKind::Fallthrough,
                conditional: false,
                target: None,
            },
        ],
        ..Default::default()
    };
    let index = FlowShapeIndex::new(&imp.flow_shapes);
    let blocks = function_blocks(index.range(0x1000, 0x2000), 0x1000, 0x2000);
    // Three blocks: the jmp's, the padding leader's (empty), and the
    // ja's. The jmp's block must not contain the ja.
    assert_eq!(blocks.len(), 3, "{blocks:?}");
    assert_eq!(blocks[0].1, vec![0x1000]);
    assert_eq!(blocks[0].2, Vec::<usize>::new()); // Branch: only the target, which is outside.
    assert_eq!(blocks[1].1, vec![0x1010]);
    assert_eq!(blocks[1].2, vec![2]);
    assert_eq!(blocks[2].1, vec![0x1012]);
}

#[test]
fn switch_analysis_indexes_unsorted_rounds_without_leaking_neighbours() {
    use crate::native_runtime::FlowKind;
    let shape = |address, kind, target| FlowShape {
        address,
        length: 2,
        kind,
        conditional: matches!(kind, FlowKind::CBranch),
        target,
    };
    let shapes = [
        shape(0x1004, FlowKind::BranchInd, None),
        shape(0x0900, FlowKind::Branch, Some(0x1004)),
        shape(0x1000, FlowKind::CBranch, Some(0x1004)),
        shape(0x1008, FlowKind::Branch, Some(0x1004)),
        shape(0x1006, FlowKind::Return, None),
        shape(0x1002, FlowKind::Fallthrough, None),
        shape(0x1004, FlowKind::Fallthrough, None),
    ];
    let index = FlowShapeIndex::new(&shapes);
    let function = index.range(0x1000, 0x1008);
    assert_eq!(
        function_blocks(function, 0x1000, 0x1008),
        vec![
            (0x1000, vec![0x1000], vec![2, 1]),
            (0x1002, vec![0x1002], vec![2]),
            (0x1004, vec![0x1004], vec![]),
            (0x1006, vec![0x1006], vec![]),
        ]
    );
    assert_eq!(
        switch_window(function, 0x1004, 0x1000, 0x1008),
        (vec![0x1004], vec![vec![0x1000], vec![0x1002]])
    );
    assert!(function_blocks(index.range(0x1008, 0x1000), 0x1008, 0x1000).is_empty());
    assert_eq!(
        switch_window(index.range(0x1004, 0x1004), 0x1004, 0x1004, 0x1004),
        (vec![], vec![])
    );
}

#[test]
fn elf_data_pointer_waits_for_flow_and_walks_indirect_call_fallthrough() {
    use crate::native_runtime::{FlowKind, FlowResult};
    let mut bytes = vec![0; 0x300];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    for (offset, value) in [(16, 2_u16), (18, 0x3e), (58, 64), (60, 4), (62, 3)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (24, 0x1000_u64),
        (40, 0x200),
        (0x248, 6),
        (0x250, 0x1000),
        (0x258, 0x100),
        (0x260, 0x80),
        (0x288, 3),
        (0x290, 0x2000),
        (0x298, 0x180),
        (0x2a0, 16),
        (0x2d8, 0x1a0),
        (0x2e0, 13),
        (0x180, 0x1020),
        (0x188, 0x1030),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (0x240, 1_u32),
        (0x244, 1),
        (0x280, 7),
        (0x284, 1),
        (0x2c4, 3),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x100..0x180].fill(1);
    bytes[0x1a0..0x1ad].copy_from_slice(b"\0.text\0.data\0");
    let mut imp = import_elf(&bytes).unwrap();
    assert!(!imp.functions.iter().any(|f| f.entry == 0x1020));
    flow_discover_with_provider(&mut imp, |_| Vec::new());
    assert!(!imp.functions.iter().any(|f| f.entry == 0x1020));
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&address| {
                let (kind, fallthrough, targets) = match address {
                    0x1020 => (FlowKind::CallInd, Some(0x1024), vec![]),
                    0x1024 => (FlowKind::Call, Some(0x1028), vec![0x1040]),
                    0x1030 => (FlowKind::Bad, None, vec![]),
                    _ => (FlowKind::Return, None, vec![]),
                };
                FlowResult {
                    terminal: kind == FlowKind::Return,
                    conditional: false,
                    return_op: kind == FlowKind::Return,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address,
                    length: 4,
                    fallthrough,
                    targets,
                    kind,
                    mode: None,
                    target_modes: Vec::new(),
                }
            })
            .collect()
    });
    assert!(imp.functions.iter().any(|f| f.entry == 0x1020));
    assert!(
        imp.functions.iter().any(|f| f.entry == 0x1040),
        "pointer-rooted traversal must continue after an indirect call"
    );
    assert!(!imp.functions.iter().any(|f| f.entry == 0x1030));
    assert!(imp.xrefs.iter().any(|x| x.from == 0x2000
        && x.to == 0x1020
        && x.kind == "DATA"
        && x.provenance == "native-import:elf-pointer"));
}

#[test]
fn distant_branch_does_not_claim_unvisited_gap() {
    use crate::native_runtime::{FlowKind, FlowResult};
    let mut imp = NativeImport {
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 0x2010,
            file_off: 0,
            flags: 6,
            bytes: vec![0x90; 0x2010],
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            name: "entry".into(),
            size: 1,
        }],
        reloc_candidates: vec![0x2000, 0x3001],
        ..Default::default()
    };
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&address| FlowResult {
                terminal: address != 0x1000,
                conditional: false,
                return_op: address != 0x1000,
                delay_slots: Vec::new(),
                no_op: false,
                pure_jump: false,
                address,
                length: 4,
                fallthrough: None,
                targets: if address == 0x1000 {
                    vec![0x3000]
                } else {
                    vec![]
                },
                kind: if address == 0x1000 {
                    FlowKind::Branch
                } else {
                    FlowKind::Return
                },
                mode: None,
                target_modes: Vec::new(),
            })
            .collect()
    });
    assert!(
        imp.functions.iter().any(|f| f.entry == 0x2000),
        "a distant branch must not suppress a function in the unvisited gap"
    );
    assert!(
        !imp.functions.iter().any(|f| f.entry == 0x3001),
        "an instruction-interior pointer must still be rejected"
    );
}

#[test]
fn an_elf_records_the_machine_it_names_and_selects_no_language_alone() {
    // The machine and flags an ELF header names are facts of the file;
    // which language answers for them is the install's decision, made by
    // `opinion::elf_selection` and tested against the pinned tree there.
    // A parse on its own selects nothing, so no caller can inherit a
    // language that no install agreed to.
    let mut bytes = elf32_with_pltgot(16);
    bytes[36..40].copy_from_slice(&0x0580_0000u32.to_le_bytes()); // e_flags
    let import = import_elf(&bytes).unwrap();
    assert_eq!(
        import.elf_machine,
        Some(crate::opinion::ElfMachine {
            machine: 3,
            flags: 0x0580_0000,
            bits: 32,
            big_endian: false,
            e_type: 2,
        })
    );
    assert!(import.language.is_empty() && import.compiler.is_none());

    // With an install, the same bytes are answered from its data.
    let cfg = crate::session::RuntimeConfig::from_env();
    let mut selected = import;
    if cfg.ghidra_install.join("Ghidra/Processors").is_dir() {
        select_language(&mut selected, &cfg).unwrap();
        assert_eq!(selected.language, "x86:LE:32:default");
        assert_eq!(selected.compiler.as_deref(), Some("gcc"));
    }
    // A machine no install declares is refused rather than guessed.
    let mut unknown = selected;
    unknown.elf_machine = Some(crate::opinion::ElfMachine {
        machine: 0xfffe,
        flags: 0,
        bits: 32,
        big_endian: false,
        e_type: 0,
    });
    assert!(select_language(&mut unknown, &cfg).is_err());
}

#[test]
fn elf32_startup_section_seeds() {
    for be in [false, true] {
        let word = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let half = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut data = vec![0u8; 0x400];
        data[..6].copy_from_slice(if be {
            b"\x7fELF\x01\x02"
        } else {
            b"\x7fELF\x01\x01"
        });
        for (offset, value) in [
            (16, 2),
            (18, if be { 20 } else { 3 }),
            (46, 40),
            (48, 5),
            (50, 4),
        ] {
            data[offset..offset + 2].copy_from_slice(&half(value));
        }
        data[32..36].copy_from_slice(&word(0x100));
        let names = b"\0.init\0.fini\0.plt\0.shstrtab\0";
        data[0x300..0x300 + names.len()].copy_from_slice(names);
        for (index, name, typ, flags, addr, offset, size) in [
            (1usize, 1, 1, 6, 0x1000, 0x340, 16),
            (2, 7, 1, 6, 0x2000, 0x350, 16),
            (3, 13, 1, 6, 0x3000, 0x360, 32),
            (4, 18, 3, 0, 0, 0x300, names.len() as u32),
        ] {
            let start = 0x100 + index * 40;
            for (field, value) in [name, typ, flags, addr, offset, size]
                .into_iter()
                .enumerate()
            {
                data[start + field * 4..start + field * 4 + 4].copy_from_slice(&word(value));
            }
        }
        let import = import_elf(&data).unwrap();
        let entries: Vec<_> = import
            .functions
            .iter()
            .map(|f| (f.entry, f.name.as_str()))
            .collect();
        assert_eq!(
            entries,
            [(0x1000, "_init"), (0x2000, "_fini"), (0x3000, "_plt")],
            "stripped ELF32 must retain loader-declared executable starts"
        );
        // Section names alone do not make data executable.
        for index in 1..=3 {
            let flags = 0x100 + index * 40 + 8;
            data[flags..flags + 4].copy_from_slice(&word(2));
        }
        assert!(import_elf(&data).unwrap().functions.is_empty());
    }
}

#[test]
fn elf_load_populates_functions() {
    // Build a tiny synthetic ELF64 with one symtab entry.
    let mut b = vec![0u8; 0x1000];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    // e_entry
    b[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    // ehdr: e_shoff (0x200), e_shentsize (64), e_shnum (4),
    // e_shstrndx (3)
    b[40..48].copy_from_slice(&0x200u64.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&4u16.to_le_bytes());
    b[62..64].copy_from_slice(&3u16.to_le_bytes());
    // section 0 null; section 1 .text; section 2 .symtab; section 3 .strtab
    for (o, typ, flags, addr, off, size, link) in [
        (0x200usize, 0u32, 0u64, 0u64, 0u64, 0u64, 0u32),
        (0x240, 1, 0x2, 0x401000, 0x300, 0x10, 0), // .text
        (0x280, 2, 0, 0, 0x400, 24, 3),            // .symtab -> .strtab
        (0x2c0, 3, 0, 0, 0x380, 8, 0),             // .strtab
    ] {
        b[o..o + 4].copy_from_slice(&0u32.to_le_bytes());
        b[o + 4..o + 8].copy_from_slice(&typ.to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&flags.to_le_bytes());
        b[o + 16..o + 24].copy_from_slice(&addr.to_le_bytes());
        b[o + 24..o + 32].copy_from_slice(&off.to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
        b[o + 40..o + 44].copy_from_slice(&link.to_le_bytes());
    }
    b[0x380] = 0;
    b[0x381..0x381 + 4].copy_from_slice(b"add\0");
    // symtab entry: st_name=1, info=0x12 (STT_FUNC|STB_GLOBAL),
    // st_size=4, st_value=0x401000
    b[0x400..0x404].copy_from_slice(&1u32.to_le_bytes());
    b[0x404] = 0x12;
    b[0x406..0x408].copy_from_slice(&1u16.to_le_bytes());
    b[0x408..0x410].copy_from_slice(&0x401000u64.to_le_bytes());
    b[0x410..0x418].copy_from_slice(&4u64.to_le_bytes());
    // shstrtab for names: .text\0.symtab\0.strtab\0
    {
        let shstr = b".text\0.symtab\0.strtab\0";
        b[0x800..0x800 + shstr.len()].copy_from_slice(shstr);
    }
    // set section name offsets
    for (o, off) in [(0x240usize, 1usize), (0x280, 7), (0x2c0, 14)] {
        b[o..o + 4].copy_from_slice(&(off as u32).to_le_bytes());
    }
    let mut imp = import_elf(&b).unwrap();
    let f = imp.functions.iter().find(|f| f.name == "add").unwrap();
    assert_eq!(f.entry, 0x401000);
    assert_eq!(f.size, 4);
    assert_eq!(imp.mappings[0].vaddr, 0x401000);
    let cfg = crate::session::RuntimeConfig::from_env();
    if cfg.ghidra_install.join("Ghidra/Processors").is_dir() {
        select_language(&mut imp, &cfg).unwrap();
        assert_eq!(imp.language, "x86:LE:64:default");
    }
    // Definition state, not a nonzero value, distinguishes a real symbol.
    b[0x250..0x258].copy_from_slice(&0u64.to_le_bytes());
    b[0x408..0x410].copy_from_slice(&0u64.to_le_bytes());
    let zero = import_elf(&b).unwrap();
    assert!(zero.functions.iter().any(|f| f.name == "add" && f.entry == 0));
    b[0x406..0x408].copy_from_slice(&0u16.to_le_bytes());
    let undefined = import_elf(&b).unwrap();
    assert!(!undefined.functions.iter().any(|f| f.name == "add"));
    assert!(undefined.externals.iter().any(|(_, name)| name == "add"));
    b[0x406..0x408].copy_from_slice(&1u16.to_le_bytes());
    b[0x404] = 0x11;
    assert!(import_elf(&b).unwrap().object_names.contains(&(0, "add".into())));
}

#[test]
fn elf32_zero_address_definitions_keep_thumb_mode_and_exclude_undefined_symbols() {
    for be in [false, true] {
        let word = |value: u32| if be { value.to_be_bytes() } else { value.to_le_bytes() };
        let half = |value: u16| if be { value.to_be_bytes() } else { value.to_le_bytes() };
        let mut bytes = vec![0u8; 0x200];
        bytes[..7].copy_from_slice(if be { b"\x7fELF\x01\x02\x01" } else { b"\x7fELF\x01\x01\x01" });
        for (offset, value) in [(16, 1), (18, 40), (40, 52), (46, 40), (48, 4)] {
            bytes[offset..offset + 2].copy_from_slice(&half(value));
        }
        bytes[32..36].copy_from_slice(&word(0x80));
        for (index, fields) in [
            (1, [0, 1, 6, 0, 0x140, 4, 0, 0, 2, 0]),
            (2, [0, 2, 0, 0, 0x160, 32, 3, 1, 4, 16]),
            (3, [0, 3, 0, 0, 0x190, 6, 0, 0, 1, 0]),
        ] {
            for (field, value) in fields.into_iter().enumerate() {
                let offset = 0x80 + index * 40 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&word(value));
            }
        }
        bytes[0x140..0x142].copy_from_slice(&half(0x3001)); // adds r0,#1
        bytes[0x142..0x144].copy_from_slice(&half(0x4770)); // bx lr
        bytes[0x190..0x196].copy_from_slice(b"\0zero\0");
        bytes[0x170..0x174].copy_from_slice(&word(1));
        bytes[0x174..0x178].copy_from_slice(&word(1)); // Thumb at address zero.
        bytes[0x178..0x17c].copy_from_slice(&word(4));
        bytes[0x17c] = 0x12;
        bytes[0x17e..0x180].copy_from_slice(&half(1));
        let imported = import_elf(&bytes).unwrap();
        assert!(imported.functions.iter().any(|f| f.name == "zero" && f.entry == 0 && f.size == 4));
        assert!(imported.contexts.iter().any(|c| c.name == "TMode" && c.address == 0 && c.value == 1));
        bytes[0x17e..0x180].copy_from_slice(&half(0));
        let undefined = import_elf(&bytes).unwrap();
        assert!(!undefined.functions.iter().any(|f| f.name == "zero"));
        assert!(undefined.externals.iter().any(|(_, name)| name == "zero"));
        bytes[0x17e..0x180].copy_from_slice(&half(1));
        bytes[0x17c] = 0x11;
        bytes[0x174..0x178].copy_from_slice(&word(0));
        assert!(import_elf(&bytes).unwrap().object_names.contains(&(0, "zero".into())));
    }
}

#[test]
fn exported_symbol_names_win_over_internal_aliases() {
    // Three FUNC symbols share one address, as glibc does for `abort`:
    // a LOCAL alias, a versioned export, and the plain export.
    let mut b = vec![0u8; 0x1000];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    b[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    b[40..48].copy_from_slice(&0x200u64.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&4u16.to_le_bytes());
    b[62..64].copy_from_slice(&3u16.to_le_bytes());
    for (o, typ, flags, addr, off, size, link) in [
        (0x200usize, 0u32, 0u64, 0u64, 0u64, 0u64, 0u32),
        (0x240, 1, 0x2, 0x401000, 0x300, 0x10, 0),
        (0x280, 2, 0, 0, 0x400, 72, 3),
        (0x2c0, 3, 0, 0, 0x380, 40, 0),
    ] {
        b[o..o + 4].copy_from_slice(&0u32.to_le_bytes());
        b[o + 4..o + 8].copy_from_slice(&typ.to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&flags.to_le_bytes());
        b[o + 16..o + 24].copy_from_slice(&addr.to_le_bytes());
        b[o + 24..o + 32].copy_from_slice(&off.to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
        b[o + 40..o + 44].copy_from_slice(&link.to_le_bytes());
    }
    let strtab = b"\0__GI_abort\0abort@@GLIBC_2.2.5\0abort\0";
    b[0x380..0x380 + strtab.len()].copy_from_slice(strtab);
    // st_info: 0x02 = LOCAL FUNC, 0x12 = GLOBAL FUNC.
    for (index, (name_off, info)) in [(1u32, 0x02u8), (12, 0x12), (31, 0x12)]
        .into_iter()
        .enumerate()
    {
        let o = 0x400 + index * 24;
        b[o..o + 4].copy_from_slice(&name_off.to_le_bytes());
        b[o + 4] = info;
        b[o + 6..o + 8].copy_from_slice(&1u16.to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&0x401000u64.to_le_bytes());
        b[o + 16..o + 24].copy_from_slice(&8u64.to_le_bytes());
    }
    let shstr = b".text\0.symtab\0.strtab\0";
    b[0x800..0x800 + shstr.len()].copy_from_slice(shstr);
    for (o, off) in [(0x240usize, 1usize), (0x280, 7), (0x2c0, 14)] {
        b[o..o + 4].copy_from_slice(&(off as u32).to_le_bytes());
    }
    let functions = import_elf(&b).unwrap().functions;
    let named: Vec<_> = functions
        .iter()
        .filter(|f| f.entry == 0x401000)
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(
        named,
        ["abort"],
        "an internal alias must not shadow the exported name a name list matches"
    );
}

#[test]
fn pe_memory_regions_preserve_section_permissions() {
    // Section flags: READ (0x40000000) alone must NOT be executable.
    let mut b = vec![0u8; 0x200];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size
    b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
    b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase at opt + 24
    let sec = 0x80 + 24 + 0xf0;
    b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // vsize
    b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    b[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes()); // raw ptr
    b[sec + 36..sec + 40].copy_from_slice(&0x40000000u32.to_le_bytes()); // READ only
    let imp = import_pe(&b).unwrap();
    let db = ProjectDb::open_in_memory().unwrap();
    let pid = db
        .upsert_program("pe", &imp.language, &native_provenance())
        .unwrap();
    store_import(&db, "pe", &imp, None).unwrap();
    assert_eq!(db.memory_regions(pid).unwrap()[0].permissions, "r--");
    // Executable, writable code retains all three permissions.
    b[sec + 36..sec + 40].copy_from_slice(&0xe0000000u32.to_le_bytes());
    let imp = import_pe(&b).unwrap();
    store_import(&db, "pe", &imp, None).unwrap();
    assert_eq!(db.memory_regions(pid).unwrap()[0].permissions, "rwx");
}

/// A section whose raw bytes run past the end of the file keeps the
/// bytes that are there and says so; it used to become all zeros
/// without a word.
#[test]
fn a_truncated_pe_section_keeps_its_bytes_and_reports_the_cut() {
    let mut b = vec![0u8; 0x200];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
    let sec = 0x80 + 24 + 0xf0;
    b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    b[sec + 20..sec + 24].copy_from_slice(&0x1c0u32.to_le_bytes()); // raw ptr: 0x40 bytes left
    b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    b[0x1c0] = 0xc3;
    let imp = import_pe(&b).unwrap();
    let mapping = imp.mappings.iter().find(|m| m.size == 0x1000).expect("section mapped");
    assert_eq!(mapping.bytes[0], 0xc3, "the bytes the file holds are kept");
    assert!(
        imp.diagnostics.iter().any(|d| d.severity == romwright_model::DiagnosticSeverity::Partial
            && d.message.contains("64 of 512 bytes present")),
        "{:?}",
        imp.diagnostics
    );
}

/// Only direct calls from same-language siblings seed the host, each in
/// the mode its encoding enters, and a call whose bytes do not reach
/// its recorded target seeds nothing.
#[test]
fn sibling_calls_seed_the_host_in_the_mode_they_enter() {
    let code = |vaddr, bytes: Vec<u8>| Mapping { vaddr, size: bytes.len() as u64, file_off: 0, flags: 5, bytes };
    let thumb_bl = |from: u64, to: u64| {
        let offset = to.wrapping_sub(from + 4) as u32;
        let high = 0xf000 | ((offset >> 12) & 0x7ff) as u16;
        let low = 0xf800 | ((offset >> 1) & 0x7ff) as u16;
        [high.to_le_bytes(), low.to_le_bytes()].concat()
    };
    let arm_bl = |from: u64, to: u64| (0xeb00_0000 | ((to.wrapping_sub(from + 8) as u32 >> 2) & 0x00ff_ffff)).to_le_bytes().to_vec();
    let base = 0x021e_5900;
    let mut bytes = vec![0u8; 0x40];
    bytes[0x04..0x08].copy_from_slice(&thumb_bl(base + 0x04, 0x0200_0010));
    bytes[0x08..0x0c].copy_from_slice(&thumb_bl(base + 0x08, 0x0200_0010));
    bytes[0x10..0x14].copy_from_slice(&arm_bl(base + 0x10, 0x0200_0020));
    bytes[0x18..0x1c].copy_from_slice(&arm_bl(base + 0x18, 0x0200_0080));
    let mut host = NativeImport {
        language: "ARM:LE:32:v5t".into(),
        mappings: vec![code(0x0200_0000, vec![0; 0x100])],
        functions: vec![NativeFunction { entry: 0x0200_0000, name: "arm9_entry".into(), size: 1 }],
        ..Default::default()
    };
    let overlay = NativeImport {
        language: "ARM:LE:32:v5t".into(),
        mappings: vec![code(base, bytes)],
        xrefs: vec![
            NativeXref::new(base + 0x04, 0x0200_0010, "UNCONDITIONAL_CALL"),
            NativeXref::new(base + 0x08, 0x0200_0010, "UNCONDITIONAL_CALL"),
            NativeXref::new(base + 0x10, 0x0200_0020, "UNCONDITIONAL_CALL"),
            // The bytes at 0x18 call 0x02000080, not the recorded target.
            NativeXref::new(base + 0x18, 0x0200_0040, "UNCONDITIONAL_CALL"),
            NativeXref::new(base + 0x1c, 0x0200_0030, "DATA"),
            NativeXref::new(base + 0x20, 0x0300_0000, "UNCONDITIONAL_CALL"),
        ],
        ..Default::default()
    };
    let arm7 = NativeImport {
        language: "ARM:LE:32:v4t".into(),
        xrefs: vec![NativeXref::new(0x0238_0000, 0x0200_0050, "UNCONDITIONAL_CALL")],
        ..Default::default()
    };
    seed_from_siblings(&mut host, &[&overlay, &arm7]);
    let entries: Vec<u64> = host.functions.iter().map(|f| f.entry).collect();
    assert_eq!(entries, [0x0200_0000, 0x0200_0010, 0x0200_0020]);
    let modes: Vec<(u64, u64)> = host.contexts.iter().map(|c| (c.address, c.value)).collect();
    assert_eq!(modes, [(0x0200_0010, 1), (0x0200_0020, 0)]);
}

/// A table in a segment that mixes code and data names strings as well
/// as functions. Only a target with code evidence is taken: a frame
/// prologue, or a non-text start with a return close behind.
#[test]
fn mips_table_targets_need_code_evidence() {
    let mut bytes = vec![0u8; 0x400];
    let put = |bytes: &mut Vec<u8>, at: usize, word: u32| bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    put(&mut bytes, 0x000, 0x27bd_ffe0); // addiu sp, sp, -32
    bytes[0x100..0x108].copy_from_slice(b"FIGHTER\0"); // a string
    put(&mut bytes, 0x200, 0x0080_1021); // move v0, a0 (leaf)
    put(&mut bytes, 0x204, 0x03e0_0008); // jr ra
    put(&mut bytes, 0x300, 0x0080_1021); // no return within 64 words
    let imp = NativeImport {
        language: "r5900:LE:32:default".into(),
        mappings: vec![Mapping { vaddr: 0x100000, size: 0x400, file_off: 0, flags: 6, bytes }],
        ..Default::default()
    };
    assert!(mips_function_evidence(&imp, 0x100000, false));
    assert!(!mips_function_evidence(&imp, 0x100100, false));
    assert!(mips_function_evidence(&imp, 0x100200, false));
    assert!(!mips_function_evidence(&imp, 0x100300, false));
    let arm = NativeImport { language: "ARM:LE:32:v4t".into(), ..imp };
    assert!(!mips_function_evidence(&arm, 0x100000, false), "no measured rule off MIPS");
}

#[test]
fn truncated_elf_magic_errors_not_panics() {
    assert!(import_elf(b"\x7fELF").is_err());
    assert!(import_elf(b"\x7fELF\x02\x01").is_err());
    assert!(import_elf(b"\x7fELF\x02\x01\x00\x00").is_err());
}

#[test]
fn stripped_elf_names_defined_dynsym_functions() {
    // A stripped binary has no symtab; its defined dynamic functions
    // (the names a strip leaves behind) must still surface -- an
    // undefined import must stay an external, never a function.
    let mut b = vec![0u8; 0x340];
    b[..10].copy_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00");
    for (off, v) in [
        (16, 2_u16),
        (18, 0x3e),
        (54, 56),
        (58, 64),
        (60, 5),
        (62, 3),
    ] {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    b[40..48].copy_from_slice(&0x200u64.to_le_bytes()); // e_shoff
    let dynsym = 0x200 + 64;
    b[dynsym + 4..dynsym + 8].copy_from_slice(&11u32.to_le_bytes());
    b[dynsym + 24..dynsym + 32].copy_from_slice(&0x100u64.to_le_bytes());
    b[dynsym + 32..dynsym + 40].copy_from_slice(&96u64.to_le_bytes());
    b[dynsym + 40..dynsym + 44].copy_from_slice(&2u32.to_le_bytes());
    // [1] versioned "dynfunc@VER" @ 0x401000 sorts before the clean
    // spelling [3]; rank must prefer the clean name over index order.
    // [2] undefined "puts".
    let e1 = 0x100 + 24;
    b[e1..e1 + 4].copy_from_slice(&6u32.to_le_bytes());
    b[e1 + 4] = 0x12;
    b[e1 + 6..e1 + 8].copy_from_slice(&1u16.to_le_bytes());
    b[e1 + 8..e1 + 16].copy_from_slice(&0x401000u64.to_le_bytes());
    b[e1 + 16..e1 + 24].copy_from_slice(&32u64.to_le_bytes());
    let e2 = 0x100 + 48;
    b[e2..e2 + 4].copy_from_slice(&1u32.to_le_bytes());
    b[e2 + 4] = 0x12; // shndx stays 0: undefined
    let e3 = 0x100 + 72;
    b[e3..e3 + 4].copy_from_slice(&18u32.to_le_bytes());
    b[e3 + 4] = 0x12;
    b[e3 + 6..e3 + 8].copy_from_slice(&1u16.to_le_bytes());
    b[e3 + 8..e3 + 16].copy_from_slice(&0x401000u64.to_le_bytes());
    b[e3 + 16..e3 + 24].copy_from_slice(&32u64.to_le_bytes());
    // Section 2: STRTAB at 0x160 (past the four entries ending 0x160).
    // Section 3: SHSTRTAB at 0x180. Section 4: ALLOC+EXEC .text.
    b[0x160..0x180].copy_from_slice(b"\0puts\0dynfunc@VER\0dynfunc\0\0\0\0\0\0\0");
    let strtab = 0x200 + 128;
    b[strtab + 4..strtab + 8].copy_from_slice(&3u32.to_le_bytes());
    b[strtab + 24..strtab + 32].copy_from_slice(&0x160u64.to_le_bytes());
    b[strtab + 32..strtab + 40].copy_from_slice(&32u64.to_le_bytes());
    let shstr = 0x200 + 192;
    b[shstr + 4..shstr + 8].copy_from_slice(&3u32.to_le_bytes());
    b[shstr + 24..shstr + 32].copy_from_slice(&0x180u64.to_le_bytes());
    b[shstr + 32..shstr + 40].copy_from_slice(&15u64.to_le_bytes());
    b[dynsym..dynsym + 4].copy_from_slice(&1u32.to_le_bytes());
    b[0x180..0x18f].copy_from_slice(b"\0.dynsym\0.text\0");
    let text = 0x200 + 256;
    b[text..text + 4].copy_from_slice(&9u32.to_le_bytes());
    b[text + 4..text + 8].copy_from_slice(&1u32.to_le_bytes());
    b[text + 8..text + 16].copy_from_slice(&6u64.to_le_bytes());
    b[text + 16..text + 24].copy_from_slice(&0x401000u64.to_le_bytes());
    b[text + 24..text + 32].copy_from_slice(&0x190u64.to_le_bytes());
    b[text + 32..text + 40].copy_from_slice(&16u64.to_le_bytes());
    b[0x190..0x1a0].fill(0x90);
    let imp = import_elf(&b).unwrap();
    let named: Vec<_> = imp
        .functions
        .iter()
        .filter(|f| f.entry == 0x401000)
        .collect();
    assert_eq!(
        named.len(),
        1,
        "defined dynsym address must survive: {named:?}"
    );
    assert_eq!(named[0].name, "dynfunc");
    assert!(!imp.functions.iter().any(|f| f.name.contains('@')));
    assert!(
        imp.externals.iter().any(|e| e.1 == "puts"),
        "undefined import stays external"
    );
    assert!(
        !imp.externals
            .iter()
            .any(|e| e.1 == "dynfunc" || e.1.contains('@'))
    );
    assert!(!imp.functions.iter().any(|f| f.name == "puts"));
}

#[test]
fn malformed_inputs_never_panic() {
    // Deterministic PRNG (xorshift64) fuzz smoke: truncated headers,
    // magic-only files, and arbitrary byte soups must return typed
    // errors (or a parse) — never panic or OOM (review QA-002).
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut rand = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for len in 1..=64usize {
        for _ in 0..64 {
            let mut bytes = vec![0u8; len];
            for b in bytes.iter_mut() {
                *b = (rand() & 0xff) as u8;
            }
            let _ = import_elf(&bytes);
            let _ = import_pe(&bytes);
            if len >= 4 {
                let _ = crate::disasm::decode(&bytes, 0x400000);
            }
            // magic-only truncated variants
            let _ = import_elf(&b"\x7fELF"[..len.min(4)]);
            let _ = import_pe(&b"MZ"[..len.min(2)]);
        }
    }
    // Structured but corrupted: valid ELF header with bogus section
    // table offsets/counts.
    let mut b = vec![0u8; 0x100];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[40..48].copy_from_slice(&(0x100000000u64).to_le_bytes()); // absurd shoff
    b[58..60].copy_from_slice(&0xffffu16.to_le_bytes()); // shentsize
    b[60..62].copy_from_slice(&0xffffu16.to_le_bytes()); // shnum
    let _ = import_elf(&b);
}

#[test]
fn pe_image_base_reads_header_field() {
    // Minimal MZ + PE signature + optional header carrying ImageBase.
    let mut b = vec![0u8; 0x100];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
    b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
    assert_eq!(pe_image_base(&b), Some(0x140000000));
    assert_eq!(pe_image_base(b"\x7fELF"), None);
}
#[test]
fn regression_candidates_inside_known_bodies_are_rejected() {
    let mut imp = NativeImport {
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 0x100,
            file_off: 0,
            flags: 0x4,
            bytes: vec![0x90; 0x100],
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            name: "known_outer".into(),
            size: 0x80, // covers 0x1000..0x1080
        }],
        reloc_candidates: vec![0x1040], // strictly inside known_outer
        format: "ELF".into(),
        language: "x86:LE:64:default".into(),
        ..Default::default()
    };
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&address| crate::native_runtime::FlowResult {
                terminal: true,
                conditional: false,
                return_op: true,
                delay_slots: Vec::new(),
                no_op: false,
                address,
                length: 1,
                fallthrough: None,
                targets: vec![],
                kind: crate::native_runtime::FlowKind::Return,
                pure_jump: false,
                mode: None,
                target_modes: Vec::new(),
            })
            .collect()
    });
    assert!(!imp.functions.iter().any(|f| f.entry == 0x1040));
}

#[test]
fn regression_console_absence_does_not_promote_unconfirmed_candidates() {
    let mut imp = NativeImport {
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 0x200,
            file_off: 0,
            flags: 0x4,
            bytes: vec![0x90; 0x200],
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            name: "root".into(),
            size: 0x10,
        }],
        reloc_candidates: vec![0x1100],
        cfg: crate::session::RuntimeConfig {
            console_path: Some(std::path::PathBuf::from("/nonexistent/decomp_native")),
            ..Default::default()
        },
        format: "ELF".into(),
        language: "x86:LE:64:default".into(),
        ..Default::default()
    };
    discovery::discover_seeded(&mut imp);
    // Unconfirmed candidate 0x1100 must NOT be promoted when console is absent/failing
    assert_eq!(imp.functions.len(), 1);
    assert_eq!(imp.functions[0].entry, 0x1000);
}

#[test]
fn regression_invalid_relocation_target_is_not_promoted() {
    let mut imp = NativeImport {
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 0x100,
            file_off: 0,
            flags: 0x4,
            bytes: vec![0x90; 0x100],
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            name: "entry".into(),
            size: 0x10,
        }],
        reloc_candidates: vec![0x99999], // out of bounds / non-code
        format: "ELF".into(),
        language: "x86:LE:64:default".into(),
        ..Default::default()
    };
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&address| crate::native_runtime::FlowResult {
                terminal: true,
                conditional: false,
                return_op: true,
                delay_slots: Vec::new(),
                no_op: false,
                address,
                length: 1,
                fallthrough: None,
                targets: vec![],
                kind: crate::native_runtime::FlowKind::Return,
                pure_jump: false,
                mode: None,
                target_modes: Vec::new(),
            })
            .collect()
    });
    assert!(!imp.functions.iter().any(|f| f.entry == 0x99999));
}
#[test]
fn test_filter_candidate_rejects_internal_even_with_valid_flow() {
    use crate::native_runtime::FlowResult;
    let mappings = vec![Mapping {
        vaddr: 0x1000,
        size: 0x100,
        file_off: 0,
        flags: 0x4,
        bytes: vec![0x90; 0x100],
    }];
    let extents = vec![(0x1000, 0x50)]; // 0x1000..0x1050
    let initial_seeds = HashSet::from([0x1000]);
    let ctx = CandidateFilterContext {
        mappings: &mappings,
        known_extents: ExtentIndex::build(&extents),
        initial_seeds: &initial_seeds,
    };

    // Candidate 0x1020 is internal to 0x1000..0x1050.
    let result = candidate_address_is_valid(0x1020, &ctx)
        && candidate_flow_is_valid(
            0x1020,
            &ctx,
            &FlowResult {
                terminal: false,
                conditional: false,
                return_op: false,
                delay_slots: Vec::new(),
                no_op: false,
                pure_jump: false,
                address: 0x1020,
                length: 4,
                fallthrough: Some(0x1024),
                targets: Vec::new(),
                kind: crate::native_runtime::FlowKind::Fallthrough,
                mode: None,
                target_modes: Vec::new(),
            },
        );
    assert!(
        !result,
        "candidate inside known function must be rejected even with valid flow"
    );
}

#[test]
fn test_filter_candidate_rejects_out_of_code_even_with_valid_flow() {
    use crate::native_runtime::FlowResult;
    let mappings = vec![
        Mapping {
            vaddr: 0x1000,
            size: 0x100,
            file_off: 0,
            flags: 0x4, // executable
            bytes: vec![0x90; 0x100],
        },
        Mapping {
            vaddr: 0x2000,
            size: 0x100,
            file_off: 0x100,
            flags: 0x2, // non-executable data
            bytes: vec![0x00; 0x100],
        },
    ];
    let extents = vec![(0x1000, 0x20)];
    let initial_seeds = HashSet::from([0x1000]);
    let ctx = CandidateFilterContext {
        mappings: &mappings,
        known_extents: ExtentIndex::build(&extents),
        initial_seeds: &initial_seeds,
    };

    // Candidate 0x2050 is in a data mapping despite its valid instruction.
    let result = candidate_address_is_valid(0x2050, &ctx)
        && candidate_flow_is_valid(
            0x2050,
            &ctx,
            &FlowResult {
                terminal: false,
                conditional: false,
                return_op: false,
                delay_slots: Vec::new(),
                no_op: false,
                pure_jump: false,
                address: 0x2050,
                length: 4,
                fallthrough: Some(0x2054),
                targets: Vec::new(),
                kind: crate::native_runtime::FlowKind::Fallthrough,
                mode: None,
                target_modes: Vec::new(),
            },
        );
    assert!(
        !result,
        "candidate outside executable mapping must be rejected even with valid flow"
    );
}

#[test]
fn test_pe_data_to_data_relocation_recorded_in_xrefs() {
    // Build mock PE with .text (code) and .data (data) sections.
    // Relocation in .data points to .data (data-to-data).
    let mut b = vec![0u8; 0x400];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    b[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections (.text, .data, .reloc)
    b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size
    b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase at opt + 24
    // NumberOfRvaAndSizes at opt + 108: 16 directories
    b[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
    // Directory 5 (.reloc) at opt + 152:
    b[0x98 + 152..0x98 + 156].copy_from_slice(&0x3000u32.to_le_bytes()); // RVA
    b[0x98 + 156..0x98 + 160].copy_from_slice(&16u32.to_le_bytes()); // Size 16
    let sec = 0x80 + 24 + 0xf0;
    // Sec 0: .text (RVA 0x1000, size 0x1000, raw 0x100, raw_sz 0x100, flags 0x60000020 code)
    b[sec..sec + 5].copy_from_slice(b".text");
    b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
    b[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes());
    b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

    // Sec 1: .data (RVA 0x2000, size 0x1000, raw 0x200, raw_sz 0x100, flags 0xc0000040 data)
    let sec1 = sec + 40;
    b[sec1..sec1 + 5].copy_from_slice(b".data");
    b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
    b[sec1 + 20..sec1 + 24].copy_from_slice(&0x200u32.to_le_bytes());
    b[sec1 + 36..sec1 + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
    // Put a pointer at raw 0x200 (RVA 0x2000) pointing to .data at 0x140002080 (data-to-data)
    b[0x200..0x208].copy_from_slice(&0x140002080u64.to_le_bytes());

    // Sec 2: .reloc (RVA 0x3000, size 0x1000, raw 0x300, raw_sz 0x100, flags 0x42000040)
    let sec2 = sec + 80;
    b[sec2..sec2 + 6].copy_from_slice(b".reloc");
    b[sec2 + 8..sec2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec2 + 12..sec2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    b[sec2 + 16..sec2 + 20].copy_from_slice(&16u32.to_le_bytes());
    b[sec2 + 20..sec2 + 24].copy_from_slice(&0x300u32.to_le_bytes());
    b[sec2 + 36..sec2 + 40].copy_from_slice(&0x42000040u32.to_le_bytes());
    // Relocation block at 0x300:
    b[0x300..0x304].copy_from_slice(&0x2000u32.to_le_bytes()); // page RVA 0x2000
    b[0x304..0x308].copy_from_slice(&12u32.to_le_bytes()); // block size 12 (8 header + 2*2 entries)
    let entry0: u16 = (10 << 12) | 0; // DIR64 at off 0
    b[0x308..0x30a].copy_from_slice(&entry0.to_le_bytes());
    b[0x30a..0x30c].copy_from_slice(&0u16.to_le_bytes()); // padding

    let imp = import_pe(&b).unwrap();
    // 1. Data-to-data relocation must be emitted as DATA xref with pe-reloc provenance
    let xref = imp
        .xrefs
        .iter()
        .find(|x| x.from == 0x140002000 && x.to == 0x140002080);
    assert!(
        xref.is_some(),
        "data-to-data relocation must be present in xrefs"
    );
    assert_eq!(xref.unwrap().kind, "DATA");
    assert_eq!(xref.unwrap().provenance, "native-import:pe-reloc");

    // 2. Data-to-data relocation must NOT be promoted as a function candidate
    assert!(
        !imp.reloc_candidates.contains(&0x140002080),
        "data-to-data relocation must not be a function candidate"
    );
}

#[test]
fn test_pe32_fixture_import_and_discovery() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("../../tests/fixtures-src/tiny_pe32.exe");
    assert!(
        path.is_file(),
        "committed fixture must exist at {}",
        path.display()
    );
    let imp = load_native(&path).expect("tiny_pe32 must load cleanly");
    assert_eq!(imp.format, "PE");
    assert_eq!(imp.language, "x86:LE:32:default");
    assert_eq!(
        pe_image_base(&std::fs::read(&path).unwrap()),
        Some(0x400000)
    );
    assert!(imp.functions.iter().any(|f| f.entry == 0x401400));
    assert!(
        imp.xrefs
            .iter()
            .any(|x| x.provenance == "native-import:pe-reloc")
    );
    if crate::native_runtime::find_console(&imp.cfg).is_ok() {
        assert!(
            imp.functions.len() >= 10,
            "console discovery should find >= 10 functions, got {}",
            imp.functions.len()
        );
    } else {
        assert!(!imp.functions.is_empty(), "entry function must be present");
    }
}

#[test]
fn console_containers_route_to_their_loader() {
    // Each console magic must reach its own loader, not fall through to
    // the generic native path. A magic-only blob is recognized but
    // malformed, so the loader answers Some(Err) — which still proves the
    // dispatch routed (a miss would return the generic parse or None).
    let mut ncch = vec![0u8; 0x200];
    ncch[0x100..0x104].copy_from_slice(b"NCCH");
    assert!(threeds::is_ncch(&ncch), "NCCH magic must detect");
    assert!(
        threeds::import(&ncch).is_some(),
        "NCCH must route to threeds"
    );

    let mut ncsd = vec![0u8; 0x200];
    ncsd[0x100..0x104].copy_from_slice(b"NCSD");
    assert!(threeds::is_ncsd(&ncsd));
    assert!(
        threeds::import(&ncsd).is_some(),
        "NCSD must route to threeds"
    );

    // CIA: header size 0x2020 + type/version fields.
    let mut cia = vec![0u8; 0x10];
    cia[0..4].copy_from_slice(&[0x20, 0x20, 0x00, 0x00]);
    cia[4..8].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    assert!(threeds::is_cia(&cia));
    assert!(threeds::import(&cia).is_some(), "CIA must route to threeds");

    // PS3 SELF: SCE\0 magic. PS3's detector is magic-only.
    let mut ps3 = vec![0u8; 0x70];
    ps3[0..4].copy_from_slice(b"SCE\0");
    assert!(ps3::is_self(&ps3), "PS3 SELF magic must detect");

    // Vita shares the SCE\0 magic but its is_self is strict: it parses
    // the whole LE layout (version 3, type 1, embedded ARM ELF). A
    // magic-only blob is NOT a Vita image — and PS3 must not claim it
    // either, which is why vita::import runs before ps3::import.
    let mut vita = vec![0u8; 0x80];
    vita[0..4].copy_from_slice(b"SCE\0");
    vita[4..8].copy_from_slice(&3u32.to_le_bytes()); // version 3
    vita[10..12].copy_from_slice(&1u16.to_le_bytes()); // type SELF
    assert!(
        !vita::is_self(&vita),
        "a bare SCE\\0 header is not a complete Vita SELF"
    );

    // PSP PRX: ELF32 LE MIPS with e_type 0xFFA0 (ET_SCE_PSPRELEXEC).
    let mut prx = vec![0u8; 0x40];
    prx[0..4].copy_from_slice(b"\x7fELF");
    prx[4] = 1; // ELFCLASS32
    prx[5] = 1; // ELFDATA2LSB
    prx[16..18].copy_from_slice(&0xffa0u16.to_le_bytes()); // e_type
    prx[18..20].copy_from_slice(&8u16.to_le_bytes()); // EM_MIPS
    assert!(psp::is_prx(&prx), "PSP PRX must detect");
}

#[test]
fn test_relocation_only_code_function_is_promoted() {
    use crate::native_runtime::{FlowKind, FlowResult};
    // Setup:
    // func_root at 0x1000 has normal instruction-sized flow:
    // 0x1000: push rbp (len 1, fall 0x1001)
    // 0x1001: mov rbp, rsp (len 3, fall 0x1004)
    // 0x1004: ret (len 1, Return) -> proven extent 0x1000..0x1005 (size 5).
    //
    // Relocation candidate 0x1040 is in the gap outside func_root's extent:
    // 0x1040: push rbp (len 1, fall 0x1041)
    // 0x1041: mov rbp, rsp (len 3, fall 0x1044) -> reaches 0x1044 via Fallthrough!
    // 0x1044: call 0x1080 (len 5, Call target 0x1080, fall 0x1049)
    // 0x1049: ret (len 1, Return)
    //
    // Candidate 0x1044 is reached through fallthrough from 0x1040 (internal target!).
    // Candidate 0x1080 is reached through Call (call target!).
    //
    // Assert:
    // 1. Relocation-only code function at 0x1040 IS PROMOTED to imp.functions.
    // 2. Call target 0x1080 REMAINS a separate function in imp.functions.
    // 3. Internal candidate 0x1044 reached through fallthrough is merged/dropped!
    let mut imp = NativeImport {
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 0x200,
            file_off: 0,
            flags: 0x4, // executable
            bytes: vec![0x90; 0x200],
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            name: "func_root".into(),
            size: 5, // 0x1000..0x1005
        }],
        reloc_candidates: vec![0x1040, 0x1044, 0x1080],
        format: "ELF".into(),
        language: "x86:LE:64:default".into(),
        ..Default::default()
    };

    flow_discover_with_provider(&mut imp, |chunk| {
        chunk
            .iter()
            .map(|&addr| match addr {
                0x1000 => FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1000,
                    length: 1,
                    fallthrough: Some(0x1001),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None,
                    target_modes: Vec::new(),
                },
                0x1001 => FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1001,
                    length: 3,
                    fallthrough: Some(0x1004),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None,
                    target_modes: Vec::new(),
                },
                0x1004 => FlowResult {
                    terminal: true,
                    conditional: false,
                    return_op: true,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1004,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None,
                    target_modes: Vec::new(),
                },
                0x1040 => FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1040,
                    length: 1,
                    fallthrough: Some(0x1041),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None,
                    target_modes: Vec::new(),
                },
                0x1041 => FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1041,
                    length: 3,
                    fallthrough: Some(0x1044),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None,
                    target_modes: Vec::new(),
                },
                0x1044 => FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1044,
                    length: 5,
                    fallthrough: Some(0x1049),
                    targets: vec![0x1080],
                    kind: FlowKind::Call,
                    mode: None,
                    target_modes: Vec::new(),
                },
                0x1049 => FlowResult {
                    terminal: true,
                    conditional: false,
                    return_op: true,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1049,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None,
                    target_modes: Vec::new(),
                },
                0x1080 => FlowResult {
                    terminal: true,
                    conditional: false,
                    return_op: true,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1080,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None,
                    target_modes: Vec::new(),
                },
                other => FlowResult {
                    terminal: true,
                    conditional: false,
                    return_op: true,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: other,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None,
                    target_modes: Vec::new(),
                },
            })
            .collect()
    });

    // 1. Relocation-only code function at 0x1040 outside func_root's extent IS PROMOTED
    assert!(
        imp.functions.iter().any(|f| f.entry == 0x1040),
        "0x1040 must be promoted to a function"
    );

    // 2. Call target 0x1080 remains a separate function
    assert!(
        imp.functions.iter().any(|f| f.entry == 0x1080),
        "call target 0x1080 must remain a separate function"
    );

    // 3. Internal candidate 0x1044 reached through fallthrough from 0x1040 is merged/dropped
    assert!(
        !imp.functions.iter().any(|f| f.entry == 0x1044),
        "internal candidate 0x1044 reached via fallthrough must be merged/dropped"
    );

    // 4. Function size of 0x1040 covers the full span 0x1040..0x104a (size 0xa)
    let f_1040 = imp
        .functions
        .iter()
        .find(|f| f.entry == 0x1040)
        .expect("0x1040 must be present");
    assert_eq!(
        f_1040.size, 0xa,
        "0x1040 function size must be 0xa (0x1040..0x104a)"
    );
}
#[test]
fn regression_load_native_pe32_data_to_data_relocation_never_becomes_function() {
    let mut b = vec![0u8; 0x600];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
    b[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
    b[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // opt size 224
    let opt = 0x98;
    b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
    b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
    b[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // image base
    // NumberOfRvaAndSizes at opt + 92: 16 directories
    b[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    // Relocation directory at opt + 136: RVA 0x3000, size 16
    b[opt + 136..opt + 140].copy_from_slice(&0x3000u32.to_le_bytes());
    b[opt + 140..opt + 144].copy_from_slice(&16u32.to_le_bytes());

    let sec = opt + 0xe0; // 0x178
    // Sec 0: .text (RVA 0x1000, size 0x1000, raw 0x200, raw_sz 0x100, exec)
    b[sec..sec + 5].copy_from_slice(b".text");
    b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
    b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    b[0x200] = 0xc3; // ret at 0x401000

    // Sec 1: .data (RVA 0x2000, size 0x1000, raw 0x300, raw_sz 0x100, data)
    let sec1 = sec + 40;
    b[sec1..sec1 + 5].copy_from_slice(b".data");
    b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
    b[sec1 + 20..sec1 + 24].copy_from_slice(&0x300u32.to_le_bytes());
    b[sec1 + 36..sec1 + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
    // Put a 32-bit pointer at raw 0x300 (0x402000) pointing to 0x402080 (in .data)
    b[0x300..0x304].copy_from_slice(&0x402080u32.to_le_bytes());

    // Sec 2: .reloc (RVA 0x3000, size 0x1000, raw 0x400, raw_sz 0x100, reloc)
    let sec2 = sec + 80;
    b[sec2..sec2 + 6].copy_from_slice(b".reloc");
    b[sec2 + 8..sec2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    b[sec2 + 12..sec2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    b[sec2 + 16..sec2 + 20].copy_from_slice(&16u32.to_le_bytes());
    b[sec2 + 20..sec2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    b[sec2 + 36..sec2 + 40].copy_from_slice(&0x42000040u32.to_le_bytes());
    // Relocation block at 0x400: page RVA 0x2000, block size 12
    b[0x400..0x404].copy_from_slice(&0x2000u32.to_le_bytes());
    b[0x404..0x408].copy_from_slice(&12u32.to_le_bytes());
    let entry0: u16 = (3 << 12) | 0; // HIGHLOW at offset 0
    b[0x408..0x40a].copy_from_slice(&entry0.to_le_bytes());

    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join("test_pe32_data_reloc_regression.exe");
    std::fs::write(&tmp_path, &b).expect("write temp pe32");

    let imp = load_native(&tmp_path).expect("load_native must succeed on valid PE32");
    let _ = std::fs::remove_file(&tmp_path);

    assert_eq!(imp.format, "PE");
    assert_eq!(imp.language, "x86:LE:32:default");
    assert!(imp.functions.iter().any(|f| f.entry == 0x401000));

    // Proves data-to-data relocation remains an xref with pe-reloc provenance
    let xref = imp
        .xrefs
        .iter()
        .find(|x| x.from == 0x402000 && x.to == 0x402080);
    assert!(
        xref.is_some(),
        "data-to-data relocation must be recorded in xrefs"
    );
    assert_eq!(xref.unwrap().kind, "DATA");
    assert_eq!(xref.unwrap().provenance, "native-import:pe-reloc");

    // Proves data-to-data relocation target and source NEVER become functions
    assert!(
        !imp.functions.iter().any(|f| f.entry == 0x402080),
        "data-to-data relocation target must never become a function"
    );
    assert!(
        !imp.functions.iter().any(|f| f.entry == 0x402000),
        "data relocation source must never become a function"
    );
}

#[test]
fn regression_pe_truncated_optional_header_returns_error() {
    let mut b = vec![0u8; 0x100];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    b[0x94..0x96].copy_from_slice(&0x200u16.to_le_bytes()); // opt_size claims 0x200 (past 0x100 len)
    let res = import_pe(&b);
    assert!(res.is_err(), "truncated optional header must return Err");

    // Also test opt_size too small for PE32+ (e.g. 50 < 160)
    let mut b2 = vec![0u8; 0x200];
    b2[0..2].copy_from_slice(b"MZ");
    b2[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b2[0x80..0x84].copy_from_slice(b"PE\0\0");
    b2[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    b2[0x94..0x96].copy_from_slice(&50u16.to_le_bytes()); // opt_size 50
    b2[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // magic 0x20b
    let res2 = import_pe(&b2);
    assert!(
        res2.is_err(),
        "undersized PE32+ optional header must return Err"
    );

    // Also test opt_size too small for PE32 (e.g. 40 < 96)
    let mut b3 = vec![0u8; 0x200];
    b3[0..2].copy_from_slice(b"MZ");
    b3[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b3[0x80..0x84].copy_from_slice(b"PE\0\0");
    b3[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
    b3[0x94..0x96].copy_from_slice(&40u16.to_le_bytes()); // opt_size 40 < 96
    b3[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes()); // magic 0x10b
    let res3 = import_pe(&b3);
    assert!(
        res3.is_err(),
        "undersized PE32 optional header must return Err"
    );
}
#[test]
fn regression_pe_truncated_section_table_returns_error() {
    let mut b = vec![0u8; 0x200];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
    b[0x86..0x88].copy_from_slice(&50u16.to_le_bytes()); // 50 sections * 40 = 2000 bytes (past 0x200 len)
    b[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // opt_size 224
    let opt = 0x98;
    b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    let res = import_pe(&b);
    assert!(res.is_err(), "truncated section table must return Err");
}
#[test]
fn negative_test_reloc_section_ignored_when_directory_5_absent() {
    let mut b = vec![0u8; 0x600];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe_off = 0x80;
    b[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    b[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    b[pe_off + 6..pe_off + 8].copy_from_slice(&2u16.to_le_bytes()); // 2 sections (.text, .reloc)
    b[pe_off + 20..pe_off + 22].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size 240
    let opt = pe_off + 24; // 0x98
    b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
    // Explicit ImageBase (0x140000000) at opt + 24:
    b[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    // NumberOfRvaAndSizes at opt + 108 = 0 (Directory 5 ABSENT!)
    b[opt + 108..opt + 112].copy_from_slice(&0u32.to_le_bytes());

    let sec = opt + 0xf0; // 0x98 + 0xf0 = 0x188
    // Section table: 2 sections * 40 bytes = 80 bytes (0x188..0x1d8)
    // Sec 0: .text
    b[sec..sec + 5].copy_from_slice(b".text");
    b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
    b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData (after section table ends at 0x1d8)
    b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // CODE | EXECUTE | READ

    // Sec 1: .reloc with valid relocation block bytes, but Directory 5 is ABSENT
    let sec1 = sec + 40; // 0x1b0
    b[sec1..sec1 + 6].copy_from_slice(b".reloc");
    b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
    b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
    b[sec1 + 20..sec1 + 24].copy_from_slice(&0x300u32.to_le_bytes()); // PointerToRawData (after .text raw data)
    b[sec1 + 36..sec1 + 40].copy_from_slice(&0x42000040u32.to_le_bytes()); // INITIALIZED_DATA | DISCARDABLE | READ

    // Put mapped executable pointer at relocation location in .text raw data (raw 0x200, RVA 0x1000):
    // Relocated pointer 0x140001050 lands inside executable mapping (ImageBase 0x140000000 + RVA 0x1000..0x2000)
    b[0x200..0x208].copy_from_slice(&0x140001050u64.to_le_bytes());

    // Put valid relocation block in .reloc raw data (raw 0x300):
    b[0x300..0x304].copy_from_slice(&0x1000u32.to_le_bytes()); // Page RVA
    b[0x304..0x308].copy_from_slice(&12u32.to_le_bytes()); // Block Size
    let entry0: u16 = (10 << 12) | 0; // DIR64 at offset 0
    b[0x308..0x30a].copy_from_slice(&entry0.to_le_bytes());

    let imp = import_pe(&b).expect("PE must parse cleanly");
    // Directory 5 is absent, so .reloc section MUST BE IGNORED
    assert!(
        imp.xrefs.is_empty(),
        "xrefs must be empty when directory 5 is absent"
    );
    assert!(
        imp.reloc_candidates.is_empty(),
        "reloc_candidates must be empty when directory 5 is absent"
    );
}

#[test]
fn a_mode_declaration_never_takes_the_console_down() {
    // These are ARM instructions. Read in Thumb mode -- which a `$t`
    // symbol or a pattern's `setcontext` can ask for at any address --
    // they drove the constructor walk past the parser's fixed 75 states
    // (sleigh.cc:457), and indexing past the end killed the console
    // mid-import. Out of states is a decode failure, not a crash.
    use crate::native_runtime::{ConsoleSession, FlowKind, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "ARM:LE:32:v8".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/ARM/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let import = NativeImport {
        language: cfg.language_id.clone(),
        compiler: Some("default".into()),
        format: "elf32".into(),
        cfg: cfg.clone(),
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 24,
            file_off: 0,
            flags: 6,
            bytes: vec![
                0x02, 0x8b, 0x2d, 0xed, 0x00, 0x8a, 0xb7, 0xee, 0x24, 0xd0, 0x4d, 0xe2, 0x00,
                0x70, 0xa0, 0xe1, 0x10, 0x60, 0x8d, 0xe2, 0x0d, 0x50, 0xa0, 0xe1,
            ],
        }],
        contexts: vec![NativeContext {
            name: "TMode".into(),
            address: 0x1002,
            value: 1,
        }],
        ..Default::default()
    };
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    let flows = session
        .flow_batch(&[0x1002, 0x1004])
        .expect("the console must answer, not die");
    assert_eq!(flows.len(), 2, "one answer per address");
    assert_eq!(flows[0].kind, FlowKind::Bad, "no Thumb instruction there");
}

#[test]
fn pattern_search_reads_only_the_bytes_the_image_carries() {
    // A PS2 executable's last code section declares more virtual size than
    // it carries bytes for. The old range asked the console to search
    // addresses the load image never received, `loadFill` raised
    // DataUnavailError, the whole pattern search failed, and the import
    // kept one function out of 8794.
    use crate::native_runtime::{ConsoleSession, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "MIPS:LE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/MIPS/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let import = NativeImport {
        language: cfg.language_id.clone(),
        compiler: Some("default".into()),
        format: "elf".into(),
        cfg: cfg.clone(),
        mappings: vec![Mapping {
            vaddr: 0x1000,
            // Sixteen bytes of virtual extent, eight bytes of content.
            size: 16,
            file_off: 0,
            flags: 6,
            bytes: vec![0, 0, 0, 0, 0x08, 0x00, 0xe0, 0x03],
        }],
        ..Default::default()
    };
    let ranges = code_ranges(&import);
    assert_eq!(ranges, vec![(0x1000, 0x1008)], "ranges stop at the bytes");
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    session
        .function_patterns(&ranges)
        .expect("a byte-backed range is searchable");
}

#[test]
fn flow_batch_answers_every_address_it_is_asked() {
    // One undecodable address used to discard the rest of the command line,
    // so a batch came back short and discovery fell back to pointer-only
    // seeds: MIPS lost half its functions to a delay slot at a mapping's
    // end (sleigh.cc:385) and to addresses the image does not cover
    // (loadimage_xml.cc:236).
    use crate::native_runtime::{ConsoleSession, FlowKind, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "MIPS:LE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/MIPS/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let import = NativeImport {
        language: cfg.language_id.clone(),
        compiler: Some("default".into()),
        format: "elf".into(),
        cfg: cfg.clone(),
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 16,
            file_off: 0,
            flags: 6,
            // Sixteen bytes of real MIPS text. Read at 0x1002 they are a
            // branch-likely whose delay slot never reaches the pcode
            // state, so SleighBuilder::delaySlot raises a plain
            // LowlevelError (sleigh.cc:385) rather than BadDataError.
            bytes: vec![
                0x82, 0x05, 0x0e, 0x46, 0x03, 0x52, 0x0c, 0x46, 0x00, 0x45, 0x1a, 0x46, 0xda,
                0x00, 0x04, 0x0c,
            ],
        }],
        ..Default::default()
    };
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    let asked = [0x1002u64, 0x1004, 0x9000];
    let flows = session.flow_batch(&asked).expect("batch must not fail");
    assert_eq!(
        flows.iter().map(|flow| flow.address).collect::<Vec<_>>(),
        asked,
        "one answer per requested address, in order"
    );
    assert_eq!(
        flows[0].kind,
        FlowKind::Bad,
        "branch whose delay slot cannot be cached"
    );
    assert_eq!(
        flows[1].kind,
        FlowKind::Fallthrough,
        "the aligned instruction still decodes"
    );
    assert_eq!(
        flows[2].kind,
        FlowKind::Bad,
        "address the image does not map"
    );
}

#[test]
fn references_apply_pc_helper_fixups() {
    use crate::native_runtime::{ConsoleSession, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "x86:LE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/x86/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let mut import = NativeImport {
        language: cfg.language_id.clone(),
        compiler: Some("gcc".into()),
        format: "elf".into(),
        cfg: cfg.clone(),
        functions: vec![
            NativeFunction {
                entry: 0x1000,
                size: 14,
                name: "FUN_1000".into(),
            },
            NativeFunction {
                entry: 0x1100,
                size: 4,
                name: "FUN_1100".into(),
            },
        ],
        mappings: vec![
            Mapping {
                vaddr: 0x1000,
                size: 14,
                file_off: 0,
                flags: 6,
                bytes: vec![
                    0xe8, 0xfb, 0, 0, 0, // call 0x1100
                    0x8d, 0x83, 0xfb, 0x2f, 0, 0, // lea eax,[ebx+0x2ffb]
                    0x31, 0xc0, 0xc3, // discard address; ret
                ],
            },
            Mapping {
                vaddr: 0x1100,
                size: 4,
                file_off: 0,
                flags: 6,
                bytes: vec![0x8b, 0x1c, 0x24, 0xc3], // mov ebx,[esp]; ret
            },
            Mapping {
                vaddr: 0x4000,
                size: 16,
                file_off: 0,
                flags: 3,
                bytes: vec![0; 16],
            },
        ],
        ..Default::default()
    };
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
    let refs: Vec<_> = import
        .xrefs
        .iter()
        .map(|xref| (xref.from, xref.to, xref.kind.as_str()))
        .collect();
    assert_eq!(
        refs,
        vec![(0x1005, 0x4000, "DATA")],
        "a recognized helper supplies the caller PC for address formation"
    );

    import.xrefs.clear();
    import.mappings[0].bytes = vec![
        0x83, 0xe4, 0xf0, // and esp,-16
        0xe8, 0xf8, 0, 0, 0, // call 0x1100
        0x8d, 0x83, 0xf8, 0x2f, 0, 0, // lea eax,[ebx+0x2ff8]
        0x31, 0xc0, 0xc3,
    ];
    import.mappings[0].size = 17;
    import.functions[0].size = 17;
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
    let refs: Vec<_> = import
        .xrefs
        .iter()
        .map(|xref| (xref.from, xref.to, xref.kind.as_str()))
        .collect();
    assert_eq!(
        refs,
        vec![(0x1008, 0x4000, "DATA")],
        "stack realignment must retain a usable frame for the helper"
    );

    import.xrefs.clear();
    import.functions.truncate(1);
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
    assert!(
        import.xrefs.is_empty(),
        "a pattern alone cannot establish a function"
    );

    import.functions.push(NativeFunction {
        entry: 0x1100,
        size: 5,
        name: "FUN_1100".into(),
    });
    import.mappings[1].bytes = vec![0x8b, 0x5c, 0x24, 4, 0xc3]; // reads argument, not PC
    import.mappings[1].size = 5;
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
    assert!(
        import.xrefs.is_empty(),
        "ordinary calls retain unknown register context"
    );

    import.mappings[0].bytes = vec![
        0xc7, 0x04, 0x24, 0, 0x40, 0, 0, // mov dword [esp],0x4000
        0x89, 0xe1, // mov ecx,esp
        0x83, 0xe4, 0xf0, // and esp,-16
        0x8b, 0x04, 0x24, // mov eax,[esp]: old slot may not alias
        0x29, 0xe1, // sub ecx,esp: old pointer may not equal new pointer
        0x81, 0xc1, 0x08, 0x40, 0, 0, // add ecx,0x4008
        0xc3,
    ];
    import.mappings[0].size = import.mappings[0].bytes.len() as u64;
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    let facts = session
        .constants(
            0x1000,
            0x1000 + import.mappings[0].size,
            &import.mappings,
            false,
        )
        .unwrap();
    assert!(
        facts.iter().all(|fact| fact.pc < 0x1009),
        "realignment must not produce constants from stale frame aliases: {facts:?}"
    );
}

#[test]
fn inferred_references_use_writable_image_values() {
    use crate::native_runtime::{ConsoleSession, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "x86:LE:64:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/x86/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let mut import = NativeImport {
        language: cfg.language_id.clone(),
        compiler: Some("gcc".into()),
        format: "elf".into(),
        cfg: cfg.clone(),
        functions: vec![NativeFunction {
            entry: 0x1000,
            size: 14,
            name: "FUN_1000".into(),
        }],
        mappings: vec![
            Mapping {
                vaddr: 0x1000,
                size: 14,
                file_off: 0,
                flags: 6,
                bytes: vec![
                    0x48, 0x8b, 0x04, 0x25, 0, 0x30, 0, 0, // mov rax,[0x3000]
                    0x48, 0x8b, 0x08, // mov rcx,[rax]
                    0x31, 0xc0, 0xc3,
                ],
            },
            Mapping {
                vaddr: 0x3000,
                size: 8,
                file_off: 0,
                flags: 3,
                bytes: 0x4000u64.to_le_bytes().to_vec(),
            },
            Mapping {
                vaddr: 0x4000,
                size: 16,
                file_off: 0,
                flags: 3,
                bytes: vec![0; 16],
            },
        ],
        ..Default::default()
    };
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
    let refs: Vec<_> = import
        .xrefs
        .iter()
        .map(|xref| (xref.from, xref.to, xref.kind.as_str()))
        .collect();
    assert_eq!(
        refs,
        vec![(0x1000, 0x3000, "READ"), (0x1008, 0x4000, "READ")],
        "reference inference follows the selected analyzer's writable-image policy"
    );
    let strict = session
        .constants(0x1000, 0x100e, &import.mappings, false)
        .unwrap();
    assert!(
        strict.iter().all(|fact| fact.value != 0x4000),
        "strict constant queries must not inherit reference-inference heuristics: {strict:?}"
    );
}

#[test]
fn stub_jump_seeds_promotes_only_bare_jump_stubs() {
    use super::{Mapping, NativeFunction, NativeImport, NativeXref, stub_jump_seeds};
    fn imp(functions: Vec<(u64, u64)>, xrefs: Vec<(u64, u64, &str)>) -> NativeImport {
        NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x1000,
                file_off: 0,
                flags: 5,
                bytes: vec![],
            }],
            functions: functions
                .into_iter()
                .map(|(entry, size)| NativeFunction {
                    entry,
                    size,
                    name: format!("FUN_{entry:08x}"),
                })
                .collect(),
            xrefs: xrefs
                .into_iter()
                .map(|(from, to, kind)| NativeXref::new(from, to, kind))
                .collect(),
            ..Default::default()
        }
    }
    let code = |from: u64, to: u64| (from, to, "UNCONDITIONAL_JUMP");
    let call = |from: u64, to: u64| (from, to, "UNCONDITIONAL_CALL");
    // Bare jump stub seeds its destination.
    let import = imp(vec![(0x1000, 10)], vec![code(0x1004, 0x1100)]);
    assert_eq!(stub_jump_seeds(&import), vec![(0x1000, 0x1100)]);
    // Substantial body: tail call, stays parked.
    let import = imp(vec![(0x1000, 64)], vec![code(0x1030, 0x1100)]);
    assert!(stub_jump_seeds(&import).is_empty());
    // A call inside disqualifies the stub shape.
    let import = imp(
        vec![(0x1000, 10)],
        vec![code(0x1004, 0x1100), call(0x1008, 0x1200)],
    );
    assert!(stub_jump_seeds(&import).is_empty());
    // Destination already an entry, or outside code: nothing to do.
    let import = imp(vec![(0x1000, 10), (0x1100, 20)], vec![code(0x1004, 0x1100)]);
    assert!(stub_jump_seeds(&import).is_empty());
    let import = imp(vec![(0x1000, 10)], vec![code(0x1004, 0x9000)]);
    assert!(stub_jump_seeds(&import).is_empty());
}

#[test]
fn const_entry_swallowed_needs_strict_containment() {
    use super::store::const_entry_swallowed;
    // Swallows a better-evidenced entry: retract.
    assert!(const_entry_swallowed(0x1000, 100, &[0x1020]));
    // Abutting neighbour: correct boundary, keep.
    assert!(!const_entry_swallowed(0x1000, 0x20, &[0x1020]));
    // Entry itself or an address before it: not containment.
    assert!(!const_entry_swallowed(0x1000, 100, &[0x1000]));
    assert!(!const_entry_swallowed(0x1000, 100, &[0x0ff0]));
    // Zero size reads as one byte; an entry never swallows itself.
    assert!(!const_entry_swallowed(0x1000, 0, &[0x1000]));
    assert!(!const_entry_swallowed(0x1000, 0, &[0x1001]));
    // Empty evidence: nothing to swallow.
    assert!(!const_entry_swallowed(0x1000, 100, &[]));
}

/// A labelled pattern match the importer refused, or a start the
/// guard-clause merge absorbed, is no evidence of a function: counted,
/// it retracted the const-seeded callback around it (swkotor2
/// 0x727010). An accepted pattern start inside one still does.
#[test]
fn only_accepted_pattern_starts_retract_a_const_entry() {
    let stored = |pattern_starts: Vec<u64>, absorbed: Vec<u64>| {
        let imp = NativeImport {
            language: "x86:LE:32:default".into(),
            functions: vec![NativeFunction {
                entry: 0x1000,
                size: 0x100,
                name: "FUN_00001000".into(),
            }],
            const_data_starts: vec![0x1000],
            pattern_labels: vec![(0x1040, "refused".into())],
            pattern_starts,
            absorbed_starts: absorbed.into_iter().collect(),
            ..Default::default()
        };
        let db = ProjectDb::open_in_memory().unwrap();
        let pid = db.upsert_program("p", &imp.language, &native_provenance()).unwrap();
        store_import(&db, "p", &imp, None).unwrap();
        db.functions(pid).unwrap().len()
    };
    assert_eq!(stored(Vec::new(), Vec::new()), 1, "a refused match retracted the callback");
    assert_eq!(stored(vec![0x1080], vec![0x1080]), 1, "an absorbed start retracted its owner");
    assert_eq!(stored(vec![0x1080], Vec::new()), 0, "an accepted start inside must still retract");
}

#[test]
fn const_data_use_denied_refuses_compares_keeps_materialization() {
    let denied = |ops: &[&str]| {
        super::const_data_use_denied(&ops.iter().map(|op| op.to_string()).collect::<Vec<_>>())
    };
    // Measured libc shapes: comparison immediates must not seed.
    assert!(denied(&["INT_EQUAL"]));
    assert!(denied(&["INT_NOTEQUAL", "COPY"]));
    assert!(denied(&["BOOL_AND"]));
    assert!(denied(&["FLOAT_LESS"]));
    // Materialization must seed: LEA/MOV lower to INT_ADD/COPY, and
    // unknown shapes stay allowed (recall-preserving).
    assert!(!denied(&["INT_ADD"]));
    assert!(!denied(&["COPY"]));
    assert!(!denied(&["LOAD"]));
    assert!(!denied(&["INT_OR"]));
    assert!(!denied(&[]));
}

/// A local must end at or below the parameter boundary: kept, a 4-byte
/// access at -1 names bytes past the top of a 32-bit stack space and
/// the decompiler refuses to load the whole program.
#[test]
fn a_stack_access_straddling_the_parameter_boundary_is_no_local() {
    let frame = stack_frame(0x1000, &[(-1, 4), (-8, 4), (-4, 4)]);
    let slots: Vec<(Option<i64>, Option<u64>)> =
        frame.iter().map(|row| (row.offset, row.size)).collect();
    assert_eq!(slots, vec![(Some(-8), Some(4)), (Some(-4), Some(4))]);
}

#[test]
fn pattern_labels_need_a_body_and_a_generated_name() {
    let mut imp = NativeImport {
        functions: vec![
            NativeFunction {
                entry: 0x1000,
                size: 4,
                name: "FUN_00001000".into(),
            },
            NativeFunction {
                entry: 0x1004,
                size: 4,
                name: "frame_dummy".into(),
            },
            // A one-byte stub is an address, not a proven body.
            NativeFunction {
                entry: 0x1008,
                size: 1,
                name: "FUN_00001008".into(),
            },
        ],
        pattern_labels: vec![
            (0x1000, "__i686.get_pc_thunk.bx".into()),
            (0x1004, "__i686.get_pc_thunk.ax".into()),
            (0x1008, "__i686.get_pc_thunk.cx".into()),
            (0x100c, "__i686.get_pc_thunk.dx".into()),
        ],
        ..Default::default()
    };
    apply_pattern_labels(&mut imp);
    assert_eq!(
        imp.functions
            .iter()
            .map(|function| (function.entry, function.name.clone()))
            .collect::<Vec<_>>(),
        vec![
            (0x1000, "__i686.get_pc_thunk.bx".to_string()),
            (0x1004, "frame_dummy".to_string()),
            (0x1008, "FUN_00001008".to_string()),
        ]
    );
}

#[test]
fn initializer_labels_replace_only_generated_names() {
    let mut imp = NativeImport {
        functions: vec![
            NativeFunction {
                entry: 0x1000,
                size: 4,
                name: "FUN_00001000".into(),
            },
            NativeFunction {
                entry: 0x1004,
                size: 4,
                name: "frame_dummy".into(),
            },
        ],
        initializer_labels: vec![
            (0x1000, "_INIT_0".into()),
            (0x1004, "_INIT_1".into()),
            // No function there: a label for nothing is dropped.
            (0x1008, "_FINI_0".into()),
        ],
        ..Default::default()
    };
    apply_initializer_labels(&mut imp);
    assert_eq!(
        imp.functions
            .iter()
            .map(|function| (function.entry, function.name.clone()))
            .collect::<Vec<_>>(),
        vec![
            (0x1000, "_INIT_0".to_string()),
            (0x1004, "frame_dummy".to_string()),
        ]
    );
}

#[test]
fn linkage_naming_replaces_only_generated_names() {
    let mut imp = NativeImport {
        functions: vec![
            NativeFunction {
                entry: 0x1000,
                size: 4,
                name: "FUN_00001000".into(),
            },
            NativeFunction {
                entry: 0x1100,
                size: 4,
                name: "_init".into(),
            },
            NativeFunction {
                entry: 0x1200,
                size: 4,
                name: "FUN_00001200".into(),
            },
        ],
        externals: vec![(0x1000, "printf".into()), (0x1100, "__cxa_finalize".into())],
        thunks: vec![
            NativeThunk {
                entry: 0x1000,
                destination: 0x2000,
                kind: romwright_model::ThunkKind::Linkage,
                source: THUNK_SOURCE,
            },
            NativeThunk {
                entry: 0x1100,
                destination: 0x2008,
                kind: romwright_model::ThunkKind::Linkage,
                source: THUNK_SOURCE,
            },
            // A direct thunk carries no import evidence, so no name.
            NativeThunk {
                entry: 0x1200,
                destination: 0x1000,
                kind: romwright_model::ThunkKind::Direct,
                source: THUNK_SOURCE,
            },
        ],
        ..Default::default()
    };
    name_linkage_stubs(&mut imp);
    assert_eq!(
        imp.functions
            .iter()
            .map(|function| (function.entry, function.name.clone()))
            .collect::<Vec<_>>(),
        vec![
            (0x1000, "printf".to_string()),
            // A section-derived name stands: it is evidence of its own.
            (0x1100, "_init".to_string()),
            (0x1200, "FUN_00001200".to_string()),
        ]
    );
}

/// The index comes from the slot's position and the prefix from the array
/// the slot belongs to; nothing here is guessed.
#[test]
fn initializer_arrays_name_their_targets_by_index() {
    let mut bytes = vec![0u8; 0x300];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    for (offset, value) in [
        (16, 2u16),
        (18, 3),
        (40, 52),
        (42, 32),
        (44, 3),
        (46, 40),
        (48, 5),
        (50, 4),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(20, 1u32), (24, 0x1000), (28, 52), (32, 0x200)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, header) in [
        // code, data holding the arrays, and the dynamic table
        [1u32, 0x100, 0x1000, 0x1000, 0x20, 0x20, 5, 1],
        [1, 0x120, 0x3000, 0x3000, 0x10, 0x10, 6, 1],
        [2, 0x140, 0x3100, 0x3100, 0x28, 0x28, 6, 4],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 52 + index * 32 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    // Two init entries and one fini entry, pointing into the code segment.
    for (index, target) in [0x1000u32, 0x1004, 0x1008].iter().enumerate() {
        let offset = 0x120 + index * 4;
        bytes[offset..offset + 4].copy_from_slice(&target.to_le_bytes());
    }
    for (index, (tag, value)) in [(25u32, 0x3000u32), (27, 8), (26, 0x3008), (28, 4)]
        .iter()
        .enumerate()
    {
        let offset = 0x140 + index * 8;
        bytes[offset..offset + 4].copy_from_slice(&tag.to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let names = b"\0.text\0.init_array\0.fini_array\0.shstrtab\0";
    bytes[0x180..0x180 + names.len()].copy_from_slice(names);
    for (index, header) in [
        [1u32, 1, 6, 0x1000, 0x100, 0x20, 0, 0, 1, 0],
        [7, 14, 3, 0x3000, 0x120, 8, 0, 0, 4, 0],
        [19, 15, 3, 0x3008, 0x128, 4, 0, 0, 4, 0],
        [31, 3, 0, 0, 0x180, names.len() as u32, 0, 0, 1, 0],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 0x200 + (index + 1) * 40 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    let import = import_elf(&bytes).expect("elf");
    let base = import
        .mappings
        .iter()
        .map(|mapping| mapping.vaddr)
        .min()
        .unwrap();
    let bias = base - 0x1000;
    assert_eq!(
        import.initializer_labels,
        vec![
            (0x1000 + bias, "_INIT_0".to_string()),
            (0x1004 + bias, "_INIT_1".to_string()),
            (0x1008 + bias, "_FINI_0".to_string()),
        ]
    );
}

/// A 32-bit ELF whose `.dynamic` declares `DT_PLTGOT = 0x3000`, with a
/// `.got` section of `got_size` bytes at that address and a two-slot PLT
/// read at 0x1000. The GOT section size is the parameter because the ABI's
/// three reserved words only exist where the object has room for them.
fn elf32_with_pltgot(got_size: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x300];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    for (offset, value) in [
        (16, 2u16),
        (18, 3),
        (40, 52),
        (42, 32),
        (44, 3),
        (46, 40),
        (48, 5),
        (50, 4),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(20, 1u32), (24, 0x1000), (28, 52), (32, 0x200)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, header) in [
        [1u32, 0x100, 0x1000, 0x1000, 6, 6, 5, 1],
        [1, 0x120, 0x3000, 0x3000, 0x30, 0x30, 6, 1],
        [2, 0x140, 0x3020, 0x3020, 16, 16, 6, 4],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 52 + index * 32 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    bytes[0x100..0x106].copy_from_slice(&[0x8b, 0x43, 4, 0xff, 0x63, 8]);
    bytes[0x140..0x144].copy_from_slice(&3u32.to_le_bytes()); // DT_PLTGOT
    bytes[0x144..0x148].copy_from_slice(&0x3000u32.to_le_bytes());
    let names = b"\0.plt\0.got\0.dynamic\0.shstrtab\0.text\0";
    bytes[0x180..0x180 + names.len()].copy_from_slice(names);
    for (index, header) in [
        [1u32, 1, 6, 0x1000, 0x100, 6, 0, 0, 1, 0],
        [6, 1, 3, 0x3000, 0x120, got_size, 0, 0, 4, 0],
        [11, 6, 3, 0x3020, 0x140, 16, 0, 0, 4, 8],
        [20, 3, 0, 0, 0x180, names.len() as u32, 0, 0, 1, 0],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 0x200 + (index + 1) * 40 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    bytes
}

#[test]
fn reserved_words_stop_at_the_object_that_holds_them() {
    // `powerpc_many_o2`'s `.plt` is two words long, so the address the
    // third reserved word would occupy belongs to `.bss` -- the guard byte
    // `_FINI_0` reads. Typing it as a resolver pointer and treating its
    // readers as PLT headers truncated that function to `halt_baddata()`
    // (m4-022).
    let import = import_elf(&elf32_with_pltgot(16)).unwrap();
    assert_eq!(
        import.plt_reserved_slots,
        vec![(0x3000, 4), (0x3004, 4), (0x3008, 4)],
        "a GOT with room for three words reserves three"
    );
    assert_eq!(import.plt_resolver_slot, Some(0x3008));

    let import = import_elf(&elf32_with_pltgot(8)).unwrap();
    assert_eq!(
        import.plt_reserved_slots,
        vec![(0x3000, 4), (0x3004, 4)],
        "a two-word GOT reserves two, and the third address is not ours"
    );
    assert_eq!(import.plt_resolver_slot, None);
}

#[test]
fn elf_plt_register_context_is_scoped() {
    use crate::native_runtime::find_console;
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "x86:LE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/x86/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let mut bytes = elf32_with_pltgot(16);
    let analyze = |bytes: &[u8]| {
        let mut import = import_elf(bytes).unwrap();
        import.cfg = cfg.clone();
        select_language(&mut import, &cfg).unwrap();
        assert!(discovery::discover_seeded(&mut import));
        let mut session = crate::native_runtime::ConsoleSession::new(&import.cfg).unwrap();
        session.load_mapped(&import).unwrap();
        import.xrefs.clear();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        let strict = session
            .constants(0x1000, 0x1006, &import.mappings, false)
            .unwrap();
        assert!(
            strict.is_empty(),
            "reference-only context must not seed strict queries: {strict:?}"
        );
        import
            .xrefs
            .into_iter()
            .map(|xref| (xref.from, xref.to, xref.kind))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        analyze(&bytes),
        vec![
            (0x1000, 0x3004, "READ".into()),
            (0x1003, 0x3008, "READ".into())
        ],
        "ELF PLT references use the loader-declared GOT register context"
    );
    bytes[0x140..0x144].fill(0);
    assert!(
        analyze(&bytes).is_empty(),
        "a GOT section cannot substitute for DT_PLTGOT"
    );
    bytes[0x140..0x144].copy_from_slice(&3u32.to_le_bytes());
    bytes[0x228..0x22c].copy_from_slice(&30u32.to_le_bytes()); // rename .plt to .text
    assert!(
        analyze(&bytes).is_empty(),
        "PLT register context must not leak into ordinary code"
    );
}

#[test]
fn powerpc_pic_context_follows_calls_not_unrelated_functions() {
    use crate::native_runtime::{ConsoleSession, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "PowerPC:BE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/PowerPC/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let mut bytes = vec![0u8; 0x500];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
    for (offset, value) in [
        (16, 2u16),
        (18, 20),
        (40, 52),
        (42, 32),
        (44, 3),
        (46, 40),
        (48, 5),
        (50, 4),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }
    for (offset, value) in [(20, 1u32), (24, 0x1100), (28, 52), (32, 0x400)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    for (index, header) in [
        [1u32, 0x100, 0x1000, 0x1000, 0x208, 0x208, 5, 4],
        [1, 0x320, 0x3000, 0x3000, 0x20, 0x20, 6, 4],
        [2, 0x330, 0x3010, 0x3010, 16, 16, 6, 4],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 52 + index * 32 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
    }
    for (offset, instruction) in [
        (0x100, 0x807e0004u32),
        (0x104, 0x4e800020), // lwz r3,4(r30); blr
        (0x200, 0x3fc00000),
        (0x204, 0x63de3000), // lis/ori r30,0x3000
        (0x208, 0x4bfffef9),
        (0x20c, 0x4e800020), // bl 0x1000; blr
        (0x300, 0x807e0008),
        (0x304, 0x4e800020), // uncalled load
        (0x330, 0x70000000),
        (0x334, 0x3000), // DT_PPC_GOT
    ] {
        bytes[offset..offset + 4].copy_from_slice(&instruction.to_be_bytes());
    }
    let names = b"\0.text\0.got\0.dynamic\0.shstrtab\0";
    bytes[0x360..0x360 + names.len()].copy_from_slice(names);
    for (index, header) in [
        [1u32, 1, 6, 0x1000, 0x100, 0x208, 0, 0, 4, 0],
        [7, 1, 3, 0x3000, 0x320, 16, 0, 0, 4, 0],
        [12, 6, 3, 0x3010, 0x330, 16, 0, 0, 4, 8],
        [21, 3, 0, 0, 0x360, names.len() as u32, 0, 0, 1, 0],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 0x400 + (index + 1) * 40 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
    }
    let analyze = |bytes: &[u8], caller_first: bool| {
        let mut import = import_elf(bytes).unwrap();
        import.cfg = cfg.clone();
        select_language(&mut import, &cfg).unwrap();
        import.functions = [(0x1000, 8), (0x1100, 16), (0x1200, 8)]
            .into_iter()
            .map(|(entry, size)| NativeFunction {
                entry,
                size,
                name: format!("FUN_{entry:x}"),
            })
            .collect();
        if caller_first {
            import.functions.swap(0, 1);
        }
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        assert!(
            session
                .constants(0x1000, 0x1008, &import.mappings, false)
                .unwrap()
                .is_empty(),
            "call-derived reference context must not enter strict constant queries"
        );
        let mut data = Vec::new();
        let reads = import
            .xrefs
            .into_iter()
            .filter_map(|xref| {
                if xref.kind == "DATA" {
                    data.push((xref.from, xref.to));
                }
                (xref.kind == "READ").then_some((xref.from, xref.to))
            })
            .collect::<Vec<_>>();
        (reads, data)
    };
    assert_eq!(
        analyze(&bytes, false).0,
        vec![(0x1000, 0x3004)],
        "only the called function inherits the actual r30 value, independent of query order"
    );
    bytes[0x330..0x334].fill(0);
    assert!(
        analyze(&bytes, false).0.is_empty(),
        "a GOT section alone cannot enable r30 propagation"
    );
    bytes[0x330..0x334].copy_from_slice(&0x70000000u32.to_be_bytes());
    for offset in [0x200, 0x204] {
        bytes[offset..offset + 4].copy_from_slice(&0x60000000u32.to_be_bytes()); // nop
    }
    assert!(
        analyze(&bytes, false).0.is_empty(),
        "unknown caller values must not invent a GOT context"
    );
    bytes[0x200..0x204].copy_from_slice(&0x3fc00000u32.to_be_bytes()); // lis r30,0
    bytes[0x100..0x104].copy_from_slice(&0x807e3004u32.to_be_bytes()); // lwz r3,0x3004(r30)
    assert!(
        analyze(&bytes, false).0.is_empty(),
        "zero is not an established PIC register context"
    );
    bytes[0x204..0x208].copy_from_slice(&0x63de0004u32.to_be_bytes()); // ori r30,r30,4
    let (reads, data) = analyze(&bytes, false);
    assert_eq!(
        reads,
        vec![(0x1000, 0x3008)],
        "use the actual caller value, not DT_PPC_GOT"
    );
    assert!(
        data.contains(&(0x1000, 0x3004)),
        "call context adds precise accesses without erasing speculative offset DATA"
    );
    assert_eq!(
        analyze(&bytes, true),
        (reads, data),
        "caller-first scheduling must retain the same local and contextual evidence"
    );
}

#[test]
fn elf_linkage_references_do_not_require_functions() {
    use crate::native_runtime::{ConsoleSession, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "PowerPC:BE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/PowerPC/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let code = [
        0x3d, 0x60, 0, 0, 0x81, 0x6b, 0x30, 4, // lis r11,0; lwz r11,0x3004(r11)
        0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20, // mtctr r11; bctr
        0x48, 0, 0, 8, 0x60, 0, 0, 0, // disconnected resolver: b next; nop
        0x3d, 0x80, 0, 0, 0x80, 0x0c, 0x30, 8, // lis r12,0; lwz r0,0x3008(r12)
        0x4e, 0x80, 0, 0x20, // blr
    ];
    let mut bytes = vec![0u8; 0x2a0];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
    for (offset, value) in [
        (16, 2u16),
        (18, 20),
        (40, 52),
        (42, 32),
        (44, 2),
        (46, 40),
        (48, 4),
        (50, 3),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }
    for (offset, value) in [(20, 1u32), (24, 0x1000), (28, 52), (32, 0x200)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    for (index, header) in [
        [
            1u32,
            0x100,
            0x1000,
            0x1000,
            code.len() as u32,
            code.len() as u32,
            5,
            4,
        ],
        [1, 0x140, 0x3000, 0x3000, 16, 16, 6, 4],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 52 + index * 32 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
    }
    bytes[0x100..0x100 + code.len()].copy_from_slice(&code);
    let names = b"\0.glink\0.data\0.shstrtab\0.text\0";
    bytes[0x180..0x180 + names.len()].copy_from_slice(names);
    for (index, header) in [
        [1u32, 1, 6, 0x1000, 0x100, code.len() as u32, 0, 0, 4, 0],
        [8, 1, 3, 0x3000, 0x140, 16, 0, 0, 4, 0],
        [14, 3, 0, 0, 0x180, names.len() as u32, 0, 0, 1, 0],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in header.iter().enumerate() {
            let offset = 0x200 + (index + 1) * 40 + field * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
    }
    let analyze = |bytes: &[u8]| {
        let mut import = import_elf(bytes).unwrap();
        import.cfg = cfg.clone();
        select_language(&mut import, &cfg).unwrap();
        import.functions.clear();
        import.xrefs.clear();
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        assert!(
            import.functions.is_empty(),
            "reference coverage must not manufacture functions"
        );
        import
            .xrefs
            .into_iter()
            .map(|xref| (xref.from, xref.to, xref.kind))
            .collect::<Vec<_>>()
    };
    let expected = vec![(0x1004, 0x3004, "READ".into())];
    assert_eq!(
        analyze(&bytes),
        expected,
        "follow the section-address code root, not unseeded disconnected bytes"
    );
    bytes[0x230..0x234].copy_from_slice(&2u32.to_be_bytes());
    assert!(
        analyze(&bytes).is_empty(),
        "non-executable linkage data is not code"
    );
    bytes[0x230..0x234].copy_from_slice(&6u32.to_be_bytes());
    bytes[0x228..0x22c].copy_from_slice(&24u32.to_be_bytes());
    assert_eq!(
        analyze(&bytes),
        expected,
        "section-address evidence is independent of its name"
    );
}

#[test]
fn an_undecodable_code_root_does_not_abort_reference_inference() {
    use crate::native_runtime::{ConsoleSession, find_console};
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.language_id = "x86:LE:64:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/x86/data/languages");
    if find_console(&cfg).is_err() {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    }
    let mut bytes = vec![
        // 0x1000: an ELF header start, exactly how a section root can land
        // on bytes that never decode as code.
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
        // 0x1008: mov rax,[rip+0x1ff1]; ret
        0x48, 0x8b, 0x05, 0xf1, 0x1f, 0x00, 0x00, 0xc3,
    ];
    bytes.resize(0x20, 0);
    let mut import = NativeImport {
        cfg: cfg.clone(),
        language: cfg.language_id.clone(),
        format: "elf32".into(),
        mappings: vec![
            Mapping {
                vaddr: 0x1000,
                size: 0x20,
                file_off: 0,
                flags: 6,
                bytes,
            },
            Mapping {
                vaddr: 0x3000,
                size: 8,
                file_off: 0,
                flags: 2,
                bytes: vec![0; 8],
            },
        ],
        reference_roots: vec![(0x1000, 0x1008), (0x1008, 0x1010)],
        ..Default::default()
    };
    let mut session = ConsoleSession::new(&cfg).unwrap();
    session.load_mapped(&import).unwrap();
    assert!(
        session
            .optional_references(0x1000, 0x1008, &import.mappings, true)
            .unwrap()
            .is_none(),
        "the console must refuse the undecodable root instead of answering"
    );
    infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
    assert_eq!(
        import
            .xrefs
            .iter()
            .map(|xref| (xref.from, xref.to, xref.kind.clone()))
            .collect::<Vec<_>>(),
        vec![(0x1008, 0x3000, "READ".into())],
        "the decodable root still contributes its reference"
    );
}

#[test]
fn data_string_sweep_decodes_utf8_and_utf16() {
    for (language, big_endian) in [
        ("x86:LE:64:default", false),
        ("PowerPC:BE:32:default", true),
    ] {
        let wide = |value: &str| {
            value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(|unit| {
                    if big_endian {
                        unit.to_be_bytes()
                    } else {
                        unit.to_le_bytes()
                    }
                })
                .collect::<Vec<_>>()
        };
        let mappings = [
            (0x3000, 2, b"word\0".to_vec()),
            (0x3100, 2, "café\0".as_bytes().to_vec()),
            (0x3200, 2, wide("wide text")),
            (0x3300, 2, wide("A😀BC")),
            (0x3400, 2, "猫猫猫\0".as_bytes().to_vec()),
            (0x3500, 2, wide("😀😀")),
            (0x1000, 6, b"CODE\0".to_vec()),
        ]
        .into_iter()
        .map(|(vaddr, flags, bytes)| Mapping {
            vaddr,
            size: bytes.len() as u64,
            file_off: 0,
            flags,
            bytes,
        })
        .collect();
        let import = NativeImport {
            language: language.into(),
            mappings,
            ..Default::default()
        };
        let mut strings: Vec<_> = strings::discover(&import)
            .into_iter()
            .map(|row| (row.address.offset, row.value))
            .collect();
        strings.sort_unstable();
        assert_eq!(
            strings,
            vec![
                (0x3000, "word".into()),
                (0x3100, "café".into()),
                (0x3200, "wide text".into()),
                (0x3300, "A😀BC".into()),
            ],
            "decode data strings in {language}; count characters, not encoded bytes or code units"
        );
    }
}

mod ppc_sda_tests {
    use super::super::{
        ElfSection, NativeFunction, NativeRegisterContext, sda_decode_points,
        seed_ppc_sda_registers,
    };

    fn section(name: &str, addr: u64, size: u64) -> ElfSection {
        ElfSection {
            name: name.into(),
            typ: 1,
            flags: 3,
            addr,
            off: 0x1000,
            size,
            link: 0,
            entry_size: 0,
        }
    }

    fn functions() -> Vec<NativeFunction> {
        vec![
            NativeFunction {
                entry: 0x10000,
                name: "f".into(),
                size: 0x40,
            },
            NativeFunction {
                entry: 0x10100,
                name: "g".into(),
                size: 0x40,
            },
        ]
    }

    fn seed(
        machine: u16,
        abs: &[(String, u64)],
        sections: &[ElfSection],
    ) -> Vec<NativeRegisterContext> {
        let mut out = Vec::new();
        seed_ppc_sda_registers(machine, abs, sections, &functions(), &mut out);
        out
    }

    fn values(seeds: &[NativeRegisterContext], register: &str) -> Vec<u64> {
        let mut out: Vec<u64> = seeds
            .iter()
            .filter(|seed| seed.register == register)
            .map(|seed| seed.value)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    #[test]
    fn abs_symbol_beats_section_convention() {
        // base.elf shape: `_SDA_BASE_` ABS 0x806b1880 beside a `.sdata`
        // that would conventionally give something else.
        let abs = vec![("_SDA_BASE_".to_string(), 0x806b1880)];
        let sections = vec![
            section(".sdata", 0x806a9880, 0xe1),
            section(".sbss", 0x806a9980, 0x2c4),
        ];
        let seeds = seed(20, &abs, &sections);
        assert_eq!(values(&seeds, "r13"), vec![0x806b1880]);
        assert_eq!(seeds.iter().filter(|s| s.register == "r13").count(), 2);
        assert!(seeds.iter().all(|s| s.end == s.start + 0x40));
    }

    #[test]
    fn block_fallback_takes_the_least_start() {
        let sections = vec![
            section(".sbss", 0x2000, 0x100),
            section(".sdata", 0x1000, 0x100),
        ];
        assert_eq!(values(&seed(20, &[], &sections), "r13"), vec![0x1000]);
    }

    #[test]
    fn wide_range_falls_back_to_aligned_midpoint() {
        // Past fifteen bits half the range no longer reaches both ends
        // from one base, mirroring `getBaseOffset`.
        let sections = vec![
            section(".sdata", 0x10000, 0x10),
            section(".sbss", 0x30000, 0x10),
        ];
        let seeds = seed(20, &[], &sections);
        let span = 0x30010u64 - 0x10000;
        assert_eq!(values(&seeds, "r13"), vec![0x10000 + ((span / 2) & !0x0f)]);
    }

    #[test]
    fn nothing_to_derive_seeds_nothing() {
        let sections = vec![section(".text", 0x10000, 0x1000)];
        assert!(seed(20, &[], &sections).is_empty());
    }

    #[test]
    fn other_machines_seed_nothing() {
        let abs = vec![("_SDA_BASE_".to_string(), 0x1234)];
        let sections = vec![section(".sdata", 0x1000, 0x100)];
        assert!(seed(3, &abs, &sections).is_empty());
    }

    #[test]
    fn abs_zero_falls_through_to_sections() {
        // The linker leaves `_SDA_BASE_` zeroed when nothing establishes
        // it; zero is not a base.
        let abs = vec![("_SDA_BASE_".to_string(), 0)];
        let sections = vec![section(".sdata", 0x1000, 0x100)];
        assert_eq!(values(&seed(20, &abs, &sections), "r13"), vec![0x1000]);
        assert!(seed(20, &abs, &[]).is_empty());
    }

    #[test]
    fn section_convention_is_32bit_only() {
        // On 64-bit `r2` is the TOC and `r13` the thread pointer: a
        // `.sdata` there must not seed either. Declared ABS symbols
        // still win (see sda2_needs_no_machine_gate).
        let sections = vec![
            section(".sdata", 0x1000, 0x100),
            section(".sdata2", 0x2000, 0x100),
        ];
        let seeds = seed(21, &[], &sections);
        assert!(values(&seeds, "r13").is_empty());
        assert!(values(&seeds, "r2").is_empty());
    }

    #[test]
    fn sda2_needs_no_machine_gate() {
        // Ghidra establishes `_SDA2_BASE_` without a width check; the
        // 64-bit loader reaches the same seeder.
        let abs = vec![("_SDA2_BASE_".to_string(), 0x806b1c60)];
        let seeds = seed(21, &abs, &[]);
        assert_eq!(values(&seeds, "r2"), vec![0x806b1c60]);
        assert!(values(&seeds, "r13").is_empty());
    }

    #[test]
    fn funnel_passes_sda_ranges_and_drops_console_only_ones() {
        // `t9`/PLT ranges stay console-side: as decode rows the spec
        // would reject them the way it rejects any register name.
        let ranges = vec![
            NativeRegisterContext {
                start: 0x10000,
                end: 0x10040,
                register: "r13".into(),
                value: 0x11000,
            },
            NativeRegisterContext {
                start: 0x10000,
                end: 0x10040,
                register: "t9".into(),
                value: 0x10000,
            },
        ];
        let functions: Vec<_> = [0xfffc, 0x10000, 0x10010, 0x1003c, 0x10040]
            .into_iter()
            .map(|entry| NativeFunction { entry, name: String::new(), size: 4 })
            .collect();
        assert_eq!(
            sda_decode_points(&ranges, &functions),
            vec![
                (0x10000, "r13".to_string(), 0x11000),
                (0x10010, "r13".to_string(), 0x11000),
                (0x1003c, "r13".to_string(), 0x11000),
            ]
        );
    }
}
