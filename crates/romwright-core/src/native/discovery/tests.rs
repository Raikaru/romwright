use super::*;
use crate::native::Mapping;
use crate::native_runtime::FlowResult;

fn result(address: u64, kind: FlowKind, target: Option<u64>, pure_jump: bool) -> FlowResult {
    FlowResult {
        terminal: kind == FlowKind::Return,
        conditional: kind == FlowKind::CBranch,
        return_op: kind == FlowKind::Return,
        delay_slots: Vec::new(),
        no_op: false,
        address,
        length: 2,
        fallthrough: matches!(
            kind,
            FlowKind::Call | FlowKind::CallInd | FlowKind::CBranch | FlowKind::Fallthrough
        )
        .then_some(address + 2),
        targets: target.into_iter().collect(),
        kind,
        pure_jump,
        mode: None, target_modes: Vec::new(),
    }
}

/// A MIPS decode: instructions are 4 bytes (`result`'s are 2).
fn word_result(address: u64, kind: FlowKind, target: Option<u64>, pure_jump: bool) -> FlowResult {
    let mut flow = result(address, kind, target, pure_jump);
    flow.length = 4;
    if flow.fallthrough.is_some() {
        flow.fallthrough = Some(address + 4);
    }
    flow
}

fn image() -> NativeImport {
    NativeImport {
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 0x2000,
            file_off: 0,
            flags: 4,
            // Not fill: a call into 16 equal zero or 0xff bytes is refused
            // (`opens_with_fill`), and these flows are the provider's.
            bytes: (0..0x2000u32).map(|i| (i % 251) as u8 | 1).collect(),
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            size: 1,
            name: "entry".into(),
        }],
        ..Default::default()
    }
}

fn landing(address: u64) -> FlowResult {
    let mut flow = result(address, FlowKind::Fallthrough, None, false);
    flow.length = 4;
    flow.fallthrough = Some(address + 4);
    flow.no_op = true;
    flow
}

#[test]
fn landing_prefix_preserves_entry_extent_and_records_the_tail_call() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 | 0x2000 => landing(a),
                0x1004 => result(a, FlowKind::Branch, Some(0x2000), true),
                0x2004 => result(a, FlowKind::Branch, Some(0x2100), true),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
    assert_eq!(
        imp.functions
            .iter()
            .map(|f| (f.entry, f.size))
            .collect::<Vec<_>>(),
        vec![(0x1000, 6), (0x2000, 6), (0x2100, 2)]
    );
    // The branch is not itself the function entry -- a no-op landing precedes
    // it -- so Ghidra's SharedReturnAnalysisCmd gives it a CALL_RETURN
    // override, and the reference to the target function is a call. The row
    // stays owned by the thunk pass that found the transfer.
    for (from, to) in [(0x1004, 0x2000), (0x2004, 0x2100)] {
        assert!(imp.xrefs.iter().any(|x| x.from == from
            && x.to == to
            && x.kind == "UNCONDITIONAL_CALL"
            && x.provenance == "native-import:thunk"));
    }
    assert!(!imp.xrefs.iter().any(|x| x.kind == "UNCONDITIONAL_JUMP"));
}

#[test]
fn landing_prefix_requires_exact_single_no_op_and_valid_jump() {
    for case in [
        "missing-evidence",
        "wrong-address",
        "zero-length",
        "noncontiguous",
        "multiple",
        "effects",
        "conditional",
        "self",
        "invalid-target",
        "truncated-jump",
        "weak",
    ] {
        let mut imp = image();
        if case == "weak" {
            imp.functions[0].entry = 0x1100;
            imp.pointer_candidates.push(0x1000);
        }
        if case == "truncated-jump" {
            imp.mappings[0].size = 5;
            imp.mappings[0].bytes.truncate(5);
            imp.mappings.push(Mapping {
                vaddr: 0x2000,
                size: 2,
                file_off: 0,
                flags: 4,
                bytes: vec![0; 2],
            });
        }
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .map(|&a| {
                    if a == 0x1000 {
                        let mut flow = landing(a);
                        if case == "missing-evidence" {
                            flow.no_op = false;
                        }
                        if case == "wrong-address" {
                            flow.address += 1;
                        }
                        if case == "zero-length" {
                            flow.length = 0;
                        }
                        if case == "noncontiguous" {
                            flow.fallthrough = Some(0x1008);
                        }
                        return flow;
                    }
                    if a == 0x1004 && case == "multiple" {
                        return landing(a);
                    }
                    if a == 0x1004 || a == 0x1008 {
                        return result(
                            a,
                            if case == "conditional" {
                                FlowKind::CBranch
                            } else {
                                FlowKind::Branch
                            },
                            Some(if case == "self" { 0x1000 } else { 0x2000 }),
                            case != "effects",
                        );
                    }
                    result(
                        a,
                        if a == 0x2000 && case == "invalid-target" {
                            FlowKind::Bad
                        } else {
                            FlowKind::Return
                        },
                        None,
                        false,
                    )
                })
                .collect()
        });
        assert!(!imp.functions.iter().any(|f| f.entry == 0x2000), "{case}");
        assert!(
            !imp.xrefs
                .iter()
                .any(|x| x.provenance == "native-import:thunk"),
            "{case}"
        );
    }
}

#[test]
fn landing_jump_chain_returning_to_source_body_is_demoted() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 => landing(a),
                0x1004 => result(a, FlowKind::Branch, Some(0x1100), true),
                0x1100 => result(a, FlowKind::Branch, Some(0x1200), true),
                0x1200 => result(a, FlowKind::Branch, Some(0x1006), true),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
    assert_eq!(
        imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
        vec![0x1000]
    );
    assert!(!imp
        .xrefs
        .iter()
        .any(|x| x.provenance == "native-import:thunk"));
}

#[test]
fn conditional_fallthrough_discovers_call_target() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| {
                let mut flow = match a {
                    0x1000 => result(a, FlowKind::CBranch, Some(0x1100), false),
                    0x1002 => result(a, FlowKind::Call, Some(0x2000), false),
                    _ => result(a, FlowKind::Return, None, false),
                };
                if a == 0x1000 || a == 0x1002 {
                    flow.fallthrough = Some(a + 2);
                }
                flow
            })
            .collect()
    });
    assert_eq!(
        imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
        vec![0x1000, 0x2000]
    );
    assert!(imp
        .xrefs
        .iter()
        .any(|x| x.from == 0x1002 && x.to == 0x2000 && x.kind == "UNCONDITIONAL_CALL"));
}

#[test]
fn candidate_entry_uses_flow_instead_of_opcode_prefix() {
    for (byte, kind) in [
        (0x90, FlowKind::Return),
        (0x01, FlowKind::Fallthrough),
        (0x01, FlowKind::Call),
    ] {
        let mut imp = image();
        imp.mappings[0].bytes.fill(byte);
        imp.functions.push(NativeFunction {
            entry: 0x2002,
            size: 2,
            name: "neighbor".into(),
        });
        imp.reloc_candidates.push(0x2000);
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .map(|&a| {
                    let mut flow = result(a, FlowKind::Return, None, false);
                    if a == 0x2000 && kind != FlowKind::Return {
                        flow.kind = kind.clone();
                        if kind == FlowKind::Call {
                            flow.targets.push(0x60);
                        }
                        flow.fallthrough = Some(0x2002);
                    }
                    flow
                })
                .collect()
        });
        let expected = if kind == FlowKind::Fallthrough {
            vec![0x1000, 0x2002]
        } else {
            vec![0x1000, 0x2000, 0x2002]
        };
        assert_eq!(
            imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn pure_entry_jump_preserves_thunk_and_destination() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 => result(a, FlowKind::Branch, Some(0x2000), true),
                0x2000 => result(a, FlowKind::Branch, Some(0x2100), true),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
    assert_eq!(
        imp.functions
            .iter()
            .map(|f| (f.entry, f.size))
            .collect::<Vec<_>>(),
        vec![(0x1000, 2), (0x2000, 2), (0x2100, 2)]
    );
    for (from, to) in [(0x1000, 0x2000), (0x2000, 0x2100)] {
        assert!(imp
            .xrefs
            .iter()
            .any(|x| x.from == from && x.to == to && x.kind == "UNCONDITIONAL_JUMP"));
        assert!(!imp
            .xrefs
            .iter()
            .any(|x| x.from == from && x.kind.contains("CALL")));
    }
}

#[test]
fn conditional_interior_and_effectful_branches_are_not_thunks() {
    for case in [
        "conditional",
        "interior",
        "effects",
        "self",
        "outside",
        "known-body",
    ] {
        let mut imp = image();
        if case == "known-body" {
            imp.functions.push(NativeFunction {
                entry: 0x1ff0,
                size: 0x40,
                name: "other".into(),
            });
        }
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .map(|&a| {
                    if a == 0x1000 && case == "interior" {
                        let mut flow = result(a, FlowKind::Fallthrough, None, false);
                        flow.fallthrough = Some(0x1002);
                        return flow;
                    }
                    if a == 0x1000 || (a == 0x1002 && case == "interior") {
                        return result(
                            a,
                            if case == "conditional" {
                                FlowKind::CBranch
                            } else {
                                FlowKind::Branch
                            },
                            Some(match case {
                                "self" => 0x1000,
                                "outside" => 0x4000,
                                _ => 0x2000,
                            }),
                            case != "effects",
                        );
                    }
                    result(a, FlowKind::Return, None, false)
                })
                .collect()
        });
        let expected = if case == "known-body" {
            vec![0x1000, 0x1ff0]
        } else {
            vec![0x1000]
        };
        assert_eq!(
            imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
            expected,
            "{case}"
        );
    }
}

#[test]
fn thunk_destination_requires_corresponding_valid_flow() {
    for case in [
        "missing",
        "bad",
        "unimplemented",
        "wrong-address",
        "zero-length",
    ] {
        let mut imp = image();
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .filter_map(|&a| {
                    if a == 0x1000 {
                        return Some(result(a, FlowKind::Branch, Some(0x2000), true));
                    }
                    if case == "missing" {
                        return None;
                    }
                    let mut flow = result(
                        a,
                        match case {
                            "bad" => FlowKind::Bad,
                            "unimplemented" => FlowKind::Unimpl,
                            _ => FlowKind::Return,
                        },
                        None,
                        false,
                    );
                    if case == "wrong-address" {
                        flow.address += 1;
                    }
                    if case == "zero-length" {
                        flow.length = 0;
                    }
                    Some(flow)
                })
                .collect()
        });
        assert!(!imp.functions.iter().any(|f| f.entry == 0x2000), "{case}");
    }
}

#[test]
fn weak_jump_seed_does_not_establish_a_second_function() {
    let mut imp = image();
    imp.pointer_candidates.push(0x1100);
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| {
                result(
                    a,
                    if a == 0x1100 {
                        FlowKind::Branch
                    } else {
                        FlowKind::Return
                    },
                    (a == 0x1100).then_some(0x2000),
                    a == 0x1100,
                )
            })
            .collect()
    });
    assert!(imp.functions.iter().any(|f| f.entry == 0x1100));
    assert!(!imp.functions.iter().any(|f| f.entry == 0x2000));
}

#[test]
fn later_body_flow_demotes_a_provisional_thunk_destination() {
    let mut imp = image();
    imp.functions.push(NativeFunction {
        entry: 0x1ff0,
        size: 1,
        name: "other".into(),
    });
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| {
                if a == 0x1000 {
                    return result(a, FlowKind::Branch, Some(0x2000), true);
                }
                if (0x1ff0..0x2000).contains(&a) {
                    let mut flow = result(a, FlowKind::Fallthrough, None, false);
                    flow.fallthrough = Some(a + 2);
                    return flow;
                }
                result(a, FlowKind::Return, None, false)
            })
            .collect()
    });
    assert!(!imp.functions.iter().any(|f| f.entry == 0x2000));
}

#[test]
fn entry_jump_chain_returning_to_own_body_is_not_a_thunk_chain() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 => result(a, FlowKind::Branch, Some(0x1100), true),
                0x1100 => result(a, FlowKind::Branch, Some(0x1200), true),
                0x1200 => result(a, FlowKind::Branch, Some(0x1002), true),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
    assert_eq!(
        imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
        vec![0x1000]
    );
}

#[test]
fn branch_target_requires_proven_linkage_and_imported_slot() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return;
    }
    cfg.language_id = "PowerPC:BE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/PowerPC/data/languages");
    for (bound, conditional, promoted, sweep) in [
        (true, false, true, false),
        (false, false, false, false),
        (true, true, false, false),
        (true, false, true, true),
        (false, false, false, true),
        (true, true, false, true),
    ] {
        let mut bytes = vec![0; 0x50];
        bytes[..4].copy_from_slice(&[0x38, 0x60, 0, 0]); // li r3,0: caller setup, not a pure-entry jump
        bytes[4..8].copy_from_slice(&if conditional {
            [0x40, 0x82, 0, 0x3c]
        } else {
            [0x48, 0, 0, 0x3c]
        });
        bytes[8..12].copy_from_slice(&[0x4e, 0x80, 0, 0x20]);
        bytes[0x40..].copy_from_slice(&[
            0x3d, 0x60, 0, 0, 0x81, 0x6b, 0x30, 0, 0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20,
        ]); // lis/lwz/mtctr/bctr through the imported slot at 0x3000
        let mut import = NativeImport {
            cfg: cfg.clone(),
            language: cfg.language_id.clone(),
            format: "elf32".into(),
            mappings: vec![
                Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                },
                Mapping {
                    vaddr: 0x3000,
                    size: 4,
                    file_off: 0,
                    flags: 2,
                    bytes: vec![0; 4],
                },
            ],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "_entry".into(),
                size: 1,
            }],
            externals: if bound {
                vec![(0x3000, "libc_entry".into())]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        if sweep {
            discover_mapped(&mut import).unwrap();
        } else {
            discover_seeded(&mut import);
        }
        let function = import
            .functions
            .iter()
            .find(|function| function.entry == 0x1040);
        assert_eq!(
            function.is_some(),
            promoted,
            "bound={bound}, conditional={conditional}, sweep={sweep}"
        );
        if let Some(function) = function {
            assert_eq!(function.name, "libc_entry");
            assert_eq!(function.size, 16);
            assert_eq!(
                import
                    .functions
                    .iter()
                    .find(|f| f.entry == 0x1000)
                    .unwrap()
                    .size,
                8,
                "a separate linkage entry must not remain in the caller's body"
            );
        }
    }
}

#[test]
fn pic_linkage_requires_proven_consistent_caller_context() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return;
    }
    cfg.language_id = "PowerPC:BE:32:default".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/PowerPC/data/languages");
    for (known, caller) in [
        (true, "none"),
        (false, "none"),
        (true, "strong"),
        (true, "weak"),
        (true, "bypass"),
    ] {
        let mut bytes = vec![0; 0x120];
        let setup = [
            0x90, 0x01, 0, 0, // stw r0,0(r1): caller effects are not thunk effects
            0x42, 0x9f, 0, 5, // bcl to the next instruction, capturing PC
            0x7f, 0xc8, 2, 0xa6, // mflr r30
            0x3b, 0xde, 0x1f, 0xf8, // addi r30,r30,8184: r30 = 0x3000
            0x48, 0, 0, 0x30, // b 0x1040
        ];
        bytes[..setup.len()].copy_from_slice(&setup);
        if !known {
            bytes[8..12].copy_from_slice(&[0x7c, 0x7e, 0x1b, 0x78]); // mr r30,r3
        }
        bytes[0x40..0x4c].copy_from_slice(&[
            0x81, 0x7e, 0, 0x48, 0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20,
        ]); // lwz r11,72(r30); mtctr r11; bctr
        let mut functions = vec![NativeFunction {
            entry: 0x1000,
            name: "_entry".into(),
            size: 1,
        }];
        if caller != "none" {
            bytes[0x100..0x114].copy_from_slice(&setup);
            bytes[0x10c..0x110].copy_from_slice(&[0x3b, 0xde, 0x3e, 0xf8]); // r30 = 0x5000
            bytes[0x110..0x114].copy_from_slice(&[0x4b, 0xff, 0xff, 0x30]); // b 0x1040
            if caller == "bypass" {
                bytes[0x100..0x108].copy_from_slice(&[
                    0x7c, 0x7e, 0x1b, 0x78, // unknown r30
                    0x4b, 0xff, 0xff,
                    0x08, // enter the first caller at 0x100c, skipping its PC setup
                ]);
            }
            if caller != "weak" {
                functions.push(NativeFunction {
                    entry: 0x1100,
                    name: "other".into(),
                    size: 1,
                });
            }
        }
        let mut import = NativeImport {
            cfg: cfg.clone(),
            language: cfg.language_id.clone(),
            format: "elf32".into(),
            mappings: vec![
                Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                },
                Mapping {
                    vaddr: 0x3000,
                    size: 0x100,
                    file_off: 0,
                    flags: 2,
                    bytes: vec![0; 0x100],
                },
                Mapping {
                    vaddr: 0x5000,
                    size: 0x100,
                    file_off: 0,
                    flags: 2,
                    bytes: vec![0; 0x100],
                },
            ],
            functions,
            pointer_candidates: if caller == "weak" {
                vec![0x1100]
            } else {
                Vec::new()
            },
            externals: vec![
                (0x3048, "libc_entry".into()),
                (0x5048, "different_entry".into()),
            ],
            ..Default::default()
        };
        discover_seeded(&mut import);
        let function = import
            .functions
            .iter()
            .find(|function| function.entry == 0x1040);
        assert_eq!(
            function.is_some(),
            known && caller == "none",
            "known={known}, caller={caller}"
        );
        if let Some(function) = function {
            assert_eq!(function.name, "libc_entry");
            assert_eq!(function.size, 12);
        }
    }
}

#[test]
fn pattern_entries_require_defined_boundaries_and_valid_code() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return;
    }
    cfg.language_id = "AARCH64:LE:64:v8A".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/AARCH64/data/languages");
    const RET: u32 = 0xd65f03c0;
    const NOP: u32 = 0xd503201f;
    const STP: u32 = 0xa9be7bfd;
    const MOV: u32 = 0x910003fd;
    // RET x19 is terminal but is not one of the unconstrained prepatterns.
    const RET_OTHER: u32 = 0xd65f0260;
    let cases: &[(&str, &[u32], &[u64], &[(u64, u64)])] = &[
        // Validation may cross existing instructions; ownership may not.
        (
            "adjacent entry",
            &[RET, NOP, STP, MOV, RET],
            &[0x1000, 0x1008],
            &[(0x1000, 4), (0x1004, 4), (0x1008, 12)],
        ),
        (
            "owned prefix",
            &[NOP, NOP, STP, MOV, RET],
            &[0x1000, 0x1008],
            &[(0x1000, 8), (0x1008, 12)],
        ),
        (
            "three valid instructions",
            &[RET_OTHER, STP, MOV, RET],
            &[0x1000],
            &[(0x1000, 4), (0x1004, 12)],
        ),
        (
            "early return",
            &[RET_OTHER, STP, RET, NOP],
            &[0x1000],
            &[(0x1000, 4)],
        ),
        (
            "invalid instruction",
            &[RET_OTHER, STP, 0, NOP],
            &[0x1000],
            &[(0x1000, 4)],
        ),
        // Bytes matching RET are not an already-defined predecessor instruction.
        (
            "undefined predecessor",
            &[RET_OTHER, RET_OTHER, STP, MOV, RET],
            &[0x1000],
            &[(0x1000, 4)],
        ),
    ];
    for &(case, words, entries, expected) in cases {
        let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let mut import = NativeImport {
            cfg: cfg.clone(),
            language: cfg.language_id.clone(),
            format: "ELF".into(),
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: bytes.len() as u64,
                file_off: 0,
                flags: 6,
                bytes,
            }],
            functions: entries
                .iter()
                .map(|&entry| NativeFunction {
                    entry,
                    size: 1,
                    name: format!("seed_{entry:x}"),
                })
                .collect(),
            ..Default::default()
        };
        discover_seeded(&mut import);
        let actual: Vec<_> = import.functions.iter().map(|f| (f.entry, f.size)).collect();
        assert_eq!(actual, expected, "{case}");
    }
}

#[test]
fn conditional_return_preserves_its_nonreturning_path() {
    let mut import = image();
    flow_discover_with_provider(&mut import, |addresses| {
        addresses
            .iter()
            .map(|&address| {
                let mut flow = result(address, FlowKind::Return, None, false);
                if address == 0x1000 {
                    flow.conditional = true;
                    flow.fallthrough = Some(0x1002);
                } else if address == 0x1002 {
                    flow = result(address, FlowKind::Call, Some(0x2000), false);
                    flow.fallthrough = Some(0x1004);
                }
                flow
            })
            .collect()
    });
    assert!(import
        .functions
        .iter()
        .any(|function| function.entry == 0x2000));
    assert!(import
        .xrefs
        .iter()
        .any(|xref| xref.from == 0x1002 && xref.to == 0x2000 && xref.kind == "UNCONDITIONAL_CALL"));
}

#[test]
fn terminal_call_does_not_invent_fallthrough() {
    let mut import = image();
    flow_discover_with_provider(&mut import, |addresses| {
        addresses
            .iter()
            .map(|&address| {
                if address == 0x1000 {
                    let mut flow = result(address, FlowKind::Call, Some(0x2000), false);
                    flow.terminal = true;
                    flow.return_op = true;
                    flow.fallthrough = None;
                    flow
                } else if address == 0x1002 {
                    result(address, FlowKind::Call, Some(0x2100), false)
                } else {
                    result(address, FlowKind::Return, None, false)
                }
            })
            .collect()
    });
    assert_eq!(
        import
            .functions
            .iter()
            .map(|function| function.entry)
            .collect::<Vec<_>>(),
        [0x1000, 0x2000]
    );
}

#[test]
fn possible_pattern_entry_rejects_later_conditional_reference() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return;
    }
    cfg.language_id = "AARCH64:LE:64:v8A".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/AARCH64/data/languages");
    // RET x19; STP; MOV; RET; CBZ x0,0x1004; RET. The relocation-rooted
    // conditional branch is discovered after pattern prerequisites are checked.
    let words = [
        0xd65f0260u32,
        0xa9be7bfd,
        0x910003fd,
        0xd65f03c0,
        0xb4ffffa0,
        0xd65f03c0,
    ];
    let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut import = NativeImport {
        language: cfg.language_id.clone(),
        cfg,
        format: "ELF".into(),
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: bytes.len() as u64,
            file_off: 0,
            flags: 6,
            bytes,
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            size: 1,
            name: "seed".into(),
        }],
        reloc_candidates: vec![0x1010],
        ..Default::default()
    };
    discover_seeded(&mut import);
    assert_eq!(
        import
            .functions
            .iter()
            .map(|function| function.entry)
            .collect::<Vec<_>>(),
        [0x1000, 0x1010]
    );
    // The refused match is no pattern start: the store's const rule reads
    // that record as evidence of a function.
    assert!(!import.pattern_starts.contains(&0x1004), "{:?}", import.pattern_starts);
}

#[test]
fn possible_pattern_batch_waits_for_its_own_disassembly() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return;
    }
    cfg.language_id = "AARCH64:LE:64:v8A".into();
    cfg.language_dir = cfg
        .ghidra_install
        .join("Ghidra/Processors/AARCH64/data/languages");
    // Both candidates pass after=defined and validcode=3 before either is
    // disassembled. The first subsequently exposes a conditional reference to
    // the second, which must remain code rather than become a separate function.
    let words = [
        0xd65f0260u32,
        0xa9be7bfd,
        0x910003fd,
        0xb4000060,
        0xd65f03c0,
        0xd65f0260,
        0xa9be7bfd,
        0x910003fd,
        0xd65f03c0,
    ];
    let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut import = NativeImport {
        language: cfg.language_id.clone(),
        cfg,
        format: "ELF".into(),
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: bytes.len() as u64,
            file_off: 0,
            flags: 6,
            bytes,
        }],
        functions: [0x1000, 0x1014]
            .into_iter()
            .map(|entry| NativeFunction {
                entry,
                size: 1,
                name: format!("seed_{entry:x}"),
            })
            .collect(),
        ..Default::default()
    };
    discover_seeded(&mut import);
    assert_eq!(
        import
            .functions
            .iter()
            .map(|function| function.entry)
            .collect::<Vec<_>>(),
        [0x1000, 0x1004, 0x1014]
    );
}

/// m5-007: the flag decides whether a proven tail-call target is promoted.
/// Every other rule below is about the evidence, not the flag.
///
/// The seeded function sits above its tail-call target, because a target
/// *after* the branch is ordinary forward flow: the walk proves it part of
/// the same body, and no transfer leaves the function at all.
fn tailcall_image(promote: bool) -> NativeImport {
    let mut imp = image();
    imp.cfg.promote_tailcalls = promote;
    imp.functions = vec![NativeFunction {
        entry: 0x1100,
        size: 1,
        name: "entry".into(),
    }];
    imp
}

#[test]
fn a_proven_tail_call_target_is_promoted_only_when_asked() {
    // 0x1100 falls through to a branch that leaves it for 0x1000, which
    // nothing else reaches; 0x1000 falls through once and returns.
    let flow = |addresses: &[u64]| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1100 => result(a, FlowKind::Fallthrough, None, false),
                0x1102 => result(a, FlowKind::Branch, Some(0x1000), true),
                0x1000 => result(a, FlowKind::Fallthrough, None, false),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    };

    let mut off = tailcall_image(false);
    flow_discover_with_provider(&mut off, flow);
    assert_eq!(
        off.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
        vec![0x1100],
        "the target must not become a function unless the pass is enabled"
    );
    assert!(off
        .xrefs
        .iter()
        .any(|x| (x.from, x.to) == (0x1102, 0x1000) && x.kind == "UNCONDITIONAL_JUMP"));

    let mut on = tailcall_image(true);
    flow_discover_with_provider(&mut on, flow);
    assert_eq!(
        on.functions
            .iter()
            .map(|f| (f.entry, f.size))
            .collect::<Vec<_>>(),
        vec![(0x1000, 4), (0x1100, 4)],
        "the promoted entry carries the extent its own flow proved"
    );
    // The target is a function now, so Ghidra's CALL_RETURN rule applies.
    assert!(on
        .xrefs
        .iter()
        .any(|x| (x.from, x.to) == (0x1102, 0x1000) && x.kind == "UNCONDITIONAL_CALL"));
}

#[test]
fn promotion_refuses_targets_without_their_own_evidence() {
    for case in ["undecodable", "runs-into-another-entry", "inside-a-proven-body"] {
        let interior = case == "inside-a-proven-body";
        let target = if interior { 0x1004 } else { 0x1000 };
        let mut imp = tailcall_image(true);
        if interior {
            // A seeded function whose own flow proves a body over the target:
            // the code there belongs to it, reached without a prologue.
            imp.functions.push(NativeFunction {
                entry: 0x1000,
                size: 1,
                name: "owner".into(),
            });
        }
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .map(|&a| match a {
                    // The branch sits deep enough in the seeded function that
                    // the owner's body is proved before the transfer is seen.
                    0x1108 => result(a, FlowKind::Branch, Some(target), true),
                    // A call establishes 0x1004 as a function of its own, so
                    // the walk from 0x1000 runs into code that is owned.
                    0x1102 if case == "runs-into-another-entry" => {
                        result(a, FlowKind::Call, Some(0x1004), false)
                    }
                    0x1100..=0x1106 => result(a, FlowKind::Fallthrough, None, false),
                    0x1000 if case == "undecodable" => result(a, FlowKind::Bad, None, false),
                    0x1000 | 0x1002 | 0x1004 => {
                        result(a, FlowKind::Fallthrough, None, false)
                    }
                    _ => result(a, FlowKind::Return, None, false),
                })
                .collect()
        });
        let promoted = imp.functions.iter().any(|f| f.entry == target);
        assert!(
            !promoted,
            "{case}: {target:#x} was promoted without its own evidence; \
             functions {:?}",
            imp.functions
                .iter()
                .map(|f| (f.entry, f.size))
                .collect::<Vec<_>>()
        );
    }
}

/// m5-008: a function that computes and then leaves through an unconditional
/// branch is a tail call, not a thunk.
///
/// Ghidra's rule, read in the pinned sources: `getThunkedAddr` walks from the
/// entry and `getFlowingAddrFromFinalState`
/// (`CreateThunkFunctionCmd.java:763-828`) returns a thunked address only when
/// every register the body set is later used or hidden -- a body that leaves
/// its result in a register for the callee fails that test. The ARM7 fixture
/// in `tests/m5-002_nds.py` is exactly that shape, and stock Ghidra records no
/// thunk for it.
#[test]
fn a_computing_tail_call_is_not_a_thunk() {
    for promote in [false, true] {
        let mut imp = tailcall_image(promote);
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .map(|&a| match a {
                    // Two instructions of work, then the transfer out.
                    0x1100 | 0x1102 => result(a, FlowKind::Fallthrough, None, false),
                    0x1104 => result(a, FlowKind::Branch, Some(0x1000), true),
                    0x1000 => result(a, FlowKind::Fallthrough, None, false),
                    _ => result(a, FlowKind::Return, None, false),
                })
                .collect()
        });
        assert!(
            imp.thunks.is_empty(),
            "promote={promote}: recorded {:?} as a thunk; only an entry that does \
             nothing but transfer is one",
            imp.thunks
                .iter()
                .map(|thunk| (thunk.entry, thunk.destination))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn overlapping_relocation_candidates_are_case_labels_not_functions() {
    // A PE32 switch table proposes one candidate per case. The cases' chains
    // interleave through the switch's shared tail, so one case's flow-proven
    // span runs past the next case's start; the function beside them owns a
    // span that abuts nothing.
    let mut imp = image();
    imp.reloc_candidates = vec![0x1100, 0x1200, 0x1210];
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 | 0x1100 => result(a, FlowKind::Return, None, false),
                // First case: falls through, then jumps to the far tail.
                0x1200 => result(a, FlowKind::Fallthrough, None, false),
                0x1202 => result(a, FlowKind::Branch, Some(0x1240), true),
                // Second case: falls through, then jumps to the near tail.
                0x1210 => result(a, FlowKind::Fallthrough, None, false),
                0x1212 => result(a, FlowKind::Branch, Some(0x1230), true),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
    assert_eq!(
        imp.functions
            .iter()
            .map(|function| function.entry)
            .collect::<Vec<_>>(),
        [0x1000, 0x1100],
        "candidates whose proven spans overlap must not become functions"
    );
}

#[test]
fn the_plt_header_override_needs_a_branch_that_transfers() {
    // A function that merely *reads* the resolver slot is not a PLT header:
    // `powerpc_many_o2`'s `.plt` is two words long, so the address the third
    // reserved word would occupy is a `.bss` guard byte that `_FINI_0` loads
    // and stores. An override on that load truncated the whole function to
    // `halt_baddata()` (m4-022).
    let mut imp = image();
    imp.plt_resolver_slot = Some(0x5170);
    imp.functions = vec![NativeFunction { entry: 0x1000, size: 0x40, name: "_FINI_0".into() }];
    imp.xrefs = vec![
        crate::native::NativeXref::new(0x100c, 0x5170, "READ"),
        crate::native::NativeXref::new(0x102c, 0x5170, "WRITE"),
    ];
    record_plt_header_flow(&mut imp);
    assert!(
        imp.flow_overrides.is_empty(),
        "a load is not a transfer: {:?}",
        imp.flow_overrides
    );

    // The same read inside a function that does branch indirectly is the PLT
    // header, and the override belongs on that branch.
    imp.indirect_transfers = vec![0x1018];
    record_plt_header_flow(&mut imp);
    assert_eq!(
        imp.flow_overrides,
        vec![(0x1018, crate::native::PLT_HEADER_SOURCE)],
        "the override belongs on the branch the flow walk proved"
    );
}

/// `pop {..rX..}; bx rX` is Thumb's old return idiom: not a switch
/// candidate. A `bx` through a register the pop did not load, or with no
/// pop before it, still is.
#[test]
fn thumb_pop_then_bx_is_a_return_not_a_computed_jump() {
    let mut imp = image();
    let bytes = &mut imp.mappings[0].bytes;
    // 0x1000: pop {r0, r4}; bx r0
    bytes[0..2].copy_from_slice(&0xbc11u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&0x4700u16.to_le_bytes());
    // 0x1010: pop {r0}; bx r3
    bytes[0x10..0x12].copy_from_slice(&0xbc01u16.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&0x4718u16.to_le_bytes());
    // 0x1020: mov r0, r1; bx r0
    bytes[0x20..0x22].copy_from_slice(&0x1c08u16.to_le_bytes());
    bytes[0x22..0x24].copy_from_slice(&0x4700u16.to_le_bytes());
    assert!(thumb_pop_return(&imp, 0x1002));
    assert!(!thumb_pop_return(&imp, 0x1012));
    assert!(!thumb_pop_return(&imp, 0x1022));
}

/// A mapped image of pseudo-random words under `language`, swept and walked
/// by `discover_mapped`: the seed scan decodes every instruction the bytes
/// hold, so a sweep exercises far more encodings than real code would.
/// Returns the instructions decoded, or `None` without a Ghidra install.
fn random_sweep(
    language: &str,
    big_endian: bool,
    contexts: Vec<crate::native::NativeContext>,
) -> Option<u64> {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return None;
    }
    cfg.adopt_language(language);
    cfg.switch_decompiler = false;
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ language.len() as u64;
    let mut bytes = Vec::with_capacity(0x8000);
    while bytes.len() < 0x8000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let word = state as u32;
        bytes.extend_from_slice(&if big_endian { word.to_be_bytes() } else { word.to_le_bytes() });
    }
    let mut import = NativeImport {
        language: language.into(),
        mappings: vec![Mapping { vaddr: 0x10000, size: bytes.len() as u64, file_off: 0, flags: 5, bytes }],
        functions: vec![NativeFunction { entry: 0x10000, size: 1, name: "entry".into() }],
        contexts,
        cfg,
        ..Default::default()
    };
    discover_mapped(&mut import).expect("sweep");
    Some(import.xrefs.len() as u64)
}

/// The decoders sweep random ARM (with a Thumb half), MIPS, PowerPC and x86
/// words without failing the walk. PowerPC's random `lmw`/`stmw` walk
/// deeper than 32 constructors, which the decoders bound at Ghidra's 64.
#[test]
fn flow_decoders_sweep_random_words() {
    let thumb = vec![crate::native::NativeContext { name: "TMode".into(), address: 0x14000, value: 1 }];
    for (language, big_endian, contexts) in [
        ("ARM:LE:32:v5t", false, thumb.clone()),
        ("ARM:LE:32:v8", false, thumb),
        ("MIPS:BE:32:default", true, Vec::new()),
        ("MIPS:LE:32:default", false, Vec::new()),
        ("PowerPC:BE:32:default", true, Vec::new()),
        ("x86:LE:32:default", false, Vec::new()),
        ("x86:LE:64:default", false, Vec::new()),
    ] {
        if random_sweep(language, big_endian, contexts).is_none() {
            return;
        }
    }
}

/// The test image, zeroed.
fn zeroed() -> NativeImport {
    let mut imp = image();
    imp.mappings[0].bytes.fill(0);
    imp
}

/// The walk over a test image: every address falls through, except `call`
/// (an indirect call that falls through) and a return at 0x1100.
fn zero_fill_body(imp: &mut NativeImport, call: Option<u64>) -> u64 {
    flow_discover_with_provider(imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1100 => result(a, FlowKind::Return, None, false),
                _ if Some(a) == call => result(a, FlowKind::CallInd, None, false),
                _ => result(a, FlowKind::Fallthrough, None, false),
            })
            .collect()
    });
    imp.functions.iter().find(|f| f.entry == 0x1000).expect("entry").size
}

#[test]
fn a_run_of_repeated_byte_instructions_stops_after_sixteen() {
    // Ghidra's disassembler refuses the seventeenth zero instruction in a
    // row (`RepeatInstructionByteTracker`, limit 16).
    assert_eq!(zero_fill_body(&mut zeroed(), None), 16 * 2);
}

#[test]
fn a_call_or_a_differing_instruction_restarts_the_run() {
    // A call ends its block, so the count starts again after it: nine
    // instructions up to and including the call, then sixteen more.
    assert_eq!(zero_fill_body(&mut zeroed(), Some(0x1010)), (9 + 16) * 2);
    // An instruction whose bytes differ breaks the run the same way.
    let mut imp = zeroed();
    imp.mappings[0].bytes[0x10] = 1;
    assert_eq!(zero_fill_body(&mut imp, None), (9 + 16) * 2);
}

fn thumb1_image(halves: &[u16]) -> NativeImport {
    let mut bytes: Vec<u8> = halves.iter().flat_map(|half| half.to_le_bytes()).collect();
    bytes.resize(0x100, 0);
    NativeImport {
        mappings: vec![Mapping { vaddr: 0x1000, size: 0x100, file_off: 0, flags: 4, bytes }],
        language: "ARM:LE:32:v4t".into(),
        ..Default::default()
    }
}

#[test]
fn thumb1_straight_line_code_decodes_to_its_terminator() {
    // push {lr}; movs r0, #0; bl (both halves); pop {pc}
    assert!(thumb1_fallthrough_decodes(&thumb1_image(&[0xb500, 0x2000, 0xf000, 0xf810, 0xbd00]), 0x1000));
    // A switch dispatch writes pc: `mov pc, r0`.
    assert!(thumb1_fallthrough_decodes(&thumb1_image(&[0x0080, 0x4687]), 0x1000));
    // A `bl` suffix with no prefix before the terminator.
    assert!(!thumb1_fallthrough_decodes(&thumb1_image(&[0x2000, 0xf800, 0x4770]), 0x1000));
    // A prefix whose next halfword is no suffix.
    assert!(!thumb1_fallthrough_decodes(&thumb1_image(&[0xf000, 0x2000, 0x4770]), 0x1000));
    // `udf`, and a `blx` suffix on ARMv4T, which has no `blx`.
    assert!(!thumb1_fallthrough_decodes(&thumb1_image(&[0xde00, 0x4770]), 0x1000));
    assert!(!thumb1_fallthrough_decodes(&thumb1_image(&[0xf000, 0xe800, 0x4770]), 0x1000));
    let mut v5t = thumb1_image(&[0xf000, 0xe800, 0x4770]);
    v5t.language = "ARM:LE:32:v5t".into();
    assert!(thumb1_fallthrough_decodes(&v5t, 0x1000));
}

#[test]
fn sixteen_equal_bytes_are_fill() {
    let mut imp = thumb1_image(&[0xb500, 0x4770]);
    assert!(!opens_with_fill(&imp, 0x1000));
    assert!(opens_with_fill(&imp, 0x1010));
    imp.mappings[0].bytes[0x18] = 0xff;
    assert!(!opens_with_fill(&imp, 0x1010));
}

#[test]
fn a_thumb1_entry_whose_code_does_not_decode_is_no_function() {
    let mut halves = vec![0u16; 0x80];
    // 0x1000: push {lr}; pop {pc}. 0x1040: movs r0, #0; a lone `bl` suffix.
    halves[0] = 0xb500;
    halves[1] = 0xbd00;
    halves[0x20] = 0x2000;
    halves[0x21] = 0xf800;
    let mut imp = thumb1_image(&halves);
    imp.functions = [(0x1000, "code"), (0x1040, "data")]
        .into_iter()
        .map(|(entry, name)| NativeFunction { entry, size: 1, name: name.into() })
        .collect();
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| {
                let kind = if a == 0x1002 { FlowKind::Return } else { FlowKind::Fallthrough };
                let mut flow = result(a, kind, None, false);
                flow.mode = Some(1);
                flow
            })
            .collect()
    });
    assert_eq!(imp.functions.iter().map(|f| (f.entry, f.size)).collect::<Vec<_>>(), vec![(0x1000, 4)]);
}

#[test]
fn a_thumb_entry_that_gives_back_a_frame_is_no_function() {
    // `add sp, #8` and `pop {r0}` close a frame nothing here opened.
    assert!(tears_down_frame(&thumb1_image(&[0xb002, 0xbc08, 0x4700]), 0x1000));
    assert!(tears_down_frame(&thumb1_image(&[0xbc01, 0x4700]), 0x1000));
    // `push {lr}` and `sub sp, #8` open one; `bx lr` is a leaf.
    assert!(!tears_down_frame(&thumb1_image(&[0xb500, 0xbd00]), 0x1000));
    assert!(!tears_down_frame(&thumb1_image(&[0xb082, 0xbd00]), 0x1000));
    assert!(!tears_down_frame(&thumb1_image(&[0x4770]), 0x1000));
}

#[test]
fn an_odd_word_declares_a_thumb_entry() {
    let mut bytes = vec![0u8; 0x40];
    bytes[0x00..0x04].copy_from_slice(&0x0000_1021u32.to_le_bytes()); // odd: Thumb entry 0x1020
    bytes[0x04..0x08].copy_from_slice(&0x0000_1030u32.to_le_bytes()); // even: data
    bytes[0x0a..0x0e].copy_from_slice(&0x0000_1041u32.to_le_bytes()); // unaligned
    bytes[0x10..0x14].copy_from_slice(&0x0000_9001u32.to_le_bytes()); // odd, outside code
    let imp = NativeImport {
        language: "ARM:LE:32:v7".into(),
        mappings: vec![Mapping { vaddr: 0x1000, size: 0x40, file_off: 0, flags: 5, bytes }],
        ..Default::default()
    };
    let declared = patterns::thumb_declared_targets(&imp);
    assert_eq!(declared.into_iter().collect::<Vec<_>>(), vec![0x1020]);
}

fn seeded(entries: &[u64]) -> NativeImport {
    let mut imp = image();
    imp.functions.extend(entries.iter().map(|&entry| NativeFunction {
        entry,
        size: 1,
        name: format!("FUN_{entry:08x}"),
    }));
    imp
}

#[test]
fn an_entry_another_function_falls_into_is_its_code() {
    let mut imp = seeded(&[0x1008]);
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| result(a, if a == 0x100c { FlowKind::Return } else { FlowKind::Fallthrough }, None, false))
            .collect()
    });
    assert_eq!(imp.functions.iter().map(|f| (f.entry, f.size)).collect::<Vec<_>>(), vec![(0x1000, 0xe)]);
}

#[test]
fn a_called_entry_stays_a_function_where_code_falls_into_it() {
    let mut imp = seeded(&[0x1008]);
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 => result(a, FlowKind::Call, Some(0x1008), false),
                0x100c => result(a, FlowKind::Return, None, false),
                _ => result(a, FlowKind::Fallthrough, None, false),
            })
            .collect()
    });
    assert_eq!(imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(), vec![0x1000, 0x1008]);
}

fn thumb_label_image(first: u16) -> NativeImport {
    // 0x1000: a call to 0x1020 and a return. 0x1020: `first`, `pop {r4, pc}`.
    let mut halves = vec![0u16; 0x40];
    halves[0x10] = first;
    halves[0x11] = 0xbd10;
    let mut imp = thumb1_image(&halves);
    imp.functions = [0x1000, 0x1020]
        .into_iter()
        .map(|entry| NativeFunction { entry, size: 1, name: format!("FUN_{entry:08x}") })
        .collect();
    imp
}

fn thumb_label_functions(first: u16) -> Vec<u64> {
    let mut imp = thumb_label_image(first);
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| {
                let mut flow = match a {
                    0x1000 => result(a, FlowKind::Call, Some(0x1020), false),
                    0x1002 | 0x1022 => result(a, FlowKind::Return, None, false),
                    _ => result(a, FlowKind::Fallthrough, None, false),
                };
                flow.mode = Some(1);
                flow
            })
            .collect()
    });
    imp.functions.iter().map(|f| f.entry).collect()
}

#[test]
fn a_thumb_label_only_the_function_above_calls_and_that_releases_its_frame_is_that_functions_code() {
    // agbcc spells a long jump `bl`: the label opens with `movs`, pops what
    // it never pushed, and only the function above calls it.
    assert_eq!(thumb_label_functions(0x2000), vec![0x1000]);
    // A `push {lr}` opener builds its own frame: a function.
    assert_eq!(thumb_label_functions(0xb500), vec![0x1000, 0x1020]);
}

#[test]
fn a_mips_entry_that_continues_the_code_above_is_none() {
    let mut imp = seeded(&[0x1010, 0x1020]);
    imp.language = "MIPS:LE:32:default".into();
    // 0x1008 and 0x100c: `addiu v0, zero, 1`, so 0x1010 continues them.
    for at in [0x08, 0x0c] {
        imp.mappings[0].bytes[at..at + 4].copy_from_slice(&0x2402_0001u32.to_le_bytes());
    }
    // 0x1018: `jr ra`, its delay slot at 0x101c: 0x1020 follows a return.
    imp.mappings[0].bytes[0x18..0x1c].copy_from_slice(&0x03e0_0008u32.to_le_bytes());
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses.iter().map(|&a| word_result(a, FlowKind::Return, None, false)).collect()
    });
    assert_eq!(imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(), vec![0x1000, 0x1020]);
}

/// Two ARM dispatches in a row: `r0` picks case 0 or 1, and case 0 is itself
/// `cmp r1,#1; addls pc,pc,r1,lsl #2`. Recovering the first table puts a
/// dispatch with no table yet among its new cases, which value-set analysis
/// hands to the decompiler pass -- but only when that pass runs. With
/// `ROMWRIGHT_NO_SWITCH_DECOMPILER` nothing follows, and the deferred table
/// used to be dropped, so both dispatches stayed unresolved (libc: 82 of
/// the interpreter tier's 134 dispatches).
fn nested_dispatch_import(decompiler: bool) -> Option<NativeImport> {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.adopt_language("ARM:LE:32:v5t");
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return None;
    }
    cfg.switch_decompiler = decompiler;
    let words: [(u64, u32); 17] = [
        (0x1000, 0xe350_0001), // cmp r0,#1
        (0x1004, 0x908f_f100), // addls pc,pc,r0,lsl #2
        (0x1008, 0xe12f_ff1e), // bx lr (default)
        (0x100c, 0xea00_0002), // b 0x101c (case 0)
        (0x1010, 0xea00_0008), // b 0x1038 (case 1)
        (0x1014, 0xe12f_ff1e),
        (0x1018, 0xe12f_ff1e),
        (0x101c, 0xe351_0001), // cmp r1,#1
        (0x1020, 0x908f_f101), // addls pc,pc,r1,lsl #2
        (0x1024, 0xe12f_ff1e), // bx lr (default)
        (0x1028, 0xea00_0000), // b 0x1030
        (0x102c, 0xea00_0000), // b 0x1034
        (0x1030, 0xe12f_ff1e),
        (0x1034, 0xe12f_ff1e),
        (0x1038, 0xe12f_ff1e),
        (0x103c, 0xe12f_ff1e),
        (0x1040, 0xe12f_ff1e),
    ];
    let mut bytes = vec![0u8; 0x44];
    for (address, word) in words {
        let at = (address - 0x1000) as usize;
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    let mut imp = NativeImport {
        language: "ARM:LE:32:v5t".into(),
        compiler: Some("default".into()),
        format: "elf32".into(),
        cfg,
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: bytes.len() as u64,
            file_off: 0,
            flags: 5,
            bytes,
        }],
        functions: vec![NativeFunction {
            entry: 0x1000,
            name: "dispatch".into(),
            size: 0x44,
        }],
        ..Default::default()
    };
    crate::native::discover(&mut imp).expect("discovery runs");
    Some(imp)
}

#[test]
fn nested_dispatches_are_both_recovered_when_no_decompiler_follows() {
    let Some(imp) = nested_dispatch_import(false) else {
        return;
    };
    assert_eq!(imp.switch_tables.get(&0x1004), Some(&vec![0x100c, 0x1010]));
    assert_eq!(imp.switch_tables.get(&0x1020), Some(&vec![0x1028, 0x102c]));
}

#[test]
fn a_table_leading_to_an_unanswered_dispatch_is_left_to_a_following_decompiler() {
    let Some(imp) = nested_dispatch_import(true) else {
        return;
    };
    assert!(
        !imp.switch_tables.contains_key(&0x1004),
        "the decompiler path answers a dispatch whose new cases hold another one: {:?}",
        imp.switch_tables
    );
}

/// Four functions the walk never listed a jump of: an island the reference
/// pass can bound (`cmp; addls pc,pc,r0,lsl #2`), a table read with nothing
/// bounding the index, a branch through a register, and a bounded table
/// whose cases lie outside the function being traced.
fn reference_pass_jumps_import() -> Option<NativeImport> {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    cfg.adopt_language("ARM:LE:32:v5t");
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return None;
    }
    let words: [(u64, u32); 22] = [
        (0x1000, 0xe350_0001), // cmp r0,#1
        (0x1004, 0x908f_f100), // addls pc,pc,r0,lsl #2
        (0x1008, 0xe12f_ff1e), // bx lr (default)
        (0x100c, 0xea00_0000), // b 0x1014
        (0x1010, 0xea00_0000), // b 0x1018
        (0x1014, 0xe12f_ff1e),
        (0x1018, 0xe12f_ff1e),
        (0x1100, 0xe1a0_0000), // mov r0,r0
        (0x1104, 0xe79f_f100), // ldr pc,[pc,r0,lsl #2]
        (0x1108, 0xe12f_ff1e),
        (0x110c, 0x1014),
        (0x1110, 0x1018),
        (0x1200, 0xe3a0_0001), // mov r0,#1
        (0x1204, 0xe12f_ff13), // bx r3
        (0x1208, 0xe12f_ff1e),
        (0x120c, 0xe12f_ff1e),
        (0x1210, 0xe12f_ff1e),
        (0x1140, 0xe350_0001), // cmp r0,#1
        (0x1144, 0x979f_f100), // ldrls pc,[pc,r0,lsl #2]
        (0x1148, 0xe12f_ff1e),
        (0x114c, 0x1208),
        (0x1150, 0x120c),
    ];
    let mut bytes = vec![0u8; 0x220];
    for (address, word) in words {
        let at = (address - 0x1000) as usize;
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(NativeImport {
        language: "ARM:LE:32:v5t".into(),
        compiler: Some("default".into()),
        format: "elf32".into(),
        cfg,
        mappings: vec![Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 5, bytes }],
        functions: vec![
            NativeFunction { entry: 0x1000, name: "island".into(), size: 0x1c },
            NativeFunction { entry: 0x1100, name: "unbounded".into(), size: 0x14 },
            NativeFunction { entry: 0x1200, name: "pointer".into(), size: 0x14 },
            NativeFunction { entry: 0x1140, name: "outside".into(), size: 0x14 },
        ],
        ..Default::default()
    })
}

#[test]
fn the_reference_pass_stores_the_table_it_recovers_for_a_jump_the_walk_never_listed() {
    let Some(mut imp) = reference_pass_jumps_import() else {
        return;
    };
    super::super::references::infer_data_references(&mut imp).expect("the reference pass runs");
    assert_eq!(imp.switch_tables.get(&0x1004), Some(&vec![0x100c, 0x1010]));
    for target in [0x100c, 0x1010] {
        assert!(
            imp.xrefs.iter().any(|xref| xref.from == 0x1004
                && xref.to == target
                && xref.kind == "COMPUTED_JUMP"
                && xref.provenance == crate::native::SWITCH_PROVENANCE),
            "no switch reference to {target:#x}: {:?}",
            imp.xrefs
        );
    }
    // Its cases were decoded by no walk, which is a reason for another round.
    assert_eq!(imp.reference_tables_added, 1);
}

#[test]
fn the_switch_stage_is_asked_about_a_table_the_flow_bounded_but_could_not_finish() {
    let Some(mut imp) = reference_pass_jumps_import() else {
        return;
    };
    super::super::references::infer_data_references(&mut imp).expect("the reference pass runs");
    // The bounded table whose cases leave the function is the decompiler's to
    // place. The island was answered in the flow, the table read with no guard
    // and the branch through a register are calls: none of them is asked.
    assert_eq!(imp.indirect_jumps, vec![0x1144]);
    assert!(!imp.switch_tables.contains_key(&0x1144));
    assert!(!imp.switch_tables.contains_key(&0x1104));
}

/// A decoder that reads `0x1000` as a run of two-byte instructions in the
/// instruction set it holds (`modes`: what each mode makes of an address) and
/// remembers the mode `set_context` last painted.
struct ModedProvider {
    held: u64,
    /// `(mode, address)` -> answer; an address with none does not decode.
    flows: std::collections::HashMap<(u64, u64), FlowResult>,
    /// The mode of an address nothing decodes at, as `mode_at` reports it.
    undecodable_mode: Option<u64>,
}

impl FlowProvider for ModedProvider {
    fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
        addresses
            .iter()
            .map(|&address| {
                let mut flow = self.flows.get(&(self.held, address)).cloned().unwrap_or_else(|| {
                    let mut bad = result(address, FlowKind::Bad, None, false);
                    bad.length = 1;
                    bad
                });
                if flow.kind != FlowKind::Bad {
                    flow.mode = Some(self.held);
                }
                flow
            })
            .collect()
    }
    fn set_context(&mut self, _name: &str, _address: u64, value: u64) {
        self.held = value;
    }
    fn mode_at(&mut self, _address: u64) -> Option<u64> {
        self.undecodable_mode
    }
    fn linkages(&mut self, _: &[u64]) -> Vec<LinkageResult> {
        Vec::new()
    }
    fn plt_linkages(&mut self, _: &[u64]) -> Vec<LinkageResult> {
        Vec::new()
    }
    fn context_linkages(&mut self, _: &[LinkageContext]) -> Vec<LinkageResult> {
        Vec::new()
    }
}

/// Entry `0x1000`: in mode 0 one `bx lr` (a valid subroutine, one instruction
/// long); in mode 1 five instructions that fall through to a return.
fn aggressive_fixture(arm_decodes: bool) -> (NativeImport, ModedProvider, patterns::CodeRequirement) {
    let imp = image();
    let mut flows = std::collections::HashMap::new();
    if arm_decodes {
        let mut bx = result(0x1000, FlowKind::Return, None, false);
        bx.length = 4;
        flows.insert((0, 0x1000), bx);
    }
    for step in 0..5u64 {
        let address = 0x1000 + 2 * step;
        let kind = if step == 4 { FlowKind::Return } else { FlowKind::Fallthrough };
        flows.insert((1, address), result(address, kind, None, false));
    }
    let requirement = patterns::CodeRequirement { minimum: 3, maximum: 64, must_terminate: true, contiguous: false };
    (imp, ModedProvider { held: 0, flows, undecodable_mode: None }, requirement)
}

#[test]
fn a_held_mode_run_that_decodes_but_is_too_short_is_not_read_as_the_other_instruction_set() {
    // `bx lr` closing the function above reads, as Thumb, as five valid
    // instructions: Ghidra's finder does not try that, because the held mode
    // is already a subroutine (`checkValidSubroutine`); it refuses the match
    // for being two instructions or fewer.
    let (imp, mut provider, requirement) = aggressive_fixture(true);
    let indexes = patterns::PatternIndexes::build(&imp, &HashSet::default());
    assert!(patterns::aggressive_body(&imp, 0x1000, &requirement, &indexes, &[], &mut provider).is_none());
    assert_eq!(provider.held, 0, "the held mode is left alone");
}

#[test]
fn an_undecodable_held_mode_is_flipped_to_the_other_instruction_set() {
    let (imp, mut provider, requirement) = aggressive_fixture(false);
    let indexes = patterns::PatternIndexes::build(&imp, &HashSet::default());
    let (body, mode) = patterns::aggressive_body(&imp, 0x1000, &requirement, &indexes, &[], &mut provider)
        .expect("the other instruction set decodes a valid body");
    assert_eq!(mode, 1);
    assert_eq!(body.first().copied(), Some((0x1000, 0x1002)));
}

#[test]
fn the_mode_held_at_an_address_nothing_decodes_at_is_the_one_the_decoder_names() {
    let (_, mut provider, _) = aggressive_fixture(false);
    // Mode 0 does not decode at 0x1000 (no answer), yet the region has a mode:
    // a refused match must be able to hand it back after painting its own.
    provider.undecodable_mode = Some(0);
    assert_eq!(patterns::held_mode(&mut provider, 0x1000), Some(0));
    provider.undecodable_mode = None;
    assert_eq!(patterns::held_mode(&mut provider, 0x1000), None);
    provider.held = 1;
    assert_eq!(patterns::held_mode(&mut provider, 0x1000), Some(1), "a decodable address reports the mode it decoded in");
}

/// A tail-call stub (`b callee`) between two returning functions, where the
/// callee is itself a candidate: the stub's proven span stretches over its
/// callee and so over everything laid out between them.
fn stretched_stub(imp: &mut NativeImport, candidates: &[u64]) {
    flow_discover_with_sweep(imp, candidates, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1100 => result(a, FlowKind::Branch, Some(0x1400), true),
                0x1400 => result(a, FlowKind::Fallthrough, None, false),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
}

#[test]
fn a_stretched_tail_call_stub_does_not_retract_the_boundary_sweep_entries_it_spans() {
    // The sweep proposes the first instruction after each return. Their
    // evidence is that boundary, not an address read from data, so the case-
    // label overlap rule has no say: before this, the stub's span (0x1100 to
    // 0x1402) took 0x1200 and 0x1300 with it, and on a real image one stub
    // took ~11,000 functions.
    let mut imp = image();
    stretched_stub(&mut imp, &[0x1100, 0x1200, 0x1300, 0x1400]);
    assert_eq!(
        imp.functions.iter().map(|function| function.entry).collect::<Vec<_>>(),
        [0x1000, 0x1100, 0x1200, 0x1300],
        "the callee folds into its stub; the entries between them stay"
    );
}

#[test]
fn candidates_read_from_data_are_still_retracted_when_a_span_overlaps_them() {
    // The same shape proposed by relocation data (case labels) keeps the rule,
    // and so does a sweep candidate that data also names.
    for sweep in [&[][..], &[0x1100, 0x1200, 0x1300, 0x1400][..]] {
        let mut imp = image();
        imp.reloc_candidates = vec![0x1100, 0x1200, 0x1300, 0x1400];
        stretched_stub(&mut imp, sweep);
        assert_eq!(
            imp.functions.iter().map(|function| function.entry).collect::<Vec<_>>(),
            [0x1000],
            "sweep candidates given: {}",
            !sweep.is_empty()
        );
    }
}

/// A MIPS image (4-byte instructions) of `words` at 0x1000, the rest not fill.
fn mips_words(words: &[(u64, u32)]) -> NativeImport {
    let mut imp = image();
    imp.language = "MIPS:LE:32:default".into();
    for &(address, word) in words {
        let at = (address - 0x1000) as usize;
        imp.mappings[0].bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    imp
}

#[test]
fn the_gap_before_an_aligned_object_is_fill_and_a_leading_nop_is_not() {
    let words = [
        // One zero word before the 8-byte boundary 0x1008.
        (0x1004, 0),
        // Two before 0x1030, and the second of them alone.
        (0x1028, 0),
        (0x102c, 0),
        // Three before 0x1050, and the last two of them.
        (0x1044, 0),
        (0x1048, 0),
        (0x104c, 0),
        // Two on an aligned address, before 0x1068.
        (0x1060, 0),
        (0x1064, 0),
        // One zero word whose code starts at 4 mod 8: a nop that opens a function.
        (0x1080, 0),
        // The linker's `cd` fill and a word that only looks like one, `jr ra`.
        (0x1070, 0xcdcd_cdcd),
        (0x1078, 0x03e0_0008),
        // Zero words that no other word follows: the end of the mapping.
        (0x2ff8, 0),
        (0x2ffc, 0),
    ];
    let imp = mips_words(&words);
    for address in [0x1004, 0x1028, 0x102c, 0x1044, 0x1048, 0x104c, 0x1060, 0x1064, 0x1070] {
        assert!(opens_with_alignment_fill(&imp, address), "{address:#x}");
        assert!(opens_with_fill(&imp, address), "{address:#x}");
    }
    for address in [0x1000, 0x1008, 0x1078, 0x1080, 0x2ff8, 0x2ffc] {
        assert!(!opens_with_alignment_fill(&imp, address), "{address:#x}");
    }
    // They are fill all the same: nothing but zeros is left of the mapping.
    assert!(opens_with_fill(&imp, 0x2ff8) && opens_with_fill(&imp, 0x2ffc));
    // Four zero words are the 16-byte rule's, not this one.
    let mut run = mips_words(&[(0x1100, 0), (0x1104, 0), (0x1108, 0), (0x110c, 0)]);
    assert!(!opens_with_alignment_fill(&run, 0x1100));
    assert!(opens_with_fill(&run, 0x1100));
    // An instruction set of 2-byte instructions has other fill rules.
    run.language = "ARM:LE:32:v5t".into();
    assert!(!opens_with_alignment_fill(&run, 0x1104));
    let mut thumb = mips_words(&words);
    thumb.language = "ARM:LE:32:v5t".into();
    assert!(!opens_with_alignment_fill(&thumb, 0x1004));
}

#[test]
fn a_function_opening_in_alignment_fill_is_dropped_wherever_it_came_from() {
    // 0x1000: code. 0x1104: the zero word before the object at 0x1108.
    // 0x1204: the same, named by a data pointer. 0x1308: a symbol the image
    // declares, which stays.
    let mut imp = mips_words(&[(0x1104, 0), (0x1204, 0), (0x1304, 0)]);
    imp.functions.push(NativeFunction { entry: 0x1104, size: 1, name: "FUN_00001104".into() });
    imp.functions.push(NativeFunction { entry: 0x1304, size: 1, name: "declared".into() });
    imp.symbol_named = vec![0x1304];
    imp.pointer_candidates = vec![0x1204, 0x1208];
    flow_discover_with_sweep(&mut imp, &[0x1108, 0x1204], |addresses| {
        addresses.iter().map(|&a| word_result(a, FlowKind::Return, None, false)).collect()
    });
    assert_eq!(
        imp.functions.iter().map(|function| function.entry).collect::<Vec<_>>(),
        [0x1000, 0x1108, 0x1208, 0x1304]
    );
}

/// A PS2 (EE) image of four functions between linker fill, none called by
/// another but the last (`called`): 0x100000 `addiu sp,-16; jal 0x100040; nop;
/// jr ra; addiu sp,16`, one zero word, 0x100018 `addiu sp,-16; jr ra; addiu
/// sp,16`, three zero words to the 16-byte boundary, 0x100030 `li v0,1; jr ra;
/// nop`, one zero word, 0x100040 `li v0,2; jr ra; nop`, then zeros to `size`
/// bytes. Returns `None` without the r5900 language installed.
fn ee_sweep(called: bool, size: usize) -> Option<NativeImport> {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !crate::architecture::language_installed(&cfg.ghidra_install, "r5900:LE:32:default") {
        return None;
    }
    cfg.adopt_language("r5900:LE:32:default");
    cfg.switch_decompiler = false;
    let mut words = [0u32; 0x20];
    let call = if called { 0x0c04_0010 } else { 0 };
    for (at, code) in [
        (0, &[0x27bd_fff0, call, 0, 0x03e0_0008, 0x27bd_0010][..]),
        (6, &[0x27bd_fff0, 0x03e0_0008, 0x27bd_0010]),
        (12, &[0x2402_0001, 0x03e0_0008, 0]),
        (16, &[0x2402_0002, 0x03e0_0008, 0]),
    ] {
        words[at..at + code.len()].copy_from_slice(code);
    }
    let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    bytes.resize(size, 0);
    Some(NativeImport {
        language: "r5900:LE:32:default".into(),
        mappings: vec![Mapping { vaddr: 0x100000, size: bytes.len() as u64, file_off: 0, flags: 5, bytes }],
        functions: vec![NativeFunction { entry: 0x100000, size: 1, name: "entry".into() }],
        cfg,
        ..Default::default()
    })
}

fn entries(import: &NativeImport) -> Vec<u64> {
    import.functions.iter().map(|function| function.entry).collect()
}

#[test]
fn the_boundary_sweep_finds_the_objects_after_alignment_fill_on_an_ee_sequence() {
    // 128 bytes: a range no larger than `SWEEP_CALL_SPAN` needs no call into it.
    let Some(mut import) = ee_sweep(true, 0x80) else { return };
    discover_mapped(&mut import).expect("sweep");
    // Each object after a `jr ra` and its delay slot is a start, and the
    // padding between them is not: before, the first zero word took the
    // boundary and no sweep candidate was proposed after it.
    assert_eq!(entries(&import), [0x100000, 0x100018, 0x100030, 0x100040]);
}

#[test]
fn a_range_nothing_calls_is_data_and_is_not_swept() {
    let Some(mut import) = ee_sweep(false, 0x2000) else { return };
    discover_mapped(&mut import).expect("sweep");
    // The same bytes in a range of 8 KB with no call into it: no boundary is trusted.
    let found = entries(&import);
    assert!(found.contains(&0x100000));
    assert!(!found.contains(&0x100030) && !found.contains(&0x100040), "{found:x?}");
}

/// A MIPS image of one 0x1000-byte range whose words are all `li v0, 1`, with
/// `words` set over them. The range is no larger than `SWEEP_CALL_SPAN`, so
/// it needs no call into it to count as code.
fn li_image(words: &[(u64, u32)]) -> NativeImport {
    let mut bytes: Vec<u8> = 0x24020001u32.to_le_bytes().repeat(0x400);
    for &(address, word) in words {
        let at = (address - 0x1000) as usize;
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    NativeImport {
        language: "MIPS:LE:32:default".into(),
        mappings: vec![Mapping { vaddr: 0x1000, size: 0x1000, file_off: 0, flags: 5, bytes }],
        unrelocated_data_pointers: true,
        ..Default::default()
    }
}

#[test]
fn a_frame_opener_after_a_nop_on_an_aligned_address_starts_a_function() {
    const FRAME: u32 = 0x27bd_fff0;
    let imp = li_image(&[
        // After a `nop`, 8-aligned: a start.
        (0x1004, 0),
        (0x1008, FRAME),
        // 8-aligned, but the word before is code.
        (0x1010, FRAME),
        // After a `nop`, but 4 mod 8.
        (0x1018, 0),
        (0x101c, FRAME),
        // After a `nop`, 8-aligned, opening no frame (`addiu sp, sp, 16` gives one back).
        (0x1024, 0),
        (0x1028, 0x27bd_0010),
    ]);
    assert_eq!(after_fill_starts(&imp, &[(0x1000, 0x2000)]), [0x1008]);
}

/// `targets` jump instructions in an `li_image`, each to its own 8-aligned
/// address after a `nop` (0x1100, 0x1110, ..).
fn jumps_after_nops(targets: u64) -> NativeImport {
    let mut words = Vec::new();
    for index in 0..targets {
        let target = 0x1100 + 0x10 * index;
        words.push((0x1000 + 4 * index, 0x0800_0000 | (target >> 2) as u32));
        words.push((target - 4, 0));
    }
    li_image(&words)
}

#[test]
fn jump_targets_after_a_nop_start_functions_only_in_an_image_full_of_them() {
    // A handful is a function that jumps inside itself; a quorum is the image's
    // way of tail-calling (`JUMP_START_QUORUM`).
    assert!(jump_starts_after_fill(&jumps_after_nops(JUMP_START_QUORUM as u64 - 1)).is_empty());
    let imp = jumps_after_nops(JUMP_START_QUORUM as u64);
    assert_eq!(
        jump_starts_after_fill(&imp),
        (0..JUMP_START_QUORUM as u64).map(|index| 0x1100 + 0x10 * index).collect::<Vec<_>>()
    );
    // A target some function already is does not count towards it.
    let mut known = jumps_after_nops(JUMP_START_QUORUM as u64);
    known.functions.push(NativeFunction { entry: 0x1100, size: 1, name: "known".into() });
    assert!(jump_starts_after_fill(&known).is_empty());
    // Only a stripped, unrelocated MIPS executable.
    let mut relocated = jumps_after_nops(JUMP_START_QUORUM as u64);
    relocated.unrelocated_data_pointers = false;
    assert!(jump_starts_after_fill(&relocated).is_empty());
}

/// The dispatching function of a switch whose table is not recovered yet,
/// and the labels the walk made from the words of the table (God Hand
/// 0x1627d8, which holds `bnez v0,loop_head` in its last case): the last
/// label reaches the loop head in one instruction, the function itself in
/// eight, so the head, the dispatch and everything between belong to the
/// walk of that label, which sits above none of it.
fn dispatch_with_labels(imp: &mut NativeImport, call_last_label: bool) {
    imp.reloc_candidates = vec![0x1200, 0x1240, 0x1250, 0x1260];
    flow_discover_with_provider(imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 if call_last_label => result(a, FlowKind::Call, Some(0x1260), false),
                0x1222 => result(a, FlowKind::BranchInd, None, false),
                0x1260 => result(a, FlowKind::CBranch, Some(0x1210), false),
                0x1200..=0x1220 => result(a, FlowKind::Fallthrough, None, false),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
}

#[test]
fn a_case_label_that_reaches_back_into_the_function_above_leaves_its_dispatch_in_that_function() {
    let mut imp = image();
    dispatch_with_labels(&mut imp, false);
    assert_eq!(entries(&imp), [0x1000, 0x1200, 0x1240, 0x1250, 0x1260], "no entry is decided here");
    let host = imp.functions.iter().find(|function| function.entry == 0x1200).unwrap();
    // The dispatch is the two bytes at 0x1222; the function ends with it.
    assert_eq!(host.size, 0x24, "the function runs through its dispatch and no further: {host:?}");
}

#[test]
fn a_function_that_returns_where_a_tail_calling_label_begins_to_reach_is_not_extended() {
    // God Hand 0x34c930 ends with a `jr ra` right where 0x34c990 begins, and
    // the tail-calling 0x35d4f0 reaches 0x34c990 first: the two abut, but the
    // function above does not run into that code.
    let mut imp = image();
    imp.reloc_candidates = vec![0x1200, 0x1260];
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1260 => result(a, FlowKind::Branch, Some(0x1210), true),
                0x1200..=0x1206 | 0x1210..=0x121e => result(a, FlowKind::Fallthrough, None, false),
                _ => result(a, FlowKind::Return, None, false),
            })
            .collect()
    });
    let host = imp.functions.iter().find(|function| function.entry == 0x1200).unwrap();
    assert_eq!(host.size, 0xa, "{host:?}");
}

#[test]
fn a_called_label_that_reaches_back_does_not_extend_the_function_above() {
    let mut imp = image();
    dispatch_with_labels(&mut imp, true);
    let host = imp.functions.iter().find(|function| function.entry == 0x1200).unwrap();
    assert_eq!(host.size, 0x10, "the walk of the host stops at the loop head the label took: {host:?}");
}

#[test]
fn an_r5900_body_that_ends_off_the_word_grid_is_no_function_unless_the_image_declares_it() {
    // Sizes the walk proved: 8 is whole instructions; 5 and 1 stopped at
    // bytes SLEIGH has no instruction for.
    let mut imp = mips_words(&[]);
    let functions: Vec<NativeFunction> = [(0x1000, 8), (0x1010, 5), (0x1020, 1), (0x1030, 5), (0x1040, 0)]
        .into_iter()
        .map(|(entry, size)| NativeFunction { entry, size, name: format!("FUN_{entry:08x}") })
        .collect();
    imp.symbol_named = vec![0x1030];
    let found = undecodable_bodies(&imp, &functions);
    let mut found: Vec<u64> = found.into_iter().collect();
    found.sort_unstable();
    assert_eq!(found, [0x1010, 0x1020]);
}

#[test]
fn a_call_into_undecodable_bytes_makes_no_function_on_the_r5900_and_still_does_elsewhere() {
    let walk = |language: &str| {
        let mut imp = mips_words(&[]);
        imp.language = language.into();
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .map(|&a| match a {
                    0x1000 => word_result(a, FlowKind::Call, Some(0x1100), false),
                    0x1100 => {
                        // SLEIGH reads one byte of what it cannot decode.
                        let mut flow = word_result(a, FlowKind::Bad, None, false);
                        flow.length = 1;
                        flow
                    }
                    _ => word_result(a, FlowKind::Return, None, false),
                })
                .collect()
        });
        entries(&imp)
    };
    // The body of 0x1100 proves one byte: on the r5900, whose instructions are
    // words, no function; elsewhere the entry stays.
    assert_eq!(walk("r5900:LE:32:default"), [0x1000]);
    assert_eq!(walk("MIPS:LE:32:default"), [0x1000, 0x1100]);
    assert_eq!(walk("ARM:LE:32:v5t"), [0x1000, 0x1100]);
}

#[test]
fn an_entry_that_loops_back_into_the_function_above_is_that_functions_code_on_mips() {
    // 0x1000 runs on to a loop at 0x1008 whose body has a conditional branch
    // to 0x1020, laid out after the function's return. The code at 0x1020
    // branches back to the loop top, a shorter walk than the function's own,
    // so it reaches the loop body first and the branch to it is, by the walk's
    // attribution, its own: the function above is still the owner.
    let walk = |language: &str| {
        let mut imp = mips_words(&[]);
        imp.language = language.into();
        flow_discover_with_sweep(&mut imp, &[0x1020], |addresses| {
            addresses
                .iter()
                .map(|&a| match a {
                    0x100a => word_result(a, FlowKind::CBranch, Some(0x1020), false),
                    0x100c => word_result(a, FlowKind::Return, None, false),
                    0x1022 => word_result(a, FlowKind::CBranch, Some(0x1008), false),
                    0x1024 => word_result(a, FlowKind::Return, None, false),
                    0x1000..=0x1008 | 0x1020 => word_result(a, FlowKind::Fallthrough, None, false),
                    _ => word_result(a, FlowKind::Return, None, false),
                })
                .collect()
        });
        entries(&imp)
    };
    assert_eq!(walk("MIPS:LE:32:default"), [0x1000]);
    assert_eq!(walk("ARM:LE:32:v5t"), [0x1000, 0x1020]);
}

#[test]
fn the_case_blocks_of_a_dispatch_with_no_table_are_its_functions_code_on_mips() {
    // A `jr v0` at 0x1010 with three blocks right after it, none calling or
    // calling-convention-shaped, whose only reference is a run of three code
    // pointers in data. Nothing recovered the table: the blocks are the
    // dispatching function's, not three functions.
    let words = [
        (0x1010, 0x0040_0008),
        (0x1014, 0),
        (0x1018, 0x2402_0001),
        (0x1020, 0x2402_0002),
        (0x1028, 0x2402_0003),
        (0x1100, 0x1018),
        (0x1104, 0x1020),
        (0x1108, 0x1028),
    ];
    let walk = |language: &str, words: &[(u64, u32)]| {
        let mut imp = mips_words(words);
        imp.language = language.into();
        imp.reloc_candidates = vec![0x1018, 0x1020, 0x1028];
        flow_discover_with_provider(&mut imp, |addresses| {
            addresses
                .iter()
                .map(|&a| match a {
                    0x1010 => word_result(a, FlowKind::BranchInd, None, false),
                    0x1000..=0x100e => word_result(a, FlowKind::Fallthrough, None, false),
                    _ => word_result(a, FlowKind::Return, None, false),
                })
                .collect()
        });
        entries(&imp)
    };
    assert_eq!(walk("MIPS:LE:32:default", &words), [0x1000]);
    // The same bytes where the first block opens a frame (`addiu sp,sp,-16`)
    // are a function, and two words are no run.
    let mut framed = words;
    framed[2].1 = 0x27bd_fff0;
    assert!(walk("MIPS:LE:32:default", &framed).contains(&0x1018));
    let mut short = words;
    short[7].1 = 0x1234_5678;
    assert!(walk("MIPS:LE:32:default", &short).contains(&0x1018));
    assert_eq!(walk("ARM:LE:32:v5t", &words), [0x1000, 0x1018, 0x1020, 0x1028]);
}

/// 0x1000 is a function that ends in a loop, 0x1008 a block after it that a data word names and
/// nothing reaches; `first` is the block's first word.
fn dead_tail_walk(first: u32, landing_pad: bool) -> Vec<u64> {
    let mut imp = mips_words(&[(0x1000, 0x0800_0400), (0x1004, 0), (0x1008, first), (0x100c, 0x03e0_0008)]);
    imp.reloc_candidates = vec![0x1008];
    if landing_pad {
        imp.exception_sites.push(crate::native::elf_exception::ExceptionSite {
            function: 0x1000,
            start: 0x1000,
            end: 0x1004,
            landing_pad: 0x1008,
        });
    }
    flow_discover_with_provider(&mut imp, |addresses| {
        addresses
            .iter()
            .map(|&a| match a {
                0x1000 => word_result(a, FlowKind::Branch, Some(0x1000), false),
                0x100c => word_result(a, FlowKind::Return, None, false),
                _ => word_result(a, FlowKind::Fallthrough, None, false),
            })
            .collect()
    });
    entries(&imp)
}

#[test]
fn a_landing_pad_the_exception_tables_declare_is_not_a_function() {
    // Nothing calls the block and it opens no frame; only the unwinder enters it.
    assert_eq!(dead_tail_walk(0x2402_0001, false), [0x1000, 0x1008]);
    assert_eq!(dead_tail_walk(0x2402_0001, true), [0x1000]);
}

#[test]
fn a_block_that_reloads_the_return_address_first_is_the_epilogue_of_the_function_above() {
    // `lw ra, 32(sp)` opens no function; `lw v0, 32(sp)` (a stack argument) can.
    assert_eq!(dead_tail_walk(0x8fa2_0020, false), [0x1000, 0x1008]);
    assert_eq!(dead_tail_walk(0x8fbf_0020, false), [0x1000]);
}

#[test]
fn a_call_beside_bytes_with_no_instruction_is_a_word_of_data_not_a_call() {
    // The scan's decode: words every 4 bytes, one undecodable at 0x2000.
    let mut decoded = std::collections::BTreeMap::new();
    for address in (0x1000..0x3000).step_by(4) {
        let kind = if address == 0x2000 { FlowKind::Bad } else { FlowKind::Fallthrough };
        let mut flow = word_result(address, kind, None, false);
        flow.kind = kind;
        decoded.insert(address, flow);
    }
    // 16 words either side of it: a `jal`-shaped word of data.
    assert!(has_undecodable_neighbour(&decoded, 0x2000));
    assert!(has_undecodable_neighbour(&decoded, 0x2000 - CALL_NEIGHBOURHOOD));
    assert!(has_undecodable_neighbour(&decoded, 0x2000 + CALL_NEIGHBOURHOOD));
    // A real call: every word near it decodes.
    assert!(!has_undecodable_neighbour(&decoded, 0x2000 - CALL_NEIGHBOURHOOD - 4));
    assert!(!has_undecodable_neighbour(&decoded, 0x2000 + CALL_NEIGHBOURHOOD + 4));
    assert!(!has_undecodable_neighbour(&decoded, 0x1000));
}

#[test]
fn the_block_a_jump_hops_over_is_not_a_function_on_mips() {
    // 0x1000 `j 0x1048; nop`, then eight plain words that run into 0x1048
    // (`jr ra`). A function following a jump to somewhere else returns or
    // jumps first: the second image's block ends in `jr ra` at 0x1020.
    let mut words: Vec<(u64, u32)> = vec![(0x1000, 0x0800_0412), (0x1004, 0), (0x1048, 0x03e0_0008)];
    words.extend((0..8).map(|index| (0x1008 + 4 * index, 0x2402_0001)));
    let walk = |language: &str, words: &[(u64, u32)]| {
        let mut imp = mips_words(words);
        imp.language = language.into();
        flow_discover_with_sweep(&mut imp, &[0x1008], |addresses| {
            addresses
                .iter()
                .map(|&a| match a {
                    0x1000 => word_result(a, FlowKind::Branch, Some(0x1048), false),
                    0x1008..=0x1044 => word_result(a, FlowKind::Fallthrough, None, false),
                    _ => word_result(a, FlowKind::Return, None, false),
                })
                .collect()
        });
        entries(&imp)
    };
    assert_eq!(walk("MIPS:LE:32:default", &words), [0x1000]);
    assert_eq!(walk("ARM:LE:32:v5t", &words), [0x1000, 0x1008]);
    let mut returns = words.clone();
    returns.push((0x1020, 0x03e0_0008));
    assert_eq!(walk("MIPS:LE:32:default", &returns), [0x1000, 0x1008]);
}

#[test]
fn zero_words_before_a_table_of_code_pointers_or_more_fill_are_padding_not_a_function() {
    // 0x1008: three zero words, then two pointers into the mapping, the way a
    // jump table follows the code in Ratchet & Clank. 0x1028: three zero
    // words, then `cdcdcdcd`. 0x1048: three zero words, then an instruction.
    let imp = mips_words(&[
        (0x1008, 0),
        (0x100c, 0),
        (0x1010, 0),
        (0x1014, 0x1100),
        (0x1018, 0x1180),
        (0x1028, 0),
        (0x102c, 0),
        (0x1030, 0),
        (0x1034, 0xcdcd_cdcd),
        (0x1048, 0),
        (0x104c, 0),
        (0x1050, 0),
        (0x1054, 0x2402_0001),
    ]);
    assert!(opens_with_alignment_fill(&imp, 0x1008));
    assert!(opens_with_alignment_fill(&imp, 0x1028));
    assert!(!opens_with_alignment_fill(&imp, 0x1048));
}

#[test]
fn the_mips_entry_rules_ask_about_no_address_below_an_image_linked_at_zero() {
    // A PRX linked at 0 (PSP): an entry at 0 or 4 is asked about at `entry - 4`,
    // `- 8` and `- 12`, which wrap to the top of the address space. No
    // mapping holds those, and reading one must not overflow (a debug build
    // panicked at `at + 4` with `at` near `usize::MAX`).
    let mut imp = mips_words(&[]);
    imp.mappings[0].vaddr = 0;
    imp.mappings[0].size = 0x2000;
    imp.functions = vec![NativeFunction { entry: 0, size: 1, name: "entry".into() }];
    for address in [0u64, 4, 8, 12] {
        for back in [4u64, 8, 12] {
            assert_eq!(word_at(&imp, address.wrapping_sub(back)), if address >= back { word_at(&imp, address - back) } else { None });
        }
    }
    assert_eq!(word_at(&imp, u64::MAX), None);
    assert_eq!(word_at(&imp, u64::MAX - 3), None);
    imp.reloc_candidates = vec![0x4, 0x8, 0x20];
    flow_discover_with_sweep(&mut imp, &[0x4, 0x8, 0x20], |addresses| {
        addresses.iter().map(|&a| word_result(a, FlowKind::Return, None, false)).collect()
    });
    assert!(entries(&imp).contains(&0x4));
}

/// The lanes of a small image, and its plain lifter, share one decoder, each
/// with the context database its own decodes committed to: every batch
/// answers as it does with a decoder of its own for each (a `blx` committed
/// in the first lane is not seen by the others, and a mode the walk sets
/// reaches all of them).
#[test]
fn lanes_sharing_a_decoder_answer_as_lanes_with_one_each_do() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    if !cfg.ghidra_install.join("Ghidra").is_dir() {
        eprintln!("SKIP: no Ghidra install");
        return;
    }
    cfg.adopt_language("ARM:LE:32:v5t");
    let mut bytes = vec![0u8; 0x1004];
    bytes[0x4..0x8].copy_from_slice(&0xfa00_03fdu32.to_le_bytes()); // 0x1004: blx 0x2000
    bytes[0x1000..0x1004].copy_from_slice(&0xe3a0_0001u32.to_le_bytes()); // 0x2000: mov r0,#1
    let import = NativeImport {
        language: "ARM:LE:32:v5t".into(),
        cfg: cfg.clone(),
        mappings: vec![Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes }],
        ..Default::default()
    };
    let mut shared = Lanes::open_with(&import, 4, true).unwrap();
    let mut apart = Lanes::open_with(&import, 4, false).unwrap();
    assert_eq!((shared.lanes.len(), apart.lanes.len()), (1, 4));
    // Eight requests across four lanes: two each, the `blx` in the first
    // lane's, which commits Thumb at its target in that lane only.
    let first: Vec<u64> = (0..8).map(|index| 0x1000 + 4 * index).collect();
    assert_eq!(shared.flow(&first).unwrap(), apart.flow(&first).unwrap());
    let second = [0x2000, 0x1000, 0x2000, 0x1000, 0x2000, 0x1000, 0x2000, 0x1000];
    let (shared_flows, apart_flows) = (shared.flow(&second).unwrap(), apart.flow(&second).unwrap());
    assert_eq!(shared_flows, apart_flows);
    assert_eq!((shared_flows[0].length, shared_flows[2].length), (2, 4), "Thumb in the lane that committed it, ARM in the next");
    // A mode the walk sets reaches every lane, and the lifter.
    let mode = [crate::native::NativeContext { name: "TMode".into(), address: 0x2000, value: 1 }];
    shared.set_contexts(&mode).unwrap();
    apart.set_contexts(&mode).unwrap();
    let third = [0x2000; 8];
    assert_eq!(shared.flow(&third).unwrap(), apart.flow(&third).unwrap());
    assert!(shared.flow(&third).unwrap().iter().all(|flow| flow.length == 2));
    let (lifted, lifted_apart) = (shared.with_lifter(|lifter| lifter.lift(&[0x1004, 0x2000])), apart.with_lifter(|lifter| lifter.lift(&[0x1004, 0x2000])));
    assert_eq!(lifted, lifted_apart);
    // The shared decoder is a flow decoder again after a lifter call.
    assert_eq!(shared.flow(&first).unwrap(), apart.flow(&first).unwrap());
}
