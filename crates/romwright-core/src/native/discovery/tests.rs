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

fn image() -> NativeImport {
    NativeImport {
        mappings: vec![Mapping {
            vaddr: 0x1000,
            size: 0x2000,
            file_off: 0,
            flags: 4,
            bytes: vec![0; 0x2000],
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
    let Ok(console) = crate::native_runtime::find_console(&cfg) else {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    };
    cfg.console_path = Some(console);
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
            drop(discover_seeded(&mut import));
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
    let Ok(console) = crate::native_runtime::find_console(&cfg) else {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    };
    cfg.console_path = Some(console);
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
        drop(discover_seeded(&mut import));
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
    let Ok(console) = crate::native_runtime::find_console(&cfg) else {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    };
    cfg.console_path = Some(console);
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
        drop(discover_seeded(&mut import));
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
    let Ok(console) = crate::native_runtime::find_console(&cfg) else {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    };
    cfg.console_path = Some(console);
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
    drop(discover_seeded(&mut import));
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
    let Ok(console) = crate::native_runtime::find_console(&cfg) else {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    };
    cfg.console_path = Some(console);
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
    drop(discover_seeded(&mut import));
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
