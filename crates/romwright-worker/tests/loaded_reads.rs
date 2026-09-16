//! Ghidra's getBytes callback pads a valid short read, not an unmapped start.
use romwright_worker::BinaryBacking;

#[test]
fn worker_pads_short_reads_but_rejects_unmapped_starts() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "romwright-worker-bytes-{}-{stamp}",
        std::process::id()
    ));
    std::fs::write(&path, [0x90, 0xc3]).unwrap();
    let result = {
        let backing = BinaryBacking::from_file(&path, None, 0x400000).unwrap();
        let short = backing.read(0x400001, 4);
        assert!(backing.read(0x400002, 1).is_none());
        assert!(backing.read(0x3fffff, 1).is_none());
        short
    };
    std::fs::remove_file(path).unwrap();
    assert_eq!(result, Some(vec![0xc3, 0, 0, 0]));
}

#[test]
#[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
fn anonymous_readonly_loads_fold_but_mutable_loads_remain_live() {
    use romwright_model::function_ir::{IrSpace, Opcode, Operand};
    use romwright_worker::{NativeWorker, ProgramProvider};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = romwright_core::session::RuntimeConfig::from_env();
    cfg.spec_root = root.join(&cfg.spec_root);
    cfg.decompiler_path = root.join(&cfg.decompiler_path);
    let (sla, specs_path, language_dir, language) =
        romwright_core::native_runtime::language_decompile_config(&cfg, "x86:LE:64:default")
            .unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("romwright-readonly-{}-{stamp}", std::process::id()));
    // mov eax,[rip+10]; ret; padding; an anonymous 32-bit literal.
    let mut bytes = vec![0x8b, 0x05, 10, 0, 0, 0, 0xc3];
    bytes.resize(16, 0);
    bytes.extend_from_slice(&0x13579bdfu32.to_le_bytes());
    std::fs::write(&path, bytes).unwrap();
    for (readonly, named) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut provider = ProgramProvider::new(
            BinaryBacking::from_file(&path, None, 0x1000).unwrap(),
            vec![0x1000],
        );
        provider.load_language_info(&specs_path).unwrap();
        provider.function_names.insert(0x1000, "load_word".into());
        provider.function_sizes.insert(0x1000, 7);
        if readonly {
            provider.read_only.push((0x1010, 0x1014));
        }
        if named {
            provider.data_targets.insert(0x1010);
            provider.symbol_names.insert(0x1010, "literal_word".into());
        }
        let mut command = std::process::Command::new(&cfg.decompiler_path);
        command
            .env("ROMWRIGHT_SLA", &sla)
            .env("ROMWRIGHT_LANGUAGE_DIR", &language_dir)
            .env("ROMWRIGHT_LANGUAGE", &language);
        let mut worker = NativeWorker::launch(command).unwrap();
        let shell = provider.function_shell().unwrap();
        let specs = romwright_worker::load_specs(&specs_path).unwrap();
        worker
            .register_program_with_shell(
                &mut provider,
                &specs.0,
                &specs.1,
                &specs.2,
                &specs.3,
                &shell,
            )
            .unwrap();
        worker.set_action(&mut provider, "decompile", "").unwrap();
        let ram = provider.ram_space_index as u32;
        let raw = worker.decompile_at(&mut provider, ram, 0x1000).unwrap();
        let doc = romwright_worker::decode_document_with_ram_space(&raw, Some(ram as u64));
        let ir = doc.function_ir.unwrap();
        let ret = ir
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .find(|op| op.opcode == Opcode::RETURN)
            .expect("recovered return");
        let Operand::Value(id) = ret.inputs[1] else {
            panic!("missing return value")
        };
        let mut pending = vec![id];
        let mut visited = std::collections::BTreeSet::new();
        let mut reads_literal = false;
        let mut returns_constant = false;
        while let Some(value) = pending.pop() {
            if !visited.insert(value) {
                continue;
            }
            let storage = &ir.values[&value];
            reads_literal |=
                storage.space == IrSpace::Index(ram as u64) && storage.offset == Some(0x1010);
            returns_constant |=
                storage.space == IrSpace::Index(0) && storage.offset == Some(0x13579bdf);
            if let Some(def) = ir
                .blocks
                .iter()
                .flat_map(|block| &block.operations)
                .find(|op| op.output == Some(value))
            {
                pending.extend(def.inputs.iter().filter_map(|operand| match operand {
                    Operand::Value(value) => Some(*value),
                    _ => None,
                }));
            }
        }
        assert_eq!(
            reads_literal, !readonly,
            "only mutable memory remains a live dependency"
        );
        assert_eq!(
            returns_constant, readonly,
            "only immutable memory becomes its stored value"
        );
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
fn thumb_saved_return_address_is_proved_without_reclassifying_indirect_dispatch() {
    use romwright_model::function_ir::Opcode;
    use romwright_worker::{NativeWorker, ProgramProvider};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = romwright_core::session::RuntimeConfig::from_env();
    cfg.spec_root = root.join(&cfg.spec_root);
    cfg.decompiler_path = root.join(&cfg.decompiler_path);
    let (sla, specs_path, language_dir, language) =
        romwright_core::native_runtime::language_decompile_config(&cfg, "ARM:LE:32:v8").unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "romwright-saved-return-{}-{stamp}",
        std::process::id()
    ));
    // push {r4,lr}; adds r0,#1; pop {r4}; pop {r1}; bx r1.
    let saved_lr = [0x10, 0xb5, 1, 0x30, 0x10, 0xbc, 2, 0xbc, 8, 0x47];
    for (bytes, explicit_return, is_return) in [
        (saved_lr.as_slice(), "", true),
        ([8, 0x47].as_slice(), "", false), // Unproven bx r1 is not a return.
        (
            saved_lr.as_slice(),
            "<returnaddress><register name=\"r12\"/></returnaddress>",
            false,
        ),
    ] {
        std::fs::write(&path, bytes).unwrap();
        let mut provider = ProgramProvider::new(
            BinaryBacking::from_file(&path, None, 0x1000).unwrap(),
            vec![0x1000],
        );
        provider.load_language_info(&specs_path).unwrap();
        provider.function_names.insert(0x1000, "transfer".into());
        provider.function_sizes.insert(0x1000, bytes.len() as u64);
        let mut specs = romwright_worker::load_specs(&specs_path).unwrap();
        specs.1 = specs.1.replace(
            "</compiler_spec>",
            &format!(
                "{explicit_return}<context_data><context_set space=\"ram\" \
             first=\"0x1000\" last=\"0x1009\"><set name=\"TMode\" val=\"1\"/>\
             </context_set></context_data></compiler_spec>"
            ),
        );
        let mut command = std::process::Command::new(&cfg.decompiler_path);
        command
            .env("ROMWRIGHT_SLA", &sla)
            .env("ROMWRIGHT_LANGUAGE_DIR", &language_dir)
            .env("ROMWRIGHT_LANGUAGE", &language);
        let mut worker = NativeWorker::launch(command).unwrap();
        let shell = provider.function_shell().unwrap();
        worker
            .register_program_with_shell(
                &mut provider,
                &specs.0,
                &specs.1,
                &specs.2,
                &specs.3,
                &shell,
            )
            .unwrap();
        worker.set_action(&mut provider, "decompile", "").unwrap();
        let ram = provider.ram_space_index as u32;
        let raw = worker.decompile_at(&mut provider, ram, 0x1000).unwrap();
        let doc = romwright_worker::decode_document_with_ram_space(&raw, Some(ram as u64));
        let ir = doc.function_ir.unwrap();
        let operations: Vec<_> = ir
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .collect();
        let indirect = operations
            .iter()
            .any(|op| matches!(op.opcode, Opcode::CALLIND | Opcode::BRANCHIND));
        assert_eq!(
            indirect, !is_return,
            "return proof must respect the declared ABI"
        );
        if is_return {
            assert!(operations.iter().any(|op| op.opcode == Opcode::RETURN));
        }
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "requires clang/lld, the built native decompiler and installed SLEIGH specifications"]
fn switch_batches_preserve_tables_across_a_failed_function() {
    let root = std::env::temp_dir().join(format!(
        "romwright-switch-batch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&root).unwrap();
    let assembly = root.join("switch.s");
    let binary = root.join("switch.elf");
    std::fs::write(
        &assembly,
        r#"
.syntax unified
.thumb
.text
.global dispatch
.type dispatch,%function
.thumb_func
dispatch:
    cmp r0, #3
    bhi default_case
    lsls r0, r0, #2
    adr r1, table
    ldr r0, [r1, r0]
    bx r0
.balign 4
table:
    .word case0+1, case1+1, case2+1, case3+1
case0:
    movs r0, #17
    bx lr
case1:
    movs r0, #35
    bx lr
case2:
    movs r0, #53
    bx lr
case3:
    movs r0, #71
    bx lr
default_case:
    movs r0, #255
    bx lr
.size dispatch, .-dispatch
.global saved_return
.type saved_return,%function
.thumb_func
saved_return:
    push {lr}
    adds r0, #1
    pop {r1}
    bx r1
.size saved_return, .-saved_return
.section .rodata,"a"
.balign 4
/* Untyped byte addresses are not ARM-mode code-pointer declarations. */
    .word dispatch-1, dispatch+3
"#,
    )
    .unwrap();
    let assembled = std::process::Command::new("clang")
        .args([
            "--target=armv4t-none-eabi",
            "-nostdlib",
            "-fuse-ld=lld",
            "-Wl,-Ttext=0x08000000",
            "-Wl,-e,dispatch",
        ])
        .arg(&assembly)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let mut config = romwright_core::session::RuntimeConfig::from_env();
    config.worker_path = env!("CARGO_BIN_EXE_romwright-worker").into();
    config.switch_vsa = false;
    config.switch_decompiler = false;
    let project = root.join("project");
    let core = romwright_core::Core::open_with_config(&project, config.clone()).unwrap();
    core.import_native_with_signatures(
        &binary,
        "switches",
        &[],
        false,
        None,
        None,
        &romwright_core::native::keys::KeyStore::empty(),
    )
    .unwrap();
    let functions = core.functions("switches").unwrap();
    let entry = |name: &str| {
        functions
            .iter()
            .find(|function| function.name == name)
            .unwrap()
            .entry
            .offset
    };
    // Six Thumb-1 instructions, four table words, four 4-byte cases and the folded default.
    let expected: std::collections::BTreeSet<_> = [28, 32, 36, 40, 44]
        .into_iter()
        .map(|offset| entry("dispatch") + offset)
        .collect();
    let (sla, specs, language_dir, language) =
        romwright_core::native_runtime::language_decompile_config(&config, "ARM:LE:32:v8").unwrap();
    let output = std::process::Command::new(&config.worker_path)
        .arg(&config.decompiler_path)
        .arg(specs)
        .arg("switches")
        .arg(format!("{:x}", entry("dispatch")))
        .arg("ffff0000")
        .arg(format!("{:x}", entry("saved_return")))
        .arg("--project")
        .arg(&project)
        .arg("--switches")
        .env("ROMWRIGHT_SLA", sla)
        .env("ROMWRIGHT_LANGUAGE_DIR", language_dir)
        .env("ROMWRIGHT_LANGUAGE", language)
        .env("WORKER_DECOMPILE_TIMEOUT_SECS", "10")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let answers: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        answers.len(),
        3,
        "a failed function must not abandon the batch"
    );
    let tables: Vec<romwright_model::JumpTable> =
        serde_json::from_value(answers[0]["result"]["Ok"].clone()).unwrap();
    let targets: std::collections::BTreeSet<_> = tables
        .iter()
        .flat_map(|table| &table.targets)
        .map(|target| target.offset)
        .collect();
    assert_eq!(
        targets, expected,
        "completed switch cases survive a later failure"
    );
    assert!(
        answers[1]["result"]["Err"].is_string(),
        "unmapped function must report failure"
    );
    assert_eq!(
        answers[2]["result"]["Ok"],
        serde_json::json!([]),
        "the next function completes without mistaking a saved return for a switch"
    );
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}
