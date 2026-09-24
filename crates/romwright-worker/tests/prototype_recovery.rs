use romwright_model::{Address, FactKind, FactProvenance, PrototypeRow};
use romwright_worker::{BinaryBacking, NativeWorker, ProgramProvider};
use std::path::Path;

#[test]
#[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
fn inferred_targets_recover_but_assertions_remain_locked() {
    let address = 0x400466;
    let (mut worker, mut provider) = worker_for_add(PrototypeRow {
        function: Address::ram(address),
        signature: "int old_inferred_name(void)".into(),
        calling_convention: None,
        return_type: Some("int".into()),
        provenance: FactProvenance {
            kind: FactKind::Inferred,
            source: "m2-006 recovery regression".into(),
            confidence: None,
        },
    });
    let ram = provider.ram_space_index as u32;
    worker.prepare_function(&mut provider, address).unwrap();
    let read = worker.decompile_at(&mut provider, ram, address).unwrap();
    let decoded = romwright_worker::decode_document_with_ram_space(&read, Some(ram as u64));
    assert_eq!(decoded.prototype.unwrap().parameters.len(), 0);
    assert!(
        !decoded
            .tokens
            .iter()
            .any(|token| token.text.contains("old_inferred_name")),
        "an inferred signature must not rename the function"
    );

    worker
        .prepare_function_for_inference(&mut provider, address)
        .unwrap();
    let recovered = worker.decompile_at(&mut provider, ram, address).unwrap();
    let proto =
        romwright_worker::decode_document_with_ram_space(&recovered, Some(ram as u64)).prototype;
    assert_eq!(
        proto.unwrap().parameters.len(),
        2,
        "the previous inferred void-input lock must not freeze recovery"
    );

    provider
        .prototypes
        .get_mut(&address)
        .unwrap()
        .provenance
        .kind = FactKind::Asserted;
    worker
        .prepare_function_for_inference(&mut provider, address)
        .unwrap();
    let asserted = worker.decompile_at(&mut provider, ram, address).unwrap();
    let proto =
        romwright_worker::decode_document_with_ram_space(&asserted, Some(ram as u64)).prototype;
    assert_eq!(
        proto.unwrap().parameters.len(),
        0,
        "recovery must preserve the analyst's zero-parameter assertion"
    );
}

fn worker_for_add(prototype: PrototypeRow) -> (NativeWorker, ProgramProvider) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = romwright_core::session::RuntimeConfig::from_env();
    cfg.spec_root = root.join(&cfg.spec_root);
    cfg.decompiler_path = root.join(&cfg.decompiler_path);
    let (sla, specs_path, language_dir, language) =
        romwright_core::native_runtime::language_decompile_config(&cfg, "x86:LE:64:default")
            .unwrap();
    let address = prototype.function.offset;
    let mut provider = ProgramProvider::new(
        BinaryBacking::from_file(
            &root.join("tests/fixtures-src/tiny_bin"),
            Some("tiny"),
            0x400000,
        )
        .unwrap(),
        vec![address],
    );
    provider.load_language_info(&specs_path).unwrap();
    provider.function_names.insert(address, "add".into());
    provider.function_sizes.insert(address, 0x14);
    provider.prototypes.insert(address, prototype);
    let mut command = std::process::Command::new(&cfg.decompiler_path);
    command
        .env("ROMWRIGHT_SLA", sla)
        .env("ROMWRIGHT_LANGUAGE_DIR", language_dir)
        .env("ROMWRIGHT_LANGUAGE", language);
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
    (worker, provider)
}

#[test]
#[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
fn inferred_declarations_roundtrip_array_and_variadic_callback_pointers() {
    let root = std::env::temp_dir().join(format!(
        "romwright-prototype-declarations-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let core = romwright_core::Core::open(&root).unwrap();
    let db = core.store_handle().unwrap();
    let id = db
        .upsert_program(
            "types",
            "x86:LE:64:default",
            &romwright_model::Provenance {
                producer: "native declaration regression".into(),
                upstream_version: "test".into(),
            },
        )
        .unwrap();
    let address = Address::ram(0x400466);
    let proto: romwright_model::FuncProto = serde_json::from_value(serde_json::json!({
        "calling_convention": "__stdcall", "variadic": false, "no_return": false,
        "return_type": {"metatype": "ptr", "size": 8, "target": {"name": "int"}},
        "parameters": [
            {"ordinal": 0, "name": "rows", "data_type": {
                "metatype": "ptr", "size": 8, "target": {
                    "metatype": "array", "element_count": 4, "size": 16,
                    "target": {"name": "int"}
                }
            }},
            {"ordinal": 1, "name": "visit", "data_type": {
                "metatype": "ptr", "size": 8, "target": {
                    "metatype": "code", "prototype": {
                        "calling_convention": "__stdcall", "variadic": true, "no_return": false,
                        "return_type": {"name": "int"},
                        "parameters": [{"ordinal": 0, "name": "value", "data_type": {"name": "char"}}]
                    }
                }
            }}
        ]
    })).unwrap();
    core.persist_inferred_prototypes(
        "types",
        db.revision(id).unwrap(),
        &[(address.clone(), proto.clone())],
    )
    .unwrap();
    let stored = core.prototypes("types").unwrap().remove(0);
    let revision = db.revision(id).unwrap();
    let mut unknown = proto;
    unknown.return_type = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(
        core.persist_inferred_prototypes("types", revision, &[(address.clone(), unknown)])
            .is_err(),
        "an absent type must not be persisted as void"
    );
    assert_eq!(core.prototypes("types").unwrap(), vec![stored.clone()]);
    assert_eq!(db.revision(id).unwrap(), revision);
    drop(core);
    std::fs::remove_dir_all(root).unwrap();

    let (mut worker, mut provider) = worker_for_add(stored);
    worker
        .prepare_function(&mut provider, address.offset)
        .unwrap();
    let ram = provider.ram_space_index as u32;
    let raw = worker
        .decompile_at(&mut provider, ram, address.offset)
        .unwrap();
    let recovered = romwright_worker::decode_document_with_ram_space(&raw, Some(ram as u64))
        .prototype
        .unwrap();
    assert_eq!(recovered.return_type.metatype.as_deref(), Some("ptr"));
    assert_eq!(
        recovered
            .return_type
            .target
            .as_ref()
            .unwrap()
            .name
            .as_deref(),
        Some("int")
    );
    let array = recovered.parameters[0].data_type.target.as_ref().unwrap();
    assert_eq!(array.metatype.as_deref(), Some("array"));
    assert_eq!(array.element_count, Some(4));
    let callback = recovered.parameters[1]
        .data_type
        .target
        .as_ref()
        .unwrap()
        .prototype
        .as_ref()
        .unwrap();
    assert!(callback.variadic);
    assert_eq!(
        callback.parameters[0].data_type.name.as_deref(),
        Some("char")
    );
}

#[test]
#[ignore = "requires gcc, the built native decompiler and installed SLEIGH specifications"]
fn cold_callers_use_callee_arguments_without_parsing_unrelated_prototypes() {
    let root = std::env::temp_dir().join(format!(
        "romwright-cold-callee-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("original.c");
    let binary = root.join("original");
    std::fs::write(&source, "int callee(int a,int b){return a/b;}\nint caller(int a,int b){return callee(a,b)+1;}\nint main(void){return caller(9,3);}\n").unwrap();
    let compile = |source: &Path, target: &Path| {
        let output = std::process::Command::new("gcc")
            .args(["-O1", "-fno-inline", "-no-pie"])
            .arg(source)
            .arg("-o")
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    compile(&source, &binary);
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = romwright_core::session::RuntimeConfig::from_env();
    config.spec_root = repo.join(&config.spec_root);
    config.decompiler_path = repo.join(&config.decompiler_path);
    config.worker_path = env!("CARGO_BIN_EXE_romwright-worker").into();
    let core = romwright_core::Core::open_with_config(&root.join("project"), config).unwrap();
    core.import_native_with_signatures(
        &binary,
        "calls",
        &[],
        false,
        None,
        None,
        &romwright_core::native::keys::KeyStore::empty(),
    )
    .unwrap();
    let functions = core.functions("calls").unwrap();
    for (name, signature) in [
        ("caller", "int caller(int a, int b)"),
        ("callee", "int callee(int a, int b)"),
        ("main", "missing_type main(missing_type x)"),
    ] {
        let function = functions
            .iter()
            .find(|function| function.name == name)
            .unwrap();
        core.set_prototype(
            "calls",
            &PrototypeRow {
                function: function.entry.clone(),
                signature: signature.into(),
                calling_convention: None,
                return_type: None,
                provenance: FactProvenance {
                    kind: FactKind::Asserted,
                    source: "analyst".into(),
                    confidence: None,
                },
            },
        )
        .unwrap();
    }
    let caller = functions
        .iter()
        .find(|function| function.name == "caller")
        .unwrap();
    let doc = core
        .decompile_native_doc(&binary, &caller.entry, "calls", None)
        .unwrap();
    let emitted = romwright_core::emit_m2c::emit_doc(
        &doc,
        &romwright_core::emit_m2c::FuncInputs::default(),
        &romwright_core::emit_m2c::M2cOptions::default(),
    )
    .unwrap();
    let candidate = root.join("candidate.c");
    std::fs::write(&candidate, format!(
        "{}\nint callee(int a,int b){{return a/b;}}\nint main(void){{return caller(-7,2)!=-2 || caller(9,3)!=4;}}\n",
        emitted.text,
    )).unwrap();
    let executable = root.join("candidate");
    compile(&candidate, &executable);
    assert!(
        std::process::Command::new(executable)
            .status()
            .unwrap()
            .success()
    );
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
fn split_register_parameters_preserve_their_physical_locations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = romwright_core::session::RuntimeConfig::from_env();
    cfg.spec_root = root.join(&cfg.spec_root);
    cfg.decompiler_path = root.join(&cfg.decompiler_path);
    let (sla, specs_path, language_dir, language) =
        romwright_core::native_runtime::language_decompile_config(&cfg, "PowerPC:BE:32:default")
            .unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "romwright-paired-parameter-{}-{stamp}", std::process::id()
    ));
    // Public fixture: increment a 64-bit argument in r3:r4, carrying into r3.
    // llvm-mc: addic 4,4,1; addze 3,3; blr.
    let bytes: Vec<_> = [0x30840001u32, 0x7c630194, 0x4e800020]
        .into_iter().flat_map(u32::to_be_bytes).collect();
    std::fs::write(&path, bytes).unwrap();
    let mut provider = ProgramProvider::new(
        BinaryBacking::from_file(&path, None, 0x1000).unwrap(), vec![0x1000],
    );
    provider.load_language_info(&specs_path).unwrap();
    provider.function_names.insert(0x1000, "increment_pair".into());
    provider.function_sizes.insert(0x1000, 12);
    provider.prototypes.insert(0x1000, PrototypeRow {
        function: Address::ram(0x1000),
        signature: "ulonglong increment_pair(ulonglong value)".into(),
        calling_convention: None,
        return_type: Some("ulonglong".into()),
        provenance: FactProvenance {
            kind: FactKind::Asserted,
            source: "public 64-bit increment fixture".into(),
            confidence: None,
        },
    });
    let mut command = std::process::Command::new(&cfg.decompiler_path);
    command.env("ROMWRIGHT_SLA", &sla)
        .env("ROMWRIGHT_LANGUAGE_DIR", &language_dir)
        .env("ROMWRIGHT_LANGUAGE", &language);
    let mut worker = NativeWorker::launch(command).unwrap();
    let specs = romwright_worker::load_specs(&specs_path).unwrap();
    let shell = provider.function_shell().unwrap();
    worker.register_program_with_shell(
        &mut provider, &specs.0, &specs.1, &specs.2, &specs.3, &shell,
    ).unwrap();
    worker.set_action(&mut provider, "decompile", "").unwrap();
    worker.prepare_function(&mut provider, 0x1000).unwrap();
    let ram = provider.ram_space_index as u32;
    let raw = worker.decompile_at(&mut provider, ram, 0x1000).unwrap();
    let decoded = romwright_worker::decode_document_with_ram_space(&raw, Some(ram as u64));
    let ir = decoded.function_ir.expect("paired storage must not reject the function");
    let parameter = ir.high_variables.iter().filter_map(|high| high.symbol.as_ref())
        .find(|symbol| !symbol.pieces.is_empty()).expect("split-register parameter");
    assert_eq!(parameter.address, None, "a register pair is not a single address");
    assert_eq!(
        parameter.pieces.iter().map(|piece| (piece.space.as_str(), piece.offset, piece.size))
            .collect::<Vec<_>>(),
        vec![("register", 12, 4), ("register", 16, 4)],
        "the high and low halves must remain ordered and independently addressable"
    );
    std::fs::remove_file(path).unwrap();
}
