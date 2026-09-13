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
    let proto = romwright_worker::decode_document_with_ram_space(&recovered, Some(ram as u64)).prototype;
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
    let proto = romwright_worker::decode_document_with_ram_space(&asserted, Some(ram as u64)).prototype;
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
        romwright_core::native_runtime::language_decompile_config(&cfg, "x86:LE:64:default").unwrap();
    let address = prototype.function.offset;
    let mut provider = ProgramProvider::new(
        BinaryBacking::from_file(&root.join("tests/fixtures-src/tiny_bin"), 0x400000).unwrap(),
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
    drop(db);
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
