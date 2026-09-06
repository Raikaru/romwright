use lre_model::{Address, FactKind, FactProvenance, PrototypeRow};
use lre_worker::{BinaryBacking, NativeWorker, ProgramProvider};
use std::path::Path;

#[test]
#[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
fn inferred_targets_recover_but_assertions_remain_locked() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cfg = lre_core::session::RuntimeConfig::from_env();
    let (sla, specs_path, language_dir, language) =
        lre_core::native_runtime::language_decompile_config(&cfg, "x86:LE:64:default")
            .unwrap();
    let address = 0x400466;
    let mut provider = ProgramProvider::new(
        BinaryBacking::from_file(&root.join("tests/fixtures-src/tiny_bin"), 0x400000)
            .unwrap(),
        vec![address],
    );
    provider.load_language_info(&specs_path).unwrap();
    provider.function_names.insert(address, "add".into());
    provider.function_sizes.insert(address, 0x14);
    provider.prototypes.insert(address, PrototypeRow {
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
    let mut command = std::process::Command::new(&cfg.decompiler_path);
    command.env("VENTRIS_SLA", sla)
        .env("VENTRIS_LANGUAGE_DIR", language_dir)
        .env("VENTRIS_LANGUAGE", language);
    let mut worker = NativeWorker::launch(command).unwrap();
    let shell = provider.function_shell().unwrap();
    let specs = lre_worker::load_specs(&specs_path).unwrap();
    worker.register_program_with_shell(
        &mut provider, &specs.0, &specs.1, &specs.2, &specs.3, &shell,
    ).unwrap();
    worker.set_action(&mut provider, "decompile", "").unwrap();
    let ram = provider.ram_space_index as u32;
    worker.prepare_function(&mut provider, address).unwrap();
    let read = worker.decompile_at(&mut provider, ram, address).unwrap();
    let (tokens, proto) = lre_worker::decode_document_with_ram_space(&read, Some(ram as u64));
    assert_eq!(proto.unwrap().parameters.len(), 0);
    assert!(!tokens.iter().any(|token| token.text.contains("old_inferred_name")),
        "an inferred signature must not rename the function");

    worker.prepare_function_for_inference(&mut provider, address).unwrap();
    let recovered = worker.decompile_at(&mut provider, ram, address).unwrap();
    let (_, proto) = lre_worker::decode_document_with_ram_space(&recovered, Some(ram as u64));
    assert_eq!(proto.unwrap().parameters.len(), 2,
        "the previous inferred void-input lock must not freeze recovery");

    provider.prototypes.get_mut(&address).unwrap().provenance.kind = FactKind::Asserted;
    worker.prepare_function_for_inference(&mut provider, address).unwrap();
    let asserted = worker.decompile_at(&mut provider, ram, address).unwrap();
    let (_, proto) = lre_worker::decode_document_with_ram_space(&asserted, Some(ram as u64));
    assert_eq!(proto.unwrap().parameters.len(), 0,
        "recovery must preserve the analyst's zero-parameter assertion");
}
