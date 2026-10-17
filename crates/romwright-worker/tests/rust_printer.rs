//! The Rust C printer, without structuring models, reproduces PrintC's
//! markup byte for byte on a live decompile (docs/printer-ir.md). The full
//! differential is benchmarks/printer_diff.py; this pins one loop with an
//! if/else.

#[test]
#[ignore = "requires a ghidra_opt built with native/romwright_printir.hh and installed SLEIGH specifications"]
fn rust_printer_matches_printc_on_a_loop_with_branches() {
    use romwright_worker::{BinaryBacking, NativeWorker, ProgramProvider};
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
        std::env::temp_dir().join(format!("romwright-printer-{}-{stamp}", std::process::id()));
    // int f(int n) { int s = 0; for (int i = 0; i < n; i++) { if (i & 1) s += i; else s -= 1; } return s; }
    let code = [
        0x31, 0xc0, 0x31, 0xc9, 0x39, 0xf9, 0x7d, 0x10, 0xf6, 0xc1, 0x01, 0x74, 0x04, 0x01, 0xc8,
        0xeb, 0x03, 0x83, 0xe8, 0x01, 0xff, 0xc1, 0xeb, 0xec, 0xc3,
    ];
    std::fs::write(&path, code).unwrap();
    let mut provider = ProgramProvider::new(
        BinaryBacking::from_file(&path, None, 0x1000).unwrap(),
        vec![0x1000],
    );
    provider.load_language_info(&specs_path).unwrap();
    provider
        .function_names
        .insert(0x1000, "alternating_sum".into());
    provider.function_sizes.insert(0x1000, code.len() as u64);
    let mut command = std::process::Command::new(&cfg.decompiler_path);
    command
        // PrintC's markup, the reference, exists only when Ghidra structures the function.
        .env("ROMWRIGHT_NATIVE_STRUCTURE", "1")
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
    std::fs::remove_file(path).unwrap();
    let sections = romwright_worker::printc::sections(&raw).unwrap();
    let printc = sections.markup.expect("PrintC markup");
    let ours =
        romwright_worker::printc::reference(sections.printer_ir.expect("printer IR")).unwrap();
    let text: String = romwright_worker::decode_tokens(&ours)
        .iter()
        .map(|token| token.text.as_str())
        .collect();
    assert!(text.contains("alternating_sum"), "{text}");
    assert_eq!(ours, printc, "{text}");
}
