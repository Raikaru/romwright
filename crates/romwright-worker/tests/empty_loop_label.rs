//! A loop whose condition the decompiler proves constant leaves a basic
//! block with no operations whose cover is two separate ranges (the loop's
//! test and its body merged by dead-code removal). The printer IR names every
//! leaf block's label, and `BlockBasic::getEntryAddr` has no address for such
//! a block: PrintC::emitLabel dereferenced the null space and killed
//! `ghidra_opt`, which aborted the program-wide `infer_prototypes` job
//! (gc-animal-crossing `FUN_80079a68`, x360-black-ops-2).

use romwright_worker::{BinaryBacking, NativeWorker, ProgramProvider};

/// Gekko, at 0x80079a68:
///   lis r3,-0x3400; lhz r0,0(r3); ori r0,r0,1; sth r0,0(r3); lhz r0,0(r3)
///   b L; H: lhz r0,0(r3); L: clrlwi. r0,r0,31; bf eq,H; blr
const CODE: [u8; 40] = [
    0x3c, 0x60, 0xcc, 0x00, 0xa0, 0x03, 0x00, 0x00, 0x60, 0x00, 0x00, 0x01, 0xb0, 0x03, 0x00, 0x00,
    0xa0, 0x03, 0x00, 0x00, 0x48, 0x00, 0x00, 0x08, 0xa0, 0x03, 0x00, 0x00, 0x54, 0x00, 0x07, 0xff,
    0x40, 0x82, 0xff, 0xf8, 0x4e, 0x80, 0x00, 0x20,
];
const BASE: u64 = 0x8007_9a68;

#[test]
#[ignore = "requires a ghidra_opt built with native/romwright_printir.hh and installed SLEIGH specifications"]
fn printer_ir_survives_an_empty_loop_block_with_two_ranges() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = romwright_core::session::RuntimeConfig::from_env();
    cfg.spec_root = root.join(&cfg.spec_root);
    cfg.decompiler_path = root.join(&cfg.decompiler_path);
    let (sla, specs_path, language_dir, language) = romwright_core::native_runtime::language_decompile_config(
        &cfg,
        "PowerPC:BE:32:Gekko_Broadway",
    )
    .unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "romwright-empty-loop-label-{}-{stamp}",
        std::process::id()
    ));
    std::fs::write(&path, CODE).unwrap();
    let mut provider = ProgramProvider::new(
        BinaryBacking::from_file(&path, None, BASE).unwrap(),
        vec![BASE],
    );
    provider.load_language_info(&specs_path).unwrap();
    provider.function_names.insert(BASE, "wait_flag".into());
    provider.function_sizes.insert(BASE, CODE.len() as u64);
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
    // Both the plain decompile and the recovery decompile the prototype job
    // runs print the IR; the worker must answer, not die.
    worker.prepare_function(&mut provider, BASE).unwrap();
    let raw = worker.decompile_at(&mut provider, ram, BASE).unwrap();
    worker
        .prepare_function_for_inference(&mut provider, BASE)
        .unwrap();
    let recovered = worker.decompile_at(&mut provider, ram, BASE).unwrap();
    std::fs::remove_file(path).unwrap();
    for raw in [raw, recovered] {
        let sections = romwright_worker::printc::sections(&raw).unwrap();
        let printc = sections.markup.expect("PrintC markup");
        let ours =
            romwright_worker::printc::reference(sections.printer_ir.expect("printer IR")).unwrap();
        assert_eq!(ours, printc);
    }
}
