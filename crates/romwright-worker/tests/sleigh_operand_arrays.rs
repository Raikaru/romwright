//! SLEIGH sizes every parser state's operand array at 20 (`initialize(75,20)`),
//! and the Xenon `vsubuhm` constructor (Altivec; the same family as the other
//! VMX forms) has 27 operands. Indexing past the end overwrote the heap
//! neighbour's allocator header, so a long decompiler session died on a later
//! `free` (the `infer_prototypes` job on x360-black-ops-2: "corrupted size vs.
//! prev_size", "decompiler died"). Nothing fails at the overflow itself;
//! releasing the architecture, which frees every parser state, is where a
//! damaged header shows.

use romwright_worker::{BinaryBacking, NativeWorker, ProgramProvider};

/// Xenon, at 0x80003100: vsubuhm v1,v7,v6; blr
const CODE: [u8; 8] = [0x10, 0x27, 0x34, 0x40, 0x4e, 0x80, 0x00, 0x20];
const BASE: u64 = 0x8000_3100;

#[test]
#[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
fn instructions_with_more_than_twenty_operands_do_not_corrupt_the_heap() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = romwright_core::session::RuntimeConfig::from_env();
    cfg.spec_root = root.join(&cfg.spec_root);
    cfg.decompiler_path = root.join(&cfg.decompiler_path);
    let (sla, specs_path, language_dir, language) = romwright_core::native_runtime::language_decompile_config(
        &cfg,
        "PowerPC:BE:64:Xenon-32addr",
    )
    .unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "romwright-sleigh-operands-{}-{stamp}",
        std::process::id()
    ));
    std::fs::write(&path, CODE).unwrap();
    let mut provider = ProgramProvider::new(
        BinaryBacking::from_file(&path, None, BASE).unwrap(),
        vec![BASE],
    );
    provider.load_language_info(&specs_path).unwrap();
    provider.function_names.insert(BASE, "save_restore".into());
    provider.function_sizes.insert(BASE, CODE.len() as u64);
    let mut command = std::process::Command::new(&cfg.decompiler_path);
    command
        .env("ROMWRIGHT_SLA", &sla)
        .env("ROMWRIGHT_LANGUAGE_DIR", &language_dir)
        .env("ROMWRIGHT_LANGUAGE", &language)
        // Without the per-thread cache glibc validates a block's header on
        // every `free`, so a header the overflow overwrote fails here
        // rather than going unnoticed.
        .env("GLIBC_TUNABLES", "glibc.malloc.tcache_count=0");
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
    worker.prepare_function(&mut provider, BASE).unwrap();
    worker.decompile_at(&mut provider, ram, BASE).unwrap();
    std::fs::remove_file(path).unwrap();
    // Releasing the architecture frees every parser state.
    assert!(worker.deregister_program(&mut provider).unwrap());
}
