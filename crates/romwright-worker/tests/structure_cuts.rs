//! The `structure` pass forces its unstructured edges into the native
//! structurer as gotos. That may never print more gotos than the same
//! function printed without the cuts (native structuring, then the Rust
//! structuring models -- which print this shape goto-free on their own).

use std::path::Path;

/// The control flow of pokeemerald's 0x080824fc: a switch whose cases 0 and
/// 2 jump into the tail of case 5 while the others break to a shared exit.
/// Our structurer cannot place the shared tail, so it virtualises every
/// `break` to the exit; forced, those printed as extra gotos.
const SOURCE: &str = r#"
volatile int flag;
int *volatile last;
__attribute__((noinline)) int poll(void) { return flag; }
__attribute__((noinline)) int finish(int value) { return flag + value; }
int dispatch(int *state) {
    int result;
    switch (state[0]) {
    case 0: poll(); state[1] = 1; goto tail;
    case 1: if (poll()) { state[0]++; flag = 1; } break;
    case 2: poll(); goto middle;
    case 3: if (++state[2] == 10) { poll(); state[0]++; } break;
    case 4: if (poll()) { if (poll()) state[0] = 5; else { state[2] = 0; state[0] = 3; } } break;
    case 5: middle: state[1] = state[0] + 1; tail: state[0] = state[1]; state[2] = 0; break;
    case 6: if (++state[2] > 5) { flag = 0; result = 1; goto out; } break;
    }
    result = 0;
out:
    last = state;
    return finish(result);
}
"#;

fn gotos(text: &str) -> usize {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|word| *word == "goto")
        .count()
}

#[test]
#[ignore = "requires gcc, the built native decompiler and installed SLEIGH specifications"]
fn structure_cuts_never_print_more_gotos_than_native_structuring() {
    let root = std::env::temp_dir().join(format!("romwright-structure-cuts-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("original.c");
    let binary = root.join("original");
    std::fs::write(&source, SOURCE).unwrap();
    let output = std::process::Command::new("gcc")
        .args(["-O1", "-nostdlib", "-fno-pie", "-no-pie", "-fno-asynchronous-unwind-tables", "-Wl,-e,dispatch"])
        .arg(&source).arg("-o").arg(&binary).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = romwright_core::session::RuntimeConfig::from_env();
    config.spec_root = repo.join(&config.spec_root);
    config.decompiler_path = repo.join(&config.decompiler_path);
    config.worker_path = env!("CARGO_BIN_EXE_romwright-worker").into();
    let core = romwright_core::Core::open_with_config(&root.join("project"), config).unwrap();
    core.import_native_with_signatures(&binary, "cuts", &[], false, None, None,
        &romwright_core::native::keys::KeyStore::empty()).unwrap();
    let entry = core.functions("cuts").unwrap().into_iter()
        .find(|function| function.name == "dispatch").unwrap().entry;
    let export = |transforms: &[&str]| {
        let outdir = root.join(if transforms.is_empty() { "stock" } else { "structured" });
        core.export_m2c(&binary, "cuts", &outdir, None, Some(entry.offset), &romwright_core::emit_m2c::M2cOptions {
            mark_irregular_flow: false,
            transforms: transforms.iter().map(|name| (*name).to_owned()).collect(),
            ..Default::default()
        }).unwrap();
        std::fs::read_to_string(outdir.join("dispatch.c")).unwrap()
    };
    let stock = export(&[]);
    let structured = export(&["structure"]);
    // Native structuring alone prints gotos here; the default structuring
    // models may remove all of them, and the cuts must not bring any back.
    assert!(gotos(&structured) <= gotos(&stock),
        "structure printed {} gotos, without cuts {}:\n{structured}", gotos(&structured), gotos(&stock));
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}
