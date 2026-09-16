use romwright_model::{FactKind, FactProvenance, PrototypeRow};
use std::path::Path;

#[test]
#[ignore = "requires gcc, the built native decompiler and installed SLEIGH specifications"]
fn partial_and_whole_storage_share_a_compilable_translation_unit() {
    let root = std::env::temp_dir().join(format!("romwright-storage-export-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("original.c");
    let binary = root.join("original");
    std::fs::write(&source, r#"
union { unsigned long long whole; unsigned int words[2]; } storage;
union { unsigned char bytes[12]; unsigned int words[3]; } window;
unsigned int read_word(void) { return storage.words[1]; }
void write_word(unsigned int value) { storage.words[0] = value; }
unsigned long long read_all(void) { return storage.whole; }
void write_window(unsigned int value) { window.words[2] = value; }
unsigned int read_window(void) { return window.words[2]; }
unsigned char *window_address(void) { return window.bytes; }
unsigned int grouped(unsigned int value, unsigned int other) {
    return ((value + 1U) & 0xffffU) ^ ((other + 3U) << 2);
}
"#).unwrap();
    let output = std::process::Command::new("gcc")
        .args(["-O1", "-nostdlib", "-fno-pie", "-no-pie", "-fno-asynchronous-unwind-tables", "-Wl,-e,read_word"])
        .arg(&source).arg("-o").arg(&binary).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = romwright_core::session::RuntimeConfig::from_env();
    config.spec_root = repo.join(&config.spec_root);
    config.decompiler_path = repo.join(&config.decompiler_path);
    config.worker_path = env!("CARGO_BIN_EXE_romwright-worker").into();
    let core = romwright_core::Core::open_with_config(&root.join("project"), config).unwrap();
    core.import_native_with_signatures(&binary, "storage", &[], false, None, None,
        &romwright_core::native::keys::KeyStore::empty()).unwrap();
    let functions = core.functions("storage").unwrap();
    for (name, signature) in [
        ("read_word", "uint read_word(void)"),
        ("write_word", "void write_word(uint value)"),
        ("read_all", "ulonglong read_all(void)"),
        ("write_window", "void write_window(uint value)"),
        ("read_window", "uint read_window(void)"),
        ("window_address", "byte *window_address(void)"),
        ("grouped", "uint grouped(uint value, uint other)"),
    ] {
        let function = functions.iter().find(|function| function.name == name).unwrap();
        core.set_prototype("storage", &PrototypeRow {
            function: function.entry.clone(), signature: signature.into(),
            calling_convention: None, return_type: None,
            provenance: FactProvenance { kind: FactKind::Asserted, source: "fixture declaration".into(), confidence: None },
        }).unwrap();
    }
    let splits = [romwright_core::native::linkmap::SplitExtent {
        tu: "storage_unit.c".into(), start: 0, end: u64::MAX,
        name: ".text".into(), kind: "code".into(),
    }];
    core.export_m2c(&binary, "storage", &root, Some(&splits), None,
        &romwright_core::emit_m2c::M2cOptions::default()).unwrap();
    let emitted = std::fs::read_to_string(root.join("storage_unit.c")).unwrap();
    let candidate = root.join("candidate.c");
    std::fs::write(&candidate, format!("{emitted}\n{}", r#"
#include <string.h>
__typeof__(storage) storage;
__typeof__(window) window;
int main(void) {
    unsigned long long initial = 0x1122334455667788ULL, expected;
    unsigned int words[2], value = 0xabcdef01U;
    unsigned int cases[] = {0, 0xffffffffU, 0x7fffffffU, 0x13579bdfU};
    unsigned int i, j;
    memcpy(&storage, &initial, sizeof initial);
    memcpy(words, &initial, sizeof words);
    if (read_word() != words[1]) return 1;
    write_word(value);
    words[0] = value;
    memcpy(&expected, words, sizeof expected);
    if (read_all() != expected) return 2;
    write_window(value);
    if (read_window() != value) return 3;
    if ((void *)window_address() != (void *)&window) return 4;
    memcpy(&value, window_address() + 8, sizeof value);
    if (value != 0xabcdef01U) return 5;
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
            if (grouped(cases[i], cases[j]) !=
                (((cases[i] + 1U) & 0xffffU) ^ ((cases[j] + 3U) << 2))) return 6;
    return 0;
}
"#)).unwrap();
    let executable = root.join("candidate");
    let compiled = std::process::Command::new("gcc")
        .args(["-std=gnu89", "-O2", "-fstrict-aliasing", "-Wall", "-Werror", "-fsanitize=undefined", "-fsanitize-undefined-trap-on-error"])
        .arg(&candidate).arg("-o").arg(&executable).output().unwrap();
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
    assert!(std::process::Command::new(&executable).status().unwrap().success());
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires clang/lld, qemu-arm, the built native decompiler and installed SLEIGH specifications"]
fn call_result_truncation_survives_export_and_recompilation() {
    let root = std::env::temp_dir().join(format!("romwright-call-width-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir(&root).unwrap();
    let original = root.join("original.c");
    let runtime = root.join("runtime.s");
    let binary = root.join("original");
    std::fs::write(&original, "extern unsigned int wide(void);\nunsigned int narrow(void) { return (unsigned char)wide(); }\n").unwrap();
    std::fs::write(&runtime, r#"
.syntax unified
.arm
.text
.global _start
.type _start,%function
_start:
    bl narrow
    cmp r0, #0xab
    moveq r0, #0
    movne r0, #1
    mov r7, #1
    svc #0
.size _start,.-_start
.global wide
.type wide,%function
wide:
    ldr r0, =0x123456ab
    bx lr
.size wide,.-wide
"#).unwrap();
    let compile = |source: &Path, output: &Path| {
        let result = std::process::Command::new("clang")
            .args(["--target=armv4t-none-eabi", "-marm", "-O1", "-nostdlib",
                "-fuse-ld=lld", "-Wl,-e,_start", "-Wl,-Ttext=0x10000"])
            .arg(source).arg(&runtime).arg("-o").arg(output).output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    };
    compile(&original, &binary);
    assert!(std::process::Command::new("qemu-arm").arg(&binary).status().unwrap().success());
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = romwright_core::session::RuntimeConfig::from_env();
    config.spec_root = repo.join(&config.spec_root);
    config.decompiler_path = repo.join(&config.decompiler_path);
    config.worker_path = env!("CARGO_BIN_EXE_romwright-worker").into();
    let core = romwright_core::Core::open_with_config(&root.join("project"), config).unwrap();
    core.import_native_with_signatures(&binary, "call_width", &[], false, None, None,
        &romwright_core::native::keys::KeyStore::empty()).unwrap();
    let entry = core.functions("call_width").unwrap().into_iter()
        .find(|function| function.name == "narrow").unwrap().entry;
    core.set_prototype("call_width", &PrototypeRow {
        function: entry.clone(), signature: "uint narrow(void)".into(),
        calling_convention: None, return_type: None,
        provenance: FactProvenance { kind: FactKind::Asserted, source: "fixture declaration".into(), confidence: None },
    }).unwrap();
    core.export_m2c(&binary, "call_width", &root, None, Some(entry.offset),
        &romwright_core::emit_m2c::M2cOptions::default()).unwrap();
    let candidate = root.join("candidate");
    compile(&root.join("narrow.c"), &candidate);
    let result = std::process::Command::new("qemu-arm").arg(&candidate).status().unwrap();
    assert!(result.success(), "recompiled caller lost its low-byte projection: {result}");
    let reference = root.join("reference.o");
    let compiled = std::process::Command::new("clang")
        .args(["--target=armv4t-none-eabi", "-marm", "-O1", "-c"])
        .arg(&original).arg("-o").arg(&reference).output().unwrap();
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
    let scratch = root.join("scratch");
    core.export_scratch(&binary, "call_width", entry.offset, &scratch,
        &romwright_core::matching::ScratchExportOptions {
            compiler: "agbcc", compiler_flags: "-O2",
            target_object: Some(&reference), context: None,
        }).unwrap();
    // A consumer must still be able to resolve the reference object's external
    // call. A text-byte dump without its relocation/symbol tables cannot link.
    let exported_reference = root.join("exported-reference");
    compile(&scratch.join("target.o"), &exported_reference);
    assert!(std::process::Command::new("qemu-arm").arg(&exported_reference).status().unwrap().success());
    // Exercise the actual API scalar fields, not an unrelated sidecar source.
    let fields: serde_json::Value = serde_json::from_slice(&std::fs::read(scratch.join("scratch.json")).unwrap()).unwrap();
    let received_source = root.join("received.c");
    std::fs::write(&received_source, format!("{}\n{}", fields["context"].as_str().unwrap(),
        fields["source_code"].as_str().unwrap())).unwrap();
    let received = root.join("received");
    compile(&received_source, &received);
    assert!(std::process::Command::new("qemu-arm").arg(&received).status().unwrap().success());
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires gcc, the built native decompiler and installed SLEIGH specifications"]
fn asserted_qualifiers_survive_own_and_callee_exports() {
    let root = std::env::temp_dir().join(format!("romwright-qualifier-export-{}-{}",
        std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("original.c");
    let binary = root.join("original");
    std::fs::write(&source, r#"
__attribute__((noinline)) unsigned char read_byte(const volatile unsigned char *data) { return *data; }
unsigned int read_pair(const unsigned char *input) { return read_byte(input) + read_byte(input + 1); }
int unrelated(int value) { return value; }
"#).unwrap();
    let compiled = std::process::Command::new("gcc")
        .args(["-O1", "-nostdlib", "-fno-pie", "-no-pie", "-fno-asynchronous-unwind-tables", "-Wl,-e,read_pair"])
        .arg(&source).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = romwright_core::session::RuntimeConfig::from_env();
    config.spec_root = repo.join(&config.spec_root);
    config.decompiler_path = repo.join(&config.decompiler_path);
    config.worker_path = env!("CARGO_BIN_EXE_romwright-worker").into();
    let core = romwright_core::Core::open_with_config(&root.join("project"), config).unwrap();
    core.import_native_with_signatures(&binary, "qualifiers", &[], false, None, None,
        &romwright_core::native::keys::KeyStore::empty()).unwrap();
    let functions = core.functions("qualifiers").unwrap();
    for (name, signature) in [
        ("read_byte", "byte read_byte(const volatile byte *data)"),
        ("read_pair", "uint read_pair(const byte *input)"),
        ("unrelated", "unused malformed prototype {"),
    ] {
        let function = functions.iter().find(|function| function.name == name).unwrap();
        core.set_prototype("qualifiers", &PrototypeRow {
            function: function.entry.clone(), signature: signature.into(),
            calling_convention: None, return_type: None,
            provenance: FactProvenance { kind: FactKind::Asserted, source: "fixture declaration".into(), confidence: None },
        }).unwrap();
    }
    let entry = functions.iter().find(|function| function.name == "read_pair").unwrap().entry.offset;
    core.export_m2c(&binary, "qualifiers", &root, None, Some(entry),
        &romwright_core::emit_m2c::M2cOptions::default()).unwrap();
    let emitted = std::fs::read_to_string(root.join("read_pair.c")).unwrap();
    let candidate = root.join("candidate.c");
    std::fs::write(&candidate, format!(r#"
unsigned char read_byte(const volatile unsigned char *);
unsigned int read_pair(const unsigned char *);
{emitted}
unsigned char read_byte(const volatile unsigned char *data) {{ return *data; }}
int main(void) {{
    const unsigned char values[] = {{7, 250, 0, 255}};
    return read_pair(values) != 257 || read_pair(values + 2) != 255;
}}
"#)).unwrap();
    let executable = root.join("candidate");
    let compiled = std::process::Command::new("gcc")
        .args(["-std=c11", "-O2", "-Wall", "-Werror"])
        .arg(&candidate).arg("-o").arg(&executable).output().unwrap();
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
    assert!(std::process::Command::new(&executable).status().unwrap().success());
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}
