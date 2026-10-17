//! P3.12 gate: two DS overlays that load at one address are two modules with
//! two namespaces. A rename in one must not reach the other; `locate` names
//! both with their module ids; a call followed from a caller resolves in the
//! caller's own overlay; resident memory (the static ARM9) is modelled once.
//!
//! The cartridge is synthetic (an OVT and a FAT over two overlay files that
//! share `0x02100000`), the overlay programs are built the way a container
//! import builds them (`nds_overlays::programs_for`), and the facts are
//! stored by `store_import`, so the test runs on a CI box with no Ghidra and
//! no ROM.

use romwright_core::native::nds_overlays::{self, FAT_OFFSET_OFF, OVT_OFFSET_OFF};
use romwright_core::native::{Mapping, NativeFunction, NativeImport, NativeXref, store_import};
use romwright_core::Core;
use romwright_model::Address;

const LANGUAGE: &str = "ARM:LE:32:v5t";
const WINDOW: u64 = 0x0210_0000;
/// Both overlays hold a function here...
const SHARED_FUNCTION: u64 = WINDOW + 0x10;
/// ...and a caller of it at different places.
const CALLER_A: u64 = WINDOW + 0x20;
const CALLER_B: u64 = WINDOW + 0x30;
/// A resident function of the static ARM9, called from overlay A.
const RESIDENT: u64 = 0x0200_0040;

fn words(data: &mut [u8], at: usize, words: &[u32]) {
    for (index, word) in words.iter().enumerate() {
        data[at + index * 4..at + index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

/// Two 0x80-byte overlays, ids 3 and 9, both loaded at `WINDOW`, stored at
/// 0x4300 and 0x4400 in the ROM.
fn cartridge() -> Vec<u8> {
    let mut data = vec![0u8; 0x5000];
    words(&mut data, FAT_OFFSET_OFF, &[0x4240, 16]);
    words(&mut data, OVT_OFFSET_OFF, &[0x4200, 64]);
    words(&mut data, 0x4200, &[3, WINDOW as u32, 0x80, 0x10, 0, 0, 0, 0]);
    words(&mut data, 0x4220, &[9, WINDOW as u32, 0x80, 0, 0, 0, 1, 0]);
    words(&mut data, 0x4240, &[0x4300, 0x4380, 0x4400, 0x4480]);
    data[0x4300..0x4380].fill(0xAA);
    data[0x4400..0x4480].fill(0xBB);
    data
}

fn function(entry: u64, name: &str) -> NativeFunction {
    NativeFunction { entry, name: name.into(), size: 0x10 }
}

/// The project: `game.arm9`, `game.ov3`, `game.ov9`.
fn project(test: &str) -> (Core, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("romwright-module-isolation-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let core = Core::open(&dir).unwrap();
    let db = romwright_db::ProjectDb::open(&dir.join("project.sqlite")).unwrap();

    let data = cartridge();
    let (mut programs, refused) = nds_overlays::programs_for(&data, &nds_overlays::parse(&data), LANGUAGE);
    assert!(refused.is_empty());
    assert_eq!(programs.len(), 2);
    for (name, import) in &mut programs {
        // The same address, the same default name in both: only the module
        // can tell them apart.
        import.functions.push(function(SHARED_FUNCTION, "FUN_02100010"));
        match name.as_str() {
            "ov3" => {
                import.functions.push(function(CALLER_A, "FUN_02100020"));
                import.xrefs.push(NativeXref::new(CALLER_A + 4, SHARED_FUNCTION, "CALL"));
                // Resident code is not in this program: the edge leaves it.
                import.xrefs.push(NativeXref::new(CALLER_A + 8, RESIDENT, "CALL"));
            }
            "ov9" => {
                import.functions.push(function(CALLER_B, "FUN_02100030"));
                import.xrefs.push(NativeXref::new(CALLER_B + 4, SHARED_FUNCTION, "CALL"));
            }
            other => panic!("unexpected overlay program {other}"),
        }
    }
    let arm9 = NativeImport {
        language: LANGUAGE.into(),
        format: "nds".into(),
        mapping_names: vec!["arm9".into()],
        mappings: vec![Mapping { vaddr: 0x0200_0000, size: 0x100, file_off: 0x4000, flags: 7, bytes: vec![0; 0x100] }],
        functions: vec![function(RESIDENT, "FUN_02000040")],
        symbol_named: vec![RESIDENT],
        ..Default::default()
    };
    store_import(&db, "game.arm9", &arm9, None).unwrap();
    for (name, import) in &mut programs {
        // Named entries are declared, so the store's call-only retraction of
        // unproven ARM entries keeps them.
        import.symbol_named = import.functions.iter().map(|f| f.entry).collect();
        store_import(&db, &format!("game.{name}"), import, None).unwrap();
    }
    (core, dir)
}

fn name_at(core: &Core, program: &str, entry: u64) -> String {
    core.function_at(program, entry).unwrap().unwrap_or_else(|| panic!("{program} has no function at {entry:#x}")).name
}

#[test]
fn a_rename_in_one_overlay_is_invisible_in_the_overlay_at_the_same_address() {
    let (core, dir) = project("rename");
    let shared = Address::ram(SHARED_FUNCTION);

    // Before: both overlays answer with the same name at the same address.
    assert_eq!(name_at(&core, "game.ov3", SHARED_FUNCTION), "FUN_02100010");
    assert_eq!(name_at(&core, "game.ov9", SHARED_FUNCTION), "FUN_02100010");
    let before_b = (format!("{:?}", core.functions("game.ov9").unwrap()), core.symbols("game.ov9").unwrap().len());
    let revision_b = core.programs().unwrap().into_iter().find(|row| row.program == "game.ov9").unwrap().revision;

    core.rename_command("game.ov3", &shared, "overlay_three_helper").unwrap();

    assert_eq!(name_at(&core, "game.ov3", SHARED_FUNCTION), "overlay_three_helper");
    assert_eq!(name_at(&core, "game.ov9", SHARED_FUNCTION), "FUN_02100010", "B saw A's rename");
    let after_b = (format!("{:?}", core.functions("game.ov9").unwrap()), core.symbols("game.ov9").unwrap().len());
    assert_eq!(before_b.0, after_b.0, "B's functions moved");
    assert_eq!(before_b.1, after_b.1, "B's symbols moved");
    let revision_after = core.programs().unwrap().into_iter().find(|row| row.program == "game.ov9").unwrap().revision;
    assert_eq!(revision_b, revision_after, "B's store revision moved");
    // The resident image never held the name either.
    assert_eq!(name_at(&core, "game.arm9", RESIDENT), "FUN_02000040");

    // And the other way round, then undo restores A alone.
    core.rename_command("game.ov9", &shared, "overlay_nine_helper").unwrap();
    assert_eq!(name_at(&core, "game.ov3", SHARED_FUNCTION), "overlay_three_helper");
    assert_eq!(name_at(&core, "game.ov9", SHARED_FUNCTION), "overlay_nine_helper");
    core.undo_last("game.ov9").unwrap();
    assert_eq!(name_at(&core, "game.ov9", SHARED_FUNCTION), "FUN_02100010");
    assert_eq!(name_at(&core, "game.ov3", SHARED_FUNCTION), "overlay_three_helper");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn locate_names_every_overlay_at_an_address_with_its_module_id() {
    let (core, dir) = project("locate");
    let db = romwright_db::ProjectDb::open(&dir.join("project.sqlite")).unwrap();

    let rows = core.locate(&Address::ram(SHARED_FUNCTION)).unwrap();
    let mut found: Vec<(&str, Option<&str>, Option<i64>)> =
        rows.iter().map(|row| (row.program.as_str(), row.module.as_deref(), row.module_id)).collect();
    found.sort();
    assert_eq!(found.len(), 2, "the window is held by exactly the two overlays: {found:?}");
    assert_eq!((found[0].0, found[0].1), ("game.ov3", Some("ov3")));
    assert_eq!((found[1].0, found[1].1), ("game.ov9", Some("ov9")));
    let (id3, id9) = (found[0].2.expect("ov3 has a module id"), found[1].2.expect("ov9 has a module id"));
    assert_ne!(id3, id9, "two overlays, one module id");
    for row in &rows {
        assert_eq!(row.function.as_deref(), Some("FUN_02100010"));
    }

    // The ids are the rows' real ids, and the rows carry real file bytes.
    let modules = |program: &str| db.modules(db.program_id(program).unwrap()).unwrap();
    let (m3, m9) = (modules("game.ov3"), modules("game.ov9"));
    assert_eq!((m3.len(), m9.len()), (1, 1));
    assert_eq!((m3[0].module_id, m9[0].module_id), (id3, id9));
    assert_eq!((m3[0].name.as_str(), m3[0].kind.as_str()), ("ov3", "overlay"));
    assert_eq!((m3[0].file_id.as_str(), m9[0].file_id.as_str()), ("0", "1"));
    assert_eq!((m3[0].file_off, m9[0].file_off), (0x4300, 0x4400));
    assert_eq!((m3[0].size, m9[0].size), (0x90, 0x80));

    // Resident memory is modelled once: only the static image maps it.
    let resident = core.locate(&Address::ram(RESIDENT)).unwrap();
    assert_eq!(resident.iter().map(|row| row.program.as_str()).collect::<Vec<_>>(), ["game.arm9"]);
    // The static module's row carries the cartridge offset of its bytes.
    let arm9 = modules("game.arm9");
    assert_eq!((arm9.len(), arm9[0].file_off), (1, 0x4000));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn following_a_call_from_an_overlay_resolves_inside_that_overlay() {
    let (core, dir) = project("follow");
    let shared = Address::ram(SHARED_FUNCTION);
    core.rename_command("game.ov3", &shared, "overlay_three_helper").unwrap();

    for (program, caller, other) in [("game.ov3", CALLER_A, "game.ov9"), ("game.ov9", CALLER_B, "game.ov3")] {
        // The call out of the caller...
        let calls: Vec<_> = core
            .xrefs_from(program, &Address::ram(caller + 4))
            .unwrap()
            .into_iter()
            .filter(|xref| xref.kind == "CALL")
            .collect();
        assert_eq!(calls.len(), 1, "{program}: the caller's call");
        let target = calls[0].to.clone();
        assert_eq!(target, shared);
        // ...lands in a function of the same program, whose name is that
        // program's own, and whose callers are that program's alone.
        let callee = core.function_at(program, target.offset).unwrap().expect("callee");
        let expected = if program == "game.ov3" { "overlay_three_helper" } else { "FUN_02100010" };
        assert_eq!(callee.name, expected, "{program}: follow reached the wrong overlay");
        let callers: Vec<u64> = core.xrefs_to(program, &target).unwrap().iter().map(|xref| xref.from.offset).collect();
        assert_eq!(callers, [caller + 4], "{program}: callers of the shared address");
        let foreign: Vec<u64> = core.xrefs_to(other, &target).unwrap().iter().map(|xref| xref.from.offset).collect();
        assert!(!foreign.contains(&(caller + 4)), "{other} holds {program}'s call");
    }

    // A call into resident memory leaves the overlay's program: it neither
    // lands on an overlay function nor appears in the other overlay.
    let resident_call = core.xrefs_from("game.ov3", &Address::ram(CALLER_A + 8)).unwrap();
    assert_eq!(resident_call.len(), 1);
    assert_eq!(resident_call[0].to, Address::ram(RESIDENT));
    assert!(core.function_at("game.ov3", RESIDENT).unwrap().is_none());
    assert!(core.xrefs_from("game.ov9", &Address::ram(CALLER_A + 8)).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}
