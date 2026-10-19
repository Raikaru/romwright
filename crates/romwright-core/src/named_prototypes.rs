//! Library declarations applied by function name after the names are final.
//!
//! The import types what its own symbol table names (`store_import`), but a
//! 3DS image is stripped: its names arrive later, from `new-project --names`
//! (renames of the functions the import found), after that pass has run. This
//! module is the same declaration lookup (`qualified_prototypes::declared_qualified_for`,
//! the same table format as `library_types`) run over the names as they stand,
//! so the decompiler sees a callee's and a function's own signature under the
//! name its project gives it.
//!
//! The rows are inferred, with a provenance of their own: an assertion and a
//! prototype the image's own symbols or debug stream gave are never replaced,
//! and the decompiler's own recovery never refines what this wrote
//! (`types_infer::prototypes::protected`).
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use romwright_model::{AddressSpace, FactKind, PrototypeRow};

use crate::library_types::Table;

/// Provenance of the Nintendo CTR SDK declarations.
pub const CTR_SDK_SOURCE: &str = "library-prototypes:ctr-sdk";

/// The table a platform's images are typed from when `--prototypes` names none,
/// a file beside the C library table (`oracle/library-prototypes-v1/`).
pub fn platform_table(platform: &str) -> Option<(&'static str, &'static str)> {
    match platform {
        "3ds" => Some(("ctr_sdk.json", CTR_SDK_SOURCE)),
        _ => None,
    }
}

/// What one application did.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NamedPrototypeReport {
    /// The table the declarations came from.
    pub table: String,
    /// Functions whose name the table declares.
    pub named: usize,
    /// Prototypes written.
    pub applied: usize,
    /// Named functions left alone: an assertion or the image's own symbols already type them.
    pub held: usize,
    /// Named functions whose declaration names a type the language's parser does not have.
    pub unrepresentable: usize,
}

/// The rows for the functions `names` lists, and the account of what was left out.
pub fn rows_for(
    table: &Table,
    names: &[(u64, &str)],
    held: &HashSet<u64>,
    known_types: &HashSet<String>,
    source: &str,
) -> (Vec<PrototypeRow>, NamedPrototypeReport) {
    let mut report = NamedPrototypeReport { table: table.archive.clone(), ..Default::default() };
    let mut open: Vec<(u64, &str)> = Vec::new();
    for &(entry, name) in names {
        if !table.functions.contains_key(name) {
            continue;
        }
        report.named += 1;
        if held.contains(&entry) {
            report.held += 1;
        } else {
            open.push((entry, name));
        }
    }
    let applied = crate::qualified_prototypes::declared_qualified_for(table, open.iter().copied(), known_types);
    report.unrepresentable = open.len() - applied.len();
    let rows: Vec<PrototypeRow> = applied.iter().map(|prototype| prototype.to_prototype_row(source, known_types)).collect();
    report.applied = rows.len();
    (rows, report)
}

impl crate::Core {
    /// The default table file for `platform`, when the install carries it.
    pub fn platform_prototype_table(&self, platform: &str) -> Option<(PathBuf, &'static str)> {
        let (file, source) = platform_table(platform)?;
        let path = self.runtime_config().library_prototypes.with_file_name(file);
        path.is_file().then_some((path, source))
    }

    /// Types every function of `program` whose current name `table` declares,
    /// under provenance `source`.
    pub fn apply_named_prototypes(&self, program: &str, table: &Path, source: &str) -> crate::Result<NamedPrototypeReport> {
        let bad = |message: String| -> crate::CoreError { crate::native::ImportError::Bad(message).into() };
        let text = std::fs::read_to_string(table).map_err(|e| bad(format!("{}: {e}", table.display())))?;
        let declared: Table =
            serde_json::from_str(&text).map_err(|e| bad(format!("{}: not a prototype table: {e}", table.display())))?;
        let id = self.db.program_id(program)?;
        let language = self.db.program_language(id)?;
        let Some(known) = self.parser_types(&language) else {
            return Ok(NamedPrototypeReport { table: declared.archive, ..Default::default() });
        };
        let functions = self.db.functions(id)?;
        let held: HashSet<u64> = self
            .db
            .prototypes(id)?
            .into_iter()
            .filter(|row| row.provenance.kind == FactKind::Asserted || row.provenance.source.starts_with("native-import"))
            .map(|row| row.function.offset)
            .collect();
        let names: Vec<(u64, &str)> = functions
            .iter()
            .filter(|function| function.entry.space == AddressSpace::Ram)
            .map(|function| (function.entry.offset, function.name.as_str()))
            .collect();
        let (rows, report) = rows_for(&declared, &names, &held, &known, source);
        if !rows.is_empty() {
            let revision = self.db.revision(id)?;
            self.db.merge_inferred_prototypes(id, revision, &rows)?;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library_types::{Declaration, Parameter};

    fn declaration(return_type: &str, parameters: &[&str]) -> Declaration {
        Declaration {
            return_type: return_type.into(),
            varargs: false,
            parameters: parameters.iter().map(|t| Parameter { name: String::new(), data_type: (*t).into() }).collect(),
            scope: None,
            calling_convention: None,
            this_type: None,
        }
    }

    fn table() -> Table {
        Table {
            archive: "ctr".into(),
            archive_sha256: String::new(),
            functions: [
                ("nn_hid_CTR_PadReader_ReadLatest".to_string(), declaration("bool", &["void *", "uint *"])),
                ("nn_os_Odd".to_string(), declaration("bool", &["weirdtype *"])),
                ("nn_fs_Held".to_string(), declaration("int", &[])),
            ]
            .into_iter()
            .collect(),
        }
    }

    fn known() -> HashSet<String> {
        ["bool", "void", "int", "uint"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_function_named_after_a_declaration_is_typed_under_its_own_name() {
        let names = [
            (0x1000, "nn_hid_CTR_PadReader_ReadLatest"),
            (0x2000, "FUN_00002000"),
            (0x3000, "nn_os_Odd"),
            (0x4000, "nn_fs_Held"),
        ];
        let held: HashSet<u64> = [0x4000].into_iter().collect();
        let (rows, report) = rows_for(&table(), &names, &held, &known(), CTR_SDK_SOURCE);
        assert_eq!(
            report,
            NamedPrototypeReport { table: "ctr".into(), named: 3, applied: 1, held: 1, unrepresentable: 1 }
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].function.offset, 0x1000);
        assert_eq!(rows[0].signature, "bool nn_hid_CTR_PadReader_ReadLatest(void * param_1, uint * param_2)");
        assert_eq!(rows[0].provenance.source, CTR_SDK_SOURCE);
        assert_eq!(rows[0].provenance.kind, FactKind::Inferred);
    }

    #[test]
    fn only_the_3ds_has_a_default_table() {
        assert_eq!(platform_table("3ds"), Some(("ctr_sdk.json", CTR_SDK_SOURCE)));
        assert_eq!(platform_table("ps2"), None);
    }

    #[test]
    fn the_committed_ctr_table_parses_and_uses_only_the_arm_core_types() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/library-prototypes-v1").join(platform_table("3ds").unwrap().0);
        let table: Table = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let read_latest = &table.functions["nn_hid_CTR_TouchPanelReader_ReadLatest"];
        assert_eq!(read_latest.return_type, "bool");
        assert_eq!(read_latest.parameters.len(), 2);
        let specs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../native/specs/ARM-LE-32-v6");
        let mut known = crate::library_types::core_type_names(&specs).unwrap();
        known.extend(crate::library_types::language_base_types(&specs).into_keys());
        let names: Vec<(u64, &str)> = table.functions.keys().enumerate().map(|(i, name)| (i as u64, name.as_str())).collect();
        let (rows, report) = rows_for(&table, &names, &HashSet::new(), &known, CTR_SDK_SOURCE);
        assert_eq!(report.unrepresentable, 0, "a declaration names a type ARM:LE:32:v6 lacks");
        assert_eq!(rows.len(), table.functions.len());
    }
}
