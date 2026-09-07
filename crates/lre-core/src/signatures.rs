//! Applying signature databases to a stored program.
//!
//! A match is a name claim backed by bytes: the window at a function's entry
//! satisfies a record's mask. Claims are inferred facts with their package and
//! license, they never overwrite a name another producer already supplied, and
//! two databases claiming different names for one function name nothing.
use crate::native::{self, ImportError};
use lre_sig::{MatchIndex, Outcome, SignatureDb, matcher};
use std::path::Path;

/// One owner for every match this pass publishes; each row keeps the package.
pub const SOURCE: &str = "signature-match";

/// Counts from one pass. Numbers, not adjectives.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SignatureReport {
    pub databases: usize,
    pub records: usize,
    pub functions: usize,
    pub matched: usize,
    /// Functions renamed from a generated name by a match.
    pub renamed: usize,
    /// Functions where databases disagreed, so no name was written.
    pub conflicts: usize,
    /// Functions whose entry window is not fully mapped.
    pub unmapped: usize,
    pub revision: u64,
}

fn load(paths: &[std::path::PathBuf]) -> crate::Result<Vec<SignatureDb>> {
    let mut databases = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = std::fs::read(path)?;
        databases.push(SignatureDb::decode(&bytes).map_err(|error| {
            ImportError::Bad(format!("{}: {error}", path.display()))
        })?);
    }
    Ok(databases)
}

impl crate::Core {
    pub fn signature_matches(
        &self,
        program: &str,
    ) -> crate::Result<Vec<lre_model::SignatureMatchRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.signature_matches(id)?)
    }

    /// Matches every stored function's entry window against `databases` and
    /// publishes the surviving name claims.
    pub fn apply_signatures(
        &self,
        binary: &Path,
        program: &str,
        databases: &[std::path::PathBuf],
    ) -> crate::Result<SignatureReport> {
        use lre_model::{Address, AddressSpace, FactKind, FactProvenance, SignatureMatchRow};
        let databases = load(databases)?;
        let index = MatchIndex::build(&databases);
        let id = self.db.program_id(program)?;
        let language = self.db.program_language(id)?;
        let import = native::parse_native(&std::fs::read(binary)?)?;
        if import.language != language {
            return Err(
                ImportError::Bad("signature input and stored language differ".into()).into(),
            );
        }
        let mut report = SignatureReport {
            databases: databases.len(),
            records: index.records(),
            ..Default::default()
        };
        let mut functions = self.db.functions(id)?;
        let mut rows = Vec::new();
        let mut renamed = Vec::new();
        for function in functions.iter() {
            if function.entry.space != AddressSpace::Ram {
                continue;
            }
            report.functions += 1;
            let entry = function.entry.offset;
            let Some(window) = import.mappings.iter().find_map(|mapping| {
                let offset = entry.checked_sub(mapping.vaddr)? as usize;
                (mapping.flags & 4 != 0).then(|| mapping.bytes.get(offset..))?
            }) else {
                report.unmapped += 1;
                continue;
            };
            match index.lookup(&language, window, function.size as usize) {
                Outcome::Unmatched => {}
                Outcome::Conflict { .. } => report.conflicts += 1,
                Outcome::Named(signature) => {
                    report.matched += 1;
                    rows.push(SignatureMatchRow {
                        function: Address::ram(entry),
                        name: signature.name.clone(),
                        package: signature.package.clone(),
                        license: signature.license.clone(),
                        compared_bytes: signature.compared_bytes() as u64,
                        confidence: matcher::confidence(signature),
                        provenance: FactProvenance {
                            kind: FactKind::Inferred,
                            source: SOURCE.into(),
                            confidence: Some(matcher::confidence(signature)),
                        },
                    });
                    // A generated name carries no information; anything else
                    // came from a symbol table or an analyst and stays.
                    if function.name.starts_with("FUN_") {
                        renamed.push((entry, signature.name.clone()));
                    }
                }
            }
        }
        self.db.replace_signature_matches(id, SOURCE, &rows)?;
        if !renamed.is_empty() {
            for (entry, name) in renamed {
                if let Some(function) = functions
                    .iter_mut()
                    .find(|function| function.entry.offset == entry)
                {
                    function.name = name;
                    report.renamed += 1;
                }
            }
            self.db.replace_functions(id, &functions)?;
        }
        report.revision = self.db.revision(id)?;
        Ok(report)
    }

    /// Native import, then the signature pass when databases are supplied.
    pub fn import_native_with_signatures(
        &self,
        binary: &Path,
        name: &str,
        databases: &[std::path::PathBuf],
    ) -> crate::Result<(lre_model::ProgramSummary, Option<SignatureReport>)> {
        let summary = self.import_native(binary, name)?;
        if databases.is_empty() {
            return Ok((summary, None));
        }
        let report = self.apply_signatures(binary, name, databases)?;
        Ok((summary, Some(report)))
    }
}
