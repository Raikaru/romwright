//! Import diagnostics (schema v30): what an import could not do, stored
//! with the program so a restored cache entry reports the same warnings
//! as the analysis that produced it.

use romwright_model::{DiagnosticSeverity, ImportDiagnostic};
use rusqlite::params;

use crate::{ProgramId, ProjectDb, Result};

fn severity_cell(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Partial => "partial",
        DiagnosticSeverity::Degraded => "degraded",
    }
}

impl ProjectDb {
    /// Replaces every import diagnostic for `program`, keeping their order.
    pub fn replace_import_diagnostics(
        &self,
        program: ProgramId,
        rows: &[ImportDiagnostic],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM import_diagnostics WHERE program_id = ?1",
            params![program.0],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO import_diagnostics (program_id, ordinal, severity, stage, message)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for (ordinal, row) in rows.iter().enumerate() {
                insert.execute(params![
                    program.0,
                    ordinal as i64,
                    severity_cell(row.severity),
                    row.stage,
                    row.message,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The import diagnostics stored for `program`, in the order recorded.
    pub fn import_diagnostics(&self, program: ProgramId) -> Result<Vec<ImportDiagnostic>> {
        let mut stmt = self.conn.prepare(
            "SELECT severity, stage, message FROM import_diagnostics
             WHERE program_id = ?1 ORDER BY ordinal",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                let severity: String = row.get(0)?;
                Ok(ImportDiagnostic {
                    severity: match severity.as_str() {
                        "info" => DiagnosticSeverity::Info,
                        "partial" => DiagnosticSeverity::Partial,
                        _ => DiagnosticSeverity::Degraded,
                    },
                    stage: row.get(1)?,
                    message: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_diagnostics_roundtrip_in_order_and_replace() {
        let db = ProjectDb::open_in_memory().unwrap();
        let prov = romwright_model::Provenance {
            producer: "test".into(),
            upstream_version: "0".into(),
        };
        let id = db.upsert_program("p", "x86:LE:64:default", &prov).unwrap();
        let rows = vec![
            ImportDiagnostic {
                severity: DiagnosticSeverity::Partial,
                stage: "switch".into(),
                message: "0x1000: bad address".into(),
            },
            ImportDiagnostic {
                severity: DiagnosticSeverity::Degraded,
                stage: "references".into(),
                message: "console did not start".into(),
            },
        ];
        db.replace_import_diagnostics(id, &rows).unwrap();
        assert_eq!(db.import_diagnostics(id).unwrap(), rows);
        db.replace_import_diagnostics(id, &[]).unwrap();
        assert!(db.import_diagnostics(id).unwrap().is_empty());
    }
}
