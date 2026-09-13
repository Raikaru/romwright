//! How the platform enters a function. A calling convention is a model name
//! the language's own compiler spec declares, so it is a fact with an owner
//! and provenance -- not a field of a recovered signature.
use super::{
    DbError, ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance,
    validate_fact_provenance,
};
use romwright_model::{CallingConventionRow, FactKind, ProgramId};
use rusqlite::params;

impl ProjectDb {
    /// Every convention fact of a program, ordered by function.
    pub fn calling_conventions(&self, program: ProgramId) -> Result<Vec<CallingConventionRow>> {
        let mut statement = self.conn.prepare(
            "SELECT function, convention, provenance, provenance_kind, confidence
             FROM calling_conventions WHERE program_id = ?1 ORDER BY function",
        )?;
        Ok(statement
            .query_map(params![program.0], |row| {
                Ok(CallingConventionRow {
                    function: addr_from_cell(row.get(0)?, 0)?,
                    convention: row.get(1)?,
                    provenance: map_fact_provenance(row, 2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// An assertion overrides whatever a producer decoded; inference never
    /// overrides an assertion.
    pub fn set_calling_convention(
        &self,
        program: ProgramId,
        row: &CallingConventionRow,
    ) -> Result<()> {
        validate_convention(row)?;
        let tx = self.conn.unchecked_transaction()?;
        let asserted = row.provenance.kind == FactKind::Asserted;
        let changed = tx.execute(
            "INSERT INTO calling_conventions(program_id, function, convention, provenance,
                 provenance_kind, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(program_id, function) DO UPDATE SET
                 convention = excluded.convention,
                 provenance = excluded.provenance,
                 provenance_kind = excluded.provenance_kind,
                 confidence = excluded.confidence
             WHERE ?7 OR calling_conventions.provenance_kind = 'inferred'",
            params![
                program.0,
                addr_cell(&row.function),
                row.convention,
                row.provenance.source,
                if asserted { "asserted" } else { "inferred" },
                row.provenance.confidence,
                asserted,
            ],
        )?;
        if changed > 0 {
            self.bump_and_record(&tx, program, "calling-convention", &row.function.hex())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces exactly this producer's conventions. Assertions and other
    /// producers' rows stay as they are, so a re-import keeps user edits.
    pub fn replace_inferred_calling_conventions(
        &self,
        program: ProgramId,
        source: &str,
        rows: &[CallingConventionRow],
    ) -> Result<()> {
        if source.trim().is_empty() {
            return Err(DbError::InvalidFactProvenance("inference source is empty".into()));
        }
        for row in rows {
            validate_convention(row)?;
            if row.provenance.kind != FactKind::Inferred || row.provenance.source != source {
                return Err(DbError::InvalidFactProvenance(format!(
                    "calling convention does not belong to inference source {source}"
                )));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let before = self.convention_cells(&tx, program, source)?;
        tx.execute(
            "DELETE FROM calling_conventions WHERE program_id = ?1 AND provenance = ?2
                 AND provenance_kind = 'inferred'",
            params![program.0, source],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO calling_conventions(program_id, function, convention, provenance,
                     provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, 'inferred', ?5)
                 ON CONFLICT(program_id, function) DO NOTHING",
            )?;
            for row in rows {
                insert.execute(params![
                    program.0,
                    addr_cell(&row.function),
                    row.convention,
                    row.provenance.source,
                    row.provenance.confidence,
                ])?;
            }
        }
        if self.convention_cells(&tx, program, source)? != before {
            self.bump_and_record(&tx, program, "replace-inferred-conventions", source)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn convention_cells(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        source: &str,
    ) -> Result<Vec<(String, String)>> {
        let mut statement = tx.prepare(
            "SELECT function, convention FROM calling_conventions
             WHERE program_id = ?1 AND provenance = ?2 ORDER BY function",
        )?;
        Ok(statement
            .query_map(params![program.0, source], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

/// A convention with no name names nothing: the decompiler answers an
/// unrecognized model with a placeholder that has no storage at all
/// (`Architecture::createUnknownModel`, fspec.cc:4695-4698).
fn validate_convention(row: &CallingConventionRow) -> Result<()> {
    validate_fact_provenance(&row.provenance)?;
    if row.convention.trim().is_empty() {
        return Err(DbError::InvalidFactProvenance("convention name is empty".into()));
    }
    Ok(())
}
