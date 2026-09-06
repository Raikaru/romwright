//! Return behavior is a separate owned fact, not an inferred function signature.
use super::{
    ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance, validate_fact_provenance,
};
use lre_model::{ProgramId, ReturnBehaviorRow};
use rusqlite::{Transaction, params};

impl ProjectDb {
    /// An assertion can override either value; inference cannot override it.
    pub fn set_return_behavior(&self, program: ProgramId, row: &ReturnBehaviorRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        if insert_return_behavior(&tx, program, row)? {
            self.bump_and_record(&tx, program, "return-behavior", &row.function.hex())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn return_behaviors(&self, program: ProgramId) -> Result<Vec<ReturnBehaviorRow>> {
        let mut statement = self.conn.prepare(
            "SELECT function, no_return, provenance, provenance_kind, confidence
             FROM return_behaviors WHERE program_id = ?1 ORDER BY function",
        )?;
        Ok(statement
            .query_map(params![program.0], |row| {
                Ok(ReturnBehaviorRow {
                    function: addr_from_cell(row.get(0)?, 0)?,
                    no_return: row.get(1)?,
                    provenance: map_fact_provenance(row, 2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

fn insert_return_behavior(
    tx: &Transaction<'_>,
    program: ProgramId,
    row: &ReturnBehaviorRow,
) -> Result<bool> {
    let ownership = validate_fact_provenance(&row.provenance)?;
    Ok(tx.execute(
        "INSERT INTO return_behaviors(program_id, function, no_return, provenance, provenance_kind, confidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(program_id, function) DO UPDATE SET
             no_return = excluded.no_return,
             provenance = excluded.provenance,
             provenance_kind = excluded.provenance_kind,
             confidence = excluded.confidence
         WHERE (return_behaviors.provenance_kind = 'inferred' OR excluded.provenance_kind = 'asserted')
           AND (return_behaviors.no_return IS NOT excluded.no_return
             OR return_behaviors.provenance IS NOT excluded.provenance
             OR return_behaviors.provenance_kind IS NOT excluded.provenance_kind
             OR return_behaviors.confidence IS NOT excluded.confidence)",
        params![program.0, addr_cell(&row.function), row.no_return, row.provenance.source,
            ownership, row.provenance.confidence],
    )? != 0)
}
