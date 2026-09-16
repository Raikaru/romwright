//! Loader identity belongs to the program, not its name or an address guess.
use super::{DbError, ProjectDb, Result};
use romwright_model::{ProgramId, ProgramInput};
use rusqlite::{OptionalExtension, params};

impl ProjectDb {
    /// Make a multi-transaction reimport unavailable to native readers until
    /// its final loader identity is published. Existing requests become stale.
    pub fn invalidate_program_input(&self, name: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let program: Option<u64> = tx
            .query_row(
                "SELECT id FROM programs WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(program) = program {
            let changed = tx.execute(
                "DELETE FROM program_inputs WHERE program_id = ?1",
                params![program],
            )?;
            if changed != 0 {
                self.bump_and_record(&tx, ProgramId(program), "program-input-invalidated", name)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn program_input(&self, program: ProgramId) -> Result<ProgramInput> {
        let encoded: Option<String> = self
            .conn
            .query_row(
                "SELECT record FROM program_inputs WHERE program_id = ?1",
                params![program.0],
                |row| row.get(0),
            )
            .optional()?;
        let encoded = encoded.ok_or_else(|| DbError::InvalidProgramInput(
            "program predates immutable inputs; reimport its source before running native analysis".into()))?;
        serde_json::from_str(&encoded)
            .map_err(|error| DbError::InvalidProgramInput(error.to_string()))
    }

    pub fn set_program_input(&self, program: ProgramId, input: &ProgramInput) -> Result<()> {
        for digest in std::iter::once(&input.binary_digest)
            .chain(input.map_digest.iter())
            .chain(input.keys_digest.iter())
        {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(DbError::InvalidProgramInput(
                    "invalid artifact SHA-256".into(),
                ));
            }
        }
        let encoded = serde_json::to_string(input)
            .map_err(|error| DbError::InvalidProgramInput(error.to_string()))?;
        let tx = self.conn.unchecked_transaction()?;
        let changed = tx.execute(
            "INSERT INTO program_inputs(program_id, record) VALUES (?1, ?2)
             ON CONFLICT(program_id) DO UPDATE SET record = excluded.record WHERE record != excluded.record",
            params![program.0, encoded],
        )?;
        if changed != 0 {
            self.bump_and_record(&tx, program, "program-input", &input.binary_digest)?;
        }
        tx.commit()?;
        Ok(())
    }
}
