//! Structural function features (schema v28): the facts `romwright-diff` matches
//! programs on, including the masked body digest tier-0 anchors on.

use romwright_model::FunctionFeatureRow;
use rusqlite::params;

use crate::{DbError, ProgramId, ProjectDb, Result, addr_cell};

impl ProjectDb {
    /// Replaces every structural feature row for `program`.
    pub fn replace_function_features(
        &self,
        program: ProgramId,
        rows: &[FunctionFeatureRow],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM function_features WHERE program_id = ?1",
            params![program.0],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT OR REPLACE INTO function_features
                     (program_id, function, instructions, blocks, edges, body_digest,
                      shape_digest, loops, max_block, masked_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for row in rows {
                if row.body_digest.is_empty() || row.shape_digest.is_empty() || row.masked_digest.is_empty() {
                    return Err(DbError::InvalidFunctionFeatures(
                        "row has an empty digest".into(),
                    ));
                }
                insert.execute(params![
                    program.0,
                    addr_cell(&row.function),
                    row.instructions,
                    row.blocks,
                    row.edges,
                    row.body_digest,
                    row.shape_digest,
                    row.loops,
                    row.max_block,
                    row.masked_digest,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every structural feature row held for `program`, entry order.
    pub fn function_features(&self, program: ProgramId) -> Result<Vec<FunctionFeatureRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT function, instructions, blocks, edges, body_digest, shape_digest,
                    loops, max_block, masked_digest
             FROM function_features WHERE program_id = ?1 ORDER BY function",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                let function: String = row.get(0)?;
                Ok(FunctionFeatureRow {
                    function: romwright_model::Address::parse_ram_hex(&function).unwrap_or_default(),
                    instructions: row.get(1)?,
                    blocks: row.get(2)?,
                    edges: row.get(3)?,
                    body_digest: row.get(4)?,
                    shape_digest: row.get(5)?,
                    loops: row.get(6)?,
                    max_block: row.get(7)?,
                    masked_digest: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
