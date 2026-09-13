//! Semantic p-code signatures (schema v20): the facts the BSim-style
//! evidence class in `romwright-diff` matches on.
//!
//! Unlike `function_features`, these are not taken at import: p-code needs
//! a loaded console per function body, which the whole-image import does
//! not keep open. An explicit indexing pass (`Core::index_semantics`)
//! walks each body on a warm image and stores one row per decoded
//! function; a function nobody decoded gets no row, so a missing
//! signature is absence of evidence, never evidence of difference.

use romwright_model::SemanticSignatureRow;
use rusqlite::params;

use crate::{ProgramId, ProjectDb, Result, addr_cell};

impl ProjectDb {
    /// Replaces every semantic signature row for `program`.
    pub fn replace_semantic_signatures(
        &self,
        program: ProgramId,
        rows: &[SemanticSignatureRow],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM semantic_signatures WHERE program_id = ?1",
            params![program.0],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT OR REPLACE INTO semantic_signatures
                     (program_id, function, signature, ops)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for row in rows {
                insert.execute(params![
                    program.0,
                    addr_cell(&row.function),
                    row.signature,
                    row.ops,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every semantic signature row held for `program`, entry order.
    pub fn semantic_signatures(
        &self,
        program: ProgramId,
    ) -> Result<Vec<SemanticSignatureRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT function, signature, ops
             FROM semantic_signatures WHERE program_id = ?1 ORDER BY function",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                let function: String = row.get(0)?;
                Ok(SemanticSignatureRow {
                    function: romwright_model::Address::parse_ram_hex(&function).unwrap_or_default(),
                    signature: row.get(1)?,
                    ops: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::Provenance;

    fn prov() -> Provenance {
        Provenance {
            producer: "test".into(),
            upstream_version: "0".into(),
        }
    }

    #[test]
    fn semantic_signatures_roundtrip_per_program() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        // No index pass ran: absence, not an error.
        assert!(db.semantic_signatures(id).unwrap().is_empty());
        let rows = vec![
            SemanticSignatureRow {
                function: romwright_model::Address::ram(0x400100),
                signature: "ab".repeat(1024),
                ops: 12,
            },
            SemanticSignatureRow {
                function: romwright_model::Address::ram(0x400200),
                signature: "cd".repeat(1024),
                ops: 30,
            },
        ];
        db.replace_semantic_signatures(id, &rows).unwrap();
        assert_eq!(db.semantic_signatures(id).unwrap(), rows);
        // Replacing clears what the last pass wrote.
        db.replace_semantic_signatures(id, &[]).unwrap();
        assert!(db.semantic_signatures(id).unwrap().is_empty());
    }
}
