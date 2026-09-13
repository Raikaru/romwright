//! Thunk identity is an owned fact: one producer's inferences refresh together
//! and never displace another owner's rows or an analyst assertion.
use super::{
    DbError, ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance,
    validate_fact_provenance,
};
use romwright_model::{FactKind, ProgramId, ThunkKind, ThunkRow};
use rusqlite::params;

/// Comparable identity of a stored row, without provenance columns.
type Fact = (String, String, String);

impl ProjectDb {
    pub fn thunks(&self, program: ProgramId) -> Result<Vec<ThunkRow>> {
        let mut statement = self.conn.prepare(
            "SELECT function, thunked, kind, provenance, provenance_kind, confidence
             FROM thunks WHERE program_id = ?1 ORDER BY function",
        )?;
        Ok(statement
            .query_map(params![program.0], |row| {
                let kind: String = row.get(2)?;
                Ok(ThunkRow {
                    function: addr_from_cell(row.get(0)?, 0)?,
                    thunked: addr_from_cell(row.get(1)?, 1)?,
                    kind: ThunkKind::parse(&kind).ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "unknown thunk kind",
                            )),
                        )
                    })?,
                    provenance: map_fact_provenance(row, 3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replaces exactly this producer's inferred thunk facts. Rows an assertion
    /// or another producer owns stay untouched, and an unchanged pass bumps no
    /// revision.
    pub fn replace_inferred_thunks(
        &self,
        program: ProgramId,
        source: &str,
        rows: &[ThunkRow],
    ) -> Result<()> {
        if source.trim().is_empty() {
            return Err(DbError::InvalidFactProvenance(
                "inference source is empty".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            validate_fact_provenance(&row.provenance)?;
            if row.provenance.kind != FactKind::Inferred || row.provenance.source != source {
                return Err(DbError::InvalidFactProvenance(format!(
                    "thunk fact does not belong to inference source {source}"
                )));
            }
            if !seen.insert(addr_cell(&row.function)) {
                return Err(DbError::InvalidFactProvenance(
                    "duplicate thunk function in one pass".into(),
                ));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let before = owned_facts(&tx, program, source)?;
        tx.execute(
            "DELETE FROM thunks WHERE program_id = ?1 AND provenance = ?2
                 AND provenance_kind = 'inferred'",
            params![program.0, source],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO thunks(program_id, function, thunked, kind, provenance,
                     provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'inferred', ?6)
                 ON CONFLICT(program_id, function) DO NOTHING",
            )?;
            for row in rows {
                insert.execute(params![
                    program.0,
                    addr_cell(&row.function),
                    addr_cell(&row.thunked),
                    row.kind.as_str(),
                    row.provenance.source,
                    row.provenance.confidence,
                ])?;
            }
        }
        // Rows another owner already holds are skipped, so compare what landed
        // instead of what was requested.
        if owned_facts(&tx, program, source)? != before {
            self.bump_and_record(&tx, program, "replace-inferred-thunks", source)?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn owned_facts(
    tx: &rusqlite::Transaction<'_>,
    program: ProgramId,
    source: &str,
) -> Result<Vec<Fact>> {
    let mut statement = tx.prepare(
        "SELECT function, thunked, kind FROM thunks
         WHERE program_id = ?1 AND provenance = ?2 AND provenance_kind = 'inferred'
         ORDER BY function",
    )?;
    Ok(statement
        .query_map(params![program.0, source], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{Address, FactProvenance, FunctionRow, Provenance};

    const SOURCE: &str = "native-import:thunk";

    fn fact(entry: u64, target: u64, kind: ThunkKind, source: &str, asserted: bool) -> ThunkRow {
        ThunkRow {
            function: Address::ram(entry),
            thunked: Address::ram(target),
            kind,
            provenance: FactProvenance {
                kind: if asserted {
                    FactKind::Asserted
                } else {
                    FactKind::Inferred
                },
                source: source.into(),
                confidence: None,
            },
        }
    }

    fn program(db: &ProjectDb) -> ProgramId {
        let id = db
            .upsert_program(
                "thunks",
                "x86:LE:64:default",
                &Provenance {
                    producer: "test".into(),
                    upstream_version: "test".into(),
                },
            )
            .unwrap();
        db.replace_functions(
            id,
            &[FunctionRow {
                entry: Address::ram(0x1000),
                name: "stub".into(),
                size: 5,
                signature: None,
                traced: false,
            calling_convention: None,
            }],
        )
        .unwrap();
        id
    }

    fn assert_row(db: &ProjectDb, id: ProgramId, row: &ThunkRow) {
        db.conn
            .execute(
                "INSERT INTO thunks(program_id, function, thunked, kind, provenance,
                     provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, 'analyst', 'asserted', NULL)",
                params![
                    id.0,
                    addr_cell(&row.function),
                    addr_cell(&row.thunked),
                    row.kind.as_str()
                ],
            )
            .unwrap();
    }

    #[test]
    fn owned_replacement_keeps_other_owners_and_assertions() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = program(&db);
        let mine = fact(0x1000, 0x2000, ThunkKind::Direct, SOURCE, false);
        let other = fact(0x1010, 0x2010, ThunkKind::Linkage, "other-pass", false);
        let asserted = fact(0x1020, 0x2020, ThunkKind::Direct, "analyst", true);
        db.replace_inferred_thunks(id, SOURCE, &[mine]).unwrap();
        db.replace_inferred_thunks(id, "other-pass", &[other.clone()])
            .unwrap();
        assert_row(&db, id, &asserted);
        let replacement = fact(0x1030, 0x2030, ThunkKind::Linkage, SOURCE, false);
        db.replace_inferred_thunks(id, SOURCE, &[replacement.clone()])
            .unwrap();
        assert_eq!(db.thunks(id).unwrap(), vec![other, asserted, replacement]);
    }

    #[test]
    fn assertion_survives_a_conflicting_inference_without_a_revision() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = program(&db);
        let asserted = fact(0x1000, 0x2000, ThunkKind::Direct, "analyst", true);
        assert_row(&db, id, &asserted);
        let revision = db.revision(id).unwrap();
        let inferred = fact(0x1000, 0x3000, ThunkKind::Linkage, SOURCE, false);
        db.replace_inferred_thunks(id, SOURCE, &[inferred]).unwrap();
        assert_eq!(db.thunks(id).unwrap(), vec![asserted]);
        assert_eq!(db.revision(id).unwrap(), revision);
    }

    #[test]
    fn repeated_pass_is_silent_and_malformed_input_is_rejected() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = program(&db);
        let row = fact(0x1000, 0x2000, ThunkKind::Direct, SOURCE, false);
        db.replace_inferred_thunks(id, SOURCE, &[row.clone()]).unwrap();
        let revision = db.revision(id).unwrap();
        db.replace_inferred_thunks(id, SOURCE, &[row.clone()]).unwrap();
        assert_eq!(db.revision(id).unwrap(), revision);
        for invalid in [
            vec![row.clone(), row.clone()],
            vec![fact(0x1000, 0x2000, ThunkKind::Direct, "elsewhere", false)],
            vec![fact(0x1000, 0x2000, ThunkKind::Direct, SOURCE, true)],
        ] {
            assert!(matches!(
                db.replace_inferred_thunks(id, SOURCE, &invalid),
                Err(DbError::InvalidFactProvenance(_))
            ));
        }
        assert!(matches!(
            db.replace_inferred_thunks(id, "  ", &[]),
            Err(DbError::InvalidFactProvenance(_))
        ));
        assert_eq!(db.thunks(id).unwrap(), vec![row]);
        assert_eq!(db.revision(id).unwrap(), revision);
    }
}
