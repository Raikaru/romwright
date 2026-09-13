//! Signature matches are owned facts: a name a database claimed for a
//! function, with the package it came from and the evidence that supports it.
use super::{
    DbError, ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance,
    validate_fact_provenance,
};
use romwright_model::{FactKind, ProgramId, SignatureMatchRow};
use rusqlite::params;

impl ProjectDb {
    pub fn signature_matches(&self, program: ProgramId) -> Result<Vec<SignatureMatchRow>> {
        let mut statement = self.conn.prepare(
            "SELECT function, name, package, license, compared_bytes, match_confidence,
                    provenance, provenance_kind, confidence
             FROM signature_matches WHERE program_id = ?1 ORDER BY function",
        )?;
        Ok(statement
            .query_map(params![program.0], |row| {
                Ok(SignatureMatchRow {
                    function: addr_from_cell(row.get(0)?, 0)?,
                    name: row.get(1)?,
                    package: row.get(2)?,
                    license: row.get(3)?,
                    compared_bytes: row.get(4)?,
                    confidence: row.get(5)?,
                    provenance: map_fact_provenance(row, 6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replaces exactly this producer's matches. Another producer's rows and
    /// analyst assertions stay, and an unchanged pass bumps no revision.
    pub fn replace_signature_matches(
        &self,
        program: ProgramId,
        source: &str,
        rows: &[SignatureMatchRow],
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
                    "signature match does not belong to inference source {source}"
                )));
            }
            if row.name.trim().is_empty() || row.package.trim().is_empty() {
                return Err(DbError::InvalidFactProvenance(
                    "a signature match needs a name and a package".into(),
                ));
            }
            if !(0.0..=1.0).contains(&row.confidence) || row.compared_bytes == 0 {
                return Err(DbError::InvalidFactProvenance(
                    "a signature match needs compared bytes and a confidence in [0, 1]".into(),
                ));
            }
            if !seen.insert(addr_cell(&row.function)) {
                return Err(DbError::InvalidFactProvenance(
                    "duplicate signature match for one function".into(),
                ));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let before = owned(&tx, program, source)?;
        tx.execute(
            "DELETE FROM signature_matches WHERE program_id = ?1 AND provenance = ?2
                 AND provenance_kind = 'inferred'",
            params![program.0, source],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO signature_matches(program_id, function, name, package, license,
                     compared_bytes, match_confidence, provenance, provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'inferred', ?9)
                 ON CONFLICT(program_id, function) DO NOTHING",
            )?;
            for row in rows {
                insert.execute(params![
                    program.0,
                    addr_cell(&row.function),
                    row.name,
                    row.package,
                    row.license,
                    row.compared_bytes,
                    row.confidence,
                    row.provenance.source,
                    row.provenance.confidence,
                ])?;
            }
        }
        if owned(&tx, program, source)? != before {
            self.bump_and_record(&tx, program, "replace-signature-matches", source)?;
        }
        tx.commit()?;
        Ok(())
    }
}

type Fact = (String, String, String, f64);

fn owned(tx: &rusqlite::Transaction<'_>, program: ProgramId, source: &str) -> Result<Vec<Fact>> {
    let mut statement = tx.prepare(
        "SELECT function, name, package, match_confidence FROM signature_matches
         WHERE program_id = ?1 AND provenance = ?2 AND provenance_kind = 'inferred'
         ORDER BY function",
    )?;
    Ok(statement
        .query_map(params![program.0, source], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{Address, FactProvenance, FunctionRow, Provenance};

    const SOURCE: &str = "signature:test-1.0";

    fn row(entry: u64, name: &str, source: &str, asserted: bool, confidence: f64) -> SignatureMatchRow {
        SignatureMatchRow {
            function: Address::ram(entry),
            name: name.into(),
            package: "test-1.0".into(),
            license: "MIT".into(),
            compared_bytes: 32,
            confidence,
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
                "matches",
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
                name: "FUN_00001000".into(),
                size: 32,
                signature: None,
                traced: false,
            calling_convention: None,
            }],
        )
        .unwrap();
        id
    }

    #[test]
    fn owned_matches_refresh_without_touching_other_owners() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = program(&db);
        let mine = row(0x1000, "strlen", SOURCE, false, 1.0);
        let other = row(0x1010, "memcpy", "signature:other", false, 0.5);
        db.replace_signature_matches(id, SOURCE, &[mine]).unwrap();
        db.replace_signature_matches(id, "signature:other", &[other.clone()])
            .unwrap();
        let replacement = row(0x1020, "memset", SOURCE, false, 0.75);
        db.replace_signature_matches(id, SOURCE, &[replacement.clone()])
            .unwrap();
        assert_eq!(db.signature_matches(id).unwrap(), vec![other, replacement]);
    }

    #[test]
    fn repeated_matches_are_silent_and_malformed_rows_rejected() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = program(&db);
        let fact = row(0x1000, "strlen", SOURCE, false, 0.9);
        db.replace_signature_matches(id, SOURCE, &[fact.clone()])
            .unwrap();
        let revision = db.revision(id).unwrap();
        db.replace_signature_matches(id, SOURCE, &[fact.clone()])
            .unwrap();
        assert_eq!(db.revision(id).unwrap(), revision);
        let mut nameless = fact.clone();
        nameless.name = " ".into();
        let mut impossible = fact.clone();
        impossible.confidence = 1.5;
        let mut evidenceless = fact.clone();
        evidenceless.compared_bytes = 0;
        for invalid in [
            vec![fact.clone(), fact.clone()],
            vec![row(0x1000, "strlen", "elsewhere", false, 0.9)],
            vec![row(0x1000, "strlen", SOURCE, true, 0.9)],
            vec![nameless],
            vec![impossible],
            vec![evidenceless],
        ] {
            assert!(matches!(
                db.replace_signature_matches(id, SOURCE, &invalid),
                Err(DbError::InvalidFactProvenance(_))
            ));
        }
        assert_eq!(db.signature_matches(id).unwrap(), vec![fact]);
        assert_eq!(db.revision(id).unwrap(), revision);
    }
}
