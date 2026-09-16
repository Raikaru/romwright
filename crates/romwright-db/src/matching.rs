//! Append-only matching evidence. Records never follow mutable object paths.
//! Write reservations precede revision reads so concurrent analysis cannot
//! invalidate a read-to-write transaction upgrade.
use super::{DbError, ProjectDb, Result};
use romwright_model::{MatchingRun, MatchingRunRecord, ProgramId};
use rusqlite::params;

impl ProjectDb {
    pub(super) fn insert_matching_run(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        record: MatchingRunRecord,
        imported: bool,
        created: Option<&str>,
    ) -> Result<MatchingRun> {
        for digest in [
            &record.target_digest,
            &record.source_digest,
            &record.context_digest,
            &record.compiler_digest,
            &record.objdiff_digest,
        ]
        .into_iter()
        .chain(record.candidate_digest.iter())
        {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(DbError::InvalidMatchingRun(
                    "artifact identity is not SHA-256".into(),
                ));
            }
        }
        if record.recipe.compiler.is_empty()
            || record.compiler_version.is_empty()
            || record.objdiff_version.is_empty()
        {
            return Err(DbError::InvalidMatchingRun(
                "missing compiler or diff evidence".into(),
            ));
        }
        match record.status {
            romwright_model::MatchingStatus::Compared
                if record.candidate_digest.is_none() || !record.raw_result.is_object() =>
            {
                return Err(DbError::InvalidMatchingRun(
                    "comparison lacks a candidate or raw diff".into(),
                ));
            }
            romwright_model::MatchingStatus::CompileFailed if record.candidate_digest.is_some() => {
                return Err(DbError::InvalidMatchingRun(
                    "failed compilation cannot claim a candidate".into(),
                ));
            }
            romwright_model::MatchingStatus::DiffFailed if record.candidate_digest.is_none() => {
                return Err(DbError::InvalidMatchingRun(
                    "failed diff lacks its candidate".into(),
                ));
            }
            _ => {}
        }
        let encoded = serde_json::to_string(&record)
            .map_err(|error| DbError::InvalidMatchingRun(error.to_string()))?;
        let revision: u64 = tx.query_row(
            "SELECT revision FROM programs WHERE id = ?1",
            params![program.0],
            |row| row.get(0),
        )?;
        // Newer analysis facts do not invalidate historical artifact evidence.
        // A local run cannot claim a revision that has never existed.
        if !imported && record.revision > revision {
            return Err(DbError::StaleRevision {
                expected: record.revision,
                actual: revision,
            });
        }
        let (id, created_at): (u64, String) = tx.query_row(
            "INSERT INTO matching_runs(program_id, record, imported, created_at)
             VALUES (?1, ?2, ?3, COALESCE(?4, datetime('now'))) RETURNING id, created_at",
            params![program.0, encoded, imported, created], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        // Recording evidence does not mutate analysis facts or their revision.
        Ok(MatchingRun {
            id,
            created_at,
            imported,
            record,
        })
    }

    pub fn record_matching_run(&self, program: ProgramId, record: MatchingRunRecord) -> Result<MatchingRun> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        let run = self.insert_matching_run(&tx, program, record, false, None)?;
        tx.commit()?;
        Ok(run)
    }

    pub fn matching_run(&self, program: ProgramId, id: u64) -> Result<MatchingRun> {
        let (created_at, encoded, imported): (String, String, bool) = self.conn.query_row(
            "SELECT created_at, record, imported FROM matching_runs WHERE program_id = ?1 AND id = ?2",
            params![program.0, id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(MatchingRun {
            id, created_at, imported,
            record: serde_json::from_str(&encoded)
                .map_err(|error| DbError::InvalidMatchingRun(error.to_string()))?,
        })
    }

    pub fn matching_runs(
        &self,
        program: ProgramId,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MatchingRun>> {
        let mut statement = self.conn.prepare(
            "SELECT id, created_at, record, imported FROM matching_runs WHERE program_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3")?;
        let rows = statement.query_map(params![program.0, after, limit.clamp(1, 1000)], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (id, created_at, encoded, imported) = row?;
            let record = serde_json::from_str(&encoded)
                .map_err(|error| DbError::InvalidMatchingRun(error.to_string()))?;
            Ok(MatchingRun {
                id,
                created_at,
                imported,
                record,
            })
        })
        .collect()
    }
}
