//! Matching history is independently revisioned; no analysis facts are changed.
//! Writers reserve the transaction before reading: a WAL read snapshot cannot
//! be upgraded after concurrent analysis commits.
use super::{DbError, ProjectDb, Result};
use romwright_model::ProgramId;
use romwright_model::matching::*;
use rusqlite::{Transaction, params};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;

fn encode(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(|error| DbError::InvalidMatchingRun(error.to_string()))
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|error| DbError::InvalidMatchingRun(error.to_string()))
}

fn insert_workspace(
    tx: &Transaction<'_>,
    program: ProgramId,
    spec: WorkspaceSpec,
) -> Result<MatchingWorkspace> {
    let (id, created_at) = tx.query_row(
        "INSERT INTO matching_workspaces(program_id, spec) VALUES (?1, ?2) RETURNING id, created_at",
        params![program.0, encode(&spec)?], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(MatchingWorkspace {
        id,
        revision: 0,
        created_at,
        spec,
    })
}

fn insert_candidate(
    tx: &Transaction<'_>,
    workspace: u64,
    spec: CandidateSpec,
    created: Option<&str>,
) -> Result<MatchingCandidate> {
    if let Some(parent) = spec.parent {
        let owner: u64 = tx.query_row(
            "SELECT workspace_id FROM matching_candidates WHERE id = ?1",
            [parent],
            |row| row.get(0),
        )?;
        if owner != workspace {
            return Err(DbError::InvalidMatchingRun(
                "candidate parent belongs to another workspace".into(),
            ));
        }
    }
    let (id, created_at) = tx.query_row(
        "INSERT INTO matching_candidates(workspace_id, parent_id, created_at, spec)
         VALUES (?1, ?2, COALESCE(?3, datetime('now')), ?4) RETURNING id, created_at",
        params![workspace, spec.parent, created, encode(&spec)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    tx.execute(
        "UPDATE matching_workspaces SET revision = revision + 1 WHERE id = ?1",
        [workspace],
    )?;
    Ok(MatchingCandidate {
        id,
        workspace,
        created_at,
        spec,
    })
}

fn insert_trial(
    tx: &Transaction<'_>,
    workspace: u64,
    mut trial: TrialRecord,
) -> Result<TrialRecord> {
    let owner: u64 = tx.query_row(
        "SELECT workspace_id FROM matching_candidates WHERE id = ?1",
        [trial.candidate],
        |row| row.get(0),
    )?;
    if owner != workspace
        || trial
            .run
            .as_ref()
            .is_some_and(|run| run.record.status != trial.status)
        || (!trial.imported && trial.run.is_none())
    {
        return Err(DbError::InvalidMatchingRun(
            "trial provenance does not match its candidate or status".into(),
        ));
    }
    // The large compiler/diff record is stored once, in matching_runs.
    let run = trial.run.take();
    let encoded = encode(&trial)?;
    let (id, created_at) = tx.query_row(
        "INSERT INTO matching_trials(workspace_id, candidate_id, created_at, record, run_id)
         VALUES (?1, ?2, COALESCE(?3, datetime('now')), ?4, ?5) RETURNING id, created_at",
        params![
            workspace,
            trial.candidate,
            (!trial.created_at.is_empty()).then_some(trial.created_at.as_str()),
            encoded,
            run.as_ref().map(|run| run.id)
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    trial.id = id;
    trial.created_at = created_at;
    trial.run = run;
    tx.execute(
        "UPDATE matching_workspaces SET revision = revision + 1 WHERE id = ?1",
        [workspace],
    )?;
    Ok(trial)
}

fn insert_project_check(
    tx: &Transaction<'_>,
    mut check: PatchVerification,
) -> Result<PatchVerification> {
    let workspace: u64 = tx.query_row(
        "SELECT workspace_id FROM matching_candidates WHERE id = ?1",
        [check.patch.candidate],
        |row| row.get(0),
    )?;
    if workspace != check.patch.workspace {
        return Err(DbError::InvalidMatchingRun(
            "project check belongs to another candidate workspace".into(),
        ));
    }
    let (id, created_at) = tx.query_row(
        "INSERT INTO matching_project_checks(workspace_id, candidate_id, created_at, record)
         VALUES (?1, ?2, COALESCE(?3, datetime('now')), ?4) RETURNING id, created_at",
        params![
            workspace,
            check.patch.candidate,
            (!check.created_at.is_empty()).then_some(check.created_at.as_str()),
            encode(&check)?
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    check.id = id;
    check.created_at = created_at;
    tx.execute(
        "UPDATE matching_workspaces SET revision = revision + 1 WHERE id = ?1",
        [workspace],
    )?;
    Ok(check)
}

impl ProjectDb {
    pub fn create_matching_workspace(
        &self,
        program: ProgramId,
        spec: WorkspaceSpec,
    ) -> Result<WorkspaceCreated> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        let initial = CandidateSpec {
            parent: None,
            label: "Initial source".into(),
            files: spec.files.clone(),
            edits: Some(Vec::new()),
            pins: Vec::new(),
        };
        let mut workspace = insert_workspace(&tx, program, spec)?;
        let candidate = insert_candidate(&tx, workspace.id, initial, None)?;
        workspace.revision = 1;
        tx.commit()?;
        Ok(WorkspaceCreated {
            workspace,
            candidate,
        })
    }

    pub fn matching_workspace(&self, program: ProgramId, id: u64) -> Result<MatchingWorkspace> {
        let (revision, created_at, spec): (u64, String, String) = self.conn.query_row(
            "SELECT revision, created_at, spec FROM matching_workspaces WHERE program_id = ?1 AND id = ?2",
            params![program.0, id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(MatchingWorkspace {
            id,
            revision,
            created_at,
            spec: decode(&spec)?,
        })
    }

    pub fn matching_workspaces(
        &self,
        program: ProgramId,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MatchingWorkspace>> {
        let mut statement = self.conn.prepare(
            "SELECT id, revision, created_at, spec FROM matching_workspaces
             WHERE program_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3",
        )?;
        let rows = statement.query_map(params![program.0, after, limit.clamp(1, 1000)], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (id, revision, created_at, spec) = row?;
            Ok(MatchingWorkspace {
                id,
                revision,
                created_at,
                spec: decode(&spec)?,
            })
        })
        .collect()
    }

    pub fn update_matching_workspace(
        &self,
        program: ProgramId,
        id: u64,
        revision: u64,
        spec: WorkspaceSpec,
    ) -> Result<MatchingWorkspace> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE matching_workspaces SET spec = ?1, revision = revision + 1
             WHERE program_id = ?2 AND id = ?3 AND revision = ?4",
            params![encode(&spec)?, program.0, id, revision],
        )?;
        if changed != 1 {
            return Err(DbError::InvalidMatchingRun(
                "workspace changed since it was opened".into(),
            ));
        }
        tx.commit()?;
        self.matching_workspace(program, id)
    }

    pub fn matching_candidate(&self, program: ProgramId, id: u64) -> Result<MatchingCandidate> {
        let (workspace, created_at, spec): (u64, String, String) = self.conn.query_row(
            "SELECT c.workspace_id, c.created_at, c.spec FROM matching_candidates c
             JOIN matching_workspaces w ON w.id = c.workspace_id WHERE w.program_id = ?1 AND c.id = ?2",
            params![program.0, id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(MatchingCandidate {
            id,
            workspace,
            created_at,
            spec: decode(&spec)?,
        })
    }

    pub fn matching_candidates(
        &self,
        program: ProgramId,
        workspace: u64,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MatchingCandidate>> {
        let mut statement = self.conn.prepare(
            "SELECT c.id, c.created_at, c.spec FROM matching_candidates c
             JOIN matching_workspaces w ON w.id = c.workspace_id
             WHERE w.program_id = ?1 AND w.id = ?2 AND c.id > ?3 ORDER BY c.id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![program.0, workspace, after, limit.clamp(1, 1000)],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (id, created_at, spec) = row?;
            Ok(MatchingCandidate {
                id,
                workspace,
                created_at,
                spec: decode(&spec)?,
            })
        })
        .collect()
    }

    pub fn record_matching_candidate(
        &self,
        program: ProgramId,
        workspace: u64,
        spec: CandidateSpec,
    ) -> Result<MatchingCandidate> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        tx.query_row(
            "SELECT id FROM matching_workspaces WHERE program_id = ?1 AND id = ?2",
            params![program.0, workspace],
            |_| Ok(()),
        )?;
        let candidate = insert_candidate(&tx, workspace, spec, None)?;
        tx.commit()?;
        Ok(candidate)
    }

    pub fn record_matching_trial(
        &self,
        program: ProgramId,
        workspace: u64,
        mut trial: TrialRecord,
        record: romwright_model::MatchingRunRecord,
    ) -> Result<TrialRecord> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        tx.query_row(
            "SELECT id FROM matching_workspaces WHERE program_id = ?1 AND id = ?2",
            params![program.0, workspace],
            |_| Ok(()),
        )?;
        trial.run = Some(self.insert_matching_run(&tx, program, record, false, None)?);
        let trial = insert_trial(&tx, workspace, trial)?;
        tx.commit()?;
        Ok(trial)
    }

    pub fn matching_trials(
        &self,
        program: ProgramId,
        workspace: u64,
        after: u64,
        limit: usize,
    ) -> Result<Vec<TrialRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT t.id, t.created_at, t.record, t.run_id FROM matching_trials t
             JOIN matching_workspaces w ON w.id = t.workspace_id
             WHERE w.program_id = ?1 AND w.id = ?2 AND t.id > ?3 ORDER BY t.id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![program.0, workspace, after, limit.clamp(1, 1000)],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (id, created_at, record, run_id) = row?;
            let mut trial: TrialRecord = decode(&record)?;
            trial.id = id;
            trial.created_at = created_at;
            trial.run = run_id
                .map(|id| self.matching_run(program, id))
                .transpose()?;
            Ok(trial)
        })
        .collect()
    }

    pub fn record_matching_project_check(
        &self,
        program: ProgramId,
        check: PatchVerification,
    ) -> Result<PatchVerification> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        tx.query_row(
            "SELECT id FROM matching_workspaces WHERE program_id = ?1 AND id = ?2",
            params![program.0, check.patch.workspace],
            |_| Ok(()),
        )?;
        let check = insert_project_check(&tx, check)?;
        tx.commit()?;
        Ok(check)
    }

    pub fn matching_project_checks(
        &self,
        program: ProgramId,
        workspace: u64,
        after: u64,
        limit: usize,
    ) -> Result<Vec<PatchVerification>> {
        let mut statement = self.conn.prepare(
            "SELECT c.id, c.created_at, c.record FROM matching_project_checks c
             JOIN matching_workspaces w ON w.id = c.workspace_id
             WHERE w.program_id = ?1 AND w.id = ?2 AND c.id > ?3 ORDER BY c.id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![program.0, workspace, after, limit.clamp(1, 1000)],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (id, created_at, record) = row?;
            let mut check: PatchVerification = decode(&record)?;
            check.id = id;
            check.created_at = created_at;
            Ok(check)
        })
        .collect()
    }

    /// The caller validates artifact bytes and permission policy before entering
    /// this transaction. Parent and trial IDs are remapped atomically.
    pub fn import_matching_workspace(
        &self,
        program: ProgramId,
        bundle: WorkspaceBundle,
    ) -> Result<WorkspaceCreated> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        let mut workspace = insert_workspace(&tx, program, bundle.workspace)?;
        let mut ids = BTreeMap::new();
        let mut root = None;
        for candidate in bundle.candidates {
            let old_id = candidate.id;
            let mut spec = candidate.spec;
            spec.parent = match spec.parent {
                Some(parent) => Some(*ids.get(&parent).ok_or_else(|| {
                    DbError::InvalidMatchingRun("imported parent is absent or out of order".into())
                })?),
                None if root.is_none() => None,
                None => {
                    return Err(DbError::InvalidMatchingRun(
                        "import has multiple root candidates".into(),
                    ));
                }
            };
            let imported = insert_candidate(&tx, workspace.id, spec, Some(&candidate.created_at))?;
            if ids.insert(old_id, imported.id).is_some() {
                return Err(DbError::InvalidMatchingRun(
                    "duplicate imported candidate identity".into(),
                ));
            }
            if imported.spec.parent.is_none() {
                root = Some(imported);
            }
            workspace.revision += 1;
        }
        for mut trial in bundle.trials {
            trial.candidate = *ids.get(&trial.candidate).ok_or_else(|| {
                DbError::InvalidMatchingRun("imported trial has no candidate".into())
            })?;
            trial.imported = true;
            if let Some(run) = trial.run.take() {
                trial.run = Some(self.insert_matching_run(
                    &tx,
                    program,
                    run.record,
                    true,
                    Some(&run.created_at),
                )?);
            }
            insert_trial(&tx, workspace.id, trial)?;
            workspace.revision += 1;
        }
        for mut check in bundle.project_checks {
            check.patch.candidate = *ids.get(&check.patch.candidate).ok_or_else(|| {
                DbError::InvalidMatchingRun("imported project check has no candidate".into())
            })?;
            check.patch.workspace = workspace.id;
            check.imported = true;
            check.recovery_path = None;
            insert_project_check(&tx, check)?;
            workspace.revision += 1;
        }
        let candidate =
            root.ok_or_else(|| DbError::InvalidMatchingRun("import has no root candidate".into()))?;
        tx.commit()?;
        Ok(WorkspaceCreated {
            workspace,
            candidate,
        })
    }
}
