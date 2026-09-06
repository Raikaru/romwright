//! Supervised persistent decompiler worker client (WORKER-001/002).
//!
//! A pool of warm `ghidra_opt` children: lease, per-call deadlines (a
//! wedged command is killed and the session poisoned, WORKER-002), and
//! restart on the next lease. `ProgramProvider` facts are loaded once per
//! spawn from the store + the mapped binary.

use lre_model::{Address, DecompDoc};
use lre_worker::{
    BinaryBacking, ProgramProvider, WorkerError, load_specs, open_store, worker::NativeWorker,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// One warm worker session: a spawned decompiler + its program facts.
pub struct WorkerSession {
    worker: NativeWorker,
    provider: ProgramProvider,
    applied_prototypes: HashSet<u64>,
}

impl WorkerSession {
    /// Spawns `ghidra_opt`, registers `program`, selects the decompile
    /// action, and loads all durable provider facts needed by callbacks.
    /// The provider includes the native section map and store facts.
    fn spawn(config: &PoolConfig, on_launch: impl FnOnce(&NativeWorker)) -> PoolResult<Self> {
        let PoolConfig {
            decompiler,
            spec_root,
            binary,
            program,
            project_dir,
            base,
            ..
        } = config;
        lre_worker::check_setup(decompiler, &config.sla)?;
        let mut provider =
            ProgramProvider::new(BinaryBacking::from_file(binary, *base)?, Vec::new());
        provider.load_language_info(spec_root)?;
        let db = open_store(project_dir)?;
        let pid = db.program_id(program)?;
        let mut function_shells = Vec::new();
        for f in db.functions(pid)? {
            let off = f.entry.offset;
            provider.functions.push(off);
            provider.function_names.insert(off, f.name.clone());
            provider.function_sizes.insert(off, f.size as u64);
            function_shells.push((off, f.name, f.size as u64));
        }
        for symbol in db.symbols(pid)? {
            provider
                .symbol_names
                .entry(symbol.address.offset)
                .or_insert_with(|| symbol.name.clone());
            if symbol.external {
                provider
                    .external_names
                    .insert(symbol.address.offset, symbol.name);
            }
        }
        for comment in db.comments(pid)? {
            provider
                .comments
                .entry(comment.function.offset)
                .or_default()
                .push((comment.address.offset, comment.kind, comment.text));
        }
        for datatype in db.datatypes(pid)? {
            provider
                .datatypes
                .insert(datatype.name, datatype.definition);
        }
        for prototype in db.prototypes(pid)? {
            if !prototype.signature.is_empty() {
                provider
                    .prototypes
                    .insert(prototype.function.offset, prototype.signature);
            }
        }
        for string in db.strings(pid)? {
            provider.strings.insert(string.address.offset, string.value);
        }
        let shell_entries: Vec<(u64, &str, u64)> = function_shells
            .iter()
            .map(|(offset, name, size)| (*offset, name.as_str(), *size))
            .collect();
        let function_shell = NativeWorker::encode_function_shell_doc(
            provider.ram_space_index as u32,
            &shell_entries,
        );
        let spec_docs = load_specs(spec_root)?;
        let mut command = std::process::Command::new(decompiler);
        command
            .env("VENTRIS_SLA", &config.sla)
            .env("VENTRIS_LANGUAGE_DIR", &config.language_dir)
            .env("VENTRIS_LANGUAGE", &config.language_id);
        let mut worker = NativeWorker::launch(command)?;
        // Arm supervision before the first potentially blocking protocol I/O.
        on_launch(&worker);
        worker
            .register_program_with_shell(
                &mut provider,
                &spec_docs.0,
                &spec_docs.1,
                &spec_docs.2,
                &spec_docs.3,
                &function_shell,
            )
            .map_err(|error| WorkerError::Setup(format!("registerProgram: {error}")))?;
        worker
            .set_action(&mut provider, "decompile", "")
            .map_err(|error| WorkerError::Setup(format!("setAction: {error}")))?;
        Ok(Self {
            worker,
            provider,
            applied_prototypes: HashSet::new(),
        })
    }

    fn ram_space(&self) -> u32 {
        self.provider.ram_space_index as u32
    }

    /// Decompiles one address. The pool wraps this with the deadline;
    /// a kill during the call surfaces as a read error (poisoned).
    pub fn decompile(&mut self, address: u64) -> lre_worker::Result<Vec<u8>> {
        self.apply_prototype(address)?;
        let space = self.ram_space();
        self.worker.decompile_at(&mut self.provider, space, address)
    }

    fn apply_prototype(&mut self, address: u64) -> lre_worker::Result<()> {
        if self.applied_prototypes.contains(&address) {
            return Ok(());
        }
        let Some(signature) = self.provider.prototypes.get(&address).cloned() else {
            return Ok(());
        };
        let function_name = self
            .provider
            .function_names
            .get(&address)
            .cloned()
            .ok_or_else(|| {
                WorkerError::Setup(format!(
                    "prototype target {address:#x} has no function name"
                ))
            })?;
        self.worker.set_function_signature(
            &mut self.provider,
            address,
            &function_name,
            &signature,
        )?;
        self.applied_prototypes.insert(address);
        Ok(())
    }

    /// Decompiles one address and decodes the pinned packed document into
    /// structured tokens and recovered prototype facts. The returned revision
    /// is zero because the response is not a store mutation; a Core/session
    /// caller stamps its current program revision when publishing it.
    pub fn decompile_doc(&mut self, address: u64) -> lre_worker::Result<DecompDoc> {
        let raw = self.decompile(address)?;
        let (tokens, prototype) =
            lre_worker::decode_document_with_ram_space(&raw, Some(self.ram_space() as u64));
        Ok(DecompDoc {
            tokens,
            prototype,
            address: Address::ram(address),
            revision: 0,
        })
    }

    fn pid(&self) -> Option<u32> {
        self.worker.pid()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("worker: {0}")]
    Worker(#[from] WorkerError),
    #[error("store: {0}")]
    Db(#[from] lre_db::DbError),
    #[error("core: {0}")]
    Core(#[from] lre_core::CoreError),
    #[error("deadline exceeded (>{0:?}); worker killed, session poisoned")]
    Deadline(Duration),
    #[error("worker exceed memory cap (rss {0} bytes > cap {1} bytes); killed")]
    MemCap(u64, u64),
}

pub type PoolResult<T, E = PoolError> = std::result::Result<T, E>;

/// Lifecycle state for one supervised worker operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

/// One bounded worker operation record exposed to frontends.
#[derive(Clone, Debug, Serialize)]
pub struct JobRow {
    pub id: u64,
    pub operation: String,
    pub address: Option<u64>,
    pub state: JobState,
    pub detail: String,
}

/// Pool counters and configured resource limits.
#[derive(Clone, Debug, Serialize)]
pub struct PoolStatus {
    pub idle_workers: u32,
    pub busy_workers: u32,
    pub restarts: u64,
    pub memory_cap_bytes: u64,
    pub memory_cap_hits: u64,
}

/// Paged worker history plus the current pool counters.
#[derive(Clone, Debug, Serialize)]
pub struct JobsPage {
    pub rows: Vec<JobRow>,
    pub total: u64,
    pub pool: PoolStatus,
}

impl JobsPage {
    pub fn empty(memory_cap_bytes: u64) -> Self {
        Self {
            rows: Vec::new(),
            total: 0,
            pool: PoolStatus {
                idle_workers: 0,
                busy_workers: 0,
                restarts: 0,
                memory_cap_bytes,
                memory_cap_hits: 0,
            },
        }
    }
}

/// Immutable pool configuration (from the session's RuntimeConfig).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub decompiler: PathBuf,
    pub spec_root: PathBuf,
    pub sla: PathBuf,
    pub language_dir: PathBuf,
    pub language_id: String,
    pub binary: PathBuf,
    pub program: String,
    pub project_dir: PathBuf,
    /// Load base (0 for ET_DYN, image base for PE).
    pub base: u64,
    /// Per-call deadline.
    pub deadline: Duration,
    /// Peak RSS allowed for one worker (bytes); 0 = enforce nothing.
    pub memory_cap: u64,
}

impl PoolConfig {
    pub fn from_runtime(
        config: &lre_core::session::RuntimeConfig,
        binary: &Path,
        program: &str,
        project_dir: &Path,
        language: &str,
    ) -> PoolResult<Self> {
        let (sla, spec_root, language_dir, language_id) =
            lre_core::native_runtime::language_decompile_config(config, language)
                .map_err(|error| WorkerError::Setup(error.to_string()))?;
        Ok(Self {
            decompiler: config.decompiler_path.clone(),
            spec_root,
            sla,
            language_dir,
            language_id,
            binary: binary.to_path_buf(),
            program: program.to_string(),
            project_dir: project_dir.to_path_buf(),
            base: 0,
            deadline: Duration::from_secs(60),
            memory_cap: config.worker_memory_cap,
        })
    }

    pub fn with_base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }
}

/// The supervised pool: bounded idle workers per program, warm reuse,
/// deadline-kill + restart.
pub struct WorkerPool {
    idle: HashMap<String, Vec<WorkerSession>>,
    config: PoolConfig,
    jobs: Vec<JobRow>,
    next_job_id: u64,
    busy_workers: u32,
    restarts: u64,
    memory_cap_hits: u64,
}

impl WorkerPool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            idle: HashMap::new(),
            config,
            jobs: Vec::new(),
            next_job_id: 1,
            busy_workers: 0,
            restarts: 0,
            memory_cap_hits: 0,
        }
    }

    pub fn matches_config(&self, config: &PoolConfig) -> bool {
        self.config == *config
    }

    fn begin_job(&mut self, operation: &str, address: Option<u64>) -> u64 {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.saturating_add(1);
        self.jobs.push(JobRow {
            id,
            operation: operation.to_owned(),
            address,
            state: JobState::Running,
            detail: String::new(),
        });
        self.busy_workers = self.busy_workers.saturating_add(1);
        if self.jobs.len() > 256 {
            self.jobs.remove(0);
        }
        id
    }

    fn finish_job(&mut self, id: u64, detail: Option<String>) {
        if let Some(job) = self.jobs.iter_mut().find(|job| job.id == id) {
            if job.state == JobState::Running {
                self.busy_workers = self.busy_workers.saturating_sub(1);
            }
            match detail {
                Some(detail) => {
                    job.state = JobState::Failed;
                    job.detail = detail;
                    self.restarts = self.restarts.saturating_add(1);
                }
                None => {
                    job.state = JobState::Succeeded;
                    job.detail = "completed".into();
                }
            }
        }
    }

    /// Returns the bounded worker history and current pool counters.
    pub fn jobs_page(&self, offset: u64, limit: u64) -> JobsPage {
        let total = self.jobs.len() as u64;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.jobs.len());
        let end = start
            .saturating_add(usize::try_from(limit).unwrap_or(usize::MAX))
            .min(self.jobs.len());
        JobsPage {
            rows: self.jobs[start..end].to_vec(),
            total,
            pool: PoolStatus {
                idle_workers: self.idle.values().map(|workers| workers.len() as u32).sum(),
                busy_workers: self.busy_workers,
                restarts: self.restarts,
                memory_cap_bytes: self.config.memory_cap,
                memory_cap_hits: self.memory_cap_hits,
            },
        }
    }

    fn key(&self) -> String {
        format!("{}@{}", self.config.program, self.config.binary.display())
    }

    fn take_or_spawn(
        &mut self,
        on_launch: impl FnOnce(&NativeWorker),
    ) -> PoolResult<WorkerSession> {
        let key = self.key();
        let session = self.idle.get_mut(&key).and_then(|workers| workers.pop());
        let mut session = match session {
            Some(session) => {
                on_launch(&session.worker);
                session
            }
            None => WorkerSession::spawn(&self.config, on_launch)?,
        };
        if let Err(error) = self.enforce_memory_cap(&mut session) {
            if matches!(error, PoolError::MemCap(_, _)) {
                self.memory_cap_hits = self.memory_cap_hits.saturating_add(1);
            }
            return Err(error);
        }
        Ok(session)
    }

    /// Runs an operation on a pooled worker with the configured deadline.
    pub fn with_worker<T>(
        &mut self,
        op: impl FnOnce(&mut WorkerSession) -> lre_worker::Result<T>,
    ) -> PoolResult<T> {
        self.with_worker_named("worker", None, op)
    }

    fn with_worker_named<T>(
        &mut self,
        operation: &str,
        address: Option<u64>,
        op: impl FnOnce(&mut WorkerSession) -> lre_worker::Result<T>,
    ) -> PoolResult<T> {
        let job = self.begin_job(operation, address);
        let result = self.run_worker(op);
        self.finish_job(job, result.as_ref().err().map(ToString::to_string));
        result
    }

    fn run_worker<T>(
        &mut self,
        op: impl FnOnce(&mut WorkerSession) -> lre_worker::Result<T>,
    ) -> PoolResult<T> {
        let deadline = Instant::now() + self.config.deadline;
        let (done, completion) = std::sync::mpsc::sync_channel(1);
        let mut watchdog = None;
        let result: PoolResult<(WorkerSession, T)> = (|| {
            let mut session = self.take_or_spawn(|worker| {
                let handle = worker.kill_handle();
                watchdog = Some(std::thread::spawn(move || {
                    if completion
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .is_err()
                    {
                        if let Ok(mut guard) = handle.lock() {
                            if let Some(mut child) = guard.take() {
                                let _ = child.kill();
                                let _ = child.wait();
                            }
                        }
                    }
                }));
            })?;
            let value = op(&mut session)?;
            Ok((session, value))
        })();
        let _ = done.send(());
        if let Some(watchdog) = watchdog {
            let _ = watchdog.join();
        }
        if Instant::now() >= deadline {
            // Never publish late output or return a timed-out session to idle.
            drop(result);
            return Err(PoolError::Deadline(self.config.deadline));
        }
        let (session, value) = result?;
        let key = self.key();
        self.idle.entry(key).or_default().push(session);
        Ok(value)
    }

    /// Linux-only worker RSS in bytes (VmRSS from /proc/<pid>/status);
    /// `None` when the platform or process is gone.
    fn worker_rss_bytes(pid: u32) -> Option<u64> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }

    /// Enforces `memory_cap`: if the worker's RSS exceeds the cap it is
    /// killed, the session poisoned, and `MemCap` returned (the retry path
    /// spawns fresh). Linux-only measurement (WORKER-003).
    fn enforce_memory_cap(&self, session: &mut WorkerSession) -> PoolResult<()> {
        let cap = self.config.memory_cap;
        if cap == 0 {
            return Ok(());
        }
        match session.pid().and_then(WorkerPool::worker_rss_bytes) {
            Some(rss) if rss > cap => {
                session.worker.kill()?;
                Err(PoolError::MemCap(rss, cap))
            }
            _ => Ok(()),
        }
    }

    /// Convenience: decompile one address with the pool's deadline.
    pub fn decompile(&mut self, address: u64) -> PoolResult<Vec<u8>> {
        self.with_worker_named("decompile", Some(address), |session| {
            session.decompile(address)
        })
    }

    /// Convenience: decompile and decode one structured document with the
    /// pool's deadline/restart semantics.
    pub fn decompile_doc(&mut self, address: u64) -> PoolResult<DecompDoc> {
        self.with_worker_named("decompile", Some(address), |session| {
            session.decompile_doc(address)
        })
    }
}

/// Owns the pool selected for the current API program and binary.
///
/// API and Qt callers keep one manager per Core handle. Switching binaries,
/// programs, or image bases drops the warm worker and starts a fresh pool on
/// the next decompile.
pub struct WorkerPoolManager {
    pool: Option<WorkerPool>,
}

impl Default for WorkerPoolManager {
    fn default() -> Self {
        Self { pool: None }
    }
}

impl WorkerPoolManager {
    fn ensure_pool(
        &mut self,
        core: &lre_core::Core,
        binary: &Path,
        program: &str,
        base: u64,
    ) -> PoolResult<&mut WorkerPool> {
        let language =
            lre_core::session::program_language(core.runtime_config(), program, core.db_path())
                .map_err(|error| WorkerError::Setup(error.to_string()))?;
        let config = PoolConfig::from_runtime(
            core.runtime_config(),
            binary,
            program,
            core.db_path(),
            &language,
        )?
        .with_base(base);
        if self
            .pool
            .as_ref()
            .map(|pool| !pool.matches_config(&config))
            .unwrap_or(true)
        {
            self.pool = Some(WorkerPool::new(config));
        }
        Ok(self.pool.as_mut().expect("worker pool initialized"))
    }

    /// Decompiles through the supervised pool and stamps the store revision.
    pub fn decompile_doc(
        &mut self,
        core: &lre_core::Core,
        binary: &Path,
        address: &Address,
        program: &str,
        base: Option<u64>,
    ) -> PoolResult<DecompDoc> {
        let mut doc = self
            .ensure_pool(core, binary, program, base.unwrap_or(0))?
            .decompile_doc(address.offset)?;
        doc.address = address.clone();
        let store = core.store_handle()?;
        let program_id = store.program_id(program)?;
        doc.revision = store.revision(program_id)?;
        Ok(doc)
    }

    /// Returns pool history and counters, even before the first decompile.
    pub fn jobs_page(&self, memory_cap_bytes: u64, offset: u64, limit: u64) -> JobsPage {
        self.pool
            .as_ref()
            .map(|pool| pool.jobs_page(offset, limit))
            .unwrap_or_else(|| JobsPage::empty(memory_cap_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn registration_deadline_kills_and_reaps_each_poisoned_worker() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "ventris-registration-deadline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let decompiler = root.join("hang");
        std::fs::write(&decompiler, "#!/bin/sh\nexec sleep 2\n").unwrap();
        std::fs::set_permissions(&decompiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let binary = root.join("raw.bin");
        std::fs::write(&binary, [0x90, 0xc3]).unwrap();
        for name in [
            "test.sla",
            "registers.txt",
            "pspec.xml",
            "cspec.xml",
            "coretypes.xml",
        ] {
            std::fs::write(root.join(name), "").unwrap();
        }
        std::fs::write(
            root.join("tspec.xml"),
            "<spaces><space name=\"ram\" index=\"3\"/><space name=\"register\" index=\"4\"/></spaces>",
        ).unwrap();
        let db = open_store(&root).unwrap();
        db.upsert_program(
            "deadline",
            "x86:LE:64:default",
            &lre_model::Provenance {
                producer: "deadline-test".into(),
                upstream_version: "test".into(),
            },
        )
        .unwrap();
        drop(db);
        let mut pool = WorkerPool::new(PoolConfig {
            decompiler,
            spec_root: root.clone(),
            sla: root.join("test.sla"),
            language_dir: root.clone(),
            language_id: "x86:LE:64:default".into(),
            binary,
            program: "deadline".into(),
            project_dir: root.clone(),
            base: 0,
            deadline: Duration::from_millis(250),
            memory_cap: 0,
        });
        let started = Instant::now();
        // A second attempt must launch a fresh child, not reuse poisoned I/O.
        let results = [pool.decompile_doc(0), pool.decompile_doc(0)];
        let elapsed = started.elapsed();
        // A protocol failure must remain an error, not wait for EOF until the
        // deadline turns it into a timeout. This child deliberately ignores EOF.
        std::fs::write(
            root.join("hang"),
            "#!/bin/sh\nprintf '\\000\\000\\001\\177'\nexec sleep 2\n",
        )
        .unwrap();
        let rejected = pool.decompile_doc(0);
        drop(pool);
        std::fs::remove_dir_all(root).unwrap();
        for result in results {
            assert!(matches!(&result, Err(PoolError::Deadline(_))), "{result:?}");
        }
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
        assert!(
            matches!(&rejected, Err(PoolError::Worker(_))),
            "{rejected:?}"
        );
    }
}
