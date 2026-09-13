//! Supervised persistent decompiler worker client (WORKER-001/002).
//!
//! A pool of warm `ghidra_opt` children: lease, per-call deadlines (a
//! wedged command is killed and the session poisoned, WORKER-002), and
//! restart on the next lease. `ProgramProvider` facts are loaded once per
//! spawn from the store + the mapped binary.

use romwright_model::{Address, DecompDoc};
use romwright_worker::{
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
}

impl WorkerSession {
    /// Spawns `ghidra_opt`, registers `program`, selects the decompile
    /// action, and loads all durable provider facts needed by callbacks.
    /// The provider includes the native section map and store facts.
    fn spawn(
        config: &PoolConfig, on_launch: impl FnOnce(&NativeWorker), asserted_returns_only: bool,
    ) -> PoolResult<Self> {
        let PoolConfig {
            decompiler,
            spec_root,
            binary,
            program,
            project_dir,
            base,
            ..
        } = config;
        romwright_worker::check_setup(decompiler, &config.sla)?;
        let mut provider =
            ProgramProvider::new(BinaryBacking::from_file(binary, *base)?, Vec::new());
        provider.load_language_info(spec_root)?;
        let db = open_store(project_dir)?;
        let pid = db.program_id(program)?;
        for f in db.functions(pid)? {
            let off = f.entry.offset;
            provider.functions.push(off);
            provider.function_names.insert(off, f.name);
            provider.function_sizes.insert(off, f.size as u64);
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
                    .insert(prototype.function.offset, prototype);
            }
        }
        for string in db.strings(pid)? {
            provider.strings.insert(string.address.offset, string.value);
        }
        provider.load_call_edges(&db, pid)?;
        provider.load_return_behaviors(&db, pid, asserted_returns_only)?;
        provider.load_calling_conventions(&db, pid)?;
        let function_shell = provider.function_shell()?;
        let spec_docs = load_specs(spec_root)?;
        let mut command = std::process::Command::new(decompiler);
        command
            .env("ROMWRIGHT_SLA", &config.sla)
            .env("ROMWRIGHT_LANGUAGE_DIR", &config.language_dir)
            .env("ROMWRIGHT_LANGUAGE", &config.language_id);
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
        Ok(Self { worker, provider })
    }

    fn ram_space(&self) -> u32 {
        self.provider.ram_space_index as u32
    }

    /// Decompiles one address. The pool wraps this with the deadline;
    /// a kill during the call surfaces as a read error (poisoned).
    pub fn decompile(&mut self, address: u64) -> romwright_worker::Result<Vec<u8>> {
        self.worker.prepare_function(&mut self.provider, address)?;
        let space = self.ram_space();
        self.worker.decompile_at(&mut self.provider, space, address)
    }

    /// Decompiles one address and decodes the pinned packed document into
    /// structured tokens and recovered prototype facts. The returned revision
    /// is zero because the response is not a store mutation; a Core/session
    /// caller stamps its current program revision when publishing it.
    pub fn decompile_doc(&mut self, address: u64) -> romwright_worker::Result<DecompDoc> {
        self.decompile_doc_mode(address, false)
    }

    fn decompile_doc_mode(&mut self, address: u64, recover: bool) -> romwright_worker::Result<DecompDoc> {
        let raw = if recover {
            self.worker
                .prepare_function_for_inference(&mut self.provider, address)?;
            let space = self.ram_space();
            self.worker
                .decompile_at(&mut self.provider, space, address)?
        } else {
            self.decompile(address)?
        };
        let decoded =
            romwright_worker::decode_document_with_ram_space(&raw, Some(self.ram_space() as u64));
        if recover && decoded.prototype.is_none() {
            return Err(WorkerError::Decompiler(format!(
                "function {address:#x} returned no prototype"
            )));
        }
        Ok(DecompDoc {
            tokens: decoded.tokens,
            prototype: decoded.prototype,
            jump_tables: decoded.jump_tables,
            address: Address::ram(address),
            revision: 0,
            storage: decoded.storage,
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
    Db(#[from] romwright_db::DbError),
    #[error("core: {0}")]
    Core(#[from] romwright_core::CoreError),
    #[error("worker deadline exceeded (lease budget {0:?})")]
    Deadline(Duration),
    #[error("worker exceed memory cap (rss {0} bytes > cap {1} bytes); killed")]
    MemCap(u64, u64),
    #[error("program revision changed during decompilation ({0} -> {1}); result discarded")]
    StaleRevision(u64, u64),
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
        config: &romwright_core::session::RuntimeConfig,
        binary: &Path,
        program: &str,
        project_dir: &Path,
        language: &str,
    ) -> PoolResult<Self> {
        let (sla, spec_root, language_dir, language_id) =
            romwright_core::native_runtime::language_decompile_config(config, language)
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
    // Set only on a fresh inference pool: prior inferred flags are not evidence.
    asserted_returns_only: bool,
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
            asserted_returns_only: false,
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
            None => WorkerSession::spawn(&self.config, on_launch, self.asserted_returns_only)?,
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
        op: impl FnOnce(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        let deadline = Instant::now() + self.config.deadline;
        self.with_worker_named("worker", None, deadline, op)
    }

    /// Runs an operation, recycling the worker once if the one the pool hands
    /// out has grown past the memory cap.
    ///
    /// The cap bounds a long session's memory; it is not a reason to fail the
    /// request that happens to discover the growth. `enforce_memory_cap` has
    /// already killed the offending worker and it is never returned to idle,
    /// so the second attempt spawns fresh -- the retry path the cap's own
    /// comment describes. A fresh worker over the cap still fails, because
    /// then the cap is below this language's floor rather than exceeded by
    /// one session's history.
    fn with_worker_retrying<T>(
        &mut self,
        operation: &str,
        address: Option<u64>,
        deadline: Instant,
        mut op: impl FnMut(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        match self.with_worker_named(operation, address, deadline, &mut op) {
            Err(PoolError::MemCap(..)) => {
                self.restarts = self.restarts.saturating_add(1);
                self.with_worker_named(operation, address, deadline, &mut op)
            }
            other => other,
        }
    }

    fn with_worker_named<T>(
        &mut self,
        operation: &str,
        address: Option<u64>,
        deadline: Instant,
        op: impl FnOnce(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        let job = self.begin_job(operation, address);
        let result = self.run_worker(deadline, op);
        self.finish_job(job, result.as_ref().err().map(ToString::to_string));
        result
    }

    fn run_worker<T>(
        &mut self,
        deadline: Instant,
        op: impl FnOnce(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PoolError::Deadline(remaining));
        }
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
            return Err(PoolError::Deadline(remaining));
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
        let deadline = Instant::now() + self.config.deadline;
        self.with_worker_retrying("decompile", Some(address), deadline, |session| {
            session.decompile(address)
        })
    }

    /// Convenience: decompile and decode one structured document with the
    /// pool's deadline/restart semantics.
    pub fn decompile_doc(&mut self, address: u64) -> PoolResult<DecompDoc> {
        let deadline = Instant::now() + self.config.deadline;
        self.with_worker_retrying("decompile", Some(address), deadline, |session| {
            session.decompile_doc(address)
        })
    }

    fn recover_doc(&mut self, address: u64, deadline: Instant) -> PoolResult<DecompDoc> {
        self.with_worker_retrying("infer_prototype", Some(address), deadline, |session| {
            session.decompile_doc_mode(address, true)
        })
    }

    fn invalidate_facts(&mut self) {
        self.idle.clear();
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceStopReason {
    Converged,
    RoundLimit,
    Budget,
}

/// Completed rounds and actual work; a budget interruption discards its partial round.
#[derive(Debug, Serialize)]
pub struct InferenceReport {
    pub rounds: u8,
    pub stop_reason: InferenceStopReason,
    pub analyzed: u64,
    /// Number of changed facts across completed rounds, not unique functions.
    pub changed: u64,
    /// Workers the memory cap recycled while this pass ran. A module large
    /// enough to grow the decompiler's caches past the cap is the normal
    /// reason, and the count is the cost of bounding it.
    pub worker_recycles: u64,
}

/// Owns the pool selected for the current API program and binary.
///
/// API and Qt callers keep one manager per Core handle. Switching binaries,
/// programs, or image bases drops the warm worker and starts a fresh pool on
/// the next decompile.
pub struct WorkerPoolManager {
    pool: Option<WorkerPool>,
    revision: u64,
}

impl Default for WorkerPoolManager {
    fn default() -> Self {
        Self {
            pool: None,
            revision: 0,
        }
    }
}

impl WorkerPoolManager {
    fn ensure_pool(
        &mut self,
        core: &romwright_core::Core,
        binary: &Path,
        program: &str,
        base: u64,
        revision: u64,
    ) -> PoolResult<&mut WorkerPool> {
        let language =
            romwright_core::session::program_language(core.runtime_config(), program, core.db_path())
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
        if self.revision != revision {
            self.pool
                .as_mut()
                .expect("worker pool initialized")
                .invalidate_facts();
            self.revision = revision;
        }
        Ok(self.pool.as_mut().expect("worker pool initialized"))
    }

    /// Decompiles through the supervised pool and stamps the store revision.
    pub fn decompile_doc(
        &mut self,
        core: &romwright_core::Core,
        binary: &Path,
        address: &Address,
        program: &str,
        base: Option<u64>,
    ) -> PoolResult<DecompDoc> {
        let store = core.store_handle()?;
        let program_id = store.program_id(program)?;
        let revision = store.revision(program_id)?;
        let mut doc = self
            .ensure_pool(core, binary, program, base.unwrap_or(0), revision)?
            .decompile_doc(address.offset)?;
        let current = store.revision(program_id)?;
        if current != revision {
            self.pool
                .as_mut()
                .expect("worker pool initialized")
                .invalidate_facts();
            return Err(PoolError::StaleRevision(revision, current));
        }
        doc.address = address.clone();
        doc.revision = revision;
        Ok(doc)
    }

    /// Fresh native hints cannot use previous inferred no-return flags as seeds.
    /// Publish only after the entire input-revision snapshot has been analyzed.
    pub fn infer_nonreturning(
        &mut self,
        core: &romwright_core::Core,
        binary: &Path,
        program: &str,
    ) -> PoolResult<romwright_core::NonReturnInferenceReport> {
        let store = core.store_handle()?;
        let id = store.program_id(program)?;
        let revision = store.revision(id)?;
        let config = PoolConfig::from_runtime(
            core.runtime_config(), binary, program, core.db_path(), &store.program_language(id)?,
        )?;
        let mut pool = WorkerPool::new(config);
        pool.asserted_returns_only = true;
        let mut hints = Vec::new();
        for function in store.functions(id)?.into_iter()
            .filter(|function| function.entry.space == romwright_model::AddressSpace::Ram)
        {
            let actual = store.revision(id)?;
            if actual != revision {
                return Err(PoolError::StaleRevision(revision, actual));
            }
            let doc = pool.decompile_doc(function.entry.offset)?;
            if doc.address != function.entry {
                return Err(WorkerError::Protocol("no-return hint address mismatch".into()).into());
            }
            if doc.prototype.is_some_and(|prototype| prototype.no_return) {
                hints.push(function.entry);
            }
        }
        Ok(core.infer_nonreturning(binary, program, revision, &hints)?)
    }

    /// Recovers all functions, then only callers of changed callees, for at most
    /// three rounds. One caller-supplied deadline covers setup and every lease.
    pub fn infer_prototypes(
        &mut self,
        core: &romwright_core::Core,
        binary: &Path,
        program: &str,
        base: Option<u64>,
        deadline: Instant,
    ) -> PoolResult<InferenceReport> {
        let mut report = InferenceReport {
            rounds: 0,
            stop_reason: InferenceStopReason::Budget,
            analyzed: 0,
            changed: 0,
            worker_recycles: 0,
        };
        if Instant::now() >= deadline {
            return Ok(report);
        }
        let store = core.store_handle()?;
        let id = store.program_id(program)?;
        let graph_revision = store.revision(id)?;
        // The register-parameter pass reads the program's own compiler spec.
        let language = store.program_language(id)?;
        // A linkage stub has no callee body to recover. Treating its empty
        // prototype as void(void) would erase live arguments in its callers.
        let externals: HashSet<_> = store
            .symbols(id)?
            .into_iter()
            .filter(|symbol| symbol.external)
            .map(|symbol| symbol.address)
            .collect();
        let mut functions = store.functions(id)?;
        functions.retain(|function| function.entry.space == romwright_model::AddressSpace::Ram);
        let mut edges = store.call_edges(id)?;
        edges.retain(|(from, to)| {
            from.space == romwright_model::AddressSpace::Ram && to.space == romwright_model::AddressSpace::Ram
        });
        let mut callers: HashMap<u64, Vec<usize>> = HashMap::new();
        for (index, function) in functions.iter().enumerate() {
            let entry = function.entry.offset;
            let first = edges.partition_point(|(from, _)| from.offset < entry);
            for (from, to) in &edges[first..] {
                if from.offset - entry >= function.size as u64 {
                    break;
                }
                let owners = callers.entry(to.offset).or_default();
                if owners.last() != Some(&index) {
                    owners.push(index);
                }
            }
        }
        let mut revision = graph_revision;
        let mut pending: Vec<usize> = (0..functions.len()).collect();
        let mut dirty = vec![false; functions.len()];
        let mut recovered = Vec::with_capacity(functions.len());
        while report.rounds < 3 && !pending.is_empty() {
            if Instant::now() >= deadline {
                return Ok(report);
            }
            let current = store.revision(id)?;
            if current != revision {
                return Err(PoolError::StaleRevision(revision, current));
            }
            let pool = self.ensure_pool(core, binary, program, base.unwrap_or(0), revision)?;
            for &index in &pending {
                let function = &functions[index];
                // Recycles are counted as they happen: a pass that stops on
                // its budget returns from inside this loop, and the cost of
                // bounding the worker's memory has to be in the report it
                // returns.
                let restarts_before = pool.restarts;
                let doc = match pool.recover_doc(function.entry.offset, deadline) {
                    Ok(doc) => doc,
                    Err(PoolError::Deadline(_)) => return Ok(report),
                    Err(error) => return Err(error),
                };
                let current = store.revision(id)?;
                if current != revision {
                    pool.invalidate_facts();
                    return Err(PoolError::StaleRevision(revision, current));
                }
                report.worker_recycles += u64::from(pool.restarts.saturating_sub(restarts_before));
                report.analyzed += 1;
                if !externals.contains(&function.entry) {
                    let mut prototype = doc.prototype.expect("recovery requires a prototype");
                    // The decompiler's irregular inputs are evidence its own
                    // model had no slot for; the pass is off unless asked.
                    romwright_core::register_params::augment(
                        core.runtime_config(),
                        &language,
                        &mut prototype,
                        &doc.storage,
                    );
                    recovered.push((function.entry.clone(), prototype));
                }
            }
            if Instant::now() >= deadline {
                return Ok(report);
            }
            let changed = core.persist_inferred_prototypes(program, revision, &recovered)?;
            report.rounds += 1;
            report.changed += changed.len() as u64;
            // The merge is the only mutation accepted between these rounds.
            // A concurrent edit after it is still rejected by the next check.
            if !changed.is_empty() {
                revision += 1;
            }
            pending.clear();
            for function in changed {
                if let Some(owners) = callers.get(&function.offset) {
                    for &owner in owners {
                        dirty[owner] = true;
                    }
                }
            }
            for (index, changed) in dirty.iter_mut().enumerate() {
                if std::mem::take(changed) {
                    pending.push(index);
                }
            }
            recovered.clear();
        }
        report.stop_reason = if pending.is_empty() {
            InferenceStopReason::Converged
        } else {
            InferenceStopReason::RoundLimit
        };
        Ok(report)
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
            "romwright-registration-deadline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let decompiler = root.join("hang");
        std::fs::write(
            &decompiler,
            "#!/bin/sh\nprintf x >> \"$0.started\"\nexec sleep 2\n",
        )
        .unwrap();
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
            "<spaces><space name=\"ram\" index=\"3\" size=\"8\"/>\
             <space name=\"register\" index=\"4\" size=\"8\"/></spaces>",
        ).unwrap();
        let db = open_store(&root).unwrap();
        db.upsert_program(
            "deadline",
            "x86:LE:64:default",
            &romwright_model::Provenance {
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
        let deadline = Instant::now() + Duration::from_millis(250);
        let shared = [pool.recover_doc(0, deadline), pool.recover_doc(0, deadline)];
        let starts = std::fs::read(root.join("hang.started")).unwrap();
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
        for result in shared {
            assert!(matches!(result, Err(PoolError::Deadline(_))), "{result:?}");
        }
        assert_eq!(
            starts, b"xxx",
            "an expired shared deadline must not launch another child"
        );
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
        assert!(
            matches!(&rejected, Err(PoolError::Worker(_))),
            "{rejected:?}"
        );
    }
}
