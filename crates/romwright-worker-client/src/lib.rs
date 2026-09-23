//! Supervised persistent decompiler worker client (WORKER-001/002).
//!
//! Warm native sessions consume Core's captured input, language, revision and
//! absolute job deadline. Failed sessions are poisoned and their owned process
//! groups terminated; completed sessions are reused only for identical inputs
//! and store facts.

use romwright_core::exec::CancelToken;
use romwright_model::{Address, DecompDoc};
use romwright_worker::{ProgramProvider, WorkerError, open_store, worker::NativeWorker};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// One warm worker session: a spawned decompiler + its program facts.
pub struct WorkerSession {
    worker: NativeWorker,
    provider: ProgramProvider,
    ir_passes: Vec<String>,
}

impl WorkerSession {
    /// Spawns `ghidra_opt`, registers `program`, selects the decompile
    /// action, and loads all durable provider facts needed by callbacks.
    /// The provider includes the native section map and store facts.
    fn spawn(
        config: &PoolConfig,
        on_launch: impl FnOnce(&NativeWorker),
        asserted_returns_only: bool,
    ) -> PoolResult<Self> {
        let PoolConfig {
            decompiler,
            spec_root,
            program,
            project_dir,
            ..
        } = config;
        romwright_worker::check_setup(decompiler, &config.sla)?;
        let db = open_store(project_dir)?;
        let pid = db.program_id(program)?;
        let mut provider = ProgramProvider::from_store(
            project_dir,
            &config.input,
            spec_root,
            &db,
            pid,
            asserted_returns_only,
        )?;
        let spec_docs =
            romwright_worker::specs::load_program_specs(&mut provider, spec_root, &db, pid)?;
        let function_shell = provider.function_shell()?;
        let mut command = std::process::Command::new(decompiler);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
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
        Ok(Self {
            worker,
            provider,
            ir_passes: config.ir_passes.clone(),
        })
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

    /// Decodes one document under the pool's absolute deadline. The Core
    /// caller publishes it only against the revision captured before work.
    pub fn decompile_doc(
        &mut self,
        address: u64,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> romwright_worker::Result<DecompDoc> {
        self.decompile_doc_mode(address, false, deadline, cancel)
    }

    fn decompile_doc_mode(
        &mut self,
        address: u64,
        recover: bool,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> romwright_worker::Result<DecompDoc> {
        let raw = if recover {
            self.worker
                .prepare_function_for_inference(&mut self.provider, address)?;
            let space = self.ram_space();
            self.worker
                .decompile_at(&mut self.provider, space, address)?
        } else {
            self.decompile(address)?
        };
        let space = self.ram_space();
        let decoded = self.worker.finalize_document(
            &mut self.provider,
            &raw,
            space,
            address,
            &self.ir_passes,
            Some(deadline),
            Some(cancel),
        )?;
        if recover && decoded.prototype.is_none() {
            return Err(WorkerError::Decompiler(format!(
                "function {address:#x} returned no prototype"
            )));
        }
        Ok(DecompDoc {
            tokens: decoded.tokens,
            prototype: decoded.prototype,
            call_prototypes: decoded.call_prototypes,
            call_targets: decoded.call_targets,
            jump_tables: decoded.jump_tables,
            address: Address::ram(address),
            revision: 0,
            storage: decoded.storage,
            function_ir: decoded.function_ir,
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
    #[error("job cancelled; worker killed")]
    Cancelled,
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
    Cancelled,
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
    pub input: romwright_model::ProgramInput,
    pub program: String,
    pub project_dir: PathBuf,
    /// Budget for convenience calls without an explicit execution request.
    pub deadline: Duration,
    /// Peak RSS allowed for one worker (bytes); 0 = enforce nothing.
    pub memory_cap: u64,
    pub ir_passes: Vec<String>,
}

impl PoolConfig {
    pub fn from_request(request: &romwright_core::exec::ExecutionRequest) -> PoolResult<Self> {
        let config = &request.config;
        let (sla, spec_root, language_dir, language_id) =
            romwright_core::native_runtime::language_decompile_config(config, &request.language)
                .map_err(|error| WorkerError::Setup(error.to_string()))?;
        Ok(Self {
            decompiler: config.decompiler_path.clone(),
            spec_root,
            sla,
            language_dir,
            language_id,
            input: request.input.clone(),
            program: request.program.clone(),
            project_dir: request.project_dir.clone(),
            deadline: romwright_core::exec::DEFAULT_BUDGET,
            memory_cap: config.worker_memory_cap,
            ir_passes: config.ir_passes.clone(),
        })
    }
}

/// The supervised pool: bounded idle workers per program, warm reuse,
/// deadline-kill + restart.
pub struct WorkerPool {
    idle: Option<WorkerSession>,
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
            idle: None,
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
                idle_workers: u32::from(self.idle.is_some()),
                busy_workers: self.busy_workers,
                restarts: self.restarts,
                memory_cap_bytes: self.config.memory_cap,
                memory_cap_hits: self.memory_cap_hits,
            },
        }
    }

    fn take_or_spawn(
        &mut self,
        on_launch: impl FnOnce(&NativeWorker),
    ) -> PoolResult<WorkerSession> {
        let session = self.idle.take();
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
        cancel: &CancelToken,
        op: impl FnOnce(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        let deadline = Instant::now() + self.config.deadline;
        self.with_worker_named("worker", None, deadline, cancel, op)
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
        cancel: &CancelToken,
        mut op: impl FnMut(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        match self.with_worker_named(operation, address, deadline, cancel, &mut op) {
            Err(PoolError::MemCap(..)) => {
                self.restarts = self.restarts.saturating_add(1);
                self.with_worker_named(operation, address, deadline, cancel, &mut op)
            }
            other => other,
        }
    }

    fn with_worker_named<T>(
        &mut self,
        operation: &str,
        address: Option<u64>,
        deadline: Instant,
        cancel: &CancelToken,
        op: impl FnOnce(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        let job = self.begin_job(operation, address);
        let result = self.run_worker(deadline, cancel, op);
        self.finish_job(job, result.as_ref().err().map(ToString::to_string));
        result
    }

    fn run_worker<T>(
        &mut self,
        deadline: Instant,
        cancel: &CancelToken,
        op: impl FnOnce(&mut WorkerSession) -> romwright_worker::Result<T>,
    ) -> PoolResult<T> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PoolError::Deadline(remaining));
        }
        if cancel.is_cancelled() {
            return Err(PoolError::Cancelled);
        }
        let (done, completion) = std::sync::mpsc::sync_channel(1);
        let mut watchdog = None;
        let cancel_watch = cancel.clone();
        let result: PoolResult<(WorkerSession, T)> = (|| {
            let mut session = self.take_or_spawn(|worker| {
                let handle = worker.kill_handle();
                watchdog = Some(std::thread::spawn(move || {
                    // Poll so a cancel request kills a wedged child instead of
                    // waiting out the deadline. `recv_timeout` returns
                    // `Err(Disconnected)` once the worker finishes and drops
                    // `done`, which is the normal exit — not a kill.
                    loop {
                        let step = deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(50));
                        match completion.recv_timeout(step) {
                            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                if Instant::now() >= deadline || cancel_watch.is_cancelled() {
                                    if let Ok(mut guard) = handle.lock()
                                        && let Some(mut child) = guard.take()
                                    {
                                        romwright_core::exec::kill_child(&mut child);
                                        let _ = child.wait();
                                    }
                                    break;
                                }
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
        if cancel.is_cancelled() {
            // A cancelled job's output is never published and its session is
            // not returned to idle: the kill may have left the protocol
            // stream mid-message.
            drop(result);
            return Err(PoolError::Cancelled);
        }
        if Instant::now() >= deadline {
            // Never publish late output or return a timed-out session to idle.
            drop(result);
            return Err(PoolError::Deadline(remaining));
        }
        let (session, value) = result?;
        self.idle = Some(session);
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
    pub fn decompile(&mut self, address: u64, cancel: &CancelToken) -> PoolResult<Vec<u8>> {
        let deadline = Instant::now() + self.config.deadline;
        self.with_worker_retrying("decompile", Some(address), deadline, cancel, |session| {
            session.decompile(address)
        })
    }

    /// Convenience: decompile and decode one structured document with the
    /// pool's deadline/restart semantics.
    pub fn decompile_doc(
        &mut self,
        address: u64,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> PoolResult<DecompDoc> {
        self.with_worker_retrying("decompile", Some(address), deadline, cancel, |session| {
            session.decompile_doc(address, deadline, cancel)
        })
    }

    fn recover_doc(
        &mut self,
        address: u64,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> PoolResult<DecompDoc> {
        self.with_worker_retrying(
            "infer_prototype",
            Some(address),
            deadline,
            cancel,
            |session| session.decompile_doc_mode(address, true, deadline, cancel),
        )
    }

    fn invalidate_facts(&mut self) {
        self.idle.take();
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
    /// Every analyzed function entry in analysis order, across rounds:
    /// re-analyzed callers repeat. Powers per-function progress rows.
    pub analyzed_addresses: Vec<u64>,
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
        req: &romwright_core::exec::ExecutionRequest,
        revision: u64,
    ) -> PoolResult<&mut WorkerPool> {
        let config = PoolConfig::from_request(req)?;
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
    /// The request carries the resolved binary, program, base, revision, and
    /// cancellation token — the manager consumes them rather than re-deriving.
    pub fn decompile_doc(
        &mut self,
        core: &romwright_core::Core,
        req: &romwright_core::exec::ExecutionRequest,
        address: &Address,
    ) -> PoolResult<DecompDoc> {
        let store = core.store_handle()?;
        let program_id = store.program_id(&req.program)?;
        let revision = req.revision;
        let mut doc = self.ensure_pool(req, revision)?.decompile_doc(
            address.offset,
            req.deadline,
            &req.cancel,
        )?;
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
    /// The request supplies the resolved binary, program, revision, and
    /// cancellation token; each function is a cancellation checkpoint.
    pub fn infer_nonreturning(
        &mut self,
        core: &romwright_core::Core,
        req: &romwright_core::exec::ExecutionRequest,
    ) -> PoolResult<romwright_core::NonReturnInferenceReport> {
        let store = core.store_handle()?;
        let id = store.program_id(&req.program)?;
        let revision = req.revision;
        let config = PoolConfig::from_request(req)?;
        let mut pool = WorkerPool::new(config);
        pool.asserted_returns_only = true;
        let mut hints = Vec::new();
        for function in store
            .functions(id)?
            .into_iter()
            .filter(|function| function.entry.space == romwright_model::AddressSpace::Ram)
        {
            if req.cancel.is_cancelled() {
                return Err(PoolError::Cancelled);
            }
            let actual = store.revision(id)?;
            if actual != revision {
                return Err(PoolError::StaleRevision(revision, actual));
            }
            let doc = pool.decompile_doc(function.entry.offset, req.deadline, &req.cancel)?;
            if doc.address != function.entry {
                return Err(WorkerError::Protocol("no-return hint address mismatch".into()).into());
            }
            if doc.prototype.is_some_and(|prototype| prototype.no_return) {
                hints.push(function.entry);
            }
        }
        Ok(core.infer_nonreturning(req, &hints)?)
    }

    /// Recovers all functions, then only callers of changed callees, for at most
    /// three rounds. The request's deadline covers setup and every lease; its
    /// cancellation token is checked each round and each function.
    pub fn infer_prototypes(
        &mut self,
        core: &romwright_core::Core,
        req: &romwright_core::exec::ExecutionRequest,
    ) -> PoolResult<InferenceReport> {
        let deadline = req.deadline;
        let mut report = InferenceReport {
            rounds: 0,
            stop_reason: InferenceStopReason::Budget,
            analyzed: 0,
            analyzed_addresses: Vec::new(),
            changed: 0,
            worker_recycles: 0,
        };
        if Instant::now() >= deadline {
            return Ok(report);
        }
        let store = core.store_handle()?;
        let id = store.program_id(&req.program)?;
        let graph_revision = store.revision(id)?;
        if graph_revision != req.revision {
            return Err(PoolError::StaleRevision(req.revision, graph_revision));
        }
        // The register-parameter pass reads the program's own compiler spec.
        let language = &req.language;
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
            from.space == romwright_model::AddressSpace::Ram
                && to.space == romwright_model::AddressSpace::Ram
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
            if req.cancel.is_cancelled() {
                return Err(PoolError::Cancelled);
            }
            let current = store.revision(id)?;
            if current != revision {
                return Err(PoolError::StaleRevision(revision, current));
            }
            let pool = self.ensure_pool(req, revision)?;
            for &index in &pending {
                if req.cancel.is_cancelled() {
                    return Err(PoolError::Cancelled);
                }
                let function = &functions[index];
                // Recycles are counted as they happen: a pass that stops on
                // its budget returns from inside this loop, and the cost of
                // bounding the worker's memory has to be in the report it
                // returns.
                let restarts_before = pool.restarts;
                let result = pool.recover_doc(function.entry.offset, deadline, &req.cancel);
                report.worker_recycles += pool.restarts - restarts_before;
                let doc = match result {
                    Ok(doc) => doc,
                    Err(PoolError::Deadline(_)) => return Ok(report),
                    Err(error) => return Err(error),
                };
                report.analyzed += 1;
                report.analyzed_addresses.push(function.entry.offset);
                if !externals.contains(&function.entry) {
                    let mut prototype = doc.prototype.expect("recovery requires a prototype");
                    // The decompiler's irregular inputs are evidence its own
                    // model had no slot for; the pass is off unless asked.
                    romwright_core::register_params::augment(
                        &req.config,
                        language,
                        &mut prototype,
                        &doc.storage,
                    );
                    recovered.push((function.entry.clone(), prototype));
                }
            }
            if Instant::now() >= deadline {
                return Ok(report);
            }
            let changed = req.cancel.publish(deadline, || {
                core.persist_inferred_prototypes(&req.program, revision, &recovered)
            })?;
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

/// What one queued job runs.
#[derive(Debug)]
pub enum JobKind {
    DecompileDoc {
        address: u64,
    },
    InferPrototypes,
    InferNonreturning,
    MatchSource {
        prepared: romwright_core::matching::PreparedMatch,
    },
    Matching {
        operation: romwright_model::matching::MatchingOperation,
    },
}

impl JobKind {
    fn operation(&self) -> &'static str {
        match self {
            JobKind::DecompileDoc { .. } => "decompile_doc",
            JobKind::InferPrototypes => "infer_prototypes",
            JobKind::InferNonreturning => "infer_nonreturning",
            JobKind::MatchSource { .. } => "match_source",
            JobKind::Matching { operation } => match operation {
                romwright_model::matching::MatchingOperation::Trial { .. } => "matching_trial",
                romwright_model::matching::MatchingOperation::Search { .. } => "matching_search",
                romwright_model::matching::MatchingOperation::Calibrate { .. } => "matching_calibrate",
                romwright_model::matching::MatchingOperation::Context { .. } => "matching_context",
                romwright_model::matching::MatchingOperation::PreparePatch { .. } => "matching_patch",
                romwright_model::matching::MatchingOperation::VerifyPatch { .. } => "matching_verify_patch",
            },
        }
    }
}

struct Job {
    id: u64,
    kind: JobKind,
    req: romwright_core::exec::ExecutionRequest,
}

struct JobRecord {
    operation: &'static str,
    state: JobState,
    detail: String,
    cancel: CancelToken,
    result: Option<Result<serde_json::Value, String>>,
    /// Function this record analyzed, when it names one: per-function
    /// progress rows for inference passes, or a decompile target.
    address: Option<u64>,
}

struct Shared {
    queue: std::collections::VecDeque<Job>,
    records: HashMap<u64, JobRecord>,
    order: Vec<u64>,
    next_id: u64,
    shutdown: bool,
}

struct ExecutorInner {
    state: std::sync::Mutex<Shared>,
    queued: std::sync::Condvar,
    finished: std::sync::Condvar,
}

/// A bounded executor that runs long analysis jobs off the request path.
///
/// The HTTP service stays responsive because a `decompile_doc` or an
/// inference pass no longer holds the request loop: `submit` returns a job id
/// immediately and a fixed set of worker threads drains the queue. Each
/// thread opens its own `Core` on the project — the store is SQLite, so a
/// second connection is a second reader — and keeps a `WorkerPoolManager` so
/// warm decompiler children are reused across jobs on the same thread.
///
/// Cancellation is cooperative: `cancel` sets the job's token, a queued job
/// is dropped before it starts, and a running job's token is polled between
/// functions and by the worker watchdog that kills a child that does not
/// stop.
pub struct JobExecutor {
    inner: std::sync::Arc<ExecutorInner>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl JobExecutor {
    /// Spawns `workers` job threads. `workers == 0` is treated as one.
    pub fn new(workers: usize) -> Self {
        let inner = std::sync::Arc::new(ExecutorInner {
            state: std::sync::Mutex::new(Shared {
                queue: std::collections::VecDeque::new(),
                records: HashMap::new(),
                order: Vec::new(),
                next_id: 1,
                shutdown: false,
            }),
            queued: std::sync::Condvar::new(),
            finished: std::sync::Condvar::new(),
        });
        let mut handles = Vec::with_capacity(workers.max(1));
        for _ in 0..workers.max(1) {
            let inner = std::sync::Arc::clone(&inner);
            handles.push(std::thread::spawn(move || executor_loop(inner)));
        }
        Self { inner, workers: handles }
    }

    /// Enqueues a job and returns its id. The request is already resolved, so
    /// the job's inputs are fixed at this point.
    pub fn submit(&self, kind: JobKind, req: romwright_core::exec::ExecutionRequest) -> u64 {
        let mut state = self.inner.state.lock().expect("executor lock poisoned");
        let id = state.next_id;
        state.next_id = state.next_id.saturating_add(1);
        state.records.insert(
            id,
            JobRecord {
                operation: kind.operation(),
                state: JobState::Queued,
                detail: String::new(),
                cancel: req.cancel.clone(),
                result: None,
                address: match &kind {
                    JobKind::DecompileDoc { address } => Some(*address),
                    _ => None,
                },
            },
        );
        state.order.push(id);
        state.queue.push_back(Job { id, kind, req });
        self.inner.queued.notify_one();
        id
    }

    /// The job's current state and, once finished, its result.
    pub fn status(&self, id: u64) -> Option<serde_json::Value> {
        let state = self.inner.state.lock().expect("executor lock poisoned");
        let record = state.records.get(&id)?;
        Some(serde_json::json!({
            "id": id,
            "operation": record.operation,
            "state": record.state,
            "detail": record.detail,
            "result": record.result.as_ref().map(|r| match r {
                Ok(value) => value.clone(),
                Err(error) => serde_json::json!({ "error": error }),
            }),
        }))
    }

    /// Requests cancellation. A queued job is dropped; a running job's token
    /// is set so the next checkpoint or the watchdog stops it. Returns false
    /// for an unknown id.
    pub fn cancel(&self, id: u64) -> bool {
        let token = {
            let mut state = self.inner.state.lock().expect("executor lock poisoned");
            let Some(record) = state.records.get(&id) else {
                return false;
            };
            if !matches!(record.state, JobState::Queued | JobState::Running) {
                return false;
            }
            let queued = record.state == JobState::Queued;
            let token = record.cancel.clone();
            if queued {
                state.queue.retain(|job| job.id != id);
                let record = state.records.get_mut(&id).expect("known job");
                record.state = JobState::Cancelled;
                record.detail = "cancelled before start".into();
                record.result = Some(Err("cancelled".into()));
                self.inner.finished.notify_all();
            }
            token
        };
        // A publication may hold the token gate briefly. Never hold the
        // executor registry lock while waiting for that transaction.
        token.cancel();
        true
    }

    /// Blocks until the job reaches a terminal state and returns its result.
    pub fn wait(&self, id: u64) -> Option<Result<serde_json::Value, String>> {
        let mut state = self.inner.state.lock().expect("executor lock poisoned");
        loop {
            match state.records.get(&id) {
                None => return None,
                Some(record)
                    if matches!(
                        record.state,
                        JobState::Succeeded | JobState::Failed | JobState::Cancelled
                    ) =>
                {
                    return record.result.clone();
                }
                Some(_) => {
                    state = self
                        .inner
                        .finished
                        .wait(state)
                        .expect("executor lock poisoned");
                }
            }
        }
    }

    /// Paged job history, newest last, in submission order.
    pub fn jobs_page(&self, offset: u64, limit: u64) -> serde_json::Value {
        let state = self.inner.state.lock().expect("executor lock poisoned");
        let total = state.order.len() as u64;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(state.order.len());
        let end = start
            .saturating_add(usize::try_from(limit).unwrap_or(usize::MAX))
            .min(state.order.len());
        let rows: Vec<serde_json::Value> = state.order[start..end]
            .iter()
            .filter_map(|id| {
                let record = state.records.get(id)?;
                Some(serde_json::json!({
                    "id": id,
                    "operation": record.operation,
                    "state": record.state,
                    "detail": record.detail,
                    "address": record.address,
                }))
            })
            .collect();
        serde_json::json!({ "rows": rows, "total": total })
    }
}

impl Drop for JobExecutor {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.shutdown = true;
            for record in state.records.values() {
                if matches!(record.state, JobState::Queued | JobState::Running) {
                    record.cancel.cancel();
                }
            }
        }
        self.inner.queued.notify_all();
        // Cancellation must reach child-process cleanup before the owning
        // application exits and destroys the worker threads themselves.
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn executor_loop(inner: std::sync::Arc<ExecutorInner>) {
    // Warm caches per thread: one Core and one WorkerPoolManager per project,
    // so consecutive jobs on this thread reuse the parsed image and the warm
    // decompiler child instead of paying a reload and a respawn each time.
    let mut caches: HashMap<PathBuf, (romwright_core::Core, WorkerPoolManager)> = HashMap::new();
    loop {
        let job = {
            let mut state = inner.state.lock().expect("executor lock poisoned");
            loop {
                if state.shutdown {
                    return;
                }
                if let Some(job) = state.queue.pop_front() {
                    if let Some(record) = state.records.get_mut(&job.id) {
                        record.state = JobState::Running;
                    }
                    break job;
                }
                state = inner.queued.wait(state).expect("executor lock poisoned");
            }
        };
        let result = run_job(&mut caches, job.kind, &job.req);
        let mut state = inner.state.lock().expect("executor lock poisoned");
        if let Some(record) = state.records.get_mut(&job.id) {
            // Inference reports carry their analyzed addresses: expand
            // them into per-function progress rows now, while the
            // report value is at hand.
            let progress: Option<Vec<u64>> = match &result {
                Ok(value) => value.get("analyzed_addresses").map(|array| {
                    array
                        .as_array()
                        .map(|items| {
                            items.iter().filter_map(serde_json::Value::as_u64).collect()
                        })
                        .unwrap_or_default()
                }),
                Err(_) => None,
            };
            match &result {
                Ok(_) => {
                    record.state = JobState::Succeeded;
                    record.detail = "completed".into();
                }
                Err(error) if job.req.cancel.is_cancelled() => {
                    record.state = JobState::Cancelled;
                    record.detail = error.clone();
                }
                Err(error) => {
                    record.state = JobState::Failed;
                    record.detail = error.clone();
                }
            }
            record.result = Some(result);
            // A completed inference pass lists its functions, not
            // itself: swap the parent out of page order for one row
            // per analyzed address. The parent stays in records, so
            // wait and status keep working; a pass that analyzed
            // nothing (budget-exhausted round zero) leaves no rows.
            if let Some(addresses) = progress {
                let operation = record.operation;
                let cancel = job.req.cancel.clone();
                state.order.retain(|id| *id != job.id);
                for address in addresses {
                    let id = state.next_id;
                    state.next_id = state.next_id.saturating_add(1);
                    state.order.push(id);
                    state.records.insert(
                        id,
                        JobRecord {
                            operation,
                            state: JobState::Succeeded,
                            detail: "completed".into(),
                            cancel: cancel.clone(),
                            result: None,
                            address: Some(address),
                        },
                    );
                }
            }
        }
        inner.finished.notify_all();
    }
}

fn run_job(
    caches: &mut HashMap<PathBuf, (romwright_core::Core, WorkerPoolManager)>,
    kind: JobKind,
    req: &romwright_core::exec::ExecutionRequest,
) -> Result<serde_json::Value, String> {
    // Explicit cancellation fails fast here; an expired deadline is the
    // manager's graceful empty report, not a dispatch error (m2-006 pins
    // rounds 0 / stop budget for budget_ms=0).
    req.cancel
        .check_cancelled()
        .map_err(|error| error.to_string())?;
    if caches
        .get(&req.project_dir)
        .is_some_and(|(core, _)| core.runtime_config() != &req.config)
    {
        caches.remove(&req.project_dir);
    }
    if caches.len() >= 4 && !caches.contains_key(&req.project_dir) {
        caches.clear();
    }
    let (core, manager) = match caches.entry(req.project_dir.clone()) {
        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::hash_map::Entry::Vacant(entry) => {
            let core = romwright_core::Core::open_with_config(
                &req.project_dir,
                req.config.clone(),
            )
            .map_err(|error| error.to_string())?;
            entry.insert((core, WorkerPoolManager::default()))
        }
    };
    let (core, manager) = (&*core, manager);
    match kind {
        JobKind::DecompileDoc { address } => manager
            .decompile_doc(core, req, &Address::ram(address))
            .map_err(|error| error.to_string())
            .and_then(|doc| serde_json::to_value(doc).map_err(|e| e.to_string())),
        JobKind::InferPrototypes => manager
            .infer_prototypes(core, req)
            .map_err(|error| error.to_string())
            .and_then(|report| serde_json::to_value(report).map_err(|e| e.to_string())),
        JobKind::InferNonreturning => manager
            .infer_nonreturning(core, req)
            .map_err(|error| error.to_string())
            .and_then(|report| serde_json::to_value(report).map_err(|e| e.to_string())),
        JobKind::MatchSource { prepared } => core
            .run_matching(req, &prepared)
            .map_err(|error| error.to_string())
            .and_then(|report| serde_json::to_value(report).map_err(|error| error.to_string())),
        JobKind::Matching { operation } => core
            .run_matching_operation(req, operation)
            .map_err(|error| error.to_string()),
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
            "#!/bin/sh\nprintf x >> \"$0.started\"\nsleep 2\n",
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
        )
        .unwrap();
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
        let artifact = romwright_core::artifact::Artifact::capture(&root, &binary).unwrap();
        let input = romwright_model::ProgramInput {
            source_path: binary.to_string_lossy().into_owned(),
            binary_digest: artifact.digest,
            image_selector: String::new(),
            map_digest: None,
            keys_digest: None,
            raw: Some((0, "x86:LE:64:default".into())),
        };
        let mut pool = WorkerPool::new(PoolConfig {
            decompiler,
            spec_root: root.clone(),
            sla: root.join("test.sla"),
            language_dir: root.clone(),
            language_id: "x86:LE:64:default".into(),
            input,
            program: "deadline".into(),
            project_dir: root.clone(),
            deadline: Duration::from_millis(250),
            memory_cap: 0,
            ir_passes: Vec::new(),
        });
        let started = Instant::now();
        let never = CancelToken::default();
        // A second attempt must launch a fresh child, not reuse poisoned I/O.
        let results = [
            pool.decompile_doc(0, Instant::now() + Duration::from_millis(250), &never),
            pool.decompile_doc(0, Instant::now() + Duration::from_millis(250), &never),
        ];
        let elapsed = started.elapsed();
        let deadline = Instant::now() + Duration::from_millis(250);
        let shared = [
            pool.recover_doc(0, deadline, &never),
            pool.recover_doc(0, deadline, &never),
        ];
        for result in results.into_iter().chain(shared) {
            assert!(matches!(result, Err(PoolError::Deadline(_))), "{result:?}");
        }
        let starts = std::fs::read(root.join("hang.started")).unwrap();
        // A protocol failure must remain an error, not wait for EOF until the
        // deadline turns it into a timeout. This child deliberately ignores EOF.
        std::fs::write(
            root.join("hang"),
            "#!/bin/sh\nprintf '\\000\\000\\001\\177'\nsleep 2\n",
        )
        .unwrap();
        let rejected = pool.decompile_doc(0, Instant::now() + Duration::from_millis(250), &never);
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
