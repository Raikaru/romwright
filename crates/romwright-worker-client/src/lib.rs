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
    // Decompiler children this pool has launched, whether or not they ever
    // answered. Tests read it: a child's own side effects cannot count
    // launches, because a child killed before it runs leaves none.
    #[cfg(test)]
    launches: u64,
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
            #[cfg(test)]
            launches: 0,
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
            None => WorkerSession::spawn(
                &self.config,
                |worker| {
                    #[cfg(test)]
                    {
                        self.launches += 1;
                    }
                    on_launch(worker)
                },
                self.asserted_returns_only,
            )?,
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

/// What the prototype pass does with one function's recovery request.
#[derive(Debug)]
enum Recovery {
    Doc(Box<DecompDoc>),
    /// The job's budget ran out: the pass returns what it has.
    OutOfBudget,
    /// The decompiler refused the function with an exception.
    DecompilerFailure,
    /// The request lost its worker (see `InferenceReport::worker_deaths`).
    WorkerDeath,
}

/// Splits a recovery result into the failures confined to one function,
/// which the pass skips and counts, and those that end the pass:
/// cancellation, a stale revision, a store or core failure, a missing or
/// unusable decompiler. `run_worker` has already mapped cancellation, the
/// deadline and a late result to their own errors and dropped the session,
/// so a lost worker that reaches here is that function's own failure and the
/// next request spawns a fresh one.
fn triage_recovery(result: PoolResult<DecompDoc>) -> PoolResult<Recovery> {
    use romwright_worker::WorkerError;
    match result {
        Ok(doc) => Ok(Recovery::Doc(Box::new(doc))),
        Err(PoolError::Deadline(_)) => Ok(Recovery::OutOfBudget),
        Err(PoolError::Worker(WorkerError::Decompiler(_))) => Ok(Recovery::DecompilerFailure),
        Err(PoolError::Worker(
            WorkerError::Process(_) | WorkerError::Io(_) | WorkerError::Protocol(_),
        )) => Ok(Recovery::WorkerDeath),
        Err(error) => Err(error),
    }
}

/// The callees whose results a function returns, when every value it returns
/// is one: each `RETURN` carries a value, and each value is a `CALL` or
/// `CALLIND` output, possibly through casts and moves. `return g();` and
/// `g();` compile to the same code when the compiler leaves the callee's
/// register alone, so such a function has no evidence of its own that it
/// returns a value. An unresolved indirect callee is `u64::MAX`.
fn forwarded_callees(ir: &romwright_model::function_ir::FunctionIr) -> Option<Vec<u64>> {
    use romwright_model::function_ir::{Opcode, Operand};
    let defining: HashMap<_, _> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.operations)
        .filter_map(|operation| operation.output.map(|output| (output, operation)))
        .collect();
    let origin = |mut value| {
        for _ in 0..8 {
            let operation = defining.get(&value)?;
            match operation.opcode {
                Opcode::CALL => {
                    return Some(match operation.inputs.first() {
                        Some(Operand::Value(id)) => {
                            ir.values.get(id).and_then(|callee| callee.offset).unwrap_or(u64::MAX)
                        }
                        _ => u64::MAX,
                    });
                }
                Opcode::CALLIND => return Some(u64::MAX),
                Opcode::CAST
                | Opcode::COPY
                | Opcode::SUBPIECE
                | Opcode::INT_ZEXT
                | Opcode::INT_SEXT => match operation.inputs.first() {
                    Some(Operand::Value(next)) => value = *next,
                    _ => return None,
                },
                _ => return None,
            }
        }
        None
    };
    let mut callees = Vec::new();
    let mut returns = 0;
    for operation in ir.blocks.iter().flat_map(|block| &block.operations) {
        if operation.opcode != Opcode::RETURN {
            continue;
        }
        returns += 1;
        let mut any = false;
        for input in operation.inputs.iter().skip(1) {
            let Operand::Value(value) = input else { continue };
            callees.push(origin(*value)?);
            any = true;
        }
        if !any {
            return None;
        }
    }
    (returns > 0).then_some(callees)
}

/// The forwarding functions whose results nothing in the binary evidences:
/// no direct caller reads it, it is not a trap, and no callee it forwards is
/// evidenced either (a callee is evidenced when a caller reads it, when it
/// holds a trap, when it is unresolved or not a function of the image (an
/// import stub), or when it forwards an evidenced
/// callee in turn). A function that forwards the result of a syscall stub
/// returns a value even if only a function pointer ever calls it; one that
/// forwards a helper nobody reads has the helper's guess and no more.
fn unevidenced_forwarders(
    forwarding: &HashMap<u64, Vec<u64>>,
    result_read: &std::collections::BTreeSet<u64>,
    traps: &std::collections::BTreeSet<u64>,
    known: &HashSet<u64>,
) -> HashSet<u64> {
    let mut evidenced: HashSet<u64> = HashSet::new();
    loop {
        let mut grew = false;
        for (function, callees) in forwarding {
            if evidenced.contains(function) {
                continue;
            }
            let evidence = result_read.contains(function)
                || traps.contains(function)
                || callees.iter().any(|callee| {
                    *callee == u64::MAX
                        || !known.contains(callee)
                        || result_read.contains(callee)
                        || traps.contains(callee)
                        || evidenced.contains(callee)
                });
            if evidence {
                evidenced.insert(*function);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    forwarding.keys().filter(|function| !evidenced.contains(function)).copied().collect()
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
    /// Functions the decompiler refused with an exception. Each is skipped
    /// and keeps its stored prototype, as Ghidra's parameter-ID command
    /// skips a function whose decompile fails; one refusal must not cost
    /// the whole program's pass.
    pub decompiler_failures: u64,
    /// Functions whose request lost its worker: the decompiler process died
    /// (a native crash on that function), or its stream broke or violated
    /// the protocol. The session is discarded with the request, the next
    /// request spawns a fresh worker, and the function keeps its stored
    /// prototype exactly as for a refusal.
    pub worker_deaths: u64,
}

/// A decompiled function with everything a frontend shows beside the token
/// stream: the decompile post-processing the desktop decompiler panel shows.
#[derive(Clone, Debug)]
pub struct DecompiledFunction {
    pub doc: DecompDoc,
    /// Stored signatures of the document's direct callees (argument hints),
    /// keyed by callee entry offset.
    pub call_signatures: std::collections::BTreeMap<u64, String>,
    /// Entry of the stored function containing the requested address: the
    /// first retained SSA operation need not be the entry.
    pub function_entry: Option<Address>,
    /// Native CFG with shared layered layout; `None` without function IR.
    pub graph: Option<romwright_core::graph::NativeGraph>,
    /// Cost of laying out `graph` (`BRIDGE-GRAPH` on stderr).
    pub layout_ms: f64,
}

/// Owns the pool selected for the current API program and binary.
///
/// API and desktop callers keep one manager per Core handle. Switching binaries,
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

    /// [`Self::decompile_doc`] plus the post-processing every frontend
    /// shows: native CFG layout (timed; `BRIDGE-GRAPH` on stderr), stored
    /// callee signatures and the containing function's entry. Checks the
    /// request's deadline and cancellation once more before answering.
    pub fn decompile_function(
        &mut self,
        core: &romwright_core::Core,
        req: &romwright_core::exec::ExecutionRequest,
        address: &Address,
    ) -> PoolResult<DecompiledFunction> {
        use romwright_model::function_ir::{Opcode, Operand};
        let doc = self.decompile_doc(core, req, address)?;
        let started = Instant::now();
        let graph = doc.function_ir.as_ref().map(romwright_core::graph::native_layout);
        let layout = started.elapsed();
        if let Some(graph) = &graph {
            eprintln!("BRIDGE-GRAPH {layout:?} nodes={}", graph.nodes.len());
        }
        let mut callees = HashSet::new();
        if let Some(ir) = &doc.function_ir {
            for operation in ir.blocks.iter().flat_map(|block| &block.operations) {
                if operation.opcode == Opcode::CALL
                    && let Some(Operand::Value(id)) = operation.inputs.first()
                    && let Some(offset) = ir.values.get(id).and_then(|value| value.offset)
                {
                    callees.insert(offset);
                }
            }
        }
        let call_signatures = core
            .prototypes(&req.program)?
            .into_iter()
            .filter(|row| callees.contains(&row.function.offset))
            .map(|row| (row.function.offset, row.signature))
            .collect();
        let function_entry = core
            .functions(&req.program)?
            .into_iter()
            .filter(|function| function.entry.space == address.space && function.entry.offset <= address.offset)
            .max_by_key(|function| function.entry.offset)
            .filter(|function| address.offset < function.entry.offset.saturating_add(function.size.max(1)))
            .map(|function| function.entry);
        core.check_execution(req)?;
        Ok(DecompiledFunction {
            doc,
            call_signatures,
            function_entry,
            graph,
            layout_ms: layout.as_secs_f64() * 1000.0,
        })
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
            decompiler_failures: 0,
            worker_deaths: 0,
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
        // The merge refines only the decompiler's own recovery. What a user
        // asserted or an import supplied is read before the first round can
        // overwrite an inferred row.
        let protected: HashSet<u64> = store
            .prototypes(id)?
            .iter()
            .filter(|row| romwright_core::types_infer::prototypes::protected(row))
            .map(|row| row.function.offset)
            .collect();
        let mut parameter_types = None;
        let mut variadic_fixed: HashMap<u64, romwright_model::FuncProto> = HashMap::new();
        let mut forwarding: HashMap<u64, Vec<u64>> = HashMap::new();
        let float_layout = core.float_register_layout(req)?;
        let mut ir_overlap: HashMap<u64, std::collections::BTreeSet<usize>> = HashMap::new();
        // Aligned register pairs a function hands whole to a callee's declared
        // 8-byte parameter (`types_infer::pair_params`), by function, from the
        // function's latest recovery.
        let pair_layout = core.pair_layout(req)?;
        // `ROMWRIGHT_JOIN_PAIRS=0` turns the pass off, as `ROMWRIGHT_INFERRED_TYPES=0`
        // does for the type upgrades, so a measurement can name its effect.
        let join_pairs = std::env::var("ROMWRIGHT_JOIN_PAIRS").map_or(true, |value| value != "0");
        let mut pair_sightings: HashMap<u64, Vec<romwright_core::types_infer::pair_params::Sighting>> =
            HashMap::new();
        let mut functions = store.functions(id)?;
        functions.retain(|function| function.entry.space == romwright_model::AddressSpace::Ram);
        let known: HashSet<u64> = functions.iter().map(|function| function.entry.offset).collect();
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
                let doc = match triage_recovery(result)? {
                    Recovery::Doc(doc) => *doc,
                    Recovery::OutOfBudget => return Ok(report),
                    Recovery::DecompilerFailure => {
                        report.decompiler_failures += 1;
                        continue;
                    }
                    Recovery::WorkerDeath => {
                        report.worker_deaths += 1;
                        continue;
                    }
                };
                report.analyzed += 1;
                report.analyzed_addresses.push(function.entry.offset);
                if !externals.contains(&function.entry) {
                    let mut prototype = doc.prototype.expect("recovery requires a prototype");
                    if let Some(ir) = doc.function_ir.as_ref() {
                        let found = romwright_core::types_infer::register_overlap::overlapped_ir(ir, &float_layout);
                        if !found.is_empty() {
                            ir_overlap.entry(function.entry.offset).or_default().extend(found);
                        }
                    }
                    if let Some(ir) = doc.function_ir.as_ref().filter(|_| join_pairs) {
                        let found = romwright_core::types_infer::pair_params::carry_forward(
                            pair_sightings.get(&function.entry.offset).map(Vec::as_slice),
                            romwright_core::types_infer::pair_params::sightings(
                                ir,
                                &doc.call_prototypes,
                                &pair_layout,
                            ),
                        );
                        if !found.is_empty() {
                            pair_sightings.insert(function.entry.offset, found);
                        }
                    }
                    match doc.function_ir.as_ref().and_then(forwarded_callees) {
                        Some(callees) => {
                            forwarding.insert(function.entry.offset, callees);
                        }
                        None => {
                            forwarding.remove(&function.entry.offset);
                        }
                    }
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
            // The first round recovered every function, which is the callee
            // signature set the inference solves against; later rounds reuse
            // its answer, since the p-code it reads does not change. The
            // pass repairs a variadic function's register-save area and, with
            // `inferred_types`, upgrades the slots' types.
            let struct_mode = romwright_model::structs::StructMode::from_env();
            if parameter_types.is_none() {
                match core.parameter_types(req, &recovered) {
                    Ok(types) => parameter_types = Some(types),
                    Err(_) if req.cancel.is_cancelled() => return Err(PoolError::Cancelled),
                    Err(_) if Instant::now() >= deadline => return Ok(report),
                    Err(error) => return Err(error.into()),
                }
            }
            let types = parameter_types.as_ref().expect("computed above");
            let unevidenced = unevidenced_forwarders(&forwarding, &types.result_read, &types.opaque, &known);
            let mut layouts: Vec<romwright_model::structs::StructLayout> = Vec::new();
            for (address, prototype) in &mut recovered {
                if protected.contains(&address.offset) {
                    continue;
                }
                // A recovery that starts from a stored variadic prototype
                // inherits its `...` and loses the fixed parameters, so a
                // repaired function keeps its first round's prototype: the
                // register-save area is a fact of its body, which the
                // callee prototypes do not change.
                if let Some(repaired) = variadic_fixed.get(&address.offset) {
                    *prototype = repaired.clone();
                    continue;
                }
                types.apply(address.offset, prototype, req.config.inferred_types);
                if struct_mode.infers() && req.config.inferred_types {
                    layouts.extend(types.apply_structs(address.offset, prototype));
                }
                // A function that only forwards a callee's result, with no
                // evidence anywhere along the chain that it is a value.
                if unevidenced.contains(&address.offset) {
                    romwright_core::types_infer::prototypes::void_return(prototype);
                }
                if prototype.variadic && types.variadic.contains_key(&address.offset) {
                    variadic_fixed.insert(address.offset, prototype.clone());
                }
                // An aligned register pair the body hands whole to a callee's
                // declared 8-byte parameter is one parameter, not two.
                if let Some(found) = pair_sightings.get(&address.offset) {
                    romwright_core::types_infer::pair_params::join(
                        prototype,
                        found,
                        &pair_layout,
                        &types.target,
                    );
                }
            }
            // Rows another producer owns are never overwritten, and a body
            // the decompiler cannot fully read (`ParameterTypes::opaque`), or
            // whose float parameter register the body reads at another width
            // (`locks_overlapping_input`: locked, it fails to decompile),
            // gets no prototype: an absent row leaves its callers' call
            // sites to the decompiler's own argument recovery.
            recovered.retain(|(address, prototype)| {
                !protected.contains(&address.offset)
                    && !types.opaque.contains(&address.offset)
                    && !types.locks_overlapping_input(address.offset, prototype, ir_overlap.get(&address.offset))
            });
            // The layouts the retained prototypes name are stored with them.
            let named: std::collections::HashSet<String> = recovered
                .iter()
                .flat_map(|(_, prototype)| &prototype.parameters)
                .filter_map(|parameter| parameter.data_type.target.as_deref()?.name.clone())
                .collect();
            layouts.retain(|layout| named.contains(layout.name.split("_p").next().unwrap_or(&layout.name)));
            let changed = req.cancel.publish(deadline, || {
                let at = core.persist_struct_layouts(&req.program, revision, &layouts)?;
                core.persist_inferred_prototypes(&req.program, at, &recovered)
            })?;
            report.rounds += 1;
            report.changed += changed.len() as u64;
            // The stores above are the only mutations accepted between these
            // rounds. A concurrent edit after them is still rejected by the
            // next check.
            revision = store.revision(id)?;
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
        prepared: Box<romwright_core::matching::PreparedMatch>,
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

/// What a finished job answers with.
///
/// A decompiled document is megabytes of JSON, and a `serde_json::Value` tree
/// of it costs five to ten times its text. The document is therefore
/// serialized once, straight from the typed struct, into the text the reply
/// carries (`Document`), and the service writes that text into its envelope
/// without ever building the tree. Every other job answers with a small
/// report and keeps the tree. The keys of a `Document` come in the struct's
/// field order, those of a `Tree` in `serde_json`'s sorted order; both are
/// the same JSON value.
#[derive(Clone, Debug)]
pub enum JobOutput {
    Tree(serde_json::Value),
    Document(Box<serde_json::value::RawValue>),
}

impl JobOutput {
    /// The answer as a tree, for the callers that need to look inside it
    /// (a `Document` is parsed back).
    pub fn into_value(self) -> Result<serde_json::Value, serde_json::Error> {
        match self {
            JobOutput::Tree(value) => Ok(value),
            JobOutput::Document(text) => serde_json::from_str(text.get()),
        }
    }

    /// The functions an inference report analyzed (`analyzed_addresses`);
    /// only a report carries them.
    fn analyzed_addresses(&self) -> Option<Vec<u64>> {
        let JobOutput::Tree(value) = self else {
            return None;
        };
        value.get("analyzed_addresses").map(|array| {
            array
                .as_array()
                .map(|items| items.iter().filter_map(serde_json::Value::as_u64).collect())
                .unwrap_or_default()
        })
    }
}

impl serde::Serialize for JobOutput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JobOutput::Tree(value) => value.serialize(serializer),
            JobOutput::Document(text) => text.serialize(serializer),
        }
    }
}

struct JobRecord {
    operation: &'static str,
    state: JobState,
    detail: String,
    cancel: CancelToken,
    result: Option<Result<JobOutput, String>>,
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
    /// Job threads not running a job: waiting for one, or just started.
    available: usize,
    /// Job threads started, and the most the executor may start.
    spawned: usize,
    max: usize,
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
/// immediately and worker threads drain the queue. Each
/// thread opens its own `Core` on the project — the store is SQLite, so a
/// second connection is a second reader — and keeps a `WorkerPoolManager` so
/// warm decompiler children are reused across jobs on the same thread.
///
/// Threads start when a job finds none free, up to the configured count, so
/// one client asking one question after another has one thread, one `Core`
/// and one warm decompiler, not as many of each as the host has cores (each
/// a decompiler process and a parsed program of its own).
///
/// Cancellation is cooperative: `cancel` sets the job's token, a queued job
/// is dropped before it starts, and a running job's token is polled between
/// functions and by the worker watchdog that kills a child that does not
/// stop.
pub struct JobExecutor {
    inner: std::sync::Arc<ExecutorInner>,
    workers: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl JobExecutor {
    /// An executor of at most `workers` job threads (`0` is one), started as
    /// jobs need them.
    pub fn new(workers: usize) -> Self {
        let inner = std::sync::Arc::new(ExecutorInner {
            state: std::sync::Mutex::new(Shared {
                queue: std::collections::VecDeque::new(),
                records: HashMap::new(),
                order: Vec::new(),
                next_id: 1,
                shutdown: false,
                available: 0,
                spawned: 0,
                max: workers.max(1),
            }),
            queued: std::sync::Condvar::new(),
            finished: std::sync::Condvar::new(),
        });
        Self { inner, workers: std::sync::Mutex::new(Vec::new()) }
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
        // A job with no free thread to take it starts one, within the limit.
        while state.available < state.queue.len() && state.spawned < state.max {
            let inner = std::sync::Arc::clone(&self.inner);
            state.spawned += 1;
            state.available += 1;
            self.workers
                .lock()
                .expect("executor workers poisoned")
                .push(std::thread::spawn(move || executor_loop(inner)));
        }
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
                Ok(output) => output.clone().into_value().unwrap_or_else(
                    |error| serde_json::json!({ "error": error.to_string() }),
                ),
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
    pub fn wait(&self, id: u64) -> Option<Result<JobOutput, String>> {
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

    /// [`JobExecutor::wait`] for a caller that is the result's only reader (a
    /// request that submitted the job and answers with it): the executor
    /// does not keep the result afterwards, only the job's row. A session
    /// that asks a thousand questions would otherwise hold a thousand
    /// decompiled documents.
    pub fn wait_take(&self, id: u64) -> Option<Result<JobOutput, String>> {
        let mut state = self.inner.state.lock().expect("executor lock poisoned");
        loop {
            match state.records.get_mut(&id) {
                None => return None,
                Some(record)
                    if matches!(
                        record.state,
                        JobState::Succeeded | JobState::Failed | JobState::Cancelled
                    ) =>
                {
                    // Moved out, not cloned: a decompiled document is
                    // megabytes of text, and a copy of it was held for the
                    // length of the reply.
                    return record.result.take();
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
        let workers = std::mem::take(&mut *self.workers.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
        for worker in workers {
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
                    state.available = state.available.saturating_sub(1);
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
        state.available += 1;
        if let Some(record) = state.records.get_mut(&job.id) {
            // Inference reports carry their analyzed addresses: expand
            // them into per-function progress rows now, while the
            // report value is at hand.
            let progress: Option<Vec<u64>> = match &result {
                Ok(output) => output.analyzed_addresses(),
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
        prune_results(&mut state);
        drop(state);
        inner.finished.notify_all();
    }
}

/// The results the executor keeps for a client that asks later (`status`),
/// newest first; the rows stay, the older results go. Together with
/// [`JobExecutor::wait_take`] this bounds what a long session holds.
const KEPT_RESULTS: usize = 64;
const KEPT_ROWS: usize = 4096;

fn prune_results(state: &mut Shared) {
    let finished = |record: &JobRecord| !matches!(record.state, JobState::Queued | JobState::Running);
    let kept = state.records.values().filter(|record| record.result.is_some()).count();
    if kept > KEPT_RESULTS {
        let mut drop_count = kept - KEPT_RESULTS;
        for id in &state.order {
            if drop_count == 0 {
                break;
            }
            if let Some(record) = state.records.get_mut(id).filter(|record| finished(record) && record.result.is_some()) {
                record.result = None;
                drop_count -= 1;
            }
        }
    }
    if state.order.len() > KEPT_ROWS {
        let excess = state.order.len() - KEPT_ROWS;
        let mut removed = Vec::new();
        for id in &state.order {
            if removed.len() == excess {
                break;
            }
            if state.records.get(id).is_some_and(finished) {
                removed.push(*id);
            }
        }
        for id in &removed {
            state.records.remove(id);
        }
        state.order.retain(|id| !removed.contains(id));
    }
}

fn run_job(
    caches: &mut HashMap<PathBuf, (romwright_core::Core, WorkerPoolManager)>,
    kind: JobKind,
    req: &romwright_core::exec::ExecutionRequest,
) -> Result<JobOutput, String> {
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
    let tree = |report: Result<serde_json::Value, serde_json::Error>| {
        report.map(JobOutput::Tree).map_err(|error| error.to_string())
    };
    match kind {
        // The typed document goes to text and is dropped; no tree of it is
        // ever built (`JobOutput`).
        JobKind::DecompileDoc { address } => manager
            .decompile_doc(core, req, &Address::ram(address))
            .map_err(|error| error.to_string())
            .and_then(|doc| {
                serde_json::value::to_raw_value(&doc)
                    .map(JobOutput::Document)
                    .map_err(|error| error.to_string())
            }),
        JobKind::InferPrototypes => manager
            .infer_prototypes(core, req)
            .map_err(|error| error.to_string())
            .and_then(|report| tree(serde_json::to_value(report))),
        JobKind::InferNonreturning => manager
            .infer_nonreturning(core, req)
            .map_err(|error| error.to_string())
            .and_then(|report| tree(serde_json::to_value(report))),
        JobKind::MatchSource { prepared } => core
            .run_matching(req, &prepared)
            .map_err(|error| error.to_string())
            .and_then(|report| tree(serde_json::to_value(report))),
        JobKind::Matching { operation } => core
            .run_matching_operation(req, operation)
            .map_err(|error| error.to_string())
            .map(JobOutput::Tree),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_of(error: PoolError) -> PoolResult<Recovery> {
        triage_recovery(Err(error))
    }

    #[test]
    fn a_document_answer_is_the_same_value_as_its_tree() {
        let text = r#"{"tokens":[{"text":"x"}],"revision":0,"address":{"offset":4096}}"#;
        let document = JobOutput::Document(serde_json::value::RawValue::from_string(text.into()).unwrap());
        let tree = JobOutput::Tree(serde_json::from_str(text).unwrap());
        assert_eq!(
            document.clone().into_value().unwrap(),
            tree.clone().into_value().unwrap()
        );
        // Both serialize to JSON that reads back as the one value.
        let written = |output: &JobOutput| -> serde_json::Value {
            serde_json::from_str(&serde_json::to_string(output).unwrap()).unwrap()
        };
        assert_eq!(written(&document), written(&tree));
        // Only a report names the functions it analyzed.
        assert_eq!(document.analyzed_addresses(), None);
        let report = JobOutput::Tree(serde_json::json!({"analyzed_addresses": [16, 32]}));
        assert_eq!(report.analyzed_addresses(), Some(vec![16, 32]));
    }

    #[test]
    fn a_forwarded_result_needs_evidence_somewhere_along_the_chain() {
        use std::collections::BTreeSet;
        // 1 -> 2 -> 3 (leaf), 4 -> 5 -> stub 9 (a trap), 6 -> an import (7).
        let forwarding: HashMap<u64, Vec<u64>> =
            HashMap::from([(1, vec![2]), (2, vec![3]), (4, vec![5]), (5, vec![9]), (6, vec![7])]);
        let known: HashSet<u64> = HashSet::from([1, 2, 3, 4, 5, 6, 9]);
        let none: BTreeSet<u64> = BTreeSet::new();
        let traps = BTreeSet::from([9]);
        let void = unevidenced_forwarders(&forwarding, &none, &traps, &known);
        assert_eq!(void, HashSet::from([1, 2]), "a leaf nobody reads is no evidence; a trap and an import are");
        // A caller that reads the leaf's result evidences the whole chain.
        let read = BTreeSet::from([3]);
        assert!(unevidenced_forwarders(&forwarding, &read, &traps, &known).is_empty());
        // An unresolved indirect callee is never void.
        let indirect: HashMap<u64, Vec<u64>> = HashMap::from([(1, vec![u64::MAX])]);
        assert!(unevidenced_forwarders(&indirect, &none, &none, &known).is_empty());
    }

    #[test]
    fn a_function_whose_worker_is_lost_is_skipped_not_fatal() {
        use romwright_worker::WorkerError;
        for error in [
            WorkerError::Process("decompiler died".into()),
            WorkerError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            WorkerError::Protocol("unexpected burst 0x7f in command stream".into()),
        ] {
            assert!(
                matches!(recovery_of(error.into()), Ok(Recovery::WorkerDeath)),
                "worker loss must be counted and skipped"
            );
        }
        assert!(matches!(
            recovery_of(WorkerError::Decompiler("Low-level Error".into()).into()),
            Ok(Recovery::DecompilerFailure)
        ));
    }

    #[test]
    fn cancellation_deadline_stale_and_setup_failures_still_end_the_pass() {
        use romwright_worker::WorkerError;
        assert!(matches!(
            recovery_of(PoolError::Deadline(Duration::ZERO)),
            Ok(Recovery::OutOfBudget)
        ));
        assert!(matches!(
            recovery_of(PoolError::Cancelled),
            Err(PoolError::Cancelled)
        ));
        assert!(matches!(
            recovery_of(PoolError::StaleRevision(1, 2)),
            Err(PoolError::StaleRevision(1, 2))
        ));
        assert!(matches!(
            recovery_of(PoolError::MemCap(2, 1)),
            Err(PoolError::MemCap(2, 1))
        ));
        assert!(matches!(
            recovery_of(WorkerError::Setup("registerProgram: no".into()).into()),
            Err(PoolError::Worker(WorkerError::Setup(_)))
        ));
    }

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
        // The child hangs for far longer than any bound below. It writes nothing
        // itself: how many children were launched is counted by the pool (a child
        // killed before the shell reaches its first command leaves no trace), and
        // how long a child takes to start is not what this test measures.
        std::fs::write(&decompiler, "#!/bin/sh\nsleep 30\n").unwrap();
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
        assert_eq!(pool.launches, 2, "each attempt launches its own child");
        let deadline = Instant::now() + Duration::from_millis(250);
        let shared = [
            pool.recover_doc(0, deadline, &never),
            pool.recover_doc(0, deadline, &never),
        ];
        for result in results.into_iter().chain(shared) {
            assert!(matches!(result, Err(PoolError::Deadline(_))), "{result:?}");
        }
        // The first of the two shared calls runs the deadline out on its child;
        // the second finds it expired and must not launch one.
        assert_eq!(
            pool.launches, 3,
            "an expired shared deadline must not launch another child"
        );
        // A kill ends each call at its deadline. A child left alone would hold
        // the call for its full 30 s, so the bound separates the two without
        // depending on how fast this machine schedules.
        assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
        // A protocol failure must remain an error, not wait for EOF until the
        // deadline turns it into a timeout. This child deliberately ignores EOF,
        // and the deadline is far beyond the time it needs to write its burst, so
        // only a failure that waits for the deadline reports a timeout.
        std::fs::write(
            root.join("hang"),
            "#!/bin/sh\nprintf '\\000\\000\\001\\177'\nsleep 30\n",
        )
        .unwrap();
        let rejected = pool.decompile_doc(0, Instant::now() + Duration::from_secs(10), &never);
        assert_eq!(pool.launches, 4);
        assert!(
            matches!(&rejected, Err(PoolError::Worker(_))),
            "{rejected:?}"
        );
    }
}
