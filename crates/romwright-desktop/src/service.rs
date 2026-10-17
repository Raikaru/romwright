//! Off-UI-thread access to `romwright_core::Core`.
//!
//! Same ownership as the Qt bridge's `CoreHandle`: one `Mutex<Core>` serialises
//! SQLite and Core's native image cache, and a separate
//! `Mutex<WorkerPoolManager>` owns the warm decompiler worker. Lock order is
//! always worker pool, then Core (as `core_request` does).
//!
//! * [`CoreService::request`] — short store reads on a two-thread pool (the
//!   Qt bridge's `QThreadPool` size), holding the Core mutex.
//! * [`CoreService::job`] — long work (import, listing, decompile, analysis,
//!   matching) on its own thread, logged in the [`JobBoard`] with progress and
//!   cooperative cancellation. Jobs normally [`JobContext::fork`] the Core so
//!   they do not hold the mutex that page reads need.
//!
//! Every call returns a [`Task`]; the UI polls it once per frame and the
//! finishing thread wakes the event loop.

use crate::jobs::{JobBoard, JobId, JobState};
use romwright_core::Core;
use romwright_core::exec::{CancelToken, ExecutionRequest};
use romwright_worker_client::WorkerPoolManager;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

pub type TaskResult<T> = Result<T, String>;

/// The answer to one request or job, delivered to the UI thread.
pub struct Task<T> {
    receiver: mpsc::Receiver<TaskResult<T>>,
    cancel: CancelToken,
}

impl<T> Task<T> {
    fn ready(result: TaskResult<T>) -> Self {
        let (sender, receiver) = mpsc::channel();
        let _ = sender.send(result);
        Self { receiver, cancel: CancelToken::default() }
    }

    /// `None` while the work runs. A task answers once; keep it in an
    /// `Option` and use [`poll_slot`].
    pub fn poll(&self) -> Option<TaskResult<T>> {
        match self.receiver.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err("the task ended without an answer".into())),
        }
    }

    /// Requests cooperative cancellation (jobs only; requests are short).
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

/// Polls a task slot and clears it once the task has answered.
pub fn poll_slot<T>(slot: &mut Option<Task<T>>) -> Option<TaskResult<T>> {
    let result = slot.as_ref()?.poll()?;
    *slot = None;
    Some(result)
}

/// Wakes the UI when background work finishes (no-op headless: the
/// offscreen driver polls).
#[derive(Clone, Default)]
struct Waker(Arc<Mutex<Option<egui::Context>>>);

impl Waker {
    fn wake(&self) {
        if let Some(context) = self.0.lock().unwrap_or_else(|error| error.into_inner()).as_ref() {
            context.request_repaint();
        }
    }
}

type Work = Box<dyn FnOnce() + Send>;

/// Fixed-size request pool; dropping it drains queued work and joins.
struct Executor {
    sender: Option<mpsc::Sender<Work>>,
    threads: Vec<JoinHandle<()>>,
}

impl Executor {
    fn new(workers: usize) -> Self {
        let (sender, receiver) = mpsc::channel::<Work>();
        let receiver = Arc::new(Mutex::new(receiver));
        let threads = (0..workers)
            .map(|index| {
                let receiver = Arc::clone(&receiver);
                std::thread::Builder::new()
                    .name(format!("romwright-request-{index}"))
                    .spawn(move || loop {
                        let work = receiver.lock().unwrap_or_else(|error| error.into_inner()).recv();
                        match work {
                            Ok(work) => work(),
                            Err(_) => break,
                        }
                    })
                    .expect("spawn request thread")
            })
            .collect();
        Self { sender: Some(sender), threads }
    }

    fn spawn(&self, work: Work) {
        if let Some(sender) = &self.sender {
            let _ = sender.send(work);
        }
    }

    fn join(&mut self) {
        self.sender = None;
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
struct Shared {
    core: Arc<Mutex<Core>>,
    worker_pool: Arc<Mutex<WorkerPoolManager>>,
}

impl Shared {
    fn core(&self) -> TaskResult<MutexGuard<'_, Core>> {
        self.core.lock().map_err(|_| "Core mutex poisoned".to_string())
    }

    fn worker_pool(&self) -> TaskResult<MutexGuard<'_, WorkerPoolManager>> {
        self.worker_pool.lock().map_err(|_| "WorkerPool mutex poisoned".to_string())
    }
}

pub struct CoreService {
    project: PathBuf,
    shared: Result<Shared, String>,
    requests: Mutex<Executor>,
    jobs: Arc<JobBoard>,
    waker: Waker,
}

impl CoreService {
    /// Opens (or creates) the project store. A failure is kept and answered
    /// to every later call, as the Qt window showed its startup error.
    pub fn open(project: &Path) -> Self {
        let shared = Core::open(project)
            .map(|core| Shared {
                core: Arc::new(Mutex::new(core)),
                worker_pool: Arc::new(Mutex::new(WorkerPoolManager::default())),
            })
            .map_err(|error| format!("cannot open project {}: {error}", project.display()));
        Self {
            project: project.to_path_buf(),
            shared,
            requests: Mutex::new(Executor::new(2)),
            jobs: Arc::new(JobBoard::default()),
            waker: Waker::default(),
        }
    }

    pub fn project(&self) -> &Path {
        &self.project
    }

    pub fn startup_error(&self) -> Option<&str> {
        self.shared.as_ref().err().map(String::as_str)
    }

    pub fn jobs(&self) -> &JobBoard {
        &self.jobs
    }

    pub fn set_waker(&self, context: egui::Context) {
        *self.waker.0.lock().unwrap_or_else(|error| error.into_inner()) = Some(context);
    }

    /// A short store read holding the Core mutex.
    pub fn request<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Core) -> TaskResult<T> + Send + 'static,
    ) -> Task<T> {
        self.request_with(move |shared| work(&*shared.core()?))
    }

    /// A short call that also needs the worker pool (pool counters).
    pub fn request_pool<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Core, &mut WorkerPoolManager) -> TaskResult<T> + Send + 'static,
    ) -> Task<T> {
        self.request_with(move |shared| {
            let mut pool = shared.worker_pool()?;
            let core = shared.core()?;
            work(&core, &mut pool)
        })
    }

    fn request_with<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Shared) -> TaskResult<T> + Send + 'static,
    ) -> Task<T> {
        let shared = match &self.shared {
            Ok(shared) => shared.clone(),
            Err(error) => return Task::ready(Err(error.clone())),
        };
        let (sender, receiver) = mpsc::channel();
        let waker = self.waker.clone();
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .spawn(Box::new(move || {
                let result = catch_unwind(AssertUnwindSafe(|| work(&shared)))
                    .unwrap_or_else(|_| Err("the request panicked".into()));
                let _ = sender.send(result);
                waker.wake();
            }));
        Task { receiver, cancel: CancelToken::default() }
    }

    /// Long work on its own thread, logged under `label` in the job board.
    pub fn job<T: Send + 'static>(
        &self,
        label: impl Into<String>,
        work: impl FnOnce(&JobContext) -> TaskResult<T> + Send + 'static,
    ) -> Task<T> {
        self.spawn_job(Some(label.into()), work)
    }

    /// Long work on its own thread that is not worth a log entry (the
    /// window's periodic background analysis pass).
    pub fn background<T: Send + 'static>(
        &self,
        work: impl FnOnce(&JobContext) -> TaskResult<T> + Send + 'static,
    ) -> Task<T> {
        self.spawn_job(None, work)
    }

    fn spawn_job<T: Send + 'static>(
        &self,
        label: Option<String>,
        work: impl FnOnce(&JobContext) -> TaskResult<T> + Send + 'static,
    ) -> Task<T> {
        let shared = match &self.shared {
            Ok(shared) => shared.clone(),
            Err(error) => return Task::ready(Err(error.clone())),
        };
        let cancel = CancelToken::default();
        let id = label.map(|label| self.jobs.begin(label, cancel.clone()));
        let context = JobContext {
            shared,
            cancel: cancel.clone(),
            jobs: Arc::clone(&self.jobs),
            id,
            detail: Mutex::new(None),
        };
        let (sender, receiver) = mpsc::channel();
        let waker = self.waker.clone();
        let handle = std::thread::Builder::new()
            .name("romwright-job".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| work(&context)))
                    .unwrap_or_else(|_| Err("the job panicked".into()));
                if let Some(id) = context.id {
                    let (state, mut detail) = match &result {
                        Ok(_) => (
                            JobState::Succeeded,
                            context
                                .detail
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .take()
                                .unwrap_or_else(|| "done".into()),
                        ),
                        Err(error) if context.is_cancelled() => (JobState::Cancelled, error.clone()),
                        Err(error) => (JobState::Failed, error.clone()),
                    };
                    let delivered = sender.send(result).is_ok();
                    if !delivered && state == JobState::Succeeded {
                        detail = format!("superseded: {detail}");
                    }
                    context.jobs.finish(id, state, detail);
                } else {
                    let _ = sender.send(result);
                }
                waker.wake();
            })
            .expect("spawn job thread");
        self.jobs.adopt(handle);
        Task { receiver, cancel }
    }

    /// Cancels running jobs, waits for them and for in-flight requests.
    pub fn shutdown(&self) {
        self.jobs.shutdown();
        self.requests.lock().unwrap_or_else(|error| error.into_inner()).join();
    }
}

impl Drop for CoreService {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// What a job sees: Core access, cancellation and progress reporting.
pub struct JobContext {
    shared: Shared,
    cancel: CancelToken,
    jobs: Arc<JobBoard>,
    id: Option<JobId>,
    detail: Mutex<Option<String>>,
}

impl JobContext {
    /// An independent store connection sharing warm runtime state; long
    /// work owns this instead of the service's Core mutex.
    pub fn fork(&self) -> TaskResult<Core> {
        self.shared.core()?.fork().map_err(|error| error.to_string())
    }

    /// Runs `work` holding the shared Core mutex.
    pub fn with_core<R>(&self, work: impl FnOnce(&Core) -> R) -> TaskResult<R> {
        Ok(work(&*self.shared.core()?))
    }

    /// The warm decompiler pool. Take it before any Core lock.
    pub fn worker_pool(&self) -> TaskResult<MutexGuard<'_, WorkerPoolManager>> {
        self.shared.worker_pool()
    }

    pub fn cancel_token(&self) -> &CancelToken {
        &self.cancel
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// `Err("cancelled")` once cancellation was requested: a checkpoint
    /// between units of work.
    pub fn check_cancelled(&self) -> TaskResult<()> {
        if self.is_cancelled() { Err("cancelled".into()) } else { Ok(()) }
    }

    /// Replaces the job's progress line in the Jobs panel.
    pub fn progress(&self, text: impl Into<String>) {
        if let Some(id) = self.id {
            self.jobs.progress(id, text.into());
        }
    }

    /// The detail shown when the job succeeds (default `done`).
    pub fn detail(&self, text: impl Into<String>) {
        *self.detail.lock().unwrap_or_else(|error| error.into_inner()) = Some(text.into());
    }

    /// `Core::execution_request` whose cancel token is this job's, so the
    /// Jobs panel's Cancel reaches the worker watchdog.
    pub fn execution_request(
        &self,
        core: &Core,
        binary: &Path,
        program: &str,
        base: Option<u64>,
        budget: Duration,
    ) -> TaskResult<ExecutionRequest> {
        let mut request = core
            .execution_request(binary, program, base, budget)
            .map_err(|error| error.to_string())?;
        request.cancel = self.cancel.clone();
        Ok(request)
    }
}
