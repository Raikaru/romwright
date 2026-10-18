//! The execution boundary Core owns: one resolved request carries everything
//! a long-running analysis job needs, so the worker pool consumes a finished
//! decision instead of re-deriving it.
//!
//! A job's inputs are fixed at submit time: which binary and program, which
//! store revision it is computed against, when it must finish, and how it is
//! cancelled. Resolving them here — in Core, which owns the store and the
//! runtime config — means the answer cannot drift between the moment a
//! request is accepted and the moment a worker acts on it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{Core, Result};

/// Default interactive job budget; explicit requests may choose another bound.
pub const DEFAULT_BUDGET: Duration = Duration::from_secs(60);

/// Kills an unreaped child and, when it owns its process group, its descendants.
/// Callers must retain child ownership until all watchdogs stop, then reap it.
/// An inherited group belongs to the outer supervisor and must not be killed.
pub fn kill_child(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        // SAFETY: the unreaped child retains this PID; only its own group is
        // signalled, never the caller's inherited process group.
        if unsafe { libc::getpgid(pid) } == pid {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
}

/// A shared cancellation flag for one job.
///
/// Cloning shares the flag: the executor holds one handle to cancel with and
/// the job holds another to poll. Cancellation is cooperative — a job checks
/// between units of work and the worker watchdog kills a child that does not
/// stop — so a cancelled job always reaches a terminal state rather than
/// hanging on a flag nobody reads.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
    publication: Arc<Mutex<()>>,
}

impl CancelToken {
    /// Marks the job cancelled. Idempotent.
    pub fn cancel(&self) {
        let _guard = self
            .publication
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.flag.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    pub fn checkpoint(&self, deadline: Instant) -> Result<()> {
        let reason = if self.is_cancelled() {
            Some("execution cancelled")
        } else if Instant::now() >= deadline {
            Some("execution deadline exceeded")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(crate::native_runtime::NativeRuntimeError(reason.into()).into()),
            None => Ok(()),
        }
    }

    /// Fail fast on explicit cancellation only: an expired deadline is not
    /// an error at job entry — the manager returns the graceful empty
    /// report (rounds 0, stop budget), which m2-006 pins for budget_ms=0.
    /// `publish` keeps the full checkpoint, so fact publication under an
    /// expired deadline still fails.
    pub fn check_cancelled(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(crate::native_runtime::NativeRuntimeError("execution cancelled".into()).into());
        }
        Ok(())
    }

    /// Cancellation and fact publication have a single linearization point:
    /// once cancellation has been accepted, no later transaction can publish.
    pub fn publish<T>(&self, deadline: Instant, work: impl FnOnce() -> Result<T>) -> Result<T> {
        let _guard = self
            .publication
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.checkpoint(deadline)?;
        work()
    }
}

/// Everything one analysis job runs against, resolved once by Core.
///
/// `revision` is the store revision the job is computed against: a job that
/// finishes to a different revision has its result discarded, because the
/// facts it read no longer describe the store. `deadline` bounds the whole
/// job, not one worker lease. `cancel` lets a caller retract the work.
#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    /// The binary the job analyses.
    pub binary: PathBuf,
    /// Verified identity of the captured input, independent of its source path.
    pub artifact_digest: String,
    pub input: romwright_model::ProgramInput,
    pub config: crate::session::RuntimeConfig,
    /// Stored language captured with the input revision, not re-read by workers.
    pub language: String,
    /// The program within the project store.
    pub program: String,
    /// Load base (0 for ET_DYN, the image base for PE).
    pub base: u64,
    /// The store revision the job is computed against.
    pub revision: u64,
    /// The project directory a job thread opens its own `Core` on — the
    /// store is SQLite, so a second connection is a second reader, not a
    /// data race.
    pub project_dir: PathBuf,
    /// When the job must finish by.
    pub deadline: Instant,
    /// The job's cancellation flag.
    pub cancel: CancelToken,
}

impl Core {
    /// Resolves one execution request: the program's current revision, a
    /// deadline `budget` from now, and a fresh cancellation token.
    ///
    /// This is the single place a job's inputs are fixed. The worker pool
    /// receives the finished request and does not re-resolve the program,
    /// the revision, or the clock.
    pub fn execution_request(
        &self,
        binary: &Path,
        program: &str,
        base: Option<u64>,
        budget: Duration,
    ) -> Result<ExecutionRequest> {
        let deadline = Instant::now().checked_add(budget).ok_or_else(|| {
            crate::CoreError::NativeRuntime(crate::native_runtime::NativeRuntimeError(
                "execution budget overflows the clock".into(),
            ))
        })?;
        let store = &self.db;
        let program_id = store.program_id(program)?;
        let revision = store.revision(program_id)?;
        let input = self.resolve_program_input(binary, program)?;
        let language = store.program_language(program_id)?;
        let cancel = CancelToken::default();
        cancel.check_cancelled()?;
        let request = ExecutionRequest {
            binary: self.db_path().join("artifacts").join(&input.binary_digest),
            artifact_digest: input.binary_digest.clone(),
            input,
            config: self.runtime_config().clone(),
            program: program.to_string(),
            language,
            base: base
                .or_else(|| crate::native_runtime::program_image_base(program, self.db_path()))
                .unwrap_or(0),
            revision,
            project_dir: self.db_path().to_path_buf(),
            deadline,
            cancel,
        };
        // Capturing a request does not publish facts. Fact-dependent consumers
        // validate their snapshot when executing/publishing; immutable artifact
        // jobs may legitimately finish after unrelated analysis advances it.
        request.cancel.check_cancelled()?;
        Ok(request)
    }

    /// A read-only result is publishable only for its captured revision.
    pub fn check_execution(&self, request: &ExecutionRequest) -> Result<()> {
        request.cancel.checkpoint(request.deadline)?;
        let actual = self.db.revision(self.db.program_id(&request.program)?)?;
        if actual != request.revision {
            return Err(romwright_db::DbError::StaleRevision {
                expected: request.revision,
                actual,
            }
            .into());
        }
        request.cancel.checkpoint(request.deadline)
    }
}

/// Capture a tool's output under the same absolute deadline and cancellation
/// token as the rest of its job. Pipes are nonblocking: a descendant retaining
/// stdout cannot make result collection wait beyond the deadline.
#[cfg(unix)]
pub(crate) fn run_command(
    command: &mut std::process::Command,
    request: &ExecutionRequest,
    input: Option<&[u8]>,
    output_limit: usize,
) -> Result<std::process::Output> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    request.cancel.checkpoint(request.deadline)?;
    let mut child = command
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut reaped = false;
    let result = (|| {
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()]
            .into_iter()
            .chain(stdin.as_ref().map(|pipe| pipe.as_raw_fd()))
        {
            // SAFETY: these descriptors are live owned pipe endpoints;
            // fcntl changes their flags without transferring ownership.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        fn drain(
            pipe: &mut impl Read,
            output: &mut Vec<u8>,
            request: &ExecutionRequest,
            limit: usize,
        ) -> Result<bool> {
            let mut buffer = [0u8; 16384];
            loop {
                request.cancel.checkpoint(request.deadline)?;
                match pipe.read(&mut buffer) {
                    Ok(0) => return Ok(true),
                    Ok(count) => {
                        if output.len() + count > limit {
                            return Err(std::io::Error::other(
                                "tool output exceeds the configured limit",
                            )
                            .into());
                        }
                        output.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Ok(false);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let input = input.unwrap_or_default();
        let mut sent = 0;
        if input.is_empty() {
            stdin.take();
        }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let (mut out_done, mut err_done, mut exited) = (false, false, false);
        loop {
            request.cancel.checkpoint(request.deadline)?;
            if let Some(pipe) = stdin.as_mut() {
                match pipe.write(&input[sent..]) {
                    Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
                    Ok(count) => sent += count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error.into()),
                }
                if sent == input.len() {
                    stdin.take();
                }
            }
            if !out_done {
                out_done = drain(&mut stdout, &mut out, request, output_limit)?;
            }
            if !err_done {
                err_done = drain(&mut stderr, &mut err, request, output_limit)?;
            }
            if !exited {
                // Observe without reaping: retaining the leader reserves its
                // process-group ID until every descendant has been killed.
                // SAFETY: siginfo is C data, zero initializes the no-event
                // case, and waitid receives this owned child's live PID.
                let mut event: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let observed = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child.id(),
                        &mut event,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if observed < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::Interrupted {
                        return Err(error.into());
                    }
                } else {
                    exited = event.si_signo != 0;
                }
            }
            if exited && out_done && err_done {
                // Even a successful driver must not leave background children.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let status = child.wait()?;
                reaped = true;
                return Ok(std::process::Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
            std::thread::sleep(
                request
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5)),
            );
        }
    })();
    if !reaped {
        // The unreaped leader prevents process-group ID reuse on every path.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// A kill-on-close job object: terminating it, or dropping the last handle,
/// kills the tool and every process the tool started inside it.
#[cfg(windows)]
struct ToolJob(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl ToolJob {
    fn create() -> std::io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        // SAFETY: both arguments may be null (default security, unnamed job).
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = ToolJob(handle);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the pointer and length describe `limits`, the structure
        // this information class reads; the handle is the live job above.
        let set = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign(&self, child: &std::process::Child) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: both handles are live: the job is owned, the child unreaped.
        if unsafe { windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(self.0, child.as_raw_handle()) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn terminate(&self) {
        // SAFETY: the job handle is owned and live until drop.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for ToolJob {
    fn drop(&mut self) {
        // SAFETY: closes the handle this value owns, exactly once.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// The Windows form of the Unix supervisor above: the tool runs in a
/// kill-on-close job object (so a deadline, a cancellation or completion
/// also ends whatever it started), and its pipes drain on threads, so a
/// descendant holding stdout cannot hold result collection past the deadline.
/// A process the tool starts before it is assigned to the job escapes it;
/// the window is the few instructions between spawn and assignment.
#[cfg(windows)]
pub(crate) fn run_command(
    command: &mut std::process::Command,
    request: &ExecutionRequest,
    input: Option<&[u8]>,
    output_limit: usize,
) -> Result<std::process::Output> {
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::sync::mpsc;

    enum Event {
        Out(Vec<u8>),
        Err(Vec<u8>),
        OutDone,
        ErrDone,
        Failed(std::io::Error),
    }
    fn pump(
        mut pipe: impl Read + Send + 'static,
        events: mpsc::Sender<Event>,
        chunk: fn(Vec<u8>) -> Event,
        done: Event,
    ) {
        std::thread::spawn(move || {
            let mut buffer = [0u8; 16384];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if events.send(chunk(buffer[..count].to_vec())).is_err() {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    // A pipe whose writers all exited reads as broken on Windows: that is EOF.
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => break,
                    Err(error) => {
                        let _ = events.send(Event::Failed(error));
                        return;
                    }
                }
            }
            let _ = events.send(done);
        });
    }

    request.cancel.checkpoint(request.deadline)?;
    let job = ToolJob::create()?;
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut reaped = false;
    let result = (|| {
        job.assign(&child)?;
        let (events, received) = mpsc::channel();
        pump(child.stdout.take().expect("piped stdout"), events.clone(), Event::Out, Event::OutDone);
        pump(child.stderr.take().expect("piped stderr"), events.clone(), Event::Err, Event::ErrDone);
        if let Some(mut stdin) = child.stdin.take() {
            let input = input.unwrap_or_default().to_vec();
            let events = events.clone();
            std::thread::spawn(move || {
                if let Err(error) = stdin.write_all(&input) {
                    let _ = events.send(Event::Failed(error));
                }
            });
        }
        drop(events);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let (mut out_done, mut err_done) = (false, false);
        let mut status = None;
        loop {
            request.cancel.checkpoint(request.deadline)?;
            let wait = request
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(5));
            match received.recv_timeout(wait) {
                Ok(Event::Out(bytes)) => {
                    if out.len() + bytes.len() > output_limit {
                        return Err(std::io::Error::other("tool output exceeds the configured limit").into());
                    }
                    out.extend_from_slice(&bytes);
                }
                Ok(Event::Err(bytes)) => {
                    if err.len() + bytes.len() > output_limit {
                        return Err(std::io::Error::other("tool output exceeds the configured limit").into());
                    }
                    err.extend_from_slice(&bytes);
                }
                Ok(Event::OutDone) => out_done = true,
                Ok(Event::ErrDone) => err_done = true,
                Ok(Event::Failed(error)) => return Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                // Both pipes reached EOF and stdin is written: only the exit is left.
                Err(mpsc::RecvTimeoutError::Disconnected) => std::thread::sleep(wait),
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if let (Some(status), true, true) = (status, out_done, err_done) {
                // Even a successful driver must not leave background children.
                job.terminate();
                reaped = true;
                return Ok(std::process::Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
    })();
    if !reaped {
        job.terminate();
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn run_command(
    _command: &mut std::process::Command,
    _request: &ExecutionRequest,
    _input: Option<&[u8]>,
    _output_limit: usize,
) -> Result<std::process::Output> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "bounded tool execution requires Unix or Windows process supervision",
    )
    .into())
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    fn request(budget: Duration) -> ExecutionRequest {
        ExecutionRequest {
            binary: PathBuf::new(),
            artifact_digest: String::new(),
            input: romwright_model::ProgramInput {
                source_path: String::new(),
                binary_digest: String::new(),
                image_selector: String::new(),
                map_digest: None,
                raw: None,
                keys_digest: None,
            },
            config: crate::session::RuntimeConfig::from_env(),
            program: String::new(),
            language: String::new(),
            base: 0,
            revision: 0,
            project_dir: PathBuf::new(),
            deadline: Instant::now() + budget,
            cancel: CancelToken::default(),
        }
    }

    #[test]
    #[cfg(unix)]
    fn tool_deadline_interrupts_driver_and_child_output() {
        let request = request(Duration::from_millis(100));
        let start = Instant::now();
        let result = run_command(
            std::process::Command::new("/bin/sh").args(["-c", "sleep 5; printf late"]),
            &request,
            None,
            8 * 1024 * 1024,
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(windows)]
    fn tool_deadline_interrupts_driver_and_child_output() {
        let request = request(Duration::from_millis(300));
        let start = Instant::now();
        let result = run_command(
            std::process::Command::new("cmd").args(["/d", "/c", "ping -n 6 127.0.0.1 >nul & echo late"]),
            &request,
            None,
            8 * 1024 * 1024,
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(windows)]
    fn captures_output_and_input() {
        let request = request(Duration::from_secs(20));
        let output = run_command(
            std::process::Command::new("cmd").args(["/d", "/c", "findstr x"]),
            &request,
            Some(b"axb\r\nnothing\r\n"),
            8 * 1024 * 1024,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "axb");
    }

    #[test]
    #[cfg(windows)]
    fn deadline_kills_descendants_after_the_driver_exits() {
        use std::os::windows::process::CommandExt;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("romwright-descendant-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("marker");
        let child = dir.join("child.cmd");
        // The descendant writes the marker two seconds after it starts.
        std::fs::write(
            &child,
            format!("@ping -n 3 127.0.0.1 >nul\r\n@echo x> \"{}\"\r\n", marker.display()),
        )
        .unwrap();
        // Control: unsupervised, the descendant does write the marker.
        std::process::Command::new("cmd").args(["/d", "/c"]).arg(&child).status().unwrap();
        assert!(marker.exists(), "the descendant script never writes its marker");
        std::fs::remove_file(&marker).unwrap();
        // The driver starts the descendant and exits at once; the descendant
        // inherits the output pipes, so only the deadline ends collection.
        let request = request(Duration::from_millis(300));
        let result = run_command(
            std::process::Command::new("cmd")
                .args(["/d", "/c"])
                .raw_arg(format!("start \"\" /b cmd /d /c \"{}\"", child.display())),
            &request,
            None,
            8 * 1024 * 1024,
        );
        std::thread::sleep(Duration::from_secs(4));
        let survived = marker.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err());
        assert!(!survived, "deadline left a descendant running after its driver exited");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn deadline_kills_descendants_after_the_driver_exits() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid_file = std::env::temp_dir().join(format!(
            "romwright-descendant-{}-{stamp}",
            std::process::id()
        ));
        let request = request(Duration::from_millis(100));
        let result = run_command(
            std::process::Command::new("/bin/sh")
                .args(["-c", "sleep 5 & printf '%s' \"$!\" > \"$1\"", "sh"])
                .arg(&pid_file),
            &request,
            None,
            8 * 1024 * 1024,
        );
        let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        let until = Instant::now() + Duration::from_millis(500);
        let stopped = loop {
            let status = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            if status
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                || status.as_ref().is_ok_and(|text| {
                    text.rsplit_once(") ")
                        .is_some_and(|(_, fields)| fields.starts_with('Z'))
                })
            {
                break true;
            }
            if Instant::now() >= until {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if !stopped {
            // This PID came from the child we launched; clean up the failed
            // reproduction before asserting so the regression cannot leak it.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        std::fs::remove_file(pid_file).unwrap();
        assert!(result.is_err());
        assert!(
            stopped,
            "deadline left a descendant running after its driver exited"
        );
    }
}
