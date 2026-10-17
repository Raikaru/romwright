//! The bounded job log every long-running call reports into (Qt `JobsDock`
//! `beginJob`/`finishJob`). Worker threads write; the UI thread snapshots.

use romwright_core::exec::CancelToken;
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub type JobId = u64;

/// Finished entries beyond this many are pruned oldest-first; running
/// entries are never pruned.
const RETAINED: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct JobEntry {
    pub id: JobId,
    pub label: String,
    pub state: JobState,
    /// Latest progress line while running.
    pub progress: String,
    /// Full multiline result or error once finished.
    pub detail: String,
    pub started: Instant,
    pub elapsed: Option<Duration>,
    cancel: CancelToken,
}

/// One completion, for the status bar and toasts.
#[derive(Clone, Debug)]
pub struct Finished {
    pub label: String,
    pub detail: String,
    pub state: JobState,
    pub elapsed: Duration,
}

#[derive(Default)]
struct Board {
    entries: VecDeque<JobEntry>,
    next_id: JobId,
    statuses: Vec<Finished>,
    finished: u64,
}

#[derive(Default)]
pub struct JobBoard {
    board: Mutex<Board>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl JobBoard {
    fn lock(&self) -> MutexGuard<'_, Board> {
        self.board.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn begin(&self, label: String, cancel: CancelToken) -> JobId {
        let mut board = self.lock();
        prune(&mut board);
        let id = board.next_id;
        board.next_id += 1;
        board.entries.push_back(JobEntry {
            id,
            label,
            state: JobState::Running,
            progress: String::new(),
            detail: String::new(),
            started: Instant::now(),
            elapsed: None,
            cancel,
        });
        id
    }

    pub(crate) fn progress(&self, id: JobId, text: String) {
        if let Some(entry) = self.lock().entries.iter_mut().find(|entry| entry.id == id) {
            entry.progress = text;
        }
    }

    pub(crate) fn finish(&self, id: JobId, state: JobState, detail: String) {
        let mut board = self.lock();
        let mut finished = Finished { label: String::new(), detail: detail.clone(), state, elapsed: Duration::ZERO };
        if let Some(entry) = board.entries.iter_mut().find(|entry| entry.id == id) {
            entry.state = state;
            entry.elapsed = Some(entry.started.elapsed());
            entry.detail = detail;
            finished.label = entry.label.clone();
            finished.elapsed = entry.started.elapsed();
        }
        board.finished += 1;
        board.statuses.push(finished);
        prune(&mut board);
    }

    pub(crate) fn adopt(&self, handle: JoinHandle<()>) {
        let mut threads = self.threads.lock().unwrap_or_else(|error| error.into_inner());
        threads.retain(|thread| !thread.is_finished());
        threads.push(handle);
    }

    /// Requests cooperative cancellation; the job reaches a terminal state on
    /// its next checkpoint.
    pub fn cancel(&self, id: JobId) {
        if let Some(entry) = self.lock().entries.iter().find(|entry| entry.id == id) {
            entry.cancel.cancel();
        }
    }

    /// Removes a log entry only: the work itself continues.
    pub fn dismiss(&self, id: JobId) {
        self.lock().entries.retain(|entry| entry.id != id);
    }

    pub fn snapshot(&self) -> Vec<JobEntry> {
        self.lock().entries.iter().cloned().collect()
    }

    pub fn running(&self) -> usize {
        self.lock()
            .entries
            .iter()
            .filter(|entry| entry.state == JobState::Running)
            .count()
    }

    /// Monotonic count of finished jobs, so a panel can refresh derived
    /// state (pool counters) once per completion.
    pub fn finished(&self) -> u64 {
        self.lock().finished
    }

    /// Status-bar messages produced by finished jobs since the last call.
    pub fn take_finished(&self) -> Vec<Finished> {
        std::mem::take(&mut self.lock().statuses)
    }

    /// Cancels every running job and waits for its thread, so no native
    /// child outlives the window that started it.
    pub(crate) fn shutdown(&self) {
        for entry in self.lock().entries.iter() {
            if entry.state == JobState::Running {
                entry.cancel.cancel();
            }
        }
        let threads = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|error| error.into_inner()));
        for thread in threads {
            let _ = thread.join();
        }
    }
}

impl JobEntry {
    pub fn cancel_requested(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

fn prune(board: &mut Board) {
    while board.entries.len() >= RETAINED {
        let Some(position) = board
            .entries
            .iter()
            .position(|entry| entry.state != JobState::Running)
        else {
            break;
        };
        board.entries.remove(position);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finished_entries_are_bounded_and_running_ones_survive() {
        let board = JobBoard::default();
        let running = board.begin("long".into(), CancelToken::default());
        for index in 0..600 {
            let id = board.begin(format!("job {index}"), CancelToken::default());
            board.finish(id, JobState::Succeeded, "ok".into());
        }
        let entries = board.snapshot();
        assert!(entries.len() <= RETAINED);
        assert!(entries.iter().any(|entry| entry.id == running));
        assert_eq!(board.running(), 1);
        assert_eq!(board.take_finished().len(), 600);
        board.cancel(running);
        assert!(board.snapshot()[0].cancel_requested());
    }
}
