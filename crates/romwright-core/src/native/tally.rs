//! Wall-clock tallies for work that runs on helper threads or deep inside a
//! stage, where no `NativeImport` is at hand to take a `PhaseTiming`.
//!
//! Each `add` accumulates seconds under a name for the whole process;
//! `--timings` prints the totals on a `TALLY` line beside the per-program
//! stage phases. A tally is a sum over the threads that recorded it, so it can
//! exceed wall time.
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

static TALLY: Mutex<BTreeMap<&'static str, f64>> = Mutex::new(BTreeMap::new());

/// Adds the time since `started` to `name`.
pub(crate) fn add(name: &'static str, started: Instant) {
    let seconds = started.elapsed().as_secs_f64();
    *TALLY.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(name).or_default() += seconds;
}

/// Adds `value` to `name` (a count, or seconds measured elsewhere).
pub(crate) fn add_value(name: &'static str, value: f64) {
    *TALLY.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(name).or_default() += value;
}

/// Everything tallied since the last drain (a process-wide sum; see `--timings`).
pub fn drain() -> Vec<(&'static str, f64)> {
    std::mem::take(&mut *TALLY.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
        .into_iter()
        .collect()
}
