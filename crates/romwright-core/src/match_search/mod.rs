//! The near-miss search of docs/match.md: for one function, print it in a
//! bounded set of alternative ways, compile each print with the project's
//! pinned compiler and score the object's bytes against the retail ones, keep
//! the best. The decompiler's printing choices are the stage 3 variant knob
//! (docs/merge-port.md section 5) plus the existing casts and structuring
//! switches; nothing here is a fitted rule, and the retail bytes with the
//! compiler are the only oracle.

pub mod object;
pub mod pe;
pub mod plan;
pub mod project;

use plan::{Outcome, PrintVariant, cmp_key};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How one printed C scored against the retail bytes.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Score {
    /// The object holds the function.
    pub compiled: bool,
    /// Same length, every byte equal outside relocation fields.
    pub exact: bool,
    /// `objdiff-cli`'s match percent (`functionRelocDiffs=none`), the lane harness's measure.
    pub percent: f64,
    /// Differing bytes outside relocation fields (`None` when the length differs).
    pub byte_diffs: Option<usize>,
    /// Size of the compiled function.
    pub size: Option<usize>,
    pub error: Option<String>,
}

impl Score {
    /// Exact first, then compiled, then objdiff percent, then fewer byte differences.
    pub fn key(&self) -> (bool, bool, f64, i64) {
        (self.exact, self.compiled, self.percent, -(self.byte_diffs.unwrap_or(usize::MAX / 2) as i64))
    }
}

/// What the search needs from a project: print the function a way, score a C text.
pub trait Evaluator {
    fn print(&mut self, variant: &PrintVariant) -> Result<String, String>;
    fn score(&mut self, text: &str) -> Score;
}

#[derive(Clone, Debug)]
pub struct Options {
    /// Most variants to print besides the stock one.
    pub budget: usize,
    /// Wall time after which no further variant starts.
    pub time: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options { budget: plan::DEFAULT_BUDGET, time: Duration::from_secs(600) }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Row {
    pub variant: String,
    /// FNV-1a of the printed C, to see which variants printed the same text.
    pub text_hash: Option<String>,
    /// Index of the earlier row that printed the same C (it is not compiled again).
    pub same_as: Option<usize>,
    pub score: Option<Score>,
    pub error: Option<String>,
    pub decompile_ms: u64,
    pub compile_ms: u64,
    #[serde(skip)]
    pub text: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stop {
    /// A variant compiled to the retail bytes.
    Exact,
    /// Every variant of the plan was tried.
    Exhausted,
    Budget,
    Time,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Report {
    pub rows: Vec<Row>,
    /// Index into `rows` of the best variant (the stock one when nothing beat it).
    pub best: usize,
    pub stop: Stop,
    pub decompiles: usize,
    pub compiles: usize,
    pub elapsed_ms: u64,
}

impl Report {
    pub fn best_row(&self) -> &Row {
        &self.rows[self.best]
    }
}

fn hash(text: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in text.as_bytes() {
        h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
    }
    h
}

struct Run<'a, E: Evaluator> {
    evaluator: &'a mut E,
    rows: Vec<Row>,
    outcomes: Vec<Outcome>,
    seen: HashMap<u64, usize>,
    decompiles: usize,
    compiles: usize,
}

impl<E: Evaluator> Run<'_, E> {
    /// Prints and scores one variant; returns whether it is exact.
    fn try_variant(&mut self, variant: &PrintVariant) -> bool {
        let started = Instant::now();
        let printed = self.evaluator.print(variant);
        let decompile_ms = started.elapsed().as_millis() as u64;
        self.decompiles += 1;
        let mut row = Row {
            variant: variant.label(),
            text_hash: None,
            same_as: None,
            score: None,
            error: None,
            decompile_ms,
            compile_ms: 0,
            text: None,
        };
        let mut distinct = false;
        match printed {
            Err(error) => row.error = Some(error),
            Ok(text) => {
                let h = hash(&text);
                row.text_hash = Some(format!("{h:016x}"));
                if let Some(&earlier) = self.seen.get(&h) {
                    row.same_as = Some(earlier);
                    row.score = self.rows[earlier].score.clone();
                } else {
                    distinct = true;
                    let started = Instant::now();
                    let score = self.evaluator.score(&text);
                    row.compile_ms = started.elapsed().as_millis() as u64;
                    self.compiles += 1;
                    row.score = Some(score);
                    self.seen.insert(h, self.rows.len());
                    row.text = Some(text);
                }
            }
        }
        let key = row.score.as_ref().map(Score::key).unwrap_or((false, false, 0.0, i64::MIN));
        let exact = key.0;
        self.outcomes.push(Outcome { variant: variant.clone(), distinct, key });
        self.rows.push(row);
        exact
    }
}

/// Runs the search. The stock printing is always tried first; the single-knob
/// variants follow, then combinations of the ones that helped; the search stops
/// at the first exact variant, at the budget or at the wall-time limit.
pub fn search<E: Evaluator>(evaluator: &mut E, options: &Options) -> Report {
    let started = Instant::now();
    let mut run = Run { evaluator, rows: Vec::new(), outcomes: Vec::new(), seen: HashMap::new(), decompiles: 0, compiles: 0 };
    let mut stop = Stop::Exhausted;
    let mut tried: Vec<PrintVariant> = vec![PrintVariant::stock()];
    let mut done = run.try_variant(&PrintVariant::stock());
    if done {
        stop = Stop::Exact;
    }
    let singles = plan::singles(options.budget);
    let mut queue: std::collections::VecDeque<PrintVariant> = singles.iter().cloned().collect();
    let mut combined = false;
    let mut spent = 0usize;
    while !done {
        let Some(variant) = queue.pop_front() else {
            if combined || spent >= options.budget {
                break;
            }
            // Singles done: combine what helped.
            combined = true;
            let stock = run.outcomes[0].clone();
            let single_outcomes: Vec<Outcome> = run.outcomes[1..].iter().filter(|o| o.variant.knobs.len() == 1).cloned().collect();
            queue.extend(plan::combinations(&stock, &single_outcomes, &tried, options.budget - spent));
            continue;
        };
        if spent >= options.budget {
            stop = Stop::Budget;
            break;
        }
        if started.elapsed() >= options.time {
            stop = Stop::Time;
            break;
        }
        spent += 1;
        tried.push(variant.clone());
        if run.try_variant(&variant) {
            stop = Stop::Exact;
            done = true;
        }
    }
    if !done && stop == Stop::Exhausted && spent >= options.budget && plan::SINGLES.len() > options.budget {
        stop = Stop::Budget;
    }
    let mut best = 0usize;
    for (index, outcome) in run.outcomes.iter().enumerate() {
        if cmp_key(&outcome.key, &run.outcomes[best].key) == std::cmp::Ordering::Greater {
            best = index;
        }
    }
    Report {
        rows: run.rows,
        best,
        stop,
        decompiles: run.decompiles,
        compiles: run.compiles,
        elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plan::Knob;

    /// Prints a text per variant and scores the text by a table.
    struct Fake {
        scores: HashMap<String, f64>,
        printed: Vec<String>,
    }

    impl Evaluator for Fake {
        fn print(&mut self, variant: &PrintVariant) -> Result<String, String> {
            self.printed.push(variant.label());
            // Only maxref and datatype change the text.
            let mut text = String::from("body");
            for knob in &variant.knobs {
                if matches!(knob, Knob::Merge(m) if m.starts_with("maxref=1") || m.starts_with("datatype")) {
                    text.push_str(&knob.label());
                }
            }
            Ok(text)
        }

        fn score(&mut self, text: &str) -> Score {
            let percent = self.scores.get(text).copied().unwrap_or(50.0);
            Score { compiled: true, exact: percent >= 100.0, percent, byte_diffs: Some(1), size: Some(8), error: None }
        }
    }

    #[test]
    fn dedupes_stops_on_exact_and_picks_the_best() {
        let scores = [("bodymaxref=1".to_string(), 90.0), ("bodymaxref=1datatype=off".to_string(), 100.0), ("bodydatatype=off".to_string(), 60.0)];
        let mut fake = Fake { scores: scores.into_iter().collect(), printed: Vec::new() };
        let report = search(&mut fake, &Options::default());
        assert_eq!(report.stop, Stop::Exact);
        assert_eq!(report.best_row().variant, "maxref=1+datatype=off");
        // Variants that printed the stock text were not compiled again.
        assert!(report.compiles < report.decompiles);
        assert!(report.rows.iter().any(|r| r.same_as == Some(0)));
    }

    #[test]
    fn budget_bounds_the_decompiles() {
        let mut fake = Fake { scores: HashMap::new(), printed: Vec::new() };
        let report = search(&mut fake, &Options { budget: 3, time: Duration::from_secs(60) });
        assert_eq!(report.decompiles, 4);
        assert_eq!(report.stop, Stop::Budget);
        assert_eq!(report.best, 0);
    }
}
