//! `romwright-cli match`: the near-miss search inside a `new-project` repository.
//!
//!   match <name|0xADDR> [--project DIR] [--budget N] [--time SECS] [--write] [--json]
//!   match --plan [--budget N] [--outcomes FILE]
//!
//! The first form prints the function in alternative ways, compiles each with
//! the repository's pinned compiler and flags, scores the object against the
//! retail bytes and shows the table (docs/match.md). `--plan` prints the
//! variants the search tries (and, given the single-knob outcomes, the
//! combinations it would try next) without touching a project: it is what the
//! lane benchmark harness reads, so the benchmark and the command share one plan.

use super::{flag, has_flag};
use romwright_core::Core;
use romwright_core::match_search::plan::{self, Outcome, PrintVariant};
use romwright_core::match_search::project::{MatchProject, ProjectEvaluator, resolve_function};
use romwright_core::match_search::{self, Options, Stop};
use std::path::PathBuf;
use std::time::Duration;

pub fn run(args: &[String]) -> Result<(), String> {
    let budget = flag(args, "--budget")
        .map(|v| v.parse::<usize>().map_err(|e| format!("--budget: {e}")))
        .transpose()?
        .unwrap_or(plan::DEFAULT_BUDGET);
    if has_flag(args, "--plan") {
        return print_plan(args, budget);
    }
    let query = args.get(2).filter(|a| !a.starts_with("--")).ok_or("match needs a function name or address")?;
    let root = PathBuf::from(flag(args, "--project").unwrap_or_else(|| ".".into()));
    let seconds = flag(args, "--time").map(|v| v.parse::<u64>().map_err(|e| format!("--time: {e}"))).transpose()?.unwrap_or(600);
    let project = MatchProject::open(&root)?;
    let core = Core::open(&project.root.join(".romwright")).map_err(|e| e.to_string())?;
    let function = resolve_function(&core, &project.program, query)?;
    let scratch = project.root.join("build/tmp").join(format!("match-{}", std::process::id()));
    let mut evaluator = ProjectEvaluator::new(&core, &project, function.clone(), scratch.clone())?;
    let report = match_search::search(&mut evaluator, &Options { budget, time: Duration::from_secs(seconds) });
    let _ = std::fs::remove_dir_all(&scratch);

    let best = report.best_row();
    let default = &report.rows[0];
    let mut written = None;
    if has_flag(args, "--write") {
        let text = best.text.as_ref().filter(|_| best.score.as_ref().is_some_and(|s| s.compiled));
        let text = text.ok_or("--write: no variant compiled; nothing written")?;
        written = Some(project.write_best(function.entry.offset, text)?);
    }

    if has_flag(args, "--json") {
        let value = serde_json::json!({
            "function": function.name,
            "address": format!("{:#x}", function.entry.offset),
            "size": function.size,
            "compiler": project.compiler_id,
            "cflags": project.cflags,
            "metric": if project.objdiff.is_some() { "objdiff match_percent (functionRelocDiffs=none)" } else { "share of equal instruction words" },
            "best": best.variant,
            "best_index": report.best,
            "default_percent": default.score.as_ref().map(|s| s.percent),
            "best_percent": best.score.as_ref().map(|s| s.percent),
            "best_exact": best.score.as_ref().is_some_and(|s| s.exact),
            "stop": report.stop,
            "decompiles": report.decompiles,
            "compiles": report.compiles,
            "elapsed_ms": report.elapsed_ms,
            "written": written,
            "rows": report.rows,
        });
        println!("{}", serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?);
        return Ok(());
    }

    println!(
        "{} {:#x} ({} bytes)  compiler {} {}  metric: {}",
        function.name,
        function.entry.offset,
        function.size,
        project.compiler_id,
        project.cflags.join(" "),
        if project.objdiff.is_some() { "objdiff match %" } else { "equal instruction words %" }
    );
    println!("{:>3}  {:<46} {:<8} {:>9} {:>6} {:>7} {:>8} {:>8}", "#", "variant", "C", "match %", "exact", "bytes", "decomp", "compile");
    for (index, row) in report.rows.iter().enumerate() {
        let hash = row.text_hash.as_deref().map(|h| &h[..8]).unwrap_or("-");
        let (percent, exact, bytes) = match &row.score {
            Some(s) if s.compiled => (
                format!("{:.3}", s.percent),
                if s.exact { "yes" } else { "no" }.to_string(),
                s.byte_diffs.map_or_else(|| format!("size {}", s.size.unwrap_or(0)), |d| d.to_string()),
            ),
            Some(s) => ("-".into(), "-".into(), s.error.clone().unwrap_or_default().chars().take(40).collect()),
            None => ("-".into(), "-".into(), row.error.clone().unwrap_or_default().chars().take(40).collect()),
        };
        let note = match row.same_as {
            Some(earlier) => format!(" = #{earlier}"),
            None => String::new(),
        };
        println!(
            "{:>3}{} {:<46} {:<8} {:>9} {:>6} {:>7} {:>7}s {:>7}s{note}",
            index,
            if index == report.best { "*" } else { " " },
            row.variant,
            hash,
            percent,
            exact,
            bytes,
            row.decompile_ms as f64 / 1000.0,
            row.compile_ms as f64 / 1000.0,
        );
    }
    let stop = match report.stop {
        Stop::Exact => "stopped at an exact variant",
        Stop::Exhausted => "every planned variant tried",
        Stop::Budget => "stopped at the variant budget",
        Stop::Time => "stopped at the time limit",
    };
    println!(
        "best: {}  {:.3}%{}  (default {:.3}%)  {} decompiles, {} compiles, {:.1}s; {stop}",
        best.variant,
        best.score.as_ref().map_or(0.0, |s| s.percent),
        if best.score.as_ref().is_some_and(|s| s.exact) { " exact" } else { "" },
        default.score.as_ref().map_or(0.0, |s| s.percent),
        report.decompiles,
        report.compiles,
        report.elapsed_ms as f64 / 1000.0,
    );
    if let Some(path) = written {
        if project.kind == "pe" {
            println!("wrote {} (python3 build.py && python3 build.py report scores it with the project's own objects)", path.display());
        } else {
            println!("wrote {} (python3 configure.py swap {:#x} installs it)", path.display(), function.entry.offset);
        }
    }
    Ok(())
}

/// `match --plan`: the plan as JSON. With `--outcomes FILE` (`{"stock": O, "singles": [O...]}`, `O` =
/// `{"label", "distinct", "exact", "compiled", "percent", "byte_diffs"}`), the combinations to try next.
fn print_plan(args: &[String], budget: usize) -> Result<(), String> {
    let describe = |v: &PrintVariant| serde_json::json!({"label": v.label(), "env": v.env_words()});
    let Some(path) = flag(args, "--outcomes") else {
        let singles: Vec<_> = plan::singles(budget).iter().map(describe).collect();
        println!("{}", serde_json::json!({"budget": budget, "singles": singles}));
        return Ok(());
    };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let outcome = |value: &serde_json::Value| -> Result<Outcome, String> {
        let variant = plan::parse_label(value["label"].as_str().unwrap_or("default"))?;
        let diffs = value["byte_diffs"].as_i64().unwrap_or(i64::MAX / 2);
        Ok(Outcome {
            variant,
            distinct: value["distinct"].as_bool().unwrap_or(true),
            key: (
                value["exact"].as_bool().unwrap_or(false),
                value["compiled"].as_bool().unwrap_or(false),
                value["percent"].as_f64().unwrap_or(0.0),
                -diffs,
            ),
        })
    };
    let stock = outcome(&json["stock"])?;
    let singles = json["singles"].as_array().ok_or("--outcomes: no singles")?.iter().map(outcome).collect::<Result<Vec<_>, _>>()?;
    let mut tried = vec![PrintVariant::stock()];
    tried.extend(singles.iter().map(|o| o.variant.clone()));
    let spent = singles.len();
    let combinations: Vec<_> = plan::combinations(&stock, &singles, &tried, budget.saturating_sub(spent)).iter().map(describe).collect();
    println!("{}", serde_json::json!({"budget": budget, "combinations": combinations}));
    Ok(())
}
