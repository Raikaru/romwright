//! The two project commands of docs/new-project.md and docs/match.md as
//! desktop jobs.
//!
//! * [`run_new_project`] runs `romwright-cli new-project` on the open image.
//!   The CLI owns the per-platform plugins (PS2, GameCube/Wii, N64, PSX, PSP,
//!   GBA, NDS, the non-matching scaffold, Windows PE), so the desktop runs the
//!   same executable instead of a second copy of that glue: it is found beside
//!   the app (the release archive ships it there), then in the workspace's
//!   release and debug builds, and `ROMWRIGHT_CLI` pins one.
//! * [`run_match`] is `romwright-cli match` without the printing: the same
//!   `match_search::search` over a [`ProjectEvaluator`], returned as the
//!   [`Report`] the Match panel shows as a variant table.

use crate::service::{JobContext, TaskResult};
use romwright_core::Core;
use romwright_core::match_search::plan::PrintVariant;
use romwright_core::match_search::project::{MatchProject, ProjectEvaluator, resolve_function};
use romwright_core::match_search::{self, Evaluator, Options, Report, Score};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The CLI this build drives: an explicit pin, then the CLI beside the running
/// executable, then the workspace's release and debug paths (the same order
/// the worker is found in).
pub fn cli_executable() -> PathBuf {
    if let Ok(pinned) = std::env::var("ROMWRIGHT_CLI") {
        return PathBuf::from(pinned);
    }
    let name = format!("romwright-cli{}", std::env::consts::EXE_SUFFIX);
    let sibling = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|dir| dir.join(&name)));
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("."));
    let fallbacks = [
        repo_root.join("target/release").join(&name),
        repo_root.join("target/debug").join(&name),
        PathBuf::from("target/release").join(&name),
        PathBuf::from("target/debug").join(&name),
    ];
    sibling
        .into_iter()
        .chain(fallbacks)
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| repo_root.join("target/release").join(&name))
}

#[derive(Clone, Debug)]
pub struct NewProjectRequest {
    /// The image to import (the open program's binary).
    pub image: PathBuf,
    /// Name the program is imported under; the image is staged under it
    /// when `image` is the project's content-addressed artifact copy.
    pub program: String,
    /// The repository to write.
    pub outdir: PathBuf,
    /// `--name`; empty = the CLI's default (the image's file stem).
    pub name: String,
    /// `--platform`; empty = detected from the image.
    pub platform: String,
    /// `--decompile`: `none`, `all`, `first:N` or `ADDR,ADDR`.
    pub decompile: String,
    /// Where a staged copy of the image may be written.
    pub staging: PathBuf,
}

#[derive(Clone, Debug)]
pub struct NewProjectReport {
    pub outdir: PathBuf,
    /// The CLI's own summary line (`wrote <dir>: ...`).
    pub summary: String,
    /// What to run next, as the CLI or the repository's scripts say it.
    pub next: String,
    /// Files in the repository, not counting the retail copy and the store.
    pub files: usize,
    /// The CLI's output, for the job's detail view.
    pub log: String,
}

/// A path the CLI names the repository's image after: the artifact copy is
/// `<project>/artifacts/<digest>`, so it is linked under the program's name.
fn staged_image(request: &NewProjectRequest) -> Result<(PathBuf, Option<PathBuf>), String> {
    let artifact = request.image.parent().and_then(Path::file_name).is_some_and(|name| name == "artifacts");
    if !artifact {
        return Ok((request.image.clone(), None));
    }
    let name = if request.program.is_empty() { "image".to_string() } else { request.program.clone() };
    std::fs::create_dir_all(&request.staging).map_err(|error| format!("{}: {error}", request.staging.display()))?;
    let staged = request.staging.join(name);
    let _ = std::fs::remove_file(&staged);
    let absolute = std::fs::canonicalize(&request.image).map_err(|error| format!("{}: {error}", request.image.display()))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&absolute, &staged).map_err(|error| format!("{}: {error}", staged.display()))?;
    #[cfg(not(unix))]
    std::fs::hard_link(&absolute, &staged)
        .or_else(|_| std::fs::copy(&absolute, &staged).map(drop))
        .map_err(|error| format!("{}: {error}", staged.display()))?;
    Ok((staged.clone(), Some(staged)))
}

fn count_files(root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else { return 0 };
    entries
        .filter_map(Result::ok)
        .map(|entry| {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if name == ".romwright" || name == "orig" { 0 } else { count_files(&path) }
            } else {
                1
            }
        })
        .sum()
}

/// Runs `romwright-cli new-project` as a child process: stderr lines are the
/// job's progress, cancellation kills the child.
pub fn run_new_project(job: &JobContext, request: &NewProjectRequest) -> TaskResult<NewProjectReport> {
    let cli = cli_executable();
    if !cli.is_file() {
        return Err(format!(
            "romwright-cli not found at {}: it is installed beside romwright-desktop (set ROMWRIGHT_CLI to use another)",
            cli.display()
        ));
    }
    let (image, staged) = staged_image(request)?;
    let mut command = Command::new(&cli);
    command.arg("new-project").arg(&image).arg(&request.outdir);
    if !request.name.trim().is_empty() {
        command.arg("--name").arg(request.name.trim());
    }
    if !request.platform.trim().is_empty() {
        command.arg("--platform").arg(request.platform.trim());
    }
    // The CLI's default for the scaffold platforms is a whole-image decompile, hours long.
    let decompile = request.decompile.trim();
    command.arg("--decompile").arg(if decompile.is_empty() { "none" } else { decompile });
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    job.progress(format!("new-project {}", image.display()));
    let result = run_child(job, &mut command);
    if let Some(staged) = staged {
        let _ = std::fs::remove_file(staged);
    }
    let (status, stdout, stderr) = result?;
    let mut log = String::new();
    log.push_str(&stdout);
    if !stderr.is_empty() {
        log.push_str(&stderr);
    }
    if !status.success() {
        let tail: Vec<&str> = stderr.lines().rev().take(6).collect();
        let tail = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
        return Err(format!("romwright-cli new-project failed ({status}):\n{tail}"));
    }
    let line = |prefix: &str| stdout.lines().find(|line| line.starts_with(prefix)).map(str::to_string);
    let summary = line("wrote ")
        .or_else(|| stdout.lines().find(|line| !line.trim().is_empty()).map(str::to_string))
        .unwrap_or_else(|| format!("wrote {}", request.outdir.display()));
    let next = line("next:").unwrap_or_else(|| {
        let script = if request.outdir.join("configure.py").is_file() { "configure.py" } else { "build.py" };
        format!("next: cd {} && python3 {script}", request.outdir.display())
    });
    if !request.outdir.join("README.md").is_file() {
        return Err(format!("new-project reported success but {} holds no README.md", request.outdir.display()));
    }
    Ok(NewProjectReport { outdir: request.outdir.clone(), summary, next, files: count_files(&request.outdir), log })
}

fn run_child(job: &JobContext, command: &mut Command) -> TaskResult<(std::process::ExitStatus, String, String)> {
    let mut child = command.spawn().map_err(|error| format!("cannot start {:?}: {error}", command.get_program()))?;
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    std::thread::scope(|scope| {
        let out = scope.spawn(move || {
            let mut text = String::new();
            let _ = stdout.read_to_string(&mut text);
            text
        });
        let err = scope.spawn(move || {
            let mut text = String::new();
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if !line.trim().is_empty() {
                    job.progress(line.trim().to_string());
                }
                text.push_str(&line);
                text.push('\n');
            }
            text
        });
        let status = loop {
            if job.is_cancelled() {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out.join();
                let _ = err.join();
                return Err("cancelled".to_string());
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => std::thread::sleep(Duration::from_millis(40)),
                Err(error) => return Err(format!("waiting for the child: {error}")),
            }
        };
        Ok((status, out.join().unwrap_or_default(), err.join().unwrap_or_default()))
    })
}

#[derive(Clone, Debug)]
pub struct MatchRequest {
    /// The `new-project` repository.
    pub root: PathBuf,
    pub entry: u64,
    /// Variants to print besides the stock one.
    pub budget: usize,
    pub seconds: u64,
}

#[derive(Clone, Debug)]
pub struct MatchOutcome {
    pub name: String,
    pub entry: u64,
    pub size: u64,
    pub compiler: String,
    pub cflags: String,
    /// What the percent column measures.
    pub metric: &'static str,
    pub report: Report,
}

/// Cancels the search between variants and reports each print as progress.
struct Cancellable<'a, E> {
    inner: E,
    job: &'a JobContext,
}

impl<E: Evaluator> Evaluator for Cancellable<'_, E> {
    fn print(&mut self, variant: &PrintVariant) -> Result<String, String> {
        self.job.check_cancelled()?;
        self.job.progress(format!("printing variant {}", variant.label()));
        self.inner.print(variant)
    }

    fn score(&mut self, text: &str) -> Score {
        if self.job.is_cancelled() {
            return Score { error: Some("cancelled".into()), ..Score::default() };
        }
        self.inner.score(text)
    }
}

/// `match <ADDR>` inside a repository: the table of docs/match.md.
pub fn run_match(job: &JobContext, request: &MatchRequest) -> TaskResult<MatchOutcome> {
    let project = MatchProject::open(&request.root)?;
    let store = project.root.join(".romwright");
    if !store.is_dir() {
        return Err(format!("{} has no .romwright store: it is not a `new-project` repository", project.root.display()));
    }
    let core = Core::open(&store).map_err(|error| error.to_string())?;
    let function = resolve_function(&core, &project.program, &format!("{:#x}", request.entry))?;
    let scratch = project.root.join("build/tmp").join(format!("match-{}", std::process::id()));
    let inner = ProjectEvaluator::new(&core, &project, function.clone(), scratch.clone())?;
    let mut evaluator = Cancellable { inner, job };
    let report = match_search::search(&mut evaluator, &Options { budget: request.budget, time: Duration::from_secs(request.seconds) });
    let _ = std::fs::remove_dir_all(&scratch);
    job.check_cancelled()?;
    Ok(MatchOutcome {
        name: function.name,
        entry: function.entry.offset,
        size: function.size,
        compiler: project.compiler_id.clone(),
        cflags: project.cflags.join(" "),
        metric: if project.objdiff.is_some() { "objdiff match %" } else { "equal instruction words %" },
        report,
    })
}

/// `match --write`: the best variant's C into the repository's `src/`.
pub fn write_best(root: &Path, entry: u64, text: &str) -> Result<PathBuf, String> {
    MatchProject::open(root)?.write_best(entry, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(image: &str) -> NewProjectRequest {
        NewProjectRequest {
            image: PathBuf::from(image),
            program: "demo".into(),
            outdir: PathBuf::from("out"),
            name: String::new(),
            platform: String::new(),
            decompile: String::new(),
            staging: std::env::temp_dir().join(format!("romwright-staging-test-{}", std::process::id())),
        }
    }

    #[test]
    fn a_user_file_is_passed_as_it_is() {
        let (path, staged) = staged_image(&request("games/fe8.gba")).unwrap();
        assert_eq!(path, PathBuf::from("games/fe8.gba"));
        assert!(staged.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn an_artifact_copy_is_staged_under_the_program_name() {
        let root = std::env::temp_dir().join(format!("romwright-artifact-test-{}", std::process::id()));
        let artifacts = root.join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let digest = artifacts.join("0123456789abcdef");
        std::fs::write(&digest, b"MZ").unwrap();
        let mut request = request(digest.to_str().unwrap());
        request.staging = root.join("staging");
        let (path, staged) = staged_image(&request).unwrap();
        assert_eq!(path.file_name().unwrap(), "demo");
        assert_eq!(std::fs::read(&path).unwrap(), b"MZ");
        assert_eq!(staged.as_deref(), Some(path.as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn files_count_skips_the_retail_copy_and_the_store() {
        let root = std::env::temp_dir().join(format!("romwright-count-test-{}", std::process::id()));
        for directory in ["config", "orig", ".romwright"] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
            std::fs::write(root.join(directory).join("file"), b"x").unwrap();
        }
        std::fs::write(root.join("README.md"), b"x").unwrap();
        assert_eq!(count_files(&root), 2);
        let _ = std::fs::remove_dir_all(&root);
    }
}
