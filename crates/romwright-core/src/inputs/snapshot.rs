//! Hands a worker the mapped image its parent already derived.
//!
//! A switch-recovery or decompile worker needs the program's mapped bytes, not
//! the input they came from. Left to itself it opens the whole input (a
//! multi-gigabyte disc image), runs the loader again and keeps its own copy of
//! every mapped byte, so an import's peak memory grew with the worker count.
//! The parent writes the mapped image once as a content-addressed artifact
//! (`ProgramImage::write_snapshot`) and names it in the worker's environment;
//! every worker maps that one file, which the page cache shares.
use crate::{Result, artifact::Artifact, native::NativeImport, session::ProgramImage};
use romwright_model::ProgramInput;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The worker environment variable naming the snapshot: `<input identity>:<digest>`.
pub(crate) const ENV: &str = "ROMWRIGHT_IMAGE_SNAPSHOT";

/// Snapshots written (or found) by this process: the parse and the write
/// happen once per input and project, however many workers ask.
static WRITTEN: Mutex<Option<HashMap<(PathBuf, String), String>>> = Mutex::new(None);

/// What the loader's answer depends on: the captured content and the recipe,
/// not the path the input came from.
fn identity(input: &ProgramInput) -> String {
    let recipe = serde_json::to_string(&(
        &input.binary_digest,
        &input.image_selector,
        &input.map_digest,
        &input.raw,
        &input.keys_digest,
    ))
    .expect("strings and numbers serialize");
    crate::sha256::hex(crate::sha256::digest(recipe.as_bytes()))
}

/// The environment value for a snapshot this process already wrote for `id`
/// in `project`, when its file is still there.
fn recorded(project: &Path, id: &str) -> Option<String> {
    let written = WRITTEN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let digest = written.as_ref()?.get(&(project.to_path_buf(), id.to_string()))?;
    project.join("artifacts").join(digest).is_file().then(|| format!("{id}:{digest}"))
}

/// Writes the snapshot of `image` over the captured input's bytes and records
/// it. The lock is not held while writing: programs import concurrently.
fn publish(project: &Path, id: String, artifact: &Artifact, image: &NativeImport) -> Result<String> {
    let writing = std::time::Instant::now();
    let digest = crate::artifact::publish_with(project, |out| {
        ProgramImage::write_snapshot(&artifact.bytes, image, out)
    })?;
    crate::native::tally::add("snapshot-write", writing);
    WRITTEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert((project.to_path_buf(), id.clone()), digest.clone());
    Ok(format!("{id}:{digest}"))
}

/// The environment value that gives a worker of `project` the mapped image of
/// `input`, writing the snapshot first when this process has not yet.
pub(crate) fn binding(project: &Path, input: &ProgramInput) -> Result<String> {
    let id = identity(input);
    if let Some(value) = recorded(project, &id) {
        return Ok(value);
    }
    let parsing = std::time::Instant::now();
    let (artifact, image) = super::parse(project, input)?;
    crate::native::tally::add("snapshot-parse", parsing);
    publish(project, id, &artifact, &image)
}

/// `binding` for an image the caller already holds: the importing process
/// loaded it from `input`, and analysis never changes its mappings or
/// relocations, so the loader does not run again. A container of hundreds of
/// programs used to parse the whole container once per program and round to
/// hand each switch worker its own image.
pub(crate) fn binding_of(project: &Path, input: &ProgramInput, image: &NativeImport) -> Result<String> {
    let id = identity(input);
    if let Some(value) = recorded(project, &id) {
        return Ok(value);
    }
    let artifact = Artifact::open(project, &input.binary_digest)?;
    publish(project, id, &artifact, image)
}

/// The snapshot digest this process was given for exactly `input`, if any. A
/// snapshot made for another input is never used.
pub(crate) fn inherited(input: &ProgramInput) -> Option<String> {
    let value = std::env::var(ENV).ok()?;
    let (id, digest) = value.split_once(':')?;
    (id == identity(input)).then(|| digest.to_string())
}
