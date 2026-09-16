//! Matching artifacts are resolved relative to the generated project, not the
//! invoking process. Identical contents are a match; identical files are not a
//! comparison.
mod diagnosis;
mod project;
mod trials;
mod scratch;
pub use scratch::ScratchExportOptions;
mod workspace;
use std::path::{Component, Path, PathBuf};

use crate::{Core, CoreError, Result};

fn invalid(message: impl Into<String>) -> CoreError {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()).into()
}

fn resolve_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut missing = Vec::new();
    let mut ancestor = absolute.as_path();
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| invalid("object path has no existing ancestor"))?;
        missing.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid("object path has no parent"))?;
    }
    let mut resolved = ancestor.canonicalize()?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    let mut normalized = PathBuf::new();
    for component in resolved.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

pub(crate) fn distinct_objects(target: &Path, candidate: &Path) -> Result<(PathBuf, PathBuf)> {
    let target = resolve_path(target)?;
    let candidate = resolve_path(candidate)?;
    if !target.is_file() {
        return Err(invalid(format!(
            "target object {} does not exist",
            target.display()
        )));
    }
    let mut same = target == candidate;
    #[cfg(unix)]
    if let Ok(candidate_meta) = candidate.metadata() {
        use std::os::unix::fs::MetadataExt;
        let target_meta = target.metadata()?;
        same |=
            target_meta.dev() == candidate_meta.dev() && target_meta.ino() == candidate_meta.ino();
    }
    if same {
        return Err(invalid(format!(
            "target and candidate refer to the same object: {}",
            target.display()
        )));
    }
    Ok((target, candidate))
}

impl Core {
    pub fn export_objdiff(
        &self,
        program: &str,
        outdir: &Path,
        splits: &[crate::native::linkmap::SplitExtent],
        target_root: &Path,
        candidate_root: &Path,
    ) -> Result<serde_json::Value> {
        let outdir = resolve_path(outdir)?;
        let functions = self.functions(program)?;
        let mut units =
            std::collections::BTreeMap::<&str, Vec<&crate::native::linkmap::SplitExtent>>::new();
        for extent in splits {
            if !extent.tu.is_empty() {
                units.entry(&extent.tu).or_default().push(extent);
            }
        }
        let mut rows = Vec::with_capacity(units.len());
        for (tu, extents) in units {
            let stem = tu.trim_end_matches(".c").trim_end_matches(".cpp");
            let (target, candidate) = distinct_objects(
                &outdir.join(target_root).join(format!("{stem}.o")),
                &outdir.join(candidate_root).join(format!("{stem}.o")),
            )?;
            let names: Vec<_> = functions.iter().filter(|function| {
                extents.iter().any(|extent| function.entry.offset >= extent.start && function.entry.offset < extent.end)
            }).map(|function| serde_json::json!({
                "name": function.name, "vram": format!("{:#x}", function.entry.offset), "size": function.size,
            })).collect();
            rows.push(serde_json::json!({
                "name": format!("{program}/{stem}"), "target_path": target, "base_path": candidate,
                "metadata": {"auto_generated": false, "source_path": tu, "functions": names},
            }));
        }
        let count = rows.len();
        let config = serde_json::json!({
            "min_version": "2.0.0-beta.5", "custom_make": "ninja", "build_target": false, "units": rows,
        });
        std::fs::create_dir_all(&outdir)?;
        std::fs::write(
            outdir.join("objdiff.json"),
            serde_json::to_vec_pretty(&config).map_err(|e| invalid(e.to_string()))?,
        )?;
        Ok(serde_json::json!({"directory": outdir, "units": count}))
    }
}

/// Prepared outside the service's Core mutex. Queueing cannot change the
/// source, context, target object, recipe, or selected tool identities.
#[derive(Clone, Debug)]
pub struct PreparedMatch {
    target_digest: String,
    source_digest: String,
    context_digest: String,
    compiler_digest: String,
    objdiff_digest: String,
    compiler: PathBuf,
    objdiff: PathBuf,
    recipe: romwright_model::BuildRecipe,
    source_name: String,
    compile_arguments: Vec<String>,
    version_arguments: Vec<String>,
    files: std::collections::BTreeMap<String, String>,
    tools: std::collections::BTreeMap<String, romwright_model::matching::ToolRequirement>,
    symbol: Option<String>,
    versions: std::sync::Arc<std::sync::OnceLock<(String, String)>>,
}

fn executable(path: &Path, search: &str) -> Result<PathBuf> {
    let found = if path.is_absolute() || path.components().count() > 1 {
        path.to_path_buf()
    } else {
        std::env::split_paths(search)
            .map(|directory| directory.join(path))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| invalid(format!("executable {} not found", path.display())))?
    };
    if !found.is_file() {
        return Err(invalid(format!("executable {} not found", found.display())));
    }
    // Preserve symlink names: compiler wrappers such as ccache interpret argv[0].
    Ok(if found.is_absolute() {
        found
    } else {
        std::env::current_dir()?.join(found)
    })
}

fn expand_argument(
    argument: &str,
    source: &str,
    output: &str,
    root: &Path,
    tools: &std::collections::BTreeMap<String, romwright_model::matching::ToolRequirement>,
) -> Result<String> {
    let root = root
        .to_str()
        .ok_or_else(|| invalid("matching path is not UTF-8"))?;
    let mut result = String::with_capacity(argument.len());
    let mut remaining = argument;
    while let Some(start) = remaining.find('{') {
        result.push_str(&remaining[..start]);
        remaining = &remaining[start..];
        let Some(end) = remaining.find('}') else {
            if remaining.starts_with("{tool:") {
                return Err(invalid("unterminated tool operand"));
            }
            break;
        };
        let operand = &remaining[1..end];
        let replacement = match operand {
            "source" => source,
            "output" => output,
            "root" => root,
            name if name.starts_with("tool:") => {
                &tools
                    .get(&name[5..])
                    .ok_or_else(|| invalid(format!("undeclared tool {}", &name[5..])))?
                    .path
            }
            _ => &remaining[..=end],
        };
        result.push_str(replacement);
        remaining = &remaining[end + 1..];
    }
    result.push_str(remaining);
    Ok(result)
}

fn compare_objects(
    request: &crate::exec::ExecutionRequest,
    objdiff: &Path,
    root: &Path,
    target: &crate::artifact::Artifact,
    candidate: &crate::artifact::Artifact,
    candidate_path: &Path,
    symbol: Option<&str>,
) -> Result<(Option<serde_json::Value>, String)> {
    let (target_path, candidate_path) = distinct_objects(&target.path, candidate_path)?;
    let mut command = std::process::Command::new(objdiff);
    command
        .current_dir(root)
        .args(["diff", "-1"])
        .arg(&target_path)
        .arg("-2")
        .arg(&candidate_path)
        .args(["-o", "-", "--format", "json"]);
    if let Some(symbol) = symbol {
        command.arg("--").arg(symbol);
    }
    let limit = if symbol.is_some() {
        8 * 1024 * 1024
    } else {
        64 * 1024 * 1024
    };
    let output = crate::exec::run_command(&mut command, request, None, limit)?;
    let mut diagnostics = String::from_utf8_lossy(&output.stderr).into_owned();
    let raw = if output.status.success() {
        match serde_json::from_slice::<serde_json::Value>(&output.stdout) {
            Ok(value)
                if value.get("left").is_some_and(serde_json::Value::is_object)
                    && value.get("right").is_some_and(serde_json::Value::is_object) =>
            {
                Some(value)
            }
            Ok(_) => {
                diagnostics.push_str("objdiff returned an invalid comparison envelope");
                None
            }
            Err(error) => {
                diagnostics.push_str(&format!("invalid objdiff JSON: {error}"));
                None
            }
        }
    } else {
        diagnostics.push_str(&format!(
            "objdiff exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        ));
        None
    };
    if crate::import_cache::digest(&target_path).as_deref() != Some(&target.digest)
        || crate::import_cache::digest(&candidate_path).as_deref() != Some(&candidate.digest)
    {
        return Err(invalid("an object changed during comparison"));
    }
    Ok((raw, diagnostics))
}

struct MatchWork(PathBuf);
impl MatchWork {
    fn create(project: &Path) -> Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        loop {
            let path = project.join(format!(
                ".matching-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path.canonicalize()?)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}
impl Drop for MatchWork {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Core {
    pub fn prepare_matching(
        request: &crate::exec::ExecutionRequest,
        target: &Path,
        source: &Path,
        context: Option<&Path>,
        mut recipe: romwright_model::BuildRecipe,
    ) -> Result<PreparedMatch> {
        use crate::artifact::Artifact;
        request.cancel.checkpoint(request.deadline)?;
        let project = &request.project_dir;
        let search = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        recipe
            .environment
            .entry("PATH".into())
            .or_insert_with(|| search.clone());
        recipe
            .environment
            .entry("LC_ALL".into())
            .or_insert_with(|| "C".into());
        recipe
            .environment
            .entry("SOURCE_DATE_EPOCH".into())
            .or_insert_with(|| "0".into());
        let compiler = executable(Path::new(&recipe.compiler), &recipe.environment["PATH"])?;
        let objdiff = executable(&request.config.objdiff_path, &search)?;
        recipe.compiler = compiler.to_string_lossy().into_owned();
        let target_digest = Artifact::capture(project, target)?.digest;
        let source_digest = Artifact::capture(project, source)?.digest;
        let context_digest = match context {
            Some(path) => Artifact::capture(project, path)?.digest,
            None => Artifact::from_bytes(project, std::sync::Arc::from([]))?.digest,
        };
        let compiler_digest = Artifact::capture(project, &compiler)?.digest;
        let objdiff_digest = Artifact::capture(project, &objdiff)?.digest;
        request.cancel.checkpoint(request.deadline)?;
        Ok(PreparedMatch {
            source_name: "candidate.c".into(),
            compile_arguments: ["-x", "c", "-c", "{source}", "-o", "{output}"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            version_arguments: vec!["--version".into()],
            files: std::collections::BTreeMap::new(),
            tools: std::collections::BTreeMap::new(),
            symbol: None,
            versions: Default::default(),
            target_digest,
            source_digest,
            context_digest,
            compiler_digest,
            objdiff_digest,
            compiler,
            objdiff,
            recipe,
        })
    }

    pub fn matching_runs(
        &self,
        program: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<romwright_model::MatchingRun>> {
        Ok(self
            .db
            .matching_runs(self.db.program_id(program)?, after, limit)?)
    }

    fn execute_matching(
        &self,
        request: &crate::exec::ExecutionRequest,
        prepared: &PreparedMatch,
    ) -> Result<romwright_model::MatchingRunRecord> {
        use crate::{artifact::Artifact, exec::run_command};
        use romwright_model::{MatchingRunRecord, MatchingStatus};
        use std::process::Command;
        // Source, target and tool identities are frozen artifacts, not live
        // analysis facts. Their evidence retains the captured fact revision.
        request.cancel.checkpoint(request.deadline)?;
        let project = &request.project_dir;
        let target = Artifact::open(project, &prepared.target_digest)?;
        let source = Artifact::open(project, &prepared.source_digest)?;
        let context = Artifact::open(project, &prepared.context_digest)?;
        let verify_tools = || -> Result<()> {
            for (path, digest) in [
                (&prepared.compiler, &prepared.compiler_digest),
                (&prepared.objdiff, &prepared.objdiff_digest),
            ] {
                if crate::import_cache::digest(path).as_ref() != Some(digest) {
                    return Err(invalid(format!(
                        "matching tool changed: {}",
                        path.display()
                    )));
                }
            }
            for (name, tool) in &prepared.tools {
                if crate::import_cache::digest(Path::new(&tool.path)).as_ref() != Some(&tool.digest)
                {
                    return Err(invalid(format!(
                        "required tool or SDK input changed: {name}"
                    )));
                }
            }
            Ok(())
        };
        verify_tools()?;
        let work = MatchWork::create(project)?;
        for (name, digest) in &prepared.files {
            if name == &prepared.source_name {
                continue;
            }
            let file = Artifact::open(project, digest)?;
            let path = work.0.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &file.bytes)?;
        }
        let translation_unit = work.0.join(&prepared.source_name);
        if let Some(parent) = translation_unit.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if context.bytes.is_empty() {
            std::fs::write(&translation_unit, &source.bytes)?;
        } else {
            let mut combined = Vec::with_capacity(context.bytes.len() + source.bytes.len() + 1);
            combined.extend_from_slice(&context.bytes);
            combined.push(b'\n');
            combined.extend_from_slice(&source.bytes);
            std::fs::write(&translation_unit, combined)?;
        }
        let output_name = ".romwright-output/candidate.o";
        std::fs::create_dir(work.0.join(".romwright-output"))?;
        let candidate_path = work.0.join(output_name);
        let expand = |argument: &String| {
            expand_argument(
                argument,
                &prepared.source_name,
                output_name,
                &work.0,
                &prepared.tools,
            )
        };
        let version_arguments = prepared
            .version_arguments
            .iter()
            .map(&expand)
            .collect::<Result<Vec<_>>>()?;
        let compile_arguments = prepared
            .recipe
            .arguments
            .iter()
            .chain(&prepared.compile_arguments)
            .map(expand)
            .collect::<Result<Vec<_>>>()?;
        let version = |path: &Path, arguments: &[String], compiler: bool| -> Result<String> {
            let mut command = Command::new(path);
            command.current_dir(&work.0).args(arguments);
            if compiler {
                command.env_clear().envs(&prepared.recipe.environment);
            }
            let output = run_command(&mut command, request, None, 8 * 1024 * 1024)?;
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if !output.status.success() || text.trim().is_empty() {
                return Err(invalid(format!(
                    "version query for {} failed ({}): {text}",
                    path.display(),
                    output.status
                )));
            }
            Ok(text)
        };
        let cacheable = prepared.version_arguments.iter().all(|argument| {
            !["{source}", "{output}", "{root}"]
                .iter()
                .any(|operand| argument.contains(operand))
        });
        let (compiler_version, objdiff_version) =
            if let Some(versions) = cacheable.then(|| prepared.versions.get()).flatten() {
                versions.clone()
            } else {
                let versions = (
                    version(&prepared.compiler, &version_arguments, true)?,
                    version(&prepared.objdiff, &["--version".into()], false)?,
                );
                if cacheable {
                    let _ = prepared.versions.set(versions.clone());
                }
                versions
            };
        let compiled = run_command(
            Command::new(&prepared.compiler)
                .current_dir(&work.0)
                .env_clear()
                .envs(&prepared.recipe.environment)
                .args(&compile_arguments),
            request,
            None,
            8 * 1024 * 1024,
        )?;
        let mut files = prepared.files.clone();
        files.insert(prepared.source_name.clone(), prepared.source_digest.clone());
        let mut record = MatchingRunRecord {
            revision: request.revision,
            target_digest: prepared.target_digest.clone(),
            candidate_digest: None,
            source_digest: prepared.source_digest.clone(),
            context_digest: prepared.context_digest.clone(),
            compiler_digest: prepared.compiler_digest.clone(),
            compiler_version,
            recipe: prepared.recipe.clone(),
            compile_arguments,
            version_arguments,
            source_path: prepared.source_name.clone(),
            files,
            tools: prepared.tools.clone(),
            working_directory: work.0.to_string_lossy().into_owned(),
            objdiff_digest: prepared.objdiff_digest.clone(),
            objdiff_version,
            raw_result: serde_json::Value::Null,
            status: MatchingStatus::CompileFailed,
            diagnostics: format!(
                "{}{}",
                String::from_utf8_lossy(&compiled.stdout),
                String::from_utf8_lossy(&compiled.stderr)
            ),
        };
        if compiled.status.success() {
            // Equal bytes are valid; aliasing the target's physical file is not.
            let (_, candidate_path) = distinct_objects(&target.path, &candidate_path)?;
            let candidate = Artifact::capture(project, &candidate_path)?;
            record.candidate_digest = Some(candidate.digest.clone());
            let mut permissions = std::fs::metadata(&candidate_path)?.permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&candidate_path, permissions)?;
            let (raw, diagnostics) = compare_objects(
                request,
                &prepared.objdiff,
                &work.0,
                &target,
                &candidate,
                &candidate_path,
                prepared.symbol.as_deref(),
            )?;
            record.diagnostics.push_str(&diagnostics);
            record.status = if raw.is_some() {
                MatchingStatus::Compared
            } else {
                MatchingStatus::DiffFailed
            };
            record.raw_result = raw.unwrap_or(serde_json::Value::Null);
        }
        verify_tools()?;
        Ok(record)
    }

    pub fn run_matching(
        &self,
        request: &crate::exec::ExecutionRequest,
        prepared: &PreparedMatch,
    ) -> Result<romwright_model::MatchingRun> {
        let record = self.execute_matching(request, prepared)?;
        request.cancel.publish(request.deadline, || {
            Ok(self
                .db
                .record_matching_run(self.db.program_id(&request.program)?, record)?)
        })
    }

    pub fn run_matching_operation(
        &self,
        request: &crate::exec::ExecutionRequest,
        operation: romwright_model::matching::MatchingOperation,
    ) -> Result<serde_json::Value> {
        use romwright_model::matching::MatchingOperation;
        let result = match operation {
            MatchingOperation::Trial { candidate, profile } => {
                serde_json::to_value(self.run_matching_candidate(request, candidate, &profile)?)
            }
            MatchingOperation::Search { request: search } => {
                serde_json::to_value(self.search_matching_candidates(request, search)?)
            }
            MatchingOperation::Calibrate {
                candidates,
                profiles,
                max_compilations,
            } => serde_json::to_value(self.calibrate_matching_profiles(
                request,
                &candidates,
                &profiles,
                max_compilations,
            )?),
            MatchingOperation::Context { request: context } => {
                serde_json::to_value(self.trial_matching_context(request, context)?)
            }
            MatchingOperation::PreparePatch { candidate, profile } => {
                serde_json::to_value(self.matching_project_patch(request, candidate, &profile)?)
            }
            MatchingOperation::VerifyPatch { patch, apply } => {
                serde_json::to_value(self.verify_matching_patch(request, patch, apply)?)
            }
        };
        result.map_err(|error| invalid(error.to_string()))
    }

    pub fn matching_diagnosis(
        &self,
        program: &str,
        run: u64,
        symbol: &str,
    ) -> Result<romwright_model::matching::MatchDiagnosis> {
        let run = self.db.matching_run(self.db.program_id(program)?, run)?;
        let target = crate::artifact::Artifact::open(self.db_path(), &run.record.target_digest)?;
        let candidate = run
            .record
            .candidate_digest
            .as_ref()
            .map(|digest| crate::artifact::Artifact::open(self.db_path(), digest))
            .transpose()?;
        Ok(diagnosis::diagnose(
            symbol,
            &target.bytes,
            candidate.as_ref().map(|artifact| artifact.bytes.as_ref()),
            (run.record.status == romwright_model::MatchingStatus::Compared)
                .then_some(&run.record.raw_result),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_rejects_aliases_but_allows_equal_contents() {
        let dir = std::env::temp_dir().join(format!("romwright-objects-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("target.o"), b"same object bytes").unwrap();
        std::fs::write(dir.join("candidate.o"), b"same object bytes").unwrap();
        assert!(distinct_objects(&dir.join("target.o"), &dir.join("./target.o")).is_err());
        assert!(distinct_objects(&dir.join("target.o"), &dir.join("candidate.o")).is_ok());
        #[cfg(unix)]
        {
            std::fs::hard_link(dir.join("target.o"), dir.join("alias.o")).unwrap();
            assert!(distinct_objects(&dir.join("target.o"), &dir.join("alias.o")).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
