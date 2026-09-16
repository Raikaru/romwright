//! Reviewable source patches checked with the project's actual build command.
mod apply;
mod snapshot;

use super::{compare_objects, diagnosis, invalid};
use crate::{
    Core, Result,
    artifact::Artifact,
    exec::{ExecutionRequest, run_command},
};
use object::{Object, ObjectSection, ObjectSymbol};
use romwright_model::matching::*;
use snapshot::{Manifest, Snapshot};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub(super) fn relative(path: &str) -> Result<()> {
    super::workspace::relative(path)?;
    if Path::new(path).components().any(|part| {
        let name = part.as_os_str().to_string_lossy();
        name == ".git" || name == ".jj" || name.starts_with(".matching-")
    }) {
        return Err(invalid(
            "project mappings cannot modify version-control or matching bookkeeping",
        ));
    }
    Ok(())
}

pub(super) fn source_path(root: &Path, path: &str) -> Result<PathBuf> {
    relative(path)?;
    let path = root.join(path);
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_symlink()) {
        return Err(invalid(
            "map a source file directly, not through a file symlink",
        ));
    }
    let resolved = super::resolve_path(&path)?;
    let local = resolved
        .strip_prefix(root)
        .map_err(|_| invalid("project mapping escapes its root"))?;
    relative(snapshot::string(local)?)?;
    Ok(resolved)
}

fn check_build_tools(
    snapshot: &Snapshot,
    tools: &BTreeMap<PathBuf, String>,
    request: &ExecutionRequest,
) -> Result<()> {
    for (path, digest) in tools {
        if snapshot::hash_file(path, request)? != *digest {
            return Err(invalid(format!(
                "project build tool changed during verification: {}",
                path.display()
            )));
        }
        if let Ok(relative) = path.strip_prefix(&snapshot.original_root) {
            let private = snapshot.root.join(relative);
            if snapshot::hash_file(&private, request)? != *digest {
                return Err(invalid(format!(
                    "project build rewrote a pinned tool in its private snapshot: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn object_artifact(core: &Core, path: &Path) -> Result<Artifact> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err(invalid(
            "project output must be a regular object of at most 64 MiB",
        ));
    }
    let artifact = Artifact::capture(core.db_path(), path)?;
    object::File::parse(artifact.bytes.as_ref())
        .map_err(|error| invalid(format!("project output is not a supported object: {error}")))?;
    Ok(artifact)
}

#[derive(PartialEq, Eq)]
struct SymbolIdentity {
    scope: object::SymbolScope,
    weak: bool,
    kind: object::SymbolKind,
    section: Option<String>,
    data_size: Option<u64>,
    absolute_address: Option<u64>,
}

fn object_symbols(bytes: &[u8]) -> Result<BTreeMap<String, SymbolIdentity>> {
    let object = object::File::parse(bytes).map_err(|error| invalid(error.to_string()))?;
    let mut result = BTreeMap::new();
    for symbol in object.symbols() {
        if !symbol.is_definition()
            || matches!(
                symbol.kind(),
                object::SymbolKind::Section | object::SymbolKind::File
            )
            || (symbol.size() == 0
                && symbol.kind() != object::SymbolKind::Text
                && !symbol.is_global())
        {
            continue;
        }
        let section = symbol
            .section_index()
            .map(|index| object.section_by_index(index))
            .transpose()
            .map_err(|error| invalid(error.to_string()))?;
        let code = section
            .as_ref()
            .is_some_and(|section| section.kind() == object::SectionKind::Text);
        let name = symbol.name().map_err(|error| invalid(error.to_string()))?;
        let identity = SymbolIdentity {
            scope: symbol.scope(),
            weak: symbol.is_weak(),
            kind: symbol.kind(),
            section: section
                .map(|section| section.name().map(str::to_owned))
                .transpose()
                .map_err(|error| invalid(error.to_string()))?,
            data_size: (!code).then_some(symbol.size()),
            absolute_address: (symbol.section() == object::SymbolSection::Absolute)
                .then_some(symbol.address()),
        };
        if name.is_empty() || result.insert(name.to_owned(), identity).is_some() {
            return Err(invalid("project symbol identity is empty or ambiguous"));
        }
    }
    Ok(result)
}

fn build_command(
    snapshot: &Snapshot,
    binding: &ProjectBinding,
) -> Result<(Command, serde_json::Value)> {
    let search = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
    let sandbox = super::executable(Path::new("bwrap"), &search).map_err(|error| {
        invalid(format!(
            "isolated project verification requires bubblewrap: {error}"
        ))
    })?;
    let mut environment = binding.build.environment.clone();
    environment.entry("PATH".into()).or_insert(search);
    environment
        .entry("LC_ALL".into())
        .or_insert_with(|| "C".into());
    environment
        .entry("SOURCE_DATE_EPOCH".into())
        .or_insert_with(|| "0".into());
    for name in ["TMPDIR", "TEMP", "TMP"] {
        environment
            .entry(name.into())
            .or_insert_with(|| "/tmp".into());
    }
    if let Ok(home) = std::env::var("HOME") {
        environment.entry("HOME".into()).or_insert(home);
    }
    environment
        .entry("XDG_CACHE_HOME".into())
        .or_insert_with(|| "/tmp/.cache".into());
    let executable = Path::new(&binding.build.executable);
    let executable = if executable.is_absolute() {
        executable.to_path_buf()
    } else if executable.components().count() > 1 {
        snapshot.original_build_root.join(executable)
    } else {
        std::env::split_paths(&environment["PATH"])
            .map(|directory| {
                let directory = if directory.is_absolute() {
                    directory
                } else {
                    snapshot.original_build_root.join(directory)
                };
                directory.join(executable)
            })
            .find(|path| path.is_file())
            .ok_or_else(|| invalid("project build executable was not found"))?
    };
    let temporary = snapshot.work.0.join("tmp");
    fs::create_dir_all(&temporary)?;
    let mut command = Command::new(&sandbox);
    command
        .env_clear()
        .envs(&environment)
        .current_dir(&snapshot.original_build_root)
        .args([
            "--die-with-parent",
            "--unshare-pid",
            "--unshare-ipc",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
        ])
        .arg("--bind")
        .arg(&temporary)
        .arg("/tmp")
        .arg("--bind")
        .arg(&temporary)
        .arg("/var/tmp")
        // Absolute include, source and output paths still name the private
        // project. A cwd-only copy would silently build the original source.
        .arg("--bind")
        .arg(&snapshot.root)
        .arg(&snapshot.original_root)
        .arg("--chdir")
        .arg(&snapshot.original_build_root)
        .arg("--")
        .arg(&executable)
        .args(&binding.build.arguments);
    let metadata = serde_json::json!({
        "executable": executable, "arguments": binding.build.arguments,
        "environment": environment, "working_directory": snapshot.original_build_root,
        "sandbox": sandbox,
    });
    Ok((command, metadata))
}

fn output_paths(binding: &ProjectBinding) -> BTreeSet<&String> {
    binding
        .objects
        .values()
        .chain(binding.linked_output.iter())
        .collect()
}

fn remove_outputs(snapshot: &Snapshot, binding: &ProjectBinding) -> Result<()> {
    for name in output_paths(binding) {
        let path = source_path(&snapshot.build_root, name)?;
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn outputs(
    core: &Core,
    snapshot: &Snapshot,
    binding: &ProjectBinding,
    report: &mut PatchVerification,
) -> Result<BTreeMap<String, Artifact>> {
    let mut objects = BTreeMap::new();
    for name in binding.objects.values().collect::<BTreeSet<_>>() {
        let path = source_path(&snapshot.build_root, name)?;
        match object_artifact(core, &path) {
            Ok(object) => {
                objects.insert(name.clone(), object);
            }
            Err(error) => {
                report.missing_outputs.push(name.clone());
                report
                    .diagnostics
                    .push_str(&format!("\nRequired output {name}: {error}\n"));
            }
        }
    }
    if let Some(linked) = &binding.linked_output {
        if !source_path(&snapshot.build_root, linked)?.is_file() {
            report.missing_outputs.push(linked.clone());
        }
    }
    Ok(objects)
}

fn object_path(path: &Path) -> bool {
    use std::io::Read;
    if path
        .extension()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("o") || name.eq_ignore_ascii_case("obj"))
    {
        return true;
    }
    let mut header = [0u8; 64];
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let Ok(count) = file.read(&mut header) else {
        return false;
    };
    if count >= 18 && &header[..4] == b"\x7fELF" {
        return if header[5] == 1 {
            u16::from_le_bytes([header[16], header[17]]) == 1
        } else {
            u16::from_be_bytes([header[16], header[17]]) == 1
        };
    }
    object::FileKind::parse(&header[..count]).is_ok_and(|kind| {
        matches!(
            kind,
            object::FileKind::Coff | object::FileKind::CoffBig | object::FileKind::CoffImport
        )
    })
}

fn changed_paths(before: &Manifest, after: &Manifest) -> BTreeSet<String> {
    before
        .keys()
        .chain(after.keys())
        .filter(|path| {
            before.get(*path) != after.get(*path)
                && [before.get(*path), after.get(*path)]
                    .into_iter()
                    .flatten()
                    .any(|entry| entry.kind != "directory")
        })
        .cloned()
        .collect()
}

impl Core {
    pub fn matching_project_checks(
        &self,
        program: &str,
        workspace: u64,
        after: u64,
        limit: usize,
    ) -> Result<Vec<PatchVerification>> {
        Ok(self.db.matching_project_checks(
            self.db.program_id(program)?,
            workspace,
            after,
            limit,
        )?)
    }

    pub fn matching_project_patch(
        &self,
        request: &ExecutionRequest,
        candidate: u64,
        profile: &str,
    ) -> Result<ProjectPatch> {
        self.check_execution(request)?;
        let candidate = self.matching_candidate(&request.program, candidate)?;
        let workspace = self.matching_workspace(&request.program, candidate.workspace)?;
        let profile_record = workspace
            .spec
            .profiles
            .iter()
            .find(|entry| entry.name == profile)
            .ok_or_else(|| invalid("unknown compiler profile"))?;
        let binding = workspace
            .spec
            .project
            .as_ref()
            .ok_or_else(|| invalid("workspace has no real-project binding"))?;
        let root = Path::new(
            binding
                .root
                .as_deref()
                .ok_or_else(|| invalid("choose a local project root before preparing a patch"))?,
        )
        .canonicalize()?;
        if binding.sources.len() > 64 {
            return Err(invalid("a reviewed patch may map at most 64 source files"));
        }
        for (name, file) in &candidate.spec.files {
            if workspace
                .spec
                .files
                .get(name)
                .is_none_or(|original| original.digest != file.digest)
                && !binding.sources.contains_key(name)
            {
                return Err(invalid(format!(
                    "changed workspace input has no project mapping: {name}"
                )));
            }
        }
        let binding_digest = crate::sha256::hex(crate::sha256::digest(
            &serde_json::to_vec(&(
                binding,
                &workspace.spec.target,
                &workspace.spec.symbol,
                &workspace.spec.objdiff,
                profile_record,
            ))
            .map_err(|error| invalid(error.to_string()))?,
        ));
        let mut patch = ProjectPatch {
            workspace: workspace.id,
            candidate: candidate.id,
            profile: profile.into(),
            binding_digest,
            files: Vec::new(),
            unified_diff: String::new(),
        };
        let mut bytes = 0usize;
        for (source, destination) in &binding.sources {
            request.cancel.checkpoint(request.deadline)?;
            let file =
                candidate.spec.files.get(source).ok_or_else(|| {
                    invalid(format!("mapped workspace source is absent: {source}"))
                })?;
            let path = source_path(&root, destination)?;
            let before = match fs::metadata(&path) {
                Ok(metadata) => {
                    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
                        return Err(invalid(
                            "mapped source must be a regular file of at most 64 MiB",
                        ));
                    }
                    Some(Artifact::capture(self.db_path(), &path)?)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            if before
                .as_ref()
                .is_some_and(|before| before.digest == file.digest)
            {
                continue;
            }
            let after = Artifact::open(self.db_path(), &file.digest)?;
            let before_bytes = before
                .as_ref()
                .map_or(&[][..], |artifact| artifact.bytes.as_ref());
            if before_bytes.len() > 4 * 1024 * 1024 || after.bytes.len() > 4 * 1024 * 1024 {
                return Err(invalid("an edited source exceeds 4 MiB"));
            }
            bytes += before_bytes.len() + after.bytes.len();
            if bytes > 16 * 1024 * 1024 {
                return Err(invalid("a reviewed patch exceeds 16 MiB of source"));
            }
            let before_text =
                std::str::from_utf8(before_bytes).map_err(|error| invalid(error.to_string()))?;
            let after_text =
                std::str::from_utf8(&after.bytes).map_err(|error| invalid(error.to_string()))?;
            let old_name = if before.is_some() {
                format!("a/{destination}")
            } else {
                "/dev/null".into()
            };
            patch.unified_diff.push_str(
                &similar::TextDiff::configure()
                    .timeout(Duration::from_millis(500))
                    .diff_lines(before_text, after_text)
                    .unified_diff()
                    .header(&old_name, &format!("b/{destination}"))
                    .to_string(),
            );
            patch.files.push(PatchFile {
                path: destination.clone(),
                before_digest: before.map(|artifact| artifact.digest),
                after_digest: file.digest.clone(),
            });
        }
        Ok(patch)
    }

    pub fn verify_matching_patch(
        &self,
        request: &ExecutionRequest,
        patch: ProjectPatch,
        apply: bool,
    ) -> Result<PatchVerification> {
        let started = Instant::now();
        let expected = self.matching_project_patch(request, patch.candidate, &patch.profile)?;
        if patch != expected {
            return Err(invalid(
                "project patch is stale or does not describe the reviewed candidate",
            ));
        }
        let workspace = self.matching_workspace(&request.program, patch.workspace)?;
        let selected = self.matching_candidate(&request.program, patch.candidate)?;
        let profile = workspace
            .spec
            .profiles
            .iter()
            .find(|profile| profile.name == patch.profile)
            .ok_or_else(|| invalid("selected compiler profile disappeared"))?;
        let binding = workspace
            .spec
            .project
            .as_ref()
            .ok_or_else(|| invalid("project binding disappeared"))?;
        let root = Path::new(
            binding
                .root
                .as_deref()
                .ok_or_else(|| invalid("project is unbound"))?,
        );
        let snapshot = Snapshot::create(self, request, root)?;
        let (mut command, command_metadata) = build_command(&snapshot, binding)?;
        let mut tools = BTreeMap::new();
        for field in ["executable", "sandbox"] {
            let path = Path::new(
                command_metadata[field]
                    .as_str()
                    .ok_or_else(|| invalid("invalid build tool path"))?,
            );
            tools.insert(path.to_path_buf(), snapshot::hash_file(path, request)?);
        }
        for (path, expected) in std::iter::once((
            profile.recipe.compiler.as_str(),
            profile.compiler_digest.as_str(),
        ))
        .chain(
            profile
                .tools
                .values()
                .map(|tool| (tool.path.as_str(), tool.digest.as_str())),
        ) {
            let path = Path::new(path);
            let digest = snapshot::hash_file(path, request)?;
            if digest != expected {
                return Err(invalid(
                    "selected profile tool changed since workspace setup",
                ));
            }
            tools.insert(path.to_path_buf(), digest);
        }
        check_build_tools(&snapshot, &tools, request)?;
        let comparator = Path::new(&workspace.spec.objdiff.path);
        if snapshot::hash_file(comparator, request)? != workspace.spec.objdiff.digest {
            return Err(invalid("objdiff changed since workspace setup"));
        }
        let manifest = Artifact::from_bytes(
            self.db_path(),
            serde_json::to_vec(&serde_json::json!({
                "project_root": snapshot.original_root, "build_root": snapshot.original_build_root,
                "files": snapshot.inputs, "command": command_metadata, "tools": tools,
                "target": workspace.spec.target.digest, "objdiff": workspace.spec.objdiff,
                "workspace_profile": profile,
            }))
            .map_err(|error| invalid(error.to_string()))?
            .into(),
        )?;
        let mut report = PatchVerification {
            id: 0,
            created_at: String::new(),
            imported: false,
            patch,
            input_manifest_digest: manifest.digest,
            candidate_digest: None,
            comparison_digest: None,
            diagnosis: None,
            baseline_diagnosis: None,
            baseline_candidate_digest: None,
            baseline_comparison_digest: None,
            scope_comparison_digests: Vec::new(),
            applied: false,
            applied_files: Vec::new(),
            recovery_path: None,
            build_succeeded: false,
            baseline_build_succeeded: false,
            original_inputs_unchanged: false,
            rebuilt_outputs: Vec::new(),
            missing_outputs: Vec::new(),
            changed_objects: Vec::new(),
            unexpected_objects: Vec::new(),
            changed_symbols: Vec::new(),
            unexpected_symbols: Vec::new(),
            unexpected_files: Vec::new(),
            project_exactness: None,
            linked_output_digest: None,
            diagnostics: String::new(),
            elapsed_ms: 0,
        };
        let target = Artifact::open(self.db_path(), &workspace.spec.target.digest)?;
        let target_path = &binding.objects[&workspace.spec.symbol];
        // Both builds must actually produce the declared outputs. Copied stale
        // objects cannot make a no-op or incorrectly scoped command pass.
        remove_outputs(&snapshot, binding)?;
        let baseline = run_command(&mut command, request, None, 8 * 1024 * 1024)?;
        check_build_tools(&snapshot, &tools, request)?;
        report.baseline_build_succeeded = baseline.status.success();
        report.diagnostics.push_str(&format!(
            "Baseline build ({}):\n{}{}",
            baseline.status,
            String::from_utf8_lossy(&baseline.stdout),
            String::from_utf8_lossy(&baseline.stderr)
        ));
        let baseline_objects = outputs(self, &snapshot, binding, &mut report)?;
        if report.baseline_build_succeeded && report.missing_outputs.is_empty() {
            let original = &baseline_objects[target_path];
            let path = source_path(&snapshot.build_root, target_path)?;
            let (raw, diagnostics) = compare_objects(
                request,
                comparator,
                &snapshot.work.0,
                &target,
                original,
                &path,
                Some(&workspace.spec.symbol),
            )?;
            report.diagnostics.push_str(&diagnostics);
            report.baseline_candidate_digest = Some(original.digest.clone());
            report.baseline_comparison_digest = raw
                .as_ref()
                .map(|raw| {
                    Artifact::from_bytes(
                        self.db_path(),
                        serde_json::to_vec(raw)
                            .map_err(|error| invalid(error.to_string()))?
                            .into(),
                    )
                    .map(|artifact| artifact.digest)
                })
                .transpose()?;
            report.baseline_diagnosis = Some(diagnosis::diagnose(
                &workspace.spec.symbol,
                &target.bytes,
                Some(&original.bytes),
                raw.as_ref(),
            ));
            let before = snapshot.scan(request)?;
            for file in &report.patch.files {
                let path = source_path(&snapshot.build_root, &file.path)?;
                let digest = if path.exists() {
                    Some(snapshot::hash_file(&path, request)?)
                } else {
                    None
                };
                if digest != file.before_digest {
                    return Err(invalid("baseline build rewrote a reviewed source file"));
                }
                fs::create_dir_all(
                    path.parent()
                        .ok_or_else(|| invalid("source has no parent"))?,
                )?;
                if path.exists() {
                    let mut permissions = fs::metadata(&path)?.permissions();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        permissions.set_mode(permissions.mode() | 0o200);
                    }
                    #[cfg(not(unix))]
                    permissions.set_readonly(false);
                    fs::set_permissions(&path, permissions)?;
                }
                fs::write(
                    path,
                    &Artifact::open(self.db_path(), &file.after_digest)?.bytes,
                )?;
            }
            remove_outputs(&snapshot, binding)?;
            let built = run_command(&mut command, request, None, 8 * 1024 * 1024)?;
            report.build_succeeded = built.status.success();
            report.diagnostics.push_str(&format!(
                "\nCandidate build ({}):\n{}{}",
                built.status,
                String::from_utf8_lossy(&built.stdout),
                String::from_utf8_lossy(&built.stderr)
            ));
            let candidate_objects = outputs(self, &snapshot, binding, &mut report)?;
            report.rebuilt_outputs = output_paths(binding)
                .into_iter()
                .filter(|path| !report.missing_outputs.contains(path))
                .cloned()
                .collect();
            if let Some(candidate) = candidate_objects.get(target_path) {
                let path = source_path(&snapshot.build_root, target_path)?;
                let (raw, diagnostics) = compare_objects(
                    request,
                    comparator,
                    &snapshot.work.0,
                    &target,
                    candidate,
                    &path,
                    Some(&workspace.spec.symbol),
                )?;
                report.diagnostics.push_str(&diagnostics);
                report.candidate_digest = Some(candidate.digest.clone());
                report.comparison_digest = raw
                    .as_ref()
                    .map(|raw| {
                        Artifact::from_bytes(
                            self.db_path(),
                            serde_json::to_vec(raw)
                                .map_err(|error| invalid(error.to_string()))?
                                .into(),
                        )
                        .map(|artifact| artifact.digest)
                    })
                    .transpose()?;
                report.diagnosis = Some(diagnosis::diagnose(
                    &workspace.spec.symbol,
                    &target.bytes,
                    Some(&candidate.bytes),
                    raw.as_ref(),
                ));
            }
            for (path, baseline) in &baseline_objects {
                let Some(candidate) = candidate_objects.get(path) else {
                    continue;
                };
                if baseline.digest == candidate.digest {
                    continue;
                }
                let before_symbols = object_symbols(&baseline.bytes)?;
                let after_symbols = object_symbols(&candidate.bytes)?;
                let (raw, diagnostics) = compare_objects(
                    request,
                    comparator,
                    &snapshot.work.0,
                    baseline,
                    candidate,
                    &source_path(&snapshot.build_root, path)?,
                    None,
                )?;
                report.diagnostics.push_str(&diagnostics);
                if let Some(raw) = &raw {
                    report.scope_comparison_digests.push(
                        Artifact::from_bytes(
                            self.db_path(),
                            serde_json::to_vec(raw)
                                .map_err(|error| invalid(error.to_string()))?
                                .into(),
                        )?
                        .digest,
                    );
                }
                let mut names = before_symbols
                    .keys()
                    .chain(after_symbols.keys())
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                // objdiff also exposes anonymous data as synthetic symbols.
                // Omitting these would miss string-pool and unnamed data changes.
                if let Some(raw) = &raw {
                    for side in ["left", "right"] {
                        for symbol in raw
                            .get(side)
                            .and_then(|side| side.get("symbols"))
                            .and_then(serde_json::Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            if symbol.get("data_diff").is_some() {
                                if let Some(name) =
                                    symbol.get("name").and_then(serde_json::Value::as_str)
                                {
                                    names.insert(name);
                                }
                            }
                        }
                    }
                }
                for name in names {
                    let score = raw.as_ref().and_then(|raw| {
                        diagnosis::symbol(raw, "left", name)?
                            .get("match_percent")?
                            .as_f64()
                    });
                    let identity_changed = before_symbols.get(name) != after_symbols.get(name);
                    if !identity_changed && score == Some(100.0) {
                        continue;
                    }
                    let label = format!("{path}::{name}");
                    if identity_changed || score.is_some() {
                        report.changed_symbols.push(label.clone());
                    } else {
                        report.diagnostics.push_str(&format!(
                            "\nSymbol scope could not be established: {label}\n"
                        ));
                    }
                    if binding
                        .objects
                        .get(name)
                        .is_none_or(|expected| expected != path)
                    {
                        report.unexpected_symbols.push(label);
                    }
                }
            }
            let after = snapshot.scan(request)?;
            let prefix = snapshot
                .build_root
                .strip_prefix(&snapshot.root)
                .map_err(|error| invalid(error.to_string()))?;
            for name in changed_paths(&before, &after) {
                let relative = Path::new(&name)
                    .strip_prefix(prefix)
                    .ok()
                    .and_then(|path| path.to_str());
                let display = relative
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("@repository/{name}"));
                let is_object = object_path(&snapshot.root.join(&name))
                    || Path::new(&name)
                        .extension()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            name.eq_ignore_ascii_case("o") || name.eq_ignore_ascii_case("obj")
                        });
                if is_object {
                    report.changed_objects.push(display.clone());
                    if relative.is_none_or(|path| {
                        !binding.objects.values().any(|expected| expected == path)
                    }) {
                        report.unexpected_objects.push(display);
                    }
                } else {
                    let expected_source = relative
                        .and_then(|path| report.patch.files.iter().find(|file| file.path == path));
                    let expected = expected_source.is_some_and(|file| {
                        after.get(&name).is_some_and(|entry| {
                            entry.kind == "file" && entry.digest == file.after_digest
                        })
                    });
                    let generated = expected_source.is_none()
                        && relative.is_some_and(|path| {
                            binding
                                .generated
                                .iter()
                                .any(|allowed| Path::new(path).starts_with(allowed))
                                || binding.linked_output.as_deref() == Some(path)
                        });
                    if !expected && !generated {
                        report.unexpected_files.push(display);
                    }
                }
            }
            if let Some(linked) = &binding.linked_output {
                let path = source_path(&snapshot.build_root, linked)?;
                if path.is_file() {
                    let digest = snapshot::hash_file(&path, request)?;
                    report.project_exactness = Some(digest == request.artifact_digest);
                    report.linked_output_digest = Some(digest);
                }
            }
        }
        if report.baseline_candidate_digest.is_some() {
            for (source, destination) in &binding.sources {
                let path = source_path(&snapshot.build_root, destination)?;
                let expected = selected
                    .spec
                    .files
                    .get(source)
                    .ok_or_else(|| invalid("mapped candidate file disappeared"))?;
                if !path.is_file() || snapshot::hash_file(&path, request)? != expected.digest {
                    if !report.unexpected_files.contains(destination) {
                        report.unexpected_files.push(destination.clone());
                    }
                    report.diagnostics.push_str(&format!(
                        "\nBuild rewrote or removed mapped candidate source: {destination}\n"
                    ));
                }
            }
        }
        check_build_tools(&snapshot, &tools, request)?;
        if snapshot::hash_file(comparator, request)? != workspace.spec.objdiff.digest {
            return Err(invalid("objdiff changed during project verification"));
        }
        report.original_inputs_unchanged = snapshot.original_unchanged(request)?;
        let comparable = report.diagnosis.as_ref().is_some_and(|diagnosis| {
            diagnosis.exact_object_bytes
                || (diagnosis.similarity.is_some()
                    && !diagnosis
                        .mismatches
                        .iter()
                        .any(|row| row.category == MismatchCategory::MissingFunction))
        });
        let regressed = report
            .baseline_diagnosis
            .as_ref()
            .zip(report.diagnosis.as_ref())
            .is_some_and(|(before, after)| {
                (before.exact_object_bytes && !after.exact_object_bytes)
                    || before
                        .similarity
                        .zip(after.similarity)
                        .is_some_and(|(before, after)| after < before)
                    || (before.exact_instructions == Some(true)
                        && after.exact_instructions == Some(false))
                    || (before.exact_relocations == Some(true)
                        && after.exact_relocations == Some(false))
            });
        if regressed {
            report.diagnostics.push_str("\nCandidate regresses the selected function relative to a fresh project baseline; application refused.\n");
        }
        let safe = report.build_succeeded
            && report.baseline_build_succeeded
            && comparable
            && report.comparison_digest.is_some()
            && report.original_inputs_unchanged
            && !regressed
            && report.missing_outputs.is_empty()
            && report.unexpected_objects.is_empty()
            && report.unexpected_symbols.is_empty()
            && report.unexpected_files.is_empty();
        let current = self.matching_workspace(&request.program, report.patch.workspace)?;
        if current.spec.project != workspace.spec.project
            || current.spec.target != workspace.spec.target
            || current.spec.objdiff != workspace.spec.objdiff
            || current
                .spec
                .profiles
                .iter()
                .find(|entry| entry.name == report.patch.profile)
                != Some(profile)
        {
            return Err(invalid(
                "project binding or compiler profile changed during verification",
            ));
        }
        let staged = if apply && safe {
            Some(apply::StagedPatch::prepare(
                self,
                request,
                root,
                &report.patch,
            )?)
        } else {
            None
        };
        if staged.is_some() && !snapshot.original_unchanged(request)? {
            return Err(invalid("project changed before patch publication"));
        }
        report.elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.check_execution(request)?;
        request.cancel.publish(request.deadline, || {
            let program = self.db.program_id(&request.program)?;
            if let Some(staged) = staged {
                report.applied = true;
                report.applied_files = report
                    .patch
                    .files
                    .iter()
                    .map(|file| file.path.clone())
                    .collect();
                staged.commit(|| Ok(self.db.record_matching_project_check(program, report)?))
            } else {
                Ok(self.db.record_matching_project_check(program, report)?)
            }
        })
    }
}
