mod portable;
use super::{PreparedMatch, executable, invalid};
use crate::{Core, Result, artifact::Artifact};
use object::{Object, ObjectSection, ObjectSymbol};
use romwright_model::matching::*;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_SOURCE: usize = 4 * 1024 * 1024;

pub(super) fn relative(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains(['\\', ':'])
        || name.chars().any(char::is_control)
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || name.split('/').next() == Some(".romwright-output")
    {
        return Err(invalid(format!(
            "not a portable workspace-relative path: {name}"
        )));
    }
    Ok(())
}

fn layout(files: &BTreeMap<String, WorkspaceFile>) -> Result<()> {
    if files.is_empty() || files.len() > 4096 {
        return Err(invalid("workspace needs between 1 and 4096 input files"));
    }
    for name in files.keys() {
        relative(name)?;
        let mut parent = Path::new(name).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            if path.to_str().is_some_and(|path| files.contains_key(path)) {
                return Err(invalid("a workspace file is also used as a directory"));
            }
            parent = path.parent();
        }
    }
    Ok(())
}

fn capture(project: &Path, path: &Path) -> Result<Artifact> {
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("matching inputs must be regular files"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(invalid("matching input exceeds 64 MiB"));
    }
    Artifact::from_bytes(project, bytes.into())
}

fn input(project: &Path, input: MatchingInput) -> Result<WorkspaceFile> {
    let (artifact, redistributable) = match input {
        MatchingInput::Path {
            path,
            redistributable,
        } => (capture(project, Path::new(&path))?, redistributable),
        MatchingInput::Text {
            text,
            redistributable,
        } => {
            if text.len() > MAX_SOURCE {
                return Err(invalid("editable source exceeds 4 MiB"));
            }
            (
                Artifact::from_bytes(project, text.into_bytes().into())?,
                redistributable,
            )
        }
    };
    Ok(WorkspaceFile {
        digest: artifact.digest,
        redistributable,
    })
}

fn text(bytes: &[u8]) -> Result<&str> {
    if bytes.len() > MAX_SOURCE {
        return Err(invalid("editable source exceeds 4 MiB"));
    }
    std::str::from_utf8(bytes)
        .map_err(|error| invalid(format!("editable source is not UTF-8: {error}")))
}

fn range(source: &str, start: usize, end: usize) -> Result<()> {
    if start > end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return Err(invalid("source range is not an in-bounds UTF-8 byte range"));
    }
    Ok(())
}

fn intersects(edit: &SourceEdit, pin: &SourcePin) -> bool {
    edit.file == pin.file
        && if edit.start == edit.end {
            edit.start > pin.start && edit.start < pin.end
        } else {
            edit.start < pin.end && edit.end > pin.start
        }
}

fn relocated_pins(pins: &[SourcePin], edits: &[SourceEdit]) -> Vec<SourcePin> {
    pins.iter()
        .map(|pin| {
            let prior = || {
                edits
                    .iter()
                    .filter(|edit| edit.file == pin.file && edit.end <= pin.start)
            };
            let removed: usize = prior().map(|edit| edit.end - edit.start).sum();
            let added: usize = prior().map(|edit| edit.replacement.len()).sum();
            SourcePin {
                file: pin.file.clone(),
                start: pin.start - removed + added,
                end: pin.end - removed + added,
            }
        })
        .collect()
}

fn edits_between(file: &str, before: &str, after: &str) -> Vec<SourceEdit> {
    let diff = similar::TextDiff::configure()
        .timeout(Duration::from_secs(1))
        .diff_chars(before, after);
    let mut edits = Vec::new();
    let mut pending: Option<SourceEdit> = None;
    let mut offset = 0;
    for change in diff.iter_all_changes() {
        if change.tag() == similar::ChangeTag::Equal {
            if let Some(edit) = pending.take() {
                edits.push(edit);
            }
            offset += change.value().len();
            continue;
        }
        let edit = pending.get_or_insert_with(|| SourceEdit {
            file: file.to_owned(),
            start: offset,
            end: offset,
            replacement: String::new(),
            reason: "Source editor change".into(),
        });
        match change.tag() {
            similar::ChangeTag::Delete => {
                offset += change.value().len();
                edit.end = offset;
            }
            similar::ChangeTag::Insert => edit.replacement.push_str(change.value()),
            similar::ChangeTag::Equal => unreachable!(),
        }
    }
    if let Some(edit) = pending {
        edits.push(edit);
    }
    edits
}

impl Core {
    fn normalize_matching_profile(&self, profile: &mut MatchingProfile) -> Result<()> {
        if profile.name.trim().is_empty() || profile.version_arguments.is_empty() {
            return Err(invalid(
                "a compiler profile needs a name and explicit version arguments",
            ));
        }
        if !profile
            .recipe
            .arguments
            .iter()
            .chain(&profile.compile_arguments)
            .any(|argument| argument.contains("{source}"))
            || !profile
                .recipe
                .arguments
                .iter()
                .chain(&profile.compile_arguments)
                .any(|argument| argument.contains("{output}"))
        {
            return Err(invalid(
                "compiler arguments must explicitly name {source} and {output}",
            ));
        }
        let search = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        profile
            .recipe
            .environment
            .entry("PATH".into())
            .or_insert(search);
        profile
            .recipe
            .environment
            .entry("LC_ALL".into())
            .or_insert_with(|| "C".into());
        profile
            .recipe
            .environment
            .entry("SOURCE_DATE_EPOCH".into())
            .or_insert_with(|| "0".into());
        let compiler = executable(
            Path::new(&profile.recipe.compiler),
            &profile.recipe.environment["PATH"],
        )?;
        let captured = capture(self.db_path(), &compiler)?;
        if !profile.compiler_digest.is_empty() && profile.compiler_digest != captured.digest {
            return Err(invalid(format!(
                "compiler identity differs for profile {}",
                profile.name
            )));
        }
        profile.compiler_digest = captured.digest;
        profile.recipe.compiler = compiler
            .to_str()
            .ok_or_else(|| invalid("compiler path is not UTF-8"))?
            .to_owned();
        for (name, requirement) in &mut profile.tools {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            {
                return Err(invalid(
                    "tool names must contain only letters, digits, underscore, dash or dot",
                ));
            }
            let path = Path::new(&requirement.path);
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            let captured = capture(self.db_path(), &path)?;
            if !requirement.digest.is_empty() && requirement.digest != captured.digest {
                return Err(invalid(format!(
                    "required compiler/SDK input differs: {name}"
                )));
            }
            requirement.digest = captured.digest;
            requirement.path = path
                .to_str()
                .ok_or_else(|| invalid("tool path is not UTF-8"))?
                .to_owned();
        }
        for argument in profile
            .recipe
            .arguments
            .iter()
            .chain(&profile.compile_arguments)
            .chain(&profile.version_arguments)
        {
            super::expand_argument(
                argument,
                "source.c",
                "output.o",
                self.db_path(),
                &profile.tools,
            )?;
        }
        Ok(())
    }

    fn validate_matching_files(&self, files: &BTreeMap<String, WorkspaceFile>) -> Result<()> {
        layout(files)?;
        for file in files.values() {
            let artifact = Artifact::open(self.db_path(), &file.digest)?;
            if artifact.bytes.len() as u64 > MAX_FILE {
                return Err(invalid("matching input exceeds 64 MiB"));
            }
        }
        Ok(())
    }

    fn validate_matching_spec(&self, spec: &mut WorkspaceSpec) -> Result<()> {
        if spec.name.trim().is_empty()
            || spec.symbol.is_empty()
            || spec.symbol.chars().any(char::is_control)
        {
            return Err(invalid(
                "workspace needs a name and a concrete object symbol",
            ));
        }
        relative(&spec.source)?;
        self.validate_matching_files(&spec.files)?;
        let source = spec
            .files
            .get(&spec.source)
            .ok_or_else(|| invalid("primary source is not in the workspace"))?;
        text(&Artifact::open(self.db_path(), &source.digest)?.bytes)?;
        let target = Artifact::open(self.db_path(), &spec.target.digest)?;
        let object = object::File::parse(target.bytes.as_ref())
            .map_err(|error| invalid(format!("target is not a supported object: {error}")))?;
        let mut symbols = object.symbols().filter(|symbol| {
            symbol.is_definition()
                && symbol.name().ok() == Some(spec.symbol.as_str())
                && symbol
                    .section_index()
                    .and_then(|index| object.section_by_index(index).ok())
                    .is_some_and(|section| section.kind() == object::SectionKind::Text)
        });
        if symbols.next().is_none() || symbols.next().is_some() {
            return Err(invalid(
                "target symbol is absent or ambiguous in executable object sections",
            ));
        }
        let search = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        let path = if spec.objdiff.path.is_empty() {
            &self.runtime_config().objdiff_path
        } else {
            Path::new(&spec.objdiff.path)
        };
        let path = executable(path, &search)?;
        let comparator = capture(self.db_path(), &path)?;
        if !spec.objdiff.digest.is_empty() && spec.objdiff.digest != comparator.digest {
            return Err(invalid("objdiff identity differs from the workspace"));
        }
        spec.objdiff = ToolRequirement {
            path: path
                .to_str()
                .ok_or_else(|| invalid("objdiff path is not UTF-8"))?
                .to_owned(),
            digest: comparator.digest,
        };
        if spec.profiles.is_empty() || spec.profiles.len() > 64 {
            return Err(invalid(
                "workspace needs between 1 and 64 compiler profiles",
            ));
        }
        let mut names = BTreeSet::new();
        for profile in &mut spec.profiles {
            if !names.insert(profile.name.clone()) {
                return Err(invalid("duplicate compiler profile name"));
            }
            self.normalize_matching_profile(profile)?;
        }
        if let Some(project) = &mut spec.project {
            if let Some(root) = &project.root {
                let root = Path::new(root).canonicalize()?;
                if !root.is_dir() {
                    return Err(invalid("project root is not a directory"));
                }
                project.root = Some(
                    root.to_str()
                        .ok_or_else(|| invalid("project root is not UTF-8"))?
                        .to_owned(),
                );
            }
            for (source, destination) in &mut project.sources {
                relative(source)?;
                super::project::relative(destination)?;
                if let Some(root) = &project.root {
                    *destination = super::project::source_path(Path::new(root), destination)?
                        .strip_prefix(root)
                        .map_err(|error| invalid(error.to_string()))?
                        .to_str()
                        .ok_or_else(|| invalid("project source is not UTF-8"))?
                        .replace('\\', "/");
                }
            }
            for path in project
                .objects
                .values_mut()
                .chain(project.linked_output.iter_mut())
                .chain(project.generated.iter_mut())
            {
                super::project::relative(path)?;
                if let Some(root) = &project.root {
                    *path = super::project::source_path(Path::new(root), path)?
                        .strip_prefix(root)
                        .map_err(|error| invalid(error.to_string()))?
                        .to_str()
                        .ok_or_else(|| invalid("project output is not UTF-8"))?
                        .replace('\\', "/");
                }
            }
            let destinations = project.sources.values().collect::<BTreeSet<_>>();
            if destinations.len() != project.sources.len()
                || !project.sources.contains_key(&spec.source)
            {
                return Err(invalid(
                    "project mappings need a unique destination per file and a primary source mapping",
                ));
            }
            if project
                .objects
                .values()
                .chain(project.linked_output.iter())
                .any(|path| destinations.contains(path))
            {
                return Err(invalid("a project source cannot also be a build output"));
            }
            if !project.objects.contains_key(&spec.symbol) {
                return Err(invalid(
                    "project objects must map the target symbol to its build output",
                ));
            }
            if project.build.executable.is_empty() {
                return Err(invalid("project build executable is empty"));
            }
        }
        Ok(())
    }

    pub fn setup_matching_workspace(
        &self,
        program: &str,
        setup: WorkspaceSetup,
    ) -> Result<WorkspaceCreated> {
        self.db.program_id(program)?;
        let files = setup
            .files
            .into_iter()
            .map(|(name, file)| {
                relative(&name)?;
                Ok((name, input(self.db_path(), file)?))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        self.create_matching_workspace(
            program,
            WorkspaceSpec {
                name: setup.name,
                symbol: setup.symbol,
                source: setup.source,
                files,
                target: input(self.db_path(), setup.target)?,
                profiles: setup.profiles,
                project: setup.project,
                objdiff: ToolRequirement::default(),
            },
        )
    }

    pub fn create_matching_workspace(
        &self,
        program: &str,
        mut spec: WorkspaceSpec,
    ) -> Result<WorkspaceCreated> {
        let program = self.db.program_id(program)?;
        self.validate_matching_spec(&mut spec)?;
        Ok(self.db.create_matching_workspace(program, spec)?)
    }

    pub fn run_matching_workspace_operation(
        &self,
        program: &str,
        operation: WorkspaceOperation,
    ) -> Result<serde_json::Value> {
        let result = match operation {
            WorkspaceOperation::Setup { setup } => {
                serde_json::to_value(self.setup_matching_workspace(program, setup)?)
            }
            WorkspaceOperation::List { after, limit } => serde_json::to_value(
                self.matching_workspaces(program, after, limit.unwrap_or(64))?,
            ),
            WorkspaceOperation::Show { workspace } => {
                serde_json::to_value(self.matching_workspace(program, workspace)?)
            }
            WorkspaceOperation::Update {
                workspace,
                revision,
                spec,
            } => serde_json::to_value(
                self.update_matching_workspace(program, workspace, revision, spec)?,
            ),
            WorkspaceOperation::Candidates {
                workspace,
                after,
                limit,
            } => serde_json::to_value(self.matching_candidates(
                program,
                workspace,
                after,
                limit.unwrap_or(64),
            )?),
            WorkspaceOperation::Candidate { candidate } => {
                serde_json::to_value(self.matching_candidate(program, candidate)?)
            }
            WorkspaceOperation::Source { candidate, file } => {
                serde_json::to_value(self.matching_source(program, candidate, &file)?)
            }
            WorkspaceOperation::Change { change } => {
                serde_json::to_value(self.change_matching_candidate(program, change)?)
            }
            WorkspaceOperation::Replace {
                candidate,
                file,
                source,
                label,
            } => serde_json::to_value(
                self.replace_matching_source(program, candidate, &file, &source, &label)?,
            ),
            WorkspaceOperation::Trials {
                workspace,
                after,
                limit,
            } => serde_json::to_value(self.matching_trials(
                program,
                workspace,
                after,
                limit.unwrap_or(64),
            )?),
            WorkspaceOperation::Checks {
                workspace,
                after,
                limit,
            } => serde_json::to_value(self.matching_project_checks(
                program,
                workspace,
                after,
                limit.unwrap_or(64),
            )?),
            WorkspaceOperation::Export { workspace } => {
                serde_json::to_value(self.export_matching_workspace(program, workspace)?)
            }
            WorkspaceOperation::Import { request } => {
                serde_json::to_value(self.import_matching_workspace(program, request)?)
            }
        };
        result.map_err(|error| invalid(error.to_string()))
    }

    pub fn update_matching_workspace(
        &self,
        program: &str,
        id: u64,
        revision: u64,
        mut spec: WorkspaceSpec,
    ) -> Result<MatchingWorkspace> {
        let program = self.db.program_id(program)?;
        let old = self.db.matching_workspace(program, id)?;
        if old.spec.source != spec.source
            || old.spec.symbol != spec.symbol
            || old.spec.target != spec.target
            || old.spec.files != spec.files
            || old.spec.objdiff != spec.objdiff
        {
            return Err(invalid(
                "changing the target or initial inputs requires a new workspace",
            ));
        }
        self.validate_matching_spec(&mut spec)?;
        if old
            .spec
            .profiles
            .iter()
            .any(|profile| !spec.profiles.contains(profile))
        {
            return Err(invalid(
                "keep existing profiles immutable; give a changed profile a new name",
            ));
        }
        Ok(self
            .db
            .update_matching_workspace(program, id, revision, spec)?)
    }

    pub fn matching_workspaces(
        &self,
        program: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MatchingWorkspace>> {
        Ok(self
            .db
            .matching_workspaces(self.db.program_id(program)?, after, limit)?)
    }

    pub fn matching_workspace(&self, program: &str, id: u64) -> Result<MatchingWorkspace> {
        Ok(self
            .db
            .matching_workspace(self.db.program_id(program)?, id)?)
    }

    pub fn matching_candidate(&self, program: &str, id: u64) -> Result<MatchingCandidate> {
        Ok(self
            .db
            .matching_candidate(self.db.program_id(program)?, id)?)
    }

    pub fn matching_candidates(
        &self,
        program: &str,
        workspace: u64,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MatchingCandidate>> {
        Ok(self
            .db
            .matching_candidates(self.db.program_id(program)?, workspace, after, limit)?)
    }

    pub fn matching_trials(
        &self,
        program: &str,
        workspace: u64,
        after: u64,
        limit: usize,
    ) -> Result<Vec<TrialRecord>> {
        Ok(self
            .db
            .matching_trials(self.db.program_id(program)?, workspace, after, limit)?)
    }

    pub fn matching_source(&self, program: &str, candidate: u64, file: &str) -> Result<String> {
        let candidate = self.matching_candidate(program, candidate)?;
        let file = candidate
            .spec
            .files
            .get(file)
            .ok_or_else(|| invalid("candidate has no such source file"))?;
        Ok(text(&Artifact::open(self.db_path(), &file.digest)?.bytes)?.to_owned())
    }

    fn validate_matching_pins(
        &self,
        files: &BTreeMap<String, WorkspaceFile>,
        pins: &[SourcePin],
    ) -> Result<()> {
        layout(files)?;
        let mut sources = BTreeMap::new();
        for pin in pins {
            if !sources.contains_key(&pin.file) {
                let file = files
                    .get(&pin.file)
                    .ok_or_else(|| invalid("pin names a missing source file"))?;
                sources.insert(
                    pin.file.clone(),
                    Artifact::open(self.db_path(), &file.digest)?,
                );
            }
            let source = text(&sources[&pin.file].bytes)?;
            range(source, pin.start, pin.end)?;
            if pin.start == pin.end {
                return Err(invalid("a pin must protect a nonempty source range"));
            }
        }
        Ok(())
    }

    pub fn change_matching_candidate(
        &self,
        program: &str,
        mut change: CandidateChange,
    ) -> Result<MatchingCandidate> {
        let program = self.db.program_id(program)?;
        let parent = self.db.matching_candidate(program, change.parent)?;
        if change.label.trim().is_empty() {
            return Err(invalid("candidate label is empty"));
        }
        change.edits.sort_by(|left, right| {
            (&left.file, left.start, left.end).cmp(&(&right.file, right.start, right.end))
        });
        for pair in change.edits.windows(2) {
            if pair[0].file == pair[1].file
                && (pair[0].end > pair[1].start || pair[0].start == pair[1].start)
            {
                return Err(invalid(
                    "source edits overlap or have ambiguous insertion order",
                ));
            }
        }
        if change
            .edits
            .iter()
            .any(|edit| parent.spec.pins.iter().any(|pin| intersects(edit, pin)))
        {
            return Err(invalid(
                "source edit intersects a pinned range; unpin it explicitly first",
            ));
        }
        let mut files = parent.spec.files.clone();
        let mut cursor = 0;
        while cursor < change.edits.len() {
            let name = &change.edits[cursor].file;
            relative(name)?;
            let end = cursor
                + change.edits[cursor..]
                    .iter()
                    .take_while(|edit| &edit.file == name)
                    .count();
            let old = files
                .get(name)
                .map(|file| Artifact::open(self.db_path(), &file.digest))
                .transpose()?;
            let source = text(old.as_ref().map(|file| file.bytes.as_ref()).unwrap_or(&[]))?;
            let edits = &change.edits[cursor..end];
            let mut size = source.len();
            for edit in edits {
                range(source, edit.start, edit.end)?;
                size = size
                    .checked_sub(edit.end - edit.start)
                    .and_then(|size| size.checked_add(edit.replacement.len()))
                    .ok_or_else(|| invalid("edited source size overflows"))?;
            }
            if size > MAX_SOURCE {
                return Err(invalid("edited source exceeds 4 MiB"));
            }
            let mut replacement = String::with_capacity(size);
            let mut offset = 0;
            for edit in edits {
                replacement.push_str(&source[offset..edit.start]);
                replacement.push_str(&edit.replacement);
                offset = edit.end;
            }
            replacement.push_str(&source[offset..]);
            let artifact = Artifact::from_bytes(self.db_path(), replacement.into_bytes().into())?;
            let redistributable = files.get(name).is_some_and(|file| file.redistributable);
            files.insert(
                name.clone(),
                WorkspaceFile {
                    digest: artifact.digest,
                    redistributable,
                },
            );
            cursor = end;
        }
        let pins = change
            .pins
            .unwrap_or_else(|| relocated_pins(&parent.spec.pins, &change.edits));
        self.validate_matching_pins(&files, &pins)?;
        Ok(self.db.record_matching_candidate(
            program,
            parent.workspace,
            CandidateSpec {
                parent: Some(parent.id),
                label: change.label,
                files,
                edits: Some(change.edits),
                pins,
            },
        )?)
    }

    pub fn replace_matching_source(
        &self,
        program: &str,
        candidate: u64,
        file: &str,
        source: &str,
        label: &str,
    ) -> Result<MatchingCandidate> {
        text(source.as_bytes())?;
        let old = self.matching_source(program, candidate, file)?;
        self.change_matching_candidate(
            program,
            CandidateChange {
                parent: candidate,
                label: label.to_owned(),
                edits: edits_between(file, &old, source),
                pins: None,
            },
        )
    }

    pub(super) fn prepare_matching_candidate(
        &self,
        request: &crate::exec::ExecutionRequest,
        workspace: &MatchingWorkspace,
        candidate: &MatchingCandidate,
        profile: &str,
    ) -> Result<PreparedMatch> {
        request.cancel.checkpoint(request.deadline)?;
        let profile = workspace
            .spec
            .profiles
            .iter()
            .find(|item| item.name == profile)
            .ok_or_else(|| invalid(format!("workspace has no compiler profile {profile}")))?;
        let source = candidate
            .spec
            .files
            .get(&workspace.spec.source)
            .ok_or_else(|| invalid("candidate lost its primary source"))?;
        Ok(PreparedMatch {
            target_digest: workspace.spec.target.digest.clone(),
            source_digest: source.digest.clone(),
            context_digest: Artifact::from_bytes(self.db_path(), std::sync::Arc::from([]))?.digest,
            compiler_digest: profile.compiler_digest.clone(),
            objdiff_digest: workspace.spec.objdiff.digest.clone(),
            compiler: PathBuf::from(&profile.recipe.compiler),
            objdiff: PathBuf::from(&workspace.spec.objdiff.path),
            recipe: profile.recipe.clone(),
            source_name: workspace.spec.source.clone(),
            compile_arguments: profile.compile_arguments.clone(),
            version_arguments: profile.version_arguments.clone(),
            tools: profile.tools.clone(),
            files: candidate
                .spec
                .files
                .iter()
                .map(|(name, file)| (name.clone(), file.digest.clone()))
                .collect(),
            symbol: Some(workspace.spec.symbol.clone()),
            versions: Default::default(),
        })
    }
}
