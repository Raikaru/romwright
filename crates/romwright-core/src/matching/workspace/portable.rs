use super::{Artifact, Core, Result, capture, invalid};
use base64::Engine;
use romwright_model::matching::*;
use romwright_model::{MatchingRun, MatchingRunRecord, MatchingStatus};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid(
            "portable workspace contains an invalid SHA-256 identity",
        ));
    }
    Ok(())
}

fn permission(map: &mut BTreeMap<String, bool>, digest_value: &str, allowed: bool) -> Result<()> {
    digest(digest_value)?;
    map.entry(digest_value.to_owned())
        .and_modify(|value| *value &= allowed)
        .or_insert(allowed);
    Ok(())
}

fn permissions(bundle: &WorkspaceBundle) -> Result<BTreeMap<String, bool>> {
    let mut result = BTreeMap::new();
    for file in bundle
        .workspace
        .files
        .values()
        .chain(std::iter::once(&bundle.workspace.target))
    {
        permission(&mut result, &file.digest, file.redistributable)?;
    }
    let mut candidates = BTreeMap::new();
    for candidate in &bundle.candidates {
        if candidates.insert(candidate.id, candidate).is_some() {
            return Err(invalid("duplicate candidate in portable workspace"));
        }
        for file in candidate.spec.files.values() {
            permission(&mut result, &file.digest, file.redistributable)?;
        }
    }
    for trial in &bundle.trials {
        let candidate = candidates
            .get(&trial.candidate)
            .ok_or_else(|| invalid("portable trial has no candidate"))?;
        let allowed = bundle.workspace.target.redistributable
            && candidate
                .spec
                .files
                .values()
                .all(|file| file.redistributable);
        permission(&mut result, &trial.evidence_digest, allowed)?;
        if let Some(object) = &trial.candidate_digest {
            permission(&mut result, object, allowed)?;
        }
    }
    for check in &bundle.project_checks {
        if !candidates.contains_key(&check.patch.candidate) {
            return Err(invalid("portable project check has no candidate"));
        }
        // The full project's dependencies have not been licensed for export.
        permission(&mut result, &check.input_manifest_digest, false)?;
        if let Some(object) = &check.candidate_digest {
            permission(&mut result, object, false)?;
        }
        if let Some(comparison) = &check.comparison_digest {
            permission(&mut result, comparison, false)?;
        }
        for artifact in check
            .baseline_candidate_digest
            .iter()
            .chain(check.baseline_comparison_digest.iter())
            .chain(check.scope_comparison_digests.iter())
            .chain(check.linked_output_digest.iter())
        {
            permission(&mut result, artifact, false)?;
        }
        for file in &check.patch.files {
            if let Some(before) = &file.before_digest {
                digest(before)?;
            }
            digest(&file.after_digest)?;
        }
    }
    // A manifest cannot accidentally authorize a compiler by also naming it as
    // a source, header or reference object. Denial wins across every alias.
    permission(&mut result, &bundle.workspace.objdiff.digest, false)?;
    for profile in &bundle.workspace.profiles {
        permission(&mut result, &profile.compiler_digest, false)?;
        for tool in profile.tools.values() {
            permission(&mut result, &tool.digest, false)?;
        }
    }
    Ok(result)
}

impl Core {
    pub fn export_matching_workspace(&self, program: &str, id: u64) -> Result<WorkspaceBundle> {
        let workspace = self.matching_workspace(program, id)?;
        let mut candidates = Vec::new();
        let mut after = 0;
        loop {
            let page = self.matching_candidates(program, id, after, 1000)?;
            let Some(last) = page.last() else {
                break;
            };
            after = last.id;
            candidates.extend(page);
        }
        let mut trials = Vec::new();
        after = 0;
        loop {
            let page = self.matching_trials(program, id, after, 1000)?;
            let Some(last) = page.last() else {
                break;
            };
            after = last.id;
            trials.extend(page);
        }
        let mut project_checks = Vec::new();
        after = 0;
        loop {
            let page = self.matching_project_checks(program, id, after, 1000)?;
            let Some(last) = page.last() else {
                break;
            };
            after = last.id;
            project_checks.extend(page);
        }
        if self.matching_workspace(program, id)?.revision != workspace.revision {
            return Err(invalid(
                "workspace changed during export; finish the running operation before exporting",
            ));
        }
        let mut bundle = WorkspaceBundle {
            format: 1,
            workspace: workspace.spec,
            candidates,
            trials,
            project_checks,
            artifacts: BTreeMap::new(),
        };
        let allowed = permissions(&bundle)?;
        for candidate in &mut bundle.candidates {
            if candidate.spec.edits.as_ref().is_some_and(|edits| {
                edits.iter().any(|edit| {
                    !candidate
                        .spec
                        .files
                        .get(&edit.file)
                        .is_some_and(|file| allowed.get(&file.digest) == Some(&true))
                })
            }) {
                candidate.spec.edits = None;
            }
        }
        for trial in &mut bundle.trials {
            // Full records travel once, as digest-verified evidence artifacts.
            // Private diagnostics/disassembly must not bypass file permissions.
            trial.run = None;
            if allowed.get(&trial.evidence_digest) != Some(&true) {
                trial.diagnosis.mismatches.clear();
            }
        }
        for check in &mut bundle.project_checks {
            check.recovery_path = None;
            check.diagnostics.clear();
            if let Some(diagnosis) = &mut check.diagnosis {
                diagnosis.mismatches.clear();
            }
            if let Some(diagnosis) = &mut check.baseline_diagnosis {
                diagnosis.mismatches.clear();
            }
            if check.patch.files.iter().any(|file| {
                file.before_digest
                    .as_ref()
                    .is_some_and(|before| allowed.get(before) != Some(&true))
                    || allowed.get(&file.after_digest) != Some(&true)
            }) {
                check.patch.unified_diff.clear();
            }
        }
        for (digest, include) in allowed {
            if include {
                let artifact = Artifact::open(self.db_path(), &digest)?;
                bundle.artifacts.insert(
                    digest,
                    base64::engine::general_purpose::STANDARD.encode(&artifact.bytes),
                );
            }
        }
        Ok(bundle)
    }

    pub fn import_matching_workspace(
        &self,
        program: &str,
        mut import: WorkspaceImport,
    ) -> Result<WorkspaceCreated> {
        let program = self.db.program_id(program)?;
        let bundle = &mut import.bundle;
        if bundle.format != 1 {
            return Err(invalid("unsupported portable matching workspace format"));
        }
        let allowed = permissions(bundle)?;
        for (identity, encoded) in &bundle.artifacts {
            if allowed.get(identity) != Some(&true) {
                return Err(invalid(
                    "bundle contains undeclared or non-redistributable bytes",
                ));
            }
            if encoded.len() as u64 > (super::MAX_FILE + 2) / 3 * 4 {
                return Err(invalid("portable artifact exceeds 64 MiB"));
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| invalid(format!("invalid portable artifact encoding: {error}")))?;
            let artifact = Artifact::from_bytes(self.db_path(), bytes.into())?;
            if artifact.digest != *identity {
                return Err(invalid("portable artifact digest mismatch"));
            }
        }
        for (identity, path) in &import.private_files {
            if !allowed.contains_key(identity) {
                return Err(invalid(
                    "private binding is not a declared workspace dependency",
                ));
            }
            if capture(self.db_path(), Path::new(path))?.digest != *identity {
                return Err(invalid(format!(
                    "private dependency does not match {identity}"
                )));
            }
        }
        let mut required = BTreeSet::new();
        for file in bundle
            .workspace
            .files
            .values()
            .chain(std::iter::once(&bundle.workspace.target))
        {
            required.insert(file.digest.as_str());
        }
        for candidate in &bundle.candidates {
            required.extend(
                candidate
                    .spec
                    .files
                    .values()
                    .map(|file| file.digest.as_str()),
            );
        }
        // Public evidence is promised by the bundle. Private historical evidence
        // is optional; the source/target inputs needed for replay are not.
        required.extend(
            allowed
                .iter()
                .filter(|(_, value)| **value)
                .map(|(digest, _)| digest.as_str()),
        );
        let missing: Vec<_> = required
            .into_iter()
            .filter(|digest| Artifact::open(self.db_path(), digest).is_err())
            .collect();
        if !missing.is_empty() {
            return Err(invalid(format!(
                "missing workspace artifacts; provide private_files bindings: {}",
                missing.join(", ")
            )));
        }
        for (name, path) in import.compilers {
            let profile = bundle
                .workspace
                .profiles
                .iter_mut()
                .find(|profile| profile.name == name)
                .ok_or_else(|| invalid(format!("unknown imported compiler profile {name}")))?;
            profile.recipe.compiler = path;
        }
        for (name, bindings) in import.tools {
            let profile = bundle
                .workspace
                .profiles
                .iter_mut()
                .find(|profile| profile.name == name)
                .ok_or_else(|| invalid(format!("unknown imported compiler profile {name}")))?;
            for (tool, path) in bindings {
                profile
                    .tools
                    .get_mut(&tool)
                    .ok_or_else(|| invalid(format!("undeclared tool binding {tool}")))?
                    .path = path;
            }
        }
        if let Some(path) = import.objdiff {
            bundle.workspace.objdiff.path = path;
        }
        if let Some(project) = &mut bundle.workspace.project {
            project.root = import.project_root;
        }
        self.validate_matching_spec(&mut bundle.workspace)?;
        bundle.candidates.sort_by_key(|candidate| candidate.id);
        let mut candidates = BTreeMap::new();
        let mut root = None;
        for candidate in &bundle.candidates {
            self.validate_matching_files(&candidate.spec.files)?;
            self.validate_matching_pins(&candidate.spec.files, &candidate.spec.pins)?;
            if !candidate.spec.files.contains_key(&bundle.workspace.source) {
                return Err(invalid("imported candidate has no primary source"));
            }
            match candidate.spec.parent {
                Some(parent) if !candidates.contains_key(&parent) => {
                    return Err(invalid("imported parent is absent or out of order"));
                }
                None => {
                    if root.replace(candidate.id).is_some()
                        || candidate.spec.files != bundle.workspace.files
                    {
                        return Err(invalid(
                            "portable workspace must have one faithful initial candidate",
                        ));
                    }
                }
                _ => {}
            }
            candidates.insert(candidate.id, candidate);
        }
        if root.is_none() {
            return Err(invalid("portable workspace has no initial candidate"));
        }
        let empty_context = Artifact::from_bytes(self.db_path(), std::sync::Arc::from([]))?.digest;
        let mut trial_ids = BTreeSet::new();
        for trial in &mut bundle.trials {
            if !trial_ids.insert(trial.id) {
                return Err(invalid("duplicate trial in portable workspace"));
            }
            let candidate = candidates
                .get(&trial.candidate)
                .ok_or_else(|| invalid("imported trial has no candidate"))?;
            let profile = bundle
                .workspace
                .profiles
                .iter()
                .find(|profile| profile.name == trial.profile)
                .ok_or_else(|| invalid("imported trial has an undeclared compiler profile"))?;
            if trial.diagnosis.symbol != bundle.workspace.symbol
                || trial
                    .diagnosis
                    .similarity
                    .is_some_and(|score| !score.is_finite() || !(0.0..=100.0).contains(&score))
                || (trial.status == MatchingStatus::CompileFailed)
                    != trial.candidate_digest.is_none()
                || (trial.diagnosis.exact_object_bytes
                    && trial.candidate_digest.as_ref() != Some(&bundle.workspace.target.digest))
            {
                return Err(invalid("inconsistent imported matching evidence"));
            }
            trial.imported = true;
            trial.run = None;
            let evidence_path = self
                .db_path()
                .join("artifacts")
                .join(&trial.evidence_digest);
            if !evidence_path.exists() {
                trial.diagnosis.mismatches.clear();
                continue;
            }
            let evidence = Artifact::open(self.db_path(), &trial.evidence_digest)?;
            let record: MatchingRunRecord = serde_json::from_slice(&evidence.bytes)
                .map_err(|error| invalid(format!("invalid imported trial evidence: {error}")))?;
            let expand = |argument: &String| {
                super::super::expand_argument(
                    argument,
                    &bundle.workspace.source,
                    ".romwright-output/candidate.o",
                    Path::new(&record.working_directory),
                    &record.tools,
                )
            };
            if record.recipe.arguments != profile.recipe.arguments
                || record.recipe.environment != profile.recipe.environment
                || record.compile_arguments.len()
                    != profile.recipe.arguments.len() + profile.compile_arguments.len()
                || record.version_arguments.len() != profile.version_arguments.len()
                || profile
                    .recipe
                    .arguments
                    .iter()
                    .chain(&profile.compile_arguments)
                    .zip(&record.compile_arguments)
                    .any(|(template, actual)| {
                        !expand(template)
                            .as_ref()
                            .is_ok_and(|expected| expected == actual)
                    })
                || profile
                    .version_arguments
                    .iter()
                    .zip(&record.version_arguments)
                    .any(|(template, actual)| {
                        !expand(template)
                            .as_ref()
                            .is_ok_and(|expected| expected == actual)
                    })
            {
                return Err(invalid(
                    "imported run arguments or environment differ from its declared profile",
                ));
            }
            if record.status != trial.status
                || record.candidate_digest != trial.candidate_digest
                || record.target_digest != bundle.workspace.target.digest
                || record.source_path != bundle.workspace.source
                || record.source_digest != candidate.spec.files[&bundle.workspace.source].digest
                || record.context_digest != empty_context
                || record.compiler_digest != profile.compiler_digest
                || record.objdiff_digest != bundle.workspace.objdiff.digest
                || record.files.len() != candidate.spec.files.len()
                || record.files.iter().any(|(name, digest)| {
                    candidate
                        .spec
                        .files
                        .get(name)
                        .is_none_or(|file| &file.digest != digest)
                })
                || record.tools.len() != profile.tools.len()
                || record.tools.iter().any(|(name, tool)| {
                    profile
                        .tools
                        .get(name)
                        .is_none_or(|expected| expected.digest != tool.digest)
                })
            {
                return Err(invalid(
                    "imported run does not describe its declared immutable inputs",
                ));
            }
            trial.run = Some(MatchingRun {
                id: 0,
                created_at: trial.created_at.clone(),
                imported: true,
                record,
            });
        }
        let mut check_ids = BTreeSet::new();
        for check in &mut bundle.project_checks {
            if !check_ids.insert(check.id) {
                return Err(invalid("duplicate project check in portable workspace"));
            }
            let paths: BTreeSet<_> = check
                .patch
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect();
            let applied: BTreeSet<_> = check.applied_files.iter().map(String::as_str).collect();
            if paths.len() != check.patch.files.len()
                || applied.len() != check.applied_files.len()
                || (check.applied
                    && (applied != paths
                        || !check.build_succeeded
                        || !check.baseline_build_succeeded
                        || !check.original_inputs_unchanged
                        || !check.missing_outputs.is_empty()
                        || !check.unexpected_objects.is_empty()
                        || !check.unexpected_symbols.is_empty()
                        || !check.unexpected_files.is_empty()))
                || (!check.applied && !applied.is_empty())
            {
                return Err(invalid("inconsistent imported project application history"));
            }
            if !candidates.contains_key(&check.patch.candidate)
                || !bundle
                    .workspace
                    .profiles
                    .iter()
                    .any(|profile| profile.name == check.patch.profile)
            {
                return Err(invalid(
                    "imported project check has an unknown candidate or profile",
                ));
            }
            if let Some(diagnosis) = &check.diagnosis {
                if diagnosis.symbol != bundle.workspace.symbol
                    || diagnosis
                        .similarity
                        .is_some_and(|score| !score.is_finite() || !(0.0..=100.0).contains(&score))
                    || (diagnosis.exact_object_bytes
                        && check.candidate_digest.as_ref() != Some(&bundle.workspace.target.digest))
                {
                    return Err(invalid("inconsistent imported project diagnosis"));
                }
            }
            if let Some(diagnosis) = &check.baseline_diagnosis {
                if diagnosis.symbol != bundle.workspace.symbol
                    || diagnosis
                        .similarity
                        .is_some_and(|score| !score.is_finite() || !(0.0..=100.0).contains(&score))
                    || (diagnosis.exact_object_bytes
                        && check.baseline_candidate_digest.as_ref()
                            != Some(&bundle.workspace.target.digest))
                {
                    return Err(invalid("inconsistent imported project baseline"));
                }
            }
            for file in &check.patch.files {
                super::relative(&file.path)?;
            }
            for file in &check.applied_files {
                super::relative(file)?;
            }
            check.imported = true;
            check.recovery_path = None;
            // Build logs and object disassembly cannot establish local proof:
            // the private full-project snapshot is deliberately not portable.
            check.diagnostics.clear();
            if let Some(diagnosis) = &mut check.diagnosis {
                diagnosis.mismatches.clear();
            }
            if let Some(diagnosis) = &mut check.baseline_diagnosis {
                diagnosis.mismatches.clear();
            }
        }
        bundle.artifacts.clear();
        Ok(self.db.import_matching_workspace(program, import.bundle)?)
    }
}
