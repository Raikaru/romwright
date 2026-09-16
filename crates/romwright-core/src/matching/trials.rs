use super::{PreparedMatch, diagnosis, invalid};
use crate::{Core, Result, artifact::Artifact, exec::ExecutionRequest};
use romwright_model::matching::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

type Versions = Arc<OnceLock<(String, String)>>;

fn milliseconds(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn budget(value: usize) -> Result<()> {
    if value == 0 || value > 4096 {
        return Err(invalid("compilation budget must be between 1 and 4096"));
    }
    Ok(())
}

fn exact_function(diagnosis: &MatchDiagnosis) -> bool {
    diagnosis.exact_instructions == Some(true) && diagnosis.exact_relocations == Some(true)
}

fn better(left: &TrialRecord, right: &TrialRecord) -> bool {
    let left = &left.diagnosis;
    let right = &right.diagnosis;
    (
        exact_function(left),
        left.similarity.unwrap_or(-1.0),
        left.exact_instructions == Some(true),
        left.exact_relocations == Some(true),
        left.exact_object_bytes,
    ) > (
        exact_function(right),
        right.similarity.unwrap_or(-1.0),
        right.exact_instructions == Some(true),
        right.exact_relocations == Some(true),
        right.exact_object_bytes,
    )
}

fn alternatives(source: &str, selection: &SourcePin) -> Result<Vec<Vec<SourceEdit>>> {
    let selected = source
        .get(selection.start..selection.end)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid("select a nonempty UTF-8 expression or scalar-type range"))?;
    let mut replacements = Vec::new();
    // An explicitly selected declaration/cast type is a different grammar
    // position from an expression. Wrapping it in a cast only makes invalid C.
    const INTEGER_TYPES: &[&str] = &[
        "int", "unsigned int", "short", "unsigned short", "signed char", "unsigned char",
        "char", "long", "unsigned long", "long long", "unsigned long long",
    ];
    let literal = selected.trim();
    let scalar_types = if matches!(literal, "float" | "double") {
        &["float", "double"][..]
    } else {
        INTEGER_TYPES
    };
    if scalar_types.contains(&literal) {
        for ty in scalar_types {
            replacements.push(((*ty).to_string(),
                format!("Test the selected scalar type as {ty}; semantic equivalence is not assumed")));
        }
    } else {
    let digits = literal.trim_end_matches(['u', 'U', 'l', 'L']);
    let suffix = &literal[digits.len()..];
    let (radix, digits) = if let Some(digits) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        (2, digits)
    } else if digits.starts_with('0') && digits.len() > 1 {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    if let Ok(value) = u64::from_str_radix(digits, radix) {
        for value in [value.checked_sub(1), value.checked_add(1)]
            .into_iter()
            .flatten()
        {
            let value = match radix {
                16 => format!("0x{value:x}"),
                2 => format!("0b{value:b}"),
                8 => format!("0{value:o}"),
                _ => value.to_string(),
            };
            replacements.push((
                format!("{value}{suffix}"),
                "Test a neighboring literal; this changes semantics and requires review".into(),
            ));
        }
        let base = literal.trim_end_matches(['u', 'U', 'l', 'L']);
        for suffix in ["", "u", "L", "UL"] {
            replacements.push((
                format!("{base}{suffix}"),
                "Test the integer literal's type suffix".into(),
            ));
        }
    }
    for ty in [
        "int",
        "unsigned int",
        "short",
        "unsigned short",
        "signed char",
        "unsigned char",
    ] {
        replacements.push((
            format!("(({ty})({selected}))"),
            format!("Test an explicit {ty} cast; semantic equivalence is not assumed"),
        ));
    }
    }
    let mut unique = BTreeSet::new();
    Ok(replacements
        .into_iter()
        .filter(|(replacement, _)| replacement != selected && unique.insert(replacement.clone()))
        .map(|(replacement, reason)| {
            vec![SourceEdit {
                file: selection.file.clone(),
                start: selection.start,
                end: selection.end,
                replacement,
                reason,
            }]
        })
        .collect())
}

impl Core {
    fn run_prepared_candidate(
        &self,
        request: &ExecutionRequest,
        workspace: &MatchingWorkspace,
        candidate: &MatchingCandidate,
        profile: &str,
        prepared: &PreparedMatch,
    ) -> Result<TrialRecord> {
        let started = Instant::now();
        let record = self.execute_matching(request, prepared)?;
        let target = Artifact::open(self.db_path(), &record.target_digest)?;
        let object = record
            .candidate_digest
            .as_ref()
            .map(|digest| Artifact::open(self.db_path(), digest))
            .transpose()?;
        let diagnosis = diagnosis::diagnose(
            &workspace.spec.symbol,
            &target.bytes,
            object.as_ref().map(|artifact| artifact.bytes.as_ref()),
            (record.status == romwright_model::MatchingStatus::Compared)
                .then_some(&record.raw_result),
        );
        let evidence = Artifact::from_bytes(
            self.db_path(),
            serde_json::to_vec(&record)
                .map_err(|error| invalid(error.to_string()))?
                .into(),
        )?;
        let trial = TrialRecord {
            id: 0,
            created_at: String::new(),
            candidate: candidate.id,
            candidate_digest: record.candidate_digest.clone(),
            profile: profile.to_owned(),
            status: record.status,
            run: None,
            evidence_digest: evidence.digest,
            imported: false,
            diagnosis,
            elapsed_ms: milliseconds(started),
        };
        request.cancel.publish(request.deadline, || {
            Ok(self.db.record_matching_trial(
                self.db.program_id(&request.program)?,
                workspace.id,
                trial,
                record,
            )?)
        })
    }

    pub fn run_matching_candidate(
        &self,
        request: &ExecutionRequest,
        candidate: u64,
        profile: &str,
    ) -> Result<TrialRecord> {
        let candidate = self.matching_candidate(&request.program, candidate)?;
        let workspace = self.matching_workspace(&request.program, candidate.workspace)?;
        let prepared = self.prepare_matching_candidate(request, &workspace, &candidate, profile)?;
        self.run_prepared_candidate(request, &workspace, &candidate, profile, &prepared)
    }

    pub fn search_matching_candidates(
        &self,
        request: &ExecutionRequest,
        search: SearchRequest,
    ) -> Result<TrialBatch> {
        budget(search.max_compilations)?;
        let started = Instant::now();
        let parent = self.matching_candidate(&request.program, search.candidate)?;
        let workspace = self.matching_workspace(&request.program, parent.workspace)?;
        let mut prepared =
            self.prepare_matching_candidate(request, &workspace, &parent, &search.profile)?;
        let mut choices = search.alternatives;
        if let Some(selection) = search.expression {
            let source = self.matching_source(&request.program, parent.id, &selection.file)?;
            choices.extend(alternatives(&source, &selection)?);
        }
        let baseline =
            self.run_prepared_candidate(request, &workspace, &parent, &search.profile, &prepared)?;
        let mut trials = vec![baseline];
        let mut best = 0;
        let mut hypotheses = Vec::new();
        let mut stopped = "alternatives exhausted";
        let mut seen = BTreeSet::new();
        for edits in choices {
            if exact_function(&trials[best].diagnosis) {
                stopped = "exact function match";
                break;
            }
            if trials.len() >= search.max_compilations {
                stopped = "compilation budget reached";
                break;
            }
            request.cancel.checkpoint(request.deadline)?;
            let identity =
                serde_json::to_string(&edits).map_err(|error| invalid(error.to_string()))?;
            if edits.is_empty() || !seen.insert(identity) {
                continue;
            }
            let description = edits
                .iter()
                .map(|edit| edit.reason.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            let candidate = self.change_matching_candidate(
                &request.program,
                CandidateChange {
                    parent: parent.id,
                    label: format!("Search: {description}"),
                    edits,
                    pins: None,
                },
            )?;
            prepared.source_digest = candidate.spec.files[&workspace.spec.source].digest.clone();
            prepared.files = candidate
                .spec
                .files
                .iter()
                .map(|(name, file)| (name.clone(), file.digest.clone()))
                .collect();
            let trial = self.run_prepared_candidate(
                request,
                &workspace,
                &candidate,
                &search.profile,
                &prepared,
            )?;
            let before = trials[0].diagnosis.similarity;
            let after = trial.diagnosis.similarity;
            hypotheses.push(TestedHypothesis {
                candidate: candidate.id,
                description,
                before,
                after,
                improved: before.zip(after).map(|(before, after)| after > before),
            });
            if better(&trial, &trials[best]) {
                best = trials.len();
            }
            trials.push(trial);
        }
        if exact_function(&trials[best].diagnosis) {
            stopped = "exact function match";
        }
        let best_candidate = (trials[best].diagnosis.similarity.is_some()
            || exact_function(&trials[best].diagnosis))
            .then_some(trials[best].candidate);
        Ok(TrialBatch {
            compiler_invocations: trials.len(),
            trials,
            hypotheses,
            best_candidate,
            elapsed_ms: milliseconds(started),
            stopped: stopped.into(),
        })
    }

    pub fn calibrate_matching_profiles(
        &self,
        request: &ExecutionRequest,
        candidates: &[u64],
        profiles: &[String],
        max_compilations: usize,
    ) -> Result<CalibrationResult> {
        budget(max_compilations)?;
        if candidates.is_empty() || profiles.is_empty() {
            return Err(invalid(
                "calibration needs reference candidates and explicit profiles",
            ));
        }
        if candidates.iter().collect::<BTreeSet<_>>().len() != candidates.len()
            || profiles.iter().collect::<BTreeSet<_>>().len() != profiles.len()
        {
            return Err(invalid(
                "calibration candidates and profiles must be unique",
            ));
        }
        if candidates
            .len()
            .checked_mul(profiles.len())
            .is_none_or(|count| count > max_compilations)
        {
            return Err(invalid(
                "compilation budget does not cover the complete calibration matrix",
            ));
        }
        let started = Instant::now();
        let mut prepared = Vec::new();
        let mut versions: BTreeMap<String, Versions> = BTreeMap::new();
        for id in candidates {
            let candidate = self.matching_candidate(&request.program, *id)?;
            let workspace = self.matching_workspace(&request.program, candidate.workspace)?;
            for name in profiles {
                let mut invocation =
                    self.prepare_matching_candidate(request, &workspace, &candidate, name)?;
                let key = serde_json::to_string(&(
                    workspace
                        .spec
                        .profiles
                        .iter()
                        .find(|profile| &profile.name == name),
                    &workspace.spec.objdiff,
                ))
                .map_err(|error| invalid(error.to_string()))?;
                invocation.versions = versions.entry(key).or_default().clone();
                prepared.push((candidate.clone(), workspace.clone(), name, invocation));
            }
        }
        let mut trials = Vec::new();
        let mut scores: BTreeMap<String, (f64, usize)> = BTreeMap::new();
        for (candidate, workspace, name, invocation) in prepared {
            let trial =
                self.run_prepared_candidate(request, &workspace, &candidate, name, &invocation)?;
            let score = scores.entry(name.clone()).or_default();
            score.0 += trial.diagnosis.similarity.unwrap_or(0.0);
            score.1 += usize::from(trial.diagnosis.similarity.is_some());
            trials.push(trial);
        }
        let mut ranking: Vec<_> = scores
            .into_iter()
            .filter(|(_, (_, compared))| *compared > 0)
            .map(|(name, (sum, _))| (name, sum / candidates.len() as f64))
            .collect();
        ranking.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        Ok(CalibrationResult {
            trials,
            ranking,
            elapsed_ms: milliseconds(started),
        })
    }

    pub fn trial_matching_context(
        &self,
        request: &ExecutionRequest,
        context: ContextTrialRequest,
    ) -> Result<Vec<ContextComparison>> {
        budget(context.max_compilations)?;
        if context.candidates.is_empty()
            || context.edits.is_empty()
            || context
                .candidates
                .len()
                .checked_mul(2)
                .is_none_or(|count| count > context.max_compilations)
        {
            return Err(invalid(
                "context trial needs edits and enough budget for every baseline and alternative",
            ));
        }
        if context.candidates.iter().collect::<BTreeSet<_>>().len() != context.candidates.len() {
            return Err(invalid("duplicate context candidate"));
        }
        let mut prepared = Vec::new();
        let mut shared = BTreeMap::new();
        for id in context.candidates {
            let candidate = self.matching_candidate(&request.program, id)?;
            let workspace = self.matching_workspace(&request.program, candidate.workspace)?;
            for edit in &context.edits {
                let file = candidate
                    .spec
                    .files
                    .get(&edit.file)
                    .ok_or_else(|| invalid("context file is missing from a candidate"))?;
                if shared
                    .insert(edit.file.clone(), file.digest.clone())
                    .is_some_and(|previous| previous != file.digest)
                {
                    return Err(invalid(
                        "context candidates do not share the same initial header bytes",
                    ));
                }
                if candidate.spec.pins.iter().any(|pin| {
                    pin.file == edit.file
                        && if edit.start == edit.end {
                            edit.start > pin.start && edit.start < pin.end
                        } else {
                            edit.start < pin.end && edit.end > pin.start
                        }
                }) {
                    return Err(invalid(
                        "shared context change intersects a pinned source range",
                    ));
                }
            }
            let invocation =
                self.prepare_matching_candidate(request, &workspace, &candidate, &context.profile)?;
            prepared.push((candidate, workspace, invocation));
        }
        let mut comparisons = Vec::new();
        for (candidate, workspace, mut invocation) in prepared {
            let baseline = self.run_prepared_candidate(
                request,
                &workspace,
                &candidate,
                &context.profile,
                &invocation,
            )?;
            request.cancel.checkpoint(request.deadline)?;
            let changed = self.change_matching_candidate(
                &request.program,
                CandidateChange {
                    parent: candidate.id,
                    label: "Isolated shared-context trial".into(),
                    edits: context.edits.clone(),
                    pins: None,
                },
            )?;
            invocation.source_digest = changed.spec.files[&workspace.spec.source].digest.clone();
            invocation.files = changed
                .spec
                .files
                .iter()
                .map(|(name, file)| (name.clone(), file.digest.clone()))
                .collect();
            let trial = self.run_prepared_candidate(
                request,
                &workspace,
                &changed,
                &context.profile,
                &invocation,
            )?;
            let delta = baseline
                .diagnosis
                .similarity
                .zip(trial.diagnosis.similarity)
                .map(|(before, after)| after - before);
            comparisons.push(ContextComparison {
                baseline,
                trial,
                delta,
            });
        }
        Ok(comparisons)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an ELF C compiler, objdiff-cli and installed language specifications"]
    fn search_stops_at_a_function_match_with_unrelated_object_differences() {
        let root = std::env::temp_dir().join(format!(
            "romwright-function-search-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let source = "int step(int x) { return x + 1; }\n";
        let original = root.join("original.c");
        let binary = root.join("original");
        let object = root.join("original.o");
        std::fs::write(&original, format!(
            "{source}int unrelated(int x) {{ return x * 3; }}\nint main(void) {{ return step(4); }}\n"
        )).unwrap();
        for (output, object_only) in [(&binary, false), (&object, true)] {
            let mut command = std::process::Command::new("/usr/bin/cc");
            command.arg("-O2");
            if object_only { command.arg("-c"); }
            let compiled = command.arg(&original).arg("-o").arg(output).output().unwrap();
            assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
        }
        let core = Core::open_with_config(
            &root.join("project"), crate::session::RuntimeConfig::from_env(),
        ).unwrap();
        core.import_native_with_signatures(
            &binary, "match", &[], false, None, None, &crate::native::keys::KeyStore::empty(),
        ).unwrap();
        let created = core.run_matching_workspace_operation("match", WorkspaceOperation::Setup {
            setup: WorkspaceSetup {
                name: "function-scoped search".into(),
                symbol: "step".into(),
                source: "candidate.c".into(),
                files: BTreeMap::from([("candidate.c".into(), MatchingInput::Text {
                    text: source.into(), redistributable: true,
                })]),
                target: MatchingInput::Path {
                    path: object.to_str().unwrap().into(), redistributable: true,
                },
                profiles: vec![MatchingProfile {
                    name: "host".into(),
                    recipe: romwright_model::BuildRecipe {
                        compiler: "/usr/bin/cc".into(),
                        arguments: vec!["-O2".into(), "-c".into(), "{source}".into(),
                            "-o".into(), "{output}".into()],
                        environment: BTreeMap::from([(
                            "TMPDIR".into(), std::env::temp_dir().to_str().unwrap().into(),
                        )]),
                    },
                    compile_arguments: vec![],
                    version_arguments: vec!["--version".into()],
                    tools: BTreeMap::new(),
                    compiler_digest: String::new(),
                }],
                project: None,
            },
        }).unwrap();
        let candidate = created["candidate"]["id"].as_u64().unwrap();
        let request = core.execution_request(
            &binary, "match", None, std::time::Duration::from_secs(30),
        ).unwrap();
        // Background analysis can change unrelated facts after the job is
        // captured. Its immutable source/object comparison remains valid.
        let helper = core.functions("match").unwrap().into_iter()
            .find(|function| function.name == "unrelated").unwrap();
        core.rename_function("match", &helper.entry, "analysis_named_helper").unwrap();
        let program = core.db.program_id("match").unwrap();
        let current_revision = core.db.revision(program).unwrap();
        assert!(current_revision > request.revision);
        let position = source.find('1').unwrap();
        let result = core.search_matching_candidates(&request, SearchRequest {
            candidate,
            profile: "host".into(),
            max_compilations: 3,
            alternatives: vec![vec![SourceEdit {
                file: "candidate.c".into(), start: position, end: position + 1,
                replacement: "2".into(), reason: "must not compile after a proven match".into(),
            }]],
            expression: None,
        }).unwrap();
        assert_eq!(result.compiler_invocations, 1, "unrelated object bytes must not prolong search");
        assert_eq!(result.best_candidate, Some(candidate));
        let diagnosis = &result.trials[0].diagnosis;
        assert_eq!(diagnosis.exact_instructions, Some(true));
        assert_eq!(diagnosis.exact_relocations, Some(true));
        assert!(!diagnosis.exact_object_bytes);
        let saved = core.matching_trials(
            "match", created["workspace"]["id"].as_u64().unwrap(), 0, 10,
        ).unwrap();
        let record = &saved[0].run.as_ref().unwrap().record;
        assert_eq!(record.revision, request.revision,
            "historical evidence must not be relabelled as current analysis");
        let mut future = record.clone();
        future.revision = current_revision + 1;
        assert!(matches!(core.db.record_matching_run(program, future),
            Err(romwright_db::DbError::StaleRevision { .. })));
        drop(core);
        std::fs::remove_dir_all(root).unwrap();
    }
}
