//! Revision-atomic orchestration over native flow evidence and owned return facts.
use crate::native::{ImportError, nonreturn::analyze};
use std::collections::BTreeSet;

const SOURCE: &str = "native-flow nonreturn recovery";

/// Whether `name` is a function every program of this compiler and format
/// knows never returns. The names are data: the `nonreturn-names` rules in
/// `compiler_rules/` (Ghidra 12.1.3 Base/data/{Elf,PE}FunctionsThatDoNotReturn,
/// Apache-2.0; `NoReturnFunctionAnalyzer` strips leading underscores before
/// exact matching).
pub(crate) fn known_no_return(ctx: &crate::compiler::rules::Ctx, name: &str) -> bool {
    crate::compiler::rules::known_no_return(ctx, name)
}

#[derive(serde::Serialize)]
pub struct NonReturnInferenceReport {
    pub changed: Vec<romwright_model::Address>,
    pub rediscovered: Vec<romwright_model::Address>,
    pub unknown: Vec<romwright_model::Address>,
    pub revision: u64,
}

impl crate::Core {
    pub fn return_behaviors(
        &self,
        program: &str,
    ) -> crate::Result<Vec<romwright_model::ReturnBehaviorRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.return_behaviors(id)?)
    }

    pub fn thunks(&self, program: &str) -> crate::Result<Vec<romwright_model::ThunkRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.thunks(id)?)
    }

    /// Analyze a byte snapshot, then publish facts and completed caller flows
    /// against the input store revision. Partial native output is never proof.
    pub fn infer_nonreturning(
        &self,
        request: &crate::exec::ExecutionRequest,
        hints: &[romwright_model::Address],
    ) -> crate::Result<NonReturnInferenceReport> {
        use romwright_model::{Address, AddressSpace, FactKind, FactProvenance, ReturnBehaviorRow};
        request.cancel.checkpoint(request.deadline)?;
        let program = &request.program;
        let expected_revision = request.revision;
        let id = self.db.program_id(program)?;
        let revision = self.db.revision(id)?;
        if revision != expected_revision {
            return Err(romwright_db::DbError::StaleRevision {
                expected: expected_revision,
                actual: revision,
            }
            .into());
        }
        let stored = self.db.functions(id)?;
        let facts = self.db.return_behaviors(id)?;
        let mut entries: Vec<_> = stored
            .iter()
            .filter(|row| row.entry.space == AddressSpace::Ram)
            .map(|row| row.entry.offset)
            .collect();
        entries.sort_unstable();
        if entries.is_empty() {
            return Err(ImportError::Bad("no RAM function entries to analyze".into()).into());
        }
        let import = crate::inputs::load(&request.project_dir, &request.input, &request.config)?;
        if import.language != self.db.program_language(id)? {
            return Err(
                ImportError::Bad("nonreturn input and stored language differ".into()).into(),
            );
        }
        let mut flow = crate::native_runtime::SleighFlow::mapped(&import.cfg, &import)?;
        request.cancel.checkpoint(request.deadline)?;
        let mut known = BTreeSet::new();
        let mut blocked = BTreeSet::new();
        let mut protected = BTreeSet::new();
        for row in &facts {
            if row.function.space == AddressSpace::Ram
                && (row.provenance.kind == FactKind::Asserted || row.provenance.source != SOURCE)
            {
                protected.insert(row.function.offset);
                if row.no_return {
                    known.insert(row.function.offset);
                } else {
                    blocked.insert(row.function.offset);
                }
            }
        }
        let compiler = self.db.program_compiler(id).unwrap_or_default();
        let rules = crate::compiler::rules::Ctx::new(&compiler, &import.language, &import.format);
        for function in &stored {
            if function.entry.space == AddressSpace::Ram
                && !blocked.contains(&function.entry.offset)
                && known_no_return(&rules, &function.name)
            {
                known.insert(function.entry.offset);
            }
        }
        for hint in hints {
            if hint.space != AddressSpace::Ram || entries.binary_search(&hint.offset).is_err() {
                return Err(
                    ImportError::Bad("no-return hint is not a stored RAM function".into()).into(),
                );
            }
            if !blocked.contains(&hint.offset) {
                known.insert(hint.offset);
            }
        }
        // Our previous inferences are deliberately not seeds: new assertions
        // can invalidate them and must restore callers' returning continuations.
        let analysis = analyze(&entries, &import.mappings, &known, &blocked, |addresses| {
            request
                .cancel
                .checkpoint(request.deadline)
                .map_err(|error| ImportError::Bad(error.to_string()))?;
            let actual = self.db.revision(id)?;
            if actual != revision {
                return Err(romwright_db::DbError::StaleRevision {
                    expected: revision,
                    actual,
                }
                .into());
            }
            Ok(flow.flow(addresses))
        })?;
        let mut affected = BTreeSet::new();
        for target in analysis.non_returning.iter().copied().chain(
            facts
                .iter()
                .filter(|row| row.function.space == AddressSpace::Ram)
                .map(|row| row.function.offset),
        ) {
            if let Some(callers) = analysis.callers.get(&target) {
                affected.extend(callers);
            }
        }
        let mut unknown: Vec<_> = stored
            .into_iter()
            .filter(|row| row.entry.space != AddressSpace::Ram)
            .map(|row| row.entry)
            .collect();
        unknown.extend(
            analysis
                .functions
                .iter()
                .filter(|(entry, flow)| {
                    !flow.complete
                        && !analysis.non_returning.contains(entry)
                        && !blocked.contains(entry)
                })
                .map(|(&entry, _)| Address::ram(entry)),
        );
        let sizes = affected
            .iter()
            .filter_map(|entry| {
                let flow = &analysis.functions[entry];
                flow.complete.then(|| (Address::ram(*entry), flow.size))
            })
            .collect();
        let sites: BTreeSet<_> = analysis
            .call_sites
            .iter()
            .copied()
            .filter(|site| {
                analysis.call_owners[site]
                    .iter()
                    .any(|entry| affected.contains(entry))
            })
            .collect();
        let update = romwright_db::ReturnFlowUpdate {
            function_sizes: sizes,
            call_sites: sites.iter().copied().map(Address::ram).collect(),
            calls: analysis
                .calls
                .iter()
                .filter(|(from, _)| sites.contains(from))
                .map(|&(from, to)| (Address::ram(from), Address::ram(to)))
                .collect(),
        };
        let rows: Vec<_> = analysis
            .non_returning
            .iter()
            .filter(|entry| !protected.contains(entry))
            .map(|&entry| ReturnBehaviorRow {
                function: Address::ram(entry),
                no_return: true,
                provenance: FactProvenance {
                    kind: FactKind::Inferred,
                    source: SOURCE.into(),
                    confidence: None,
                },
            })
            .collect();
        let published = request.cancel.publish(request.deadline, || {
            Ok(self
                .db
                .publish_return_analysis(id, revision, SOURCE, &rows, &update)?)
        })?;
        Ok(NonReturnInferenceReport {
            changed: published.changed,
            rediscovered: update
                .function_sizes
                .into_iter()
                .map(|(address, _)| address)
                .collect(),
            unknown,
            revision: published.revision,
        })
    }
}
