//! Revision-atomic orchestration over native flow evidence and owned return facts.
use crate::native::{self, ImportError, nonreturn::analyze};
use std::collections::BTreeSet;

const SOURCE: &str = "native-flow nonreturn recovery";

#[derive(serde::Serialize)]
pub struct NonReturnInferenceReport {
    pub changed: Vec<lre_model::Address>,
    pub rediscovered: Vec<lre_model::Address>,
    pub unknown: Vec<lre_model::Address>,
    pub revision: u64,
}

impl crate::Core {
    pub fn return_behaviors(
        &self,
        program: &str,
    ) -> crate::Result<Vec<lre_model::ReturnBehaviorRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.return_behaviors(id)?)
    }

    /// Analyze a byte snapshot, then publish facts and completed caller flows
    /// against the input store revision. Partial native output is never proof.
    pub fn infer_nonreturning(
        &self,
        binary: &std::path::Path,
        program: &str,
    ) -> crate::Result<NonReturnInferenceReport> {
        use lre_model::{Address, AddressSpace, FactKind, FactProvenance, ReturnBehaviorRow};
        let id = self.db.program_id(program)?;
        let revision = self.db.revision(id)?;
        let stored = self.db.functions(id)?;
        let facts = self.db.return_behaviors(id)?;
        let entries: Vec<_> = stored
            .iter()
            .filter(|row| row.entry.space == AddressSpace::Ram)
            .map(|row| row.entry.offset)
            .collect();
        if entries.is_empty() {
            return Err(ImportError::Bad("no RAM function entries to analyze".into()).into());
        }
        let mut import = native::parse_native(&std::fs::read(binary)?)?;
        if import.language != self.db.program_language(id)? {
            return Err(
                ImportError::Bad("nonreturn input and stored language differ".into()).into(),
            );
        }
        import.cfg = self.config.clone();
        import.cfg.language_id = import.language.clone();
        import.binary = binary.canonicalize()?;
        let mut session = crate::native_runtime::ConsoleSession::new(&import.cfg)?;
        session.load_mapped(&import)?;
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
        // Our previous inferences are deliberately not seeds: new assertions
        // can invalidate them and must restore callers' returning continuations.
        let analysis = analyze(&entries, &import.mappings, &known, &blocked, |addresses| {
            let actual = self.db.revision(id)?;
            if actual != revision {
                return Err(lre_db::DbError::StaleRevision {
                    expected: revision,
                    actual,
                }
                .into());
            }
            session
                .flow_batch(addresses)
                .map_err(|error| ImportError::Bad(error.to_string()))
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
                .filter(|(_, flow)| !flow.complete)
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
        let update = lre_db::ReturnFlowUpdate {
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
        let published = self
            .db
            .publish_return_analysis(id, revision, SOURCE, &rows, &update)?;
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