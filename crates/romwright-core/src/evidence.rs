//! `function_evidence`: every fact that says an address is a function.
use romwright_model::evidence::{FunctionEvidence, IncomingEvidence, Standing};
use romwright_model::provenance;

/// Sample size per group of incoming references: enough to follow, few
/// enough that a function called from thousands of sites stays one screen.
const SAMPLE: usize = 4;

impl crate::Core {
    /// The function holding `offset`, and every fact that makes it one.
    /// `None` when no function covers the address.
    pub fn function_evidence(&self, program: &str, offset: u64) -> crate::Result<Option<FunctionEvidence>> {
        let id = self.db.program_id(program)?;
        let Some(function) = self.db.function_at(id, offset)? else {
            return Ok(None);
        };
        let key = function.entry.to_string();
        let producer = self.db.producer(id, &key)?.unwrap_or_else(|| "unknown".into());
        let state = self.db.function_analysis_state(id, &key)?;
        let symbol = self
            .db
            .symbols(id)?
            .into_iter()
            .find(|symbol| symbol.address == function.entry && !symbol.external)
            .map(|symbol| (symbol.name, symbol.source));
        let mut groups: std::collections::BTreeMap<(String, String), IncomingEvidence> =
            std::collections::BTreeMap::new();
        for xref in self.db.xrefs_to(id, &function.entry)? {
            let source = xref.provenance.source.clone();
            let group = groups
                .entry((xref.kind.clone(), source.clone()))
                .or_insert_with(|| IncomingEvidence {
                    kind: xref.kind.clone(),
                    evidence: provenance::evidence(&source).map(|kind| kind.as_str().to_string()),
                    source,
                    count: 0,
                    from: Vec::new(),
                });
            group.count += 1;
            if group.from.len() < SAMPLE {
                group.from.push(xref.from.clone());
            }
        }
        let incoming: Vec<IncomingEvidence> = groups.into_values().collect();
        let thunk = self
            .db
            .thunks(id)?
            .into_iter()
            .find(|thunk| thunk.function == function.entry);
        let signatures: Vec<_> = self
            .db
            .signature_matches(id)?
            .into_iter()
            .filter(|row| row.function == function.entry)
            .collect();
        let reached = incoming.iter().any(|group| {
            group.kind.ends_with("CALL") || group.kind.ends_with("JUMP") || group.kind == "DATA"
        });
        let standing = if symbol.is_some() || thunk.is_some() || matches!(producer.as_str(), "symbol" | "thunk") {
            Standing::Declared
        } else if reached {
            Standing::Attested
        } else if producer == "pattern" {
            Standing::PatternOnly
        } else {
            Standing::Unattested
        };
        Ok(Some(FunctionEvidence {
            program: program.to_string(),
            entry: function.entry,
            name: function.name,
            size: function.size,
            producer,
            analysis_state: state.as_ref().map(|(state, _)| state.clone()),
            analysed_revision: state.map(|(_, revision)| revision),
            symbol,
            incoming,
            thunk,
            signatures,
            traced: function.traced,
            standing,
        }))
    }
}
