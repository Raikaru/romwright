//! Return behavior is a separate owned fact, not an inferred function signature.
use super::{
    DbError, ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance,
    validate_fact_provenance,
};
use romwright_model::{Address, FactKind, ProgramId, ReturnBehaviorRow};
use rusqlite::{Transaction, params};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Flow-proven updates; sites are instruction addresses, never an entry-distance range.
pub struct ReturnFlowUpdate {
    pub function_sizes: Vec<(Address, u64)>,
    pub call_sites: Vec<Address>,
    pub calls: Vec<(Address, Address)>,
}

pub struct ReturnPublication {
    pub changed: Vec<Address>,
    pub revision: u64,
}

impl ProjectDb {
    /// An assertion can override either value; inference cannot override it.
    pub fn set_return_behavior(&self, program: ProgramId, row: &ReturnBehaviorRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        if insert_return_behavior(&tx, program, row)? {
            self.bump_and_record(&tx, program, "return-behavior", &row.function.hex())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn return_behaviors(&self, program: ProgramId) -> Result<Vec<ReturnBehaviorRow>> {
        let mut statement = self.conn.prepare(
            "SELECT function, no_return, provenance, provenance_kind, confidence
             FROM return_behaviors WHERE program_id = ?1 ORDER BY function",
        )?;
        Ok(statement
            .query_map(params![program.0], |row| {
                Ok(ReturnBehaviorRow {
                    function: addr_from_cell(row.get(0)?, 0)?,
                    no_return: row.get(1)?,
                    provenance: map_fact_provenance(row, 2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replaces only this producer's inferred return facts, together with
    /// completed caller flow. Assertions and other producers remain untouched.
    pub fn publish_return_analysis(
        &self,
        program: ProgramId,
        expected: u64,
        source: &str,
        rows: &[ReturnBehaviorRow],
        flow: &ReturnFlowUpdate,
    ) -> Result<ReturnPublication> {
        if source.trim().is_empty()
            || rows.iter().any(|row| {
                row.provenance.kind != FactKind::Inferred
                    || row.provenance.source != source
                    || !row.no_return
            })
        {
            return Err(DbError::InvalidFactProvenance(
                "nonreturn batch must contain owned positive inferences".into(),
            ));
        }
        let incoming: HashMap<_, _> = rows.iter().map(|row| (&row.function, row)).collect();
        if incoming.len() != rows.len()
            || flow
                .function_sizes
                .iter()
                .any(|(address, size)| *size == 0 || address.offset.checked_add(*size).is_none())
        {
            return Err(DbError::InvalidReturnAnalysis(
                "duplicate facts or invalid function extent".into(),
            ));
        }
        let sites: HashSet<_> = flow.call_sites.iter().map(addr_cell).collect();
        let calls: BTreeSet<_> = flow
            .calls
            .iter()
            .map(|(from, to)| (addr_cell(from), addr_cell(to)))
            .collect();
        if calls.iter().any(|(from, _)| !sites.contains(from)) {
            return Err(DbError::InvalidReturnAnalysis(
                "call lies outside refreshed sites".into(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        let actual = self.revision(program)?;
        if actual != expected {
            return Err(DbError::StaleRevision { expected, actual });
        }
        let previous = self.return_behaviors(program)?;
        let by_address: HashMap<_, _> = previous.iter().map(|row| (&row.function, row)).collect();
        let mut changed = Vec::new();
        for row in rows {
            if by_address.get(&row.function).is_some_and(|old| {
                old.provenance.kind == FactKind::Asserted || old.provenance.source != source
            }) {
                validate_fact_provenance(&row.provenance)?;
                continue;
            }
            if insert_return_behavior(&tx, program, row)? {
                changed.push(row.function.clone());
            }
        }
        for old in &previous {
            if old.provenance.kind == FactKind::Inferred
                && old.provenance.source == source
                && !incoming.contains_key(&old.function)
            {
                tx.execute(
                    "DELETE FROM return_behaviors WHERE program_id = ?1 AND function = ?2",
                    params![program.0, addr_cell(&old.function)],
                )?;
                changed.push(old.function.clone());
            }
        }
        let mut mutations = changed.len();
        {
            let mut update = tx.prepare(
                "UPDATE functions SET size = ?3 WHERE program_id = ?1 AND entry = ?2 AND size IS NOT ?3",
            )?;
            for (address, size) in &flow.function_sizes {
                mutations += update.execute(params![program.0, addr_cell(address), size])?;
            }
        }
        if !sites.is_empty() {
            let mut owned = BTreeSet::new();
            let mut protected = BTreeSet::new();
            let mut query = tx.prepare(
                "SELECT src, dst, provenance = 'native-import' AND provenance_kind = 'inferred'
                 FROM xrefs WHERE program_id = ?1 AND kind = 'UNCONDITIONAL_CALL'",
            )?;
            let mut cursor = query.query(params![program.0])?;
            while let Some(row) = cursor.next()? {
                let from: String = row.get(0)?;
                if sites.contains(&from) {
                    let key = (from, row.get::<_, String>(1)?);
                    if row.get::<_, bool>(2)? {
                        owned.insert(key);
                    } else {
                        protected.insert(key);
                    }
                }
            }
            drop(cursor);
            drop(query);
            let mut delete = tx.prepare(
                "DELETE FROM xrefs WHERE program_id = ?1 AND src = ?2 AND dst = ?3
                 AND kind = 'UNCONDITIONAL_CALL' AND provenance = 'native-import'
                 AND provenance_kind = 'inferred'",
            )?;
            for (from, to) in owned.difference(&calls) {
                mutations += delete.execute(params![program.0, from, to])?;
            }
            let mut insert = tx.prepare(
                "INSERT INTO xrefs(program_id, src, dst, kind, provenance, provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, 'UNCONDITIONAL_CALL', 'native-import', 'inferred', NULL)",
            )?;
            for (from, to) in calls
                .difference(&owned)
                .filter(|key| !protected.contains(*key))
            {
                mutations += insert.execute(params![program.0, from, to])?;
            }
        }
        let revision = if mutations != 0 {
            self.bump_and_record(&tx, program, "infer-nonreturning", &mutations.to_string())?;
            self.revision(program)?
        } else {
            expected
        };
        tx.commit()?;
        Ok(ReturnPublication { changed, revision })
    }
}

fn insert_return_behavior(
    tx: &Transaction<'_>,
    program: ProgramId,
    row: &ReturnBehaviorRow,
) -> Result<bool> {
    let ownership = validate_fact_provenance(&row.provenance)?;
    Ok(tx.execute(
        "INSERT INTO return_behaviors(program_id, function, no_return, provenance, provenance_kind, confidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(program_id, function) DO UPDATE SET
             no_return = excluded.no_return,
             provenance = excluded.provenance,
             provenance_kind = excluded.provenance_kind,
             confidence = excluded.confidence
         WHERE (return_behaviors.provenance_kind = 'inferred' OR excluded.provenance_kind = 'asserted')
           AND (return_behaviors.no_return IS NOT excluded.no_return
             OR return_behaviors.provenance IS NOT excluded.provenance
             OR return_behaviors.provenance_kind IS NOT excluded.provenance_kind
             OR return_behaviors.confidence IS NOT excluded.confidence)",
        params![program.0, addr_cell(&row.function), row.no_return, row.provenance.source,
            ownership, row.provenance.confidence],
    )? != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbError;
    use romwright_model::{Address, FactKind, FactProvenance, FunctionRow, Provenance, XrefRow};

    #[test]
    fn publication_is_atomic_scoped_revision_checked_and_retractable() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db
            .upsert_program(
                "return-publication",
                "x86:LE:64:default",
                &Provenance {
                    producer: "test".into(),
                    upstream_version: "test".into(),
                },
            )
            .unwrap();
        db.replace_functions(
            id,
            &[FunctionRow {
                entry: Address::ram(0x1000),
                name: "analyst_name".into(),
                size: 9,
                signature: Some("int analyst_name(void)".into()),
                traced: false,
            calling_convention: None,
            }],
        )
        .unwrap();
        let fact = |address, no_return, kind, source: &str| ReturnBehaviorRow {
            function: Address::ram(address),
            no_return,
            provenance: FactProvenance {
                kind,
                source: source.into(),
                confidence: None,
            },
        };
        let asserted = fact(0x4000, false, FactKind::Asserted, "analyst");
        let foreign = fact(0x3000, true, FactKind::Inferred, "other-producer");
        db.set_return_behavior(id, &asserted).unwrap();
        db.set_return_behavior(id, &foreign).unwrap();
        db.replace_xrefs(
            id,
            &[
                XrefRow {
                    from: Address::ram(0x1005),
                    to: Address::ram(0x3000),
                    kind: "UNCONDITIONAL_CALL".into(),
                    function: None,
                    provenance: FactProvenance {
                        kind: FactKind::Inferred,
                        source: "native-import".into(),
                        confidence: None,
                    },
                },
                XrefRow {
                    from: Address::ram(0x1005),
                    to: Address::ram(0x4000),
                    kind: "UNCONDITIONAL_CALL".into(),
                    function: None,
                    provenance: FactProvenance {
                        kind: FactKind::Asserted,
                        source: "analyst".into(),
                        confidence: None,
                    },
                },
                XrefRow {
                    from: Address::ram(0x1006),
                    to: Address::ram(0x5000),
                    kind: "DATA".into(),
                    function: None,
                    provenance: FactProvenance {
                        kind: FactKind::Inferred,
                        source: "native-import".into(),
                        confidence: None,
                    },
                },
            ],
        )
        .unwrap();
        let revision = db.revision(id).unwrap();
        let recovered = fact(0x2000, true, FactKind::Inferred, "flow");
        let rows = [
            recovered.clone(),
            fact(0x4000, true, FactKind::Inferred, "flow"),
        ];
        let update = ReturnFlowUpdate {
            function_sizes: vec![(Address::ram(0x1000), 5)],
            call_sites: vec![Address::ram(0x1005)],
            calls: vec![],
        };
        let result = db
            .publish_return_analysis(id, revision, "flow", &rows, &update)
            .unwrap();
        assert_eq!(result.changed, vec![recovered.function.clone()]);
        assert_eq!(result.revision, revision + 1);
        let function = &db.functions(id).unwrap()[0];
        assert_eq!(function.name, "analyst_name");
        assert_eq!(
            function.signature.as_deref(),
            Some("int analyst_name(void)")
        );
        assert_eq!(function.size, 5);
        let xrefs = db.xrefs(id).unwrap();
        assert_eq!(xrefs.len(), 2);
        assert!(
            xrefs
                .iter()
                .any(|row| row.provenance.kind == FactKind::Asserted)
        );
        assert!(xrefs.iter().any(|row| row.kind == "DATA"));
        assert_eq!(
            db.return_behaviors(id).unwrap(),
            vec![recovered.clone(), foreign.clone(), asserted.clone()]
        );
        let repeat = db
            .publish_return_analysis(id, result.revision, "flow", &rows, &update)
            .unwrap();
        assert!(repeat.changed.is_empty());
        assert_eq!(repeat.revision, result.revision);
        assert!(matches!(
            db.publish_return_analysis(id, revision, "flow", &[], &update),
            Err(DbError::StaleRevision { .. })
        ));
        let mut invalid = fact(0x2020, true, FactKind::Inferred, "flow");
        invalid.provenance.confidence = Some(f64::NAN);
        assert!(
            db.publish_return_analysis(
                id,
                result.revision,
                "flow",
                &[fact(0x2010, true, FactKind::Inferred, "flow"), invalid],
                &update
            )
            .is_err()
        );
        assert_eq!(
            db.return_behaviors(id).unwrap(),
            vec![recovered.clone(), foreign.clone(), asserted.clone()]
        );
        assert_eq!(db.revision(id).unwrap(), result.revision);
        let restore = ReturnFlowUpdate {
            function_sizes: vec![(Address::ram(0x1000), 9)],
            call_sites: vec![Address::ram(0x1005)],
            calls: vec![(Address::ram(0x1005), Address::ram(0x3000))],
        };
        let retracted = db
            .publish_return_analysis(id, result.revision, "flow", &[], &restore)
            .unwrap();
        assert_eq!(retracted.changed, vec![recovered.function]);
        assert_eq!(db.return_behaviors(id).unwrap(), vec![foreign, asserted]);
        assert_eq!(db.functions(id).unwrap()[0].size, 9);
        assert_eq!(db.xrefs(id).unwrap().len(), 3);
    }
}
