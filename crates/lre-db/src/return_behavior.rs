//! Return behavior is a separate owned fact, not an inferred function signature.
use super::{
    ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance, validate_fact_provenance,
};
use lre_model::{ProgramId, ReturnBehaviorRow};
use rusqlite::{Transaction, params};

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
    use lre_model::{Address, FactKind, FactProvenance, FunctionRow, Provenance, XrefRow};

    #[test]
    fn publication_is_atomic_scoped_revision_checked_and_retractable() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("return-publication", "x86:LE:64:default",
            &Provenance { producer: "test".into(), upstream_version: "test".into() }).unwrap();
        db.replace_functions(id, &[FunctionRow {
            entry: Address::ram(0x1000), name: "analyst_name".into(), size: 9,
            signature: Some("int analyst_name(void)".into()), calling_convention: None,
        }]).unwrap();
        let fact = |address, no_return, kind, source: &str| ReturnBehaviorRow {
            function: Address::ram(address), no_return,
            provenance: FactProvenance { kind, source: source.into(), confidence: None },
        };
        let asserted = fact(0x4000, false, FactKind::Asserted, "analyst");
        let foreign = fact(0x3000, true, FactKind::Inferred, "other-producer");
        db.set_return_behavior(id, &asserted).unwrap();
        db.set_return_behavior(id, &foreign).unwrap();
        db.replace_xrefs(id, &[
            XrefRow { from: Address::ram(0x1005), to: Address::ram(0x3000),
                kind: "UNCONDITIONAL_CALL".into(), function: None,
                provenance: FactProvenance { kind: FactKind::Inferred,
                    source: "native-import".into(), confidence: None } },
            XrefRow { from: Address::ram(0x1005), to: Address::ram(0x4000),
                kind: "UNCONDITIONAL_CALL".into(), function: None,
                provenance: FactProvenance { kind: FactKind::Asserted,
                    source: "analyst".into(), confidence: None } },
            XrefRow { from: Address::ram(0x1006), to: Address::ram(0x5000),
                kind: "DATA".into(), function: None,
                provenance: FactProvenance { kind: FactKind::Inferred,
                    source: "native-import".into(), confidence: None } },
        ]).unwrap();
        let revision = db.revision(id).unwrap();
        let recovered = fact(0x2000, true, FactKind::Inferred, "flow");
        let rows = [recovered.clone(), fact(0x4000, true, FactKind::Inferred, "flow")];
        let update = ReturnFlowUpdate {
            function_sizes: vec![(Address::ram(0x1000), 5)],
            call_sites: vec![Address::ram(0x1005)], calls: vec![],
        };
        let result = db.publish_return_analysis(id, revision, "flow", &rows, &update).unwrap();
        assert_eq!(result.changed, vec![recovered.function.clone()]);
        assert_eq!(result.revision, revision + 1);
        let function = &db.functions(id).unwrap()[0];
        assert_eq!(function.name, "analyst_name");
        assert_eq!(function.signature.as_deref(), Some("int analyst_name(void)"));
        assert_eq!(function.size, 5);
        let xrefs = db.xrefs(id).unwrap();
        assert_eq!(xrefs.len(), 2);
        assert!(xrefs.iter().any(|row| row.provenance.kind == FactKind::Asserted));
        assert!(xrefs.iter().any(|row| row.kind == "DATA"));
        assert_eq!(db.return_behaviors(id).unwrap(), vec![recovered.clone(), foreign.clone(), asserted.clone()]);
        let repeat = db.publish_return_analysis(id, result.revision, "flow", &rows, &update).unwrap();
        assert!(repeat.changed.is_empty());
        assert_eq!(repeat.revision, result.revision);
        assert!(matches!(db.publish_return_analysis(id, revision, "flow", &[], &update),
            Err(DbError::StaleRevision { .. })));
        let mut invalid = fact(0x2020, true, FactKind::Inferred, "flow");
        invalid.provenance.confidence = Some(f64::NAN);
        assert!(db.publish_return_analysis(id, result.revision, "flow",
            &[fact(0x2010, true, FactKind::Inferred, "flow"), invalid], &update).is_err());
        assert_eq!(db.return_behaviors(id).unwrap(), vec![recovered.clone(), foreign.clone(), asserted.clone()]);
        assert_eq!(db.revision(id).unwrap(), result.revision);
        let restore = ReturnFlowUpdate {
            function_sizes: vec![(Address::ram(0x1000), 9)],
            call_sites: vec![Address::ram(0x1005)],
            calls: vec![(Address::ram(0x1005), Address::ram(0x3000))],
        };
        let retracted = db.publish_return_analysis(id, result.revision, "flow", &[], &restore).unwrap();
        assert_eq!(retracted.changed, vec![recovered.function]);
        assert_eq!(db.return_behaviors(id).unwrap(), vec![foreign, asserted]);
        assert_eq!(db.functions(id).unwrap()[0].size, 9);
        assert_eq!(db.xrefs(id).unwrap().len(), 3);
    }
}
