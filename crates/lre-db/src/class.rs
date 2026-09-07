//! Recovered C++ classes are owned facts: a type_info address, the primary
//! vtable it belongs to, and the bases the ABI records for it.
use super::{
    DbError, ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance,
    validate_fact_provenance,
};
use lre_model::{ClassBase, ClassKind, ClassRow, FactKind, ProgramId};
use rusqlite::params;

impl ProjectDb {
    pub fn classes(&self, program: ProgramId) -> Result<Vec<ClassRow>> {
        let mut statement = self.conn.prepare(
            "SELECT typeinfo, vtable, name, mangled, kind, vtable_slots,
                    provenance, provenance_kind, confidence
             FROM classes WHERE program_id = ?1 ORDER BY typeinfo",
        )?;
        let mut classes = statement
            .query_map(params![program.0], |row| {
                let kind: String = row.get(4)?;
                Ok(ClassRow {
                    typeinfo: addr_from_cell(row.get(0)?, 0)?,
                    vtable: addr_from_cell(row.get(1)?, 1)?,
                    name: row.get(2)?,
                    mangled: row.get(3)?,
                    kind: ClassKind::parse(&kind).ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "unknown class kind",
                            )),
                        )
                    })?,
                    vtable_slots: row.get(5)?,
                    bases: Vec::new(),
                    provenance: map_fact_provenance(row, 6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut statement = self.conn.prepare(
            "SELECT typeinfo, base_typeinfo, base_mangled, base_offset, virtual_base,
                    public_base
             FROM class_bases WHERE program_id = ?1 ORDER BY typeinfo, ordinal",
        )?;
        let bases = statement
            .query_map(params![program.0], |row| {
                Ok((
                    addr_from_cell(row.get(0)?, 0)?,
                    ClassBase {
                        typeinfo: addr_from_cell(row.get(1)?, 1)?,
                        mangled: row.get(2)?,
                        offset: row.get(3)?,
                        virtual_base: row.get(4)?,
                        public_base: row.get(5)?,
                    },
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (owner, base) in bases {
            if let Some(class) = classes.iter_mut().find(|class| class.typeinfo == owner) {
                class.bases.push(base);
            }
        }
        Ok(classes)
    }

    /// Replaces exactly this producer's classes and their bases. Another
    /// producer's rows and analyst assertions stay; an unchanged pass bumps no
    /// revision.
    pub fn replace_inferred_classes(
        &self,
        program: ProgramId,
        source: &str,
        rows: &[ClassRow],
    ) -> Result<()> {
        if source.trim().is_empty() {
            return Err(DbError::InvalidFactProvenance(
                "inference source is empty".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            validate_fact_provenance(&row.provenance)?;
            if row.provenance.kind != FactKind::Inferred || row.provenance.source != source {
                return Err(DbError::InvalidFactProvenance(format!(
                    "class fact does not belong to inference source {source}"
                )));
            }
            if row.mangled.trim().is_empty() || row.name.trim().is_empty() {
                return Err(DbError::InvalidFactProvenance(
                    "a class needs a mangled type name".into(),
                ));
            }
            if !seen.insert(addr_cell(&row.typeinfo)) {
                return Err(DbError::InvalidFactProvenance(
                    "duplicate class for one type_info".into(),
                ));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let before = owned(&tx, program, source)?;
        tx.execute(
            "DELETE FROM class_bases WHERE program_id = ?1 AND typeinfo IN
                 (SELECT typeinfo FROM classes WHERE program_id = ?1 AND provenance = ?2
                      AND provenance_kind = 'inferred')",
            params![program.0, source],
        )?;
        tx.execute(
            "DELETE FROM classes WHERE program_id = ?1 AND provenance = ?2
                 AND provenance_kind = 'inferred'",
            params![program.0, source],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO classes(program_id, typeinfo, vtable, name, mangled, kind,
                     vtable_slots, provenance, provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'inferred', ?9)
                 ON CONFLICT(program_id, typeinfo) DO NOTHING",
            )?;
            let mut base = tx.prepare(
                "INSERT INTO class_bases(program_id, typeinfo, ordinal, base_typeinfo,
                     base_mangled, base_offset, virtual_base, public_base)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for row in rows {
                let inserted = insert.execute(params![
                    program.0,
                    addr_cell(&row.typeinfo),
                    addr_cell(&row.vtable),
                    row.name,
                    row.mangled,
                    row.kind.as_str(),
                    row.vtable_slots,
                    row.provenance.source,
                    row.provenance.confidence,
                ])?;
                if inserted == 0 {
                    continue; // Another owner holds this type_info.
                }
                for (ordinal, item) in row.bases.iter().enumerate() {
                    base.execute(params![
                        program.0,
                        addr_cell(&row.typeinfo),
                        ordinal as i64,
                        addr_cell(&item.typeinfo),
                        item.mangled,
                        item.offset,
                        item.virtual_base,
                        item.public_base,
                    ])?;
                }
            }
        }
        if owned(&tx, program, source)? != before {
            self.bump_and_record(&tx, program, "replace-inferred-classes", source)?;
        }
        tx.commit()?;
        Ok(())
    }
}

type Fact = (String, String, String, String, i64);

fn owned(tx: &rusqlite::Transaction<'_>, program: ProgramId, source: &str) -> Result<Vec<Fact>> {
    let mut statement = tx.prepare(
        "SELECT c.typeinfo, c.vtable, c.mangled, c.kind, c.vtable_slots FROM classes c
         WHERE c.program_id = ?1 AND c.provenance = ?2 AND c.provenance_kind = 'inferred'
         ORDER BY c.typeinfo",
    )?;
    Ok(statement
        .query_map(params![program.0, source], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lre_model::{Address, FactProvenance, Provenance};

    const SOURCE: &str = "itanium-rtti";

    fn class(typeinfo: u64, mangled: &str, source: &str, bases: Vec<ClassBase>) -> ClassRow {
        ClassRow {
            typeinfo: Address::ram(typeinfo),
            vtable: Address::ram(typeinfo + 0x100),
            name: mangled.trim_start_matches(|c: char| c.is_ascii_digit()).into(),
            mangled: mangled.into(),
            kind: if bases.is_empty() {
                ClassKind::Plain
            } else {
                ClassKind::SingleBase
            },
            vtable_slots: 3,
            bases,
            provenance: FactProvenance {
                kind: FactKind::Inferred,
                source: source.into(),
                confidence: None,
            },
        }
    }

    fn base(typeinfo: u64, mangled: &str) -> ClassBase {
        ClassBase {
            typeinfo: Address::ram(typeinfo),
            mangled: mangled.into(),
            offset: 0,
            virtual_base: false,
            public_base: true,
        }
    }

    fn program(db: &ProjectDb) -> ProgramId {
        db.upsert_program(
            "classes",
            "x86:LE:64:default",
            &Provenance {
                producer: "test".into(),
                upstream_version: "test".into(),
            },
        )
        .unwrap()
    }

    #[test]
    fn owned_classes_refresh_with_their_bases() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = program(&db);
        let derived = class(0x2000, "6Middle", SOURCE, vec![base(0x1000, "4Base")]);
        db.replace_inferred_classes(id, SOURCE, &[class(0x1000, "4Base", SOURCE, vec![]), derived.clone()])
            .unwrap();
        assert_eq!(db.classes(id).unwrap().len(), 2);
        let stored = db.classes(id).unwrap();
        assert_eq!(stored[1], derived);
        assert_eq!(stored[0].bases, Vec::new());
        // A later pass with one class drops the other class and its bases.
        db.replace_inferred_classes(id, SOURCE, &[class(0x1000, "4Base", SOURCE, vec![])])
            .unwrap();
        let stored = db.classes(id).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].bases.is_empty());
        let other = class(0x3000, "5Other", "other-pass", vec![]);
        db.replace_inferred_classes(id, "other-pass", &[other.clone()])
            .unwrap();
        db.replace_inferred_classes(id, SOURCE, &[]).unwrap();
        assert_eq!(db.classes(id).unwrap(), vec![other]);
    }

    #[test]
    fn repeated_passes_are_silent_and_malformed_rows_rejected() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = program(&db);
        let fact = class(0x1000, "4Base", SOURCE, vec![base(0x900, "4Root")]);
        db.replace_inferred_classes(id, SOURCE, &[fact.clone()]).unwrap();
        let revision = db.revision(id).unwrap();
        db.replace_inferred_classes(id, SOURCE, &[fact.clone()]).unwrap();
        assert_eq!(db.revision(id).unwrap(), revision);
        let mut nameless = fact.clone();
        nameless.mangled = "  ".into();
        for invalid in [
            vec![fact.clone(), fact.clone()],
            vec![class(0x1000, "4Base", "elsewhere", vec![])],
            vec![nameless],
        ] {
            assert!(matches!(
                db.replace_inferred_classes(id, SOURCE, &invalid),
                Err(DbError::InvalidFactProvenance(_))
            ));
        }
        assert_eq!(db.classes(id).unwrap(), vec![fact]);
        assert_eq!(db.revision(id).unwrap(), revision);
    }
}
