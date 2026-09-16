//! Class identity follows a real ABI descriptor when present, otherwise the
//! encoded type name. Missing RTTI is not the address zero.
use super::{
    DbError, ProjectDb, Result, addr_cell, addr_from_cell, map_fact_provenance,
    validate_fact_provenance,
};
use romwright_model::{ClassBase, ClassKind, ClassRow, FactKind, ProgramId};
use rusqlite::params;

impl ProjectDb {
    pub fn classes(&self, program: ProgramId) -> Result<Vec<ClassRow>> {
        let mut statement = self.conn.prepare(
            "SELECT typeinfo, vtable, name, mangled, kind, vtable_slots,
                    provenance, provenance_kind, confidence, identity
             FROM classes WHERE program_id = ?1 ORDER BY identity",
        )?;
        let mut classes = statement
            .query_map(params![program.0], |row| {
                let kind: String = row.get(4)?;
                Ok((row.get::<_, String>(9)?, ClassRow {
                    typeinfo: row.get::<_, Option<String>>(0)?
                        .map(|value| addr_from_cell(value, 0)).transpose()?,
                    vtable: row.get::<_, Option<String>>(1)?
                        .map(|value| addr_from_cell(value, 1)).transpose()?,
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
                }))
            })?
            .collect::<std::result::Result<std::collections::BTreeMap<_, _>, _>>()?;
        let mut statement = self.conn.prepare(
            "SELECT identity, base_typeinfo, base_mangled, base_offset, virtual_base,
                    public_base
             FROM class_bases WHERE program_id = ?1 ORDER BY identity, ordinal",
        )?;
        let bases = statement
            .query_map(params![program.0], |row| {
                Ok((
                    row.get::<_, String>(0)?,
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
            if let Some(class) = classes.get_mut(&owner) {
                class.bases.push(base);
            }
        }
        Ok(classes.into_values().collect())
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
            if row.vtable.is_none() && row.vtable_slots != 0 {
                return Err(DbError::InvalidFactProvenance(
                    "virtual slots require a proven vtable".into(),
                ));
            }
            if !seen.insert(identity(row)) {
                return Err(DbError::InvalidFactProvenance(
                    "duplicate class identity".into(),
                ));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let owned = || -> Result<Vec<ClassRow>> {
            Ok(self.classes(program)?.into_iter().filter(|row|
                row.provenance.kind == FactKind::Inferred && row.provenance.source == source
            ).collect())
        };
        let before = owned()?;
        tx.execute(
            "DELETE FROM class_bases WHERE program_id = ?1 AND identity IN
                 (SELECT identity FROM classes WHERE program_id = ?1 AND provenance = ?2
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
                "INSERT INTO classes(program_id, identity, typeinfo, vtable, name, mangled, kind,
                     vtable_slots, provenance, provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'inferred', ?10)
                 ON CONFLICT(program_id, identity) DO NOTHING",
            )?;
            let mut base = tx.prepare(
                "INSERT INTO class_bases(program_id, identity, ordinal, base_typeinfo,
                     base_mangled, base_offset, virtual_base, public_base)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for row in rows {
                let inserted = insert.execute(params![
                    program.0,
                    identity(row),
                    row.typeinfo.as_ref().map(addr_cell),
                    row.vtable.as_ref().map(addr_cell),
                    row.name,
                    row.mangled,
                    row.kind.as_str(),
                    row.vtable_slots,
                    row.provenance.source,
                    row.provenance.confidence,
                ])?;
                if inserted == 0 {
                    continue; // Another owner holds this class identity.
                }
                for (ordinal, item) in row.bases.iter().enumerate() {
                    base.execute(params![
                        program.0,
                        identity(row),
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
        if owned()? != before {
            self.bump_and_record(&tx, program, "replace-inferred-classes", source)?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn identity(row: &ClassRow) -> String {
    match &row.typeinfo {
        Some(address) => format!("typeinfo:{}", addr_cell(address)),
        None => format!("name:{}", row.mangled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{Address, FactProvenance, Provenance};

    const SOURCE: &str = "itanium-rtti";

    fn class(typeinfo: u64, mangled: &str, source: &str, bases: Vec<ClassBase>) -> ClassRow {
        ClassRow {
            typeinfo: Some(Address::ram(typeinfo)),
            vtable: Some(Address::ram(typeinfo + 0x100)),
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

    #[test]
    fn rtti_less_classes_keep_distinct_names_without_fabricated_addresses() {
        let db = ProjectDb::open_in_memory().unwrap();
        let program = program(&db);
        let mut rows = vec![
            class(0, "1A", SOURCE, vec![]),
            class(0, "1B", SOURCE, vec![]),
        ];
        for row in &mut rows {
            row.typeinfo = None;
            row.vtable = None;
            row.vtable_slots = 0;
        }
        db.replace_inferred_classes(program, SOURCE, &rows).unwrap();
        assert_eq!(db.classes(program).unwrap(), rows);
        let revision = db.revision(program).unwrap();
        db.replace_inferred_classes(program, SOURCE, &rows).unwrap();
        assert_eq!(db.revision(program).unwrap(), revision);
        rows[0].name = "renamed".into();
        db.replace_inferred_classes(program, SOURCE, &rows).unwrap();
        assert!(db.revision(program).unwrap() > revision);
        assert_eq!(db.classes(program).unwrap(), rows);
    }

    #[test]
    fn populated_v24_migration_preserves_rtti_bases_and_removes_fake_identity() {
        let db = ProjectDb::open_in_memory().unwrap();
        let program = program(&db);
        let original = class(0x1000, "7Derived", SOURCE, vec![base(0x800, "4Base")]);
        db.replace_inferred_classes(program, SOURCE, std::slice::from_ref(&original)).unwrap();
        db.conn.execute_batch(
            "CREATE TABLE classes_v24 (
                program_id INTEGER NOT NULL REFERENCES programs(id),
                typeinfo TEXT NOT NULL, vtable TEXT NOT NULL, name TEXT NOT NULL,
                mangled TEXT NOT NULL, kind TEXT NOT NULL, vtable_slots INTEGER NOT NULL,
                provenance TEXT NOT NULL, provenance_kind TEXT NOT NULL, confidence REAL,
                PRIMARY KEY(program_id, typeinfo));
             INSERT INTO classes_v24 SELECT program_id, typeinfo, vtable, name, mangled,
                kind, vtable_slots, provenance, provenance_kind, confidence FROM classes;
             CREATE TABLE class_bases_v24 (
                program_id INTEGER NOT NULL REFERENCES programs(id), typeinfo TEXT NOT NULL,
                ordinal INTEGER NOT NULL, base_typeinfo TEXT NOT NULL, base_mangled TEXT NOT NULL,
                base_offset INTEGER NOT NULL, virtual_base INTEGER NOT NULL, public_base INTEGER NOT NULL,
                PRIMARY KEY(program_id, typeinfo, ordinal));
             INSERT INTO class_bases_v24 SELECT b.program_id, c.typeinfo, b.ordinal,
                b.base_typeinfo, b.base_mangled, b.base_offset, b.virtual_base, b.public_base
                FROM class_bases b JOIN classes c ON c.program_id = b.program_id AND c.identity = b.identity;
             DROP TABLE class_bases; DROP TABLE classes;
             ALTER TABLE classes_v24 RENAME TO classes;
             ALTER TABLE class_bases_v24 RENAME TO class_bases;
             DROP TABLE matching_project_checks; DROP TABLE matching_trials;
             DROP TABLE matching_candidates; DROP TABLE matching_workspaces;
             ALTER TABLE matching_runs DROP COLUMN imported;
             UPDATE meta SET value = '24' WHERE key = 'schema_version';"
        ).unwrap();
        db.conn.execute("INSERT INTO classes VALUES (?1, ?2, ?2, 'Legacy', '6Legacy', 'class', 0, 'mwcc-rtti-less', 'inferred', NULL)",
            params![program.0, addr_cell(&Address::ram(0))]).unwrap();
        db.migrate().unwrap();
        let rows = db.classes(program).unwrap();
        assert_eq!(rows.iter().find(|row| row.mangled == "7Derived"), Some(&original));
        let legacy = rows.iter().find(|row| row.mangled == "6Legacy").unwrap();
        assert_eq!(legacy.typeinfo, None);
        assert_eq!(legacy.vtable, None);
        let mut second = legacy.clone();
        second.name = "Other".into();
        second.mangled = "5Other".into();
        db.replace_inferred_classes(program, "mwcc-rtti-less", &[legacy.clone(), second]).unwrap();
        assert_eq!(db.classes(program).unwrap().iter().map(|row| row.mangled.clone()).collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["5Other".to_owned(), "6Legacy".to_owned(), "7Derived".to_owned()]));
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
