//! SQLite persistence for durable facts (spec 13.1, 14.4).
//!
//! The database stores project-owned records: the program identity, functions,
//! symbols, xrefs, and the provenance of whoever produced them. Every mutation
//! runs in a transaction and bumps the program revision; bridge exports carry
//! producer + upstream version so reopening never depends on the bridge.

use romwright_model::{
    BookmarkRow, CollaborationOp, CommentRow, DataTypeRow, FunctionRow, GraphEdge, GraphNode,
    JournalEntry, MemoryRegion, PatchRow, ProgramId, PrototypeRow, Provenance, RevisionEvent,
    SearchHit, StackVariableRow, StringRow, SymbolRow, TraceEvent, TypeDefRow, TypeFieldRow,
    TypeGraphNode, TypeLinkRow, XrefRow, FactKind, FactProvenance,
};
use romwright_model::provenance::EvidenceKind;
use rusqlite::types::Value;
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::Path;

mod class;
mod feature;
mod convention;
mod return_behavior;
mod semantic;
mod signature;
mod thunk;
pub use return_behavior::{ReturnFlowUpdate, ReturnPublication};

/// Schema version; bump on any incompatible change and add a migration.
pub const SCHEMA_VERSION: i64 = 22;

/// Database open or query failure.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Underlying SQLite failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Program ID not present.
    #[error("program not found: {0}")]
    ProgramNotFound(u64),
    /// Stored patch data was not valid hexadecimal.
    #[error("invalid hexadecimal patch data: {0}")]
    InvalidHex(String),
    /// Function filter could not be parsed (bad `re:` regex).
    #[error("invalid function filter: {0}")]
    InvalidFilter(String),
    /// Stored collaboration operation was not present.
    #[error("collaboration operation not found: {0}")]
    OperationNotFound(String),
    #[error("invalid fact provenance: {0}")]
    InvalidFactProvenance(String),
    #[error("stale fact revision: expected {expected}, found {actual}")]
    StaleRevision { expected: u64, actual: u64 },
    #[error("invalid return analysis: {0}")]
    InvalidReturnAnalysis(String),
    /// A structural feature row was missing a measurement it must carry.
    #[error("invalid function features: {0}")]
    InvalidFunctionFeatures(String),
}
/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = DbError> = std::result::Result<T, E>;

/// Sort key for paged functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionSort {
    Entry,
    Name,
    Size,
}

impl FunctionSort {
    /// SQL ORDER BY fragment. Fixed whitelist: never built from user text.
    pub fn sql_column(self) -> &'static str {
        match self {
            FunctionSort::Entry => "entry",
            FunctionSort::Name => "name COLLATE NOCASE",
            FunctionSort::Size => "size",
        }
    }

    fn compare(self, a: &FunctionRow, b: &FunctionRow) -> std::cmp::Ordering {
        match self {
            FunctionSort::Entry => a.entry.offset.cmp(&b.entry.offset),
            FunctionSort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            FunctionSort::Size => a.size.cmp(&b.size),
        }
    }

    /// Parses a sort key name ("entry" | "name" | "size").
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "entry" => Some(FunctionSort::Entry),
            "name" => Some(FunctionSort::Name),
            "size" => Some(FunctionSort::Size),
            _ => None,
        }
    }
}

/// Function-name filter for paged queries: case-insensitive substring, or
/// a regex when the text carries a `re:` prefix.
#[derive(Clone, Debug)]
pub enum FunctionsFilter {
    Substring(String),
    Regex(regex::Regex),
}

impl FunctionsFilter {
    /// Parses user filter text; empty text means no filter.
    pub fn parse(text: &str) -> Result<Option<Self>> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if let Some(pattern) = trimmed.strip_prefix("re:") {
            let regex = regex::Regex::new(pattern)
                .map_err(|error| DbError::InvalidFilter(error.to_string()))?;
            Ok(Some(FunctionsFilter::Regex(regex)))
        } else {
            Ok(Some(FunctionsFilter::Substring(trimmed.to_lowercase())))
        }
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            FunctionsFilter::Substring(needle) => name.to_lowercase().contains(needle),
            FunctionsFilter::Regex(regex) => regex.is_match(name),
        }
    }
}

/// Opened project database.
pub struct ProjectDb {
    conn: Connection,
}

impl ProjectDb {
    /// Opens (creating if needed) a project database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // WAL: durable enough for crash tests, allows concurrent readers while
        // the CLI writes (spec 13.1 leaves WAL vs rollback to measurement).
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // Under WAL, NORMAL fsyncs at checkpoints rather than at every
        // commit. A crash can lose the most recent commits, never corrupt
        // the database (SQLite "PRAGMA synchronous"), and an import is
        // reproducible from the image, so the trade is a store that keeps
        // up with an interactive session: 45687 rows took 2.76 s at FULL.
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // A reader must never fail because a background pass is committing.
        // WAL lets readers run during a write, but the brief exclusive lock
        // a commit takes still returns SQLITE_BUSY immediately without a
        // timeout: a listing query failed outright while per-function
        // analysis was committing beside it.
        conn.busy_timeout(std::time::Duration::from_secs(15))?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Opens an in-memory database (tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '2');

             CREATE TABLE IF NOT EXISTS programs (
                 id INTEGER PRIMARY KEY,
                 name TEXT NOT NULL UNIQUE,
                 language TEXT NOT NULL,
                 compiler TEXT NOT NULL DEFAULT '',
                 revision INTEGER NOT NULL DEFAULT 1,
                 imported_at TEXT NOT NULL DEFAULT (datetime('now'))
             );

             CREATE TABLE IF NOT EXISTS provenance (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 producer TEXT NOT NULL,
                 upstream_version TEXT NOT NULL,
                 PRIMARY KEY (program_id)
             );

             CREATE TABLE IF NOT EXISTS functions (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 entry TEXT NOT NULL,
                 name TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 signature TEXT,
                 -- What has actually been done to this function, as opposed
                 -- to what the loader asserted: 'seeded' is a declared entry
                 -- nobody has walked, 'walked' carries a decoded body, and
                 -- 'batch' is whole-image analysis, and 'undecodable' is a
                 -- seed a walk could not decode at all.
                 analysis_state TEXT NOT NULL DEFAULT 'batch',
                 analysed_revision INTEGER NOT NULL DEFAULT 0,
                 -- Which producer put this function here: the image's own
                 -- symbol table, a byte pattern, a call, a linkage stub, a
                 -- pointer in data, the flow walk, or graph shape. Without
                 -- it a recall number is one number for six passes and no
                 -- way to tell which of them is carrying it.
                 producer TEXT NOT NULL DEFAULT 'unknown',
                 PRIMARY KEY (program_id, entry)
             );

             CREATE TABLE IF NOT EXISTS symbols (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 name TEXT NOT NULL,
                 external INTEGER NOT NULL,
                 source TEXT NOT NULL,
                 PRIMARY KEY (program_id, address, name)
             );

             CREATE TABLE IF NOT EXISTS xrefs (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 src TEXT NOT NULL,
                 dst TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, src, dst, kind)
             );
             CREATE INDEX IF NOT EXISTS idx_xrefs_dst ON xrefs(program_id, dst);

             CREATE TABLE IF NOT EXISTS exception_sites (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 function TEXT NOT NULL,
                 start TEXT NOT NULL,
                 end TEXT NOT NULL,
                 landing_pad TEXT NOT NULL,
                 provenance TEXT NOT NULL,
                 provenance_kind TEXT NOT NULL
                     CHECK(provenance_kind IN ('asserted', 'inferred')),
                 confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                 PRIMARY KEY(program_id, start)
             );
             CREATE INDEX IF NOT EXISTS idx_exception_sites_fn
                 ON exception_sites(program_id, function);

             CREATE TABLE IF NOT EXISTS comments (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 function TEXT NOT NULL,
                 type TEXT NOT NULL,
                 text TEXT NOT NULL,
                 PRIMARY KEY (program_id, address, type)
             );
             CREATE INDEX IF NOT EXISTS idx_comments_fn ON comments(program_id, function);

             CREATE TABLE IF NOT EXISTS datatypes (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 name TEXT NOT NULL,
                 definition TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, name)
             );

             CREATE TABLE IF NOT EXISTS strings (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 value TEXT NOT NULL,
                 kind TEXT NOT NULL DEFAULT 'string',
                 PRIMARY KEY (program_id, address, value)
             );
             CREATE INDEX IF NOT EXISTS idx_strings_value
                 ON strings(program_id, value);

             CREATE TABLE IF NOT EXISTS memory_regions (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 name TEXT NOT NULL,
                 start TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 permissions TEXT NOT NULL DEFAULT '',
                 source TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, name, start)
             );

             CREATE TABLE IF NOT EXISTS bookmarks (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 label TEXT NOT NULL,
                 comment TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, address)
             );

             CREATE TABLE IF NOT EXISTS patches (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 original_hex TEXT NOT NULL,
                 patched_hex TEXT NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1,
                 PRIMARY KEY (program_id, address)
             );

             CREATE TABLE IF NOT EXISTS type_defs (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 name TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 definition TEXT NOT NULL DEFAULT '',
                 size INTEGER,
                 alignment INTEGER,
                 base_type TEXT,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, name)
             );

             CREATE TABLE IF NOT EXISTS type_fields (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 type_name TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 field_name TEXT NOT NULL,
                 offset INTEGER NOT NULL,
                 size INTEGER,
                 type_ref TEXT,
                 PRIMARY KEY (program_id, type_name, ordinal)
             );

             CREATE TABLE IF NOT EXISTS prototypes (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 function TEXT NOT NULL,
                 signature TEXT NOT NULL,
                 calling_convention TEXT,
                 return_type TEXT,
                 PRIMARY KEY (program_id, function)
             );

             CREATE TABLE IF NOT EXISTS decode_contexts (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 name TEXT NOT NULL,
                 value INTEGER NOT NULL,
                 PRIMARY KEY (program_id, address, name)
             );

             CREATE TABLE IF NOT EXISTS stack_variables (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 function TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 name TEXT NOT NULL,
                 storage TEXT NOT NULL,
                 type_name TEXT,
                 offset INTEGER,
                 size INTEGER,
                 PRIMARY KEY (program_id, function, ordinal)
             );

             CREATE TABLE IF NOT EXISTS type_links (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 source TEXT NOT NULL,
                 target TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, source, target, kind)
             );

             CREATE TABLE IF NOT EXISTS revision_events (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 revision INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 detail TEXT NOT NULL DEFAULT '',
                 at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE INDEX IF NOT EXISTS idx_rev_events
                 ON revision_events(program_id, revision);

             CREATE TABLE IF NOT EXISTS command_journal (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 seq INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 payload TEXT NOT NULL DEFAULT '',
                 undo_payload TEXT NOT NULL DEFAULT '',
                 done INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (program_id, seq)
             );
             CREATE TABLE IF NOT EXISTS trace_events (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 sequence INTEGER NOT NULL,
                 at TEXT NOT NULL,
                 thread TEXT NOT NULL DEFAULT '',
                 address TEXT,
                 kind TEXT NOT NULL,
                 payload TEXT NOT NULL DEFAULT '',
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, sequence)
             );
             CREATE INDEX IF NOT EXISTS idx_trace_events
                 ON trace_events(program_id, sequence);

             CREATE TABLE IF NOT EXISTS collaboration_ops (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 op_id TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 lamport INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 payload TEXT NOT NULL DEFAULT '',
                 applied INTEGER NOT NULL DEFAULT 0,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, op_id)
             );
             CREATE INDEX IF NOT EXISTS idx_collaboration_order
                 ON collaboration_ops(program_id, lamport, actor, op_id);
             COMMIT;",
        )?;
        let v_text: String = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| {
                r.get(0)
            })?;
        let v: i64 = v_text.parse().map_err(|_| {
            DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                "meta.schema_version not an integer".into(),
            ))
        })?;
        if v > SCHEMA_VERSION {
            return Err(DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                format!("database schema {v} newer than supported {SCHEMA_VERSION}"),
            )));
        }
        if v < SCHEMA_VERSION {
            let tx = self.conn.unchecked_transaction()?;
            if v < 5 {
                let has_provenance: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('xrefs') WHERE name = 'provenance')",
                [], |row| row.get(0),
            )?;
                if !has_provenance {
                    tx.execute(
                        "ALTER TABLE xrefs ADD COLUMN provenance TEXT NOT NULL DEFAULT ''",
                        [],
                    )?;
                }
                tx.execute_batch(
                    "ALTER TABLE xrefs ADD COLUMN provenance_kind TEXT NOT NULL DEFAULT 'asserted'
                     CHECK(provenance_kind IN ('asserted', 'inferred'));
                 ALTER TABLE xrefs ADD COLUMN confidence REAL
                     CHECK(confidence >= 0 AND confidence <= 1);
                 UPDATE xrefs SET provenance_kind = 'inferred'
                     WHERE provenance = 'native-import'
                        OR provenance GLOB 'native-import:*'
                        OR provenance GLOB 'native-analysis:*';",
                )?;
            }
            // Version 6 permits typed non-RAM address cells; existing RAM
            // hex cells are unchanged. Older readers must reject this format.
            if v < 7 {
                tx.execute_batch(
                    "ALTER TABLE prototypes ADD COLUMN provenance TEXT NOT NULL DEFAULT '';
                     ALTER TABLE prototypes ADD COLUMN provenance_kind TEXT NOT NULL DEFAULT 'asserted'
                         CHECK(provenance_kind IN ('asserted', 'inferred'));
                     ALTER TABLE prototypes ADD COLUMN confidence REAL
                         CHECK(confidence >= 0 AND confidence <= 1);
                     ALTER TABLE type_defs ADD COLUMN primitive TEXT
                         CHECK(primitive IN ('signed_integer', 'unsigned_integer', 'float', 'boolean', 'void'));
                     ALTER TABLE type_defs ADD COLUMN element_count INTEGER
                         CHECK(element_count >= 0);",
                )?;
            }
            if v < 8 {
                tx.execute_batch(
                    "CREATE TABLE return_behaviors (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         function TEXT NOT NULL,
                         no_return INTEGER NOT NULL CHECK(no_return IN (0, 1)),
                         provenance TEXT NOT NULL,
                         provenance_kind TEXT NOT NULL
                             CHECK(provenance_kind IN ('asserted', 'inferred')),
                         confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                         PRIMARY KEY(program_id, function)
                     );",
                )?;
            }
            if v < 9 {
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS thunks (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         function TEXT NOT NULL,
                         thunked TEXT NOT NULL,
                         kind TEXT NOT NULL CHECK(kind IN ('direct', 'linkage')),
                         provenance TEXT NOT NULL,
                         provenance_kind TEXT NOT NULL
                             CHECK(provenance_kind IN ('asserted', 'inferred')),
                         confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                         PRIMARY KEY(program_id, function)
                     );",
                )?;
            }
            if v < 10 {
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS signature_matches (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         function TEXT NOT NULL,
                         name TEXT NOT NULL,
                         package TEXT NOT NULL,
                         license TEXT NOT NULL,
                         compared_bytes INTEGER NOT NULL CHECK(compared_bytes > 0),
                         match_confidence REAL NOT NULL
                             CHECK(match_confidence >= 0 AND match_confidence <= 1),
                         provenance TEXT NOT NULL,
                         provenance_kind TEXT NOT NULL
                             CHECK(provenance_kind IN ('asserted', 'inferred')),
                         confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                         PRIMARY KEY(program_id, function)
                     );",
                )?;
            }
            if v < 11 {
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS classes (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         typeinfo TEXT NOT NULL,
                         vtable TEXT NOT NULL,
                         name TEXT NOT NULL,
                         mangled TEXT NOT NULL,
                         kind TEXT NOT NULL
                             CHECK(kind IN ('class', 'single_base', 'multiple_base')),
                         vtable_slots INTEGER NOT NULL CHECK(vtable_slots >= 0),
                         provenance TEXT NOT NULL,
                         provenance_kind TEXT NOT NULL
                             CHECK(provenance_kind IN ('asserted', 'inferred')),
                         confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                         PRIMARY KEY(program_id, typeinfo)
                     );
                     CREATE TABLE IF NOT EXISTS class_bases (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         typeinfo TEXT NOT NULL,
                         ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                         base_typeinfo TEXT NOT NULL,
                         base_mangled TEXT NOT NULL,
                         base_offset INTEGER NOT NULL,
                         virtual_base INTEGER NOT NULL CHECK(virtual_base IN (0, 1)),
                         public_base INTEGER NOT NULL CHECK(public_base IN (0, 1)),
                         PRIMARY KEY(program_id, typeinfo, ordinal)
                     );",
                )?;
            }
            if v < 12 {
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS flow_overrides (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         address TEXT NOT NULL,
                         kind TEXT NOT NULL
                             CHECK(kind IN ('branch', 'call', 'callreturn', 'return')),
                         provenance TEXT NOT NULL,
                         provenance_kind TEXT NOT NULL
                             CHECK(provenance_kind IN ('asserted', 'inferred')),
                         confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                         PRIMARY KEY(program_id, address)
                     );",
                )?;
            }
            if v < 13 {
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS data_definitions (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         address TEXT NOT NULL,
                         type TEXT NOT NULL,
                         size INTEGER NOT NULL CHECK(size > 0),
                         provenance TEXT NOT NULL,
                         provenance_kind TEXT NOT NULL
                             CHECK(provenance_kind IN ('asserted', 'inferred')),
                         confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                         PRIMARY KEY(program_id, address)
                     );",
                )?;
            }
            if v < 14 {
                // The convention is its own fact with its own provenance. The
                // `functions` column that used to hold it was never written:
                // one value, one owner.
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS calling_conventions (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         function TEXT NOT NULL,
                         convention TEXT NOT NULL,
                         provenance TEXT NOT NULL,
                         provenance_kind TEXT NOT NULL
                             CHECK(provenance_kind IN ('asserted', 'inferred')),
                         confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
                         PRIMARY KEY(program_id, function)
                     );",
                )?;
                let carried: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('functions')
                                   WHERE name = 'calling_convention')",
                    [], |row| row.get(0),
                )?;
                if carried {
                    tx.execute("ALTER TABLE functions DROP COLUMN calling_convention", [])?;
                }
            }
            if v < 16 {
                // Structural measurements of a body, taken at decode time:
                // what a whole-program diff matches on (romwright-diff).
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS function_features (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         function TEXT NOT NULL,
                         instructions INTEGER NOT NULL CHECK(instructions >= 0),
                         blocks INTEGER NOT NULL CHECK(blocks >= 0),
                         edges INTEGER NOT NULL CHECK(edges >= 0),
                         body_digest TEXT NOT NULL,
                         shape_digest TEXT NOT NULL,
                         PRIMARY KEY(program_id, function)
                     );",
                )?;
            }
            if v < 17 {
                // Two more structural measurements: loops and the largest
                // block. Both survive a change of optimisation level better
                // than a byte count does, which is what a diff needs.
                let present: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('function_features')
                                   WHERE name = 'loops')",
                    [],
                    |row| row.get(0),
                )?;
                if !present {
                    tx.execute_batch(
                        "ALTER TABLE function_features ADD COLUMN loops INTEGER NOT NULL DEFAULT 0;
                         ALTER TABLE function_features ADD COLUMN max_block INTEGER NOT NULL DEFAULT 0;",
                    )?;
                }
            }
            if v < 18 {
                // Demand-driven analysis needs to say what has been done to
                // each function, and at which revision: a listing row from a
                // loader-only import is a seed, not a walked body.
                let present: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('functions')
                                   WHERE name = 'analysis_state')",
                    [],
                    |row| row.get(0),
                )?;
                if !present {
                    tx.execute_batch(
                        "ALTER TABLE functions ADD COLUMN analysis_state TEXT NOT NULL
                             DEFAULT 'batch';
                         ALTER TABLE functions ADD COLUMN analysed_revision INTEGER NOT NULL
                             DEFAULT 0;",
                    )?;
                }
            }
            if v < 19 {
                let present: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('functions')
                                   WHERE name = 'producer')",
                    [],
                    |row| row.get(0),
                )?;
                if !present {
                    tx.execute(
                        "ALTER TABLE functions ADD COLUMN producer TEXT NOT NULL
                             DEFAULT 'unknown'",
                        [],
                    )?;
                }
            }
            if v < 20 {
                // Semantic p-code signatures, taken by an explicit indexing
                // pass rather than at import: hashing a body's data-flow
                // needs its p-code, which needs a loaded console per body.
                // One row per decoded function; a function nobody decoded
                // gets no row, so absence never counts as difference.
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS semantic_signatures (
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         function TEXT NOT NULL,
                         signature TEXT NOT NULL,
                         ops INTEGER NOT NULL CHECK(ops >= 0),
                         PRIMARY KEY(program_id, function)
                     );",
                )?;
            }
            if v < 21 {
                // M-C overlay modules: a program's loadable parts (REL
                // images, PSX overlays, DOL sections) get rows so
                // `locate` can name the module an address belongs to.
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS modules (
                         module_id INTEGER PRIMARY KEY,
                         program_id INTEGER NOT NULL REFERENCES programs(id),
                         name TEXT NOT NULL,
                         kind TEXT NOT NULL DEFAULT '',
                         file_id TEXT NOT NULL DEFAULT '',
                         load_vaddr TEXT NOT NULL,
                         size INTEGER NOT NULL,
                         file_off INTEGER NOT NULL DEFAULT 0,
                         resident INTEGER NOT NULL DEFAULT 1
                     );
                     CREATE INDEX IF NOT EXISTS idx_modules_program
                         ON modules(program_id);
                     CREATE TABLE IF NOT EXISTS module_xrefs (
                         module_id INTEGER NOT NULL REFERENCES modules(module_id),
                         from_addr TEXT NOT NULL,
                         to_module_id INTEGER,
                         to_addr TEXT NOT NULL,
                         to_external TEXT NOT NULL DEFAULT '',
                         kind TEXT NOT NULL DEFAULT ''
                     );
                     CREATE INDEX IF NOT EXISTS idx_module_xrefs_from
                         ON module_xrefs(module_id, from_addr);",
                )?;
            }
            if v < 22 {
                // M-E compiler label on programs + M-F trace coverage on
                // functions. Both are pure additions with stable defaults
                // (empty / untraced), so old stores migrate without
                // changing any existing row's meaning.
                let has_compiler: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('programs')
                                   WHERE name = 'compiler')",
                    [],
                    |row| row.get(0),
                )?;
                if !has_compiler {
                    tx.execute(
                        "ALTER TABLE programs ADD COLUMN compiler TEXT NOT NULL
                             DEFAULT ''",
                        [],
                    )?;
                }
                let has_traced: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('functions')
                                   WHERE name = 'traced')",
                    [],
                    |row| row.get(0),
                )?;
                if !has_traced {
                    tx.execute(
                        "ALTER TABLE functions ADD COLUMN traced INTEGER NOT NULL
                             DEFAULT 0",
                        [],
                    )?;
                }
            }
            tx.execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Writes a compact copy of this store to `path`, replacing whatever is
    /// there. `VACUUM INTO` takes a consistent snapshot through the open
    /// connection, so no handle has to be closed to make a durable copy.
    pub fn export_to(&self, path: &Path) -> Result<()> {
        let _ = std::fs::remove_file(path);
        self.conn.execute(
            "VACUUM INTO ?1",
            params![path.to_string_lossy().as_ref()],
        )?;
        Ok(())
    }

    /// Replaces this store's contents with those of the database at `path`.
    ///
    /// Every table is copied through an attached database rather than by
    /// swapping files, because the connection stays open across the
    /// operation. The schemas match by construction: a caller reaches this
    /// only through a key that names `SCHEMA_VERSION`.
    pub fn import_from(&self, path: &Path) -> Result<()> {
        // ATTACH is refused inside a transaction, so the attach brackets the
        // transaction rather than sitting in it.
        self.conn.execute(
            "ATTACH DATABASE ?1 AS restore",
            params![path.to_string_lossy().as_ref()],
        )?;
        let result = (|| -> Result<()> {
            let tables: Vec<String> = {
                let mut stmt = self.conn.prepare(
                    "SELECT name FROM restore.sqlite_master
                     WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                )?;
                stmt.query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            let tx = self.conn.unchecked_transaction()?;
            tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
            for table in tables.iter().rev() {
                tx.execute_batch(&format!("DELETE FROM main.\"{table}\""))?;
            }
            for table in &tables {
                tx.execute_batch(&format!(
                    "INSERT INTO main.\"{table}\" SELECT * FROM restore.\"{table}\""
                ))?;
            }
            tx.commit()?;
            Ok(())
        })();
        self.conn.execute_batch("DETACH DATABASE restore")?;
        result
    }

    /// Inserts or replaces a program summary and its provenance. Returns the ID.
    /// `compiler` is the toolchain the import detected (`mwcc_233_163`,
    /// `gcc`, `msvc`, ...), or empty when nothing in the image named one:
    /// a non-empty value overwrites, an empty one preserves what the store
    /// holds, so a re-import that cannot see the markers (e.g. from cache)
    /// never blanks a recorded compiler.
    pub fn upsert_program(
        &self,
        name: &str,
        language: &str,
        provenance: &Provenance,
    ) -> Result<ProgramId> {
        self.upsert_program_with_compiler(name, language, provenance, "")
    }

    /// `upsert_program` with an explicit toolchain label.
    pub fn upsert_program_with_compiler(
        &self,
        name: &str,
        language: &str,
        provenance: &Provenance,
        compiler: &str,
    ) -> Result<ProgramId> {
        self.conn.execute(
            "INSERT INTO programs(name, language, compiler) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET language = excluded.language,
                                              compiler = CASE WHEN excluded.compiler <> ''
                                                              THEN excluded.compiler
                                                              ELSE programs.compiler END,
                                              revision = revision + 1",
            params![name, language, compiler],
        )?;
        let id = self.conn.query_row(
            "SELECT id FROM programs WHERE name = ?1",
            params![name],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "INSERT INTO provenance(program_id, producer, upstream_version)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(program_id) DO UPDATE SET producer = excluded.producer,
                                                   upstream_version = excluded.upstream_version",
            params![id, provenance.producer, provenance.upstream_version],
        )?;
        Ok(ProgramId(id))
    }

    /// Records the toolchain that produced `program` (`mwcc_233_163`,
    /// `gcc`, `msvc`, ...).
    pub fn set_program_compiler(&self, program: ProgramId, compiler: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE programs SET compiler = ?2 WHERE id = ?1",
            params![program.0, compiler],
        )?;
        Ok(())
    }

    /// Toolchain label recorded for a program; empty when none was detected.
    pub fn program_compiler(&self, program: ProgramId) -> Result<String> {
        let compiler: String = self.conn.query_row(
            "SELECT compiler FROM programs WHERE id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        Ok(compiler)
    }

    /// Replaces the function set of a program inside one transaction.
    /// Marks every function of a program with how it was produced. A
    /// loader-only import declares seeds; whole-image analysis declares
    /// walked bodies. Demand-driven work then upgrades single rows.
    pub fn set_all_analysis_states(&self, program: ProgramId, state: &str) -> Result<()> {
        let revision = self.revision(program)?;
        self.conn.execute(
            "UPDATE functions SET analysis_state = ?2, analysed_revision = ?3
             WHERE program_id = ?1",
            params![program.0, state, revision as i64],
        )?;
        Ok(())
    }

    /// Records one function's body as analysed at the current revision,
    /// inserting it when demand-driven analysis found a function the loader
    /// never declared.
    pub fn upsert_analysed_function(
        &self,
        program: ProgramId,
        row: &FunctionRow,
        state: &str,
    ) -> Result<()> {
        let revision = self.revision(program)?;
        self.conn.execute(
            "INSERT INTO functions(program_id, entry, name, size, signature,
                                   analysis_state, analysed_revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(program_id, entry) DO UPDATE SET
                 size = excluded.size,
                 analysis_state = excluded.analysis_state,
                 analysed_revision = excluded.analysed_revision",
            params![
                program.0,
                row.entry.to_string(),
                row.name,
                row.size as i64,
                row.signature,
                state,
                revision as i64
            ],
        )?;
        Ok(())
    }

    /// Records which producer claimed each function entry.
    pub fn set_producers(&self, program: ProgramId, rows: &[(String, String)]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "UPDATE functions SET producer = ?3 WHERE program_id = ?1 AND entry = ?2",
            )?;
            for (entry, producer) in rows {
                stmt.execute(params![program.0, entry, producer])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every function entry with the producer that claimed it.
    pub fn producers(&self, program: ProgramId) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT entry, producer FROM functions WHERE program_id = ?1")?;
        let rows = stmt
            .query_map(params![program.0], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Marks every function whose body contains one of `entries` as
    /// trace-covered, and returns the marked entries. A trace event that
    /// lands mid-body marks the whole body: coverage is per-function, not
    /// per-instruction. Unknown addresses mark nothing and seed nothing.
    pub fn mark_traced(&self, program: ProgramId, entries: &[String]) -> Result<Vec<String>> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "UPDATE functions SET traced = 1
                 WHERE program_id = ?1 AND entry = ?2",
            )?;
            for entry in entries {
                stmt.execute(params![program.0, entry])?;
            }
        }
        let marked: Vec<String> = tx
            .prepare("SELECT entry FROM functions WHERE program_id = ?1 AND traced <> 0")?
            .query_map(params![program.0], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        self.bump_and_record(&tx, program, "mark-traced", &format!("{}", marked.len()))?;
        tx.commit()?;
        Ok(marked)
    }

    /// Entries currently carrying the trace mark.
    pub fn traced_functions(&self, program: ProgramId) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT entry FROM functions WHERE program_id = ?1 AND traced <> 0 ORDER BY entry",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Inserts one module row and returns its assigned id.
    pub fn insert_module(
        &self,
        program: ProgramId,
        module: &romwright_model::ModuleRow,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO modules(
                 program_id, name, kind, file_id, load_vaddr, size, file_off, resident
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                program.0,
                module.name,
                module.kind,
                module.file_id,
                addr_cell(&module.load_vaddr),
                module.size as i64,
                module.file_off as i64,
                module.resident as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lists a program's modules in load order.
    pub fn modules(&self, program: ProgramId) -> Result<Vec<romwright_model::ModuleRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT module_id, name, kind, file_id, load_vaddr, size, file_off, resident
             FROM modules WHERE program_id = ?1 ORDER BY load_vaddr",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                let vaddr: String = row.get(4)?;
                Ok(romwright_model::ModuleRow {
                    module_id: row.get(0)?,
                    program: String::new(),
                    name: row.get(1)?,
                    kind: row.get(2)?,
                    file_id: row.get(3)?,
                    load_vaddr: romwright_model::Address::parse_ram_hex(&vaddr)
                        .unwrap_or_else(|| romwright_model::Address::ram(0)),
                    size: row.get::<_, i64>(5)? as u64,
                    file_off: row.get::<_, i64>(6)? as u64,
                    resident: row.get::<_, i64>(7)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Inserts one cross-module reference.
    pub fn insert_module_xref(
        &self,
        xref: &romwright_model::ModuleXrefRow,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO module_xrefs(
                 module_id, from_addr, to_module_id, to_addr, to_external, kind
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                xref.module_id,
                addr_cell(&xref.from_addr),
                xref.to_module_id,
                addr_cell(&xref.to_addr),
                xref.to_external,
                xref.kind,
            ],
        )?;
        Ok(())
    }

    /// Lists a module's outgoing cross-module references.
    pub fn module_xrefs(
        &self,
        module_id: i64,
    ) -> Result<Vec<romwright_model::ModuleXrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT module_id, from_addr, to_module_id, to_addr, to_external, kind
             FROM module_xrefs WHERE module_id = ?1 ORDER BY from_addr",
        )?;
        let rows = stmt
            .query_map(params![module_id], |row| {
                let from: String = row.get(1)?;
                let to: String = row.get(3)?;
                Ok(romwright_model::ModuleXrefRow {
                    module_id: row.get(0)?,
                    from_addr: romwright_model::Address::parse_ram_hex(&from)
                        .unwrap_or_else(|| romwright_model::Address::ram(0)),
                    to_module_id: row.get(2)?,
                    to_addr: romwright_model::Address::parse_ram_hex(&to)
                        .unwrap_or_else(|| romwright_model::Address::ram(0)),
                    to_external: row.get(4)?,
                    kind: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// How much of a program has actually been analysed, by state.
    ///
    /// A consumer that answers from the store needs to say what the answer
    /// is missing: a listing built from a loader-only import is every
    /// function the image names and no body anyone walked, and a caller
    /// that cannot tell the two apart will present a seed as a finished
    /// answer.
    pub fn analysis_progress(&self, program: ProgramId) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT analysis_state, COUNT(*) FROM functions WHERE program_id = ?1
             GROUP BY analysis_state ORDER BY analysis_state",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// What has been done to one function, and when.
    pub fn function_analysis_state(
        &self,
        program: ProgramId,
        entry: &str,
    ) -> Result<Option<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT analysis_state, analysed_revision FROM functions
             WHERE program_id = ?1 AND entry = ?2",
        )?;
        let mut rows = stmt.query(params![program.0, entry])?;
        match rows.next()? {
            Some(row) => Ok(Some((row.get(0)?, row.get::<_, i64>(1)? as u64))),
            None => Ok(None),
        }
    }

    pub fn replace_functions(&self, program: ProgramId, rows: &[FunctionRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM functions WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO functions(program_id, entry, name, size, signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        let mut seen = std::collections::HashSet::new();
        for r in rows {
            if !seen.insert(r.entry.clone()) {
                continue;
            }
            stmt.execute(params![
                program.0,
                addr_cell(&r.entry),
                r.name,
                r.size,
                r.signature
            ])?;
        }
        drop(stmt);
        // An analyst's rename is an assertion, and an assertion outlives the
        // pass that rediscovered the function: Ghidra never renames a
        // `USER_DEFINED` symbol during re-analysis
        // (`SymbolUtilities.createPreferredLabelOrFunctionSymbol`, and
        // `DemanglerAnalyzer.skipSymbol` refuses to touch one). The command
        // journal is the record of those assertions, so the name each live
        // `rename` still carries is re-applied over this pass's name. An
        // undone rename is marked `done` and never comes back; a rename of a
        // function this pass no longer recovers simply does not apply.
        for (entry, name) in Self::asserted_names(&tx, program)? {
            tx.execute(
                "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
                params![program.0, entry, name],
            )?;
        }
        self.bump_and_record(&tx, program, "replace-functions", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// The name every live analyst rename asserts, by address cell, oldest
    /// first so the newest rename of an address wins.
    fn asserted_names(
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
    ) -> Result<Vec<(String, String)>> {
        let mut statement = tx.prepare(
            "SELECT payload FROM command_journal
             WHERE program_id = ?1 AND kind = 'rename' AND done = 0
             ORDER BY seq",
        )?;
        let payloads = statement
            .query_map(params![program.0], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut named = Vec::new();
        for payload in payloads {
            let value: serde_json::Value = match serde_json::from_str(&payload) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if let (Some(entry), Some(name)) = (
                value.get("entry").and_then(serde_json::Value::as_str),
                value.get("name").and_then(serde_json::Value::as_str),
            ) {
                named.push((entry.to_string(), name.to_string()));
            }
        }
        Ok(named)
    }

    /// Replaces the symbol set of a program inside one transaction.
    pub fn replace_symbols(&self, program: ProgramId, rows: &[SymbolRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM symbols WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO symbols(program_id, address, name, external, source)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        // Real binaries (libc) repeat (address, name) pairs — versioned
        // exporters alias the same entry; dedupe within the batch or the
        // UNIQUE index aborts the whole replace.
        let mut seen = std::collections::HashSet::new();
        for r in rows {
            if !seen.insert((r.address.clone(), r.name.clone())) {
                continue;
            }
            stmt.execute(params![program.0, addr_cell(&r.address), r.name, r.external as i64, r.source])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-symbols", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Replace analysis results while retaining existing analyst assertions.
    pub fn replace_xrefs(&self, program: ProgramId, rows: &[XrefRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM xrefs WHERE program_id = ?1 AND provenance_kind = 'inferred'",
            params![program.0],
        )?;
        Self::insert_xrefs(&tx, program, rows, None)?;
        self.bump_and_record(&tx, program, "replace-xrefs", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the inferred references whose *source* lies in one address
    /// range: what demand-driven analysis of a single body may overwrite.
    /// References into the range are other functions' facts and survive.
    pub fn replace_xrefs_from_range(
        &self,
        program: ProgramId,
        start: &romwright_model::Address,
        end: &romwright_model::Address,
        rows: &[XrefRow],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM xrefs WHERE program_id = ?1 AND provenance_kind = 'inferred'
                 AND src >= ?2 AND src < ?3",
            params![program.0, start.to_string(), end.to_string()],
        )?;
        Self::insert_xrefs(&tx, program, rows, None)?;
        self.bump_and_record(&tx, program, "analyse-function", &start.to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically replace one inference pass without deleting other producers.
    pub fn replace_inferred_xrefs(
        &self, program: ProgramId, source: &str, rows: &[XrefRow],
    ) -> Result<()> {
        if source.trim().is_empty() {
            return Err(DbError::InvalidFactProvenance("inference source is empty".into()));
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM xrefs WHERE program_id = ?1 AND provenance = ?2
                 AND provenance_kind = 'inferred'",
            params![program.0, source],
        )?;
        Self::insert_xrefs(&tx, program, rows, Some(source))?;
        self.bump_and_record(&tx, program, "replace-inferred-xrefs", source)?;
        tx.commit()?;
        Ok(())
    }

    fn insert_xrefs(
        tx: &rusqlite::Transaction<'_>, program: ProgramId, rows: &[XrefRow],
        expected_source: Option<&str>,
    ) -> Result<()> {
        let mut stmt = tx.prepare(
            "INSERT INTO xrefs(program_id, src, dst, kind, provenance, provenance_kind, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(program_id, src, dst, kind) DO UPDATE SET
                 provenance = excluded.provenance,
                 provenance_kind = excluded.provenance_kind,
                 confidence = excluded.confidence
             WHERE xrefs.provenance_kind = 'inferred' OR excluded.provenance_kind = 'asserted'"
        )?;
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            let provenance = &row.provenance;
            if expected_source.is_some_and(|source|
                provenance.kind != FactKind::Inferred || provenance.source != source)
            {
                return Err(DbError::InvalidFactProvenance("row does not belong to the inference pass".into()));
            }
            let ownership = validate_fact_provenance(provenance)?;
            if !seen.insert((&row.from, &row.to, row.kind.as_str(), provenance.kind)) {
                continue;
            }
            stmt.execute(params![
                program.0, addr_cell(&row.from), addr_cell(&row.to), row.kind,
                provenance.source, ownership, provenance.confidence,
            ])?;
        }
        Ok(())
    }

    /// Applies an analyst rename: bumps the program revision and rewrites the
    /// function name. Fails when the function is unknown.
    pub fn rename_function(&self, program: ProgramId, entry: &romwright_model::Address, name: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            params![program.0, addr_cell(entry), name],
        )?;
        if n == 0 {
            return Err(DbError::ProgramNotFound(program.0));
        }
        self.bump_and_record(&tx, program, "rename", name)?;
        tx.commit()?;
        Ok(())
    }

    /// Applies an analyst comment command and records its prior state for
    /// undo. One transaction owns the row mutation, revision event, and
    /// journal entry.
    pub fn comment_command(
        &self,
        program: ProgramId,
        address: &romwright_model::Address,
        function: &romwright_model::Address,
        kind: &str,
        text: &str,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let previous: Option<(String, String)> = tx
            .query_row(
                "SELECT function, text FROM comments
                 WHERE program_id = ?1 AND address = ?2 AND type = ?3",
                params![program.0, addr_cell(address), kind],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if previous.is_some() {
            tx.execute(
                "UPDATE comments SET function = ?4, text = ?5
                 WHERE program_id = ?1 AND address = ?2 AND type = ?3",
                params![program.0, addr_cell(address), kind, addr_cell(function), text],
            )?;
        } else {
            tx.execute(
                "INSERT INTO comments(program_id, address, function, type, text)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![program.0, addr_cell(address), addr_cell(function), kind, text],
            )?;
        }
        self.bump_and_record(&tx, program, "comment", text)?;
        let payload = serde_json::json!({
            "address": address.hex(),
            "function": function.hex(),
            "kind": kind,
            "text": text,
        })
        .to_string();
        let undo = serde_json::json!({
            "address": address.hex(),
            "kind": kind,
            "exists": previous.is_some(),
            "function": previous.as_ref().map(|(function, _)| function),
            "text": previous.as_ref().map(|(_, text)| text),
        })
        .to_string();
        self.journal_push(&tx, program, "comment", &payload, &undo)?;
        tx.commit()?;
        Ok(())
    }

    /// Restores one comment's prior state and marks its journal entry done.
    pub fn undo_comment(
        &self,
        program: ProgramId,
        address: &romwright_model::Address,
        kind: &str,
        previous: Option<(&romwright_model::Address, &str)>,
        seq: u64,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        if let Some((function, text)) = previous {
            tx.execute(
                "INSERT INTO comments(program_id, address, function, type, text)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(program_id, address, type)
                 DO UPDATE SET function = excluded.function, text = excluded.text",
                params![program.0, addr_cell(address), addr_cell(function), kind, text],
            )?;
        } else {
            tx.execute(
                "DELETE FROM comments WHERE program_id = ?1 AND address = ?2 AND type = ?3",
                params![program.0, addr_cell(address), kind],
            )?;
        }
        self.bump_and_record(
            &tx,
            program,
            "comment-undo",
            if previous.is_some() { "restore" } else { "delete" },
        )?;
        tx.execute(
            "UPDATE command_journal SET done = 1 WHERE program_id = ?1 AND seq = ?2",
            params![program.0, seq],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Lists functions of a program ordered by entry address.
    pub fn functions(&self, program: ProgramId) -> Result<Vec<FunctionRow>> {
        let mut stmt = self.conn.prepare(
            &format!("{FUNCTION_SELECT} WHERE f.program_id = ?1 ORDER BY f.entry"),
        )?;
        let rows = stmt
            .query_map(params![program.0], map_function)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Paged functions (review CORE-004): a bounded window + total + the
    /// revision the window was read at. Views never preload. `filter`
    /// narrows by function name (case-insensitive substring, or a regex
    /// when the text carries a `re:` prefix); `sort` orders the window.
    pub fn functions_page(
        &self,
        program: ProgramId,
        offset: u64,
        limit: u64,
        filter: Option<&FunctionsFilter>,
        sort: Option<(FunctionSort, bool)>,
    ) -> Result<(Vec<FunctionRow>, Option<u64>, u64)> {
        let (sort_key, ascending) = sort.unwrap_or((FunctionSort::Entry, true));
        match filter {
            None => {
                let total: i64 = self.conn.query_row(
                    "SELECT COUNT(*) FROM functions WHERE program_id = ?1",
                    params![program.0],
                    |r| r.get(0),
                )?;
                let sql = format!(
                    "{FUNCTION_SELECT} WHERE f.program_id = ?1
                     ORDER BY f.{} {} LIMIT ?2 OFFSET ?3",
                    sort_key.sql_column(),
                    if ascending { "ASC" } else { "DESC" }
                );
                let mut stmt = self.conn.prepare(&sql)?;
                let rows = stmt
                    .query_map(params![program.0, limit, offset], map_function)?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok((rows, Some(total as u64), self.revision(program)?))
            }
            Some(filter) => {
                // Filtered path: scan, filter, sort, and paginate in Rust.
                // SQLite cannot evaluate regex, and function tables are
                // small (thousands of rows), so one code path keeps the
                // total count consistent with the returned window.
                let mut stmt = self.conn.prepare(
                    &format!("{FUNCTION_SELECT} WHERE f.program_id = ?1"),
                )?;
                let mut rows = stmt
                    .query_map(params![program.0], map_function)?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows.retain(|row| filter.matches(&row.name));
                rows.sort_by(|a, b| sort_key.compare(a, b));
                if !ascending {
                    rows.reverse();
                }
                let total = rows.len() as u64;
                let start = (offset as usize).min(rows.len());
                let end = (start + limit as usize).min(rows.len());
                Ok((rows[start..end].to_vec(), Some(total), self.revision(program)?))
            }
        }
    }

    /// Paged symbols (review CORE-004).
    pub fn symbols_page(
        &self,
        program: ProgramId,
        offset: u64,
        limit: u64,
        evidence: Option<EvidenceKind>,
    ) -> Result<(Vec<SymbolRow>, Option<u64>, u64)> {
        // The filter narrows the count as well as the window: a total that
        // counted facts the page cannot return would be a lie about the page.
        let (filter, bound) = evidence_clause("source", evidence, 2);
        let total: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM symbols WHERE program_id = ?1{filter}"),
            rusqlite::params_from_iter(
                std::iter::once(Value::Integer(program.0 as i64)).chain(bound.iter().cloned())),
            |r| r.get(0),
        )?;
        let (filter, bound) = evidence_clause("source", evidence, 4);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT address, name, external, source FROM symbols
             WHERE program_id = ?1{filter} ORDER BY address LIMIT ?2 OFFSET ?3",
        ))?;
        let rows = stmt
            .query_map(
                rusqlite::params_from_iter(
                    [Value::Integer(program.0 as i64), Value::Integer(limit as i64),
                     Value::Integer(offset as i64)]
                        .into_iter()
                        .chain(bound),
                ),
                map_symbol,
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, Some(total as u64), self.revision(program)?))
    }

    /// Paged xrefs in one direction (review CORE-004).
    pub fn xrefs_page(
        &self,
        program: ProgramId,
        address: &romwright_model::Address,
        incoming: bool,
        offset: u64,
        limit: u64,
        evidence: Option<EvidenceKind>,
    ) -> Result<(Vec<XrefRow>, Option<u64>, u64)> {
        let cell = addr_cell(address);
        let (src, dst) = (cell.clone(), cell);
        let column = if incoming { "dst" } else { "src" };
        let (filter, bound) = evidence_clause("provenance", evidence, 3);
        let total: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM xrefs \
                 WHERE program_id = ?1 AND {column} = ?2{filter}"
            ),
            rusqlite::params_from_iter(
                [Value::Integer(program.0 as i64), Value::Text(dst.clone())]
                    .into_iter()
                    .chain(bound),
            ),
            |r| r.get(0),
        )?;
        // The containing function resolves at query time: the function
        // whose [entry, entry+size) range holds the source address.
        let (order, key) = if incoming { ("x.src", dst) } else { ("x.dst", src) };
        let (filter, bound) = evidence_clause("x.provenance", evidence, 5);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT x.src, x.dst, x.kind, \
              NULL, \
              x.provenance, x.provenance_kind, x.confidence \
              FROM xrefs x WHERE x.program_id = ?1 AND x.{column} = ?2{filter}
              ORDER BY {order} LIMIT ?3 OFFSET ?4"
        ))?;
        let mut rows = stmt
            .query_map(
                rusqlite::params_from_iter(
                    [Value::Integer(program.0 as i64), Value::Text(key),
                     Value::Integer(limit as i64), Value::Integer(offset as i64)]
                        .into_iter()
                        .chain(bound),
                ),
                map_xref,
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.resolve_containing(program, &mut rows)?;
        Ok((rows, Some(total as u64), self.revision(program)?))
    }

    /// Function extents in entry order, for resolving the function that
    /// contains a reference's source address.
    ///
    /// This was a correlated subquery comparing `x.src` (hex text) with
    /// `f.entry + f.size` (an integer expression). SQLite coerced the text
    /// entry to a decimal integer -- `'0040033c'` became 40033 -- so the
    /// containment test compared unrelated numbers and named whichever row
    /// the scan reached first. Parsing the addresses is the only way to
    /// compare them.
    fn function_extents(&self, program: ProgramId) -> Result<Vec<(u64, u64, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT entry, size, name FROM functions WHERE program_id = ?1")?;
        let mut extents = stmt
            .query_map(params![program.0], |row| {
                let entry: String = row.get(0)?;
                let size: i64 = row.get(1)?;
                let name: String = row.get(2)?;
                let entry = addr_from_cell(entry, 0)?;
                Ok((entry.offset, entry.offset.saturating_add(size.max(0) as u64), name))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        extents.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Ok(extents)
    }

    /// Names the function containing each row's source address; a source
    /// outside every function body keeps `None`, which is what a reference
    /// from data is.
    fn resolve_containing(&self, program: ProgramId, rows: &mut [XrefRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let extents = self.function_extents(program)?;
        for row in rows {
            let index = extents.partition_point(|(entry, _, _)| *entry <= row.from.offset);
            row.function = index
                .checked_sub(1)
                .and_then(|index| extents.get(index))
                .filter(|(_, end, _)| row.from.offset < *end)
                .map(|(_, _, name)| name.clone());
        }
        Ok(())
    }

    /// Lists xrefs pointing at `address`.
    pub fn xrefs_to(&self, program: ProgramId, address: &romwright_model::Address) -> Result<Vec<XrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT x.src, x.dst, x.kind, \
              NULL, \
              x.provenance, x.provenance_kind, x.confidence \
              FROM xrefs x WHERE x.program_id = ?1 AND x.dst = ?2 ORDER BY x.src",
        )?;
        let mut rows = stmt
            .query_map(params![program.0, addr_cell(address)], map_xref)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.resolve_containing(program, &mut rows)?;
        Ok(rows)
    }

    /// Lists xrefs leaving `address`.
    pub fn xrefs_from(&self, program: ProgramId, address: &romwright_model::Address) -> Result<Vec<XrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT x.src, x.dst, x.kind, \
              NULL, \
              x.provenance, x.provenance_kind, x.confidence \
              FROM xrefs x WHERE x.program_id = ?1 AND x.src = ?2 ORDER BY x.dst",
        )?;
        let mut rows = stmt
            .query_map(params![program.0, addr_cell(address)], map_xref)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.resolve_containing(program, &mut rows)?;
        Ok(rows)
    }
    /// Lists all xrefs of a program ordered by source and destination.
    pub fn xrefs(&self, program: ProgramId) -> Result<Vec<XrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT x.src, x.dst, x.kind, \
              NULL, \
              x.provenance, x.provenance_kind, x.confidence \
              FROM xrefs x WHERE x.program_id = ?1 ORDER BY x.src, x.dst",
        )?;
        let mut rows = stmt
            .query_map(params![program.0], map_xref)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.resolve_containing(program, &mut rows)?;
        Ok(rows)
    }

    /// Lists unique call edges in numeric source/destination offset order.
    /// Address spaces are preserved; branches and data references are excluded.
    pub fn call_edges(
        &self,
        program: ProgramId,
    ) -> Result<Vec<(romwright_model::Address, romwright_model::Address)>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT src, dst FROM xrefs WHERE program_id = ?1 AND instr(kind, 'CALL') > 0",
        )?;
        let mut edges = stmt.query_map(params![program.0], |row| {
            Ok((addr_from_cell(row.get(0)?, 0)?, addr_from_cell(row.get(1)?, 1)?))
        })?.collect::<std::result::Result<Vec<_>, _>>()?;
        // Hex cells can have different widths; SQL text order is not numeric.
        edges.sort_unstable_by_key(|(from, to)| (from.offset, to.offset));
        Ok(edges)
    }

    /// Locations whose contents a fact types.
    pub fn data_definitions(
        &self,
        program: ProgramId,
    ) -> Result<Vec<romwright_model::DataDefinitionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, type, size, provenance, provenance_kind, confidence
             FROM data_definitions WHERE program_id = ?1 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                Ok(romwright_model::DataDefinitionRow {
                    address: addr_from_cell(row.get(0)?, 0)?,
                    data_type: row.get(1)?,
                    size: row.get::<_, i64>(2)?.max(0) as u64,
                    provenance: romwright_model::FactProvenance {
                        kind: if row.get::<_, String>(4)? == "asserted" {
                            romwright_model::FactKind::Asserted
                        } else {
                            romwright_model::FactKind::Inferred
                        },
                        source: row.get(3)?,
                        confidence: row.get(5)?,
                    },
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Replaces exactly this producer's inferred data definitions.
    pub fn replace_inferred_data_definitions(
        &self,
        program: ProgramId,
        source: &str,
        rows: &[romwright_model::DataDefinitionRow],
    ) -> Result<()> {
        if source.trim().is_empty() {
            return Err(DbError::InvalidFactProvenance(
                "inference source is empty".into(),
            ));
        }
        for row in rows {
            validate_fact_provenance(&row.provenance)?;
            if row.provenance.kind != FactKind::Inferred || row.provenance.source != source {
                return Err(DbError::InvalidFactProvenance(format!(
                    "data definition does not belong to inference source {source}"
                )));
            }
            if row.size == 0 {
                return Err(DbError::InvalidFactProvenance(
                    "a data definition needs a width".into(),
                ));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let before = self.definition_cells(&tx, program, source)?;
        tx.execute(
            "DELETE FROM data_definitions WHERE program_id = ?1 AND provenance = ?2
                 AND provenance_kind = 'inferred'",
            params![program.0, source],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO data_definitions(program_id, address, type, size,
                     provenance, provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'inferred', ?6)
                 ON CONFLICT(program_id, address) DO NOTHING",
            )?;
            for row in rows {
                insert.execute(params![
                    program.0,
                    addr_cell(&row.address),
                    row.data_type,
                    row.size as i64,
                    row.provenance.source,
                    row.provenance.confidence,
                ])?;
            }
        }
        if self.definition_cells(&tx, program, source)? != before {
            self.bump_and_record(&tx, program, "replace-inferred-data-definitions", source)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn definition_cells(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        source: &str,
    ) -> Result<Vec<(String, String, i64)>> {
        let mut stmt = tx.prepare(
            "SELECT address, type, size FROM data_definitions
             WHERE program_id = ?1 AND provenance = ?2 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0, source], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Instruction flow the image's own structure corrects.
    /// The protected call sites of one program, ordered by range start.
    pub fn exception_sites(
        &self,
        program: ProgramId,
    ) -> Result<Vec<romwright_model::ExceptionSiteRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT function, start, end, landing_pad, provenance, provenance_kind, confidence
             FROM exception_sites WHERE program_id = ?1 ORDER BY start",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                Ok(romwright_model::ExceptionSiteRow {
                    function: addr_from_cell(row.get(0)?, 0)?,
                    start: addr_from_cell(row.get(1)?, 1)?,
                    end: addr_from_cell(row.get(2)?, 2)?,
                    landing_pad: addr_from_cell(row.get(3)?, 3)?,
                    provenance: romwright_model::FactProvenance {
                        kind: if row.get::<_, String>(5)? == "asserted" {
                            romwright_model::FactKind::Asserted
                        } else {
                            romwright_model::FactKind::Inferred
                        },
                        source: row.get(4)?,
                        confidence: row.get(6)?,
                    },
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Replaces the protected call sites one producer owns, leaving another
    /// producer's rows alone.
    pub fn replace_exception_sites(
        &self,
        program: ProgramId,
        source: &str,
        rows: &[romwright_model::ExceptionSiteRow],
    ) -> Result<()> {
        if source.trim().is_empty() {
            return Err(DbError::InvalidFactProvenance(
                "exception site source is empty".into(),
            ));
        }
        for row in rows {
            validate_fact_provenance(&row.provenance)?;
            if row.provenance.source != source {
                return Err(DbError::InvalidFactProvenance(format!(
                    "exception site does not belong to source {source}"
                )));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM exception_sites WHERE program_id = ?1 AND provenance = ?2",
            params![program.0, source],
        )?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO exception_sites(program_id, function, start, end,
                     landing_pad, provenance, provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for row in rows {
                stmt.execute(params![
                    program.0,
                    addr_cell(&row.function),
                    addr_cell(&row.start),
                    addr_cell(&row.end),
                    addr_cell(&row.landing_pad),
                    row.provenance.source,
                    match row.provenance.kind {
                        FactKind::Asserted => "asserted",
                        FactKind::Inferred => "inferred",
                    },
                    row.provenance.confidence,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn flow_overrides(
        &self,
        program: ProgramId,
    ) -> Result<Vec<romwright_model::FlowOverrideRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, kind, provenance, provenance_kind, confidence
             FROM flow_overrides WHERE program_id = ?1 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                Ok(romwright_model::FlowOverrideRow {
                    address: addr_from_cell(row.get(0)?, 0)?,
                    kind: row.get(1)?,
                    provenance: romwright_model::FactProvenance {
                        kind: if row.get::<_, String>(3)? == "asserted" {
                            romwright_model::FactKind::Asserted
                        } else {
                            romwright_model::FactKind::Inferred
                        },
                        source: row.get(2)?,
                        confidence: row.get(4)?,
                    },
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Replaces exactly this producer's inferred flow overrides.
    pub fn replace_inferred_flow_overrides(
        &self,
        program: ProgramId,
        source: &str,
        rows: &[romwright_model::FlowOverrideRow],
    ) -> Result<()> {
        if source.trim().is_empty() {
            return Err(DbError::InvalidFactProvenance(
                "inference source is empty".into(),
            ));
        }
        for row in rows {
            validate_fact_provenance(&row.provenance)?;
            if row.provenance.kind != FactKind::Inferred || row.provenance.source != source {
                return Err(DbError::InvalidFactProvenance(format!(
                    "flow override does not belong to inference source {source}"
                )));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let before = self.flow_override_cells(&tx, program, source)?;
        tx.execute(
            "DELETE FROM flow_overrides WHERE program_id = ?1 AND provenance = ?2
                 AND provenance_kind = 'inferred'",
            params![program.0, source],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO flow_overrides(program_id, address, kind, provenance,
                     provenance_kind, confidence)
                 VALUES (?1, ?2, ?3, ?4, 'inferred', ?5)
                 ON CONFLICT(program_id, address) DO NOTHING",
            )?;
            for row in rows {
                insert.execute(params![
                    program.0,
                    addr_cell(&row.address),
                    row.kind,
                    row.provenance.source,
                    row.provenance.confidence,
                ])?;
            }
        }
        if self.flow_override_cells(&tx, program, source)? != before {
            self.bump_and_record(&tx, program, "replace-inferred-flow-overrides", source)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn flow_override_cells(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        source: &str,
    ) -> Result<Vec<(String, String)>> {
        let mut stmt = tx.prepare(
            "SELECT address, kind FROM flow_overrides
             WHERE program_id = ?1 AND provenance = ?2 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0, source], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Distinct destinations of data references, address spaces preserved.
    /// The decompiler names such a location on demand, so the worker needs
    /// the set rather than one edge at a time.
    pub fn data_reference_targets(&self, program: ProgramId) -> Result<Vec<romwright_model::Address>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT dst FROM xrefs
             WHERE program_id = ?1 AND kind IN ('DATA', 'READ', 'WRITE')",
        )?;
        let mut targets = stmt
            .query_map(params![program.0], |row| addr_from_cell(row.get(0)?, 0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        targets.sort_unstable_by_key(|address| address.offset);
        Ok(targets)
    }


    /// Lists symbols of a program ordered by address.
    pub fn symbols(&self, program: ProgramId) -> Result<Vec<SymbolRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, name, external, source
             FROM symbols WHERE program_id = ?1 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0], map_symbol)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Replaces discovered strings atomically.
    pub fn replace_strings<'a>(&self, program: ProgramId, rows: impl IntoIterator<Item = &'a StringRow>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM strings WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO strings(program_id, address, value, kind)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        let mut count = 0usize;
        for row in rows {
            stmt.execute(params![
                program.0,
                addr_cell(&row.address),
                row.value,
                row.kind
            ])?;
            count += 1;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-strings", &count.to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists strings ordered by address.
    pub fn strings(&self, program: ProgramId) -> Result<Vec<StringRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, value, kind FROM strings
             WHERE program_id = ?1 ORDER BY address, value",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(StringRow {
                    address: addr_from_cell(row.get(0)?, 0)?,
                    value: row.get(1)?,
                    kind: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Paged strings (Phase 2.3): a bounded window + total + revision,
    /// ordered by address like the full listing.
    pub fn strings_page(
        &self,
        program: ProgramId,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<StringRow>, Option<u64>, u64)> {
        let total: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM strings WHERE program_id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT address, value, kind FROM strings
             WHERE program_id = ?1 ORDER BY address, value LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt
            .query_map(params![program.0, limit, offset], |row| {
                Ok(StringRow {
                    address: addr_from_cell(row.get(0)?, 0)?,
                    value: row.get(1)?,
                    kind: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, Some(total as u64), self.revision(program)?))
    }

    /// Searches durable names, strings, comments, and data types. The query
    /// is bounded by `limit` and never loads native bytes or starts a worker.
    pub fn search(&self, program: ProgramId, term: &str, limit: u64) -> Result<Vec<SearchHit>> {
        let pattern = format!("%{term}%");
        let mut hits = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT entry, name FROM functions
                 WHERE program_id = ?1 AND (entry LIKE ?2 OR name LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?, 0)?),
                    kind: "function".into(),
                    name: row.get(1)?,
                    context: String::new(),
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT address, name, source FROM symbols
                 WHERE program_id = ?1 AND (address LIKE ?2 OR name LIKE ?2 OR source LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?, 0)?),
                    kind: "symbol".into(),
                    name: row.get(1)?,
                    context: row.get(2)?,
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT address, value, kind FROM strings
                 WHERE program_id = ?1 AND (address LIKE ?2 OR value LIKE ?2 OR kind LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?, 0)?),
                    kind: "string".into(),
                    name: row.get(1)?,
                    context: row.get(2)?,
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT address, type, text FROM comments
                 WHERE program_id = ?1 AND (address LIKE ?2 OR type LIKE ?2 OR text LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?, 0)?),
                    kind: "comment".into(),
                    name: row.get(2)?,
                    context: row.get(1)?,
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT name, definition FROM datatypes
                 WHERE program_id = ?1 AND (name LIKE ?2 OR definition LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: None,
                    kind: "datatype".into(),
                    name: row.get(0)?,
                    context: row.get(1)?,
                })
            })? {
                hits.push(row?);
            }
        }
        hits.sort_by_key(|hit| {
            (
                hit.address.as_ref().map(|address| address.offset).unwrap_or(u64::MAX),
                hit.kind.clone(),
                hit.name.clone(),
            )
        });
        hits.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(hits)
    }

    /// Returns graph nodes for functions and all stored reference edges.
    pub fn function_graph(&self, program: ProgramId) -> Result<(Vec<GraphNode>, Vec<GraphEdge>)> {
        let mut nodes = self
            .functions(program)?
            .into_iter()
            .map(|function| GraphNode {
                address: function.entry,
                name: function.name,
            })
            .collect::<Vec<_>>();
        let mut known = nodes
            .iter()
            .map(|node| node.address.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut stmt = self
            .conn
            .prepare("SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 ORDER BY src, dst")?;
        let edges = stmt
            .query_map(params![program.0], |row| {
                Ok(GraphEdge {
                    from: addr_from_cell(row.get(0)?, 0)?,
                    to: addr_from_cell(row.get(1)?, 1)?,
                    kind: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for edge in &edges {
            if known.insert(edge.to.clone()) {
                nodes.push(GraphNode {
                    name: format!("loc_{}", edge.to.hex()),
                    address: edge.to.clone(),
                });
            }
            if known.insert(edge.from.clone()) {
                nodes.push(GraphNode {
                    name: format!("loc_{}", edge.from.hex()),
                    address: edge.from.clone(),
                });
            }
        }
        nodes.sort_by_key(|node| node.address.offset);
        Ok((nodes, edges))
    }



    /// Replaces the memory map associated with a program.
    pub fn replace_memory_regions(
        &self,
        program: ProgramId,
        rows: &[MemoryRegion],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM memory_regions WHERE program_id = ?1",
            params![program.0],
        )?;
        let mut stmt = tx.prepare(
            "INSERT INTO memory_regions(program_id, name, start, size, permissions, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.name,
                addr_cell(&row.start),
                row.size,
                row.permissions,
                row.source
            ])?;
        }
        drop(stmt);
        self.bump_and_record(
            &tx,
            program,
            "replace-memory-regions",
            &rows.len().to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Lists mapped memory regions by start address.
    pub fn memory_regions(&self, program: ProgramId) -> Result<Vec<MemoryRegion>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, start, size, permissions, source FROM memory_regions
             WHERE program_id = ?1 ORDER BY start, name",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(MemoryRegion {
                    name: row.get(0)?,
                    start: addr_from_cell(row.get(1)?, 1)?,
                    size: row.get(2)?,
                    permissions: row.get(3)?,
                    source: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Upserts one bookmark and records the revision change.
    pub fn set_bookmark(&self, program: ProgramId, row: &BookmarkRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO bookmarks(program_id, address, label, comment)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(program_id, address)
             DO UPDATE SET label = excluded.label, comment = excluded.comment",
            params![program.0, addr_cell(&row.address), row.label, row.comment],
        )?;
        self.bump_and_record(&tx, program, "bookmark", &row.label)?;
        tx.commit()?;
        Ok(())
    }

    /// Removes one bookmark and records the revision change.
    pub fn delete_bookmark(&self, program: ProgramId, address: &romwright_model::Address) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM bookmarks WHERE program_id = ?1 AND address = ?2",
            params![program.0, addr_cell(address)],
        )?;
        self.bump_and_record(&tx, program, "bookmark-delete", &address.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists bookmarks by address.
    pub fn bookmarks(&self, program: ProgramId) -> Result<Vec<BookmarkRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, label, comment FROM bookmarks
             WHERE program_id = ?1 ORDER BY address",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(BookmarkRow {
                    address: addr_from_cell(row.get(0)?, 0)?,
                    label: row.get(1)?,
                    comment: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Stores both the original bytes and the currently selected patch.
    pub fn set_patch(
        &self,
        program: ProgramId,
        row: &PatchRow,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO patches(program_id, address, original_hex, patched_hex, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(program_id, address)
             DO UPDATE SET original_hex = excluded.original_hex,
                           patched_hex = excluded.patched_hex,
                           enabled = excluded.enabled",
            params![
                program.0,
                addr_cell(&row.address),
                hex_encode(&row.original),
                hex_encode(&row.patched),
                row.enabled as i64
            ],
        )?;
        self.bump_and_record(&tx, program, "patch", &row.address.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Removes one patch record.
    pub fn delete_patch(&self, program: ProgramId, address: &romwright_model::Address) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM patches WHERE program_id = ?1 AND address = ?2",
            params![program.0, addr_cell(address)],
        )?;
        self.bump_and_record(&tx, program, "patch-delete", &address.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists patch records by address.
    pub fn patches(&self, program: ProgramId) -> Result<Vec<PatchRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, original_hex, patched_hex, enabled FROM patches
             WHERE program_id = ?1 ORDER BY address",
        )?;
        let raw = stmt
            .query_map(params![program.0], |row| {
                Ok((
                    addr_from_cell(row.get(0)?, 0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? != 0,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(|(address, original, patched, enabled)| {
                Ok(PatchRow {
                    address,
                    original: hex_decode(&original)?,
                    patched: hex_decode(&patched)?,
                    enabled,
                })
            })
            .collect()
    }

    /// Replaces the comment set of a program inside one transaction.
    pub fn replace_comments(&self, program: ProgramId, rows: &[CommentRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM comments WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO comments(program_id, address, function, type, text)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for r in rows {
            stmt.execute(params![
                program.0,
                addr_cell(&r.address),
                addr_cell(&r.function),
                r.kind,
                r.text
            ])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-comments", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the datatype set of a program inside one transaction.
    pub fn replace_datatypes(&self, program: ProgramId, rows: &[DataTypeRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM datatypes WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO datatypes(program_id, name, definition)
             VALUES (?1, ?2, ?3)",
        )?;
        for r in rows {
            stmt.execute(params![program.0, r.name, r.definition])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-datatypes", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Lists comments of a program ordered by address.
    pub fn comments(&self, program: ProgramId) -> Result<Vec<CommentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, function, type, text FROM comments
             WHERE program_id = ?1 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0], |r| {
                Ok(CommentRow {
                    address: addr_from_cell(r.get(0)?, 0)?,
                    function: addr_from_cell(r.get(1)?, 1)?,
                    kind: r.get(2)?,
                    text: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists datatypes of a program ordered by name.
    pub fn datatypes(&self, program: ProgramId) -> Result<Vec<DataTypeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, definition FROM datatypes
             WHERE program_id = ?1 ORDER BY name",
        )?;
        let rows = stmt
            .query_map(params![program.0], |r| {
                Ok(DataTypeRow {
                    name: r.get(0)?,
                    definition: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
    /// Upserts one rich type definition.
    pub fn set_type_def(&self, program: ProgramId, row: &TypeDefRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO type_defs(
                 program_id, name, kind, definition, size, alignment, base_type, provenance,
                 primitive, element_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(program_id, name) DO UPDATE SET
                 kind = excluded.kind, definition = excluded.definition,
                 size = excluded.size, alignment = excluded.alignment,
                 base_type = excluded.base_type, provenance = excluded.provenance,
                 primitive = excluded.primitive, element_count = excluded.element_count",
            params![
                program.0,
                row.name,
                row.kind,
                row.definition,
                row.size,
                row.alignment,
                row.base_type,
                row.provenance,
                row.primitive.map(romwright_model::PrimitiveKind::as_str),
                row.element_count
            ],
        )?;
        self.bump_and_record(&tx, program, "type-def", &row.name)?;
        tx.commit()?;
        Ok(())
    }

    /// Upserts one composite type field.
    pub fn set_type_field(&self, program: ProgramId, row: &TypeFieldRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO type_fields(
                 program_id, type_name, ordinal, field_name, offset, size, type_ref
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(program_id, type_name, ordinal) DO UPDATE SET
                 field_name = excluded.field_name, offset = excluded.offset,
                 size = excluded.size, type_ref = excluded.type_ref",
            params![
                program.0,
                row.type_name,
                row.ordinal,
                row.field_name,
                row.offset,
                row.size,
                row.type_ref
            ],
        )?;
        self.bump_and_record(&tx, program, "type-field", &row.type_name)?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the rich type definitions exported by a provider.
    pub fn replace_type_defs(&self, program: ProgramId, rows: &[TypeDefRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM type_defs WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO type_defs(
                 program_id, name, kind, definition, size, alignment, base_type, provenance,
                 primitive, element_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.name,
                row.kind,
                row.definition,
                row.size,
                row.alignment,
                row.base_type,
                row.provenance,
                row.primitive.map(romwright_model::PrimitiveKind::as_str),
                row.element_count
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-type-defs", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists rich type definitions by name.
    pub fn type_defs(&self, program: ProgramId) -> Result<Vec<TypeDefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, kind, definition, size, alignment, base_type, provenance,
                    primitive, element_count
             FROM type_defs WHERE program_id = ?1 ORDER BY name",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(TypeDefRow {
                    name: row.get(0)?,
                    kind: row.get(1)?,
                    definition: row.get(2)?,
                    size: row.get::<_, Option<i64>>(3)?.map(|value| value as u64),
                    alignment: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
                    base_type: row.get(5)?,
                    provenance: row.get(6)?,
                    primitive: row.get::<_, Option<String>>(7)?.map(|value| {
                        serde_json::from_value(serde_json::Value::String(value)).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                7, rusqlite::types::Type::Text, Box::new(error),
                            )
                        })
                    }).transpose()?,
                    element_count: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replaces all composite fields for a program.
    pub fn replace_type_fields(&self, program: ProgramId, rows: &[TypeFieldRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM type_fields WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO type_fields(
                 program_id, type_name, ordinal, field_name, offset, size, type_ref
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.type_name,
                row.ordinal,
                row.field_name,
                row.offset,
                row.size,
                row.type_ref
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-type-fields", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists fields, optionally restricted to one type.
    pub fn type_fields(
        &self,
        program: ProgramId,
        type_name: Option<&str>,
    ) -> Result<Vec<TypeFieldRow>> {
        let mut rows = Vec::new();
        if let Some(type_name) = type_name {
            let mut stmt = self.conn.prepare(
                "SELECT type_name, ordinal, field_name, offset, size, type_ref
                 FROM type_fields WHERE program_id = ?1 AND type_name = ?2
                 ORDER BY ordinal",
            )?;
            for row in stmt.query_map(params![program.0, type_name], map_type_field)? {
                rows.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT type_name, ordinal, field_name, offset, size, type_ref
                 FROM type_fields WHERE program_id = ?1 ORDER BY type_name, ordinal",
            )?;
            for row in stmt.query_map(params![program.0], map_type_field)? {
                rows.push(row?);
            }
        }
        Ok(rows)
    }

    /// Lists the type graph and its provenance-bearing edges.
    pub fn type_graph(
        &self,
        program: ProgramId,
    ) -> Result<(Vec<TypeGraphNode>, Vec<TypeLinkRow>)> {
        let nodes = self
            .type_defs(program)?
            .into_iter()
            .map(|row| TypeGraphNode {
                name: row.name,
                kind: row.kind,
                size: row.size,
            })
            .collect();
        Ok((nodes, self.type_links(program)?))
    }

    /// Replaces inferred prototypes while retaining existing assertions.
    pub fn replace_prototypes(&self, program: ProgramId, rows: &[PrototypeRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM prototypes WHERE program_id = ?1 AND provenance_kind = 'inferred'",
            params![program.0],
        )?;
        Self::insert_prototypes(&tx, program, rows, None)?;
        self.bump_and_record(&tx, program, "replace-prototypes", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Upserts one prototype; an inference cannot overwrite an assertion.
    pub fn set_prototype(&self, program: ProgramId, row: &PrototypeRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        Self::insert_prototypes(&tx, program, std::slice::from_ref(row), None)?;
        self.bump_and_record(&tx, program, "prototype", &row.function.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Merges one inference round against its input snapshot. Unchanged facts
    /// and assertion conflicts neither advance the revision nor notify callers.
    pub fn merge_inferred_prototypes(
        &self, program: ProgramId, expected: u64, rows: &[PrototypeRow],
    ) -> Result<Vec<romwright_model::Address>> {
        if rows.iter().any(|row| row.provenance.kind != FactKind::Inferred) {
            return Err(DbError::InvalidFactProvenance(
                "inference batches must contain only inferred facts".into(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        let actual = self.revision(program)?;
        if actual != expected {
            return Err(DbError::StaleRevision { expected, actual });
        }
        let mut changed = Vec::new();
        Self::insert_prototypes(&tx, program, rows, Some(&mut changed))?;
        if !changed.is_empty() {
            self.bump_and_record(&tx, program, "infer-prototypes", &changed.len().to_string())?;
        }
        tx.commit()?;
        Ok(changed)
    }

    fn insert_prototypes(
        tx: &rusqlite::Transaction<'_>, program: ProgramId, rows: &[PrototypeRow],
        mut changed: Option<&mut Vec<romwright_model::Address>>,
    ) -> Result<()> {
        let mut stmt = tx.prepare(
            "INSERT INTO prototypes(
                 program_id, function, signature, calling_convention, return_type,
                 provenance, provenance_kind, confidence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(program_id, function) DO UPDATE SET
                 signature = excluded.signature,
                 calling_convention = excluded.calling_convention,
                 return_type = excluded.return_type,
                 provenance = excluded.provenance,
                 provenance_kind = excluded.provenance_kind,
                 confidence = excluded.confidence
             WHERE (prototypes.provenance_kind = 'inferred'
                OR excluded.provenance_kind = 'asserted')
               AND (prototypes.signature IS NOT excluded.signature
                OR prototypes.calling_convention IS NOT excluded.calling_convention
                OR prototypes.return_type IS NOT excluded.return_type
                OR prototypes.provenance IS NOT excluded.provenance
                OR prototypes.provenance_kind IS NOT excluded.provenance_kind
                OR prototypes.confidence IS NOT excluded.confidence)",
        )?;
        for row in rows {
            let ownership = validate_fact_provenance(&row.provenance)?;
            let count = stmt.execute(params![
                program.0, addr_cell(&row.function), row.signature,
                row.calling_convention, row.return_type, row.provenance.source,
                ownership, row.provenance.confidence,
            ])?;
            if count != 0 {
                if let Some(changed) = changed.as_mut() {
                    changed.push(row.function.clone());
                }
            }
        }
        Ok(())
    }

    /// Lists prototypes ordered by function address.
    pub fn prototypes(&self, program: ProgramId) -> Result<Vec<PrototypeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT function, signature, calling_convention, return_type,
                    provenance, provenance_kind, confidence
             FROM prototypes WHERE program_id = ?1 ORDER BY function",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(PrototypeRow {
                    function: addr_from_cell(row.get(0)?, 0)?,
                    signature: row.get(1)?,
                    calling_convention: row.get(2)?,
                    return_type: row.get(3)?,
                    provenance: map_fact_provenance(row, 4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replaces recovered stack variables.
    /// Replaces the processor-context values discovery settled for this
    /// program: the instruction set each function entry was decoded in and
    /// every declared mode change (`LowBitCodeMode`/`TMode` on ARM,
    /// `ISA_MODE` on MIPS). A decompile worker replays them so it reads the
    /// same bytes the same way.
    pub fn replace_decode_contexts(
        &self,
        program: ProgramId,
        rows: &[(romwright_model::Address, String, u64)],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM decode_contexts WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO decode_contexts(program_id, address, name, value)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (address, name, value) in rows {
            stmt.execute(params![program.0, addr_cell(address), name, *value as i64])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    /// The decode contexts recorded for a program, ascending by address.
    pub fn decode_contexts(&self, program: ProgramId) -> Result<Vec<(romwright_model::Address, String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, name, value FROM decode_contexts WHERE program_id = ?1 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                Ok((addr_from_cell(row.get(0)?, 0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)? as u64))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }


    pub fn set_stack_variable(
        &self,
        program: ProgramId,
        row: &StackVariableRow,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO stack_variables(
                 program_id, function, ordinal, name, storage, type_name, offset, size
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(program_id, function, ordinal) DO UPDATE SET
                 name = excluded.name, storage = excluded.storage,
                 type_name = excluded.type_name, offset = excluded.offset,
                 size = excluded.size",
            params![
                program.0,
                addr_cell(&row.function),
                row.ordinal,
                row.name,
                row.storage,
                row.type_name,
                row.offset,
                row.size
            ],
        )?;
        self.bump_and_record(&tx, program, "stack-variable", &row.name)?;
        tx.commit()?;
        Ok(())
    }
    pub fn replace_stack_variables(
        &self,
        program: ProgramId,
        rows: &[StackVariableRow],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM stack_variables WHERE program_id = ?1",
            params![program.0],
        )?;
        let mut stmt = tx.prepare(
            "INSERT INTO stack_variables(
                 program_id, function, ordinal, name, storage, type_name, offset, size
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                addr_cell(&row.function),
                row.ordinal,
                row.name,
                row.storage,
                row.type_name,
                row.offset,
                row.size
            ])?;
        }
        drop(stmt);
        self.bump_and_record(
            &tx,
            program,
            "replace-stack-variables",
            &rows.len().to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }


    /// Lists stack variables, optionally restricted to a function.
    pub fn stack_variables(
        &self,
        program: ProgramId,
        function: Option<&romwright_model::Address>,
    ) -> Result<Vec<StackVariableRow>> {
        let mut rows = Vec::new();
        if let Some(function) = function {
            let mut stmt = self.conn.prepare(
                "SELECT function, ordinal, name, storage, type_name, offset, size
                 FROM stack_variables WHERE program_id = ?1 AND function = ?2
                 ORDER BY ordinal",
            )?;
            for row in stmt.query_map(params![program.0, addr_cell(function)], map_stack_variable)? {
                rows.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT function, ordinal, name, storage, type_name, offset, size
                 FROM stack_variables WHERE program_id = ?1 ORDER BY function, ordinal",
            )?;
            for row in stmt.query_map(params![program.0], map_stack_variable)? {
                rows.push(row?);
            }
        }
        Ok(rows)
    }

    /// Replaces type dependency edges and their provenance.
    pub fn replace_type_links(&self, program: ProgramId, rows: &[TypeLinkRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM type_links WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO type_links(program_id, source, target, kind, provenance)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.source,
                row.target,
                row.kind,
                row.provenance
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-type-links", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Every program the project holds, in import order.
    pub fn programs(&self) -> Result<Vec<romwright_model::ProgramRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.name, p.language, p.compiler, p.revision, \
             (SELECT COUNT(*) FROM functions f WHERE f.program_id = p.id) \
             FROM programs p ORDER BY p.id",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let revision: i64 = row.get(3)?;
                let functions: i64 = row.get(4)?;
                Ok(romwright_model::ProgramRow {
                    program: row.get(0)?,
                    language: row.get(1)?,
                    compiler: row.get(2)?,
                    functions: functions.max(0) as u64,
                    revision: revision.max(0) as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Upserts one provenance-bearing type dependency.
    pub fn set_type_link(&self, program: ProgramId, row: &TypeLinkRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO type_links(program_id, source, target, kind, provenance)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(program_id, source, target, kind) DO UPDATE SET
                 provenance = excluded.provenance",
            params![
                program.0,
                row.source,
                row.target,
                row.kind,
                row.provenance
            ],
        )?;
        self.bump_and_record(
            &tx,
            program,
            "type-link",
            &format!("{} -> {}", row.source, row.target),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Lists type dependency edges.
    pub fn type_links(&self, program: ProgramId) -> Result<Vec<TypeLinkRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT source, target, kind, provenance FROM type_links
             WHERE program_id = ?1 ORDER BY source, target",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(TypeLinkRow {
                    source: row.get(0)?,
                    target: row.get(1)?,
                    kind: row.get(2)?,
                    provenance: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }


    /// Every program mapping `address`, with the region that maps it and the
    /// function containing it. A project holds more than one image -- a DS
    /// pair, an executable and its overlays -- and those images overlap, so
    /// the answer is a list rather than one program.
    pub fn locate(&self, address: &romwright_model::Address) -> Result<Vec<romwright_model::LocationRow>> {
        let mut found = Vec::new();
        for program in self.programs()? {
            let id = self.program_id(&program.program)?;
            let Some(region) = self.memory_regions(id)?.into_iter().find(|region| {
                region.start.space == address.space
                    && region.start.offset <= address.offset
                    && address.offset - region.start.offset < region.size
            }) else {
                continue;
            };
            let extents = self.function_extents(id)?;
            let index = extents.partition_point(|(entry, _, _)| *entry <= address.offset);
            let function = index
                .checked_sub(1)
                .and_then(|index| extents.get(index))
                .filter(|(_, end, _)| address.offset < *end)
                .map(|(_, _, name)| name.clone());
            // The module covering the address, when the program declares
            // modules (REL sections, overlays, container images).
            let module = self
                .modules(id)?
                .into_iter()
                .find(|module| {
                    module.load_vaddr.offset <= address.offset
                        && address.offset - module.load_vaddr.offset < module.size
                })
                .map(|module| module.name);
            found.push(romwright_model::LocationRow {
                program: program.program,
                language: program.language,
                region,
                function,
                module,
            });
        }
        Ok(found)
    }

    /// Looks up a program ID by name.
    pub fn program_id(&self, name: &str) -> Result<ProgramId> {
        let id = self
            .conn
            .query_row(
                "SELECT id FROM programs WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::ProgramNotFound(0),
                other => other.into(),
            })?;
        Ok(ProgramId(id))
    }

    /// Appends one timeline event and assigns its per-program sequence.
    pub fn append_trace_event(&self, program: ProgramId, row: &TraceEvent) -> Result<TraceEvent> {
        let tx = self.conn.unchecked_transaction()?;
        let sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM trace_events WHERE program_id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        let address = row.address.as_ref().map(addr_cell);
        tx.execute(
            "INSERT INTO trace_events(
                 program_id, sequence, at, thread, address, kind, payload, provenance
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                program.0,
                sequence,
                row.at,
                row.thread,
                address,
                row.kind,
                row.payload,
                row.provenance
            ],
        )?;
        self.bump_and_record(&tx, program, "trace-event", &row.kind)?;
        tx.commit()?;
        let mut stored = row.clone();
        stored.sequence = sequence as u64;
        Ok(stored)
    }

    /// Lists timeline events after `since`, in sequence order.
    pub fn trace_events(
        &self,
        program: ProgramId,
        since: u64,
        limit: u64,
    ) -> Result<Vec<TraceEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT sequence, at, thread, address, kind, payload, provenance
             FROM trace_events
             WHERE program_id = ?1 AND sequence > ?2
             ORDER BY sequence
             LIMIT ?3",
        )?;
        let limit = limit.min(i64::MAX as u64) as i64;
        let rows = stmt
            .query_map(params![program.0, since, limit], |row| {
                let address: Option<String> = row.get(3)?;
                Ok(TraceEvent {
                    sequence: row.get::<_, i64>(0)? as u64,
                    at: row.get(1)?,
                    thread: row.get(2)?,
                    address: address.and_then(|value| romwright_model::Address::parse_ram_hex(&value)),
                    kind: row.get(4)?,
                    payload: row.get(5)?,
                    provenance: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Adds a collaboration operation once. Duplicate op ids are idempotent
    /// and do not advance the program revision.
    pub fn append_collaboration_op(
        &self,
        program: ProgramId,
        row: &CollaborationOp,
    ) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO collaboration_ops(
                 program_id, op_id, actor, lamport, kind, payload, applied, provenance
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                program.0,
                row.op_id,
                row.actor,
                row.lamport,
                row.kind,
                row.payload,
                row.applied as i64,
                row.provenance
            ],
        )? != 0;
        if inserted {
            self.bump_and_record(&tx, program, "collaboration-op", &row.op_id)?;
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Lists operations in deterministic Lamport/actor/id order.
    pub fn collaboration_ops(&self, program: ProgramId) -> Result<Vec<CollaborationOp>> {
        let mut stmt = self.conn.prepare(
            "SELECT op_id, actor, lamport, kind, payload, applied, provenance
             FROM collaboration_ops
             WHERE program_id = ?1
             ORDER BY lamport, actor, op_id",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                Ok(CollaborationOp {
                    op_id: row.get(0)?,
                    actor: row.get(1)?,
                    lamport: row.get::<_, i64>(2)? as u64,
                    kind: row.get(3)?,
                    payload: row.get(4)?,
                    applied: row.get::<_, i64>(5)? != 0,
                    provenance: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Marks an existing operation applied; repeating the call is idempotent.
    pub fn apply_collaboration_op(&self, program: ProgramId, op_id: &str) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM collaboration_ops WHERE program_id = ?1 AND op_id = ?2
             )",
            params![program.0, op_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(DbError::OperationNotFound(op_id.into()));
        }
        let changed = tx.execute(
            "UPDATE collaboration_ops
             SET applied = 1
             WHERE program_id = ?1 AND op_id = ?2 AND applied = 0",
            params![program.0, op_id],
        )? != 0;
        if changed {
            self.bump_and_record(&tx, program, "collaboration-apply", op_id)?;
        }
        tx.commit()?;
        Ok(changed)
    }

    /// Current revision of a program; facts older than this are stale.
    pub fn revision(&self, program: ProgramId) -> Result<u64> {
        let rev = self.conn.query_row(
            "SELECT revision FROM programs WHERE id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        Ok(rev)
    }

    /// Events after `since` (exclusive) for the program, ascending.
    pub fn events_since(&self, program: ProgramId, since: u64) -> Result<Vec<RevisionEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT revision, kind, detail FROM revision_events
             WHERE program_id = ?1 AND revision > ?2 ORDER BY revision",
        )?;
        let rows = stmt
            .query_map(params![program.0, since], |r| {
                Ok(RevisionEvent {
                    revision: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    detail: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// UNDOABLE rename (CORE-006): rename + revision bump/event + journal
    /// entry, all in one transaction.
    pub fn rename_command(
        &self,
        program: ProgramId,
        entry: &romwright_model::Address,
        name: &str,
        undo_name: &str,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            params![program.0, addr_cell(entry), name],
        )?;
        if n == 0 {
            return Err(DbError::ProgramNotFound(program.0));
        }
        self.bump_and_record(&tx, program, "rename", name)?;
        let payload = serde_json::json!({"entry": entry.hex(), "name": name}).to_string();
        let undo = serde_json::json!({"entry": entry.hex(), "name": undo_name}).to_string();
        self.journal_push(&tx, program, "rename", &payload, &undo)?;
        tx.commit()?;
        Ok(())
    }

    /// Renames many functions as one undoable command (CORE-006). A ported
    /// name set is one analyst decision, so it is one journal entry and one
    /// revision bump: undoing a diff should not take thousands of undos, and
    /// a half-applied port is not a state the store can be left in.
    pub fn rename_batch_command(
        &self,
        program: ProgramId,
        renames: &[(romwright_model::Address, String)],
        detail: &str,
    ) -> Result<u64> {
        if renames.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.unchecked_transaction()?;
        let mut applied: Vec<(String, String, String)> = Vec::with_capacity(renames.len());
        {
            let mut read = tx.prepare(
                "SELECT name FROM functions WHERE program_id = ?1 AND entry = ?2",
            )?;
            let mut write = tx.prepare(
                "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            )?;
            for (entry, name) in renames {
                let cell = addr_cell(entry);
                let old: String = match read.query_row(params![program.0, &cell], |row| row.get(0))
                {
                    Ok(old) => old,
                    Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                    Err(error) => return Err(error.into()),
                };
                if old == *name {
                    continue;
                }
                write.execute(params![program.0, &cell, name])?;
                applied.push((entry.hex(), name.clone(), old));
            }
        }
        if applied.is_empty() {
            return Ok(0);
        }
        let payload = serde_json::json!({
            "renames": applied
                .iter()
                .map(|(entry, name, _)| serde_json::json!({"entry": entry, "name": name}))
                .collect::<Vec<_>>(),
        })
        .to_string();
        let undo = serde_json::json!({
            "renames": applied
                .iter()
                .map(|(entry, _, old)| serde_json::json!({"entry": entry, "name": old}))
                .collect::<Vec<_>>(),
        })
        .to_string();
        self.bump_and_record(&tx, program, "rename-batch", detail)?;
        self.journal_push(&tx, program, "rename-batch", &payload, &undo)?;
        tx.commit()?;
        Ok(applied.len() as u64)
    }

    /// Undoes a batched rename: every name goes back, one transaction, and
    /// the journal entry is marked done exactly as a single rename's is.
    pub fn undo_rename_batch(
        &self,
        program: ProgramId,
        renames: &[(romwright_model::Address, String)],
        seq: u64,
    ) -> Result<u64> {
        let tx = self.conn.unchecked_transaction()?;
        let mut restored = 0u64;
        {
            let mut write = tx.prepare(
                "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            )?;
            for (entry, name) in renames {
                restored += write.execute(params![program.0, addr_cell(entry), name])? as u64;
            }
        }
        self.bump_and_record(&tx, program, "rename-batch-undo", &restored.to_string())?;
        tx.execute(
            "UPDATE command_journal SET done = 1 WHERE program_id = ?1 AND seq = ?2",
            params![program.0, seq],
        )?;
        tx.commit()?;
        Ok(restored)
    }

    /// Applies the undo for a rename (CORE-006): rename back + event +
    /// journal marked done, one transaction.
    pub fn undo_rename(
        &self,
        program: ProgramId,
        entry: &romwright_model::Address,
        name: &str,
        seq: u64,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            params![program.0, addr_cell(entry), name],
        )?;
        if n == 0 {
            return Err(DbError::ProgramNotFound(program.0));
        }
        self.bump_and_record(&tx, program, "rename-undo", name)?;
        tx.execute(
            "UPDATE command_journal SET done = 1 WHERE program_id = ?1 AND seq = ?2",
            params![program.0, seq],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Pushes one command-journal entry (inside a transaction).
    pub fn journal_push(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        kind: &str,
        payload: &str,
        undo_payload: &str,
    ) -> Result<u64> {
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM command_journal WHERE program_id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO command_journal(program_id, seq, kind, payload, undo_payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![program.0, seq, kind, payload, undo_payload],
        )?;
        Ok(seq as u64)
    }

    /// The latest undone-able entry (done = 0), if any.
    pub fn journal_latest(&self, program: ProgramId) -> Result<Option<JournalEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, kind, payload, undo_payload, done FROM command_journal
             WHERE program_id = ?1 AND done = 0
             ORDER BY seq DESC LIMIT 1",
        )?;
        let rows = stmt
            .query_map(params![program.0], |r| {
                Ok(JournalEntry {
                    seq: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    payload: r.get(2)?,
                    undo_payload: r.get(3)?,
                    done: r.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().next())
    }

    /// Marks an entry undone.
    pub fn journal_mark_done(&self, program: ProgramId, seq: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE command_journal SET done = 1 WHERE program_id = ?1 AND seq = ?2",
            params![program.0, seq],
        )?;
        Ok(())
    }

    /// Record one mutation event (inside the caller's transaction).
    fn record_event(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        revision: u64,
        kind: &str,
        detail: &str,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO revision_events(program_id, revision, kind, detail)
             VALUES (?1, ?2, ?3, ?4)",
            params![program.0, revision, kind, detail],
        )?;
        Ok(())
    }

    /// Bumps the program revision by one and records an event (inside the
    /// caller's transaction).
    fn bump_and_record(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        kind: &str,
        detail: &str,
    ) -> Result<u64> {
        tx.execute(
            "UPDATE programs SET revision = revision + 1 WHERE id = ?1",
            params![program.0],
        )?;
        let rev: i64 = tx.query_row(
            "SELECT revision FROM programs WHERE id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        self.record_event(tx, program, rev as u64, kind, detail)?;
        Ok(rev as u64)
    }


    /// Language ID recorded for a program.
    pub fn program_language(&self, program: ProgramId) -> Result<String> {
        let lang = self.conn.query_row(
            "SELECT language FROM programs WHERE id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        Ok(lang)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(DbError::InvalidHex(value.into()));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| DbError::InvalidHex(value.into()))?;
        let byte = u8::from_str_radix(text, 16)
            .map_err(|_| DbError::InvalidHex(value.into()))?;
        out.push(byte);
    }
    Ok(out)
}

fn map_symbol(r: &Row<'_>) -> rusqlite::Result<SymbolRow> {
    Ok(SymbolRow {
        address: addr_from_cell(r.get(0)?, 0)?,
        name: r.get(1)?,
        external: r.get::<_, i64>(2)? != 0,
        source: r.get(3)?,
    })
}

/// RAM addresses use compact hex cells; non-RAM addresses use the typed JSON
/// representation so identical offsets in distinct spaces remain distinct.
fn addr_cell(a: &romwright_model::Address) -> String {
    if a.space == romwright_model::AddressSpace::Ram {
        format!("{:08x}", a.offset)
    } else {
        serde_json::to_string(a).expect("address contains only serializable fields")
    }
}
fn addr_from_cell(s: String, column: usize) -> rusqlite::Result<romwright_model::Address> {
    if s.starts_with('{') {
        return serde_json::from_str(&s).map_err(|error| rusqlite::Error::FromSqlConversionFailure(
            column, rusqlite::types::Type::Text, Box::new(error),
        ));
    }
    romwright_model::Address::parse_ram_hex(&s).ok_or_else(|| rusqlite::Error::FromSqlConversionFailure(
        column, rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hexadecimal address")),
    ))
}

/// A function row with its convention fact joined in: `calling_conventions`
/// owns the value and its provenance, and every reader of a function sees it.
/// `traced` rides the same select: it is a reader projection of the
/// `functions.traced` column, never written by the function writer.
const FUNCTION_SELECT: &str = "SELECT f.entry, f.name, f.size, f.signature, f.traced, c.convention
     FROM functions f LEFT JOIN calling_conventions c
       ON c.program_id = f.program_id AND c.function = f.entry";

fn map_function(r: &Row<'_>) -> rusqlite::Result<FunctionRow> {
    Ok(FunctionRow {
        entry: addr_from_cell(r.get(0)?, 0)?,
        name: r.get(1)?,
        size: r.get(2)?,
        signature: r.get(3)?,
        traced: r.get::<_, i64>(4).map(|v| v != 0)?,
        calling_convention: r.get(5)?,
    })
}

fn validate_fact_provenance(provenance: &FactProvenance) -> Result<&'static str> {
    if provenance.kind == FactKind::Inferred && provenance.source.trim().is_empty() {
        return Err(DbError::InvalidFactProvenance("inference source is empty".into()));
    }
    if provenance.confidence.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
        return Err(DbError::InvalidFactProvenance("confidence must be finite and within [0, 1]".into()));
    }
    Ok(match provenance.kind {
        FactKind::Inferred => "inferred",
        FactKind::Asserted => "asserted",
    })
}

/// `AND <column> IN (?n, ?n+1, ...)` for one evidence kind, with the sources
/// taken from the shared table. A kind with no classes matches nothing rather
/// than producing `IN ()`, which is not SQL.
fn evidence_clause(
    column: &str,
    evidence: Option<EvidenceKind>,
    first_index: usize,
) -> (String, Vec<Value>) {
    let Some(kind) = evidence else {
        return (String::new(), Vec::new());
    };
    let sources = romwright_model::provenance::sources(kind);
    if sources.is_empty() {
        return (" AND 0".to_owned(), Vec::new());
    }
    let placeholders: Vec<String> = (0..sources.len())
        .map(|offset| format!("?{}", first_index + offset))
        .collect();
    (
        format!(" AND {column} IN ({})", placeholders.join(", ")),
        sources.into_iter().map(|source| Value::Text(source.to_owned())).collect(),
    )
}

fn map_fact_provenance(r: &Row<'_>, source_index: usize) -> rusqlite::Result<FactProvenance> {
    let ownership: String = r.get(source_index + 1)?;
    let kind = match ownership.as_str() {
        "inferred" => FactKind::Inferred,
        "asserted" => FactKind::Asserted,
        _ => return Err(rusqlite::Error::FromSqlConversionFailure(
            source_index + 1, rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown fact ownership")),
        )),
    };
    Ok(FactProvenance {
        source: r.get(source_index)?,
        kind,
        confidence: r.get(source_index + 2)?,
    })
}

fn map_xref(r: &Row<'_>) -> rusqlite::Result<XrefRow> {
    Ok(XrefRow {
        from: addr_from_cell(r.get(0)?, 0)?,
        to: addr_from_cell(r.get(1)?, 1)?,
        kind: r.get(2)?,
        function: r.get(3)?,
        provenance: map_fact_provenance(r, 4)?,
    })
}

fn map_type_field(r: &Row<'_>) -> rusqlite::Result<TypeFieldRow> {
    Ok(TypeFieldRow {
        type_name: r.get(0)?,
        ordinal: r.get(1)?,
        field_name: r.get(2)?,
        offset: r.get(3)?,
        size: r.get::<_, Option<i64>>(4)?.map(|value| value as u64),
        type_ref: r.get(5)?,
    })
}

fn map_stack_variable(r: &Row<'_>) -> rusqlite::Result<StackVariableRow> {
    Ok(StackVariableRow {
        function: addr_from_cell(r.get(0)?, 0)?,
        ordinal: r.get(1)?,
        name: r.get(2)?,
        storage: r.get(3)?,
        type_name: r.get(4)?,
        offset: r.get(5)?,
        size: r.get::<_, Option<i64>>(6)?.map(|value| value as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov() -> Provenance {
        Provenance {
            producer: "ghidra-bridge".into(),
            upstream_version: "12.1.3".into(),
        }
    }

    #[test]
    fn program_roundtrip_and_revision_bump() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("smoke_bin", "x86:LE:64:default", &prov()).unwrap();
        assert_eq!(db.revision(id).unwrap(), 1);
        db.upsert_program("smoke_bin", "x86:LE:64:default", &prov()).unwrap();
        assert_eq!(db.revision(id).unwrap(), 2, "upsert bumps revision");
    }

    #[test]
    fn functions_replaced_atomically() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![FunctionRow {
            entry: romwright_model::Address::ram(0x400466),
            name: "add".into(),
            size: 20,
            signature: None,
            traced: false,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        db.replace_functions(id, &[]).unwrap();
        assert!(db.functions(id).unwrap().is_empty());
    }

    fn seed_functions(db: &ProjectDb, id: ProgramId) {
        let rows = vec![
            FunctionRow {
                entry: romwright_model::Address::ram(0x400500),
                name: "handle_request".into(),
                size: 300,
                signature: None,
                traced: false,
            calling_convention: None,
            },
            FunctionRow {
                entry: romwright_model::Address::ram(0x400000),
                name: "add".into(),
                size: 20,
                signature: None,
                traced: false,
            calling_convention: None,
            },
            FunctionRow {
                entry: romwright_model::Address::ram(0x400100),
                name: "AddEntry".into(),
                size: 80,
                signature: None,
                traced: false,
            calling_convention: None,
            },
            FunctionRow {
                entry: romwright_model::Address::ram(0x400200),
                name: "malloc".into(),
                size: 120,
                signature: None,
                traced: false,
            calling_convention: None,
            },
        ];
        db.replace_functions(id, &rows).unwrap();
    }

    #[test]
    fn functions_page_filter_substring_is_case_insensitive() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        seed_functions(&db, id);
        let filter = FunctionsFilter::parse("ADD").unwrap();
        let (rows, total, _) = db
            .functions_page(id, 0, 256, filter.as_ref(), None)
            .unwrap();
        assert_eq!(total, Some(2));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.name.to_lowercase().contains("add")));
    }

    #[test]
    fn functions_page_filter_regex_with_prefix() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        seed_functions(&db, id);
        let filter = FunctionsFilter::parse("re:^(add|malloc)$").unwrap();
        let (rows, total, _) = db
            .functions_page(id, 0, 256, filter.as_ref(), None)
            .unwrap();
        assert_eq!(total, Some(2));
        let mut names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["add", "malloc"]);
    }

    #[test]
    fn functions_page_filter_regex_invalid_is_structured_error() {
        let filter = FunctionsFilter::parse("re:[unclosed");
        assert!(matches!(filter, Err(DbError::InvalidFilter(_))));
    }

    #[test]
    fn functions_page_sort_by_size_desc_paginates() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        seed_functions(&db, id);
        let (rows, total, _) = db
            .functions_page(id, 1, 2, None, Some((FunctionSort::Size, false)))
            .unwrap();
        assert_eq!(total, Some(4));
        let sizes: Vec<u64> = rows.iter().map(|r| r.size).collect();
        assert_eq!(sizes, vec![120, 80], "sizes desc, window 1..3");
    }

    #[test]
    fn functions_page_sort_by_name_case_insensitive() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        seed_functions(&db, id);
        let (rows, _, _) = db
            .functions_page(id, 0, 256, None, Some((FunctionSort::Name, true)))
            .unwrap();
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["add", "AddEntry", "handle_request", "malloc"]);
    }

    #[test]
    fn functions_page_unfiltered_default_sort_is_entry_asc() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        seed_functions(&db, id);
        let (rows, total, _) = db.functions_page(id, 0, 256, None, None).unwrap();
        assert_eq!(total, Some(4));
        let entries: Vec<u64> = rows.iter().map(|r| r.entry.offset).collect();
        let mut sorted = entries.clone();
        sorted.sort_unstable();
        assert_eq!(entries, sorted);
    }

    #[test]
    fn rename_updates_name_and_revision() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![FunctionRow {
            entry: romwright_model::Address::ram(0x400000),
            name: "FUN_00400000".into(),
            size: 4,
            signature: None,
            traced: false,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        let before = db.revision(id).unwrap();
        db.rename_function(id, &romwright_model::Address::ram(0x400000), "main").unwrap();
        assert_eq!(db.revision(id).unwrap(), before + 1);
        assert_eq!(db.functions(id).unwrap()[0].name, "main");
    }

    /// The containing function is resolved by address, not by whichever row a
    /// scan reaches first: the old SQL compared hex text with an integer
    /// expression and named `_init` for a reference inside `main`.
    #[test]
    fn xref_names_the_function_that_contains_its_source() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        db.replace_functions(
            id,
            &[
                FunctionRow {
                    entry: romwright_model::Address::ram(0x0040_033c),
                    name: "_init".into(),
                    size: 27,
                    signature: None,
                    traced: false,
            calling_convention: None,
                },
                FunctionRow {
                    entry: romwright_model::Address::ram(0x0040_047a),
                    name: "main".into(),
                    size: 43,
                    signature: None,
                    traced: false,
            calling_convention: None,
                },
            ],
        )
        .unwrap();
        let row = |from: u64, to: u64, kind: &str| XrefRow {
            from: romwright_model::Address::ram(from),
            to: romwright_model::Address::ram(to),
            kind: kind.into(),
            function: None,
            provenance: romwright_model::FactProvenance::default(),
        };
        db.replace_xrefs(
            id,
            &[
                // inside `main`
                row(0x0040_0488, 0x0040_0466, "UNCONDITIONAL_CALL"),
                // in data: no function contains it
                row(0x0040_11a8, 0x0040_0466, "DATA"),
                // one byte past `main`'s proven end
                row(0x0040_04a5, 0x0040_0466, "DATA"),
            ],
        )
        .unwrap();
        let named: Vec<_> = db
            .xrefs_to(id, &romwright_model::Address::ram(0x0040_0466))
            .unwrap()
            .into_iter()
            .map(|xref| (xref.from.offset, xref.function))
            .collect();
        assert_eq!(
            named,
            vec![
                (0x0040_0488, Some("main".to_string())),
                (0x0040_04a5, None),
                (0x0040_11a8, None),
            ]
        );
    }

    #[test]
    fn comments_and_types_replace_atomically() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let cmts = vec![CommentRow {
            address: romwright_model::Address::ram(0x400488),
            function: romwright_model::Address::ram(0x400466),
            kind: "eol".into(),
            text: "a + b".into(),
        }];
        db.replace_comments(id, &cmts).unwrap();
        assert_eq!(db.comments(id).unwrap().len(), 1);
        let types = vec![DataTypeRow {
            name: "int".into(),
            definition: "4-byte signed".into(),
        }];
        db.replace_datatypes(id, &types).unwrap();
        assert_eq!(db.datatypes(id).unwrap()[0].name, "int");
        db.replace_comments(id, &[]).unwrap();
        assert!(db.comments(id).unwrap().is_empty());
    }

    #[test]
    fn an_analyst_rename_survives_the_next_import() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let entry = romwright_model::Address::ram(0x401000);
        let discovered = |name: &str| {
            vec![FunctionRow {
                entry: entry.clone(),
                name: name.into(),
                size: 32,
                signature: None,
                traced: false,
            calling_convention: None,
            }]
        };
        db.replace_functions(id, &discovered("FUN_00401000")).unwrap();
        db.rename_command(id, &entry, "parse_header", "FUN_00401000")
            .unwrap();
        // The same image imported again: discovery names it by default once
        // more, and the analyst's name still wins.
        db.replace_functions(id, &discovered("FUN_00401000")).unwrap();
        assert_eq!(db.functions(id).unwrap()[0].name, "parse_header");
    }

    #[test]
    fn an_undone_rename_is_not_reapplied_by_an_import() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let entry = romwright_model::Address::ram(0x401000);
        let rows = vec![FunctionRow {
            entry: entry.clone(),
            name: "FUN_00401000".into(),
            size: 32,
            signature: None,
            traced: false,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        db.rename_command(id, &entry, "parse_header", "FUN_00401000")
            .unwrap();
        let journal = db.journal_latest(id).unwrap().unwrap();
        db.undo_rename(id, &entry, "FUN_00401000", journal.seq).unwrap();
        db.replace_functions(id, &rows).unwrap();
        assert_eq!(db.functions(id).unwrap()[0].name, "FUN_00401000");
    }

    #[test]
    fn comment_command_undo_roundtrip() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let address = romwright_model::Address::ram(0x400466);
        db.comment_command(id, &address, &address, "eol", "first").unwrap();
        let after_add = db.revision(id).unwrap();
        assert_eq!(db.comments(id).unwrap()[0].text, "first");
        let journal = db.journal_latest(id).unwrap().unwrap();
        assert_eq!(journal.kind, "comment");
        let undo = serde_json::from_str::<serde_json::Value>(&journal.undo_payload).unwrap();
        assert_eq!(undo["exists"], false);
        db.undo_comment(id, &address, "eol", None, journal.seq).unwrap();
        assert!(db.comments(id).unwrap().is_empty());
        assert!(db.revision(id).unwrap() > after_add);
        assert!(db.journal_latest(id).unwrap().is_none());
    }

    #[test]
    fn paged_functions_window() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows: Vec<FunctionRow> = (0..100u64)
            .map(|i| FunctionRow {
                entry: romwright_model::Address::ram(0x400000 + i * 0x10),
                name: format!("f{i}"),
                size: 16,
                signature: None,
                traced: false,
            calling_convention: None,
            })
            .collect();
        db.replace_functions(id, &rows).unwrap();
        let (p1, total, rev) = db.functions_page(id, 0, 10, None, None).unwrap();
        assert_eq!(p1.len(), 10);
        assert_eq!(total, Some(100));
        assert_eq!(p1[0].entry.offset, 0x400000);
        let (p2, _, _) = db.functions_page(id, 90, 10, None, None).unwrap();
        assert_eq!(p2.len(), 10);
        assert_eq!(p2[0].entry.offset, 0x400000 + 90 * 0x10);
        let (p3, _, _) = db.functions_page(id, 999, 10, None, None).unwrap();
        assert!(p3.is_empty());
        // replace bumps the revision (mutation event model: CORE-005)
        assert!(rev >= 2);
    }

    #[test]
    fn rename_command_undo_roundtrip() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![FunctionRow {
            entry: romwright_model::Address::ram(0x400000),
            name: "FUN_00400000".into(),
            size: 4,
            signature: None,
            traced: false,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        db.rename_command(id, &romwright_model::Address::ram(0x400000), "main", "FUN_00400000").unwrap();
        assert_eq!(db.functions(id).unwrap()[0].name, "main");
        let latest = db.journal_latest(id).unwrap().unwrap();
        assert_eq!(latest.kind, "rename");
        assert!(!latest.done);
        assert!(latest.undo_payload.contains("FUN_00400000"));
        db.undo_rename(id, &romwright_model::Address::ram(0x400000), "FUN_00400000", latest.seq)
            .unwrap();
        assert_eq!(db.functions(id).unwrap()[0].name, "FUN_00400000");
        assert!(db.journal_latest(id).unwrap().is_none(), "entry marked done");
    }

    #[test]
    fn revision_events_recorded() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        assert!(db.events_since(id, 0).unwrap().is_empty());
        let rows = vec![FunctionRow {
            entry: romwright_model::Address::ram(0x400000),
            name: "FUN_00400000".into(),
            size: 4,
            signature: None,
            traced: false,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        let evs = db.events_since(id, 0).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "replace-functions");
        assert_eq!(evs[0].revision, 2, "upsert=1, replace bumps to 2");
        db.rename_function(id, &romwright_model::Address::ram(0x400000), "main").unwrap();
        // after the replace (rev 2); the rename is rev 3
        let evs = db.events_since(id, 2).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "rename");
        assert_eq!(evs[0].detail, "main");
        assert_eq!(evs[0].revision, 3);
        // since = current revision -> nothing
        assert!(db.events_since(id, 3).unwrap().is_empty());
    }

    #[test]
    fn xref_directional_queries() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![XrefRow {
            function: None,
            from: romwright_model::Address::ram(0x400488),
            to: romwright_model::Address::ram(0x400466),
            kind: "UNCONDITIONAL_CALL".into(),
            provenance: FactProvenance::default(),
        }];
        db.replace_xrefs(id, &rows).unwrap();
        assert_eq!(db.xrefs_to(id, &romwright_model::Address::ram(0x400466)).unwrap().len(), 1);
        assert_eq!(db.xrefs_from(id, &romwright_model::Address::ram(0x400488)).unwrap().len(), 1);
        assert!(db.xrefs_to(id, &romwright_model::Address::ram(0x400488)).unwrap().is_empty());
    }

    #[test]
    fn flow_overrides_belong_to_their_producer_and_survive_another_pass() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db
            .upsert_program("plt", "x86:LE:64:default", &prov())
            .unwrap();
        let row = romwright_model::FlowOverrideRow {
            address: romwright_model::Address::ram(0x201716),
            kind: "callreturn".into(),
            provenance: romwright_model::FactProvenance {
                kind: FactKind::Inferred,
                source: "native-import:plt-header".into(),
                confidence: None,
            },
        };
        db.replace_inferred_flow_overrides(id, "native-import:plt-header", &[row.clone()])
            .unwrap();
        assert_eq!(db.flow_overrides(id).unwrap(), vec![row.clone()]);
        // A different producer may not write another's rows...
        let foreign = db.replace_inferred_flow_overrides(id, "other-pass", &[row.clone()]);
        assert!(matches!(foreign, Err(DbError::InvalidFactProvenance(_))));
        // ...and replacing its own leaves the other producer's rows alone.
        db.replace_inferred_flow_overrides(id, "other-pass", &[]).unwrap();
        assert_eq!(db.flow_overrides(id).unwrap(), vec![row]);
    }

    #[test]
    fn call_edges_exclude_branches_and_data_and_deduplicate_kinds() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("calls", "x86:LE:64:default", &prov()).unwrap();
        let row = |from, to, kind: &str| XrefRow {
            from: romwright_model::Address::ram(from),
            to: romwright_model::Address::ram(to),
            kind: kind.into(),
            function: None,
            provenance: FactProvenance::default(),
        };
        db.replace_xrefs(id, &[
            row(0x1000, 0x2000, "UNCONDITIONAL_CALL"),
            row(0x1000, 0x2000, "CONDITIONAL_CALL"),
            row(0x1010, 0x2000, "CONDITIONAL_JUMP"),
            row(0x1020, 0x2000, "READ"),
            row(0x1030, 0x2100, "COMPUTED_CALL"),
            // Hex text order puts the wider address before 0x20000000.
            row(0x1_0000_0000, 0x2200, "UNCONDITIONAL_CALL"),
            row(0x2000_0000, 0x2200, "UNCONDITIONAL_CALL"),
        ]).unwrap();
        assert_eq!(db.call_edges(id).unwrap(), vec![
            (romwright_model::Address::ram(0x1000), romwright_model::Address::ram(0x2000)),
            (romwright_model::Address::ram(0x1030), romwright_model::Address::ram(0x2100)),
            (romwright_model::Address::ram(0x2000_0000), romwright_model::Address::ram(0x2200)),
            (romwright_model::Address::ram(0x1_0000_0000), romwright_model::Address::ram(0x2200)),
        ]);
    }

    #[test]
    fn inferred_xrefs_replace_only_their_pass_and_preserve_assertions() {
        use romwright_model::{FactKind, FactProvenance};
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("refs", "x86:LE:64:default", &prov()).unwrap();
        let source = "native-analysis:constant-propagation";
        let row = |from, kind, producer: &str| XrefRow {
            from: romwright_model::Address::ram(from),
            to: romwright_model::Address::ram(0x3000),
            kind: "READ".into(),
            function: None,
            provenance: FactProvenance {
                kind,
                source: producer.into(),
                confidence: None,
            },
        };
        let asserted = row(0x1000, FactKind::Asserted, "analyst");
        let old = row(0x1010, FactKind::Inferred, source);
        let other = row(0x1020, FactKind::Inferred, "another-pass");
        db.replace_xrefs(id, &[asserted.clone(), old, other.clone()]).unwrap();
        let conflict = row(0x1000, FactKind::Inferred, source);
        let mut fresh = row(0x1030, FactKind::Inferred, source);
        fresh.provenance.confidence = Some(0.9);
        db.replace_inferred_xrefs(id, source, &[conflict, fresh.clone()]).unwrap();
        assert_eq!(db.xrefs(id).unwrap(), vec![asserted.clone(), other.clone(), fresh]);
        let before = db.xrefs(id).unwrap();
        let revision = db.revision(id).unwrap();
        assert!(db.replace_inferred_xrefs(id, source, &[other.clone()]).is_err());
        assert_eq!(db.xrefs(id).unwrap(), before);
        assert_eq!(db.revision(id).unwrap(), revision);
        // SQLite converts NaN to NULL; reject it before it can become "unknown".
        let mut invalid = row(0x1040, FactKind::Inferred, source);
        invalid.provenance.confidence = Some(f64::NAN);
        assert!(db.replace_inferred_xrefs(id, source, &[invalid]).is_err());
        assert_eq!(db.xrefs(id).unwrap(), before);
        assert_eq!(db.revision(id).unwrap(), revision);
        db.replace_inferred_xrefs(id, source, &[]).unwrap();
        assert_eq!(db.xrefs(id).unwrap(), vec![asserted.clone(), other]);
        // Reimporting an empty analysis must not erase an analyst's assertion.
        db.replace_xrefs(id, &[]).unwrap();
        assert_eq!(db.xrefs(id).unwrap(), vec![asserted]);
    }

    #[test]
    fn legacy_xref_migration_preserves_unknown_ownership_and_confidence() {
        use romwright_model::FactKind;
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("legacy", "x86:LE:64:default", &prov()).unwrap();
        db.conn.execute_batch(
            "DROP TABLE xrefs;
             CREATE TABLE xrefs (
                program_id INTEGER NOT NULL REFERENCES programs(id),
                src TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL,
                provenance TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (program_id, src, dst, kind));
             ALTER TABLE prototypes DROP COLUMN provenance;
             ALTER TABLE prototypes DROP COLUMN provenance_kind;
             ALTER TABLE prototypes DROP COLUMN confidence;
             ALTER TABLE type_defs DROP COLUMN primitive;
             ALTER TABLE type_defs DROP COLUMN element_count;
             DROP TABLE return_behaviors;
             UPDATE meta SET value = '4' WHERE key = 'schema_version';"
        ).unwrap();
        for (from, source) in [("00001000", "legacy-author"), ("00001010", "native-import")] {
            db.conn.execute(
                "INSERT INTO xrefs VALUES (?1, ?2, '00003000', 'DATA', ?3)",
                params![id.0, from, source],
            ).unwrap();
        }
        db.migrate().unwrap();
        db.migrate().unwrap();
        let rows = db.xrefs(id).unwrap();
        assert_eq!(rows[0].provenance.kind, FactKind::Asserted);
        assert_eq!(rows[0].provenance.source, "legacy-author");
        assert_eq!(rows[0].provenance.confidence, None);
        assert_eq!(rows[1].provenance.kind, FactKind::Inferred);
        assert_eq!(rows[1].provenance.source, "native-import");
        assert_eq!(rows[1].provenance.confidence, None);
        db.replace_xrefs(id, &[]).unwrap();
        assert_eq!(db.xrefs(id).unwrap(), vec![rows[0].clone()]);
    }

    #[test]
    fn prototype_inference_preserves_assertions_and_rolls_back_invalid_confidence() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("prototypes", "x86:LE:64:default", &prov()).unwrap();
        let row = |address, kind, source: &str| PrototypeRow {
            function: romwright_model::Address::ram(address),
            signature: format!("int {source}(void)"),
            return_type: Some("int".into()),
            calling_convention: None,
            provenance: FactProvenance { kind, source: source.into(), confidence: None },
        };
        let asserted = row(0x1000, FactKind::Asserted, "analyst");
        let old = row(0x1010, FactKind::Inferred, "analysis");
        db.replace_prototypes(id, &[asserted.clone(), old.clone()]).unwrap();
        let mut invalid = row(0x1020, FactKind::Inferred, "analysis");
        invalid.provenance.confidence = Some(f64::NAN);
        let revision = db.revision(id).unwrap();
        assert!(matches!(db.replace_prototypes(id, &[invalid]),
            Err(DbError::InvalidFactProvenance(_))));
        assert_eq!(db.prototypes(id).unwrap(), vec![asserted.clone(), old]);
        assert_eq!(db.revision(id).unwrap(), revision);
        let conflict = row(0x1000, FactKind::Inferred, "analysis");
        let mut fresh = row(0x1020, FactKind::Inferred, "analysis");
        fresh.provenance.confidence = Some(0.9);
        db.replace_prototypes(id, &[conflict.clone(), fresh.clone()]).unwrap();
        db.set_prototype(id, &conflict).unwrap();
        assert_eq!(db.prototypes(id).unwrap(), vec![asserted.clone(), fresh]);
        db.replace_prototypes(id, &[]).unwrap();
        assert_eq!(db.prototypes(id).unwrap(), vec![asserted]);
    }

    #[test]
    fn inferred_batches_are_revision_checked_atomic_and_idempotent() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("inference", "x86:LE:64:default", &prov()).unwrap();
        let inferred = |address, signature: &str| PrototypeRow {
            function: romwright_model::Address::ram(address),
            signature: signature.into(),
            return_type: Some("int".into()),
            calling_convention: None,
            provenance: FactProvenance {
                kind: FactKind::Inferred, source: "native recovery".into(), confidence: None,
            },
        };
        let mut asserted = inferred(0x1000, "int analyst(void)");
        asserted.provenance.kind = FactKind::Asserted;
        db.set_prototype(id, &asserted).unwrap();
        let revision = db.revision(id).unwrap();
        let conflict = inferred(0x1000, "int conflict(int x)");
        let fresh = inferred(0x1010, "int recovered(int x)");
        let batch = [conflict, fresh.clone()];
        assert_eq!(db.merge_inferred_prototypes(id, revision, &batch).unwrap(),
            vec![fresh.function.clone()]);
        let updated = db.revision(id).unwrap();
        assert_eq!(updated, revision + 1);
        assert_eq!(db.prototypes(id).unwrap(), vec![asserted.clone(), fresh.clone()]);
        assert!(db.merge_inferred_prototypes(id, updated, &batch).unwrap().is_empty());
        assert_eq!(db.revision(id).unwrap(), updated);

        let next = inferred(0x1020, "int next(void)");
        assert!(matches!(db.merge_inferred_prototypes(id, revision, &[next.clone()]),
            Err(DbError::StaleRevision { .. })));
        let mut invalid = inferred(0x1030, "int invalid(void)");
        invalid.provenance.confidence = Some(f64::NAN);
        assert!(matches!(db.merge_inferred_prototypes(id, updated, &[next, invalid]),
            Err(DbError::InvalidFactProvenance(_))));
        assert!(matches!(db.merge_inferred_prototypes(id, updated, &[asserted.clone()]),
            Err(DbError::InvalidFactProvenance(_))));
        assert_eq!(db.prototypes(id).unwrap(), vec![asserted, fresh]);
        assert_eq!(db.revision(id).unwrap(), updated);
    }

    #[test]
    fn version_seven_migration_keeps_functions_and_starts_return_facts_unknown() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("return-migration", "x86:LE:64:default", &prov()).unwrap();
        db.replace_functions(id, &[FunctionRow {
            entry: romwright_model::Address::ram(0x1000), name: "analyst_name".into(), size: 9,
            signature: Some("int analyst_name(void)".into()), traced: false,
            calling_convention: None,
        }]).unwrap();
        let revision = db.revision(id).unwrap();
        db.conn.execute_batch(
            "DROP TABLE IF EXISTS return_behaviors;
             UPDATE meta SET value = '7' WHERE key = 'schema_version';"
        ).unwrap();
        db.migrate().unwrap();
        assert!(db.return_behaviors(id).unwrap().is_empty());
        let rows = db.functions(id).unwrap();
        assert_eq!(rows[0].name, "analyst_name");
        assert_eq!(rows[0].signature.as_deref(), Some("int analyst_name(void)"));
        assert_eq!(rows[0].size, 9);
        assert_eq!(db.revision(id).unwrap(), revision);
    }

    #[test]
    fn return_behavior_assertions_override_inference_without_spurious_revisions() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("return-ownership", "x86:LE:64:default", &prov()).unwrap();
        let inferred = romwright_model::ReturnBehaviorRow {
            function: romwright_model::Address::ram(0x1000), no_return: true,
            provenance: FactProvenance {
                kind: FactKind::Inferred, source: "flow".into(), confidence: None,
            },
        };
        db.set_return_behavior(id, &inferred).unwrap();
        let mut asserted = inferred.clone();
        asserted.no_return = false;
        asserted.provenance.kind = FactKind::Asserted;
        asserted.provenance.source = "analyst".into();
        db.set_return_behavior(id, &asserted).unwrap();
        let revision = db.revision(id).unwrap();
        db.set_return_behavior(id, &inferred).unwrap();
        db.set_return_behavior(id, &asserted).unwrap();
        assert_eq!(db.return_behaviors(id).unwrap(), vec![asserted.clone()]);
        assert_eq!(db.revision(id).unwrap(), revision);
        asserted.provenance.confidence = Some(f64::NAN);
        assert!(matches!(db.set_return_behavior(id, &asserted),
            Err(DbError::InvalidFactProvenance(_))));
        assert_eq!(db.revision(id).unwrap(), revision);
    }

    #[test]
    fn version_six_migration_preserves_prototypes_and_structured_types() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("legacy-types", "x86:LE:64:default", &prov()).unwrap();
        db.conn.execute_batch(
            "DROP TABLE prototypes;
             CREATE TABLE prototypes (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 function TEXT NOT NULL, signature TEXT NOT NULL,
                 calling_convention TEXT, return_type TEXT,
                 PRIMARY KEY(program_id, function));
             DROP TABLE type_defs;
             CREATE TABLE type_defs (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 name TEXT NOT NULL, kind TEXT NOT NULL, definition TEXT NOT NULL,
                 size INTEGER, alignment INTEGER, base_type TEXT,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY(program_id, name));
             DROP TABLE return_behaviors;
             UPDATE meta SET value = '6' WHERE key = 'schema_version';"
        ).unwrap();
        db.conn.execute(
            "INSERT INTO prototypes VALUES (?1, '00001000', 'unsigned int legacy(void)', 'cdecl', 'Count')",
            params![id.0],
        ).unwrap();
        for (name, kind, size, alignment, base) in [
            ("Count", "primitive", 4, 4, None),
            ("CountPtr", "pointer", 8, 8, Some("Count")),
            ("CountArray", "array", 12, 4, Some("Count")),
            ("Node", "structure", 16, 8, None),
        ] {
            db.conn.execute(
                "INSERT INTO type_defs VALUES (?1, ?2, ?3, '', ?4, ?5, ?6, 'legacy-author')",
                params![id.0, name, kind, size, alignment, base],
            ).unwrap();
        }
        db.conn.execute(
            "INSERT INTO type_fields VALUES (?1, 'Node', 0, 'next', 8, 8, 'CountPtr')",
            params![id.0],
        ).unwrap();
        db.migrate().unwrap();
        db.migrate().unwrap();
        let ownership: (String, String, Option<f64>) = db.conn.query_row(
            "SELECT provenance_kind, provenance, confidence FROM prototypes WHERE program_id = ?1",
            params![id.0], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(ownership, ("asserted".into(), String::new(), None));
        let prototype = db.prototypes(id).unwrap().remove(0);
        assert_eq!(prototype.function.offset, 0x1000);
        assert_eq!(prototype.signature, "unsigned int legacy(void)");
        assert_eq!(prototype.calling_convention.as_deref(), Some("cdecl"));
        assert_eq!(prototype.return_type.as_deref(), Some("Count"));
        let types = db.type_defs(id).unwrap();
        assert_eq!(types.iter().map(|row| (row.name.as_str(), row.kind.as_str(),
            row.size, row.alignment, row.base_type.as_deref(), row.provenance.as_str()))
            .collect::<Vec<_>>(), vec![
                ("Count", "primitive", Some(4), Some(4), None, "legacy-author"),
                ("CountArray", "array", Some(12), Some(4), Some("Count"), "legacy-author"),
                ("CountPtr", "pointer", Some(8), Some(8), Some("Count"), "legacy-author"),
                ("Node", "structure", Some(16), Some(8), None, "legacy-author"),
            ]);
        let fields = db.type_fields(id, None).unwrap();
        assert_eq!(fields, vec![TypeFieldRow { type_name: "Node".into(), ordinal: 0,
            field_name: "next".into(), offset: 8, size: Some(8), type_ref: Some("CountPtr".into()) }]);
        for mut row in types {
            let mut value = serde_json::to_value(&row).unwrap();
            if row.name == "Count" { value["primitive"] = serde_json::json!("unsigned_integer"); }
            if row.name == "CountArray" { value["element_count"] = serde_json::json!(3); }
            row = serde_json::from_value(value).unwrap();
            db.set_type_def(id, &row).unwrap();
        }
        let updated = db.type_defs(id).unwrap();
        assert_eq!(serde_json::to_value(&updated[0]).unwrap()["primitive"], "unsigned_integer");
        assert_eq!(serde_json::to_value(&updated[1]).unwrap()["element_count"], 3);
        let inferred: PrototypeRow = serde_json::from_value(serde_json::json!({
            "function": {"space": "Ram", "offset": 4112},
            "signature": "Count recovered(void)", "calling_convention": "cdecl",
            "return_type": "Count",
            "provenance": {"kind": "inferred", "source": "test-analysis", "confidence": 0.875}
        })).unwrap();
        db.set_prototype(id, &inferred).unwrap();
        let stored = serde_json::to_value(&db.prototypes(id).unwrap()[1]).unwrap();
        // Provenance now serialises its explanation from the shared table; an
        // unknown source has none, and the rest of the object is unchanged.
        assert_eq!(stored["provenance"], serde_json::json!({
            "kind": "inferred", "source": "test-analysis", "confidence": 0.875,
            "explanation": null, "evidence": null
        }));
    }

    #[test]
    fn analysis_records_search_graph_memory_bookmarks_and_patches() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let entry = romwright_model::Address::ram(0x400000);
        db.replace_functions(
            id,
            &[FunctionRow {
                entry: entry.clone(),
                name: "main".into(),
                size: 8,
                signature: None,
                traced: false,
            calling_convention: None,
            }],
        )
        .unwrap();
        db.replace_symbols(
            id,
            &[SymbolRow {
                name: "main".into(),
                address: entry.clone(),
                external: false,
                source: "USER_DEFINED".into(),
            }],
        )
        .unwrap();
        db.replace_strings(
            id,
            &[StringRow {
                address: romwright_model::Address::ram(0x401000),
                value: "hello romwright".into(),
                kind: "ASCII".into(),
            }],
        )
        .unwrap();
        db.replace_xrefs(
            id,
            &[XrefRow {
                function: None,
                from: entry.clone(),
                to: romwright_model::Address::ram(0x401000),
                kind: "DATA".into(),
                provenance: FactProvenance::default(),
            }],
        )
        .unwrap();
        assert_eq!(db.search(id, "hello", 10).unwrap()[0].kind, "string");
        let (nodes, edges) = db.function_graph(id).unwrap();
        assert!(nodes.iter().any(|node| node.address.offset == 0x401000));
        assert_eq!(edges.len(), 1);
        db.replace_memory_regions(
            id,
            &[MemoryRegion {
                name: "elf:0".into(),
                start: entry.clone(),
                size: 0x100,
                permissions: "r-x".into(),
                source: "native-import".into(),
            }],
        )
        .unwrap();
        assert_eq!(db.memory_regions(id).unwrap()[0].permissions, "r-x");
        db.set_bookmark(
            id,
            &BookmarkRow {
                address: entry.clone(),
                label: "entry".into(),
                comment: "start".into(),
            },
        )
        .unwrap();
        assert_eq!(db.bookmarks(id).unwrap()[0].label, "entry");
        db.set_patch(
            id,
            &PatchRow {
                address: entry.clone(),
                original: vec![0x55, 0x48],
                patched: vec![0x90, 0x90],
                enabled: true,
            },
        )
        .unwrap();
        assert_eq!(db.patches(id).unwrap()[0].patched, vec![0x90, 0x90]);
    }
    #[test]
    fn rich_types_and_provenance_roundtrip() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        db.replace_type_defs(
            id,
            &[TypeDefRow {
                name: "struct point".into(),
                kind: "structure".into(),
                definition: "struct point { int x; int y; }".into(),
                size: Some(8),
                alignment: Some(4),
                base_type: None,
                provenance: "native-analysis".into(),
                primitive: None,
                element_count: None,
            }],
        )
        .unwrap();
        db.replace_type_fields(
            id,
            &[TypeFieldRow {
                type_name: "struct point".into(),
                ordinal: 0,
                field_name: "x".into(),
                offset: 0,
                size: Some(4),
                type_ref: Some("int".into()),
            }],
        )
        .unwrap();
        db.replace_type_links(
            id,
            &[TypeLinkRow {
                source: "struct point".into(),
                target: "int".into(),
                kind: "field".into(),
                provenance: "native-analysis".into(),
            }],
        )
        .unwrap();
        let function = romwright_model::Address::ram(0x400000);
        db.replace_prototypes(
            id,
            &[PrototypeRow {
                function: function.clone(),
                signature: "int main(void)".into(),
                calling_convention: Some("__cdecl".into()),
                return_type: Some("int".into()),
                provenance: FactProvenance::default(),
            }],
        )
        .unwrap();
        db.replace_stack_variables(
            id,
            &[StackVariableRow {
                function,
                ordinal: 0,
                name: "point".into(),
                storage: "stack[-0x10]".into(),
                type_name: Some("struct point".into()),
                offset: Some(-16),
                size: Some(8),
            }],
        )
        .unwrap();
        assert_eq!(db.type_defs(id).unwrap()[0].name, "struct point");
        assert_eq!(db.type_fields(id, Some("struct point")).unwrap()[0].field_name, "x");
        assert_eq!(db.type_graph(id).unwrap().1[0].provenance, "native-analysis");
        assert_eq!(db.prototypes(id).unwrap()[0].signature, "int main(void)");
        assert_eq!(db.stack_variables(id, None).unwrap()[0].offset, Some(-16));
    }
    #[test]
    fn trace_and_collaboration_logs_are_ordered_and_idempotent() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let first = db
            .append_trace_event(
                id,
                &TraceEvent {
                    sequence: 0,
                    at: "2026-09-02T08:00:00Z".into(),
                    thread: "main".into(),
                    address: Some(romwright_model::Address::ram(0x401000)),
                    kind: "breakpoint".into(),
                    payload: r#"{"reason":"entry"}"#.into(),
                    provenance: "debug-gdb".into(),
                },
            )
            .unwrap();
        let second = db
            .append_trace_event(
                id,
                &TraceEvent {
                    sequence: 0,
                    at: "2026-09-02T08:00:01Z".into(),
                    thread: "main".into(),
                    address: None,
                    kind: "step".into(),
                    payload: String::new(),
                    provenance: "debug-gdb".into(),
                },
            )
            .unwrap();
        assert_eq!((first.sequence, second.sequence), (1, 2));
        let events = db.trace_events(id, 0, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].address.as_ref().unwrap().offset, 0x401000);
        assert_eq!(events[1].kind, "step");

        let op_b = CollaborationOp {
            op_id: "b-2".into(),
            actor: "b".into(),
            lamport: 2,
            kind: "rename".into(),
            payload: r#"{"name":"second"}"#.into(),
            applied: false,
            provenance: "team-b".into(),
        };
        let op_a = CollaborationOp {
            op_id: "a-1".into(),
            actor: "a".into(),
            lamport: 1,
            kind: "comment".into(),
            payload: r#"{"text":"first"}"#.into(),
            applied: false,
            provenance: "team-a".into(),
        };
        assert!(db.append_collaboration_op(id, &op_b).unwrap());
        assert!(db.append_collaboration_op(id, &op_a).unwrap());
        assert!(!db.append_collaboration_op(id, &op_a).unwrap());
        let operations = db.collaboration_ops(id).unwrap();
        assert_eq!(
            operations.iter().map(|op| op.op_id.as_str()).collect::<Vec<_>>(),
            vec!["a-1", "b-2"]
        );
        assert!(db.apply_collaboration_op(id, "a-1").unwrap());
        assert!(!db.apply_collaboration_op(id, "a-1").unwrap());
        assert!(db.collaboration_ops(id).unwrap()[0].applied);
        assert!(matches!(
            db.apply_collaboration_op(id, "missing"),
            Err(DbError::OperationNotFound(_))
        ));
    }
}
