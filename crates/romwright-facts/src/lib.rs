//! romwright-facts: the hosted shared-fact store (P2.2).
//!
//! `Core::push_facts` (romwright-core `fact_sync`) serialises one program's
//! shareable facts — function names, symbols, prototypes, type definitions
//! and fields, `.vsig` library matches, and per-function semantic
//! signatures — into one JSON bundle. This crate is the server half of that
//! loop: it holds pushed bundles and hands the best one back.
//!
//! Matching, mirroring `Core::pull_facts`:
//!
//! * **Exact.** A query carrying `binary_sha256` returns the bundle pushed
//!   for that image verbatim — same build, same addresses.
//! * **Cross-build.** A query carrying the local program's semantic
//!   signatures (`signatures: [hex, …]`) scores each held bundle by the
//!   number of query signatures some pushed function matches at or above
//!   [`romwright_diff::semantic::MATCH_FLOOR`]. The best-scoring bundle is
//!   returned; `pull_facts` then maps its pushed names onto local
//!   functions by signature.
//!
//! The store is durable (SQLite) so a hosted instance accumulates facts
//! across uploads. The wire surface is one JSON object per line over TCP
//! (`serve_tcp`): `{"method":"push_facts","params":{"bundle":{…}}}` and
//! `{"method":"pull_facts","params":{"binary_sha256":…,"signatures":[…]}}`.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use thiserror::Error;

/// Errors the store can raise.
#[derive(Debug, Error)]
pub enum FactsError {
    /// A bundle or request was malformed.
    #[error("bad request: {0}")]
    Request(String),
    /// The backing store failed.
    #[error("store: {0}")]
    Store(#[from] rusqlite::Error),
    /// JSON (de)serialisation failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Transport I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, FactsError>;

/// What [`FactStore::ingest`] recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestReport {
    /// Row id the bundle was stored under.
    pub bundle_id: i64,
    /// Function signatures indexed for cross-build matching.
    pub signatures: usize,
    /// True when an existing bundle for the same `binary_sha256` was
    /// replaced rather than appended.
    pub replaced: bool,
}

/// A durable store of pushed fact bundles.
pub struct FactStore {
    db: Connection,
}

impl FactStore {
    /// Opens (or creates) a store at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let db = Connection::open(path)?;
        Self::init(db)
    }

    /// An in-memory store, for tests and ephemeral hosting.
    pub fn open_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(db: Connection) -> Result<Self> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS bundles (
                id INTEGER PRIMARY KEY,
                binary_sha256 TEXT,
                language TEXT NOT NULL,
                program TEXT NOT NULL,
                bundle TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS bundles_sha ON bundles(binary_sha256);
            CREATE TABLE IF NOT EXISTS signatures (
                bundle_id INTEGER NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS signatures_sig ON signatures(signature);",
        )?;
        Ok(Self { db })
    }

    /// Stores one pushed bundle and indexes its function signatures.
    ///
    /// A bundle with a `binary_sha256` that already exists replaces the
    /// earlier upload for that image (re-analysis of the same binary
    /// supersedes, it does not duplicate).
    pub fn ingest(&mut self, bundle: &Value) -> Result<IngestReport> {
        let sha = bundle
            .get("binary_sha256")
            .and_then(Value::as_str)
            .map(str::to_string);
        let language = bundle
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let program = bundle
            .get("program")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if bundle.get("functions").is_none() {
            return Err(FactsError::Request("bundle has no functions".into()));
        }

        // Replace any prior upload for the same image.
        let mut replaced = false;
        if let Some(sha) = sha.as_deref() {
            let prior: Option<i64> = self
                .db
                .query_row(
                    "SELECT id FROM bundles WHERE binary_sha256 = ?1",
                    params![sha],
                    |row| row.get(0),
                )
                .ok();
            if let Some(id) = prior {
                self.db
                    .execute("DELETE FROM signatures WHERE bundle_id = ?1", params![id])?;
                self.db.execute("DELETE FROM bundles WHERE id = ?1", params![id])?;
                replaced = true;
            }
        }

        let text = serde_json::to_string(bundle)?;
        self.db.execute(
            "INSERT INTO bundles (binary_sha256, language, program, bundle) VALUES (?1, ?2, ?3, ?4)",
            params![sha, language, program, text],
        )?;
        let bundle_id = self.db.last_insert_rowid();

        // Index each function's semantic signature for cross-build match.
        let mut count = 0usize;
        if let Some(functions) = bundle.get("functions").and_then(Value::as_array) {
            for function in functions {
                if let Some(sig) = function
                    .get("semantic_signature")
                    .and_then(Value::as_str)
                {
                    self.db.execute(
                        "INSERT INTO signatures (bundle_id, signature) VALUES (?1, ?2)",
                        params![bundle_id, sig],
                    )?;
                    count += 1;
                }
            }
        }
        Ok(IngestReport {
            bundle_id,
            signatures: count,
            replaced,
        })
    }

    /// The bundle pushed for exactly this image, if any.
    pub fn query_exact(&self, binary_sha256: &str) -> Result<Option<Value>> {
        let found: Option<String> = self
            .db
            .query_row(
                "SELECT bundle FROM bundles WHERE binary_sha256 = ?1 ORDER BY id DESC LIMIT 1",
                params![binary_sha256],
                |row| row.get(0),
            )
            .ok();
        found
            .map(|text| serde_json::from_str(&text).map_err(FactsError::from))
            .transpose()
    }

    /// The held bundle whose function signatures best cover `query`
    /// signatures, or `None` when nothing reaches [`MATCH_FLOOR`].
    ///
    /// Score = the count of distinct query signatures some pushed function
    /// in the bundle matches at or above the floor. Ties break toward the
    /// most recently ingested bundle.
    pub fn query_by_signatures(&self, query: &[String]) -> Result<Option<Value>> {
        // Parse the query signatures once; unparseable ones are dropped.
        let wanted: Vec<romwright_diff::semantic::Signature> = query
            .iter()
            .filter_map(|hex| romwright_diff::semantic::Signature::parse_hex(hex))
            .collect();
        if wanted.is_empty() {
            return Ok(None);
        }

        // Load every (bundle_id, signature) and score per bundle.
        let mut stmt = self
            .db
            .prepare("SELECT bundle_id, signature FROM signatures")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut by_bundle: std::collections::BTreeMap<i64, Vec<romwright_diff::semantic::Signature>> =
            std::collections::BTreeMap::new();
        for (bundle_id, hex) in rows {
            if let Some(sig) = romwright_diff::semantic::Signature::parse_hex(&hex) {
                by_bundle.entry(bundle_id).or_default().push(sig);
            }
        }

        let mut best: Option<(i64, usize)> = None;
        for (bundle_id, sigs) in &by_bundle {
            // Count query signatures this bundle covers at the floor.
            let covered = wanted
                .iter()
                .filter(|want| {
                    sigs.iter().any(|have| {
                        have.similarity(want)
                            .is_some_and(|s| s >= romwright_diff::semantic::MATCH_FLOOR)
                    })
                })
                .count();
            if covered == 0 {
                continue;
            }
            let better = match best {
                None => true,
                Some((_, score)) => covered > score,
                // Equal coverage: the newer bundle (higher id) wins.
            } || matches!(best, Some((id, score)) if covered == score && *bundle_id > id);
            if better {
                best = Some((*bundle_id, covered));
            }
        }

        let Some((bundle_id, _)) = best else {
            return Ok(None);
        };
        let text: String = self.db.query_row(
            "SELECT bundle FROM bundles WHERE id = ?1",
            params![bundle_id],
            |row| row.get(0),
        )?;
        Ok(Some(serde_json::from_str(&text)?))
    }

    /// Dispatches one JSON request line to a JSON response line.
    ///
    /// Methods:
    /// * `push_facts` — `params.bundle` is a `Core::push_facts` bundle;
    ///   returns the ingest report.
    /// * `pull_facts` — `params.binary_sha256` (exact) or
    ///   `params.signatures` (cross-build); returns the bundle or `null`.
    pub fn handle_line(&mut self, line: &str) -> String {
        match self.dispatch(line) {
            Ok(value) => serde_json::to_string(&json!({"result": value}))
                .unwrap_or_else(|_| "{\"result\":null}".into()),
            Err(error) => serde_json::to_string(&json!({"error": error.to_string()}))
                .unwrap_or_else(|_| "{\"error\":\"encode\"}".into()),
        }
    }

    fn dispatch(&mut self, line: &str) -> Result<Value> {
        let request: Value = serde_json::from_str(line.trim())
            .map_err(|e| FactsError::Request(format!("not json: {e}")))?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| FactsError::Request("missing method".into()))?;
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "push_facts" => {
                let bundle = params
                    .get("bundle")
                    .ok_or_else(|| FactsError::Request("push_facts needs params.bundle".into()))?;
                let report = self.ingest(bundle)?;
                Ok(json!({
                    "bundle_id": report.bundle_id,
                    "signatures": report.signatures,
                    "replaced": report.replaced,
                }))
            }
            "pull_facts" => {
                if let Some(sha) = params.get("binary_sha256").and_then(Value::as_str) {
                    if let Some(bundle) = self.query_exact(sha)? {
                        return Ok(json!({"bundle": bundle, "matched": "exact"}));
                    }
                }
                let signatures: Vec<String> = params
                    .get("signatures")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                match self.query_by_signatures(&signatures)? {
                    Some(bundle) => Ok(json!({"bundle": bundle, "matched": "signature"})),
                    None => Ok(json!({"bundle": Value::Null, "matched": "none"})),
                }
            }
            other => Err(FactsError::Request(format!("unknown method {other}"))),
        }
    }
}

/// Serves one JSON-line request per TCP connection (localhost hosting).
pub fn serve_tcp(store: &std::sync::Mutex<FactStore>, listener: std::net::TcpListener) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.is_empty() {
            continue;
        }
        let response = store
            .lock()
            .map(|mut guard| guard.handle_line(&line))
            .unwrap_or_else(|_| "{\"error\":\"store poisoned\"}".into());
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(b"\n");
        let _ = stream.flush();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_diff::semantic::{signature, SemOp};

    /// A semantic signature hex string for a small op sequence.
    fn sig(ops: &[(&str, u64)]) -> String {
        let sem: Vec<SemOp> = ops
            .iter()
            .map(|(opcode, off)| SemOp::plain(opcode, &[("register", *off, 8)]))
            .collect();
        signature(&sem).to_hex()
    }

    /// A minimal `Core::push_facts`-shaped bundle.
    fn bundle(sha: Option<&str>, sigs: &[String]) -> Value {
        let functions: Vec<Value> = sigs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                json!({
                    "function": {"space":"ram","offset": 4096 + i as u64 * 16},
                    "name": format!("func_{i}"),
                    "size": 16,
                    "semantic_signature": s,
                    "ops": 4,
                })
            })
            .collect();
        json!({
            "bundle": 1,
            "program": "test",
            "language": "x86:LE:64:default",
            "binary_sha256": sha,
            "functions": functions,
            "symbols": [],
            "prototypes": [],
            "type_defs": [],
            "type_fields": [],
            "signature_matches": [],
        })
    }

    #[test]
    fn exact_sha_returns_the_pushed_bundle() {
        let mut store = FactStore::open_memory().unwrap();
        let sigs = vec![sig(&[("COPY", 0x10), ("INT_ADD", 0x11)])];
        store.ingest(&bundle(Some("abc123"), &sigs)).unwrap();
        let found = store.query_exact("abc123").unwrap().expect("exact hit");
        assert_eq!(found["binary_sha256"], "abc123");
        assert!(store.query_exact("missing").unwrap().is_none());
    }

    #[test]
    fn signature_query_finds_the_covering_bundle() {
        let mut store = FactStore::open_memory().unwrap();
        let shared = sig(&[("COPY", 0x10), ("INT_ADD", 0x11), ("STORE", 0x12)]);
        let other = sig(&[("BRANCH", 0x20), ("CALL", 0x21)]);
        store.ingest(&bundle(Some("a"), &[shared.clone()])).unwrap();
        store.ingest(&bundle(Some("b"), &[other])).unwrap();
        // A query carrying `shared` matches bundle "a", not "b".
        let found = store
            .query_by_signatures(&[shared])
            .unwrap()
            .expect("signature hit");
        assert_eq!(found["binary_sha256"], "a");
    }

    #[test]
    fn unrelated_signatures_match_nothing() {
        let mut store = FactStore::open_memory().unwrap();
        store
            .ingest(&bundle(Some("a"), &[sig(&[("COPY", 0x10)])]))
            .unwrap();
        let query = vec![sig(&[("FLOAT_DIV", 0x99), ("FLOAT_MUL", 0x98)])];
        assert!(store.query_by_signatures(&query).unwrap().is_none());
    }

    #[test]
    fn reuploading_an_image_replaces_not_duplicates() {
        let mut store = FactStore::open_memory().unwrap();
        let first = store.ingest(&bundle(Some("dup"), &[])).unwrap();
        assert!(!first.replaced);
        let second = store.ingest(&bundle(Some("dup"), &[])).unwrap();
        assert!(second.replaced);
        // Only one bundle survives for the image.
        let count: i64 = store
            .db
            .query_row(
                "SELECT COUNT(*) FROM bundles WHERE binary_sha256='dup'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn handle_line_round_trips_push_then_pull() {
        let mut store = FactStore::open_memory().unwrap();
        let sigs = vec![sig(&[("COPY", 0x10), ("INT_ADD", 0x11)])];
        let push = json!({"method":"push_facts","params":{"bundle": bundle(Some("rt"), &sigs)}});
        let reply: Value =
            serde_json::from_str(&store.handle_line(&push.to_string())).unwrap();
        assert!(reply.get("error").is_none(), "push failed: {reply}");
        assert_eq!(reply["result"]["signatures"], 1);

        let pull = json!({"method":"pull_facts","params":{"binary_sha256":"rt"}});
        let reply: Value =
            serde_json::from_str(&store.handle_line(&pull.to_string())).unwrap();
        assert_eq!(reply["result"]["matched"], "exact");
        assert_eq!(reply["result"]["bundle"]["binary_sha256"], "rt");
    }
}
