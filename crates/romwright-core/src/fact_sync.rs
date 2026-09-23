//! Shared-fact exchange: serialise a program's facts for upload and apply
//! a downloaded bundle (P2.2).
//!
//! The hosted fact store (`romwright-facts`) is keyed by `sha256(binary)`
//! for exact matches plus per-function semantic signatures for matches
//! across rebuilds. These methods are the store-facing edge of that loop:
//!
//! * [`Core::push_facts`] serialises one program's facts — function names,
//!   symbols, prototypes, type definitions and fields, `.vsig`
//!   library matches, and the semantic signatures in the
//!   `semantic_signatures` table — into one JSON bundle. It performs no
//!   I/O: the caller that holds the image bytes fills `binary_sha256`
//!   (hex of the file; [`crate::import_cache::digest_bytes`]) and ships
//!   the bundle to the server.
//! * [`Core::pull_facts`] applies a bundle to one program: same-address
//!   facts first, then cross-build name transfer by semantic signature
//!   ([`romwright_diff::semantic`], similarity at or above
//!   [`romwright_diff::semantic::MATCH_FLOOR`]).
//!
//! Wire format (bundle schema [`FACTS_BUNDLE_VERSION`]): a JSON object
//! with `program`, `language`, `binary_sha256` (hex string or null),
//! `functions` (`[{function: Address, name, size, semantic_signature?,
//! ops}]`), `symbols`, `prototypes`, `type_defs`, `type_fields` and
//! `signature_matches` (the matching `romwright-model` row shapes).
//! `romwright-facts` parses this verbatim, so any field added here must
//! be `#[serde(default)]`-tolerant there, and vice versa.
//!
//! Application policy, mirroring [`Core::apply_signatures`]:
//!
//! * A name is only written over a generated one (`FUN_` prefix).
//!   Anything else came from the image's own symbols or an analyst and
//!   stays. A bundle name that is itself generated carries no
//!   information and is never applied.
//! * Facts keep the provenance they were pushed with, verbatim: a pushed
//!   assertion applies as an assertion, a pushed inference as an
//!   inference, so the store's ownership rules (`set_prototype` refusing
//!   to let an inference overwrite an assertion) keep working across the
//!   transfer. Pulled renames go through the rename command, so they
//!   become local assertions that survive re-analysis like any analyst
//!   rename.
//! * Symbols and types merge: rows absent locally are added, rows present
//!   locally are never overwritten. Signature matches replace exactly
//!   their own producer's rows, as a re-run of the matching pass would.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Bundle schema version written by [`Core::push_facts`].
pub const FACTS_BUNDLE_VERSION: u64 = 1;

/// Provenance source recorded on the envelope of a pushed bundle, not on
/// its rows: rows keep the provenance they were pushed with (see module
/// docs).
pub const FACTS_ENVELOPE_SOURCE: &str = "factdb";

/// A name this pass may overwrite: the loader's generated placeholder.
/// Mirrors the rule in [`Core::apply_signatures`].
fn is_generated(name: &str) -> bool {
    name.starts_with("FUN_")
}

fn bundle_error(message: String) -> crate::CoreError {
    crate::CoreError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

fn parse_bundle<T: for<'de> Deserialize<'de>>(bundle: &Value, field: &str) -> crate::Result<T> {
    let value = bundle.get(field).cloned().unwrap_or(Value::Null);
    if value.is_null() {
        let empty: T = serde_json::from_value(Value::Array(Vec::new()))
            .map_err(|error| bundle_error(format!("facts bundle: invalid {field}: {error}")))?;
        return Ok(empty);
    }
    serde_json::from_value(value)
        .map_err(|error| bundle_error(format!("facts bundle: invalid {field}: {error}")))
}

/// One function fact inside a bundle: the name the push observed plus the
/// semantic signature that lets a different build claim it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BundleFunction {
    function: romwright_model::Address,
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    semantic_signature: Option<String>,
    #[serde(default)]
    ops: u32,
}

impl crate::Core {
    /// Serialises one program's shareable facts into a fact-bundle value.
    ///
    /// `binary_sha256` is always null here: the store does not retain the
    /// image bytes, so the caller that holds them (the CLI, the API
    /// layer) fills the hex digest before upload.
    pub fn push_facts(&self, program: &str) -> crate::Result<Value> {
        let id = self.db.program_id(program)?;
        let language = self.db.program_language(id)?;
        let mut signatures: HashMap<romwright_model::Address, (String, u32)> = HashMap::new();
        for row in self.db.semantic_signatures(id)? {
            signatures.insert(row.function, (row.signature, row.ops));
        }
        let mut functions = Vec::new();
        for function in self.db.functions(id)? {
            let (semantic_signature, ops) = signatures
                .get(&function.entry)
                .map(|(signature, ops)| (Some(signature.clone()), *ops))
                .unwrap_or((None, 0));
            functions.push(json!({
                "function": function.entry,
                "name": function.name,
                "size": function.size,
                "semantic_signature": semantic_signature,
                "ops": ops,
            }));
        }
        Ok(json!({
            "bundle": FACTS_BUNDLE_VERSION,
            "program": program,
            "language": language,
            "binary_sha256": Value::Null,
            "provenance": FACTS_ENVELOPE_SOURCE,
            "functions": functions,
            "symbols": self.db.symbols(id)?,
            "prototypes": self.db.prototypes(id)?,
            "type_defs": self.db.type_defs(id)?,
            "type_fields": self.db.type_fields(id, None)?,
            "signature_matches": self.db.signature_matches(id)?,
        }))
    }

    /// Applies a fact bundle (as produced by [`Core::push_facts`]) to one
    /// program: same-address facts, then cross-build names by semantic
    /// signature. Returns the pull report (counts; see module docs).
    pub fn pull_facts(&self, program: &str, bundle: &Value) -> crate::Result<Value> {
        let id = self.db.program_id(program)?;
        let bundle_functions: Vec<BundleFunction> = parse_bundle(bundle, "functions")?;
        let mut renamed = 0usize;
        let mut signature_transferred = 0usize;
        let mut skipped = 0usize;

        let local: Vec<romwright_model::FunctionRow> = self.db.functions(id)?;
        let mut local_name: HashMap<romwright_model::Address, String> = HashMap::new();
        for function in &local {
            local_name.insert(function.entry.clone(), function.name.clone());
        }

        // 1. Same-address names: a pushed name lands where the address is
        // held locally and the local name is still generated.
        let mut claimed: HashSet<romwright_model::Address> = HashSet::new();
        for fact in &bundle_functions {
            if is_generated(&fact.name) {
                skipped += 1;
                continue;
            }
            match local_name.get(&fact.function) {
                None => skipped += 1,
                Some(current) if !is_generated(current) => skipped += 1,
                Some(current) => {
                    self.db
                        .rename_command(id, &fact.function, &fact.name, current)?;
                    local_name.insert(fact.function.clone(), fact.name.clone());
                    claimed.insert(fact.function.clone());
                    renamed += 1;
                }
            }
        }

        // 2. Cross-build names: a local function with no exact fact but a
        // semantic signature takes the best same-signature pushed name.
        // Greedy by descending similarity; each pushed function names at
        // most one local function, so two identical siblings cannot both
        // claim one library name.
        let mut local_sigs: HashMap<romwright_model::Address, romwright_diff::semantic::Signature> =
            HashMap::new();
        for row in self.db.semantic_signatures(id)? {
            if let Some(signature) = romwright_diff::semantic::Signature::parse_hex(&row.signature)
            {
                local_sigs.insert(row.function, signature);
            }
        }
        let mut candidates: Vec<(f64, usize, romwright_model::Address)> = Vec::new();
        for (index, fact) in bundle_functions.iter().enumerate() {
            if is_generated(&fact.name) || claimed.contains(&fact.function) {
                continue;
            }
            let Some(push_sig) = fact
                .semantic_signature
                .as_deref()
                .and_then(romwright_diff::semantic::Signature::parse_hex)
            else {
                continue;
            };
            for (entry, current) in &local_name {
                if claimed.contains(entry) || !is_generated(current) {
                    continue;
                }
                let Some(local_sig) = local_sigs.get(entry) else {
                    continue;
                };
                if let Some(similarity) = local_sig.similarity(&push_sig)
                    && similarity >= romwright_diff::semantic::MATCH_FLOOR
                {
                    candidates.push((similarity, index, entry.clone()));
                }
            }
        }
        // Highest similarity first; ties break by pushed-function order so
        // the outcome is deterministic.
        candidates.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.cmp(&b.1))
        });
        let mut used_push: HashSet<usize> = HashSet::new();
        for (_, index, entry) in candidates {
            if claimed.contains(&entry) || !used_push.insert(index) {
                continue;
            }
            let name = bundle_functions[index].name.clone();
            self.db
                .rename_command(id, &entry, &name, local_name[&entry].as_str())?;
            local_name.insert(entry.clone(), name);
            claimed.insert(entry);
            signature_transferred += 1;
        }

        // 3. Prototypes for locally-held functions, through the ownership
        // rules: a pushed inference cannot overwrite a local assertion.
        let prototypes: Vec<romwright_model::PrototypeRow> = parse_bundle(bundle, "prototypes")?;
        let mut applied_prototypes = 0usize;
        for row in &prototypes {
            if !local_name.contains_key(&row.function) {
                skipped += 1;
                continue;
            }
            self.db.set_prototype(id, row)?;
            applied_prototypes += 1;
        }

        // 4. Symbols merge: absent (address, name) pairs are added, held
        // rows are never rewritten.
        let symbols: Vec<romwright_model::SymbolRow> = parse_bundle(bundle, "symbols")?;
        let mut applied_symbols = 0usize;
        if !symbols.is_empty() {
            let mut have: HashSet<(romwright_model::Address, String)> = HashSet::new();
            for row in self.db.symbols(id)? {
                have.insert((row.address, row.name));
            }
            let mut merged = self.db.symbols(id)?;
            for row in &symbols {
                if have.insert((row.address.clone(), row.name.clone())) {
                    merged.push(row.clone());
                    applied_symbols += 1;
                }
            }
            if applied_symbols > 0 {
                self.db.replace_symbols(id, &merged)?;
            }
        }

        // 5. Types merge: definitions and fields absent locally are added.
        let type_defs: Vec<romwright_model::TypeDefRow> = parse_bundle(bundle, "type_defs")?;
        let mut applied_type_defs = 0usize;
        if !type_defs.is_empty() {
            let have: HashSet<String> = self
                .db
                .type_defs(id)?
                .into_iter()
                .map(|row| row.name)
                .collect();
            for row in &type_defs {
                if !have.contains(&row.name) {
                    self.db.set_type_def(id, row)?;
                    applied_type_defs += 1;
                }
            }
        }
        let type_fields: Vec<romwright_model::TypeFieldRow> = parse_bundle(bundle, "type_fields")?;
        let mut applied_type_fields = 0usize;
        if !type_fields.is_empty() {
            let mut have: HashSet<(String, u32)> = HashSet::new();
            let mut merged = self.db.type_fields(id, None)?;
            for row in &merged {
                have.insert((row.type_name.clone(), row.ordinal));
            }
            for row in &type_fields {
                if have.insert((row.type_name.clone(), row.ordinal)) {
                    merged.push(row.clone());
                    applied_type_fields += 1;
                }
            }
            if applied_type_fields > 0 {
                self.db.replace_type_fields(id, &merged)?;
            }
        }

        // 6. Library matches, grouped by producing source so one
        // producer's rows replace exactly that producer's rows — the same
        // ownership a re-run of the matching pass has. Facts for
        // functions the local program does not hold are dropped: a match
        // names a function, and there is no function to name.
        let matches: Vec<romwright_model::SignatureMatchRow> =
            parse_bundle(bundle, "signature_matches")?;
        let mut applied_matches = 0usize;
        if !matches.is_empty() {
            let mut by_source: HashMap<String, Vec<romwright_model::SignatureMatchRow>> =
                HashMap::new();
            for row in &matches {
                if !local_name.contains_key(&row.function) {
                    skipped += 1;
                    continue;
                }
                // A remote claim is evidence, not a locally verified match
                // against the captured bytes. Only the local matcher binds it.
                let mut imported = row.clone();
                imported.input = None;
                by_source
                    .entry(row.provenance.source.clone())
                    .or_default()
                    .push(imported);
            }
            for (source, rows) in &by_source {
                self.db
                    .replace_signature_matches(id, self.db.revision(id)?, source, rows, &[])?;
                applied_matches += rows.len();
            }
        }

        Ok(json!({
            "program": program,
            "renamed": renamed,
            "signature_transferred": signature_transferred,
            "prototypes": applied_prototypes,
            "symbols": applied_symbols,
            "type_defs": applied_type_defs,
            "type_fields": applied_type_fields,
            "signature_matches": applied_matches,
            "skipped": skipped,
            "revision": self.db.revision(id)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{FactKind, FactProvenance, PrototypeRow};

    fn core_in(suffix: &str) -> (crate::Core, tempfile_path::TempProject) {
        let project = tempfile_path::TempProject::new(suffix);
        let core = crate::Core::open(project.path()).expect("open project");
        (core, project)
    }

    /// A unique scratch directory without a tempfile dependency.
    mod tempfile_path {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);

        pub struct TempProject {
            path: std::path::PathBuf,
        }

        impl TempProject {
            pub fn new(suffix: &str) -> Self {
                let id = NEXT.fetch_add(1, Ordering::SeqCst);
                let path = std::env::temp_dir().join(format!(
                    "romwright-fact-sync-{}-{}-{}",
                    std::process::id(),
                    id,
                    suffix
                ));
                std::fs::create_dir_all(&path).expect("create temp project");
                Self { path }
            }

            pub fn path(&self) -> &std::path::Path {
                &self.path
            }
        }

        impl Drop for TempProject {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    fn analysed_core() -> (crate::Core, tempfile_path::TempProject) {
        use romwright_model::{Address, FunctionRow};
        let (core, _tmp) = core_in("push");
        let db = core.store_handle().expect("store handle");
        let prov = romwright_model::Provenance {
            producer: "test".into(),
            upstream_version: "0".into(),
        };
        let id = db
            .upsert_program("synth", "x86:LE:64:default", &prov)
            .expect("upsert");
        let fun = |entry: u64| FunctionRow {
            entry: Address::ram(entry),
            name: format!("FUN_{entry:08x}"),
            size: 32,
            signature: None,
            traced: false,
            calling_convention: None,
        };
        db.replace_functions(id, &[fun(0x401000), fun(0x401040)])
            .expect("seed functions");
        core.rename_command("synth", &Address::ram(0x401000), "parse_header")
            .expect("rename");
        db.set_prototype(
            id,
            &PrototypeRow {
                function: Address::ram(0x401000),
                signature: "int parse_header(char const *path)".into(),
                calling_convention: None,
                return_type: Some("int".into()),
                provenance: FactProvenance {
                    kind: FactKind::Asserted,
                    source: "analyst".into(),
                    confidence: None,
                },
            },
        )
        .expect("prototype");
        (core, _tmp)
    }

    #[test]
    fn push_pull_roundtrip_restores_names() {
        use romwright_model::{Address, FunctionRow};
        let (source, _a) = analysed_core();
        let bundle = source.push_facts("synth").expect("push");
        assert_eq!(bundle["program"], serde_json::json!("synth"));

        let (target, _b) = core_in("pull");
        {
            let db = target.store_handle().expect("store handle");
            let prov = romwright_model::Provenance {
                producer: "test".into(),
                upstream_version: "0".into(),
            };
            let id = db
                .upsert_program("synth", "x86:LE:64:default", &prov)
                .expect("upsert");
            let fun = |entry: u64| FunctionRow {
                entry: Address::ram(entry),
                name: format!("FUN_{entry:08x}"),
                size: 32,
                signature: None,
                traced: false,
                calling_convention: None,
            };
            db.replace_functions(id, &[fun(0x401000), fun(0x401040)])
                .expect("seed");
        }
        let report = target.pull_facts("synth", &bundle).expect("pull");
        assert_eq!(report["renamed"], serde_json::json!(1));
        let names: HashMap<u64, String> = target
            .functions("synth")
            .expect("functions")
            .into_iter()
            .map(|row| (row.entry.offset, row.name))
            .collect();
        assert_eq!(names[&0x401000], "parse_header");
        assert_eq!(names[&0x401040], "FUN_00401040");
        assert_eq!(target.prototypes("synth").expect("protos").len(), 1);
    }

    #[test]
    fn pull_matches_names_by_semantic_signature_across_builds() {
        use romwright_diff::semantic::{SemOp, signature};
        use romwright_model::{Address, FunctionRow, SemanticSignatureRow};
        // Two builds of one library function: different load addresses,
        // identical data-flow, so the semantic signatures agree exactly.
        let ops = vec![
            SemOp::plain("INT_ADD", &[("register", 0, 4), ("const", 1, 4)]),
            SemOp::plain("INT_MULT", &[("register", 0, 4), ("const", 16, 4)]),
        ];
        let hex = signature(&ops).to_hex();
        let other = vec![SemOp::plain("BRANCH", &[("ram", 0x1000, 8)])];

        let (source, _a) = core_in("sig-push");
        {
            let db = source.store_handle().expect("store handle");
            let prov = romwright_model::Provenance {
                producer: "test".into(),
                upstream_version: "0".into(),
            };
            let id = db
                .upsert_program("lib", "x86:LE:64:default", &prov)
                .expect("upsert");
            db.replace_functions(
                id,
                &[FunctionRow {
                    entry: Address::ram(0x1000),
                    name: "FUN_00001000".into(),
                    size: 16,
                    signature: None,
                    traced: false,
                    calling_convention: None,
                }],
            )
            .expect("seed");
            source
                .rename_command("lib", &Address::ram(0x1000), "crc32_update")
                .expect("rename");
            db.replace_semantic_signatures(
                id,
                &[SemanticSignatureRow {
                    function: Address::ram(0x1000),
                    signature: hex.clone(),
                    ops: 2,
                    constants: Vec::new(),
                }],
            )
            .expect("sigs");
        }
        let bundle = source.push_facts("lib").expect("push");

        let (target, _b) = core_in("sig-pull");
        {
            let db = target.store_handle().expect("store handle");
            let prov = romwright_model::Provenance {
                producer: "test".into(),
                upstream_version: "0".into(),
            };
            let id = db
                .upsert_program("lib", "x86:LE:64:default", &prov)
                .expect("upsert");
            // Rebuilt at a new base, plus an unrelated function that must
            // keep its generated name.
            db.replace_functions(
                id,
                &[
                    FunctionRow {
                        entry: Address::ram(0x2000),
                        name: "FUN_00002000".into(),
                        size: 16,
                        signature: None,
                        traced: false,
                        calling_convention: None,
                    },
                    FunctionRow {
                        entry: Address::ram(0x3000),
                        name: "FUN_00003000".into(),
                        size: 8,
                        signature: None,
                        traced: false,
                        calling_convention: None,
                    },
                ],
            )
            .expect("seed");
            db.replace_semantic_signatures(
                id,
                &[
                    SemanticSignatureRow {
                        function: Address::ram(0x2000),
                        signature: hex.clone(),
                        ops: 2,
                        constants: Vec::new(),
                    },
                    SemanticSignatureRow {
                        function: Address::ram(0x3000),
                        signature: signature(&other).to_hex(),
                        ops: 1,
                        constants: Vec::new(),
                    },
                ],
            )
            .expect("sigs");
        }
        let report = target.pull_facts("lib", &bundle).expect("pull");
        assert_eq!(report["renamed"], serde_json::json!(0));
        assert_eq!(report["signature_transferred"], serde_json::json!(1));
        let names: HashMap<u64, String> = target
            .functions("lib")
            .expect("functions")
            .into_iter()
            .map(|row| (row.entry.offset, row.name))
            .collect();
        assert_eq!(names[&0x2000], "crc32_update");
        assert_eq!(names[&0x3000], "FUN_00003000");
    }
}
