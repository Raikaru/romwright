//! The struct pass of a decompile.
//!
//! The decompiler recovers a function's parameters before anything can say
//! what they point at, so typing one with a struct takes a second decompile:
//!
//! 1. decompile the functions as asked (pass 1);
//! 2. solve each body's accesses with the subtype solver, as the
//!    `infer_prototypes` job does (`types_infer::prototypes`), and for every
//!    pointer parameter whose type says nothing of its pointee and whose
//!    accesses pass the [gate](crate::struct_types::gate), synthesize
//!    `struct fn_<entry>_arg<n>` and retype that parameter in the pass-1
//!    prototype;
//! 3. store the layouts (`type_defs`/`type_fields`, source
//!    `native-inferred:struct-layout`) and decompile the retyped functions
//!    again with that prototype handed to the worker for that function alone
//!    (`ROMWRIGHT_STRUCT_OVERLAY`): nothing is written to the prototype table,
//!    so an asserted prototype stays asserted and no other function sees a
//!    callee's struct.
//!
//! `ROMWRIGHT_STRUCTS` decides whether the pass runs at all
//! (`romwright_model::structs::StructMode`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::exec::ExecutionRequest;
use crate::{native_runtime, Core, Result};
use romwright_model::structs::{StructLayout, StructMode};
use romwright_model::{Address, DecompDoc, FuncProto};

/// What a pass decided: the request the retyped functions decompile under, and
/// which functions that is. Dropping it removes the overlay file.
pub(crate) struct Plan {
    pub request: ExecutionRequest,
    pub changed: Vec<String>,
    overlay: PathBuf,
}

impl Drop for Plan {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.overlay);
    }
}

impl Core {
    /// Pass 1 over `addresses`, then the struct pass over what it recovered.
    /// A failure of the pass leaves the pass-1 documents and is reported in
    /// the returned warnings: structs are an addition to a decompile, not a
    /// reason for it to fail.
    pub(crate) fn decompile_docs_structs(
        &self,
        request: &ExecutionRequest,
        addresses: &[String],
    ) -> Result<(BTreeMap<String, DecompDoc>, Vec<String>)> {
        let mut docs = native_runtime::decompile_native_docs(request, addresses)?;
        let mut warnings = Vec::new();
        if !self.struct_pass_enabled(request) || docs.is_empty() {
            return Ok((docs, warnings));
        }
        match self.plan_structs(request, &docs) {
            Ok(Some(plan)) => {
                let mut retyped = BTreeMap::new();
                let mut failed = Vec::new();
                attempt(&plan.request, &plan.changed, &native_runtime::decompile_native_docs, &mut retyped, &mut failed);
                warnings.extend(failed.into_iter().map(|(address, error)| {
                    format!("struct pass: {address} left untyped: {error}")
                }));
                let table = self.struct_table(request)?;
                for (key, doc) in retyped {
                    if !table.misprints(&doc_text(&doc)) {
                        docs.insert(key, doc);
                    }
                }
            }
            Ok(None) => {}
            Err(error) => warnings.push(format!("struct pass: {error}")),
        }
        Ok((docs, warnings))
    }

    /// The printed text of `addresses` with the struct pass applied, and the
    /// definitions of the structs the text names written before it.
    pub(crate) fn decompile_texts_structs(
        &self,
        request: &ExecutionRequest,
        addresses: &[String],
    ) -> Result<BTreeMap<String, String>> {
        if !self.struct_pass_enabled(request) || addresses.is_empty() {
            return Ok(native_runtime::decompile_native_batch(request, addresses)?);
        }
        let docs = native_runtime::decompile_native_docs(request, addresses)?;
        let plan = match self.plan_structs(request, &docs) {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!("struct pass: {error}");
                None
            }
        };
        let mut texts = BTreeMap::new();
        match &plan {
            Some(plan) => {
                let mut failed = Vec::new();
                attempt(&plan.request, addresses, &native_runtime::decompile_native_batch, &mut texts, &mut failed);
                if !failed.is_empty() {
                    let failed: Vec<String> = failed.into_iter().map(|(address, _)| address).collect();
                    texts.extend(native_runtime::decompile_native_batch(request, &failed)?);
                }
            }
            None => texts = native_runtime::decompile_native_batch(request, addresses)?,
        }
        drop(plan);
        let table = self.struct_table(request)?;
        let untyped: Vec<String> = texts
            .iter()
            .filter(|(_, text)| table.misprints(text))
            .map(|(address, _)| address.clone())
            .collect();
        if !untyped.is_empty() {
            texts.extend(native_runtime::decompile_native_batch(request, &untyped)?);
        }
        for text in texts.values_mut() {
            let definitions = table.definitions(text, "");
            if !definitions.is_empty() {
                *text = format!("{definitions}\n{text}");
            }
        }
        Ok(texts)
    }

    /// The layouts the mode shows, as stored now.
    fn struct_table(&self, request: &ExecutionRequest) -> Result<crate::struct_types::StructTable> {
        let program = self.db.program_id(&request.program)?;
        crate::struct_types::StructTable::load(&self.db, program, StructMode::from_env())
    }

    fn struct_pass_enabled(&self, request: &ExecutionRequest) -> bool {
        StructMode::from_env().infers() && request.config.inferred_types
    }

    /// Steps 2 and 3 above, up to the point the retyped functions can be
    /// decompiled. `None` when no function qualifies.
    pub(crate) fn plan_structs(
        &self,
        request: &ExecutionRequest,
        docs: &BTreeMap<String, DecompDoc>,
    ) -> Result<Option<Plan>> {
        let mut recovered: Vec<(Address, FuncProto)> = Vec::with_capacity(docs.len());
        let mut texts: BTreeMap<u64, String> = BTreeMap::new();
        for (key, doc) in docs {
            let (Some(prototype), Ok(entry)) = (doc.prototype.as_ref(), u64::from_str_radix(key, 16)) else {
                continue;
            };
            let mut prototype = prototype.clone();
            crate::register_params::augment(&request.config, &request.language, &mut prototype, &doc.storage);
            recovered.push((Address::ram(entry), prototype));
            texts.insert(entry, doc_text(doc));
        }
        if recovered.is_empty() {
            return Ok(None);
        }
        let types = self.parameter_types(request, &recovered)?;
        let no_pointees = Vec::new();
        // Functions whose prototype a user asserted or an import supplied.
        let program = self.db.program_id(&request.program)?;
        let declared: std::collections::HashSet<u64> = self
            .db
            .prototypes(program)?
            .iter()
            .filter(|row| crate::types_infer::prototypes::protected(row))
            .map(|row| row.function.offset)
            .collect();
        let mut layouts: BTreeMap<String, StructLayout> = BTreeMap::new();
        let mut signatures: BTreeMap<u64, String> = BTreeMap::new();
        for (address, prototype) in recovered {
            let entry = address.offset;
            let Some(slots) = types.functions.get(&entry) else { continue };
            if types.opaque.contains(&entry) {
                continue;
            }
            // A variadic function's register-save area is not parameters.
            let fixed = types.variadic.get(&entry).copied().unwrap_or(slots.len()).min(slots.len());
            let pointees = types.pointees.get(&entry).unwrap_or(&no_pointees);
            let mut retyped = prototype.clone();
            // A parameter the pass-1 text reads at one offset as two things (a float and
            // bits, two overlapping widths) is not a struct.
            let mut evidence = slots[..fixed].to_vec();
            if let Some(text) = texts.get(&entry) {
                for (index, parameter) in prototype.parameters.iter().enumerate().take(evidence.len()) {
                    if crate::struct_types::mixed_accesses(text, &parameter.name) {
                        evidence[index] = crate::types_infer::Ty::Unknown;
                    }
                }
            }
            let mut made = crate::types_infer::prototypes::upgrade_structs(
                &mut retyped,
                entry,
                &evidence,
                pointees,
                &types.target,
                declared.contains(&entry),
            );
            // The solver leaves a field `undefined<N>` where it proved nothing, and the
            // decompiler prints no cast for a value stored into or read from one: a float
            // parameter stored into it, or a float compare on it, then converts numerically.
            // Where the untyped text typed every access at that offset the same, that is
            // the field's type.
            if let Some(text) = texts.get(&entry) {
                for (index, parameter) in prototype.parameters.iter().enumerate() {
                    let name = romwright_model::structs::inferred_name(entry, index);
                    let Some(layout) = made.iter_mut().find(|layout| layout.name == name) else { continue };
                    let seen = crate::struct_types::access_field_types(text, &parameter.name);
                    for field in &mut layout.fields {
                        if field.type_ref.starts_with("undefined")
                            && let Some((width, spelled)) = seen.get(&field.offset)
                            && u64::from(*width) == field.size
                        {
                            field.type_ref = spelled.clone();
                        }
                    }
                }
            }
            if made.is_empty() || types.locks_overlapping_input(entry, &retyped, None) {
                continue;
            }
            signatures.insert(entry, crate::prototypes::transport_signature(&retyped)?);
            for layout in made {
                layouts.insert(layout.name.clone(), layout);
            }
        }
        if signatures.is_empty() {
            return Ok(None);
        }
        let program = self.db.program_id(&request.program)?;
        let rows: Vec<_> = layouts.values().map(StructLayout::rows).collect();
        // The layouts are derived data and advance no revision, so the request
        // stays valid for the caller's final check.
        self.check_execution(request)?;
        self.db.store_struct_layouts(program, None, &rows)?;
        let directory = request.project_dir.join("struct-overlay");
        std::fs::create_dir_all(&directory)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let overlay = directory.join(format!("{}-{nanos}.json", std::process::id()));
        let prototypes: BTreeMap<String, &String> =
            signatures.iter().map(|(entry, signature)| (entry.to_string(), signature)).collect();
        std::fs::write(&overlay, serde_json::json!({ "prototypes": prototypes }).to_string())?;
        let mut pass_two = request.clone();
        pass_two.config.struct_overlay = Some(overlay.clone());
        Ok(Some(Plan {
            request: pass_two,
            changed: signatures.keys().map(|entry| format!("{entry:x}")).collect(),
            overlay,
        }))
    }
}

impl Core {
    /// Stores the layouts one `infer_prototypes` round synthesized, against the
    /// revision the round computed from, and returns the revision the round's
    /// prototypes merge against (the layouts are written first: a row that
    /// names a struct is applied by the worker only when the struct exists).
    pub fn persist_struct_layouts(
        &self,
        program: &str,
        revision: u64,
        layouts: &[StructLayout],
    ) -> Result<u64> {
        if layouts.is_empty() {
            return Ok(revision);
        }
        let id = self.db.program_id(program)?;
        let actual = self.db.revision(id)?;
        if actual != revision {
            return Err(romwright_db::DbError::StaleRevision { expected: revision, actual }.into());
        }
        let rows: Vec<_> = layouts.iter().map(StructLayout::rows).collect();
        self.db.store_struct_layouts(id, None, &rows)?;
        Ok(self.db.revision(id)?)
    }
}

/// The printed text of a document: its tokens as they are written.
fn doc_text(doc: &DecompDoc) -> String {
    doc.tokens.iter().map(|token| token.text.as_str()).collect()
}

/// The longest one function's retyped decompile may take, and the least time
/// left worth another attempt.
const LEAF_BUDGET: Duration = Duration::from_secs(20);
const LEAST_BUDGET: Duration = Duration::from_secs(2);

/// One decompiler attempt over a batch of addresses.
type Runner<'r, V, E> =
    dyn Fn(&ExecutionRequest, &[String]) -> std::result::Result<BTreeMap<String, V>, E> + 'r;

/// Runs the retyped decompile of `addresses` and keeps what finishes. Every
/// attempt has a deadline of its own, a fraction of what is left, because the
/// decompiler can fail to settle on a retyped function (its rule pool
/// rewrites without end): the attempt is killed at that deadline, a batch is
/// then split in two and each half tried again, and a function that still
/// fails is returned in `failed` with the reason, to be printed untyped.
fn attempt<V, E: std::fmt::Display>(
    request: &ExecutionRequest,
    addresses: &[String],
    run: &Runner<'_, V, E>,
    done: &mut BTreeMap<String, V>,
    failed: &mut Vec<(String, String)>,
) {
    if addresses.is_empty() {
        return;
    }
    let now = Instant::now();
    let left = request.deadline.saturating_duration_since(now);
    if left < LEAST_BUDGET {
        failed.extend(addresses.iter().map(|address| (address.clone(), "no time left".to_string())));
        return;
    }
    let share = if addresses.len() == 1 { (left / 4).min(LEAF_BUDGET) } else { left / 2 };
    let mut bounded = request.clone();
    bounded.deadline = now + share;
    match run(&bounded, addresses) {
        Ok(found) => done.extend(found),
        Err(error) if addresses.len() == 1 => failed.push((addresses[0].clone(), error.to_string())),
        Err(_) => {
            let (first, second) = addresses.split_at(addresses.len() / 2);
            attempt(request, first, run, done, failed);
            attempt(request, second, run, done, failed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(budget: Duration) -> ExecutionRequest {
        ExecutionRequest {
            binary: PathBuf::new(),
            artifact_digest: String::new(),
            input: romwright_model::ProgramInput {
                source_path: String::new(),
                binary_digest: String::new(),
                image_selector: String::new(),
                map_digest: None,
                raw: None,
                keys_digest: None,
            },
            config: crate::session::RuntimeConfig::from_env(),
            program: String::new(),
            language: String::new(),
            base: 0,
            revision: 0,
            project_dir: PathBuf::new(),
            deadline: Instant::now() + budget,
            cancel: crate::exec::CancelToken::default(),
        }
    }

    #[test]
    fn one_function_the_decompiler_cannot_finish_costs_only_itself() {
        let addresses: Vec<String> = ["a", "b", "bad", "d", "e"].iter().map(|a| a.to_string()).collect();
        let calls = std::cell::Cell::new(0);
        let run = |_: &ExecutionRequest, batch: &[String]| -> std::result::Result<BTreeMap<String, u32>, String> {
            calls.set(calls.get() + 1);
            if batch.iter().any(|address| address == "bad") {
                return Err("execution deadline exceeded".into());
            }
            Ok(batch.iter().map(|address| (address.clone(), 1)).collect())
        };
        let (mut done, mut failed) = (BTreeMap::new(), Vec::new());
        attempt(&request(Duration::from_secs(60)), &addresses, &run, &mut done, &mut failed);
        assert_eq!(done.keys().map(String::as_str).collect::<Vec<_>>(), ["a", "b", "d", "e"]);
        assert_eq!(failed, [("bad".to_string(), "execution deadline exceeded".to_string())]);
        // Splitting is logarithmic, not one call per function.
        assert!(calls.get() <= 9, "{} calls", calls.get());
    }

    #[test]
    fn an_attempt_has_a_deadline_inside_the_request_and_none_runs_when_no_time_is_left() {
        let seen = std::cell::Cell::new(None);
        let run = |request: &ExecutionRequest, batch: &[String]| -> std::result::Result<BTreeMap<String, u32>, String> {
            seen.set(Some(request.deadline));
            Ok(batch.iter().map(|address| (address.clone(), 1)).collect())
        };
        let outer = request(Duration::from_secs(60));
        let (mut done, mut failed) = (BTreeMap::new(), Vec::new());
        attempt(&outer, &["a".to_string()], &run, &mut done, &mut failed);
        let inner = seen.get().expect("ran");
        assert!(inner < outer.deadline - Duration::from_secs(30), "a lone function gets a fraction");
        let (mut done, mut failed) = (BTreeMap::new(), Vec::new());
        seen.set(None);
        attempt(&request(Duration::from_millis(500)), &["a".to_string()], &run, &mut done, &mut failed);
        assert!(seen.get().is_none() && done.is_empty());
        assert_eq!(failed.len(), 1);
    }
}
