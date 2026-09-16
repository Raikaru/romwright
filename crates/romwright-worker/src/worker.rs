//! The native decompiler worker client: ghidra_opt as a supervised child
//! process speaking the burst/packed protocol (WORKER-001 extraction — the
//! protocol client is now a library so sessions can pool/lease/restart it).
//!
//! Spawns the pinned `ghidra_opt` binary, speaks the burst/packed protocol
//! on its stdio, and answers its program queries from the project store
//! (`romwright-db`) plus the selected immutable program input. This is the
//! no-JVM replacement for the Stage-1 bridge, per ADR-0001.

use romwright_db::ProjectDb;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::provider::ProgramProvider;
use crate::wire::{self, burst, decode_burst, encode_addr_element};
#[cfg(test)]
use crate::wire::{encode_burst, encode_string_stream};

/// Worker failure.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// Process spawn or pipe failure.
    #[error("worker process: {0}")]
    Process(String),
    /// The decompiler answered with an exception burst.
    #[error("decompiler exception: {0}")]
    Decompiler(String),
    /// Protocol violation (wrong burst sequence).
    #[error("protocol: {0}")]
    Protocol(String),
    /// The pinned binary or specs are missing.
    #[error("setup: {0}")]
    Setup(String),
    /// Underlying IO.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Store failure while serving callbacks.
    #[error("store: {0}")]
    Store(#[from] romwright_db::DbError),
    /// The decompiler did not answer within the deadline and was killed, as
    /// Ghidra's client kills it (`DecompileProcess.timeoutRunnable`:100-106,
    /// armed by `sendCommandTimeout`:564-595).
    #[error("decompiler timed out after {0}s")]
    Timeout(u64),
}

/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = WorkerError> = std::result::Result<T, E>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrototypeMode {
    Asserted,
    Inferred,
    Recovery,
}

/// A running `ghidra_opt` child with one registered program.
pub struct NativeWorker {
    /// The child, behind a mutex so a watchdog thread can kill it (deadline
    /// semantics, WORKER-002) while the protocol read is blocked.
    child: std::sync::Arc<std::sync::Mutex<Option<Child>>>,
    pub(crate) stdin: Option<ChildStdin>,
    pub(crate) stdout: ChildStdout,
    pub(crate) out_buf: Vec<u8>,
    /// Architecture slot returned by registerProgram.
    arch_id: i32,
    applied_prototypes: HashMap<u64, PrototypeMode>,
    /// Path passed to ghidra_opt for diagnostics.
    pub binary: PathBuf,
}

impl NativeWorker {
    /// Spawns a configured native decompiler command. Language inputs belong
    /// on this child command, not in process-global environment mutations.
    pub fn launch(mut command: Command) -> Result<Self> {
        let binary = PathBuf::from(command.get_program());
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| WorkerError::Process(e.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| WorkerError::Process("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| WorkerError::Process("no stdout".into()))?;
        Ok(Self {
            child: std::sync::Arc::new(std::sync::Mutex::new(Some(child))),
            arch_id: 0,
            applied_prototypes: HashMap::new(),
            stdin: Some(stdin),
            stdout,
            out_buf: Vec::new(),
            binary,
        })
    }

    /// Activates stored prototypes for this function and its direct callees.
    /// Unrelated prototypes must not affect an independent decompile.
    pub fn prepare_function(&mut self, provider: &mut ProgramProvider, address: u64) -> Result<()> {
        self.prepare_function_mode(provider, address, false)
    }

    /// Recovers an inferred target anew while retaining locked callee facts.
    /// Analyst assertions remain locked even when they are the target.
    pub fn prepare_function_for_inference(
        &mut self,
        provider: &mut ProgramProvider,
        address: u64,
    ) -> Result<()> {
        self.prepare_function_mode(provider, address, true)
    }

    fn prepare_function_mode(
        &mut self,
        provider: &mut ProgramProvider,
        address: u64,
        recover: bool,
    ) -> Result<()> {
        if let Some(&size) = provider.function_sizes.get(&address) {
            let first = provider
                .call_edges
                .partition_point(|(from, _)| from.offset < address);
            for index in first..provider.call_edges.len() {
                if provider.call_edges[index].0.offset - address >= size {
                    break;
                }
                let callee = provider.call_edges[index].1.offset;
                self.apply_stored_prototype(provider, callee, false)?;
            }
        }
        self.apply_stored_prototype(provider, address, recover)
    }

    fn apply_stored_prototype(
        &mut self,
        provider: &mut ProgramProvider,
        address: u64,
        recover: bool,
    ) -> Result<()> {
        let Some(prototype) = provider.prototypes.get(&address) else {
            return Ok(());
        };
        let mode = match prototype.provenance.kind {
            romwright_model::FactKind::Asserted => PrototypeMode::Asserted,
            romwright_model::FactKind::Inferred if recover => PrototypeMode::Recovery,
            romwright_model::FactKind::Inferred => PrototypeMode::Inferred,
        };
        if self.applied_prototypes.get(&address) == Some(&mode) {
            return Ok(());
        }
        let signature = prototype.signature.clone();
        let name = provider
            .function_names
            .get(&address)
            .cloned()
            .ok_or_else(|| {
                WorkerError::Setup(format!(
                    "prototype target {address:#x} has no function name"
                ))
            })?;
        self.set_function_signature(provider, address, &name, &signature, mode)?;
        self.applied_prototypes.insert(address, mode);
        Ok(())
    }

    /// Writes one complete frame to the child's stdin.
    pub(crate) fn write_frame(&mut self, buf: &[u8]) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| WorkerError::Process("stdin closed".into()))?;
        stdin.write_all(buf).map_err(WorkerError::Io)?;
        stdin.flush().map_err(WorkerError::Io)?;
        if let Ok(log) = std::env::var("WORKER_LOG") {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .unwrap();
            use std::io::Write as _;
            let _ = writeln!(
                f,
                "--> {}",
                buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
        }
        Ok(())
    }

    /// Sends `registerProgram` with the four spec XML documents the pinned
    /// ArchitectureGhidra::buildSpecFile expects plus a packed function-shell
    /// document. The empty shell document preserves the old lazy symbol
    /// lookup behavior for pooled callers.
    ///
    /// The native program queries are answered by `provider` during
    /// registration (getBytes, getRegister, ...) exactly as during any
    /// other command.
    pub fn register_program(
        &mut self,
        provider: &mut ProgramProvider,
        pspec: &str,
        cspec: &str,
        tspec: &str,
        corespec: &str,
    ) -> Result<()> {
        let shell = Self::encode_function_shell_doc(
            provider.ram_space_index as u32,
            &[],
            &provider.non_returning,
            &provider.conventions,
            &std::collections::HashMap::new(),
            &provider.call_return_branches,
            |_| Vec::new(),
        );
        self.register_program_with_shell(provider, pspec, cspec, tspec, corespec, &shell)
    }

    /// Sends `registerProgram` with one or more preloaded function shells.
    /// Shells are symbol-table backed by the native process, which lets the
    /// subsequent `setFunctionSignature` command apply a full C prototype.
    pub fn register_program_with_shell(
        &mut self,
        provider: &mut ProgramProvider,
        pspec: &str,
        cspec: &str,
        tspec: &str,
        corespec: &str,
        function_shell: &[u8],
    ) -> Result<()> {
        let response = self.run_command(
            provider,
            "registerProgram",
            &[
                pspec.as_bytes(),
                cspec.as_bytes(),
                tspec.as_bytes(),
                corespec.as_bytes(),
                function_shell,
            ],
        )?;
        self.arch_id = std::str::from_utf8(&response)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .ok_or_else(|| {
                WorkerError::Protocol("registerProgram returned no architecture id".into())
            })?;
        self.applied_prototypes.clear();
        self.configure_options(provider, false)
    }

    fn configure_options(&mut self, provider: &mut ProgramProvider, switches: bool) -> Result<()> {
        // setOptions resets defaults: retain readonly propagation in both modes.
        let mut options = Vec::new();
        wire::encode_header(&mut options, wire::ELEMENT_START, wire::elem::OPTIONSLIST);
        wire::encode_header(&mut options, wire::ELEMENT_START, wire::elem::READONLY);
        wire::encode_string_attribute(&mut options, wire::attr::CONTENT, b"on");
        wire::encode_header(&mut options, wire::ELEMENT_END, wire::elem::READONLY);
        if switches {
            wire::encode_header(&mut options, wire::ELEMENT_START, wire::elem::CURRENTACTION);
            for (element, value) in [
                (wire::elem::PARAM1, "decompile"),
                (wire::elem::PARAM2, "unreachable"),
                (wire::elem::PARAM3, "off"),
            ] {
                wire::encode_header(&mut options, wire::ELEMENT_START, element);
                wire::encode_string_attribute(&mut options, wire::attr::CONTENT, value.as_bytes());
                wire::encode_header(&mut options, wire::ELEMENT_END, element);
            }
            wire::encode_header(&mut options, wire::ELEMENT_END, wire::elem::CURRENTACTION);
        }
        wire::encode_header(&mut options, wire::ELEMENT_END, wire::elem::OPTIONSLIST);
        let arch_id = self.arch_id.to_string();
        let response = self.run_command(provider, "setOptions", &[arch_id.as_bytes(), &options])?;
        if response != b"t" {
            return Err(WorkerError::Protocol(
                "setOptions rejected analysis options".into(),
            ));
        }
        Ok(())
    }

    /// Recover jump tables without rendering C or serializing the syntax tree.
    pub fn configure_switch_recovery(&mut self, provider: &mut ProgramProvider) -> Result<()> {
        self.configure_options(provider, true)?;
        self.set_action(provider, "decompile", "noc")?;
        self.set_action(provider, "", "notree")?;
        self.set_action(provider, "", "jumpload")
    }

    /// Applies a C declaration to a preloaded function through the native
    /// decompiler's own prototype parser.
    fn set_function_signature(
        &mut self,
        provider: &mut ProgramProvider,
        function_address: u64,
        function_name: &str,
        signature: &str,
        mode: PrototypeMode,
    ) -> Result<()> {
        let arch_id = self.arch_id.to_string();
        let address = format!("{function_address:x}");
        let signature = signature.trim();
        let normalized = if signature.ends_with(';') {
            signature.to_owned()
        } else {
            format!("{signature};")
        };
        let response = self.run_command(
            provider,
            "setFunctionSignature",
            &[
                arch_id.as_bytes(),
                function_name.as_bytes(),
                normalized.as_bytes(),
                address.as_bytes(),
                match mode {
                    PrototypeMode::Asserted => b"asserted",
                    PrototypeMode::Inferred => b"inferred",
                    PrototypeMode::Recovery => b"recovery",
                },
            ],
        )?;
        if !response.is_empty() {
            return Err(WorkerError::Decompiler(
                String::from_utf8_lossy(&response).trim().to_string(),
            ));
        }
        Ok(())
    }

    /// Encodes the packed document accepted as registerProgram's fifth
    /// parameter. Entries are `(RAM address, function name, byte size)`.
    /// Known non-returning entries carry full prototypes instead of lazy shells.
    pub fn encode_function_shell_doc(
        space_index: u32,
        entries: &[(u64, &str, u64)],
        non_returning: &std::collections::HashSet<u64>,
        conventions: &std::collections::HashMap<u64, String>,
        fixups: &std::collections::HashMap<u64, String>,
        call_return_branches: &std::collections::HashMap<u64, Vec<u64>>,
        locals_for: impl Fn(u64) -> Vec<(String, u64, u64, String, u64)>,
    ) -> Vec<u8> {
        let mut doc = Vec::new();
        crate::wire::encode_header(&mut doc, crate::wire::ELEMENT_START, crate::wire::elem::DOC);
        for (index, (offset, name, size)) in entries.iter().enumerate() {
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_START,
                crate::wire::elem::MAPSYM,
            );
            let branches = call_return_branches
                .get(offset)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            // A shell carries no override, so a function whose flow the store
            // corrects is sent whole even when it returns normally.
            let convention = conventions.get(offset).map(String::as_str);
            let fixup = fixups.get(offset).map(String::as_str);
            // A declared frame is a fact the shell cannot carry: a lazy shell
            // gets a default local scope when the decompiler builds it
            // (funcdata.cc:828-833), so a function with locals is sent whole.
            let owned = locals_for(*offset);
            let locals: Vec<crate::wire::StackLocal> = owned
                .iter()
                .map(
                    |(name, offset, size, type_name, type_id)| crate::wire::StackLocal {
                        name,
                        offset: *offset,
                        size: *size,
                        type_name,
                        type_id: *type_id,
                    },
                )
                .collect();
            if non_returning.contains(offset)
                || convention.is_some()
                || fixup.is_some()
                || !branches.is_empty()
                || !locals.is_empty()
            {
                crate::wire::encode_function_element(
                    &mut doc,
                    space_index,
                    index as u64 + 1,
                    *offset,
                    name,
                    *size,
                    non_returning.contains(offset),
                    convention,
                    fixup,
                    branches,
                    &locals,
                );
            } else {
                crate::wire::encode_header(
                    &mut doc,
                    crate::wire::ELEMENT_START,
                    crate::wire::elem::FUNCTIONSHELL,
                );
                crate::wire::encode_string_attribute(
                    &mut doc,
                    crate::wire::attr::NAME,
                    name.as_bytes(),
                );
                crate::wire::encode_string_attribute(
                    &mut doc,
                    crate::wire::attr::LABEL,
                    name.as_bytes(),
                );
                crate::wire::encode_header(
                    &mut doc,
                    crate::wire::ELEMENT_END,
                    crate::wire::elem::FUNCTIONSHELL,
                );
            }
            crate::wire::encode_addr_element_size(&mut doc, space_index, *offset, *size);
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_START,
                crate::wire::elem::RANGELIST,
            );
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_END,
                crate::wire::elem::RANGELIST,
            );
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_END,
                crate::wire::elem::MAPSYM,
            );
        }
        crate::wire::encode_header(&mut doc, crate::wire::ELEMENT_END, crate::wire::elem::DOC);
        doc
    }

    /// Frame shape per DecompileProcess.sendCommandTimeout (Java client):
    /// command name, then the arch id as a string stream, then the packed
    /// `<addr>` parameter, then command close. The C++ base
    /// GhidraCommand::loadParameters (ghidra_process.cc:82-97) reads that
    /// arch-id frame first, so omitting it kills the command.
    pub fn decompile_at(
        &mut self,
        provider: &mut ProgramProvider,
        space_index: u32,
        offset: u64,
    ) -> Result<Vec<u8>> {
        let mut addr = Vec::new();
        encode_addr_element(&mut addr, space_index, offset);
        let arch_id = self.arch_id.to_string();
        self.run_command(provider, "decompileAt", &[arch_id.as_bytes(), &addr])
    }

    /// Structures a control-flow graph through the decompiler's own
    /// `structureGraph` command (`ghidra_process.cc:503`): no function, no
    /// p-code and no decompilation, just `structureLoops`,
    /// `calcForwardDominator` and `CollapseStructure` over the graph given.
    ///
    /// This is what makes our own structuring measurable: both algorithms see
    /// the same blocks and the same edges, so a difference in goto count is a
    /// difference in structuring and not in anything upstream of it.
    pub fn structure_graph(
        &mut self,
        provider: &mut ProgramProvider,
        graph: &crate::structure::ControlFlow,
    ) -> Result<crate::structure::StructuredBlock> {
        let arch_id = self.arch_id.to_string();
        let encoded = graph.encode();
        let response =
            self.run_command(provider, "structureGraph", &[arch_id.as_bytes(), &encoded])?;
        crate::structure::decode(&response).ok_or_else(|| {
            WorkerError::Process(format!(
                "structureGraph answered {} bytes this side cannot decode",
                response.len()
            ))
        })
    }

    /// Applies semantic proposals while their native Funcdata is still live.
    /// The returned tokens and SSA are decoded from the same native response.
    pub fn finalize_document(
        &mut self,
        provider: &mut ProgramProvider,
        raw: &[u8],
        space: u32,
        address: u64,
        passes: &[String],
        deadline: Option<std::time::Instant>,
        cancel: Option<&romwright_core::exec::CancelToken>,
    ) -> Result<crate::doc::DecodedDocument> {
        use romwright_core::func_ir::{Pipeline, TransformContext};
        let mut decoded = crate::doc::decode_document_with_ram_space(raw, Some(space as u64));
        // Stored xrefs can be absent on an unanalysed import. Resolve the
        // actual native calls before transforming their arguments, rather
        // than treating the store's current call graph as exhaustive.
        loop {
            if let Some(error) = decoded.semantic_error.take() {
                return Err(WorkerError::Decompiler(error));
            }
            if cancel.is_some_and(romwright_core::exec::CancelToken::is_cancelled) {
                return Err(WorkerError::Process("execution cancelled".into()));
            }
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err(WorkerError::Timeout(0));
            }
            let mut callees = Vec::new();
            if let Some(ir) = &decoded.function_ir {
                use romwright_model::function_ir::{Opcode, Operand};
                for op in ir.blocks.iter().flat_map(|block| &block.operations) {
                    if op.opcode != Opcode::CALL {
                        continue;
                    }
                    let Some(Operand::Value(target)) = op.inputs.first() else {
                        continue;
                    };
                    let Some(callee) = ir.values.get(target).and_then(|value| value.offset) else {
                        continue;
                    };
                    if provider.prototypes.contains_key(&callee)
                        && !self.applied_prototypes.contains_key(&callee)
                    {
                        callees.push(callee);
                    }
                }
            }
            if callees.is_empty() {
                break;
            }
            callees.sort_unstable();
            callees.dedup();
            let mut applied: Vec<_> = self
                .applied_prototypes
                .iter()
                .map(|(&entry, &mode)| (entry, mode))
                .collect();
            applied.sort_unstable_by_key(|&(entry, _)| entry);
            // The native caller already incorporated the old callee facts.
            // Rebuild it, retaining the target's inferred/recovery mode.
            // Each round adds a previously unapplied stored prototype.
            self.flush_native(provider)?;
            for (entry, mode) in applied {
                self.apply_stored_prototype(provider, entry, mode == PrototypeMode::Recovery)?;
            }
            for callee in callees {
                self.apply_stored_prototype(provider, callee, false)?;
            }
            let response = self.decompile_at(provider, space, address)?;
            decoded = crate::doc::decode_document_with_ram_space(&response, Some(space as u64));
        }
        let pipeline = Pipeline::from_names(passes).map_err(WorkerError::Decompiler)?;
        let mut plan = {
            let ir = decoded.function_ir.as_ref().ok_or_else(|| {
                WorkerError::Decompiler("native document has no semantic graph".into())
            })?;
            let context = TransformContext {
                verified_helpers: Some(&provider.verified_helpers),
                deadline,
                cancel,
            };
            pipeline
                .run(ir, &context)
                .map_err(WorkerError::Decompiler)?
        };
        if !plan.edits.is_empty() || !plan.cuts.is_empty() {
            use crate::wire::{
                ELEMENT_END, ELEMENT_START, attr_type, encode_attribute, encode_header,
                encode_string_attribute,
            };
            // Pinned ELEM_DOC/OP/EDGE and their native attributes.
            let mut encoded = Vec::new();
            encode_header(&mut encoded, ELEMENT_START, 229);
            for edit in &plan.edits {
                encode_header(&mut encoded, ELEMENT_START, 27);
                for (attribute, value) in [
                    (16, edit.address.offset),
                    (18, edit.operation.0),
                    (25, edit.constant),
                ] {
                    encode_attribute(&mut encoded, attribute, attr_type::UNSIGNED_INT, value);
                }
                for (attribute, value) in [
                    (78, edit.before as u64),
                    (43, edit.after as u64),
                    (19, edit.width as u64),
                ] {
                    encode_attribute(&mut encoded, attribute, attr_type::POSITIVE_INT, value);
                }
                encode_string_attribute(&mut encoded, 14, edit.helper.as_bytes());
                encode_header(&mut encoded, ELEMENT_END, 27);
            }
            for cut in &plan.cuts {
                encode_header(&mut encoded, ELEMENT_START, 105);
                for (attribute, value) in [
                    (10, cut.source.0),
                    (79, cut.successor_slot as u64),
                    (77, cut.target.0),
                ] {
                    encode_attribute(&mut encoded, attribute, attr_type::POSITIVE_INT, value);
                }
                encode_header(&mut encoded, ELEMENT_END, 105);
            }
            encode_header(&mut encoded, ELEMENT_END, 229);
            let mut location = Vec::new();
            encode_addr_element(&mut location, space, address);
            let arch = self.arch_id.to_string();
            let response = self.run_command(
                provider,
                "renderFunctionIR",
                &[arch.as_bytes(), &location, &encoded],
            )?;
            decoded = crate::doc::decode_document_with_ram_space(&response, Some(space as u64));
            if let Some(error) = decoded.semantic_error.take() {
                return Err(WorkerError::Decompiler(error));
            }
        }
        if decoded.cut_projection.len() != plan.cuts.len() {
            return Err(WorkerError::Decompiler(
                "native projection did not acknowledge every control-flow cut".into(),
            ));
        }
        for (cut, (original, projected)) in plan.cuts.iter_mut().zip(decoded.cut_projection.drain(..)) {
            if *cut != original || original.source != projected.source || original.target != projected.target {
                return Err(WorkerError::Decompiler(
                    "native projection changed a control-flow cut identity".into(),
                ));
            }
            *cut = projected;
        }
        let ir = decoded.function_ir.as_mut().ok_or_else(|| {
            WorkerError::Decompiler("native projection has no semantic graph".into())
        })?;
        let context = TransformContext {
            verified_helpers: Some(&provider.verified_helpers),
            deadline,
            cancel,
        };
        pipeline
            .finish(ir, plan, &context)
            .map_err(WorkerError::Decompiler)?;
        Ok(decoded)
    }

    /// Decompiles one address, killing the decompiler if it does not answer
    /// within `timeout`.
    ///
    /// This is Ghidra's own remedy, not a new policy: `sendCommandTimeout`
    /// (:564-595) arms a timer whose only action is to dispose of the process
    /// (:100-106), and the analyzer that needs it most sets 60 seconds
    /// (`DecompilerSwitchAnalyzer.OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS`;
    /// `DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS` is 30 for a
    /// reader). Without it one function that never converges blocks the whole
    /// batch: a statically linked image took the switch round past fifteen
    /// minutes on one body.
    pub fn decompile_at_within(
        &mut self,
        provider: &mut ProgramProvider,
        space_index: u32,
        offset: u64,
        timeout: Option<std::time::Duration>,
    ) -> Result<Vec<u8>> {
        self.within_deadline(
            timeout.map(|duration| std::time::Instant::now() + duration),
            |worker| worker.decompile_at(provider, space_index, offset),
        )
    }

    /// One absolute deadline covers protocol commands and semantic passes.
    pub fn within_deadline<T>(
        &mut self,
        deadline: Option<std::time::Instant>,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let Some(deadline) = deadline else {
            return operation(self);
        };
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(WorkerError::Timeout(0));
        }
        let handle = self.kill_handle();
        let (answered, wait) = std::sync::mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if wait
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .is_err()
            {
                if let Ok(mut slot) = handle.lock() {
                    if let Some(child) = slot.as_mut() {
                        romwright_core::exec::kill_child(child);
                    }
                }
            }
        });
        let result = operation(self);
        let expired = std::time::Instant::now() >= deadline;
        let _ = answered.send(());
        let _ = watchdog.join();
        if expired {
            Err(WorkerError::Timeout(remaining.as_secs()))
        } else {
            result
        }
    }

    /// Clears the caches the decompiler keeps between functions, as Ghidra's
    /// own client does after every decompile
    /// (`DecompInterface.decompileFunction`:828-834 sends `flushNative`
    /// unconditionally). The comment cache is the load-bearing one: it is
    /// filled once per function and only `clear()` refills it
    /// (`comment_ghidra.hh`: "The cache needs to be cleared between
    /// functions"), so a batch that never flushed gave every function the
    /// first one's comments -- which is none, for the first function that has
    /// none (m4-024).
    pub fn flush_native(&mut self, provider: &mut ProgramProvider) -> Result<()> {
        let arch_id = self.arch_id.to_string();
        let _ = self.run_command(provider, "flushNative", &[arch_id.as_bytes()])?;
        // The flush deletes the scopes the applied signatures live in, so the
        // memo that avoids re-applying them is now a lie: without this, the
        // second function in a batch decompiled `printf` as `void
        // printf(void)` while the first saw the declaration.
        self.applied_prototypes.clear();
        Ok(())
    }

    /// Selects the decompiler action root (Java: `setAction "decompile" ""`),
    /// which also enables C-code printing on the result. Without it the
    /// default action name leaves the raw C out of the response.
    pub fn set_action(
        &mut self,
        provider: &mut ProgramProvider,
        action: &str,
        print: &str,
    ) -> Result<()> {
        let arch_id = self.arch_id.to_string();
        let _ = self.run_command(
            provider,
            "setAction",
            &[arch_id.as_bytes(), action.as_bytes(), print.as_bytes()],
        )?;
        Ok(())
    }

    pub(crate) fn next_burst(&mut self) -> Result<u8> {
        let mut pos = 0usize;
        loop {
            if let Some(code) = decode_burst(&self.out_buf, &mut pos) {
                self.out_buf.drain(..pos);
                return Ok(code);
            }
            pos = 0;
            let mut chunk = [0u8; 4096];
            let n = self.stdout.read(&mut chunk).map_err(WorkerError::Io)?;
            if n == 0 {
                return Err(WorkerError::Process("decompiler died".into()));
            }
            if let Ok(log) = std::env::var("WORKER_LOG") {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                    .unwrap();
                use std::io::Write as _;
                let _ = writeln!(
                    f,
                    "<-- {}",
                    chunk[..n]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
            }
            self.out_buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub(crate) fn expect_burst(&mut self, want: u8) -> Result<()> {
        let got = self.next_burst()?;
        if got != want {
            return Err(WorkerError::Protocol(format!(
                "expected burst 0x{want:x}, got 0x{got:x}"
            )));
        }
        Ok(())
    }

    /// Reads the payload of a string stream whose 0x0e open burst was
    /// already consumed, up to the close burst (0x0f), answering any
    /// query the decompiler interleaves mid-stream. This mirrors the Java
    /// readResponse loop: the C++ encodes the result via packed element
    /// writes that themselves trigger client queries (e.g. namespaces),
    /// which arrive as 0x04 frames between result bytes.
    pub(crate) fn read_string_payload(
        &mut self,
        provider: &mut ProgramProvider,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let byte = self.raw_byte()?;
            if byte == 0 {
                // Structural burst: skip NULs, expect 0x01 then a code.
                let code = loop {
                    let b = self.raw_byte()?;
                    if b == 0 {
                        continue;
                    }
                    if b != 1 {
                        return Err(WorkerError::Protocol(format!(
                            "malformed burst under payload (got 0x{b:x})"
                        )));
                    }
                    break self.raw_byte()?;
                };
                match code {
                    burst::STRINGSTREAM_CLOSE => return Ok(out),
                    burst::QUERY_OPEN => {
                        // Queries inside the result stream are answered and
                        // the ingest continues (Java readResponse, same).
                        self.answer_query(provider)?;
                    }
                    other => {
                        let tail: Vec<String> = out
                            .iter()
                            .rev()
                            .take(24)
                            .rev()
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        return Err(WorkerError::Protocol(format!(
                            "unexpected burst 0x{other:x} in payload (tail: {})",
                            tail.join("")
                        )));
                    }
                }
            } else {
                out.push(byte);
            }
        }
    }

    /// Reads one raw byte from the child's stdout, blocking until data.
    pub(crate) fn raw_byte(&mut self) -> Result<u8> {
        loop {
            if let Some(b) = self.out_buf.first().copied() {
                self.out_buf.drain(..1);
                return Ok(b);
            }
            let mut chunk = [0u8; 4096];
            let n = self.stdout.read(&mut chunk).map_err(WorkerError::Io)?;
            if n == 0 {
                return Err(WorkerError::Process("decompiler died".into()));
            }
            if let Ok(log) = std::env::var("WORKER_LOG") {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                    .unwrap();
                use std::io::Write as _;
                let _ = writeln!(
                    f,
                    "<-- {}",
                    chunk[..n]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
            }
            self.out_buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub(crate) fn read_string_stream(&mut self) -> Result<Vec<u8>> {
        self.expect_burst(burst::STRINGSTREAM_OPEN)?;
        // Query answers need the provider for interleaved queries; the
        // plain read_string_stream is only used by answer paths, where the
        // payload is the query's own data (no nested queries to expect).
        self.read_payload_plain()
    }

    /// Payload read without provider support (query payloads).
    pub(crate) fn read_payload_plain(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let byte = self.raw_byte()?;
            if byte == 0 {
                let code = loop {
                    let b = self.raw_byte()?;
                    if b == 0 {
                        continue;
                    }
                    if b != 1 {
                        return Err(WorkerError::Protocol(format!(
                            "malformed burst under payload (got 0x{b:x})"
                        )));
                    }
                    break self.raw_byte()?;
                };
                if code == burst::STRINGSTREAM_CLOSE {
                    return Ok(out);
                }
                return Err(WorkerError::Protocol(format!(
                    "unexpected burst 0x{code:x} in plain payload"
                )));
            }
            out.push(byte);
        }
    }

    /// Reads raw payload bytes until a burst with the given code. Used for
    /// the warnings frame (ghidra_process.cc:146-148) which carries the
    /// text unwrapped between the 0x10 and 0x11 markers.
    pub(crate) fn read_until(&mut self, code: u8) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let got = self.next_burst()?;
            if got == code {
                return Ok(out);
            }
            out.push(got);
        }
    }
}

impl Drop for NativeWorker {
    fn drop(&mut self) {
        // A failed or wedged child may ignore EOF. It owns no durable state;
        // terminate and reap it rather than letting teardown block indefinitely.
        drop(self.stdin.take());
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                romwright_core::exec::kill_child(&mut child);
                let _ = child.wait();
            }
        }
    }
}

impl NativeWorker {
    /// A handle a watchdog can use to kill the child from another thread
    /// (deadline semantics).
    pub fn kill_handle(&self) -> std::sync::Arc<std::sync::Mutex<Option<Child>>> {
        self.child.clone()
    }

    /// Kills the child immediately (used when a deadline was exceeded).
    pub fn kill(&mut self) -> Result<()> {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut c) = guard.take() {
                romwright_core::exec::kill_child(&mut c);
                let _ = c.wait();
            }
        }
        Ok(())
    }

    /// The child's process id, when alive (diagnostics/tests).
    pub fn pid(&self) -> Option<u32> {
        self.child
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.id()))
    }
}

/// Verifies the pinned build is present; called before launch.
pub fn check_setup(ghidra_opt: &Path, sla_path: &Path) -> Result<()> {
    for p in [ghidra_opt, sla_path] {
        if !p.is_file() {
            return Err(WorkerError::Setup(format!("missing: {}", p.display())));
        }
    }
    Ok(())
}

/// Loads the four spec documents from a language directory laid out like
/// the spike tree (pspec, cspec, sleigh tspec, coretypes).
pub fn load_specs(lang_dir: &Path) -> Result<(String, String, String, String)> {
    let read = |name: &str| -> Result<String> {
        std::fs::read_to_string(lang_dir.join(name))
            .map_err(|e| WorkerError::Setup(format!("{name}: {e}")))
    };
    Ok((
        read("pspec.xml")?,
        read("cspec.xml")?,
        read("tspec.xml")?,
        read("coretypes.xml")?,
    ))
}

/// Opens (or creates) the store the callbacks will read facts from.
pub fn open_store(project_dir: &Path) -> Result<ProjectDb> {
    Ok(ProjectDb::open(&project_dir.join("project.sqlite"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_setup_rejects_missing_binary() {
        let err = check_setup(Path::new("/nonexistent/ghidra_opt"), Path::new("/tmp")).unwrap_err();
        assert!(matches!(err, WorkerError::Setup(_)));
    }
}
