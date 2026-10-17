//! romwright-core: the CoreService facade.
//!
//! The core owns durable state (romwright-db) and orchestrates the bridge. Every
//! imported fact is exported into the project database with provenance, so
//! reopening and browsing never needs the JVM (spec 14.4, Phase 3 exit).

pub mod cfg_functions;
pub mod demand;
pub mod export;
pub mod new_project;
pub mod matching;
pub mod match_search;
pub mod import_cache;
pub mod artifact;
pub mod exec;
pub mod inputs;
pub mod func_ir;
pub(crate) mod sha256;
pub mod gte;
pub mod library_types;
pub mod demangle;
pub mod bridge;
pub mod compiler;
pub mod architecture;
pub mod disasm;
pub mod ir;
pub mod graph;
pub mod sigscan;
pub mod listing;
pub mod native;
pub mod opinion;
pub mod native_runtime;
pub mod rsp;
pub mod session;
pub mod structuring;
pub mod speclint;
pub mod vu;
pub mod facts;
pub mod subtype;
pub mod struct_types;
mod struct_pass;
pub mod types_infer;
mod prototypes;
pub mod qualified_prototypes;
pub mod register_params;
mod nonreturn;
mod evidence;
mod signatures;
pub mod rtti;
pub mod sdk_types;
pub mod cross_module;
pub mod emit_m2c;
pub mod fact_sync;
pub mod fact_pack;
pub mod gbi;
pub mod gekko;
pub mod rsp_parity;
pub mod vif;
pub use nonreturn::NonReturnInferenceReport;

use romwright_db::ProjectDb;
use romwright_model::{
    Address, AddressSpace, ArchitectureSpec, BookmarkRow, CollaborationOp, CommentRow, DataTypeRow,
    DecompDoc, DisasmRow, FunctionRow, GraphEdge, GraphNode, MemoryRegion, PatchRow, ProgramId,
    ProgramSummary, PrototypeRow, SearchHit, StackVariableRow, StringRow, SymbolRow, TraceEvent,
    TypeDefRow, TypeFieldRow, TypeGraphNode, TypeLinkRow, XrefRow,
};
use std::path::{Path, PathBuf};

#[derive(Debug, serde::Deserialize)]
struct CollaborationRename {
    address: Address,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct CollaborationComment {
    address: Address,
    #[serde(default)]
    function: Option<Address>,
    kind: String,
    text: String,
}

fn decode_collaboration<T: serde::de::DeserializeOwned>(
    op_id: &str,
    payload: &str,
) -> Result<T> {
    serde_json::from_str(payload).map_err(|error| {
        CoreError::Collaboration(format!("operation {op_id} has invalid payload: {error}"))
    })
}

/// Core facade failure: wraps the layer that actually failed.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Database layer failure.
    #[error("db: {0}")]
    Db(#[from] romwright_db::DbError),
    /// Bridge layer failure.
    #[error("bridge: {0}")]
    Bridge(#[from] bridge::BridgeError),
    /// Live-memory debugger transport failure.
    #[error("debug: {0}")]
    Debug(#[from] romwright_debug::DebugError),
    /// Filesystem or environment problem outside db/bridge.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Native runtime (console, worker) or setup failure.
    #[error("native runtime: {0}")]
    NativeRuntime(#[from] native_runtime::NativeRuntimeError),
    /// Native import/parse failure.
    #[error("native: {0}")]
    Native(#[from] native::ImportError),
    /// Collaboration payload or operation application failure.
    #[error("collaboration: {0}")]
    Collaboration(String),
    /// Installed-architecture catalog failure.
    #[error("architecture: {0}")]
    Architecture(#[from] architecture::ArchitectureError),
    /// Function sort key was not one of entry|name|size[:asc|:desc].
    #[error("invalid sort key: {0}")]
    InvalidSortKey(String),
    #[error("invalid recovered prototype: {0}")]
    InvalidPrototype(String),
}

/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = CoreError> = std::result::Result<T, E>;

struct LiveMemoryConnection {
    endpoint: String,
    client: romwright_debug::DolphinGdb,
}

/// The Core API: one authoritative semantic surface (spec 8.1).
///
/// A GUI would call this in-process; the CLI does exactly that; the bridge is
/// an implementation detail behind `import_program`/`refresh_from_bridge`.
pub struct Core {
    db: ProjectDb,
    db_path: PathBuf,
    /// Shared viewport snapshot; independent request connections reuse it.
    native_cache: std::sync::Arc<std::sync::Mutex<Option<(PathBuf, std::sync::Arc<session::ProgramImage>)>>>,
    /// Reusable read-only Dolphin GDB connection for live-memory overlays.
    live_memory: std::sync::Arc<std::sync::Mutex<Option<LiveMemoryConnection>>>,
    /// Immutable runtime configuration (env-derived by default).
    config: session::RuntimeConfig,
    /// Images kept parsed and loaded in a console between requests, so
    /// demand-driven analysis costs a walk and not a reload.
    live: std::sync::Arc<demand::LiveImages>,
}

/// A diff failure, as a Core error: the reference project is an input like
/// any other, and a bad one is not an internal fault.
fn diff_error(error: romwright_diff::DiffError) -> CoreError {
    CoreError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        error.to_string(),
    ))
}

impl Core {
    /// Opens (or creates) a project at `project_dir` holding `project.sqlite`.
    pub fn open(project_dir: &Path) -> Result<Self> {
        Self::open_with_config(project_dir, session::RuntimeConfig::from_env())
    }

    /// Opens (or creates) a project with an explicit runtime configuration.
    pub fn open_with_config(project_dir: &Path, config: session::RuntimeConfig) -> Result<Self> {
        std::fs::create_dir_all(project_dir)?;
        let db = ProjectDb::open(&project_dir.join("project.sqlite"))?;
        Ok(Self {
            db,
            db_path: project_dir.to_path_buf(),
            native_cache: std::sync::Arc::new(std::sync::Mutex::new(None)),
            live_memory: std::sync::Arc::new(std::sync::Mutex::new(None)),
            live: std::sync::Arc::new(demand::LiveImages::new(project_dir, &config)),
            config,
        })
    }

    /// Opens an independent store connection without discarding warm runtime
    /// state. Long requests own this handle, not the service's Core mutex.
    pub fn fork(&self) -> Result<Self> {
        Ok(Self {
            db: ProjectDb::open(&self.db_path.join("project.sqlite"))?,
            db_path: self.db_path.clone(),
            native_cache: self.native_cache.clone(),
            live_memory: self.live_memory.clone(),
            config: self.config.clone(),
            live: self.live.clone(),
        })
    }

    /// Project directory containing the backing database (diagnostics).
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
    /// Runtime configuration used by native consumers such as the supervised
    /// worker pool. The configuration remains owned by Core.
    pub fn runtime_config(&self) -> &session::RuntimeConfig {
        &self.config
    }
    /// Lists language variants available in the configured Ghidra install.
    pub fn architectures(&self) -> Result<Vec<ArchitectureSpec>> {
        Ok(architecture::discover(&self.config.ghidra_install)?)
    }

    /// Imports a binary through the bridge, exports facts into the project
    /// store, and returns the normalized summary. `name` stores the program
    /// under a caller-chosen name; without one the loader's name is kept.
    pub fn import_program(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        binary: &Path,
        name: Option<&str>,
    ) -> Result<ProgramSummary> {
        self.import_program_as(bridge, session, binary, name, None, None)
    }

    /// Imports with an explicit language/compiler pair, overriding Ghidra's
    /// opinion (e.g. `PowerPC:BE:64:default` for a PS3 PPE image).
    pub fn import_program_as(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        binary: &Path,
        name: Option<&str>,
        language: Option<&str>,
        compiler: Option<&str>,
    ) -> Result<ProgramSummary> {
        let mut summary = bridge.import_as(session, binary, language, compiler)?;
        if let Some(name) = name {
            summary.program = name.to_string();
        }
        let id = self.db.upsert_program(
            &summary.program,
            &summary.language,
            &bridge.provenance,
        )?;
        let functions = bridge.functions(session)?;
        let symbols = bridge.symbols(session)?;
        self.db.replace_symbols(id, &symbols)?;
        self.export(bridge, session, id, &functions)?;
        Ok(summary)
    }

    /// Reopens an already-imported program. Reads come from the project store;
    /// the bridge starts only if the caller explicitly asks for a refresh.
    pub fn open_program(&self, program: &str) -> Result<ProgramSummary> {
        let id = self.db.program_id(program)?;
        let functions = self.db.functions(id)?;
        Ok(ProgramSummary {
            program: program.to_string(),
            functions: functions.len() as u64,
            language: self.db.program_language(id)?,
            compiler: self.db.program_compiler(id).unwrap_or_default(),
            phases: Vec::new(),
            flow: None,
            patterns: None,
            references_refused: 0,
            diagnostics: self.db.import_diagnostics(id)?,
            switch: None,
        })
    }

    /// Borrows the project store (native-import persistence path).
    pub fn store_handle(&self) -> Result<&ProjectDb> {
        Ok(&self.db)
    }

    /// Lists functions from the project store (no JVM).
    pub fn functions(&self, program: &str) -> Result<Vec<FunctionRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.functions(id)?)
    }
    /// Returns the stored function containing a RAM address.
    pub fn function_at(&self, program: &str, offset: u64) -> Result<Option<FunctionRow>> {
        Ok(self.db.function_at(self.db.program_id(program)?, offset)?)
    }
    /// One listing window (CORE-007): in-process SLEIGH rows, bounded +
    /// overscan, stable ids. Instruction bytes come from the listing's
    /// `Bytes` lines, sized by the program's own SLEIGH decoder.
    pub fn listing_window(
        &self,
        binary: &std::path::Path,
        start: &romwright_model::Address,
        count: u32,
        overscan_fraction: f32,
    ) -> Result<romwright_model::ListingWindow> {
        let source = listing::SleighListingSource::new(self.config.clone(), binary);
        Ok(listing::window(&source, start, count, overscan_fraction)?)
    }


    /// Byte-pattern signature search over all mappings (Phase 4).
    pub fn search_bytes(
        &self,
        binary: &std::path::Path,
        pattern: &str,
        limit: u64,
    ) -> Result<Vec<romwright_model::SearchHit>> {
        let imp = native::load_native(binary)?;
        let parsed = sigscan::parse_pattern(pattern)
            .ok_or_else(|| CoreError::Collaboration(format!("bad pattern: {pattern}")))?;
        let hits = sigscan::search_bytes(&imp.mappings, &parsed, limit as usize);
        Ok(hits
            .into_iter()
            .map(|hit| romwright_model::SearchHit {
                address: Some(romwright_model::Address::ram(hit.address)),
                kind: "bytes".into(),
                name: pattern.to_string(),
                context: String::new(),
            })
            .collect())
    }

    /// Vtable recovery over data mappings (Phase 4): runs of pointers into
    /// executable ranges. Pointer size and endianness follow the import.
    pub fn recover_vtables(
        &self,
        binary: &std::path::Path,
        limit: u64,
    ) -> Result<Vec<serde_json::Value>> {
        let imp = native::load_native(binary)?;
        let big_endian = !imp.language.contains(":LE:");
        let pointer_size = if imp.language.contains(":64:") { 8 } else { 4 };
        let code_ranges: Vec<(u64, u64)> = imp
            .mappings
            .iter()
            .filter(|m| m.flags & 0x4 != 0)
            .map(|m| (m.vaddr, m.vaddr + m.size))
            .collect();
        let vtables = sigscan::recover_vtables(
            &imp.mappings,
            &code_ranges,
            pointer_size,
            big_endian,
            3,
            limit as usize,
        );
        Ok(vtables
            .into_iter()
            .map(|v| {
                serde_json::json!({
                    "address": format!("{:x}", v.address),
                    "targets": v.targets.iter().map(|t| format!("{t:x}")).collect::<Vec<_>>(),
                })
            })
            .collect())
    }

    /// Complete native function CFG, keyed by block identity and laid out for
    /// every frontend. Missing native IR is an error, never a bounded fallback.
    pub fn function_bb_graph(
        &self,
        program: &str,
        binary: &std::path::Path,
        address: &str,
    ) -> Result<serde_json::Value> {
        let hex = address.trim_start_matches("0x");
        let offset = u64::from_str_radix(hex, 16)
            .map_err(|_| CoreError::Collaboration(format!("bad address: {address}")))?;
        let doc = self.decompile_native_doc(
            binary, &Address { space: AddressSpace::Ram, offset }, program, None,
        )?;
        let ir = doc.function_ir.as_ref().ok_or_else(|| {
            CoreError::Collaboration("native function CFG is unavailable".into())
        })?;
        Ok(graph::native_graph(ir))
    }

    /// Revision events after `since` for the program (CORE-005).
    pub fn events_since(&self, program: &str, since: u64) -> Result<Vec<romwright_model::RevisionEvent>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.events_since(id, since)?)
    }

    /// Reads a bounded execution/analysis timeline window.
    pub fn trace_events(
        &self,
        program: &str,
        since: u64,
        limit: u64,
    ) -> Result<Vec<TraceEvent>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.trace_events(id, since, limit)?)
    }

    /// Appends a timeline event and returns its assigned sequence.
    pub fn append_trace_event(&self, program: &str, row: &TraceEvent) -> Result<TraceEvent> {
        let id = self.db.program_id(program)?;
        Ok(self.db.append_trace_event(id, row)?)
    }

    /// Lists collaboration operations in deterministic merge order.
    pub fn collaboration_ops(&self, program: &str) -> Result<Vec<CollaborationOp>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.collaboration_ops(id)?)
    }

    /// Adds one idempotent collaboration operation.
    pub fn append_collaboration_op(
        &self,
        program: &str,
        row: &CollaborationOp,
    ) -> Result<bool> {
        let id = self.db.program_id(program)?;
        Ok(self.db.append_collaboration_op(id, row)?)
    }

    /// Applies a collaboration operation once. Known fact mutations are
    /// decoded and routed through the same Core command/type APIs; note
    /// operations remain durable log entries without changing facts.
    pub fn apply_collaboration_op(&self, program: &str, op_id: &str) -> Result<bool> {
        let id = self.db.program_id(program)?;
        let operation = self
            .db
            .collaboration_ops(id)?
            .into_iter()
            .find(|operation| operation.op_id == op_id)
            .ok_or_else(|| romwright_db::DbError::OperationNotFound(op_id.into()))?;
        if operation.applied {
            return Ok(false);
        }
        match operation.kind.as_str() {
            "rename" => {
                let payload: CollaborationRename =
                    decode_collaboration(op_id, &operation.payload)?;
                self.rename_command(program, &payload.address, &payload.name)?;
            }
            "comment" => {
                let payload: CollaborationComment =
                    decode_collaboration(op_id, &operation.payload)?;
                let function = payload.function.unwrap_or_else(|| payload.address.clone());
                self.comment_command(
                    program,
                    &payload.address,
                    &function,
                    &payload.kind,
                    &payload.text,
                )?;
            }
            "bookmark" => {
                let payload: BookmarkRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_bookmark(program, &payload)?;
            }
            "patch" => {
                let payload: PatchRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_patch(program, &payload)?;
            }
            "set_type_def" => {
                let payload: TypeDefRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_type_def(program, &payload)?;
            }
            "set_type_field" => {
                let payload: TypeFieldRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_type_field(program, &payload)?;
            }
            "set_prototype" => {
                let payload: PrototypeRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_prototype(program, &payload)?;
            }
            "set_stack_variable" => {
                let payload: StackVariableRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_stack_variable(program, &payload)?;
            }
            "set_type_link" => {
                let payload: TypeLinkRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_type_link(program, &payload)?;
            }
            "note" | "trace" => {}
            other => {
                return Err(CoreError::Collaboration(format!(
                    "operation {op_id} has unsupported kind {other:?}"
                )));
            }
        }
        Ok(self.db.apply_collaboration_op(id, op_id)?)
    }

    /// Paged functions (review CORE-004): bounded window + total + revision.
    /// `filter` is a case-insensitive name substring, or a regex when it
    /// carries a `re:` prefix. `sort` is "entry" | "name" | "size" with an
    /// optional ":asc"/":desc" suffix; defaults to entry ascending.
    pub fn functions_page(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
        filter: Option<&str>,
        sort: Option<&str>,
        address: Option<u64>,
    ) -> Result<romwright_model::Page<FunctionRow>> {
        let id = self.db.program_id(program)?;
        let filter = romwright_db::FunctionsFilter::parse(filter.unwrap_or(""))?;
        let sort = sort.map(parse_function_sort).transpose()?;
        let (rows, total, revision, offset) =
            self.db.functions_page(id, offset, limit, filter.as_ref(), sort, address)?;
        Ok(romwright_model::Page { rows, offset, total, revision })
    }

    /// Paged symbols (review CORE-004).
    pub fn symbols_page(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
        evidence: Option<romwright_model::provenance::EvidenceKind>,
    ) -> Result<romwright_model::Page<SymbolRow>> {
        let id = self.db.program_id(program)?;
        let (rows, total, revision) = self.db.symbols_page(id, offset, limit, evidence)?;
        Ok(romwright_model::Page { rows, offset, total, revision })
    }

    /// Paged xrefs in one direction (review CORE-004).
    pub fn xrefs_page(
        &self,
        program: &str,
        address: &romwright_model::Address,
        incoming: bool,
        offset: u64,
        limit: u64,
        evidence: Option<romwright_model::provenance::EvidenceKind>,
    ) -> Result<romwright_model::Page<XrefRow>> {
        let id = self.db.program_id(program)?;
        let (rows, total, revision) =
            self.db.xrefs_page(id, address, incoming, offset, limit, evidence)?;
        Ok(romwright_model::Page { rows, offset, total, revision })
    }

    /// Every program this project holds (no JVM).
    pub fn programs(&self) -> Result<Vec<romwright_model::ProgramRow>> {
        Ok(self.db.programs()?)
    }

    /// Every program mapping `address`, with the region and the containing
    /// function. Images overlap, so this answers with a list.
    pub fn locate(&self, address: &romwright_model::Address) -> Result<Vec<romwright_model::LocationRow>> {
        Ok(self.db.locate(address)?)
    }

    /// Lists comments from the project store (no JVM).
    pub fn comments(&self, program: &str) -> Result<Vec<CommentRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.comments(id)?)
    }

    /// Lists datatypes from the project store (no JVM).
    pub fn datatypes(&self, program: &str) -> Result<Vec<DataTypeRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.datatypes(id)?)
    }

    /// Lists symbols from the project store (no JVM).
    pub fn symbols(&self, program: &str) -> Result<Vec<SymbolRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.symbols(id)?)
    }

    /// Lists data definitions (typed data extents) from the store.
    pub fn data_definitions(
        &self,
        program: &str,
    ) -> Result<Vec<romwright_model::DataDefinitionRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.data_definitions(id)?)
    }

    /// Lists discovered strings from the durable project store.
    /// Paged strings (Phase 2.3).
    pub fn strings_page(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
    ) -> Result<romwright_model::Page<StringRow>> {
        let id = self.db.program_id(program)?;
        let (rows, total, revision) = self.db.strings_page(id, offset, limit)?;
        Ok(romwright_model::Page { rows, offset, total, revision })
    }

    pub fn strings(&self, program: &str) -> Result<Vec<StringRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.strings(id)?)
    }

    /// Searches durable analysis facts without loading the native image.
    pub fn search(&self, program: &str, term: &str, limit: u64) -> Result<Vec<SearchHit>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.search(id, term, limit)?)
    }

    /// Returns function vertices and reference edges for graph rendering.
    pub fn function_graph(&self, program: &str) -> Result<(Vec<GraphNode>, Vec<GraphEdge>)> {
        let id = self.db.program_id(program)?;
        Ok(self.db.function_graph(id)?)
    }

    /// Lists persisted memory mappings (no JVM, no worker).
    pub fn memory_regions(&self, program: &str) -> Result<Vec<MemoryRegion>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.memory_regions(id)?)
    }

    /// Lists analyst bookmarks.
    pub fn bookmarks(&self, program: &str) -> Result<Vec<BookmarkRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.bookmarks(id)?)
    }

    /// Sets one analyst bookmark.
    pub fn set_bookmark(&self, program: &str, row: &BookmarkRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_bookmark(id, row)?;
        Ok(())
    }

    /// Removes one analyst bookmark.
    pub fn delete_bookmark(&self, program: &str, address: &Address) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.delete_bookmark(id, address)?;
        Ok(())
    }

    /// Lists analyst byte patches.
    pub fn patches(&self, program: &str) -> Result<Vec<PatchRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.patches(id)?)
    }

    /// Stores one analyst byte patch.
    pub fn set_patch(&self, program: &str, row: &PatchRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_patch(id, row)?;
        Ok(())
    }

    /// Removes one analyst byte patch.
    pub fn delete_patch(&self, program: &str, address: &Address) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.delete_patch(id, address)?;
        Ok(())
    }
    /// Lists rich named types and their composite metadata.
    pub fn type_defs(&self, program: &str) -> Result<Vec<TypeDefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.type_defs(id)?)
    }
    /// Replaces the project's rich type definitions.
    pub fn replace_type_defs(&self, program: &str, rows: &[TypeDefRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_type_defs(id, rows)?;
        Ok(())
    }
    /// Upserts one type definition.
    pub fn set_type_def(&self, program: &str, row: &TypeDefRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_type_def(id, row)?;
        Ok(())
    }


    /// Replaces the project's composite type fields.
    pub fn replace_type_fields(&self, program: &str, rows: &[TypeFieldRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_type_fields(id, rows)?;
        Ok(())
    }
    /// Upserts one composite field.
    pub fn set_type_field(&self, program: &str, row: &TypeFieldRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_type_field(id, row)?;
        Ok(())
    }


    /// Lists fields, optionally restricted to one type.
    pub fn type_fields(
        &self,
        program: &str,
        type_name: Option<&str>,
    ) -> Result<Vec<TypeFieldRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.type_fields(id, type_name)?)
    }

    /// Lists function prototypes.
    pub fn prototypes(&self, program: &str) -> Result<Vec<PrototypeRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.prototypes(id)?)
    }
    /// Replaces function prototypes.
    pub fn replace_prototypes(&self, program: &str, rows: &[PrototypeRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_prototypes(id, rows)?;
        Ok(())
    }
    /// Upserts one function prototype.
    pub fn set_prototype(&self, program: &str, row: &PrototypeRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_prototype(id, row)?;
        Ok(())
    }


    /// Replaces recovered stack variables.
    pub fn replace_stack_variables(
        &self,
        program: &str,
        rows: &[StackVariableRow],
    ) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_stack_variables(id, rows)?;
        Ok(())
    }
    /// Upserts one stack variable.
    pub fn set_stack_variable(&self, program: &str, row: &StackVariableRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_stack_variable(id, row)?;
        Ok(())
    }


    /// Replaces type dependency links.
    pub fn replace_type_links(&self, program: &str, rows: &[TypeLinkRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_type_links(id, rows)?;
        Ok(())
    }
    /// Upserts one type dependency link.
    pub fn set_type_link(&self, program: &str, row: &TypeLinkRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_type_link(id, row)?;
        Ok(())
    }


    /// Lists recovered stack variables, optionally for one function.
    pub fn stack_variables(
        &self,
        program: &str,
        function: Option<&Address>,
    ) -> Result<Vec<StackVariableRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.stack_variables(id, function)?)
    }

    /// Lists type nodes and provenance-bearing dependency edges.
    pub fn type_graph(
        &self,
        program: &str,
    ) -> Result<(Vec<TypeGraphNode>, Vec<TypeLinkRow>)> {
        let id = self.db.program_id(program)?;
        Ok(self.db.type_graph(id)?)
    }

    /// Returns the durable type-link set after transitive propagation.
    ///
    /// Propagated edges are explicitly marked, so consumers can distinguish
    /// provider evidence from an inferred relationship.
    pub fn propagate_type_links(&self, program: &str) -> Result<Vec<TypeLinkRow>> {
        let id = self.db.program_id(program)?;
        let mut links = self.db.type_links(id)?;
        let mut changed = true;
        while changed {
            changed = false;
            let snapshot = links.clone();
            for left in &snapshot {
                for right in &snapshot {
                    if left.target != right.source || left.source == right.target {
                        continue;
                    }
                    let candidate = TypeLinkRow {
                        source: left.source.clone(),
                        target: right.target.clone(),
                        kind: "transitive".into(),
                        provenance: "type-propagation".into(),
                    };
                    if !links.contains(&candidate) {
                        links.push(candidate);
                        changed = true;
                    }
                }
            }
        }
        if links.len() != self.db.type_links(id)?.len() {
            self.db.replace_type_links(id, &links)?;
        }
        Ok(links)
    }


    /// Lists all xrefs from the project store (no JVM).
    pub fn xrefs(&self, program: &str) -> Result<Vec<XrefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.xrefs(id)?)
    }

    /// Incoming xrefs from the project store (no JVM).
    pub fn xrefs_to(&self, program: &str, address: &romwright_model::Address) -> Result<Vec<XrefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.xrefs_to(id, address)?)
    }

    /// Outgoing xrefs from the project store (no JVM).
    pub fn xrefs_from(&self, program: &str, address: &romwright_model::Address) -> Result<Vec<XrefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.xrefs_from(id, address)?)
    }

    /// CORE API: matches `target` in this project against a program in
    /// another project and reports the correspondence.
    ///
    /// The reference project is opened read-only; nothing in it changes. With
    /// `apply`, the names the reference holds are written onto the matched
    /// target functions as one undoable command, so porting a decompilation's
    /// names onto a stripped image is a single analyst decision.
    pub fn diff_program(
        &self,
        target: &str,
        reference_project: &Path,
        reference: Option<&str>,
        options: &romwright_diff::Options,
        apply: bool,
    ) -> Result<romwright_diff::DiffReport> {
        let path = if reference_project.is_file() {
            reference_project.to_path_buf()
        } else {
            reference_project.join("project.sqlite")
        };
        let other = ProjectDb::open(&path)?;
        let reference_name = match reference {
            Some(name) => name.to_string(),
            None => romwright_diff::Program::only_program(&other).map_err(diff_error)?,
        };
        // The semantic class reads stored signatures; a side without them
        // silently loses the only content term that carries identity across
        // a compiler change. The target is indexed from its own captured
        // input; the reference project is read-only, so it is named instead.
        let mut warnings = Vec::new();
        if options.semantic {
            let id = self.db.program_id(target)?;
            if !self.db.has_semantic_signatures(id)? {
                match self
                    .program_input(target)
                    .and_then(|input| self.index_semantics_from(input, target))
                {
                    Ok(indexed) => warnings.push(format!(
                        "indexed {indexed} semantic signatures for {target}, which had none"
                    )),
                    Err(error) => warnings.push(format!(
                        "{target} has no semantic signatures and could not be indexed ({error}); \
                         it is matched without them"
                    )),
                }
            }
            if !other.has_semantic_signatures(other.program_id(&reference_name)?)? {
                warnings.push(format!(
                    "{reference_name} has no semantic signatures and is matched without them; \
                     run `romwright-cli index-semantics <binary> {reference_name} --project {}`",
                    reference_project.display()
                ));
            }
        }
        let left = romwright_diff::Program::load(&other, &reference_name).map_err(diff_error)?;
        let right = romwright_diff::Program::load(&self.db, target).map_err(diff_error)?;
        let mut report = romwright_diff::diff(&left, &right, options);
        report.warnings = warnings;
        if apply && !report.names.is_empty() {
            let id = self.db.program_id(target)?;
            let renames: Vec<(romwright_model::Address, String)> = report
                .names
                .iter()
                .map(|row| (row.entry.clone(), row.name.clone()))
                .collect();
            self.db.rename_batch_command(
                id,
                &renames,
                &format!("diff {reference_name} -> {target}"),
            )?;
        }
        Ok(report)
    }

    /// Indexes BSim-style semantic signatures for every function of
    /// `program`: each body is walked on a warm image of `binary`, its
    /// p-code hashed into a data-flow signature, and one row per decoded
    /// function stored for the diff to match on.
    ///
    /// The binary is needed because p-code comes from a loaded console,
    /// which the store does not keep. A function the walk cannot decode
    /// gets no row -- absence of evidence, never evidence of difference.
    /// Replaces whatever the last pass wrote, so re-indexing after an
    /// edit cannot leave stale signatures beside fresh ones.
    pub fn index_semantics(&self, binary: &Path, program: &str) -> Result<usize> {
        self.index_semantics_from(self.resolve_program_input(binary, program)?, program)
    }

    /// `index_semantics` over the input the program was imported from.
    fn index_semantics_from(&self, input: romwright_model::ProgramInput, program: &str) -> Result<usize> {
        let id = self.db.program_id(program)?;
        let entries: Vec<romwright_model::Address> =
            self.db.functions(id)?.into_iter().map(|row| row.entry).collect();
        let mapped: Vec<(u64, u64)> = self
            .db
            .memory_regions(id)?
            .into_iter()
            .map(|region| (region.start.offset, region.start.offset.saturating_add(region.size)))
            .collect();
        let mut rows: Vec<romwright_model::SemanticSignatureRow> = Vec::new();
        self.live.with(&input, program, None, |live| {
            for entry in &entries {
                let walk = live.walk(entry.offset)?;
                if walk.instructions == 0 {
                    continue;
                }
                let mut addresses: Vec<u64> = walk
                    .instruction_extents
                    .iter()
                    .map(|(address, _)| *address)
                    .collect();
                addresses.sort_unstable();
                addresses.dedup();
                let pcode = live.pcode(&addresses)?;
                let ops: Vec<romwright_diff::semantic::SemOp> = pcode
                    .iter()
                    .flat_map(|instruction| instruction.ops.iter())
                    .map(|op| romwright_diff::semantic::SemOp {
                        opcode: op.opcode.clone(),
                        output: op.output.as_ref().map(|varnode| {
                            romwright_diff::semantic::SemVar {
                                space: varnode.space.clone(),
                                offset: varnode.offset,
                                size: varnode.size,
                            }
                        }),
                        inputs: op
                            .inputs
                            .iter()
                            .map(|varnode| romwright_diff::semantic::SemVar {
                                space: varnode.space.clone(),
                                offset: varnode.offset,
                                size: varnode.size,
                            })
                            .collect(),
                    })
                    .collect();
                if ops.is_empty() {
                    continue;
                }
                let signature = romwright_diff::semantic::signature(&ops);
                rows.push(romwright_model::SemanticSignatureRow {
                    function: entry.clone(),
                    signature: signature.to_hex(),
                    ops: ops.len() as u32,
                    constants: romwright_diff::semantic::constants(&ops, &mapped),
                });
            }
            Ok(())
        })?;
        let indexed = rows.len();
        self.db.replace_semantic_signatures(id, &rows)?;
        Ok(indexed)
    }

    /// Analyses one function on demand and commits its facts.
    ///
    /// A loader-only import leaves every declared entry as a seed: a name
    /// and an address with no proven body. This walks exactly one of them
    /// on a warm image, records the body size, the references inside it,
    /// and the direct call targets it reaches, and marks the row `walked`
    /// at the revision it was analysed. A function already walked at the
    /// current revision is returned unchanged rather than re-walked.
    pub fn analyse_function(
        &self,
        binary: &Path,
        program: &str,
        entry: &romwright_model::Address,
    ) -> Result<demand::FunctionAnalysis> {
        let request = self.execution_request(binary, program, None, exec::DEFAULT_BUDGET)?;
        self.analyse_function_request(&request, entry)
    }

    /// Runs a demand walk under the caller's captured revision and job control.
    pub fn analyse_function_request(
        &self,
        request: &exec::ExecutionRequest,
        entry: &romwright_model::Address,
    ) -> Result<demand::FunctionAnalysis> {
        self.check_execution(request)?;
        let program = request.program.as_str();
        let started = std::time::Instant::now();
        let id = self.db.program_id(program)?;
        let revision = request.revision;
        let key = entry.to_string();
        let known = self.db.function_analysis_state(id, &key)?;
        if let Some((state, analysed)) = &known
            && matches!(state.as_str(), "walked" | "batch")
            && *analysed == revision
        {
            let row = self
                .db
                .functions(id)?
                .into_iter()
                .find(|function| function.entry == *entry);
            return Ok(demand::FunctionAnalysis {
                program: program.to_string(),
                entry: key,
                size: row.as_ref().map(|row| row.size).unwrap_or(0),
                instructions: 0,
                calls: Vec::new(),
                xrefs: 0,
                state: state.clone(),
                reused: true,
                seconds: started.elapsed().as_secs_f64(),
                phases: Vec::new(),
            });
        }
        let name = self
            .db
            .functions(id)?
            .into_iter()
            .find(|function| function.entry == *entry)
            .map(|function| function.name)
            .unwrap_or_else(|| format!("FUN_{:08x}", entry.offset));
        let address = entry.offset;
        let mut phases = Vec::new();
        let opening = std::time::Instant::now();
        let (walk, xrefs, transfers) = self.live.with(&request.input, program, Some(request), |live| {
            phases.push(("open".to_string(), opening.elapsed().as_secs_f64()));
            let walking = std::time::Instant::now();
            let walk = live.walk(address)?;
            phases.push(("walk".to_string(), walking.elapsed().as_secs_f64()));
            let referencing = std::time::Instant::now();
            // Nothing decoded means nothing to ask about: an entry outside
            // every mapping, or bytes the console refuses. The empty range
            // is reported as such rather than sent to the console.
            let xrefs = if walk.end > walk.entry {
                live.references(walk.entry, walk.end)?
            } else {
                Vec::new()
            };
            phases.push(("references".to_string(), referencing.elapsed().as_secs_f64()));
            let transfers = walk.transfer_facts(&live.declared_entries());
            Ok((walk, xrefs, transfers))
        })?;
        let row = walk.row(name);
        // A walk that decoded nothing proves nothing: the row stays a seed
        // so a later attempt -- with the image based differently, or with
        // the switch pass run -- is free to try again.
        let state = if walk.instructions == 0 {
            "undecodable"
        } else {
            "walked"
        };
        // The walk's own control flow is a fact too: the whole-image pass
        // writes one `UNCONDITIONAL_CALL` per direct call site, and a body
        // analysed on demand has exactly the same edges.
        let mut facts = xrefs.clone();
        facts.extend(transfers);
        for (from, to) in &walk.call_sites {
            if !facts.iter().any(|xref| xref.from == *from && xref.to == *to) {
                facts.push(native::NativeXref::new(*from, *to, "UNCONDITIONAL_CALL"));
            }
        }
        // The body's own references replace whatever a previous walk of the
        // same range asserted; references from elsewhere into it are other
        // functions' facts and are left alone.
        request.cancel.checkpoint(request.deadline)?;
        self.db.publish_function_analysis(
            id,
            revision,
            &row,
            state,
            &romwright_model::Address::ram(walk.end),
            &facts
                .iter()
                .map(|xref| romwright_model::XrefRow {
                    from: romwright_model::Address::ram(xref.from),
                    to: romwright_model::Address::ram(xref.to),
                    kind: xref.kind.clone(),
                    function: None,
                    provenance: romwright_model::FactProvenance {
                        kind: romwright_model::FactKind::Inferred,
                        source: if xref.provenance.is_empty() {
                            "native-import".into()
                        } else {
                            xref.provenance.clone()
                        },
                        confidence: None,
                    },
                })
                .collect::<Vec<_>>(),
        )?;
        Ok(demand::FunctionAnalysis {
            program: program.to_string(),
            entry: key,
            size: walk.size(),
            instructions: walk.instructions,
            calls: walk
                .calls
                .iter()
                .map(|target| romwright_model::Address::ram(*target).to_string())
                .collect(),
            xrefs: facts.len() as u64,
            state: state.into(),
            reused: false,
            seconds: started.elapsed().as_secs_f64(),
            phases,
        })
    }

    /// Structures functions' control-flow graphs with the decompiler's own
    /// structuring pass, over the blocks and edges *our* walk decoded.
    ///
    /// The graphs come from the demand-driven walk, so both this answer and
    /// any structuring of ours see identical input: a difference in goto
    /// count is then a difference between two structuring algorithms, and
    /// not between two ways of recovering a CFG.
    pub fn structure_functions(
        &self,
        binary: &Path,
        program: &str,
        entries: &[romwright_model::Address],
    ) -> Result<Vec<serde_json::Value>> {
        let request = self.execution_request(binary, program, None, exec::DEFAULT_BUDGET)?;
        let mut requests = Vec::with_capacity(entries.len());
        // What the walk proved about each body travels with its answer: a
        // block count is only comparable to another producer's when both
        // attributed the same code to the function.
        type WalkFacts = (u64, u64, Vec<u64>, usize, crate::structuring::Structured);
        let mut walked: std::collections::HashMap<String, WalkFacts> =
            std::collections::HashMap::new();
        self.live.with(&request.input, program, Some(&request), |live| {
            for entry in entries {
                let walk = live.walk(entry.offset)?;
                let (blocks, edges) = walk.basic_blocks();
                if blocks.is_empty() {
                    continue;
                }
                // Our own structuring of the same graph, so both answers
                // travel together and no consumer can compare two different
                // CFGs by accident.
                let ours = crate::structuring::structure(blocks.len(), &edges);
                walked.insert(
                    entry.to_string(),
                    (walk.size(), walk.instructions, blocks.clone(), edges.len(), ours),
                );
                requests.push(
                    serde_json::json!({
                        "id": entry.to_string(),
                        "blocks": blocks,
                        "edges": edges,
                    })
                    .to_string(),
                );
            }
            Ok(())
        })?;
        let answers = native_runtime::structure_native(&request, &requests)?;
        self.check_execution(&request)?;
        Ok(answers
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .map(|mut answer| {
                if let Some((size, instructions, starts, edges, ours)) = answer
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|id| walked.get(id))
                    .cloned()
                    && let Some(object) = answer.as_object_mut()
                {
                    object.insert("size".into(), size.into());
                    object.insert("instructions".into(), instructions.into());
                    object.insert("blocks".into(), starts.len().into());
                    object.insert("edges".into(), edges.into());
                    object.insert(
                        "block_starts".into(),
                        starts
                            .iter()
                            .map(|start| format!("{start:08x}"))
                            .collect::<Vec<_>>()
                            .into(),
                    );
                    object.insert(
                        "ours".into(),
                        // Stock's count is over the collapsed graph, whose
                        // parallel edges it merges; ours is scored on the
                        // same category, and the original edges behind it
                        // (one printed jump each) are reported beside it.
                        serde_json::json!({
                            "unstructured": ours.virtualised,
                            "original_edges": ours.unstructured_edges(),
                            "duplicated": ours.duplicated.len(),
                        }),
                    );
                }
                answer
            })
            .collect())
    }

    /// What the store can answer about a program right now, and what it
    /// cannot yet.
    ///
    /// Every query answers immediately from facts already committed; this
    /// says how complete those facts are, so a consumer can render an
    /// answer *and* say it is provisional instead of choosing between
    /// showing nothing and pretending to be finished. `analysed` counts
    /// bodies somebody walked, `seeded` the entries only the image
    /// declared, and `stale` is true while any seed remains.
    pub fn analysis_status(&self, program: &str) -> Result<romwright_model::AnalysisStatus> {
        let id = self.db.program_id(program)?;
        let states = self.db.analysis_progress(id)?;
        let mut analysed = 0;
        let mut seeded = 0;
        let mut undecodable = 0;
        for (state, count) in &states {
            match state.as_str() {
                "walked" | "batch" => analysed += count,
                "undecodable" => undecodable += count,
                _ => seeded += count,
            }
        }
        Ok(romwright_model::AnalysisStatus {
            program: program.to_string(),
            revision: self.db.revision(id)?,
            functions: analysed + seeded + undecodable,
            analysed,
            seeded,
            undecodable,
            stale: seeded > 0,
        })
    }

    /// Analyses the seeds of a program one at a time, committing each
    /// body's facts as it is walked.
    ///
    /// This is the background half of the facts-so-far contract: a query
    /// answers from what is committed, and this commits more. Each function
    /// is its own transaction and bumps the revision, so a consumer polling
    /// `events_since` sees the store grow rather than waiting for a whole
    /// image. `budget` bounds the work in one call, because a caller that
    /// wants to stay responsive decides when to stop, not this.
    pub fn analyse_pending(
        &self,
        binary: &Path,
        program: &str,
        budget: usize,
    ) -> Result<romwright_model::AnalysisStatus> {
        let id = self.db.program_id(program)?;
        // Seeds in address order: an analyst reads a listing downwards, so
        // the facts arrive in the order they are likely to be looked at.
        let pending: Vec<romwright_model::Address> = self
            .db
            .functions(id)?
            .into_iter()
            .filter(|function| {
                matches!(
                    self.db
                        .function_analysis_state(id, &function.entry.to_string())
                        .ok()
                        .flatten()
                        .map(|(state, _)| state),
                    Some(state) if state == "seeded"
                )
            })
            .map(|function| function.entry)
            .take(budget)
            .collect();
        for entry in &pending {
            // One function's failure is that function's: a body the console
            // cannot decode must not stop the pass over the rest.
            let _ = self.analyse_function(binary, program, entry);
        }
        self.analysis_status(program)
    }

    /// Finds functions by the shape of the control-flow graph, in the code
    /// no other producer claimed.
    ///
    /// Every other producer needs something pointing at a function: a
    /// symbol, a relocation, a call, a byte pattern. This one needs only
    /// that the code *is* code -- it sweeps the gaps between known bodies,
    /// clusters what decodes into connected components, and calls each
    /// component a function (`cfg_functions`, after Nucleus). The result is
    /// returned rather than committed, so a caller can score this producer
    /// on its own before anything believes it.
    pub fn detect_functions_cfg(
        &self,
        binary: &Path,
        program: &str,
        unit: u64,
        whole_range: bool,
    ) -> Result<serde_json::Value> {
        let id = self.db.program_id(program)?;
        // What is already claimed: a body somebody walked, with its extent.
        // Scoring this producer on its own means sweeping everything, not
        // only what nothing else claimed: a pass that is handed the answers
        // cannot be measured against them.
        let mut claimed: Vec<(u64, u64)> = if whole_range { Vec::new() } else { self
            .db
            .functions(id)?
            .into_iter()
            .map(|function| {
                (
                    function.entry.offset,
                    function.entry.offset.saturating_add(function.size.max(1)),
                )
            })
            .collect() };
        claimed.sort_unstable();
        let started = std::time::Instant::now();
        let mut found = crate::cfg_functions::Clustered::default();
        let mut swept_bytes = 0u64;
        self.live.with(&self.resolve_program_input(binary, program)?, program, None, |live| {
            for (start, end) in live.code_ranges() {
                // The gaps between claimed bodies inside this range.
                let mut cursor = start;
                let mut gaps: Vec<(u64, u64)> = Vec::new();
                for (claim_start, claim_end) in claimed
                    .iter()
                    .copied()
                    .filter(|(claim_start, _)| *claim_start >= start && *claim_start < end)
                {
                    if claim_start > cursor {
                        gaps.push((cursor, claim_start));
                    }
                    cursor = cursor.max(claim_end);
                }
                if cursor < end {
                    gaps.push((cursor, end));
                }
                for (gap_start, gap_end) in gaps {
                    if gap_end <= gap_start {
                        continue;
                    }
                    swept_bytes += gap_end - gap_start;
                    let steps = live.sweep(gap_start, gap_end, unit)?;
                    let clustered = crate::cfg_functions::cluster(&steps);
                    found.entries.extend(clustered.entries);
                    found.called.extend(clustered.called);
                    found.blocks += clustered.blocks;
                    found.components += clustered.components;
                }
            }
            Ok(())
        })?;
        found.entries.sort_unstable();
        found.entries.dedup();
        found.called.sort_unstable();
        found.called.dedup();
        Ok(serde_json::json!({
            "program": program,
            "provenance": "native-analysis:cfg-cluster",
            "claimed_functions": claimed.len(),
            "swept_bytes": swept_bytes,
            "blocks": found.blocks,
            "components": found.components,
            "entries": found
                .entries
                .iter()
                .map(|entry| format!("{entry:08x}"))
                .collect::<Vec<_>>(),
            "called_entries": found
                .called
                .iter()
                .map(|entry| format!("{entry:08x}"))
                .collect::<Vec<_>>(),
            "seconds": started.elapsed().as_secs_f64(),
        }))
    }

    /// Infers parameter and return types for functions, from p-code alone.
    ///
    /// The constraints come from what the instructions commit to (see
    /// `types_infer`); the mapping from a constraint on a register to a
    /// parameter index comes from the compiler spec's own prototype model,
    /// so the answer is in the same terms DWARF states its truth in.
    pub fn infer_types(
        &self,
        binary: &Path,
        program: &str,
        entries: &[romwright_model::Address],
    ) -> Result<Vec<serde_json::Value>> {
        let language = self.db.program_language(self.db.program_id(program)?)?;
        let (_, specs, _, _) =
            native_runtime::language_decompile_config(&self.config, &language)?;
        let cspec = std::fs::read_to_string(specs.join("cspec.xml"))?;
        let table = std::fs::read_to_string(specs.join("registers.txt"))?;
        let conventions = register_params::Conventions::parse(&cspec, &table);
        let machine = conventions.machine(&language);
        // The model with the longest register parameter list is the one a
        // compiler uses for ordinary functions; a spec that names none
        // leaves nothing to map a constraint onto.
        let Some(model) = conventions.default() else {
            return Ok(Vec::new());
        };
        let slot = |name: &str| conventions.registers.get(name).map(|(offset, _)| *offset);
        let killed: std::collections::BTreeSet<u64> = model.killed.iter().filter_map(|name| slot(name)).collect();
        // A float parameter slot is the register the cspec names — a pair
        // like `f12_13` for a `double`, a single like `f12` for a `float`.
        // On big-endian MIPS the single sits at the pair's high offset, so
        // both offsets are slots: the pair for a double, the first single
        // for a float.
        let float_offsets = |name: &str| {
            let mut offsets = Vec::new();
            if let Some(offset) = slot(name) {
                offsets.push(offset);
            }
            if let Some(single) = name.split('_').next().filter(|s| *s != name)
                && let Some(offset) = slot(single)
                && !offsets.contains(&offset)
            {
                offsets.push(offset);
            }
            offsets
        };
        let parameter_slots: Vec<(String, u64)> = model
            .registers
            .iter()
            .filter_map(|name| slot(name).map(|offset| (name.clone(), offset)))
            .collect();
        // One entry per logical float parameter; each carries the offsets a
        // value of that slot could occupy — the pair for a `double`, the
        // first single for a `float` (which sits at the pair's high offset
        // on big-endian MIPS).
        let float_slots: Vec<(String, Vec<u64>)> = model
            .float_registers
            .iter()
            .map(|name| (name.clone(), float_offsets(name)))
            .collect();
        // A float result arrives in a float register and an integer one in
        // an integer register, but the integer register is written on the
        // way out of almost every function, so the float slot is consulted
        // first and only accepted when it holds float evidence.
        let float_return_slots: Vec<u64> = model
            .float_returns
            .iter()
            .flat_map(|name| float_offsets(name))
            .collect();
        let return_slots: Vec<(String, u64)> = model
            .returns
            .iter()
            .filter_map(|name| slot(name).map(|offset| (name.clone(), offset)))
            .collect();
        let mut rows = Vec::with_capacity(entries.len());
        self.live.with(&self.resolve_program_input(binary, program)?, program, None, |live| {
            // Pass 1: lift every function and solve it in isolation, so
            // each has a Signature the callers' second pass can consume.
            let mut lifted: Vec<(u64, usize, Vec<crate::native_runtime::PcodeInstruction>)> =
                Vec::with_capacity(entries.len());
            // The Knowledge DB: each function's signature is a fact with
            // provenance. The solver's own recovery is Inferred; the
            // decompiler's FuncProto is Strong and overrides it, so a
            // caller sees the more authoritative signature.
            let mut signatures: crate::facts::FactStore<u64, crate::subtype::Signature> =
                crate::facts::FactStore::default();
            for entry in entries {
                let walk = live.walk(entry.offset)?;
                if walk.instructions == 0 {
                    continue;
                }
                let addresses: Vec<u64> = {
                    let mut all: Vec<u64> = walk
                        .instruction_extents
                        .iter()
                        .map(|(address, _)| *address)
                        .collect();
                    all.sort_unstable();
                    all.dedup();
                    all
                };
                let pcode = live.pcode(&addresses)?;
                let solution = crate::subtype::solve_with(
                    &pcode,
                    &std::collections::BTreeMap::new(),
                    &killed,
                    &machine,
                );
                let params = parameter_slots
                    .iter()
                    .filter_map(|(_, offset)| {
                        solution.types.get(offset).map(|ty| (*offset, ty.clone()))
                    })
                    .collect();
                let returns = return_slots
                    .iter()
                    .filter_map(|(_, offset)| {
                        solution.types.get(offset).map(|ty| (*offset, ty.clone()))
                    })
                    .collect();
                signatures.assert(
                    entry.offset,
                    crate::facts::Fact::new(
                        crate::subtype::Signature { params, returns },
                        crate::facts::Confidence::Inferred,
                        crate::facts::FactOrigin::TypeInference,
                    ),
                );
                lifted.push((entry.offset, walk.instructions as usize, pcode));
            }
            // The decompiler's own prototype recovery is the stronger
            // source: a FuncProto asserts each function's signature at
            // Strong, overriding the solver's Inferred fact. Best-effort —
            // a function the decompiler declines keeps its inferred
            // signature.
            let int_slots: Vec<u64> = parameter_slots.iter().map(|(_, o)| *o).collect();
            let float_slot_offsets: Vec<u64> =
                float_slots.iter().flat_map(|(_, o)| o.iter().copied()).collect();
            let int_ret: Vec<u64> = return_slots.iter().map(|(_, o)| *o).collect();
            for (entry_offset, _, _) in &lifted {
                let address = romwright_model::Address {
                    space: romwright_model::AddressSpace::Ram,
                    offset: *entry_offset,
                };
                if let Ok(doc) = self.decompile_native_doc(binary, &address, program, None)
                    && let Some(proto) = doc.prototype
                {
                    let sig = crate::subtype::Signature::from_funcproto(
                        &proto,
                        &int_slots,
                        &float_slot_offsets,
                        &int_ret,
                        &float_return_slots,
                        &machine,
                    );
                    signatures.assert(
                        *entry_offset,
                        crate::facts::Fact::new(
                            sig,
                            crate::facts::Confidence::Strong,
                            crate::facts::FactOrigin::Ghidra,
                        ),
                    );
                }
            }
            // The callee map the solver consumes is the winning fact per
            // function — the Knowledge DB's answer, not a bare map.
            let mut callees: std::collections::BTreeMap<u64, crate::subtype::Signature> =
                signatures
                    .iter()
                    .map(|(addr, fact)| (*addr, fact.value.clone()))
                    .collect();
            // Pass 2 iterates to a fixpoint. Each solve observes what every
            // caller passes; those observations join into the callee's
            // inferred signature, which re-constrains the callers — the
            // bidirectional BinSub direction. A Strong/Ghidra signature is
            // authoritative and is not refined by caller observations.
            let mut solutions: Vec<crate::subtype::Solution> = Vec::new();
            for _round in 0..8 {
                solutions = lifted
                    .iter()
                    .map(|(_, _, pcode)| {
                        crate::subtype::solve_with(pcode, &callees, &killed, &machine)
                    })
                    .collect();
                // caller→callee: join each observed argument type into the
                // callee's inferred signature.
                for sol in &solutions {
                    for (callee, args) in &sol.calls {
                        if let Some(fact) = signatures.get_mut(callee)
                            && fact.confidence == crate::facts::Confidence::Inferred
                        {
                            for (reg, ty) in args {
                                match fact.value.params.iter_mut().find(|(r, _)| r == reg) {
                                    Some((_, existing)) => {
                                        *existing = existing.join(ty);
                                    }
                                    None => fact.value.params.push((*reg, ty.clone())),
                                }
                            }
                        }
                    }
                }
                let next: std::collections::BTreeMap<u64, crate::subtype::Signature> = signatures
                    .iter()
                    .map(|(addr, fact)| (*addr, fact.value.clone()))
                    .collect();
                if next == callees {
                    break;
                }
                callees = next;
            }
            for ((entry_offset, instructions, pcode), solution) in
                lifted.iter().zip(solutions.iter())
            {
                let facts = crate::types_infer::infer(pcode, &machine);
                let parameters: Vec<String> = parameter_slots
                    .iter()
                    .map(|(_, offset)| facts.get(*offset).name())
                    .collect();
                // The return value is whatever the result register was last
                // constrained to. A function that returns without writing a
                // result register returns void; one that writes it — even a
                // `LOAD` whose class is unproven — carries a value.
                let return_class = float_return_slots
                    .iter()
                    .map(|offset| facts.written(*offset))
                    .find(|class| matches!(class, romwright_model::type_evidence::Class::Float(_)))
                    .or_else(|| {
                        return_slots
                            .iter()
                            .map(|(_, offset)| facts.written(*offset))
                            .find(|class| *class != romwright_model::type_evidence::Class::Unknown)
                    });
                let returns = return_class
                    .map(|class| class.name())
                    .unwrap_or_else(|| {
                        if return_slots.iter().any(|(_, o)| facts.touched(*o)) {
                            "unknown".into()
                        } else {
                            "void".into()
                        }
                    });
                // The C spelling of the return: `void` stays `void`, an
                // unproven value takes the signed default.
                let return_c = match returns.as_str() {
                    "void" => "void".to_string(),
                    _ => return_class
                        .map(|class| class.c_name())
                        .unwrap_or_else(|| "int".into()),
                };
                let float_parameters: Vec<String> = float_slots
                    .iter()
                    .map(|(_, offsets)| {
                        offsets
                            .iter()
                            .map(|offset| facts.get(*offset))
                            .find(|class| *class != romwright_model::type_evidence::Class::Unknown)
                            .unwrap_or(romwright_model::type_evidence::Class::Unknown)
                            .name()
                    })
                    .collect();
                // The structural type each parameter register's accesses
                // prove — `*struct{+0x34: float32}` for a register
                // dereferenced at several offsets. This is the BinSub
                // layer: the subtype solver propagates capabilities and
                // structure along `src <: dst` copy edges to a fixpoint, and
                // a call asserts the callee's signature onto the argument
                // and return registers — the interprocedural direction.
                // A float parameter lives in a float register, so the
                // structural slot falls back to it when the integer side
                // proved nothing.
                let structural: Vec<(crate::types_infer::Ty, String)> = parameter_slots
                    .iter()
                    .enumerate()
                    .map(|(i, (_, offset))| {
                        // The solver's structural types (pointer, struct,
                        // array) are the ones only it can prove; for a bare
                        // scalar the alias-aware `facts` is more accurate —
                        // it follows a spilled parameter back to its
                        // register where the solver only sees the temp.
                        let solved = solution.types.get(offset);
                        let scalar = facts.get(*offset);
                        let ty = match solved {
                            Some(ty) if !matches!(ty, crate::types_infer::Ty::Scalar(_)
                                | crate::types_infer::Ty::Unknown) => ty.clone(),
                            _ => crate::types_infer::Ty::Scalar(scalar),
                        };
                        let ty = if matches!(ty, crate::types_infer::Ty::Scalar(
                            romwright_model::type_evidence::Class::Unknown)) {
                            float_parameters
                                .get(i)
                                .filter(|f| f.as_str() != "unknown")
                                .map(|_| ty.clone())
                                .unwrap_or(ty)
                        } else {
                            ty
                        };
                        let name = ty.name();
                        (ty, name)
                    })
                    .collect();
                let structural_names: Vec<String> =
                    structural.iter().map(|(_, n)| n.clone()).collect();
                // The C prototype a reader sees: `num`/`opaque` take C's
                // signed default, a proven struct/array pointer spells
                // `void *`. The analysis fields keep the honest classes.
                // Arity is the highest parameter register the body actually
                // read — a callee never touches the slots past its last
                // argument.
                let arity = parameter_slots
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, (_, offset))| {
                        facts.read_before_write(*offset)
                            || facts.get(*offset) != romwright_model::type_evidence::Class::Unknown
                            || solution.types.get(offset).is_some_and(|ty| {
                                !matches!(ty, crate::types_infer::Ty::Unknown)
                            })
                    })
                    .map(|(i, _)| i + 1)
                    .unwrap_or(0);
                let params_c = if arity == 0 {
                    "void".to_string()
                } else {
                    structural
                        .iter()
                        .take(arity)
                        .map(|(ty, _)| ty.c_name())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let signature =
                    format!("{} FUN_{:08x}({})", return_c, entry_offset, params_c);
                rows.push(serde_json::json!({
                    "entry": format!("{:08x}", entry_offset),
                    "model": model.name,
                    "signature": signature,
                    "parameters": parameters,
                    "structural": structural_names,
                    "float_parameters": float_parameters,
                    "returns": returns,
                    "instructions": instructions,
                }));
            }
            Ok(())
        })?;
        Ok(rows)
    }

    /// Prunes the candidate set at one function's indirect-call sites by
    /// signature compatibility: a callee whose recovered signature does
    /// not match the argument registers the site sets cannot be the call's
    /// target. The pool is every address-taken function the image names --
    /// an initializer slot, a pointer slot, or a code-immediate reference
    /// to a function entry.
    ///
    /// Returns one row per `CallInd` site in the function: the site's
    /// address, the pool, and the pool members the site's signature admits.
    pub fn prune_indirect_calls(
        &self,
        binary: &Path,
        program: &str,
        entry: &romwright_model::Address,
    ) -> Result<Vec<serde_json::Value>> {
        let language = self.db.program_language(self.db.program_id(program)?)?;
        let (_, specs, _, _) =
            native_runtime::language_decompile_config(&self.config, &language)?;
        let cspec = std::fs::read_to_string(specs.join("cspec.xml"))?;
        let table = std::fs::read_to_string(specs.join("registers.txt"))?;
        let conventions = register_params::Conventions::parse(&cspec, &table);
        let machine = conventions.machine(&language);
        let Some(model) = conventions.default() else {
            return Ok(Vec::new());
        };
        let slot = |name: &str| conventions.registers.get(name).map(|(offset, _)| *offset);
        let parameter_slots: Vec<u64> = model
            .registers
            .iter()
            .filter_map(|name| slot(name))
            .collect();
        let float_slots: Vec<u64> = model
            .float_registers
            .iter()
            .filter_map(|name| slot(name))
            .collect();
        let id = self.db.program_id(program)?;
        // The pool: every function entry the image's own structure takes
        // the address of. Initializer and pointer slots name them; a
        // code-immediate reference (a `lea`/`mov` of a function entry) does
        // too, since the callee of a `call *reg` is always an address the
        // image carries somewhere.
        let functions = self.db.functions(id)?;
        let entries: std::collections::HashSet<u64> =
            functions.iter().map(|f| f.entry.offset).collect();
        let pool: std::collections::BTreeSet<u64> = self
            .db
            .xrefs(id)?
            .into_iter()
            .filter(|xref| {
                // An unwind entry names every function for the stack
                // walker; it is not the image taking the function's
                // address. Only a data reference -- an initializer slot,
                // a pointer slot, or a code immediate -- is.
                xref.kind == "DATA"
                    && !xref.provenance.source.contains("elf-unwind")
                    && entries.contains(&xref.to.offset)
            })
            .map(|xref| xref.to.offset)
            .collect();
        // A switch's computed jump is a BRANCHIND whose target the store
        // recorded as COMPUTED_JUMP; a tail call through a register is not.
        let switch_branches: std::collections::HashSet<u64> = self
            .db
            .xrefs(id)?
            .into_iter()
            .filter(|xref| xref.kind == "COMPUTED_JUMP")
            .map(|xref| xref.from.offset)
            .collect();
        let mut rows = Vec::new();
        self.live.with(&self.resolve_program_input(binary, program)?, program, None, |live| {
            let walk = live.walk(entry.offset)?;
            if walk.instructions == 0 {
                return Ok(());
            }
            let addresses: Vec<u64> = {
                let mut all: Vec<u64> = walk
                    .instruction_extents
                    .iter()
                    .map(|(address, _)| *address)
                    .collect();
                all.sort_unstable();
                all.dedup();
                all
            };
            let pcode = live.pcode(&addresses)?;
            // The call sites are the CALLIND instructions; the signature
            // the site states is the class of each argument register at
            // the call.
            for instruction in &pcode {
                // A `call *reg` is a CALLIND; a tail call through a
                // register is a BRANCHIND that is not a switch's computed
                // jump. The store's xrefs name the switch branches.
                let is_call = instruction.ops.iter().any(|op| {
                    op.opcode == "CALLIND"
                        || (op.opcode == "BRANCHIND"
                            && !switch_branches.contains(&instruction.address))
                });
                if !is_call {
                    continue;
                }
                // The classes the site sets: run the caller's p-code up to
                // this instruction and read the argument registers' last
                // written class.
                let prefix: Vec<crate::native_runtime::PcodeInstruction> = pcode
                    .iter()
                    .take_while(|i| i.address <= instruction.address)
                    .cloned()
                    .collect();
                let facts = crate::types_infer::infer(&prefix, &machine);
                // The site's signature is the class of the value last
                // written to each argument register before the call.
                let site_ints: Vec<romwright_model::type_evidence::Class> = parameter_slots
                    .iter()
                    .map(|offset| facts.written(*offset))
                    .collect();
                let site_floats: Vec<romwright_model::type_evidence::Class> = float_slots
                    .iter()
                    .map(|offset| facts.written(*offset))
                    .collect();
                // The site's arity is the contiguous prefix of argument
                // registers whose last write before the call sets an
                // argument. The target register itself is excluded -- it
                // holds the callee address, not an argument.
                let target = instruction
                    .ops
                    .iter()
                    .find(|op| op.opcode == "CALLIND" || op.opcode == "BRANCHIND")
                    .and_then(|op| op.inputs.first());
                let target_register = target.and_then(|target| {
                    if target.space == "register" {
                        Some(target.offset)
                    } else {
                        instruction
                            .ops
                            .iter()
                            .find(|op| {
                                op.output.as_ref().is_some_and(|output| {
                                    output.space == target.space
                                        && output.offset == target.offset
                                })
                            })
                            .and_then(|op| op.inputs.first())
                            .filter(|input| input.space == "register")
                            .map(|input| input.offset)
                    }
                });
                let site_facts = crate::types_infer::infer(&prefix, &machine);
                let mut spilled_write: std::collections::BTreeSet<u64> =
                    std::collections::BTreeSet::new();
                let mut last_write: std::collections::BTreeSet<u64> =
                    std::collections::BTreeSet::new();
                for instruction in prefix.iter() {
                    for op in &instruction.ops {
                        if let Some(output) = &op.output
                            && output.space == "register"
                            && Some(output.offset) != target_register
                        {
                            // A register holding its own entry value
                            // reloaded itself from its frame slot: the
                            // function shuffling a parameter it never
                            // passes. Anything else -- a computed value,
                            // or another register's value moved into
                            // place -- is an argument the call sets.
                            if site_facts
                                .alias_origin(output.offset)
                                .is_some_and(|(origin, _)| origin == output.offset)
                            {
                                spilled_write.insert(output.offset);
                            } else {
                                spilled_write.remove(&output.offset);
                            }
                            last_write.insert(output.offset);
                        }
                    }
                }
                let arity = parameter_slots
                    .iter()
                    .take_while(|offset| {
                        last_write.contains(*offset) && !spilled_write.contains(*offset)
                    })
                    .count();
                let float_arity = float_slots
                    .iter()
                    .take_while(|offset| {
                        last_write.contains(*offset) && !spilled_write.contains(*offset)
                    })
                    .count();
                let kept: Vec<u64> = pool
                    .iter()
                    .copied()
                    .filter(|candidate| {
                        // A candidate is compatible when its signature does
                        // not contradict the site's: it needs no more
                        // parameters than the site sets, and no parameter
                        // class contradicts the site's.
                        let candidate_facts = live
                            .walk(*candidate)
                            .ok()
                            .and_then(|walk| {
                                if walk.instructions == 0 {
                                    return None;
                                }
                                let addresses: Vec<u64> = walk
                                    .instruction_extents
                                    .iter()
                                    .map(|(address, _)| *address)
                                    .collect();
                                live.pcode(&addresses).ok()
                            })
                            .map(|pcode| crate::types_infer::infer(&pcode, &machine));
                        let Some(candidate_facts) = candidate_facts else {
                            return true; // undecodable: nothing to contradict
                        };
                        let candidate_ints: Vec<romwright_model::type_evidence::Class> =
                            parameter_slots
                                .iter()
                                .map(|offset| candidate_facts.get(*offset))
                                .collect();
                        let candidate_floats: Vec<romwright_model::type_evidence::Class> =
                            float_slots
                                .iter()
                                .map(|offset| candidate_facts.get(*offset))
                                .collect();
                        // Arity: a candidate that reads a parameter register
                        // before writing it is taking an argument; one that
                        // reads a register the site never set is
                        // incompatible -- it would read a caller-saved
                        // leftover as an argument.
                        let candidate_arity = parameter_slots
                            .iter()
                            .rposition(|offset| candidate_facts.read_before_write(*offset))
                            .map(|index| index + 1)
                            .unwrap_or(0);
                        let candidate_float_arity = float_slots
                            .iter()
                            .rposition(|offset| candidate_facts.read_before_write(*offset))
                            .map(|index| index + 1)
                            .unwrap_or(0);
                        // Arity: the candidate must take exactly the
                        // arguments the site sets, or none at all when the
                        // site sets at most one -- a single written
                        // register may be a coincidence, but two or more
                        // state a signature the callee must match.
                        if std::env::var("ROMWRIGHT_DEBUG_PRUNE").is_ok() {
                            eprintln!(
                                "candidate {candidate:#x}: int_arity={candidate_arity} site={arity} float_arity={candidate_float_arity} site={float_arity}"
                            );
                        }
                        if candidate_arity != arity && !(candidate_arity == 0 && arity <= 1) {
                            return false;
                        }
                        if candidate_float_arity != float_arity
                            && !(candidate_float_arity == 0 && float_arity <= 1)
                        {
                            return false;
                        }
                        // Class: a candidate that reads a parameter as a
                        // float where the site sets an integer, or the
                        // reverse, is incompatible. `unknown` on either side
                        // is no evidence and never contradicts.
                        for (site_class, candidate_class) in site_ints
                            .iter()
                            .zip(candidate_ints.iter())
                            .chain(site_floats.iter().zip(candidate_floats.iter()))
                        {
                            use romwright_model::type_evidence::Class;
                            let contradicts = matches!(
                                (site_class, candidate_class),
                                (Class::Float(_), Class::Int(_))
                                    | (Class::Float(_), Class::Uint(_))
                                    | (Class::Float(_), Class::Num(_))
                                    | (Class::Int(_), Class::Float(_))
                                    | (Class::Uint(_), Class::Float(_))
                                    | (Class::Num(_), Class::Float(_))
                                    | (Class::Ptr, Class::Float(_))
                                    | (Class::Float(_), Class::Ptr)
                                    | (Class::Code, Class::Float(_))
                                    | (Class::Float(_), Class::Code)
                            );
                            if contradicts {
                                return false;
                            }
                        }
                        true
                    })
                    .collect();
                rows.push(serde_json::json!({
                    "site": format!("{:#x}", instruction.address),
                    "candidates": pool.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>(),
                    "kept": kept.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>(),
                }));
            }
            Ok(())
        })?;
        Ok(rows)
    }

    /// Applies an analyst rename in the project store and bumps the revision.
    /// (Direct mutation — no journal entry.)
    pub fn rename_function(&self, program: &str, entry: &romwright_model::Address, name: &str) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.rename_function(id, entry, name)?;
        Ok(())
    }

    /// UNDOABLE command: rename with journal entry + captured undo state
    /// (CORE-006). The UI and automation go through this, not raw renames.
    pub fn rename_command(&self, program: &str, entry: &romwright_model::Address, name: &str) -> Result<()> {
        let id = self.db.program_id(program)?;
        let old_name = self
            .db
            .functions(id)?
            .into_iter()
            .find(|f| f.entry == *entry)
            .map(|f| f.name)
            .ok_or_else(|| {
                CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no function at {entry}"),
                ))
            })?;
        self.db.rename_command(id, entry, name, &old_name)?;
        Ok(())
    }

    /// UNDOABLE analyst comment command. Comment rows, revision events, and
    /// the prior value all enter the same durable transaction.
    pub fn comment_command(
        &self,
        program: &str,
        address: &Address,
        function: &Address,
        kind: &str,
        text: &str,
    ) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db
            .comment_command(id, address, function, kind, text)?;
        Ok(())
    }

    /// Undoes the latest undone command, returning what it did (CORE-006).
    pub fn undo_last(&self, program: &str) -> Result<String> {
        let id = self.db.program_id(program)?;
        let entry = self
            .db
            .journal_latest(id)?
            .ok_or_else(|| {
                CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "nothing to undo",
                ))
            })?;
        match entry.kind.as_str() {
            "rename" => {
                let undo: serde_json::Value =
                    serde_json::from_str(&entry.undo_payload).map_err(|e| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("bad undo payload: {e}"),
                        ))
                    })?;
                let entry_addr = romwright_model::Address::parse_ram_hex(
                    undo.get("entry").and_then(|v| v.as_str()).unwrap_or_default(),
                )
                .ok_or_else(|| {
                    CoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "undo payload has no entry",
                    ))
                })?;
                let old_name = undo
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                self.db.undo_rename(id, &entry_addr, &old_name, entry.seq)?;
                Ok(format!(
                    "undid rename seq {} ({} -> {old_name})",
                    entry.seq, entry_addr
                ))
            }
            "rename-batch" => {
                let undo: serde_json::Value =
                    serde_json::from_str(&entry.undo_payload).map_err(|e| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("bad undo payload: {e}"),
                        ))
                    })?;
                let renames: Vec<(romwright_model::Address, String)> = undo
                    .get("renames")
                    .and_then(|value| value.as_array())
                    .map(|rows| {
                        rows.iter()
                            .filter_map(|row| {
                                let address = romwright_model::Address::parse_ram_hex(
                                    row.get("entry").and_then(|v| v.as_str())?,
                                )?;
                                let name = row.get("name").and_then(|v| v.as_str())?;
                                Some((address, name.to_string()))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let restored = self.db.undo_rename_batch(id, &renames, entry.seq)?;
                Ok(format!(
                    "undid rename-batch seq {} ({restored} names)",
                    entry.seq
                ))
            }
            "comment" => {
                let undo: serde_json::Value =
                    serde_json::from_str(&entry.undo_payload).map_err(|e| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("bad comment undo payload: {e}"),
                        ))
                    })?;
                let address = romwright_model::Address::parse_ram_hex(
                    undo.get("address").and_then(|value| value.as_str()).unwrap_or_default(),
                )
                .ok_or_else(|| {
                    CoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "comment undo payload has no address",
                    ))
                })?;
                let kind = undo
                    .get("kind")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "comment undo payload has no kind",
                        ))
                    })?;
                let previous = if undo
                    .get("exists")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    let function = romwright_model::Address::parse_ram_hex(
                        undo.get("function")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default(),
                    )
                    .ok_or_else(|| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "comment undo payload has no prior function",
                        ))
                    })?;
                    let text = undo
                        .get("text")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();
                    Some((function, text))
                } else {
                    None
                };
                let prior = previous
                    .as_ref()
                    .map(|(function, text)| (function, text.as_str()));
                self.db.undo_comment(id, &address, kind, prior, entry.seq)?;
                Ok(format!("undid comment seq {} at {}", entry.seq, address))
            }
            other => Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("unsupported command kind: {other}"),
            ))),
        }
    }

    /// Imports `binary` natively (no JVM): format parse, flow discovery
    /// (in-Rust walk + SLEIGH console closure when the binary looks
    /// stripped), and store writes with native provenance.
    pub fn import_native(&self, binary: &Path, name: &str) -> Result<ProgramSummary> {
        let mut stored = self.import_container(binary, name)?;
        // A container's first image is the one its console boots; every
        // image is stored, and `import_container` returns them all.
        stored
            .drain(..)
            .next()
            .ok_or_else(|| CoreError::InvalidPrototype("import produced no program".into()))
    }

    /// Imports every image a container carries. A single-image file stores
    /// one program under `name`; a container stores one per processor,
    /// named `<name>.<image>`, because a program holds one language and its
    /// processors do not share one.
    /// Loads a binary's own facts without analysing it: mappings, declared
    /// regions, relocations and the image's symbol table, stored and
    /// returned. An interactive session opens with this and analyses after.
    pub fn load_program(&self, binary: &Path, name: &str) -> Result<Vec<ProgramSummary>> {
        self.import_container_with(binary, name, false, "", None, None, &native::keys::KeyStore::empty())
    }

    pub fn import_container(&self, binary: &Path, name: &str) -> Result<Vec<ProgramSummary>> {
        self.import_container_with(binary, name, true, "", None, None, &native::keys::KeyStore::empty())
    }

    /// `import_container` with a user-supplied key store: encrypted console
    /// content the user has dumped keys for (a Switch `prod.keys`, a PS3
    /// `.rap`, a Vita `klic`, a 3DS `aes_keys.txt`) decrypts on the way in.
    /// An empty store behaves exactly like `import_container`.
    pub fn import_container_keys(
        &self,
        binary: &Path,
        name: &str,
        keys: &native::keys::KeyStore,
    ) -> Result<Vec<ProgramSummary>> {
        self.import_container_with(binary, name, true, "", None, None, keys)
    }

    pub(crate) fn import_container_with(
        &self,
        binary: &Path,
        name: &str,
        analyse: bool,
        flavour: &str,
        map: Option<&Path>,
        raw: Option<(u64, &str)>,
        keys: &native::keys::KeyStore,
    ) -> Result<Vec<ProgramSummary>> {
        // A `.cue` sheet stands for the data track's `.bin` beside it.
        let resolved = native::cue::resolve(binary)?;
        let binary = resolved.as_ref();
        let map_bytes = map.map(std::fs::read).transpose()?.map(Into::into);
        let (artifact, input) = inputs::capture_file(&self.db_path, binary, map_bytes, raw, keys)?;
        let binary = artifact.path.as_path();
        let map_path = input.map_digest.as_ref().map(|digest| self.db_path.join("artifacts").join(digest));
        let map = map_path.as_deref();
        // Reuse first: the same bytes analysed by the same analyser produce
        // the same facts, and gates re-import the same corpus constantly.
        // Only a project this import would be the sole occupant of can be
        // restored wholesale, which is every gate's shape and no analyst's
        // multi-image project.
        // A MAP changes what the import produces, so its digest rides the
        // reuse key beside the signature flavour: a map'd import must never
        // be served a mapless cache.
        let map_flavour = map
            .map(|path| {
                let digest = std::fs::read(path)
                    .map(|bytes| crate::import_cache::digest_bytes(&bytes))
                    .unwrap_or_else(|_| "absent".into());
                format!("|map:{}:{digest}", path.display())
            })
            .unwrap_or_default();
        let raw_flavour = raw
            .map(|(base, language)| format!("|raw:{base:x}:{language}"))
            .unwrap_or_default();
        let cache_key = (self.db.programs()?.is_empty())
            .then(|| {
                import_cache::key(
                    binary,
                    &format!(
                        "{name}|{}|{flavour}{map_flavour}{raw_flavour}",
                        if analyse { "analysed" } else { "loaded" }
                    ),
                    &self.config,
                )
            })
            .flatten();
        if std::env::var_os("ROMWRIGHT_TRACE_CACHE").is_some() {
            eprintln!("import cache key {cache_key:?} hit {:?}",
                cache_key.as_deref().and_then(import_cache::hit));
        }
        if let Some(key) = cache_key.as_deref() {
            if self.restore_cached_import(key)? {
                let names: Vec<String> = self
                    .db
                    .programs()?
                    .into_iter()
                    .map(|row| row.program)
                    .collect();
                let mut stored = Vec::with_capacity(names.len());
                for program in names {
                    stored.push(self.open_program(&program)?);
                }
                if !stored.is_empty() {
                    return Ok(stored);
                }
            }
        }
        let mut images = native::load_container_with(binary, &artifact.bytes, false, map, raw, keys, &self.config)?;
        native::discover_programs(&mut images, &self.db_path, &input, analyse)?;
        let mut stored = Vec::with_capacity(images.len());
        for (suffix, imp) in &images {
            let program = if suffix.is_empty() {
                name.to_string()
            } else {
                format!("{name}.{suffix}")
            };
            let started = std::time::Instant::now();
            let entry_model = native::declared_entry_model(&self.config, &imp.language);
            let mut summary = native::store_import(&self.db, &program, imp, entry_model)?;
            summary.phases.push(romwright_model::PhaseTiming {
                phase: "store".into(),
                seconds: started.elapsed().as_secs_f64(),
            });
            stored.push(summary);
        }
        if let Some(key) = cache_key.as_deref().filter(|_| !images.iter().any(|(_, imp)| imp.degraded())) {
            // Snapshot through the connection, then publish it under the key.
            let staging = self.db_path.join("project.cache-staging.sqlite");
            if self.db.export_to(&staging).is_ok() {
                import_cache::publish(key, &staging);
            }
            let _ = std::fs::remove_file(&staging);
        }
        Ok(stored)
    }

    /// Fills this project's store from the cached one, through the open
    /// connection: the file is never swapped underneath it.
    fn restore_cached_import(&self, key: &str) -> Result<bool> {
        let Some(cached) = import_cache::hit(key) else {
            return Ok(false);
        };
        match self.db.import_from(&cached) {
            Ok(()) => Ok(true),
            // A cache that cannot be read is a miss, never a failure: the
            // import that follows produces the same facts.
            Err(error) => {
                if std::env::var_os("ROMWRIGHT_TRACE_CACHE").is_some() {
                    eprintln!("import cache restore failed: {error}");
                }
                Ok(false)
            }
        }
    }

    /// Native disassembly of `count` instructions at `address`.
    pub fn disasm_native(&self, binary: &Path, address: &str, count: u32) -> Result<String> {
        Ok(native_runtime::disasm_native(&self.config, binary, address, count)?)
    }

    /// Lift the p-code at `addresses` into the typed IR (`ir::IrInstruction`)
    /// — the normalized form analyses consume. The binary is imported
    /// natively so the lifter decodes under the program's real language.
    pub fn ir_native(
        &self,
        binary: &Path,
        addresses: &[u64],
    ) -> Result<Vec<ir::IrInstruction>> {
        let import = native::load_native(binary)?;
        let mut lifter = native_runtime::SleighLifter::mapped(&import.cfg, &import)
            .map_err(CoreError::NativeRuntime)?;
        Ok(ir::lift_all(&lifter.lift(addresses)))
    }

    /// Exhaustive length sweep over a mapped range plus point queries
    /// answered from it: pre-disassembly byte analysis in the SBA shape
    /// (clean-room; every offset decoded, truth checked only where the
    /// gate holds ground truth). Returns the sweep digest, the
    /// flow-class histogram, the sweep milliseconds, and one
    /// (address, length, flow-class) triple per asked offset.
    pub fn byte_scan(
        &self,
        binary: &Path,
        vaddr: u64,
        size: usize,
        ask: &[u64],
    ) -> Result<(String, [u64; 8], u64, u64, Vec<(u64, u8, u8)>)> {
        let bytes = self.mem_native(binary, vaddr, size)?;
        let started = std::time::Instant::now();
        let (digest, flows, decoded) = crate::disasm::sweep_digest(&bytes, vaddr);
        let ms = started.elapsed().as_millis();
        let mut answered = Vec::with_capacity(ask.len());
        for &address in ask {
            let index = address.wrapping_sub(vaddr) as usize;
            if index < bytes.len() {
                let info = crate::disasm::decode(&bytes[index..], address);
                answered.push((address, info.len, crate::disasm::flow_code(&info.flow)));
            }
        }
        Ok((digest, flows, ms as u64, decoded, answered))
    }

    /// Native decompilation from the program's captured loader input. The
    /// revision is captured *before* the worker runs and re-checked after: a
    /// store edit during decompilation means the answer reflects a snapshot
    /// that no longer exists, so it is rejected rather than stamped with a
    /// revision it was not computed against.
    pub fn decompile_native(
        &self,
        binary: &Path,
        address: &str,
        program: &str,
        base: Option<u64>,
    ) -> Result<String> {
        let request = self.execution_request(binary, program, base, exec::DEFAULT_BUDGET)?;
        let text = self
            .decompile_texts_structs(&request, &[address.to_string()])?
            .into_values()
            .next()
            .ok_or_else(|| {
                native_runtime::NativeRuntimeError(format!("no decompilation for {address}"))
            })?;
        self.check_execution(&request)?;
        Ok(text)
    }

    /// Native decompilation of several addresses from one worker launch. The
    /// decompiler loads its language once per launch, so a batch is what makes
    /// comparing a hundreds-of-functions image affordable. Keys are
    /// eight-digit addresses.
    pub fn decompile_native_batch(
        &self,
        binary: &Path,
        addresses: &[String],
        program: &str,
        base: Option<u64>,
    ) -> Result<std::collections::BTreeMap<String, String>> {
        let request = self.execution_request(binary, program, base, exec::DEFAULT_BUDGET)?;
        let texts = self.decompile_texts_structs(&request, addresses)?;
        self.check_execution(&request)?;
        Ok(texts)
    }

    /// Structured decompilation for a typed RAM address. Tokens and semantic
    /// IR are returned only for the captured revision.
    pub fn decompile_native_doc(
        &self,
        binary: &Path,
        address: &Address,
        program: &str,
        base: Option<u64>,
    ) -> Result<DecompDoc> {
        if !matches!(&address.space, AddressSpace::Ram) {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("native decompiler only accepts RAM addresses: {address}"),
            )));
        }
        let address_hex = format!("{:x}", address.offset);
        let request = self.execution_request(binary, program, base, exec::DEFAULT_BUDGET)?;
        let mut doc = native_runtime::decompile_native_doc(&request, &address_hex)?;
        self.check_execution(&request)?;
        doc.address = address.clone();
        doc.revision = request.revision;
        // Register-passed parameters are part of prototype recovery, so
        // every consumer of the document sees the same answer the
        // inference rounds persist. The pass is off unless asked.
        if let Some(prototype) = doc.prototype.as_mut() {
            register_params::augment(&request.config, &request.language, prototype, &doc.storage);
        }
        Ok(doc)
    }

    /// Decompiles selected or all functions and writes m2c-shaped C to `outdir`,
    /// producing the source tree `export-objdiff`'s project compiles.
    ///
    /// With `splits` (dtk `splits.txt`), functions are grouped into one
    /// `<tu>.c` per translation unit so the files line up with objdiff's
    /// `target_path`/`base_path` objects; without it, one `<name>.c` per
    /// function. Returns a JSON report: files written, semantic rewrites,
    /// native warnings, and which bodies were irregular. Every output belongs
    /// to one captured revision; no file is published unless the whole batch
    /// validates against it.
    pub fn export_m2c(
        &self,
        binary: &Path,
        program: &str,
        outdir: &Path,
        splits: Option<&[crate::native::linkmap::SplitExtent]>,
        entry: Option<u64>,
        opts: &emit_m2c::M2cOptions,
    ) -> Result<serde_json::Value> {
        let budget = opts.budget.unwrap_or(exec::DEFAULT_BUDGET);
        let mut request = self.execution_request(binary, program, None, budget)?;
        let id = self.db.program_id(program)?;
        // The printer's compiler rules are keyed by the program's compiler.
        let opts = &emit_m2c::M2cOptions {
            compiler: self.db.program_compiler(id).unwrap_or_default(),
            stdcall_imports: if emit_m2c::stdcall_imports_enabled() {
                std::fs::read(binary).map(|data| native::stdcall_import_slots(&data)).unwrap_or_default()
            } else {
                Default::default()
            },
            ..opts.clone()
        };
        let revision = request.revision;
        let mut functions = self.functions(program)?;
        if functions.is_empty() {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("program {program} has no functions"),
            )));
        }

        // Names that must never be renamed: every function and symbol.
        let mut keep: Vec<String> = functions.iter().map(|f| f.name.clone()).collect();
        for sym in self.symbols(program)? {
            keep.push(sym.name.clone());
        }
        let address_names = emit_m2c::address_names(
            functions.iter().map(|f| (f.entry.offset, f.name.as_str())),
            self.symbols(program)?.iter().map(|s| (s.address.offset, s.name.as_str())),
        );
        if let Some(entry) = entry {
            functions.retain(|function| function.entry.offset == entry);
            if functions.is_empty() {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, format!("no function at {entry:#x} in {program}"),
                )));
            }
        }

        request.config.ir_passes = opts.transforms.clone();
        request.config.worker_env = opts.worker_env.clone();
        crate::func_ir::Pipeline::from_names(&request.config.ir_passes)
            .map_err(native::ImportError::Bad)?;
        // Batch-decompile every function to a DecompDoc.
        let addresses: Vec<String> = functions
            .iter()
            .map(|f| format!("{:x}", f.entry.offset))
            .collect();
        let (mut docs, struct_warnings) = self.decompile_docs_structs(&request, &addresses)?;

        // Group functions into output units: by TU when splits are given,
        // else one unit per function.
        let mut units: Vec<(String, Vec<&FunctionRow>)> = Vec::new();
        for f in &functions {
            let unit = splits
                .and_then(|extents| {
                    extents
                        .iter()
                        .find(|e| f.entry.offset >= e.start && f.entry.offset < e.end)
                        .map(|e| {
                            e.tu.trim_end_matches(".c")
                                .trim_end_matches(".cpp")
                                .to_string()
                        })
                })
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| f.name.clone());
            if let Some((_, list)) = units.iter_mut().find(|(n, _)| *n == unit) {
                list.push(f);
            } else {
                units.push((unit, vec![f]));
            }
        }

        std::fs::create_dir_all(outdir).map_err(CoreError::Io)?;
        let asserted_prototypes = emit_m2c::DeclaredPrototypes::new(self.db.prototypes(id)?);
        let gp_at_entry: std::collections::BTreeMap<u64, u64> = self
            .db
            .decode_contexts(id)?
            .into_iter()
            .filter(|(_, name, _)| name == "gp")
            .map(|(address, _, value)| (address.offset, value))
            .collect();
        let mut files = Vec::new();
        let mut pending = Vec::new();
        let mut irregular_count = 0usize;
        let mut rewrite_count = 0usize;
        let mut warnings: Vec<serde_json::Value> = struct_warnings
            .into_iter()
            .map(|message| serde_json::json!({ "message": message }))
            .collect();
        let struct_table = struct_types::StructTable::load(
            &self.db,
            id,
            romwright_model::structs::StructMode::from_env(),
        )?;
        for (unit, fns) in &units {
            let mut text = String::new();
            let layouts = if opts.emit_globals {
                emit_m2c::UnitLayouts::new(fns.iter().filter_map(|f| docs.get(&format!("{:08x}", f.entry.offset))))
                    .map_err(native::ImportError::Bad)?
            } else {
                emit_m2c::UnitLayouts::default()
            };
            // The structs the unit's functions name are part of the context
            // the printed function is made to agree with.
            let unit_opts = {
                let names: String = fns
                    .iter()
                    .filter_map(|f| docs.get(&format!("{:08x}", f.entry.offset)))
                    .map(emit_m2c::render_doc_text)
                    .collect();
                let definitions = struct_table.definitions(&names, &opts.context);
                if definitions.is_empty() {
                    opts.clone()
                } else {
                    emit_m2c::M2cOptions { context: format!("{}\n{definitions}", opts.context), ..opts.clone() }
                }
            };
            for f in fns {
                request.cancel.checkpoint(request.deadline)?;
                let key = format!("{:08x}", f.entry.offset);
                let doc = docs.get_mut(&key).ok_or_else(|| {
                    native_runtime::NativeRuntimeError(format!(
                        "missing decompilation for {}",
                        f.name
                    ))
                })?;
                doc.address = f.entry.clone();
                doc.revision = revision;
                if let Some(prototype) = doc.prototype.as_mut() {
                    register_params::augment(&request.config, request.language.as_str(), prototype, &doc.storage);
                }
                let stack = self.db.stack_variables(id, Some(&f.entry))?;
                let bytes = self.mem_native(binary, f.entry.offset, f.size as usize).unwrap_or_default();
                let machine_code = emit_m2c::MachineCode::new(request.language.as_str(), f.entry.offset, &bytes);
                let address_pairs = machine_code.address_pairs(|address| self.mem_native(binary, address, 1).is_ok());
                let inputs = emit_m2c::FuncInputs {
                    stack: &stack,
                    generated_extra: &[],
                    keep: &keep,
                    asserted_prototypes: Some(&asserted_prototypes),
                    gp: gp_at_entry.get(&f.entry.offset).copied(),
                    machine: Some(emit_m2c::Machine { code: &machine_code, constants: &address_pairs, names: &address_names }),
                };
                let emitted = emit_m2c::emit_doc_in_unit(doc, &inputs, &unit_opts, &layouts)
                    .map_err(native::ImportError::Bad)?;
                if emitted.irregular {
                    irregular_count += 1;
                }
                for warning in &emitted.warnings {
                    warnings.push(serde_json::json!({
                        "function": f.name, "address": f.entry.offset, "message": warning,
                    }));
                }
                rewrite_count += doc
                    .function_ir
                    .as_ref()
                    .into_iter()
                    .flat_map(|ir| &ir.passes)
                    .filter(|pass| pass.role == romwright_model::function_ir::PassRole::Transform)
                    .map(|pass| pass.items)
                    .sum::<usize>();
                text.push_str(&emitted.text);
                text.push_str("\n\n");
            }
            // The struct definitions the unit's text names, before all of it.
            let definitions = struct_table.definitions(&text, &opts.context);
            if !definitions.is_empty() {
                text.insert_str(0, &format!("{definitions}\n"));
            }
            if text.trim().is_empty() {
                continue;
            }
            if Path::new(unit).components().any(|part| !matches!(part, std::path::Component::Normal(_))) {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, format!("invalid output unit {unit:?}"))));
            }
            let path = outdir.join(format!("{unit}.c"));
            pending.push((path, text));
        }
        self.check_execution(&request)?;
        // Every document and every store-derived input belongs to the same
        // revision. No file is published until the complete batch validates.
        for (path, text) in pending {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, text).map_err(CoreError::Io)?;
            files.push(serde_json::json!({
                "file": path.display().to_string(),
            }));
        }

        Ok(serde_json::json!({
            "program": program,
            "files": files,
            "functions": functions.len(),
            "irregular": irregular_count,
            "semantic_rewrites": rewrite_count,
            "revision": revision,
            "artifact_digest": request.artifact_digest,
            "warnings": warnings,
        }))
    }

    /// Bytes at `vaddr` from the binary's mappings (native memory inspection).
    ///
    /// Uses a one-entry cache of the parsed import so viewport-sized reads
    /// don't re-read and re-discover the whole binary per call.
    pub fn mem_native(&self, binary: &Path, vaddr: u64, size: usize) -> Result<Vec<u8>> {
        let binary = binary.to_path_buf();
        let image = {
            let mut cache = self
                .native_cache
                .lock()
                .map_err(|_| std::io::Error::other("native memory cache lock poisoned"))?;
            let hit = cache.as_ref().map(|(p, _)| p == &binary).unwrap_or(false);
            if !hit {
                let opened = std::sync::Arc::new(session::ProgramImage::open(&binary)?);
                *cache = Some((binary.clone(), opened.clone()));
                opened
            } else {
                cache.as_ref().unwrap().1.clone()
            }
        };

        image
            .read(vaddr, size as u64)
            .ok_or_else(|| {
                CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("no mapping covers {vaddr:#x}..+{size:#x}"),
                ))
            })
    }

    /// Reads live target memory through Dolphin's GDB stub.
    ///
    /// The TCP connection is reused for successive viewport reads at the
    /// same endpoint. A failed request drops the connection so the next
    /// request starts cleanly.
    pub fn read_memory_live(
        &self,
        endpoint: &str,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        let endpoint = endpoint.trim();
        let mut cached = self
            .live_memory
            .lock()
            .map_err(|_| std::io::Error::other("live memory connection lock poisoned"))?;
        let reconnect = cached
            .as_ref()
            .map(|connection| connection.endpoint != endpoint)
            .unwrap_or(true);
        if reconnect {
            let client = romwright_debug::DolphinGdb::connect(endpoint)?;
            *cached = Some(LiveMemoryConnection {
                endpoint: endpoint.to_string(),
                client,
            });
        }
        let result = cached
            .as_mut()
            .expect("live-memory connection initialized")
            .client
            .read_memory(address, size);
        if result.is_err() {
            *cached = None;
        }
        result.map_err(CoreError::from)
    }
    /// Opens a program session: the binary mapped once, regions derived,
    /// metadata captured. Every interactive view and worker shares the
    /// image; repeated reads never re-parse or re-discover the file.
    pub fn open_session(&self, binary: &Path, program: &str) -> Result<session::ProgramSession> {
        let imp = native::load_native(binary)?;
        let image = std::sync::Arc::new(session::ProgramImage::open(binary)?);
        let metadata = session::SessionMetadata::from_import(&imp);
        Ok(session::ProgramSession {
            program: program.to_string(),
            image,
            metadata,
        })
    }

    /// Re-exports fresh facts from the bridge after an edit session.
    pub fn refresh_from_bridge(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        program: &str,
    ) -> Result<ProgramSummary> {
        let id = self.db.program_id(program)?;
        let functions = bridge.functions(session)?;
        let symbols = bridge.symbols(session)?;
        self.db.replace_symbols(id, &symbols)?;
        self.export(bridge, session, id, &functions)?;
        Ok(ProgramSummary {
            program: program.to_string(),
            functions: functions.len() as u64,
            language: self.db.program_language(id)?,
            compiler: self.db.program_compiler(id).unwrap_or_default(),
            phases: Vec::new(),
            flow: None,
            patterns: None,
            references_refused: 0,
            diagnostics: self.db.import_diagnostics(id)?,
            switch: None,
        })
    }

    /// Reads bytes through the bridge (memory lives in the JVM for Stage 1).
    pub fn read_memory(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        address: &str,
        size: u32,
    ) -> Result<Vec<u8>> {
        Ok(bridge.read_memory(session, address, size)?)
    }

    /// Decompiles through the bridge (native worker replaces this in Stage 3).
    pub fn decompile(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        address: &str,
    ) -> Result<String> {
        Ok(bridge.decompile(session, address)?)
    }

    /// Disassembles through the bridge (native SLEIGH replaces this in Stage 3).
    pub fn disassemble(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        address: &str,
        n: u32,
    ) -> Result<Vec<DisasmRow>> {
        Ok(bridge.disassemble(session, address, n)?)
    }

    fn export(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        id: ProgramId,
        functions: &[FunctionRow],
    ) -> Result<()> {
        self.db.replace_functions(id, functions)?;
        // One batched round-trip instead of one RPC per function: the per-call
        // overhead after analysis dominated the import time otherwise.
        let (functions, xrefs, comments, datatypes, signatures, stack_variables) =
            bridge.export_facts(session)?;
        self.db.replace_functions(id, &functions)?;
        self.db.replace_xrefs(id, &xrefs)?;
        self.db.replace_comments(id, &comments)?;
        self.db.replace_datatypes(id, &datatypes)?;
        // Ghidra's recovered stack frame. Its decompiler prints these names,
        // so a store without them cannot be compared against one with them.
        self.db.replace_stack_variables(id, &stack_variables)?;
        // What stock says it recovered, recorded as stock's own fact: an
        // oracle store that holds no signature makes every comparison against
        // it measure silence (m4-018).
        for row in &signatures {
            let Some(signature) = row.signature.as_deref().filter(|text| !text.is_empty())
            else {
                continue;
            };
            let Ok(offset) = u64::from_str_radix(row.entry.trim_start_matches("0x"), 16)
            else {
                continue;
            };
            self.db.set_prototype(
                id,
                &romwright_model::PrototypeRow {
                    function: romwright_model::Address::ram(offset),
                    signature: signature.to_string(),
                    calling_convention: row.calling_convention.clone(),
                    return_type: row.return_type.clone(),
                    provenance: romwright_model::FactProvenance {
                        kind: romwright_model::FactKind::Asserted,
                        source: "ghidra-bridge:recovered-signature".into(),
                        confidence: None,
                    },
                },
            )?;
        }
        Ok(())
    }
}

/// Parses a function sort spec: "entry" | "name" | "size" with an optional
/// ":asc"/":desc" suffix.
fn parse_function_sort(text: &str) -> Result<(romwright_db::FunctionSort, bool)> {
    let (key, direction) = match text.split_once(':') {
        Some((key, dir)) => (
            key,
            match dir {
                "asc" => true,
                "desc" => false,
                _ => return Err(CoreError::InvalidSortKey(text.into())),
            },
        ),
        None => (text, true),
    };
    let key = romwright_db::FunctionSort::parse(key)
        .ok_or_else(|| CoreError::InvalidSortKey(text.into()))?;
    Ok((key, direction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn collaboration_rename_applies_once_through_core() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let core = Core::open(&std::env::temp_dir().join(format!("romwright-core-collab-{nonce}")))
            .unwrap();
        let id = core
            .store_handle()
            .unwrap()
            .upsert_program(
                "p",
                "x86:LE:64:default",
                &romwright_model::Provenance {
                    producer: "test".into(),
                    upstream_version: "test".into(),
                },
            )
            .unwrap();
        core.store_handle()
            .unwrap()
            .replace_functions(
                id,
                &[FunctionRow {
                    entry: Address::ram(0x400000),
                    name: "FUN_00400000".into(),
                    size: 4,
                    signature: None,
                    traced: false,
            calling_convention: None,
                }],
            )
            .unwrap();
        let operation = CollaborationOp {
            op_id: "rename-1".into(),
            actor: "tester".into(),
            lamport: 1,
            kind: "rename".into(),
            payload: serde_json::json!({
                "address": "00400000",
                "name": "main"
            })
            .to_string(),
            applied: false,
            provenance: "test".into(),
        };
        assert!(core.append_collaboration_op("p", &operation).unwrap());
        assert!(core.apply_collaboration_op("p", "rename-1").unwrap());
        assert_eq!(core.functions("p").unwrap()[0].name, "main");
        assert!(!core.apply_collaboration_op("p", "rename-1").unwrap());
    }
    #[test]
    fn live_memory_reuses_dolphin_connection() {
        fn frame(payload: &[u8]) -> Vec<u8> {
            let checksum = payload.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
            let mut result = Vec::with_capacity(payload.len() + 5);
            result.push(b'$');
            result.extend_from_slice(payload);
            result.extend_from_slice(format!("#{checksum:02x}").as_bytes());
            result
        }

        fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
            let mut start = [0u8; 1];
            stream.read_exact(&mut start).unwrap();
            assert_eq!(start[0], b'$');
            let mut payload = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).unwrap();
                if byte[0] == b'#' {
                    break;
                }
                payload.push(byte[0]);
            }
            let mut checksum = [0u8; 2];
            stream.read_exact(&mut checksum).unwrap();
            payload
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for (request, response) in [(b"m10,2".as_slice(), b"0102".as_slice()),
                                         (b"m20,2".as_slice(), b"a0b0".as_slice())] {
                assert_eq!(read_request(&mut stream), request);
                stream.write_all(b"+").unwrap();
                stream.write_all(&frame(response)).unwrap();
                let mut ack = [0u8; 1];
                stream.read_exact(&mut ack).unwrap();
                assert_eq!(ack[0], b'+');
            }
        });

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let project = std::env::temp_dir().join(format!("romwright-core-live-{nonce}"));
        let core = Core::open(&project).unwrap();
        assert_eq!(core.read_memory_live(&endpoint, 0x10, 2).unwrap(), vec![1, 2]);
        assert_eq!(core.read_memory_live(&endpoint, 0x20, 2).unwrap(), vec![0xa0, 0xb0]);
        server.join().unwrap();
    }
}
