//! Core data model.
//!
//! Addresses are address-space identity plus offset (spec 8.3): a plain `u64`
//! cannot name overlays, registers, or split spaces, and Ghidra's own model
//! does not pretend they can. Entities use compact stable IDs (spec 8.2).

pub mod evidence;
pub mod function_ir;
pub mod matching;
/// Stable ID for a program inside a project.
pub mod provenance;
pub mod structs;
pub mod type_evidence;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ProgramId(pub u64);

/// Stable ID for a function inside a program.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct FunctionId(pub u32);

/// Stable ID for a symbol inside a program.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SymbolId(pub u32);

/// Address-space identity, including non-loaded metadata. Callers must not
/// silently project offsets from other spaces into RAM.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default, serde::Serialize, serde::Deserialize)]
pub enum AddressSpace {
    /// Main loaded memory.
    #[default]
    Ram,
    /// External (linked library) space.
    External,
    /// Other spaces Ghidra knows: registers, uniques, constants, overlays.
    Other(String),
}

impl AddressSpace {
    /// Parses the space portion of a Ghidra address string (`"00400466"` or
    /// `"ram:00400466"`). Ghidra prints bare hex offsets for the default space.
    pub fn from_ghidra_str(s: &str) -> Self {
        match s.split_once(':') {
            Some((space, _)) if space.eq_ignore_ascii_case("ram") => Self::Ram,
            Some((space, _)) if space.eq_ignore_ascii_case("ext") => Self::External,
            Some((space, _)) => Self::Other(space.to_string()),
            None => Self::Ram,
        }
    }
}

/// A resolved address: space identity plus offset.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default, serde::Serialize)]
pub struct Address {
    /// Address space the offset is relative to.
    pub space: AddressSpace,
    /// Offset into the space.
    pub offset: u64,
}

impl Address {
    /// Builds a RAM address, the overwhelmingly common case.
    pub fn ram(offset: u64) -> Self {
        Self {
            space: AddressSpace::Ram,
            offset,
        }
    }

    /// Parses a canonical RAM hex string (`"00400466"`, `"0x400466"`),
    /// the compact storage convention for RAM address cells.
    pub fn parse_ram_hex(s: &str) -> Option<Self> {
        let hex = s.trim().trim_start_matches("0x");
        if hex.is_empty() {
            return None;
        }
        u64::from_str_radix(hex, 16).ok().map(Self::ram)
    }

    /// The offset-only hex form (`"00400466"`), without space identity.
    pub fn hex(&self) -> String {
        format!("{:08x}", self.offset)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

// The wire/storage serialization edge: Ghidra-style hex strings
// ("00400466", "ram:00400466") and the structured form both deserialize.
// Serde's derive accepts only the structured form; the JSON-RPC bridge and
// older consumers talk in strings, so this visitor keeps them compatible.
impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AddrVisitor;
        impl<'de> serde::de::Visitor<'de> for AddrVisitor {
            type Value = Address;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a hex address string or {space, offset} object")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Address, E> {
                // LAST colon: Ghidra overlay/space names can contain
                // colons (".annobin.notes::00000000").
                let (space, offset_part) = match v.rsplit_once(':') {
                    Some((sp, off)) => (AddressSpace::from_ghidra_str(sp), off),
                    None => (AddressSpace::Ram, v),
                };
                let hex = offset_part.trim_start_matches("0x");
                let offset = u64::from_str_radix(hex, 16)
                    .map_err(|_| E::custom(format!("bad hex address: {v}")))?;
                Ok(Address { space, offset })
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Address, A::Error> {
                let mut space = AddressSpace::Ram;
                let mut offset = 0u64;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "space" => space = map.next_value::<AddressSpace>()?,
                        "offset" => offset = map.next_value::<u64>()?,
                        _ => {
                            map.next_value::<serde_json::Value>()?;
                        }
                    }
                }
                Ok(Address { space, offset })
            }
        }
        deserializer.deserialize_any(AddrVisitor)
    }
}

/// One function row as the Core API returns it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FunctionRow {
    /// Entry address (typed; formatted only at serialization edges).
    pub entry: Address,
    /// Display name, primary symbol.
    pub name: String,
    /// Number of bytes in the function body footprint.
    pub size: u64,
    /// Recovered prototype string, when analysis produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Whether an emulator trace covered this function: set by
    /// `import-trace` when a trace event lands inside the body. A
    /// reader's projection of the `traced` column, like
    /// `calling_convention`: writing a function row never sets it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub traced: bool,
    /// The convention fact held for this function, when there is one. A
    /// reader's projection of `CallingConventionRow`: the fact table owns the
    /// value and its provenance, so writing a function row never sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<String>,
}

/// One cross-reference record.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct XrefRow {
    /// Source (incoming) address (typed).
    pub from: Address,
    /// Destination address (typed).
    pub to: Address,
    /// Ghidra reference type name (`UNCONDITIONAL_CALL`, `DATA`, ...).
    pub kind: String,
    /// Name of the function containing the source address, resolved at
    /// query time; None for data xrefs or unmapped sources.
    pub function: Option<String>,
    /// Ownership, producing pass, and optional confidence of this fact.
    #[serde(default)]
    pub provenance: FactProvenance,
}

/// Assertions survive replacement of inferred analysis results.
#[derive(
    Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    Inferred,
    #[default]
    Asserted,
}

#[derive(Clone, Debug, Default, serde::Deserialize, PartialEq)]
pub struct FactProvenance {
    pub kind: FactKind,
    pub source: String,
    /// A supplied confidence in [0, 1]; None means unknown, not zero.
    #[serde(default)]
    pub confidence: Option<f64>,
}

impl FactProvenance {
    /// The shared sentence for this fact's class (`provenance::CLASSES`),
    /// or `None` when nothing explains the source. Every surface that shows
    /// a fact reads this rather than the serialized `explanation` field.
    pub fn explanation(&self) -> Option<&'static str> {
        provenance::explain(&self.source)
    }

    /// What kind of evidence the class rests on, or `None` for an unknown
    /// source.
    pub fn evidence(&self) -> Option<provenance::EvidenceKind> {
        provenance::evidence(&self.source)
    }
}

impl serde::Serialize for FactProvenance {
    /// Adds `explanation` from the shared table: a consumer that shows a fact
    /// can always say what proved it, without mapping the string itself.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut row = serializer.serialize_struct("FactProvenance", 5)?;
        row.serialize_field("kind", &self.kind)?;
        row.serialize_field("source", &self.source)?;
        row.serialize_field("confidence", &self.confidence)?;
        row.serialize_field("explanation", &self.explanation())?;
        // What kind of evidence this is: the image said so, the decoder proved
        // it, or a pass concluded it.
        row.serialize_field("evidence", &self.evidence())?;
        row.end()
    }
}

/// One program a project holds, for an inventory rather than a single answer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProgramRow {
    pub program: String,
    pub language: String,
    /// Toolchain that produced the image (`mwcc_233_163`, `gcc`, `msvc`,
    /// ...): recorded at import from the image's own markers, empty when
    /// nothing in the image names one.
    #[serde(default)]
    pub compiler: String,
    /// Functions the store holds for it.
    pub functions: u64,
    /// Store revision, which moves when a fact changes.
    pub revision: u64,
}

/// Where one address lands in one program: the region that maps it, and the
/// function containing it when a function does. Images overlap -- a PE and an
/// ELF can both start at `0x400000`, and two DS overlays load into one RAM
/// window -- so an address alone names no program and no module. One row is
/// answered per (program, covering module); a program with no module row
/// over the address answers one row with `module: None`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct LocationRow {
    pub program: String,
    pub language: String,
    pub region: MemoryRegion,
    /// The function whose body holds the address, or `None` when none does.
    #[serde(default)]
    pub function: Option<String>,
    /// The overlay module owning the address, when the program declares
    /// modules (REL sections, PSX overlays). `None` for single-module
    /// programs and for addresses no module covers.
    #[serde(default)]
    pub module: Option<String>,
    /// The `modules` row behind `module`. Two overlays of one window carry
    /// the same name in no program but distinct ids in a project, so the id
    /// is what a caller keeps to say *which* overlay an address was in.
    #[serde(default)]
    pub module_id: Option<i64>,
}

/// One overlay module a program holds: a REL image, a PSX overlay, one CPU
/// of a multi-image container. A module is a load extent with a name, so
/// `locate` can say *which* overlay an address belongs to.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ModuleRow {
    /// Store-assigned id; 0 on the way in means "assign one".
    pub module_id: i64,
    /// Program that owns this module.
    pub program: String,
    /// Module name (REL name table, overlay file stem, ...).
    pub name: String,
    /// Module kind: `rel`, `overlay`, ...
    #[serde(default)]
    pub kind: String,
    /// File the module came from, when it has one.
    #[serde(default)]
    pub file_id: String,
    /// Where the module loads.
    pub load_vaddr: Address,
    /// Loaded size in bytes.
    pub size: u64,
    /// File offset of the module's first byte.
    #[serde(default)]
    pub file_off: u64,
    /// False for a module described but not resident (declared windows).
    #[serde(default = "resident_default")]
    pub resident: bool,
}

fn resident_default() -> bool {
    true
}

/// One reference from an address in one module to an address in another:
/// a REL relocation against the DOL, a call from a main image into an
/// overlay. `to_module_id` is `None` for a target outside the store
/// (the DOL a REL links against), named by `to_external` instead.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ModuleXrefRow {
    pub module_id: i64,
    /// Source address (typed).
    pub from_addr: Address,
    /// Owning module of the target, when the store holds it.
    pub to_module_id: Option<i64>,
    /// Destination address (typed).
    pub to_addr: Address,
    /// External target name (`module0` for the DOL), when the store does
    /// not hold the target module.
    #[serde(default)]
    pub to_external: String,
    /// Reference kind (`rel-import`, `call`, ...).
    #[serde(default)]
    pub kind: String,
}

/// One symbol row.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SymbolRow {
    /// Symbol name.
    pub name: String,
    /// Address it anchors (typed).
    pub address: Address,
    /// True for symbols naming external/library functions.
    pub external: bool,
    /// Ghidra source type: USER_DEFINED, ANALYSIS, IMPORTED, DEFAULT, ...
    pub source: String,
}

/// Disassembly line: address plus rendered text.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DisasmRow {
    /// Instruction address (typed).
    pub address: Address,
    /// Rendered mnemonic + operands, Ghidra style.
    pub text: String,
}

/// Decompiler token kinds (from the packed document's element ids — pinned
/// from ElementId.java; WORKER-004).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TokenKind {
    Value,
    Variable,
    Op,
    Syntax,
    FuncName,
    Type,
    Comment,
    Label,
    Field,
    Bitfield,
    Break,
    Other,
}

/// One structured decompiler token: text + kind + any entity mapping the
/// packed document carried (WORKER-004).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DecompToken {
    pub text: String,
    pub kind: TokenKind,
    /// Ghidra syntax color class (0..7; ATTRIB_COLOR).
    pub color: u8,
    /// Entity name when the token carried ATTRIB_NAME.
    pub symbol: Option<String>,
    /// Native symbol identity inherited from a declaration's SYMREF.
    pub symbol_id: Option<u64>,
    /// Entity address when the token carried space+off attributes.
    pub address: Option<Address>,
    /// Both native identities may occur on one token. They are response-local,
    /// not database IDs; attribute order must not discard either identity.
    pub varnode: Option<function_ir::ValueId>,
    pub operation: Option<function_ir::OperationId>,
    /// Data-type id carried by ClangTypeToken/ClangFieldToken.
    pub datatype_id: Option<u64>,
    /// Number of characters of indentation carried by ClangBreak.
    pub indent: Option<i64>,
}

/// A data-type reference or inline shape carried by a recovered prototype.
/// IDs are decompiler identities, not durable database IDs. Named references
/// may omit size and metatype; absence must not be interpreted as void.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecompType {
    pub name: Option<String>,
    pub id: Option<u64>,
    pub size: Option<u64>,
    pub metatype: Option<String>,
    pub element_count: Option<u64>,
    pub target: Option<Box<DecompType>>,
    pub prototype: Option<Box<FuncProto>>,
}

/// One recovered input parameter, ordered by the native symbol category index.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuncParam {
    pub ordinal: u32,
    pub name: String,
    pub data_type: DecompType,
}

/// Native prototype facts, independent of rendered C.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuncProto {
    pub calling_convention: String,
    pub return_type: DecompType,
    pub parameters: Vec<FuncParam>,
    pub variadic: bool,
    /// A positive native no-return hint; false does not prove a return path.
    pub no_return: bool,
    /// Set when the parameter list did not come from the decompiler's own
    /// model recovery, naming the pass that supplied it instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_source: Option<String>,
}

/// Recovered indirect branch targets, in native table order. Several case
/// entries may share a target; this does not claim a default-case identity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JumpTable {
    pub branch: Address,
    pub targets: Vec<Address>,
}

/// A local symbol the decompiler mapped to fixed storage. A name of the form
/// `in_<REGISTER>` marks an "irregular input": dataflow found the function
/// reads that register before writing it while the prototype model has no
/// slot for it (`Scope::buildDefaultName`, database.cc:2470-2478 of the
/// pinned tree).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StorageSymbol {
    pub name: String,
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

/// The structured decompiler document for one function (WORKER-004): a
/// token stream the UI renders without re-parsing C text.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DecompDoc {
    pub tokens: Vec<DecompToken>,
    /// Recovered native facts; absent for legacy or incomplete documents.
    #[serde(default)]
    pub prototype: Option<FuncProto>,
    /// Native call-site signatures keyed by p-code operation, not guessed from C.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub call_prototypes: std::collections::BTreeMap<function_ir::OperationId, FuncProto>,
    /// Native callee entry addresses; absent for unresolved indirect calls.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub call_targets: std::collections::BTreeMap<function_ir::OperationId, Address>,
    /// None means unavailable metadata; an empty list means no recovered tables.
    #[serde(default)]
    pub jump_tables: Option<Vec<JumpTable>>,
    pub address: Address,
    pub revision: u64,
    /// Local symbols with fixed storage; empty when the document predates
    /// storage capture or the function has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<StorageSymbol>,
    /// Native typed SSA and ordered basic-block graph; never inferred from C.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_ir: Option<function_ir::FunctionIr>,
}

/// Structural row kinds emitted by the core listing source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListingRowKind {
    Instruction,
    FunctionHeader,
    BbSeparator,
    Data,
    Label,
}

/// One listing row (CORE-007): stable id (= instruction address),
/// typed address, structural kind, and rendered text a virtualized view shows.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ListingRow {
    /// Stable row identity: the source address offset.
    pub stable_id: u64,
    pub address: Address,
    /// Structural kind from the listing source.
    pub kind: ListingRowKind,
    /// Rendered mnemonic + operands or structural label.
    pub text: String,
    /// Raw instruction bytes as hex; empty when the source cannot read
    /// the image or the row is not an instruction.
    pub bytes: String,
}

/// One listing window (CORE-007): bounded rows + overscan for a
/// virtualized view.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ListingWindow {
    pub rows: Vec<ListingRow>,
    pub start: Address,
    pub count: u32,
    /// Rows fetched beyond the window (above+below the visible set).
    pub overscan: u64,
}

/// One recorded command (CORE-006): the undoable mutation journal entry.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JournalEntry {
    /// Monotonic sequence within the program.
    pub seq: u64,
    /// Command kind: "rename" (the CORE-006 first command).
    pub kind: String,
    /// Command payload (JSON; kind-specific).
    pub payload: String,
    /// Undo payload (JSON; applied by the undo dispatcher).
    pub undo_payload: String,
    /// 1 once undone.
    pub done: bool,
}

/// One durable change record: the mutation stream consumers watch
/// (review CORE-005: every change carries a revision, and revisions are
/// observable).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RevisionEvent {
    /// Revision the program reached with this change.
    pub revision: u64,
    /// Machine kind: "rename", "replace-functions", ...
    pub kind: String,
    /// Human/detail payload (new name, replaced row count, ...).
    pub detail: String,
}

/// A paged query result: a bounded window plus cursor info and the
/// revision the window was read at (review CORE-004: views never preload).
#[derive(Clone, Debug, serde::Serialize)]
pub struct Page<T> {
    /// The window of rows (at most `limit`).
    pub rows: Vec<T>,
    /// Offset of the first row in the full result.
    pub offset: u64,
    /// Total row count when known cheaply (COUNT), else `None`.
    pub total: Option<u64>,
    /// Store revision the window was read at (CORE-005 precursor).
    pub revision: u64,
}

/// How complete a program's facts are, at one revision.
///
/// The contract a consumer needs is "answer now, and say what is missing":
/// a query never waits for analysis, and this rides alongside it so the
/// answer can be marked provisional rather than presented as final.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnalysisStatus {
    pub program: String,
    /// Store revision these counts were read at.
    pub revision: u64,
    pub functions: u64,
    /// Bodies somebody walked, whether by whole-image analysis or on demand.
    pub analysed: u64,
    /// Entries the image declared that nobody has walked yet.
    pub seeded: u64,
    /// Entries a walk could not decode at all.
    pub undecodable: u64,
    /// True while any seed remains: the answer is what is known so far.
    pub stale: bool,
}

/// Wall time of one import phase, in seconds. Phases are measured, never
/// estimated: a consumer that reports a budget must report these numbers.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PhaseTiming {
    /// Phase name (`parse`, `discovery`, `references`, `store`).
    pub phase: String,
    /// Measured wall time in seconds.
    pub seconds: f64,
}

/// What the flow phase asked of its decoders. Batched flow is a claim
/// about `instructions` per `requests`, which no machine speed can flatter.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct FlowStats {
    /// Batches handed to the in-process SLEIGH flow decoders.
    pub requests: u64,
    /// Instructions decoded for the flow walk.
    pub instructions: u64,
    /// Discovery rounds that ran. Every phase timing is a sum over these,
    /// because each round re-walks what the previous one grew, so a
    /// per-pass budget must divide by this.
    #[serde(default)]
    pub rounds: u64,
}

/// What a byte-pattern search proposed and what survived the prerequisites.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PatternStats {
    /// Matches the pattern search reported.
    pub hits: u64,
    /// Matches that became function candidates.
    pub accepted: u64,
    /// Why the rest were refused, by prerequisite name.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub refused: std::collections::BTreeMap<String, u64>,
}

/// How much a diagnostic changes what the import stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticSeverity {
    /// Nothing is missing that could have been there: an image with no
    /// symbol table, an import asked not to analyse.
    Info,
    /// A stage ran and some items failed, the same way every time on the
    /// same inputs (a function the decompiler rejects). The rest stands,
    /// and the result is safe to reuse.
    Partial,
    /// A stage did not run, or stopped for reasons outside the inputs (a
    /// console that did not start, a worker that crashed). The facts are
    /// incomplete, and the import is never cached.
    Degraded,
}

/// One thing an import could not do.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportDiagnostic {
    pub severity: DiagnosticSeverity,
    /// The stage that reported it (`discovery`, `references`, `switch`, ...).
    pub stage: String,
    pub message: String,
}

/// Program summary returned by import/open.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProgramSummary {
    /// Program name in the project.
    pub program: String,
    /// Function count discovered by analysis.
    pub functions: u64,
    /// Ghidra language ID, e.g. `x86:LE:64:default`.
    pub language: String,
    /// Toolchain that produced the image, as recorded in the store.
    /// Empty when nothing in the image named one.
    #[serde(default)]
    pub compiler: String,
    /// Measured phase wall times; empty for paths that do not measure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phases: Vec<PhaseTiming>,
    /// Console request accounting for the flow phase, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<FlowStats>,
    /// Byte-pattern accounting for the pattern phase, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patterns: Option<PatternStats>,
    /// Ranges whose reference query the console refused, when any did.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub references_refused: u64,
    /// What the import could not do, and how much that matters. Empty when
    /// every stage ran in full. Stored with the program, so a cached import
    /// reports the same diagnostics as the analysis that produced it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<ImportDiagnostic>,
    /// Switch-recovery accounting: dispatches value-set analysis resolved,
    /// and dispatches it refused and handed to the decompiler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch: Option<SwitchStats>,
}

/// What each switch path answered.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SwitchStats {
    pub vsa_resolved: u64,
    pub vsa_refused: u64,
    /// Decompiler-round owners skipped by the owner budget.
    pub decompiler_skipped: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    /// Producing component: always `ghidra-bridge` in Stage 1.
    pub producer: String,
    /// Pinned upstream version.
    pub upstream_version: String,
}

/// A stored comment (from the bridge export).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CommentRow {
    /// Code unit address (typed).
    pub address: Address,
    /// Owning function entry (typed).
    pub function: Address,
    /// Comment kind: "eol" | "pre" | "plate" (bridge reports its kind).
    pub kind: String,
    /// Comment text.
    pub text: String,
}

/// A stored data type (from the bridge export; name + free text definition).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DataTypeRow {
    pub name: String,
    pub definition: String,
}

/// A string discovered in loaded memory or a string table.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StringRow {
    pub address: Address,
    pub value: String,
    pub kind: String,
}

/// One mapped binary region used by the memory map and hex view.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MemoryRegion {
    pub name: String,
    pub start: Address,
    pub size: u64,
    pub permissions: String,
    pub source: String,
}

/// A full-text search result across durable analysis facts.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    pub address: Option<Address>,
    pub kind: String,
    pub name: String,
    pub context: String,
}

/// A function graph vertex.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GraphNode {
    pub address: Address,
    pub name: String,
}

/// A function graph edge.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: Address,
    pub to: Address,
    pub kind: String,
}

/// User bookmark attached to an address.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BookmarkRow {
    pub address: Address,
    pub label: String,
    pub comment: String,
}

/// One byte patch with both source and active values retained.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PatchRow {
    pub address: Address,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub enabled: bool,
}

/// Primitive semantics, independent of display names and legacy kind labels.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveKind {
    SignedInteger,
    UnsignedInteger,
    Float,
    Boolean,
    Void,
}

impl PrimitiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignedInteger => "signed_integer",
            Self::UnsignedInteger => "unsigned_integer",
            Self::Float => "float",
            Self::Boolean => "boolean",
            Self::Void => "void",
        }
    }
}

/// A named data type with its composite metadata.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeDefRow {
    pub name: String,
    pub kind: String,
    pub definition: String,
    pub size: Option<u64>,
    pub alignment: Option<u64>,
    pub base_type: Option<String>,
    pub provenance: String,
    /// None preserves an unclassified legacy primitive without guessing.
    #[serde(default)]
    pub primitive: Option<PrimitiveKind>,
    /// Declared array length; zero and an unknown length are distinct.
    #[serde(default)]
    pub element_count: Option<u64>,
}

/// One field in a composite type.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeFieldRow {
    pub type_name: String,
    pub ordinal: u32,
    pub field_name: String,
    pub offset: u64,
    pub size: Option<u64>,
    pub type_ref: Option<String>,
}

/// Function prototype and calling convention.
/// One location whose contents a fact types: an address, what is there and how
/// wide it is. Ghidra holds the same as defined data, and composes labels from
/// it (`SymbolUtilities.getDynamicDataName`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct DataDefinitionRow {
    pub address: Address,
    /// A core type name, e.g. `pointer`.
    pub data_type: String,
    /// Width in bytes.
    pub size: u64,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct PrototypeRow {
    pub function: Address,
    pub signature: String,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    #[serde(default)]
    pub provenance: FactProvenance,
}

/// A function's return behavior is unknown unless a producer supplies a fact.
/// `no_return = false` can explicitly override an inferred non-returning flag.
/// One call site an image declares protected by an exception handler, and the
/// handler it branches to. The range is the call site's own, inclusive at both
/// ends, exactly as `.gcc_except_table` states it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExceptionSiteRow {
    /// Entry of the function the frame describes.
    pub function: Address,
    /// First address of the protected range.
    pub start: Address,
    /// Last address of the protected range, inclusive.
    pub end: Address,
    /// The handler the call site enters when it throws.
    pub landing_pad: Address,
    pub provenance: FactProvenance,
}

/// One instruction whose flow a fact corrects: the raw decode says "branch",
/// the image's own structure says the transfer behaves like a call. Ghidra
/// holds the same fact per instruction (`Instruction.getFlowOverride`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct FlowOverrideRow {
    /// The branch instruction.
    pub address: Address,
    /// Ghidra's override name, e.g. `callreturn`.
    pub kind: String,
    pub provenance: FactProvenance,
}

/// How the platform enters a function: a named model the language's own
/// compiler spec declares, not an invented signature. The operating system
/// enters a process outside the C convention, and the ABI says where.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CallingConventionRow {
    pub function: Address,
    /// A model name the compiler spec declares (`processEntry`, `__stdcall`).
    pub convention: String,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ReturnBehaviorRow {
    pub function: Address,
    pub no_return: bool,
    pub provenance: FactProvenance,
}

/// How a thunk's destination was proven. A direct thunk transfers to another
/// image function's entry; a linkage thunk leaves the image through a
/// loader-recorded pointer slot.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThunkKind {
    Direct,
    Linkage,
}

impl ThunkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ThunkKind::Direct => "direct",
            ThunkKind::Linkage => "linkage",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "direct" => Some(ThunkKind::Direct),
            "linkage" => Some(ThunkKind::Linkage),
            _ => None,
        }
    }
}

/// A function whose whole body transfers to one proven destination. Tail calls
/// from inside a larger body are not thunks and never produce this fact.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ThunkRow {
    pub function: Address,
    /// The thunked function entry, or the imported pointer slot for linkage.
    pub thunked: Address,
    pub kind: ThunkKind,
    pub provenance: FactProvenance,
}

/// Structural measurements of one function's body, taken while it was
/// decoded. These are the facts a whole-program diff matches on: they are
/// invariant to where the code was loaded, unlike an address, and they need
/// no decompiler, unlike a rendered body.
///
/// `blocks` and `edges` follow Ghidra's basic-block model
/// (`BasicBlockModel.hasEndOfBlockFlow`): a jump or a terminal instruction
/// ends a block and a branch target starts one, while a call does neither.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FunctionFeatureRow {
    pub function: Address,
    /// Instructions decoded inside the body.
    pub instructions: u32,
    /// Basic blocks in the body.
    pub blocks: u32,
    /// Intra-function control-flow edges between those blocks.
    pub edges: u32,
    /// Back edges: intra-function edges to an address at or before the
    /// branching instruction. A loop count is one of the few structural
    /// facts that survives a change of optimisation level.
    pub loops: u32,
    /// Instructions in the largest block of the body.
    pub max_block: u32,
    /// Digest of the body bytes exactly as the image holds them. Equal
    /// digests are the same code at the same load address.
    pub body_digest: String,
    /// Digest of the body's decoded shape -- the sequence of instruction
    /// lengths and flow kinds, with no addresses in it. Equal digests are
    /// the same code, wherever it was loaded and however it was relocated.
    pub shape_digest: String,
    /// Digest of the body bytes with relocations and image addresses
    /// masked: loader-written bytes read zero, and a pc-relative field
    /// naming an image address reads zero. Equal digests are the same
    /// instructions with the same constants, however they were loaded or
    /// relocated -- the tier-0 diff anchor between the body (same address
    /// only) and the shape (lengths and flow kinds only).
    pub masked_digest: String,
}

/// A BSim-style semantic signature of one function's p-code data-flow,
/// taken at demand time rather than at import: p-code needs a loaded
/// console, which the whole-image import does not keep open per function.
/// `signature` is the hex of the fixed-size hashed feature-count vector
/// (`romwright_diff::semantic`), so two builds of the same source compare by
/// what they compute rather than how they encode it. `ops` is how many
/// p-code operations were hashed; a function nobody decoded gets no row,
/// for the same reason an unmeasured body gets no feature row.
/// `constants` are the distinct literal operands of that p-code worth
/// comparing across builds (`romwright_diff::semantic::constants`): magic
/// values and masks survive a change of compiler where counts do not.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SemanticSignatureRow {
    pub function: Address,
    pub signature: String,
    pub ops: u32,
    #[serde(default)]
    pub constants: Vec<u64>,
}

/// A name a signature database claimed for a function, with the evidence.
/// `confidence` is the share of the pattern that was actually compared.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SignatureMatchRow {
    pub function: Address,
    pub name: String,
    /// Exact package build the signature was extracted from.
    pub package: String,
    pub license: String,
    pub compared_bytes: u64,
    pub confidence: f64,
    pub provenance: FactProvenance,
    /// Exact imported image and loader inputs compared by the signature pass.
    /// Older unbound matches are display evidence, not rewrite authority.
    pub input: Option<ProgramInput>,
}

/// An explicit compiler invocation. Arguments are passed directly, never to a
/// shell. Source and output operands are supplied by the matching runner.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BuildRecipe {
    pub compiler: String,
    pub arguments: Vec<String>,
    pub environment: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchingStatus {
    CompileFailed,
    DiffFailed,
    Compared,
}

/// Immutable evidence for a source-to-object comparison. Every digest names
/// captured bytes in the project's artifact store, not a mutable source path.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct MatchingRunRecord {
    pub revision: u64,
    pub target_digest: String,
    pub candidate_digest: Option<String>,
    pub source_digest: String,
    pub context_digest: String,
    pub compiler_digest: String,
    pub compiler_version: String,
    pub recipe: BuildRecipe,
    /// Complete arguments used, including source/output operands.
    #[serde(default)]
    pub compile_arguments: Vec<String>,
    #[serde(default)]
    pub version_arguments: Vec<String>,
    #[serde(default)]
    pub source_path: String,
    #[serde(default)]
    pub working_directory: String,
    /// Workspace-relative input paths and their immutable contents.
    #[serde(default)]
    pub files: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub tools: std::collections::BTreeMap<String, matching::ToolRequirement>,
    pub objdiff_digest: String,
    pub objdiff_version: String,
    pub raw_result: serde_json::Value,
    pub status: MatchingStatus,
    pub diagnostics: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct MatchingRun {
    pub id: u64,
    pub created_at: String,
    #[serde(default)]
    pub imported: bool,
    pub record: MatchingRunRecord,
}

/// Loader inputs captured when a program is imported. The selector is the
/// exact container image id, independent of the editable program name or base.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProgramInput {
    pub source_path: String,
    pub binary_digest: String,
    pub image_selector: String,
    pub map_digest: Option<String>,
    pub raw: Option<(u64, String)>,
    pub keys_digest: Option<String>,
}

/// Which Itanium ABI type_info shape described a class, and therefore what
/// base information the image carries.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassKind {
    /// `__class_type_info`: no bases.
    Plain,
    /// `__si_class_type_info`: one public, non-virtual base at offset zero.
    SingleBase,
    /// `__vmi_class_type_info`: any other base layout.
    MultipleBase,
}

impl ClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ClassKind::Plain => "class",
            ClassKind::SingleBase => "single_base",
            ClassKind::MultipleBase => "multiple_base",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "class" => Some(ClassKind::Plain),
            "single_base" => Some(ClassKind::SingleBase),
            "multiple_base" => Some(ClassKind::MultipleBase),
            _ => None,
        }
    }
}

/// One base of a recovered class, as the ABI's base_class_type_info states it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ClassBase {
    pub typeinfo: Address,
    /// Mangled type name of the base, or the empty string when its typeinfo
    /// lives outside this image.
    pub mangled: String,
    /// Byte offset of the base within the derived object, or the virtual-base
    /// offset slot when `virtual_base` is set.
    pub offset: i64,
    pub virtual_base: bool,
    pub public_base: bool,
}

/// A recovered class. RTTI-less membership does not imply ABI metadata exists.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ClassRow {
    /// ABI type descriptor, absent for classes known only through members.
    pub typeinfo: Option<Address>,
    /// Proven primary vtable start; absent until its binding is established.
    pub vtable: Option<Address>,
    /// Demangled name where the Itanium grammar this build parses covers it,
    /// otherwise the mangled form.
    pub name: String,
    pub mangled: String,
    pub kind: ClassKind,
    /// Virtual function slots after the address point.
    pub vtable_slots: u64,
    pub bases: Vec<ClassBase>,
    pub provenance: FactProvenance,
}

/// One recovered stack variable.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StackVariableRow {
    pub function: Address,
    pub ordinal: u32,
    pub name: String,
    pub storage: String,
    pub type_name: Option<String>,
    pub offset: Option<i64>,
    pub size: Option<u64>,
}

/// A typed dependency edge retained with provenance.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeLinkRow {
    pub source: String,
    pub target: String,
    pub kind: String,
    pub provenance: String,
}

/// Type graph node used by the type manager.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeGraphNode {
    pub name: String,
    pub kind: String,
    pub size: Option<u64>,
}

/// One installed SLEIGH processor/language variant.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ArchitectureSpec {
    pub id: String,
    pub processor: String,
    pub endian: String,
    pub bits: Option<u32>,
    pub language_dir: String,
    pub sla_count: u32,
}

/// One execution/analysis event in a durable timeline.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    /// Monotonic sequence within a program.
    pub sequence: u64,
    /// Source timestamp supplied by the recorder.
    pub at: String,
    /// Thread or execution context label.
    pub thread: String,
    /// Optional RAM address associated with the event.
    pub address: Option<Address>,
    /// Event kind, for example `breakpoint` or `instruction`.
    pub kind: String,
    /// Structured payload retained at the serialization edge.
    pub payload: String,
    /// Producer/provenance label.
    pub provenance: String,
}

/// One deterministic, idempotent collaboration operation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CollaborationOp {
    /// Client-generated idempotency key.
    pub op_id: String,
    /// Stable actor identity used for deterministic ordering.
    pub actor: String,
    /// Lamport clock supplied by the actor.
    pub lamport: u64,
    /// Operation kind, interpreted by the collaboration client.
    pub kind: String,
    /// Operation payload.
    pub payload: String,
    /// Whether this operation has been applied locally.
    pub applied: bool,
    /// Producer/provenance label.
    pub provenance: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ghidra_address_strings() {
        assert_eq!(AddressSpace::from_ghidra_str("00400466"), AddressSpace::Ram);
        assert_eq!(AddressSpace::from_ghidra_str("ram:1000"), AddressSpace::Ram);
        assert_eq!(
            AddressSpace::from_ghidra_str("ext:1000"),
            AddressSpace::External
        );
        assert!(matches!(
            AddressSpace::from_ghidra_str("ov1:1000"),
            AddressSpace::Other(s) if s == "ov1"
        ));
    }

    #[test]
    fn ram_address_defaults() {
        let a = Address::ram(0x404000);
        assert_eq!(a.space, AddressSpace::Ram);
        assert_eq!(a.offset, 0x404000);
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}
