//! Core data model.
//!
//! Addresses are address-space identity plus offset (spec 8.3): a plain `u64`
//! cannot name overlays, registers, or split spaces, and Ghidra's own model
//! does not pretend they can. Entities use compact stable IDs (spec 8.2).

/// Stable ID for a program inside a project.
pub mod provenance;

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

impl serde::Serialize for FactProvenance {
    /// Adds `explanation` from the shared table: a consumer that shows a fact
    /// can always say what proved it, without mapping the string itself.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let class = provenance::class(&self.source);
        let mut row = serializer.serialize_struct("FactProvenance", 5)?;
        row.serialize_field("kind", &self.kind)?;
        row.serialize_field("source", &self.source)?;
        row.serialize_field("confidence", &self.confidence)?;
        row.serialize_field("explanation", &class.map(|entry| entry.explanation))?;
        // What kind of evidence this is: the image said so, the decoder proved
        // it, or a pass concluded it.
        row.serialize_field("evidence", &class.map(|entry| entry.evidence))?;
        row.end()
    }
}

/// One program a project holds, for an inventory rather than a single answer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProgramRow {
    pub program: String,
    pub language: String,
    /// Functions the store holds for it.
    pub functions: u64,
    /// Store revision, which moves when a fact changes.
    pub revision: u64,
}

/// Where one address lands in one program: the region that maps it, and the
/// function containing it when a function does. Images overlap -- a PE and an
/// ELF can both start at `0x400000` -- so an address alone names no program.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct LocationRow {
    pub program: String,
    pub language: String,
    pub region: MemoryRegion,
    /// The function whose body holds the address, or `None` when none does.
    #[serde(default)]
    pub function: Option<String>,
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

/// The p-code object reference carried by a specialized Clang token.
///
/// `id` is the decompiler's per-response PcodeFactory index. It is not a
/// durable database id or an address; consumers must treat it as scoped to
/// this decompiler document.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecompReference {
    pub kind: DecompReferenceKind,
    pub id: u64,
}

/// Which p-code object a decompiler token references.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DecompReferenceKind {
    Varnode,
    Operation,
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
    /// Entity address when the token carried space+off attributes.
    pub address: Option<Address>,
    /// Per-response p-code reference from ATTRIB_VARREF/ATTRIB_OPREF.
    pub reference: Option<DecompReference>,
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
    /// None means unavailable metadata; an empty list means no recovered tables.
    #[serde(default)]
    pub jump_tables: Option<Vec<JumpTable>>,
    pub address: Address,
    pub revision: u64,
    /// Local symbols with fixed storage; empty when the document predates
    /// storage capture or the function has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<StorageSymbol>,
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

/// Wall time of one import phase, in seconds. Phases are measured, never
/// estimated: a consumer that reports a budget must report these numbers.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PhaseTiming {
    /// Phase name (`parse`, `discovery`, `references`, `store`).
    pub phase: String,
    /// Measured wall time in seconds.
    pub seconds: f64,
}

/// What the flow phase asked of the SLEIGH console. Batched flow is a claim
/// about `instructions` per `requests`, which no machine speed can flatter.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct FlowStats {
    /// Commands written to every console during discovery.
    pub requests: u64,
    /// Instructions the console decoded for the flow walk.
    pub instructions: u64,
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
    /// Measured phase wall times; empty for paths that do not measure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phases: Vec<PhaseTiming>,
    /// Console request accounting for the flow phase, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<FlowStats>,
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

/// A polymorphic class recovered from its Itanium type_info and vtable.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ClassRow {
    pub typeinfo: Address,
    /// Primary vtable start: the `offset_to_top` word, two pointers before the
    /// address point objects hold.
    pub vtable: Address,
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
