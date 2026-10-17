//! Reproducible matching inputs, immutable candidates and evidence-backed trials.
use crate::{BuildRecipe, MatchingRun};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceFile {
    pub digest: String,
    /// Explicit permission to include these bytes in an exported workspace.
    #[serde(default)]
    pub redistributable: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRequirement {
    pub path: String,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchingProfile {
    pub name: String,
    pub recipe: BuildRecipe,
    /// Appended to recipe.arguments. {source}, {output}, {root} and
    /// {tool:NAME} are whole or embedded operands, never shell expansions.
    pub compile_arguments: Vec<String>,
    /// Complete arguments for the version query, including any wrapper target.
    pub version_arguments: Vec<String>,
    /// Compiler wrappers and separately installed compiler/SDK support files.
    /// Tool bytes are never bundled by workspace export.
    #[serde(default)]
    pub tools: BTreeMap<String, ToolRequirement>,
    #[serde(default)]
    pub compiler_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectBinding {
    /// Imported workspaces stay unbound until a local root is chosen explicitly.
    #[serde(default)]
    pub root: Option<String>,
    /// Workspace-relative paths mapped to project-relative paths.
    pub sources: BTreeMap<String, String>,
    pub build: ProjectCommand,
    /// Symbol names allowed to change, mapped to build outputs.
    /// Includes defined functions/data and objdiff's named anonymous-data ranges.
    /// Multiple symbols may share an object; undeclared changes are reported.
    pub objects: BTreeMap<String, String>,
    /// Optional final build output compared with the imported program artifact.
    #[serde(default)]
    pub linked_output: Option<String>,
    /// Additional generated files or directories allowed to change. Object
    /// changes are still checked against `objects`, even inside these paths.
    #[serde(default)]
    pub generated: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSpec {
    pub name: String,
    pub symbol: String,
    pub source: String,
    pub files: BTreeMap<String, WorkspaceFile>,
    pub target: WorkspaceFile,
    #[serde(default)]
    pub objdiff: ToolRequirement,
    pub profiles: Vec<MatchingProfile>,
    #[serde(default)]
    pub project: Option<ProjectBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchingWorkspace {
    pub id: u64,
    pub revision: u64,
    pub created_at: String,
    pub spec: WorkspaceSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceEdit {
    pub file: String,
    /// Byte offsets in the parent candidate's UTF-8 source; end is exclusive.
    pub start: usize,
    pub end: usize,
    pub replacement: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourcePin {
    pub file: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateSpec {
    pub parent: Option<u64>,
    pub label: String,
    pub files: BTreeMap<String, WorkspaceFile>,
    /// None means edit notes were withheld from an imported private workspace.
    /// Full file snapshots, not these notes, define every candidate.
    pub edits: Option<Vec<SourceEdit>>,
    pub pins: Vec<SourcePin>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchingCandidate {
    pub id: u64,
    pub workspace: u64,
    pub created_at: String,
    pub spec: CandidateSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MismatchCategory {
    Extension,
    MemoryAccess,
    StackFrame,
    ControlFlow,
    ConstantOrInstruction,
    CallSequence,
    RegisterOrScheduling,
    Relocation,
    MissingFunction,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MismatchEvidence {
    pub category: MismatchCategory,
    /// Addresses in the comparator's object coordinate system, not ROM addresses.
    pub target_address: Option<u64>,
    pub candidate_address: Option<u64>,
    pub target: String,
    pub candidate: String,
    pub hypothesis: String,
    /// Compiler-provided source position, never inferred from instruction order.
    pub source_line: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MatchDiagnosis {
    pub symbol: String,
    pub similarity: Option<f64>,
    pub exact_object_bytes: bool,
    /// Exact emitted function bytes; None means the object lacks a proven range.
    pub exact_instructions: Option<bool>,
    pub exact_relocations: Option<bool>,
    pub mismatches: Vec<MismatchEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TrialRecord {
    pub id: u64,
    pub created_at: String,
    pub candidate: u64,
    pub candidate_digest: Option<String>,
    pub profile: String,
    pub status: crate::MatchingStatus,
    /// Full evidence may be withheld from a portable private workspace.
    pub run: Option<MatchingRun>,
    pub evidence_digest: String,
    /// Imported scores remain unverified until the local toolchain reruns them.
    pub imported: bool,
    pub diagnosis: MatchDiagnosis,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TestedHypothesis {
    pub candidate: u64,
    pub description: String,
    pub before: Option<f64>,
    pub after: Option<f64>,
    /// Score improvement is not a proof of semantic equivalence.
    pub improved: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TrialBatch {
    pub trials: Vec<TrialRecord>,
    pub hypotheses: Vec<TestedHypothesis>,
    pub best_candidate: Option<u64>,
    pub compiler_invocations: usize,
    pub elapsed_ms: u64,
    pub stopped: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchRequest {
    pub candidate: u64,
    pub profile: String,
    pub max_compilations: usize,
    /// Each alternative is applied independently to the immutable parent.
    pub alternatives: Vec<Vec<SourceEdit>>,
    /// Optional selected expression or builtin scalar type for generated variants.
    pub expression: Option<SourcePin>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CalibrationResult {
    pub trials: Vec<TrialRecord>,
    /// Equal scores remain tied; this is evidence, not unique identification.
    pub ranking: Vec<(String, f64)>,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextTrialRequest {
    pub candidates: Vec<u64>,
    pub profile: String,
    pub edits: Vec<SourceEdit>,
    pub max_compilations: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ContextComparison {
    pub baseline: TrialRecord,
    pub trial: TrialRecord,
    pub delta: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchFile {
    pub path: String,
    pub before_digest: Option<String>,
    pub after_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectPatch {
    pub workspace: u64,
    pub candidate: u64,
    pub profile: String,
    /// Identity of the selected binding, target and profile at review time.
    pub binding_digest: String,
    pub files: Vec<PatchFile>,
    pub unified_diff: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PatchVerification {
    pub id: u64,
    pub created_at: String,
    pub imported: bool,
    pub patch: ProjectPatch,
    /// A filesystem snapshot is not a sandbox for hostile build commands.
    pub input_manifest_digest: String,
    pub candidate_digest: Option<String>,
    pub comparison_digest: Option<String>,
    pub diagnosis: Option<MatchDiagnosis>,
    pub baseline_diagnosis: Option<MatchDiagnosis>,
    pub baseline_candidate_digest: Option<String>,
    pub baseline_comparison_digest: Option<String>,
    pub scope_comparison_digests: Vec<String>,
    pub applied: bool,
    pub applied_files: Vec<String>,
    /// Retained backups if concurrent edits or I/O errors prevent rollback.
    pub recovery_path: Option<String>,
    pub build_succeeded: bool,
    pub baseline_build_succeeded: bool,
    pub original_inputs_unchanged: bool,
    pub rebuilt_outputs: Vec<String>,
    pub missing_outputs: Vec<String>,
    pub changed_objects: Vec<String>,
    pub unexpected_objects: Vec<String>,
    pub changed_symbols: Vec<String>,
    pub unexpected_symbols: Vec<String>,
    pub unexpected_files: Vec<String>,
    /// None means no final-program comparison was performed.
    pub project_exactness: Option<bool>,
    pub linked_output_digest: Option<String>,
    pub diagnostics: String,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateChange {
    pub parent: u64,
    pub label: String,
    pub edits: Vec<SourceEdit>,
    /// None inherits and relocates the parent's pins. Removing pins is an
    /// explicit, separately reviewable candidate change.
    pub pins: Option<Vec<SourcePin>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceCreated {
    pub workspace: MatchingWorkspace,
    pub candidate: MatchingCandidate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WorkspaceBundle {
    pub format: u32,
    pub workspace: WorkspaceSpec,
    pub candidates: Vec<MatchingCandidate>,
    #[serde(default)]
    pub project_checks: Vec<PatchVerification>,
    pub trials: Vec<TrialRecord>,
    /// SHA-256 to base64. Only explicitly redistributable bytes are included.
    /// Compiler/tool bytes are excluded even if also listed as workspace files.
    pub artifacts: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WorkspaceImport {
    pub bundle: WorkspaceBundle,
    /// Required private input digests mapped to user-owned local files.
    #[serde(default)]
    pub private_files: BTreeMap<String, String>,
    /// Profile names mapped to locally installed compiler/wrapper executables.
    #[serde(default)]
    pub compilers: BTreeMap<String, String>,
    /// Profile name, then declared tool name, mapped to a local requirement.
    #[serde(default)]
    pub tools: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub objdiff: Option<String>,
    #[serde(default)]
    pub project_root: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MatchingOperation {
    Trial {
        candidate: u64,
        profile: String,
    },
    Search {
        request: SearchRequest,
    },
    Calibrate {
        candidates: Vec<u64>,
        profiles: Vec<String>,
        max_compilations: usize,
    },
    Context {
        request: ContextTrialRequest,
    },
    PreparePatch {
        candidate: u64,
        profile: String,
    },
    VerifyPatch {
        patch: ProjectPatch,
        apply: bool,
    },
}

/// Workspace management does not require the original binary to be available.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum WorkspaceOperation {
    Setup {
        setup: WorkspaceSetup,
    },
    List {
        #[serde(default)]
        after: u64,
        limit: Option<usize>,
    },
    Show {
        workspace: u64,
    },
    Update {
        workspace: u64,
        revision: u64,
        spec: WorkspaceSpec,
    },
    Candidates {
        workspace: u64,
        #[serde(default)]
        after: u64,
        limit: Option<usize>,
    },
    Candidate {
        candidate: u64,
    },
    Source {
        candidate: u64,
        file: String,
    },
    Change {
        change: CandidateChange,
    },
    Replace {
        candidate: u64,
        file: String,
        source: String,
        label: String,
    },
    Trials {
        workspace: u64,
        #[serde(default)]
        after: u64,
        limit: Option<usize>,
    },
    Checks {
        workspace: u64,
        #[serde(default)]
        after: u64,
        limit: Option<usize>,
    },
    Export {
        workspace: u64,
    },
    Import {
        request: Box<WorkspaceImport>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MatchingInput {
    Path {
        path: String,
        #[serde(default)]
        redistributable: bool,
    },
    Text {
        text: String,
        #[serde(default)]
        redistributable: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSetup {
    pub name: String,
    pub symbol: String,
    pub source: String,
    pub files: BTreeMap<String, MatchingInput>,
    pub target: MatchingInput,
    pub profiles: Vec<MatchingProfile>,
    #[serde(default)]
    pub project: Option<ProjectBinding>,
}
