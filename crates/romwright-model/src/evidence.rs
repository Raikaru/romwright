//! Why a function exists, in one record.
//!
//! The facts that make an address a function live in several tables: the
//! producer that claimed it, the symbol the image declares, the references
//! that reach it, thunk and signature claims, and what analysis has done to
//! it. A reader asking "is this real?" needs all of them at once.

use crate::{Address, SignatureMatchRow, ThunkRow};

/// References of one kind and provenance that reach a function.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IncomingEvidence {
    /// Ghidra reference type (`UNCONDITIONAL_CALL`, `DATA`, ...).
    pub kind: String,
    /// The pass that wrote them (`provenance::CLASSES`).
    pub source: String,
    /// `declared`, `decoded` or `inferred`, from the source's class.
    pub evidence: Option<String>,
    pub count: usize,
    /// A few of the instructions or words they come from.
    pub from: Vec<Address>,
}

/// How far the function is attested, most solid first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Standing {
    /// The image names it: a symbol, an export, a linkage stub.
    Declared,
    /// Code calls or jumps to it, or data points at it.
    Attested,
    /// Only a byte pattern says it starts here.
    PatternOnly,
    /// Discovered, but nothing else reaches or names it.
    Unattested,
}

/// Every fact that says `entry` is a function.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FunctionEvidence {
    pub program: String,
    pub entry: Address,
    pub name: String,
    pub size: u64,
    /// The discovery rule that claimed the entry: `symbol`, `thunk`,
    /// `pattern`, `pointer`, `const`, `call`, `flow` or `unknown`.
    pub producer: String,
    /// `seeded`, `walked`, `batch` or `undecodable`, and the revision.
    pub analysis_state: Option<String>,
    pub analysed_revision: Option<u64>,
    /// The image's own name for the entry and the source that read it.
    pub symbol: Option<(String, String)>,
    pub incoming: Vec<IncomingEvidence>,
    pub thunk: Option<ThunkRow>,
    pub signatures: Vec<SignatureMatchRow>,
    pub traced: bool,
    pub standing: Standing,
}
