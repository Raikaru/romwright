//! lre-worker: the no-JVM decompiler worker as a library (protocol client +
//! provider + supervision-friendly handle). The `lre-worker` binary is a
//! thin CLI on top; interactive/session consumers use this library so the
//! same protocol code serves the CLI, the worker pool, and the UI runtime.
pub mod doc;
mod prototype;
pub mod provider;
pub mod wire;
pub mod worker;

pub use doc::{
    DecodedDocument, decode_document_with_ram_space, decode_tokens, decode_tokens_with_ram_space,
};
pub use provider::{
    BinaryBacking, ProgramProvider, c_identifier, decode_addr_element, parse_core_types,
    spec_dir,
};
pub use worker::*;

/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = WorkerError> = std::result::Result<T, E>;
