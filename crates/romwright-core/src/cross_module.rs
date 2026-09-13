//! Cross-module analysis policy (P3.12): how the tool treats references
//! between a main executable and its overlays/modules. A PSX overlay set
//! or an N64 overlay set is several images that call into each other;
//! the policy decides which cross-module references are real xrefs and
//! which are the console's loader machinery.
//!
//! The policy is a set of rules the analysis applies when it sees a
//! transfer whose target is outside the current image:
//!
//! - **Sibling call**: a call/jump whose target lands inside another
//!   member of the same overlay set is a real xref — recorded with the
//!   target module named.
//! - **Loader transfer**: a transfer to the console's loader stub (the
//!   overlay manager's dispatch) is not a call to the overlay — it is
//!   recorded as a loader edge so the graph shows the swap, not a false
//!   callee.
//! - **Shared address**: two overlays that load at the same address are
//!   alternates, not duplicates — a reference to that address is
//!   attributed to whichever overlay the set's manifest marks resident.

use std::collections::HashMap;

/// One member of an overlay set: its name and the address range it
/// occupies when resident.
#[derive(Clone, Debug)]
pub struct ModuleSpan {
    pub name: String,
    /// Inclusive start of the module's resident address range.
    pub start: u64,
    /// Exclusive end.
    pub end: u64,
}

/// How a cross-module transfer is classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferKind {
    /// A real call/branch into a sibling module.
    SiblingCall { target_module: String },
    /// A transfer to the console's loader — the overlay swap machinery.
    LoaderTransfer,
    /// The target is inside no known module.
    External,
}

/// The policy over one overlay set: the member spans plus the loader's
/// dispatch addresses.
pub struct CrossModulePolicy {
    members: Vec<ModuleSpan>,
    /// Addresses that are the console's loader/dispatch stubs — a
    /// transfer to one is a swap, not a call.
    loader_stubs: Vec<u64>,
    /// For a shared load address, which member is resident by default.
    resident: HashMap<u64, String>,
}

impl CrossModulePolicy {
    pub fn new(members: Vec<ModuleSpan>) -> Self {
        Self {
            members,
            loader_stubs: Vec::new(),
            resident: HashMap::new(),
        }
    }

    /// Marks an address as a loader/dispatch stub.
    pub fn with_loader_stub(mut self, address: u64) -> Self {
        self.loader_stubs.push(address);
        self
    }

    /// Marks which member is resident at a shared load address.
    pub fn with_resident(mut self, address: u64, member: impl Into<String>) -> Self {
        self.resident.insert(address, member.into());
        self
    }

    /// Classifies a transfer target: which module it lands in, or whether
    /// it is the loader or external.
    pub fn classify(&self, target: u64) -> TransferKind {
        if self.loader_stubs.contains(&target) {
            return TransferKind::LoaderTransfer;
        }
        for member in &self.members {
            if target >= member.start && target < member.end {
                return TransferKind::SiblingCall {
                    target_module: member.name.clone(),
                };
            }
        }
        TransferKind::External
    }
}
