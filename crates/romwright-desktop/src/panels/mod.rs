//! Panel registration point. Adding a panel = one module here plus one line
//! in [`builtin`]; the shell builds menus, docking, persistence and event
//! delivery from this list. Order is View-menu order and event order.

pub mod analyst;
pub mod decompiler;
pub mod facts;
pub mod functions;
pub mod graph;
pub mod jobs;
pub mod listing;
pub mod match_search;
pub mod matching;
pub mod memory;
pub mod setup;
pub mod types;
pub mod vtables;
pub mod xrefs;

use crate::panel::Panel;

/// Every panel the window offers. `program`/`binary` seed the setup form
/// from the command line.
pub fn builtin(program: &str, binary: &str) -> Vec<Box<dyn Panel>> {
    vec![
        Box::new(functions::FunctionsPanel::default()),
        Box::new(listing::ListingPanel::default()),
        Box::new(decompiler::DecompilerPanel::default()),
        Box::new(graph::GraphPanel::default()),
        Box::new(xrefs::XrefsPanel::default()),
        Box::new(facts::FactsPanel::default()),
        Box::new(memory::MemoryPanel::default()),
        Box::new(jobs::JobsPanel::default()),
        Box::new(vtables::VtablesPanel::default()),
        Box::new(types::TypesPanel::default()),
        Box::new(analyst::AnalystPanel::default()),
        Box::new(match_search::MatchPanel::default()),
        Box::new(matching::MatchingPanel::default()),
        Box::new(setup::SetupPanel::new(program, binary)),
    ]
}
