//! A measurement harness, not a gate: the decompiler's own jump-table
//! recovery (`recover_native_switches`, `jumptable.cc` inside the worker) for
//! the owner functions of an imported project, printed one table per line.
//!
//! The reference pass recovers tables for indirect jumps the import never
//! stored; the soundness of those answers is their agreement with this
//! oracle, run on a project that holds none of them (the same image imported
//! before the recovery existed, or with `ROMWRIGHT_NO_BRANCHIND_RECOVERY=1`).
//! Environment: `ORACLE_PROJECT` (project directory), `ORACLE_PROGRAM`,
//! `ORACLE_BINARY` (the imported image), `ORACLE_OWNERS` (comma-separated hex
//! entries of the functions to decompile), `ORACLE_BUDGET_SECS` (default 3600).
//! Output on stdout: `TABLE <branch> <target,target,...>` per recovered table
//! and `FAILURE <text>` per function the decompiler refused.
use crate::session::RuntimeConfig;
use std::time::Duration;

#[test]
#[ignore = "measurement harness: needs an imported project and its image"]
fn decompiler_recovers_the_tables_of_the_owners_asked() {
    let (Ok(project), Ok(program), Ok(binary), Ok(owners)) = (
        std::env::var("ORACLE_PROJECT"),
        std::env::var("ORACLE_PROGRAM"),
        std::env::var("ORACLE_BINARY"),
        std::env::var("ORACLE_OWNERS"),
    ) else {
        eprintln!("SKIP: ORACLE_PROJECT/PROGRAM/BINARY/OWNERS not set");
        return;
    };
    let budget = std::env::var("ORACLE_BUDGET_SECS").ok().and_then(|raw| raw.parse().ok()).unwrap_or(3600);
    let owners: Vec<String> = owners.split(',').filter(|owner| !owner.is_empty()).map(str::to_owned).collect();
    let core = crate::Core::open_with_config(std::path::Path::new(&project), RuntimeConfig::from_env()).unwrap();
    let request = core
        .execution_request(std::path::Path::new(&binary), &program, None, Duration::from_secs(budget))
        .unwrap();
    // One worker launch per chunk keeps a hung function from costing the rest.
    for chunk in owners.chunks(64) {
        let recovery = super::recover_native_switches(&request, chunk).unwrap();
        for table in &recovery.tables {
            let mut targets: Vec<u64> = table.targets.iter().map(|target| target.offset).collect();
            targets.sort_unstable();
            targets.dedup();
            let targets: Vec<String> = targets.iter().map(|target| format!("{target:#x}")).collect();
            println!("TABLE {:#x} {}", table.branch.offset, targets.join(","));
        }
        for failure in &recovery.failures {
            println!("FAILURE {failure}");
        }
    }
}
