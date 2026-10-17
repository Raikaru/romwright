//! `romwright-cli compiler-rules [--json]`: the embedded compiler rules
//! (`crates/romwright-core/compiler_rules/`) and whether each is switched on
//! under `ROMWRIGHT_NO_COMPILER_RULES`, `ROMWRIGHT_COMPILER_RULES_DISABLE` and
//! `ROMWRIGHT_COMPILER_RULES_ENABLE`. See docs/compiler-rules.md.

use super::has_flag;
use romwright_core::compiler::{self, rules};

pub fn run(args: &[String]) -> Result<(), String> {
    let views = rules::describe();
    if has_flag(args, "--json") {
        println!("{}", serde_json::to_string_pretty(&views).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("compiler ids the detectors produce: {}", compiler::KNOWN_IDS.join(", "));
    for rule in views {
        println!(
            "{:<34} {:<16} {:<9} {:<8} {}{}",
            rule.id,
            rule.kind,
            rule.status,
            rule.origin,
            if rule.active { "active   " } else { "inactive " },
            rule.compilers.join(","),
        );
        if rule.unknown {
            println!("{:<34} also covers a program whose compiler is unknown", "");
        }
    }
    Ok(())
}
