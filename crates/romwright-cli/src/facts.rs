//! `romwright-cli facts ...`: build and apply the universal fact pack.
//!
//!   facts add-donor --pack PACK --project DIR --program NAME --truth TSV --donor JSON [--prototypes TSV] [--json]
//!   facts set-meta --pack PACK KEY VALUE        (gate_short_body, gate_min_donors)
//!   facts apply --project DIR --program NAME [--pack PACK] [--exclude GAME]... [--scan] [--json]
//!
//! Both are thin delegates to `Core::add_donor_to_pack` and
//! `Core::apply_fact_pack`; see docs/fact-pack.md.

use super::{flag, has_flag};
use romwright_core::Core;
use romwright_core::fact_pack::{self, Donor, FactPackOptions};
use std::path::PathBuf;

/// `facts set-meta` touches only the pack file, so no project is opened for it.
pub fn set_meta(args: &[String]) -> Result<(), String> {
    let pack = PathBuf::from(required(args, "--pack", "set-meta")?);
    let rest: Vec<&String> = args
        .iter()
        .skip(3)
        .scan(false, |skip, argument| {
            let take = !*skip && argument != "--pack";
            *skip = argument == "--pack";
            Some(take.then_some(argument))
        })
        .flatten()
        .collect();
    let [key, value] = rest.as_slice() else {
        return Err("facts set-meta needs --pack PACK KEY VALUE".into());
    };
    let pack_file = romwright_core::fact_pack::open_pack_rw(&pack).map_err(|e| e.to_string())?;
    pack_file.set_meta(key, value).map_err(|e| e.to_string())?;
    println!("{key} = {value}");
    Ok(())
}

pub fn run(core: &Core, args: &[String]) -> Result<(), String> {
    match args.get(2).map(String::as_str) {
        Some("add-donor") => add_donor(core, args),
        Some("apply") => apply(core, args),
        _ => Err("facts needs `add-donor`, `apply` or `set-meta`".into()),
    }
}

fn required(args: &[String], name: &str, command: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("facts {command} needs {name}"))
}

fn add_donor(core: &Core, args: &[String]) -> Result<(), String> {
    let pack = PathBuf::from(required(args, "--pack", "add-donor")?);
    let program = required(args, "--program", "add-donor")?;
    let truth_path = required(args, "--truth", "add-donor")?;
    let donor_path = required(args, "--donor", "add-donor")?;
    let truth = fact_pack::parse_truth(
        &std::fs::read_to_string(&truth_path).map_err(|e| format!("{truth_path}: {e}"))?,
    )
    .map_err(|e| format!("{truth_path}: {e}"))?;
    // One donor object, or a list holding one (the shape of licenses.json).
    let donor_text = std::fs::read_to_string(&donor_path).map_err(|e| format!("{donor_path}: {e}"))?;
    let donor: Donor = match serde_json::from_str::<Vec<Donor>>(&donor_text) {
        Ok(mut list) if list.len() == 1 => list.remove(0),
        Ok(_) => return Err(format!("{donor_path}: expected exactly one donor")),
        Err(_) => serde_json::from_str(&donor_text).map_err(|e| format!("{donor_path}: {e}"))?,
    };
    let prototypes = match flag(args, "--prototypes") {
        Some(path) => fact_pack::parse_prototypes(
            &std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?,
        ),
        None => Vec::new(),
    };
    let report = core
        .add_donor_to_pack(&pack, &program, &donor, &truth, &prototypes)
        .map_err(|e| e.to_string())?;
    if has_flag(args, "--json") {
        println!("{}", serde_json::to_string(&report).map_err(|e| e.to_string())?);
    } else {
        println!(
            "donor {} ({}): {} truth rows, {} added ({} generic-named), skipped {} short / {} unmapped / {} no-family; \
             {} prototypes; {} replaced; pack holds {} bodies",
            report.game,
            report.program,
            report.rows,
            report.added,
            report.generic_named,
            report.skipped_short,
            report.skipped_unmapped,
            report.skipped_no_family,
            report.prototypes,
            report.replaced,
            report.pack_bodies
        );
    }
    Ok(())
}

fn apply(core: &Core, args: &[String]) -> Result<(), String> {
    let program = required(args, "--program", "apply")?;
    let explicit = flag(args, "--pack").map(PathBuf::from);
    let (pack, _) = fact_pack::resolve_pack(explicit.as_deref())
        .ok_or("no fact pack: pass --pack, set ROMWRIGHT_FACT_PACK, or install one in $XDG_DATA_HOME/romwright/fact-pack.sqlite")?;
    let exclude_games: Vec<String> = args
        .windows(2)
        .filter(|pair| pair[0] == "--exclude")
        .map(|pair| pair[1].clone())
        .collect();
    let options = FactPackOptions { exclude_games, scan: has_flag(args, "--scan") };
    let report = core.apply_fact_pack(&program, &pack, &options).map_err(|e| e.to_string())?;
    if has_flag(args, "--json") {
        println!("{}", serde_json::to_string(&report).map_err(|e| e.to_string())?);
    } else {
        println!(
            "fact pack {}: {} probed ({} scanned), {} matched, {} renamed, {} kept, {} abstained, {} gated, {} scan-only, {} prototypes",
            report.pack,
            report.probed_functions,
            report.probed_scan,
            report.matched,
            report.renamed,
            report.kept_name,
            report.abstained,
            report.gated,
            report.scan_only,
            report.prototypes
        );
        if let Some(compiler) = &report.implied_compiler {
            println!("implied compiler: {compiler}");
        }
        for found in report.matches.iter().filter(|m| m.action == "renamed").take(20) {
            println!(
                "  {:#x} {} ({} B, {})",
                found.address,
                found.name.as_deref().unwrap_or("?"),
                found.length,
                found.donors.join(",")
            );
        }
    }
    Ok(())
}
