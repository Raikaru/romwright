//! Measurement driver for `benchmarks/struct_inference_audit.py` (not product code).
//!
//! The audit script copies this file to `crates/romwright-core/examples/` of a
//! scratch checkout and builds it there: it only calls public API of
//! `romwright-core`, so no product file changes. It reruns the interprocedural
//! solve of `Core::infer_types` (`lib.rs`, "Pass 1" / "Pass 2") over a list of
//! entries, with the same code path, and records per function the structural
//! type of every integer parameter slot under four configurations:
//!
//! * `iso`     pass 1: every function solved alone (no callee signatures);
//! * `fwd`     callee -> caller only: one round with the `iso` signatures as callees;
//! * `whatif`  the full fixpoint of `infer_types` (callee -> caller injection and
//!             caller -> callee joins) with every signature `Inferred`, i.e. as if
//!             the decompiler's FuncProto did not override them;
//! * `shipped` what `infer_types` really does: the decompiler's FuncProto is
//!             asserted `Strong` for every function it decompiles, and joins only
//!             touch `Inferred` signatures (`--strong`, slow: decompiles each entry).
//!
//! Output: one JSON document on the path given as `--out`.
//!
//! usage: struct_audit_dump --project DIR --binary FILE --program NAME
//!        --language r5900:LE:32:default --entries FILE --out FILE
//!        [--strong [--threads N] [--strong-entries FILE]]
//!
//! `--strong-entries` decompiles only the listed entries; the other functions then have no callee signature in the
//! `shipped` run. The decompiler's signatures carry no structure, so that changes only the scalar caps of callers'
//! arguments (measured: `shipped` equals `iso` to 0.1 point on every game). Memory: the warm image is dropped once
//! every body is lifted, and each variant keeps only the parameter-slot types, not the whole `Solution`.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use romwright_core::demand::LiveImages;
use romwright_core::native_runtime::{language_decompile_config, PcodeInstruction};
use romwright_core::register_params::Conventions;
use romwright_core::subtype::{solve_with, Signature, Solution};
use romwright_core::types_infer::Ty;
use romwright_core::Core;
use romwright_model::Address;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// What a variant keeps of a solve: the parameter-slot types and the callees' call observations. The full
/// `Solution` (every variable of every function) is dropped at once, which is what keeps a large image in memory.
struct Slim {
    slots: Vec<Ty>,
    calls: BTreeMap<u64, Vec<(u64, Ty)>>,
}

fn slim(sol: Solution, slots: &[u64]) -> Slim {
    Slim {
        slots: slots.iter().map(|o| sol.types.get(o).cloned().unwrap_or(Ty::Unknown)).collect(),
        calls: sol.calls,
    }
}

/// Offsets a type proves fields at (the join log keeps these, not the whole types).
fn offsets(ty: &Ty) -> BTreeSet<i64> {
    match ty {
        Ty::Ptr(inner) => match inner.as_ref() {
            Ty::Struct(fields) => fields.keys().copied().collect(),
            Ty::Scalar(c) if *c != romwright_model::type_evidence::Class::Unknown => BTreeSet::from([0]),
            _ => BTreeSet::new(),
        },
        Ty::Struct(fields) => fields.keys().copied().collect(),
        _ => BTreeSet::new(),
    }
}

fn run_rounds(
    lifted: &[(u64, Vec<PcodeInstruction>)],
    signatures: &mut BTreeMap<u64, (Signature, bool)>, // value, joinable (Inferred)
    killed: &BTreeSet<u64>,
    machine: &romwright_core::types_infer::Machine,
    int_slots: &[u64],
    rounds: usize,
    joins: bool,
    log: &mut Vec<serde_json::Value>,
) -> Vec<Slim> {
    let mut callees: BTreeMap<u64, Signature> =
        signatures.iter().map(|(a, (s, _))| (*a, s.clone())).collect();
    let mut solutions: Vec<Slim> = Vec::new();
    for round in 0..rounds {
        solutions = lifted
            .iter()
            .map(|(_, p)| slim(solve_with(p, &callees, killed, machine), int_slots))
            .collect();
        if joins {
            for ((caller, _), sol) in lifted.iter().zip(solutions.iter()) {
                for (callee, args) in &sol.calls {
                    if let Some((sig, joinable)) = signatures.get_mut(callee)
                        && *joinable
                    {
                        for (reg, ty) in args {
                            let before = sig.params.iter().find(|(r, _)| r == reg).map(|(_, t)| offsets(t)).unwrap_or_default();
                            match sig.params.iter_mut().find(|(r, _)| r == reg) {
                                Some((_, existing)) => *existing = existing.join(ty),
                                None => sig.params.push((*reg, ty.clone())),
                            }
                            let after = sig.params.iter().find(|(r, _)| r == reg).map(|(_, t)| offsets(t)).unwrap_or_default();
                            if before != after && log.len() < 300_000 {
                                let added: Vec<i64> = after.difference(&before).copied().collect();
                                log.push(serde_json::json!({
                                    "round": round, "caller": format!("{caller:08x}"),
                                    "callee": format!("{callee:08x}"), "reg": reg, "added": added,
                                }));
                            }
                        }
                    }
                }
            }
        }
        let next: BTreeMap<u64, Signature> =
            signatures.iter().map(|(a, (s, _))| (*a, s.clone())).collect();
        if next == callees {
            break;
        }
        callees = next;
    }
    solutions
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let project = PathBuf::from(arg(&args, "--project").ok_or("--project")?);
    let binary = PathBuf::from(arg(&args, "--binary").ok_or("--binary")?);
    let program = arg(&args, "--program").ok_or("--program")?;
    let language = arg(&args, "--language").ok_or("--language")?;
    let entries_path = arg(&args, "--entries").ok_or("--entries")?;
    let out = arg(&args, "--out").ok_or("--out")?;
    let strong = args.iter().any(|a| a == "--strong");
    // `--strong-entries FILE`: decompile only these entries (the decompiler is the slow part). The other
    // functions then have no callee signature at all; the decompiler's signatures carry no structure, so
    // a callee's Strong signature changes only the scalar caps of a caller's arguments.
    let strong_only: Option<BTreeSet<u64>> = arg(&args, "--strong-entries").map(|p| {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| u64::from_str_radix(l.trim().trim_start_matches("0x"), 16).ok())
            .collect()
    });

    let entries: Vec<u64> = std::fs::read_to_string(&entries_path)?
        .lines()
        .filter_map(|l| u64::from_str_radix(l.trim().trim_start_matches("0x"), 16).ok())
        .collect();

    let core = Core::open(&project)?;
    let config = core.runtime_config().clone();
    let input = core.program_input(&program)?;
    let (_, specs, _, _) = language_decompile_config(&config, &language)?;
    let cspec = std::fs::read_to_string(specs.join("cspec.xml"))?;
    let table = std::fs::read_to_string(specs.join("registers.txt"))?;
    let conventions = Conventions::parse(&cspec, &table);
    let machine = conventions.machine(&language);
    let model = conventions.default().ok_or("no default prototype model")?;
    let slot = |name: &str| conventions.registers.get(name).map(|(offset, _)| *offset);
    let killed: BTreeSet<u64> = model.killed.iter().filter_map(|n| slot(n)).collect();
    let int_slots: Vec<u64> = model.registers.iter().filter_map(|n| slot(n)).collect();
    let int_ret: Vec<u64> = model.returns.iter().filter_map(|n| slot(n)).collect();
    let float_offsets = |name: &str| {
        let mut offsets: Vec<u64> = slot(name).into_iter().collect();
        if let Some(single) = name.split('_').next().filter(|s| *s != name)
            && let Some(offset) = slot(single)
            && !offsets.contains(&offset)
        {
            offsets.push(offset);
        }
        offsets
    };
    let float_slots: Vec<u64> = model.float_registers.iter().flat_map(|n| float_offsets(n)).collect();
    let float_ret: Vec<u64> = model.float_returns.iter().flat_map(|n| float_offsets(n)).collect();

    let live = LiveImages::new(core.db_path(), &config);
    // Pass 1: lift and solve every function alone.
    let mut lifted: Vec<(u64, Vec<PcodeInstruction>)> = Vec::new();
    let mut insns: BTreeMap<u64, u64> = BTreeMap::new();
    live.with(&input, &program, None, |live| {
        for &entry in &entries {
            let Ok(walk) = live.walk(entry) else { continue };
            if walk.instructions == 0 {
                continue;
            }
            let mut addresses: Vec<u64> = walk.instruction_extents.iter().map(|(a, _)| *a).collect();
            addresses.sort_unstable();
            addresses.dedup();
            let pcode = live.pcode(&addresses)?;
            insns.insert(entry, walk.instructions);
            lifted.push((entry, pcode));
        }
        Ok(())
    })?;
    // The warm image holds every decoded body; nothing below needs it.
    live.forget(&program);
    drop(live);
    eprintln!("lifted {} of {} entries", lifted.len(), entries.len());

    let inferred_signature = |sol: &Solution| Signature {
        params: int_slots
            .iter()
            .filter_map(|o| sol.types.get(o).map(|t| (*o, t.clone())))
            .collect(),
        returns: int_ret.iter().filter_map(|o| sol.types.get(o).map(|t| (*o, t.clone()))).collect(),
    };
    let mut base_signatures: BTreeMap<u64, (Signature, bool)> = BTreeMap::new();
    let mut iso: Vec<Slim> = Vec::with_capacity(lifted.len());
    for (entry, pcode) in &lifted {
        let sol = solve_with(pcode, &BTreeMap::new(), &killed, &machine);
        base_signatures.insert(*entry, (inferred_signature(&sol), true));
        iso.push(slim(sol, &int_slots));
    }

    // fwd: one round, iso signatures as callees, no joins.
    let mut sigs = base_signatures.clone();
    let mut none_log = Vec::new();
    let fwd = run_rounds(&lifted, &mut sigs, &killed, &machine, &int_slots, 1, false, &mut none_log);
    // whatif: the full fixpoint, all Inferred.
    let mut sigs = base_signatures.clone();
    let mut whatif_log = Vec::new();
    let whatif = run_rounds(&lifted, &mut sigs, &killed, &machine, &int_slots, 8, true, &mut whatif_log);
    let whatif_sigs: BTreeMap<u64, Signature> = sigs.iter().map(|(a, (s, _))| (*a, s.clone())).collect();
    eprintln!("fwd and whatif done");

    // shipped: FuncProto Strong overrides.
    let mut shipped: Option<Vec<Slim>> = None;
    let mut shipped_log = Vec::new();
    let mut protos: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    if strong {
        let mut sigs = base_signatures.clone();
        if let Some(only) = &strong_only {
            sigs.retain(|entry, _| only.contains(entry));
        }
        // The decompiler is the slow part: spread the entries over `--threads` forks of the Core
        // (independent store connections, one shared warm image cache).
        let threads: usize = arg(&args, "--threads").and_then(|s| s.parse().ok()).unwrap_or(6).max(1);
        let entry_list: Vec<u64> = lifted
            .iter()
            .map(|(e, _)| *e)
            .filter(|e| strong_only.as_ref().is_none_or(|only| only.contains(e)))
            .collect();
        let per = entry_list.len().div_ceil(threads).max(1);
        let done = std::sync::atomic::AtomicUsize::new(0);
        let recovered: Vec<Vec<(u64, Option<romwright_model::FuncProto>)>> = std::thread::scope(|scope| {
            let handles: Vec<_> = entry_list
                .chunks(per)
                .map(|chunk| {
                    let worker = core.fork().expect("fork core");
                    let (binary, program, done) = (&binary, &program, &done);
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|entry| {
                                let proto = worker
                                    .decompile_native_doc(binary, &Address::ram(*entry), program, None)
                                    .ok()
                                    .and_then(|doc| doc.prototype);
                                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                if n % 500 == 0 {
                                    eprintln!("decompiled {n}");
                                }
                                (*entry, proto)
                            })
                            .collect()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("decompile thread")).collect()
        });
        for (entry, proto) in recovered.into_iter().flatten() {
            let Some(proto) = proto else { continue };
            protos.insert(
                entry,
                proto
                    .parameters
                    .iter()
                    .map(|p| {
                        format!(
                            "{}|{}",
                            p.data_type.metatype.clone().unwrap_or_default(),
                            p.data_type.name.clone().unwrap_or_default()
                        )
                    })
                    .collect(),
            );
            let sig = Signature::from_funcproto(&proto, &int_slots, &float_slots, &int_ret, &float_ret, &machine);
            sigs.insert(entry, (sig, false));
        }
        shipped = Some(run_rounds(&lifted, &mut sigs, &killed, &machine, &int_slots, 8, true, &mut shipped_log));
    }

    let mut functions = Vec::new();
    for (i, (entry, _)) in lifted.iter().enumerate() {
        let mut row = serde_json::json!({
            "entry": format!("{entry:08x}"),
            "instructions": insns.get(entry),
            "iso": iso[i].slots,
            "fwd": fwd[i].slots,
            "whatif": whatif[i].slots,
        });
        if let Some(sh) = &shipped {
            row["shipped"] = serde_json::to_value(&sh[i].slots)?;
            row["proto"] = serde_json::to_value(protos.get(entry))?;
        }
        // The direct callees of this function as the final whatif solve saw them.
        let calls: Vec<String> = whatif[i].calls.keys().map(|callee| format!("{callee:08x}")).collect();
        row["callees"] = serde_json::to_value(calls)?;
        functions.push(row);
    }
    let doc = serde_json::json!({
        "program": program,
        "strong_subset": strong_only.as_ref().map(|s| s.len()),
        "strong_decompiled": protos.len(),
        "language": language,
        "int_slots": int_slots,
        "model": model.name,
        "pointer_size": machine.pointer_size,
        "functions": functions,
        "whatif_signatures": whatif_sigs.iter().map(|(a, s)| (format!("{a:08x}"), serde_json::json!({"params": s.params}))).collect::<BTreeMap<_, _>>(),
        "whatif_joins": whatif_log,
        "shipped_joins": shipped_log,
    });
    std::fs::write(Path::new(&out), serde_json::to_vec(&doc)?)?;
    Ok(())
}
