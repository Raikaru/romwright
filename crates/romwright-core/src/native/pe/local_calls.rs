//! Local procedures and trailing data: what Visual C++ leaves behind a function that is not a function.
//!
//! **Local procedures.** A `__try { } __finally { }`, a CRT lock region (`_lock_file` ... `_unlock_file`) and a
//! structured-exception handler's cleanup are compiled as code behind the function's last `ret` that the function
//! reaches with a `call` and leaves with a `ret`. They are part of the function (the PDB's `S_GPROC32` extent covers
//! them, the frame's unwind table says so), but flow sees a call, and a call target is a function to every analyzer.
//!
//! The shape that tells them from a helper that happens to follow its only caller: the target starts exactly where
//! the preceding function's body ends (no alignment fill: Visual C++ aligns the functions it emits as separate
//! units), and every reference to it is a `call` from inside that preceding function. Nothing else names it: not a
//! symbol, an export, a linkage stub, a pattern the importer accepted, a data pointer or a constant. Such a target
//! is folded into the preceding function. A block of more than [`LARGEST`] bytes is left alone.
//!
//! **Trailing data.** The data a compiler puts behind the code that uses it (the frame description a Debug build's
//! run-time checks `_RTC_CheckStackVars` read, a jump table, their name tables) is named by that function's own code
//! and by the data itself. An entry with no evidence of its own (no call, symbol, accepted pattern, linkage stub or
//! pointer in data) that starts behind the body of the function before it, ahead of the next entry that has some,
//! and that only addresses inside that stretch name, whose decoded body does not end in a return or a jump, is that
//! function's trailing data. It is dropped.

use std::collections::{HashMap, HashSet};

use crate::native::{NativeFunction, NativeImport};
use crate::native_runtime::FlowKind;

/// Local procedures are small: the largest in the Quake 2 CRT is a few dozen bytes.
const LARGEST: u64 = 0x100;

/// `functions` (sorted by entry) with the local procedures folded into the function before them and the trailing
/// data dropped.
pub(in crate::native) fn fold(imp: &NativeImport, functions: Vec<NativeFunction>) -> Vec<NativeFunction> {
    if imp.format != "PE" || imp.language != "x86:LE:32:default" {
        return functions;
    }
    let ctx = crate::compiler::ctx_of(imp);
    let calls = crate::compiler::rules::applies("pe-x86-local-calls", &ctx);
    let tables = crate::compiler::rules::applies("pe-x86-trailing-data", &ctx);
    let runs = crate::compiler::rules::applies("pe-x86-case-runs", &ctx);
    if !calls && !tables && !runs {
        return functions;
    }
    // The exception dispatcher's scope-table words name a handler the function itself pushed the table for.
    let scope_sites = super::x86_operands::scope_table_sites(imp);
    let mut referrers: HashMap<u64, Vec<(u64, bool)>> = HashMap::new();
    for xref in &imp.xrefs {
        if scope_sites.contains(&xref.from) {
            continue;
        }
        referrers.entry(xref.to).or_default().push((xref.from, xref.kind.contains("CALL")));
    }
    let named: HashSet<u64> = imp
        .symbol_named
        .iter()
        .copied()
        .chain(imp.thunks.iter().map(|thunk| thunk.entry))
        .chain(imp.pattern_starts.iter().copied())
        .chain(imp.pointer_slots.iter().map(|(_, target)| *target))
        .chain(imp.initializer_slots.iter().map(|(_, target)| *target))
        .chain(imp.const_data_starts.iter().copied())
        .collect();
    let mut functions = functions;
    if calls {
        let mut kept: Vec<NativeFunction> = Vec::with_capacity(functions.len());
        for function in functions {
            let folds = kept.last().is_some_and(|before| {
                let end = before.entry + before.size;
                end == function.entry
                    && function.size <= LARGEST
                    && function.name.starts_with("FUN_")
                    && !named.contains(&function.entry)
                    && referrers.get(&function.entry).is_some_and(|from| {
                        !from.is_empty()
                            && from.iter().all(|&(site, call)| call && site >= before.entry && site < end)
                    })
            });
            if folds {
                let before = kept.last_mut().expect("checked above");
                before.size = function.entry + function.size - before.entry;
            } else {
                kept.push(function);
            }
        }
        functions = kept;
    }
    if tables || runs {
        functions = drop_trailing_data(imp, functions, &referrers, &named, tables, runs);
    }
    functions
}

/// Targets of the runs of four or more adjacent relocated words naming code that all lie in one stretch between two
/// entries with evidence of their own, none of them such an entry: the case labels of one function's switch.
fn case_run_targets(imp: &NativeImport, strong_entries: &[u64], strong_of: &dyn Fn(u64) -> bool) -> (HashSet<u64>, HashSet<u64>) {
    let in_code = |address: u64| {
        imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0 && address >= mapping.vaddr && address - mapping.vaddr < mapping.size
        })
    };
    let mut words: Vec<(u64, u64)> = imp
        .xrefs
        .iter()
        .filter(|x| x.kind == "DATA" && x.provenance == "native-import:pe-reloc" && in_code(x.to) && !in_code(x.from))
        .map(|x| (x.from, x.to))
        .collect();
    words.sort_unstable();
    words.dedup_by_key(|&mut (from, _)| from);
    let (mut targets, mut sites) = (HashSet::new(), HashSet::new());
    let mut start = 0;
    for index in 1..=words.len() {
        if index < words.len() && words[index].0 == words[index - 1].0 + 4 {
            continue;
        }
        let run = &words[start..index];
        start = index;
        if run.len() < 4 {
            continue;
        }
        let stretch = |target: u64| strong_entries.partition_point(|&entry| entry <= target);
        let first = stretch(run[0].1);
        if first > 0 && run.iter().all(|&(_, target)| stretch(target) == first && !strong_of(target)) {
            targets.extend(run.iter().map(|&(_, target)| target));
            sites.extend(run.iter().map(|&(site, _)| site));
        }
    }
    (targets, sites)
}

fn drop_trailing_data(
    imp: &NativeImport,
    functions: Vec<NativeFunction>,
    referrers: &HashMap<u64, Vec<(u64, bool)>>,
    named: &HashSet<u64>,
    trailing: bool,
    case_runs: bool,
) -> Vec<NativeFunction> {
    let called: HashSet<u64> = imp
        .xrefs
        .iter()
        .filter(|xref| xref.kind.contains("CALL"))
        .map(|xref| xref.to)
        .collect();
    // Entries with evidence of their own. A constant-propagation seed is not: it is the kind of entry being judged.
    let consted: HashSet<u64> = imp.const_data_starts.iter().copied().collect();
    let strong = |function: &NativeFunction| {
        !function.name.starts_with("FUN_")
            || called.contains(&function.entry)
            || (named.contains(&function.entry) && !consted.contains(&function.entry))
    };
    let strong_entries: Vec<u64> = functions.iter().filter(|function| strong(function)).map(|function| function.entry).collect();
    // The decoded instructions, to see how a body ends: a function the walk proved ends in a return or a jump; bytes
    // of data that decoded as code end where decoding stopped.
    let mut shapes: Vec<(u64, FlowKind)> = imp.flow_shapes.iter().map(|shape| (shape.address, shape.kind)).collect();
    shapes.sort_unstable_by_key(|&(address, _)| address);
    let ends_properly = |function: &NativeFunction| {
        let end = function.entry + function.size;
        let index = shapes.partition_point(|&(address, _)| address < end);
        index
            .checked_sub(1)
            .map(|last| shapes[last])
            .is_some_and(|(address, kind)| {
                address >= function.entry && matches!(kind, FlowKind::Return | FlowKind::Branch | FlowKind::BranchInd)
            })
    };
    let strong_set: HashSet<u64> = functions.iter().filter(|function| strong(function)).map(|function| function.entry).collect();
    let (case_targets, case_sites) = if case_runs {
        case_run_targets(imp, &strong_entries, &|target| strong_set.contains(&target))
    } else {
        (HashSet::new(), HashSet::new())
    };
    let mut kept: Vec<NativeFunction> = Vec::with_capacity(functions.len());
    let mut owner: Option<(u64, u64)> = None; // the last strong function: entry, end of its body
    for function in functions {
        if strong(&function) {
            owner = Some((function.entry, function.entry + function.size));
            kept.push(function);
            continue;
        }
        // A case label of one function's switch: only the words of such a run name it.
        if case_targets.contains(&function.entry)
            && referrers.get(&function.entry).is_some_and(|from| from.iter().all(|&(site, _)| case_sites.contains(&site)))
        {
            continue;
        }
        let dropped = trailing && owner.is_some_and(|(entry, end)| {
            let next = strong_entries.partition_point(|&strong| strong <= function.entry);
            let limit = strong_entries.get(next).copied().unwrap_or(u64::MAX);
            function.entry >= end
                && !ends_properly(&function)
                && referrers.get(&function.entry).is_some_and(|from| {
                    !from.is_empty() && from.iter().all(|&(site, _)| site >= entry && site < limit)
                })
        });
        if !dropped {
            kept.push(function);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::NativeXref;

    fn function(entry: u64, size: u64) -> NativeFunction {
        NativeFunction { entry, name: format!("FUN_{entry:08x}"), size }
    }

    fn image(functions: &[NativeFunction], calls: &[(u64, u64)]) -> NativeImport {
        let mut imp = NativeImport {
            format: "PE".into(),
            language: "x86:LE:32:default".into(),
            functions: functions.to_vec(),
            ..Default::default()
        };
        imp.xrefs = calls.iter().map(|&(from, to)| NativeXref::new(from, to, "UNCONDITIONAL_CALL")).collect();
        imp.identity = Some(crate::compiler::Detection::found("msvc-14", crate::compiler::Confidence::High, vec![]));
        imp
    }

    #[test]
    fn a_block_only_its_predecessor_calls_and_that_starts_where_it_ends_is_folded() {
        let functions = [function(0x1000, 0x40), function(0x1040, 0x10), function(0x1050, 0x20)];
        let imp = image(&functions, &[(0x1010, 0x1040), (0x2000, 0x1050)]);
        let folded = fold(&imp, functions.to_vec());
        assert_eq!(folded.iter().map(|f| (f.entry, f.size)).collect::<Vec<_>>(), [(0x1000, 0x50), (0x1050, 0x20)]);
    }

    #[test]
    fn the_case_labels_of_one_function_are_dropped_and_an_array_of_functions_is_not() {
        // 0x1000 and 0x1200 are called (strong); 0x1020..0x1050 lie between them
        let functions = [
            function(0x1000, 0x10), function(0x1020, 0x10), function(0x1030, 0x10), function(0x1040, 0x10),
            function(0x1050, 0x10), function(0x1200, 0x20),
        ];
        let mut imp = image(&functions, &[(0x5000, 0x1000), (0x5000, 0x1200)]);
        imp.mappings.push(crate::native::Mapping { vaddr: 0x401000, size: 0x1000, file_off: 0, flags: 5, bytes: vec![0; 0x1000] });
        let functions = functions.map(|f| NativeFunction { entry: f.entry + 0x400000, ..f });
        imp.functions = functions.to_vec();
        imp.xrefs = [(0x5000u64, 0x1000u64), (0x5000, 0x1200)]
            .iter()
            .map(|&(from, to)| NativeXref::new(from + 0x400000, to + 0x400000, "UNCONDITIONAL_CALL"))
            .collect();
        for (index, target) in [0x1020u64, 0x1030, 0x1040, 0x1050].iter().enumerate() {
            imp.xrefs.push(NativeXref::with_provenance(0x800000 + 4 * index as u64, target + 0x400000, "DATA", "native-import:pe-reloc"));
        }
        let kept = fold(&imp, functions.to_vec());
        assert_eq!(kept.iter().map(|f| f.entry).collect::<Vec<_>>(), [0x401000, 0x401200]);
        // a run that reaches the next strong entry is an array of functions
        imp.xrefs.pop();
        imp.xrefs.push(NativeXref::with_provenance(0x80000c, 0x401200, "DATA", "native-import:pe-reloc"));
        assert_eq!(fold(&imp, functions.to_vec()).len(), 6);
    }

    #[test]
    fn a_target_with_a_caller_elsewhere_or_after_alignment_fill_is_a_function() {
        let functions = [function(0x1000, 0x40), function(0x1050, 0x10)];
        let imp = image(&functions, &[(0x1010, 0x1050)]);
        assert_eq!(fold(&imp, functions.to_vec()).len(), 2, "fill between: a function of its own");
        let functions = [function(0x1000, 0x40), function(0x1040, 0x10)];
        let imp = image(&functions, &[(0x1010, 0x1040), (0x3000, 0x1040)]);
        assert_eq!(fold(&imp, functions.to_vec()).len(), 2, "called from elsewhere too");
    }

    #[test]
    fn data_behind_a_function_that_only_it_and_the_data_name_is_dropped() {
        // 0x1000 is called (strong); 0x1040 and 0x1054 trail it, ahead of 0x1080 (called); the code takes the first,
        // the first takes the second
        let functions = [function(0x1000, 0x3c), function(0x1040, 0x9), function(0x1054, 0x3), function(0x1080, 0x20)];
        let mut imp = image(&functions, &[(0x5000, 0x1000), (0x5000, 0x1080)]);
        imp.xrefs.push(NativeXref::new(0x1010, 0x1040, "DATA"));
        imp.xrefs.push(NativeXref::new(0x1050, 0x1054, "DATA"));
        // what decoded there is a few instructions that run into something undecodable
        for (address, kind) in [(0x1044, FlowKind::Fallthrough), (0x1056, FlowKind::Fallthrough), (0x1080, FlowKind::Return)] {
            imp.flow_shapes.push(crate::native::FlowShape { address, length: 2, kind, conditional: false, target: None });
        }
        let kept = fold(&imp, functions.to_vec());
        assert_eq!(kept.iter().map(|f| f.entry).collect::<Vec<_>>(), [0x1000, 0x1080]);
        // a pointer in data elsewhere makes the first one an entry the code names from outside
        imp.xrefs.push(NativeXref::new(0x9000, 0x1040, "DATA"));
        assert!(fold(&imp, functions.to_vec()).iter().any(|f| f.entry == 0x1040));
        // a body that ends in a return is a function whoever names it
        let mut proper = image(&functions, &[(0x5000, 0x1000), (0x5000, 0x1080)]);
        proper.xrefs.push(NativeXref::new(0x1010, 0x1040, "DATA"));
        proper.flow_shapes.push(crate::native::FlowShape { address: 0x1046, length: 1, kind: FlowKind::Return, conditional: false, target: None });
        assert!(fold(&proper, functions.to_vec()).iter().any(|f| f.entry == 0x1040));
    }
}
