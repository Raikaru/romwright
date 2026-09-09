//! A closed, fully decoded intraprocedural graph can prove absence of a return.
//! Terminal flags alone, incomplete decoding, and indirect transfers cannot.
use super::{ImportError, Mapping, Result};
use crate::native_runtime::{FlowKind, FlowResult};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub(crate) struct FunctionFlow {
    pub instructions: HashSet<u64>,
    pub complete: bool,
    pub returns: bool,
    pub size: u64,
}

pub(crate) struct Analysis {
    pub non_returning: BTreeSet<u64>,
    pub functions: BTreeMap<u64, FunctionFlow>,
    /// Exact decoded call sites, excluding sites shared with incomplete flows.
    pub call_sites: BTreeSet<u64>,
    pub calls: BTreeSet<(u64, u64)>,
    pub callers: BTreeMap<u64, BTreeSet<u64>>,
    pub call_owners: BTreeMap<u64, BTreeSet<u64>>,
}

fn mapped(mappings: &[Mapping], address: u64, length: u64) -> bool {
    length != 0
        && address.checked_add(length).is_some()
        && mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address - mapping.vaddr < mapping.size
                && length <= mapping.size - (address - mapping.vaddr)
                && address - mapping.vaddr < mapping.bytes.len() as u64
                && length <= mapping.bytes.len() as u64 - (address - mapping.vaddr)
        })
}

fn walk(
    entry: u64,
    flows: &HashMap<u64, FlowResult>,
    mappings: &[Mapping],
    known: &BTreeSet<u64>,
    blocked: &BTreeSet<u64>,
) -> FunctionFlow {
    let mut result = FunctionFlow {
        instructions: HashSet::new(),
        complete: true,
        returns: false,
        size: 0,
    };
    let mut pending = vec![entry];
    while let Some(address) = pending.pop() {
        // A transfer to another established function is a tail transfer.
        // Explicit return-behavior facts take precedence over its body.
        if address != entry {
            if known.contains(&address) {
                continue;
            }
            if blocked.contains(&address) {
                result.returns = true;
                continue;
            }
        }
        if !result.instructions.insert(address) {
            continue;
        }
        let Some(flow) = flows
            .get(&address)
            .filter(|flow| mapped(mappings, address, flow.length as u64))
        else {
            result.complete = false;
            continue;
        };
        result.size = result
            .size
            .max((address + flow.length as u64).saturating_sub(entry));
        result.returns |= flow.return_op;
        let mut fallthrough = flow.fallthrough;
        match flow.kind {
            FlowKind::Bad | FlowKind::Unimpl | FlowKind::BranchInd | FlowKind::CallInd => {
                result.complete = false;
            }
            FlowKind::Return => {
                result.complete &= flow.return_op && (flow.conditional == fallthrough.is_some());
            }
            FlowKind::Branch | FlowKind::CBranch => {
                result.complete &= !flow.targets.is_empty()
                    && (flow.kind == FlowKind::CBranch) == flow.conditional
                    && flow.conditional == fallthrough.is_some();
                pending.extend(flow.targets.iter().copied());
            }
            FlowKind::Call => {
                result.complete &= !flow.targets.is_empty();
                if !flow.conditional
                    && !flow.targets.is_empty()
                    && flow.targets.iter().all(|target| known.contains(target))
                {
                    fallthrough = None;
                } else if fallthrough.is_none() {
                    result.complete = false;
                }
            }
            FlowKind::Fallthrough => {
                result.complete &= fallthrough.is_some() && flow.targets.is_empty();
            }
        }
        if let Some(next) = fallthrough {
            if Some(next) != address.checked_add(flow.length as u64) {
                result.complete = false;
            }
            pending.push(next);
        }
    }
    result
}

pub(crate) fn analyze(
    entries: &[u64],
    mappings: &[Mapping],
    known: &BTreeSet<u64>,
    blocked: &BTreeSet<u64>,
    mut query: impl FnMut(&[u64]) -> Result<Vec<FlowResult>>,
) -> Result<Analysis> {
    // Cache native instruction evidence once. Never turn a missing batch row
    // into an empty successor list: that would manufacture a closed graph.
    let mut flows = HashMap::new();
    let mut pending: BTreeSet<_> = entries.iter().copied().collect();
    while !pending.is_empty() {
        let batch: Vec<_> = pending.iter().copied().take(1024).collect();
        for address in &batch {
            pending.remove(address);
        }
        let addresses: Vec<_> = batch
            .into_iter()
            .filter(|address| !flows.contains_key(address) && mapped(mappings, *address, 1))
            .collect();
        if addresses.is_empty() {
            continue;
        }
        let replies = query(&addresses)?;
        if replies.len() != addresses.len()
            || replies
                .iter()
                .zip(&addresses)
                .any(|(flow, address)| flow.address != *address)
        {
            return Err(ImportError::Bad(
                "incomplete or mismatched nonreturn flow batch".into(),
            ));
        }
        for flow in replies {
            if mapped(mappings, flow.address, flow.length as u64)
                && !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl)
            {
                if let Some(next) = flow.fallthrough {
                    if !flows.contains_key(&next) {
                        pending.insert(next);
                    }
                }
                if matches!(flow.kind, FlowKind::Branch | FlowKind::CBranch) {
                    pending.extend(
                        flow.targets.iter().copied().filter(|target| {
                            *target != flow.address && !flows.contains_key(target)
                        }),
                    );
                }
            }
            flows.insert(flow.address, flow);
        }
    }
    let empty = BTreeSet::new();
    let mut functions: BTreeMap<_, _> = entries
        .iter()
        .map(|&entry| (entry, walk(entry, &flows, mappings, &empty, &empty)))
        .collect();
    let mut callers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut call_owners: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (&entry, function) in &functions {
        for address in &function.instructions {
            if *address != entry
                && (functions.contains_key(address)
                    || known.contains(address)
                    || blocked.contains(address))
            {
                callers.entry(*address).or_default().insert(entry);
            }
            if let Some(flow) = flows
                .get(address)
                .filter(|flow| flow.kind == FlowKind::Call)
            {
                call_owners.entry(*address).or_default().insert(entry);
                for target in &flow.targets {
                    callers.entry(*target).or_default().insert(entry);
                }
            }
        }
    }
    let mut non_returning: BTreeSet<_> = known.difference(blocked).copied().collect();
    // First apply all input assertions before deriving any new facts.
    pending.clear();
    for target in known.iter().chain(blocked) {
        if let Some(users) = callers.get(target) {
            pending.extend(users);
        }
    }
    for entry in std::mem::take(&mut pending) {
        functions.insert(
            entry,
            walk(entry, &flows, mappings, &non_returning, blocked),
        );
    }
    for (&entry, function) in &functions {
        if function.complete
            && !function.returns
            && !blocked.contains(&entry)
            && non_returning.insert(entry)
        {
            if let Some(users) = callers.get(&entry) {
                pending.extend(users);
            }
        }
    }
    // Each new fact is monotone; only callers of changed callees are revisited.
    while let Some(entry) = pending.pop_first() {
        let function = walk(entry, &flows, mappings, &non_returning, blocked);
        if function.complete
            && !function.returns
            && !blocked.contains(&entry)
            && non_returning.insert(entry)
        {
            if let Some(users) = callers.get(&entry) {
                pending.extend(users);
            }
        }
        functions.insert(entry, function);
    }
    let mut call_sites = BTreeSet::new();
    let mut calls = BTreeSet::new();
    for (&address, owners) in &call_owners {
        if owners.iter().all(|entry| functions[entry].complete) {
            call_sites.insert(address);
            if owners
                .iter()
                .any(|entry| functions[entry].instructions.contains(&address))
            {
                calls.extend(
                    flows[&address]
                        .targets
                        .iter()
                        .map(|target| (address, *target)),
                );
            }
        }
    }
    Ok(Analysis {
        non_returning,
        functions,
        call_sites,
        calls,
        callers,
        call_owners,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::Mapping;
    use crate::native_runtime::{FlowKind, FlowResult};
    use std::collections::{BTreeSet, HashMap};

    fn mapping() -> Mapping {
        Mapping {
            vaddr: 0x1000,
            size: 0x100,
            file_off: 0,
            flags: 6,
            bytes: vec![0; 0x100],
        }
    }

    fn flow(
        address: u64,
        kind: FlowKind,
        fallthrough: Option<u64>,
        targets: Vec<u64>,
    ) -> FlowResult {
        FlowResult {
            address,
            length: 1,
            fallthrough,
            targets,
            kind,
            pure_jump: false,
            no_op: false,
            terminal: kind == FlowKind::Return,
            conditional: kind == FlowKind::CBranch,
            return_op: kind == FlowKind::Return,
            delay_slots: Vec::new(),
            mode: None, target_modes: Vec::new(),
        }
    }

    #[test]
    fn closed_graph_proof_propagates_without_erasing_returning_paths() {
        use FlowKind::*;
        let flows: HashMap<_, _> = [
            flow(0x1000, Call, Some(0x1001), vec![0x1010]),
            flow(0x1001, Return, None, vec![]),
            flow(0x1010, Branch, None, vec![0x1010]),
            flow(0x1020, CBranch, Some(0x1021), vec![0x1000]),
            flow(0x1021, Return, None, vec![]),
            flow(0x1040, CallInd, Some(0x1041), vec![]),
            flow(0x1041, Return, None, vec![]),
            flow(0x1060, BranchInd, None, vec![]),
            flow(0x1080, Branch, None, vec![0x2000]),
            flow(0x1090, Fallthrough, Some(0x1091), vec![]),
            flow(0x1091, Bad, None, vec![]),
        ]
        .into_iter()
        .map(|flow| (flow.address, flow))
        .collect();
        let entries = [0x1000, 0x1010, 0x1020, 0x1040, 0x1060, 0x1080, 0x1090];
        let result = analyze(
            &entries,
            &[mapping()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            |addresses| {
                Ok(addresses
                    .iter()
                    .map(|address| flows[address].clone())
                    .collect())
            },
        )
        .unwrap();
        assert_eq!(result.non_returning, BTreeSet::from([0x1000, 0x1010]));
        assert!(!result.functions[&0x1000].instructions.contains(&0x1001));
        assert!(result.functions[&0x1020].instructions.contains(&0x1021));
        assert!(!result.functions[&0x1060].complete);
        assert!(!result.functions[&0x1080].complete);
        assert!(!result.functions[&0x1090].complete);
        let blocked = analyze(
            &entries,
            &[mapping()],
            &BTreeSet::new(),
            &BTreeSet::from([0x1010]),
            |addresses| {
                Ok(addresses
                    .iter()
                    .map(|address| flows[address].clone())
                    .collect())
            },
        )
        .unwrap();
        assert!(blocked.non_returning.is_empty());
    }

    #[test]
    fn conditional_calls_and_hidden_returns_prevent_false_nonreturn_facts() {
        use FlowKind::*;
        let mut conditional_call = flow(0x1000, Call, Some(0x1001), vec![0x1010]);
        conditional_call.conditional = true;
        let mut hidden_return = flow(0x1020, Branch, None, vec![0x1020]);
        hidden_return.return_op = true;
        hidden_return.terminal = true;
        let mut terminal_only = flow(0x1030, Return, None, vec![]);
        terminal_only.return_op = false;
        let flows: HashMap<_, _> = [
            conditional_call,
            flow(0x1001, Return, None, vec![]),
            flow(0x1010, Branch, None, vec![0x1010]),
            hidden_return,
            terminal_only,
        ]
        .into_iter()
        .map(|flow| (flow.address, flow))
        .collect();
        let result = analyze(
            &[0x1000, 0x1010, 0x1020, 0x1030],
            &[mapping()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            |addresses| {
                Ok(addresses
                    .iter()
                    .map(|address| flows[address].clone())
                    .collect())
            },
        )
        .unwrap();
        assert_eq!(result.non_returning, BTreeSet::from([0x1010]));
        assert!(result.functions[&0x1000].instructions.contains(&0x1001));
        assert!(!result.functions[&0x1030].complete);
    }

    #[test]
    fn missing_mismatched_and_out_of_mapping_flow_cannot_prove_nonreturn() {
        let empty = BTreeSet::new();
        assert!(analyze(&[0x1000], &[mapping()], &empty, &empty, |_| Ok(Vec::new())).is_err());
        assert!(
            analyze(&[0x1000], &[mapping()], &empty, &empty, |_| {
                Ok(vec![flow(0x1001, FlowKind::Branch, None, vec![0x1001])])
            })
            .is_err()
        );
        for (entry, length) in [(0x1000, 0), (0x10ff, 2)] {
            let result = analyze(&[entry], &[mapping()], &empty, &empty, |_| {
                let mut result = flow(entry, FlowKind::Branch, None, vec![entry]);
                result.length = length;
                Ok(vec![result])
            })
            .unwrap();
            assert!(result.non_returning.is_empty());
            assert!(!result.functions[&entry].complete);
        }
    }
}