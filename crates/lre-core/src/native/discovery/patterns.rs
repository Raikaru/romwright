//! Ghidra FunctionStartAnalyzer/PseudoDisassembler prerequisites (Apache-2.0).
//! A byte-pattern match is evidence to check, never an instruction or function.
use super::{FlowKind, FlowProvider, NativeImport};
use crate::native::ExtentIndex;
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub(super) struct CodeRequirement {
    pub minimum: usize,
    pub maximum: usize,
    pub must_terminate: bool,
    pub contiguous: bool,
}

fn loaded_byte(import: &NativeImport, address: u64) -> Option<u8> {
    let mapping = import
        .mappings
        .iter()
        .find(|mapping| address >= mapping.vaddr && address - mapping.vaddr < mapping.size)?;
    if !mapping.bytes.is_empty() {
        return mapping
            .bytes
            .get((address - mapping.vaddr) as usize)
            .copied();
    }
    // Initialized bytes already contain loader fixups; only zero-fill mappings
    // need the separately retained relocation overlay.
    for relocation in &import.relocations {
        if let Some(offset) = address.checked_sub(relocation.address) {
            if offset < relocation.width as u64 {
                return Some(relocation.bytes[offset as usize]);
            }
        }
    }
    Some(0)
}

fn contains(extents: &[(u64, u64)], address: u64) -> bool {
    extents
        .iter()
        .any(|&(start, end)| start <= address && address < end)
}

/// Instruction extents are sorted by address and their lengths come from the
/// u8 FLOW protocol. A bounded look-behind also handles overlapping starts;
/// checking only the closest preceding instruction would miss longer spans.
fn nearby_instructions(
    instructions: &[(u64, u64)],
    start: u64,
    end: u64,
) -> impl Iterator<Item = &(u64, u64)> {
    let lower = start.saturating_sub(u64::from(u8::MAX));
    let first = instructions.partition_point(|&(address, _)| address < lower);
    instructions[first..]
        .iter()
        .take_while(move |&&(address, _)| address < end)
}

/// Follows the source validator's bounded control-flow walk. Delay slots belong
/// to the body but do not contribute to its contiguous instruction count.
/// Per-round indexes over the whole image for pattern validation: every
/// check below used to scan functions, relocations or xrefs per match.
/// Built once per pattern round; the round's accepts only add entries,
/// which the walk re-derives next round.
pub(super) struct PatternIndexes {
    pub entries: HashSet<u64>,
    pub funcs: ExtentIndex,
    pub data_targets: HashSet<u64>,
    pub nondata_targets: HashSet<u64>,
    pub all_targets: BTreeSet<u64>,
    pub data: BTreeMap<u64, u64>,
    pub max_data_width: u64,
}

impl PatternIndexes {
    pub fn build(import: &NativeImport, entries: &HashSet<u64>) -> Self {
        let mut data_targets = HashSet::new();
        let mut nondata_targets = HashSet::new();
        let mut all_targets = BTreeSet::new();
        for xref in &import.xrefs {
            // `to` names code the reference reaches (owned-by-reference,
            // body-range checks); `from` names the referencing site, which
            // is what a relocation address matches for the data ranges.
            all_targets.insert(xref.to);
            if xref.kind == "DATA" {
                data_targets.insert(xref.from);
            } else {
                nondata_targets.insert(xref.to);
            }
        }
        let mut data = BTreeMap::new();
        let mut max_data_width = 0u64;
        for relocation in &import.relocations {
            if !data_targets.contains(&relocation.address) {
                continue;
            }
            if let Some(end) = relocation.address.checked_add(relocation.width as u64) {
                // Same start twice keeps the widest end.
                data.entry(relocation.address)
                    .and_modify(|kept: &mut u64| *kept = (*kept).max(end))
                    .or_insert(end);
                max_data_width = max_data_width.max(relocation.width as u64);
            }
        }
        let funcs = ExtentIndex::build(
            &import
                .functions
                .iter()
                .map(|f| (f.entry, f.size))
                .collect::<Vec<_>>(),
        );
        PatternIndexes {
            entries: entries.clone(),
            funcs,
            data_targets,
            nondata_targets,
            all_targets,
            data,
            max_data_width,
        }
    }

    /// A relocation data range covering the address (inclusive start).
    pub fn data_contains(&self, address: u64) -> bool {
        self.data
            .range(..=address)
            .next_back()
            .is_some_and(|(&start, &end)| address - start < end - start)
    }

    /// A relocation data range overlapping [start, end).
    pub fn data_overlaps(&self, start: u64, end: u64) -> bool {
        // Any overlapping range starts within max_data_width before start.
        let from = start.saturating_sub(self.max_data_width);
        self.data
            .range(from..end)
            .any(|(&range_start, &range_end)| range_start < end && start < range_end)
    }
}

pub(super) fn valid_code<P: FlowProvider>(
    import: &NativeImport,
    entry: u64,
    requirement: &CodeRequirement,
    indexes: &PatternIndexes,
    instructions: &[(u64, u64)],
    provider: &mut P,
) -> Option<Vec<(u64, u64)>> {
    let mut nonzero = false;
    for offset in 0..8 {
        let byte = entry
            .checked_add(offset)
            .and_then(|address| loaded_byte(import, address))?;
        nonzero |= byte != 0;
    }
    if !nonzero {
        return None;
    }
    let mut body = Vec::new();
    let mut starts = HashSet::new();
    let mut pending = Vec::new();
    let mut targets = Vec::new();
    let mut target = Some(entry);
    let mut contiguous_end = None;
    let mut count = 0;
    let mut terminated = false;
    let mut valid_call = false;
    let mut repeat_byte = None;
    let mut repeat_count = 0;
    for _ in 0..requirement.maximum {
        let Some(address) = target else { break };
        let mut flows = provider.flow(&[address]);
        let Some(flow) = flows.pop() else {
            return None;
        };
        if !flows.is_empty()
            || flow.address != address
            || flow.length == 0
            || matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl)
        {
            return None;
        }
        let Some(end) = address.checked_add(flow.length as u64) else {
            return None;
        };
        let slots: u64 = flow
            .delay_slots
            .iter()
            .map(|&length| u64::from(length))
            .sum();
        if slots >= u64::from(flow.length) {
            return None;
        }
        let instruction_end = end - slots;
        // Existing starts are allowed; offcut decoding and overlapping pseudo
        // instructions are not. Extent inputs use (address, length).
        if nearby_instructions(instructions, address, instruction_end).any(|&(start, length)| {
            let end = start.saturating_add(length);
            start < instruction_end && address < end && start != address
        }) || body
            .iter()
            .any(|&(start, end)| start < instruction_end && address < end)
        {
            return None;
        }
        if contiguous_end.is_none() || !requirement.contiguous || contiguous_end == Some(address) {
            count += 1;
            contiguous_end = Some(instruction_end);
        }
        let mut repeated = loaded_byte(import, address);
        for byte_address in address..instruction_end {
            let Some(byte) = loaded_byte(import, byte_address) else {
                return None;
            };
            if Some(byte) != repeated {
                repeated = None;
            }
        }
        if repeated.is_some() && repeated == repeat_byte {
            repeat_count += 1;
            if repeat_count > 4 {
                return None;
            }
        } else {
            repeat_byte = repeated;
            repeat_count = usize::from(repeated.is_some());
        }
        body.push((address, instruction_end));
        starts.insert(address);
        let mut slot_address = instruction_end;
        for &length in &flow.delay_slots {
            let mut slots = provider.flow(&[slot_address]);
            let Some(slot) = slots.pop() else {
                return None;
            };
            if length == 0
                || !slots.is_empty()
                || slot.address != slot_address
                || slot.length != length
                || !slot.delay_slots.is_empty()
                || matches!(slot.kind, FlowKind::Bad | FlowKind::Unimpl)
            {
                return None;
            }
            let slot_end = slot_address + u64::from(length);
            if nearby_instructions(instructions, slot_address, slot_end).any(|&(start, length)| {
                start != address
                    && start < slot_end
                    && slot_address < start.saturating_add(length)
                    && start != slot_address
            }) || body
                .iter()
                .any(|&(start, end)| start < slot_end && slot_address < end)
            {
                return None;
            }
            body.push((slot_address, slot_end));
            starts.insert(slot_address);
            slot_address = slot_end;
        }
        terminated |= flow.terminal && flow.return_op;
        let jump = matches!(
            flow.kind,
            FlowKind::Branch | FlowKind::CBranch | FlowKind::BranchInd
        );
        let call = matches!(flow.kind, FlowKind::Call | FlowKind::CallInd);
        target = flow.fallthrough.or_else(|| {
            if targets.contains(&end) {
                Some(end)
            } else if jump {
                flow.targets
                    .iter()
                    .copied()
                    .find(|&to| !contains(&body, to))
            } else {
                None
            }
        });
        if jump {
            for &to in &flow.targets {
                if flow.fallthrough == Some(to) && flow.delay_slots.is_empty() {
                    return None;
                }
                if indexes.entries.contains(&to) {
                    valid_call = true;
                    target = None;
                } else {
                    targets.push(to);
                    pending.push(to);
                }
            }
            if flow.kind == FlowKind::BranchInd && flow.targets.is_empty() {
                terminated = true;
            }
        }
        if call || flow.kind == FlowKind::BranchInd {
            valid_call |= flow.targets.iter().any(|to| indexes.entries.contains(to));
        }
        if target.is_none() {
            while let Some(next) = pending.pop() {
                if !contains(&body, next) {
                    target = Some(next);
                    break;
                }
            }
        }
    }
    let valid = count >= requirement.minimum
        && (!requirement.must_terminate || terminated || valid_call)
        && targets
            .iter()
            .all(|&to| !contains(&body, to) || starts.contains(&to))
        && body.iter().all(|&(start, end)| {
            // An xref target strictly inside the segment must be one of
            // the walk's own starts: body starts are all in `starts`, so
            // excluding segment starts here changes no verdict, and
            // anything else owns those bytes.
            indexes
                .all_targets
                .range((start + 1)..end)
                .all(|to| starts.contains(to))
        })
        && body
            .iter()
            .all(|&(start, end)| !indexes.data_overlaps(start, end));
    valid.then_some(body)
}

#[derive(Clone, Copy)]
pub(super) struct Candidate {
    pub address: u64,
    pub possible: bool,
}

pub(super) fn collect<P: FlowProvider>(
    import: &NativeImport,
    patterns: &crate::native_runtime::FunctionPatterns,
    indexes: &PatternIndexes,
    instructions: &[(u64, u64)],
    conditional_targets: &HashSet<u64>,
    fell_into: &HashSet<u64>,
    refused: &mut std::collections::BTreeMap<String, u64>,
    applied: &mut Vec<crate::native::NativeContext>,
    provider: &mut P,
) -> super::Result<Vec<Candidate>> {
    let mut refuse = |reason: &str, refused: &mut std::collections::BTreeMap<String, u64>| {
        *refused.entry(reason.to_string()).or_default() += 1;
    };
    let mut candidates = Vec::new();
    // Bodies the round's earlier accepted matches decoded, in address order.
    // Ghidra disassembles every match of a pass in that order and a later
    // start landing inside an instruction is a conflict it skips; its
    // delayed creator then finds a function already containing the address
    // (PossibleDelayedFunctionCreator, 1001-1012).
    let mut round_bodies = ExtentIndex::build(&[]);
    for hit in &patterns.matches {
        let address = hit.address;
        if indexes.data_contains(address) {
            refuse("data-slot", refused);
            continue;
        }
        if round_bodies.contains(address) {
            refuse("offcut", refused);
            continue;
        }
        if address % patterns.alignment != 0 {
            refuse("alignment", refused);
            continue;
        }
        if indexes.entries.contains(&address) {
            refuse("known-entry", refused);
            continue;
        }
        if indexes.funcs.contains(address) {
            refuse("in-known-body", refused);
            continue;
        }
        // nothing above flows into it (FunctionStartAnalyzer.applyActionToSet,
        // 289-324). Offcut inside an instruction is never a start.
        if nearby_instructions(instructions, address, address.saturating_add(1))
            .any(|&(start, length)| start < address && address - start < length)
        {
            refuse("offcut", refused);
            continue;
        }
        let decoded_here = nearby_instructions(instructions, address, address.saturating_add(1))
            .any(|&(start, _)| start == address);
        if decoded_here {
            if fell_into.contains(&address) {
                refuse("flows-in-above", refused);
                continue;
            }
            // Any reference other than a plain data reference means some other
            // flow already created this location (checkAlreadyInFunctionAbove,
            // 514-527).
            if indexes.nondata_targets.contains(&address)
            {
                refuse("owned-by-reference", refused);
                continue;
            }
        }
        let rule = &patterns.rules[hit.rule];
        // A declared processor mode is applied first, and only where nothing
        // has been decoded yet: Ghidra queues the value in `ContextAction` and
        // lays it down from `setCurrentContext` before scheduling the
        // disassembly that the same match asks for
        // (FunctionStartAnalyzer, 133-150 and 709-742). Applying it after the
        // bytes were read in the other mode would prove nothing.
        // Ghidra lays the value down at the one address (setCurrentContext,
        // 133-150); the console paints it to the next change point, so a
        // match refused below hands the region back the value it held.
        let mut restore: Vec<(String, u64)> = Vec::new();
        let mut pushed = 0usize;
        for action in &rule.actions {
            if action.kind != "setcontext" || decoded_here {
                continue;
            }
            let Some(name) = action.attributes.get("name") else {
                return Err(super::ImportError::Bad(format!(
                    "pattern setcontext without a register name: {}",
                    rule.file
                )));
            };
            let value = action
                .attributes
                .get("value")
                .ok_or_else(|| {
                    super::ImportError::Bad(format!(
                        "pattern setcontext without a value: {}",
                        rule.file
                    ))
                })?
                .parse::<u64>()
                .map_err(|error| {
                    super::ImportError::Bad(format!("invalid pattern context value: {error}"))
                })?;
            if let Some(held) = provider
                .flow(&[address])
                .pop()
                .filter(|flow| flow.address == address)
                .and_then(|flow| flow.mode)
            {
                if held != value {
                    restore.push((name.clone(), held));
                }
            }
            provider.set_context(name, address, value);
            applied.push(crate::native::NativeContext {
                name: name.clone(),
                address,
                value,
            });
            pushed += 1;
        }
        let mut accepted = None;
        for action in &rule.actions {
            match action.kind.as_str() {
                "codeboundary" | "setcontext" => continue,
                "funcstart" | "possiblefuncstart" => {}
                kind => {
                    return Err(super::ImportError::Bad(format!(
                        "unknown pattern action: {kind}"
                    )))
                }
            }
            if action.kind == "possiblefuncstart" && conditional_targets.contains(&address) {
                refuse("possible-conditional-target", refused);
                continue;
            }
            let attribute = |name| action.attributes.get(name).map(String::as_str);
            if attribute("section").is_some() {
                return Err(super::ImportError::Bad(format!(
                    "function-pattern section prerequisite is unavailable: {}",
                    rule.file
                )));
            }
            let valid = attribute("validcode").unwrap_or(if attribute("validcodemax").is_some() {
                "subroutine"
            } else {
                "0"
            });
            if valid.eq_ignore_ascii_case("function") {
                // This action annotates an existing function, never creates one.
                refuse("annotation-only", refused);
                continue;
            }
            if let Some(after) = attribute("after") {
                let block_start = import
                    .mappings
                    .iter()
                    .any(|mapping| mapping.vaddr == address)
                    || address.checked_sub(1).is_none_or(|previous| {
                        !import.mappings.iter().any(|mapping| {
                            previous >= mapping.vaddr && previous - mapping.vaddr < mapping.size
                        })
                    });
                let instruction_before =
                    nearby_instructions(instructions, address.saturating_sub(1), address)
                        .any(|&(start, length)| start < address && address - start <= length);
                let data_before = address
                    .checked_sub(1)
                    .is_some_and(|previous| indexes.data_contains(previous));
                let has_references = indexes.data_targets.contains(&address)
                    || indexes.nondata_targets.contains(&address);
                let pure_data =
                    has_references
                        && indexes.data_targets.contains(&address)
                        && !indexes.nondata_targets.contains(&address);
                let satisfied = if after.starts_with("func") || after.starts_with("inst") {
                    // Input instructions have already been reached from functions.
                    instruction_before
                } else if after.starts_with("data") {
                    data_before
                } else if after.starts_with("ptr") {
                    pure_data
                } else if after.starts_with("def") {
                    instruction_before || data_before || pure_data
                } else {
                    return Err(super::ImportError::Bad(format!(
                        "invalid pattern after prerequisite: {after}"
                    )));
                };
                if !block_start && !satisfied {
                    refuse("after-prerequisite", refused);
                    continue;
                }
            }
            let minimum =
                if valid.eq_ignore_ascii_case("true") || valid.eq_ignore_ascii_case("subroutine") {
                    -1
                } else if valid == "false" {
                    0
                } else {
                    valid.parse::<i32>().map_err(|error| {
                        super::ImportError::Bad(format!("invalid validcode: {error}"))
                    })?
                };
            if minimum != 0 {
                let maximum = attribute("validcodemax")
                    .map(str::parse::<i32>)
                    .transpose()
                    .map_err(|error| {
                        super::ImportError::Bad(format!("invalid validcodemax: {error}"))
                    })?
                    .unwrap_or(minimum);
                let requirement = CodeRequirement {
                    minimum: minimum.max(0) as usize,
                    maximum: if maximum > 0 { maximum as usize } else { 4000 },
                    must_terminate: minimum < 0,
                    contiguous: !attribute("contiguous")
                        .is_some_and(|value| value.eq_ignore_ascii_case("false")),
                };
                let Some(body) = valid_code(
                    import,
                    address,
                    &requirement,
                    indexes,
                    instructions,
                    provider,
                ) else {
                    refuse("valid-code", refused);
                    continue;
                };
                for (start, end) in body {
                    round_bodies.insert(start, end - start);
                }
            } else {
                let flows = provider.flow(&[address]);
                if flows.len() != 1
                    || flows[0].address != address
                    || flows[0].length == 0
                    || matches!(flows[0].kind, FlowKind::Bad | FlowKind::Unimpl)
                {
                    refuse("undecodable", refused);
                    continue;
                }
                round_bodies.insert(address, flows[0].length as u64);
            }
            let candidate = Candidate {
                address,
                possible: action.kind == "possiblefuncstart",
            };
            candidates.push(candidate);
            accepted = Some(candidate);
        }
        if accepted.is_none() {
            for (name, held) in restore {
                provider.set_context(&name, address, held);
            }
            applied.truncate(applied.len() - pushed);
        }
    }
    // A definite action wins over a possible action at the same address.
    candidates.sort_unstable_by_key(|candidate| (candidate.address, candidate.possible));
    candidates.dedup_by_key(|candidate| candidate.address);
    Ok(candidates)
}
