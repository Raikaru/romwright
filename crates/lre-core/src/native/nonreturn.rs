#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::Mapping;
    use crate::native_runtime::{FlowKind, FlowResult};
    use std::collections::{BTreeSet, HashMap};

    fn mapping() -> Mapping {
        Mapping { vaddr: 0x1000, size: 0x100, file_off: 0, flags: 6, bytes: vec![0; 0x100] }
    }

    fn flow(address: u64, kind: FlowKind, fallthrough: Option<u64>, targets: Vec<u64>) -> FlowResult {
        FlowResult { address, length: 1, fallthrough, targets, kind, pure_jump: false, no_op: false,
            terminal: kind == FlowKind::Return, conditional: kind == FlowKind::CBranch,
            return_op: kind == FlowKind::Return, delay_slots: Vec::new() }
    }

    #[test]
    fn closed_graph_proof_propagates_without_erasing_returning_paths() {
        use FlowKind::*;
        let flows: HashMap<_, _> = [
            flow(0x1000, Call, Some(0x1001), vec![0x1010]), flow(0x1001, Return, None, vec![]),
            flow(0x1010, Branch, None, vec![0x1010]),
            flow(0x1020, CBranch, Some(0x1021), vec![0x1000]), flow(0x1021, Return, None, vec![]),
            flow(0x1040, CallInd, Some(0x1041), vec![]), flow(0x1041, Return, None, vec![]),
            flow(0x1060, BranchInd, None, vec![]), flow(0x1080, Branch, None, vec![0x2000]),
            flow(0x1090, Fallthrough, Some(0x1091), vec![]), flow(0x1091, Bad, None, vec![]),
        ].into_iter().map(|flow| (flow.address, flow)).collect();
        let entries = [0x1000, 0x1010, 0x1020, 0x1040, 0x1060, 0x1080, 0x1090];
        let result = analyze(&entries, &[mapping()], &BTreeSet::new(), &BTreeSet::new(), |addresses| {
            Ok(addresses.iter().map(|address| flows[address].clone()).collect())
        }).unwrap();
        assert_eq!(result.non_returning, BTreeSet::from([0x1000, 0x1010]));
        assert!(!result.functions[&0x1000].instructions.contains(&0x1001));
        assert!(result.functions[&0x1020].instructions.contains(&0x1021));
        assert!(!result.functions[&0x1060].complete);
        assert!(!result.functions[&0x1080].complete);
        assert!(!result.functions[&0x1090].complete);
        let blocked = analyze(&entries, &[mapping()], &BTreeSet::new(), &BTreeSet::from([0x1010]), |addresses| {
            Ok(addresses.iter().map(|address| flows[address].clone()).collect())
        }).unwrap();
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
        let flows: HashMap<_, _> = [conditional_call, flow(0x1001, Return, None, vec![]),
            flow(0x1010, Branch, None, vec![0x1010]), hidden_return, terminal_only]
            .into_iter().map(|flow| (flow.address, flow)).collect();
        let result = analyze(&[0x1000, 0x1010, 0x1020, 0x1030], &[mapping()],
            &BTreeSet::new(), &BTreeSet::new(), |addresses| {
                Ok(addresses.iter().map(|address| flows[address].clone()).collect())
            }).unwrap();
        assert_eq!(result.non_returning, BTreeSet::from([0x1010]));
        assert!(result.functions[&0x1000].instructions.contains(&0x1001));
        assert!(!result.functions[&0x1030].complete);
    }

    #[test]
    fn missing_mismatched_and_out_of_mapping_flow_cannot_prove_nonreturn() {
        let empty = BTreeSet::new();
        assert!(analyze(&[0x1000], &[mapping()], &empty, &empty, |_| Ok(Vec::new())).is_err());
        assert!(analyze(&[0x1000], &[mapping()], &empty, &empty, |_| {
            Ok(vec![flow(0x1001, FlowKind::Branch, None, vec![0x1001])])
        }).is_err());
        for (entry, length) in [(0x1000, 0), (0x10ff, 2)] {
            let result = analyze(&[entry], &[mapping()], &empty, &empty, |_| {
                let mut result = flow(entry, FlowKind::Branch, None, vec![entry]);
                result.length = length;
                Ok(vec![result])
            }).unwrap();
            assert!(result.non_returning.is_empty());
            assert!(!result.functions[&entry].complete);
        }
    }
}
