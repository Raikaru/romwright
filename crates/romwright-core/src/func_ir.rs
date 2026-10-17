//! Passes read the shared SSA graph. Evidence and diagnostics cannot mutate
//! it; transforms propose checked operation edits; one structuring pass may
//! propose original CFG edge cuts. The native backend applies the plan before
//! printing and returns the resulting semantic graph and presentation
//! together. The worker keeps cuts only when the printed function (after the
//! Rust structuring models) has fewer gotos than without them
//! ([`Plan::withdraw_cuts`] otherwise).
pub mod types;

use crate::structuring;
use romwright_model::Address;
use romwright_model::function_ir::*;
use romwright_model::type_evidence::Class;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub fn default_pass_names() -> Vec<String> {
    ["additive_inverse", "canonical_helpers", "structure"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// The subprocess transport uses the same spelling and validation as Core.
pub fn parse_pass_names(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Clone, Copy, Default)]
pub struct TransformContext<'a> {
    /// Exact, input-bound signature identities, never analyst names alone.
    pub verified_helpers: Option<&'a HashMap<u64, String>>,
    pub deadline: Option<std::time::Instant>,
    pub cancel: Option<&'a crate::exec::CancelToken>,
}
impl TransformContext<'_> {
    pub(crate) fn checkpoint(&self) -> Result<(), String> {
        if self
            .cancel
            .is_some_and(crate::exec::CancelToken::is_cancelled)
        {
            Err("semantic passes cancelled".into())
        } else if self
            .deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            Err("semantic pass deadline exceeded".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct OperationEdit {
    pub operation: OperationId,
    pub address: Address,
    pub before: Opcode,
    pub after: Opcode,
    pub width: u32,
    pub constant: u64,
    pub helper: String,
}

#[derive(Default)]
pub struct Plan {
    pub edits: Vec<OperationEdit>,
    pub cuts: Vec<ControlFlowCut>,
    pub evidence: BTreeMap<ValueId, Class>,
    pub reports: Vec<PassReport>,
}
impl Plan {
    /// Withdraws the structuring pass's cuts, e.g. when rendering them
    /// printed no fewer gotos than the native structuring alone.
    pub fn withdraw_cuts(&mut self) {
        self.cuts.clear();
        for report in &mut self.reports {
            if report.role == PassRole::Structure {
                report.items = 0;
            }
        }
    }
}

pub trait EvidencePass {
    fn name(&self) -> &'static str;
    fn analyze(
        &self,
        ir: &FunctionIr,
        context: &TransformContext,
    ) -> Result<BTreeMap<ValueId, Class>, String>;
}
pub trait TransformPass {
    fn name(&self) -> &'static str;
    fn propose(
        &self,
        ir: &FunctionIr,
        evidence: &BTreeMap<ValueId, Class>,
        context: &TransformContext,
    ) -> Result<Vec<OperationEdit>, String>;
}
pub trait StructuringPass {
    fn name(&self) -> &'static str;
    fn structure(
        &self,
        ir: &FunctionIr,
        context: &TransformContext,
    ) -> Result<Vec<ControlFlowCut>, String>;
}
pub trait DiagnosticPass {
    fn name(&self) -> &'static str;
    fn inspect(&self, ir: &FunctionIr, evidence: &BTreeMap<ValueId, Class>) -> Vec<IrDiagnostic>;
}

pub enum Pass {
    Analyze(Box<dyn EvidencePass>),
    Transform(Box<dyn TransformPass>),
    Structure(Box<dyn StructuringPass>),
    Diagnostic(Box<dyn DiagnosticPass>),
}
#[derive(Default)]
pub struct Pipeline {
    analyses: Vec<Box<dyn EvidencePass>>,
    transforms: Vec<Box<dyn TransformPass>>,
    structure: Option<Box<dyn StructuringPass>>,
    diagnostics: Vec<Box<dyn DiagnosticPass>>,
}
impl Pipeline {
    pub fn add(&mut self, pass: Pass) -> Result<(), String> {
        let name = match &pass {
            Pass::Analyze(pass) => pass.name(),
            Pass::Transform(pass) => pass.name(),
            Pass::Structure(pass) => pass.name(),
            Pass::Diagnostic(pass) => pass.name(),
        };
        if self.analyses.iter().any(|pass| pass.name() == name)
            || self.transforms.iter().any(|pass| pass.name() == name)
            || self
                .structure
                .as_ref()
                .is_some_and(|pass| pass.name() == name)
            || self.diagnostics.iter().any(|pass| pass.name() == name)
        {
            return Err(format!("duplicate semantic pass {name:?}"));
        }
        match pass {
            Pass::Analyze(pass) => self.analyses.push(pass),
            Pass::Transform(pass) => self.transforms.push(pass),
            Pass::Structure(pass) => {
                if self.structure.is_some() {
                    return Err("a pipeline may have only one structuring pass".into());
                }
                self.structure = Some(pass);
            }
            Pass::Diagnostic(pass) => self.diagnostics.push(pass),
        }
        Ok(())
    }
    pub fn from_names(names: &[String]) -> Result<Self, String> {
        let mut pipeline = Self::default();
        pipeline.add(Pass::Analyze(Box::new(TypeInference)))?;
        for name in names {
            pipeline.add(match name.as_str() {
                "additive_inverse" => Pass::Transform(Box::new(AdditiveInverse)),
                "canonical_helpers" => Pass::Transform(Box::new(CanonicalHelpers)),
                "structure" => Pass::Structure(Box::new(Structure)),
                _ => return Err(format!("unknown transform {name:?}")),
            })?;
        }
        pipeline.add(Pass::Diagnostic(Box::new(TypeConflicts)))?;
        Ok(pipeline)
    }
    pub fn run(&self, ir: &FunctionIr, context: &TransformContext) -> Result<Plan, String> {
        context.checkpoint()?;
        ir.validate()?;
        let mut plan = Plan::default();
        for pass in &self.analyses {
            context.checkpoint()?;
            let facts = pass.analyze(ir, context)?;
            ir.validate_evidence(&facts)?;
            plan.reports.push(PassReport {
                name: pass.name().into(),
                role: PassRole::Analyze,
                items: facts.len(),
            });
            for (value, class) in facts {
                let entry = plan.evidence.entry(value).or_default();
                *entry = entry.join(class);
            }
        }
        let operations: BTreeMap<_, _> = ir
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .map(|op| (op.id, op))
            .collect();
        let mut written = BTreeSet::new();
        for pass in &self.transforms {
            context.checkpoint()?;
            let edits = pass.propose(ir, &plan.evidence, context)?;
            for edit in &edits {
                let op = operations
                    .get(&edit.operation)
                    .ok_or("transform edits an unknown operation")?;
                if op.opcode != edit.before
                    || op.address != edit.address
                    || !written.insert(edit.operation)
                {
                    return Err(format!("conflicting operation edit from {}", pass.name()));
                }
                if op.output.and_then(|value| ir.values[&value].size) != Some(edit.width) {
                    return Err(format!("{} changed an operation's width", pass.name()));
                }
                if !matches!(
                    (edit.before, edit.after),
                    (Opcode::INT_ADD, Opcode::INT_SUB)
                        | (
                            Opcode::CALL,
                            Opcode::INT_DIV | Opcode::INT_SDIV | Opcode::INT_REM | Opcode::INT_SREM
                        )
                ) {
                    return Err(format!(
                        "{} proposed an unsupported semantic edit",
                        pass.name()
                    ));
                }
            }
            plan.reports.push(PassReport {
                name: pass.name().into(),
                role: PassRole::Transform,
                items: edits.len(),
            });
            plan.edits.extend(edits);
        }
        if let Some(pass) = &self.structure {
            context.checkpoint()?;
            plan.cuts = pass.structure(ir, context)?;
            let mut seen = BTreeSet::new();
            for cut in &plan.cuts {
                let block = ir
                    .blocks
                    .iter()
                    .find(|block| block.id == cut.source)
                    .ok_or("unknown cut source")?;
                if block.successors.get(cut.successor_slot) != Some(&cut.target)
                    || !seen.insert((cut.source, cut.successor_slot))
                {
                    return Err("structuring pass changed an edge identity".into());
                }
            }
            plan.reports.push(PassReport {
                name: pass.name().into(),
                role: PassRole::Structure,
                items: plan.cuts.len(),
            });
        }
        context.checkpoint()?;
        Ok(plan)
    }

    /// Only the native acknowledgement may publish transformed semantics.
    pub fn finish(
        &self,
        ir: &mut FunctionIr,
        mut plan: Plan,
        context: &TransformContext,
    ) -> Result<(), String> {
        context.checkpoint()?;
        ir.validate()?;
        for edit in &plan.edits {
            let op = ir
                .blocks
                .iter()
                .flat_map(|block| &block.operations)
                .find(|op| op.id == edit.operation)
                .ok_or("native projection lost an operation")?;
            if op.opcode != edit.after
                || op.address != edit.address
                || op.output.and_then(|value| ir.values[&value].size) != Some(edit.width)
            {
                return Err("native projection did not apply the semantic edit".into());
            }
        }
        if !plan.edits.is_empty() {
            plan.evidence.clear();
            for pass in &self.analyses {
                context.checkpoint()?;
                let facts = pass.analyze(ir, context)?;
                ir.validate_evidence(&facts)?;
                if let Some(report) = plan
                    .reports
                    .iter_mut()
                    .find(|report| report.name == pass.name())
                {
                    report.items = facts.len();
                }
                for (value, class) in facts {
                    let entry = plan.evidence.entry(value).or_default();
                    *entry = entry.join(class);
                }
            }
        }
        let mut diagnostics = Vec::new();
        for pass in &self.diagnostics {
            context.checkpoint()?;
            let result = pass.inspect(ir, &plan.evidence);
            plan.reports.push(PassReport {
                name: pass.name().into(),
                role: PassRole::Diagnostic,
                items: result.len(),
            });
            diagnostics.extend(result);
        }
        ir.type_evidence = plan.evidence;
        ir.control_flow_cuts = plan.cuts;
        ir.passes = plan.reports;
        ir.diagnostics = diagnostics;
        context.checkpoint()?;
        ir.validate()
    }
}

struct TypeInference;
impl EvidencePass for TypeInference {
    fn name(&self) -> &'static str {
        "type_inference"
    }
    fn analyze(
        &self,
        ir: &FunctionIr,
        context: &TransformContext,
    ) -> Result<BTreeMap<ValueId, Class>, String> {
        types::infer(ir, context)
    }
}
fn native_integer_types(ir: &FunctionIr) -> BTreeMap<ValueId, (&str, u64)> {
    let mut types = BTreeMap::new();
    for high in &ir.high_variables {
        if let (Some(kind @ ("int" | "uint")), Some(size)) =
            (high.data_type.metatype.as_deref(), high.data_type.size)
        {
            for member in &high.members {
                if ir.values[member].size.map(u64::from) == Some(size) {
                    types.insert(*member, (kind, size));
                }
            }
        }
    }
    types
}
struct AdditiveInverse;
impl TransformPass for AdditiveInverse {
    fn name(&self) -> &'static str {
        "additive_inverse"
    }
    fn propose(
        &self,
        ir: &FunctionIr,
        _: &BTreeMap<ValueId, Class>,
        context: &TransformContext,
    ) -> Result<Vec<OperationEdit>, String> {
        let types = native_integer_types(ir);
        let constants: BTreeSet<_> = ir
            .high_variables
            .iter()
            .filter(|high| high.class == "constant")
            .flat_map(|high| high.members.iter().copied())
            .collect();
        let mut edits = Vec::new();
        for op in ir.blocks.iter().flat_map(|block| &block.operations) {
            context.checkpoint()?;
            if op.opcode != Opcode::INT_ADD {
                continue;
            }
            let [Operand::Value(left), Operand::Value(right)] = op.inputs.as_slice() else {
                continue;
            };
            let Some(output) = op.output else { continue };
            let Some(width @ 1..=8) = ir.values[&output].size else {
                continue;
            };
            if ir.values[left].size != Some(width)
                || types.get(right) != Some(&("int", u64::from(width)))
                || !constants.contains(right)
            {
                continue;
            }
            let Some(bits) = ir.values[right].offset else {
                continue;
            };
            let mask = u64::MAX >> (64 - width * 8);
            let bits = bits & mask;
            let sign = 1u64 << (width * 8 - 1);
            if bits & sign == 0 || bits == sign {
                continue;
            }
            edits.push(OperationEdit {
                operation: op.id,
                address: op.address.clone(),
                before: op.opcode,
                after: Opcode::INT_SUB,
                width,
                constant: bits.wrapping_neg() & mask,
                helper: String::new(),
            });
        }
        Ok(edits)
    }
}
/// Known ABI semantics. A matching spelling is not proof of helper identity.
pub fn helper_semantics(name: &str) -> Option<(Opcode, u32, &'static str)> {
    use Opcode::*;
    Some(match name {
        "__divsi3" | "__aeabi_idiv" => (INT_SDIV, 4, "int"),
        "__udivsi3" | "__aeabi_uidiv" => (INT_DIV, 4, "uint"),
        "__modsi3" => (INT_SREM, 4, "int"),
        "__umodsi3" => (INT_REM, 4, "uint"),
        "__divdi3" | "__alldiv" => (INT_SDIV, 8, "int"),
        "__udivdi3" | "__aulldiv" => (INT_DIV, 8, "uint"),
        "__moddi3" | "__allrem" => (INT_SREM, 8, "int"),
        "__umoddi3" | "__aullrem" => (INT_REM, 8, "uint"),
        _ => return None,
    })
}
struct CanonicalHelpers;
impl TransformPass for CanonicalHelpers {
    fn name(&self) -> &'static str {
        "canonical_helpers"
    }
    fn propose(
        &self,
        ir: &FunctionIr,
        _: &BTreeMap<ValueId, Class>,
        context: &TransformContext,
    ) -> Result<Vec<OperationEdit>, String> {
        let Some(names) = context.verified_helpers else {
            return Ok(Vec::new());
        };
        let types = native_integer_types(ir);
        let mut edits = Vec::new();
        for op in ir.blocks.iter().flat_map(|block| &block.operations) {
            context.checkpoint()?;
            if op.opcode != Opcode::CALL {
                continue;
            }
            let [
                Operand::Value(target),
                Operand::Value(left),
                Operand::Value(right),
            ] = op.inputs.as_slice()
            else {
                continue;
            };
            let Some(name) = ir.values[target]
                .offset
                .and_then(|address| names.get(&address))
            else {
                continue;
            };
            let Some((opcode, width, kind)) = helper_semantics(name) else {
                continue;
            };
            let Some(output) = op.output else { continue };
            if [*left, *right, output]
                .iter()
                .any(|value| types.get(value) != Some(&(kind, u64::from(width))))
            {
                continue;
            }
            edits.push(OperationEdit {
                operation: op.id,
                address: op.address.clone(),
                before: Opcode::CALL,
                after: opcode,
                width,
                constant: 0,
                helper: name.clone(),
            });
        }
        Ok(edits)
    }
}
struct Structure;
impl StructuringPass for Structure {
    fn name(&self) -> &'static str {
        "structure"
    }
    fn structure(
        &self,
        ir: &FunctionIr,
        context: &TransformContext,
    ) -> Result<Vec<ControlFlowCut>, String> {
        let indices: BTreeMap<_, _> = ir
            .blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (block.id, index))
            .collect();
        let edges: Vec<_> = ir
            .blocks
            .iter()
            .enumerate()
            .flat_map(|(source, block)| {
                let indices = &indices;
                block
                    .successors
                    .iter()
                    .map(move |target| (source, indices[target]))
            })
            .collect();
        let chosen =
            structuring::structure_from(ir.blocks.len(), &edges, 0, &|| context.checkpoint())?;
        let mut cuts = Vec::new();
        let mut used = BTreeSet::new();
        for (source, target) in chosen.unstructured {
            let block = &ir.blocks[source];
            let target = ir.blocks[target].id;
            let slot = block
                .successors
                .iter()
                .enumerate()
                .find(|(slot, next)| **next == target && used.insert((block.id, *slot)))
                .map(|(slot, _)| slot)
                .ok_or("structurer returned a non-original edge")?;
            cuts.push(ControlFlowCut {
                source: block.id,
                successor_slot: slot,
                target,
            });
        }
        Ok(cuts)
    }
}
struct TypeConflicts;
impl DiagnosticPass for TypeConflicts {
    fn name(&self) -> &'static str {
        "type_conflicts"
    }
    fn inspect(&self, _: &FunctionIr, evidence: &BTreeMap<ValueId, Class>) -> Vec<IrDiagnostic> {
        evidence
            .iter()
            .filter(|(_, class)| **class == Class::Top)
            .map(|(value, _)| IrDiagnostic {
                pass: self.name().into(),
                message: format!("conflicting scalar evidence for value {}", value.0),
                operation: None,
            })
            .collect()
    }
}
