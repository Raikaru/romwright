//! The BinSub layer: a subtype-constraint solver over type variables.
//!
//! The flat lattice in `types_infer` joins each register's evidence
//! independently — it cannot say "this value flows into that one, so they
//! share a type." This solver adds the missing relation: `t1 <: t2`
//! (t1 is usable as t2), asserted by every copy and alias. Capabilities
//! and structure then propagate along the edges — a value used as a
//! pointer constrains the register it was copied from — to a fixpoint,
//! and each variable resolves to a `Ty`.
//!
//! Direction: `dst = src` asserts `src <: dst` — the source value must be
//! usable wherever the destination is. Capabilities therefore flow from
//! the supertype (dst) to the subtype (src): if dst is dereferenced, the
//! value it holds — which came from src — is a pointer, so src is too.

use std::collections::{BTreeMap, BTreeSet};

use crate::native_runtime::{PcodeInstruction, PcodeOp, PcodeVarnode};
use crate::types_infer::{Class, Field, Ty};

/// A type variable: one storage location (register offset, or a unique
/// temporary) whose type the solver determines.
pub type Var = u32;

/// A constraint the collector asserts about a variable or between two.
#[derive(Debug, Clone, PartialEq)]
enum Constraint {
    /// `sub <: sup` — sub's value is usable as sup; sup's capabilities
    /// flow down to sub.
    Subtype(Var, Var),
    /// The variable must satisfy this flat class (a capability: pointer,
    /// code, signed, float, a width).
    Cap(Var, Class),
    /// The variable is a struct base with this field at `offset`.
    Field(Var, i64, Field),
    /// The variable is an array base: `base[index]` at `stride`.
    Array(Var, u64, Class),
}

/// The solver's per-variable state, accumulated to a fixpoint.
#[derive(Debug, Default)]
struct Node {
    cap: Class,
    fields: BTreeMap<i64, Field>,
    array: Option<(u64, Class)>,
}

/// The result of solving: each variable's resolved structural type.
pub struct Solution {
    /// Register offset (or unique id) -> resolved type.
    pub types: BTreeMap<u64, Ty>,
}

/// Solve the subtype constraints a function's p-code implies and return
/// each register's structural type.
pub fn solve(instructions: &[PcodeInstruction]) -> Solution {
    let mut c = Collector::default();
    c.collect(instructions);
    c.solve()
}

/// Interns variables and gathers constraints in one pass over the p-code.
#[derive(Default)]
struct Collector {
    vars: BTreeMap<(String, u64), Var>,
    names: Vec<(String, u64)>,
    constraints: Vec<Constraint>,
    // --- tracking, mirroring types_infer::infer ---
    defined: BTreeSet<u64>,
    alias: BTreeMap<(String, u64), (u64, u32)>,
    address_of: BTreeMap<(String, u64), (u64, i64)>,
    spilled: BTreeMap<(u64, i64), u64>,
    built_from: BTreeMap<(String, u64), BTreeSet<u64>>,
    sum_of: BTreeMap<(String, u64), ((String, u64), (String, u64))>,
    scaled: BTreeMap<(String, u64), u64>,
    struct_bases: BTreeSet<u64>,
    pending: BTreeMap<(String, u64), (u64, i64, u32)>,
    spill_alias: Option<(u64, u32)>,
}

impl Collector {
    fn var(&mut self, v: &PcodeVarnode) -> Var {
        let key = (v.space.clone(), v.offset);
        if let Some(&var) = self.vars.get(&key) {
            return var;
        }
        let var = self.names.len() as Var;
        self.vars.insert(key.clone(), var);
        self.names.push(key);
        var
    }

    fn cap(&mut self, v: &PcodeVarnode, class: Class) {
        if v.space == "const" {
            return;
        }
        let var = self.var(v);
        self.constraints.push(Constraint::Cap(var, class));
    }

    fn collect(&mut self, instructions: &[PcodeInstruction]) {
        for instruction in instructions {
            for op in &instruction.ops {
                self.op(op);
            }
        }
    }

    /// The register a varnode's value was copied from, following the
    /// alias chain — the subtype edge's real source.
    fn resolve(&self, v: &PcodeVarnode) -> Option<u64> {
        if v.space == "register" {
            return Some(v.offset);
        }
        let mut seen = BTreeSet::new();
        let mut key = (v.space.clone(), v.offset);
        while let Some(&(origin, _)) = self.alias.get(&key) {
            if !seen.insert(origin) {
                break;
            }
            key = ("register".to_string(), origin);
        }
        if key.0 == "register" {
            Some(key.1)
        } else {
            None
        }
    }

    fn op(&mut self, op: &PcodeOp) {
        let opcode = op.opcode.as_str();
        match opcode {
            "COPY" => {
                if let (Some(output), Some(input)) = (&op.output, op.inputs.first()) {
                    // `dst = src` asserts src <: dst.
                    if input.space != "const" {
                        let src = self.var(input);
                        let dst = self.var(output);
                        self.constraints.push(Constraint::Subtype(src, dst));
                    }
                    if output.space == "register" {
                        self.defined.insert(output.offset);
                    }
                    // Track the alias so a later use of the temp reaches
                    // the source register.
                    if let Some(origin) = self.resolve(input) {
                        self.alias
                            .insert((output.space.clone(), output.offset), (origin, input.size));
                    }
                }
            }
            "INT_ADD" | "INT_SUB" => {
                if let (Some(output), Some(a), Some(b)) =
                    (&op.output, op.inputs.first(), op.inputs.get(1))
                {
                    // `t = reg + const` resolves t to (reg, disp).
                    if a.space == "register" && b.space == "const" {
                        let disp: i64 = if opcode == "INT_SUB" {
                            (b.offset as i64).wrapping_neg()
                        } else {
                            b.offset as i64
                        };
                        self.address_of
                            .insert((output.space.clone(), output.offset), (a.offset, disp));
                        self.built_from
                            .entry((output.space.clone(), output.offset))
                            .or_default()
                            .insert(a.offset);
                    } else {
                        // `t = a + b` where neither is a constant: a
                        // possible `base + index` array address.
                        self.sum_of.insert(
                            (output.space.clone(), output.offset),
                            ((a.space.clone(), a.offset), (b.space.clone(), b.offset)),
                        );
                    }
                    if output.space == "register" {
                        self.defined.insert(output.offset);
                    }
                }
            }
            "INT_MULT" | "INT_LEFT" => {
                if let (Some(output), Some(a), Some(b)) =
                    (&op.output, op.inputs.first(), op.inputs.get(1))
                {
                    // `t = index * stride` / `t = index << shift`.
                    let stride = if b.space == "const" {
                        if opcode == "INT_LEFT" {
                            Some(1u64 << b.offset.min(63))
                        } else {
                            Some(b.offset)
                        }
                    } else if a.space == "const" {
                        if opcode == "INT_LEFT" {
                            Some(1u64 << a.offset.min(63))
                        } else {
                            Some(a.offset)
                        }
                    } else {
                        None
                    };
                    if let Some(stride) = stride {
                        self.scaled
                            .insert((output.space.clone(), output.offset), stride);
                    }
                    if output.space == "register" {
                        self.defined.insert(output.offset);
                    }
                }
            }
            "LOAD" => self.load(op),
            "STORE" => self.store(op),
            "CALLIND" | "BRANCHIND" => {
                if let Some(target) = op.inputs.first() {
                    self.cap(target, Class::Code);
                    if let Some(origin) = self.resolve(target) {
                        if !self.defined.contains(&origin) {
                            let var = self.var(&PcodeVarnode {
                                space: "register".into(),
                                offset: origin,
                                size: 8,
                            });
                            self.constraints.push(Constraint::Cap(var, Class::Code));
                        }
                    }
                }
            }
            "INT_EQUAL" | "INT_NOTEQUAL" | "INT_SLESS" | "INT_SLESSEQUAL"
            | "INT_LESS" | "INT_LESSEQUAL" | "INT_CARRY" | "INT_SCARRY"
            | "INT_SBORROW" | "INT_AND" | "INT_OR" | "INT_XOR" | "INT_RIGHT"
            | "INT_SRIGHT" | "INT_DIV" | "INT_SDIV" | "INT_REM" | "INT_SREM" => {
                for input in &op.inputs {
                    let class = if opcode.starts_with("INT_S") {
                        Class::Int(input.size * 8)
                    } else {
                        Class::Num(input.size * 8)
                    };
                    self.cap(input, class);
                }
            }
            "INT_SEXT" | "INT_ZEXT" | "INT_NEGATE" | "INT_2COMP" | "POPCOUNT" => {
                for input in &op.inputs {
                    self.cap(input, Class::Num(input.size * 8));
                }
            }
            "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV" | "FLOAT_NEG"
            | "FLOAT_ABS" | "FLOAT_SQRT" | "FLOAT_CEIL" | "FLOAT_FLOOR"
            | "FLOAT_ROUND" | "FLOAT_EQUAL" | "FLOAT_NOTEQUAL" | "FLOAT_LESS"
            | "FLOAT_LESSEQUAL" | "FLOAT_NAN" => {
                for input in &op.inputs {
                    self.cap(input, Class::Float(input.size * 8));
                }
            }
            "FLOAT_INT2FLOAT" | "FLOAT_FLOAT2FLOAT" | "FLOAT_TRUNC" => {
                for input in &op.inputs {
                    self.cap(input, Class::Float(input.size * 8));
                }
            }
            _ => {}
        }

        // Resolve a pending field read: the loaded temporary's first use
        // commits the field's class.
        for input in &op.inputs {
            if let Some((base, disp, size)) =
                self.pending.remove(&(input.space.clone(), input.offset))
            {
                let class = match opcode {
                    "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV" => {
                        Class::Float(size * 8)
                    }
                    "INT_SLESS" | "INT_SLESSEQUAL" | "INT_SDIV" | "INT_SREM"
                    | "INT_SRIGHT" | "INT_SEXT" => Class::Int(size * 8),
                    _ => Class::Num(size * 8),
                };
                let base_var = self.var(&PcodeVarnode {
                    space: "register".into(),
                    offset: base,
                    size: 8,
                });
                self.constraints.push(Constraint::Field(
                    base_var,
                    disp,
                    Field { offset: disp, size, class },
                ));
            }
        }

        // Mark outputs defined and record the alias a spill reload holds.
        if let Some(output) = &op.output {
            if output.space == "register" {
                self.defined.insert(output.offset);
            }
            if let Some((origin, size)) = self.spill_alias.take() {
                self.alias
                    .insert((output.space.clone(), output.offset), (origin, size));
            }
        }
    }

    fn load(&mut self, op: &PcodeOp) {
        let Some(address) = op.inputs.get(1) else { return };
        let slot = self
            .address_of
            .get(&(address.space.clone(), address.offset))
            .copied();
        match slot.and_then(|key| self.spilled.get(&key)).copied() {
            Some(origin) => {
                // A reload of a spilled parameter: the output aliases it.
                // `out = *(slot)` asserts origin <: out, so whatever the
                // reload is used as constrains the parameter it holds.
                if let Some(output) = &op.output {
                    self.spill_alias = Some((origin, output.size));
                    if output.space != "const" {
                        let src = self.var(&PcodeVarnode {
                            space: "register".into(),
                            offset: origin,
                            size: output.size,
                        });
                        let dst = self.var(output);
                        self.constraints.push(Constraint::Subtype(src, dst));
                    }
                }
            }
            None if slot.is_none() => {
                self.cap(address, Class::Ptr);
                for origin in self
                    .built_from
                    .get(&(address.space.clone(), address.offset))
                    .cloned()
                    .unwrap_or_default()
                {
                    if !self.defined.contains(&origin) {
                        let var = self.var(&PcodeVarnode {
                            space: "register".into(),
                            offset: origin,
                            size: 8,
                        });
                        self.constraints.push(Constraint::Cap(var, Class::Ptr));
                    }
                }
                // `base[index]` with a constant stride is an array access.
                if let Some((a, b)) = self
                    .sum_of
                    .get(&(address.space.clone(), address.offset))
                    .cloned()
                {
                    let pair = if self.scaled.contains_key(&b) {
                        Some((a, b))
                    } else if self.scaled.contains_key(&a) {
                        Some((b, a))
                    } else {
                        None
                    };
                    if let Some((base_key, idx_key)) = pair
                        && let Some(stride) = self.scaled.get(&idx_key).copied()
                    {
                        let bases: Vec<u64> = if base_key.0 == "register" {
                            vec![base_key.1]
                        } else {
                            self.built_from.get(&base_key).cloned().unwrap_or_default().into_iter().collect()
                        };
                        let elem = op
                            .output
                            .as_ref()
                            .map(|o| Class::Num(o.size * 8))
                            .unwrap_or(Class::Unknown);
                        for base in bases {
                            if !self.defined.contains(&base) {
                                let var = self.var(&PcodeVarnode {
                                    space: "register".into(),
                                    offset: base,
                                    size: 8,
                                });
                                self.constraints
                                    .push(Constraint::Array(var, stride, elem));
                            }
                        }
                    }
                }
            }
            None => {
                // `*(base + disp)` through a resolved non-spill address: a
                // field read, pending until the loaded value's first use.
                if let Some((base, disp)) = slot
                    && let Some(output) = &op.output
                {
                    self.struct_bases.insert(base);
                    self.pending.insert(
                        (output.space.clone(), output.offset),
                        (base, disp, output.size),
                    );
                    if !self.defined.contains(&base) {
                        let var = self.var(&PcodeVarnode {
                            space: "register".into(),
                            offset: base,
                            size: 8,
                        });
                        self.constraints.push(Constraint::Cap(var, Class::Ptr));
                    }
                }
            }
        }
    }

    fn store(&mut self, op: &PcodeOp) {
        let Some(address) = op.inputs.get(1) else { return };
        let key = self
            .address_of
            .get(&(address.space.clone(), address.offset))
            .copied();
        match key {
            Some(key) => {
                let is_struct_base = self.struct_bases.contains(&key.0);
                if let Some(value) = op.inputs.get(2) {
                    let origin = if value.space == "register" && !self.defined.contains(&value.offset)
                    {
                        Some(value.offset)
                    } else {
                        self.alias
                            .get(&(value.space.clone(), value.offset))
                            .map(|(origin, _)| *origin)
                    };
                    if !is_struct_base {
                        match origin {
                            Some(origin) => {
                                self.spilled.insert(key, origin);
                            }
                            None => {
                                self.spilled.remove(&key);
                            }
                        }
                    }
                    // A store into a resolved non-spill address is a field
                    // write; the field's class is the stored value's own.
                    if is_struct_base || !self.spilled.contains_key(&key) {
                        let (base, disp) = key;
                        self.struct_bases.insert(base);
                        let class = if value.space == "const" {
                            Class::Num(value.size * 8)
                        } else if value.space == "register" {
                            Class::Num(value.size * 8)
                        } else {
                            Class::Num(value.size * 8)
                        };
                        let base_var = self.var(&PcodeVarnode {
                            space: "register".into(),
                            offset: base,
                            size: 8,
                        });
                        self.constraints.push(Constraint::Field(
                            base_var,
                            disp,
                            Field { offset: disp, size: value.size, class },
                        ));
                        if !self.defined.contains(&base) {
                            self.constraints.push(Constraint::Cap(base_var, Class::Ptr));
                        }
                    }
                }
            }
            None => {
                self.cap(address, Class::Ptr);
                for origin in self
                    .built_from
                    .get(&(address.space.clone(), address.offset))
                    .cloned()
                    .unwrap_or_default()
                {
                    if !self.defined.contains(&origin) {
                        let var = self.var(&PcodeVarnode {
                            space: "register".into(),
                            offset: origin,
                            size: 8,
                        });
                        self.constraints.push(Constraint::Cap(var, Class::Ptr));
                    }
                }
            }
        }
    }

    /// Propagate capabilities and structure along `sub <: sup` edges to a
    /// fixpoint, then resolve each variable to a `Ty`.
    fn solve(mut self) -> Solution {
        // Edges: sub -> sup (sup's capabilities flow down to sub).
        let mut edges: BTreeMap<Var, BTreeSet<Var>> = BTreeMap::new();
        let mut nodes: BTreeMap<Var, Node> = BTreeMap::new();
        for c in &self.constraints {
            match c {
                Constraint::Subtype(sub, sup) => {
                    nodes.entry(*sub).or_default();
                    nodes.entry(*sup).or_default();
                    edges.entry(*sub).or_default().insert(*sup);
                }
                Constraint::Cap(var, class) => {
                    let node = nodes.entry(*var).or_default();
                    node.cap = node.cap.join(*class);
                }
                Constraint::Field(var, off, field) => {
                    let entry = nodes
                        .entry(*var)
                        .or_default()
                        .fields
                        .entry(*off)
                        .or_insert(*field);
                    entry.class = entry.class.join(field.class);
                    entry.size = entry.size.max(field.size);
                }
                Constraint::Array(var, stride, elem) => {
                    nodes.entry(*var).or_default().array = Some((*stride, *elem));
                }
            }
        }

        // Fixpoint: for each edge sub <: sup, sup's cap/fields/array merge
        // into sub. Iterate until nothing changes.
        loop {
            let mut changed = false;
            for (sub, sups) in &edges {
                for sup in sups {
                    let (sup_cap, sup_fields, sup_array) = {
                        let n = nodes.get(sup);
                        (
                            n.map(|n| n.cap).unwrap_or(Class::Unknown),
                            n.map(|n| n.fields.clone()).unwrap_or_default(),
                            n.and_then(|n| n.array),
                        )
                    };
                    let sub_node = nodes.entry(*sub).or_default();
                    let joined = sub_node.cap.join(sup_cap);
                    if joined != sub_node.cap {
                        sub_node.cap = joined;
                        changed = true;
                    }
                    for (off, f) in sup_fields {
                        let e = sub_node.fields.entry(off).or_insert(f);
                        let nc = e.class.join(f.class);
                        if nc != e.class {
                            e.class = nc;
                            changed = true;
                        }
                    }
                    if sub_node.array.is_none() && sup_array.is_some() {
                        sub_node.array = sup_array;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Resolve each variable to a structural type.
        let mut types = BTreeMap::new();
        for (var, node) in &nodes {
            let (space, offset) = &self.names[*var as usize];
            if space != "register" {
                continue;
            }
            let ty = if !node.fields.is_empty() {
                if node.fields.len() == 1 && node.fields.contains_key(&0) {
                    Ty::Ptr(Box::new(Ty::Scalar(node.fields[&0].class)))
                } else {
                    Ty::Ptr(Box::new(Ty::Struct(node.fields.clone())))
                }
            } else if let Some((stride, elem)) = node.array {
                Ty::Array { elem: Box::new(Ty::Scalar(elem)), stride }
            } else if node.cap == Class::Ptr {
                Ty::Ptr(Box::new(Ty::Scalar(Class::Unknown)))
            } else {
                Ty::Scalar(node.cap)
            };
            types.insert(*offset, ty);
        }
        Solution { types }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varnode(space: &str, offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode { space: space.to_string(), offset, size }
    }

    fn instruction(ops: Vec<PcodeOp>) -> PcodeInstruction {
        PcodeInstruction { address: 0x1000, length: 4, ops, error: None }
    }

    fn op(opcode: &str, output: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOp {
        PcodeOp { opcode: opcode.to_string(), output, inputs }
    }

    #[test]
    fn a_copy_propagates_pointer_capability_to_the_source() {
        // `mov rax, rdi` then `*(rax) = 1`: rax is dereferenced, so the
        // value it holds — rdi — is a pointer. The subtype edge rdi <: rax
        // carries the capability down to rdi.
        let solution = solve(&[
            instruction(vec![op(
                "COPY",
                Some(varnode("register", 0x0, 8)), // rax
                vec![varnode("register", 0x38, 8)], // rdi
            )]),
            instruction(vec![op(
                "STORE",
                None,
                vec![
                    varnode("const", 0x1b1, 4),
                    varnode("register", 0x0, 8), // *rax
                    varnode("const", 1, 4),
                ],
            )]),
        ]);
        assert_eq!(
            solution.types.get(&0x38),
            Some(&Ty::Ptr(Box::new(Ty::Scalar(Class::Unknown)))),
            "rdi should be a pointer because its copy rax is dereferenced"
        );
    }

    #[test]
    fn a_struct_base_recovers_its_fields() {
        // `*(rdi+0x34) = 1.0f` then `*(rdi+0x10) = rsi`: rdi is a pointer
        // to a struct with a float at +0x34 and a number at +0x10.
        let solution = solve(&[
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x100, 8)),
                    vec![varnode("register", 0x38, 8), varnode("const", 0x34, 4)],
                ),
                op(
                    "STORE",
                    None,
                    vec![
                        varnode("const", 0x1b1, 4),
                        varnode("unique", 0x100, 8),
                        varnode("const", 0x3f800000, 4), // 1.0f
                    ],
                ),
            ]),
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x108, 8)),
                    vec![varnode("register", 0x38, 8), varnode("const", 0x10, 4)],
                ),
                op(
                    "STORE",
                    None,
                    vec![
                        varnode("const", 0x1b1, 4),
                        varnode("unique", 0x108, 8),
                        varnode("register", 0x30, 8), // rsi
                    ],
                ),
            ]),
        ]);
        match solution.types.get(&0x38) {
            Some(Ty::Ptr(inner)) => match inner.as_ref() {
                Ty::Struct(fields) => {
                    assert!(fields.contains_key(&0x34), "field at +0x34: {fields:?}");
                    assert!(fields.contains_key(&0x10), "field at +0x10: {fields:?}");
                }
                other => panic!("expected a struct, got {other:?}"),
            },
            other => panic!("expected a pointer, got {other:?}"),
        }
    }
}
