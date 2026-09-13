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
    /// What each call site passed: callee address -> (param register,
    /// observed argument type). This is the caller→callee direction — the
    /// caller's solved argument type refines the callee's parameter.
    pub calls: BTreeMap<u64, Vec<(u64, Ty)>>,
}

/// A callee's recovered signature, asserted into a caller's solve so the
/// argument registers and the return value take the callee's types. This
/// is the interprocedural half of BinSub: the callee's `Fact` flows into
/// the caller as a constraint.
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    /// Parameter register offset -> the callee's solved type for it.
    pub params: Vec<(u64, Ty)>,
    /// Return register offset -> the callee's solved return type.
    pub returns: Vec<(u64, Ty)>,
}


/// A decompiler type as a structural `Ty` — the Ghidra/`Strong` direction,
/// where a recovered `FuncProto` overrides the solver's inference.
fn decomp_to_ty(ty: &lre_model::DecompType) -> Ty {
    let name = ty.name.as_deref().unwrap_or("");
    // Ghidra often omits `size`; fall back to the C type's canonical width
    // (LP64) so `int` is 32, not the 64 a missing size would default to.
    let name_bits = |n: &str| -> u32 {
        match n {
            "char" | "byte" | "bool" | "schar" | "uchar" => 8,
            "short" | "ushort" | "wchar_t" => 16,
            "int" | "uint" | "float" | "long32" => 32,
            "long" | "ulong" | "double" | "long64" | "pointer" => 64,
            _ => 64,
        }
    };
    let bits = ty.size.map(|s| (s * 8) as u32).unwrap_or_else(|| name_bits(name));
    match ty.metatype.as_deref() {
        Some("ptr") => Ty::Ptr(Box::new(
            ty.target.as_deref().map(decomp_to_ty).unwrap_or(Ty::Unknown),
        )),
        Some("array") => Ty::Array {
            elem: Box::new(ty.target.as_deref().map(decomp_to_ty).unwrap_or(Ty::Unknown)),
            stride: ty.target.as_ref().and_then(|t| t.size).unwrap_or(1),
        },
        Some("float") => Ty::Scalar(Class::Float(bits)),
        Some("code") => Ty::Scalar(Class::Code),
        _ => match name {
            "float" | "double" => Ty::Scalar(Class::Float(bits)),
            n if n.starts_with("uint") || n.starts_with("unsigned") || n.starts_with('u') => {
                Ty::Scalar(Class::Uint(bits))
            }
            "int" | "long" | "short" | "char" | "schar" => Ty::Scalar(Class::Int(bits)),
            _ => Ty::Scalar(Class::Num(bits)),
        },
    }
}

impl Signature {
    /// Build a `Signature` from a decompiler-recovered `FuncProto`: each
    /// parameter's `DecompType` becomes a `Ty` on its register slot, split
    /// across the integer and float parameter registers by kind.
    pub fn from_funcproto(
        proto: &lre_model::FuncProto,
        int_slots: &[u64],
        float_slots: &[u64],
        int_ret: &[u64],
        float_ret: &[u64],
    ) -> Signature {
        let mut params = Vec::new();
        let mut int_i = 0;
        let mut float_i = 0;
        for param in &proto.parameters {
            let ty = decomp_to_ty(&param.data_type);
            let is_float = matches!(ty, Ty::Scalar(Class::Float(_)));
            let slot = if is_float {
                float_slots.get(float_i).copied().inspect(|_| float_i += 1)
            } else {
                int_slots.get(int_i).copied().inspect(|_| int_i += 1)
            };
            if let Some(reg) = slot {
                params.push((reg, ty));
            }
        }
        let ret_ty = decomp_to_ty(&proto.return_type);
        let returns = if matches!(ret_ty, Ty::Scalar(Class::Float(_))) {
            float_ret.first().map(|r| (*r, ret_ty)).into_iter().collect()
        } else {
            int_ret.first().map(|r| (*r, ret_ty)).into_iter().collect()
        };
        Signature { params, returns }
    }
}
/// Solve a function in isolation — no callee facts.
pub fn solve(instructions: &[PcodeInstruction]) -> Solution {
    solve_with(instructions, &BTreeMap::new())
}

/// Solve with callee signatures: at each `CALL`/`CALLIND` to a known
/// address, the callee's parameter types constrain the caller's argument
/// registers and the callee's return type constrains the caller's use of
/// the return register.
pub fn solve_with(
    instructions: &[PcodeInstruction],
    callees: &BTreeMap<u64, Signature>,
) -> Solution {
    let mut c = Collector::new(callees);
    c.collect(instructions);
    c.solve()
}

/// Interns variables and gathers constraints in one pass over the p-code.
struct Collector<'a> {
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
    /// Callee signatures by call target address, for interprocedural
    /// constraint injection.
    callees: &'a BTreeMap<u64, Signature>,
    /// Which type-var currently holds each register's value. A copy makes
    /// the destination register hold the source's var; a CALL makes the
    /// return register hold a fresh var carrying the callee's return type.
    holding: BTreeMap<u64, Var>,
    /// (callee address, param register, argument var) at each call — the
    /// caller→callee observations the fixpoint feeds back.
    call_args: Vec<(u64, u64, Var)>,
}

impl<'a> Collector<'a> {
    fn new(callees: &'a BTreeMap<u64, Signature>) -> Self {
        Self {
            vars: BTreeMap::new(),
            names: Vec::new(),
            constraints: Vec::new(),
            defined: BTreeSet::new(),
            alias: BTreeMap::new(),
            address_of: BTreeMap::new(),
            spilled: BTreeMap::new(),
            built_from: BTreeMap::new(),
            sum_of: BTreeMap::new(),
            scaled: BTreeMap::new(),
            struct_bases: BTreeSet::new(),
            pending: BTreeMap::new(),
            spill_alias: None,
            callees,
            holding: BTreeMap::new(),
            call_args: Vec::new(),
        }
    }

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

    /// A fresh type variable not tied to a varnode — for a call's return
    /// value, which has no storage location until the caller uses it.
    fn fresh(&mut self) -> Var {
        let var = self.names.len() as Var;
        self.names.push(("fresh".to_string(), var as u64));
        var
    }

    /// Assert a structural type onto a variable as constraints — the
    /// interprocedural direction, where a callee's solved `Ty` becomes
    /// this variable's capabilities and structure.
    fn assert_ty(&mut self, var: Var, ty: &Ty) {
        match ty {
            Ty::Unknown => {}
            Ty::Scalar(class) => {
                self.constraints.push(Constraint::Cap(var, *class));
            }
            Ty::Ptr(inner) => {
                self.constraints.push(Constraint::Cap(var, Class::Ptr));
                // The pointee's structure is this variable's own: a `*T`
                // is a field at offset 0, a `*struct{..}` is each field.
                match inner.as_ref() {
                    Ty::Scalar(class) => {
                        self.constraints.push(Constraint::Field(
                            var,
                            0,
                            Field { offset: 0, size: class.width() / 8, class: *class },
                        ));
                    }
                    Ty::Struct(fields) => {
                        for field in fields.values() {
                            self.constraints
                                .push(Constraint::Field(var, field.offset, *field));
                        }
                    }
                    Ty::Array { elem, stride } => {
                        if let Ty::Scalar(class) = elem.as_ref() {
                            self.constraints
                                .push(Constraint::Array(var, *stride, *class));
                        }
                    }
                    _ => {}
                }
            }
            // A variable that *is* an aggregate (not a pointer to one):
            // assert its fields/elements directly.
            Ty::Struct(fields) => {
                for field in fields.values() {
                    self.constraints
                        .push(Constraint::Field(var, field.offset, *field));
                }
            }
            Ty::Array { elem, stride } => {
                if let Ty::Scalar(class) = elem.as_ref() {
                    self.constraints
                        .push(Constraint::Array(var, *stride, *class));
                }
            }
        }
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
                        // The destination register now holds the source's
                        // value — the same type-var.
                        if input.space != "const" {
                            let src = self.var(input);
                            self.holding.insert(output.offset, src);
                        }
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
            "CALL" => {
                // A direct call to a known callee: the callee's parameter
                // types constrain the value each argument register holds,
                // and the callee's return type constrains the caller's use
                // of the return register. The argument is the *value* in
                // the register — which `holding` tracks through copies —
                // not the register's own var.
                if let Some(target) = op.inputs.first()
                    && (target.space == "ram" || target.space == "const")
                    && let Some(sig) = self.callees.get(&target.offset)
                {
                    for (reg, ty) in &sig.params {
                        let var = match self.holding.get(reg) {
                            Some(&v) => v,
                            None => self.var(&PcodeVarnode {
                                space: "register".into(),
                                offset: *reg,
                                size: 8,
                            }),
                        };
                        self.assert_ty(var, ty);
                        // The caller→callee observation: the type this var
                        // resolves to refines the callee's parameter.
                        self.call_args.push((target.offset, *reg, var));
                    }
                    for (reg, ty) in &sig.returns {
                        // The return register holds a fresh value after the
                        // call — a new var carrying the callee's return type.
                        let var = self.fresh();
                        self.assert_ty(var, ty);
                        self.holding.insert(*reg, var);
                    }
                }
            }
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
                        if output.space == "register" {
                            self.holding.insert(output.offset, src);
                        }
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

        // Resolve each variable to a structural type — keyed by var so a
        // call argument that is a temp (not a register) still resolves.
        let mut var_types: BTreeMap<Var, Ty> = BTreeMap::new();
        for (var, node) in &nodes {
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
            var_types.insert(*var, ty);
        }
        // The register-offset view callers read.
        let mut types = BTreeMap::new();
        for (var, ty) in &var_types {
            let (space, offset) = &self.names[*var as usize];
            if space == "register" {
                types.insert(*offset, ty.clone());
            }
        }
        // The caller→callee observations: each call's argument var resolves
        // to the type the caller actually passed.
        let mut calls: BTreeMap<u64, Vec<(u64, Ty)>> = BTreeMap::new();
        for (callee, reg, var) in &self.call_args {
            if let Some(ty) = var_types.get(var) {
                calls.entry(*callee).or_default().push((*reg, ty.clone()));
            }
        }
        Solution { types, calls }
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

    #[test]
    fn a_call_constrains_the_argument_register_to_the_callees_type() {
        // The callee at 0x2000 takes a struct pointer in rdi. A caller that
        // copies its own rdi into the argument register and calls should
        // see its rdi take the callee's type — the interprocedural edge.
        let mut callees = BTreeMap::new();
        let mut fields = BTreeMap::new();
        fields.insert(
            0x34i64,
            Field { offset: 0x34, size: 4, class: Class::Float(32) },
        );
        callees.insert(
            0x2000u64,
            Signature {
                params: vec![(0x38, Ty::Ptr(Box::new(Ty::Struct(fields))))],
                returns: vec![],
            },
        );
        let solution = solve_with(
            &[
                instruction(vec![op(
                    "COPY",
                    Some(varnode("register", 0x38, 8)), // rdi = rdi (param)
                    vec![varnode("register", 0x38, 8)],
                )]),
                instruction(vec![op(
                    "CALL",
                    None,
                    vec![varnode("ram", 0x2000, 8)],
                )]),
            ],
            &callees,
        );
        match solution.types.get(&0x38) {
            Some(Ty::Ptr(inner)) => match inner.as_ref() {
                Ty::Struct(fields) => {
                    assert!(fields.contains_key(&0x34), "callee field at +0x34: {fields:?}");
                }
                other => panic!("expected a struct, got {other:?}"),
            },
            other => panic!("expected a pointer, got {other:?}"),
        }
    }

    #[test]
    fn a_call_records_the_argument_type_the_caller_observed() {
        // The caller dereferences rdi at +0x34 (making it a struct
        // pointer), then passes it to a callee whose signature is still
        // unknown. `calls` should record the struct type so the callee's
        // inferred signature refines — the caller→callee direction.
        let mut callees = BTreeMap::new();
        callees.insert(
            0x2000u64,
            Signature {
                params: vec![(0x38, Ty::Scalar(Class::Unknown))],
                returns: vec![],
            },
        );
        let solution = solve_with(
            &[
                // *(rdi + 0x34) = 1.0f — rdi is a struct pointer.
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
                            varnode("const", 0x3f800000, 4),
                        ],
                    ),
                ]),
                instruction(vec![op(
                    "CALL",
                    None,
                    vec![varnode("ram", 0x2000, 8)],
                )]),
            ],
            &callees,
        );
        let observed = solution
            .calls
            .get(&0x2000)
            .and_then(|args| args.iter().find(|(r, _)| *r == 0x38))
            .map(|(_, ty)| ty);
        match observed {
            Some(Ty::Ptr(inner)) => match inner.as_ref() {
                Ty::Struct(fields) => {
                    assert!(fields.contains_key(&0x34), "observed field: {fields:?}");
                }
                other => panic!("expected a struct, got {other:?}"),
            },
            other => panic!("expected a pointer observation, got {other:?}"),
        }
    }
}
