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
use crate::types_infer::{Field, Ty};
use romwright_model::type_evidence::Class;

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
fn decomp_to_ty(ty: &romwright_model::DecompType) -> Ty {
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
    let bits = ty
        .size
        .map(|s| (s * 8) as u32)
        .unwrap_or_else(|| name_bits(name));
    match ty.metatype.as_deref() {
        Some("ptr") => Ty::Ptr(Box::new(
            ty.target
                .as_deref()
                .map(decomp_to_ty)
                .unwrap_or(Ty::Unknown),
        )),
        Some("array") => Ty::Array {
            elem: Box::new(
                ty.target
                    .as_deref()
                    .map(decomp_to_ty)
                    .unwrap_or(Ty::Unknown),
            ),
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
        proto: &romwright_model::FuncProto,
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
            float_ret
                .first()
                .map(|r| (*r, ret_ty))
                .into_iter()
                .collect()
        } else {
            int_ret.first().map(|r| (*r, ret_ty)).into_iter().collect()
        };
        Signature { params, returns }
    }
}
/// Solve a function in isolation — no callee facts.
pub fn solve(instructions: &[PcodeInstruction]) -> Solution {
    solve_with(instructions, &BTreeMap::new(), &BTreeSet::new())
}

/// `solve` with callee signatures for interprocedural constraint injection
/// and the register offsets a call destroys (`killedbycall` from the
/// compiler spec). The killed set is what lets a call clobber the
/// caller-saved registers it must not leave holding their pre-call values.
pub fn solve_with(
    instructions: &[PcodeInstruction],
    callees: &BTreeMap<u64, Signature>,
    killed: &BTreeSet<u64>,
) -> Solution {
    let mut c = Collector::new(callees, killed);
    c.collect(instructions);
    c.solve()
}

/// Interns variables and gathers constraints in one pass over the p-code.
struct Collector<'a> {
    vars: BTreeMap<(String, u64), Var>,
    names: Vec<(String, u64)>,
    constraints: Vec<Constraint>,
    defined: BTreeSet<u64>,
    /// A value var's register origin — set for a spill reload, whose loaded
    /// temp aliases the parameter it was spilled from.
    alias: BTreeMap<Var, u64>,
    /// A value var that is `base + const` -> (base register offset, disp).
    address_of: BTreeMap<Var, (u64, i64)>,
    spilled: BTreeMap<(u64, i64), u64>,
    built_from: BTreeMap<Var, BTreeSet<u64>>,
    /// A value var that is `a + b` (neither const) -> the operand vars.
    sum_of: BTreeMap<Var, (Var, Var)>,
    /// A value var that is `index * stride` / `index << shift` -> stride.
    scaled: BTreeMap<Var, u64>,
    struct_bases: BTreeSet<u64>,
    /// A loaded value var -> (base register offset, disp, size), resolved
    /// to a field class at the value's first use.
    pending: BTreeMap<Var, (u64, i64, u32)>,
    /// Callee signatures by call target address, for interprocedural
    /// constraint injection.
    callees: &'a BTreeMap<u64, Signature>,
    /// Which type-var currently holds each register's value. A copy makes
    /// the destination register hold the source's var; a CALL makes the
    /// return register hold a fresh var carrying the callee's return type.
    holding: BTreeMap<u64, Var>,
    /// The current version var of each `unique` temp. P-code reuses a
    /// `unique` offset for distinct values (a reload's temp and a later
    /// load's temp share an offset), so each definition mints a fresh var
    /// and reads resolve to the latest one — the same SSA discipline
    /// `holding` gives registers.
    unique_vars: BTreeMap<u64, Var>,
    /// Set when the current op's register output already recorded what it
    /// holds (a spill reload or a call return); otherwise the definition
    /// is a fresh value and gets a fresh var.
    output_held: bool,
    /// Set when the current op's `unique` output already minted its
    /// version var (def_var); otherwise the tail mints it.
    output_versioned: bool,
    /// caller→callee observations the fixpoint feeds back.
    call_args: Vec<(u64, u64, Var)>,
    /// Register offsets a call destroys — the compiler spec's
    /// `killedbycall` set. A call gives each a fresh value so a post-call
    /// read cannot resolve to the caller's pre-call value.
    killed: &'a BTreeSet<u64>,
}

impl<'a> Collector<'a> {
    fn new(callees: &'a BTreeMap<u64, Signature>, killed: &'a BTreeSet<u64>) -> Self {
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
            callees,
            holding: BTreeMap::new(),
            unique_vars: BTreeMap::new(),
            output_held: false,
            output_versioned: false,
            call_args: Vec::new(),
            killed,
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

    /// The var a *read* resolves to. A register read resolves to the value
    /// it currently holds (a reloaded parameter or a call return); a
    /// `unique` read resolves to the current version of that temp, since a
    /// `unique` offset is reused for distinct values.
    fn use_var(&mut self, v: &PcodeVarnode) -> Var {
        if v.space == "register"
            && let Some(&held) = self.holding.get(&v.offset)
        {
            return held;
        }
        if v.space == "unique"
            && let Some(&version) = self.unique_vars.get(&v.offset)
        {
            return version;
        }
        self.var(v)
    }

    /// The var a `unique` *definition* binds: a fresh version, so a reused
    /// `unique` offset's distinct values stay distinct. Register outputs
    /// are handled by `holding`, not here.
    fn def_var(&mut self, v: &PcodeVarnode) -> Var {
        if v.space == "unique" {
            let var = self.names.len() as Var;
            self.names.push((v.space.clone(), v.offset));
            self.unique_vars.insert(v.offset, var);
            self.output_versioned = true;
            return var;
        }
        self.var(v)
    }

    fn cap(&mut self, v: &PcodeVarnode, class: Class) {
        if v.space == "const" {
            return;
        }
        let var = self.use_var(v);
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
                            Field {
                                offset: 0,
                                size: class.width() / 8,
                                class: *class,
                            },
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

    /// A call destroys every register the compiler spec marks
    /// `killedbycall`: each gets a fresh value so a post-call read resolves
    /// to the call's clobber, not the caller's pre-call value. This runs
    /// before the return registers are set, so a return that is also
    /// caller-saved still lands the callee's typed return.
    fn clobber_call(&mut self) {
        for &offset in self.killed.iter() {
            self.defined.insert(offset);
            let var = self.fresh();
            self.holding.insert(offset, var);
        }
    }

    fn collect(&mut self, instructions: &[PcodeInstruction]) {
        for instruction in instructions {
            for op in &instruction.ops {
                self.op(op);
            }
        }
    }

    /// The register offset a value var originates from, following the
    /// alias a spill reload records — the subtype edge's real source.
    fn resolve_var(&self, var: Var) -> Option<u64> {
        let mut seen = BTreeSet::new();
        let mut cur = var;
        while let Some(&origin) = self.alias.get(&cur) {
            if !seen.insert(cur) {
                break;
            }
            cur = match self
                .names
                .iter()
                .position(|n| *n == ("register".into(), origin))
            {
                Some(i) => i as Var,
                None => return Some(origin),
            };
        }
        match self.names.get(cur as usize) {
            Some((space, offset)) if space == "register" => Some(*offset),
            _ => None,
        }
    }

    /// The register offset a varnode's value originates from — through a
    /// spill reload or a copy — or its own offset when it is a computed
    /// register value. Used so an array/field base recorded on a reload
    /// temporary resolves to the parameter it holds.
    fn origin_of(&self, v: &PcodeVarnode) -> u64 {
        if v.space == "register" {
            if let Some(&held) = self.holding.get(&v.offset)
                && let Some(origin) = self.resolve_var(held)
            {
                return origin;
            }
            return v.offset;
        }
        if v.space == "unique"
            && let Some(&version) = self.unique_vars.get(&v.offset)
            && let Some(origin) = self.resolve_var(version)
        {
            return origin;
        }
        v.offset
    }

    /// The var an op's output binds, recording the definition. A `unique`
    /// output mints a fresh version; a register output that is not a
    /// reload or call return holds a fresh value.
    fn out_value(&mut self, output: &PcodeVarnode) -> Var {
        if output.space == "unique" {
            return self.def_var(output);
        }
        if output.space == "register" {
            self.defined.insert(output.offset);
            let var = self.fresh();
            self.holding.insert(output.offset, var);
            self.output_held = true;
            return var;
        }
        self.var(output)
    }

    fn op(&mut self, op: &PcodeOp) {
        let opcode = op.opcode.as_str();
        self.output_held = false;
        self.output_versioned = false;
        match opcode {
            "COPY" => {
                if let (Some(output), Some(input)) = (&op.output, op.inputs.first()) {
                    // `dst = src`: the destination holds the source's var.
                    if input.space != "const" {
                        let src = self.use_var(input);
                        if output.space == "register" {
                            self.defined.insert(output.offset);
                            self.holding.insert(output.offset, src);
                            self.output_held = true;
                        } else if output.space == "unique" {
                            self.unique_vars.insert(output.offset, src);
                            self.output_versioned = true;
                        }
                    }
                }
            }
            "INT_ADD" | "INT_SUB" => {
                if let (Some(output), Some(a), Some(b)) =
                    (&op.output, op.inputs.first(), op.inputs.get(1))
                {
                    if a.space == "register" && b.space == "const" {
                        let disp: i64 = if opcode == "INT_SUB" {
                            (b.offset as i64).wrapping_neg()
                        } else {
                            b.offset as i64
                        };
                        // Record the *origin* register, not the reload
                        // temporary, so a `*(base+disp)` access through a
                        // reloaded pointer resolves to the parameter.
                        let base = self.origin_of(a);
                        let out = self.out_value(output);
                        self.address_of.insert(out, (base, disp));
                        self.built_from.entry(out).or_default().insert(base);
                    } else {
                        // `t = a + b` where neither is a constant: a
                        // possible `base + index` array address. Record the
                        // operand value vars so a base held in a reload
                        // temporary resolves to the parameter it holds.
                        let ra = self.use_var(a);
                        let rb = self.use_var(b);
                        let out = self.out_value(output);
                        self.sum_of.insert(out, (ra, rb));
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
                    let out = self.out_value(output);
                    if let Some(stride) = stride {
                        self.scaled.insert(out, stride);
                    }
                }
            }
            "LOAD" => self.load(op),
            "STORE" => self.store(op),
            "CALL" => {
                // Arguments refer to pre-call values. Save the signature
                // before killing registers, then install only return values.
                let signature = op
                    .inputs
                    .first()
                    .filter(|target| target.space == "ram" || target.space == "const")
                    .and_then(|target| {
                        self.callees
                            .get(&target.offset)
                            .map(|sig| (target.offset, sig.clone()))
                    });
                if let Some((target, sig)) = &signature {
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
                        self.call_args.push((*target, *reg, var));
                    }
                }
                self.clobber_call();
                if let Some((_, sig)) = &signature {
                    for (reg, ty) in &sig.returns {
                        // The return register holds a fresh value after the
                        // call — a new var carrying the callee's return type.
                        let var = self.fresh();
                        self.assert_ty(var, ty);
                        self.holding.insert(*reg, var);
                        if let Some(output) = &op.output
                            && output.space == "register"
                            && output.offset == *reg
                        {
                            self.output_held = true;
                        }
                    }
                }
            }
            "CALLIND" | "BRANCHIND" => {
                // An indirect call clobbers caller-saved registers exactly
                // as a direct one does; a computed branch does not.
                if let Some(target) = op.inputs.first() {
                    self.cap(target, Class::Code);
                    let origin = self.origin_of(target);
                    if !self.defined.contains(&origin) {
                        let var = self.var(&PcodeVarnode {
                            space: "register".into(),
                            offset: origin,
                            size: 8,
                        });
                        self.constraints.push(Constraint::Cap(var, Class::Code));
                    }
                }
                if opcode == "CALLIND" {
                    self.clobber_call();
                }
            }
            "INT_EQUAL" | "INT_NOTEQUAL" | "INT_SLESS" | "INT_SLESSEQUAL" | "INT_LESS"
            | "INT_LESSEQUAL" | "INT_CARRY" | "INT_SCARRY" | "INT_SBORROW" | "INT_RIGHT"
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
            // A value you mask or XOR is conventionally unsigned; a 64-bit
            // mask still joins with a pointer without losing it.
            "INT_AND" | "INT_OR" | "INT_XOR" => {
                for input in &op.inputs {
                    self.cap(input, Class::Uint(input.size * 8));
                }
            }
            "INT_SEXT" | "INT_ZEXT" | "INT_NEGATE" | "INT_2COMP" | "POPCOUNT" => {
                for input in &op.inputs {
                    self.cap(input, Class::Num(input.size * 8));
                }
            }
            "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV" | "FLOAT_NEG" | "FLOAT_ABS"
            | "FLOAT_SQRT" | "FLOAT_CEIL" | "FLOAT_FLOOR" | "FLOAT_ROUND" | "FLOAT_EQUAL"
            | "FLOAT_NOTEQUAL" | "FLOAT_LESS" | "FLOAT_LESSEQUAL" | "FLOAT_NAN" => {
                for input in &op.inputs {
                    self.cap(input, Class::Float(input.size * 8));
                }
            }
            // `int2float` consumes a *signed* integer — Ghidra's
            // `opInt2Float` sign-extends its input (float.cc:614) — so the
            // generic conversion rule would misclassify it as a float.
            "FLOAT_INT2FLOAT" => {
                for input in &op.inputs {
                    self.cap(input, Class::Int(input.size * 8));
                }
            }
            "FLOAT_FLOAT2FLOAT" | "FLOAT_TRUNC" => {
                for input in &op.inputs {
                    self.cap(input, Class::Float(input.size * 8));
                }
            }
            _ => {}
        }

        // Resolve a pending field read: the loaded temporary's first use
        // commits the field's class.
        for input in &op.inputs {
            if input.space == "const" {
                continue;
            }
            let ivar = self.use_var(input);
            if let Some((base, disp, size)) = self.pending.remove(&ivar) {
                let class = match opcode {
                    "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV" => {
                        Class::Float(size * 8)
                    }
                    "INT_SLESS" | "INT_SLESSEQUAL" | "INT_SDIV" | "INT_SREM" | "INT_SRIGHT"
                    | "INT_SEXT" => Class::Int(size * 8),
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
                    Field {
                        offset: disp,
                        size,
                        class,
                    },
                ));
            }
        }

        // A register output that did not record what it holds (a reload or
        // call return) is a fresh value; a `unique` output not yet minted
        // gets its version here.
        if let Some(output) = &op.output {
            if output.space == "register" {
                self.defined.insert(output.offset);
                if !self.output_held {
                    let var = self.fresh();
                    self.holding.insert(output.offset, var);
                }
            } else if output.space == "unique" && !self.output_versioned {
                self.def_var(output);
            }
        }
    }

    fn load(&mut self, op: &PcodeOp) {
        let Some(address) = op.inputs.get(1) else {
            return;
        };
        let addr_var = self.use_var(address);
        let slot = self.address_of.get(&addr_var).copied();
        match slot.and_then(|key| self.spilled.get(&key)).copied() {
            Some(origin) => {
                // A reload of a spilled parameter: the loaded value aliases
                // it, so whatever the reload is used as constrains the
                // parameter it holds.
                if let Some(output) = &op.output {
                    let src = self.var(&PcodeVarnode {
                        space: "register".into(),
                        offset: origin,
                        size: output.size,
                    });
                    if output.space == "register" {
                        self.holding.insert(output.offset, src);
                        self.output_held = true;
                    } else if output.space == "unique" {
                        let dst = self.def_var(output);
                        self.constraints.push(Constraint::Subtype(src, dst));
                        self.alias.insert(dst, origin);
                    }
                }
            }
            None if slot.is_none() => {
                self.cap(address, Class::Ptr);
                for origin in self.built_from.get(&addr_var).cloned().unwrap_or_default() {
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
                if let Some((a, b)) = self.sum_of.get(&addr_var).copied() {
                    let pair = if self.scaled.contains_key(&b) {
                        Some((a, b))
                    } else if self.scaled.contains_key(&a) {
                        Some((b, a))
                    } else {
                        None
                    };
                    if let Some((base_var, idx_var)) = pair
                        && let Some(stride) = self.scaled.get(&idx_var).copied()
                    {
                        let bases: Vec<u64> = match self.resolve_var(base_var) {
                            Some(origin) => vec![origin],
                            None => self
                                .built_from
                                .get(&base_var)
                                .cloned()
                                .unwrap_or_default()
                                .into_iter()
                                .collect(),
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
                                self.constraints.push(Constraint::Array(var, stride, elem));
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
                    let out = self.out_value(output);
                    self.pending.insert(out, (base, disp, output.size));
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
        let Some(address) = op.inputs.get(1) else {
            return;
        };
        let addr_var = self.use_var(address);
        let key = self.address_of.get(&addr_var).copied();
        match key {
            Some(key) => {
                let is_struct_base = self.struct_bases.contains(&key.0);
                if let Some(value) = op.inputs.get(2) {
                    let origin =
                        if value.space == "register" && !self.defined.contains(&value.offset) {
                            Some(value.offset)
                        } else {
                            let vvar = self.use_var(value);
                            self.resolve_var(vvar)
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
                        let class = Class::Num(value.size * 8);
                        let base_var = self.var(&PcodeVarnode {
                            space: "register".into(),
                            offset: base,
                            size: 8,
                        });
                        self.constraints.push(Constraint::Field(
                            base_var,
                            disp,
                            Field {
                                offset: disp,
                                size: value.size,
                                class,
                            },
                        ));
                        if !self.defined.contains(&base) {
                            self.constraints.push(Constraint::Cap(base_var, Class::Ptr));
                        }
                    }
                }
            }
            None => {
                self.cap(address, Class::Ptr);
                for origin in self.built_from.get(&addr_var).cloned().unwrap_or_default() {
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
                        // A field the sub did not have is new information and
                        // must keep the fixpoint going — otherwise a field
                        // that has to travel more than one subtype edge is
                        // inserted on the last pass and never propagated.
                        if !sub_node.fields.contains_key(&off) {
                            sub_node.fields.insert(off, f);
                            changed = true;
                            continue;
                        }
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
        if std::env::var("RW_SUBTYPE_DEBUG").is_ok() {
            for c in &self.constraints {
                eprintln!("  constraint: {:?}", c);
            }
            for (i, n) in self.names.iter().enumerate() {
                eprintln!("  var {} = {:?}", i, n);
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
                Ty::Array {
                    elem: Box::new(Ty::Scalar(elem)),
                    stride,
                }
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
        PcodeVarnode {
            space: space.to_string(),
            offset,
            size,
        }
    }

    fn instruction(ops: Vec<PcodeOp>) -> PcodeInstruction {
        PcodeInstruction {
            address: 0x1000,
            length: 4,
            ops,
            error: None,
        }
    }

    fn op(opcode: &str, output: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOp {
        PcodeOp {
            opcode: opcode.to_string(),
            output,
            inputs,
        }
    }

    #[test]
    fn a_copy_propagates_pointer_capability_to_the_source() {
        // `mov rax, rdi` then `*(rax) = 1`: rax is dereferenced, so the
        // value it holds — rdi — is a pointer. The subtype edge rdi <: rax
        // carries the capability down to rdi.
        let solution = solve(&[
            instruction(vec![op(
                "COPY",
                Some(varnode("register", 0x0, 8)),  // rax
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
    fn a_spilled_pointer_recovers_its_field_through_the_reload() {
        // `mov [rbp-8], rdi` (spill), `mov rax, [rbp-8]` (reload),
        // `mov eax, [rax+8]` (field read): rdi is a pointer to a struct
        // with a field at +8. The reload's value is a unique that aliases
        // rdi, so the field must reach rdi through the subtype chain.
        let solution = solve(&[
            // spill: [rbp-8] = rdi
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x8f00, 8)),
                    vec![
                        varnode("register", 0x28, 8),
                        varnode("const", 0xfffffffffffffff8, 8),
                    ],
                ),
                op(
                    "COPY",
                    Some(varnode("unique", 0xd500, 8)),
                    vec![varnode("register", 0x38, 8)],
                ),
                op(
                    "STORE",
                    None,
                    vec![
                        varnode("const", 0x1b1, 4),
                        varnode("unique", 0x8f00, 8),
                        varnode("unique", 0xd500, 8),
                    ],
                ),
            ]),
            // reload: rax = [rbp-8]
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x8f00, 8)),
                    vec![
                        varnode("register", 0x28, 8),
                        varnode("const", 0xfffffffffffffff8, 8),
                    ],
                ),
                op(
                    "LOAD",
                    Some(varnode("unique", 0x23e00, 8)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x8f00, 8)],
                ),
                op(
                    "COPY",
                    Some(varnode("register", 0x0, 8)),
                    vec![varnode("unique", 0x23e00, 8)],
                ),
            ]),
            // field read: eax = [rax+8]
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x8f00, 8)),
                    vec![varnode("register", 0x0, 8), varnode("const", 0x8, 8)],
                ),
                op(
                    "LOAD",
                    Some(varnode("unique", 0x23d00, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x8f00, 8)],
                ),
                op(
                    "COPY",
                    Some(varnode("register", 0x0, 4)),
                    vec![varnode("unique", 0x23d00, 4)],
                ),
            ]),
        ]);
        assert!(
            matches!(solution.types.get(&0x38), Some(Ty::Ptr(_))),
            "rdi should be a pointer to a struct, got {:?}",
            solution.types.get(&0x38)
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
            Field {
                offset: 0x34,
                size: 4,
                class: Class::Float(32),
            },
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
                instruction(vec![op("CALL", None, vec![varnode("ram", 0x2000, 8)])]),
            ],
            &callees,
            &BTreeSet::new(),
        );
        match solution.types.get(&0x38) {
            Some(Ty::Ptr(inner)) => match inner.as_ref() {
                Ty::Struct(fields) => {
                    assert!(
                        fields.contains_key(&0x34),
                        "callee field at +0x34: {fields:?}"
                    );
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
                instruction(vec![op("CALL", None, vec![varnode("ram", 0x2000, 8)])]),
            ],
            &callees,
            &BTreeSet::from([0x38]),
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

    /// A spilled parameter reloaded and then used under both a signed and
    /// an unsigned read: the reload's `Subtype` edge carries the conflict
    /// back to the parameter. Under the old `Int join Uint = Num` collapse
    /// the join was order-dependent and the fixpoint's answer depended on
    /// which cap landed first; with `IntOrUint` the conflict resolves to
    /// the sign-unresolved width regardless of order.
    #[test]
    fn a_reloaded_parameter_with_disputed_sign_converges_to_int_or_uint() {
        let solution = solve(&[
            // spill: [rbp-8] = edi
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x8f00, 8)),
                    vec![
                        varnode("register", 0x28, 8),
                        varnode("const", 0xfffffffffffffff8, 8),
                    ],
                ),
                op(
                    "COPY",
                    Some(varnode("unique", 0xd500, 4)),
                    vec![varnode("register", 0x38, 4)],
                ),
                op(
                    "STORE",
                    None,
                    vec![
                        varnode("const", 0x1b1, 4),
                        varnode("unique", 0x8f00, 8),
                        varnode("unique", 0xd500, 4),
                    ],
                ),
            ]),
            // reload: eax = [rbp-8]  (a unique that aliases edi)
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x8f00, 8)),
                    vec![
                        varnode("register", 0x28, 8),
                        varnode("const", 0xfffffffffffffff8, 8),
                    ],
                ),
                op(
                    "LOAD",
                    Some(varnode("unique", 0x23e00, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x8f00, 8)],
                ),
            ]),
            // signed use of the reloaded value
            instruction(vec![op(
                "INT_SLESS",
                Some(varnode("unique", 0x300, 1)),
                vec![varnode("unique", 0x23e00, 4), varnode("const", 10, 4)],
            )]),
            // unsigned use of the same reloaded value: a mask is
            // conventionally unsigned, so `INT_AND` caps it `Uint` where
            // `INT_SLESS` capped it `Int` — the sign conflict.
            instruction(vec![op(
                "INT_AND",
                Some(varnode("unique", 0x301, 4)),
                vec![varnode("unique", 0x23e00, 4), varnode("const", 0xff, 4)],
            )]),
        ]);
        assert_eq!(
            solution.types.get(&0x38),
            Some(&Ty::Scalar(Class::IntOrUint(32))),
            "the sign-conflicted reload must converge to int-or-uint32, got {:?}",
            solution.types.get(&0x38)
        );
    }
}
