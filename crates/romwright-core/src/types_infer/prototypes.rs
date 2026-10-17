//! Inferred parameter types merged into the prototypes the decompiler
//! recovers (on by default; `ROMWRIGHT_INFERRED_TYPES=0` turns it off).
//!
//! The decompiler's own recovery commits a parameter list but rarely a
//! kind: a slot is `undefined<N>` when it saw the register used, and a
//! register-width `int`/`uint` when the value fed address arithmetic — its
//! type propagation spells `*(int *)(param_1 + 8)` with an integer base.
//! Neither is evidence against a pointer. This pass upgrades those slots
//! only where the evidence is the kind that measured precise against DWARF
//! on console images:
//!
//! * a pointer, when the subtype solver proved the register is the base of
//!   loads/stores (`*struct{..}`, `*T`, `T[stride]`). On a stripped
//!   pokeemerald ELF that structural evidence marks 4185 of 6064 DWARF
//!   pointer parameters and 4 of 8761 scalars. Applies to `undefined<N>`
//!   and to register-width `int`/`uint` slots.
//! * a signed integer, when a branch-relevant signed operation read the
//!   entry value (`Class::Int`), at a width no wider than the slot.
//!   Applies to `undefined<N>` only. Unsigned evidence is not used:
//!   unsigned compares and shifts are what address arithmetic and agbcc's
//!   `u8` truncation emit, so a `uint32` parameter class was a DWARF
//!   `uint32` 164 of 1026 times and a pointer 733 times.
//!
//! Returns are left alone: no evidence the inference produces for a result
//! register measured precise (a flat `ptr` return was right 0 of 11 times,
//! a flat `int32` return 7 of 53).
//!
//! The type upgrades change no arity, ordering, names, calling convention
//! or slot register; any other type the decompiler committed to (a pointer,
//! a float, a narrow integer, `bool`) stays, and a prototype a user
//! asserted or an import supplied is never touched (`protected`). Every
//! upgrade is named in the prototype's provenance source with the type it
//! replaced, so the precedence is inspectable from the store.
//!
//! The same pass, which already reads every function's p-code, repairs what
//! persisting a recovered prototype would otherwise spread. A locked callee
//! prototype is read at every call site, so a parameter or return the
//! callee's own code does not evidence is inherited by its callers, round
//! after round. Four rules, each named in the provenance source:
//!
//! * a variadic function's register-save area is `...`, not parameters
//!   (`variadic`);
//! * a trailing parameter almost no direct caller sets is optional: the
//!   prototype keeps the slots every caller uses and ends in `...`
//!   (`call_support`);
//! * a function whose result registers hold only what its callees returned,
//!   and whose result no direct caller reads, gets a `void` return;
//! * a body holding a trap into the environment (`software_interrupt`,
//!   `syscall`) gets no prototype at all: the registers the trap consumes are
//!   invisible to the decompiler, and `void(void)` would erase its callers'
//!   arguments.
use std::collections::BTreeMap;

use super::{Machine, Ty};
use crate::demand::LiveProgram;
use crate::exec::ExecutionRequest;
use crate::native_runtime::PcodeInstruction;
use crate::{Core, Result};
use romwright_model::type_evidence::Class;
use romwright_model::{Address, DecompType, FactKind, FuncProto, PrototypeRow};

/// One function's address and its lifted instructions.
type Lifted = (u64, Vec<PcodeInstruction>);

/// The name this pass appends to a prototype's provenance source.
pub const SOURCE: &str = "native-prototype:inferred-types";

/// The provenance source of the decompiler's own prototype recovery
/// (`Core::persist_inferred_prototypes`).
const RECOVERY_SOURCE: &str = "native-decompiler prototype recovery";

/// Whether a stored prototype outranks inference: a user's assertion, or an
/// inferred fact some other producer (an SDK/library type, a signature
/// match, an import) supplied. Only the decompiler's recovery — with or
/// without the register-input pass, and this pass's own earlier output —
/// may be refined.
pub fn protected(row: &PrototypeRow) -> bool {
    row.provenance.kind == FactKind::Asserted || !recovered_by_job(&row.provenance.source)
}

/// Whether a prototype's provenance source names the decompiler's own
/// recovery or a pass of the `infer_prototypes` job that refined it, as
/// opposed to an import, a library type, a signature match or a user.
fn recovered_by_job(source: &str) -> bool {
    source.starts_with(RECOVERY_SOURCE)
        || source.starts_with(crate::register_params::SOURCE)
        || source.contains(SOURCE)
}

/// What a merge needs to know about the target: the slots the inference
/// typed and the types the decompiler's prototypes name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Target {
    /// The prototype model the slots belong to. A prototype the decompiler
    /// recovered under another model has differently placed slots.
    pub model: String,
    pub pointer_size: u32,
    /// Bytes in each integer parameter register, by slot.
    pub slot_sizes: Vec<u32>,
    /// Type name -> (metatype, size): the language's `coretypes.xml` over
    /// the compiler spec's C base types, exactly the precedence the worker
    /// answers the decompiler with. A core type arrives in a recovered
    /// prototype as a bare reference — a name and an id — so its kind and
    /// width are read from here.
    pub types: BTreeMap<String, (String, u32)>,
}

impl Target {
    /// The metatype and width of a recovered type, if known.
    pub(super) fn shape<'a>(&'a self, ty: &'a DecompType) -> Option<(&'a str, u32)> {
        let named = ty.name.as_deref().and_then(|name| self.types.get(name));
        let metatype = ty.metatype.as_deref().or(named.map(|(metatype, _)| metatype.as_str()))?;
        let size = match ty.size {
            Some(size) => u32::try_from(size).ok()?,
            None if metatype == "ptr" => self.pointer_size,
            None => named?.1,
        };
        Some((metatype, size))
    }
}

/// What the inference proved about each function's integer parameter
/// slots, in the default prototype model's register order.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterTypes {
    pub target: Target,
    /// Entry -> the structural type of each slot (`Ty::Unknown` where
    /// nothing constrained it). Empty when the inference is off.
    pub functions: BTreeMap<u64, Vec<Ty>>,
    /// Entry -> the number of leading integer slots that are named
    /// parameters, for a function whose remaining argument registers are a
    /// variadic register-save area (`types_infer::variadic`).
    pub variadic: BTreeMap<u64, usize>,
    /// Functions whose body holds a user-defined operation (`CALLOTHER`:
    /// `swi`, `syscall`, ...). The decompiler cannot see which registers it
    /// consumes, so a parameter list recovered for such a function is a lower
    /// bound, and `void(void)` is no evidence that nothing is passed: no
    /// prototype is persisted for it, and its callers keep working out their
    /// own arguments at each call site.
    pub opaque: std::collections::BTreeSet<u64>,
    /// Functions at least `READ_PERCENT` of whose direct callers read the result. A function
    /// that only forwards a callee's result (`return g();`, which compiles
    /// like `g();`) has no evidence of returning a value unless some caller
    /// uses it: the job types its return `void` otherwise (`void_return`).
    pub result_read: std::collections::BTreeSet<u64>,
    /// Per function, the indices of the floating-point parameter registers
    /// its body reads at another width (`register_overlap`).
    pub float_overlap: BTreeMap<u64, std::collections::BTreeSet<usize>>,
    /// Entry -> per slot: the pointees the body dereferences through the
    /// slot's fields, by field offset (`subtype::Solution::pointees`).
    pub pointees: BTreeMap<u64, Vec<BTreeMap<i64, Ty>>>,
}

impl ParameterTypes {
    /// Repairs one recovered prototype in place, then (with `types`)
    /// upgrades its slots; returns the number of slots changed.
    pub fn apply(&self, entry: u64, prototype: &mut FuncProto, types: bool) -> usize {
        if let Some(named) = self.variadic.get(&entry) {
            variadic_tail(prototype, *named, &self.target);
        }
        let Some(slots) = self.functions.get(&entry).filter(|_| types) else {
            return 0;
        };
        upgrade(prototype, slots, &self.target)
    }

    /// Types `prototype`'s open pointer parameters with the structs the body
    /// proves ([`upgrade_structs`]) and returns their layouts. Call after
    /// [`apply`](Self::apply): its pointer upgrade is what makes an
    /// `undefined4` slot a pointer the struct can replace.
    pub fn apply_structs(
        &self,
        entry: u64,
        prototype: &mut FuncProto,
    ) -> Vec<romwright_model::structs::StructLayout> {
        let Some(slots) = self.functions.get(&entry) else {
            return Vec::new();
        };
        let none = Vec::new();
        let pointees = self.pointees.get(&entry).unwrap_or(&none);
        upgrade_structs(prototype, entry, slots, pointees, &self.target, false)
    }

    /// Whether persisting `prototype` for `entry` would break the function's
    /// own decompile: a floating-point parameter whose register the body also
    /// touches at another width (`register_overlap`), in the lifted p-code or
    /// in the decompiler's own recovery (`recovered`).
    pub fn locks_overlapping_input(
        &self,
        entry: u64,
        prototype: &FuncProto,
        recovered: Option<&std::collections::BTreeSet<usize>>,
    ) -> bool {
        let lifted = self.float_overlap.get(&entry);
        if lifted.is_none() && recovered.is_none() {
            return false;
        }
        prototype
            .parameters
            .iter()
            .filter(|parameter| {
                self.target.shape(&parameter.data_type).is_some_and(|(metatype, _)| metatype == "float")
            })
            .enumerate()
            .any(|(index, _)| {
                lifted.is_some_and(|set| set.contains(&index))
                    || recovered.is_some_and(|set| set.contains(&index))
            })
    }
}

/// The provenance suffix of a prototype whose return type was a callee's
/// result forwarded and was dropped.
pub const FORWARDED_RETURN_SOURCE: &str = "native-prototype:forwarded-return";

/// Types the return of a function that only forwards a callee's result as
/// `void` (see `ParameterTypes::result_read`). Returns whether it changed.
pub fn void_return(prototype: &mut FuncProto) -> bool {
    if prototype.return_type.metatype.as_deref() == Some("void")
        || prototype.return_type.name.as_deref() == Some("void")
    {
        return false;
    }
    prototype.return_type = DecompType {
        name: Some("void".into()),
        id: None,
        size: Some(0),
        metatype: Some("void".into()),
        element_count: None,
        target: None,
        prototype: None,
    };
    let base = prototype
        .parameter_source
        .take()
        .unwrap_or_else(|| RECOVERY_SOURCE.to_string());
    prototype.parameter_source = Some(format!("{base}+{FORWARDED_RETURN_SOURCE}"));
    true
}

/// The provenance suffix of a prototype whose register-save area was
/// dropped from its parameters.
pub const VARIADIC_SOURCE: &str = "native-prototype:variadic-save-area";

/// Turns the tail of a recovered prototype that `types_infer::variadic`
/// proved is a register-save area into `...`: the integer parameters from
/// slot `named` on are dropped and the prototype is marked variadic.
/// Returns whether it changed. Floats before the cut stay (they are placed
/// from their own register list), and a parameter whose placement is not
/// one register ends the mapping without a change.
pub fn variadic_tail(prototype: &mut FuncProto, named: usize, target: &Target) -> bool {
    if prototype.variadic
        || (!matches!(prototype.calling_convention.as_str(), "" | "unknown" | "default")
            && prototype.calling_convention != target.model)
    {
        return false;
    }
    let mut slot = 0usize;
    let mut cut = None;
    for (index, parameter) in prototype.parameters.iter().enumerate() {
        let Some((metatype, size)) = target.shape(&parameter.data_type) else {
            return false;
        };
        if metatype == "float" {
            continue;
        }
        let Some(&register) = target.slot_sizes.get(slot) else {
            return false;
        };
        let integral = matches!(metatype, "unknown" | "int" | "uint" | "bool" | "ptr");
        if !integral || size == 0 || size > register {
            return false;
        }
        if slot == named {
            cut = Some(index);
            break;
        }
        slot += 1;
    }
    let Some(cut) = cut else {
        return false;
    };
    let dropped = prototype.parameters.len() - cut;
    prototype.parameters.truncate(cut);
    prototype.variadic = true;
    let base = prototype
        .parameter_source
        .take()
        .unwrap_or_else(|| RECOVERY_SOURCE.to_string());
    prototype.parameter_source = Some(format!("{base}+{VARIADIC_SOURCE}(dropped {dropped})"));
    true
}

/// Merges slot evidence into `prototype`. Parameters map onto integer
/// slots in order; mapping stops at the first parameter whose placement is
/// not one-register-per-parameter (a float, an aggregate, a value wider
/// than its register, a type of unknown width), since every later slot
/// would be a guess.
pub fn upgrade(prototype: &mut FuncProto, slots: &[Ty], target: &Target) -> usize {
    if !matches!(prototype.calling_convention.as_str(), "" | "unknown" | "default")
        && prototype.calling_convention != target.model
    {
        return 0;
    }
    let mut upgrades = Vec::new();
    for (index, parameter) in prototype.parameters.iter_mut().enumerate() {
        let (Some(evidence), Some(&register)) = (slots.get(index), target.slot_sizes.get(index))
        else {
            break;
        };
        let Some((metatype, size)) = target.shape(&parameter.data_type) else {
            break;
        };
        let integral = matches!(metatype, "unknown" | "int" | "uint" | "bool" | "ptr");
        if !integral || size == 0 || size > register {
            break;
        }
        // `undefined<N>` is the decompiler's "used, kind unknown"; a
        // register-width integer is what it calls an address base it has
        // no pointer type for, so only a proven pointer replaces it. Any
        // other type it committed to is its own evidence and stays.
        let unknown = metatype == "unknown";
        let address_width = matches!(metatype, "int" | "uint") && size >= target.pointer_size;
        let replacement = match evidence {
            Ty::Ptr(_) | Ty::Struct(_) | Ty::Array { .. }
                if (unknown || address_width) && size >= target.pointer_size =>
            {
                Some(pointer(target.pointer_size))
            }
            Ty::Scalar(Class::Int(bits)) if unknown && bits % 8 == 0 && bits / 8 <= size => {
                signed(bits / 8, target)
            }
            _ => None,
        };
        if let Some(data_type) = replacement {
            let was = parameter.data_type.name.as_deref().unwrap_or(metatype);
            let now = data_type.name.as_deref().unwrap_or("ptr");
            upgrades.push(format!("{}:{was}->{now}", parameter.name));
            parameter.data_type = data_type;
        }
    }
    if upgrades.is_empty() {
        return 0;
    }
    let base = prototype
        .parameter_source
        .take()
        .unwrap_or_else(|| RECOVERY_SOURCE.to_string());
    prototype.parameter_source = Some(format!("{base}+{SOURCE}({})", upgrades.join(",")));
    upgrades.len()
}

/// Whether a pointer type says nothing of what it points at: `void *`,
/// `undefined *`, `undefined1 *`. A pointer the decompiler or a declaration
/// typed (`char *`, `Node *`) is that source's claim and stays.
fn opaque_pointer(ty: &DecompType) -> bool {
    match ty.target.as_deref() {
        None => true,
        Some(target) => {
            target.metatype.as_deref() == Some("void")
                || matches!(target.name.as_deref(), Some("void" | "undefined" | "undefined1"))
        }
    }
}

/// Types a parameter that is a pointer to a struct the body's accesses prove
/// with `struct fn_<entry>_arg<n> *`, for every slot `upgrade` maps (same
/// slot rules) whose type says nothing of its pointee, and returns the
/// layouts those names stand for. `slots[i]` is the solver's type for slot
/// `i`, `pointees[i]` the layouts it proved behind that slot's pointer
/// fields. The parameter source records each retyped parameter. `declared`:
/// the prototype is one a user or an import supplied (`protected`), where only
/// a pointer that says nothing (`void *`, the erasure of a struct pointer) is
/// open and an integer is the declaration's word.
pub fn upgrade_structs(
    prototype: &mut FuncProto,
    entry: u64,
    slots: &[Ty],
    pointees: &[BTreeMap<i64, Ty>],
    target: &Target,
    declared: bool,
) -> Vec<romwright_model::structs::StructLayout> {
    if !matches!(prototype.calling_convention.as_str(), "" | "unknown" | "default")
        && prototype.calling_convention != target.model
    {
        return Vec::new();
    }
    let none = BTreeMap::new();
    let mut layouts = Vec::new();
    let mut named = Vec::new();
    for (index, parameter) in prototype.parameters.iter_mut().enumerate() {
        let (Some(evidence), Some(&register)) = (slots.get(index), target.slot_sizes.get(index))
        else {
            break;
        };
        let Some((metatype, size)) = target.shape(&parameter.data_type) else {
            break;
        };
        let integral = matches!(metatype, "unknown" | "int" | "uint" | "bool" | "ptr");
        if !integral || size == 0 || size > register {
            break;
        }
        let open = match metatype {
            // An integer a declaration or the compiler's debug info typed is
            // that source's claim; only the decompiler's own guess is open.
            "unknown" | "int" | "uint" => !declared && size >= target.pointer_size,
            "ptr" => opaque_pointer(&parameter.data_type),
            _ => false,
        };
        if !open {
            continue;
        }
        let made = crate::struct_types::synthesize(entry, index, evidence, pointees.get(index).unwrap_or(&none));
        let Some(first) = made.first() else { continue };
        named.push(format!("{}:{}", parameter.name, first.name));
        parameter.data_type = DecompType {
            name: None,
            id: None,
            size: Some(target.pointer_size.into()),
            metatype: Some("ptr".into()),
            element_count: None,
            target: Some(Box::new(DecompType {
                name: Some(first.name.clone()),
                id: None,
                size: Some(first.size),
                metatype: Some("struct".into()),
                element_count: None,
                target: None,
                prototype: None,
            })),
            prototype: None,
        };
        layouts.extend(made);
    }
    if named.is_empty() {
        return layouts;
    }
    let base = prototype
        .parameter_source
        .take()
        .unwrap_or_else(|| RECOVERY_SOURCE.to_string());
    prototype.parameter_source = Some(format!(
        "{base}+{}({})",
        romwright_model::structs::PROTOTYPE_SOURCE,
        named.join(",")
    ));
    layouts
}

/// `undefined1 *` at the target's pointer width: a pointer whose pointee
/// the evidence does not name, spelled the way the decompiler spells one.
fn pointer(pointer_size: u32) -> DecompType {
    DecompType {
        name: None,
        id: None,
        size: Some(pointer_size.into()),
        metatype: Some("ptr".into()),
        element_count: None,
        target: Some(Box::new(DecompType {
            name: Some("undefined1".into()),
            id: None,
            size: Some(1),
            metatype: Some("unknown".into()),
            element_count: None,
            target: None,
            prototype: None,
        })),
        prototype: None,
    }
}

/// The language's core signed integer type of `size` bytes, if it names one.
fn signed(size: u32, target: &Target) -> Option<DecompType> {
    let name = match size {
        1 => "sbyte",
        2 => "short",
        4 => "int",
        _ => return None,
    };
    if target.types.get(name) != Some(&("int".to_string(), size)) {
        return None;
    }
    Some(DecompType {
        name: Some(name.into()),
        id: None,
        size: Some(size.into()),
        metatype: Some("int".into()),
        element_count: None,
        target: None,
        prototype: None,
    })
}

/// `<type name=".." size=".." metatype=".."/>` entries of a `coretypes.xml`.
fn core_types(text: &str) -> impl Iterator<Item = (String, (String, u32))> + '_ {
    let attribute = |header: &str, name: &str| {
        let marker = format!("{name}=\"");
        let start = header.find(&marker)? + marker.len();
        let end = header[start..].find('"')?;
        Some(header[start..start + end].to_string())
    };
    text.split("<type ").skip(1).filter_map(move |rest| {
        let header = &rest[..rest.find('>')?];
        let size = attribute(header, "size")?.parse().ok()?;
        Some((attribute(header, "name")?, (attribute(header, "metatype")?, size)))
    })
}

/// Runs `work` over `items` on up to `workers` threads and returns the
/// results in item order. The first failure (lowest item index) wins and
/// stops the remaining threads from taking new items.
fn map_parallel<T: Sync, R: Send>(
    items: &[T],
    workers: usize,
    work: impl Fn(&T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let workers = workers.clamp(1, items.len().max(1));
    if workers == 1 {
        return items.iter().map(work).collect();
    }
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let parts: Vec<Vec<(usize, Result<R>)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut part = Vec::new();
                    while !failed.load(Ordering::Relaxed) {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(index) else { break };
                        let result = work(item);
                        if result.is_err() {
                            failed.store(true, Ordering::Relaxed);
                        }
                        part.push((index, result));
                    }
                    part
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
            .collect()
    });
    let mut results: Vec<(usize, Result<R>)> = parts.into_iter().flatten().collect();
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

/// Whether a user-defined p-code operation hands control to the environment
/// (SLEIGH names them `software_interrupt`, `syscall`, `swi`, `svc`, `sc`,
/// `hypercall`, ...), so that registers its caller set are inputs the
/// decompiler cannot see read.
fn traps_to_environment(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(name.as_str(), "sc" | "swi" | "svc" | "int" | "sysenter" | "syscall")
        || ["software_interrupt", "supervisor", "hypercall", "syscall"]
            .iter()
            .any(|marker| name.contains(marker))
}

/// Whether enough direct callers read a function's result for it to be a value
/// the function returns. A lone reader among 1,249 call sites (Capcom's
/// `0x1d0670`, whose callers drop the result) is not evidence; the callees of
/// the PSP forwarders that DWARF types as values (21 forwarders) have callees
/// read by at least 28% of their call sites. Two images, a wide gap
/// ([INFERENCE]: the threshold anywhere between 1% and 28% gives the same
/// answer there).
const READ_PERCENT: u32 = 10;

fn read_often(calls: u32, used: u32) -> bool {
    used > 0 && used * 100 >= calls * READ_PERCENT
}

/// Call sites a callee needs before its callers can vote on its arity.
const MIN_CALL_SITES: u32 = 8;

/// A slot is optional when at most this percentage of the call sites set it.
/// Measured on the 15.3k pokeemerald functions DWARF covers (call sites >= 8):
/// 578 of 596 real trailing parameters are set by 90% or more of their callers,
/// while 1,479 of the 1,633 slots past the real arity are set by at most 50%.
const OPTIONAL_PERCENT: u32 = 60;

/// The number of leading integer slots every caller of a function really
/// uses, when the slots after them are almost never set (`call_support`).
/// The first slot is always kept: C needs a named parameter before `...`.
fn optional_from(calls: u32, set: &[u32]) -> Option<usize> {
    if calls < MIN_CALL_SITES {
        return None;
    }
    let rarely = |count: u32| count * 100 <= calls * OPTIONAL_PERCENT;
    (1..set.len()).rev().take_while(|slot| rarely(set[*slot])).last()
}

/// Functions each handle on the image must have to be worth opening: a
/// handle costs a console start and an image parse.
const FUNCTIONS_PER_HANDLE: usize = 2_000;

/// Handles on the image for walking and lifting `functions` bodies.
fn lift_workers(functions: usize, job_workers: usize) -> usize {
    job_workers.min(functions / FUNCTIONS_PER_HANDLE).max(1)
}

/// The p-code of each function of `chunk`, in order; a function whose walk
/// decodes nothing has none.
fn lift_slice(
    live: &mut LiveProgram,
    chunk: &[(Address, FuncProto)],
    req: &ExecutionRequest,
) -> Result<Vec<(u64, Vec<PcodeInstruction>)>> {
    let mut lifted = Vec::with_capacity(chunk.len());
    for (address, _) in chunk {
        req.cancel.checkpoint(req.deadline)?;
        let walk = live.walk(address.offset)?;
        if walk.instructions == 0 {
            continue;
        }
        let mut addresses: Vec<u64> =
            walk.instruction_extents.iter().map(|(address, _)| *address).collect();
        addresses.sort_unstable();
        addresses.dedup();
        lifted.push((address.offset, live.pcode(&addresses)?));
    }
    Ok(lifted)
}

impl Core {
    /// The float parameter registers and the stack pointer of the program's
    /// default prototype model (`register_overlap::FloatLayout`).
    pub fn float_register_layout(
        &self,
        req: &ExecutionRequest,
    ) -> Result<super::register_overlap::FloatLayout> {
        let (_, specs, _, _) =
            crate::native_runtime::language_decompile_config(&req.config, &req.language)?;
        let cspec = std::fs::read_to_string(specs.join("cspec.xml"))?;
        let table = std::fs::read_to_string(specs.join("registers.txt"))?;
        let conventions = crate::register_params::Conventions::parse(&cspec, &table);
        let size = |name: &str| {
            conventions
                .registers
                .get(name)
                .map(|(offset, size)| (*offset, u32::try_from(*size).unwrap_or(u32::MAX)))
        };
        let machine: Machine = conventions.machine(&req.language);
        let mut known: Vec<(u64, u32)> = Vec::new();
        if let Some(offset) = machine.stack_pointer {
            known.extend(
                conventions
                    .registers
                    .values()
                    .filter(|(at, _)| *at == offset)
                    .map(|(at, width)| (*at, u32::try_from(*width).unwrap_or(u32::MAX))),
            );
        }
        let mut registers = Vec::new();
        if let Some(model) = conventions.default() {
            known.extend(
                model
                    .registers
                    .iter()
                    .chain(&model.returns)
                    .chain(&model.float_returns)
                    .filter_map(|name| size(name)),
            );
            registers = model.float_registers.iter().filter_map(|name| size(name)).collect();
            known.extend(registers.iter().copied());
        }
        Ok(super::register_overlap::FloatLayout { known, registers })
    }

    /// Solves every function in `recovered` the way `infer_types` does —
    /// the subtype solver to an interprocedural fixpoint, the decompiler's
    /// recovered prototypes asserted for callees — and keeps each integer
    /// parameter slot's structural type.
    pub fn parameter_types(
        &self,
        req: &ExecutionRequest,
        recovered: &[(Address, FuncProto)],
    ) -> Result<ParameterTypes> {
        let (_, specs, _, _) =
            crate::native_runtime::language_decompile_config(&req.config, &req.language)?;
        let cspec = std::fs::read_to_string(specs.join("cspec.xml"))?;
        let table = std::fs::read_to_string(specs.join("registers.txt"))?;
        let conventions = crate::register_params::Conventions::parse(&cspec, &table);
        let machine: Machine = conventions.machine(&req.language);
        let mut target = Target {
            pointer_size: machine.pointer_size,
            ..Target::default()
        };
        target.types = crate::library_types::language_base_types(&specs)
            .into_iter()
            .map(|(name, base)| (name, (base.metatype.to_string(), base.size)))
            .collect();
        if let Ok(text) = std::fs::read_to_string(specs.join("coretypes.xml")) {
            target.types.extend(core_types(&text));
        }
        let Some(model) = conventions.default() else {
            return Ok(ParameterTypes {
                target,
                functions: BTreeMap::new(),
                variadic: BTreeMap::new(),
                opaque: Default::default(),
                result_read: Default::default(),
                float_overlap: Default::default(),
                pointees: Default::default(),
            });
        };
        target.model = model.name.clone();
        let register = |name: &str| conventions.registers.get(name).copied();
        let offset = |name: &str| register(name).map(|(offset, _)| offset);
        let killed: std::collections::BTreeSet<u64> =
            model.killed.iter().filter_map(|name| offset(name)).collect();
        // A float slot is the register the spec names, plus — for a pair
        // like `f12_13` — its first single (`infer_types` does the same).
        let float_offsets = |name: &str| {
            let mut offsets: Vec<u64> = offset(name).into_iter().collect();
            if let Some(single) = name.split('_').next().filter(|single| *single != name)
                && let Some(single) = offset(single)
                && !offsets.contains(&single)
            {
                offsets.push(single);
            }
            offsets
        };
        let int_slots: Vec<u64> = model.registers.iter().filter_map(|name| offset(name)).collect();
        target.slot_sizes = model
            .registers
            .iter()
            .filter_map(|name| register(name))
            .map(|(_, size)| u32::try_from(size).unwrap_or(u32::MAX))
            .collect();
        let float_slots: Vec<u64> = model.float_registers.iter().flat_map(|name| float_offsets(name)).collect();
        let float_regs: Vec<(u64, u32)> = model
            .float_registers
            .iter()
            .filter_map(|name| register(name))
            .map(|(offset, size)| (offset, u32::try_from(size).unwrap_or(u32::MAX)))
            .collect();
        let int_returns: Vec<u64> = model.returns.iter().filter_map(|name| offset(name)).collect();
        let float_returns: Vec<u64> =
            model.float_returns.iter().flat_map(|name| float_offsets(name)).collect();
        // A call's result may arrive in an integer or a float register.
        let result_registers: Vec<u64> = int_returns.iter().chain(&float_returns).copied().collect();
        // The decompiler's recovered prototype is each callee's signature
        // in a caller's solve: the Strong fact `infer_types` asserts.
        let signatures: BTreeMap<u64, crate::subtype::Signature> = recovered
            .iter()
            .map(|(address, prototype)| {
                let signature = crate::subtype::Signature::from_funcproto(
                    prototype,
                    &int_slots,
                    &float_slots,
                    &int_returns,
                    &float_returns,
                    &machine,
                );
                (address.offset, signature)
            })
            .collect();
        let mut trapping: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        // Walking a body needs a console and lifting it needs a lifter, one
        // of each per thread. Bodies are independent, so a large image
        // spreads contiguous slices of the function list over several
        // handles on the image (`open_extra`), and the slices come back in
        // order: the list is the one a single handle would have built.
        let workers = lift_workers(recovered.len(), req.config.job_workers);
        let mut extra = if workers > 1 {
            self.live.open_extra(&req.input, &req.program, Some(req), workers - 1)?
        } else {
            Vec::new()
        };
        let lifted = self.live.with(&req.input, &req.program, Some(req), |live| {
            trapping = live
                .user_op_names()?
                .iter()
                .enumerate()
                .filter(|(_, name)| traps_to_environment(name))
                .map(|(index, _)| index as u64)
                .collect();
            let slice = recovered.len().div_ceil(workers).max(1);
            let handles: Vec<&mut LiveProgram> =
                std::iter::once(live).chain(extra.iter_mut()).collect();
            let parts: Vec<Result<Vec<Lifted>>> =
                std::thread::scope(|scope| {
                    let spawned: Vec<_> = handles
                        .into_iter()
                        .zip(recovered.chunks(slice))
                        .map(|(program, chunk)| scope.spawn(move || lift_slice(program, chunk, req)))
                        .collect();
                    spawned
                        .into_iter()
                        .map(|handle| {
                            handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                        })
                        .collect()
                });
            let mut lifted = Vec::with_capacity(recovered.len());
            for part in parts {
                lifted.extend(part?);
            }
            Ok(lifted)
        })?;
        drop(extra);
        // Every function carries the decompiler's signature, so the callee
        // map is fixed and each function's solve reads nothing but its own
        // p-code: the solves are independent. Worker threads take them in
        // any order and the answers are collected by position, so the
        // result is the one a serial pass would build.
        let types = req.config.inferred_types;
        let solved = map_parallel(&lifted, req.config.job_workers, |(entry, pcode)| {
            req.cancel.checkpoint(req.deadline)?;
            let named = super::variadic::named_slots(pcode, &int_slots, &machine);
            // A trap into the environment (a software interrupt, a system
            // call) consumes registers the decompiler never sees read.
            let opaque = pcode.iter().any(|instruction| {
                instruction.ops.iter().any(|op| {
                    op.opcode == "CALLOTHER"
                        && op.inputs.first().is_some_and(|index| trapping.contains(&index.offset))
                })
            });
            let sites = super::call_support::call_sites(pcode, &int_slots, &result_registers);
            let overlap = super::register_overlap::overlapped(pcode, &float_regs);
            if !types {
                return Ok((*entry, Vec::new(), Vec::new(), named, opaque, sites, overlap));
            }
            let solution = crate::subtype::solve_with(pcode, &signatures, &killed, &machine);
            let facts = super::infer(pcode, &machine);
            // The solver's pointer/struct/array is what only it proves;
            // for a scalar the alias-aware flat inference is the better
            // reader of a spilled parameter (`infer_types`' rule).
            let slots = int_slots
                .iter()
                .map(|offset| match solution.types.get(offset) {
                    Some(ty @ (Ty::Ptr(_) | Ty::Struct(_) | Ty::Array { .. })) => ty.clone(),
                    _ => Ty::Scalar(facts.get(*offset)),
                })
                .collect();
            let slot_pointees = int_slots
                .iter()
                .map(|offset| solution.pointees.get(offset).cloned().unwrap_or_default())
                .collect();
            Ok((*entry, slots, slot_pointees, named, opaque, sites, overlap))
        })?;
        let mut functions = BTreeMap::new();
        let mut pointees = BTreeMap::new();
        let mut variadic = BTreeMap::new();
        let mut opaque_entries = std::collections::BTreeSet::new();
        let mut float_overlap = BTreeMap::new();
        // Per callee: its direct call sites, per slot how many set it, and
        // how many read what it returns.
        let mut support: BTreeMap<u64, (u32, Vec<u32>, u32)> = BTreeMap::new();
        for (entry, slots, slot_pointees, named, opaque, sites, overlap) in solved {
            if types {
                functions.insert(entry, slots);
                pointees.insert(entry, slot_pointees);
            }
            if let Some(named) = named {
                variadic.insert(entry, named);
            }
            if opaque {
                opaque_entries.insert(entry);
            }
            if !overlap.is_empty() {
                float_overlap.insert(entry, overlap);
            }
            for site in sites {
                if site.callee == entry {
                    continue;
                }
                let (calls, set, used) = support
                    .entry(site.callee)
                    .or_insert_with(|| (0, vec![0; int_slots.len()], 0));
                *calls += 1;
                *used += u32::from(site.uses_result);
                for (slot, count) in set.iter_mut().enumerate().take(64) {
                    *count += u32::from(site.set >> slot & 1 == 1);
                }
            }
        }
        // A trailing slot nearly no caller sets is optional, not a parameter.
        for (callee, (calls, set, _)) in &support {
            if let Some(named) = optional_from(*calls, set) {
                let named = variadic.get(callee).map_or(named, |spilled| named.min(*spilled));
                variadic.insert(*callee, named);
            }
        }
        let result_read = support
            .iter()
            .filter(|(_, (calls, _, used))| read_often(*calls, *used))
            .map(|(callee, _)| *callee)
            .collect();
        Ok(ParameterTypes {
            target,
            functions,
            pointees,
            variadic,
            opaque: opaque_entries,
            result_read,
            float_overlap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{FactProvenance, FuncParam};

    /// A core type as a recovered prototype carries it: a bare reference.
    fn undefined(size: u64) -> DecompType {
        DecompType {
            name: Some(format!("undefined{size}")),
            id: None,
            size: None,
            metatype: None,
            element_count: None,
            target: None,
            prototype: None,
        }
    }

    fn named(name: &str, metatype: &str, size: u64) -> DecompType {
        DecompType {
            name: Some(name.into()),
            id: None,
            size: Some(size),
            metatype: Some(metatype.into()),
            element_count: None,
            target: None,
            prototype: None,
        }
    }

    fn proto(types: Vec<DecompType>) -> FuncProto {
        FuncProto {
            calling_convention: "__stdcall".into(),
            return_type: undefined(4),
            parameters: types
                .into_iter()
                .enumerate()
                .map(|(index, data_type)| FuncParam {
                    ordinal: index as u32,
                    name: format!("param_{}", index + 1),
                    data_type,
                })
                .collect(),
            variadic: false,
            no_return: false,
            parameter_source: None,
        }
    }

    fn structural() -> Ty {
        Ty::Ptr(Box::new(Ty::Struct(BTreeMap::from([(
            4,
            super::super::Field { offset: 4, size: 4, class: Class::Int(32) },
        )]))))
    }

    const CORETYPES: &str = r#"<coretypes><type name="undefined1" size="1" metatype="unknown" id="0x1"/><type name="undefined2" size="2" metatype="unknown" id="0x2"/><type name="undefined4" size="4" metatype="unknown" id="0x3"/><type name="undefined8" size="8" metatype="unknown" id="0x4"/><type name="short" size="2" metatype="int" id="0x5"/><type name="int" size="4" metatype="int" id="0x6"/><type name="float" size="4" metatype="float" id="0x7"/></coretypes>"#;

    fn target(slot_sizes: &[u32]) -> Target {
        Target {
            model: "__stdcall".into(),
            pointer_size: 4,
            slot_sizes: slot_sizes.to_vec(),
            types: core_types(CORETYPES).collect(),
        }
    }

    const SLOTS: [u32; 4] = [4, 4, 4, 4];

    #[test]
    fn core_types_are_read_with_kind_and_width() {
        let types = target(&SLOTS).types;
        assert_eq!(types.len(), 7);
        assert_eq!(types["undefined8"], ("unknown".to_string(), 8));
        assert_eq!(types["short"], ("int".to_string(), 2));
    }

    fn row(kind: FactKind, source: &str) -> PrototypeRow {
        PrototypeRow {
            function: Address::ram(0x0800_0000),
            signature: "void f(void)".into(),
            calling_convention: None,
            return_type: Some("void".into()),
            provenance: FactProvenance { kind, source: source.into(), confidence: None },
        }
    }

    #[test]
    fn user_and_import_prototypes_are_protected() {
        assert!(protected(&row(FactKind::Asserted, "analyst")));
        assert!(protected(&row(FactKind::Asserted, RECOVERY_SOURCE)));
        assert!(protected(&row(FactKind::Inferred, crate::library_types::SOURCE)));
        assert!(protected(&row(FactKind::Inferred, "native-import:type-archive")));
        assert!(!protected(&row(FactKind::Inferred, RECOVERY_SOURCE)));
        assert!(!protected(&row(FactKind::Inferred, "native-prototype:register-input(ECX)")));
        assert!(!protected(&row(
            FactKind::Inferred,
            "native-decompiler prototype recovery+native-prototype:inferred-types(param_1:ptr)"
        )));
    }

    #[test]
    fn decompiler_committed_types_win_over_inference() {
        // A pointer, a narrow integer and `bool` the decompiler committed
        // to all stay; so does a register-width `uint` against anything
        // short of a proven pointer.
        let mut prototype = proto(vec![
            named("int", "int", 4),
            named("short", "int", 2),
            named("bool", "bool", 1),
            named("uint", "uint", 4),
        ]);
        prototype.parameters[0].data_type = DecompType {
            name: None,
            metatype: Some("ptr".into()),
            size: Some(4),
            target: Some(Box::new(named("int", "int", 4))),
            ..undefined(4)
        };
        let before = prototype.clone();
        let slots = [structural(), structural(), structural(), Ty::Scalar(Class::Int(32))];
        assert_eq!(upgrade(&mut prototype, &slots, &target(&SLOTS)), 0);
        assert_eq!(prototype, before);
    }

    #[test]
    fn register_width_integer_yields_only_to_a_proven_pointer() {
        let mut prototype = proto(vec![named("int", "int", 4), named("uint", "uint", 4)]);
        let slots = [structural(), Ty::Scalar(Class::Ptr)];
        assert_eq!(upgrade(&mut prototype, &slots, &target(&SLOTS)), 1);
        assert_eq!(prototype.parameters[0].data_type.metatype.as_deref(), Some("ptr"));
        assert_eq!(prototype.parameters[1].data_type, named("uint", "uint", 4));
        assert_eq!(
            prototype.parameter_source.as_deref(),
            Some("native-decompiler prototype recovery+native-prototype:inferred-types(param_1:int->ptr)")
        );
    }

    #[test]
    fn scalar_evidence_never_becomes_a_pointer() {
        let mut prototype = proto(vec![undefined(4), undefined(4), undefined(4), undefined(4)]);
        let slots = [
            Ty::Scalar(Class::Uint(32)),
            Ty::Scalar(Class::Num(32)),
            Ty::Scalar(Class::Ptr),
            Ty::Unknown,
        ];
        assert_eq!(upgrade(&mut prototype, &slots, &target(&SLOTS)), 0);
        assert!(prototype.parameters.iter().all(|p| p.data_type == undefined(4)));
        assert_eq!(prototype.parameter_source, None);
    }

    #[test]
    fn structural_pointer_and_signed_evidence_upgrade_without_changing_arity() {
        let mut prototype = proto(vec![undefined(4), undefined(4), undefined(4)]);
        let slots = [structural(), Ty::Unknown, Ty::Scalar(Class::Int(16)), Ty::Scalar(Class::Int(32))];
        assert_eq!(upgrade(&mut prototype, &slots, &target(&SLOTS)), 2);
        assert_eq!(prototype.parameters.len(), 3);
        let first = &prototype.parameters[0].data_type;
        assert_eq!(first.metatype.as_deref(), Some("ptr"));
        assert_eq!(first.size, Some(4));
        assert_eq!(prototype.parameters[1].data_type, undefined(4));
        assert_eq!(prototype.parameters[2].data_type, named("short", "int", 2));
        assert_eq!(
            prototype.parameter_source.as_deref(),
            Some(
                "native-decompiler prototype recovery+native-prototype:inferred-types(param_1:undefined4->ptr,param_3:undefined4->short)"
            )
        );
        // Names, ordinals and the convention are the decompiler's.
        let names: Vec<_> = prototype.parameters.iter().map(|p| (p.ordinal, p.name.as_str())).collect();
        assert_eq!(names, [(0, "param_1"), (1, "param_2"), (2, "param_3")]);
        assert_eq!(prototype.calling_convention, "__stdcall");
    }

    #[test]
    fn pointer_takes_the_target_width_and_needs_a_slot_that_holds_it() {
        // A 64-bit register slot (PS2 `undefined8`) narrows to a 4-byte
        // pointer; a 2-byte slot cannot hold one.
        let mut prototype = proto(vec![undefined(8), undefined(2)]);
        let slots = [structural(), structural()];
        assert_eq!(upgrade(&mut prototype, &slots, &target(&[16, 16])), 1);
        assert_eq!(prototype.parameters[0].data_type.size, Some(4));
        assert_eq!(prototype.parameters[1].data_type, undefined(2));
    }

    #[test]
    fn mapping_stops_where_slots_stop_lining_up() {
        // A float or a register pair shifts every later slot: nothing after
        // it is upgraded.
        let mut prototype = proto(vec![named("float", "float", 4), undefined(4)]);
        assert_eq!(upgrade(&mut prototype, &[structural(), structural()], &target(&SLOTS)), 0);
        let mut prototype = proto(vec![undefined(8), undefined(4)]);
        assert_eq!(upgrade(&mut prototype, &[structural(), structural()], &target(&SLOTS)), 0);
        // A type whose width nothing states cannot be placed.
        let mut prototype = proto(vec![named("mystery", "unknown", 4), undefined(4)]);
        prototype.parameters[0].data_type.size = None;
        assert_eq!(upgrade(&mut prototype, &[structural(), structural()], &target(&SLOTS)), 0);
        // A prototype recovered under another model has other slots.
        let mut prototype = proto(vec![undefined(4)]);
        prototype.calling_convention = "__fastcall".into();
        assert_eq!(upgrade(&mut prototype, &[structural()], &target(&SLOTS)), 0);
    }

    #[test]
    fn existing_parameter_source_is_kept_as_the_base() {
        let mut prototype = proto(vec![undefined(4)]);
        prototype.parameter_source = Some("native-prototype:register-input(r0)".into());
        assert_eq!(upgrade(&mut prototype, &[structural()], &target(&SLOTS)), 1);
        assert_eq!(
            prototype.parameter_source.as_deref(),
            Some("native-prototype:register-input(r0)+native-prototype:inferred-types(param_1:undefined4->ptr)")
        );
    }

    #[test]
    fn a_save_area_becomes_ellipsis() {
        let mut prototype = proto(vec![undefined(4), undefined(4), undefined(4), undefined(4)]);
        assert!(variadic_tail(&mut prototype, 1, &target(&SLOTS)));
        assert_eq!(prototype.parameters.len(), 1);
        assert!(prototype.variadic);
        assert_eq!(
            prototype.parameter_source.as_deref(),
            Some("native-decompiler prototype recovery+native-prototype:variadic-save-area(dropped 3)")
        );
        // Already variadic, nothing to cut, another model: unchanged.
        assert!(!variadic_tail(&mut prototype, 1, &target(&SLOTS)));
        let mut short = proto(vec![undefined(4)]);
        assert!(!variadic_tail(&mut short, 1, &target(&SLOTS)));
        assert!(!short.variadic);
        let mut other = proto(vec![undefined(4), undefined(4), undefined(4)]);
        other.calling_convention = "__fastcall".into();
        assert!(!variadic_tail(&mut other, 1, &target(&SLOTS)));
    }

    #[test]
    fn floats_before_the_cut_do_not_consume_integer_slots() {
        let mut prototype =
            proto(vec![undefined(4), named("float", "float", 4), undefined(4), undefined(4)]);
        assert!(variadic_tail(&mut prototype, 1, &target(&SLOTS)));
        assert_eq!(prototype.parameters.len(), 2);
        // An aggregate before the cut breaks the slot mapping: no change.
        let mut prototype = proto(vec![undefined(8), undefined(4), undefined(4)]);
        assert!(!variadic_tail(&mut prototype, 1, &target(&SLOTS)));
        assert!(!prototype.variadic);
    }

    #[test]
    fn parallel_results_are_the_serial_results() {
        let items: Vec<u64> = (0..2_000).collect();
        let serial = map_parallel(&items, 1, |n| Ok(n * n)).unwrap();
        for workers in [2, 3, 8, 64] {
            assert_eq!(map_parallel(&items, workers, |n| Ok(n * n)).unwrap(), serial);
        }
        assert!(map_parallel(&[] as &[u64], 4, |n| Ok(*n)).unwrap().is_empty());
    }

    #[test]
    fn the_lowest_failing_item_is_the_error() {
        let items: Vec<u64> = (0..500).collect();
        let fail = |n: &u64| {
            if n % 100 == 37 {
                Err(crate::CoreError::InvalidPrototype(format!("item {n}")))
            } else {
                Ok(*n)
            }
        };
        for workers in [1, 4] {
            let error = map_parallel(&items, workers, fail).unwrap_err();
            assert!(error.to_string().contains("item 37"), "{error}");
        }
    }

    #[test]
    fn only_traps_into_the_environment_are_opaque() {
        for name in ["software_interrupt", "syscall", "sc", "swi", "SVC", "hypercall"] {
            assert!(traps_to_environment(name), "{name}");
        }
        for name in ["setISAMode", "ClearExclusiveLocal", "disableIRQinterrupts", "sync", "mfc0"] {
            assert!(!traps_to_environment(name), "{name}");
        }
    }

    #[test]
    fn a_trailing_slot_most_callers_leave_unset_is_optional() {
        // GetMonData(mon, field[, data]): 1,159 call sites, 39% set the third.
        assert_eq!(optional_from(1159, &[1109, 1159, 453, 91]), Some(2));
        assert_eq!(optional_from(100, &[96, 100, 95, 9]), Some(3));
        assert_eq!(optional_from(100, &[100, 100, 100, 100]), None);
        // Too few call sites to vote, and the first slot is always kept.
        assert_eq!(optional_from(7, &[7, 7, 0, 0]), None);
        assert_eq!(optional_from(100, &[100, 1, 1, 1]), Some(1));
    }

    #[test]
    fn a_forwarded_return_type_is_dropped() {
        let mut prototype = proto(vec![undefined(4)]);
        prototype.return_type = named("uchar", "uint", 1);
        assert!(void_return(&mut prototype));
        assert_eq!(prototype.return_type.name.as_deref(), Some("void"));
        assert_eq!(
            prototype.parameter_source.as_deref(),
            Some("native-decompiler prototype recovery+native-prototype:forwarded-return")
        );
        assert!(!void_return(&mut prototype));
    }

    #[test]
    fn a_result_is_read_often_enough_when_a_tenth_of_the_callers_read_it() {
        assert!(read_often(1, 1));
        assert!(read_often(7, 2));
        assert!(read_often(10, 1));
        assert!(!read_often(83, 0));
        assert!(!read_often(1249, 1));
        assert!(!read_often(11, 1));
    }

    /// Three fields that are not a run of one width: evidence of a struct.
    fn record() -> Ty {
        let at = |offset, class| (offset, super::super::Field { offset, size: 4, class });
        Ty::Ptr(Box::new(Ty::Struct(BTreeMap::from([
            at(0, Class::Num(32)),
            at(4, Class::Int(32)),
            at(0x10, Class::Num(32)),
        ]))))
    }

    fn pointer_to(name: &str, metatype: &str) -> DecompType {
        DecompType {
            name: None,
            id: None,
            size: Some(4),
            metatype: Some("ptr".into()),
            element_count: None,
            target: Some(Box::new(named(name, metatype, 1))),
            prototype: None,
        }
    }

    #[test]
    fn a_struct_replaces_a_pointer_that_says_nothing_and_a_guess_but_not_a_declared_integer() {
        let slots = [record(), record(), record(), record()];
        // The decompiler's own recovery: `undefined4` and `void *` are open, `char *` is a claim.
        let mut recovered =
            proto(vec![undefined(4), pointer_to("void", "void"), pointer_to("char", "int"), named("int", "int", 4)]);
        let layouts = upgrade_structs(&mut recovered, 0x8000_1000, &slots, &[], &target(&SLOTS), false);
        let names: Vec<_> = layouts.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["fn_80001000_arg0", "fn_80001000_arg1", "fn_80001000_arg3"]);
        let pointee = |index: usize| recovered.parameters[index].data_type.target.as_ref().and_then(|t| t.name.clone());
        assert_eq!(pointee(0).as_deref(), Some("fn_80001000_arg0"));
        assert_eq!(pointee(2).as_deref(), Some("char"), "a typed pointer stays");
        assert!(recovered.parameter_source.as_deref().unwrap().contains(romwright_model::structs::PROTOTYPE_SOURCE));
        // A declaration's integer is its word; its `void *` is an erasure and is open.
        let mut declared = proto(vec![named("int", "int", 4), pointer_to("void", "void"), undefined(4)]);
        let layouts = upgrade_structs(&mut declared, 0x8000_1000, &slots, &[], &target(&SLOTS), true);
        let names: Vec<_> = layouts.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["fn_80001000_arg1"]);
        assert_eq!(declared.parameters[0].data_type.metatype.as_deref(), Some("int"));
        // Evidence that is not a struct changes nothing.
        let mut untouched = proto(vec![undefined(4)]);
        assert!(upgrade_structs(&mut untouched, 0x8000_1000, &[structural()], &[], &target(&SLOTS), false).is_empty());
        assert_eq!(untouched.parameter_source, None);
    }

    #[test]
    fn a_float_parameter_whose_register_the_body_touches_wide_is_not_persisted() {
        let overlap = BTreeMap::from([(0x1000, std::collections::BTreeSet::from([0usize, 1]))]);
        let types = ParameterTypes {
            target: target(&SLOTS),
            functions: BTreeMap::new(),
            variadic: BTreeMap::new(),
            opaque: Default::default(),
            result_read: Default::default(),
            float_overlap: overlap,
            pointees: Default::default(),
        };
        // `float param_1` pins register 0 of the float list.
        let floats = proto(vec![named("float", "float", 4), undefined(4)]);
        assert!(types.locks_overlapping_input(0x1000, &floats, None));
        // No float parameter: the integer slots are not in the overlap.
        assert!(!types.locks_overlapping_input(0x1000, &proto(vec![undefined(4)]), None));
        // The third float register is not touched wide.
        let three = proto(vec![undefined(4), named("float", "float", 4)]);
        assert!(types.locks_overlapping_input(0x1000, &three, None), "its first float is register 0");
        assert!(!types.locks_overlapping_input(0x2000, &floats, None), "another function");
        // Seen only in the decompiler's own recovery of another function.
        let recovered = std::collections::BTreeSet::from([0usize]);
        assert!(types.locks_overlapping_input(0x2000, &floats, Some(&recovered)));
        assert!(!types.locks_overlapping_input(0x2000, &proto(vec![undefined(4)]), Some(&recovered)));
    }
}
