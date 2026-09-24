//! Parameters passed in registers that no shipped prototype model claims.
//!
//! clang compiles `static int fn(int x)` for i386 into `lea 0x3(%ecx),%eax`:
//! the argument arrives in ECX under the compiler's internal convention.
//! `__cdecl` has no register parameter slot, so Ghidra's parameter
//! identification commits none -- but its dataflow still sees the input and
//! names the varnode `in_ECX` ("Irregular input", `Scope::buildDefaultName`,
//! database.cc:2470-2478 of the pinned tree).
//!
//! This pass commits exactly the registers that evidence names, and only
//! registers the compiler spec says a call destroys: a callee-saved register
//! read before it is written is something else -- on i386 PIC it is the GOT
//! pointer in EBX, not an argument. x86-32 gcc ships no model that passes
//! ECX first (`__regparm*` start at EAX, and its `__thiscall` passes `this`
//! on the stack), so a model name is claimed only when the evidence matches
//! one; otherwise the convention stays `unknown` rather than becoming a
//! false `__cdecl`. Ordering follows a model that covers every observed
//! register, else the register file's own offsets.
//!
//! Off unless `RuntimeConfig::register_params` is set: II.1 reserves
//! enabling an M4 pass.

use crate::session::RuntimeConfig;
use romwright_model::{DecompType, FuncParam, FuncProto, StorageSymbol};
use std::collections::{BTreeMap, BTreeSet};

/// The name this pass records in prototype provenance.
pub const SOURCE: &str = "native-prototype:register-input";

/// One prototype model: the registers it passes parameters in, in order, up
/// to its first non-register entry, and the registers it says a call
/// destroys.
#[derive(Debug, PartialEq, Eq)]
pub struct RegisterModel {
    pub name: String,
    pub registers: Vec<String>,
    pub killed: BTreeSet<String>,
    /// The registers this model passes floating-point parameters in: a
    /// separate sequence from the integer one, so parameter index `i` names
    /// a register only once the argument's class is known.
    pub float_registers: Vec<String>,
    /// The registers this model returns a value in, in the order the spec
    /// lists them: the first non-float entry is where an integer or pointer
    /// result arrives, which is what a return type is read from.
    pub returns: Vec<String>,
    /// Where a floating-point result arrives.
    pub float_returns: Vec<String>,
}

/// A parsed compiler spec: its models plus its register file.
pub struct Conventions {
    pub models: Vec<RegisterModel>,
    pub registers: BTreeMap<String, (u64, u64)>,
    /// The model `<default_proto>` names: the one a compiler uses for
    /// ordinary functions. Choosing by "most registers" instead picks
    /// `syscall`, whose first slot is a call number and not a parameter.
    pub default_model: Option<String>,
}

impl Conventions {
    pub fn parse(cspec: &str, table: &str) -> Self {
        let registers = registers(table);
        let default_model = elements(cspec, "default_proto")
            .into_iter()
            .next()
            .and_then(|element| {
                elements(element.body, "prototype")
                    .into_iter()
                    .next()
                    .and_then(|prototype| attribute(prototype.header, "name"))
            });
        Self { models: models(cspec, &registers), registers, default_model }
    }

    /// The model to read an ordinary function's parameters from.
    pub fn default(&self) -> Option<&RegisterModel> {
        self.default_model
            .as_deref()
            .and_then(|name| self.models.iter().find(|model| model.name == name))
            .or_else(|| self.models.iter().max_by_key(|model| model.registers.len()))
    }

    /// Registers any model says a call destroys. A parameter register must
    /// be one: the caller cannot expect it to survive.
    pub(crate) fn volatile(&self) -> BTreeSet<&str> {
        self.models
            .iter()
            .flat_map(|model| model.killed.iter().map(String::as_str))
            .collect()
    }

    /// The registers the decompiler reported as irregular inputs, in the
    /// order this pass will commit them. A captured storage offset must
    /// agree with the register file, so a name alone never decides which
    /// register was read.
    pub(crate) fn observed(&self, storage: &[StorageSymbol]) -> Vec<String> {
        let volatile = self.volatile();
        let mut names: Vec<String> = Vec::new();
        for symbol in storage {
            let Some(register) = symbol.name.strip_prefix("in_") else { continue };
            let Some(&(offset, _)) = self.registers.get(register) else { continue };
            if symbol.offset != 0 && symbol.offset != offset {
                continue;
            }
            if !volatile.contains(register) {
                continue;
            }
            if !names.iter().any(|seen| seen == register) {
                names.push(register.to_string());
            }
        }
        self.order(&mut names);
        names
    }

    /// Orders observed registers by a model that passes all of them, else by
    /// their offsets in the register file.
    fn order(&self, names: &mut Vec<String>) {
        let covering = self.models.iter().find(|model| {
            names.iter().all(|name| model.registers.contains(name))
        });
        match covering {
            Some(model) => names.sort_by_key(|name| {
                model.registers.iter().position(|register| register == name).unwrap_or(usize::MAX)
            }),
            None => names.sort_by_key(|name| self.registers.get(name).map_or(u64::MAX, |&(o, _)| o)),
        }
    }

    /// The model whose leading registers are exactly `observed`, if any.
    pub(crate) fn matching_model(&self, observed: &[String]) -> Option<&RegisterModel> {
        if observed.is_empty() {
            return None;
        }
        self.models.iter().find(|model| {
            model.registers.len() >= observed.len()
                && model.registers[..observed.len()] == observed[..]
        })
    }
}

/// Applies the pass to one recovered prototype. Returns true when it
/// supplied parameters, leaving the prototype untouched otherwise.
pub fn augment(
    cfg: &RuntimeConfig,
    language: &str,
    prototype: &mut FuncProto,
    storage: &[StorageSymbol],
) -> bool {
    if !cfg.register_params || !prototype.parameters.is_empty() || storage.is_empty() {
        return false;
    }
    let Ok((_, specs, _, _)) = crate::native_runtime::language_decompile_config(cfg, language)
    else {
        return false;
    };
    let (Ok(cspec), Ok(table)) = (
        std::fs::read_to_string(specs.join("cspec.xml")),
        std::fs::read_to_string(specs.join("registers.txt")),
    ) else {
        return false;
    };
    let conventions = Conventions::parse(&cspec, &table);
    let observed = conventions.observed(storage);
    if observed.is_empty() {
        return false;
    }
    prototype.parameters = observed
        .iter()
        .enumerate()
        .map(|(index, register)| FuncParam {
            ordinal: index as u32,
            name: format!("param_{}", index + 1),
            data_type: integer(conventions.registers.get(register).map_or(0, |&(_, size)| size)),
        })
        .collect();
    // Claim a model only when the evidence is exactly its leading registers.
    prototype.calling_convention = conventions
        .matching_model(&observed)
        .map_or_else(|| "unknown".to_string(), |model| model.name.clone());
    prototype.parameter_source = Some(format!("{SOURCE}({})", observed.join(",")));
    true
}

/// Whether a compiler spec declares a prototype model by that name. Ghidra
/// asks the same question through `CompilerSpec.getCallingConvention` and
/// skips the fact when the answer is nothing.
pub(crate) fn declares_model(cspec: &str, name: &str) -> bool {
    elements(cspec, "prototype")
        .into_iter()
        .any(|element| attribute(element.header, "name").as_deref() == Some(name))
}

/// Reads the models of one compiler spec. A dumped spec encodes parameter
/// storage as `<addr space="register" offset="..">`; an installed spec uses
/// `<register name="..">`. Both are accepted, resolved through the register
/// file.
pub fn models(cspec: &str, registers: &BTreeMap<String, (u64, u64)>) -> Vec<RegisterModel> {
    let by_offset: BTreeMap<u64, &str> = registers
        .iter()
        .filter(|(_, (_, size))| *size == 4 || *size == 8)
        .map(|(name, (offset, _))| (*offset, name.as_str()))
        .collect();
    let mut found = Vec::new();
    for element in elements(cspec, "prototype") {
        let Some(name) = attribute(element.header, "name") else { continue };
        let Some(input) = elements(element.body, "input").into_iter().next() else { continue };
        // Integer/pointer parameter slots in spec order. The old prefix
        // scan stopped at the first multi-register entry, which on x86-64
        // swept in the interleaved float entries first.
        let registers = integer_entries(input.body, &by_offset);
        if registers.is_empty() {
            continue;
        }
        let killed = elements(element.body, "killedbycall")
            .into_iter()
            .flat_map(|killed| register_names(killed.body, &by_offset))
            .collect();
        let float_registers = float_entries(input.body, &by_offset);
        let returns = elements(element.body, "output")
            .into_iter()
            .next()
            .map(|output| integer_entries(output.body, &by_offset))
            .unwrap_or_default();
        let float_returns = elements(element.body, "output")
            .into_iter()
            .next()
            .map(|output| float_entries(output.body, &by_offset))
            .unwrap_or_default();
        found.push(RegisterModel {
            name,
            registers,
            float_registers,
            killed,
            returns,
            float_returns,
        });
    }
    found
}

/// Register name to `(offset, size)` from a spec bundle's `registers.txt`.
pub fn registers(table: &str) -> BTreeMap<String, (u64, u64)> {
    table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let offset = fields.next()?.parse().ok()?;
            let size = fields.next()?.parse().ok()?;
            Some((name.to_string(), (offset, size)))
        })
        .collect()
}

/// A width-named integer for a register-sized parameter; the pass claims a
/// storage width, never a source-level type.
fn integer(size: u64) -> DecompType {
    let name = match size {
        1 => "char",
        2 => "short",
        8 => "longlong",
        _ => "int",
    };
    DecompType {
        name: Some(name.to_string()),
        id: None,
        size: Some(if size == 0 { 4 } else { size }),
        metatype: Some("int".to_string()),
        element_count: None,
        target: None,
        prototype: None,
    }
}

struct Element<'a> {
    header: &'a str,
    body: &'a str,
}

/// The direct occurrences of `<name ...>...</name>`; self-closing elements
/// yield an empty body.
fn elements<'a>(text: &'a str, name: &str) -> Vec<Element<'a>> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        rest = &rest[start..];
        let Some(header_end) = rest.find('>') else { break };
        let header = &rest[..header_end];
        let self_closing = header.ends_with('/');
        let after = &rest[header_end + 1..];
        let body_end = if self_closing { 0 } else { after.find(&close).unwrap_or(after.len()) };
        found.push(Element { header, body: &after[..body_end] });
        rest = &after[body_end..];
    }
    found
}

/// The float-classified single-register entries, in order.
fn float_entries(body: &str, by_offset: &BTreeMap<u64, &str>) -> Vec<String> {
    let mut registers = Vec::new();
    for entry in elements(body, "pentry") {
        // Specs spell the float marker two ways: `metatype="float"` (MIPS)
        // and `storage="float"` (aarch64).
        if attribute(entry.header, "metatype").as_deref() != Some("float")
            && attribute(entry.header, "storage").as_deref() != Some("float")
        {
            continue;
        }
        let names = register_names(entry.body, by_offset);
        if names.len() == 1 {
            registers.push(names.into_iter().next().expect("one name"));
        }
    }
    registers
}

/// Every single-register entry of an element that carries an integer or
/// pointer value, in order.
///
/// A parameter or return list interleaves float entries with integer ones
/// (`<pentry ... metatype="float">`), and they are different sequences: on
/// the x86-64 spec the first six integer entries are RDI..R9 while the
/// float entries are XMM0..XMM7. Mixing them makes parameter index `i`
/// name the wrong register, which is how this first read reported fourteen
/// parameters for a function of one.
fn integer_entries(body: &str, by_offset: &BTreeMap<u64, &str>) -> Vec<String> {
    let mut registers = Vec::new();
    for entry in elements(body, "pentry") {
        // A float or hidden-return pentry is not an integer parameter slot.
        // aarch64's `hiddenret` x8 is a return-slot register, never an
        // argument, and its `storage="float"` q0-q7 are not integers.
        let storage = attribute(entry.header, "storage");
        if attribute(entry.header, "metatype").as_deref() == Some("float")
            || matches!(storage.as_deref(), Some("float") | Some("hiddenret"))
        {
            continue;
        }
        let names = register_names(entry.body, by_offset);
        if names.len() == 1 {
            registers.push(names.into_iter().next().expect("one name"));
        }
    }
    registers
}

/// Register names inside one element. An installed spec names registers
/// (`<register name="ECX"/>`); a dumped spec gives storage, as `<addr>` for
/// parameter entries and `<varnode>` for register sets.
fn register_names(body: &str, by_offset: &BTreeMap<u64, &str>) -> Vec<String> {
    let mut names: Vec<String> = elements(body, "register")
        .into_iter()
        .filter_map(|register| attribute(register.header, "name"))
        .collect();
    for storage in ["addr", "varnode"]
        .into_iter()
        .flat_map(|element| elements(body, element))
    {
        if attribute(storage.header, "space").as_deref() != Some("register") {
            continue;
        }
        let Some(offset) = attribute(storage.header, "offset") else { continue };
        let parsed = offset
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .or_else(|| offset.parse().ok());
        if let Some(name) = parsed.and_then(|offset| by_offset.get(&offset)) {
            names.push((*name).to_string());
        }
    }
    names
}

fn attribute(header: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = header.find(&needle)? + needle.len();
    let end = header[start..].find('"')? + start;
    Some(header[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dumped encoding: register storage as offsets in register space.
    const DUMPED: &str = concat!(
        r#"<compiler_spec><prototype name="__cdecl" extrapop="4"><input killedbycall="false">"#,
        r#"<pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="0x4"/></pentry>"#,
        r#"</input><killedbycall><addr space="register" offset="0x4"/>"#,
        r#"<addr space="register" offset="0x8"/></killedbycall></prototype>"#,
        r#"<prototype name="__regparm3" extrapop="4"><input killedbycall="false">"#,
        r#"<pentry minsize="1" maxsize="4"><addr space="register" offset="0x0"/></pentry>"#,
        r#"<pentry minsize="1" maxsize="4"><addr space="register" offset="0x8"/></pentry>"#,
        r#"<pentry minsize="1" maxsize="4"><addr space="register" offset="0x4"/></pentry>"#,
        r#"<pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="0x4"/></pentry>"#,
        r#"</input><killedbycall><addr space="register" offset="0x4"/>"#,
        r#"<addr space="register" offset="0x8"/></killedbycall></prototype></compiler_spec>"#,
    );
    const TABLE: &str = "EAX\t0\t4\nECX\t4\t4\nEDX\t8\t4\nEBX\t12\t4\n";

    fn input(name: &str, offset: u64) -> StorageSymbol {
        StorageSymbol { name: name.into(), space: String::new(), offset, size: 0 }
    }

    #[test]
    fn dumped_specs_resolve_register_parameters_by_offset() {
        let conventions = Conventions::parse(DUMPED, TABLE);
        let regparm = conventions
            .models
            .iter()
            .find(|model| model.name == "__regparm3")
            .expect("regparm3");
        assert_eq!(regparm.registers, ["EAX", "EDX", "ECX"]);
        // A stack-only model contributes no parameter registers.
        assert!(conventions.models.iter().all(|model| model.name != "__cdecl"));
    }

    #[test]
    fn one_ecx_input_commits_one_parameter_without_claiming_a_model() {
        let conventions = Conventions::parse(DUMPED, TABLE);
        let observed = conventions.observed(&[input("in_ECX", 4)]);
        assert_eq!(observed, ["ECX"]);
        // __regparm3 passes ECX third; adopting it would claim two
        // parameters no evidence supports.
        assert!(conventions.matching_model(&observed).is_none());
    }

    #[test]
    fn dumped_killedbycall_uses_varnode_storage() {
        const DUMPED_VARNODE: &str = concat!(
            r#"<compiler_spec><prototype name="__regparm1"><input killedbycall="false">"#,
            r#"<pentry minsize="1" maxsize="4"><addr space="register" offset="0x0"/></pentry>"#,
            r#"</input><killedbycall><varnode space="register" offset="0x0" size="4"/>"#,
            r#"<varnode space="register" offset="0x4" size="4"/></killedbycall>"#,
            r#"</prototype></compiler_spec>"#,
        );
        let conventions = Conventions::parse(DUMPED_VARNODE, TABLE);
        assert_eq!(conventions.volatile(), ["EAX", "ECX"].into_iter().collect());
        // EAX is this model's first parameter register, and the spec says a
        // call destroys it, so an EAX input is a parameter here.
        assert_eq!(conventions.observed(&[input("in_EAX", 0)]), ["EAX"]);
    }

    #[test]
    fn callee_saved_inputs_are_not_parameters() {
        let conventions = Conventions::parse(DUMPED, TABLE);
        // i386 PIC reads the GOT pointer from EBX before writing it.
        assert!(conventions.observed(&[input("in_EBX", 12)]).is_empty());
    }

    #[test]
    fn storage_offset_must_agree_with_the_register_file() {
        let conventions = Conventions::parse(DUMPED, TABLE);
        assert!(conventions.observed(&[input("in_ECX", 8)]).is_empty());
    }

    #[test]
    fn covering_model_order_beats_register_offsets() {
        let conventions = Conventions::parse(DUMPED, TABLE);
        let observed = conventions.observed(&[input("in_EDX", 8), input("in_ECX", 4)]);
        // Offsets would order ECX before EDX; __regparm3 covers both and
        // passes EDX first.
        assert_eq!(observed, ["EDX", "ECX"]);
        assert!(conventions.matching_model(&observed).is_none());
    }

    /// IDO (the SGI/MIPS compiler behind N64 and PS1) implements the o32
    /// ABI: the first two floating-point arguments travel in dedicated FP
    /// registers (f12/f14, or the f12_13/f14_15 pairs on a 32-bit float
    /// unit) independently of the integer argument registers a0..a3. The
    /// shipped MIPS bundles must declare that split so a float parameter
    /// does not consume an a-register slot (P2.4).
    #[test]
    fn mips_bundles_carry_the_o32_float_argument_registers() {
        let specs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../native/specs");
        for bundle in ["MIPS-LE-32-default", "MIPS-BE-64-64-32addr"] {
            let dir = specs.join(bundle);
            let cspec = std::fs::read_to_string(dir.join("cspec.xml"))
                .unwrap_or_else(|e| panic!("{bundle} cspec.xml: {e}"));
            let table = std::fs::read_to_string(dir.join("registers.txt"))
                .unwrap_or_else(|e| panic!("{bundle} registers.txt: {e}"));
            let conventions = Conventions::parse(&cspec, &table);
            let model = conventions
                .default()
                .unwrap_or_else(|| panic!("{bundle} has no default prototype"));
            // Integer args in a0..a3.
            assert_eq!(
                model.registers,
                ["a0", "a1", "a2", "a3"],
                "{bundle} integer argument registers"
            );
            // FP args in the o32 float registers (f12/f14, or the
            // f12_13/f14_15 pairs on a 32-bit float unit), independent of
            // a0..a3. The first is always f12-derived.
            let floats = &model.float_registers;
            assert!(
                !floats.is_empty() && floats[0].starts_with("f12"),
                "{bundle} o32 float argument registers: {floats:?}"
            );
            assert!(
                floats.iter().all(|r| r.starts_with('f')),
                "{bundle} float args must not alias integer registers: {floats:?}"
            );
        }
    }
}
