//! One native registration recipe for standalone and pooled decompilation.
use crate::{ProgramProvider, Result};
use std::path::Path;

pub fn load_program_specs(
    provider: &mut ProgramProvider,
    root: &Path,
    db: &romwright_db::ProjectDb,
    program: romwright_model::ProgramId,
) -> Result<(String, String, String, String)> {
    let mut specs = crate::load_specs(root)?;
    provider.core_types = crate::parse_core_types(&specs.3);
    let mut contexts: Vec<_> = db
        .decode_contexts(program)?
        .into_iter()
        .filter(|(address, _, _)| address.space == romwright_model::AddressSpace::Ram)
        .map(|(address, name, value)| (address.offset, name, value))
        .collect();
    contexts.sort_by_key(|row| row.0);
    for (address, name, value) in &contexts {
        if romwright_core::native::STORED_BASE_REGISTERS.contains(&name.as_str()) {
            provider
                .tracked_values
                .insert((*address, name.clone()), *value);
        }
    }
    let language = db.program_language(program)?;
    let compiler = db.program_compiler(program).unwrap_or_default();
    // i386 PE programs: the Windows models (`__stdcall`, `__fastcall`,
    // `__thiscall`), which the gcc spec the bundle carries lacks.
    if is_windows_x86(&language, db, program) {
        specs.1 = WINDOWS_X86_CSPEC.to_string();
        provider.declared_models = crate::provider::prototype_models(&specs.1);
        provider.call_fixups = crate::provider::call_fixup_targets(&specs.1);
        // the stored models were filtered against the gcc spec's names when the provider was built
        provider.conventions = db
            .calling_conventions(program)?
            .into_iter()
            .filter(|row| row.function.space == romwright_model::AddressSpace::Ram)
            .filter(|row| provider.declared_models.contains(crate::wire::split_model_purge(&row.convention).0))
            .map(|row| (row.function.offset, row.convention))
            .collect();
    }
    specs.1 = with_entry_register_tracking(&specs.1, provider, &language, &contexts);
    // The register-save helpers are a CodeWarrior runtime: the compiler rules
    // decide whether this program has them (`compiler_rules/mwcc.json`).
    let has_sleds = romwright_core::compiler::rules::register_sleds(&romwright_core::compiler::rules::Ctx::new(
        &compiler, &language, "",
    ))
    .is_some();
    let helpers = if has_sleds { with_mwcc_callfixups(&specs.1, &language) } else { specs.1.clone() };
    if helpers != specs.1 {
        // The provider reads the fixup targets from the cspec on disk. These
        // fixups carry no `<target>`: Ghidra matches the function whose name is
        // the fixup's own (`CallFixupAnalyzer.getCallFixupNameForFunction`).
        for name in mwcc_helper_names() {
            provider.call_fixups.insert(name.clone(), name);
        }
        specs.1 = helpers;
    }
    specs.1 = with_psyq_soft_float(&specs.1, &language);
    specs.1 = with_o32_argument_rules(&specs.1, &language);
    specs.1 = with_gekko_argument_rules(&specs.1, &language);
    specs.1 = with_allegrex_argument_rules(&specs.1, &language);
    Ok(specs)
}

/// Ghidra 12.1.3's `x86win.cspec` (the `windows` compiler spec of `x86:LE:32:default`, Apache-2.0) with `__cdecl` as the
/// default model and `__stdcall`, `__fastcall`, `__thiscall` beside it, plus the MSVC runtime call fixups
/// (`_SEH_prolog`, `_EH_prolog`, `__alloca_probe`); the change is described in the file's header. `__stdcall` is the
/// model `native/pe/x86_conventions.rs` records for a function whose `ret N` proves it.
const WINDOWS_X86_CSPEC: &str = include_str!("../specs/x86win.cspec");

/// An i386 PE. The native importer records the language `x86:LE:32:default`
/// for every i386 image, ELF and PE alike, so the image's own `MZ` says Windows
/// (whatever compiler built it: Visual C++, MinGW, Borland all use these models).
fn is_windows_x86(language: &str, db: &romwright_db::ProjectDb, program: romwright_model::ProgramId) -> bool {
    use std::io::Read;
    // `ROMWRIGHT_PE_WINDOWS_SPEC=off` keeps the gcc spec (the arm the lane measures the Windows models against)
    if language != "x86:LE:32:default" || std::env::var("ROMWRIGHT_PE_WINDOWS_SPEC").is_ok_and(|v| v == "off") {
        return false;
    }
    let Ok(input) = db.program_input(program) else { return false };
    let mut magic = [0u8; 2];
    std::fs::File::open(&input.source_path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok_and(|()| &magic == b"MZ")
}

/// psyq's o32 on the R3000A, which has no FPU: a `float` or `double` is an
/// integer-register value (a0..a3, then the stack from `sp+16`; a result is in
/// `v0`/`v1:v0`), and no FP register is callee-saved. The PSX spec is
/// MIPS32's with GTE added, so it still lists `f12_13`, `f14_15` and `f0_1` as
/// float slots: a declared `float` parameter (a library prototype) was
/// assigned to `f12`, a register the machine does not have. The float
/// entries and the callee-saved `f20..f30` are removed; every other entry
/// stays.
fn with_psyq_soft_float(cspec: &str, language: &str) -> String {
    if !language.starts_with("PSX") {
        return cspec.to_owned();
    }
    // The float slots, then the rules that route a float to them (they name
    // the float storage class, which no longer exists).
    let out = without_elements(cspec, "pentry", |element| {
        element[..element.find('>').unwrap_or(element.len())].contains("metatype=\"float\"")
    });
    let out = without_elements(&out, "rule", |element| {
        element.contains("datatype name=\"float\"") || element.contains("storage=\"float\"")
    });
    // callee-saved and killed FP registers: `<register name="f0"/>` .. `f30`
    let mut lines: Vec<&str> = out.lines().collect();
    lines.retain(|line| {
        let line = line.trim();
        !(line.starts_with("<register name=\"f") && line.ends_with("\"/>")
            && line["<register name=\"f".len()..line.len() - 3].parse::<u32>().is_ok())
    });
    let mut text = lines.join("\n");
    if cspec.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// `text` without every `<tag ...>...</tag>` element `remove` accepts (given
/// the element's whole text), with its indentation and the line break after it.
fn without_elements(text: &str, tag: &str, remove: impl Fn(&str) -> bool) -> String {
    let open = format!("<{tag}");
    let close_tag = format!("</{tag}>");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        // `<rule` must not match `<rules`, `<pentry` not `<pentryx`
        let after = rest[start + open.len()..].chars().next();
        let Some(close) = rest[start..].find(&close_tag).map(|end| start + end + close_tag.len()) else { break };
        if !matches!(after, Some(' ' | '>' | '\n' | '\t')) || !remove(&rest[start..close]) {
            out.push_str(&rest[..close]);
            rest = &rest[close..];
            continue;
        }
        out.push_str(rest[..start].trim_end_matches([' ', '\t']));
        rest = rest[close..].strip_prefix('\n').unwrap_or(&rest[close..]);
    }
    out.push_str(rest);
    out
}

/// The pinned MIPS64 `o64` compiler spec (what `MIPS:BE:64:64-32addr` carries)
/// has no notion of the o32 calling convention IDO emits for N64 games:
/// floating-point arguments are listed as registers independent of the
/// integer ones (so a leading float leaves `a0` looking like a hole the
/// decompiler then prints as a phantom parameter), and the first stack
/// argument is placed at `sp+32` instead of `sp+16`.
///
/// o32 (MIPS ABI handbook, "Calling Convention Implementation"): arguments
/// take consecutive word slots; the first two slots are `a0`/`a1`, or, for
/// a *leading* run of floating-point arguments, `f12`/`f14` while still
/// reserving the integer register of that slot (the hole); a float that
/// follows any integer argument travels in integer registers like everything
/// else; slots 2 and 3 are `a2`/`a3`; the rest are on the stack from `sp+16`.
/// Expressed with Ghidra's own constructs: `<group>` ties `f12`+`a0` and
/// `f14`+`a1` to one slot each, and the rules send a float to the FP file
/// only at position 0, or at position 1 behind a float, as the stock MIPS32
/// spec does for the same convention.
fn with_o32_argument_rules(cspec: &str, language: &str) -> String {
    if language != "MIPS:BE:64:64-32addr" {
        return cspec.to_owned();
    }
    let Some(start) = cspec.find("<input") else { return cspec.to_owned() };
    let Some(close) = cspec[start..].find("</input>").map(|end| start + end + "</input>".len()) else {
        return cspec.to_owned();
    };
    // A spec that already declares slot groups owns its argument layout.
    if cspec[start..close].contains("<group>") {
        return cspec.to_owned();
    }
    const INPUT: &str = r#"<input killedbycall="true">
        <group>
          <pentry minsize="1" maxsize="8" metatype="float"><register name="f12"/></pentry>
          <pentry minsize="1" maxsize="8" extension="sign"><register name="a0"/></pentry>
        </group>
        <group>
          <pentry minsize="1" maxsize="8" metatype="float"><register name="f14"/></pentry>
          <pentry minsize="1" maxsize="8" extension="sign"><register name="a1"/></pentry>
        </group>
        <pentry minsize="1" maxsize="8" extension="sign"><register name="a2"/></pentry>
        <pentry minsize="1" maxsize="8" extension="sign"><register name="a3"/></pentry>
        <pentry minsize="1" maxsize="500" align="4"><addr offset="16" space="stack"/></pentry>
        <rule><datatype name="float"/><varargs first="0"/><consume storage="general"/></rule>
        <rule><datatype name="float"/><position index="0"/><consume storage="float"/></rule>
        <rule><datatype name="float"/><position index="1"/>
          <datatype_at index="0"><datatype name="float"/></datatype_at>
          <consume storage="float"/></rule>
        <rule><datatype name="float"/><consume storage="general"/></rule>
      </input>"#;
    let mut out = String::with_capacity(cspec.len() + INPUT.len());
    out.push_str(&cspec[..start]);
    out.push_str(INPUT);
    out.push_str(&cspec[close..]);
    // The 16 bytes above the first stack argument are the callee's home area
    // for `a0`..`a3`; code spills there, so they are locals (the stock MIPS32
    // spec says the same).
    const LOCALS: &str = "<localrange>\n\
        <range space=\"stack\" first=\"0xfff0bdc0\" last=\"0xffffffff\"/>\n\
        <range space=\"stack\" first=\"0\" last=\"15\"/>\n\
        </localrange>\n      ";
    if !out.contains("<localrange>") {
        if let Some(end) = out.find("</prototype>") {
            out.insert_str(end, LOCALS);
        }
    }
    out
}

/// The pinned Gekko extension predates rule-based EABI argument allocation.
/// Preserve its register table while applying the standard PPC32 assignment
/// rules: independent FPRs, indirect aggregates, and aligned GPR pairs.
fn with_gekko_argument_rules(cspec: &str, language: &str) -> String {
    if language != "PowerPC:BE:32:Gekko_Broadway" {
        return cspec.to_owned();
    }
    let Some(default) = cspec.find("<default_proto>") else { return cspec.to_owned() };
    let Some(end) = cspec[default..].find("</default_proto>").map(|end| default + end) else {
        return cspec.to_owned();
    };
    let Some(input) = cspec[default..end].find("<input").map(|start| default + start) else {
        return cspec.to_owned();
    };
    let Some(close) = cspec[input..end].find("</input>").map(|end| input + end) else {
        return cspec.to_owned();
    };
    // An updated or custom spec already defining assignment rules owns them.
    if cspec[input..close].contains("<rule") {
        return cspec.to_owned();
    }
    const RULES: &str = "<rule><datatype name=\"float\"/><consume storage=\"float\"/></rule>\n\
        <rule><datatype name=\"float\"/><goto_stack/></rule>\n\
        <rule><datatype name=\"struct\"/><convert_to_ptr/></rule>\n\
        <rule><datatype name=\"union\"/><convert_to_ptr/></rule>\n\
        <rule><datatype name=\"any\"/><join align=\"true\"/></rule>\n";
    let mut result = String::with_capacity(cspec.len() + RULES.len());
    result.push_str(&cspec[..close]);
    result.push_str(RULES);
    result.push_str(&cspec[close..]);
    result
}

/// The PSP's EABI32 (psp-gcc, `-mabi=eabi`, single-precision FPU only): the
/// Allegrex bundle keeps the extension's register table (`f12`..`f19` for
/// `float`, `a0`..`a3` then `t0`..`t3` for everything else) but no assignment
/// rules, so a declared `double` or `long long` found no register slot and went
/// to the stack. The PSP has no double-precision hardware: a `double` is two
/// integer words, and an 8-byte value takes an aligned pair, low word first
/// (`a0:a1`, `a2:a3`, `t0:t1`, `t2:t3`), skipping an odd register. Read off
/// Puzzle Bobble Pocket's own libgcc/libm (GCC 3.3.3 allegrex): `__adddf3`
/// spills `a0:a1` and `a2:a3` as its two doubles and returns `v0:v1`;
/// `__make_dp(int, uint, int, uint64)` reads `a0`, `a1`, `a2` and `t0:t1`, never
/// `a3`; `scalbnf`/`__kernel_sinf` take their floats in `f12`, `f13`.
fn with_allegrex_argument_rules(cspec: &str, language: &str) -> String {
    if language != "Allegrex:LE:32:default" {
        return cspec.to_owned();
    }
    let Some(default) = cspec.find("<default_proto>") else { return cspec.to_owned() };
    let Some(end) = cspec[default..].find("</default_proto>").map(|end| default + end) else {
        return cspec.to_owned();
    };
    let Some(input) = cspec[default..end].find("<input").map(|start| default + start) else {
        return cspec.to_owned();
    };
    let Some(close) = cspec[input..end].find("</input>").map(|end| input + end) else {
        return cspec.to_owned();
    };
    // A spec that already defines assignment rules owns them.
    if cspec[input..close].contains("<rule") {
        return cspec.to_owned();
    }
    const RULES: &str = "<rule><datatype name=\"float\" minsize=\"5\"/><join align=\"true\"/></rule>\n\
        <rule><datatype name=\"float\"/><consume storage=\"float\"/></rule>\n\
        <rule><datatype name=\"float\"/><goto_stack/></rule>\n\
        <rule><datatype name=\"struct\" minsize=\"5\"/><convert_to_ptr/></rule>\n\
        <rule><datatype name=\"union\" minsize=\"5\"/><convert_to_ptr/></rule>\n\
        <rule><datatype name=\"any\"/><join align=\"true\"/></rule>\n";
    let mut result = String::with_capacity(cspec.len() + RULES.len());
    result.push_str(&cspec[..close]);
    result.push_str(RULES);
    result.push_str(&cspec[close..]);
    result
}

/// The compiler spec, plus the tracked register a processor's ABI defines on
/// entry to every function the store holds. Unchanged for every language that
/// defines no such register.
///
/// Every entry, not just the one being asked for: the spec is pushed once per
/// launch and a batch answers many functions from that launch, so a spec
/// carrying one function's tracked set seeds the batch's first address and
/// silently leaves the rest unseeded. Ghidra seeds each function the same way
/// -- its MIPS analyzer writes the value at every function entry it evaluates
/// (`MipsAddressAnalyzer`, `assumeT9EntryAddress`).
fn with_entry_register_tracking(
    cspec: &str,
    provider: &ProgramProvider,
    lang_dir: &str,
    contexts: &[(u64, String, u64)],
) -> String {
    let Some(close) = cspec.rfind("</compiler_spec>") else {
        return cspec.to_string();
    };
    let mut data = String::new();
    // The instruction set discovery settled at each point, replayed as the
    // `<context_set>` ranges `ContextDatabase::decodeFromSpec` takes: a value
    // holds from its address up to the next recorded point. This is the
    // program context Ghidra's client carries for it; without it a Thumb
    // function decoded as ARM and the decompiler reported bad instruction
    // data (182 of 512 sampled DS functions).
    let image_end = provider.backing.image_end();
    // The stored base-register values are not context fields: raw-SLEIGH
    // resolves each `<context_set>` name against the `.sla`'s declared
    // context variables, and a register (`r13`, `r2`, `gp`) is rejected
    // there -- registers ride `<tracked_set>` and `getTrackedRegisters`
    // instead (below, and `tracked_values`). Match exactly the names the
    // importer seeds, not "is in registers.txt": ARM `TMode` mode rows share
    // a name with an ARM register and must still decode. Folding ranges
    // over the filtered rows keeps a skipped point from punching a
    // one-address hole in its neighbour.
    let fields: Vec<&(u64, String, u64)> = contexts
        .iter()
        .filter(|(_, name, _)| !romwright_core::native::STORED_BASE_REGISTERS.contains(&name.as_str()))
        .collect();
    for (index, (address, name, value)) in fields.iter().enumerate() {
        let last = fields
            .get(index + 1)
            .map(|(next, _, _)| next.saturating_sub(1))
            .unwrap_or(image_end.saturating_sub(1))
            .max(*address);
        data.push_str(&format!(
            "<context_set space=\"ram\" first=\"0x{address:x}\" last=\"0x{last:x}\">\n\
             <set name=\"{name}\" val=\"{value}\"/>\n\
             </context_set>\n"
        ));
    }
    // The R5900 (PS2 Emotion Engine) is a MIPS core with its own language
    // directory; it shares the `t9`/`gp` conventions. The PSX language (R3000A)
    // is the third MIPS directory: `gp` only.
    if lang_dir.contains("MIPS") || lang_dir.contains("r5900") || lang_dir.starts_with("PSX") {
        // `t9` = the entry address by convention; `gp` = the stored global
        // pointer of non-PIC images. One element per entry holding both:
        // decoding a second element over the same range clears the first
        // (see the PowerPC block below).
        // psyq (the PSX language) is not position-independent: no `t9`.
        let t9 = provider
            .registers
            .get("t9")
            .copied()
            .filter(|&(_, size)| size != 0 && size <= 8 && !lang_dir.starts_with("PSX"));
        let gp_storage = provider.registers.get("gp").copied().filter(|&(_, size)| size != 0 && size <= 8);
        let gp_values: std::collections::HashMap<u64, u64> = contexts
            .iter()
            .filter(|(_, name, _)| name == "gp")
            .map(|(address, _, value)| (*address, *value))
            .collect();
        let mut entries: Vec<u64> = provider.functions.clone();
        entries.sort_unstable();
        entries.dedup();
        for entry in entries {
            let mut sets = String::new();
            if let Some((register_offset, register_size)) = t9 {
                sets.push_str(&format!(
                    "<set space=\"register\" offset=\"0x{register_offset:x}\" size=\"{register_size}\" val=\"0x{entry:x}\"/>\n"
                ));
            }
            if let (Some((register_offset, register_size)), Some(value)) = (gp_storage, gp_values.get(&entry)) {
                sets.push_str(&format!(
                    "<set space=\"register\" offset=\"0x{register_offset:x}\" size=\"{register_size}\" val=\"0x{value:x}\"/>\n"
                ));
            }
            if !sets.is_empty() {
                data.push_str(&format!(
                    "<tracked_set space=\"ram\" first=\"0x{entry:x}\" last=\"0x{entry:x}\">\n{sets}</tracked_set>\n"
                ));
            }
        }
    }
    // PowerPC EABI small-data-area bases over each function body the
    // store holds: `r13` addresses `.sdata`, `r2` (32-bit EABI) `.sdata2`.
    // Values come from the stored decode contexts (ABS symbols when
    // declared, section convention otherwise), not from the entry address
    // the way MIPS `t9` does. Ranges, not points: the decompiler paints a
    // tracked set over exactly the range it names (`decodeTracked`), so a
    // point seeds only its own byte -- the whole body must be covered, the
    // way Ghidra paints execute blocks (`setRegisterContext`). Without them
    // an `lwz` through `r13` decompiles as `in_r13 + offset` instead of the
    // object it addresses.
    if lang_dir.contains("PowerPC") {
        let mut bases: std::collections::HashMap<(u64, &str), u64> =
            std::collections::HashMap::new();
        for (address, name, value) in contexts {
            if name == "r13" || name == "r2" {
                bases.insert((*address, name.as_str()), *value);
            }
        }
        // One element per range holding every register set there: decoding
        // a second element over a range clears the first
        // (`ContextInternal::createSet`: `clearRange` plus `clear`), so a
        // per-register loop leaves only the last register standing.
        let mut points: Vec<u64> = bases.keys().map(|(address, _)| *address).collect();
        points.sort_unstable();
        points.dedup();
        for entry in points {
            let mut sets = String::new();
            for register in ["r13", "r2"] {
                let (Some(&value), Some(&(register_offset, register_size))) = (
                    bases.get(&(entry, register)),
                    provider.registers.get(register),
                ) else {
                    continue;
                };
                if register_size == 0 || register_size > 8 {
                    continue;
                }
                sets.push_str(&format!(
                    "<set space=\"register\" offset=\"0x{register_offset:x}\" size=\"{register_size}\" val=\"0x{value:x}\"/>\n"
                ));
            }
            if sets.is_empty() {
                continue;
            }
            let size = provider
                .function_sizes
                .get(&entry)
                .copied()
                .unwrap_or(1)
                .max(1);
            let last = entry
                .saturating_add(size)
                .saturating_sub(1)
                .min(image_end.saturating_sub(1))
                .max(entry);
            data.push_str(&format!(
                "<tracked_set space=\"ram\" first=\"0x{entry:x}\" last=\"0x{last:x}\">\n{sets}</tracked_set>\n"
            ));
        }
    }
    if data.is_empty() {
        return cspec.to_string();
    }
    let mut out = String::with_capacity(cspec.len() + data.len() + 32);
    out.push_str(&cspec[..close]);
    out.push_str("<context_data>\n");
    out.push_str(&data);
    out.push_str("</context_data>\n");
    out.push_str(&cspec[close..]);
    out
}

/// MWCC register-save helpers (P2.3). A prologue sets `r11` to the caller's
/// stack pointer (`addi r11,r1,frame`) and calls into a sled that stores the
/// callee-saved registers from `rN` up through `r31` (or `fN`..`f31`) at
/// negative offsets from `r11`: `_savegpr_N` stores `rN` at
/// `r11 - 4*(32-N)` (`stw`), `_savefpr_N` stores `fN` at `r11 - 8*(32-N)`
/// (`stfd`); `_restgpr_N`/`_restfpr_N` load them back (`lwz`/`lfd`) after the
/// epilogue recomputes `r11`. Bytes: Animal Crossing `main.dol`
/// 0x8009ae00..0x8009af2c, `romwright-core` `native/mwcc_runtime.rs`.
///
/// Expanded as these stores and loads, a `bl _savegpr_26` is neither an
/// opaque call (which makes the decompiler assume `r3`..`r12` changed, so the
/// first `mr r31,r3` reads the call's result and the parameter disappears) nor
/// an unknown writer of the stack. The restore reads the slot the save
/// wrote -- both are `sp+frame-0x18` once `r11` is propagated -- so the
/// callee-saved registers come back unchanged and no `unaff_r26` is left.
fn mwcc_callfixups() -> String {
    let sleds = mwcc_sleds();
    let mut out = String::new();
    for family in &sleds.families {
        let (reg, size) = (family.class, family.slot);
        for first in sleds.first..=sleds.last {
            let mut body = String::new();
            for number in first..=sleds.last {
                let offset = size * (32 - number);
                if family.store {
                    body.push_str(&format!("      *:{size} (r11 - 0x{offset:02x}) = {reg}{number};\n"));
                } else {
                    body.push_str(&format!("      {reg}{number} = *:{size} (r11 - 0x{offset:02x});\n"));
                }
            }
            out.push_str(&format!(
                "  <callfixup name=\"{}{first}\">\n    <pcode><body><![CDATA[\n{body}    ]]></body></pcode>\n  </callfixup>\n",
                family.prefix
            ));
        }
    }
    out
}

/// The helper layout the `mwcc-register-sleds` rule defines.
fn mwcc_sleds() -> &'static romwright_core::compiler::rules::SledSet {
    romwright_core::compiler::rules::sled_definition(romwright_core::compiler::rules::MWCC_SLEDS)
        .expect("compiler_rules/mwcc.json defines the register sleds")
}

/// The names `mwcc_callfixups` defines a fixup for.
fn mwcc_helper_names() -> Vec<String> {
    mwcc_sleds().names()
}

/// True for the name of a helper `mwcc_callfixups` defines.
fn is_mwcc_helper(name: &str) -> bool {
    mwcc_sleds().is_helper(name)
}

/// `cspec` without any `<callfixup>` for one of the helpers (self-closing or
/// not).
fn without_mwcc_callfixups(cspec: &str) -> String {
    let mut out = String::with_capacity(cspec.len());
    let mut rest = cspec;
    while let Some(start) = rest.find("<callfixup name=\"") {
        let name_at = start + "<callfixup name=\"".len();
        let name = rest[name_at..].split('"').next().unwrap_or("");
        let Some(open_end) = rest[start..].find('>').map(|end| start + end) else { break };
        let end = if rest[..open_end].ends_with('/') {
            open_end + 1
        } else {
            match rest[open_end..].find("</callfixup>") {
                Some(close) => open_end + close + "</callfixup>".len(),
                None => break,
            }
        };
        if is_mwcc_helper(name) {
            // Drop the element with its indentation and the line break after it.
            out.push_str(rest[..start].trim_end_matches([' ', '\t']));
            rest = rest[end..].strip_prefix('\n').unwrap_or(&rest[end..]);
        } else {
            out.push_str(&rest[..end]);
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out
}

/// Puts the MWCC helpers' call fixups in a 32-bit PowerPC cspec, before
/// `</compiler_spec>`. The pinned Gekko/Broadway spec ships `_savegpr_N` and
/// `_restgpr_N` too, but addressing them from `r1` (the helper writes below
/// the *caller's* sp, in `r11`), so a shipped fixup is replaced, not kept:
/// re-adding a name is a duplicate the decompiler rejects, and a kept
/// `r1`-relative one stores below the new frame and reloads what nothing
/// wrote.
fn with_mwcc_callfixups(cspec: &str, lang_dir: &str) -> String {
    if !lang_dir.replace('-', ":").starts_with("PowerPC:BE:32") {
        return cspec.to_string();
    }
    let stripped = without_mwcc_callfixups(cspec);
    let Some(close) = stripped.rfind("</compiler_spec>") else {
        return cspec.to_string();
    };
    let extra = mwcc_callfixups();
    let mut out = String::with_capacity(stripped.len() + extra.len() + 16);
    out.push_str(&stripped[..close]);
    out.push_str(&extra);
    out.push_str(&stripped[close..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{mwcc_callfixups, with_mwcc_callfixups, with_o32_argument_rules, with_psyq_soft_float};

    /// MWCC register-save helpers expand to the per-register effects the
    /// sled performs, for all four helper families (P2.3).
    #[test]
    fn mwcc_callfixups_cover_every_helper() {
        let fixups = mwcc_callfixups();
        for family in ["_savegpr_", "_restgpr_", "_savefpr_", "_restfpr_"] {
            for n in 14..32 {
                assert!(fixups.contains(&format!("name=\"{family}{n}\"")), "missing {family}{n}");
            }
            assert_eq!(fixups.matches(&format!("name=\"{family}")).count(), 18, "{family}");
        }
        // `_savegpr_14` stores r14..r31 at r11-4*(32-r), the caller's sp.
        assert!(fixups.contains("*:4 (r11 - 0x48) = r14;"));
        assert!(fixups.contains("*:4 (r11 - 0x04) = r31;"));
        // `_restgpr_14` loads them back from the same slots.
        assert!(fixups.contains("r14 = *:4 (r11 - 0x48);"));
        assert!(fixups.contains("r31 = *:4 (r11 - 0x04);"));
        // The FP sleds move 8-byte doubles at r11-8*(32-f).
        assert!(fixups.contains("*:8 (r11 - 0x90) = f14;"));
        assert!(fixups.contains("*:8 (r11 - 0x08) = f31;"));
        assert!(fixups.contains("f14 = *:8 (r11 - 0x90);"));
        // Nothing is addressed from the new frame's r1.
        assert!(!fixups.contains("(r1 "));
        // `_savegpr_26` keeps exactly r26..r31.
        let start = fixups.find("name=\"_savegpr_26\"").unwrap();
        let end = start + fixups[start..].find("</callfixup>").unwrap();
        assert_eq!(fixups[start..end].matches(" = r").count(), 6);
        assert!(!fixups[start..end].contains("= r25;"));
    }

    #[test]
    fn mwcc_callfixups_inject_only_for_32_bit_powerpc_and_replace_present() {
        let ppc = "PowerPC-BE-32-Gekko_Broadway";
        let bare = "<compiler_spec>\n</compiler_spec>";

        // 32-bit PowerPC gets the helpers (directory or language-id spelling);
        // MIPS and 64-bit PowerPC are untouched.
        let injected = with_mwcc_callfixups(bare, ppc);
        assert!(injected.contains("name=\"_savegpr_14\""));
        assert!(injected.contains("name=\"_restfpr_31\""));
        assert!(with_mwcc_callfixups(bare, "PowerPC:BE:32:Gekko_Broadway").contains("name=\"_savefpr_20\""));
        assert_eq!(with_mwcc_callfixups(bare, "MIPS-BE-64-64-32addr"), bare);
        assert_eq!(with_mwcc_callfixups(bare, "PowerPC-BE-64-Xenon-32addr"), bare);

        // A shipped helper (the pinned Gekko spec's, addressed from r1) is
        // replaced by ours, once, in both its element forms; other fixups
        // survive.
        let shipped = "<compiler_spec>\n  <callfixup name=\"_savegpr_14\"/>\n  \
            <callfixup name=\"_restgpr_15\">\n    <pcode><body><![CDATA[\n r15 = *(r1 - 0x44);\n ]]></body></pcode>\n  </callfixup>\n  \
            <callfixup name=\"get_pc_thunk_lr\"><pcode><body><![CDATA[LR = inst_dest + 4;]]></body></pcode></callfixup>\n</compiler_spec>";
        let merged = with_mwcc_callfixups(shipped, ppc);
        assert_eq!(merged.matches("name=\"_savegpr_14\"").count(), 1);
        assert_eq!(merged.matches("name=\"_restgpr_15\"").count(), 1);
        assert!(!merged.contains("(r1 - 0x44)"), "the r1-relative body must be gone");
        assert!(merged.contains("r15 = *:4 (r11 - 0x44);"));
        assert_eq!(merged.matches("name=\"get_pc_thunk_lr\"").count(), 1);
        assert!(merged.ends_with("</compiler_spec>"));
        // Idempotent: applying it twice leaves one of each.
        let twice = with_mwcc_callfixups(&merged, ppc);
        assert_eq!(twice, merged);
    }

    /// The N64 spec is rebuilt around o32's slot rule: `f12`/`a0` and
    /// `f14`/`a1` share a slot, floats only lead into the FP file, stack
    /// arguments start at `sp+16` (P2.4).
    #[test]
    fn o32_rules_replace_the_o64_input_block_for_n64_only() {
        let o64 = "<compiler_spec>\n<default_proto>\n<prototype name=\"__stdcall\">\n\
            <input killedbycall=\"true\">\n<pentry minsize=\"1\" maxsize=\"8\" metatype=\"float\"><register name=\"f12\"/></pentry>\n\
            <pentry minsize=\"1\" maxsize=\"500\" align=\"8\"><addr offset=\"32\" space=\"stack\"/></pentry>\n</input>\n\
            <output><pentry minsize=\"1\" maxsize=\"8\"><register name=\"v0\"/></pentry></output>\n\
            <unaffected><register name=\"sp\"/></unaffected>\n</prototype>\n</default_proto>\n</compiler_spec>";
        let n64 = with_o32_argument_rules(o64, "MIPS:BE:64:64-32addr");
        assert_ne!(n64, o64);
        // Slot groups: f12 with a0, f14 with a1.
        assert!(n64.contains("<group>\n          <pentry minsize=\"1\" maxsize=\"8\" metatype=\"float\"><register name=\"f12\"/></pentry>\n          <pentry minsize=\"1\" maxsize=\"8\" extension=\"sign\"><register name=\"a0\"/></pentry>"));
        assert!(n64.contains("<register name=\"f14\"/>") && n64.contains("<register name=\"a1\"/>"));
        // No o64 leftovers: stack arguments from sp+16, 4-byte slots.
        assert!(n64.contains("<addr offset=\"16\" space=\"stack\"/>"));
        assert!(!n64.contains("offset=\"32\""));
        assert!(!n64.contains("align=\"8\""));
        // A float is in the FP file only at position 0, or at position 1
        // behind a float; otherwise it takes an integer slot.
        assert!(n64.contains("<position index=\"0\"/><consume storage=\"float\"/>"));
        assert!(n64.contains("<position index=\"1\"/>"));
        assert!(n64.contains("<datatype_at index=\"0\"><datatype name=\"float\"/></datatype_at>"));
        assert!(n64.contains("<rule><datatype name=\"float\"/><consume storage=\"general\"/></rule>"));
        // The home area of a0..a3 is locals; the rest of the spec is intact.
        assert!(n64.contains("<localrange>") && n64.contains("last=\"15\""));
        assert!(n64.contains("<output><pentry minsize=\"1\" maxsize=\"8\"><register name=\"v0\"/></pentry></output>"));
        assert!(n64.contains("<unaffected><register name=\"sp\"/></unaffected>"));
        // Applying it again changes nothing (the spec already has groups).
        assert_eq!(with_o32_argument_rules(&n64, "MIPS:BE:64:64-32addr"), n64);
        // Only the N64 language: MIPS32, PS2 and little-endian MIPS64 keep theirs.
        for other in ["MIPS:BE:32:default", "MIPS:LE:64:64-32addr", "r5900:LE:32:default"] {
            assert_eq!(with_o32_argument_rules(o64, other), o64, "{other}");
        }
    }

    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn gekko_arguments_preserve_aligned_pairs_and_stack_spills() {
        use crate::{BinaryBacking, NativeWorker, ProgramProvider};
        use romwright_model::{Address, FactKind, FactProvenance, PrototypeRow};
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut cfg = romwright_core::session::RuntimeConfig::from_env();
        cfg.spec_root = repo.join(&cfg.spec_root);
        cfg.decompiler_path = repo.join(&cfg.decompiler_path);
        let (sla, specs_path, language_dir, language) =
            romwright_core::native_runtime::language_decompile_config(&cfg, "PowerPC:BE:32:Gekko_Broadway").unwrap();
        let path = std::env::temp_dir().join(format!("romwright-gekko-args-{}-{}",
            std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        // Authored instruction fixtures. MWCC uses r3:r4 initially, skips r4
        // after a pointer, and spills an aligned pair when only r10 remains.
        for (signature, words, registers) in [
            ("ulonglong probe(ulonglong value)", vec![0x4e800020u32], Some([12, 16])),
            ("ulonglong probe(void *before, ulonglong value, void *after)",
                vec![0x7ca32b78, 0x7cc43378, 0x4e800020], Some([20, 24])),
            ("ulonglong probe(uint a, uint b, uint c, uint d, uint e, uint f, uint g, ulonglong value, uint after)",
                vec![0x80610008, 0x8081000c, 0x4e800020], None),
        ] {
            let size = words.len() as u64 * 4;
            std::fs::write(&path, words.into_iter().flat_map(u32::to_be_bytes).collect::<Vec<_>>()).unwrap();
            let mut provider = ProgramProvider::new(
                BinaryBacking::from_file(&path, None, 0x1000).unwrap(), vec![0x1000]);
            provider.load_language_info(&specs_path).unwrap();
            provider.function_names.insert(0x1000, "probe".into());
            provider.function_sizes.insert(0x1000, size);
            provider.prototypes.insert(0x1000, PrototypeRow {
                function: Address::ram(0x1000), signature: signature.into(),
                calling_convention: None, return_type: Some("ulonglong".into()),
                provenance: FactProvenance { kind: FactKind::Asserted, source: "public ABI fixture".into(), confidence: None },
            });
            let mut command = std::process::Command::new(&cfg.decompiler_path);
            command.env("ROMWRIGHT_SLA", &sla).env("ROMWRIGHT_LANGUAGE_DIR", &language_dir)
                .env("ROMWRIGHT_LANGUAGE", &language);
            let mut worker = NativeWorker::launch(command).unwrap();
            let mut specs = crate::load_specs(&specs_path).unwrap();
            specs.1 = super::with_gekko_argument_rules(
                &super::with_gekko_argument_rules(&specs.1, &language), &language);
            let shell = provider.function_shell().unwrap();
            worker.register_program_with_shell(&mut provider, &specs.0, &specs.1, &specs.2, &specs.3, &shell).unwrap();
            worker.set_action(&mut provider, "decompile", "").unwrap();
            worker.prepare_function(&mut provider, 0x1000).unwrap();
            let ram = provider.ram_space_index as u32;
            let raw = worker.decompile_at(&mut provider, ram, 0x1000).unwrap();
            let decoded = crate::decode_document_with_ram_space(&raw, Some(ram as u64));
            let ir = decoded.function_ir.unwrap();
            let parameter = ir.high_variables.iter().filter(|high| high.class == "param")
                .filter_map(|high| high.symbol.as_ref()).find(|symbol| symbol.name == "value")
                .expect("the returned machine value must be the declared argument");
            if let Some(registers) = registers {
                assert_eq!(parameter.address, None);
                assert_eq!(parameter.pieces.iter().map(|piece| (piece.space.as_str(), piece.offset, piece.size))
                    .collect::<Vec<_>>(), vec![("register", registers[0], 4), ("register", registers[1], 4)]);
            } else {
                assert!(parameter.pieces.is_empty());
                let address = parameter.address.as_ref().unwrap();
                assert_ne!(address.space, romwright_model::AddressSpace::Ram);
                assert_eq!(address.offset, 8);
            }
        }
        std::fs::remove_file(path).unwrap();
    }

    /// What a decompile of authored instruction words recovered: the storage
    /// of each parameter, the registers read before written that no model slot
    /// covers (`in_*`), the printed text, and the return type's size.
    struct Probe {
        params: Vec<(String, u64)>,
        joined: Vec<(String, Vec<u64>)>,
        irregular: Vec<String>,
        text: String,
        return_size: Option<u64>,
        registers: std::collections::HashMap<String, (u64, u64)>,
    }

    /// Registers `words` (big-endian) at `base` with the production spec
    /// transforms for `language` and decompiles `entry`. `functions` names every
    /// function in the image (`entry` included); `prototype` declares one for
    /// `entry`.
    fn probe(language_id: &str, base: u64, words: &[u32], functions: &[(u64, &str, u64)],
             prototype: Option<(&str, &str)>, entry: u64) -> Probe {
        use crate::{BinaryBacking, NativeWorker, ProgramProvider};
        use romwright_model::{Address, FactKind, FactProvenance, PrototypeRow};
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut cfg = romwright_core::session::RuntimeConfig::from_env();
        cfg.spec_root = repo.join(&cfg.spec_root);
        cfg.decompiler_path = repo.join(&cfg.decompiler_path);
        let (sla, specs_path, language_dir, language) =
            romwright_core::native_runtime::language_decompile_config(&cfg, language_id).unwrap();
        let path = std::env::temp_dir().join(format!("romwright-abi-probe-{}-{}",
            std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let little = language_id.contains(":LE:");
        std::fs::write(&path, words.iter().flat_map(|word| if little { word.to_le_bytes() } else { word.to_be_bytes() })
            .collect::<Vec<_>>()).unwrap();
        let entries: Vec<u64> = functions.iter().map(|(address, _, _)| *address).collect();
        let mut provider = ProgramProvider::new(BinaryBacking::from_file(&path, None, base).unwrap(), entries);
        provider.load_language_info(&specs_path).unwrap();
        for (address, name, size) in functions {
            provider.function_names.insert(*address, (*name).into());
            provider.function_sizes.insert(*address, *size);
        }
        if let Some((signature, return_type)) = prototype {
            provider.prototypes.insert(entry, PrototypeRow {
                function: Address::ram(entry), signature: signature.into(),
                calling_convention: None, return_type: Some(return_type.into()),
                provenance: FactProvenance { kind: FactKind::Asserted, source: "public ABI fixture".into(), confidence: None },
            });
        }
        let mut specs = crate::load_specs(&specs_path).unwrap();
        // The production order (`load_program_specs`).
        let helpers = super::with_mwcc_callfixups(&specs.1, &language);
        if helpers != specs.1 {
            for name in super::mwcc_helper_names() {
                provider.call_fixups.insert(name.clone(), name);
            }
            specs.1 = helpers;
        }
        specs.1 = super::with_psyq_soft_float(&specs.1, &language);
        specs.1 = super::with_o32_argument_rules(&specs.1, &language);
        specs.1 = super::with_gekko_argument_rules(&specs.1, &language);
        specs.1 = super::with_allegrex_argument_rules(&specs.1, &language);
        let mut command = std::process::Command::new(&cfg.decompiler_path);
        command.env("ROMWRIGHT_SLA", &sla).env("ROMWRIGHT_LANGUAGE_DIR", &language_dir)
            .env("ROMWRIGHT_LANGUAGE", &language);
        let mut worker = NativeWorker::launch(command).unwrap();
        let shell = provider.function_shell().unwrap();
        worker.register_program_with_shell(&mut provider, &specs.0, &specs.1, &specs.2, &specs.3, &shell).unwrap();
        worker.set_action(&mut provider, "decompile", "").unwrap();
        worker.prepare_function(&mut provider, entry).unwrap();
        let ram = provider.ram_space_index as u32;
        let raw = worker.decompile_at(&mut provider, ram, entry).unwrap();
        let decoded = crate::decode_document_with_ram_space(&raw, Some(ram as u64));
        assert!(decoded.semantic_error.is_none(), "{:?}", decoded.semantic_error);
        let ir = decoded.function_ir.as_ref().expect("function IR");
        let params = ir.high_variables.iter().filter(|high| high.class == "param")
            .filter_map(|high| high.symbol.as_ref())
            .filter(|symbol| symbol.pieces.is_empty())
            .map(|symbol| {
                let address = symbol.address.as_ref().expect("a single-storage parameter");
                assert_ne!(address.space, romwright_model::AddressSpace::Ram);
                (symbol.name.clone(), address.offset)
            })
            .collect();
        // Parameters the model joined from several registers: name and the
        // piece offsets, most significant first.
        let joined = ir.high_variables.iter().filter(|high| high.class == "param")
            .filter_map(|high| high.symbol.as_ref())
            .filter(|symbol| !symbol.pieces.is_empty())
            .map(|symbol| (symbol.name.clone(), symbol.pieces.iter().map(|piece| piece.offset).collect()))
            .collect();
        let probe = Probe {
            params,
            joined,
            irregular: decoded.storage.iter().filter(|symbol| symbol.name.starts_with("in_"))
                .map(|symbol| symbol.name.clone()).collect(),
            text: decoded.tokens.iter().map(|token| token.text.as_str()).collect(),
            return_size: decoded.prototype.as_ref().and_then(|proto| proto.return_type.size),
            registers: provider.registers.clone(),
        };
        std::fs::remove_file(path).unwrap();
        probe
    }

    /// Storage offsets of the 4-byte values o32 passes in 8-byte registers:
    /// the low word, `+4` on a big-endian machine. Sorted: the IR lists
    /// parameters in variable order, not argument order.
    fn offsets(probe: &Probe, registers: &[&str]) -> Vec<u64> {
        let mut offsets: Vec<u64> = registers.iter().map(|name| probe.registers[*name].0 + 4).collect();
        offsets.sort_unstable();
        offsets
    }

    /// o32: a leading float takes the FP register and still reserves its
    /// integer slot, an integer pushes a later float into integer registers,
    /// and the fifth word is the first stack argument at `sp+16` (P2.4).
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn o32_slots_follow_the_abi_for_declared_prototypes() {
        const N64: &str = "MIPS:BE:64:64-32addr";
        const RET: u32 = 0x03e0_0008; // jr ra, then the delay slot
        let swc1 = |ft: u32, base: u32, offset: u32| 0xe400_0000 | (base << 21) | (ft << 16) | offset;
        let sw = |rt: u32, base: u32, offset: u32| 0xac00_0000 | (base << 21) | (rt << 16) | offset;
        let (a0, a1, a2, a3, t0, sp) = (4, 5, 6, 7, 8, 29);
        let cases: Vec<(&str, Vec<u32>, Vec<&str>, Option<u64>)> = vec![
            // (float, int *): f12 leaves a0 as the hole, the pointer is a1.
            ("void probe(float a, int *b)", vec![swc1(12, a1, 0), RET, 0], vec!["f12", "a1"], None),
            // (int *, float): the float follows an integer, so it is a1's bits.
            ("void probe(int *a, float b)", vec![sw(a1, a0, 0), RET, 0], vec!["a0", "a1"], None),
            // (float, float, int *): f12, f14, then slot 2.
            ("void probe(float a, float b, int *c)", vec![swc1(12, a2, 0), swc1(14, a2, 4), RET, 0],
                vec!["f12", "f14", "a2"], None),
            // Four integers and a fifth: the fifth is at sp+16.
            ("void probe(int a, int b, int c, int d, int *e)",
                vec![0x8c00_0000 | (sp << 21) | (t0 << 16) | 16, sw(a0, t0, 0), sw(a1, t0, 4), sw(a2, t0, 8),
                     sw(a3, t0, 12), RET, 0],
                vec!["a0", "a1", "a2", "a3"], Some(16)),
        ];
        for (signature, words, registers, stack) in cases {
            let size = words.len() as u64 * 4;
            let probe = probe(N64, 0x8000_1000, &words, &[(0x8000_1000, "probe", size)],
                Some((signature, "void")), 0x8000_1000);
            let mut expected = offsets(&probe, &registers);
            expected.extend(stack);
            expected.sort_unstable();
            let mut got: Vec<u64> = probe.params.iter().map(|(_, offset)| *offset).collect();
            got.sort_unstable();
            assert_eq!(got, expected, "{signature}: {:?}", probe.params);
        }
    }

    /// With no declared prototype, `(float, float, int *)` is three
    /// parameters: the integer registers the floats shadow are not phantom
    /// parameters (the o64 spec printed `f12, f14, a0, a1, a2`).
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn o32_inference_has_no_phantom_shadow_parameters() {
        let swc1 = |ft: u32, base: u32, offset: u32| 0xe400_0000 | (base << 21) | (ft << 16) | offset;
        let words = [swc1(12, 6, 0), swc1(14, 6, 4), 0x03e0_0008, 0];
        let probe = probe("MIPS:BE:64:64-32addr", 0x8000_1000, &words, &[(0x8000_1000, "probe", 16)], None, 0x8000_1000);
        let mut got: Vec<u64> = probe.params.iter().map(|(_, offset)| *offset).collect();
        got.sort_unstable();
        assert_eq!(got, offsets(&probe, &["f12", "f14", "a2"]), "{:?}", probe.params);
        // and the floats print as floats, whatever the stores' integer types say
        assert!(probe.text.contains("float param_1"), "{}", probe.text);
    }

    /// `bl _savegpr_30` is the helper's stores, not an unknown call: the
    /// first argument survives it, and the callee-saved registers come back.
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn mwcc_register_save_helpers_keep_arguments_and_callee_saved_registers() {
        const GEKKO: &str = "PowerPC:BE:32:Gekko_Broadway";
        let base = 0x8000_1000u64;
        let bl = |from: u64, to: u64| 0x4800_0001 | ((to - from) as u32 & 0x03ff_fffc);
        let words = vec![
            0x9421_ffe0, // stwu r1,-0x20(r1)
            0x7c08_02a6, // mflr r0
            0x9001_0024, // stw r0,0x24(r1)
            0x3961_0020, // addi r11,r1,0x20      (r11 = the caller's sp)
            bl(base + 0x10, base + 0x100), // bl _savegpr_30
            0x7c7e_1b78, // mr r30,r3
            0x7c9f_2378, // mr r31,r4
            0x7c7e_fa14, // add r3,r30,r31
            0x3961_0020, // addi r11,r1,0x20
            bl(base + 0x24, base + 0x110), // bl _restgpr_30
            0x8001_0024, // lwz r0,0x24(r1)
            0x7c08_03a6, // mtlr r0
            0x3821_0020, // addi r1,r1,0x20
            0x4e80_0020, // blr
        ];
        let mut image = words;
        // The sled bodies as the runtime has them: rN..r31 then blr.
        image.resize(0x120 / 4, 0);
        image[0x100 / 4..0x100 / 4 + 3].copy_from_slice(&[0x93cb_fff8, 0x93eb_fffc, 0x4e80_0020]);
        image[0x110 / 4..0x110 / 4 + 3].copy_from_slice(&[0x83cb_fff8, 0x83eb_fffc, 0x4e80_0020]);
        let functions = [(base, "probe", 0x38), (base + 0x100, "_savegpr_30", 12), (base + 0x110, "_restgpr_30", 12)];
        let with = probe(GEKKO, base, &image, &functions, None, base);
        assert_eq!(with.params.len(), 2, "{:?}\n{}", with.params, with.text);
        assert!(with.irregular.is_empty(), "{:?}\n{}", with.irregular, with.text);
        assert!(!with.text.contains("unaff_r30") && !with.text.contains("unaff_r31"), "{}", with.text);
        // The same bytes with the helpers unnamed (what a stripped image
        // gave before the sled pass) lose the first argument to the call.
        let unnamed = [(base, "probe", 0x38), (base + 0x100, "FUN_80001100", 12), (base + 0x110, "FUN_80001110", 12)];
        let without = probe(GEKKO, base, &image, &unnamed, None, base);
        assert!(without.params.len() < 2 || !without.irregular.is_empty() || without.text.contains("unaff_"),
            "an unexpanded helper call must show: {}", without.text);
    }

    /// `fmadds` is one fused multiply-add: a single `a * b + c` rounded to
    /// single, not a multiply statement and an add statement.
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn gekko_fused_multiply_add_prints_one_expression() {
        let fm = |op: u32, xo: u32, d: u32, a: u32, b: u32, c: u32| (op << 26) | (d << 21) | (a << 16) | (b << 11) | (c << 6) | (xo << 1);
        // fmadds f1,f1,f2,f3 ; blr
        let words = [fm(59, 29, 1, 1, 3, 2), 0x4e80_0020];
        let probe = probe("PowerPC:BE:32:Gekko_Broadway", 0x8000_1000, &words, &[(0x8000_1000, "probe", 8)], None, 0x8000_1000);
        assert!(probe.text.contains("param_1 * param_2 + param_3"), "{}", probe.text);
        assert_eq!(probe.text.matches('*').count(), 1, "{}", probe.text);
        // fnmsubs: -(a * b - c)
        let words = [fm(59, 30, 1, 1, 3, 2), 0x4e80_0020];
        let probe = probe_again(&words);
        assert!(probe.text.contains("param_1 * param_2") && probe.text.contains("param_3"), "{}", probe.text);
    }

    fn probe_again(words: &[u32]) -> Probe {
        probe("PowerPC:BE:32:Gekko_Broadway", 0x8000_1000, words, &[(0x8000_1000, "probe", 8)], None, 0x8000_1000)
    }

    /// An 8-byte value returns in `r3:r4`, high word first.
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn gekko_eight_byte_result_returns_in_r3_r4() {
        // lwz r4,4(r3) ; lwz r3,0(r3) ; blr
        let words = [0x8083_0004, 0x8063_0000, 0x4e80_0020];
        let probe = probe("PowerPC:BE:32:Gekko_Broadway", 0x8000_1000, &words, &[(0x8000_1000, "probe", 12)], None, 0x8000_1000);
        assert!(probe.text.contains("undefined8 probe"), "{}", probe.text);
    }

    /// The PSX convention has no FPU registers once the soft-float transform
    /// has run over the vendored spec bundle (P2.5); nothing else goes.
    #[test]
    fn psx_soft_float_removes_exactly_the_fp_entries() {
        let bundle = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../native/specs/PSX-LE-32-default/cspec.xml"),
        )
        .unwrap();
        let before = &bundle[bundle.find("<default_proto>").unwrap()..bundle.find("</default_proto>").unwrap()];
        for needle in ["f12_13", "f14_15", "f0_1", "\"f20\"", "\"f30\""] {
            assert!(before.contains(needle), "{needle} should be in the stock-derived spec");
        }
        let soft = with_psyq_soft_float(&bundle, "PSX:LE:32:default");
        let default = &soft[soft.find("<default_proto>").unwrap()..soft.find("</default_proto>").unwrap()];
        for needle in ["metatype=\"float\"", "f12", "f14", "f0_1", "f20", "f30", "storage=\"float\"",
                       "datatype name=\"float\""] {
            assert!(!default.contains(needle), "{needle} in the PSX default prototype");
        }
        // integer slots a0..a3, then the stack from sp+16; the integer callee-saved
        // set, the return rules and the GTE register range are untouched
        for needle in ["\"a0\"", "\"a3\"", "offset=\"16\" space=\"stack\"", "\"s8\"", "\"gp\"", "<output>",
                       "<join/>", "first=\"0x5000\""] {
            assert!(soft.contains(needle), "{needle} missing");
        }
        // nothing is added, and every other line of the bundle is still there
        let original: Vec<&str> = bundle.lines().collect();
        assert!(soft.lines().all(|line| original.contains(&line)));
        assert!(soft.lines().count() < original.len());
        assert!(soft.contains("<datatype name=\"struct\"/>"), "the aggregate rules stay");
        // other languages, including the PSP's MIPS32, keep their FP slots
        assert_eq!(with_psyq_soft_float(&bundle, "MIPS:LE:32:default"), bundle);
        assert_eq!(with_psyq_soft_float(&soft, "PSX:LE:32:default"), soft);
    }

    /// A declared `float` is an integer-register argument on the PSX: a0, not f12.
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn psx_declared_float_arguments_use_integer_registers() {
        // sw a0,0(a1) ; jr ra ; nop
        let words = [0xaca4_0000u32, 0x03e0_0008, 0];
        let probe = probe("PSX:LE:32:default", 0x8001_0000, &words, &[(0x8001_0000, "probe", 12)],
            Some(("void probe(float a, int *b)", "void")), 0x8001_0000);
        let mut got: Vec<u64> = probe.params.iter().map(|(_, offset)| *offset).collect();
        got.sort_unstable();
        let mut want: Vec<u64> = ["a0", "a1"].iter().map(|name| probe.registers[*name].0).collect();
        want.sort_unstable();
        assert_eq!(got, want, "{:?}\n{}", probe.params, probe.text);
    }

    /// What the GBA/DS ARM7 `v4t` convention carries, which agbcc's APCS and
    /// AAPCS agree on for 32-bit values: r0..r3 in, then the stack; r0 or the
    /// r1:r0 pair out; r4..r11 and sp callee-saved; no VFP/float slots at all.
    #[test]
    fn the_arm_v4t_spec_is_soft_float_with_the_full_callee_saved_set() {
        let spec = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../native/specs/ARM-LE-32-v4t/cspec.xml"),
        )
        .unwrap();
        let default = &spec[spec.find("<default_proto>").unwrap()..spec.find("</default_proto>").unwrap()];
        assert!(!default.contains("metatype=\"float\""), "a VFP/float slot in a pre-v7 spec");
        let input = &default[default.find("<input").unwrap()..default.find("</input>").unwrap()];
        let registers: Vec<&str> = input.split("<register name=\"").skip(1).map(|part| part.split('"').next().unwrap()).collect();
        assert_eq!(registers, ["r0", "r1", "r2", "r3"]);
        let saved = &default[default.find("<unaffected>").unwrap()..default.find("</unaffected>").unwrap()];
        for register in ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "sp"] {
            assert!(saved.contains(&format!("<register name=\"{register}\"/>")), "{register} must be callee-saved");
        }
        assert!(!saved.contains("\"r12\"") && !saved.contains("\"lr\""), "scratch registers are not callee-saved");
        assert!(default.contains("piece1=\"r1\" piece2=\"r0\""), "64-bit results come back in r1:r0");
    }

    /// No VFP: a declared `float` is r0, as it is for agbcc and AAPCS soft-float.
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn arm_declared_float_arguments_use_integer_registers() {
        // str r0,[r1] ; bx lr
        let words = [0xe581_0000u32, 0xe12f_ff1e];
        let probe = probe("ARM:LE:32:v4t", 0x0800_0000, &words, &[(0x0800_0000, "probe", 8)],
            Some(("void probe(float a, int *b)", "void")), 0x0800_0000);
        let mut got: Vec<u64> = probe.params.iter().map(|(_, offset)| *offset).collect();
        got.sort_unstable();
        let mut want: Vec<u64> = ["r0", "r1"].iter().map(|name| probe.registers[*name].0).collect();
        want.sort_unstable();
        assert_eq!(got, want, "{:?}\n{}", probe.params, probe.text);
    }

    /// `push {r4,lr}` .. `pop {r4,pc}` keeps r4 callee-saved: the register is a
    /// local, neither an input nor an unrestored `unaff_r4`.
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn arm_callee_saved_r4_is_a_local_not_an_artefact() {
        // push {r4,lr} ; mov r4,r0 ; str r4,[r1] ; pop {r4,pc}
        let words = [0xe92d_4010u32, 0xe1a0_4000, 0xe581_4000, 0xe8bd_8010];
        let probe = probe("ARM:LE:32:v4t", 0x0800_0000, &words, &[(0x0800_0000, "probe", 16)], None, 0x0800_0000);
        assert_eq!(probe.params.len(), 2, "{:?}\n{}", probe.params, probe.text);
        assert!(probe.irregular.is_empty(), "{:?}\n{}", probe.irregular, probe.text);
        assert!(!probe.text.contains("unaff_r4"), "{}", probe.text);
    }

    /// The Allegrex rules leave the register table alone and add exactly the
    /// six assignment rules; a spec that has rules keeps them.
    #[test]
    fn allegrex_rules_are_added_once_and_only_for_the_psp() {
        let bundle = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../native/specs/Allegrex-LE-32-default/cspec.xml"),
        )
        .unwrap();
        assert!(!bundle.contains("<rule"), "the extension's spec ships no assignment rules");
        let ruled = super::with_allegrex_argument_rules(&bundle, "Allegrex:LE:32:default");
        assert_eq!(ruled.matches("<rule>").count(), 6);
        assert_eq!(ruled.matches("<pentry").count(), bundle.matches("<pentry").count());
        assert!(ruled.find("<rule>").unwrap() < ruled.find("</input>").unwrap());
        assert_eq!(super::with_allegrex_argument_rules(&ruled, "Allegrex:LE:32:default"), ruled);
        assert_eq!(super::with_allegrex_argument_rules(&bundle, "MIPS:LE:32:default"), bundle);
    }

    /// PSP EABI32: a declared `float` is `f12`.., an 8-byte value (a soft-float
    /// `double`, a `long long`) an aligned integer pair, low word in the lower
    /// register, and an odd register is skipped for it (`__make_dp` reads
    /// `a0`, `a1`, `a2` and `t0:t1`, never `a3`).
    #[test]
    #[ignore = "requires the built native decompiler and installed SLEIGH specifications"]
    fn allegrex_declared_arguments_follow_the_psp_eabi() {
        const RET: u32 = 0x03e0_0008; // jr ra, then the delay slot
        let sw = |rt: u32, base: u32, offset: u32| 0xac00_0000 | (base << 21) | (rt << 16) | offset;
        let (a0, a1, a2, a3, t0, t1) = (4, 5, 6, 7, 8, 9);
        let registers = |probe: &Probe, names: &[&str]| -> Vec<u64> {
            names.iter().map(|name| probe.registers[*name].0).collect()
        };
        // (double a, int *b): a is a1:a0 (most significant first), b is a2.
        let words = [sw(a0, a2, 0), sw(a1, a2, 4), RET, 0];
        let first = probe("Allegrex:LE:32:default", 0x0880_4000, &words, &[(0x0880_4000, "probe", 16)],
            Some(("void probe(double a, int *b)", "void")), 0x0880_4000);
        assert_eq!(first.joined, [("a".to_string(), registers(&first, &["a1", "a0"]))], "{:?}\n{}", first.joined, first.text);
        assert_eq!(first.params, [("b".to_string(), registers(&first, &["a2"])[0])], "{:?}\n{}", first.params, first.text);
        // (int a, int b, int c, ulonglong d): d skips a3 for t1:t0.
        let words = [sw(t0, a0, 0), sw(t1, a0, 4), RET, 0];
        let second = probe("Allegrex:LE:32:default", 0x0880_4000, &words, &[(0x0880_4000, "probe", 16)],
            Some(("void probe(int *a, int b, int c, ulonglong d)", "void")), 0x0880_4000);
        assert_eq!(second.joined, [("d".to_string(), registers(&second, &["t1", "t0"]))], "{:?}\n{}", second.joined, second.text);
        let _ = a3;
        // (float a, double b, int *c): the float is f12 and costs no integer register.
        let swc1 = 0xe400_0000 | (a2 << 21) | (12 << 16);
        let words = [swc1, sw(a0, a2, 4), sw(a1, a2, 8), RET, 0];
        let third = probe("Allegrex:LE:32:default", 0x0880_4000, &words, &[(0x0880_4000, "probe", 20)],
            Some(("void probe(float a, double b, int *c)", "void")), 0x0880_4000);
        assert_eq!(third.joined, [("b".to_string(), registers(&third, &["a1", "a0"]))], "{:?}\n{}", third.joined, third.text);
        let mut singles: Vec<u64> = third.params.iter().map(|(_, offset)| *offset).collect();
        singles.sort_unstable();
        let mut want = registers(&third, &["f12", "a2"]);
        want.sort_unstable();
        assert_eq!(singles, want, "{:?}\n{}", third.params, third.text);
    }
}
