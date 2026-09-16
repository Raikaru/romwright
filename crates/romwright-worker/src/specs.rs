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
        if name == "r13" || name == "r2" {
            provider
                .tracked_values
                .insert((*address, name.clone()), *value);
        }
    }
    let language = db.program_language(program)?;
    specs.1 = with_entry_register_tracking(&specs.1, provider, &language, &contexts);
    specs.1 = with_mwcc_callfixups(&specs.1, &language);
    specs.1 = with_gekko_argument_rules(&specs.1, &language);
    Ok(specs)
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
    // The SDA register values are not context fields: raw-SLEIGH
    // resolves each `<context_set>` name against the `.sla`'s declared
    // context variables, and a register (`r13`, `r2`) is rejected there --
    // registers ride `<tracked_set>` and `getTrackedRegisters` instead
    // (below, and `tracked_values`). Match exactly the names the importer
    // seeds, not "is in registers.txt": ARM `TMode` mode rows share a
    // name with an ARM register and must still decode. Folding ranges
    // over the filtered rows keeps a skipped point from punching a
    // one-address hole in its neighbour.
    let fields: Vec<&(u64, String, u64)> = contexts
        .iter()
        .filter(|(_, name, _)| name != "r13" && name != "r2")
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
    if lang_dir.contains("MIPS") {
        if let Some(&(register_offset, register_size)) = provider.registers.get("t9") {
            if register_size != 0 && register_size <= 8 {
                let mut entries: Vec<u64> = provider.functions.clone();
                entries.sort_unstable();
                entries.dedup();
                for entry in entries {
                    data.push_str(&format!(
                        "<tracked_set space=\"ram\" first=\"0x{entry:x}\" last=\"0x{entry:x}\">\n\
                         <set space=\"register\" offset=\"0x{register_offset:x}\" size=\"{register_size}\" val=\"0x{entry:x}\"/>\n\
                         </tracked_set>\n"
                    ));
                }
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

/// MWCC prologue/epilogue helpers (P2.3): `_savegpr_N`/`_restgpr_N` save and
/// restore rN..r31 across the frame. A `bl _savegpr_14` is an opaque call to
/// the decompiler unless the cspec carries a `<callfixup>` that expands it to
/// the per-register stores the helper performs. Injected for PowerPC so a
/// MWCC binary's frames read as callee-saved setup, not an unknown call.
/// Stack layout: r31 at -4(sp), r30 at -8, …, rN at -4*(32-N).
fn mwcc_callfixups() -> String {
    let mut out = String::new();
    for n in 14..32u8 {
        let mut body = String::new();
        for reg in n..32u8 {
            let off = 4 * (32 - reg);
            body.push_str(&format!("      *(r1 - 0x{off:02x}) = r{reg};\n"));
        }
        out.push_str(&format!(
            "  <callfixup name=\"_savegpr_{n}\">\n    <pcode><body><![CDATA[\n{body}    ]]></body></pcode>\n  </callfixup>\n"
        ));
    }
    for n in 14..32u8 {
        let mut body = String::new();
        for reg in n..32u8 {
            let off = 4 * (32 - reg);
            body.push_str(&format!("      r{reg} = *(r1 - 0x{off:02x});\n"));
        }
        out.push_str(&format!(
            "  <callfixup name=\"_restgpr_{n}\">\n    <pcode><body><![CDATA[\n{body}    ]]></body></pcode>\n  </callfixup>\n"
        ));
    }
    out
}

/// Injects the MWCC callfixups into a cspec before `</compiler_spec>`,
/// alongside the context_data the entry-tracking pass already adds. A cspec
/// that already ships a helper (the Gekko/Broadway MWCC-aware spec carries
/// every `_savegpr_N`/`_restgpr_N`) keeps its own — re-adding the name is a
/// duplicate the decompiler rejects, so only absent fixups are injected.
fn with_mwcc_callfixups(cspec: &str, lang_dir: &str) -> String {
    if !lang_dir.contains("PowerPC") {
        return cspec.to_string();
    }
    let Some(close) = cspec.rfind("</compiler_spec>") else {
        return cspec.to_string();
    };
    // Keep only the fixups the cspec does not already declare.
    let mut extra = String::new();
    for line in mwcc_callfixups().split("</callfixup>") {
        let Some(name) = line
            .split("name=\"")
            .nth(1)
            .and_then(|s| s.split('\"').next())
        else {
            continue;
        };
        let needle = format!("name=\"{name}\"");
        if !cspec.contains(&needle) {
            extra.push_str(line);
            extra.push_str("</callfixup>\n");
        }
    }
    let mut out = String::with_capacity(cspec.len() + extra.len() + 16);
    out.push_str(&cspec[..close]);
    out.push_str(&extra);
    out.push_str(&cspec[close..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{mwcc_callfixups, with_mwcc_callfixups};

    /// MWCC prologue/epilogue helpers (`_savegpr_N`/`_restgpr_N`) must be
    /// injected for PowerPC so a `bl _savegpr_14` reads as callee-saved
    /// stores, not an opaque call (P2.3).
    #[test]
    fn mwcc_callfixups_cover_every_gpr_helper() {
        let fixups = mwcc_callfixups();
        for n in 14..32 {
            assert!(
                fixups.contains(&format!("name=\"_savegpr_{n}\"")),
                "missing _savegpr_{n}"
            );
            assert!(
                fixups.contains(&format!("name=\"_restgpr_{n}\"")),
                "missing _restgpr_{n}"
            );
        }
        // _savegpr_14 stores r14..r31 at -4*(32-r) below the frame.
        assert!(fixups.contains("*(r1 - 0x48) = r14;"));
        assert!(fixups.contains("*(r1 - 0x04) = r31;"));
        // _restgpr_14 loads them back.
        assert!(fixups.contains("r14 = *(r1 - 0x48);"));
        assert!(fixups.contains("r31 = *(r1 - 0x04);"));
    }

    #[test]
    fn mwcc_callfixups_inject_only_for_powerpc_and_skip_present() {
        let ppc = "PowerPC-BE-32-Gekko_Broadway";
        let mips = "MIPS-BE-64-64-32addr";
        let bare = "<compiler_spec>\n</compiler_spec>";

        // PowerPC gets the helpers; a non-PowerPC lang_dir is untouched.
        let injected = with_mwcc_callfixups(bare, ppc);
        assert!(injected.contains("name=\"_savegpr_14\""));
        assert!(injected.contains("name=\"_restgpr_31\""));
        assert_eq!(with_mwcc_callfixups(bare, mips), bare);

        // A cspec that already ships a helper keeps its own (no duplicate).
        let already = "<compiler_spec>\n  <callfixup name=\"_savegpr_14\"/>\n</compiler_spec>";
        let merged = with_mwcc_callfixups(already, ppc);
        assert_eq!(merged.matches("name=\"_savegpr_14\"").count(), 1);
        assert!(merged.contains("name=\"_savegpr_15\""));
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
}
