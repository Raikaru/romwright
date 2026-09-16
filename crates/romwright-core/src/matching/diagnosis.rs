use object::{Object, ObjectSection, ObjectSymbol};
use romwright_model::matching::{MatchDiagnosis, MismatchCategory, MismatchEvidence};
use serde_json::Value;

struct Function<'a> {
    implicit_addends: bool,
    architecture: object::Architecture,
    little_endian: bool,
    thumb: bool,
    bytes: &'a [u8],
    // Preserve relocation order: paired/compound relocations are not a set.
    relocations: Option<Vec<(u64, String)>>,
}

fn function<'a>(bytes: &'a [u8], name: &str) -> Option<Function<'a>> {
    let file = object::File::parse(bytes).ok()?;
    if file.architecture() == object::Architecture::Unknown {
        return None;
    }
    let mut symbols = file
        .symbols()
        .filter(|symbol| symbol.is_definition() && symbol.name().ok() == Some(name));
    let symbol = symbols.next()?;
    if symbols.next().is_some() || symbol.size() == 0 {
        return None;
    }
    let section = file.section_by_index(symbol.section_index()?).ok()?;
    if section.kind() != object::SectionKind::Text {
        return None;
    }
    // ELF ARM function values carry the Thumb mode bit, not a byte offset.
    let thumb = file.format() == object::BinaryFormat::Elf
        && file.architecture() == object::Architecture::Arm
        && symbol.kind() == object::SymbolKind::Text
        && symbol.address() & 1 != 0;
    let address = if thumb { symbol.address() & !1 } else { symbol.address() };
    let start = address.checked_sub(section.address())?;
    let end = start.checked_add(symbol.size())?;
    let instructions = section.data_range(address, symbol.size()).ok()??;
    let mut implicit_addends = false;
    let relocations = (|| {
        let mut entries = section
            .relocations()
            .filter(|(offset, _)| *offset >= start && *offset < end)
            .peekable();
        if entries.peek().is_none() {
            return Some(Vec::new());
        }
        let mut names = std::collections::HashMap::new();
        for symbol in file.symbols() {
            *names.entry(symbol.name().ok()?).or_insert(0usize) += 1;
        }
        let mut sections = std::collections::HashMap::new();
        for section in file.sections() {
            *sections.entry(section.name().ok()?).or_insert(0usize) += 1;
        }
        let mut rows = Vec::new();
        for (offset, relocation) in entries {
            implicit_addends |= relocation.has_implicit_addend();
            let target = match relocation.target() {
                object::RelocationTarget::Symbol(index) => {
                    let target = file.symbol_by_index(index).ok()?;
                    let name = target.name().ok()?;
                    if name.is_empty() {
                        let section = file.section_by_index(target.section_index()?).ok()?;
                        let name = section.name().ok()?;
                        if sections.get(name) != Some(&1) {
                            return None;
                        }
                        format!(
                            "section:{name}+{}",
                            target.address().checked_sub(section.address())?
                        )
                    } else {
                        if names.get(name) != Some(&1) {
                            return None;
                        }
                        format!(
                            "symbol:{name}/{:?}/{:?}/{}/{}",
                            target.kind(),
                            target.scope(),
                            target.is_weak(),
                            target.is_undefined()
                        )
                    }
                }
                object::RelocationTarget::Section(index) => {
                    let name = file.section_by_index(index).ok()?.name().ok()?;
                    if sections.get(name) != Some(&1) {
                        return None;
                    }
                    format!("section:{name}")
                }
                object::RelocationTarget::Absolute => "absolute".to_owned(),
                _ => return None,
            };
            // MWCC records SDA21 at the low halfword; decomp-toolkit split
            // objects record the containing instruction word (ObjReloc::to_elf).
            // These describe the same PPC32 patch site, not different symbols.
            // Preserve odd/malformed sites and every other relocation convention.
            let offset = if file.architecture() == object::Architecture::PowerPc
                && !file.is_little_endian()
                && offset & 1 == 0
                && matches!(relocation.flags(), object::RelocationFlags::Elf {
                    r_type: object::elf::R_PPC_EMB_SDA21
                })
            {
                offset & !3
            } else {
                offset
            };
            rows.push((
                offset.checked_sub(start)?,
                format!(
                    "{:?}/{:?}/{:?}/{}/{}/{}/{}",
                    relocation.kind(),
                    relocation.encoding(),
                    relocation.flags(),
                    relocation.size(),
                    relocation.addend(),
                    relocation.has_implicit_addend(),
                    target,
                ),
            ));
        }
        Some(rows)
    })();
    Some(Function {
        architecture: file.architecture(),
        little_endian: file.is_little_endian(),
        thumb,
        bytes: instructions,
        relocations,
        implicit_addends,
    })
}

fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

pub(super) fn symbol<'a>(raw: &'a Value, side: &str, name: &str) -> Option<&'a Value> {
    let mut found = raw
        .get(side)?
        .get("symbols")?
        .as_array()?
        .iter()
        .filter(|symbol| symbol.get("name").and_then(Value::as_str) == Some(name));
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn mnemonic(instruction: &Value) -> &str {
    instruction
        .get("parts")
        .and_then(Value::as_array)
        .and_then(|parts| {
            parts
                .iter()
                .find_map(|part| part.get("opcode")?.get("mnemonic")?.as_str())
        })
        .unwrap_or("")
}

fn uses_register(instruction: &Value, register: &str) -> bool {
    instruction
        .get("parts")
        .and_then(Value::as_array)
        .is_some_and(|parts| {
            parts.iter().any(|part| {
                part.get("arg")
                    .and_then(|arg| arg.get("opaque"))
                    .and_then(Value::as_str)
                    .is_some_and(|arg| arg.trim_start_matches('$') == register)
            })
        })
}

fn classify(
    left: &Value,
    right: &Value,
    architecture: Option<object::Architecture>,
) -> (MismatchCategory, &'static str) {
    use MismatchCategory::*;
    let opcodes = [mnemonic(left), mnemonic(right)];
    if [left, right]
        .iter()
        .any(|instruction| instruction.get("relocation").is_some())
    {
        return (
            Relocation,
            "Compare referenced symbols, relocation kinds and addends; source names alone do not prove equivalent references.",
        );
    }
    if opcodes.iter().any(|opcode| {
        matches!(
            *opcode,
            "movsx"
                | "movsxd"
                | "movzx"
                | "extsb"
                | "extsh"
                | "extsw"
                | "sxtb"
                | "sxth"
                | "sxtw"
                | "uxtb"
                | "uxth"
                | "uxtw"
                | "seb"
                | "seh"
        )
    }) {
        return (
            Extension,
            "Test the operand width and signedness, or an explicit cast. This is a hypothesis, not proof of the original type.",
        );
    }
    let stack = match architecture {
        Some(object::Architecture::PowerPc | object::Architecture::PowerPc64) => "r1",
        Some(object::Architecture::I386) => "esp",
        Some(object::Architecture::X86_64) => "rsp",
        _ => "sp",
    };
    if uses_register(left, stack)
        || uses_register(right, stack)
        || opcodes
            .iter()
            .any(|opcode| matches!(*opcode, "push" | "pop" | "enter" | "leave"))
    {
        return (
            StackFrame,
            "Inspect local lifetimes, spills, alignment and outgoing arguments before changing the frame layout.",
        );
    }
    if opcodes.iter().any(|opcode| {
        matches!(
            *opcode,
            "call" | "callq" | "bl" | "blx" | "bctrl" | "jal" | "jalr"
        ) || (*opcode == "blr" && architecture == Some(object::Architecture::Aarch64))
    }) {
        return (
            CallSequence,
            "Compare the call target, prototype, argument evaluation and calling convention.",
        );
    }
    if [left, right]
        .iter()
        .any(|instruction| instruction.get("branch_dest").is_some())
        || opcodes
            .iter()
            .any(|opcode| matches!(*opcode, "ret" | "retq" | "blr" | "bx"))
    {
        return (
            ControlFlow,
            "Test condition signedness and control-flow shape; equivalent source forms can select different branches.",
        );
    }
    if opcodes.iter().any(|opcode| {
        [
            "ldr", "str", "ldp", "stp", "lw", "sw", "lh", "sh", "lb", "sb", "sth", "lfs", "stfs",
            "lfd", "stfd",
        ]
        .iter()
        .any(|prefix| opcode.starts_with(prefix))
            || matches!(*opcode, "ld" | "sd" | "std")
    }) || [left, right].iter().any(|instruction| {
        mnemonic(instruction).starts_with("mov")
            && instruction
                .get("formatted")
                .and_then(Value::as_str)
                .is_some_and(|text| text.contains('['))
    }) {
        return (
            MemoryAccess,
            "Compare access width, field offset and addressing mode; trial a layout or pointer-type change in isolation.",
        );
    }
    if opcodes[0] == opcodes[1]
        && [left, right].iter().all(|instruction| {
            instruction
                .get("parts")
                .and_then(Value::as_array)
                .is_some_and(|parts| {
                    !parts.iter().any(|part| {
                        part.get("arg").is_some_and(|arg| {
                            arg.get("signed").is_some() || arg.get("unsigned").is_some()
                        })
                    })
                })
        })
    {
        return (
            RegisterOrScheduling,
            "Test expression ordering or variable lifetimes; register differences can also be consequences of earlier source differences.",
        );
    }
    (
        ConstantOrInstruction,
        "Compare the literal, expression and selected operation. Compile a bounded alternative before accepting this hypothesis.",
    )
}

pub(super) fn diagnose(
    symbol_name: &str,
    target: &[u8],
    candidate: Option<&[u8]>,
    comparison: Option<&Value>,
) -> MatchDiagnosis {
    let target_function = function(target, symbol_name);
    let candidate_function = candidate.and_then(|bytes| function(bytes, symbol_name));
    let compatible = target_function
        .as_ref()
        .zip(candidate_function.as_ref())
        .filter(|(left, right)| {
            left.architecture == right.architecture && left.little_endian == right.little_endian
                && left.thumb == right.thumb
        });
    let raw = comparison.unwrap_or(&Value::Null);
    let left = symbol(raw, "left", symbol_name);
    let right = symbol(raw, "right", symbol_name);
    let mut result = MatchDiagnosis {
        symbol: symbol_name.to_owned(),
        similarity: left
            .and_then(|symbol| symbol.get("match_percent")?.as_f64())
            .filter(|score| score.is_finite() && (0.0..=100.0).contains(score)),
        exact_object_bytes: candidate.is_some_and(|candidate| candidate == target),
        exact_instructions: compatible.map(|(left, right)| left.bytes == right.bytes),
        exact_relocations: compatible.and_then(|(left, right)| {
            if left.relocations.as_ref()? != right.relocations.as_ref()? {
                return Some(false);
            }
            // REL addends live in instruction/data bytes. Without decoding
            // their architecture-specific fields, differing bytes are unknown.
            if (left.implicit_addends || right.implicit_addends) && left.bytes != right.bytes {
                None
            } else {
                Some(true)
            }
        }),
        mismatches: Vec::new(),
    };
    if comparison.is_none() {
        return result;
    }
    let (Some(left), Some(right)) = (left, right) else {
        result.mismatches.push(MismatchEvidence {
            category: MismatchCategory::MissingFunction, target_address: None,
            candidate_address: None, target: symbol_name.to_owned(), candidate: String::new(),
            hypothesis: "The requested symbol is absent or ambiguous in the comparison. Check its spelling, linkage and whether the compiler removed it.".to_owned(),
            source_line: None,
        });
        return result;
    };
    let empty = Vec::new();
    let left_rows = left
        .get("instructions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let right_rows = right
        .get("instructions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for index in 0..left_rows.len().max(right_rows.len()) {
        let left = left_rows.get(index).unwrap_or(&Value::Null);
        let right = right_rows.get(index).unwrap_or(&Value::Null);
        let changed = [left, right].iter().any(|row| {
            row.get("diff_kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| !kind.is_empty() && kind != "DIFF_NONE")
        });
        let left = left.get("instruction").unwrap_or(&Value::Null);
        let right = right.get("instruction").unwrap_or(&Value::Null);
        if left.is_null() && right.is_null() {
            continue;
        }
        if !changed && left.get("formatted") == right.get("formatted") {
            continue;
        }
        let (category, hypothesis) = classify(
            left,
            right,
            target_function
                .as_ref()
                .map(|function| function.architecture),
        );
        result.mismatches.push(MismatchEvidence {
            category,
            target_address: (!left.is_null())
                .then(|| left.get("address").and_then(number).unwrap_or(0)),
            candidate_address: (!right.is_null())
                .then(|| right.get("address").and_then(number).unwrap_or(0)),
            target: left
                .get("formatted")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            candidate: right
                .get("formatted")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            hypothesis: hypothesis.to_owned(),
            source_line: right
                .get("line_number")
                .and_then(number)
                .filter(|line| *line > 0),
        });
    }
    if result.mismatches.is_empty() && result.exact_instructions == Some(false) {
        result.mismatches.push(MismatchEvidence {
            category: MismatchCategory::ConstantOrInstruction,
            target_address: None, candidate_address: None,
            target: "Different emitted function bytes".to_owned(), candidate: String::new(),
            hypothesis: "The comparator normalized away a byte difference. Inspect instruction encodings; a 100% similarity score is not byte equality.".to_owned(),
            source_line: None,
        });
    }
    if result.exact_relocations == Some(false)
        && !result
            .mismatches
            .iter()
            .any(|row| row.category == MismatchCategory::Relocation)
    {
        result.mismatches.push(MismatchEvidence {
            category: MismatchCategory::Relocation,
            target_address: None, candidate_address: None,
            target: "Different function relocation metadata".to_owned(), candidate: String::new(),
            hypothesis: "Check symbol binding, relocation addends and addressing flags. Identical formatted instructions do not prove relocation equality.".to_owned(),
            source_line: None,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal public ELF32/PPC object: two instructions, named data and
    // one explicit relocation. No proprietary compiler or game input.
    fn ppc_object(offset: u32, kind: u32, addend: u32, target: u32) -> Vec<u8> {
        fn words(values: &[u32]) -> Vec<u8> {
            values.iter().flat_map(|value| value.to_be_bytes()).collect()
        }
        fn append(bytes: &mut Vec<u8>, data: &[u8]) -> u32 {
            while bytes.len() % 4 != 0 { bytes.push(0); }
            let offset = bytes.len() as u32;
            bytes.extend_from_slice(data);
            offset
        }
        let mut bytes = vec![0u8; 52];
        bytes[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
        bytes[16..18].copy_from_slice(&1u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&20u16.to_be_bytes()); // EM_PPC
        bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
        bytes[40..42].copy_from_slice(&52u16.to_be_bytes());
        bytes[46..48].copy_from_slice(&40u16.to_be_bytes());
        bytes[48..50].copy_from_slice(&7u16.to_be_bytes());
        bytes[50..52].copy_from_slice(&5u16.to_be_bytes());
        let text = append(&mut bytes, &[0x80, 0x6d, 0, 0, 0x4e, 0x80, 0, 0x20]);
        let data = append(&mut bytes, &[0, 0, 0, 7]);
        let mut symbols = vec![0; 16];
        for (name, size, info, section) in [(1u32, 8u32, 0x12u8, 1u16),
                                          (6, 4, 0x11, 2), (11, 4, 0x11, 2)] {
            symbols.extend_from_slice(&words(&[name, 0, size]));
            symbols.extend_from_slice(&[info, 0]);
            symbols.extend_from_slice(&section.to_be_bytes());
        }
        let symtab = append(&mut bytes, &symbols);
        let strtab = append(&mut bytes, b"\0step\0data\0other\0");
        let section_names = b"\0.text\0.data\0.symtab\0.strtab\0.shstrtab\0.rela.text\0";
        let shstrtab = append(&mut bytes, section_names);
        let relocations = append(&mut bytes, &words(&[offset, (target << 8) | kind, addend]));
        let headers = [
            [0; 10],
            [1, 1, 6, 0, text, 8, 0, 0, 4, 0],
            [7, 1, 3, 0, data, 4, 0, 0, 4, 0],
            [13, 2, 0, 0, symtab, symbols.len() as u32, 4, 1, 4, 16],
            [21, 3, 0, 0, strtab, 17, 0, 0, 1, 0],
            [29, 3, 0, 0, shstrtab, section_names.len() as u32, 0, 0, 1, 0],
            [39, 4, 0, 0, relocations, 12, 3, 1, 4, 12],
        ];
        let shoff = append(&mut bytes, &headers.iter().flat_map(|row| words(row)).collect::<Vec<_>>());
        bytes[32..36].copy_from_slice(&shoff.to_be_bytes());
        bytes
    }

    #[test]
    fn ppc_sda21_compiler_and_split_object_patch_sites_are_equivalent() {
        let kind = object::elf::R_PPC_EMB_SDA21;
        let target = ppc_object(0, kind, 0, 2);
        let compiler = ppc_object(2, kind, 0, 2);
        let result = diagnose("step", &target, Some(&compiler), None);
        assert_eq!(result.exact_instructions, Some(true));
        assert_eq!(result.exact_relocations, Some(true));
        assert!(!result.exact_object_bytes);
        // Do not hide different instructions, symbols, addends or malformed sites.
        for candidate in [ppc_object(4, kind, 0, 2), ppc_object(2, kind, 1, 2),
                          ppc_object(2, kind, 0, 3), ppc_object(1, kind, 0, 2)] {
            assert_eq!(diagnose("step", &target, Some(&candidate), None).exact_relocations, Some(false));
        }
        let other = ppc_object(0, object::elf::R_PPC_ADDR16_LO, 0, 2);
        let shifted = ppc_object(2, object::elf::R_PPC_ADDR16_LO, 0, 2);
        assert_eq!(diagnose("step", &other, Some(&shifted), None).exact_relocations, Some(false));
    }

    #[test]
    fn thumb_function_values_do_not_shift_code_or_erase_instruction_set_identity() {
        let mut target = ppc_object(4, object::elf::R_ARM_ABS32, 0, 2);
        let (text, symbols) = {
            let file = object::File::parse(target.as_slice()).unwrap();
            (
                file.section_by_name(".text").unwrap().file_range().unwrap().0 as usize,
                file.section_by_name(".symtab").unwrap().file_range().unwrap().0 as usize,
            )
        };
        target[18..20].copy_from_slice(&object::elf::EM_ARM.to_be_bytes());
        // Big-endian Thumb: adds r0,#1; bx lr; a relocated literal.
        target[text..text + 8].copy_from_slice(&[0x30, 1, 0x47, 0x70, 0, 0, 0, 0]);
        target[symbols + 20..symbols + 24].copy_from_slice(&1u32.to_be_bytes());
        let mut candidate = target.clone();
        candidate.push(0); // Container padding is not part of the function.
        let result = diagnose("step", &target, Some(&candidate), None);
        assert_eq!(result.exact_instructions, Some(true));
        assert_eq!(result.exact_relocations, Some(true));
        assert!(!result.exact_object_bytes);
        // Identical bytes interpreted as ARM are not the same function.
        candidate[symbols + 20..symbols + 24].copy_from_slice(&0u32.to_be_bytes());
        let result = diagnose("step", &target, Some(&candidate), None);
        assert_eq!(result.exact_instructions, None);
        assert_eq!(result.exact_relocations, None);
    }
}
