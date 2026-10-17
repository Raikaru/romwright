//! Code addresses an i386 image only *reads as memory*: the table base of a `jmp [reg*4+table]`.
//!
//! Microsoft's compilers put a switch's jump table in `.text`, behind the function that uses it (Visual C++ 4.x
//! through 8.0 on i386), and a base relocation (or a constant the propagation proves) names the table's address in
//! the `jmp`'s displacement. Such an address is a candidate function entry to every pass that reads relocations or
//! constants, and the bytes behind it decode as plausible instructions. What tells it apart is the *use*: the four
//! bytes are the displacement of a memory operand, `[index*scale+disp32]` or `[disp32]`, so the program reads data
//! there. A function pointer is used as a value (`push offset f`, `mov reg, imm32`, a pointer in a data table).
//!
//! The rule is on the instruction bytes (ModRM/SIB), which the importer already has, and is limited to an i386 PE.
//! A target some reference uses as a value stays a candidate.
//!
//! The other reference that is not evidence of a function is a structured-exception *scope table* record
//! (`{EnclosingLevel, FilterFunc, HandlerFunc}`, Visual C++ 7.0 and later): its filter and handler are blocks of the
//! function that pushes the table, reached by the exception dispatcher, not entries.

use std::collections::{HashMap, HashSet};

use crate::native::NativeImport;

fn bytes_at(imp: &NativeImport, address: u64, len: usize) -> Option<&[u8]> {
    let mapping = imp
        .mappings
        .iter()
        .find(|mapping| address >= mapping.vaddr && address - mapping.vaddr < mapping.size)?;
    let offset = (address - mapping.vaddr) as usize;
    mapping.bytes.get(offset..offset.checked_add(len)?)
}

/// One-byte opcodes that carry a ModRM byte and read or write the memory operand it names, not `lea` (which
/// takes an address as a value) and not the shifts/`mov r/m, imm` forms whose memory operand is the target of a
/// store (still a data access, so they stay in).
fn takes_modrm(opcode: u8) -> bool {
    match opcode {
        0x00..=0x3f => opcode & 7 < 4,
        0x62 | 0x63 | 0x69 | 0x6b => true,
        0x80..=0x8b | 0x8f => true,
        0xc0 | 0xc1 | 0xc4..=0xc7 => true,
        0xd0..=0xd3 | 0xd8..=0xdf => true,
        0xf6 | 0xf7 | 0xfe | 0xff => true,
        _ => false,
    }
}

/// The opcodes compilers use for the data accesses that name a table or an array with a plain displacement
/// (`mov`, the ALU r/m forms, `cmp`, `test`, `xchg`, the immediate groups, the FPU, `call`/`jmp`/`push` `[m]`). Narrower
/// than [`takes_modrm`]: where the operand has no SIB byte, the bytes in front of a `mov reg, imm32` or an `add eax,
/// imm32` read as a ModRM byte too, and the previous instruction's last byte is arbitrary, so an opcode that such a byte
/// seldom equals (not `0x00`, the commonest) has to stand in front of it.
fn takes_data_modrm(opcode: u8) -> bool {
    matches!(opcode,
        0x02 | 0x03 | 0x0a | 0x0b | 0x12 | 0x13 | 0x1a | 0x1b | 0x22 | 0x23 | 0x2a | 0x2b | 0x32 | 0x33 | 0x3a | 0x3b
        | 0x38 | 0x39 | 0x62 | 0x63 | 0x69 | 0x6b | 0x80 | 0x81 | 0x83..=0x8b | 0x8f | 0xc0 | 0xc1 | 0xc6 | 0xc7
        | 0xd0..=0xdf | 0xf6 | 0xf7 | 0xfe | 0xff)
}

/// Whether the four bytes at `site` are the `disp32` of a memory operand: `[index*scale+disp32]` (a SIB byte whose
/// base is the "none" encoding) or `[disp32]` (ModRM `mod=00 rm=101`), or the moffs of `mov al/eax, [..]`/`mov [..], al/eax`.
pub(in crate::native) fn site_is_memory_displacement(imp: &NativeImport, site: u64) -> bool {
    let Some(before) = site.checked_sub(3).and_then(|start| bytes_at(imp, start, 3)) else {
        return false;
    };
    let (b3, b2, b1) = (before[0], before[1], before[2]);
    // The byte before them may be the instruction's prefix-escape (`0f`); absent at the start of a mapping.
    let b4 = site.checked_sub(4).and_then(|at| bytes_at(imp, at, 1)).map_or(0, |byte| byte[0]);
    let broad = |modrm_at: u8, escape_at: u8| takes_modrm(modrm_at) || escape_at == 0x0f;
    let narrow = |modrm_at: u8, escape_at: u8| takes_data_modrm(modrm_at) || escape_at == 0x0f;
    // [index*scale + disp32]: ModRM mod=00 rm=100, SIB base=101: a shape that is nothing else.
    if b2 & 0xc7 == 0x04 && b1 & 7 == 5 && broad(b3, b4) {
        return true;
    }
    // [disp32]: ModRM mod=00 rm=101.
    if b1 & 0xc7 == 0x05 && narrow(b2, b3) {
        return true;
    }
    // [base + disp32] and [base + index*scale + disp32]: ModRM mod=10 (no SIB, or SIB follows the ModRM byte).
    // (`0xb8..=0xbf` is also `mov reg, imm32`: the four bytes after it are a value, and the byte before it any byte.)
    if b1 & 0xc0 == 0x80 && b1 & 7 != 4 && !matches!(b1, 0xb8..=0xbf) && narrow(b2, b3) {
        return true;
    }
    if b2 & 0xc0 == 0x80 && b2 & 7 == 4 && narrow(b3, b4) {
        return true;
    }
    // moffs32 forms.
    matches!(b1, 0xa0..=0xa3)
}

/// Whether the byte(s) before `address` are what a linker or compiler puts between functions: `int3`, `nop`, a
/// multi-byte nop, or zero fill.
pub(in crate::native) fn follows_fill(imp: &NativeImport, address: u64) -> bool {
    const NOPS: [&[u8]; 8] = [
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x8d, 0x74, 0x26, 0x00],
        &[0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00],
        &[0x8d, 0x76, 0x00],
    ];
    let Some(before) = address.checked_sub(8).and_then(|start| bytes_at(imp, start, 8)) else {
        return false;
    };
    matches!(before[7], 0xcc | 0x90) || before.ends_with(&[0, 0, 0]) || NOPS.iter().any(|nop| before.ends_with(nop))
}

/// Targets of the case-label tables nothing has decoded yet: a run of three or more adjacent relocated data words
/// naming code, none an entry, most of whose targets do not follow function fill (or four or more in which an
/// address recurs). Functions a compiler lays out
/// start on fill (`int3`, `nop`s), so a run of targets packed inside one routine is a jump table even when no
/// walk has reached the labels (the CRT's hand-written floating-point helpers).
pub(in crate::native) fn dense_table_targets(imp: &NativeImport, entry: impl Fn(u64) -> bool) -> HashSet<u64> {
    if imp.format != "PE"
        || !crate::compiler::rules::applies("pe-dense-case-tables", &crate::compiler::ctx_of(imp))
    {
        return HashSet::new();
    }
    let in_code = |address: u64| {
        imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0 && address >= mapping.vaddr && address - mapping.vaddr < mapping.size
        })
    };
    let width: u64 = if imp.language.contains(":64:") { 8 } else { 4 };
    let mut words: Vec<(u64, u64)> = imp
        .xrefs
        .iter()
        .filter(|x| x.kind == "DATA" && x.provenance == "native-import:pe-reloc")
        .filter(|x| in_code(x.to) && !in_code(x.from))
        .map(|x| (x.from, x.to))
        .collect();
    words.sort_unstable();
    words.dedup_by_key(|&mut (from, _)| from);
    let mut tables = HashSet::new();
    let mut elsewhere = HashSet::new();
    let mut start = 0;
    for index in 1..=words.len() {
        if index < words.len() && words[index].0 == words[index - 1].0 + width {
            continue;
        }
        let run = &words[start..index];
        let unaligned = run.iter().filter(|&&(_, target)| !follows_fill(imp, target)).count();
        // A run in which one code address recurs (a switch's default case fills the gaps in its case values) is a table
        // whatever the labels follow: no array of functions names the same function twice running.
        let mut distinct: Vec<u64> = run.iter().map(|&(_, target)| target).collect();
        distinct.sort_unstable();
        distinct.dedup();
        let repeats = run.len() >= 4 && distinct.len() < run.len();
        let table = run.len() >= 3
            && !run.iter().any(|&(_, target)| entry(target))
            && (unaligned * 3 >= run.len() * 2 || repeats);
        for &(_, target) in run {
            if table {
                tables.insert(target);
            } else {
                elsewhere.insert(target);
            }
        }
        start = index;
    }
    tables.retain(|target| !elsewhere.contains(target));
    tables
}

fn word_at(imp: &NativeImport, address: u64) -> Option<u32> {
    let bytes = bytes_at(imp, address, 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// A scope-table level: the "none" markers of an outermost record. A nested record's level is a small index, which a
/// float `0.0` or a count equals just as well (Quake 2's `mframe_t {aifunc, dist, thinkfunc}` arrays read as scope
/// records with it: 62 of the game module's functions), so only the markers count.
fn is_level(value: u32) -> bool {
    value == 0xffff_fffe || value == 0xffff_ffff
}

/// Whether the data word at `site` is the filter or the handler of an exception scope-table record.
pub(in crate::native) fn is_scope_table_site(imp: &NativeImport, site: u64, in_code: &dyn Fn(u64) -> bool) -> bool {
    let word = |at: Option<u64>| at.and_then(|at| word_at(imp, at));
    let code = |value: Option<u32>| value.is_some_and(|value| in_code(u64::from(value)));
    // The handler: {level, filter or 0, handler = site}.
    let handler = word(site.checked_sub(8)).is_some_and(is_level)
        && (word(site.checked_sub(4)) == Some(0) || code(word(site.checked_sub(4))));
    // The filter: {level, filter = site, handler}.
    let filter = word(site.checked_sub(4)).is_some_and(is_level) && code(word(Some(site + 4)));
    handler || filter
}

/// Code addresses an image names only as memory operands or scope-table records: every reference to them is an
/// instruction's memory displacement or such a record, and none uses the address as a value.
pub(in crate::native) fn memory_operand_only_targets(imp: &NativeImport) -> HashSet<u64> {
    if imp.format != "PE" || imp.language != "x86:LE:32:default" {
        return HashSet::new();
    }
    let ctx = crate::compiler::ctx_of(imp);
    let operands = crate::compiler::rules::applies("pe-x86-memory-operands", &ctx);
    let scopes = crate::compiler::rules::applies("pe-x86-scope-tables", &ctx);
    if !operands && !scopes {
        return HashSet::new();
    }
    let in_code = |address: u64| {
        imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0 && address >= mapping.vaddr && address - mapping.vaddr < mapping.size
        })
    };
    let lengths: HashMap<u64, u8> = imp.flow_shapes.iter().map(|shape| (shape.address, shape.length)).collect();
    let mut operand: HashSet<u64> = HashSet::new();
    let mut value: HashSet<u64> = HashSet::new();
    for xref in &imp.xrefs {
        if xref.kind != "DATA" || !in_code(xref.to) {
            continue;
        }
        match xref.provenance.as_str() {
            "native-import:pe-reloc" => {
                if operands && in_code(xref.from) && site_is_memory_displacement(imp, xref.from)
                    || scopes && !in_code(xref.from) && is_scope_table_site(imp, xref.from, &in_code)
                {
                    operand.insert(xref.to);
                } else {
                    value.insert(xref.to);
                }
            }
            "native-analysis:constant-propagation" if operands => {
                // `from` is the instruction; find where it holds the constant.
                let length = lengths.get(&xref.from).map_or(15, |&length| length as usize);
                let Some(bytes) = bytes_at(imp, xref.from, length).or_else(|| bytes_at(imp, xref.from, 1)) else {
                    value.insert(xref.to);
                    continue;
                };
                let needle = (xref.to as u32).to_le_bytes();
                let mut hits = 0;
                let mut operands = 0;
                for at in 0..bytes.len().saturating_sub(3) {
                    if bytes[at..at + 4] == needle {
                        hits += 1;
                        if site_is_memory_displacement(imp, xref.from + at as u64) {
                            operands += 1;
                        }
                    }
                }
                if hits > 0 && hits == operands {
                    operand.insert(xref.to);
                } else {
                    value.insert(xref.to);
                }
            }
            _ => {}
        }
    }
    operand.retain(|target| !value.contains(target));
    operand
}

/// Data words that are the filter or handler of an exception scope-table record.
pub(in crate::native) fn scope_table_sites(imp: &NativeImport) -> HashSet<u64> {
    if imp.format != "PE"
        || imp.language != "x86:LE:32:default"
        || !crate::compiler::rules::applies("pe-x86-scope-tables", &crate::compiler::ctx_of(imp))
    {
        return HashSet::new();
    }
    let in_code = |address: u64| {
        imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0 && address >= mapping.vaddr && address - mapping.vaddr < mapping.size
        })
    };
    imp.xrefs
        .iter()
        .filter(|xref| xref.kind == "DATA" && xref.provenance == "native-import:pe-reloc")
        .filter(|xref| in_code(xref.to) && !in_code(xref.from) && is_scope_table_site(imp, xref.from, &in_code))
        .map(|xref| xref.from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{Mapping, NativeXref};

    fn image(code: Vec<u8>) -> NativeImport {
        NativeImport {
            format: "PE".into(),
            language: "x86:LE:32:default".into(),
            mappings: vec![Mapping { vaddr: 0x401000, size: code.len() as u64, file_off: 0, flags: 5, bytes: code }],
            ..Default::default()
        }
    }

    #[test]
    fn a_jump_table_base_is_a_memory_operand_and_a_pushed_function_is_a_value() {
        // 0x401000: jmp [eax*4 + 0x401020]   ff 24 85 20 10 40 00
        // 0x401007: push 0x401030            68 30 10 40 00
        let mut code = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0x40, 0x00, 0x68, 0x30, 0x10, 0x40, 0x00];
        code.resize(0x40, 0xcc);
        let mut imp = image(code);
        imp.xrefs.push(NativeXref::with_provenance(0x401003, 0x401020, "DATA", "native-import:pe-reloc"));
        imp.xrefs.push(NativeXref::with_provenance(0x401008, 0x401030, "DATA", "native-import:pe-reloc"));
        let targets = memory_operand_only_targets(&imp);
        assert!(targets.contains(&0x401020), "a table base is data");
        assert!(!targets.contains(&0x401030), "a pushed address is a value");
    }

    #[test]
    fn a_constant_the_propagation_found_in_an_indexed_load_is_data() {
        // mov eax, [ecx*4 + 0x401020]   8b 04 8d 20 10 40 00
        let mut code = vec![0x8b, 0x04, 0x8d, 0x20, 0x10, 0x40, 0x00];
        code.resize(0x40, 0xcc);
        let mut imp = image(code);
        imp.xrefs.push(NativeXref::with_provenance(0x401000, 0x401020, "DATA", "native-analysis:constant-propagation"));
        assert!(memory_operand_only_targets(&imp).contains(&0x401020));
    }

    #[test]
    fn a_scope_table_handler_is_not_an_entry() {
        // data at 0x402000: {-2, 0, 0x401010} then a lone pointer table {0x401020, 0x401030}
        let mut code = vec![0xcc; 0x40];
        code[0x10] = 0xc3;
        let mut imp = image(code);
        // the scope-table rule covers Visual C++ images
        imp.identity = Some(crate::compiler::Detection::found("msvc-14", crate::compiler::Confidence::High, vec![]));
        let mut data = Vec::new();
        for word in [0xffff_fffeu32, 0, 0x401010, 0x1234_5678, 0x401020, 0x401030] {
            data.extend(word.to_le_bytes());
        }
        imp.mappings.push(Mapping { vaddr: 0x402000, size: data.len() as u64, file_off: 0, flags: 1, bytes: data });
        imp.xrefs.push(NativeXref::with_provenance(0x402008, 0x401010, "DATA", "native-import:pe-reloc"));
        imp.xrefs.push(NativeXref::with_provenance(0x402010, 0x401020, "DATA", "native-import:pe-reloc"));
        imp.xrefs.push(NativeXref::with_provenance(0x402014, 0x401030, "DATA", "native-import:pe-reloc"));
        let targets = memory_operand_only_targets(&imp);
        assert!(targets.contains(&0x401010), "the handler of a scope record");
        assert!(!targets.contains(&0x401020) && !targets.contains(&0x401030), "a plain pointer table is not");
    }

    #[test]
    fn a_table_indexed_through_a_base_register_is_data_too() {
        // movzx ecx, byte ptr [eax + 0x401020]   0f b6 88 20 10 40 00
        let mut code = vec![0x0f, 0xb6, 0x88, 0x20, 0x10, 0x40, 0x00];
        code.resize(0x40, 0xcc);
        let mut imp = image(code);
        imp.xrefs.push(NativeXref::with_provenance(0x401003, 0x401020, "DATA", "native-import:pe-reloc"));
        assert!(memory_operand_only_targets(&imp).contains(&0x401020));
    }

    #[test]
    fn a_function_address_moved_into_a_register_is_a_value_whatever_precedes_it() {
        // mov ecx, [edx]  (8b 0a) then mov edi, 0x401020 (bf 20 10 40 00): the byte before the opcode is `0a`, the
        // opcode `bf` reads as a ModRM `[edi+disp32]` byte
        let mut code = vec![0x8b, 0x8b, 0xbf, 0x20, 0x10, 0x40, 0x00];
        code.resize(0x40, 0xcc);
        let mut imp = image(code);
        imp.xrefs.push(NativeXref::with_provenance(0x401003, 0x401020, "DATA", "native-import:pe-reloc"));
        assert!(memory_operand_only_targets(&imp).is_empty());
    }

    #[test]
    fn a_run_of_packed_labels_is_a_table_and_aligned_functions_are_not() {
        // three labels 9 bytes apart in one routine, then three functions on int3 fill
        let mut code = vec![0x8b; 0x100];
        for at in [0x20usize, 0x29, 0x32] {
            code[at] = 0x55;
        }
        for at in [0x80usize, 0xa0, 0xc0] {
            code[at - 1] = 0xcc;
            code[at] = 0x55;
        }
        let mut imp = image(code);
        let mut data = Vec::new();
        for target in [0x401020u32, 0x401029, 0x401032, 0x401080, 0x4010a0, 0x4010c0] {
            data.extend(target.to_le_bytes());
        }
        // two runs: a gap word between the labels and the functions
        data.splice(12..12, 0u32.to_le_bytes());
        imp.mappings.push(Mapping { vaddr: 0x402000, size: data.len() as u64, file_off: 0, flags: 1, bytes: data });
        for (at, target) in [(0x402000u64, 0x401020u64), (0x402004, 0x401029), (0x402008, 0x401032), (0x402010, 0x401080), (0x402014, 0x4010a0), (0x402018, 0x4010c0)] {
            imp.xrefs.push(NativeXref::with_provenance(at, target, "DATA", "native-import:pe-reloc"));
        }
        let tables = dense_table_targets(&imp, |_| false);
        assert!(tables.contains(&0x401020) && tables.contains(&0x401032));
        assert!(!tables.contains(&0x401080) && !tables.contains(&0x4010c0));
        // functions on fill, the first named twice: a table of case labels with a default, whatever they follow
        let mut code = vec![0x8b; 0x100];
        for at in [0x80usize, 0xa0, 0xc0] {
            code[at - 1] = 0xcc;
        }
        let mut repeated = image(code);
        repeated.mappings.push(Mapping { vaddr: 0x402000, size: 16, file_off: 0, flags: 1, bytes: vec![0; 16] });
        for (at, target) in [(0x402000u64, 0x401080u64), (0x402004, 0x4010a0), (0x402008, 0x401080), (0x40200c, 0x4010c0)] {
            repeated.xrefs.push(NativeXref::with_provenance(at, target, "DATA", "native-import:pe-reloc"));
        }
        assert!(dense_table_targets(&repeated, |_| false).contains(&0x4010a0));
        repeated.xrefs.truncate(3);
        repeated.xrefs[2].to = 0x4010c0;
        assert!(dense_table_targets(&repeated, |_| false).is_empty(), "three distinct functions on fill are an array of functions");
    }

    #[test]
    fn one_value_use_keeps_the_address_a_candidate() {
        let mut code = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0x40, 0x00, 0xb8, 0x20, 0x10, 0x40, 0x00];
        code.resize(0x40, 0xcc);
        let mut imp = image(code);
        imp.xrefs.push(NativeXref::with_provenance(0x401003, 0x401020, "DATA", "native-import:pe-reloc"));
        imp.xrefs.push(NativeXref::with_provenance(0x401008, 0x401020, "DATA", "native-import:pe-reloc"));
        assert!(memory_operand_only_targets(&imp).is_empty());
    }
}
