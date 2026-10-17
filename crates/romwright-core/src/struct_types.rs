//! Struct layouts in the decompiled C.
//!
//! Three jobs, one vocabulary (`romwright_model::structs`):
//!
//! * **Synthesis**: a pointer parameter the solver proved is dereferenced at
//!   several offsets (`Ty::Ptr(Ty::Struct)`) becomes `struct fn_<entry>_arg<n>`
//!   holding only the fields the body accesses; the rest is padding. A
//!   [`gate`] keeps the inference from naming a struct where the evidence is
//!   an array or a scalar pointer indexed at constant offsets.
//! * **Reading** the stored layouts the mode lets through ([`StructTable`]).
//! * **Printing**: the `typedef`/`struct` definitions a printed function
//!   names ([`StructTable::definitions`]), so the C it prints compiles.

use std::collections::{BTreeMap, BTreeSet};

use crate::types_infer::{Field, Ty};
use romwright_model::structs::{
    self, StructField, StructLayout, StructMode, TypeSpelling, INFERRED_SOURCE,
};
use romwright_model::type_evidence::Class;

/// Whether the accessed fields are an array: every one the same width and
/// each right after the one before it, from wherever the run starts. That is
/// what `p[2]`, `p[3]`, `p[4]` of a scalar or float pointer looks like, and a
/// matrix or a vector held in a `float *` looks no different from three floats
/// of a struct.
pub fn array_run(fields: &BTreeMap<i64, Field>) -> bool {
    let Some(first) = fields.values().next() else { return false };
    fields
        .values()
        .enumerate()
        .all(|(index, field)| field.size == first.size && field.offset == first.offset + index as i64 * i64::from(first.size))
}

/// Fewest distinct fields a struct needs.
pub const MIN_FIELDS: usize = 3;

/// Whether an inferred layout is evidence of a struct: at least
/// [`MIN_FIELDS`] fields that are not an [array run](array_run). See
/// `benchmarks/struct_gate_sweep.py` for the measurement the thresholds come
/// from and `docs/structs.md` for the trade-off.
pub fn gate(fields: &BTreeMap<i64, Field>) -> bool {
    fields.len() >= MIN_FIELDS && !array_run(fields)
}

/// Whether a pointer field to a run of one scalar is typed `T *` (`ROMWRIGHT_STRUCT_POINTEE_RUNS`, default on).
fn pointee_run_enabled() -> bool {
    std::env::var("ROMWRIGHT_STRUCT_POINTEE_RUNS").map_or(true, |mode| mode != "off")
}

/// The type a field of this evidence is declared with: what the first use
/// proved, and for a value of no proven kind `undefined<N>`, which is what
/// Ghidra spells it and which takes whatever the use makes of it (an `int`
/// there would turn a float's bit move into a conversion). A word typed
/// `undefined4` instead of `int`/`uint` was tried for the locals it types
/// and dropped: the decompiler casts nothing that is stored into an undefined
/// field, so a stored pointer prints uncast and MWCC rejects the assignment
/// (`illegal implicit conversion from 'unsigned char *'`, m22-002 lane 1).
pub fn field_type(class: Class, size: u32) -> String {
    match (class, size) {
        (Class::Float(_), 4) => "float".into(),
        (Class::Float(_), 8) => "double".into(),
        (Class::Ptr, _) => "void *".into(),
        (Class::Code, _) => "code *".into(),
        (Class::Int(_), 1) => "char".into(),
        (Class::Int(_), 2) => "short".into(),
        (Class::Int(_), 4) => "int".into(),
        (Class::Int(_), 8) => "longlong".into(),
        (Class::Uint(_), 1) => "byte".into(),
        (Class::Uint(_), 2) => "ushort".into(),
        (Class::Uint(_), 4) => "uint".into(),
        (Class::Uint(_), 8) => "ulonglong".into(),
        (_, 1 | 2 | 4 | 8) => format!("undefined{size}"),
        (_, size) => format!("byte[{size}]"),
    }
}

/// The natural alignment of a field of `size` bytes in a C struct.
fn alignment(size: u32) -> i64 {
    i64::from(size.clamp(1, 8))
}

/// Fields as a C compiler would lay them out: sorted, one per offset, none
/// overlapping an earlier one (the wider wins a tie), each at a multiple of its
/// natural alignment (one that is not could not sit there in a C struct).
fn placeable(fields: &BTreeMap<i64, Field>) -> Vec<Field> {
    let mut all: Vec<Field> = fields
        .values()
        .copied()
        .filter(|field| field.offset >= 0 && field.size > 0 && field.offset % alignment(field.size) == 0)
        .collect();
    all.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));
    let mut kept: Vec<Field> = Vec::new();
    let mut covered = 0i64;
    for field in all {
        if field.offset < covered {
            continue;
        }
        covered = field.offset + i64::from(field.size);
        kept.push(field);
    }
    kept
}

/// [`placeable`] fields keyed by offset.
fn placed(fields: &BTreeMap<i64, Field>) -> BTreeMap<i64, Field> {
    placeable(fields).into_iter().map(|field| (field.offset, field)).collect()
}

/// The layouts for a function's `index`th pointer parameter, from the type the
/// solver proved for it and the layouts it proved for the pointers loaded from
/// its fields: the parameter's own struct first, then one per such pointee
/// that is a struct. Empty when the evidence does not pass the [`gate`].
pub fn synthesize(
    entry: u64,
    index: usize,
    ty: &Ty,
    pointees: &BTreeMap<i64, Ty>,
) -> Vec<StructLayout> {
    let Ty::Ptr(inner) = ty else { return Vec::new() };
    let Ty::Struct(fields) = inner.as_ref() else { return Vec::new() };
    // The gate looks at what would be printed: fields a C struct could not
    // hold at those offsets are not evidence of one.
    let fields = placed(fields);
    if !gate(&fields) {
        return Vec::new();
    }
    let name = structs::inferred_name(entry, index);
    let mut out = Vec::new();
    let mut members = Vec::new();
    let mut nested = Vec::new();
    for field in fields.values().copied() {
        let mut type_ref = field_type(field.class, field.size);
        if field.class == Class::Ptr && field.size == 4
            && let Some(Ty::Ptr(pointee)) = pointees.get(&field.offset) { match pointee.as_ref() {
                Ty::Struct(inner_fields) if gate(&placed(inner_fields)) => {
                    let pointee_name = structs::inferred_pointee_name(&name, field.offset);
                    nested.push((pointee_name.clone(), placed(inner_fields)));
                    type_ref = format!("{pointee_name} *");
                }
                // Two or more accesses at consecutive offsets of one width: a vector or a table, not a
                // struct (`float *`, `u_short *`). `ROMWRIGHT_STRUCT_POINTEE_RUNS=off` leaves it `void *`.
                Ty::Struct(inner_fields) if pointee_run_enabled() => {
                    let inner = placed(inner_fields);
                    if inner.len() >= 2
                        && array_run(&inner)
                        && let Some(first) = inner.values().next()
                        && matches!(first.class, Class::Float(_) | Class::Int(_) | Class::Uint(_))
                    {
                        let spelled = field_type(first.class, first.size);
                        if !spelled.contains('[') && !spelled.starts_with("undefined") {
                            type_ref = format!("{spelled} *");
                        }
                    }
                }
                Ty::Scalar(class) if !matches!(class, Class::Unknown | Class::Top) => {
                    let spelled = field_type(*class, class.width() / 8);
                    type_ref = if spelled.contains('[') { "void *".into() } else { format!("{spelled} *") };
                }
                _ => {}
            } }
        members.push(StructField {
            name: format!("field_0x{:x}", field.offset),
            offset: field.offset as u64,
            size: u64::from(field.size),
            type_ref,
        });
    }
    if members.is_empty() {
        return out;
    }
    let size = members.iter().map(|m| m.offset + m.size).max().unwrap_or(0);
    out.push(StructLayout { name, size, provenance: INFERRED_SOURCE.into(), fields: members });
    for (pointee_name, inner_fields) in nested {
        let members: Vec<StructField> = placeable(&inner_fields)
            .into_iter()
            .map(|field| StructField {
                name: format!("field_0x{:x}", field.offset),
                offset: field.offset as u64,
                size: u64::from(field.size),
                type_ref: field_type(field.class, field.size),
            })
            .collect();
        if members.is_empty() {
            continue;
        }
        let size = members.iter().map(|m| m.offset + m.size).max().unwrap_or(0);
        out.push(StructLayout { name: pointee_name, size, provenance: INFERRED_SOURCE.into(), fields: members });
    }
    // A pointer field to a pointee that came to nothing keeps `void *`; one
    // whose pointee layout was written names it. Drop a name that no layout
    // answers.
    let written: BTreeSet<String> = out.iter().map(|layout| layout.name.clone()).collect();
    for layout in &mut out {
        for field in &mut layout.fields {
            if let Some(target) = field.type_ref.strip_suffix(" *")
                && structs::is_inferred_name(target)
                && !written.contains(target)
            {
                field.type_ref = "void *".into();
            }
        }
    }
    out
}

/// The layouts a mode shows, by name.
#[derive(Debug, Default, Clone)]
pub struct StructTable {
    layouts: BTreeMap<String, StructLayout>,
}

impl StructTable {
    /// The program's stored layouts that `mode` allows.
    pub fn load(
        db: &romwright_db::ProjectDb,
        program: romwright_model::ProgramId,
        mode: StructMode,
    ) -> crate::Result<StructTable> {
        if mode == StructMode::Off {
            return Ok(StructTable::default());
        }
        let defs = db.type_defs(program)?;
        if defs.iter().all(|def| def.kind != "struct") {
            return Ok(StructTable::default());
        }
        let fields = db.type_fields(program, None)?;
        Ok(StructTable::from_layouts(structs::layouts(&defs, &fields), mode))
    }

    pub fn from_layouts(layouts: Vec<StructLayout>, mode: StructMode) -> StructTable {
        StructTable {
            layouts: layouts
                .into_iter()
                .filter(|layout| mode.allows(layout.source()))
                .map(|layout| (layout.name.clone(), layout))
                .collect(),
        }
    }

    /// Whether `text` takes the address of a member the layouts of the structs it
    /// names say nothing typed of: a gap the printer named (`&p->field_0x20`)
    /// or an `undefined<N>` field. The decompiler leaves that address uncast
    /// where it is passed on as a `float *` (an undefined type fits any), and
    /// the printed `unsigned char *` does not convert to one in C++: a layout
    /// that cannot tell what is at the address it hands out is not worth
    /// printing, so the caller keeps the function untyped.
    pub fn takes_untyped_address(&self, text: &str) -> bool {
        let in_text = words(text);
        let typed: BTreeSet<&str> = self
            .layouts
            .values()
            .filter(|layout| in_text.contains(layout.name.as_str()))
            .flat_map(|layout| &layout.fields)
            .filter(|field| !field.type_ref.starts_with("undefined"))
            .map(|field| field.name.as_str())
            .collect();
        text.match_indices("field_0x").any(|(at, _)| {
            let name: String = text[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            !typed.contains(name.as_str()) && address_of_member(text, at)
        })
    }

    /// Whether `text` converts a member by a cast placed directly on it where
    /// the untyped text moved bits: an integer cast on a `float`/`double`
    /// member (`(unsigned int)p->field_0x48`, the same word read as a float and
    /// copied as bits: one `float` field turns the copy into a numeric
    /// conversion, m22-003 dds `func_0016F7B0`, 250 instructions became 309), or
    /// a float cast on an `undefined<N>` member (`(float)p->field_0x10`: the
    /// decompiler converts an undefined type to the float a compare wants where
    /// the bits were meant, m22-003 dc `SetPosition__9mgCObjectFPf`, 100 to 0).
    pub fn converts_float_member(&self, text: &str) -> bool {
        let in_text = words(text);
        let fields = || {
            self.layouts
                .values()
                .filter(|layout| in_text.contains(layout.name.as_str()))
                .flat_map(|layout| &layout.fields)
        };
        let floats: BTreeSet<&str> = fields()
            .filter(|field| matches!(field.type_ref.as_str(), "float" | "double"))
            .map(|field| field.name.as_str())
            .collect();
        let undefined: BTreeSet<&str> = fields()
            .filter(|field| field.type_ref.starts_with("undefined"))
            .map(|field| field.name.as_str())
            .collect();
        text.match_indices("field_0x").any(|(at, _)| {
            let name: String = text[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            (floats.contains(name.as_str()) && integer_cast_on_member(text, at))
                || (undefined.contains(name.as_str()) && float_cast_on_member(text, at))
        })
    }

    /// Whether the printed function is one the layouts misstate: it takes the
    /// address of a member they know nothing typed of, or converts a float member
    /// where the untyped text copied bits. Such a function is kept untyped.
    pub fn misprints(&self, text: &str) -> bool {
        self.takes_untyped_address(text) || self.converts_float_member(text)
    }

    /// The definitions of every struct `text` names, and of those they name,
    /// as C: a forward `typedef` per struct (the decompiler prints a struct by
    /// its bare name), then the bodies, a struct held by value after the one it
    /// is held in. Names `declared` already holds (the project's own header)
    /// are not defined again. Empty when `text` names no struct.
    pub fn definitions(&self, text: &str, declared: &str) -> String {
        if self.layouts.is_empty() {
            return String::new();
        }
        let in_text = words(text);
        let in_header = words(declared);
        let named = named_offsets(text);
        let mut wanted: BTreeSet<&str> = BTreeSet::new();
        let mut queue: Vec<&str> = self
            .layouts
            .keys()
            .map(String::as_str)
            .filter(|name| in_text.contains(*name) && !in_header.contains(*name))
            .collect();
        while let Some(name) = queue.pop() {
            if !wanted.insert(name) {
                continue;
            }
            let Some(layout) = self.layouts.get(name) else { continue };
            for field in &layout.fields {
                let Some(spelling) = TypeSpelling::parse(&field.type_ref) else { continue };
                let target = base_name(&spelling);
                if let Some((known, _)) = self.layouts.get_key_value(target)
                    && !in_header.contains(known.as_str())
                {
                    queue.push(known.as_str());
                }
            }
        }
        if wanted.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for name in &wanted {
            out.push_str(&format!("typedef struct {name} {name};\n"));
        }
        // A struct held by value must be complete before the struct that holds it.
        let mut done: BTreeSet<&str> = BTreeSet::new();
        let mut pending: Vec<&str> = wanted.iter().copied().collect();
        while !pending.is_empty() {
            let before = pending.len();
            let mut rest = Vec::new();
            for name in pending {
                let layout = &self.layouts[name];
                let ready = layout.fields.iter().all(|field| {
                    TypeSpelling::parse(&field.type_ref).is_none_or(|spelling| {
                        by_value_struct(&spelling).is_none_or(|held| {
                            !wanted.contains(held) || done.contains(held) || held == name
                        })
                    })
                });
                if ready {
                    out.push_str(&body(layout, &named));
                    done.insert(name);
                } else {
                    rest.push(name);
                }
            }
            if rest.len() == before {
                // A cycle by value cannot be a C struct; write them as they are.
                for name in rest {
                    out.push_str(&body(&self.layouts[name], &named));
                }
                break;
            }
            pending = rest;
        }
        out
    }
}

/// The identifiers of C text.
fn words(text: &str) -> BTreeSet<&str> {
    let mut found = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
                index += 1;
            }
            found.insert(&text[start..index]);
        } else {
            index += 1;
        }
    }
    found
}

/// The name at the bottom of a type spelling.
fn base_name(spelling: &TypeSpelling) -> &str {
    match spelling {
        TypeSpelling::Name(name) => name,
        TypeSpelling::Pointer(inner) | TypeSpelling::Array(inner, _) => base_name(inner),
    }
}

/// The struct a spelling holds by value (not through a pointer).
fn by_value_struct(spelling: &TypeSpelling) -> Option<&str> {
    match spelling {
        TypeSpelling::Name(name) => Some(name),
        TypeSpelling::Array(inner, _) => by_value_struct(inner),
        TypeSpelling::Pointer(_) => None,
    }
}

/// `type name`, `type *name`, `type name[3]`.
fn declarator(spelling: &TypeSpelling, name: &str) -> String {
    let mut dimensions = String::new();
    let mut inner = spelling;
    while let TypeSpelling::Array(element, count) = inner {
        dimensions.push_str(&format!("[{count}]"));
        inner = element;
    }
    let mut stars = String::new();
    while let TypeSpelling::Pointer(target) = inner {
        stars.push('*');
        inner = target;
    }
    let TypeSpelling::Name(base) = inner else { return format!("int {name}") };
    if base == "code" && !stars.is_empty() {
        // Ghidra's function type, spelled as C spells a pointer to one.
        return format!("int ({stars}{name}{dimensions})()");
    }
    if stars.is_empty() {
        format!("{base} {name}{dimensions}")
    } else {
        format!("{base} {stars}{name}{dimensions}")
    }
}

/// The offsets the text names as `field_0x<hex>`. The printer names an
/// offset it reaches inside a struct that has no field there that way
/// (`printc.cc`:1019: a member of an array element, an access into a gap), so
/// the definition must hold a member of that name.
fn named_offsets(text: &str) -> BTreeSet<u64> {
    let mut found = BTreeSet::new();
    for (at, _) in text.match_indices("field_0x") {
        let digits: String = text[at + 8..].chars().take_while(char::is_ascii_hexdigit).collect();
        if let Ok(offset) = u64::from_str_radix(&digits, 16) {
            found.insert(offset);
        }
    }
    found
}

/// Where the operand a member is read from begins: back over `p`, `a->b`,
/// `a[1].b`, `((S *)p)`.
fn operand_start(text: &str, mut end: usize) -> usize {
    let bytes = text.as_bytes();
    loop {
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        match bytes.get(end.wrapping_sub(1)) {
            Some(b')') | Some(b']') => {
                let (close, open) = if bytes[end - 1] == b')' { (b')', b'(') } else { (b']', b'[') };
                let mut depth = 0usize;
                let mut at = end;
                while at > 0 {
                    at -= 1;
                    if bytes[at] == close {
                        depth += 1;
                    } else if bytes[at] == open {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break;
                        }
                    }
                }
                end = at;
                if close == b')' {
                    // `f(x)->m` is a call; `((S *)p)->m` after a cast `(int)` is a group of its own.
                    let mut prior = at;
                    while prior > 0 && bytes[prior - 1].is_ascii_whitespace() {
                        prior -= 1;
                    }
                    if !(prior > 0 && (bytes[prior - 1].is_ascii_alphanumeric() || bytes[prior - 1] == b'_')) {
                        return end;
                    }
                }
                continue;
            }
            Some(byte) if byte.is_ascii_alphanumeric() || *byte == b'_' => {
                while end > 0 && (bytes[end - 1].is_ascii_alphanumeric() || bytes[end - 1] == b'_') {
                    end -= 1;
                }
            }
            _ => return end,
        }
        // `a->b` and `a.b` continue the operand; anything else ends it.
        let mut before = end;
        while before > 0 && bytes[before - 1].is_ascii_whitespace() {
            before -= 1;
        }
        if text[..before].ends_with("->") {
            end = before - 2;
        } else if text[..before].ends_with('.') {
            end = before - 1;
        } else {
            return end;
        }
    }
}

/// Whether the member named at `at` has its address taken (`&p->field_0x20`).
fn address_of_member(text: &str, at: usize) -> bool {
    let before = text[..at].trim_end();
    let Some(before) = before.strip_suffix("->").or_else(|| before.strip_suffix('.')) else { return false };
    let start = operand_start(text, before.len());
    let lead = text[..start].trim_end();
    lead.ends_with('&')
        && !lead.ends_with("&&")
        && !lead[..lead.len() - 1]
            .trim_end()
            .bytes()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b')' || c == b']')
}

/// The type a cast spells when the member named at `at` is the whole operand
/// of it: `(unsigned int)((S *)p)->field_0x48` gives `unsigned int`.
fn cast_on_member(text: &str, at: usize) -> Option<&str> {
    let before = text[..at].trim_end();
    let before = before.strip_suffix("->").or_else(|| before.strip_suffix('.'))?;
    let start = operand_start(text, before.len());
    let lead = text[..start].trim_end();
    if !lead.ends_with(')') {
        return None;
    }
    let bytes = lead.as_bytes();
    let mut depth = 0usize;
    let mut open = None;
    for index in (0..bytes.len()).rev() {
        match bytes[index] {
            b')' => depth += 1,
            b'(' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    open = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    Some(lead[open? + 1..lead.len() - 1].trim())
}

/// Whether the member named at `at` is the whole operand of a cast to an
/// integer type: `(unsigned int)((S *)p)->field_0x48`.
fn integer_cast_on_member(text: &str, at: usize) -> bool {
    let Some(kind) = cast_on_member(text, at) else { return false };
    let kind = kind.strip_prefix("unsigned ").or_else(|| kind.strip_prefix("signed ")).unwrap_or(kind);
    matches!(
        kind,
        "int" | "uint" | "short" | "ushort" | "char" | "uchar" | "byte" | "long" | "long long" | "longlong" | "ulonglong"
    )
}

/// Whether the member named at `at` is the whole operand of a cast to
/// `float` or `double`: `(float)p->field_0x10`.
fn float_cast_on_member(text: &str, at: usize) -> bool {
    matches!(cast_on_member(text, at), Some("float" | "double"))
}

/// The width and kind of what a printed cast `(T *)` dereferences: `float`
/// and `double` are `Float`, the integers and every pointer `Bits`. A name
/// the table cannot size (a struct) is `None`.
fn access_shape(kind: &str) -> Option<(u64, bool)> {
    let kind = kind.trim();
    if kind.ends_with('*') {
        return Some((4, false));
    }
    let kind = kind.strip_prefix("unsigned ").or_else(|| kind.strip_prefix("signed ")).unwrap_or(kind);
    Some(match kind {
        "float" => (4, true),
        "double" => (8, true),
        "char" | "uchar" | "byte" | "bool" | "undefined1" => (1, false),
        "short" | "ushort" | "undefined2" => (2, false),
        // `long` is 8 bytes on a MIPS64 language and 4 on a 32-bit one: it is not sized here.
        "int" | "uint" | "undefined4" => (4, false),
        "long long" | "longlong" | "ulonglong" | "undefined8" => (8, false),
        _ => return None,
    })
}

/// What the untyped `text` reads of the parameter `name`: the offset and the
/// cast type `T` of each `*(T *)((int)name + N)`, `*(T *)(name + N)` and
/// `*(T *)name` it prints (the forms the decompiler gives an access through a
/// pointer it has no struct for).
fn read_accesses(text: &str, name: &str) -> Vec<(u64, String)> {
    let bytes = text.as_bytes();
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut found = Vec::new();
    for (at, _) in text.match_indices(name) {
        let end = at + name.len();
        if (at > 0 && word(bytes[at - 1])) || bytes.get(end).is_some_and(|b| word(*b)) {
            continue;
        }
        let mut before = text[..at].trim_end();
        let mut after = text[end..].trim_start();
        let mut offset = 0u64;
        let mut wrapped = false;
        if let Some(rest) = before.strip_suffix("(int)") {
            before = rest.trim_end();
            wrapped = true;
        }
        if wrapped || before.ends_with('(') && after.starts_with('+') {
            let Some(rest) = after.strip_prefix('+') else { continue };
            let rest = rest.trim_start();
            let digits: String = rest.chars().take_while(char::is_ascii_alphanumeric).collect();
            let parsed = match digits.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => digits.parse(),
            };
            let Ok(parsed) = parsed else { continue };
            offset = parsed;
            after = rest[digits.len()..].trim_start();
            if !after.starts_with(')') {
                continue;
            }
            let Some(rest) = before.strip_suffix('(') else { continue };
            before = rest.trim_end();
        } else if after.starts_with('[') || after.starts_with("->") {
            continue;
        }
        // `*(T *)` in front of the operand.
        let Some(rest) = before.strip_suffix(')') else { continue };
        let Some(open) = rest.rfind('(') else { continue };
        if !rest[..open].trim_end().ends_with('*') {
            continue;
        }
        let Some(kind) = rest[open + 1..].trim().strip_suffix('*') else { continue };
        found.push((offset, kind.trim().to_string()));
    }
    found
}

/// Whether the untyped `text` reads the parameter `name` at one offset as two
/// things a struct field cannot be both: a float and bits, or two overlapping
/// widths (`*(int *)p` and `*(unsigned long long *)p`). Such a parameter is
/// not a struct: its one field would turn a bit copy into a conversion, or a
/// 32-bit store into a 64-bit one (m22-003 rc `_sysbitFlush`).
pub fn mixed_accesses(text: &str, name: &str) -> bool {
    let seen: BTreeSet<(u64, u64, bool)> = read_accesses(text, name)
        .into_iter()
        .filter_map(|(offset, kind)| access_shape(&kind).map(|(width, float)| (offset, width, float)))
        .collect();
    let accesses: Vec<&(u64, u64, bool)> = seen.iter().collect();
    accesses.iter().enumerate().any(|(index, a)| {
        accesses[index + 1..].iter().any(|b| {
            let overlap = a.0 < b.0 + b.1 && b.0 < a.0 + a.1;
            overlap && (a.0 != b.0 || a.1 != b.1 || a.2 != b.2)
        })
    })
}

/// The field type the decompiler's own untyped text gives each offset of the
/// parameter `name`: the one type every access at that offset is cast to. An
/// offset read as two things, or as a type with no field spelling (a struct, a
/// plain `long` whose width depends on the target), has no entry.
pub fn access_field_types(text: &str, name: &str) -> BTreeMap<u64, (u32, String)> {
    let mut types: BTreeMap<u64, BTreeSet<(u32, String)>> = BTreeMap::new();
    for (offset, kind) in read_accesses(text, name) {
        if let Some(spelled) = spelling_of_access(&kind) {
            types.entry(offset).or_default().insert(spelled);
        }
    }
    types
        .into_iter()
        .filter_map(|(offset, set)| (set.len() == 1).then(|| (offset, set.into_iter().next().unwrap())))
        .collect()
}

/// The width and field type a printed access cast names.
fn spelling_of_access(kind: &str) -> Option<(u32, String)> {
    let kind = kind.trim();
    if kind.ends_with('*') {
        return Some((4, "void *".into()));
    }
    Some(match kind {
        "float" => (4, "float".into()),
        "double" => (8, "double".into()),
        "char" | "signed char" => (1, "char".into()),
        "unsigned char" | "uchar" | "byte" => (1, "byte".into()),
        "short" | "signed short" => (2, "short".into()),
        "unsigned short" | "ushort" => (2, "ushort".into()),
        "int" | "signed int" => (4, "int".into()),
        "unsigned int" | "uint" => (4, "uint".into()),
        "long long" | "longlong" => (8, "longlong".into()),
        "unsigned long long" | "ulonglong" => (8, "ulonglong".into()),
        _ => return None,
    })
}

/// A gap of `unsigned char` padding from `from` to `to`, with a one-byte member
/// at each offset in `named` that falls inside it.
fn gap(out: &mut String, from: u64, to: u64, named: &BTreeSet<u64>, taken: &BTreeSet<&str>) {
    let mut at = from;
    if to > from {
        for &hole in named.range(from..to) {
            let name = format!("field_0x{hole:x}");
            if taken.contains(name.as_str()) {
                continue;
            }
            if hole > at {
                out.push_str(&format!("    unsigned char pad_0x{at:x}[0x{:x}];\n", hole - at));
            }
            out.push_str(&format!("    unsigned char {name}; /* +0x{hole:x} */\n"));
            at = hole + 1;
        }
    }
    if to > at {
        out.push_str(&format!("    unsigned char pad_0x{at:x}[0x{:x}];\n", to - at));
    }
}

/// One struct body, with `unsigned char` padding where its fields leave a gap,
/// and a one-byte member in a gap at each offset `named` holds.
fn body(layout: &StructLayout, named: &BTreeSet<u64>) -> String {
    let mut out = format!("struct {} {{\n", layout.name);
    let mut end = 0u64;
    let mut fields: Vec<&StructField> = layout.fields.iter().collect();
    fields.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));
    let taken: BTreeSet<&str> = layout.fields.iter().map(|field| field.name.as_str()).collect();
    for field in fields {
        if field.offset < end || field.size == 0 {
            continue;
        }
        let Some(spelling) = TypeSpelling::parse(&field.type_ref) else { continue };
        gap(&mut out, end, field.offset, named, &taken);
        out.push_str(&format!("    {}; /* +0x{:x} */\n", declarator(&spelling, &field.name), field.offset));
        end = field.offset + field.size;
    }
    gap(&mut out, end, layout.size, named, &taken);
    out.push_str("};\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(offset: i64, size: u32, class: Class) -> (i64, Field) {
        (offset, Field { offset, size, class })
    }

    fn ptr_to_struct(fields: &[(i64, Field)]) -> Ty {
        Ty::Ptr(Box::new(Ty::Struct(fields.iter().copied().collect())))
    }

    #[test]
    fn a_struct_is_synthesized_from_accessed_fields_with_padding() {
        let ty = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(8, 4, Class::Float(32)),
            field(0x10, 1, Class::Uint(8)),
        ]);
        let layouts = synthesize(0x80012340, 0, &ty, &BTreeMap::new());
        assert_eq!(layouts.len(), 1);
        let layout = &layouts[0];
        assert_eq!(layout.name, "fn_80012340_arg0");
        assert_eq!(layout.provenance, INFERRED_SOURCE);
        let spelled: Vec<_> = layout.fields.iter().map(|f| (f.offset, f.type_ref.as_str())).collect();
        assert_eq!(spelled, vec![(0, "undefined4"), (8, "float"), (0x10, "byte")]);
        let table = StructTable::from_layouts(layouts, StructMode::Inferred);
        let text = table.definitions("void f(fn_80012340_arg0 *param_1) {}", "");
        assert_eq!(
            text,
            "typedef struct fn_80012340_arg0 fn_80012340_arg0;\n\
             struct fn_80012340_arg0 {\n    undefined4 field_0x0; /* +0x0 */\n    unsigned char pad_0x4[0x4];\n    \
             float field_0x8; /* +0x8 */\n    unsigned char pad_0xc[0x4];\n    byte field_0x10; /* +0x10 */\n};\n"
        );
    }

    #[test]
    fn a_pointer_indexed_at_constant_offsets_is_not_a_struct() {
        // `p[0]`, `p[1]`, `p[2]` of an `int *`: one width, consecutive.
        let array = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(4, 4, Class::Num(32)),
            field(8, 4, Class::Num(32)),
        ]);
        assert!(synthesize(0x1000, 0, &array, &BTreeMap::new()).is_empty());
        // A run of floats is an array (a vector, a matrix) as much as it is a struct.
        let floats = ptr_to_struct(&[
            field(0, 4, Class::Float(32)),
            field(4, 4, Class::Float(32)),
            field(8, 4, Class::Float(32)),
            field(12, 4, Class::Float(32)),
        ]);
        assert!(synthesize(0x1000, 0, &floats, &BTreeMap::new()).is_empty());
        // From wherever it starts: `q[2]`..`q[5]` is as much an array as `q[0]`..`q[3]`.
        let shifted = ptr_to_struct(&[
            field(8, 4, Class::Float(32)),
            field(12, 4, Class::Float(32)),
            field(16, 4, Class::Float(32)),
        ]);
        assert!(synthesize(0x1000, 0, &shifted, &BTreeMap::new()).is_empty());
        // One field is a pointer to a scalar, not a struct.
        let lone = ptr_to_struct(&[field(0x14, 4, Class::Num(32))]);
        assert!(synthesize(0x1000, 0, &lone, &BTreeMap::new()).is_empty());
        // Three fields that are not one width in a row are evidence of a struct.
        let mixed = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(4, 4, Class::Ptr),
            field(0x10, 4, Class::Num(32)),
        ]);
        assert_eq!(synthesize(0x1000, 0, &mixed, &BTreeMap::new()).len(), 1);
        let widths = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(4, 2, Class::Num(16)),
            field(8, 4, Class::Num(32)),
        ]);
        assert_eq!(synthesize(0x1000, 0, &widths, &BTreeMap::new()).len(), 1);
    }

    #[test]
    fn a_loaded_pointer_that_is_dereferenced_is_a_pointer_field_with_its_own_struct() {
        let outer = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(8, 4, Class::Ptr),
            field(0x10, 4, Class::Num(32)),
        ]);
        let inner = ptr_to_struct(&[
            field(0, 4, Class::Float(32)),
            field(4, 4, Class::Float(32)),
            field(0x10, 4, Class::Float(32)),
        ]);
        let pointees = BTreeMap::from([(8, inner)]);
        let layouts = synthesize(0x2000, 1, &outer, &pointees);
        assert_eq!(layouts.len(), 2);
        let pointer_field = layouts[0].fields.iter().find(|f| f.offset == 8).unwrap();
        assert_eq!(pointer_field.type_ref, "fn_00002000_arg1_p8 *");
        assert_eq!(layouts[1].name, "fn_00002000_arg1_p8");
        // Without a struct behind it the field is still a pointer.
        let bare = synthesize(0x2000, 1, &outer, &BTreeMap::new());
        assert_eq!(bare[0].fields.iter().find(|f| f.offset == 8).unwrap().type_ref, "void *");
        // A misaligned or overlapping access never becomes a field, and the
        // gate counts what is left: these leave three.
        let odd = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(2, 4, Class::Num(32)),
            field(3, 1, Class::Uint(8)),
            field(8, 4, Class::Ptr),
            field(0x10, 4, Class::Num(32)),
        ]);
        let layouts = synthesize(0x2000, 0, &odd, &BTreeMap::new());
        let offsets: Vec<u64> = layouts[0].fields.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, vec![0, 8, 0x10]);
        let mostly_odd = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(2, 4, Class::Num(32)),
            field(3, 1, Class::Uint(8)),
            field(8, 4, Class::Ptr),
        ]);
        assert!(synthesize(0x2000, 0, &mostly_odd, &BTreeMap::new()).is_empty(), "two fields are left");
    }

    #[test]
    fn a_pointer_field_to_a_run_of_one_scalar_is_a_pointer_to_that_scalar() {
        let outer = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(8, 4, Class::Ptr),
            field(0x10, 4, Class::Num(32)),
        ]);
        let floats = ptr_to_struct(&[field(0, 4, Class::Float(32)), field(4, 4, Class::Float(32)), field(8, 4, Class::Float(32))]);
        let layouts = synthesize(0x2000, 1, &outer, &BTreeMap::from([(8, floats)]));
        assert_eq!(layouts.len(), 1, "a run is not a struct");
        assert_eq!(layouts[0].fields.iter().find(|f| f.offset == 8).unwrap().type_ref, "float *");
        // one access is not a run
        let one = ptr_to_struct(&[field(0, 4, Class::Float(32))]);
        let layouts = synthesize(0x2000, 1, &outer, &BTreeMap::from([(8, one)]));
        assert_eq!(layouts[0].fields.iter().find(|f| f.offset == 8).unwrap().type_ref, "void *");
        // nor is a run of pointers or of values of no proven kind
        let pointers = ptr_to_struct(&[field(0, 4, Class::Ptr), field(4, 4, Class::Ptr)]);
        let layouts = synthesize(0x2000, 1, &outer, &BTreeMap::from([(8, pointers)]));
        assert_eq!(layouts[0].fields.iter().find(|f| f.offset == 8).unwrap().type_ref, "void *");
    }

    #[test]
    fn definitions_follow_what_the_text_names_and_what_those_hold() {
        let by_value = StructLayout {
            name: "Inner".into(),
            size: 8,
            provenance: structs::DEBUG_SOURCE.into(),
            fields: vec![StructField { name: "a".into(), offset: 0, size: 4, type_ref: "int".into() }],
        };
        let outer = StructLayout {
            name: "Outer".into(),
            size: 0x10,
            provenance: structs::DEBUG_SOURCE.into(),
            fields: vec![
                StructField { name: "inner".into(), offset: 0, size: 8, type_ref: "Inner".into() },
                StructField { name: "next".into(), offset: 8, size: 4, type_ref: "Outer *".into() },
                StructField { name: "tab".into(), offset: 0xc, size: 4, type_ref: "Inner *[1]".into() },
            ],
        };
        let unrelated = StructLayout { name: "Other".into(), size: 4, ..by_value.clone() };
        let table = StructTable::from_layouts(vec![outer, by_value, unrelated], StructMode::Debug);
        let text = table.definitions("int f(Outer *p) { return p->inner.a; }", "");
        let inner_at = text.find("struct Inner {").expect("Inner defined");
        let outer_at = text.find("struct Outer {").expect("Outer defined");
        assert!(inner_at < outer_at, "a struct held by value comes first:\n{text}");
        assert!(text.contains("    Outer *next;") && text.contains("    Inner *tab[1];"), "{text}");
        assert!(!text.contains("Other"), "only what the text reaches:\n{text}");
        // What the project's header declares is its own.
        assert_eq!(table.definitions("int f(Outer *p);", "typedef struct Outer Outer; typedef struct Inner Inner;"), "");
        // The mode decides what exists at all.
        let none = StructTable::from_layouts(Vec::new(), StructMode::Off);
        assert!(none.definitions("Outer *", "").is_empty());
        assert_eq!(StructTable::from_layouts(table.layouts.values().cloned().collect(), StructMode::Inferred).definitions("Outer", ""), "");
    }

    #[test]
    fn a_hole_the_printer_names_gets_a_member_of_that_name_at_that_offset() {
        // `&p[1].field_0x8`: the printer reached byte 8 of the next element, where
        // the layout has only padding. The definition must hold `field_0x8` there,
        // and still put every other byte where it was.
        let ty = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(0x10, 4, Class::Num(32)),
            field(0x20, 4, Class::Num(32)),
        ]);
        let layouts = synthesize(0x3000, 0, &ty, &BTreeMap::new());
        let table = StructTable::from_layouts(layouts, StructMode::Inferred);
        let text = "int f(fn_00003000_arg0 *p) { return &p[1].field_0x8 != 0 && p->field_0x10; }";
        let defined = table.definitions(text, "");
        assert!(
            defined.contains(
                "    unsigned char pad_0x4[0x4];\n    unsigned char field_0x8; /* +0x8 */\n    unsigned char pad_0x9[0x7];\n    undefined4 field_0x10;"
            ),
            "{defined}"
        );
        // A name a real field already carries is not defined twice, and the struct stays 0x24 bytes.
        assert_eq!(defined.matches("field_0x10;").count(), 1, "{defined}");
        assert!(!defined.contains("pad_0x24"), "{defined}");
    }

    #[test]
    fn the_address_of_a_gap_or_an_undefined_field_is_untyped_but_a_typed_field_or_a_read_is_not() {
        let ty = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(0x10, 4, Class::Float(32)),
            field(0x20, 2, Class::Int(16)),
        ]);
        let table = StructTable::from_layouts(synthesize(0x3000, 0, &ty, &BTreeMap::new()), StructMode::Inferred);
        let call = |arg: &str| format!("void f(fn_00003000_arg0 *p) {{ g({arg}, 1); }}");
        // Offset 8 is a gap, offset 0 an `undefined4` field.
        assert!(table.takes_untyped_address(&call("&p->field_0x8")));
        assert!(table.takes_untyped_address(&call("&((fn_00003000_arg0 *)p)->field_0x0")));
        assert!(table.takes_untyped_address(&call("&p [1].field_0x8")));
        // A float and an int are typed: the decompiler casts where they are passed on.
        assert!(!table.takes_untyped_address(&call("&p->field_0x10")));
        assert!(!table.takes_untyped_address(&call("&p->field_0x20")));
        // A read of a gap is a value, a cast says what the address is, and `a & p->f` is a bit-and.
        assert!(!table.takes_untyped_address(&call("p->field_0x8")));
        assert!(!table.takes_untyped_address(&call("(float *)&p->field_0x8")));
        assert!(!table.takes_untyped_address("void f(fn_00003000_arg0 *p) { x = y & p->field_0x8; }"));
    }

    #[test]
    fn a_field_is_typed_by_the_evidence_it_has_and_undefined_without() {
        // A pointer stored into an `undefined4` field prints uncast: a word with sign evidence keeps `int`/`uint`.
        assert_eq!(field_type(Class::Int(32), 4), "int");
        assert_eq!(field_type(Class::Uint(32), 4), "uint");
        assert_eq!(field_type(Class::Int(16), 2), "short");
        assert_eq!(field_type(Class::Uint(8), 1), "byte");
        assert_eq!(field_type(Class::Float(32), 4), "float");
        assert_eq!(field_type(Class::Num(32), 4), "undefined4");
    }

    #[test]
    fn a_float_member_under_an_integer_cast_is_a_conversion_the_untyped_text_did_not_have() {
        let ty = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(8, 4, Class::Float(32)),
            field(0x10, 4, Class::Float(32)),
        ]);
        let table = StructTable::from_layouts(synthesize(0x3000, 0, &ty, &BTreeMap::new()), StructMode::Inferred);
        let body = |stmt: &str| format!("void f(fn_00003000_arg0 *p, unsigned int *q) {{ {stmt} }}");
        // The bits of a float field copied through an integer pointer, now a numeric conversion.
        assert!(table.converts_float_member(&body("q[3] = (unsigned int)p->field_0x8;")));
        assert!(table.converts_float_member(&body("q[3] = (int)((fn_00003000_arg0 *)p)->field_0x10;")));
        // The float read as a float, an `undefined4` word, a cast of a larger expression, a float cast: all fine.
        assert!(!table.converts_float_member(&body("x = p->field_0x8 + 1.0f;")));
        assert!(!table.converts_float_member(&body("q[3] = (unsigned int)p->field_0x0;")));
        assert!(!table.converts_float_member(&body("q[3] = (unsigned int)(p->field_0x8 * 2.0f);")));
        assert!(!table.converts_float_member(&body("y = (float)p->field_0x8;")));
        assert!(table.misprints(&body("q[3] = (unsigned int)p->field_0x8;")));
    }

    #[test]
    fn a_parameter_read_at_one_offset_as_float_and_bits_or_at_two_widths_is_not_a_struct() {
        // rc `_sysbitFlush`: a 32-bit shift and a 64-bit or at offset 0.
        let widths = "void f(void *param_1, int param_2) { *(int *)param_1 = *(int *)param_1 << (int)param_2; \
                      x = *(unsigned long long *)param_1 | 1; }";
        assert!(mixed_accesses(widths, "param_1"));
        assert!(!mixed_accesses(widths, "param_2"));
        // dds `func_0016F7B0`: a float read of 0x48 and a copy of its bits.
        let kinds = "void f(void *param_1, unsigned int *q) { a = *(float *)((int)param_1 + 0x48); \
                     q[3] = *(unsigned int *)((int)param_1 + 0x48); }";
        assert!(mixed_accesses(kinds, "param_1"));
        // One kind and one width per offset, a pointer and an integer alike (4 bytes), decimal offsets.
        let clean = "void f(void *param_1) { a = *(float *)((int)param_1 + 0x48); b = *(int *)((int)param_1 + 0x10); \
                     c = *(unsigned int *)((int)param_1 + 100); d = *(int *)param_1; \
                     e = **(unsigned char **)((int)param_1 + 0xc); g = *(int *)((int)param_1 + 0xc); \
                     h = *(unsigned char *)(param_1 + 8); k = (int)param_1 + 4; }";
        assert!(!mixed_accesses(clean, "param_1"));
        // A halfword inside a word overlaps it.
        let inside = "void f(void *param_1) { a = *(int *)param_1; b = *(unsigned short *)((int)param_1 + 2); }";
        assert!(mixed_accesses(inside, "param_1"));
    }

    #[test]
    fn an_untyped_offset_takes_the_type_the_decompiler_gave_every_access_to_it() {
        // dc `SetPosition`: floats compared; dk `__ct__`: a float parameter stored, a pointer stored.
        let text = "void f(void *param_1, float *param_2) { if (*(float *)(param_1 + 0x10) != *param_2) { \
                    *(float *)((int)param_1 + 0x2d8) = param_3; **(unsigned char **)((int)param_1 + 0xc) = 1; \
                    *(unsigned int *)((int)param_1 + 0x44) = 1; x = *(unsigned long *)((int)param_1 + 0x50); \
                    y = *(int *)param_1; z = *(unsigned int *)param_1; } }";
        let types = access_field_types(text, "param_1");
        assert_eq!(types[&0x10], (4, "float".to_string()));
        assert_eq!(types[&0x2d8], (4, "float".to_string()));
        assert_eq!(types[&0xc], (4, "void *".to_string()));
        assert_eq!(types[&0x44], (4, "uint".to_string()));
        // A plain `long` has no width here, and an offset read as `int` and as `unsigned int` is two things.
        assert!(!types.contains_key(&0x50));
        assert!(!types.contains_key(&0));
    }

    #[test]
    fn a_float_cast_on_an_undefined_member_keeps_the_function_untyped() {
        let ty = ptr_to_struct(&[
            field(0, 4, Class::Num(32)),
            field(0x10, 4, Class::Num(32)),
            field(0x20, 4, Class::Float(32)),
        ]);
        let table = StructTable::from_layouts(synthesize(0x3000, 0, &ty, &BTreeMap::new()), StructMode::Inferred);
        let body = |stmt: &str| format!("void f(fn_00003000_arg0 *p, float *q) {{ {stmt} }}");
        assert!(table.converts_float_member(&body("if ((float)p->field_0x10 != *q) { x = 1; }")));
        assert!(table.converts_float_member(&body("if (*q != (double)((fn_00003000_arg0 *)p)->field_0x0) { x = 1; }")));
        // A typed float member under a float cast, an undefined member under an integer cast, and an undefined
        // member compared as it is are the untyped text's own.
        assert!(!table.converts_float_member(&body("if ((float)p->field_0x20 != *q) { x = 1; }")));
        assert!(!table.converts_float_member(&body("x = (unsigned int)p->field_0x10;")));
        assert!(!table.converts_float_member(&body("if (p->field_0x10 != 0) { x = 1; }")));
    }
}
