//! Struct datatypes for the decompiler: the stored layouts (`type_defs` /
//! `type_fields`), gated by `ROMWRIGHT_STRUCTS`, answered as the `<type>`
//! element `TypeStruct::decodeFields` (type.cc:2104-2260) accepts.
//!
//! The decoder is strict, and a rejected element fails the whole decompile
//! (`LowlevelError`), so the encoder never sends what the decoder would
//! refuse: fields are in increasing offset order, none overlaps another, none
//! is void or unnamed, and the struct's size covers every field's *decoded*
//! size (the decoder adds `offset + type->getSize()`, not the row's size).
//! A layout that cannot be encoded is hidden, and a signature that names it
//! is erased to `void` before the decompiler reads it.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use romwright_core::library_types::BaseType;
use romwright_model::structs::{StructLayout, StructMode, TypeSpelling};
use romwright_model::{PrototypeRow, TypeDefRow};

use crate::wire;

/// `ELEM_FIELD` (type.cc:56).
const ELEM_FIELD: u32 = 49;

/// A struct nested by value this deep is a cycle or nonsense, not a layout.
const DEPTH: usize = 16;

/// The language's types a field may name: `coretypes.xml` (with ids), the
/// compiler spec's C base types, and the pointer width.
pub struct TypeEnv<'a> {
    pub core: &'a HashMap<String, (u64, u64)>,
    pub base: &'a BTreeMap<String, BaseType>,
    pub pointer_size: u64,
}

/// A field type once its spelling is resolved against the store and the
/// language.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ty {
    Core { name: String, id: u64, size: u64 },
    Base { name: String, metatype: &'static str, size: u64 },
    Struct(String),
    Void,
    Pointer(Box<Ty>),
    Array(Box<Ty>, u64),
}

/// Layouts the mode lets the decompiler see, and the names it must not.
#[derive(Default, Debug)]
pub struct Layouts {
    structs: BTreeMap<String, StructLayout>,
    /// Struct names the store holds that this run does not answer: gated out
    /// by the mode, or not encodable. A signature naming one is erased.
    hidden: BTreeSet<String>,
    /// Non-struct type rows (`pointer`, `array`, aliases), for `type_ref`s
    /// that name them.
    other: BTreeMap<String, TypeDefRow>,
    infer: bool,
    /// Signatures the struct pass wrote for single functions this run
    /// (`ROMWRIGHT_STRUCT_OVERLAY`), by entry. Never stored with the project.
    overlay: HashMap<u64, String>,
}

impl Layouts {
    /// Reads the store's layouts and keeps those `mode` allows.
    pub fn load(
        db: &romwright_db::ProjectDb,
        program: romwright_model::ProgramId,
        mode: StructMode,
    ) -> crate::Result<Layouts> {
        let defs = db.type_defs(program)?;
        let mut layouts = if defs.iter().all(|def| def.kind != "struct") {
            Layouts::default()
        } else {
            let fields = db.type_fields(program, None)?;
            Layouts::from_rows(&defs, &fields, mode)
        };
        layouts.infer = mode.infers();
        if layouts.infer {
            layouts.overlay = read_overlay()?;
        }
        Ok(layouts)
    }

    pub fn from_rows(
        defs: &[TypeDefRow],
        fields: &[romwright_model::TypeFieldRow],
        mode: StructMode,
    ) -> Layouts {
        let mut out = Layouts { infer: mode.infers(), ..Layouts::default() };
        for def in defs.iter().filter(|def| def.kind != "struct") {
            out.other.insert(def.name.clone(), def.clone());
        }
        for layout in romwright_model::structs::layouts(defs, fields) {
            if mode.allows(layout.source()) {
                out.structs.insert(layout.name.clone(), layout);
            } else {
                out.hidden.insert(layout.name.clone());
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.structs.is_empty() && self.hidden.is_empty()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.structs.contains_key(name)
    }

    /// Hides every layout `env` cannot encode, so nothing the decompiler is
    /// told about can fail when it is asked for.
    pub fn validate(&mut self, env: &TypeEnv<'_>) {
        let names: Vec<String> = self.structs.keys().cloned().collect();
        for name in names {
            if self.encode_struct(&name, env).is_none() {
                self.structs.remove(&name);
                self.hidden.insert(name);
            }
        }
    }

    /// The prototype row the decompiler may be given, or `None` to leave it
    /// out. Rows owned by the inference pass vanish when the mode does not
    /// infer; a signature that names a struct this run does not answer has it
    /// erased to `void`.
    pub fn gate_prototype(&self, mut row: PrototypeRow) -> Option<PrototypeRow> {
        if romwright_model::structs::is_struct_prototype(&row.provenance.source) && !self.infer {
            return None;
        }
        row.signature = self.erase_unresolved(&row.signature);
        Some(row)
    }

    /// `signature` with every struct this run cannot answer erased to `void`:
    /// the hidden ones, and any inferred struct name with no layout stored.
    pub fn erase_unresolved(&self, signature: &str) -> String {
        erase_where(signature, |word| {
            self.hidden.contains(word)
                || (romwright_model::structs::is_inferred_name(word) && !self.structs.contains_key(word))
        })
    }

    /// Every struct name erased: the signature as the decompiler read it
    /// before the structs existed.
    pub fn erase_all(&self, signature: &str) -> String {
        erase_where(signature, |word| {
            self.structs.contains_key(word)
                || self.hidden.contains(word)
                || romwright_model::structs::is_inferred_name(word)
        })
    }

    /// The signature the struct pass wrote for `entry` alone, if this run
    /// uses it.
    pub fn overlay_signature(&self, entry: u64) -> Option<String> {
        if !self.infer {
            return None;
        }
        self.overlay.get(&entry).map(|signature| self.erase_unresolved(signature))
    }


    /// Whether the row types its parameters with inferred structs: its
    /// signature belongs to the one function it was written for.
    pub fn is_function_local(row: &PrototypeRow) -> bool {
        romwright_model::structs::is_struct_prototype(&row.provenance.source)
    }

    /// The `<type>` element for struct `name`, or `None` when there is no such
    /// struct this run answers.
    pub fn answer(&self, name: &str, env: &TypeEnv<'_>) -> Option<Vec<u8>> {
        self.encode_struct(name, env)
    }

    fn resolve(&self, spelling: &TypeSpelling, env: &TypeEnv<'_>, depth: usize) -> Option<Ty> {
        if depth > DEPTH {
            return None;
        }
        match spelling {
            TypeSpelling::Pointer(inner) => {
                let target = match self.resolve(inner, env, depth + 1) {
                    Some(target) => target,
                    // A pointer to something this run cannot name points at
                    // nothing in particular.
                    None => Ty::Void,
                };
                Some(Ty::Pointer(Box::new(target)))
            }
            TypeSpelling::Array(inner, count) => {
                let element = self.resolve(inner, env, depth + 1)?;
                (*count > 0).then(|| Ty::Array(Box::new(element), *count))
            }
            TypeSpelling::Name(name) => self.resolve_name(name, env, depth),
        }
    }

    fn resolve_name(&self, name: &str, env: &TypeEnv<'_>, depth: usize) -> Option<Ty> {
        // A typedef chain that loops back on itself ends here instead of overflowing the stack.
        if depth > DEPTH {
            return None;
        }
        if name == "void" {
            return Some(Ty::Void);
        }
        if self.structs.contains_key(name) {
            return Some(Ty::Struct(name.to_string()));
        }
        if self.hidden.contains(name) {
            return None;
        }
        if let Some(&(id, size)) = env.core.get(name) {
            return Some(Ty::Core { name: name.to_string(), id, size });
        }
        if let Some(base) = env.base.get(name) {
            return Some(Ty::Base {
                name: name.to_string(),
                metatype: base.metatype,
                size: u64::from(base.size),
            });
        }
        let def = self.other.get(name)?;
        let target = def.base_type.as_deref()?;
        match def.kind.as_str() {
            "pointer" => {
                let target = self.resolve_name(target, env, depth + 1).unwrap_or(Ty::Void);
                Some(Ty::Pointer(Box::new(target)))
            }
            "array" => {
                let element = self.resolve_name(target, env, depth + 1)?;
                def.element_count.filter(|count| *count > 0).map(|count| Ty::Array(Box::new(element), count))
            }
            _ => self.resolve_name(target, env, depth + 1),
        }
    }

    /// `undefined<size>` where the language has one, else the byte it is made of.
    fn undefined(size: u64, env: &TypeEnv<'_>) -> Option<Ty> {
        let name = format!("undefined{size}");
        if let Some(&(id, width)) = env.core.get(&name) {
            return Some(Ty::Core { name, id, size: width });
        }
        let &(id, _) = env.core.get("undefined1")?;
        let byte = Ty::Core { name: "undefined1".into(), id, size: 1 };
        (size > 0).then(|| if size == 1 { byte } else { Ty::Array(Box::new(byte), size) })
    }

    fn size_of(&self, ty: &Ty, env: &TypeEnv<'_>, depth: usize) -> Option<u64> {
        if depth > DEPTH {
            return None;
        }
        Some(match ty {
            Ty::Core { size, .. } | Ty::Base { size, .. } => *size,
            Ty::Void => return None,
            Ty::Pointer(_) => env.pointer_size,
            Ty::Array(element, count) => self.size_of(element, env, depth + 1)?.checked_mul(*count)?,
            Ty::Struct(name) => self.struct_size(name, env, depth + 1)?,
        })
    }

    /// The decoded size of a struct: the row's size, grown to cover every
    /// field's decoded type.
    fn struct_size(&self, name: &str, env: &TypeEnv<'_>, depth: usize) -> Option<u64> {
        let layout = self.structs.get(name)?;
        let fields = self.fields(layout, env, depth)?;
        let end = fields.iter().map(|(_, offset, size, _)| offset + size).max().unwrap_or(0);
        Some(layout.size.max(end))
    }

    /// The fields the decoder will keep, in order: resolved, sized, and with
    /// overlaps dropped (the first by offset wins, the wider on a tie).
    fn fields(
        &self,
        layout: &StructLayout,
        env: &TypeEnv<'_>,
        depth: usize,
    ) -> Option<Vec<(String, u64, u64, Ty)>> {
        if depth > DEPTH {
            return None;
        }
        let mut resolved: Vec<(String, u64, u64, Ty)> = Vec::new();
        for field in &layout.fields {
            if field.name.is_empty() || field.size == 0 {
                continue;
            }
            let named = TypeSpelling::parse(&field.type_ref)
                .and_then(|spelling| self.resolve(&spelling, env, depth + 1))
                .filter(|ty| *ty != Ty::Void);
            // A type that cannot be named or sized (an unknown name, a struct
            // nested by value in a cycle) is the bytes it occupies.
            let sized = named
                .into_iter()
                .chain(Self::undefined(field.size, env))
                .find_map(|ty| self.size_of(&ty, env, depth + 1).map(|size| (size, ty)));
            let Some((size, ty)) = sized else { continue };
            resolved.push((field.name.clone(), field.offset, size, ty));
        }
        resolved.sort_by(|a, b| a.1.cmp(&b.1).then(b.2.cmp(&a.2)));
        let mut kept: Vec<(String, u64, u64, Ty)> = Vec::new();
        let mut covered = 0u64;
        for field in resolved {
            if field.1 < covered {
                continue;
            }
            covered = field.1 + field.2;
            kept.push(field);
        }
        Some(kept)
    }

    fn encode_struct(&self, name: &str, env: &TypeEnv<'_>) -> Option<Vec<u8>> {
        let layout = self.structs.get(name)?;
        let fields = self.fields(layout, env, 0)?;
        let end = fields.iter().map(|(_, offset, size, _)| offset + size).max().unwrap_or(0);
        let size = layout.size.max(end);
        if size == 0 {
            return None;
        }
        let mut doc = Vec::new();
        wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::TYPE);
        wire::encode_string_attribute(&mut doc, wire::attr::NAME, name.as_bytes());
        wire::encode_attribute(&mut doc, wire::attr::SIZE, wire::attr_type::POSITIVE_INT, size);
        wire::encode_string_attribute(&mut doc, wire::attr::METATYPE, b"struct");
        for (field, offset, _, ty) in &fields {
            wire::encode_header(&mut doc, wire::ELEMENT_START, ELEM_FIELD);
            wire::encode_string_attribute(&mut doc, wire::attr::NAME, field.as_bytes());
            wire::encode_attribute(&mut doc, wire::attr::OFFSET, wire::attr_type::POSITIVE_INT, *offset);
            self.encode_type(&mut doc, ty, env)?;
            wire::encode_header(&mut doc, wire::ELEMENT_END, ELEM_FIELD);
        }
        wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::TYPE);
        Some(doc)
    }

    fn encode_type(&self, out: &mut Vec<u8>, ty: &Ty, env: &TypeEnv<'_>) -> Option<()> {
        match ty {
            Ty::Core { name, id, .. } => wire::encode_typeref(out, name, *id),
            Ty::Base { name, metatype, size } => wire::encode_basic_type(out, name, metatype, *size),
            // No id: the decoder derives `hashName(name)`, which is the id the
            // struct's own answer carries.
            Ty::Struct(name) => {
                wire::encode_header(out, wire::ELEMENT_START, wire::elem::TYPEREF);
                wire::encode_string_attribute(out, wire::attr::NAME, name.as_bytes());
                wire::encode_header(out, wire::ELEMENT_END, wire::elem::TYPEREF);
            }
            Ty::Void => {
                wire::encode_header(out, wire::ELEMENT_START, wire::elem::VOID);
                wire::encode_header(out, wire::ELEMENT_END, wire::elem::VOID);
            }
            Ty::Pointer(target) => {
                let mut failed = false;
                wire::encode_pointer_to(out, env.pointer_size, |out| {
                    failed = self.encode_type(out, target, env).is_none();
                });
                if failed {
                    return None;
                }
            }
            Ty::Array(element, count) => {
                let total = self.size_of(ty, env, 0)?;
                wire::encode_header(out, wire::ELEMENT_START, wire::elem::TYPE);
                wire::encode_string_attribute(out, wire::attr::NAME, b"");
                wire::encode_string_attribute(out, wire::attr::METATYPE, b"array");
                wire::encode_attribute(out, wire::attr::SIZE, wire::attr_type::POSITIVE_INT, total);
                wire::encode_attribute(out, wire::attr::ARRAYSIZE, wire::attr_type::POSITIVE_INT, *count);
                self.encode_type(out, element, env)?;
                wire::encode_header(out, wire::ELEMENT_END, wire::elem::TYPE);
            }
        }
        Some(())
    }
}

/// Replaces every identifier in `text` for which `erase` holds by `void`. A
/// pointer to an erased struct is then `void *`, which is what the signature
/// said before the struct was known.
pub fn erase_where(text: &str, erase: impl Fn(&str) -> bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            out.push_str(if erase(word) { "void" } else { word });
            word.clear();
        }
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// The signatures the struct pass wrote for single functions of this run:
/// the JSON file `ROMWRIGHT_STRUCT_OVERLAY` names, `{"prototypes": {"<entry>":
/// "<signature>"}}` with the entry in decimal.
fn read_overlay() -> crate::Result<HashMap<u64, String>> {
    let Some(path) = std::env::var_os("ROMWRIGHT_STRUCT_OVERLAY").filter(|path| !path.is_empty()) else {
        return Ok(HashMap::new());
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|error| crate::WorkerError::Setup(format!("struct overlay {path:?}: {error}")))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| crate::WorkerError::Setup(format!("struct overlay {path:?}: {error}")))?;
    let mut out = HashMap::new();
    if let Some(prototypes) = value.get("prototypes").and_then(serde_json::Value::as_object) {
        for (entry, signature) in prototypes {
            if let (Ok(entry), Some(signature)) = (entry.parse::<u64>(), signature.as_str()) {
                out.insert(entry, signature.to_string());
            }
        }
    }
    Ok(out)
}

impl crate::provider::ProgramProvider {
    /// Checks the stored layouts against this language's types, once. Until
    /// the language is loaded the core types are unknown, so this waits for
    /// the first use.
    fn check_structs(&mut self) {
        if self.structs_checked {
            return;
        }
        self.structs_checked = true;
        let mut structs = std::mem::take(&mut self.structs);
        structs.validate(&TypeEnv {
            core: &self.core_types,
            base: &self.base_types,
            pointer_size: self.pointer_size,
        });
        self.structs = structs;
    }

    /// The `<type>` element answering a query for struct `name`.
    pub fn struct_datatype(&mut self, name: &str) -> Option<Vec<u8>> {
        self.check_structs();
        self.structs.answer(
            name,
            &TypeEnv { core: &self.core_types, base: &self.base_types, pointer_size: self.pointer_size },
        )
    }

    /// A stored prototype as the decompiler may read it under the current
    /// mode, or `None` when this run does not use it.
    pub fn gated_prototype(&mut self, row: &PrototypeRow) -> Option<PrototypeRow> {
        self.check_structs();
        self.structs.gate_prototype(row.clone())
    }

    /// The signature written for `entry` alone, to type that function's own
    /// decompile and nothing else: from this run's overlay, else a stored row
    /// of the struct pass. `None` when there is none, or the mode does not use
    /// the inferred layouts.
    pub fn local_prototype(&mut self, entry: u64) -> Option<String> {
        self.check_structs();
        if let Some(signature) = self.structs.overlay_signature(entry) {
            return Some(signature);
        }
        let row = self.prototypes.get(&entry).filter(|row| Layouts::is_function_local(row))?.clone();
        self.structs.gate_prototype(row).map(|row| row.signature)
    }

    /// `signature` as the decompiler read it before any struct existed.
    pub fn erase_struct_names(&self, signature: &str) -> String {
        self.structs.erase_all(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::structs::{StructField, DEBUG_SOURCE, INFERRED_SOURCE, PROTOTYPE_SOURCE};

    // ---- a decoder for the packed form, with TypeStruct::decodeFields' rules ----

    #[derive(Debug, Default)]
    struct Node {
        id: u32,
        attrs: Vec<(u32, Attr)>,
        children: Vec<Node>,
    }

    #[derive(Debug, PartialEq)]
    enum Attr {
        Int(i64),
        Unsigned(u64),
        Text(String),
    }

    impl Node {
        fn int(&self, id: u32) -> Option<i64> {
            self.attrs.iter().find(|(a, _)| *a == id).and_then(|(_, v)| match v {
                Attr::Int(v) => Some(*v),
                _ => None,
            })
        }
        fn text(&self, id: u32) -> Option<&str> {
            self.attrs.iter().find(|(a, _)| *a == id).and_then(|(_, v)| match v {
                Attr::Text(v) => Some(v.as_str()),
                _ => None,
            })
        }
    }

    fn read_header(bytes: &[u8], pos: &mut usize) -> (u8, u32) {
        let header = bytes[*pos];
        *pos += 1;
        let mut id = u32::from(header & 0x1f);
        if header & 0x20 != 0 {
            id = (id << 7) | u32::from(bytes[*pos] & 0x7f);
            *pos += 1;
        }
        (header & 0xc0, id)
    }

    fn read_node(bytes: &[u8], pos: &mut usize) -> Node {
        let (kind, id) = read_header(bytes, pos);
        assert_eq!(kind, 0x40, "element start");
        let mut node = Node { id, ..Node::default() };
        loop {
            match bytes[*pos] & 0xc0 {
                0xc0 => {
                    let (_, attr) = read_header(bytes, pos);
                    let type_byte = bytes[*pos];
                    *pos += 1;
                    let code = type_byte >> 4;
                    let length = usize::from(type_byte & 0xf);
                    let mut value = 0u64;
                    match code {
                        1 => node.attrs.push((attr, Attr::Unsigned(u64::from(length as u8)))),
                        2..=4 => {
                            for _ in 0..length {
                                value = (value << 7) | u64::from(bytes[*pos] & 0x7f);
                                *pos += 1;
                            }
                            node.attrs.push((
                                attr,
                                if code == 4 { Attr::Unsigned(value) } else { Attr::Int(value as i64) },
                            ));
                        }
                        7 => {
                            // string: a length integer (in length-code groups), then bytes
                            let mut len = 0usize;
                            for _ in 0..length {
                                len = (len << 7) | usize::from(bytes[*pos] & 0x7f);
                                *pos += 1;
                            }
                            let text = String::from_utf8(bytes[*pos..*pos + len].to_vec()).unwrap();
                            *pos += len;
                            node.attrs.push((attr, Attr::Text(text)));
                        }
                        other => panic!("attribute type {other}"),
                    }
                }
                0x40 => node.children.push(read_node(bytes, pos)),
                0x80 => {
                    let (_, end) = read_header(bytes, pos);
                    assert_eq!(end, id, "element end");
                    return node;
                }
                other => panic!("header {other:#x}"),
            }
        }
    }

    /// `TypeStruct::decodeFields`' acceptance, over the decoded tree: the
    /// struct has a size and a name, each field a name, an offset no lower than
    /// the last, a type that is not void, and ends within the struct.
    fn accepts(doc: &[u8], sizes: &dyn Fn(&Node) -> u64) -> Result<Vec<(String, i64)>, String> {
        let mut pos = 0;
        let ty = read_node(doc, &mut pos);
        assert_eq!(pos, doc.len(), "trailing bytes");
        if ty.id != wire::elem::TYPE || ty.text(wire::attr::METATYPE) != Some("struct") {
            return Err("not a struct".into());
        }
        let size = ty.int(wire::attr::SIZE).ok_or("no size")?;
        let mut last = -1i64;
        let mut calc = 0i64;
        let mut kept = Vec::new();
        for field in &ty.children {
            if field.id != ELEM_FIELD {
                return Err("expecting <field>".into());
            }
            let name = field.text(wire::attr::NAME).unwrap_or("");
            if name.is_empty() {
                return Err("empty field name".into());
            }
            let offset = field.int(wire::attr::OFFSET).ok_or("no offset")?;
            let [child] = field.children.as_slice() else { return Err("field needs one type".into()) };
            if child.id == wire::elem::VOID {
                return Err("void field".into());
            }
            if offset < last {
                return Err("Fields are out of order".into());
            }
            if offset < calc {
                return Err(format!("overlapping field {name}"));
            }
            last = offset;
            calc = offset + sizes(child) as i64;
            if calc > size {
                return Err(format!("Field {name} does not fit"));
            }
            kept.push((name.to_string(), offset));
        }
        Ok(kept)
    }

    fn core_env() -> (HashMap<String, (u64, u64)>, BTreeMap<String, BaseType>) {
        let mut core = HashMap::new();
        for (index, (name, size)) in [
            ("int", 4u64),
            ("uint", 4),
            ("short", 2),
            ("char", 1),
            ("byte", 1),
            ("float", 4),
            ("undefined1", 1),
            ("undefined2", 2),
            ("undefined4", 4),
            ("undefined8", 8),
        ]
        .into_iter()
        .enumerate()
        {
            core.insert(name.to_string(), (0x100 + index as u64, size));
        }
        (core, BTreeMap::new())
    }

    fn size_of_node(core: &HashMap<String, (u64, u64)>) -> impl Fn(&Node) -> u64 {
        let core = core.clone();
        move |node: &Node| match node.id {
            id if id == wire::elem::TYPEREF => {
                let name = node.text(wire::attr::NAME).unwrap_or("");
                core.get(name).map(|(_, size)| *size).unwrap_or(4)
            }
            id if id == wire::elem::TYPE => node.int(wire::attr::SIZE).unwrap_or(0) as u64,
            _ => 0,
        }
    }

    fn layout(name: &str, size: u64, provenance: &str, fields: &[(&str, u64, u64, &str)]) -> StructLayout {
        StructLayout {
            name: name.into(),
            size,
            provenance: provenance.into(),
            fields: fields
                .iter()
                .map(|(field, offset, size, type_ref)| StructField {
                    name: (*field).into(),
                    offset: *offset,
                    size: *size,
                    type_ref: (*type_ref).into(),
                })
                .collect(),
        }
    }

    fn layouts_of(list: Vec<StructLayout>, mode: StructMode) -> Layouts {
        let mut defs = Vec::new();
        let mut fields = Vec::new();
        for l in &list {
            let (def, rows) = l.rows();
            defs.push(def);
            fields.extend(rows);
        }
        Layouts::from_rows(&defs, &fields, mode)
    }

    #[test]
    fn a_layout_encodes_to_what_the_decoder_accepts() {
        let (core, base) = core_env();
        let env = TypeEnv { core: &core, base: &base, pointer_size: 4 };
        let layouts = layouts_of(
            vec![
                layout(
                    "fn_80012340_arg0",
                    0x20,
                    INFERRED_SOURCE,
                    &[
                        ("field_0x0", 0, 4, "int"),
                        ("field_0x8", 8, 4, "float"),
                        ("field_0xc", 0xc, 4, "fn_80012340_arg0 *"),
                        ("field_0x10", 0x10, 4, "void *"),
                        ("field_0x14", 0x14, 4, "Mystery"),
                        ("field_0x18", 0x18, 8, "byte[8]"),
                    ],
                ),
            ],
            StructMode::All,
        );
        let doc = layouts.answer("fn_80012340_arg0", &env).expect("encodes");
        let size = size_of_node(&core);
        let kept = accepts(&doc, &size).expect("decoder accepts");
        assert_eq!(
            kept.iter().map(|(_, offset)| *offset).collect::<Vec<_>>(),
            vec![0, 8, 0xc, 0x10, 0x14, 0x18]
        );
    }

    #[test]
    fn overlap_unordered_input_and_oversized_fields_never_reach_the_decoder() {
        let (core, base) = core_env();
        let env = TypeEnv { core: &core, base: &base, pointer_size: 4 };
        // Out of order, overlapping (a word over a halfword), and a field
        // that ends past the row's own size: the decoder would throw on the
        // last and warn on the second.
        let layouts = layouts_of(
            vec![layout(
                "S",
                8,
                DEBUG_SOURCE,
                &[
                    ("c", 8, 4, "int"),
                    ("a", 0, 4, "int"),
                    ("b", 2, 2, "short"),
                    ("zero", 4, 0, "int"),
                ],
            )],
            StructMode::Debug,
        );
        let doc = layouts.answer("S", &env).expect("encodes");
        let size = size_of_node(&core);
        let kept = accepts(&doc, &size).expect("decoder accepts");
        assert_eq!(kept, vec![("a".to_string(), 0), ("c".to_string(), 8)]);
        let mut pos = 0;
        let node = read_node(&doc, &mut pos);
        assert_eq!(node.int(wire::attr::SIZE), Some(12), "size grows to cover the last field");
    }

    #[test]
    fn mode_hides_layouts_and_erases_their_names_from_signatures() {
        let all = vec![
            layout("Dbg", 8, DEBUG_SOURCE, &[("a", 0, 4, "int")]),
            layout("Inf", 8, INFERRED_SOURCE, &[("a", 0, 4, "int")]),
            layout("Mine", 8, "user", &[("a", 0, 4, "int")]),
        ];
        let debug = layouts_of(all.clone(), StructMode::Debug);
        assert!(debug.contains("Dbg") && debug.contains("Mine") && !debug.contains("Inf"));
        let inferred = layouts_of(all.clone(), StructMode::Inferred);
        assert!(inferred.contains("Inf") && inferred.contains("Mine") && !inferred.contains("Dbg"));
        let off = layouts_of(all, StructMode::Off);
        assert!(off.is_empty() || (!off.contains("Dbg") && !off.contains("Mine")));
        let row = |signature: &str, source: &str| PrototypeRow {
            function: romwright_model::Address::ram(0x1000),
            signature: signature.into(),
            calling_convention: None,
            return_type: None,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: source.into(),
                confidence: None,
            },
        };
        let gated = debug
            .gate_prototype(row("void f(Dbg * a, Inf * b, Dbg ** c)", DEBUG_SOURCE))
            .expect("row kept");
        assert_eq!(gated.signature, "void f(Dbg * a, void * b, Dbg ** c)");
        // The inference pass's own rows disappear unless the mode infers.
        assert!(debug.gate_prototype(row("void f(Inf * a)", PROTOTYPE_SOURCE)).is_none());
        assert!(inferred.gate_prototype(row("void f(Inf * a)", PROTOTYPE_SOURCE)).is_some());
    }

    #[test]
    fn a_cyclic_by_value_struct_is_hidden_not_sent() {
        let (core, base) = core_env();
        let env = TypeEnv { core: &core, base: &base, pointer_size: 4 };
        let mut layouts = layouts_of(
            vec![
                layout("A", 8, DEBUG_SOURCE, &[("b", 0, 8, "B")]),
                layout("B", 8, DEBUG_SOURCE, &[("a", 0, 8, "A")]),
                layout("Ok", 4, DEBUG_SOURCE, &[("p", 0, 4, "A *")]),
            ],
            StructMode::All,
        );
        layouts.validate(&env);
        // The by-value cycle has no size, so its fields fall back to undefined
        // bytes instead of failing the decompile; a pointer to it stays a name.
        assert!(layouts.answer("Ok", &env).is_some());
        for name in ["A", "B"] {
            if let Some(doc) = layouts.answer(name, &env) {
                let size = size_of_node(&core);
                accepts(&doc, &size).expect("whatever is sent is accepted");
            }
        }
    }
}
