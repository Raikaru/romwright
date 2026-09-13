//! Prototype projection of the packed document, using doc.rs's single decoder.
//! Contracts: funcdata.cc Funcdata::encode; fspec.cc FuncProto::encode and
//! ProtoStoreInternal::encode; database.cc Symbol::encodeHeader; type.cc
//! Datatype::encodeRef, TypePointer/TypeArray/TypeCode::encode (pinned tree).

use crate::doc::Value;
use crate::wire::attr::{NAME, OFFSET, SIZE, SPACE};
use crate::wire::elem::{ADDR, DOC, FUNCTION, MAPSYM, PROTOTYPE, RETURNSYM, SYMBOL, TYPE, TYPEREF, VOID};
use romwright_model::{DecompType, FuncParam, FuncProto, StorageSymbol};

const DEF: u32 = 43;
const INTERNALLIST: u32 = 161;
const PARAM: u32 = 166;
const LOCALDB: u32 = 228;

#[derive(Default)]
struct Node {
    id: u32,
    depth: usize,
    attributes: Vec<(u32, Value)>,
    children: Vec<Node>,
}

impl Node {
    fn value(&self, id: u32) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|(key, _)| *key == id)
            .map(|(_, value)| value)
    }

    fn string(&mut self, id: u32) -> Option<String> {
        let index = self.attributes.iter().position(|(key, _)| *key == id)?;
        match self.attributes.swap_remove(index).1 {
            Value::String(value) => Some(value),
            _ => None,
        }
    }

    fn unsigned(&self, id: u32) -> Option<u64> {
        self.value(id)?.unsigned()
    }

    fn boolean(&self, id: u32) -> Option<bool> {
        match self.value(id) {
            None => Some(false),
            Some(Value::Boolean(value)) => Some(*value),
            _ => None,
        }
    }

    fn take_child(&mut self, id: u32) -> Option<Node> {
        let index = self.children.iter().position(|node| node.id == id)?;
        Some(self.children.remove(index))
    }

    fn take_type(&mut self) -> Option<DecompType> {
        let index = self.children.iter().position(|node| is_type(node.id))?;
        decode_type(self.children.remove(index))
    }
}

fn is_type(id: u32) -> bool {
    matches!(id, VOID | DEF | TYPE | TYPEREF)
}

fn decode_type(mut node: Node) -> Option<DecompType> {
    let is_void = node.id == VOID;
    let mut result = DecompType {
        name: if is_void {
            Some("void".into())
        } else {
            node.string(14).filter(|name| !name.is_empty())
        },
        id: node.unsigned(9),
        size: node.unsigned(19),
        metatype: if is_void {
            Some("void".into())
        } else {
            node.string(12)
        },
        element_count: node.unsigned(48),
        target: None,
        prototype: None,
    };
    if (node.id == TYPEREF && result.name.is_none() && result.id.is_none())
        || (node.id == TYPE && result.metatype.is_none())
    {
        return None;
    }
    if let Some(prototype) = node.take_child(PROTOTYPE) {
        result.prototype = Some(Box::new(decode_prototype(prototype, Vec::new())?));
    }
    if node.children.iter().any(|child| is_type(child.id)) {
        result.target = Some(Box::new(node.take_type()?));
    }
    Some(result)
}

fn decode_parameter(mut node: Node, ordinal: u32) -> Option<FuncParam> {
    Some(FuncParam {
        ordinal,
        name: node.string(14).unwrap_or_default(),
        data_type: node.take_type()?,
    })
}

fn decode_prototype(mut node: Node, mut parameters: Vec<FuncParam>) -> Option<FuncProto> {
    let calling_convention = node.string(13)?;
    let variadic = node.boolean(115)?;
    let return_type = node.take_child(RETURNSYM)?.take_type()?;
    if let Some(internal) = node.take_child(INTERNALLIST) {
        parameters.clear();
        for child in internal
            .children
            .into_iter()
            .filter(|child| child.id == PARAM)
        {
            parameters.push(decode_parameter(
                child,
                u32::try_from(parameters.len()).ok()?,
            )?);
        }
    }
    parameters.sort_unstable_by_key(|parameter| parameter.ordinal);
    // Missing/duplicate category indices must not become a plausible signature.
    if parameters
        .iter()
        .enumerate()
        .any(|(index, parameter)| index != parameter.ordinal as usize)
    {
        return None;
    }
    Some(FuncProto {
        calling_convention,
        return_type,
        parameters,
        variadic,
        no_return: node.boolean(crate::wire::attr::NORETURN)?,
        parameter_source: None,
    })
}

/// Capture only prototype/type subtrees and local symbols, never the AST.
/// A closed native function is required; C markup also uses FUNCTION but has
/// no direct PROTOTYPE. Nested function-pointer prototypes remain type data.
/// What one document yields besides its tokens.
#[derive(Default)]
pub(crate) struct Recovered {
    pub prototype: Option<FuncProto>,
    pub storage: Vec<StorageSymbol>,
}

#[derive(Default)]
pub(crate) struct Collector {
    function_depth: Option<usize>,
    localdb_depth: Option<usize>,
    /// `<mapsym>` pairs one `<symbol>` with the `<addr>` entries that store
    /// it (database.cc:2643-2654 of the pinned tree), so storage arrives as
    /// the symbol's sibling rather than its child.
    mapsym_depth: Option<usize>,
    pending_input: Option<String>,
    addr_depth: Option<usize>,
    addr_space: Option<String>,
    addr_offset: Option<u64>,
    addr_size: Option<u32>,
    storage: Vec<StorageSymbol>,
    capture: Vec<Node>,
    parameters: Vec<FuncParam>,
    prototype: Option<Node>,
    result: Option<FuncProto>,
    failed: bool,
    seen_prototype: bool,
}

impl Collector {
    pub(crate) fn start(&mut self, id: u32, parent: Option<u32>, depth: usize) {
        if self.failed {
            return;
        }
        if id == FUNCTION && parent == Some(DOC) {
            self.function_depth = Some(depth);
        }
        if id == LOCALDB && self.function_depth == depth.checked_sub(1) {
            self.localdb_depth = Some(depth);
        }
        if id == MAPSYM && self.localdb_depth.is_some() {
            self.mapsym_depth = Some(depth);
            self.pending_input = None;
        }
        if id == ADDR
            && self.pending_input.is_some()
            && self.mapsym_depth == depth.checked_sub(1)
        {
            self.addr_depth = Some(depth);
            self.addr_space = None;
            self.addr_offset = None;
            self.addr_size = None;
        }
        let root = (id == PROTOTYPE && self.function_depth == depth.checked_sub(1))
            || (id == SYMBOL && self.localdb_depth.is_some());
        let child = self
            .capture
            .last()
            .is_some_and(|node| node.depth + 1 == depth)
            && (is_type(id) || matches!(id, PROTOTYPE | RETURNSYM | INTERNALLIST | PARAM));
        if root || child {
            // Bound recursive type projection and drop depth without constraining
            // the unrelated p-code AST. Do not publish an incomplete signature.
            if self.capture.len() >= 64 {
                self.failed = true;
                self.capture.clear();
                return;
            }
            self.capture.push(Node {
                id,
                depth,
                ..Node::default()
            });
        }
    }

    pub(crate) fn attribute(&mut self, id: u32, value: Value, depth: usize) -> Option<Value> {
        if self.addr_depth == Some(depth) {
            match (id, &value) {
                (SPACE, Value::String(space)) => self.addr_space = Some(space.clone()),
                (OFFSET, _) => self.addr_offset = value.unsigned(),
                (SIZE, _) => self.addr_size = value.unsigned().and_then(|s| u32::try_from(s).ok()),
                _ => {}
            }
        }
        let Some(node) = self.capture.last_mut() else {
            return Some(value);
        };
        if node.depth == depth && matches!(id, 9 | 10 | 12 | 13 | 14 | 19 | 48 | 61 | 115 | crate::wire::attr::NORETURN) {
            node.attributes.push((id, value));
        }
        // Metadata is not a Clang token. Move its attributes instead of copying
        // strings into both the token context and the recovered prototype.
        None
    }

    pub(crate) fn end(&mut self, id: u32, depth: usize) {
        if self.failed {
            return;
        }
        if self.capture.last().is_some_and(|node| node.depth == depth) {
            let Some(mut node) = self.capture.pop() else {
                return;
            };
            if node.id != id {
                self.failed = true;
                return;
            }
            if let Some(parent) = self.capture.last_mut() {
                parent.children.push(node);
            } else if id == PROTOTYPE {
                if self.prototype.replace(node).is_some() {
                    self.failed = true;
                }
            } else if node.value(61).and_then(Value::signed) == Some(0) {
                let parameter = node
                    .unsigned(10)
                    .and_then(|index| u32::try_from(index).ok())
                    .and_then(|index| decode_parameter(node, index));
                if let Some(parameter) = parameter {
                    self.parameters.push(parameter);
                } else {
                    self.failed = true;
                }
            } else if id == SYMBOL && self.mapsym_depth.is_some() {
                // An irregular input carries its evidence in its name; the
                // storage arrives in the sibling `<addr>`.
                self.pending_input = node
                    .string(NAME)
                    .filter(|name| name.starts_with("in_"));
            }
        }
        if id == ADDR && self.addr_depth == Some(depth) {
            self.addr_depth = None;
        }
        if id == MAPSYM && self.mapsym_depth == Some(depth) {
            self.mapsym_depth = None;
            // A live-in register symbol is dynamic: `SymbolEntry::encode`
            // writes `<hash>` rather than `<addr>` for storage the decompiler
            // did not address-tie (database.cc:187-198). The register is then
            // carried by the name alone, which is the documented encoding.
            if let Some(name) = self.pending_input.take() {
                if self.storage.len() < 64 {
                    self.storage.push(StorageSymbol {
                        name,
                        space: self.addr_space.take().unwrap_or_default(),
                        offset: self.addr_offset.take().unwrap_or_default(),
                        size: self.addr_size.take().unwrap_or_default(),
                    });
                }
            }
        }
        if id == LOCALDB && self.localdb_depth == Some(depth) {
            self.localdb_depth = None;
        }
        if id == FUNCTION && self.function_depth == Some(depth) {
            if let Some(node) = self.prototype.take() {
                if self.seen_prototype {
                    self.failed = true;
                }
                self.seen_prototype = true;
                self.result = decode_prototype(node, std::mem::take(&mut self.parameters));
            }
            self.parameters.clear();
            self.function_depth = None;
        }
    }

    pub(crate) fn finish(self) -> Recovered {
        if self.failed || self.function_depth.is_some() || !self.capture.is_empty() {
            Recovered::default()
        } else {
            Recovered { prototype: self.result, storage: self.storage }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::decode_document_with_ram_space;
    use crate::wire::{
        ELEMENT_END, ELEMENT_START, attr_type, encode_attribute, encode_header,
        encode_string_attribute,
    };

    fn element(out: &mut Vec<u8>, id: u32, body: impl FnOnce(&mut Vec<u8>)) {
        encode_header(out, ELEMENT_START, id);
        body(out);
        encode_header(out, ELEMENT_END, id);
    }

    fn text(out: &mut Vec<u8>, id: u32, value: &str) {
        encode_string_attribute(out, id, value.as_bytes());
    }

    fn int_type(out: &mut Vec<u8>) {
        element(out, TYPEREF, |out| text(out, 14, "int"));
    }

    fn parameter(out: &mut Vec<u8>, index: u64, name: &str, ty: impl FnOnce(&mut Vec<u8>)) {
        element(out, SYMBOL, |out| {
            encode_attribute(out, 61, attr_type::POSITIVE_INT, 0);
            encode_attribute(out, 10, attr_type::UNSIGNED_INT, index);
            text(out, 14, name);
            ty(out);
        });
    }

    fn prototype(out: &mut Vec<u8>, model: &str, variadic: bool, ty: impl FnOnce(&mut Vec<u8>)) {
        element(out, PROTOTYPE, |out| {
            text(out, 13, model);
            encode_header(out, crate::wire::ATTRIBUTE, 115);
            out.push((attr_type::BOOLEAN << 4) | u8::from(variadic));
            element(out, RETURNSYM, ty);
        });
    }

    #[test]
    fn orders_parameters_without_adopting_a_nested_function_pointer_prototype() {
        let mut packed = Vec::new();
        element(&mut packed, DOC, |out| {
            element(out, FUNCTION, |out| {
                element(out, LOCALDB, |out| {
                    parameter(out, 1, "count", int_type);
                    parameter(out, 0, "callback", |out| {
                        element(out, TYPE, |out| {
                            text(out, 12, "ptr");
                            encode_attribute(out, 19, attr_type::POSITIVE_INT, 8);
                            element(out, TYPE, |out| {
                                text(out, 12, "code");
                                prototype(out, "__cdecl", true, |out| element(out, VOID, |_| {}));
                            });
                        })
                    });
                });
                prototype(out, "__stdcall", false, int_type);
            })
        });
        let recovered = decode_document_with_ram_space(&packed, Some(3))
            .prototype
            .unwrap();
        assert_eq!(recovered.calling_convention, "__stdcall");
        assert!(!recovered.variadic);
        assert_eq!(recovered.return_type.name.as_deref(), Some("int"));
        assert_eq!(
            recovered
                .parameters
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["callback", "count"]
        );
        let pointer = &recovered.parameters[0].data_type;
        assert_eq!(pointer.metatype.as_deref(), Some("ptr"));
        assert_eq!(pointer.size, Some(8));
        let nested = pointer.target.as_ref().unwrap().prototype.as_ref().unwrap();
        assert_eq!(nested.calling_convention, "__cdecl");
        assert!(nested.variadic);
        assert_eq!(nested.return_type.metatype.as_deref(), Some("void"));
    }

    #[test]
    fn refuses_ambiguous_or_incomplete_prototypes() {
        let mut packed = Vec::new();
        element(&mut packed, DOC, |out| {
            element(out, FUNCTION, |out| {
                element(out, LOCALDB, |out| {
                    parameter(out, 0, "first", int_type);
                    parameter(out, 0, "duplicate", int_type);
                });
                prototype(out, "__cdecl", false, int_type);
            })
        });
        assert!(
            decode_document_with_ram_space(&packed, Some(3))
                .prototype
                .is_none()
        );
        let raw = include_bytes!("../fixtures/doc_add.bin");
        assert!(
            decode_document_with_ram_space(&raw[..raw.len() - 1], Some(3))
                .prototype
                .is_none()
        );
    }

    #[test]
    fn rejects_a_packed_parameter_index_that_would_wrap_to_zero() {
        let mut packed = Vec::new();
        element(&mut packed, DOC, |out| {
            element(out, FUNCTION, |out| {
                element(out, LOCALDB, |out| {
                    element(out, SYMBOL, |out| {
                        text(out, 14, "overflow");
                        encode_attribute(out, 61, attr_type::POSITIVE_INT, 0);
                        encode_header(out, crate::wire::ATTRIBUTE, 10);
                        // 2^64 in ten seven-bit groups, not the valid ordinal zero.
                        out.extend_from_slice(&[
                            0x4a, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                        ]);
                        int_type(out);
                    })
                });
                prototype(out, "__cdecl", false, int_type);
            })
        });
        assert!(
            decode_document_with_ram_space(&packed, Some(3))
                .prototype
                .is_none()
        );
    }
}